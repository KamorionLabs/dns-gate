// Package server is the HTTP layer of eurodns-gate: the EuroDNS-compatible
// API (engine or passthrough), the gate extension endpoints, the read-only
// UI API and the UI itself.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/audit"
	"github.com/KamorionLabs/eurodns-gate/internal/authn"
	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/requestid"
	"github.com/KamorionLabs/eurodns-gate/internal/routes"
	"github.com/KamorionLabs/eurodns-gate/internal/store"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-gate/internal/version"
	"github.com/KamorionLabs/eurodns-gate/internal/zonewrite"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// Engine is the zone engine, including the inventory used by the UI API.
type Engine = zonewrite.Engine

// AuditReader reads persisted audit events.
type AuditReader interface {
	ListAudit(ctx context.Context, q store.AuditQuery) ([]audit.Event, string, error)
}

// Config wires the server.
type Config struct {
	Config      *config.Config
	Authn       *authn.Authenticator
	Authz       policy.Authorizer
	Engine      Engine
	Audit       audit.Logger
	AuditReader AuditReader
	// Upstream is the round tripper towards EuroDNS (eurodns.Transport with
	// API key auth and the shared rate limiter).
	Upstream http.RoundTripper
	// UIFiles is the built web UI (web.FS()); nil disables static serving.
	UIFiles fs.FS
	// Policy is the layered policy (base + managed); PolicyStore keeps the
	// managed revisions and Ownership feeds the impact analysis. Without
	// them /api/v1/policy is disabled.
	Policy      *policy.Holder
	PolicyStore store.PolicyStore
	Ownership   OwnershipLister
	// Ops and Terraform back adoption, RRset plans (MCP) and the HCL export.
	Ops       Operations
	Terraform TerraformRenderer
	// HTTPClient is used for the UI OIDC login (discovery, token exchange).
	HTTPClient *http.Client
	Log        *slog.Logger
	Now        func() time.Time
}

// Server is the gate HTTP handler.
type Server struct {
	cfg      Config
	table    *routes.Table
	upstream *url.URL
	proxy    http.Handler
	ui       *uiAuth
	static   http.Handler
	pol      *policy.Engine
	mcp      *mcpServer
	log      *slog.Logger
	now      func() time.Time
}

// New builds the server.
func New(c Config) (*Server, error) {
	if c.Config == nil || c.Authn == nil || c.Authz == nil || c.Engine == nil || c.Audit == nil || c.Upstream == nil {
		return nil, errors.New("server: incomplete configuration")
	}
	up, err := url.Parse(c.Config.Upstream.BaseURL)
	if err != nil {
		return nil, err
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if c.Policy == nil {
		h, err := policy.NewHolder(c.Config)
		if err != nil {
			return nil, err
		}
		c.Policy = h
	}
	s := &Server{cfg: c, table: routes.New(c.Config.Zones), upstream: up, log: c.Log, now: c.Now, pol: policy.New(c.Policy)}
	s.proxy = s.newProxy()
	if c.Config.MCP.Enabled {
		s.mcp = s.newMCP()
	}
	if c.Config.UI.Enabled {
		s.ui = newUIAuth(c.Config, c.Authn, c.HTTPClient, c.Now)
		if c.UIFiles != nil {
			s.static = spaHandler(c.UIFiles)
		}
	}
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler {
	return s.withRequestID(securityHeaders(http.HandlerFunc(s.route)))
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Config.Limits.MaxBodyBytes)
	p := r.URL.Path
	switch {
	case p == "/healthz" || p == "/readyz":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	case p == mcpPath && s.mcp != nil:
		s.mcp.ServeHTTP(w, r)
	case (p == resourceMetaPath || p == resourceMetaPath+mcpPath) && s.mcp != nil:
		s.mcp.serveResourceMetadata(w, r)
	case p == eurodns.GateInfoPath:
		s.handleGateInfo(w, r)
	case strings.HasPrefix(p, eurodns.GateInfoPath+"/"):
		s.handleExtension(w, r)
	case p == "/" && s.ui != nil:
		http.Redirect(w, r, "/ui/", http.StatusFound)
	case p == "/ui" && s.ui != nil:
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
	case strings.HasPrefix(p, "/ui/") && s.ui != nil && s.static != nil:
		s.static.ServeHTTP(w, r)
	case strings.HasPrefix(p, "/auth/") && s.ui != nil:
		s.ui.ServeHTTP(w, r)
	case p == "/api/v1" || strings.HasPrefix(p, "/api/v1/"):
		s.handleUIAPI(w, r)
	case p == "/" || p == "/ui" || strings.HasPrefix(p, "/ui/") || strings.HasPrefix(p, "/auth/"):
		writeError(w, http.StatusNotFound, "not_found", "UI disabled")
	default:
		s.handleEuroDNS(w, r)
	}
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestid.FromHeader(r.Header.Get(requestid.Header))
		w.Header().Set(requestid.Header, id)
		ctx := zonewrite.WithRequestID(requestid.With(r.Context(), id), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/ui/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// handleEuroDNS serves the EuroDNS-compatible API.
func (s *Server) handleEuroDNS(w http.ResponseWriter, r *http.Request) {
	m, rerr := s.table.Resolve(r)
	if rerr != nil && m == nil {
		status, reason := http.StatusNotFound, "not_found"
		switch {
		case errors.Is(rerr, routes.ErrMethod):
			status, reason = http.StatusMethodNotAllowed, "method_not_allowed"
		case errors.Is(rerr, routes.ErrNotFound):
		default:
			status, reason = http.StatusBadRequest, "bad_request"
		}
		writeError(w, status, reason, rerr.Error())
		return
	}

	subj, aerr := s.cfg.Authn.Authenticate(r)
	if aerr != nil {
		var ae *authn.Error
		if !errors.As(aerr, &ae) {
			ae = &authn.Error{Status: http.StatusUnauthorized, Reason: "unauthenticated", Message: "authentication failed"}
		}
		s.audit(r, nil, m.Operation.ID, m.Zone, "deny", ae.Reason)
		writeError(w, ae.Status, ae.Reason, ae.Message)
		return
	}
	authn.StripCredentials(r.Header)
	ctx := identity.With(r.Context(), subj)
	r = r.WithContext(ctx)

	if rerr != nil {
		reason := "operation_denied"
		if errors.Is(rerr, routes.ErrZoneUnknown) {
			reason = "zone_not_managed"
		}
		s.audit(r, subj, m.Operation.ID, m.Zone, "deny", reason)
		writeError(w, http.StatusForbidden, reason, rerr.Error())
		return
	}
	if !s.cfg.Authz.Allow(subj, m.Rule.Action, m.Zone) {
		s.audit(r, subj, m.Operation.ID, m.Zone, "deny", "forbidden")
		writeError(w, http.StatusForbidden, "forbidden", "action "+m.Rule.Action+" not allowed on "+m.Zone)
		return
	}

	switch m.Rule.Kind {
	case routes.Passthrough:
		s.audit(r, subj, m.Operation.ID, m.Zone, "allow", "")
		s.servePassthrough(w, r, m)
	case routes.Engine:
		s.serveEngine(w, r, subj, m)
	default:
		writeError(w, http.StatusForbidden, "operation_denied", "operation not allowed by the gate")
	}
}

func (s *Server) serveEngine(w http.ResponseWriter, r *http.Request, subj *identity.Subject, m *routes.Match) {
	ctx := r.Context()
	e := s.cfg.Engine
	ifMatch := normalizeETag(r.Header.Get("If-Match"))
	switch m.Operation.ID {
	case "getDnsZone":
		z, err := e.GetZone(ctx, subj, m.Zone)
		if err != nil {
			s.engineError(w, r, subj, m, err)
			return
		}
		setETag(w, z.ETag)
		writeJSON(w, http.StatusOK, z)
	case "checkDnsZone":
		var z eurodns.Zone
		if !decodeBody(w, r, &z) {
			return
		}
		out, err := e.CheckZone(ctx, subj, m.Zone, &z)
		if err != nil {
			s.engineError(w, r, subj, m, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case "saveDnsZone":
		var z eurodns.Zone
		if !decodeBody(w, r, &z) {
			return
		}
		if err := e.SaveZone(ctx, subj, m.Zone, &z, ifMatch); err != nil {
			s.engineError(w, r, subj, m, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "addDnsRecords":
		var recs []eurodns.Record
		if !decodeBody(w, r, &recs) {
			return
		}
		if len(recs) == 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "at least one record is required")
			return
		}
		z, err := e.AddRecords(ctx, subj, m.Zone, recs, ifMatch)
		if err != nil {
			s.engineError(w, r, subj, m, err)
			return
		}
		setETag(w, z.ETag)
		writeJSON(w, http.StatusOK, z)
	case "deleteDnsRecord":
		id, err := parseInt64(m.Params["record-id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid record id")
			return
		}
		z, err := e.DeleteRecord(ctx, subj, m.Zone, id, ifMatch)
		if err != nil {
			s.engineError(w, r, subj, m, err)
			return
		}
		setETag(w, z.ETag)
		writeJSON(w, http.StatusOK, z)
	default:
		writeError(w, http.StatusForbidden, "operation_denied", "operation not allowed by the gate")
	}
}

func (s *Server) engineError(w http.ResponseWriter, r *http.Request, subj *identity.Subject, m *routes.Match, err error) {
	if ze, ok := zonewrite.AsError(err); ok {
		status := reasonStatus(ze.Reason)
		if ze.Reason == zonewrite.ReasonLocked {
			w.Header().Set("Retry-After", "5")
		}
		writeJSON(w, status, errorBody{Reason: string(ze.Reason), Message: ze.Message, Details: ze.Details})
		return
	}
	var ae *eurodns.APIError
	if errors.As(err, &ae) {
		s.log.Warn("upstream error", "request_id", requestid.From(r.Context()), "status", ae.StatusCode, "op", m.Operation.ID)
		writeError(w, http.StatusBadGateway, string(zonewrite.ReasonUpstream), "EuroDNS returned an error")
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeError(w, http.StatusGatewayTimeout, "timeout", "request timed out")
		return
	}
	s.log.Error("engine error", "request_id", requestid.From(r.Context()), "op", m.Operation.ID, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func reasonStatus(r zonewrite.Reason) int {
	switch r {
	case zonewrite.ReasonForbidden, zonewrite.ReasonNotOwner, zonewrite.ReasonTooMany:
		return http.StatusForbidden
	case zonewrite.ReasonForeignRRset, zonewrite.ReasonTainted, "adopt_conflict":
		return http.StatusConflict
	case zonewrite.ReasonPrecondition:
		return http.StatusPreconditionFailed
	case zonewrite.ReasonInvalid:
		return http.StatusBadRequest
	case zonewrite.ReasonLocked:
		return http.StatusServiceUnavailable
	case zonewrite.ReasonUpstream:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) handleGateInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	writeJSON(w, http.StatusOK, eurodns.GateInfo{
		Version:  version.Version,
		Features: []string{eurodns.FeatureIfMatch, eurodns.FeatureOwnership, eurodns.FeatureAdopt},
	})
}

// handleExtension serves POST /.well-known/eurodns-gate/zones/{domain}/adopt.
func (s *Server) handleExtension(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, eurodns.GateInfoPath+"/")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] != "zones" || parts[2] != "adopt" || r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path {
		writeError(w, http.StatusNotFound, "not_found", "unknown extension endpoint")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	zone := strings.TrimSuffix(strings.ToLower(parts[1]), ".")
	if !config.ValidFQDN(zone) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid zone")
		return
	}
	subj, aerr := s.cfg.Authn.Authenticate(r)
	if aerr != nil {
		var ae *authn.Error
		if !errors.As(aerr, &ae) {
			ae = &authn.Error{Status: http.StatusUnauthorized, Reason: "unauthenticated", Message: "authentication failed"}
		}
		s.audit(r, nil, "adopt", zone, "deny", ae.Reason)
		writeError(w, ae.Status, ae.Reason, ae.Message)
		return
	}
	authn.StripCredentials(r.Header)
	r = r.WithContext(identity.With(r.Context(), subj))
	// Adopting an RRset already owned by one of the subject's teams is a
	// no-op (Terraform import of gate-created RRsets) and only needs write
	// access; the engine checks dns.record.adopt per RRset for real adoptions.
	if !s.cfg.Authz.Allow(subj, policy.ActionRecordAdopt, zone) && !s.cfg.Authz.Allow(subj, policy.ActionRecordWrite, zone) {
		s.audit(r, subj, "adopt", zone, "deny", "forbidden")
		writeError(w, http.StatusForbidden, "forbidden", "dns.record.adopt or dns.record.write required on "+zone)
		return
	}
	var req eurodns.AdoptRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.RRsets) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "rrsets required")
		return
	}
	m := &routes.Match{Operation: routes.Operation{ID: "adopt"}, Zone: zone}
	if err := s.cfg.Engine.Adopt(r.Context(), subj, zone, req); err != nil {
		s.engineError(w, r, subj, m, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) audit(r *http.Request, subj *identity.Subject, action, zone, decision, reason string) {
	e := audit.Event{
		Time:      s.now().UTC(),
		RequestID: requestid.From(r.Context()),
		Action:    action,
		Zone:      zone,
		Decision:  decision,
		Reason:    reason,
	}
	if subj != nil {
		e.Subject, e.SubjectName, e.SubjectCategory, e.Teams = subj.String(), subj.Name, subj.Category, subj.Teams
	} else {
		e.Extra = map[string]any{"remote_addr": s.cfg.Authn.ClientIP(r).String()}
	}
	s.cfg.Audit.Log(r.Context(), e)
}

type errorBody struct {
	Reason  string                  `json:"reason"`
	Message string                  `json:"message"`
	Details any                     `json:"details,omitempty"`
	Errors  []uiapi.ValidationError `json:"errors,omitempty"`
}

func writeError(w http.ResponseWriter, status int, reason, msg string) {
	writeJSON(w, status, errorBody{Reason: reason, Message: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "application/json expected")
		return false
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "bad_request", "trailing data after JSON body")
		return false
	}
	return true
}

// normalizeETag strips W/ and quotes: the engine works with bare tokens.
func normalizeETag(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "W/")
	return strings.Trim(v, `"`)
}

func setETag(w http.ResponseWriter, tag string) {
	if tag = normalizeETag(tag); tag != "" {
		w.Header().Set("ETag", `"`+tag+`"`)
	}
}

func parseInt64(s string) (int64, error) {
	var n int64
	if s == "" || len(s) > 19 {
		return 0, errors.New("invalid")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid")
		}
		n = n*10 + int64(c-'0')
		if n < 0 {
			return 0, errors.New("overflow")
		}
	}
	return n, nil
}
