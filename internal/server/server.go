// Package server is the HTTP layer of dns-gate: the EuroDNS-compatible
// API (served by the EuroDNS facade for EuroDNS zones), the gate extension
// endpoints, the UI API and the UI itself.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/discovery"
	"github.com/KamorionLabs/dns-gate/internal/eurodnsapi"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/identitystore"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/routes"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/version"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
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
	// EuroDNS serves the EuroDNS-compatible API (internal/eurodnsapi); nil
	// when no provider is of kind eurodns.
	EuroDNS EuroDNSAPI
	// UIFiles is the built web UI (web.FS()); nil disables static serving.
	UIFiles fs.FS
	// Policy is the layered policy (base + managed); PolicyStore keeps the
	// managed revisions and Ownership feeds the impact analysis. Without
	// them /api/v1/policy is disabled.
	Policy      *policy.Holder
	PolicyStore store.PolicyStore
	Ownership   OwnershipLister
	// Discovery is the zone listing of the provider accounts, nil when
	// absent: policy revisions may then not add zones.
	Discovery ZoneDiscovery
	// Ops and Terraform back adoption, RRset plans (MCP) and the HCL export.
	Ops       Operations
	Terraform TerraformRenderer
	// Plans persists the RRset plans of MCP and of the REST API, shared by
	// every gate instance; an in-process store when nil (one replica).
	Plans store.PlanStore
	// Versions reads zone versions: ETag of the REST inventory, disabled
	// when nil.
	Versions ZoneVersions
	// Transfers serves the ownership transfer requests and team renames;
	// their routes answer 501 when nil.
	Transfers zonewrite.Transfers
	// Tombstones feeds the team views with the RRsets reserved for each
	// team; optional.
	Tombstones TombstoneLister
	// HTTPClient is used for the UI OIDC login (discovery, token exchange)
	// and the SAML IdP metadata.
	HTTPClient *http.Client
	// APIKeys stores the gate-issued API keys and their acme-dns
	// registrations; nil disables /api/v1/api-keys and acme-dns.
	APIKeys store.APIKeyStore
	// SAMLGroups resolves the groups of SAML users; nil builds the AWS
	// identity store lookup of ui.saml.groups_from_identity_store, if any.
	SAMLGroups GroupLookup
	Log        *slog.Logger
	Now        func() time.Time

	// Propagation checks the propagation of RRsets; nil builds the checker
	// of the propagation section, unless disabled.
	Propagation Propagator
}

// EuroDNSAPI is the EuroDNS-compatible API facade (internal/eurodnsapi).
type EuroDNSAPI interface {
	// Serves reports whether zone is served by a EuroDNS provider.
	Serves(zone string) bool
	// Do runs an engine-backed operation.
	Do(ctx context.Context, s *identity.Subject, c eurodnsapi.Call) (*eurodnsapi.Reply, error)
	// AdoptJSON serves the gate adopt extension for a EuroDNS zone.
	AdoptJSON(ctx context.Context, s *identity.Subject, zone string, body json.RawMessage) error
	// Proxy forwards an authorized passthrough request to the account of
	// zone; path is the validated upstream path.
	Proxy(w http.ResponseWriter, r *http.Request, zone, path string)
	// ProfileAccount returns the EuroDNS provider of the zone profile
	// operations: the provider named id, or the only EuroDNS provider.
	ProfileAccount(id string) (*eurodnsprov.Provider, error)
}

// ZoneVersions reads the gate version of a zone (store.Store).
type ZoneVersions interface {
	ZoneVersion(ctx context.Context, zone string) (int64, error)
}

// ZoneDiscovery is the account zone listing (internal/discovery).
type ZoneDiscovery interface {
	policy.Discovery
	Loaded() bool
	Status() discovery.Status
	// RefreshIfOlder lists the account again if the last listing is older
	// than age (bounded below by discovery.MinOnDemand).
	RefreshIfOlder(ctx context.Context, age time.Duration) error
}

// Server is the gate HTTP handler.
type Server struct {
	cfg     Config
	table   *routes.Table
	ui      *uiAuth
	static  http.Handler
	pol     *policy.Engine
	mcp     *mcpServer
	log     *slog.Logger
	now     func() time.Time
	delegMu sync.Mutex // serializes delegated policy writes in this replica
	owners  ownerCounts
	// profileLimiter bounds the zone profile operations per subject.
	profileLimiter *subjectLimiter
}

// New builds the server.
func New(c Config) (*Server, error) {
	if c.Config == nil || c.Authn == nil || c.Authz == nil || c.Engine == nil || c.Audit == nil {
		return nil, errors.New("server: incomplete configuration")
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
	if c.Plans == nil {
		c.Plans = store.NewMemory()
	}
	if c.Propagation == nil {
		c.Propagation = newPropagator(c)
	}
	if c.Policy == nil {
		h, err := policy.NewHolder(c.Config)
		if err != nil {
			return nil, err
		}
		c.Policy = h
	}
	s := &Server{cfg: c, log: c.Log, now: c.Now, pol: policy.New(c.Policy), profileLimiter: newSubjectLimiter(profileRequestsPerMinute, c.Now)}
	s.table = routes.NewDynamic(s.pol.Managed)
	if c.Config.MCP.Enabled {
		s.mcp = s.newMCP()
	}
	if c.Config.UI.Enabled {
		groups := c.SAMLGroups
		if sc := c.Config.UI.SAML; groups == nil && sc != nil && sc.GroupsFromIdentityStore != nil {
			l, err := identitystore.NewAWS(context.Background(), *sc.GroupsFromIdentityStore)
			if err != nil {
				return nil, err
			}
			groups = l
		}
		ui, err := newUIAuth(c.Config, c.Authn, c.HTTPClient, c.Now, groups)
		if err != nil {
			return nil, err
		}
		s.ui = ui
		s.ui.log = c.Log
		if c.UIFiles != nil {
			s.static = spaHandler(c.UIFiles)
		}
	}
	return s, nil
}

// samlACSMaxBody is the body limit of the SAML assertion consumer service,
// whatever limits.max_body_bytes (a signed response is several kilobytes).
const samlACSMaxBody = 512 << 10

// Handler returns the root handler.
func (s *Server) Handler() http.Handler {
	return s.withRequestID(securityHeaders(http.HandlerFunc(s.route)))
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	limit := s.cfg.Config.Limits.MaxBodyBytes
	if p == config.SAMLACSPath && limit < samlACSMaxBody {
		limit = samlACSMaxBody
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	switch {
	case p == "/healthz" || p == "/readyz":
		w.Header().Set("Content-Type", "text/plain")
		body := "ok\n"
		if s.cfg.Policy.LoadError() != "" {
			body += "policy: managed policy not served, its grants may be missing (see the logs or GET /api/v1/policy)\n"
		}
		_, _ = w.Write([]byte(body))
	case p == mcpPath && s.mcp != nil:
		s.mcp.ServeHTTP(w, r)
	case (p == resourceMetaPath || p == resourceMetaPath+mcpPath) && s.mcp != nil:
		s.mcp.serveResourceMetadata(w, r)
	case p == GateInfoPath || p == LegacyGateInfoPath:
		s.handleGateInfo(w, r)
	case p == jwksPath && s.cfg.Authn.TokenIssuer() != nil:
		s.handleJWKS(w, r)
	case (p == oidcConfigPath || p == oauthMetadataPath) && s.authorizationServer():
		s.handleOAuthMetadata(w, r)
	case p == oauthAuthorizePath && s.authorizationServer():
		s.handleAuthorize(w, r)
	case p == oauthTokenPath && s.authorizationServer():
		s.handleToken(w, r)
	case strings.HasPrefix(p, GateInfoPath+"/") || strings.HasPrefix(p, LegacyGateInfoPath+"/"):
		s.handleExtension(w, r)
	case strings.HasPrefix(p, "/acme/"):
		s.handleACME(w, r)
	case p == TokenExchangePath:
		s.handleTokenExchange(w, r)
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
		if !presentsAPIKey(r) {
			s.audit(r, nil, m.Operation.ID, m.Zone, "deny", ae.Reason)
		}
		writeError(w, ae.Status, ae.Reason, ae.Message)
		return
	}
	authn.StripCredentials(r.Header)
	ctx := identity.With(r.Context(), subj)
	r = r.WithContext(ctx)

	if rerr == nil && m.Rule.Kind == routes.Account {
		s.serveEuroDNSProfile(w, r, subj, m)
		return
	}
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

	if s.cfg.EuroDNS == nil || !s.cfg.EuroDNS.Serves(m.Zone) {
		s.audit(r, subj, m.Operation.ID, m.Zone, "deny", "zone_not_eurodns")
		writeError(w, http.StatusNotFound, "zone_not_eurodns", "zone "+m.Zone+" is not served by a EuroDNS provider: use /api/v1")
		return
	}
	switch m.Rule.Kind {
	case routes.Passthrough:
		s.audit(r, subj, m.Operation.ID, m.Zone, "allow", "")
		s.cfg.EuroDNS.Proxy(w, r, m.Zone, m.Path)
	case routes.Engine:
		s.serveEngine(w, r, subj, m)
	default:
		writeError(w, http.StatusForbidden, "operation_denied", "operation not allowed by the gate")
	}
}

func (s *Server) serveEngine(w http.ResponseWriter, r *http.Request, subj *identity.Subject, m *routes.Match) {
	c := eurodnsapi.Call{Op: m.Operation.ID, Zone: m.Zone, Params: m.Params, IfMatch: normalizeETag(r.Header.Get("If-Match"))}
	switch m.Operation.ID {
	case "checkDnsZone", "saveDnsZone", "addDnsRecords":
		if !decodeBody(w, r, &c.Body) {
			return
		}
	}
	rep, err := s.cfg.EuroDNS.Do(r.Context(), subj, c)
	if err != nil {
		s.engineError(w, r, subj, m, err)
		return
	}
	setETag(w, rep.ETag)
	if rep.Body == nil {
		w.WriteHeader(rep.Status)
		return
	}
	writeJSON(w, rep.Status, rep.Body)
}

func (s *Server) engineError(w http.ResponseWriter, r *http.Request, subj *identity.Subject, m *routes.Match, err error) {
	if ze, ok := zonewrite.AsError(err); ok {
		status := reasonStatus(ze.Reason)
		if ze.Reason == zonewrite.ReasonLocked {
			w.Header().Set("Retry-After", "5")
		}
		if ze.Reason == zonewrite.ReasonUpstream {
			s.log.Warn("upstream error", "request_id", requestid.From(r.Context()), "op", m.Operation.ID, "err", ze.Err)
		}
		writeJSON(w, status, errorBody{Reason: string(ze.Reason), Message: ze.Message, Details: ze.Details})
		return
	}
	var bad *eurodnsapi.BadRequestError
	if errors.As(err, &bad) {
		writeError(w, http.StatusBadRequest, "bad_request", bad.Message)
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
	case zonewrite.ReasonForeignRRset, zonewrite.ReasonTainted, "adopt_conflict", zonewrite.ReasonHTTPS:
		return http.StatusConflict
	case zonewrite.ReasonPrecondition:
		return http.StatusPreconditionFailed
	case zonewrite.ReasonInvalid:
		return http.StatusBadRequest
	case zonewrite.ReasonLocked:
		return http.StatusServiceUnavailable
	case zonewrite.ReasonNotFound:
		return http.StatusNotFound
	case zonewrite.ReasonUpstream:
		return http.StatusBadGateway
	case zonewrite.ReasonExpired:
		return http.StatusGone
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) handleGateInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	features := []string{FeatureIfMatch, FeatureOwnership, FeatureAdopt, FeaturePolicyDelegation}
	if s.cfg.Ops != nil {
		features = append(features, FeaturePlans, FeatureRRsetAPI, FeatureForwards)
	}
	if s.tokenExchange() {
		features = append(features, FeatureTokenExchange)
	}
	if s.cfg.APIKeys != nil {
		features = append(features, FeatureAPIKeys, FeatureACMEHTTPReq, FeatureACMEDNS)
	}
	writeJSON(w, http.StatusOK, GateInfo{Version: version.Version, Features: features})
}

// GateInfo is the gate discovery document (GET /.well-known/dns-gate).
type GateInfo struct {
	Version  string   `json:"version"`
	Features []string `json:"features"`
}

// Gate features advertised by GET /.well-known/dns-gate.
const (
	FeatureIfMatch   = "if-match"
	FeatureOwnership = "ownership"
	FeatureAdopt     = "adopt"
	// FeatureAPIKeys: /api/v1/api-keys; FeatureACMEHTTPReq and
	// FeatureACMEDNS: the lego httpreq and acme-dns endpoints under /acme.
	FeatureAPIKeys     = "api-keys"
	FeatureACMEHTTPReq = "acme-httpreq"
	FeatureACMEDNS     = "acme-dns"
)

// GateInfoPath is the gate's discovery document, also used by clients to
// detect a gate.
const GateInfoPath = "/.well-known/dns-gate"

// LegacyGateInfoPath serves the same discovery document and extensions under
// the name of eurodns-gate, for terraform-provider-eurodns before v0.4.0.
const LegacyGateInfoPath = "/.well-known/eurodns-gate"

// handleExtension serves POST /.well-known/dns-gate/zones/{domain}/adopt
// (and the same path under LegacyGateInfoPath).
func (s *Server) handleExtension(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, GateInfoPath+"/")
	if !ok {
		rest = strings.TrimPrefix(r.URL.Path, LegacyGateInfoPath+"/")
	}
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
		if !presentsAPIKey(r) {
			s.audit(r, nil, "adopt", zone, "deny", ae.Reason)
		}
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
	var body json.RawMessage
	if !decodeBody(w, r, &body) {
		return
	}
	m := &routes.Match{Operation: routes.Operation{ID: "adopt"}, Zone: zone}
	if s.cfg.EuroDNS == nil {
		writeError(w, http.StatusNotFound, "zone_not_eurodns", "zone "+zone+" is not served by a EuroDNS provider: use /api/v1")
		return
	}
	if err := s.cfg.EuroDNS.AdoptJSON(r.Context(), subj, zone, body); err != nil {
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
