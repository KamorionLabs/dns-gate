package server

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/mcpb"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/version"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// uiSubject authenticates a UI API request: session cookie first, then
// bearer token or virtual key.
// The session is returned when the request was authenticated by cookie
// (mutations then require the CSRF token).
func (s *Server) uiSubject(r *http.Request) (*identity.Subject, *session, *authn.Error) {
	if s.ui != nil {
		subj, sess, err := s.ui.sessionSubject(r)
		if err != nil {
			var ae *authn.Error
			if errors.As(err, &ae) {
				return nil, nil, ae
			}
			return nil, nil, &authn.Error{Status: http.StatusForbidden, Reason: "forbidden", Message: "not allowed"}
		}
		if subj != nil {
			return subj, sess, nil
		}
	}
	if r.Header.Get("Authorization") == "" && r.Header.Get("X-Api-Key") == "" {
		return nil, nil, &authn.Error{Status: http.StatusUnauthorized, Reason: "unauthenticated", Message: "login required"}
	}
	subj, err := s.cfg.Authn.Authenticate(r)
	if err != nil {
		var ae *authn.Error
		if errors.As(err, &ae) {
			return nil, nil, ae
		}
		return nil, nil, &authn.Error{Status: http.StatusUnauthorized, Reason: "unauthenticated", Message: "authentication failed"}
	}
	return subj, nil, nil
}

func (s *Server) handleUIAPI(w http.ResponseWriter, r *http.Request) {
	if p := r.URL.Path; len(p) > len("/api/v1/") && strings.HasSuffix(p, "/") && !strings.HasSuffix(p, "//") {
		r.URL.Path = strings.TrimSuffix(p, "/")
	}
	pattern, params, status := matchAPIRoute(r.Method, r.URL.Path)
	switch status {
	case http.StatusNotFound:
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
		return
	case http.StatusMethodNotAllowed:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	subj, sess, ae := s.uiSubject(r)
	if ae != nil {
		writeError(w, ae.Status, ae.Reason, ae.Message)
		return
	}
	if r.Method != http.MethodGet && sess != nil && !s.ui.checkCSRF(r) {
		writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token or origin")
		return
	}
	authn.StripCredentials(r.Header)
	me := subj
	if team := strings.TrimSpace(r.Header.Get(TeamHeader)); team != "" && pattern != "/api/v1/me" {
		var e *policyError
		if subj, e = forTeam(subj, team); e != nil {
			s.writePolicyError(w, e)
			return
		}
	}
	ctx := identity.With(r.Context(), subj)
	r = r.WithContext(ctx)
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case pattern == routeZoneTransfers || pattern == routeTeamRename || strings.HasPrefix(pattern, routeTransfers):
		s.handleTransfers(w, r, subj, sess, pattern, params)
		return
	case pattern == routePolicy || strings.HasPrefix(pattern, routePolicy+"/"):
		s.handlePolicyAPI(w, r, subj, sess, strings.TrimPrefix(rest, "/policy"))
		return
	case pattern == routeTokens:
		s.handleIssueToken(w, r, subj, sess)
		return
	case strings.HasPrefix(pattern, routeProfiles):
		s.handleZoneProfilesAPI(w, r, subj, sess, pattern, params)
		return
	case pattern == routeAPIKeys || strings.HasPrefix(pattern, routeAPIKeys+"/"):
		s.handleAPIKeys(w, r, subj, sess, pattern, params["id"])
		return
	case pattern == routeRRset:
		s.handleRRset(w, r, subj, sess, params["zone"], params["host"], params["type"])
		return
	case pattern == routePlan:
		s.handlePlan(w, r, subj, params["zone"])
		return
	case pattern == routeApply:
		s.handleApply(w, r, subj, sess, params["zone"])
		return
	case pattern != routeZoneRRsets && strings.HasPrefix(pattern, routeZoneOps):
		s.handleZoneOps(w, r, subj, sess, params["zone"], strings.TrimPrefix(pattern, routeZoneOps))
		return
	}

	readable := s.readableZones(subj)
	if len(readable) == 0 && rest != "/me" {
		writeError(w, http.StatusForbidden, "forbidden", "ui.read not granted")
		return
	}

	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case rest == "/me":
		out := uiapi.Me{
			Subject:     me.String(),
			Name:        me.Name,
			Category:    me.Category,
			Roles:       nonNil(me.Roles),
			Teams:       nonNil(me.Teams),
			Groups:      nonNil(me.Groups),
			Permissions: s.cfg.Policy.Current().Permissions(me.Roles),
		}
		if len(me.Teams) > 0 {
			out.DefaultTeam = me.Teams[0]
		}
		writeJSON(w, http.StatusOK, out)
	case pattern == routeTeams || pattern == routeTeam:
		s.handleTeams(w, r, subj, readable, strings.ToLower(params["team"]))
	case rest == "/connect":
		writeJSON(w, http.StatusOK, s.connectInfo(r))
	case rest == claudeDesktopExtensionPath:
		s.serveClaudeDesktopExtension(w, r)
	case rest == "/zones":
		folder := r.URL.Query().Get("folder")
		if folder != "" {
			if err := glob.ValidFolderPattern(folder); err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "folder: "+err.Error())
				return
			}
		}
		zs, err := s.cfg.Engine.Zones(ctx, subj)
		if err != nil {
			s.log.Error("ui zones", "err", err)
			writeError(w, http.StatusBadGateway, "upstream", "inventory unavailable")
			return
		}
		writeJSON(w, http.StatusOK, readableZones(s.cfg.Policy.Current(), zs, readable, folder))
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "rrsets":
		zone := strings.ToLower(parts[1])
		if !config.ValidFQDN(zone) {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid zone")
			return
		}
		if !readable[zone] {
			writeError(w, http.StatusForbidden, "forbidden", "ui.read not granted on "+zone)
			return
		}
		inv, err := s.cfg.Engine.Inventory(ctx, subj, zone)
		if ze, ok := zonewrite.AsError(err); ok && (ze.Reason == zonewrite.ReasonForbidden || ze.Reason == zonewrite.ReasonNotFound) {
			status := http.StatusForbidden
			if ze.Reason == zonewrite.ReasonNotFound {
				status = http.StatusNotFound
			}
			writeError(w, status, string(ze.Reason), ze.Message)
			return
		}
		if err != nil {
			s.log.Error("ui inventory", "zone", zone, "err", err)
			writeError(w, http.StatusBadGateway, "upstream", "inventory unavailable")
			return
		}
		if inv.RRsets == nil {
			inv.RRsets = []uiapi.RRset{}
		}
		inv.Folder = s.cfg.Policy.Current().Folder(zone)
		fillHashes(inv.RRsets)
		if s.cfg.Versions != nil {
			if v, err := s.cfg.Versions.ZoneVersion(ctx, zone); err == nil {
				w.Header().Set("ETag", zoneETag(v))
			}
		}
		writeJSON(w, http.StatusOK, inv)
	case rest == "/audit":
		s.handleAudit(w, r, subj, readable)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	}
}

// publicBaseURL is the public base URL of the gate: mcp.public_url, else
// the UI origin, else the request host.
func (s *Server) publicBaseURL(r *http.Request) string {
	c := s.cfg.Config
	if c.MCP.PublicURL != "" {
		return strings.TrimSuffix(c.MCP.PublicURL, "/")
	}
	if s.ui != nil {
		return s.ui.origin
	}
	scheme := "https"
	if r.TLS == nil && (strings.HasPrefix(r.Host, "127.0.0.1") || strings.HasPrefix(r.Host, "localhost")) {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// connectInfo describes how clients reach the gate (UI Connect page).
func (s *Server) connectInfo(r *http.Request) uiapi.Connect {
	c := s.cfg.Config
	base := s.publicBaseURL(r)
	out := uiapi.Connect{
		BaseURL:  base,
		MCP:      uiapi.ConnectMCP{Enabled: s.mcp != nil, URL: base + mcpPath, AllowWrites: s.mcp != nil && c.MCP.AllowWrites && s.cfg.Ops != nil},
		CLIScope: c.UI.CLIScope,
	}
	if s.claudeDesktopAvailable() {
		out.ClaudeDesktopExtensionURL = base + "/api/v1" + claudeDesktopExtensionPath
	}
	t := s.cfg.Authn.TokenIssuer()
	if t != nil && s.ui != nil {
		out.TokensURL = base + "/api/v1/tokens"
	}
	switch {
	case s.ui != nil && s.ui.saml != nil:
		out.Issuer = &uiapi.ConnectIssuer{Kind: "saml"}
		if t != nil {
			out.Issuer.URL, out.ClientID = t.URL(), RelayClientID
		}
	case s.ui != nil:
		out.ClientID = c.UI.ClientID
		out.Issuer = &uiapi.ConnectIssuer{URL: s.ui.issuer.Issuer, Kind: "oidc"}
		if tid, ok := config.EntraTenant(s.ui.issuer.Issuer); ok {
			out.Issuer.Kind, out.Issuer.TenantID = "entra", tid
		}
	}
	return out
}

// extensionLogin returns the issuer and client the Claude Desktop extension
// signs in with: the UI OIDC issuer and client, or the gate issuer when the
// UI login is SAML.
func (s *Server) extensionLogin() (issuer, clientID, scope string, ok bool) {
	if s.ui == nil {
		return "", "", "", false
	}
	if s.ui.saml != nil {
		if t := s.cfg.Authn.TokenIssuer(); t != nil {
			return t.URL(), RelayClientID, "", true
		}
		return "", "", "", false
	}
	c := s.cfg.Config.UI
	return s.ui.issuer.Issuer, c.ClientID, c.CLIScope, c.ClientID != ""
}

// claudeDesktopExtensionPath serves the Claude Desktop extension, under /api/v1.
const claudeDesktopExtensionPath = "/connect/claude-desktop.mcpb"

// claudeDesktopAvailable reports whether the Claude Desktop extension can be
// offered: it needs the MCP endpoint and the UI login (OIDC issuer and
// client id, or SAML with the gate issuer), which also signs the extension
// in.
func (s *Server) claudeDesktopAvailable() bool {
	_, _, _, ok := s.extensionLogin()
	return s.mcp != nil && ok
}

// serveClaudeDesktopExtension returns the Claude Desktop extension (MCP
// Bundle) of this gate, with its URLs, issuer, client id and scope baked in.
func (s *Server) serveClaudeDesktopExtension(w http.ResponseWriter, r *http.Request) {
	if !s.claudeDesktopAvailable() {
		writeError(w, http.StatusNotFound, "not_found", "the Claude Desktop extension needs mcp.enabled and the UI login")
		return
	}
	base := s.publicBaseURL(r)
	issuer, clientID, scope, _ := s.extensionLogin()
	bundle, err := mcpb.Build(mcpb.Params{
		GateURL:  base,
		MCPURL:   base + mcpPath,
		Issuer:   issuer,
		ClientID: clientID,
		Scope:    scope,
		Version:  version.Version,
	})
	if err != nil {
		s.log.Error("claude desktop extension", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "extension unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": mcpb.Filename(base)}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(bundle)))
	_, _ = w.Write(bundle)
}

// readableZones returns the zones the subject may see in the UI: managed
// zones and zones discovered in the account (unmanaged), with ui.read.
func (s *Server) readableZones(subj *identity.Subject) map[string]bool {
	out := map[string]bool{}
	for _, list := range [][]string{s.pol.ManagedZones(), s.pol.UnmanagedZones()} {
		for _, z := range list {
			if s.cfg.Authz.Allow(subj, policy.ActionUIRead, z) {
				out[z] = true
			}
		}
	}
	return out
}

// readsEveryManagedZone reports whether readable covers every managed zone
// (audit events without a zone are shown only then).
func (s *Server) readsEveryManagedZone(readable map[string]bool) bool {
	for _, z := range s.pol.ManagedZones() {
		if !readable[z] {
			return false
		}
	}
	return true
}

var auditParams = map[string]bool{
	"zone": true, "host": true, "type": true, "subject": true, "category": true,
	"decision": true, "since": true, "until": true, "limit": true, "cursor": true,
}

// handleAudit lists audit events. Events of zones the subject cannot read
// are filtered out; events without a zone (authentication failures) are
// only shown to subjects that can read every managed zone.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, subj *identity.Subject, readable map[string]bool) {
	if s.cfg.AuditReader == nil {
		writeError(w, http.StatusNotFound, "not_found", "audit storage not configured")
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		if !auditParams[k] || len(v) != 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "unknown or repeated query parameter "+k)
			return
		}
	}
	aq := store.AuditQuery{
		Zone:     strings.ToLower(q.Get("zone")),
		Host:     q.Get("host"),
		Type:     strings.ToUpper(q.Get("type")),
		Subject:  q.Get("subject"),
		Category: q.Get("category"),
		Decision: q.Get("decision"),
		Cursor:   q.Get("cursor"),
		Limit:    50,
	}
	if aq.Zone != "" && !readable[aq.Zone] {
		writeError(w, http.StatusForbidden, "forbidden", "ui.read not granted on "+aq.Zone)
		return
	}
	switch aq.Category {
	case "", identity.CategoryHuman, identity.CategoryPipeline, identity.CategoryKey:
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "category must be human, pipeline or key")
		return
	}
	switch aq.Decision {
	case "", "allow", "deny", "error":
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "decision must be allow, deny or error")
		return
	}
	var err error
	if v := q.Get("since"); v != "" {
		if aq.Since, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "since must be RFC 3339")
			return
		}
	}
	if v := q.Get("until"); v != "" {
		if aq.Until, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "until must be RFC 3339")
			return
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 500")
			return
		}
		aq.Limit = n
	}
	events, next, err := s.cfg.AuditReader.ListAudit(r.Context(), aq)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid audit query")
		return
	}
	all := s.readsEveryManagedZone(readable)
	page := uiapi.AuditPage{Entries: []uiapi.AuditEntry{}, NextCursor: next}
	for _, e := range events {
		if (e.Zone == "" && !all) || (e.Zone != "" && !readable[e.Zone]) || !s.auditVisible(subj, e) {
			continue
		}
		page.Entries = append(page.Entries, toAuditEntry(e))
	}
	writeJSON(w, http.StatusOK, page)
}

func toAuditEntry(e audit.Event) uiapi.AuditEntry {
	return uiapi.AuditEntry{
		Time:       e.Time,
		RequestID:  e.RequestID,
		Actor:      uiapi.Actor{Subject: e.Subject, Name: e.SubjectName, Category: e.SubjectCategory},
		Teams:      e.Teams,
		Action:     e.Action,
		Zone:       e.Zone,
		Decision:   e.Decision,
		Reason:     e.Reason,
		Changes:    e.Changes,
		Provider:   e.Provider,
		SnapshotID: e.SnapshotID,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// spaHandler serves the built UI under /ui/, falling back to index.html for
// client-side routes.
func spaHandler(files fs.FS) http.Handler {
	fileServer := http.StripPrefix("/ui/", http.FileServer(http.FS(files)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/ui")
		name = strings.TrimPrefix(name, "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(files, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		index, err := fs.ReadFile(files, "index.html")
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "UI not built")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
