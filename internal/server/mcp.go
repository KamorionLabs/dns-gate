package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/version"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

const (
	mcpPath          = "/mcp"
	resourceMetaPath = "/.well-known/oauth-protected-resource"
	// subjectRefHeader carries, inside the gate only, a reference to the
	// subject authenticated by the HTTP middleware; the MCP SDK hands the
	// request headers to tool handlers. Client values are always replaced.
	subjectRefHeader = "X-Gate-Internal-Subject-Ref"
)

const recordRules = "Hosts are relative to the zone, \"@\" is the apex. Targets of CNAME, MX, NS, SRV and PTR records must be fully qualified with a trailing dot (\"target.example.net.\"), otherwise EuroDNS appends the zone. TXT values are raw text, without surrounding quotes. Accepted TTLs depend on the provider of the zone (list_zones gives it): EuroDNS only accepts 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400, 172800, 432000, 604800. URL forwards (HTTP redirects, EuroDNS only) are the type URLFWD with a forward {type: 301, 302 or frame, url: absolute http(s) URL; title, keywords, description for frames} and no ttl nor values; they need dns.forward.write, and answer HTTPS only with an HTTPS redirect subscription on the domain (get_rrset gives its status; require_https=true refuses the change without one)."

type mcpServer struct {
	s       *Server
	handler http.Handler
	refs    sync.Map // ref -> *identity.Subject
	limiter *subjectLimiter
}

func (s *Server) newMCP() *mcpServer {
	m := &mcpServer{
		s:       s,
		limiter: newSubjectLimiter(s.cfg.Config.MCP.RequestsPerMinute, s.now),
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "dns-gate", Version: version.Version}, &mcp.ServerOptions{
		Instructions: "dns-gate manages DNS zones (EuroDNS, Route53) under RBAC and record ownership. Read tools are always available; changes are made with plan_rrset_change then apply_rrset_change, and only on RRsets owned by your team. " + recordRules,
	})
	m.addReadTools(srv)
	m.addTeamTools(srv)
	if s.cfg.EuroDNS != nil {
		m.addProfileReadTools(srv)
		if s.cfg.Config.MCP.AllowWrites {
			m.addProfileWriteTools(srv)
		}
	}
	if s.cfg.Propagation != nil {
		m.addPropagationTool(srv)
	}
	if s.cfg.Config.MCP.AllowWrites && s.cfg.Ops != nil {
		m.addWriteTools(srv)
	}
	if s.cfg.Config.MCP.AllowWrites && s.cfg.Transfers != nil {
		m.addTransferWriteTools(srv)
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	m.handler = h
	return m
}

// baseURL is the public base URL of the gate.
func (m *mcpServer) baseURL(r *http.Request) string { return m.s.publicBaseURL(r) }

// serveResourceMetadata serves the RFC 9728 protected resource metadata.
func (m *mcpServer) serveResourceMetadata(w http.ResponseWriter, r *http.Request) {
	base := m.baseURL(r)
	doc := map[string]any{
		"resource":                 base + mcpPath,
		"authorization_servers":    []string{},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{},
		"resource_name":            "dns-gate",
	}
	if issuer, _, _, ok := m.s.extensionLogin(); ok {
		doc["authorization_servers"] = []string{issuer}
	}
	writeJSON(w, http.StatusOK, doc)
}

func (m *mcpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del(subjectRefHeader)
	r.Header.Del("Cookie")
	subj, err := m.s.cfg.Authn.Authenticate(r)
	if err != nil {
		var ae *authn.Error
		if !errors.As(err, &ae) {
			ae = &authn.Error{Status: http.StatusUnauthorized, Reason: "unauthenticated", Message: "authentication failed"}
		}
		if ae.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s%s"`, m.baseURL(r), resourceMetaPath))
		}
		m.s.audit(r, nil, "mcp", "", "deny", ae.Reason)
		writeError(w, ae.Status, ae.Reason, ae.Message)
		return
	}
	if !m.limiter.allow(subj.String()) {
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many MCP requests")
		return
	}
	authn.StripCredentials(r.Header)
	ref := randomToken()
	m.refs.Store(ref, subj)
	defer m.refs.Delete(ref)
	r.Header.Set(subjectRefHeader, ref)
	m.handler.ServeHTTP(w, r.WithContext(identity.With(r.Context(), subj)))
}

// call resolves the subject of a tool call.
func (m *mcpServer) subject(ctx context.Context, req *mcp.CallToolRequest) (*identity.Subject, error) {
	if s := identity.From(ctx); s != nil {
		return s, nil
	}
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		if v, ok := m.refs.Load(req.Extra.Header.Get(subjectRefHeader)); ok {
			return v.(*identity.Subject), nil
		}
	}
	return nil, errors.New("unauthenticated")
}

func clientName(req *mcp.CallToolRequest) string {
	if req != nil && req.Session != nil {
		if p := req.Session.InitializeParams(); p != nil && p.ClientInfo != nil && p.ClientInfo.Name != "" {
			return p.ClientInfo.Name
		}
	}
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		return req.Extra.Header.Get("User-Agent")
	}
	return ""
}

func (m *mcpServer) audit(ctx context.Context, req *mcp.CallToolRequest, subj *identity.Subject, tool, zone, decision, reason string, extra map[string]any) {
	e := audit.Event{
		Time: m.s.now().UTC(), RequestID: requestid.From(ctx), Action: "mcp." + tool, Zone: zone,
		Decision: decision, Reason: reason, Extra: map[string]any{"via": "mcp", "mcp_client": clientName(req)},
	}
	if e.RequestID == "" {
		e.RequestID = requestid.New()
	}
	if subj != nil {
		e.Subject, e.SubjectName, e.SubjectCategory, e.Teams = subj.String(), subj.Name, subj.Category, subj.Teams
	}
	for k, v := range extra {
		e.Extra[k] = v
	}
	m.s.cfg.Audit.Log(ctx, e)
}

func ptr[T any](v T) *T { return &v }

func readOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)}
}

// canRead reports whether the subject may read a zone (ui.read or dns.read).
func (m *mcpServer) canRead(subj *identity.Subject, zone string) bool {
	return m.s.cfg.Authz.Allow(subj, policy.ActionUIRead, zone) || m.s.cfg.Authz.Allow(subj, policy.ActionDNSRead, zone)
}

// readable returns the managed and unmanaged (discovered) zones the subject
// may read.
func (m *mcpServer) readable(subj *identity.Subject) map[string]bool {
	out := map[string]bool{}
	for _, list := range [][]string{m.s.pol.ManagedZones(), m.s.pol.UnmanagedZones()} {
		for _, z := range list {
			if m.canRead(subj, z) {
				out[z] = true
			}
		}
	}
	return out
}

// inventoryError keeps refusals readable for the agent and hides upstream
// details.
func inventoryError(err error) error {
	if ze, ok := zonewrite.AsError(err); ok && (ze.Reason == zonewrite.ReasonForbidden || ze.Reason == zonewrite.ReasonNotFound) {
		return errors.New(ze.Message)
	}
	return errors.New("inventory unavailable")
}

func normZoneArg(z string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
}

// Tool inputs and outputs.

type zoneArg struct {
	Zone string `json:"zone" jsonschema:"managed zone name, e.g. example.com"`
}

type listZonesIn struct {
	Folder string `json:"folder,omitempty" jsonschema:"optional EuroDNS folder glob: /ES is the folder ES only, /ES/** every folder below it, / the zones in no folder"`
}

type listZonesOut struct {
	Zones []uiapi.ZoneSummary `json:"zones"`
}

type listRRsetsIn struct {
	Zone   string `json:"zone" jsonschema:"zone name (managed or unmanaged), e.g. example.com"`
	Status string `json:"status,omitempty" jsonschema:"filter: managed, tainted, pending, foreign or missing"`
	Host   string `json:"host,omitempty" jsonschema:"host glob relative to the zone, * matches any characters, @ is the apex"`
	Type   string `json:"type,omitempty" jsonschema:"record type, e.g. CNAME"`
	Owner  string `json:"owner,omitempty" jsonschema:"owner team"`
}

type listRRsetsOut struct {
	Zone         string        `json:"zone"`
	Unmanaged    bool          `json:"unmanaged,omitempty"`
	LastSyncedAt *time.Time    `json:"last_synced_at,omitempty"`
	RRsets       []uiapi.RRset `json:"rrsets"`
	// Tombstones are RRsets deleted recently, reserved for their team.
	Tombstones []uiapi.Tombstone `json:"tombstones,omitempty"`
}

type getRRsetIn struct {
	Zone string `json:"zone" jsonschema:"zone name (managed or unmanaged)"`
	Host string `json:"host" jsonschema:"host relative to the zone, @ for the apex"`
	Type string `json:"type" jsonschema:"record type"`
}

type getRRsetOut struct {
	RRset     *uiapi.RRset     `json:"rrset,omitempty"`
	Tombstone *uiapi.Tombstone `json:"tombstone,omitempty"`
	// HTTPS is, for a URL forward, whether the forwards of the zone answer
	// HTTPS requests.
	HTTPS     *provider.HTTPSRedirect `json:"https,omitempty"`
	Ownership string                  `json:"ownership,omitempty"`
	History   []uiapi.AuditEntry      `json:"history"`
}

type searchAuditIn struct {
	Zone     string `json:"zone,omitempty"`
	Host     string `json:"host,omitempty"`
	Type     string `json:"type,omitempty"`
	Subject  string `json:"subject,omitempty" jsonschema:"partial, case-insensitive match on the subject or its name"`
	Category string `json:"category,omitempty" jsonschema:"human, pipeline, key or system"`
	Decision string `json:"decision,omitempty" jsonschema:"allow, deny or error"`
	Since    string `json:"since,omitempty" jsonschema:"RFC 3339 time"`
	Until    string `json:"until,omitempty" jsonschema:"RFC 3339 time"`
	Limit    int    `json:"limit,omitempty" jsonschema:"1 to 200, default 50"`
	Cursor   string `json:"cursor,omitempty"`
}

type explainIn struct {
	Issuer string              `json:"issuer" jsonschema:"issuer name from the gate configuration"`
	Claims map[string][]string `json:"claims" jsonschema:"concrete claim values of the subject to simulate"`
	Action string              `json:"action" jsonschema:"e.g. dns.record.write"`
	Zone   string              `json:"zone"`
	Host   string              `json:"host,omitempty"`
	Type   string              `json:"type,omitempty"`
}

type whoCanIn struct {
	Zone   string `json:"zone"`
	Host   string `json:"host,omitempty"`
	Type   string `json:"type,omitempty"`
	Action string `json:"action,omitempty" jsonschema:"default dns.record.write"`
}

type planIn struct {
	Zone    string              `json:"zone" jsonschema:"managed zone name"`
	Changes []uiapi.RRsetChange `json:"changes" jsonschema:"desired state per RRset; delete=true removes it"`
	Team    string              `json:"team,omitempty" jsonschema:"one of your teams to act for (list_teams, or your default team when omitted): new RRsets go to it and only its RRsets may change"`
}

type applyIn struct {
	PlanID string `json:"plan_id" jsonschema:"plan_id returned by plan_rrset_change"`
	Team   string `json:"team,omitempty" jsonschema:"optional; must be the team of the plan when given"`
}

type adoptPreviewIn struct {
	Zone      string               `json:"zone"`
	Selection uiapi.AdoptSelection `json:"selection"`
	Team      string               `json:"team,omitempty" jsonschema:"one of your teams to act for (list_teams, or your default team when omitted): new RRsets go to it and only its RRsets may change"`
}

type adoptApplyIn struct {
	Zone         string           `json:"zone"`
	RRsets       []uiapi.RRsetRef `json:"rrsets"`
	Owner        string           `json:"owner,omitempty"`
	Comment      string           `json:"comment"`
	PreviewToken string           `json:"preview_token"`
	Team         string           `json:"team,omitempty" jsonschema:"one of your teams to act for (list_teams, or your default team when omitted): new RRsets go to it and only its RRsets may change"`
}

func (m *mcpServer) addReadTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_zones",
		Description: "List the DNS zones you can read, with their provider folder (EuroDNS folders, \"/\" for a zone in no folder) and counts of managed, foreign, tainted and pending RRsets. Zones flagged unmanaged exist in a provider account but are not managed by the gate: their RRsets are readable (list_rrsets, get_rrset) but cannot be changed or adopted until a policy administrator brings them under management. Optional filter on a folder glob.",
		Annotations: readOnly("List zones"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listZonesIn) (*mcp.CallToolResult, listZonesOut, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, listZonesOut{}, err
		}
		if in.Folder != "" {
			if err := glob.ValidFolderPattern(in.Folder); err != nil {
				return nil, listZonesOut{}, fmt.Errorf("folder: %w", err)
			}
		}
		zs, err := m.s.cfg.Engine.Zones(ctx, subj)
		if err != nil {
			return nil, listZonesOut{}, errors.New("inventory unavailable")
		}
		out := listZonesOut{Zones: readableZones(m.s.cfg.Policy.Current(), zs, m.readable(subj), in.Folder)}
		m.audit(ctx, req, subj, "list_zones", "", "allow", "", nil)
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_rrsets",
		Description: "List the RRsets of a zone, URL forwards included (type URLFWD), with their owner team and ownership status (managed: owned by a team through the gate; foreign: created outside the gate, read-only; tainted: changed outside the gate, writes blocked; pending; missing), and the tombstones: RRsets deleted recently, reserved for their team until they expire. Optional filters on status, host glob, type and owner team.",
		Annotations: readOnly("List RRsets"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listRRsetsIn) (*mcp.CallToolResult, listRRsetsOut, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, listRRsetsOut{}, err
		}
		zone := normZoneArg(in.Zone)
		if !m.canRead(subj, zone) {
			return nil, listRRsetsOut{}, fmt.Errorf("read access to %q not granted", zone)
		}
		inv, err := m.s.cfg.Engine.Inventory(ctx, subj, zone)
		if err != nil {
			return nil, listRRsetsOut{}, inventoryError(err)
		}
		out := listRRsetsOut{Zone: inv.Zone, Unmanaged: inv.Unmanaged, LastSyncedAt: inv.LastSyncedAt, RRsets: []uiapi.RRset{}}
		match := func(host, typ, owner string) bool {
			return (in.Host == "" || glob.Match(strings.ToLower(in.Host), host)) && (in.Type == "" || strings.EqualFold(in.Type, typ)) &&
				(in.Owner == "" || owner == in.Owner)
		}
		for _, rs := range inv.RRsets {
			if (in.Status == "" || rs.Status == in.Status) && match(rs.Host, rs.Type, rs.Owner) {
				out.RRsets = append(out.RRsets, rs)
			}
		}
		if in.Status == "" {
			for _, tb := range inv.Tombstones {
				if match(tb.Host, tb.Type, tb.Team) {
					out.Tombstones = append(out.Tombstones, tb)
				}
			}
		}
		m.audit(ctx, req, subj, "list_rrsets", zone, "allow", "", nil)
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_rrset",
		Description: "Get one RRset (values, TTL, owner team, status; for type URLFWD the URL forward of the host and whether forwards answer HTTPS), its tombstone when it was deleted recently, whether and why you may change it (ownership), and its recent audit history.",
		Annotations: readOnly("Get RRset"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getRRsetIn) (*mcp.CallToolResult, getRRsetOut, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, getRRsetOut{}, err
		}
		zone := normZoneArg(in.Zone)
		if !m.canRead(subj, zone) {
			return nil, getRRsetOut{}, fmt.Errorf("read access to %q not granted", zone)
		}
		inv, err := m.s.cfg.Engine.Inventory(ctx, subj, zone)
		if err != nil {
			return nil, getRRsetOut{}, inventoryError(err)
		}
		out := getRRsetOut{History: []uiapi.AuditEntry{}}
		host := strings.ToLower(in.Host)
		if host == "" {
			host = "@"
		}
		for i := range inv.RRsets {
			if inv.RRsets[i].Host == host && strings.EqualFold(inv.RRsets[i].Type, in.Type) {
				out.RRset = &inv.RRsets[i]
			}
		}
		for i := range inv.Tombstones {
			if inv.Tombstones[i].Host == host && strings.EqualFold(inv.Tombstones[i].Type, in.Type) {
				out.Tombstone = &inv.Tombstones[i]
			}
		}
		out.Ownership = m.ownershipNote(subj, zone, inv.Unmanaged, out.RRset, out.Tombstone)
		if strings.EqualFold(in.Type, dns.TypeURLForward) && !inv.Unmanaged {
			if st, err := m.s.cfg.Engine.HTTPSRedirect(ctx, subj, zone); err == nil {
				out.HTTPS = &st
			}
		}
		if m.s.cfg.AuditReader != nil {
			events, _, err := m.s.cfg.AuditReader.ListAudit(ctx, store.AuditQuery{Zone: zone, Host: host, Type: strings.ToUpper(in.Type), Limit: 20})
			if err == nil {
				for _, e := range events {
					out.History = append(out.History, toAuditEntry(e))
				}
			}
		}
		m.audit(ctx, req, subj, "get_rrset", zone, "allow", "", nil)
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search_audit",
		Description: "Search the gate audit log, newest first. Only events of zones you can read are returned. Use next_cursor to page.",
		Annotations: readOnly("Search audit log"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in searchAuditIn) (*mcp.CallToolResult, uiapi.AuditPage, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.AuditPage{}, err
		}
		if m.s.cfg.AuditReader == nil {
			return nil, uiapi.AuditPage{}, errors.New("audit storage not configured")
		}
		readable := m.readable(subj)
		q := store.AuditQuery{Zone: normZoneArg(in.Zone), Host: in.Host, Type: strings.ToUpper(in.Type), Subject: in.Subject,
			Category: in.Category, Decision: in.Decision, Cursor: in.Cursor, Limit: 50}
		if q.Zone != "" && !readable[q.Zone] {
			return nil, uiapi.AuditPage{}, fmt.Errorf("read access to %q not granted", q.Zone)
		}
		if in.Limit > 0 {
			q.Limit = min(in.Limit, 200)
		}
		for _, t := range []struct {
			v   string
			dst *time.Time
		}{{in.Since, &q.Since}, {in.Until, &q.Until}} {
			if t.v != "" {
				ts, err := time.Parse(time.RFC3339, t.v)
				if err != nil {
					return nil, uiapi.AuditPage{}, errors.New("since and until must be RFC 3339 times")
				}
				*t.dst = ts
			}
		}
		events, next, err := m.s.cfg.AuditReader.ListAudit(ctx, q)
		if err != nil {
			return nil, uiapi.AuditPage{}, errors.New("invalid audit query")
		}
		all := m.s.readsEveryManagedZone(readable)
		page := uiapi.AuditPage{Entries: []uiapi.AuditEntry{}, NextCursor: next}
		for _, e := range events {
			if ((e.Zone == "" && all) || readable[e.Zone]) && m.s.auditVisible(subj, e) {
				page.Entries = append(page.Entries, toAuditEntry(e))
			}
		}
		return nil, page, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "explain",
		Description: "Simulate an authorization decision of the active policy for a subject with given claims: groups, bindings, teams and default team, the rule that grants or the reason of the denial and, for an RRset of a managed zone, its owner team (or the team a tombstone reserves it for) and whether the subject's teams may change it. Requires policy.read.",
		Annotations: readOnly("Explain a decision"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in explainIn) (*mcp.CallToolResult, explainOut, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, explainOut{}, err
		}
		if !m.s.pol.AllowMeta(subj, uiapi.ActionPolicyRead) {
			return nil, explainOut{}, errors.New("policy.read not granted")
		}
		claims := map[string]any{}
		for k, v := range in.Claims {
			if len(v) == 1 {
				claims[k] = v[0]
			} else {
				arr := make([]any, len(v))
				for i, x := range v {
					arr[i] = x
				}
				claims[k] = arr
			}
		}
		return nil, m.explainOwnership(ctx, in, claims), nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "who_can",
		Description: "List the bindings and virtual keys allowed to perform an action (default dns.record.write) on an RRset of a zone. Requires policy.read.",
		Annotations: readOnly("Who can"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in whoCanIn) (*mcp.CallToolResult, uiapi.WhoCanResponse, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.WhoCanResponse{}, err
		}
		if !m.s.pol.AllowMeta(subj, uiapi.ActionPolicyRead) {
			return nil, uiapi.WhoCanResponse{}, errors.New("policy.read not granted")
		}
		action := in.Action
		if action == "" {
			action = policy.ActionRecordWrite
		}
		return nil, m.s.cfg.Policy.Current().WhoCan(action, normZoneArg(in.Zone), in.Host, in.Type), nil
	})
}

func (m *mcpServer) addWriteTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "plan_rrset_change",
		Description: "Dry run of RRset changes in a zone: checks RBAC, ownership and the provider validation without writing, and returns the changes and a plan_id valid for a few minutes. Each change is the full desired state of one RRset (host, type, ttl, values) or delete=true. " +
			recordRules + " Only RRsets owned by your teams, or new ones in your scope, can change; new RRsets go to your default team, or to team when given (one of your teams, list_teams). A recently deleted RRset is reserved for its previous team (tombstone). Show the plan to the user before applying it.",
		Annotations: readOnly("Plan RRset changes"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in planIn) (*mcp.CallToolResult, uiapi.PlanResult, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.PlanResult{}, err
		}
		zone := normZoneArg(in.Zone)
		if len(in.Changes) == 0 || len(in.Changes) > 100 {
			return nil, uiapi.PlanResult{}, errors.New("between 1 and 100 changes are required")
		}
		if subj, err = m.forTeam(ctx, req, subj, "plan_rrset_change", zone, in.Team); err != nil {
			return nil, uiapi.PlanResult{}, err
		}
		if !m.s.cfg.Authz.Allow(subj, policy.ActionRecordWrite, zone) && !m.s.cfg.Authz.Allow(subj, policy.ActionForwardWrite, zone) {
			m.audit(ctx, req, subj, "plan_rrset_change", zone, "deny", "forbidden", nil)
			return nil, uiapi.PlanResult{}, fmt.Errorf("dns.record.write or dns.forward.write not granted on %q", zone)
		}
		plan, err := m.s.cfg.Ops.PlanRRsets(ctx, subj, zone, in.Changes)
		if err != nil {
			return nil, uiapi.PlanResult{}, toolError(err)
		}
		plan.Team = in.Team
		if plan.Allowed {
			if plan.PlanID, err = m.s.savePlan(ctx, subj, zone, in.Team, in.Changes, plan.ZoneVersion); err != nil {
				m.s.log.Error("save plan", "zone", zone, "err", err)
				return nil, uiapi.PlanResult{}, errors.New("plan storage unavailable")
			}
		}
		m.audit(ctx, req, subj, "plan_rrset_change", zone, "allow", plan.Reason, withTeam(map[string]any{"plan_id": plan.PlanID, "allowed": plan.Allowed}, in.Team))
		return nil, *plan, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "apply_rrset_change",
		Description: "Apply a plan returned by plan_rrset_change, exactly as planned and for the team it was planned for. Fails if the plan expired, belongs to another caller, or if the zone changed since the plan (plan again). Only apply after the user confirmed the plan.",
		Annotations: &mcp.ToolAnnotations{Title: "Apply RRset plan", DestructiveHint: ptr(true), IdempotentHint: false, OpenWorldHint: ptr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in applyIn) (*mcp.CallToolResult, uiapi.PlanResult, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.PlanResult{}, err
		}
		p, err := m.s.takePlan(ctx, in.PlanID, subj)
		if err != nil {
			_, reason := planErrorStatus(err)
			m.audit(ctx, req, subj, "apply_rrset_change", "", "deny", reason, map[string]any{"plan_id": in.PlanID})
			return nil, uiapi.PlanResult{}, fmt.Errorf("%s: %w", reason, err)
		}
		team := p.Team
		if in.Team != "" && team != "" && in.Team != team {
			m.audit(ctx, req, subj, "apply_rrset_change", p.Zone, "deny", "team_mismatch", map[string]any{"plan_id": in.PlanID})
			return nil, uiapi.PlanResult{}, fmt.Errorf("team_mismatch: the plan was made for team %s, not %s", team, in.Team)
		} else if team == "" {
			team = in.Team
		}
		if team != "" {
			if !slices.Contains(subj.Teams, team) {
				m.audit(ctx, req, subj, "apply_rrset_change", p.Zone, "deny", "not_team_member", map[string]any{"plan_id": in.PlanID})
				return nil, uiapi.PlanResult{}, fmt.Errorf("not_team_member: team %s is not one of your teams", team)
			}
			subj = subj.ForTeam(team)
		}
		res, err := m.s.cfg.Ops.ApplyRRsets(ctx, subj, p.Zone, p.Changes, p.ZoneVersion)
		if err != nil {
			m.audit(ctx, req, subj, "apply_rrset_change", p.Zone, "error", reasonOf(err), map[string]any{"plan_id": in.PlanID})
			return nil, uiapi.PlanResult{}, toolError(err)
		}
		m.audit(ctx, req, subj, "apply_rrset_change", p.Zone, "allow", "", withTeam(map[string]any{"plan_id": in.PlanID}, team))
		res.PlanID, res.Team = in.PlanID, team
		return nil, *res, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "adopt_preview",
		Description: "Preview the adoption of foreign RRsets (created outside the gate) by a team: which ones are adoptable and why not (protected, server-managed, owned by another team, reserved for another team by a tombstone, relative target). The owner of the selection must be one of your teams unless you hold dns.ownership.approve; team acts for one of your teams only. Returns a preview_token for adopt_apply. Requires dns.record.adopt.",
		Annotations: readOnly("Preview adoption"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in adoptPreviewIn) (*mcp.CallToolResult, uiapi.AdoptPreview, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.AdoptPreview{}, err
		}
		zone := normZoneArg(in.Zone)
		if subj, err = m.forTeam(ctx, req, subj, "adopt_preview", zone, in.Team); err != nil {
			return nil, uiapi.AdoptPreview{}, err
		}
		if !m.s.cfg.Authz.Allow(subj, policy.ActionRecordAdopt, zone) {
			return nil, uiapi.AdoptPreview{}, fmt.Errorf("dns.record.adopt not granted on %q", zone)
		}
		p, err := m.s.cfg.Ops.PreviewAdopt(ctx, subj, zone, in.Selection)
		if err != nil {
			return nil, uiapi.AdoptPreview{}, toolError(err)
		}
		return nil, *p, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "adopt_apply",
		Description: "Adopt RRsets listed by adopt_preview, all or nothing, with the preview_token (and the same owner and team as the preview). A comment explaining why is required. Fails if any RRset changed since the preview.",
		Annotations: &mcp.ToolAnnotations{Title: "Adopt RRsets", DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in adoptApplyIn) (*mcp.CallToolResult, uiapi.AdoptResult, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.AdoptResult{}, err
		}
		zone := normZoneArg(in.Zone)
		if subj, err = m.forTeam(ctx, req, subj, "adopt_apply", zone, in.Team); err != nil {
			return nil, uiapi.AdoptResult{}, err
		}
		if !m.s.cfg.Authz.Allow(subj, policy.ActionRecordAdopt, zone) {
			return nil, uiapi.AdoptResult{}, fmt.Errorf("dns.record.adopt not granted on %q", zone)
		}
		if e := m.s.stepUp(subj, nil); e != nil {
			return nil, uiapi.AdoptResult{}, errors.New(e.msg)
		}
		if strings.TrimSpace(in.Comment) == "" || len(in.RRsets) == 0 || in.PreviewToken == "" {
			return nil, uiapi.AdoptResult{}, errors.New("rrsets, comment and preview_token are required")
		}
		res, err := m.s.cfg.Ops.AdoptMany(ctx, subj, zone, uiapi.AdoptApply{RRsets: in.RRsets, Owner: in.Owner, Comment: in.Comment, PreviewToken: in.PreviewToken})
		if err != nil {
			m.audit(ctx, req, subj, "adopt_apply", zone, "error", reasonOf(err), nil)
			return nil, uiapi.AdoptResult{}, toolError(err)
		}
		m.audit(ctx, req, subj, "adopt_apply", zone, "allow", "", map[string]any{"adopted": len(res.Adopted)})
		return nil, *res, nil
	})
}

func reasonOf(err error) string {
	if ze, ok := zonewrite.AsError(err); ok {
		return string(ze.Reason)
	}
	return "error"
}

// toolError turns engine errors into messages useful to the model,
// without upstream details.
func toolError(err error) error {
	if ze, ok := zonewrite.AsError(err); ok {
		return fmt.Errorf("%s: %s", ze.Reason, ze.Message)
	}
	return errors.New("internal error")
}

// subjectLimiter is a token bucket per subject.
type subjectLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newSubjectLimiter(perMinute int, now func() time.Time) *subjectLimiter {
	burst := float64(perMinute) / 4
	if burst < 5 {
		burst = 5
	}
	return &subjectLimiter{rate: float64(perMinute) / 60, burst: burst, now: now, buckets: map[string]*bucket{}}
}

func (l *subjectLimiter) allow(subject string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[subject]
	if b == nil {
		if len(l.buckets) > 10000 {
			l.gc(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[subject] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *subjectLimiter) gc(now time.Time) {
	keys := make([]string, 0, len(l.buckets))
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		delete(l.buckets, k)
	}
}
