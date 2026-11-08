package server

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/scope"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func delegatedEnv(t *testing.T, requireKnown bool) *env {
	return newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, AllowWrites: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.Roles["auditor"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{policy.ActionUIRead, policy.ActionDNSRead, "policy.read", policy.ActionAPIKeyManage}}}}
		c.Bindings = append(c.Bindings, config.Binding{Role: "auditor", Team: "web", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"writer"}}}}})
		c.Issuers[0].RequireKnownClient = requireKnown
		c.Issuers[0].DelegatedClients = []config.DelegatedClient{
			{ID: "copilot", Name: "Microsoft 365 Copilot", AZP: config.StringList{"copilot-app"}, Scopes: []string{scope.DNSRead}, Surfaces: []string{scope.SurfaceAPI, scope.SurfaceMCP}},
			{ID: "planner", Name: "Planner", AZP: config.StringList{"planner-app"}, Scopes: []string{scope.DNSRead, scope.DNSPlan}, Surfaces: []string{scope.SurfaceAPI}},
			{ID: "deployer", AppID: config.StringList{"deployer-app"}, Scopes: []string{scope.DNSRead, scope.DNSWrite}, Surfaces: []string{scope.SurfaceAPI, scope.SurfaceMCP}},
			{ID: "org-only", AZP: config.StringList{"org-app"}, Scopes: []string{scope.DNSRead, scope.PolicyRead}, Zones: []string{"example.org"}, Surfaces: []string{scope.SurfaceAPI}},
			{ID: "self", AZP: config.StringList{"gate-cli"}, Scopes: scope.All, Surfaces: []string{scope.SurfaceAPI, scope.SurfaceMCP}},
		}
	})
}

func (e *env) clientToken(sub, claim, client string) string {
	c := map[string]any{"sub": sub, "aud": "dns-gate", "email": sub + "@example.com"}
	if claim != "" {
		c[claim] = client
	}
	return e.idp.Sign(c)
}

func errBody(t *testing.T, r *http.Response) errorBody {
	t.Helper()
	var b errorBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDelegatedClientRoutes(t *testing.T) {
	e := delegatedEnv(t, false)
	copilot := e.clientToken("writer", "azp", "copilot-app")

	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets", copilot, "", nil); r.StatusCode != 200 {
		t.Fatalf("read: %d", r.StatusCode)
	}
	r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", copilot, `{"ttl":600,"values":["192.0.2.7"]}`, nil)
	if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "scope_insufficient" || b.RequiredScope != scope.DNSWrite {
		t.Fatalf("write with dns.read: %d %+v", r.StatusCode, b)
	}
	if len(e.ops.applied) != 0 {
		t.Fatal("a refused write reached the engine")
	}
	r = e.do(t, "POST", "/api/v1/zones/example.com/plan", copilot, `{"changes":[{"host":"app","type":"A","ttl":600,"values":["192.0.2.1"]}]}`, nil)
	if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "scope_insufficient" || b.RequiredScope != scope.DNSPlan {
		t.Fatalf("plan with dns.read: %d %+v", r.StatusCode, b)
	}

	self := e.clientToken("writer", "azp", "gate-cli")
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/v1/tokens", `{}`},
		{"GET", "/api/v1/policy", ""},
		{"POST", "/api/v1/policy/revisions", `{}`},
		{"GET", "/api/v1/api-keys", ""},
		{"POST", "/api/v1/api-keys", `{}`},
		{"GET", "/api/v1/connect", ""},
		{"POST", "/api/v1/teams/web/rename", `{}`},
		{"GET", "/api/v1/providers/eurodns/zone-profiles", ""},
		{"PUT", "/api/v1/policy/delegated/roles/x", `{}`},
	} {
		r := e.do(t, c.method, c.path, self, c.body, nil)
		if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "not_delegable" {
			t.Errorf("%s %s: %d %+v", c.method, c.path, r.StatusCode, b)
		}
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/dns-zones/example.com"},
		{"PUT", "/dns-zones/example.com"},
		{"POST", "/.well-known/dns-gate/zones/example.com/adopt"},
	} {
		r := e.do(t, c.method, c.path, self, `{}`, nil)
		if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "not_delegable" {
			t.Errorf("%s %s: %d %+v", c.method, c.path, r.StatusCode, b)
		}
	}

	for path := range map[string]bool{"/api/v1/zones/example.com/rrsets": true, "/api/v1/policy/who-can?zone=example.com": true} {
		if r := e.do(t, "GET", path, e.clientToken("writer", "azp", "unknown-app"), "", nil); r.StatusCode != 200 {
			t.Errorf("unknown client keeps the rights of the user on %s: %d", path, r.StatusCode)
		}
	}
	if r := e.do(t, "GET", "/api/v1/api-keys", e.token("writer"), "", nil); r.StatusCode == 403 {
		t.Fatalf("a token without client is not delegated: %d", r.StatusCode)
	}
}

func TestDelegatedRoutesDefaultDeny(t *testing.T) {
	for _, rt := range apiRoutes {
		if _, ok := delegableRoutes[rt.Method+" "+rt.Pattern]; ok {
			continue
		}
		if de := delegatedRoute(delegatedSubject(scope.All...), rt.Method, rt.Pattern); de == nil || de.reason != "not_delegable" {
			t.Errorf("%s %s: %+v", rt.Method, rt.Pattern, de)
		}
	}
	known := map[string]bool{}
	for _, rt := range apiRoutes {
		known[rt.Method+" "+rt.Pattern] = true
	}
	for k := range delegableRoutes {
		if !known[k] {
			t.Errorf("delegable route %s is not an API route", k)
		}
	}
	for _, never := range []string{"POST " + routeTokens, "GET " + routePolicy, "POST " + routeAPIKeys, "PUT " + routeProfile, "POST /api/v1/policy/revisions/{id}/activate", "POST " + routeTeamRename} {
		if _, ok := delegableRoutes[never]; ok {
			t.Errorf("%s must never be delegable", never)
		}
	}
	if de := delegatedRoute(delegatedSubject(), "GET", "/api/v1/me"); de != nil {
		t.Errorf("/me: %+v", de)
	}
}

func TestDelegatedClientMe(t *testing.T) {
	e := delegatedEnv(t, false)
	r := e.do(t, "GET", "/api/v1/me", e.clientToken("writer", "azp", "copilot-app"), "", nil)
	me := decode[uiapi.Me](t, r)
	if r.StatusCode != 200 || me.Client == nil || me.Client.ID != "copilot" || me.Client.Name != "Microsoft 365 Copilot" || !slices.Equal(me.Scopes, []string{scope.DNSRead}) || me.Subject != "idp:writer" {
		t.Fatalf("me: %d %+v", r.StatusCode, me)
	}
	for _, p := range me.Permissions {
		for _, a := range p.Actions {
			if a != policy.ActionUIRead && a != policy.ActionDNSRead {
				t.Fatalf("permission beyond the scopes: %+v", p)
			}
		}
	}
	r = e.do(t, "GET", "/api/v1/me", e.clientToken("writer", "azp", "org-app"), "", nil)
	me = decode[uiapi.Me](t, r)
	for _, p := range me.Permissions {
		if slices.Contains(p.Zones, "example.com") || len(p.Zones) == 0 {
			t.Fatalf("zones beyond the client zones: %+v", me.Permissions)
		}
	}
	r = e.do(t, "GET", "/api/v1/me", e.token("writer"), "", nil)
	me = decode[uiapi.Me](t, r)
	if me.Client != nil || me.Scopes != nil {
		t.Fatalf("direct caller: %+v", me)
	}
}

func TestDelegatedClientZones(t *testing.T) {
	e := delegatedEnv(t, false)
	org := e.clientToken("writer", "azp", "org-app")
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets", org, "", nil); r.StatusCode != 403 {
		t.Fatalf("zone outside the client zones: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/zones/example.org/rrsets", org, "", nil); r.StatusCode != 200 {
		t.Fatalf("zone of the client: %d", r.StatusCode)
	}
	for path, want := range map[string]int{
		"/api/v1/policy/who-can?zone=example.org":                 200,
		"/api/v1/policy/who-can?zone=example.com":                 403,
		"/api/v1/policy/who-can?zone=example.org&revision_id=r-1": 403,
	} {
		if r := e.do(t, "GET", path, org, "", nil); r.StatusCode != want {
			t.Errorf("%s: %d", path, r.StatusCode)
		}
	}
	r := e.do(t, "GET", "/api/v1/zones", org, "", nil)
	var zs []uiapi.ZoneSummary
	_ = json.NewDecoder(r.Body).Decode(&zs)
	for _, z := range zs {
		if z.Zone == "example.com" {
			t.Fatalf("zone list: %+v", zs)
		}
	}
}

func TestDelegatedClientPlanBinding(t *testing.T) {
	e := delegatedEnv(t, false)
	body := `{"changes":[{"host":"app","type":"A","ttl":600,"values":["192.0.2.1"]}]}`
	plan := func(tok string) string {
		t.Helper()
		r := e.do(t, "POST", "/api/v1/zones/example.com/plan", tok, body, nil)
		p := decode[uiapi.PlanResult](t, r)
		if r.StatusCode != 200 || p.PlanID == "" {
			t.Fatalf("plan: %d %+v", r.StatusCode, p)
		}
		return p.PlanID
	}
	apply := func(tok, id string) *http.Response {
		return e.do(t, "POST", "/api/v1/zones/example.com/apply", tok, `{"plan_id":"`+id+`"}`, nil)
	}
	planner := e.clientToken("writer", "azp", "planner-app")
	deployer := e.clientToken("writer", "appid", "deployer-app")
	direct := e.token("writer")

	id := plan(planner)
	r := apply(planner, id)
	if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "scope_insufficient" || b.RequiredScope != scope.DNSWrite {
		t.Fatalf("apply with dns.plan: %d %+v", r.StatusCode, b)
	}
	for _, tok := range []string{deployer, direct} {
		if r := apply(tok, id); r.StatusCode != 403 || reason(t, r) != "forbidden" {
			t.Fatalf("plan of the planner applied by another client: %d", r.StatusCode)
		}
	}
	id = plan(direct)
	if r := apply(deployer, id); r.StatusCode != 403 {
		t.Fatalf("plan without client applied by a client: %d", r.StatusCode)
	}
	if r := apply(direct, id); r.StatusCode != 200 {
		t.Fatalf("own plan: %d", r.StatusCode)
	}
	id = plan(deployer)
	if r := apply(direct, id); r.StatusCode != 403 {
		t.Fatalf("plan of a client applied without it: %d", r.StatusCode)
	}
	if r := apply(deployer, id); r.StatusCode != 200 {
		t.Fatalf("plan applied by its client: %d", r.StatusCode)
	}
}

func TestRequireKnownClient(t *testing.T) {
	e := delegatedEnv(t, true)
	for name, tok := range map[string]string{
		"unknown azp":   e.clientToken("writer", "azp", "other-app"),
		"unknown appid": e.clientToken("writer", "appid", "other-app"),
		"no client":     e.token("writer"),
	} {
		r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets", tok, "", nil)
		if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "unknown_client" {
			t.Errorf("%s: %d %+v", name, r.StatusCode, b)
		}
	}
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets", e.clientToken("writer", "azp", "copilot-app"), "", nil); r.StatusCode != 200 {
		t.Fatalf("known client: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets", e.clientToken("writer", "appid", "copilot-app"), "", nil); r.StatusCode != 200 {
		t.Fatalf("a v1 token (appid) of a declared client: %d", r.StatusCode)
	}
	denied := 0
	for _, ev := range e.audit.events {
		if ev.Reason == "unknown_client" && ev.Decision == "deny" {
			denied++
		}
	}
	if denied != 3 {
		t.Fatalf("refusals audited: %d", denied)
	}
}

func TestDelegatedClientAudit(t *testing.T) {
	e := delegatedEnv(t, false)
	out := &syncBuffer{}
	jl, err := audit.NewJSONWith(out, audit.Options{HashChain: true})
	if err != nil {
		t.Fatal(err)
	}
	e.server.cfg.Audit = &audit.Tee{Primary: jl, Store: appender{e.audit}}
	deployer := e.clientToken("writer", "appid", "deployer-app")
	r := e.do(t, "POST", "/api/v1/zones/example.com/plan", deployer, `{"changes":[{"host":"app","type":"A","ttl":600,"values":["192.0.2.1"]}]}`, nil)
	if r.StatusCode != 200 {
		t.Fatalf("plan: %d", r.StatusCode)
	}
	e.do(t, "GET", "/api/v1/tokens", deployer, "", nil)
	e.do(t, "POST", "/api/v1/tokens", deployer, `{}`, nil)
	e.do(t, "POST", "/api/v1/zones/example.com/plan", e.token("writer"), `{"changes":[{"host":"app","type":"A","ttl":600,"values":["192.0.2.1"]}]}`, nil)

	lines := out.lines(t)
	if len(lines) != 3 {
		t.Fatalf("lines: %v", lines)
	}
	rs := loadAuditSchema(t)
	for i, l := range lines {
		if err := rs.Validate(l); err != nil {
			t.Errorf("line %d: %v\n%v", i, err, l)
		}
	}
	for i, want := range []string{"api.plan", "api"} {
		l := lines[i]
		actor, _ := l["actor"].(map[string]any)
		if l["action"] != want || l["client_id"] != "deployer" || l["auth_method"] != audit.AuthOAuthDelegated || actor["type"] != "oauth_client" || actor["id"] != "deployer" || actor["name"] != "deployer" || l["subject"] != "idp:writer" {
			t.Errorf("line %d: %v", i, l)
		}
	}
	if lines[1]["reason"] != "not_delegable" {
		t.Errorf("refusal: %v", lines[1])
	}
	if lines[2]["client_id"] != nil || lines[2]["actor"] != nil || lines[2]["auth_method"] != audit.AuthOIDC {
		t.Errorf("direct caller: %v", lines[2])
	}
	var buf strings.Builder
	for _, l := range lines {
		b, _ := json.Marshal(l)
		buf.Write(append(b, '\n'))
	}
	if rep, err := audit.Verify(strings.NewReader(buf.String())); err != nil || !rep.OK() {
		t.Fatalf("chain: %+v %v", rep, err)
	}

	r = e.do(t, "GET", "/api/v1/audit?zone=example.com", e.token("writer"), "", nil)
	page := decode[uiapi.AuditPage](t, r)
	found := false
	for _, en := range page.Entries {
		if en.Action == "api.plan" && en.Client != nil && en.Client.ID == "deployer" {
			found = true
		}
	}
	if !found {
		t.Fatalf("journal: %+v", page.Entries)
	}
}

func TestDelegatedClientMCP(t *testing.T) {
	e := delegatedEnv(t, false)
	out := &syncBuffer{}
	e.server.cfg.Audit = &audit.Tee{Primary: audit.NewJSON(out), Store: appender{e.audit}}

	cs := connect(t, e, e.clientToken("writer", "azp", "copilot-app"))
	tools := toolNames(t, cs)
	for name := range tools {
		if want := mcpToolScopes[name]; want == nil || !slices.Contains(want, scope.DNSRead) {
			t.Errorf("tool %s listed for a dns.read client", name)
		}
	}
	for _, name := range []string{"list_zones", "list_rrsets", "get_rrset", "search_audit"} {
		if tools[name] == nil {
			t.Errorf("read tool %s missing", name)
		}
	}
	res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": "plan-x"}, nil)
	if !res.IsError || !strings.Contains(errText(res), "scope_insufficient") {
		t.Fatalf("hidden tool: %s", errText(res))
	}
	res = call(t, cs, "create_zone_profile", map[string]any{}, nil)
	if !res.IsError || !strings.Contains(errText(res), "not_delegable") {
		t.Fatalf("never delegable tool: %s", errText(res))
	}
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com"}, nil); res.IsError {
		t.Fatalf("read tool: %s", errText(res))
	}

	direct := toolNames(t, connect(t, e, e.token("writer")))
	if direct["apply_rrset_change"] == nil || direct["plan_rrset_change"] == nil {
		t.Fatal("a direct caller sees every tool")
	}

	dep := connect(t, e, e.clientToken("writer", "appid", "deployer-app"))
	var plan uiapi.PlanResult
	if res := call(t, dep, "plan_rrset_change", map[string]any{"zone": "example.com", "changes": []map[string]any{{"host": "app", "type": "A", "ttl": 600, "values": []string{"192.0.2.1"}}}}, &plan); res.IsError || plan.PlanID == "" {
		t.Fatalf("plan: %s", errText(res))
	}
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, nil); !res.IsError {
		t.Fatal("apply through a dns.read client")
	}
	directCS := connect(t, e, e.token("writer"))
	if res := call(t, directCS, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, nil); !res.IsError {
		t.Fatal("plan of a client applied without it")
	}
	if res := call(t, dep, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, nil); res.IsError {
		t.Fatalf("apply by the client of the plan: %s", errText(res))
	}

	r := e.do(t, "POST", "/mcp", e.clientToken("writer", "azp", "planner-app"), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, nil)
	if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "not_delegable" {
		t.Fatalf("surface not allowed: %d %+v", r.StatusCode, b)
	}

	found := false
	for _, l := range out.lines(t) {
		if l["action"] == "mcp.list_rrsets" {
			found = l["client_id"] == "copilot" && l["auth_method"] == audit.AuthOAuthDelegated
		}
	}
	if !found {
		raw, _ := io.ReadAll(strings.NewReader(out.buf.String()))
		t.Fatalf("mcp event without the client: %s", raw)
	}
}

func delegatedSubject(scopes ...string) *identity.Subject {
	return &identity.Subject{Kind: identity.KindOIDC, Issuer: "idp", ID: "writer", Client: &identity.Client{ID: "c"}, Scopes: scopes}
}

func TestDelegatedClientIDsIgnoreCaseAndClaim(t *testing.T) {
	e := newEnvWith(t, func(c *config.Config) {
		c.Issuers[0].DelegatedClients = []config.DelegatedClient{
			{ID: "copilot", ClientIDs: config.StringList{"AB3BE6B7-F5DF-413D-AC2D-ABF1E3FD9C0B"}, Scopes: []string{scope.DNSRead}, Surfaces: []string{scope.SurfaceAPI}},
			{ID: "legacy", AZP: config.StringList{"Legacy-App"}, Scopes: []string{scope.DNSRead}, Surfaces: []string{scope.SurfaceAPI}},
		}
	})
	body := `{"ttl":600,"values":["192.0.2.7"]}`
	for name, tok := range map[string]string{
		"lowercase azp of an uppercase client id": e.clientToken("writer", "azp", "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b"),
		"v1 appid of a client_ids entry":          e.clientToken("writer", "appid", "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b"),
		"v1 appid of an azp-only entry":           e.clientToken("writer", "appid", "legacy-app"),
	} {
		r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, body, nil)
		if b := errBody(t, r); r.StatusCode != 403 || b.Reason != "scope_insufficient" {
			t.Errorf("%s: %d %+v", name, r.StatusCode, b)
		}
	}
	if len(e.ops.applied) != 0 {
		t.Fatal("a delegated write reached the engine")
	}
}

func TestStepUpOfDelegatedSubject(t *testing.T) {
	e := delegatedEnv(t, false)
	human := &identity.Subject{Issuer: "idp", ID: "u", Category: identity.CategoryHuman, Claims: map[string]any{}}
	if pe := e.server.stepUp(human, nil); pe == nil || pe.reason != "reauth_required" {
		t.Fatalf("direct human without auth_time: %+v", pe)
	}
	d := *human
	d.Client, d.Scopes = &identity.Client{ID: "copilot"}, []string{scope.DNSAdopt}
	if pe := e.server.stepUp(&d, nil); pe == nil || pe.reason != "reauth_required" {
		t.Fatalf("a delegated subject never skips the step-up: %+v", pe)
	}
	d.Claims = map[string]any{"auth_time": float64(time.Now().Unix())}
	if pe := e.server.stepUp(&d, nil); pe != nil {
		t.Fatalf("delegated subject with a recent auth_time: %+v", pe)
	}
}
