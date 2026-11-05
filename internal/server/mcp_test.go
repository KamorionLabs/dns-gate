package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

type fakeOps struct {
	mu       sync.Mutex
	version  int64
	applied  [][]uiapi.RRsetChange
	adopted  []uiapi.AdoptApply
	conflict bool
	// applyErrs are returned by the next ApplyRRsets calls, in order;
	// bumpOnErr moves the zone version along, as a concurrent writer would.
	applyErrs []error
	bumpOnErr bool
	calls     []int64
}

func (f *fakeOps) ZoneVersion(ctx context.Context, zone string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.version, nil
}

func (f *fakeOps) PreviewAdopt(ctx context.Context, s *identity.Subject, zone string, sel uiapi.AdoptSelection) (*uiapi.AdoptPreview, error) {
	return &uiapi.AdoptPreview{Zone: zone, Owner: "ops", PreviewToken: "tok-1", Candidates: []uiapi.AdoptCandidate{
		{Host: "www", Type: "A", TTL: 600, Values: []string{"192.0.2.1"}, Status: uiapi.StatusForeign, Adoptable: true},
		{Host: "@", Type: "NS", Status: uiapi.StatusForeign, Reason: "protected"},
	}}, nil
}

func (f *fakeOps) AdoptMany(ctx context.Context, s *identity.Subject, zone string, req uiapi.AdoptApply) (*uiapi.AdoptResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conflict || req.PreviewToken != "tok-1" {
		return nil, &zonewrite.Error{Reason: "adopt_conflict", Message: "www A changed since the preview"}
	}
	f.adopted = append(f.adopted, req)
	return &uiapi.AdoptResult{Zone: zone, Owner: "ops", Adopted: req.RRsets}, nil
}

func (f *fakeOps) PlanRRsets(ctx context.Context, s *identity.Subject, zone string, changes []uiapi.RRsetChange) (*uiapi.PlanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &uiapi.PlanResult{Zone: zone, Allowed: true, ZoneVersion: f.version, Changes: []uiapi.Change{{Op: "create", Host: changes[0].Host, Type: changes[0].Type, NewValues: changes[0].Values}}}, nil
}

func (f *fakeOps) ApplyRRsets(ctx context.Context, s *identity.Subject, zone string, changes []uiapi.RRsetChange, v int64) (*uiapi.PlanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, v)
	if len(f.applyErrs) > 0 {
		err := f.applyErrs[0]
		f.applyErrs = f.applyErrs[1:]
		if err != nil {
			if f.bumpOnErr {
				f.version++
			}
			return nil, err
		}
	}
	if v != f.version {
		return nil, &zonewrite.Error{Reason: zonewrite.ReasonPrecondition, Message: "zone changed since the plan"}
	}
	f.version++
	f.applied = append(f.applied, changes)
	return &uiapi.PlanResult{Zone: zone, Allowed: true, ZoneVersion: f.version}, nil
}

func (f *fakeOps) terraform(ctx context.Context, s *identity.Subject, zone string, flt TerraformFilter) (string, error) {
	var refs []string
	for _, r := range flt.RRsets {
		refs = append(refs, r.Host+"/"+r.Type)
	}
	return "# zone " + zone + " team=" + flt.Team + " hosts=" + strings.Join(flt.Hosts, ",") + " types=" + strings.Join(flt.Types, ",") + " rrsets=" + strings.Join(refs, ",") + "\n", nil
}

func mcpEnv(t *testing.T, writes bool) *env {
	return newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, AllowWrites: writes, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.Roles["adopter"] = config.Role{Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{policy.ActionRecordAdopt, policy.ActionUIRead}}}}
		c.Bindings = append(c.Bindings, config.Binding{Role: "adopter", Team: "ops", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"adopter", "human-adopter"}}}}})
		c.Issuers[0].CategoryClaim = "kind"
		c.Issuers[0].CategoryMap = map[string]string{"user": "human"}
	})
}

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, e *env, tok string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: e.srv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok}}, MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.Tool {
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		out[tl.Name] = tl
	}
	return out
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if out != nil && res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, out)
	}
	return res
}

func errText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestMCPUnauthenticated(t *testing.T) {
	e := mcpEnv(t, false)
	r := e.do(t, "POST", "/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, nil)
	if r.StatusCode != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), `resource_metadata="`+e.srv.URL+`/.well-known/oauth-protected-resource"`) {
		t.Fatalf("401: %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
	r = e.do(t, "GET", "/.well-known/oauth-protected-resource", "", "", nil)
	var meta map[string]any
	_ = json.NewDecoder(r.Body).Decode(&meta)
	as, _ := meta["authorization_servers"].([]any)
	if meta["resource"] != e.srv.URL+"/mcp" || len(as) != 1 || as[0] != e.idp.URL {
		t.Fatalf("metadata: %v", meta)
	}
}

func TestMCPReadOnly(t *testing.T) {
	e := mcpEnv(t, false)
	cs := connect(t, e, e.token("writer"))
	tools := toolNames(t, cs)
	for _, n := range []string{"list_zones", "list_rrsets", "get_rrset", "search_audit", "explain", "who_can"} {
		if tools[n] == nil || !tools[n].Annotations.ReadOnlyHint {
			t.Errorf("read tool %s missing or not read-only", n)
		}
	}
	if tools["plan_rrset_change"] != nil || tools["apply_rrset_change"] != nil {
		t.Fatal("write tools exposed without allow_writes")
	}
	var zs listZonesOut
	if res := call(t, cs, "list_zones", map[string]any{}, &zs); res.IsError || len(zs.Zones) != 1 || zs.Zones[0].Zone != "example.com" {
		t.Fatalf("list_zones: %v %+v", errText(res), zs)
	}
	var rs listRRsetsOut
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "status": "managed"}, &rs); res.IsError || len(rs.RRsets) != 1 {
		t.Fatalf("list_rrsets: %s %+v", errText(res), rs)
	}
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.org"}, nil); !res.IsError {
		t.Fatal("unreadable zone listed")
	}
	if res := call(t, cs, "who_can", map[string]any{"zone": "example.com"}, nil); !res.IsError {
		t.Fatal("who_can without policy.read")
	}
	found := false
	for _, ev := range e.audit.events {
		if ev.Action == "mcp.list_zones" && ev.Extra["via"] == "mcp" && ev.Extra["mcp_client"] != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("MCP call not audited with via=mcp and the client name")
	}
}

func TestMCPPlanApply(t *testing.T) {
	e := mcpEnv(t, true)
	cs := connect(t, e, e.token("writer"))
	tools := toolNames(t, cs)
	if a := tools["apply_rrset_change"].Annotations; a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Fatalf("apply annotations: %+v", a)
	}
	if !strings.Contains(tools["plan_rrset_change"].Description, "trailing dot") {
		t.Fatal("plan description must document FQDN targets")
	}
	changes := map[string]any{"zone": "example.com", "changes": []map[string]any{{"host": "app", "type": "CNAME", "ttl": 600, "values": []string{"target.example.net."}}}}
	var plan uiapi.PlanResult
	if res := call(t, cs, "plan_rrset_change", changes, &plan); res.IsError || plan.PlanID == "" {
		t.Fatalf("plan: %s %+v", errText(res), plan)
	}

	// Another subject cannot apply the plan.
	other := connect(t, e, e.token("adopter"))
	if res := call(t, other, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, nil); !res.IsError || !strings.Contains(errText(res), "another caller") {
		t.Fatalf("foreign apply: %s", errText(res))
	}
	var applied uiapi.PlanResult
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, &applied); res.IsError || len(e.ops.applied) != 1 {
		t.Fatalf("apply: %s", errText(res))
	}
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, nil); !res.IsError {
		t.Fatal("plan reused")
	}

	// Zone moved since the plan.
	call(t, cs, "plan_rrset_change", changes, &plan)
	e.ops.mu.Lock()
	e.ops.version += 5
	e.ops.mu.Unlock()
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, nil); !res.IsError || !strings.Contains(errText(res), "precondition") {
		t.Fatalf("stale plan: %s", errText(res))
	}

	// Expired plan.
	call(t, cs, "plan_rrset_change", changes, &plan)
	e.offset = 11 * time.Minute
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, nil); !res.IsError || !strings.Contains(errText(res), "expired") {
		t.Fatalf("expired plan: %s", errText(res))
	}
	e.offset = 0

	// A reader cannot plan.
	reader := connect(t, e, e.token("adopter"))
	if res := call(t, reader, "plan_rrset_change", changes, nil); !res.IsError {
		t.Fatal("plan without dns.record.write")
	}
}

func TestMCPRateLimit(t *testing.T) {
	e := newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 1}
	})
	tok := e.token("writer")
	codes := map[int]int{}
	for i := 0; i < 8; i++ {
		r := e.do(t, "POST", "/mcp", tok, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, map[string]string{"Accept": "application/json, text/event-stream"})
		_, _ = io.Copy(io.Discard, r.Body)
		codes[r.StatusCode]++
	}
	if codes[429] == 0 {
		t.Fatalf("no rate limiting: %v", codes)
	}
}

func TestAdoptEndpoints(t *testing.T) {
	e := mcpEnv(t, false)
	tok := e.token("adopter")
	r := e.do(t, "POST", "/api/v1/zones/example.com/adopt/preview", tok, `{"hosts":["*"]}`, nil)
	var p uiapi.AdoptPreview
	_ = json.NewDecoder(r.Body).Decode(&p)
	if r.StatusCode != 200 || p.PreviewToken != "tok-1" || len(p.Candidates) != 2 {
		t.Fatalf("preview: %d %+v", r.StatusCode, p)
	}
	body := `{"rrsets":[{"host":"www","type":"A"}],"comment":"take over","preview_token":"tok-1"}`
	if r = e.do(t, "POST", "/api/v1/zones/example.com/adopt", tok, body, nil); r.StatusCode != 200 || len(e.ops.adopted) != 1 {
		t.Fatalf("adopt: %d", r.StatusCode)
	}
	e.ops.conflict = true
	if r = e.do(t, "POST", "/api/v1/zones/example.com/adopt", tok, body, nil); r.StatusCode != 409 || reason(t, r) != "adopt_conflict" || len(e.ops.adopted) != 1 {
		t.Fatalf("conflict: %d", r.StatusCode)
	}
	if r = e.do(t, "POST", "/api/v1/zones/example.com/adopt", tok, `{"rrsets":[{"host":"www","type":"A"}],"preview_token":"tok-1"}`, nil); r.StatusCode != 400 {
		t.Fatalf("missing comment: %d", r.StatusCode)
	}
	if r = e.do(t, "POST", "/api/v1/zones/example.com/adopt/preview", e.token("writer"), `{}`, nil); r.StatusCode != 403 {
		t.Fatalf("preview without adopt: %d", r.StatusCode)
	}
	// Humans need a recent authentication to adopt.
	old := e.idp.Sign(map[string]any{"sub": "human-adopter", "aud": "dns-gate", "kind": "user", "auth_time": time.Now().Add(-time.Hour).Unix()})
	e.ops.conflict = false
	if r = e.do(t, "POST", "/api/v1/zones/example.com/adopt", old, body, nil); r.StatusCode != 403 || reason(t, r) != "reauth_required" {
		t.Fatalf("step-up: %d", r.StatusCode)
	}

	r = e.do(t, "GET", "/api/v1/zones/example.com/terraform?team=ops&types=cname", tok, "", nil)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") || !strings.Contains(string(b), "team=ops hosts= types=CNAME") ||
		!strings.Contains(r.Header.Get("Content-Disposition"), "example_com.tf") {
		t.Fatalf("terraform: %d %s", r.StatusCode, b)
	}
	r = e.do(t, "GET", "/api/v1/zones/example.com/terraform?hosts=www,api&hosts=mail&types=a,cname&types=mx&rrsets=www/a,@/MX&rrsets=api/CNAME", tok, "", nil)
	b, _ = io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(b), "hosts=www,api,mail types=A,CNAME,MX rrsets=www/A,@/MX,api/CNAME") {
		t.Fatalf("terraform lists: %d %s", r.StatusCode, b)
	}
	if r = e.do(t, "GET", "/api/v1/zones/example.com/terraform?rrsets=www", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("bad rrsets: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/api/v1/zones/example.com/terraform?team=a&team=b", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("repeated team: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/api/v1/zones/example.org/terraform", tok, "", nil); r.StatusCode != 403 {
		t.Fatalf("terraform of unreadable zone: %d", r.StatusCode)
	}
}

func TestAdoptCSRF(t *testing.T) {
	e := mcpEnv(t, false)
	e.idp.LoginClaims = map[string]any{"sub": "human-adopter", "kind": "user", "auth_time": time.Now().Unix()}
	jar, _ := cookiejarNew()
	client := &http.Client{Jar: jar}
	resp, err := client.Get(e.srv.URL + "/auth/login")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v %v", err, resp)
	}
	resp.Body.Close()
	body := `{"rrsets":[{"host":"www","type":"A"}],"comment":"x","preview_token":"tok-1"}`
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/zones/example.com/adopt", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", e.srv.URL)
	resp, _ = client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 || len(e.ops.adopted) != 0 {
		t.Fatalf("adopt without CSRF token: %d", resp.StatusCode)
	}
}
func cookiejarNew() (*cookiejar.Jar, error) { return cookiejar.New(nil) }

func TestInventoryTerraform(t *testing.T) {
	render := InventoryTerraform(&fakeEngine{})
	out, err := render(context.Background(), &identity.Subject{}, "example.com", TerraformFilter{Team: "web", Types: []string{"A"}})
	if err != nil || !strings.Contains(out, "eurodns_record_set") || !strings.Contains(out, "192.0.2.1") && !strings.Contains(out, `"www"`) {
		t.Fatalf("render: %v\n%s", err, out)
	}
	out, _ = render(context.Background(), &identity.Subject{}, "example.com", TerraformFilter{RRsets: []uiapi.RRsetRef{{Host: "WWW", Type: "a"}}, Types: []string{"MX"}})
	if !strings.Contains(out, "eurodns_record_set") {
		t.Fatalf("exact selection must take precedence over types:\n%s", out)
	}
	out, _ = render(context.Background(), &identity.Subject{}, "example.com", TerraformFilter{RRsets: []uiapi.RRsetRef{{Host: "api", Type: "A"}}})
	if strings.Contains(out, "eurodns_record_set\" ") {
		t.Fatalf("unselected RRset exported:\n%s", out)
	}
	out, _ = render(context.Background(), &identity.Subject{}, "example.com", TerraformFilter{Team: "other"})
	if strings.Contains(out, "eurodns_record_set\" ") {
		t.Fatalf("team filter ignored:\n%s", out)
	}
}
