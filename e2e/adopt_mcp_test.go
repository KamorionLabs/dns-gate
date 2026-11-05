//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/KamorionLabs/dns-gate/internal/app"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func (e *env) scenarioBulkAdopt(t *testing.T) {
	base := "/api/v1/zones/" + zone
	// Apex NS is managed by EuroDNS: listed only when selected explicitly.
	sel := uiapi.AdoptSelection{RRsets: []uiapi.RRsetRef{{Host: "@", Type: "NS"}}, Hosts: []string{"shop", "blog", "@"}}
	var prev uiapi.AdoptPreview
	e.postJSON(t, "ci-admin", base+"/adopt/preview", sel, http.StatusOK, &prev)
	got := map[string]uiapi.AdoptCandidate{}
	for _, c := range prev.Candidates {
		got[c.Host+"/"+c.Type] = c
	}
	for k, want := range map[string]string{"@/NS": "server_managed", "@/MX": "protected"} {
		if c := got[k]; c.Adoptable || c.Reason != want {
			t.Errorf("preview %s: adoptable=%v reason=%q, want refused with %q", k, c.Adoptable, c.Reason, want)
		}
	}
	for _, k := range []string{"shop/A", "blog/CNAME"} {
		if !got[k].Adoptable {
			t.Errorf("preview %s not adoptable: %+v", k, got[k])
		}
	}
	if prev.Owner != "web" || prev.PreviewToken == "" {
		t.Fatalf("preview owner/token: %q %q", prev.Owner, prev.PreviewToken)
	}

	// The console changes blog between preview and apply: nothing is adopted.
	z := e.fake.Zone(zone)
	for i := range z.Records {
		if z.Records[i].Host == "blog" {
			z.Records[i].RData = "blog-v2.example.net."
		}
	}
	e.fake.Seed(z)
	pick := []uiapi.RRsetRef{{Host: "shop", Type: "A"}, {Host: "blog", Type: "CNAME"}}
	e.postJSON(t, "ci-admin", base+"/adopt", uiapi.AdoptApply{RRsets: pick, Comment: "take over shop and blog", PreviewToken: prev.PreviewToken}, http.StatusConflict, nil)
	if s := e.status(t, "shop", "A"); s != uiapi.StatusForeign {
		t.Errorf("shop adopted by a conflicting apply (all-or-nothing): %s", s)
	}

	e.postJSON(t, "ci-admin", base+"/adopt/preview", sel, http.StatusOK, &prev)
	var res uiapi.AdoptResult
	e.postJSON(t, "ci-admin", base+"/adopt", uiapi.AdoptApply{RRsets: pick, Comment: "take over shop and blog", PreviewToken: prev.PreviewToken}, http.StatusOK, &res)
	if len(res.Adopted) != 2 || res.Owner != "web" {
		t.Fatalf("adopt result: %+v", res)
	}

	hcl := e.getText(t, "ci-admin", base+"/terraform?rrsets=shop/A,blog/CNAME")
	if strings.Count(hcl, `resource "eurodns_record_set"`) != 2 || strings.Count(hcl, "import {") != 2 {
		t.Fatalf("export:\n%s", hcl)
	}
	// A team member with write only takes the exported RRsets into its stack.
	dir := e.t.TempDir()
	_, tokenFile := e.token("ci-web")
	e.writeTF(t, dir, tokenFile, "")
	if err := os.WriteFile(filepath.Join(dir, "records.tf"), []byte(hcl), 0o600); err != nil {
		t.Fatal(err)
	}
	out := e.mustTF(t, dir, "plan", "-no-color")
	if !strings.Contains(out, "2 to import, 0 to add, 0 to change, 0 to destroy") {
		t.Fatalf("plan of the export is not import-only:\n%s", out)
	}
	apply(e, t, dir)
	out = e.mustTF(t, dir, "plan", "-no-color")
	if !strings.Contains(out, "No changes") {
		t.Fatalf("plan after import not empty:\n%s", out)
	}
	edited := strings.Replace(hcl, `"192.0.2.10"`, `"192.0.2.11"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "records.tf"), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	apply(e, t, dir)
	if v := e.values("shop", "A"); len(v) != 1 || v[0] != "192.0.2.11" {
		t.Errorf("shop after Terraform update: %v", v)
	}
	e.assertForeignIntact(t)
}

func (e *env) scenarioImportOwned(t *testing.T) {
	// "other" was created by ci-web (team web) in scenario 6; web-writer has
	// no dns.record.adopt.
	dir := e.workspace(t, "ci-web", recordTF("other", "other", "CNAME", "other.example.net."))
	e.mustTF(t, dir, "import", "-no-color", "eurodns_record_set.other", zone+"/other/CNAME")
	out := e.mustTF(t, dir, "plan", "-no-color")
	if !strings.Contains(out, "No changes") {
		t.Fatalf("plan after import of an owned RRset:\n%s", out)
	}
}

func (e *env) scenarioMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A gate without mcp.allow_writes exposes read tools only.
	ro := e.readOnlyGate(t)
	names := toolNames(t, e.mcpSession(t, ctx, ro.URL, "ci-web"))
	if names["plan_rrset_change"] || names["apply_rrset_change"] || names["adopt_apply"] || !names["list_rrsets"] {
		t.Errorf("read-only gate tools: %v", names)
	}

	web := e.mcpSession(t, ctx, e.gate.URL, "ci-web")
	if names := toolNames(t, web); !names["plan_rrset_change"] || !names["apply_rrset_change"] {
		t.Fatalf("write tools missing: %v", names)
	}
	var plan uiapi.PlanResult
	callTool(t, ctx, web, "plan_rrset_change", map[string]any{
		"zone":    zone,
		"changes": []uiapi.RRsetChange{{Host: "mcp", Type: "CNAME", TTL: 3600, Values: []string{"mcp.example.net."}}},
	}, false, &plan)
	if !plan.Allowed || plan.PlanID == "" {
		t.Fatalf("plan: %+v", plan)
	}
	if v := e.values("mcp", "CNAME"); len(v) != 0 {
		t.Fatalf("plan wrote: %v", v)
	}

	// Another subject cannot apply it, and cannot burn it either.
	admin := e.mcpSession(t, ctx, e.gate.URL, "ci-admin")
	callTool(t, ctx, admin, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, true, nil)

	var applied uiapi.PlanResult
	callTool(t, ctx, web, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, false, &applied)
	if v := e.values("mcp", "CNAME"); len(v) != 1 || v[0] != "mcp.example.net." {
		t.Fatalf("mcp CNAME after apply: %v", v)
	}
	// A plan is single use.
	callTool(t, ctx, web, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, true, nil)

	evs, _, err := e.app.Store.ListAudit(ctx, store.AuditQuery{Zone: zone, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var viaMCP, deniedForeign bool
	for _, ev := range evs {
		if ev.Extra["via"] != "mcp" {
			continue
		}
		if strings.Contains(ev.Action, "apply_rrset_change") && ev.Decision == "allow" && strings.Contains(ev.Subject, "ci-web") {
			viaMCP = true
		}
	}
	all, _, _ := e.app.Store.ListAudit(ctx, store.AuditQuery{Limit: 500})
	for _, ev := range all {
		if ev.Extra["via"] == "mcp" && strings.Contains(ev.Action, "apply_rrset_change") && ev.Decision == "deny" && strings.Contains(ev.Subject, "ci-admin") {
			deniedForeign = true
		}
	}
	if !viaMCP {
		t.Errorf("audit: no allowed apply_rrset_change with via=mcp")
	}
	if !deniedForeign {
		t.Errorf("audit: no denied apply_rrset_change by the other subject")
	}
}

// helpers

func (e *env) status(t *testing.T, host, typ string) string {
	t.Helper()
	var inv uiapi.ZoneInventory
	e.getJSON(t, "ci-admin", "/api/v1/zones/"+zone+"/rrsets", &inv)
	for _, r := range inv.RRsets {
		if r.Host == host && r.Type == typ {
			return r.Status
		}
	}
	return ""
}

func (e *env) getText(t *testing.T, sub, path string) string {
	t.Helper()
	tok, _ := e.token(sub)
	req, _ := http.NewRequest(http.MethodGet, e.gate.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	return string(b)
}

func (e *env) readOnlyGate(t *testing.T) *httptest.Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, err := app.New(ctx, e.config("mcp: {enabled: true}"), slog.New(slog.NewTextHandler(io.Discard, nil)), app.Options{Holder: "e2e-ro", AuditOutput: e.auditBuf})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func (e *env) mcpSession(t *testing.T, ctx context.Context, base, sub string) *mcp.ClientSession {
	t.Helper()
	tok, _ := e.token(sub)
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-" + sub, Version: "test"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   base + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token: tok, base: http.DefaultTransport}},
		MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("mcp connect as %s: %v", sub, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

// callTool calls a tool; wantErr expects a tool or protocol error.
func callTool(t *testing.T, ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any, wantErr bool, out any) {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	failed := err != nil || (res != nil && res.IsError)
	if failed != wantErr {
		t.Fatalf("%s: error=%v (err %v, result %s), want error=%v", name, failed, err, toolText(res), wantErr)
	}
	if out != nil && res != nil && res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s: decode %s: %v", name, b, err)
		}
	}
}

func toolText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, " ")
}
