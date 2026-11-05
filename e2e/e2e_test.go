//go:build e2e

// Package e2e runs Terraform (and OpenTofu when available) with the real
// provider against a real gate in front of the EuroDNS fake.
//
//	go test -tags e2e ./e2e/...
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/app"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/oidctest"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

const (
	zone        = "example.com"
	upstreamApp = "gate-app"
	upstreamKey = "upstream-secret"
	acmeAppID   = "vk-acme"
	acmeKey     = "acme-test-key-0123456789abcdef"
)

type env struct {
	t        *testing.T
	fake     *eurodnstest.Server
	upstream *httptest.Server // fake plus the account domain listing
	account  *accountDomains
	idp      *oidctest.Provider
	gate     *httptest.Server
	app      *app.App
	tfBin    string
	cliCfg   string
	tokens   string
	auditBuf *os.File
	appDir   string
}

func TestEndToEnd(t *testing.T) {
	start := time.Now()
	e := setup(t)
	defer func() { t.Logf("e2e duration: %s", time.Since(start).Round(time.Millisecond)) }()

	t.Run("1_create_update_preserve_foreign", e.scenarioCreateUpdate)
	t.Run("2_foreign_host_refused", e.scenarioForeign)
	t.Run("3_import_adopt", e.scenarioImportAdopt)
	t.Run("4_console_drift_tainted", e.scenarioTainted)
	t.Run("5_protected_refused", e.scenarioProtected)
	t.Run("6_acme_stale_put_rebased", e.scenarioACME)
	t.Run("7_ui_api", e.scenarioUIAPI)
	t.Run("8_managed_policy", e.scenarioManagedPolicy)
	t.Run("9_bulk_adopt_and_terraform_export", e.scenarioBulkAdopt)
	t.Run("10_import_owned_rrset_with_write_only", e.scenarioImportOwned)
	t.Run("11_mcp", e.scenarioMCP)
	t.Run("12_zone_discovery_and_team_from", e.scenarioDiscoveryTeamFrom)
	t.Run("13_policy_delegation", e.scenarioDelegation)
	t.Run("14_dnsgate_provider", e.scenarioDNSGateProvider)
}

func setup(t *testing.T) *env {
	t.Helper()
	tfBin := firstExisting(os.Getenv("E2E_TERRAFORM"), "/opt/homebrew/bin/terraform", lookPath("terraform"))
	if tfBin == "" {
		t.Skip("terraform not found (set E2E_TERRAFORM)")
	}
	e := &env{t: t, tfBin: tfBin, tokens: t.TempDir()}

	e.fake = eurodnstest.NewServer(eurodnstest.Options{AppID: upstreamApp, APIKey: upstreamKey})
	t.Cleanup(e.fake.Close)
	e.fake.Seed(&eurodns.Zone{Name: zone, Records: []eurodns.Record{
		{Type: "NS", Host: "@", TTL: 86400, RData: "ns1.eurodns.com."},
		{Type: "NS", Host: "@", TTL: 86400, RData: "ns2.eurodns.com."},
		{Type: "MX", Host: "@", TTL: 3600, RData: "10 mail.example.com."},
		{Type: "CNAME", Host: "www", TTL: 3600, RData: "web.example.net."},
		{Type: "CNAME", Host: "legacy", TTL: 3600, RData: "old.example.net."},
		{Type: "A", Host: "shop", TTL: 3600, RData: "192.0.2.10"},
		{Type: "CNAME", Host: "blog", TTL: 3600, RData: "blog.example.net."},
		{Type: "CNAME", Host: "rel", TTL: 3600, RData: "internal"},
	}})

	e.account = &accountDomains{names: []string{zone}}
	e.upstream = e.account.server(t, e.fake.URL)

	e.idp = oidctest.New()
	t.Cleanup(e.idp.Close)

	cfg := e.config("mcp: {enabled: true, allow_writes: true}")
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	e.auditBuf = f
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("E2E_VERBOSE") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	e.app, err = app.New(ctx, cfg, log, app.Options{PolicyReloadInterval: 200 * time.Millisecond, Holder: "e2e", AuditOutput: f})
	if err != nil {
		t.Fatalf("app: %v", err)
	}
	e.app.Run(ctx)
	e.gate = httptest.NewServer(e.app.Handler())
	t.Cleanup(e.gate.Close)

	e.cliCfg = buildProvider(t)
	return e
}

func (e *env) config(extra string) *config.Config {
	t := e.t
	sum := sha256.Sum256([]byte(acmeKey))
	yaml := fmt.Sprintf(`
listen: {address: "127.0.0.1:0"}
providers:
  - id: eurodns
    kind: eurodns
    eurodns:
      base_url: %[1]s
      app_id: %[2]s
      rate: {every: 5ms, burst: 50}
zones: [%[3]s]
check_on_write: true
reconcile_interval: 1h
limits: {max_changes_per_request: 20}
lock: {ttl: 30s, wait: 20s}
store:
  type: sqlite
  sqlite: {path: %[4]s}
issuers:
  - name: ci
    issuer: %[5]s
    audiences: [dns-gate]
    category: pipeline
virtual_keys:
  - id: vk-acme
    app_id: %[6]s
    key_sha256: %[7]s
    roles: [acme-solver]
    teams: [edge]
    expires_at: 2099-01-01T00:00:00Z
roles:
  web-writer:
    rules:
      - zones: [%[3]s]
        actions: [dns.read, dns.record.write, ui.read]
        records: {hosts: ["@", "**"]}
  dns-admin:
    rules:
      - zones: [%[3]s]
        actions: [dns.read, dns.record.write, dns.record.adopt, ui.read]
  acme-solver:
    rebase_on_save: true
    ephemeral_ttl: 1h
    rules:
      - zones: ["*"]
        actions: [dns.read, dns.record.write]
        records: {hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT]}
  policy-admin:
    rules:
      - zones: ["*"]
        actions: [policy.read, policy.propose, policy.approve, ui.read]
  pipeline-writer:
    rules:
      - zones: [%[9]s]
        actions: [dns.read, dns.record.write, ui.read]
        records: {hosts: ["*.apps"], types: [CNAME]}
bindings:
  - role: pipeline-writer
    team_from: {claim: sub, regex: "^pipeline:([a-z0-9-]+)$", prefix: p-}
    subjects: [{issuer: ci, claims: {sub: ["pipeline:*"]}}]
  - role: web-writer
    team: web
    subjects: [{issuer: ci, claims: {sub: [ci-web]}}]
  - role: dns-admin
    team: web
    subjects: [{issuer: ci, claims: {sub: [ci-admin]}}]
  - role: policy-admin
    subjects:
      - {issuer: ci, claims: {sub: [admin-a]}}
      - {issuer: ci, claims: {sub: [admin-b]}}
protected:
  - {zones: ["*"], hosts: ["@"], types: [NS, SOA, MX]}
policy:
  editable: true
  require_approval: true
  bounds:
    zones: [%[3]s, %[9]s]
    actions: [dns.read, dns.record.write, ui.read]
  delegations:
    - name: workloads-pipelines
      subjects: [{issuer: ci, claims: {sub: [%[10]q]}}]
      allow:
        zones: [%[3]s]
        actions: [dns.read, dns.record.write, ui.read]
        records: {hosts: ["**.wl"], types: [CNAME, TXT]}
        binding_subjects: [{issuer: ci, claims: {sub: ["sc://org/proj/dns-gate-*"]}}]
        teams:
          from_subject: {claim: sub, regex: "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"}
%[8]s
`, e.upstream.URL, upstreamApp, zone, filepath.Join(t.TempDir(), "gate.db"), e.idp.URL, acmeAppID, hex.EncodeToString(sum[:]), extra, discoveredZone, workloadsSubject)
	cfg, err := config.Parse([]byte(yaml), func(k string) string {
		if k == "EURODNS_API_KEY" {
			return upstreamKey
		}
		return ""
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// token returns a fresh JWT for sub and a file holding it.
func (e *env) token(sub string) (string, string) {
	tok := e.idp.Sign(map[string]any{"sub": sub, "aud": "dns-gate"})
	path := filepath.Join(e.tokens, strings.NewReplacer("/", "_", ":", "_").Replace(sub)+".jwt")
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		e.t.Fatal(err)
	}
	return tok, path
}

// workspace writes main.tf for sub and returns the directory.
func (e *env) workspace(t *testing.T, sub, body string) string {
	t.Helper()
	dir := e.t.TempDir() // outlives the subtest: later scenarios reuse it
	_, tokenFile := e.token(sub)
	e.writeTF(t, dir, tokenFile, body)
	return dir
}

func (e *env) writeTF(t *testing.T, dir, tokenFile, body string) {
	t.Helper()
	main := fmt.Sprintf(`
terraform {
  required_providers {
    eurodns = { source = "kamorionlabs/eurodns" }
  }
}
provider "eurodns" {
  request_interval = "5ms"
  request_burst    = 50
  gate {
    url = %q
    auth { token_file = %q }
  }
}
%s
`, e.gate.URL, tokenFile, body)
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *env) tf(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(e.tfBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"TF_CLI_CONFIG_FILE="+e.cliCfg,
		"TF_IN_AUTOMATION=1",
		"TF_INPUT=0",
		"CHECKPOINT_DISABLE=1",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func (e *env) mustTF(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := e.tf(t, dir, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(e.tfBin), strings.Join(args, " "), err, out)
	}
	return out
}

func apply(e *env, t *testing.T, dir string) string {
	return e.mustTF(t, dir, "apply", "-auto-approve", "-no-color")
}

func (e *env) values(host, typ string) []string {
	var v []string
	for _, r := range e.fake.Zone(zone).Records {
		if r.Host == host && r.Type == typ {
			v = append(v, r.RData)
		}
	}
	return v
}

func (e *env) assertForeignIntact(t *testing.T) {
	t.Helper()
	if got := e.values("www", "CNAME"); len(got) != 1 || got[0] != "web.example.net." {
		t.Errorf("www CNAME changed: %v", got)
	}
	if got := e.values("@", "NS"); len(got) != 2 {
		t.Errorf("apex NS changed: %v", got)
	}
	if got := e.values("@", "MX"); len(got) != 1 {
		t.Errorf("apex MX changed: %v", got)
	}
}

func recordTF(name, host, typ string, values ...string) string {
	return recordTFIn(zone, name, host, typ, values...)
}

func recordTFIn(zoneName, name, host, typ string, values ...string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf(`
resource "eurodns_record_set" %q {
  zone   = %q
  host   = %q
  type   = %q
  ttl    = 3600
  values = [%s]
}
`, name, zoneName, host, typ, strings.Join(q, ", "))
}

func (e *env) scenarioCreateUpdate(t *testing.T) {
	dir := e.workspace(t, "ci-web", recordTF("app", "app", "CNAME", "app-v1.example.net."))
	apply(e, t, dir)
	if got := e.values("app", "CNAME"); len(got) != 1 || got[0] != "app-v1.example.net." {
		t.Fatalf("app CNAME after create: %v", got)
	}
	out := e.mustTF(t, dir, "plan", "-detailed-exitcode", "-no-color")
	if !strings.Contains(out, "No changes") {
		t.Fatalf("second plan not empty:\n%s", out)
	}
	_, tokenFile := e.token("ci-web")
	e.writeTF(t, dir, tokenFile, recordTF("app", "app", "CNAME", "app-v2.example.net."))
	apply(e, t, dir)
	if got := e.values("app", "CNAME"); len(got) != 1 || got[0] != "app-v2.example.net." {
		t.Fatalf("app CNAME after update: %v", got)
	}
	e.assertForeignIntact(t)
	e.appDir = dir
}

func (e *env) scenarioForeign(t *testing.T) {
	dir := e.workspace(t, "ci-web", recordTF("www", "www", "CNAME", "hijack.example.net."))
	out, err := e.tf(t, dir, "apply", "-auto-approve", "-no-color")
	if err == nil {
		t.Fatalf("creating over a foreign RRset succeeded:\n%s", out)
	}
	if !strings.Contains(out, "already exists") && !strings.Contains(out, "foreign") {
		t.Errorf("unclear error:\n%s", out)
	}
	// The gate itself refuses, whatever the client does.
	c := e.bearerClient("ci-web")
	_, err = c.AddRecords(context.Background(), zone, []eurodns.Record{{Type: "CNAME", Host: "www", TTL: 3600, RData: "hijack.example.net."}})
	if reason(err) != "foreign_rrset" {
		t.Errorf("direct add on foreign RRset: want foreign_rrset, got %v", err)
	}
	e.assertForeignIntact(t)
}

func (e *env) scenarioImportAdopt(t *testing.T) {
	body := recordTF("legacy", "legacy", "CNAME", "old.example.net.")
	dir := e.workspace(t, "ci-web", body)
	out, err := e.tf(t, dir, "import", "-no-color", "eurodns_record_set.legacy", zone+"/legacy/CNAME")
	if err == nil {
		t.Fatalf("import without adopt right succeeded:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "forbidden") && !strings.Contains(out, "adopt") {
		t.Errorf("unclear import refusal:\n%s", out)
	}

	dir = e.workspace(t, "ci-admin", body)
	e.mustTF(t, dir, "import", "-no-color", "eurodns_record_set.legacy", zone+"/legacy/CNAME")
	_, tokenFile := e.token("ci-admin")
	e.writeTF(t, dir, tokenFile, recordTF("legacy", "legacy", "CNAME", "new.example.net."))
	apply(e, t, dir)
	if got := e.values("legacy", "CNAME"); len(got) != 1 || got[0] != "new.example.net." {
		t.Fatalf("legacy after adopt+update: %v", got)
	}
	e.assertForeignIntact(t)
}

func (e *env) scenarioTainted(t *testing.T) {
	if e.appDir == "" {
		t.Skip("scenario 1 failed")
	}
	z := e.fake.Zone(zone)
	for i := range z.Records {
		if z.Records[i].Host == "app" && z.Records[i].Type == "CNAME" {
			z.Records[i].RData = "console-edit.example.net."
		}
	}
	e.fake.Seed(z)
	if err := e.app.Engine.Reconcile(context.Background(), zone); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	_, tokenFile := e.token("ci-web")
	e.writeTF(t, e.appDir, tokenFile, recordTF("app", "app", "CNAME", "app-v2.example.net."))
	out, err := e.tf(t, e.appDir, "apply", "-auto-approve", "-no-color")
	if err == nil {
		t.Fatalf("apply over a tainted RRset succeeded:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "tainted") && !strings.Contains(strings.ToLower(out), "outside the gate") {
		t.Errorf("unclear tainted error:\n%s", out)
	}
	if got := e.values("app", "CNAME"); len(got) != 1 || got[0] != "console-edit.example.net." {
		t.Errorf("console edit overwritten: %v", got)
	}
}

func (e *env) scenarioProtected(t *testing.T) {
	c := e.bearerClient("ci-admin")
	tok, _ := e.token("ci-admin")
	req, _ := http.NewRequest(http.MethodPost, e.gate.URL+"/.well-known/dns-gate/zones/"+zone+"/adopt", strings.NewReader(`{"rrsets":[{"host":"@","type":"NS"}]}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("adopting apex NS: want 403, got %v %v", resp, err)
	}
	if resp != nil {
		resp.Body.Close()
	}
	_, err = c.AddRecords(context.Background(), zone, []eurodns.Record{{Type: "MX", Host: "@", TTL: 3600, RData: "5 evil.example.net."}})
	if err == nil {
		t.Errorf("adding to apex MX succeeded")
	}
	dir := e.workspace(t, "ci-admin", recordTF("ns", "@", "NS", "ns1.eurodns.com.", "ns2.eurodns.com."))
	out, err := e.tf(t, dir, "import", "-no-color", "eurodns_record_set.ns", zone+"/@/NS")
	if err == nil {
		t.Errorf("import of protected apex NS succeeded:\n%s", out)
	}
	e.assertForeignIntact(t)
}

func (e *env) scenarioACME(t *testing.T) {
	ctx := context.Background()
	acme, err := eurodns.New(eurodns.WithBaseURL(e.gate.URL),
		eurodns.WithAuth(eurodns.APIKeyAuth{AppID: acmeAppID, APIKey: acmeKey}),
		eurodns.WithRateLimit(5*time.Millisecond, 50))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := acme.GetZone(ctx, zone)
	if err != nil {
		t.Fatalf("acme get zone: %v", err)
	}
	// Another write lands after the ACME client read the zone.
	if _, err := e.bearerClient("ci-web").AddRecords(ctx, zone, []eurodns.Record{{Type: "CNAME", Host: "other", TTL: 3600, RData: "other.example.net."}}); err != nil {
		t.Fatalf("concurrent write: %v", err)
	}
	stale.Records = append(stale.Records, eurodns.Record{Type: "TXT", Host: "_acme-challenge.app", TTL: 600, RData: `"challenge-token"`})
	if err := acme.SaveZone(ctx, zone, stale); err != nil {
		t.Fatalf("acme stale PUT: %v", err)
	}
	if got := e.values("_acme-challenge.app", "TXT"); len(got) != 1 {
		t.Errorf("challenge TXT not created: %v", got)
	}
	if got := e.values("other", "CNAME"); len(got) != 1 {
		t.Errorf("concurrent write lost by the stale PUT: %v", got)
	}
	e.assertForeignIntact(t)

	// Out of scope even with a fresh zone: refused.
	fresh, _ := acme.GetZone(ctx, zone)
	fresh.Records = append(fresh.Records, eurodns.Record{Type: "TXT", Host: "app", TTL: 600, RData: `"nope"`})
	_ = acme.SaveZone(ctx, zone, fresh)
	if got := e.values("app", "TXT"); len(got) != 0 {
		t.Errorf("acme key wrote outside its scope: %v", got)
	}
}

func (e *env) scenarioUIAPI(t *testing.T) {
	var zones []uiapi.ZoneSummary
	e.getJSON(t, "ci-web", "/api/v1/zones", &zones)
	if len(zones) != 1 || zones[0].Zone != zone || zones[0].Managed < 1 || zones[0].Foreign < 1 {
		t.Errorf("zones summary: %+v", zones)
	}
	var inv uiapi.ZoneInventory
	e.getJSON(t, "ci-web", "/api/v1/zones/"+zone+"/rrsets", &inv)
	status := map[string]uiapi.RRset{}
	for _, r := range inv.RRsets {
		status[r.Host+"/"+r.Type] = r
	}
	want := map[string]string{
		"www/CNAME":    uiapi.StatusForeign,
		"legacy/CNAME": uiapi.StatusManaged,
		"other/CNAME":  uiapi.StatusManaged,
		"@/NS":         uiapi.StatusForeign,
	}
	if e.appDir != "" {
		want["app/CNAME"] = uiapi.StatusTainted
	}
	for k, w := range want {
		if got := status[k].Status; got != w {
			t.Errorf("%s: status %q, want %q", k, got, w)
		}
	}
	if r := status["@/NS"]; !r.Protected {
		t.Errorf("apex NS not flagged protected")
	}
	if r := status["legacy/CNAME"]; !r.Adopted || r.Owner != "web" {
		t.Errorf("legacy ownership: %+v", r)
	}
	if r := status["other/CNAME"]; r.CreatedBy == nil || !strings.Contains(r.CreatedBy.Subject, "ci-web") || r.CreatedBy.Category != "pipeline" {
		t.Errorf("other created_by: %+v", r.CreatedBy)
	}

	var page uiapi.AuditPage
	e.getJSON(t, "ci-web", "/api/v1/audit?decision=deny&limit=100", &page)
	reasons := map[string]bool{}
	for _, en := range page.Entries {
		reasons[en.Reason] = true
	}
	for _, r := range []string{"foreign_rrset", "tainted"} {
		if !reasons[r] {
			t.Errorf("audit: no deny with reason %s (got %v)", r, keys(reasons))
		}
	}
	e.getJSON(t, "ci-web", "/api/v1/audit?subject=ci-admin&limit=100", &page)
	found := false
	for _, en := range page.Entries {
		if en.Decision == "allow" && strings.Contains(en.Actor.Subject, "ci-admin") {
			found = true
		}
	}
	if !found {
		t.Errorf("audit: no allowed action by ci-admin")
	}
}

func (e *env) scenarioManagedPolicy(t *testing.T) {
	body := recordTF("newapp", "newapp", "CNAME", "newapp.example.net.")
	dir := e.workspace(t, "ci-new", body)
	if out, err := e.tf(t, dir, "apply", "-auto-approve", "-no-color"); err == nil {
		t.Fatalf("ci-new wrote before being granted:\n%s", out)
	}

	doc := uiapi.PolicyDocument{
		Groups: map[string]uiapi.Group{},
		Roles: map[string]uiapi.Role{"newapp-writer": {Rules: []uiapi.Rule{{
			Zones: []string{zone}, Actions: []string{"dns.read", "dns.record.write"},
			Records: &uiapi.RecordScope{Hosts: []string{"newapp"}, Types: []string{"CNAME"}},
		}}}},
		Bindings: []uiapi.Binding{{Role: "newapp-writer", Team: "newapp",
			Subjects: []uiapi.SubjectMatcher{{Issuer: "ci", Claims: map[string][]string{"sub": {"ci-new"}}}}}},
		VirtualKeys: []uiapi.VirtualKey{},
	}
	var rev uiapi.RevisionDetail
	e.postJSON(t, "admin-a", "/api/v1/policy/revisions", uiapi.ProposeRequest{Document: doc, Comment: "grant newapp to ci-new"}, http.StatusCreated, &rev)
	if rev.ID == "" || rev.Status != uiapi.RevisionProposed {
		t.Fatalf("proposal: %+v", rev.RevisionSummary)
	}
	// The author cannot approve their own proposal.
	e.postJSON(t, "admin-a", "/api/v1/policy/revisions/"+rev.ID+"/approve", uiapi.DecisionRequest{Comment: "self"}, http.StatusForbidden, nil)
	// Not approved yet: activation refused.
	e.postJSON(t, "admin-b", "/api/v1/policy/revisions/"+rev.ID+"/activate", nil, 0, nil)
	e.postJSON(t, "admin-b", "/api/v1/policy/revisions/"+rev.ID+"/approve", uiapi.DecisionRequest{Comment: "ok"}, http.StatusOK, nil)
	e.postJSON(t, "admin-b", "/api/v1/policy/revisions/"+rev.ID+"/activate", nil, http.StatusOK, nil)

	deadline := time.Now().Add(5 * time.Second)
	for {
		var eff uiapi.EffectivePolicy
		e.getJSON(t, "admin-a", "/api/v1/policy", &eff)
		if eff.Active != nil && eff.Active.ID == rev.ID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revision %s not active: %+v", rev.ID, eff.Active)
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond) // reload interval of the policy holder

	_, tokenFile := e.token("ci-new")
	e.writeTF(t, dir, tokenFile, body)
	apply(e, t, dir)
	if got := e.values("newapp", "CNAME"); len(got) != 1 {
		t.Fatalf("newapp not created after activation: %v", got)
	}
	// Still bounded by the managed role: another host is refused.
	_, err := e.bearerClient("ci-new").AddRecords(context.Background(), zone, []eurodns.Record{{Type: "CNAME", Host: "elsewhere", TTL: 3600, RData: "x.example.net."}})
	if !eurodns.IsForbidden(err) {
		t.Errorf("managed binding wider than its role: %v", err)
	}
}

// helpers

func (e *env) bearerClient(sub string) *eurodns.Client {
	tok, _ := e.token(sub)
	c, err := eurodns.New(eurodns.WithBaseURL(e.gate.URL),
		eurodns.WithAuth(eurodns.BearerAuth{Source: eurodns.StaticToken(tok)}),
		eurodns.WithRateLimit(5*time.Millisecond, 50))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) getJSON(t *testing.T, sub, path string, v any) {
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
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("GET %s: %v: %s", path, err, b)
	}
}

// postJSON posts body; want 0 accepts any non-2xx status.
func (e *env) postJSON(t *testing.T, sub, path string, body any, want int, v any) {
	t.Helper()
	tok, _ := e.token(sub)
	var r io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(http.MethodPost, e.gate.URL+path, r)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	switch {
	case want == 0 && resp.StatusCode < 300:
		t.Fatalf("POST %s: expected a refusal, got %d %s", path, resp.StatusCode, b)
	case want != 0 && resp.StatusCode != want:
		t.Fatalf("POST %s: %d, want %d: %s", path, resp.StatusCode, want, b)
	}
	if v != nil {
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("POST %s: %v: %s", path, err, b)
		}
	}
}

func reason(err error) string {
	if ae, ok := err.(*eurodns.APIError); ok {
		return ae.Reason
	}
	return fmt.Sprint(err)
}

func keys(m map[string]bool) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	return k
}

// buildProvider compiles the provider and returns a CLI config using it
// through dev_overrides.
func buildProvider(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(here), "..", "..", "terraform-provider-eurodns")
	if p := os.Getenv("E2E_PROVIDER_SRC"); p != "" {
		src = p
	}
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Skipf("provider sources not found at %s", src)
	}
	bin := t.TempDir()
	cmd := exec.Command("go", "build", "-o", filepath.Join(bin, "terraform-provider-eurodns"), ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v\n%s", err, out)
	}
	cli := filepath.Join(t.TempDir(), "cli.tfrc")
	content := fmt.Sprintf("provider_installation {\n  dev_overrides {\n    \"kamorionlabs/eurodns\" = %q\n  }\n  direct {}\n}\n", bin)
	if err := os.WriteFile(cli, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cli
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func lookPath(name string) string {
	p, _ := exec.LookPath(name)
	return p
}
