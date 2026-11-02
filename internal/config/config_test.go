package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const base = `
zones: [example.com]
upstream:
  app_id: app
issuers:
  - name: ci
    issuer: https://token.example.net
    audiences: [eurodns-gate]
roles:
  writer:
    rules:
      - zones: [example.com]
        actions: [dns.read, dns.record.write]
        records: {hosts: ["*.staging"], types: [CNAME]}
bindings:
  - role: writer
    team: web
    subjects:
      - issuer: ci
        claims: {sub: "repo:acme/web:*"}
`

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(base), env(map[string]string{"EURODNS_API_KEY": "secret"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Upstream.APIKey != "secret" || c.Listen.Address != ":8080" || *c.CheckOnWrite != true || c.Store.Type != "memory" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Issuers[0].Category != "pipeline" || len(c.Issuers[0].Algorithms) == 0 {
		t.Fatal("issuer defaults not applied")
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	_, err := Parse([]byte(base+"\nunknown_field: 1\n"), env(map[string]string{"EURODNS_API_KEY": "x"}))
	if err == nil || !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestAPIKeyNotInFile(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(base, "app_id: app", "app_id: app\n  api_key: x", 1)), env(nil))
	if err == nil {
		t.Fatal("api_key in file must be refused")
	}
}

func TestAPIKeyFromFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Parse([]byte(base), env(map[string]string{"EURODNS_API_KEY_FILE": f}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Upstream.APIKey != "from-file" {
		t.Fatalf("got %q", c.Upstream.APIKey)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"missing key":      base,
		"hmac alg":         strings.Replace(base, "audiences: [eurodns-gate]", "audiences: [eurodns-gate]\n    algorithms: [HS256]", 1),
		"no audience":      strings.Replace(base, "audiences: [eurodns-gate]", "audiences: []", 1),
		"unknown action":   strings.Replace(base, "dns.record.write]", "dns.record.delete]", 1),
		"unknown role":     strings.Replace(base, "- role: writer", "- role: ghost", 1),
		"bad zone":         strings.Replace(base, "zones: [example.com]", "zones: [example]", 1),
		"http issuer":      strings.Replace(base, "https://token.example.net", "http://token.example.net", 1),
		"ui without key":   base + "ui: {enabled: true, issuer: ci, client_id: x, redirect_url: https://gate.example.com/auth/callback}\n",
		"ui bad redirect":  base + "ui: {enabled: true, issuer: ci, client_id: x, redirect_url: https://gate.example.com/cb}\n",
		"binding no claim": strings.Replace(base, `claims: {sub: "repo:acme/web:*"}`, "claims: {}", 1),
	}
	for name, doc := range cases {
		e := map[string]string{"EURODNS_API_KEY": "k"}
		if name == "missing key" {
			e = nil
		}
		if _, err := Parse([]byte(doc), env(e)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestUISessionKey(t *testing.T) {
	doc := base + "ui: {enabled: true, issuer: ci, client_id: x, redirect_url: https://gate.example.com/auth/callback}\n"
	c, err := Parse([]byte(doc), env(map[string]string{
		"EURODNS_API_KEY":          "k",
		"EURODNS_GATE_SESSION_KEY": strings.Repeat("ab", 32),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.UI.SessionKey) != 32 || c.UI.Scopes[0] != "openid" {
		t.Fatalf("ui not configured: %+v", c.UI)
	}
}

func TestExampleConfig(t *testing.T) {
	data, err := os.ReadFile("../../examples/config.yaml")
	if err != nil {
		t.Skip("examples/config.yaml absent")
	}
	if _, err := Parse(data, env(map[string]string{
		"EURODNS_API_KEY":          "k",
		"EURODNS_GATE_SESSION_KEY": strings.Repeat("ab", 32),
	})); err != nil {
		t.Fatal(err)
	}
}

func TestEntraIssuers(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	doc := func(issuer, aud string) string {
		return strings.NewReplacer("https://token.example.net", issuer, "audiences: [eurodns-gate]", "audiences: ["+aud+"]").Replace(base)
	}
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	ok := []struct{ issuer, aud string }{
		{"https://login.microsoftonline.com/" + tenant + "/v2.0", "api://eurodns-gate"},
		{"https://login.microsoftonline.com/" + tenant + "/v2.0", "99999999-8888-7777-6666-555555555555"},
		{"https://sts.windows.net/" + tenant + "/", "api://eurodns-gate"},
	}
	for _, c := range ok {
		cfg, err := Parse([]byte(doc(c.issuer, c.aud)), e)
		if err != nil {
			t.Errorf("%s: %v", c.issuer, err)
			continue
		}
		if strings.Contains(c.issuer, "sts.windows.net") && cfg.Issuers[0].JWKSURL != "https://login.microsoftonline.com/"+tenant+"/discovery/v2.0/keys" {
			t.Errorf("v1 issuer JWKS default: %q", cfg.Issuers[0].JWKSURL)
		}
	}
	ko := []struct{ issuer, aud string }{
		{"https://login.microsoftonline.com/common/v2.0", "api://eurodns-gate"},
		{"https://login.microsoftonline.com/organizations/v2.0", "api://eurodns-gate"},
		{"https://login.microsoftonline.com/consumers/v2.0", "api://eurodns-gate"},
		{"https://login.microsoftonline.com/" + tenant, "api://eurodns-gate"},
		{"https://login.microsoftonline.com/" + tenant + "/v2.0", "eurodns-gate"},
		{"https://sts.windows.net/common/", "api://eurodns-gate"},
		{"https://sts.windows.net/" + tenant, "api://eurodns-gate"},
	}
	for _, c := range ko {
		if _, err := Parse([]byte(doc(c.issuer, c.aud)), e); err == nil {
			t.Errorf("%s aud=%s: expected an error", c.issuer, c.aud)
		}
	}
}

func TestSubjectTemplate(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	with := func(extra string) string {
		return strings.Replace(base, "audiences: [eurodns-gate]", "audiences: [eurodns-gate]\n    "+extra, 1)
	}
	c, err := Parse([]byte(with(`subject_template: "{{tid}}/{{oid}}"`)), e)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuers[0].SubjectClaim != "" {
		t.Fatal("subject_claim must stay empty with a template")
	}
	id, err := RenderSubject(c.Issuers[0].SubjectTemplate, map[string]any{"tid": "t", "oid": "o"})
	if err != nil || id != "t/o" {
		t.Fatalf("%q %v", id, err)
	}
	if _, err := RenderSubject("{{tid}}/{{oid}}", map[string]any{"tid": "t"}); err == nil {
		t.Fatal("missing claim accepted")
	}
	for _, bad := range []string{
		`subject_template: "static"`,
		`subject_template: "{{tid}} {{oid}}"`,
		"subject_template: \"{{tid}}\"\n    subject_claim: oid",
		"category_map: {app: pipeline}",
		"category_claim: idtyp\n    category_map: {app: robot}",
	} {
		if _, err := Parse([]byte(with(bad)), e); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestGroupsAndPolicySection(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	groups := "\ngroups:\n  admins:\n    members:\n      - issuer: ci\n        claims: {roles: [Gate.PolicyAdmin]}\n"
	ok := strings.Replace(base, "    subjects:\n      - issuer: ci\n        claims: {sub: \"repo:acme/web:*\"}", "    groups: [admins]", 1) + groups +
		"policy:\n  editable: true\n  bounds: {zones: [example.com], actions: [dns.read, dns.record.write]}\n"
	c, err := Parse([]byte(ok), e)
	if err != nil {
		t.Fatal(err)
	}
	if !*c.Policy.RequireApproval || c.Policy.EditMaxAge.D() != 15*time.Minute || c.Hash == "" {
		t.Fatalf("policy defaults: %+v", c.Policy)
	}
	bad := map[string]string{
		"unknown group":   strings.Replace(ok, "groups: [admins]", "groups: [ghost]", 1),
		"no bounds":       strings.Replace(ok, "  bounds: {zones: [example.com], actions: [dns.read, dns.record.write]}\n", "", 1),
		"meta in bounds":  strings.Replace(ok, "actions: [dns.read, dns.record.write]}", "actions: [policy.propose]}", 1),
		"group no claims": strings.Replace(ok, "claims: {roles: [Gate.PolicyAdmin]}", "claims: {}", 1),
		"vk meta role":    ok + "virtual_keys:\n  - {id: k, app_id: vk-k, key_sha256: " + strings.Repeat("0", 64) + ", roles: [admin]}\n",
	}
	bad["vk meta role"] = strings.Replace(bad["vk meta role"], "roles:\n  writer:", "roles:\n  admin:\n    rules: [{zones: [\"*\"], actions: [policy.approve]}]\n  writer:", 1)
	for name, doc := range bad {
		if _, err := Parse([]byte(doc), e); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
