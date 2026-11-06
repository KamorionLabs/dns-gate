package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const base = `
zones: [example.com]
providers:
  - id: eurodns
    kind: eurodns
    eurodns: {app_id: app}
issuers:
  - name: ci
    issuer: https://token.example.net
    audiences: [dns-gate]
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
	if c.Providers[0].EuroDNS.APIKey != "secret" || c.Listen.Address != ":8080" || *c.CheckOnWrite != true || c.Store.Type != "memory" {
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
	if c.Providers[0].EuroDNS.APIKey != "from-file" {
		t.Fatalf("got %q", c.Providers[0].EuroDNS.APIKey)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"missing key":      base,
		"hmac alg":         strings.Replace(base, "audiences: [dns-gate]", "audiences: [dns-gate]\n    algorithms: [HS256]", 1),
		"no audience":      strings.Replace(base, "audiences: [dns-gate]", "audiences: []", 1),
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
		"EURODNS_API_KEY":      "k",
		"DNS_GATE_SESSION_KEY": strings.Repeat("ab", 32),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.UI.SessionKey) != 32 || c.UI.Scopes[0] != "openid" {
		t.Fatalf("ui not configured: %+v", c.UI)
	}
}

func TestUICLIScope(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	const client = "99999999-8888-7777-6666-555555555555"
	e := env(map[string]string{"EURODNS_API_KEY": "k", "DNS_GATE_SESSION_KEY": strings.Repeat("ab", 32)})
	ui := "ui: {enabled: true, issuer: ci, client_id: " + client + ", redirect_url: https://gate.example.com/auth/callback%s}\n"
	entra := strings.NewReplacer("https://token.example.net", "https://login.microsoftonline.com/"+tenant+"/v2.0", "audiences: [dns-gate]", "audiences: ["+client+"]").Replace(base)

	c, err := Parse([]byte(entra+fmt.Sprintf(ui, "")), e)
	if err != nil {
		t.Fatal(err)
	}
	if c.UI.CLIScope != "api://"+client+"/.default" {
		t.Fatalf("Entra default cli_scope: %q", c.UI.CLIScope)
	}
	if c, err = Parse([]byte(entra+fmt.Sprintf(ui, ", cli_scope: api://dns-gate/.default")), e); err != nil || c.UI.CLIScope != "api://dns-gate/.default" {
		t.Fatalf("explicit cli_scope: %v %q", err, c.UI.CLIScope)
	}
	if c, err = Parse([]byte(base+fmt.Sprintf(ui, "")), e); err != nil || c.UI.CLIScope != "" {
		t.Fatalf("non-Entra issuer has no default: %v %q", err, c.UI.CLIScope)
	}
	for _, bad := range []string{`"api://x/.default openid"`, `"api://x/.default'"`, `"$(id)"`, `"-x"`} {
		if _, err := Parse([]byte(entra+fmt.Sprintf(ui, ", cli_scope: "+bad)), e); err == nil || !strings.Contains(err.Error(), "ui.cli_scope") {
			t.Errorf("cli_scope %s: expected an error, got %v", bad, err)
		}
	}
}

func TestExampleConfig(t *testing.T) {
	data, err := os.ReadFile("../../examples/config.yaml")
	if err != nil {
		t.Skip("examples/config.yaml absent")
	}
	if _, err := Parse(data, env(map[string]string{
		"EURODNS_API_KEY":      "k",
		"DNS_GATE_SESSION_KEY": strings.Repeat("ab", 32),
	})); err != nil {
		t.Fatal(err)
	}
}

func TestEntraIssuers(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	doc := func(issuer, aud string) string {
		return strings.NewReplacer("https://token.example.net", issuer, "audiences: [dns-gate]", "audiences: ["+aud+"]").Replace(base)
	}
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	ok := []struct{ issuer, aud string }{
		{"https://login.microsoftonline.com/" + tenant + "/v2.0", "api://dns-gate"},
		{"https://login.microsoftonline.com/" + tenant + "/v2.0", "99999999-8888-7777-6666-555555555555"},
		{"https://sts.windows.net/" + tenant + "/", "api://dns-gate"},
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
		{"https://login.microsoftonline.com/common/v2.0", "api://dns-gate"},
		{"https://login.microsoftonline.com/organizations/v2.0", "api://dns-gate"},
		{"https://login.microsoftonline.com/consumers/v2.0", "api://dns-gate"},
		{"https://login.microsoftonline.com/" + tenant, "api://dns-gate"},
		{"https://login.microsoftonline.com/" + tenant + "/v2.0", "dns-gate"},
		{"https://sts.windows.net/common/", "api://dns-gate"},
		{"https://sts.windows.net/" + tenant, "api://dns-gate"},
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
		return strings.Replace(base, "audiences: [dns-gate]", "audiences: [dns-gate]\n    "+extra, 1)
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

func TestProviders(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	c, err := Parse([]byte(base), e)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Providers[0]
	if p.Zones.Refresh.D() != time.Hour || strings.Join(p.Zones.Include, ",") != "*" || p.EuroDNS.BaseURL != "https://rest-api.eurodns.com" ||
		p.EuroDNS.Rate.Burst != 5 || *p.EuroDNS.MaxRetries != 3 {
		t.Fatalf("defaults: %+v %+v", p, p.EuroDNS)
	}
	// Zones may all come from the policy: the accounts are always listed.
	noZones := strings.Replace(base, "zones: [example.com]\n", "", 1)
	if _, err := Parse([]byte(noZones), e); err != nil {
		t.Fatal(err)
	}

	two := strings.Replace(base, "    eurodns: {app_id: app}\n", `    zones: {include: ["*.com"], exclude: ["*.Internal.COM."]}
    eurodns: {app_id: app}
  - id: route53-main
    kind: route53
    zones: {include: ["*.fr"]}
    route53:
      region: eu-west-3
      assume_role_arn: arn:aws:iam::123456789012:role/dns-gate
      external_id: x
      hosted_zones: {"Example.FR.": Z123ABC}
  - id: eu-2
    kind: eurodns
    zones: {include: ["*.net"]}
    eurodns: {app_id: other}
`, 1)
	c, err = Parse([]byte(two), env(map[string]string{"EURODNS_API_KEY": "k", "EURODNS_EU_2_API_KEY": "k2", "EURODNS_EU_2_APP_ID": "app2"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Providers[0].Zones.Exclude[0] != "*.internal.com" || c.Providers[1].Route53.HostedZones["example.fr"] != "Z123ABC" {
		t.Fatalf("normalization: %+v %+v", c.Providers[0].Zones, c.Providers[1].Route53)
	}
	if c.Providers[2].EuroDNS.APIKey != "k2" || c.Providers[2].EuroDNS.AppID != "app2" || c.Providers[0].EuroDNS.APIKey != "k" {
		t.Fatalf("per-provider credentials: %+v %+v", c.Providers[2].EuroDNS, c.Providers[0].EuroDNS)
	}
	if got := strings.Join(c.ProvidersFor("example.fr"), ","); got != "route53-main" {
		t.Fatalf("providers for example.fr: %s", got)
	}
	if len(c.ProvidersFor("a.internal.com")) != 0 {
		t.Fatal("exclude must win over include")
	}

	for name, doc := range map[string]string{
		"no provider":       strings.Replace(base, "providers:\n  - id: eurodns\n    kind: eurodns\n    eurodns: {app_id: app}\n", "", 1),
		"refresh too short": strings.Replace(base, "    kind: eurodns\n", "    kind: eurodns\n    zones: {refresh: 1m}\n", 1),
		"bad glob":          strings.Replace(base, "    kind: eurodns\n", "    kind: eurodns\n    zones: {include: [\"a?b.com\"]}\n", 1),
		"unknown field":     strings.Replace(base, "    kind: eurodns\n", "    kind: eurodns\n    zones: {interval: 1h}\n", 1),
		"unknown kind":      strings.Replace(base, "kind: eurodns", "kind: cloudflare", 1),
		"bad id":            strings.Replace(base, "id: eurodns", "id: EuroDNS", 1),
		"missing block":     strings.Replace(base, "    eurodns: {app_id: app}\n", "", 1),
		"wrong block":       strings.Replace(base, "    eurodns: {app_id: app}\n", "    eurodns: {app_id: app}\n    route53: {}\n", 1),
		"zone not served":   strings.Replace(base, "    kind: eurodns\n", "    kind: eurodns\n    zones: {include: [\"*.fr\"]}\n", 1),
		"duplicate id":      strings.Replace(two, "id: eu-2", "id: eurodns", 1),
		"bad hosted zone":   strings.Replace(two, "Z123ABC", "not an id", 1),
		"hosted zone excl":  strings.Replace(two, "Example.FR.", "example.de", 1),
		"bad role":          strings.Replace(two, "arn:aws:iam::123456789012:role/dns-gate", "dns-gate", 1),
		"bad region":        strings.Replace(two, "eu-west-3", "paris", 1),
		"http base url":     strings.Replace(base, "eurodns: {app_id: app}", "eurodns: {app_id: app, base_url: \"http://api.example.net\"}", 1),
	} {
		if _, err := Parse([]byte(doc), env(map[string]string{"EURODNS_API_KEY": "k", "EURODNS_EU_2_API_KEY": "k2"})); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Parse([]byte(base), env(nil)); err == nil || !strings.Contains(err.Error(), "EURODNS_EURODNS_API_KEY") {
		t.Fatalf("missing key: %v", err)
	}
}

func TestBindingTeamFrom(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	from := strings.Replace(base, "    team: web\n", "    team_from: {claim: sub, regex: \"^repo:acme/([a-z0-9-]+):.*$\", prefix: gh-}\n", 1)
	c, err := Parse([]byte(from), e)
	if err != nil {
		t.Fatal(err)
	}
	if tf := c.Bindings[0].TeamFrom; tf == nil || tf.Claim != "sub" || tf.Prefix != "gh-" {
		t.Fatalf("team_from: %+v", tf)
	}
	for name, doc := range map[string]string{
		"with team":    strings.Replace(base, "    team: web\n", "    team: web\n    team_from: {claim: sub, regex: \"^(.+)$\"}\n", 1),
		"unanchored":   strings.Replace(from, `"^repo:acme/([a-z0-9-]+):.*$"`, `"repo:acme/([a-z0-9-]+)"`, 1),
		"two captures": strings.Replace(from, `"^repo:acme/([a-z0-9-]+):.*$"`, `"^repo:(acme)/([a-z0-9-]+):.*$"`, 1),
		"bad prefix":   strings.Replace(from, "prefix: gh-", "prefix: \"GH \"", 1),
		"no claim":     strings.Replace(from, "claim: sub, ", "", 1),
	} {
		if _, err := Parse([]byte(doc), e); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// Issuer names used by internal subjects (API keys, virtual keys, the
// gate's own actors) are reserved: an OIDC issuer named like them would
// share their subject ids.
func TestReservedIssuerNames(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	for _, name := range []string{"api-key", "virtual-key", "gate"} {
		doc := strings.ReplaceAll(base, "issuer: ci", "issuer: "+name)
		doc = strings.Replace(doc, "name: ci", "name: "+name, 1)
		if _, err := Parse([]byte(doc), e); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTeamsMigration(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	c, err := Parse([]byte(base), e)
	if err != nil {
		t.Fatal(err)
	}
	if c.TeamsDeclared() || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], `team "web" is not declared`) {
		t.Fatalf("migration warning: declared=%v %q", c.TeamsDeclared(), c.Warnings)
	}
	if c.TombstoneTTL() != DefaultTombstoneTTL || c.Ownership.TransferTTL.D() != DefaultTransferTTL {
		t.Fatalf("ownership defaults: %v %v", c.TombstoneTTL(), c.Ownership.TransferTTL)
	}
}

func TestTeamsBlock(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	teams := "teams:\n  web:\n    description: Web shop\n    members:\n      groups: [devs]\n      subjects:\n        - issuer: ci\n          claims: {sub: \"repo:acme/web:*\"}\n" +
		"groups:\n  devs:\n    members:\n      - issuer: ci\n        claims: {sub: \"user:*\"}\n"
	byTeam := strings.Replace(base, "    subjects:\n      - issuer: ci\n        claims: {sub: \"repo:acme/web:*\"}\n", "", 1) + teams
	c, err := Parse([]byte(byTeam), e)
	if err != nil {
		t.Fatal(err)
	}
	if !c.TeamsDeclared() || len(c.Warnings) != 0 || c.Teams["web"].Description != "Web shop" {
		t.Fatalf("teams: %+v %q", c.Teams, c.Warnings)
	}
	off, err := Parse([]byte(byTeam+"ownership: {tombstone_ttl: 0s, transfer_ttl: 48h}\n"), e)
	if err != nil || off.TombstoneTTL() != 0 || off.Ownership.TransferTTL.D() != 48*time.Hour {
		t.Fatalf("ownership settings: %v", err)
	}
	for name, doc := range map[string]string{
		"undeclared binding team": strings.Replace(byTeam, "    team: web\n", "    team: wbe\n", 1),
		"undeclared key team":     byTeam + "virtual_keys:\n  - {id: k, app_id: vk-k, key_sha256: " + strings.Repeat("0", 64) + ", roles: [writer], teams: [other]}\n",
		"team without members":    strings.Replace(byTeam, "    members:\n      groups: [devs]\n      subjects:\n        - issuer: ci\n          claims: {sub: \"repo:acme/web:*\"}\n", "", 1),
		"unknown member group":    strings.Replace(byTeam, "groups: [devs]", "groups: [ghost]", 1),
		"unknown member issuer":   strings.Replace(byTeam, "        - issuer: ci\n          claims", "        - issuer: nope\n          claims", 1),
		"bad team name":           strings.Replace(byTeam, "teams:\n  web:", "teams:\n  web:\n    description: x\n  Web:", 1),
		"negative tombstone ttl":  byTeam + "ownership: {tombstone_ttl: -1h}\n",
		"short transfer ttl":      byTeam + "ownership: {transfer_ttl: 1m}\n",
	} {
		if _, err := Parse([]byte(doc), e); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	empty := base + "teams: {}\n"
	if _, err := Parse([]byte(empty), e); err == nil || !strings.Contains(err.Error(), `team "web" is not declared`) {
		t.Fatalf("an empty teams block must make references strict: %v", err)
	}
}

func TestTeamFamiliesStrict(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	family := strings.Replace(base, "    team: web\n", "    team_from: {claim: sub, regex: \"^repo:acme/([a-z0-9-]+):.*$\", prefix: gh-}\n", 1) +
		"teams:\n  corporate: {description: Corporate}\n"
	if _, err := Parse([]byte(family), e); err != nil {
		t.Fatal(err)
	}
	vk := "virtual_keys:\n  - {id: k, app_id: vk-k, key_sha256: " + strings.Repeat("0", 64) + ", roles: [writer], teams: [gh-site]}\n"
	for name, doc := range map[string]string{
		"family without prefix":      strings.Replace(family, ", prefix: gh-}", "}", 1),
		"declared team in family":    family + "  gh-corporate: {description: x}\n",
		"virtual key team in family": strings.Replace(family, "teams:\n  corporate:", "teams:\n  gh-site: {}\n  corporate:", 1) + vk,
	} {
		if _, err := Parse([]byte(doc), e); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	mig := strings.Replace(family, ", prefix: gh-}", "}", 1)
	mig = mig[:strings.Index(mig, "teams:")]
	if _, err := Parse([]byte(mig), e); err != nil {
		t.Fatalf("an empty prefix stays accepted without a teams block: %v", err)
	}
}

func TestTeamClaimFamilies(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	strict := base + "teams:\n  web: {}\n"
	withClaim := strings.Replace(strict, "    audiences: [dns-gate]\n", "    audiences: [dns-gate]\n    team_claim: teams\n    team_claim_prefix: idp-\n", 1)
	if _, err := Parse([]byte(withClaim), e); err != nil {
		t.Fatal(err)
	}
	fam := func(prefix string) string {
		return "  - role: writer\n    team_from: {claim: sub, regex: \"^repo:acme/([a-z0-9-]+):.*$\", prefix: " + prefix + "}\n    subjects:\n      - issuer: ci\n        claims: {sub: \"repo:acme/*\"}\n"
	}
	addBinding := func(doc, b string) string { return strings.Replace(doc, "\nteams:", "\n"+b+"teams:", 1) }
	ok := addBinding(withClaim, fam("gh-")+fam("gh-"))
	if _, err := Parse([]byte(ok), e); err != nil {
		t.Fatalf("two bindings of one family: %v", err)
	}
	for name, doc := range map[string]string{
		"claim without prefix":          strings.Replace(withClaim, "    team_claim_prefix: idp-\n", "", 1),
		"claim family = binding family": addBinding(withClaim, fam("idp-")),
		"nested prefixes":               addBinding(withClaim, fam("gh-")+strings.Replace(fam("gh-web-"), "acme/", "acme2/", 1)),
		"bad claim prefix":              strings.Replace(withClaim, "team_claim_prefix: idp-", "team_claim_prefix: \"IDP \"", 1),
	} {
		if _, err := Parse([]byte(doc), e); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPersonIssuers(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	ok := base + "ownership: {require_second_approver: true, person_issuers: [ci], person_claims: [tid+oid, email]}\n"
	c, err := Parse([]byte(ok), e)
	if err != nil || c.Ownership.PersonIssuers[0] != "ci" {
		t.Fatalf("%v %+v", err, c)
	}
	for name, doc := range map[string]string{
		"unknown person issuer":   base + "ownership: {require_second_approver: true, person_issuers: [nope]}\n",
		"with machine approvers":  base + "ownership: {require_second_approver: true, person_issuers: [ci], machine_approvers: true}\n",
		"without second approver": base + "ownership: {person_issuers: [ci]}\n",
		"broken composite claim":  base + "ownership: {person_claims: [tid+]}\n",
	} {
		if _, err := Parse([]byte(doc), e); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSecondApproverNeedsPersonIssuers(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	human := strings.Replace(base, "    audiences: [dns-gate]\n", "    audiences: [dns-gate]\n    category: human\n", 1)
	second := "  - name: other\n    issuer: https://idp.example.org\n    audiences: [dns-gate]\n    category_claim: idtyp\n    category_map: {user: human}\nroles:"
	two := strings.Replace(human, "roles:", second, 1) + "ownership: {require_second_approver: true}\n"
	if _, err := Parse([]byte(two), e); err == nil || !strings.Contains(err.Error(), "person_issuers") {
		t.Fatalf("two human issuers without person_issuers: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(two, "require_second_approver: true", "require_second_approver: true, person_issuers: [other]", 1)), e); err != nil {
		t.Fatalf("explicit person issuer: %v", err)
	}
	one, err := Parse([]byte(human+"ownership: {require_second_approver: true}\n"), e)
	if err != nil || len(one.Ownership.PersonIssuers) != 1 || one.Ownership.PersonIssuers[0] != "ci" {
		t.Fatalf("the only human issuer becomes the person issuer: %v %+v", err, one)
	}
	if !strings.Contains(strings.Join(one.Warnings, "\n"), "person_issuers") {
		t.Fatalf("the implicit person issuer is not explained: %q", one.Warnings)
	}
	if _, err := Parse([]byte(base+"ownership: {require_second_approver: true}\n"), e); err == nil || !strings.Contains(err.Error(), "human") {
		t.Fatalf("no issuer yields humans: %v", err)
	}
}

func TestTeamFamilyFromOneIssuer(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	issuer := "  - name: other\n    issuer: https://idp.example.org\n    audiences: [dns-gate]\nroles:"
	fam := func(issuer string) string {
		return "  - role: writer\n    team_from: {claim: sub, regex: \"^repo:acme/([a-z0-9-]+):.*$\", prefix: gh-}\n    subjects:\n      - issuer: " + issuer + "\n        claims: {sub: \"repo:acme/*\"}\n"
	}
	doc := strings.Replace(base, "roles:", issuer, 1) + fam("ci") + fam("other")
	if _, err := Parse([]byte(doc), e); err != nil {
		t.Fatalf("migration mode: %v", err)
	}
	if _, err := Parse([]byte(doc+"teams:\n  web: {}\n"), e); err == nil || !strings.Contains(err.Error(), "several issuers") {
		t.Fatalf("one family fed by two issuers: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(base, "roles:", issuer, 1)+fam("ci")+fam("ci")+"teams:\n  web: {}\n"), e); err != nil {
		t.Fatalf("one family, one issuer: %v", err)
	}
}

func TestZoneProfileGrantWarning(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	roles := `roles:
  profiles:
    rules:
      - zones: ["*"]
        actions: [dns.zone.profile]
  narrow:
    rules:
      - zones: [example.com]
        actions: [dns.zone.profile]
`
	doc := strings.Replace(base, "eurodns: {app_id: app}", "eurodns: {app_id: app, zone_profiles: true}", 1)
	c, err := Parse([]byte(strings.Replace(doc, "roles:\n", roles, 1)), e)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, w := range c.Warnings {
		if strings.Contains(w, "dns.zone.profile") {
			n++
			if !strings.Contains(w, "roles.narrow") {
				t.Errorf("warning on the wrong role: %s", w)
			}
		}
	}
	if n != 1 {
		t.Fatalf("warnings: %q", c.Warnings)
	}
}

func TestZoneProfileGrantWarningGlobs(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	roles := `roles:
  stars:
    rules:
      - zones: ["**"]
        actions: [dns.zone.profile]
  com:
    rules:
      - zones: ["*.com"]
        actions: [dns.zone.profile]
`
	c, err := Parse([]byte(strings.Replace(base, "roles:\n", roles, 1)), e)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(c.Warnings, "\n")
	if strings.Contains(w, "roles.stars") || !strings.Contains(w, "roles.com") || !strings.Contains(w, "no eurodns provider sets zone_profiles") {
		t.Fatalf("warnings: %q", c.Warnings)
	}
}

func TestEuroDNSZoneProfilesOptIn(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	c, err := Parse([]byte(base), e)
	if err != nil {
		t.Fatal(err)
	}
	if c.Providers[0].EuroDNS.ZoneProfiles {
		t.Fatal("zone profiles enabled by default")
	}
	c, err = Parse([]byte(strings.Replace(base, "eurodns: {app_id: app}", "eurodns: {app_id: app, zone_profiles: true}", 1)), e)
	if err != nil || !c.Providers[0].EuroDNS.ZoneProfiles {
		t.Fatalf("zone_profiles: %v", err)
	}
}

func TestAuditConfig(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "x"})
	c, err := Parse([]byte(base), e)
	if err != nil || c.Audit.Format != AuditNative || c.Audit.HashChain {
		t.Fatalf("default: %+v %v", c.Audit, err)
	}
	c, err = Parse([]byte(base+"\naudit: {format: ocsf, hash_chain: true}\n"), e)
	if err != nil || c.Audit.Format != AuditOCSF || !c.Audit.HashChain {
		t.Fatalf("ocsf: %+v %v", c.Audit, err)
	}
	if _, err := Parse([]byte(base+"\naudit: {format: cef}\n"), e); err == nil || !strings.Contains(err.Error(), "audit.format") {
		t.Fatalf("unknown format: %v", err)
	}
}

func TestFolders(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	groups := "\ngroups:\n  admins:\n    members:\n      - issuer: ci\n        claims: {roles: [Gate.PolicyAdmin]}\n"
	ok := strings.Replace(base, "      - zones: [example.com]\n", "      - folders: [\"/ES\", \"/ES/**\"]\n", 1)
	ok = strings.Replace(ok, "    kind: eurodns\n", "    kind: eurodns\n    zones: {folders: [\"/ES/**\", \"/\"]}\n", 1) + groups + `policy:
  editable: true
  bounds: {zones: ["*"], folders: ["/ES/**"], actions: [dns.read, dns.record.write]}
  delegations:
    - name: es
      subjects: [{issuer: ci, claims: {sub: "repo:acme/gate:*"}}]
      allow: {zones: ["*"], folders: ["/ES/Madrid/**"], actions: [dns.record.write], binding_subjects: [{issuer: ci, claims: {sub: "repo:acme/*"}}], teams: {names: [web]}}
`
	c, err := Parse([]byte(ok), e)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Roles["writer"].Rules[0].Folders, ","); got != "/ES,/ES/**" || strings.Join(c.Providers[0].Zones.Folders, ",") != "/ES/**,/" {
		t.Fatalf("folders: %q %+v", got, c.Providers[0].Zones)
	}
	if z := c.Providers[0].Zones; z.FolderExpiry != DefaultFolderExpiry || z.FolderMaxAge() != 3*time.Hour {
		t.Fatalf("folder expiry: %+v", z)
	}
	route53 := `  - id: r53
    kind: route53
    zones: {include: ["*.fr"], folders: ["/ES"]}
    route53: {region: eu-west-3}
`
	for name, doc := range map[string]string{
		"rule without zones nor folders": strings.Replace(ok, "      - folders: [\"/ES\", \"/ES/**\"]\n        actions", "      - actions", 1),
		"relative folder":                strings.Replace(ok, "folders: [\"/ES\", \"/ES/**\"]", "folders: [\"ES\"]", 1),
		"partial double star":            strings.Replace(ok, "folders: [\"/ES\", \"/ES/**\"]", "folders: [\"/ES/a**\"]", 1),
		"bad provider folder":            strings.Replace(ok, "zones: {folders: [\"/ES/**\", \"/\"]}", "zones: {folders: [\"/ES/\"]}", 1),
		"route53 folders":                strings.Replace(ok, "providers:\n", "providers:\n"+route53, 1),
		"bad folder expiry":              strings.Replace(ok, "zones: {folders: [\"/ES/**\", \"/\"]}", "zones: {folders: [\"/ES/**\", \"/\"], folder_expiry: 1}", 1),
		"bad bounds folder":              strings.Replace(ok, "folders: [\"/ES/**\"], actions", "folders: [\"/ES?\"], actions", 1),
		"allow outside bounds":           strings.Replace(ok, "folders: [\"/ES/Madrid/**\"]", "folders: [\"/FR\"]", 1),
		"bounds folders without zones":   strings.Replace(ok, "bounds: {zones: [\"*\"], ", "bounds: {", 1),
		"allow folders without zones":    strings.Replace(ok, "allow: {zones: [\"*\"], ", "allow: {", 1),
	} {
		if _, err := Parse([]byte(doc), e); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestFolderWarnings(t *testing.T) {
	e := env(map[string]string{"EURODNS_API_KEY": "k"})
	fw := func(c *Config) []string {
		var out []string
		for _, w := range c.Warnings {
			if strings.Contains(w, "folder") {
				out = append(out, w)
			}
		}
		return out
	}
	rules := strings.Replace(base, "      - zones: [example.com]\n", "      - zones: [example.com]\n        folders: [\"/IT/**\"]\n", 1)
	c, err := Parse([]byte(rules), e)
	if err != nil {
		t.Fatal(err)
	}
	if len(fw(c)) != 0 {
		t.Fatalf("every folder is reachable without a folder filter: %q", fw(c))
	}
	filtered := strings.Replace(rules, "    kind: eurodns\n", "    kind: eurodns\n    zones: {folders: [\"/ES\", \"/ES/**\"]}\n", 1)
	if c, err = Parse([]byte(filtered), e); err != nil {
		t.Fatal(err)
	}
	if len(fw(c)) != 1 || !strings.Contains(fw(c)[0], `roles.writer.rules[0].folders: "/IT/**" is outside the zones.folders`) {
		t.Fatalf("unreachable folder: %q", fw(c))
	}
	if c, err = Parse([]byte(strings.Replace(filtered, `"/IT/**"`, `"/ES/Madrid"`, 1)), e); err != nil || len(fw(c)) != 0 {
		t.Fatalf("reachable folder: %v %q", err, fw(c))
	}
	r53 := strings.Replace(rules, "    kind: eurodns\n    eurodns: {app_id: app}\n", "    kind: route53\n    route53: {region: eu-west-3}\n", 1)
	if c, err = Parse([]byte(r53), env(nil)); err != nil {
		t.Fatal(err)
	}
	if len(fw(c)) != 1 || !strings.Contains(fw(c)[0], "no EuroDNS provider") {
		t.Fatalf("no EuroDNS provider: %q", fw(c))
	}
}

func TestAuditChainKey(t *testing.T) {
	key := strings.Repeat("ab", 32)
	c, err := Parse([]byte(base+"\naudit: {hash_chain: true}\n"), env(map[string]string{"EURODNS_API_KEY": "x", EnvAuditChainKey: key}))
	if err != nil || len(c.Audit.HashChainKey) != 32 {
		t.Fatalf("key: %v", err)
	}
	if _, err := Parse([]byte(base), env(map[string]string{"EURODNS_API_KEY": "x", EnvAuditChainKey: key})); err == nil || !strings.Contains(err.Error(), "hash_chain") {
		t.Fatalf("key without chain: %v", err)
	}
	if _, err := Parse([]byte(base+"\naudit: {hash_chain: true}\n"), env(map[string]string{"EURODNS_API_KEY": "x", EnvAuditChainKey: "short"})); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := Parse([]byte(base+"\naudit: {hash_chain_key: x}\n"), env(map[string]string{"EURODNS_API_KEY": "x"})); err == nil {
		t.Fatal("key in the file accepted")
	}
}

func TestForwardWriteWithoutHostsWarns(t *testing.T) {
	c := &Config{Roles: map[string]Role{
		"wide":   {Rules: []Rule{{Zones: []string{"example.com"}, Actions: []string{"dns.forward.write"}, Records: &RecordScope{Types: []string{"CNAME"}}}}},
		"scoped": {Rules: []Rule{{Zones: []string{"example.com"}, Actions: []string{"dns.forward.write"}, Records: &RecordScope{Hosts: []string{"go"}, Types: []string{"CNAME"}}}}},
	}}
	w := c.forwardWarnings()
	if len(w) != 1 || !strings.Contains(w[0], "roles.wide.rules[0]") {
		t.Fatalf("warnings %q", w)
	}
}

func TestPropagation(t *testing.T) {
	key := env(map[string]string{"EURODNS_API_KEY": "k"})
	c, err := Parse([]byte(base), key)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Propagation
	if !p.On() || len(p.Resolvers) != 0 || p.QueryTimeout.D() != 1500*time.Millisecond || p.Timeout.D() != 4*time.Second ||
		p.Concurrency != 16 || p.CacheTTL.D() != 10*time.Second || p.RequestsPerMinute != 30 || p.MaxInFlight != 3 {
		t.Fatalf("defaults: %+v", p)
	}
	c, err = Parse([]byte(base+`propagation:
  enabled: false
  allow_private_resolvers: true
  resolvers:
    - {name: Corp, address: 10.0.0.53, location: Paris, country: FR, region: europe, filtering: true}
    - {name: Lab, address: "[2001:db8::53]:5353"}
`), key)
	if err != nil {
		t.Fatal(err)
	}
	if c.Propagation.On() || len(c.Propagation.Resolvers) != 2 || c.Propagation.Resolvers[0].Location != "Paris" || !c.Propagation.Resolvers[0].Filtering {
		t.Fatalf("parsed: %+v", c.Propagation)
	}
	lambda := env(map[string]string{"EURODNS_API_KEY": "k", EnvLambdaRuntime: "127.0.0.1:9001"})
	dynamo := base + "store: {type: dynamodb, dynamodb: {table: gate}}\n"
	if c, err := Parse([]byte(dynamo), lambda); err != nil || c.Propagation.On() {
		t.Fatalf("Lambda default: %v %v", err, c != nil && c.Propagation.On())
	}
	if c, err := Parse([]byte(dynamo+"propagation: {enabled: true}\n"), lambda); err != nil || !c.Propagation.On() {
		t.Fatalf("Lambda opt-in: %v", err)
	}
	for name, doc := range map[string]string{
		"host name":      "propagation: {resolvers: [{name: a, address: dns.google}]}\n",
		"no name":        "propagation: {resolvers: [{address: 1.1.1.1}]}\n",
		"duplicate":      "propagation: {resolvers: [{name: a, address: 1.1.1.1}, {name: a, address: 8.8.8.8}]}\n",
		"port zero":      "propagation: {resolvers: [{name: a, address: \"1.1.1.1:0\"}]}\n",
		"query timeout":  "propagation: {query_timeout: 20s}\n",
		"timeout":        "propagation: {query_timeout: 3s, timeout: 2s}\n",
		"concurrency":    "propagation: {concurrency: 100}\n",
		"cache":          "propagation: {cache_ttl: 1h}\n",
		"rate":           "propagation: {requests_per_minute: 1000}\n",
		"long timeout":   "propagation: {timeout: 6s}\n",
		"in flight":      "propagation: {max_in_flight: 65}\n",
		"private":        "propagation: {resolvers: [{name: a, address: 10.0.0.2}]}\n",
		"loopback":       "propagation: {resolvers: [{name: a, address: \"127.0.0.1:5353\"}]}\n",
		"link-local":     "propagation: {resolvers: [{name: a, address: \"fe80::1\"}]}\n",
		"nat64 private":  "propagation: {resolvers: [{name: a, address: \"64:ff9b::a00:1\"}]}\n",
		"unknown option": "propagation: {resolver: []}\n",
	} {
		if _, err := Parse([]byte(base+doc), key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
