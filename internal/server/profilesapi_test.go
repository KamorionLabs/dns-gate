package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/eurodnsapi"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/provider/eurodns/profiletest"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

const testProfile = `{"name":"transfer-example","records":[{"type":"A","host":"@","ttl":3600,"rdata":"192.0.2.10"},{"type":"MX","host":"@","ttl":3600,"rdata":"10 mx.example.net."}],"urlForwards":[],"mailForwards":[{"source":"*","destination":"ops@example.net"}]}`

type otherKind struct {
	provider.Provider
	id string
}

func (o otherKind) ID() string   { return o.id }
func (o otherKind) Kind() string { return "route53" }

// profileEnv is the test server with a zone profile fake behind a EuroDNS
// provider "eurodns", the given other accounts, and the roles profiles
// (dns.zone.profile on "*", subject profiler) and narrow (on example.com
// only, subject narrow).
func profileEnv(t *testing.T, writes bool, others ...provider.Provider) (*env, *profiletest.Fake) {
	t.Helper()
	return profileEnvTweak(t, writes, nil, others...)
}

// profileEnvTweak is profileEnv with a change of the configuration.
func profileEnvTweak(t *testing.T, writes bool, tweak func(*config.Config), others ...provider.Provider) (*env, *profiletest.Fake) {
	t.Helper()
	e := newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, AllowWrites: writes, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.Issuers[0].CategoryClaim = "kind"
		c.Issuers[0].CategoryMap = map[string]string{"user": "human"}
		c.Policy.EditMaxAge = config.Duration(15 * time.Minute)
		c.Protected = []config.Protected{{Zones: []string{"*"}, Hosts: []string{"@"}, Types: []string{"NS", "CAA", "AAAA"}},
			{Zones: []string{"*"}, Hosts: []string{"login"}, Types: []string{"CNAME"}},
			{Zones: []string{"example.com"}, Hosts: []string{"_dmarc"}, Types: []string{"TXT"}}}
		c.Roles["profiles"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{policy.ActionZoneProfile}}}}
		c.Roles["narrow"] = config.Role{Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{policy.ActionZoneProfile, policy.ActionUIRead}}}}
		c.Bindings = append(c.Bindings,
			config.Binding{Role: "profiles", Team: "ops", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"profiler"}}}}},
			config.Binding{Role: "narrow", Team: "web", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"narrow"}}}}},
			config.Binding{Role: "admin", Team: "ops", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"profile-auditor"}}}}},
			config.Binding{Role: "profiles", Team: "ops", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"profile-auditor"}}}}})
		if tweak != nil {
			tweak(c)
		}
	})
	fake := profiletest.New()
	fake.APIKey = "upstream-secret"
	up := httptest.NewServer(fake.Wrap(nil))
	t.Cleanup(up.Close)
	client, err := eurodns.New(eurodns.WithBaseURL(up.URL), eurodns.WithAuth(eurodns.APIKeyAuth{AppID: "gate", APIKey: "upstream-secret"}),
		eurodns.WithRateLimit(time.Microsecond, 100))
	if err != nil {
		t.Fatal(err)
	}
	ep := eurodnsprov.NewWithClient("eurodns", up.URL, client)
	enabled := map[string]bool{"eurodns": true}
	for _, o := range others {
		if o.ID() != "eurodns-off" {
			enabled[o.ID()] = true
		}
	}
	e.facade.Facade = eurodnsapi.New(eurodnsapi.Config{Providers: provider.Single(ep), Accounts: append([]provider.Provider{ep}, others...), ZoneProfiles: enabled})
	e.server.profileLimiter = newSubjectLimiter(6000, e.clock)
	return e, fake
}

func (e *env) events(action string) []audit.Event {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	var out []audit.Event
	for _, ev := range e.audit.events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

func decodeJSON(t *testing.T, r *http.Response, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestZoneProfilesEuroDNSRoutes(t *testing.T) {
	e, fake := profileEnv(t, false)
	tok := e.token("profiler")

	r := e.do(t, "POST", "/zone-profiles", tok, testProfile, nil)
	var created eurodnsprov.ZoneProfile
	if r.StatusCode != 201 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("create: %d %s", r.StatusCode, b)
	}
	decodeJSON(t, r, &created)
	if created.ID == nil || created.Name != "transfer-example" || len(created.Records) != 2 {
		t.Fatalf("created: %+v", created)
	}
	id := *created.ID
	ev := e.events("createZoneProfile")
	if len(ev) != 1 || ev[0].Decision != "allow" || ev[0].Provider != "eurodns" || ev[0].Extra["profile_id"] != id || ev[0].Subject == "" {
		t.Fatalf("create audit: %+v", ev)
	}
	b, _ := json.Marshal(ev[0].Extra["profile"])
	if !strings.Contains(string(b), `"rdata":"10 mx.example.net."`) || !strings.Contains(string(b), `"destination":"ops@example.net"`) {
		t.Fatalf("audited profile: %s", b)
	}
	if strings.Contains(string(b), "upstream-secret") {
		t.Fatal("secret in the audit event")
	}

	r = e.do(t, "GET", "/zone-profiles", tok, "", map[string]string{"pagination-page": "1", "pagination-size": "10", "pagination-sortfield": "name"})
	var list []eurodnsprov.ZoneProfileSummary
	if r.StatusCode != 200 || r.Header.Get("pagination-count") != "1" || r.Header.Get("Set-Cookie") != "" {
		t.Fatalf("list: %d %v", r.StatusCode, r.Header)
	}
	decodeJSON(t, r, &list)
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("list: %+v", list)
	}
	if r = e.do(t, "GET", "/zone-profiles", tok, "", map[string]string{"pagination-size": "x"}); r.StatusCode != 400 {
		t.Fatalf("bad pagination: %d", r.StatusCode)
	}

	path := "/zone-profiles/" + itoa(id)
	if r = e.do(t, "GET", path, tok, "", nil); r.StatusCode != 200 {
		t.Fatalf("get: %d", r.StatusCode)
	}

	r = e.do(t, "POST", "/zone-profiles/check", tok, `{"name":"x","records":[{"type":"A","host":"@","ttl":60,"rdata":"192.0.2.1"}]}`, nil)
	var checked eurodnsprov.ZoneProfile
	decodeJSON(t, r, &checked)
	if r.StatusCode != 200 || checked.Report == nil || checked.Report.Valid() {
		t.Fatalf("check: %d %+v", r.StatusCode, checked.Report)
	}

	r = e.do(t, "POST", "/zone-profiles", tok, `{"name":"bad","records":[{"type":"A","host":"@","ttl":60,"rdata":"192.0.2.1"}]}`, nil)
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != 400 || !strings.Contains(string(body), "INVALID_ZONE_PROFILE") {
		t.Fatalf("invalid create: %d %s", r.StatusCode, body)
	}
	if ev := e.events("createZoneProfile"); ev[len(ev)-1].Decision != "error" || ev[len(ev)-1].Reason != "rejected" {
		t.Fatalf("rejected create audit: %+v", ev[len(ev)-1])
	}
	if r = e.do(t, "POST", "/zone-profiles", tok, `{"records":[]}`, nil); r.StatusCode != 400 || reason(t, r) != "invalid" {
		t.Fatalf("nameless create: %d", r.StatusCode)
	}

	r = e.do(t, "PUT", path, tok, `{"name":"transfer-example","records":[{"type":"A","host":"@","ttl":600,"rdata":"192.0.2.20"}]}`, nil)
	if r.StatusCode != 200 || fake.Profile(id).Records[0].RData != "192.0.2.20" {
		t.Fatalf("update: %d", r.StatusCode)
	}

	if r = e.do(t, "DELETE", path, tok, "", nil); r.StatusCode != 204 || fake.Len() != 0 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
	ev = e.events("deleteZoneProfile")
	b, _ = json.Marshal(ev[0].Extra["profile"])
	if len(ev) != 1 || ev[0].Decision != "allow" || !strings.Contains(string(b), "192.0.2.20") {
		t.Fatalf("delete audit: %+v %s", ev, b)
	}
	if r = e.do(t, "GET", path, tok, "", nil); r.StatusCode != 404 {
		t.Fatalf("get deleted: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/zone-profiles/0", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("id 0: %d", r.StatusCode)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestZoneProfilesAuthorization(t *testing.T) {
	e, fake := profileEnv(t, false)
	for _, sub := range []string{"writer", "admin", "narrow"} {
		r := e.do(t, "POST", "/zone-profiles", e.token(sub), testProfile, nil)
		if r.StatusCode != 403 || reason(t, r) != "forbidden" {
			t.Fatalf("%s create: %d", sub, r.StatusCode)
		}
		if r = e.do(t, "GET", "/api/v1/providers/eurodns/zone-profiles", e.token(sub), "", nil); r.StatusCode != 403 {
			t.Fatalf("%s list: %d", sub, r.StatusCode)
		}
	}
	if r := e.do(t, "GET", "/zone-profiles", "", "", nil); r.StatusCode != 401 {
		t.Fatalf("anonymous: %d", r.StatusCode)
	}
	if fake.Requests() != 0 {
		t.Fatalf("refused requests reached EuroDNS: %d", fake.Requests())
	}
	ev := e.events("createZoneProfile")
	if len(ev) != 3 || ev[0].Decision != "deny" || ev[0].Reason != "forbidden" {
		t.Fatalf("deny audit: %+v", ev)
	}
}

func TestZoneProfilesNeutralAPI(t *testing.T) {
	e, _ := profileEnv(t, false, otherKind{id: "aws"})
	tok := e.token("profiler")
	base := "/api/v1/providers/eurodns/zone-profiles"

	r := e.do(t, "POST", base, tok, testProfile, map[string]string{TeamHeader: "ops"})
	var created eurodnsprov.ZoneProfile
	decodeJSON(t, r, &created)
	if r.StatusCode != 201 || created.ID == nil {
		t.Fatalf("create: %d", r.StatusCode)
	}
	if ev := e.events("zone_profile.create"); len(ev) != 1 || ev[0].Extra["via"] != "api" || ev[0].Provider != "eurodns" || ev[0].Extra["profile"] == nil {
		t.Fatalf("audit: %+v", ev)
	}
	r = e.do(t, "GET", base, tok, "", nil)
	var list uiapi.ZoneProfileList
	decodeJSON(t, r, &list)
	if r.StatusCode != 200 || list.Provider != "eurodns" || len(list.Profiles) != 1 || list.Profiles[0].Name != "transfer-example" {
		t.Fatalf("list: %d %+v", r.StatusCode, list)
	}
	id := itoa(*created.ID)
	if r = e.do(t, "GET", base+"/"+id, tok, "", nil); r.StatusCode != 200 {
		t.Fatalf("get: %d", r.StatusCode)
	}
	r = e.do(t, "POST", base+"/check", tok, `{"name":"x","records":[{"type":"BOGUS","host":"@","ttl":600,"rdata":"x"}]}`, nil)
	var checked eurodnsprov.ZoneProfile
	decodeJSON(t, r, &checked)
	if r.StatusCode != 200 || checked.Report.Valid() {
		t.Fatalf("check: %d", r.StatusCode)
	}
	r = e.do(t, "PUT", base+"/"+id, tok, `{"name":"renamed","records":[{"type":"BOGUS","host":"@","ttl":600,"rdata":"x"}]}`, nil)
	if r.StatusCode != 400 || reason(t, r) != "rejected" {
		t.Fatalf("rejected update: %d", r.StatusCode)
	}
	if r = e.do(t, "PUT", base+"/"+id, tok, `{"name":"renamed","records":[]}`, nil); r.StatusCode != 200 {
		t.Fatalf("update: %d", r.StatusCode)
	}
	if r = e.do(t, "DELETE", base+"/"+id, tok, "", nil); r.StatusCode != 204 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
	if r = e.do(t, "DELETE", base+"/"+id, tok, "", nil); r.StatusCode != 404 || reason(t, r) != "not_found" {
		t.Fatalf("delete again: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", base+"/abc", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("bad id: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/api/v1/providers/nope/zone-profiles", tok, "", nil); r.StatusCode != 404 {
		t.Fatalf("unknown provider: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/api/v1/providers/aws/zone-profiles", tok, "", nil); r.StatusCode != 400 || reason(t, r) != "invalid_provider" {
		t.Fatalf("route53 provider: %d", r.StatusCode)
	}
	if r = e.do(t, "PATCH", base, tok, "", nil); r.StatusCode != 405 {
		t.Fatalf("method: %d", r.StatusCode)
	}
}

func TestZoneProfilesSeveralAccounts(t *testing.T) {
	c, err := eurodns.New(eurodns.WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	other := eurodnsprov.NewWithClient("eurodns-b", "http://127.0.0.1:1", c)
	e, _ := profileEnv(t, false, other)
	tok := e.token("profiler")
	r := e.do(t, "GET", "/zone-profiles", tok, "", nil)
	if r.StatusCode != 400 || !strings.Contains(readAll(r), eurodnsapi.ProviderHeader) {
		t.Fatalf("ambiguous: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/zone-profiles", tok, "", map[string]string{eurodnsapi.ProviderHeader: "eurodns"}); r.StatusCode != 200 {
		t.Fatalf("named provider: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/zone-profiles", tok, "", map[string]string{eurodnsapi.ProviderHeader: "Bad Provider!"}); r.StatusCode != 400 {
		t.Fatalf("malformed provider header: %d", r.StatusCode)
	}
}

func readAll(r *http.Response) string { b, _ := io.ReadAll(r.Body); return string(b) }

func profileJSON(p any) string { b, _ := json.Marshal(p); return string(b) }

func TestMCPZoneProfiles(t *testing.T) {
	e, fake := profileEnv(t, false)
	cs := connect(t, e, e.token("profiler"))
	tools := toolNames(t, cs)
	for _, n := range []string{"list_zone_profiles", "get_zone_profile", "check_zone_profile"} {
		if tools[n] == nil || !tools[n].Annotations.ReadOnlyHint {
			t.Errorf("read tool %s missing or not read-only", n)
		}
	}
	if tools["create_zone_profile"] != nil || tools["delete_zone_profile"] != nil {
		t.Fatal("profile write tools exposed without allow_writes")
	}
	var chk profileOut
	res := call(t, cs, "check_zone_profile", map[string]any{"name": "x", "records": []map[string]any{{"type": "A", "host": "@", "ttl": 60, "rdata": "192.0.2.1"}}}, &chk)
	if res.IsError || chk.Valid == nil || *chk.Valid || chk.Provider != "eurodns" {
		t.Fatalf("check: %s %+v", errText(res), chk)
	}

	e, fake = profileEnv(t, true)
	cs = connect(t, e, e.token("profiler"))
	var created profileOut
	res = call(t, cs, "create_zone_profile", map[string]any{"name": "transfer-example",
		"records":       []map[string]any{{"type": "A", "host": "@", "ttl": 3600, "rdata": "192.0.2.10"}},
		"mail_forwards": []map[string]any{{"source": "*", "destination": "ops@example.net"}}}, &created)
	if res.IsError || fake.Len() != 1 {
		t.Fatalf("create: %s", errText(res))
	}
	var list profileListOut
	if res = call(t, cs, "list_zone_profiles", map[string]any{}, &list); res.IsError || len(list.Profiles) != 1 {
		t.Fatalf("list: %s %+v", errText(res), list)
	}
	id := list.Profiles[0].ID
	var got profileOut
	if res = call(t, cs, "get_zone_profile", map[string]any{"id": id}, &got); res.IsError || !strings.Contains(profileJSON(got.Profile), "ops@example.net") {
		t.Fatalf("get: %s %+v", errText(res), got)
	}
	if res = call(t, cs, "update_zone_profile", map[string]any{"id": id, "name": "renamed", "records": []map[string]any{}}, nil); res.IsError || fake.Profile(id).Name != "renamed" {
		t.Fatalf("update: %s", errText(res))
	}
	if res = call(t, cs, "delete_zone_profile", map[string]any{"id": id}, nil); res.IsError || fake.Len() != 0 {
		t.Fatalf("delete: %s", errText(res))
	}
	if ev := e.events("mcp.delete_zone_profile"); len(ev) != 1 || ev[0].Extra["via"] != "mcp" || ev[0].Extra["profile"] == nil {
		t.Fatalf("mcp audit: %+v", ev)
	}

	cs = connect(t, e, e.token("writer"))
	if res = call(t, cs, "list_zone_profiles", map[string]any{}, nil); !res.IsError || !strings.Contains(errText(res), "forbidden") {
		t.Fatalf("writer list: %s", errText(res))
	}
}

// humanToken is a token of a human subject who logged in age ago.
func (e *env) humanToken(sub string, age time.Duration) string {
	return e.idp.Sign(map[string]any{"sub": sub, "aud": "dns-gate", "kind": "user", "auth_time": time.Now().Add(-age).Unix()})
}

func TestZoneProfilesStepUp(t *testing.T) {
	e, fake := profileEnv(t, true)
	old := e.humanToken("profiler", time.Hour)
	base := "/api/v1/providers/eurodns/zone-profiles"
	if r := e.do(t, "POST", base, old, testProfile, nil); r.StatusCode != 403 || reason(t, r) != "reauth_required" {
		t.Fatalf("REST create with an old login: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/zone-profiles", old, testProfile, nil); r.StatusCode != 403 || reason(t, r) != "reauth_required" {
		t.Fatalf("EuroDNS create with an old login: %d", r.StatusCode)
	}
	cs := connect(t, e, old)
	if res := call(t, cs, "create_zone_profile", map[string]any{"name": "x", "records": []map[string]any{}}, nil); !res.IsError || !strings.Contains(errText(res), "reauth_required") {
		t.Fatalf("MCP create with an old login: %s", errText(res))
	}
	if fake.Len() != 0 {
		t.Fatal("a profile was created without a recent login")
	}
	if ev := e.events("zone_profile.create"); len(ev) != 1 || ev[0].Decision != "deny" || ev[0].Reason != "reauth_required" {
		t.Fatalf("step-up audit: %+v", ev)
	}
	if r := e.do(t, "GET", base, old, "", nil); r.StatusCode != 200 {
		t.Fatalf("read with an old login: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", base+"/check", old, testProfile, nil); r.StatusCode != 200 {
		t.Fatalf("check with an old login: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", base, e.humanToken("profiler", time.Minute), testProfile, nil); r.StatusCode != 201 {
		t.Fatalf("create with a recent login: %d", r.StatusCode)
	}
}

func TestZoneProfilesProtectedRecords(t *testing.T) {
	e, fake := profileEnv(t, false)
	tok := e.token("profiler")
	base := "/api/v1/providers/eurodns/zone-profiles"
	r := e.do(t, "POST", base, tok, testProfile, nil)
	var created eurodnsprov.ZoneProfile
	decodeJSON(t, r, &created)
	id := itoa(*created.ID)
	for _, rec := range []string{
		`{"type":"NS","host":"@","ttl":3600,"rdata":"ns1.attacker.example."}`,
		`{"type":"caa","host":"","ttl":3600,"rdata":"0 issue \"ca.example\""}`,
		`{"type":"TXT","host":"_dmarc","ttl":3600,"rdata":"v=DMARC1; p=none"}`,
	} {
		body := `{"name":"p","records":[` + rec + `]}`
		for _, c := range []struct{ method, path string }{{"POST", base}, {"POST", base + "/check"}, {"PUT", base + "/" + id}, {"POST", "/zone-profiles"}} {
			if r := e.do(t, c.method, c.path, tok, body, nil); r.StatusCode != 403 || reason(t, r) != "protected" {
				t.Fatalf("%s %s %s: %d", c.method, c.path, rec, r.StatusCode)
			}
		}
	}
	if fake.Len() != 1 || fake.Profile(*created.ID).Name != "transfer-example" {
		t.Fatal("a protected record reached EuroDNS")
	}
	if ev := e.events("zone_profile.check"); len(ev) == 0 || ev[0].Decision != "deny" || ev[0].Reason != "protected" {
		t.Fatalf("protected audit: %+v", ev)
	}
}

func TestZoneProfileUpdateAuditsPrevious(t *testing.T) {
	e, _ := profileEnv(t, false)
	tok := e.token("profiler")
	base := "/api/v1/providers/eurodns/zone-profiles"
	r := e.do(t, "POST", base, tok, testProfile, nil)
	var created eurodnsprov.ZoneProfile
	decodeJSON(t, r, &created)
	upd := `{"name":"transfer-example","records":[{"type":"A","host":"@","ttl":600,"rdata":"192.0.2.20"},{"type":"TXT","host":"@","ttl":600,"rdata":"v=spf1 -all"}]}`
	if r = e.do(t, "PUT", base+"/"+itoa(*created.ID), tok, upd, nil); r.StatusCode != 200 {
		t.Fatalf("update: %d", r.StatusCode)
	}
	ev := e.events("zone_profile.update")
	if len(ev) != 1 {
		t.Fatalf("update audit: %+v", ev)
	}
	prev, _ := json.Marshal(ev[0].Extra["previous"])
	if !strings.Contains(string(prev), "192.0.2.10") || !strings.Contains(string(prev), "ops@example.net") {
		t.Fatalf("previous content: %s", prev)
	}
	ops := map[string]string{}
	for _, c := range ev[0].Changes {
		ops[c.Host+" "+c.Type] = c.Op
	}
	if ops["@ A"] != "update" || ops["@ MX"] != "delete" || ops["@ TXT"] != "create" || len(ops) != 3 {
		t.Fatalf("changes: %+v", ev[0].Changes)
	}
	if ev := e.events("zone_profile.create"); len(ev[0].Changes) != 2 {
		t.Fatalf("create changes: %+v", ev[0].Changes)
	}
	for _, c := range ev[0].Changes {
		if c.OldValues != nil || c.NewValues != nil || c.OldTTL != 0 || c.NewTTL != 0 {
			t.Fatalf("record values in the journal changes: %+v", c)
		}
	}
}

func TestZoneProfilesProviderOptIn(t *testing.T) {
	c, err := eurodns.New(eurodns.WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	off := eurodnsprov.NewWithClient("eurodns-off", "http://127.0.0.1:1", c)
	e, _ := profileEnv(t, false, off)
	tok := e.token("profiler")
	if r := e.do(t, "GET", "/api/v1/providers/eurodns-off/zone-profiles", tok, "", nil); r.StatusCode != 403 || reason(t, r) != "zone_profiles_disabled" {
		t.Fatalf("disabled provider: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/zone-profiles", tok, "", nil); r.StatusCode != 200 {
		t.Fatalf("the only enabled provider is the default: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/zone-profiles", tok, "", map[string]string{eurodnsapi.ProviderHeader: "eurodns-off"}); r.StatusCode != 403 {
		t.Fatalf("disabled provider by header: %d", r.StatusCode)
	}
}

func TestZoneProfilesRateLimit(t *testing.T) {
	e, _ := profileEnv(t, false)
	e.server.profileLimiter = newSubjectLimiter(4, e.clock)
	tok := e.token("profiler")
	var last int
	for range 8 {
		last = e.do(t, "GET", "/api/v1/providers/eurodns/zone-profiles", tok, "", nil).StatusCode
	}
	if last != 429 {
		t.Fatalf("no per-subject limit: %d", last)
	}
	if r := e.do(t, "GET", "/zone-profiles", e.token("profiler"), "", nil); r.StatusCode != 429 || reason(t, r) != "rate_limited" {
		t.Fatalf("limit shared by the EuroDNS routes: %d", r.StatusCode)
	}
	e.server.profileLimiter = newSubjectLimiter(6000, e.clock)
	if r := e.do(t, "GET", "/zone-profiles", tok, "", map[string]string{"pagination-size": "500"}); r.StatusCode != 400 {
		t.Fatalf("oversized page: %d", r.StatusCode)
	}
}

func TestZoneProfilesBadRequestsAudited(t *testing.T) {
	e, _ := profileEnv(t, false)
	tok := e.token("profiler")
	cases := []struct{ method, path, body, action string }{
		{"GET", "/api/v1/providers/eurodns/zone-profiles/abc", "", "zone_profile.get"},
		{"POST", "/api/v1/providers/eurodns/zone-profiles", "{bad", "zone_profile.create"},
		{"GET", "/api/v1/providers/Bad!/zone-profiles", "", "zone_profile.list"},
		{"POST", "/zone-profiles", "{bad", "createZoneProfile"},
		{"GET", "/zone-profiles/0", "", "getProfile"},
	}
	for _, c := range cases {
		if r := e.do(t, c.method, c.path, tok, c.body, nil); r.StatusCode != 400 {
			t.Fatalf("%s %s: %d", c.method, c.path, r.StatusCode)
		}
		if ev := e.events(c.action); len(ev) != 1 || ev[0].Decision != "deny" || ev[0].Reason != "bad_request" || ev[0].Subject == "" {
			t.Fatalf("%s %s audit: %+v", c.method, c.path, ev)
		}
	}
	e.do(t, "GET", "/zone-profiles", tok, "", map[string]string{"pagination-page": "x"})
	if ev := e.events("listZoneProfiles"); len(ev) != 1 || ev[0].Reason != "bad_request" {
		t.Fatalf("pagination audit: %+v", ev)
	}
}

func TestMCPZoneProfileUpdateKeepsForwards(t *testing.T) {
	e, fake := profileEnv(t, true)
	r := e.do(t, "POST", "/api/v1/providers/eurodns/zone-profiles", e.token("profiler"), testProfile, nil)
	var created eurodnsprov.ZoneProfile
	decodeJSON(t, r, &created)
	id := *created.ID
	cs := connect(t, e, e.token("profiler"))
	res := call(t, cs, "update_zone_profile", map[string]any{"id": id, "name": "renamed",
		"records": []map[string]any{{"type": "A", "host": "@", "ttl": 600, "rdata": "192.0.2.30", "isDynDns": true}}}, nil)
	if res.IsError {
		t.Fatalf("update: %s", errText(res))
	}
	p := fake.Profile(id)
	if len(p.MailForwards) != 1 || p.Records[0].IsDynDNS == nil || !*p.Records[0].IsDynDNS {
		t.Fatalf("forwards or record fields dropped: %+v", p)
	}
	if res = call(t, cs, "update_zone_profile", map[string]any{"id": id, "name": "renamed", "records": []map[string]any{}, "mail_forwards": []any{}}, nil); res.IsError || len(fake.Profile(id).MailForwards) != 0 {
		t.Fatalf("explicit removal of the forwards: %s", errText(res))
	}
}

func TestZoneProfileEventsHiddenFromJournalReaders(t *testing.T) {
	e, _ := profileEnv(t, true)
	secret := `{"name":"p","records":[{"type":"TXT","host":"@","ttl":600,"rdata":"google-site-verification=SECRET123"}]}`
	if r := e.do(t, "POST", "/api/v1/providers/eurodns/zone-profiles", e.token("profiler"), secret, nil); r.StatusCode != 201 {
		t.Fatalf("create: %d", r.StatusCode)
	}
	e.do(t, "POST", "/zone-profiles/check", e.token("profiler"), secret, nil)
	cs := connect(t, e, e.token("profiler"))
	call(t, cs, "list_zone_profiles", map[string]any{}, nil)

	r := e.do(t, "GET", "/api/v1/audit?limit=500", e.token("admin"), "", nil)
	body := readAll(r)
	if r.StatusCode != 200 || strings.Contains(body, "SECRET123") || strings.Contains(body, "zone_profile") || strings.Contains(body, "ZoneProfile") {
		t.Fatalf("profile events shown to a ui.read holder without dns.zone.profile: %d %s", r.StatusCode, body)
	}
	cs = connect(t, e, e.token("admin"))
	var page uiapi.AuditPage
	if res := call(t, cs, "search_audit", map[string]any{"limit": 200}, &page); res.IsError {
		t.Fatalf("search_audit: %s", errText(res))
	}
	for _, en := range page.Entries {
		if strings.Contains(en.Action, "zone_profile") || strings.Contains(en.Action, "ZoneProfile") {
			t.Fatalf("MCP search_audit shows %s", en.Action)
		}
	}

	r = e.do(t, "GET", "/api/v1/audit?limit=500", e.token("profile-auditor"), "", nil)
	body = readAll(r)
	for _, a := range []string{"zone_profile.create", "checkZoneProfile", "mcp.list_zone_profiles"} {
		if !strings.Contains(body, `"`+a+`"`) {
			t.Fatalf("%s hidden from a dns.zone.profile holder: %s", a, body)
		}
	}
	if strings.Contains(body, "SECRET123") {
		t.Fatal("record values in the journal")
	}
}

func TestZoneProfilesProtectedForwards(t *testing.T) {
	e, fake := profileEnvTweak(t, false, func(c *config.Config) {
		c.Protected = append(c.Protected, config.Protected{Zones: []string{"example.com"}, Hosts: []string{"@"}, Types: []string{"MX"}})
	})
	tok := e.token("profiler")
	for _, body := range []string{
		`{"name":"p","records":[],"mailForwards":[{"source":"*","destination":"x@attacker.example"}]}`,
		`{"name":"p","records":[],"urlForwards":[{"forwardType":"HTTP301","host":"","url":"https://attacker.example"}]}`,
		`{"name":"p","records":[],"urlForwards":[{"forwardType":"HTTP302","host":"login","url":"https://attacker.example"}]}`,
	} {
		for _, path := range []string{"/api/v1/providers/eurodns/zone-profiles", "/api/v1/providers/eurodns/zone-profiles/check", "/zone-profiles"} {
			if r := e.do(t, "POST", path, tok, body, nil); r.StatusCode != 403 || reason(t, r) != "protected" {
				t.Fatalf("%s %s: %d", path, body, r.StatusCode)
			}
		}
	}
	if r := e.do(t, "POST", "/zone-profiles", tok, `{"name":"p","records":[],"urlForwards":[{"forwardType":"HTTP301","host":"www","url":"https://example.net"}]}`, nil); r.StatusCode != 201 {
		t.Fatalf("unprotected URL forward: %d", r.StatusCode)
	}
	if fake.Len() != 1 {
		t.Fatalf("profiles: %d", fake.Len())
	}
}
