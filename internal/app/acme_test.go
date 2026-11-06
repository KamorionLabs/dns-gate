package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/lambdarun"
	"github.com/KamorionLabs/dns-gate/internal/oidctest"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// acmeEnv is a gate wired by New in front of the EuroDNS fake, with an
// OIDC issuer for key management.
type acmeEnv struct {
	t     *testing.T
	fake  *eurodnstest.Server
	idp   *oidctest.Provider
	other *oidctest.Provider // issuer without token_exchange
	gate  *httptest.Server
	app   *App
	audit string // JSON audit lines
}

func newACMEEnv(t *testing.T) *acmeEnv {
	t.Helper()
	return newACMEEnvWith(t, "")
}

// newACMEEnvWith adds extra top-level YAML to the configuration.
func newACMEEnvWith(t *testing.T, extra string) *acmeEnv {
	t.Helper()
	e := &acmeEnv{t: t, fake: eurodnstest.NewServer(eurodnstest.Options{AppID: "app", APIKey: "k"}), idp: oidctest.New(), other: oidctest.New()}
	t.Cleanup(e.fake.Close)
	t.Cleanup(e.idp.Close)
	t.Cleanup(e.other.Close)
	e.fake.Seed(&eurodns.Zone{Name: "example.com", Records: []eurodns.Record{
		{Type: "A", Host: "www", TTL: 3600, RData: "192.0.2.1"},
		{Type: "TXT", Host: "_acme-challenge.legacy", TTL: 600, RData: `"foreign"`},
	}})
	yaml := `
providers:
  - id: eurodns
    kind: eurodns
    eurodns: {base_url: "` + e.fake.URL + `", app_id: app, rate: {every: 1ms, burst: 50}}
zones: [example.com]
store: {type: sqlite, sqlite: {path: ` + filepath.Join(t.TempDir(), "g.db") + `}}
issuers:
  - {name: ci, issuer: "` + e.idp.URL + `", audiences: [dns-gate], category: pipeline, token_exchange: true}
  - {name: other, issuer: "` + e.other.URL + `", audiences: [dns-gate], category: pipeline}
  - {name: gate, self: true, issuer: "http://127.0.0.1:1", token_ttl: 1h}
roles:
  acme:
    ephemeral_ttl: 1h
    rules:
      - zones: [example.com]
        actions: [dns.read, dns.record.write]
        records: {hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT]}
  acme-permanent:
    rules:
      - zones: [example.com]
        actions: [dns.record.write]
        records: {hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT]}
  key-admin:
    rules:
      - zones: [example.com]
        actions: [dns.read, dns.record.write, ui.read, gate.apikey.manage]
  writer:
    rules:
      - zones: [example.com]
        actions: [dns.read, dns.record.write, ui.read]
  keys-elsewhere:
    rules:
      - zones: [example.org]
        actions: [dns.read, gate.apikey.manage]
bindings:
  - {role: key-admin, team: web, subjects: [{issuer: ci, claims: {sub: [admin]}}]}
  - {role: writer, team: web, subjects: [{issuer: ci, claims: {sub: [writer]}}]}
  - {role: keys-elsewhere, team: web, subjects: [{issuer: ci, claims: {sub: [teammate]}}]}
  - {role: acme, team: web, subjects: [{issuer: ci, claims: {sub: ["repo:example/certs:*"]}}, {issuer: other, claims: {sub: [acme]}}]}
` + extra
	signingKey := signingKeyPEM(t)
	cfg, err := config.Parse([]byte(yaml), func(k string) string {
		switch k {
		case "EURODNS_API_KEY":
			return "k"
		case "DNS_GATE_TOKEN_SIGNING_KEY":
			return signingKey
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.audit = filepath.Join(t.TempDir(), "audit.jsonl")
	auditOut, err := os.Create(e.audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditOut.Close() })
	a, err := New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Holder: "t", AuditOutput: auditOut})
	if err != nil {
		t.Fatal(err)
	}
	e.app = a
	e.gate = httptest.NewServer(a.Handler())
	t.Cleanup(e.gate.Close)
	return e
}

func signingKeyPEM(t *testing.T) string {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func (e *acmeEnv) do(method, path string, hdr map[string]string, body string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.gate.URL+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *acmeEnv) bearer(sub string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + e.idp.Sign(map[string]any{"sub": sub, "aud": "dns-gate"}), "Content-Type": "application/json"}
}

func (e *acmeEnv) createKey(body string) uiapi.IssuedAPIKey {
	e.t.Helper()
	status, b := e.do("POST", "/api/v1/api-keys", e.bearer("admin"), body)
	if status != http.StatusCreated {
		e.t.Fatalf("create key: %d %s", status, b)
	}
	var k uiapi.IssuedAPIKey
	if err := json.Unmarshal(b, &k); err != nil {
		e.t.Fatal(err)
	}
	return k
}

// txt returns the upstream values of a TXT RRset, unquoted and sorted.
func (e *acmeEnv) txt(host string) []string {
	var out []string
	for _, r := range e.fake.Zone("example.com").Records {
		if r.Type == "TXT" && r.Host == host {
			out = append(out, strings.Trim(r.RData, `"`))
		}
	}
	slices.Sort(out)
	return out
}

func basic(user, pass string) map[string]string {
	return map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)),
		"Content-Type":  "application/json",
	}
}

// challenge returns a DNS-01 TXT value (43 base64url characters).
func challenge(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// lego httpreq, default and RAW modes: a wildcard and an apex challenge
// coexist in one RRset and are removed one by one.
func TestACMEHTTPReq(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "lego", "team": "web", "role": "acme"}`)
	auth := basic(k.ID, k.Key)
	apex, wild := challenge("apex"), challenge("wildcard")
	for _, v := range []string{apex, wild, wild} {
		if status, b := e.do("POST", "/acme/httpreq/present", auth, `{"fqdn": "_acme-challenge.example.com.", "value": "`+v+`"}`); status != 200 {
			t.Fatalf("present: %d %s", status, b)
		}
	}
	if got := e.txt("_acme-challenge"); !slices.Equal(got, sortedOf(apex, wild)) {
		t.Fatalf("after present: %v", got)
	}
	if status, b := e.do("POST", "/acme/httpreq/cleanup", auth, `{"fqdn": "_acme-challenge.example.com.", "value": "`+apex+`"}`); status != 200 {
		t.Fatalf("cleanup: %d %s", status, b)
	}
	if got := e.txt("_acme-challenge"); !slices.Equal(got, []string{wild}) {
		t.Fatalf("after first cleanup: %v", got)
	}
	e.do("POST", "/acme/httpreq/cleanup", auth, `{"fqdn": "_acme-challenge.example.com.", "value": "`+wild+`"}`)
	if got := e.txt("_acme-challenge"); len(got) != 0 {
		t.Fatalf("after cleanup: %v", got)
	}

	raw := `{"domain": "*.www.example.com", "token": "tok", "keyAuth": "tok.thumbprint"}`
	if status, b := e.do("POST", "/acme/httpreq/present", auth, raw); status != 200 {
		t.Fatalf("raw present: %d %s", status, b)
	}
	if got := e.txt("_acme-challenge.www"); !slices.Equal(got, []string{challenge("tok.thumbprint")}) {
		t.Fatalf("raw mode: %v", got)
	}
	e.do("POST", "/acme/httpreq/cleanup", auth, raw)
	if got := e.txt("_acme-challenge.www"); len(got) != 0 {
		t.Fatalf("raw cleanup: %v", got)
	}

	for body, want := range map[string]int{
		`{"fqdn": "www.example.com.", "value": "x"}`:                      400,
		`{"fqdn": "_acme-challenge.example.org.", "value": "x"}`:          400,
		`{"fqdn": "_acme-challenge.legacy.example.com.", "value": "abc"}`: 409,
		`{"value": "x"}`: 400,
	} {
		if status, b := e.do("POST", "/acme/httpreq/present", auth, body); status != want {
			t.Errorf("%s: %d %s, want %d", body, status, b, want)
		}
	}
	if status, _ := e.do("POST", "/acme/httpreq/present", basic(k.ID, k.Key+"x"), `{"fqdn": "_acme-challenge.example.com.", "value": "x"}`); status != 401 {
		t.Errorf("bad key: %d", status)
	}
	if status, _ := e.do("GET", "/acme/httpreq/present", auth, ""); status != 405 {
		t.Errorf("GET present: %d", status)
	}
	if status, b := e.do("POST", "/acme/httpreq/present", e.bearer("writer"), `{"fqdn": "_acme-challenge.example.com.", "value": "x"}`); status != 403 || !strings.Contains(string(b), "ephemeral_required") {
		t.Errorf("permanent role: %d %s", status, b)
	}
}

func sortedOf(v ...string) []string {
	slices.Sort(v)
	return v
}

// acme.sh dns_acmedns: the exact request of dnsapi/dns_acmedns.sh (curl
// POST, X-Api-User / X-Api-Key, body {"subdomain":"...", "txt": "..."}),
// whose response must contain the quoted value. ACMEDNS_SUBDOMAIN is the
// domain itself; like acme-dns, the two most recent values are kept.
func TestACMEDNSAcmeSh(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "acme.sh", "team": "web", "role": "acme"}`)
	hdr := map[string]string{"X-Api-User": k.ID, "X-Api-Key": k.Key, "Content-Type": "application/json"}
	values := []string{challenge("a"), challenge("b"), challenge("c")}
	for _, v := range values {
		status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"www.example.com", "txt": "`+v+`"}`)
		if status != 200 || !strings.Contains(string(b), `"`+v+`"`) {
			t.Fatalf("update: %d %s", status, b)
		}
	}
	if got := e.txt("_acme-challenge.www"); !slices.Equal(got, sortedOf(values[1], values[2])) {
		t.Fatalf("two most recent values expected: %v", got)
	}
	status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"www.example.com", "txt": "`+values[1]+`"}`)
	if status != 200 || !slices.Equal(e.txt("_acme-challenge.www"), sortedOf(values[1], values[2])) {
		t.Fatalf("repeated value: %d %s %v", status, b, e.txt("_acme-challenge.www"))
	}

	for body, want := range map[string]string{
		`{"subdomain":"www.example.com", "txt": "short"}`:                                  "bad_txt",
		`{"subdomain":"www.example.org", "txt": "` + values[0] + `"}`:                      "bad_subdomain",
		`{"subdomain":"8e5700ea-a4bf-41c7-8a77-e990661dcc6a", "txt": "` + values[0] + `"}`: "bad_subdomain",
	} {
		status, b := e.do("POST", "/acme/acme-dns/update", hdr, body)
		var r struct{ Error string }
		_ = json.Unmarshal(b, &r)
		if status != 400 || r.Error != want {
			t.Errorf("%s: %d %s, want %s", body, status, b, want)
		}
	}
	bad := map[string]string{"X-Api-User": k.ID, "X-Api-Key": tamper(k.Key)}
	if status, _ := e.do("POST", "/acme/acme-dns/update", bad, `{"subdomain":"www.example.com", "txt": "`+values[0]+`"}`); status != 401 {
		t.Errorf("bad key: %d", status)
	}
	other := map[string]string{"X-Api-User": "0123456789abcdef", "X-Api-Key": k.Key}
	if status, _ := e.do("POST", "/acme/acme-dns/update", other, `{"subdomain":"www.example.com", "txt": "`+values[0]+`"}`); status != 401 {
		t.Errorf("user of another key: %d", status)
	}
}

// The certbot acme-dns hook (acme-dns-certbot-joohoi, acme-dns-auth.py):
// /register without credentials is refused with an explanation; with the
// storage file seeded from acme_dns_accounts, the hook only calls /update
// with the stored subdomain (python requests also sends basic auth when the
// URL carries the key). /register with the key and a domain works too.
func TestACMEDNSCertbotHook(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "certbot", "team": "web", "role": "acme", "acme_domains": ["www.example.com", "*.example.com", "example.com"]}`)
	if len(k.ACMEDNSAccounts) != 2 || len(k.ACMEDomains) != 2 {
		t.Fatalf("accounts %+v", k.ACMEDNSAccounts)
	}
	acct := k.ACMEDNSAccounts["www.example.com"]
	if acct.Username != k.ID || acct.Password != k.Key || acct.FullDomain != "_acme-challenge.www.example.com" || len(acct.SubDomain) != 36 {
		t.Fatalf("account %+v", acct)
	}

	status, b := e.do("POST", "/acme/acme-dns/register", nil, "")
	if status != 401 || !strings.Contains(string(b), "registration_requires_api_key") {
		t.Fatalf("anonymous register: %d %s", status, b)
	}

	update := func(a uiapi.ACMEDNSAccount, txt string, extra map[string]string) (int, []byte) {
		body, _ := json.Marshal(map[string]string{"subdomain": a.SubDomain, "txt": txt})
		hdr := map[string]string{"X-Api-User": a.Username, "X-Api-Key": a.Password, "Content-Type": "application/json"}
		for k, v := range extra {
			hdr[k] = v
		}
		return e.do("POST", "/acme/acme-dns/update", hdr, strings.ReplaceAll(string(body), `","`, `", "`))
	}
	v1, v2 := challenge("www-1"), challenge("www-2")
	if status, b := update(acct, v1, nil); status != 200 {
		t.Fatalf("hook update: %d %s", status, b)
	}
	if status, b := update(acct, v2, map[string]string{"Authorization": basic(k.ID, k.Key)["Authorization"]}); status != 200 {
		t.Fatalf("hook update with URL credentials: %d %s", status, b)
	}
	if got := e.txt("_acme-challenge.www"); !slices.Equal(got, sortedOf(v1, v2)) {
		t.Fatalf("www values: %v", got)
	}
	apex := k.ACMEDNSAccounts["example.com"]
	if status, b := update(apex, v1, nil); status != 200 || !slices.Equal(e.txt("_acme-challenge"), []string{v1}) {
		t.Fatalf("apex: %d %s %v", status, b, e.txt("_acme-challenge"))
	}

	reg := basic(k.ID, k.Key)
	delete(reg, "Content-Type")
	status, b = e.do("POST", "/acme/acme-dns/register", reg, `{"allowfrom": ["127.0.0.0/8"]}`)
	if status != 400 || !strings.Contains(string(b), "domain_required") {
		t.Fatalf("register without domain: %d %s", status, b)
	}
	status, b = e.do("POST", "/acme/acme-dns/register", reg, `{"allowfrom": ["127.0.0.0/8"], "domain": "api.example.com"}`)
	var created uiapi.ACMEDNSAccount
	_ = json.Unmarshal(b, &created)
	if status != 201 || created.Username != k.ID || created.Password != k.Key || created.FullDomain != "_acme-challenge.api.example.com" || created.AllowFrom[0] != "127.0.0.0/8" {
		t.Fatalf("register: %d %s", status, b)
	}
	if status, b := update(created, v2, nil); status != 200 || !slices.Equal(e.txt("_acme-challenge.api"), []string{v2}) {
		t.Fatalf("registered update: %d %s", status, b)
	}
	if status, b := e.do("POST", "/acme/acme-dns/register", reg, `{"allowfrom": ["192.0.2.0/24"], "domain": "api.example.com"}`); status == 201 {
		var far uiapi.ACMEDNSAccount
		_ = json.Unmarshal(b, &far)
		if status, _ := update(far, v1, nil); status != 401 {
			t.Errorf("update outside allowfrom: %d", status)
		}
	}
	if status, b := e.do("POST", "/acme/acme-dns/register", reg, `{"domain": "www.example.org"}`); status != 400 {
		t.Errorf("register outside managed zones: %d %s", status, b)
	}

	var view uiapi.APIKey
	_, b = e.do("GET", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), "")
	_ = json.Unmarshal(b, &view)
	if view.LastUsedAt == nil || view.LastUsedIP != "127.0.0.1" || len(view.ACMEDNS) < 3 {
		t.Fatalf("key view %+v", view)
	}
}

// Keys: rotation overlap, revocation, roles beyond the caller's rights.
func TestAPIKeyLifecycle(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "lego", "team": "web", "role": "acme", "allowed_cidrs": ["127.0.0.0/8"]}`)
	present := func(key string) int {
		status, _ := e.do("POST", "/acme/httpreq/present", basic(k.ID, key), `{"fqdn": "_acme-challenge.example.com.", "value": "v"}`)
		return status
	}
	if present(k.Key) != 200 {
		t.Fatal("new key refused")
	}
	status, b := e.do("POST", "/api/v1/api-keys/"+k.ID+"/rotate", e.bearer("admin"), `{"overlap": "1h"}`)
	var rot uiapi.IssuedAPIKey
	_ = json.Unmarshal(b, &rot)
	if status != 200 || rot.Key == k.Key || rot.PreviousKeyExpiresAt == nil {
		t.Fatalf("rotate: %d %s", status, b)
	}
	if present(k.Key) != 200 || present(rot.Key) != 200 {
		t.Fatal("overlap not honoured")
	}
	if status, _ := e.do("POST", "/api/v1/api-keys/"+k.ID+"/rotate", e.bearer("admin"), `{"overlap": "0s"}`); status != 200 {
		t.Fatal("second rotation")
	}
	if present(rot.Key) != 401 {
		t.Fatal("previous key still accepted after a rotation without overlap")
	}

	for body, want := range map[string]int{
		`{"name": "x", "team": "web", "role": "key-admin"}`:                                           403,
		`{"name": "x", "team": "ops", "role": "acme"}`:                                                403,
		`{"name": "x", "team": "web", "role": "nope"}`:                                                403,
		`{"name": "", "team": "web", "role": "acme"}`:                                                 400,
		`{"name": "x", "team": "web", "role": "acme", "allowed_cidrs": ["x"]}`:                        400,
		`{"name": "x", "team": "web", "role": "acme-permanent", "acme_domains": ["www.example.com"]}`: 400,
		`{"name": "x", "team": "web", "role": "acme", "acme_domains": ["www.example.org"]}`:           400,
	} {
		if status, b := e.do("POST", "/api/v1/api-keys", e.bearer("admin"), body); status != want {
			t.Errorf("%s: %d %s, want %d", body, status, b, want)
		}
	}
	if status, _ := e.do("GET", "/api/v1/api-keys", e.bearer("writer"), ""); status != 403 {
		t.Errorf("list without gate.apikey.manage: %d", status)
	}
	other := e.createKey(`{"name": "other", "team": "web", "role": "acme"}`)
	if status, _ := e.do("GET", "/api/v1/api-keys", basic(other.ID, other.Key), ""); status != 403 {
		t.Errorf("a key listed keys: %d", status)
	}

	status, b = e.do("PUT", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), `{"name": "lego renamed", "description": "d", "acme_domains": ["www.example.com"]}`)
	var upd uiapi.APIKey
	_ = json.Unmarshal(b, &upd)
	if status != 200 || upd.Name != "lego renamed" || len(upd.AllowedCIDRs) != 0 || !slices.Equal(upd.ACMEDomains, []string{"www.example.com"}) {
		t.Fatalf("put: %d %s", status, b)
	}
	if status, _ := e.do("PUT", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), `{"name": "x", "role": "writer"}`); status != 409 {
		t.Errorf("role change: %d", status)
	}

	if status, _ := e.do("DELETE", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), ""); status != 204 {
		t.Fatal("revoke")
	}
	_, b = e.do("GET", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), "")
	var rev uiapi.APIKey
	_ = json.Unmarshal(b, &rev)
	if rev.Status != uiapi.APIKeyRevoked || len(rev.ACMEDNS) != 0 {
		t.Fatalf("revoked view %s", b)
	}
	var list []uiapi.APIKey
	_, b = e.do("GET", "/api/v1/api-keys", e.bearer("admin"), "")
	_ = json.Unmarshal(b, &list)
	if len(list) != 1 || list[0].ID != other.ID {
		t.Fatalf("list %s", b)
	}
	_, b = e.do("GET", "/api/v1/api-keys?include_revoked=true", e.bearer("admin"), "")
	_ = json.Unmarshal(b, &list)
	if len(list) != 2 {
		t.Fatalf("list with revoked %s", b)
	}
	if status, _ := e.do("POST", "/acme/httpreq/present", basic(other.ID, other.Key), `{"fqdn": "_acme-challenge.example.com.", "value": "w"}`); status != 200 {
		t.Fatal("other key")
	}
	time.Sleep(10 * time.Millisecond)
	if present(k.Key) != 401 {
		t.Fatal("revoked key accepted")
	}
}

// TestACMEDNSRealCertbotHook runs the unmodified acme-dns-auth.py of
// acme-dns-certbot-joohoi when DNS_GATE_TEST_CERTBOT_HOOK names it (python3
// with requests on the PATH): seeded storage, then the hook as certbot
// calls it, for a name and its wildcard.
func TestACMEDNSRealCertbotHook(t *testing.T) {
	hook := os.Getenv("DNS_GATE_TEST_CERTBOT_HOOK")
	if hook == "" {
		t.Skip("DNS_GATE_TEST_CERTBOT_HOOK not set")
	}
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "certbot", "team": "web", "role": "acme", "acme_domains": ["www.example.com"]}`)
	dir := t.TempDir()
	storage := filepath.Join(dir, "acmedns.json")
	b, _ := json.Marshal(k.ACMEDNSAccounts)
	if err := os.WriteFile(storage, b, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(hook)
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Replace(string(src), `ACMEDNS_URL = "https://auth.acme-dns.io"`, `ACMEDNS_URL = "`+e.gate.URL+`/acme/acme-dns"`, 1)
	script = strings.Replace(script, `STORAGE_PATH = "/etc/letsencrypt/acmedns.json"`, `STORAGE_PATH = "`+storage+`"`, 1)
	path := filepath.Join(dir, "acme-dns-auth.py")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	values := []string{challenge("certbot-www"), challenge("certbot-wildcard")}
	for i, domain := range []string{"www.example.com", "*.www.example.com"} {
		cmd := exec.Command("python3", path)
		cmd.Env = append(os.Environ(), "CERTBOT_DOMAIN="+domain, "CERTBOT_VALIDATION="+values[i])
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook %s: %v\n%s", domain, err, out)
		}
	}
	if got := e.txt("_acme-challenge.www"); !slices.Equal(got, sortedOf(values...)) {
		t.Fatalf("values %v", got)
	}
}

// TestACMEDNSRealAcmeSh sources the unmodified dnsapi/dns_acmedns.sh of
// acme.sh when DNS_GATE_TEST_ACMESH_DNSAPI names it, with the few acme.sh
// helpers it uses (_post is curl, as in acme.sh).
func TestACMEDNSRealAcmeSh(t *testing.T) {
	dnsapi := os.Getenv("DNS_GATE_TEST_ACMESH_DNSAPI")
	if dnsapi == "" {
		t.Skip("DNS_GATE_TEST_ACMESH_DNSAPI not set")
	}
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "acme.sh", "team": "web", "role": "acme"}`)
	shim := `
_info() { :; }; _debug() { :; }; _err() { echo "$@" >&2; }
_readaccountconf_mutable() { :; }; _clearaccountconf_mutable() { :; }
_readdomainconf() { :; }; _savedomainconf() { :; }
_post() { curl -sS -X "$4" -H "Content-Type: $5" -H "$_H1" -H "$_H2" --data "$1" "$2"; }
. "$DNSAPI"
dns_acmedns_add "_acme-challenge.example.com" "$V1" && dns_acmedns_add "_acme-challenge.example.com" "$V2"
`
	v1, v2 := challenge("acmesh-apex"), challenge("acmesh-wildcard")
	cmd := exec.Command("sh", "-c", shim)
	cmd.Env = append(os.Environ(), "DNSAPI="+dnsapi, "V1="+v1, "V2="+v2,
		"ACMEDNS_BASE_URL="+e.gate.URL+"/acme/acme-dns", "ACMEDNS_USERNAME="+k.ID, "ACMEDNS_PASSWORD="+k.Key, "ACMEDNS_SUBDOMAIN=example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dns_acmedns_add: %v\n%s", err, out)
	}
	if got := e.txt("_acme-challenge"); !slices.Equal(got, sortedOf(v1, v2)) {
		t.Fatalf("values %v", got)
	}
}

// On AWS Lambda (API Gateway HTTP API, payload 2.0), the acme-dns and
// httpreq requests reach the gate with their credential headers.
func TestACMEOnLambda(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "lambda", "team": "web", "role": "acme"}`)
	h := &lambdarun.Handler{HTTP: e.app.LambdaHandler(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	v := challenge("lambda")
	event := func(path string, headers map[string]string, body string) map[string]any {
		return map[string]any{
			"version": "2.0", "routeKey": "$default", "rawPath": path, "headers": headers, "body": body,
			"requestContext": map[string]any{"domainName": "dns-gate.example.com", "requestId": "r",
				"http": map[string]any{"method": "POST", "path": path, "protocol": "HTTP/1.1", "sourceIp": "198.51.100.7"}},
		}
	}
	for _, ev := range []map[string]any{
		event("/acme/acme-dns/update", map[string]string{"x-api-user": k.ID, "x-api-key": k.Key, "content-type": "application/json"},
			`{"subdomain":"www.example.com", "txt": "`+v+`"}`),
		event("/acme/httpreq/present", map[string]string{"authorization": basic(k.ID, k.Key)["Authorization"]},
			`{"fqdn": "_acme-challenge.example.com.", "value": "`+v+`"}`),
	} {
		payload, _ := json.Marshal(ev)
		out, err := h.Invoke(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		var resp struct {
			StatusCode int    `json:"statusCode"`
			Body       string `json:"body"`
		}
		_ = json.Unmarshal(out, &resp)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", ev["rawPath"], resp.StatusCode, resp.Body)
		}
	}
	if !slices.Equal(e.txt("_acme-challenge.www"), []string{v}) || !slices.Equal(e.txt("_acme-challenge"), []string{v}) {
		t.Fatalf("values %v %v", e.txt("_acme-challenge.www"), e.txt("_acme-challenge"))
	}
	_, b := e.do("GET", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), "")
	if !strings.Contains(string(b), `"last_used_ip":"198.51.100.7"`) {
		t.Fatalf("source address of the Lambda event not used: %s", b)
	}
}

// tamper changes one character of the secret part of a key.
func tamper(key string) string {
	i := len(key) - 10
	c := byte('A')
	if key[i] == 'A' {
		c = 'B'
	}
	return key[:i] + string(c) + key[i+1:]
}

func (e *acmeEnv) exchange(form url.Values) (int, map[string]any) {
	e.t.Helper()
	status, b := e.do("POST", "/api/v1/token-exchange", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form.Encode())
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return status, out
}

func exchangeForm(token string) url.Values {
	return url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {token},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
	}
}

// Token exchange (RFC 8693) of a CI token, then acme.sh dns_acmedns with
// the exchanged token as ACMEDNS_PASSWORD and any ACMEDNS_USERNAME: the
// exact requests of dnsapi/dns_acmedns.sh, with the domain as subdomain.
func TestTokenExchangeAcmeSh(t *testing.T) {
	e := newACMEEnv(t)
	ci := e.idp.Sign(map[string]any{"sub": "repo:example/certs:ref:refs/heads/main", "aud": "dns-gate", "jti": "ci-run-1"})
	status, out := e.exchange(exchangeForm(ci))
	tok, _ := out["access_token"].(string)
	if status != 200 || tok == "" || out["token_type"] != "Bearer" || out["expires_in"].(float64) != 900 ||
		out["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("exchange: %d %v", status, out)
	}
	audit, _ := os.ReadFile(e.audit)
	if !strings.Contains(string(audit), `"action":"gate.token.exchange","decision":"allow"`) || !strings.Contains(string(audit), `"subject_token_jti":"ci-run-1"`) {
		t.Fatalf("exchange not audited:\n%s", audit)
	}
	var me struct{ Subject, Category string }
	_, b := e.do("GET", "/api/v1/me", map[string]string{"Authorization": "Bearer " + tok}, "")
	_ = json.Unmarshal(b, &me)
	if me.Subject != "ci:repo:example/certs:ref:refs/heads/main" || me.Category != "pipeline" {
		t.Fatalf("exchanged identity %s", b)
	}

	values := []string{challenge("x1"), challenge("x2"), challenge("x3")}
	for _, user := range []string{"oidc", "repo:example/certs"} {
		for _, v := range values {
			hdr := map[string]string{"X-Api-User": user, "X-Api-Key": tok, "Content-Type": "application/json"}
			status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"example.com", "txt": "`+v+`"}`)
			if status != 200 || !strings.Contains(string(b), `"`+v+`"`) {
				t.Fatalf("update as %s: %d %s", user, status, b)
			}
		}
	}
	if got := e.txt("_acme-challenge"); !slices.Equal(got, sortedOf(values[1], values[2])) {
		t.Fatalf("two most recent values expected: %v", got)
	}

	direct := map[string]string{"X-Api-User": "oidc", "X-Api-Key": ci, "Content-Type": "application/json"}
	if status, b := e.do("POST", "/acme/acme-dns/update", direct, `{"subdomain":"www.example.com", "txt": "`+values[0]+`"}`); status != 200 {
		t.Fatalf("direct OIDC token: %d %s", status, b)
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
	if status, b := e.do("POST", "/acme/httpreq/present", bearer, `{"fqdn": "_acme-challenge.api.example.com.", "value": "v"}`); status != 200 {
		t.Fatalf("httpreq with the exchanged token: %d %s", status, b)
	}
	hdr := map[string]string{"X-Api-User": "oidc", "X-Api-Key": tok}
	if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"8e5700ea-a4bf-41c7-8a77-e990661dcc6a", "txt": "`+values[0]+`"}`); status != 400 || !strings.Contains(string(b), "bad_subdomain") {
		t.Errorf("registration subdomain with a token: %d %s", status, b)
	}
	if status, b := e.do("POST", "/acme/acme-dns/register", hdr, `{"domain": "example.com"}`); status != 403 {
		t.Errorf("register with a token: %d %s", status, b)
	}
	other := map[string]string{"X-Api-User": "oidc", "X-Api-Key": e.idp.Sign(map[string]any{"sub": "writer", "aud": "dns-gate"})}
	if status, b := e.do("POST", "/acme/acme-dns/update", other, `{"subdomain":"example.com", "txt": "`+values[0]+`"}`); status != 403 || !strings.Contains(string(b), "ephemeral_required") {
		t.Errorf("permanent role: %d %s", status, b)
	}
}

func TestTokenExchangeRefusals(t *testing.T) {
	e := newACMEEnv(t)
	ci := e.idp.Sign(map[string]any{"sub": "repo:example/certs:ref:refs/heads/main", "aud": "dns-gate"})
	_, out := e.exchange(exchangeForm(ci))
	gateTok, _ := out["access_token"].(string)
	k := e.createKey(`{"name": "k", "team": "web", "role": "acme"}`)

	short := exchangeForm(ci)
	short.Set("expires_in", "120")
	short.Set("requested_token_type", "urn:ietf:params:oauth:token-type:jwt")
	if status, out := e.exchange(short); status != 200 || out["expires_in"].(float64) != 120 || out["issued_token_type"] != "urn:ietf:params:oauth:token-type:jwt" {
		t.Fatalf("requested lifetime: %d %v", status, out)
	}
	for name, tc := range map[string]struct {
		form url.Values
		want string
	}{
		"gate token":       {exchangeForm(gateTok), "invalid_grant"},
		"api key":          {exchangeForm(k.Key), "invalid_grant"},
		"issuer not opted": {exchangeForm(e.other.Sign(map[string]any{"sub": "acme", "aud": "dns-gate"})), "invalid_grant"},
		"unbound":          {exchangeForm(e.idp.Sign(map[string]any{"sub": "nobody", "aud": "dns-gate"})), "invalid_grant"},
		"wrong audience":   {exchangeForm(e.idp.Sign(map[string]any{"sub": "admin", "aud": "other"})), "invalid_grant"},
		"grant type":       {func() url.Values { f := exchangeForm(ci); f.Set("grant_type", "client_credentials"); return f }(), "unsupported_grant_type"},
		"token type":       {func() url.Values { f := exchangeForm(ci); f.Set("subject_token_type", "urn:x"); return f }(), "invalid_request"},
		"short lifetime":   {func() url.Values { f := exchangeForm(ci); f.Set("expires_in", "10"); return f }(), "invalid_request"},
		"actor":            {func() url.Values { f := exchangeForm(ci); f.Set("actor_token", ci); return f }(), "invalid_request"},
	} {
		if status, out := e.exchange(tc.form); status != 400 || out["error"] != tc.want {
			t.Errorf("%s: %d %v, want %s", name, status, out, tc.want)
		}
	}
	if status, _ := e.do("GET", "/api/v1/token-exchange", nil, ""); status != 405 {
		t.Errorf("GET: %d", status)
	}
	if status, b := e.do("GET", "/.well-known/dns-gate", nil, ""); status != 200 || !strings.Contains(string(b), "token-exchange") {
		t.Errorf("feature not advertised: %s", b)
	}
}

// docBlock returns the first fenced code block of docs/ACME.md after marker.
func docBlock(t *testing.T, marker string) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/ACME.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	i := strings.Index(doc, marker)
	if i < 0 {
		t.Fatalf("%q not found in docs/ACME.md", marker)
	}
	rest := doc[i:]
	start := strings.Index(rest, "```sh\n")
	end := strings.Index(rest[start+6:], "```")
	if start < 0 || end < 0 {
		t.Fatalf("no code block after %q", marker)
	}
	return rest[start+6 : start+6+end]
}

// The certbot hook and the exchange function of docs/ACME.md, run as
// certbot and the recipes run them, with a token and with an API key.
func TestDocsACMEScripts(t *testing.T) {
	for _, tool := range []string{"sh", "curl", "base64", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not found")
		}
	}
	e := newACMEEnv(t)
	dir := t.TempDir()
	hook := filepath.Join(dir, "dns-gate-hook.sh")
	if err := os.WriteFile(hook, []byte(docBlock(t, "Save it as `dns-gate-hook.sh`")), 0o700); err != nil {
		t.Fatal(err)
	}
	exchange := docBlock(t, "as a shell function")
	ci := e.idp.Sign(map[string]any{"sub": "repo:example/certs:ref:refs/heads/main", "aud": "dns-gate"})
	cmd := exec.Command("sh", "-ec", exchange+"\nexchange \"$OIDC_TOKEN\"")
	cmd.Env = append(os.Environ(), "GATE="+e.gate.URL, "OIDC_TOKEN="+ci)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("exchange: %v %s", err, out)
	}
	gateToken := strings.TrimSpace(string(out))
	k := e.createKey(`{"name": "certbot", "team": "web", "role": "acme"}`)

	run := func(env []string, cleanup bool, domain, value string) {
		t.Helper()
		cmd := exec.Command("sh", hook)
		cmd.Env = append(os.Environ(), append(env, "DNS_GATE="+e.gate.URL, "DNS_GATE_PROPAGATION=0",
			"CERTBOT_DOMAIN="+domain, "CERTBOT_VALIDATION="+value)...)
		if cleanup {
			cmd.Env = append(cmd.Env, "CERTBOT_AUTH_OUTPUT=")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook %v: %v\n%s", env, err, out)
		}
	}
	for _, creds := range [][]string{
		{"DNS_GATE_TOKEN=" + gateToken},
		{"DNS_GATE_TOKEN=" + ci},
		{"DNS_GATE_KEY_ID=" + k.ID, "DNS_GATE_KEY=" + k.Key},
	} {
		apex, wild := challenge("hook-apex"), challenge("hook-wild")
		run(creds, false, "example.com", apex)
		run(creds, false, "*.example.com", wild)
		if got := e.txt("_acme-challenge"); !slices.Equal(got, sortedOf(apex, wild)) {
			t.Fatalf("%v: after present %v", creds, got)
		}
		run(creds, true, "example.com", apex)
		run(creds, true, "*.example.com", wild)
		if got := e.txt("_acme-challenge"); len(got) != 0 {
			t.Fatalf("%v: after cleanup %v", creds, got)
		}
	}
}

// The lifetime of an exchanged token is bounded by max_exchanged_ttl
// (default 15m) and by the expiry of the subject token plus 5 minutes.
func TestTokenExchangeLifetimeBounds(t *testing.T) {
	e := newACMEEnv(t)
	long := exchangeForm(e.idp.Sign(map[string]any{"sub": "repo:example/certs:ref:refs/heads/main", "aud": "dns-gate"}))
	long.Set("expires_in", "3600")
	if status, out := e.exchange(long); status != 200 || out["expires_in"].(float64) != 900 {
		t.Fatalf("not capped by max_exchanged_ttl: %d %v", status, out)
	}
	short := exchangeForm(e.idp.Sign(map[string]any{"sub": "repo:example/certs:ref:refs/heads/main", "aud": "dns-gate", "exp": time.Now().Add(time.Minute).Unix()}))
	status, out := e.exchange(short)
	if got, _ := out["expires_in"].(float64); status != 200 || got > 361 || got < 355 {
		t.Fatalf("not capped by the subject token expiry: %d %v", status, out)
	}
}

func (e *acmeEnv) denials() int {
	b, _ := os.ReadFile(e.audit)
	return strings.Count(string(b), `"decision":"deny"`)
}

// A refused API key is audited once, by the authentication, not again by
// the endpoint.
func TestAPIKeyRefusalAuditedOnce(t *testing.T) {
	e := newACMEEnv(t)
	for _, tc := range []struct {
		path string
		hdr  func(id, key string) map[string]string
		body string
	}{
		{"/acme/httpreq/present", func(id, key string) map[string]string { return basic(id, key) }, `{"fqdn": "_acme-challenge.example.com.", "value": "v"}`},
		{"/acme/acme-dns/update", func(id, key string) map[string]string { return map[string]string{"X-Api-User": id, "X-Api-Key": key} }, `{"subdomain":"example.com", "txt": "` + challenge("x") + `"}`},
		{"/acme/acme-dns/register", func(id, key string) map[string]string { return basic(id, key) }, `{"domain": "example.com"}`},
	} {
		k := e.createKey(`{"name": "k", "team": "web", "role": "acme"}`)
		before := e.denials()
		if status, _ := e.do("POST", tc.path, tc.hdr(k.ID, tamper(k.Key)), tc.body); status != 401 {
			t.Fatalf("%s: %d", tc.path, status)
		}
		if n := e.denials() - before; n != 1 {
			t.Errorf("%s: %d audit events for one refusal", tc.path, n)
		}
	}
}

// The allowfrom of a registration holds for every registration of the same
// key and domain: neither the domain name as subdomain nor a second
// registration without allowfrom bypasses it.
func TestACMEDNSAllowFromPerDomain(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "k", "team": "web", "role": "acme"}`)
	reg := basic(k.ID, k.Key)
	status, b := e.do("POST", "/acme/acme-dns/register", reg, `{"allowfrom": ["192.0.2.0/24"], "domain": "api.example.com"}`)
	if status != 201 {
		t.Fatalf("register: %d %s", status, b)
	}
	hdr := map[string]string{"X-Api-User": k.ID, "X-Api-Key": k.Key}
	if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"api.example.com", "txt": "`+challenge("a")+`"}`); status != 401 {
		t.Errorf("domain as subdomain bypassed allowfrom: %d %s", status, b)
	}
	_, b = e.do("POST", "/acme/acme-dns/register", reg, `{"domain": "api.example.com"}`)
	var open uiapi.ACMEDNSAccount
	_ = json.Unmarshal(b, &open)
	if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"`+open.SubDomain+`", "txt": "`+challenge("a")+`"}`); status != 401 {
		t.Errorf("second registration bypassed allowfrom: %d %s", status, b)
	}
	if got := e.txt("_acme-challenge.api"); len(got) != 0 {
		t.Errorf("written: %v", got)
	}
	if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"www.example.com", "txt": "`+challenge("a")+`"}`); status != 200 {
		t.Errorf("other domain: %d %s", status, b)
	}
}

func (e *acmeEnv) registrations(id string) []uiapi.ACMEDNSRegistration {
	e.t.Helper()
	var v uiapi.APIKey
	_, b := e.do("GET", "/api/v1/api-keys/"+id, e.bearer("admin"), "")
	if err := json.Unmarshal(b, &v); err != nil {
		e.t.Fatal(err)
	}
	return v.ACMEDNS
}

// Registrations and their values are persisted only after a successful
// write; an owner has at most acme.max_registrations of them, and idle
// registrations of token subjects are purged by the maintenance.
func TestACMERegistrationsPostCommitAndBounded(t *testing.T) {
	e := newACMEEnvWith(t, "acme: {max_registrations: 3, registration_idle: 24h}\n")
	k := e.createKey(`{"name": "k", "team": "web", "role": "acme"}`)
	hdr := map[string]string{"X-Api-User": k.ID, "X-Api-Key": k.Key}
	if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"legacy.example.com", "txt": "`+challenge("x")+`"}`); status != 409 {
		t.Fatalf("foreign RRset: %d %s", status, b)
	}
	if regs := e.registrations(k.ID); len(regs) != 0 {
		t.Fatalf("registration persisted by a refused write: %+v", regs)
	}
	for _, d := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"`+d+`", "txt": "`+challenge(d)+`"}`); status != 200 {
			t.Fatalf("%s: %d %s", d, status, b)
		}
	}
	status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"d.example.com", "txt": "`+challenge("d")+`"}`)
	if status != 409 || !strings.Contains(string(b), "too_many_registrations") {
		t.Fatalf("registration cap: %d %s", status, b)
	}
	if status, b := e.do("POST", "/acme/acme-dns/register", basic(k.ID, k.Key), `{"domain": "d.example.com"}`); status != 409 {
		t.Fatalf("registration cap on /register: %d %s", status, b)
	}

	tok := map[string]string{"X-Api-User": "oidc", "X-Api-Key": e.idp.Sign(map[string]any{"sub": "repo:example/certs:ref:refs/heads/main", "aud": "dns-gate"})}
	if status, b := e.do("POST", "/acme/acme-dns/update", tok, `{"subdomain":"e.example.com", "txt": "`+challenge("e")+`"}`); status != 200 {
		t.Fatalf("token: %d %s", status, b)
	}
	owner := "ci:repo:example/certs:ref:refs/heads/main"
	if regs, _ := e.app.Store.(store.APIKeyStore).ListACMERegistrations(context.Background(), owner); len(regs) != 1 || regs[0].ExpiresAt == nil {
		t.Fatalf("token registration %+v", regs)
	}
	e.app.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if err := e.app.GCPlans(context.Background()); err != nil {
		t.Fatal(err)
	}
	if regs, _ := e.app.Store.(store.APIKeyStore).ListACMERegistrations(context.Background(), owner); len(regs) != 0 {
		t.Fatalf("idle token registration kept: %+v", regs)
	}
	if regs := e.registrations(k.ID); len(regs) != 3 {
		t.Fatalf("key registrations purged: %+v", regs)
	}
}

// A PUT without acme_domains keeps every registration; with acme_domains it
// syncs only those created through the API, never those of clients.
func TestAPIKeyPutKeepsClientRegistrations(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "k", "team": "web", "role": "acme", "acme_domains": ["www.example.com"]}`)
	if status, b := e.do("POST", "/acme/acme-dns/register", basic(k.ID, k.Key), `{"domain": "api.example.com"}`); status != 201 {
		t.Fatalf("register: %d %s", status, b)
	}
	if status, b := e.do("PUT", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), `{"name": "renamed"}`); status != 200 {
		t.Fatalf("put: %d %s", status, b)
	}
	if regs := e.registrations(k.ID); len(regs) != 2 {
		t.Fatalf("a PUT without acme_domains removed registrations: %+v", regs)
	}
	e.do("PUT", "/api/v1/api-keys/"+k.ID, e.bearer("admin"), `{"name": "renamed", "acme_domains": []}`)
	regs := e.registrations(k.ID)
	if len(regs) != 1 || regs[0].Domain != "api.example.com" {
		t.Fatalf("client registration removed by the sync: %+v", regs)
	}
}

// httpreq: each value belongs to its author, who alone cleans it up, and a
// challenge RRset holds at most acme.max_values values.
func TestHTTPReqValueAuthors(t *testing.T) {
	e := newACMEEnvWith(t, "acme: {max_values: 3}\n")
	k1 := e.createKey(`{"name": "one", "team": "web", "role": "acme"}`)
	k2 := e.createKey(`{"name": "two", "team": "web", "role": "acme"}`)
	body := func(v string) string { return `{"fqdn": "_acme-challenge.example.com.", "value": "` + v + `"}` }
	e.do("POST", "/acme/httpreq/present", basic(k1.ID, k1.Key), body("v1"))
	if status, b := e.do("POST", "/acme/httpreq/cleanup", basic(k2.ID, k2.Key), body("v1")); status != 200 {
		t.Fatalf("cleanup of another's value: %d %s", status, b)
	}
	if got := e.txt("_acme-challenge"); !slices.Equal(got, []string{"v1"}) {
		t.Fatalf("value of another key removed: %v", got)
	}
	e.do("POST", "/acme/httpreq/present", basic(k2.ID, k2.Key), body("v2"))
	e.do("POST", "/acme/httpreq/present", basic(k2.ID, k2.Key), body("v3"))
	if status, b := e.do("POST", "/acme/httpreq/present", basic(k1.ID, k1.Key), body("v4")); status != 409 || !strings.Contains(string(b), "too_many_values") {
		t.Fatalf("values cap: %d %s", status, b)
	}
	e.do("POST", "/acme/httpreq/cleanup", basic(k1.ID, k1.Key), body("v1"))
	if got := e.txt("_acme-challenge"); !slices.Equal(got, []string{"v2", "v3"}) {
		t.Fatalf("after cleanup by its author: %v", got)
	}
}

// A member of the key's team holding gate.apikey.manage anywhere can always
// see and revoke the key, even without rights on the zones of its role.
func TestAPIKeyRevocationByTeam(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "k", "team": "web", "role": "acme"}`)
	if status, _ := e.do("POST", "/api/v1/api-keys/"+k.ID+"/rotate", e.bearer("teammate"), ""); status != 404 {
		t.Fatalf("rotation by a teammate without rights on the zones: %d", status)
	}
	if status, b := e.do("DELETE", "/api/v1/api-keys/"+k.ID, e.bearer("teammate"), ""); status != 204 {
		t.Fatalf("revocation by a teammate: %d %s", status, b)
	}
	if status, _ := e.do("POST", "/acme/httpreq/present", basic(k.ID, k.Key), `{"fqdn": "_acme-challenge.example.com.", "value": "v"}`); status != 401 {
		t.Fatalf("revoked key accepted: %d", status)
	}
}

// A value already in the RRset cannot be claimed by another author, who
// then could clean it up.
func TestHTTPReqNoClaimOfOthersValue(t *testing.T) {
	e := newACMEEnv(t)
	k1 := e.createKey(`{"name": "one", "team": "web", "role": "acme"}`)
	k2 := e.createKey(`{"name": "two", "team": "web", "role": "acme"}`)
	body := `{"fqdn": "_acme-challenge.example.com.", "value": "v1"}`
	if status, b := e.do("POST", "/acme/httpreq/present", basic(k1.ID, k1.Key), body); status != 200 {
		t.Fatalf("present: %d %s", status, b)
	}
	if status, b := e.do("POST", "/acme/httpreq/present", basic(k2.ID, k2.Key), body); status != 409 || !strings.Contains(string(b), "value_taken") {
		t.Errorf("claim of another's value: %d %s", status, b)
	}
	e.do("POST", "/acme/httpreq/cleanup", basic(k2.ID, k2.Key), body)
	if got := e.txt("_acme-challenge"); !slices.Equal(got, []string{"v1"}) {
		t.Fatalf("value of another key removed: %v", got)
	}
	hdr := map[string]string{"X-Api-User": k2.ID, "X-Api-Key": k2.Key}
	v := challenge("shared")
	e.do("POST", "/acme/httpreq/present", basic(k1.ID, k1.Key), `{"fqdn": "_acme-challenge.www.example.com.", "value": "`+v+`"}`)
	if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"www.example.com", "txt": "`+v+`"}`); status != 409 {
		t.Errorf("acme-dns claim of another's value: %d %s", status, b)
	}
}

// The allowfrom of a key's registrations for a domain also holds on the
// httpreq endpoints and the RRset API: every write by that key to the
// _acme-challenge RRset of the domain.
func TestACMEAllowFromAllEntryPoints(t *testing.T) {
	e := newACMEEnv(t)
	k := e.createKey(`{"name": "k", "team": "web", "role": "acme"}`)
	if status, b := e.do("POST", "/acme/acme-dns/register", basic(k.ID, k.Key), `{"allowfrom": ["192.0.2.0/24"], "domain": "api.example.com"}`); status != 201 {
		t.Fatalf("register: %d %s", status, b)
	}
	if status, b := e.do("POST", "/acme/httpreq/present", basic(k.ID, k.Key), `{"fqdn": "_acme-challenge.api.example.com.", "value": "v"}`); status != 403 {
		t.Errorf("httpreq from a refused address: %d %s", status, b)
	}
	put := map[string]string{"Authorization": "Bearer " + k.Key, "Content-Type": "application/json"}
	if status, b := e.do("PUT", "/api/v1/zones/example.com/rrsets/_acme-challenge.api/TXT", put, `{"ttl": 600, "values": ["v"]}`); status != 403 {
		t.Errorf("RRset API from a refused address: %d %s", status, b)
	}
	if got := e.txt("_acme-challenge.api"); len(got) != 0 {
		t.Fatalf("written: %v", got)
	}
	if status, b := e.do("POST", "/acme/httpreq/present", basic(k.ID, k.Key), `{"fqdn": "_acme-challenge.www.example.com.", "value": "v"}`); status != 200 {
		t.Errorf("other domain: %d %s", status, b)
	}
}

// One author cannot fill a challenge RRset: values are capped per author
// below the RRset cap.
func TestHTTPReqValuesPerAuthor(t *testing.T) {
	e := newACMEEnvWith(t, "acme: {max_values_per_author: 2}\n")
	k1 := e.createKey(`{"name": "one", "team": "web", "role": "acme"}`)
	k2 := e.createKey(`{"name": "two", "team": "web", "role": "acme"}`)
	body := func(v string) string { return `{"fqdn": "_acme-challenge.example.com.", "value": "` + v + `"}` }
	for _, v := range []string{"v1", "v2"} {
		if status, b := e.do("POST", "/acme/httpreq/present", basic(k1.ID, k1.Key), body(v)); status != 200 {
			t.Fatalf("%s: %d %s", v, status, b)
		}
	}
	if status, b := e.do("POST", "/acme/httpreq/present", basic(k1.ID, k1.Key), body("v3")); status != 409 || !strings.Contains(string(b), "too_many_values") {
		t.Fatalf("per-author cap: %d %s", status, b)
	}
	if status, b := e.do("POST", "/acme/httpreq/present", basic(k2.ID, k2.Key), body("w1")); status != 200 {
		t.Fatalf("another author blocked: %d %s", status, b)
	}
	hdr := map[string]string{"X-Api-User": k1.ID, "X-Api-Key": k1.Key}
	if status, b := e.do("POST", "/acme/acme-dns/update", hdr, `{"subdomain":"example.com", "txt": "`+challenge("d")+`"}`); status != 409 {
		t.Fatalf("per-author cap across protocols: %d %s", status, b)
	}
}

// Concurrent first uses of new subdomains cannot exceed the registration
// cap: it is checked under the zone lock.
func TestACMERegistrationCapConcurrent(t *testing.T) {
	e := newACMEEnvWith(t, "acme: {max_registrations: 3}\n")
	k := e.createKey(`{"name": "k", "team": "web", "role": "acme"}`)
	hdr := map[string]string{"X-Api-User": k.ID, "X-Api-Key": k.Key}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := fmt.Sprintf("n%d.example.com", i)
			req, _ := http.NewRequest("POST", e.gate.URL+"/acme/acme-dns/update", strings.NewReader(`{"subdomain":"`+d+`", "txt": "`+challenge(d)+`"}`))
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()
	if regs := e.registrations(k.ID); len(regs) > 3 {
		t.Fatalf("%d registrations beyond the cap of 3", len(regs))
	}
}
