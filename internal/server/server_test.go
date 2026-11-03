package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/audit"
	"github.com/KamorionLabs/eurodns-gate/internal/authn"
	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/mcpb"
	"github.com/KamorionLabs/eurodns-gate/internal/oidctest"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/store"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-gate/internal/zonewrite"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

type fakeEngine struct {
	zonewrite.Engine
	mu        sync.Mutex
	lastMatch string
	lastZone  *eurodns.Zone
	saveErr   error
}

func (f *fakeEngine) GetZone(ctx context.Context, s *identity.Subject, zone string) (*eurodns.Zone, error) {
	return &eurodns.Zone{Name: zone, Records: []eurodns.Record{{Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"}}, ETag: `"v7"`}, nil
}

func (f *fakeEngine) SaveZone(ctx context.Context, s *identity.Subject, zone string, z *eurodns.Zone, ifMatch string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastMatch, f.lastZone = ifMatch, z
	return f.saveErr
}

func (f *fakeEngine) AddRecords(ctx context.Context, s *identity.Subject, zone string, recs []eurodns.Record, ifMatch string) (*eurodns.Zone, error) {
	return &eurodns.Zone{Name: zone, Records: recs, ETag: "v8"}, nil
}

func (f *fakeEngine) DeleteRecord(ctx context.Context, s *identity.Subject, zone string, id int64, ifMatch string) (*eurodns.Zone, error) {
	if id != 42 {
		return nil, &zonewrite.Error{Reason: zonewrite.ReasonForeignRRset, Message: "record not owned by the gate"}
	}
	return &eurodns.Zone{Name: zone}, nil
}

func (f *fakeEngine) Adopt(ctx context.Context, s *identity.Subject, zone string, req eurodns.AdoptRequest) error {
	return nil
}

func (f *fakeEngine) Zones(ctx context.Context, s *identity.Subject) ([]uiapi.ZoneSummary, error) {
	return []uiapi.ZoneSummary{{Zone: "example.com", RRsets: 3, Managed: 1}, {Zone: "example.org", RRsets: 1}}, nil
}

func (f *fakeEngine) Inventory(ctx context.Context, s *identity.Subject, zone string) (*uiapi.ZoneInventory, error) {
	return &uiapi.ZoneInventory{Zone: zone, RRsets: []uiapi.RRset{{Host: "www", Type: "A", Status: uiapi.StatusManaged, Owner: "web"}}}, nil
}

type memAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memAudit) Log(_ context.Context, e audit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
}

func (m *memAudit) ListAudit(_ context.Context, q store.AuditQuery) ([]audit.Event, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]audit.Event(nil), m.events...), "next", nil
}

type env struct {
	srv      *httptest.Server
	idp      *oidctest.Provider
	engine   *fakeEngine
	audit    *memAudit
	upstream *httptest.Server
	upReq    chan *http.Request
	holder   *policy.Holder
	ops      *fakeOps
	store    store.Store
	offset   time.Duration
}

func (e *env) clock() time.Time { return time.Now().Add(e.offset) }

// keyTransport plays the role of eurodns.Transport: it injects the API key.
type keyTransport struct{}

func (keyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-API-KEY", "upstream-secret")
	return http.DefaultTransport.RoundTrip(r)
}

func newEnv(t *testing.T) *env { return newEnvWith(t, nil) }

func newEnvWith(t *testing.T, tweak func(*config.Config)) *env {
	t.Helper()
	e := &env{idp: oidctest.New(), engine: &fakeEngine{}, audit: &memAudit{}, upReq: make(chan *http.Request, 4), ops: &fakeOps{}}
	t.Cleanup(e.idp.Close)
	e.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.upReq <- r.Clone(context.Background())
		w.Header().Set("Set-Cookie", "upstream=1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1}]`))
	}))
	t.Cleanup(e.upstream.Close)

	cfg := &config.Config{
		Zones:    []string{"example.com", "example.org"},
		Limits:   config.Limits{MaxBodyBytes: 4096, MaxChangesPerRequest: 20},
		Upstream: config.Upstream{BaseURL: e.upstream.URL},
		Issuers: []config.Issuer{{
			Name: "idp", Issuer: e.idp.URL, Audiences: []string{"eurodns-gate"}, Category: "pipeline",
			NameClaim: "email", Algorithms: config.DefaultAlgorithms, ClockSkew: config.Duration(time.Minute),
		}},
		Roles: map[string]config.Role{
			"writer": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{policy.ActionDNSRead, policy.ActionRecordWrite, policy.ActionUIRead}}}},
			"admin":  {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{policy.ActionRecordAdopt, policy.ActionUIRead}}}},
		},
		Bindings: []config.Binding{
			{Role: "writer", Team: "web", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"writer"}}}}},
			{Role: "admin", Team: "ops", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"admin"}}}}},
		},
	}
	e.srv = httptest.NewUnstartedServer(nil)
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	cfg.UI = config.UI{
		Enabled: true, Issuer: "idp", ClientID: e.idp.ClientID, RedirectURL: e.srv.URL + "/auth/callback",
		Scopes: []string{"openid", "email"}, SessionTTL: config.Duration(time.Hour), SessionKey: []byte(strings.Repeat("k", 32)),
	}

	if tweak != nil {
		tweak(cfg)
	}
	h, err := policy.NewHolder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.holder, e.store = h, store.NewMemory()
	an, err := authn.New(cfg, e.idp.Client(), h)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		Config: cfg, Authn: an, Authz: policy.New(h), Engine: e.engine, Audit: e.audit, AuditReader: e.audit,
		Policy: h, PolicyStore: e.store, Ownership: e.store, Now: func() time.Time { return e.clock() },
		Ops: e.ops, Terraform: e.ops.terraform,
		Upstream: keyTransport{}, HTTPClient: e.idp.Client(),
		UIFiles: fstest.MapFS{"index.html": {Data: []byte("<html>ui</html>")}, "assets/app.js": {Data: []byte("js")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Config.Handler = s.Handler()
	return e
}

func (e *env) token(sub string) string {
	return e.idp.Sign(map[string]any{"sub": sub, "aud": "eurodns-gate", "email": sub + "@example.com"})
}

func (e *env) do(t *testing.T, method, path, tok, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func reason(t *testing.T, r *http.Response) string {
	var b errorBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	return b.Reason
}

func TestEngineRoutes(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")

	r := e.do(t, "GET", "/dns-zones/example.com", tok, "", nil)
	if r.StatusCode != 200 || r.Header.Get("ETag") != `"v7"` || r.Header.Get("X-Request-ID") == "" {
		t.Fatalf("get zone: %d %v", r.StatusCode, r.Header)
	}

	r = e.do(t, "PUT", "/dns-zones/example.com", tok, `{"records":[],"urlForwards":[],"mailForwards":[]}`, map[string]string{"If-Match": `W/"v7"`})
	if r.StatusCode != 204 || e.engine.lastMatch != "v7" {
		t.Fatalf("save: %d if-match=%q", r.StatusCode, e.engine.lastMatch)
	}

	e.engine.saveErr = &zonewrite.Error{Reason: zonewrite.ReasonPrecondition, Message: "zone changed"}
	if r = e.do(t, "PUT", "/dns-zones/example.com", tok, `{}`, nil); r.StatusCode != 412 || reason(t, r) != "precondition" {
		t.Fatalf("precondition: %d", r.StatusCode)
	}
	e.engine.saveErr = &zonewrite.Error{Reason: zonewrite.ReasonTainted, Message: "x"}
	if r = e.do(t, "PUT", "/dns-zones/example.com", tok, `{}`, nil); r.StatusCode != 409 {
		t.Fatalf("tainted: %d", r.StatusCode)
	}

	if r = e.do(t, "POST", "/dns-zones/example.com/dns-records", tok, `[{"type":"TXT","host":"a","ttl":600,"rdata":"x"}]`, nil); r.StatusCode != 200 || r.Header.Get("ETag") != `"v8"` {
		t.Fatalf("add: %d", r.StatusCode)
	}
	if r = e.do(t, "DELETE", "/dns-zones/example.com/dns-records/7", tok, "", nil); r.StatusCode != 409 || reason(t, r) != "foreign_rrset" {
		t.Fatalf("delete foreign: %d", r.StatusCode)
	}
	if r = e.do(t, "PUT", "/dns-zones/example.com", tok, `{"records":[`+strings.Repeat(" ", 5000)+`]}`, nil); r.StatusCode != 413 {
		t.Fatalf("body limit: %d", r.StatusCode)
	}
}

func TestDenials(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	cases := []struct {
		method, path, tok string
		status            int
		reason            string
	}{
		{"GET", "/dns-zones/example.com", "", 401, "unauthenticated"},
		{"GET", "/dns-zones/example.com", e.token("nobody"), 403, "no_binding"},
		{"GET", "/dns-zones/example.org", tok, 403, "forbidden"},
		{"GET", "/dns-zones/other.com", tok, 403, "zone_not_managed"},
		{"PUT", "/contact-profiles/1", tok, 403, "operation_denied"},
		{"GET", "/accounts/prepaid-balance", tok, 403, "operation_denied"},
		{"GET", "/dns-zones/example.com%2Fsnapshots", tok, 400, "bad_request"},
		{"GET", "/dns-zones/example.com?debug=1", tok, 400, "bad_request"},
		{"GET", "/does-not-exist", tok, 404, "not_found"},
	}
	for _, c := range cases {
		r := e.do(t, c.method, c.path, c.tok, "", nil)
		if r.StatusCode != c.status || reason(t, r) != c.reason {
			t.Errorf("%s %s: %d, want %d %s", c.method, c.path, r.StatusCode, c.status, c.reason)
		}
	}
	if len(e.audit.events) == 0 {
		t.Fatal("denials must be audited")
	}
}

func TestPassthrough(t *testing.T) {
	e := newEnv(t)
	r := e.do(t, "GET", "/dns-zones/EXAMPLE.com/snapshots", e.token("writer"), "", map[string]string{"X-Custom": "leak", "Cookie": "a=b"})
	if r.StatusCode != 200 || r.Header.Get("Set-Cookie") != "" {
		t.Fatalf("passthrough: %d %v", r.StatusCode, r.Header)
	}
	up := <-e.upReq
	if up.URL.Path != "/dns-zones/example.com/snapshots" || up.Header.Get("Authorization") != "" || up.Header.Get("X-Custom") != "" || up.Header.Get("Cookie") != "" {
		t.Fatalf("upstream request %s %v", up.URL.Path, up.Header)
	}
	if up.Header.Get("X-API-KEY") != "upstream-secret" {
		t.Fatal("upstream credentials not injected")
	}
}

func TestVirtualKeyNotForwarded(t *testing.T) {
	e := newEnv(t)
	r := e.do(t, "GET", "/dns-zones/example.com/snapshots", "", "", map[string]string{"X-APP-ID": "client", "X-API-KEY": "client-key"})
	if r.StatusCode != 401 {
		t.Fatalf("unknown virtual key: %d", r.StatusCode)
	}
	select {
	case <-e.upReq:
		t.Fatal("request reached upstream")
	default:
	}
}

func TestGateInfoAndAdopt(t *testing.T) {
	e := newEnv(t)
	r := e.do(t, "GET", eurodns.GateInfoPath, "", "", nil)
	var info eurodns.GateInfo
	_ = json.NewDecoder(r.Body).Decode(&info)
	if r.StatusCode != 200 || !info.HasFeature(eurodns.FeatureOwnership) {
		t.Fatalf("gate info: %d %+v", r.StatusCode, info)
	}
	body := `{"rrsets":[{"host":"www","type":"A"}]}`
	if r = e.do(t, "POST", eurodns.GateInfoPath+"/zones/example.org/adopt", e.token("writer"), body, nil); r.StatusCode != 403 {
		t.Fatalf("adopt without adopt nor write: %d", r.StatusCode)
	}
	// A writer reaches the engine: importing its own RRsets is a no-op there.
	if r = e.do(t, "POST", eurodns.GateInfoPath+"/zones/example.com/adopt", e.token("writer"), body, nil); r.StatusCode != 204 {
		t.Fatalf("no-op adopt by the owner team: %d", r.StatusCode)
	}
	if r = e.do(t, "POST", eurodns.GateInfoPath+"/zones/example.com/adopt", e.token("admin"), body, nil); r.StatusCode != 204 {
		t.Fatalf("adopt: %d", r.StatusCode)
	}
	if r = e.do(t, "POST", eurodns.GateInfoPath+"/zones/example.com/delete", e.token("admin"), body, nil); r.StatusCode != 404 {
		t.Fatalf("unknown extension: %d", r.StatusCode)
	}
}

func TestUIAPIWithBearer(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	if r := e.do(t, "GET", "/api/v1/me", "", "", nil); r.StatusCode != 401 {
		t.Fatalf("me without auth: %d", r.StatusCode)
	}
	r := e.do(t, "GET", "/api/v1/me", tok, "", nil)
	var me uiapi.Me
	_ = json.NewDecoder(r.Body).Decode(&me)
	if me.Name != "writer@example.com" || me.Category != "pipeline" || me.Teams[0] != "web" {
		t.Fatalf("me: %+v", me)
	}
	r = e.do(t, "GET", "/api/v1/zones", tok, "", nil)
	var zs []uiapi.ZoneSummary
	_ = json.NewDecoder(r.Body).Decode(&zs)
	if len(zs) != 1 || zs[0].Zone != "example.com" {
		t.Fatalf("zones filtered by ui.read: %+v", zs)
	}
	if r = e.do(t, "GET", "/api/v1/zones/example.org/rrsets", tok, "", nil); r.StatusCode != 403 {
		t.Fatalf("inventory of unreadable zone: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/api/v1/zones/example.com/rrsets", tok, "", nil); r.StatusCode != 200 {
		t.Fatalf("inventory: %d", r.StatusCode)
	}

	e.audit.Log(context.Background(), audit.Event{Time: time.Now(), Zone: "example.com", Decision: "allow", Subject: "idp:writer", SubjectCategory: "pipeline"})
	e.audit.Log(context.Background(), audit.Event{Time: time.Now(), Zone: "example.org", Decision: "allow"})
	e.audit.Log(context.Background(), audit.Event{Time: time.Now(), Decision: "deny", Reason: "unauthenticated"})
	r = e.do(t, "GET", "/api/v1/audit?category=pipeline&limit=10", tok, "", nil)
	var page uiapi.AuditPage
	_ = json.NewDecoder(r.Body).Decode(&page)
	for _, en := range page.Entries {
		if en.Zone != "example.com" {
			t.Fatalf("audit leaks %+v", en)
		}
	}
	if page.NextCursor != "next" || len(page.Entries) == 0 {
		t.Fatalf("audit page: %+v", page)
	}
	if r = e.do(t, "GET", "/api/v1/audit?zone=example.org", tok, "", nil); r.StatusCode != 403 {
		t.Fatalf("audit of unreadable zone: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/api/v1/audit?limit=0", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("bad limit: %d", r.StatusCode)
	}
	if r = e.do(t, "GET", "/api/v1/audit?evil=1", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("unknown param: %d", r.StatusCode)
	}
	if r = e.do(t, "POST", "/api/v1/me", tok, "{}", nil); r.StatusCode != 405 {
		t.Fatalf("POST on read API: %d", r.StatusCode)
	}
}

func TestLoginFlow(t *testing.T) {
	e := newEnv(t)
	e.idp.LoginClaims = map[string]any{"sub": "admin", "email": "alice@example.com"}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(e.srv.URL + "/auth/login?next=/ui/zones/example.com")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "<html>ui</html>" || resp.Request.URL.Path != "/ui/zones/example.com" {
		t.Fatalf("login did not land on the UI: %d %s %s", resp.StatusCode, resp.Request.URL, body)
	}

	resp, err = client.Get(e.srv.URL + "/api/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	var me uiapi.Me
	_ = json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if resp.StatusCode != 200 || me.Category != identity.CategoryHuman || me.Name != "alice@example.com" || me.Subject != "idp:admin" {
		t.Fatalf("session me: %d %+v", resp.StatusCode, me)
	}

	resp, _ = client.Post(e.srv.URL+"/auth/logout", "", nil)
	resp.Body.Close()
	resp, _ = client.Get(e.srv.URL + "/api/v1/me")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}
}

func TestLoginRejectsForgedState(t *testing.T) {
	e := newEnv(t)
	e.idp.LoginClaims = map[string]any{"sub": "admin"}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(e.srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	auth, _ := url.Parse(resp.Header.Get("Location"))
	q := auth.Query()
	q.Set("state", "forged")
	auth.RawQuery = q.Encode()
	resp, err = client.Get(auth.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("forged state accepted: %d", resp.StatusCode)
	}
	if u, _ := url.Parse(e.srv.URL); len(jar.Cookies(u)) != 0 {
		for _, c := range jar.Cookies(u) {
			if strings.Contains(c.Name, "session") {
				t.Fatal("session issued with a forged state")
			}
		}
	}
}

func TestLoginRejectsUnboundUser(t *testing.T) {
	e := newEnv(t)
	e.idp.LoginClaims = map[string]any{"sub": "stranger"}
	jar, _ := cookiejar.New(nil)
	resp, err := (&http.Client{Jar: jar}).Get(e.srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("unbound user: %d", resp.StatusCode)
	}
}

func TestStaticUI(t *testing.T) {
	e := newEnv(t)
	r := e.do(t, "GET", "/ui/assets/app.js", "", "", nil)
	if b, _ := io.ReadAll(r.Body); string(b) != "js" || !strings.Contains(r.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("asset: %s %v", b, r.Header)
	}
	r = e.do(t, "GET", "/ui/zones/example.com", "", "", nil)
	if b, _ := io.ReadAll(r.Body); string(b) != "<html>ui</html>" {
		t.Fatalf("SPA fallback: %s", b)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := client.Get(e.srv.URL + "/")
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/ui/" {
		t.Fatalf("root redirect: %d", resp.StatusCode)
	}
}

func TestUIAPIConnect(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	if r := e.do(t, "GET", "/api/v1/connect", "", "", nil); r.StatusCode != 401 {
		t.Fatalf("connect without auth: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/connect", e.token("nobody"), "", nil); r.StatusCode != 403 {
		t.Fatalf("connect without ui.read: %d", r.StatusCode)
	}
	r := e.do(t, "GET", "/api/v1/connect", tok, "", nil)
	var c uiapi.Connect
	_ = json.NewDecoder(r.Body).Decode(&c)
	if r.StatusCode != 200 || c.BaseURL != e.srv.URL || c.MCP.Enabled || c.MCP.URL != e.srv.URL+"/mcp" || c.ClientID != e.idp.ClientID || c.CLIScope != "" {
		t.Fatalf("connect: %d %+v", r.StatusCode, c)
	}
	if c.Issuer == nil || c.Issuer.Kind != "oidc" || c.Issuer.URL != e.idp.URL || c.Issuer.TenantID != "" {
		t.Fatalf("connect issuer: %+v", c.Issuer)
	}
}

func TestUIAPIConnectEntraAndMCP(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	e := newEnvWith(t, func(c *config.Config) {
		c.Issuers = append(c.Issuers, config.Issuer{
			Name: "entra", Issuer: "https://login.microsoftonline.com/" + tenant + "/v2.0", Audiences: []string{"api://gate"},
			JWKSURL: "https://login.microsoftonline.com/" + tenant + "/discovery/v2.0/keys", Algorithms: config.DefaultAlgorithms, Category: "human",
		})
		c.UI.Issuer, c.UI.ClientID, c.UI.CLIScope = "entra", "99999999-8888-7777-6666-555555555555", "api://99999999-8888-7777-6666-555555555555/.default"
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600, PublicURL: "https://gate.example.com/"}
	})
	r := e.do(t, "GET", "/api/v1/connect", e.token("writer"), "", nil)
	var c uiapi.Connect
	_ = json.NewDecoder(r.Body).Decode(&c)
	if c.BaseURL != "https://gate.example.com" || !c.MCP.Enabled || c.MCP.AllowWrites || c.MCP.URL != "https://gate.example.com/mcp" {
		t.Fatalf("connect mcp: %+v", c)
	}
	if c.Issuer == nil || c.Issuer.Kind != "entra" || c.Issuer.TenantID != tenant || c.CLIScope != "api://99999999-8888-7777-6666-555555555555/.default" {
		t.Fatalf("connect entra: %+v %+v", c, c.Issuer)
	}

	e = newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, AllowWrites: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
	})
	r = e.do(t, "GET", "/api/v1/connect", e.token("writer"), "", nil)
	c = uiapi.Connect{}
	_ = json.NewDecoder(r.Body).Decode(&c)
	if !c.MCP.AllowWrites || c.BaseURL != e.srv.URL {
		t.Fatalf("connect writes: %+v", c)
	}
}

func TestUIAPIClaudeDesktopExtension(t *testing.T) {
	const path = "/api/v1/connect/claude-desktop.mcpb"
	connect := func(e *env) uiapi.Connect {
		var c uiapi.Connect
		_ = json.NewDecoder(e.do(t, "GET", "/api/v1/connect", e.token("writer"), "", nil).Body).Decode(&c)
		return c
	}

	// Without MCP, or without the UI login, there is no extension.
	for name, tweak := range map[string]func(*config.Config){
		"mcp off": nil,
		"ui off": func(c *config.Config) {
			c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
			c.UI.Enabled = false
		},
	} {
		e := newEnvWith(t, tweak)
		if tweak == nil {
			if c := connect(e); c.ClaudeDesktopExtensionURL != "" {
				t.Fatalf("%s: extension URL %q", name, c.ClaudeDesktopExtensionURL)
			}
		}
		if r := e.do(t, "GET", path, e.token("writer"), "", nil); r.StatusCode != 404 {
			t.Fatalf("%s: extension %d", name, r.StatusCode)
		}
	}

	e := newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600, PublicURL: "https://gate.example.com"}
		c.UI.CLIScope = "api://" + c.UI.ClientID + "/.default"
	})
	if c := connect(e); c.ClaudeDesktopExtensionURL != "https://gate.example.com"+path || c.CLIScope != "api://"+e.idp.ClientID+"/.default" {
		t.Fatalf("extension URL: %q, cli scope %q", c.ClaudeDesktopExtensionURL, c.CLIScope)
	}
	if r := e.do(t, "GET", path, "", "", nil); r.StatusCode != 401 {
		t.Fatalf("extension without auth: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", path, e.token("nobody"), "", nil); r.StatusCode != 403 {
		t.Fatalf("extension without ui.read: %d", r.StatusCode)
	}
	r := e.do(t, "GET", path, e.token("writer"), "", nil)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/zip" || r.Header.Get("Content-Disposition") != `attachment; filename=eurodns-gate-gate.example.com.mcpb` {
		t.Fatalf("extension: %d %v", r.StatusCode, r.Header)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	var m mcpb.Manifest
	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			rc, _ := f.Open()
			err = json.NewDecoder(rc).Decode(&m)
			rc.Close()
		}
	}
	env := m.Server.MCPConfig.Env
	if err != nil || env["EURODNS_GATE_MCP_URL"] != "https://gate.example.com/mcp" || env["EURODNS_GATE_ISSUER"] != e.idp.URL ||
		env["EURODNS_GATE_CLIENT_ID"] != e.idp.ClientID || env["EURODNS_GATE_SCOPE"] != e.idp.ClientID+"/.default" || m.DisplayName != "EuroDNS gate (gate.example.com)" {
		t.Fatalf("manifest: %v %+v", err, m)
	}
}

func TestUIAPIMePermissions(t *testing.T) {
	e := policyEnv(t, true)
	r := e.do(t, "GET", "/api/v1/me", e.human("alice", time.Minute, "Gate.PolicyAdmin"), "", nil)
	var me uiapi.Me
	_ = json.NewDecoder(r.Body).Decode(&me)
	got := map[string]uiapi.Permission{}
	for _, p := range me.Permissions {
		got[p.Role] = p
	}
	if p := got["padmin"]; len(me.Permissions) != 1 || strings.Join(p.Actions, ",") != "policy.read,policy.propose,policy.approve" || p.Hosts == nil || p.Types == nil {
		t.Fatalf("policy admin permissions: %+v", me.Permissions)
	}

	// A managed role shows up once its revision is active.
	tok := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	_, d := propose(t, e, tok, "", managedDoc("app-*"))
	if code, rsn := post(t, e, e.human("bob", time.Minute, "Gate.PolicyAdmin"), "/api/v1/policy/revisions/"+d.ID+"/approve"); code != 200 {
		t.Fatalf("approve: %d %s", code, rsn)
	}
	if code, rsn := post(t, e, tok, "/api/v1/policy/revisions/"+d.ID+"/activate"); code != 200 {
		t.Fatalf("activate: %d %s", code, rsn)
	}
	r = e.do(t, "GET", "/api/v1/me", e.human("dave", time.Minute, "Gate.Operator"), "", nil)
	me = uiapi.Me{}
	_ = json.NewDecoder(r.Body).Decode(&me)
	if len(me.Permissions) != 1 {
		t.Fatalf("operator permissions: %+v", me.Permissions)
	}
	p := me.Permissions[0]
	if p.Role != "web-writer" || p.Zones[0] != "example.com" || p.Actions[0] != policy.ActionRecordWrite || p.Hosts[0] != "app-*" || p.Types[0] != "CNAME" {
		t.Fatalf("managed permission: %+v", p)
	}
}
