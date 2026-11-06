package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

// The binary must expose adoption, the Terraform export and MCP writes:
// they are wired here and nowhere else.
func TestNewWiresOperations(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	keyHash := hex.EncodeToString(sum[:])
	yaml := `
providers:
  - {id: eurodns, kind: eurodns, eurodns: {base_url: "http://127.0.0.1:1", app_id: app, max_retries: 0}}
zones: [example.com]
store: {type: sqlite, sqlite: {path: ` + filepath.Join(t.TempDir(), "g.db") + `}}
mcp: {enabled: true, allow_writes: true}
virtual_keys:
  - {id: t, app_id: vk, key_sha256: ` + keyHash + `, roles: [admin], teams: [web], expires_at: 2099-01-01T00:00:00Z}
roles:
  admin:
    rules: [{zones: [example.com], actions: [dns.read, dns.record.adopt, ui.read]}]
`
	cfg, err := config.Parse([]byte(yaml), func(k string) string {
		if k == "EURODNS_API_KEY" {
			return "k"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Holder: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/zones/example.com/adopt/preview", "/api/v1/zones/example.com/terraform"} {
		method := http.MethodPost
		if strings.HasSuffix(path, "terraform") {
			method = http.MethodGet
		}
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("X-APP-ID", "vk")
		req.Header.Set("X-API-KEY", "secret")
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code == http.StatusNotImplemented || rec.Code == http.StatusUnauthorized {
			t.Errorf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
		}
	}
}

// Zone discovery: the account listing goes through the shared upstream
// transport of the provider and discovered zones are served read-only.
func TestZonesDiscoveryWiring(t *testing.T) {
	var searches atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "k" {
			http.Error(w, "no key", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/domains/search":
			searches.Add(1)
			w.Header().Set("pagination-count", "2")
			_, _ = w.Write([]byte(`[{"domainName":"example.com"},{"domainName":"other.org"}]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dns-zones/"):
			name := strings.TrimPrefix(r.URL.Path, "/dns-zones/")
			_, _ = w.Write([]byte(`{"name":"` + name + `","records":[{"id":1,"type":"A","host":"www","ttl":3600,"rdata":"192.0.2.1"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()
	sum := sha256.Sum256([]byte("secret"))
	yaml := `
providers:
  - id: eurodns
    kind: eurodns
    eurodns: {base_url: "` + up.URL + `", app_id: app, rate: {every: 1ms, burst: 10}}
zones: [example.com]
virtual_keys:
  - {id: t, app_id: vk, key_sha256: ` + hex.EncodeToString(sum[:]) + `, roles: [reader], expires_at: 2099-01-01T00:00:00Z}
roles:
  reader:
    rules: [{zones: ["*"], actions: [dns.read, ui.read]}]
`
	cfg, err := config.Parse([]byte(yaml), func(k string) string {
		if k == "EURODNS_API_KEY" {
			return "k"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, err := New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Holder: "t"})
	if err != nil {
		t.Fatal(err)
	}
	a.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for !a.Discovery.Loaded() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !a.Discovery.Loaded() || searches.Load() != 1 {
		t.Fatalf("discovery not loaded (%d searches)", searches.Load())
	}
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-APP-ID", "vk")
		req.Header.Set("X-API-KEY", "secret")
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/api/v1/zones"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"zone":"other.org","provider":"eurodns","folder":"/","unmanaged":true`) ||
		!strings.Contains(rec.Body.String(), `"zone":"example.com","provider":"eurodns"`) {
		t.Fatalf("zones: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/v1/zones/other.org/rrsets"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"provider":"eurodns","unmanaged":true`) {
		t.Fatalf("rrsets: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/dns-zones/other.org"); rec.Code != http.StatusForbidden {
		t.Fatalf("EuroDNS API on an unmanaged zone: %d", rec.Code)
	}
}

// A route53 provider is built from its configuration (no AWS call at
// startup), and the plan GC of Run and Maintenance is the store's.
func TestNewWiresRoute53AndPlanGC(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	yaml := `
providers:
  - id: r53
    kind: route53
    route53: {region: eu-west-3, hosted_zones: {example.com: Z1EXAMPLE}}
zones: [example.com]
issuers:
  - {name: ci, issuer: "https://token.example.net", audiences: [dns-gate]}
roles:
  reader:
    rules: [{zones: [example.com], actions: [dns.read]}]
`
	cfg, err := config.Parse([]byte(yaml), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Holder: "t"})
	if err != nil {
		t.Fatal(err)
	}
	st := a.Discovery.Status()
	if len(st.Providers) != 1 || st.Providers[0].ID != "r53" || st.Providers[0].Kind != "route53" {
		t.Fatalf("providers %+v", st.Providers)
	}
	if a.PlanGC == nil {
		t.Fatal("plan GC not wired")
	}
	if err := a.PlanGC(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The transfer and team routes are wired, and undeclared store owners and
// config teams are reported.
func TestTeamsWiringAndWarnings(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	yaml := `
providers:
  - {id: eurodns, kind: eurodns, eurodns: {base_url: "http://127.0.0.1:1", app_id: app, max_retries: 0}}
zones: [example.com]
virtual_keys:
  - {id: t, app_id: vk, key_sha256: ` + hex.EncodeToString(sum[:]) + `, roles: [reader], teams: [web], expires_at: 2099-01-01T00:00:00Z}
roles:
  reader:
    rules: [{zones: [example.com], actions: [dns.read, ui.read]}]
`
	cfg, err := config.Parse([]byte(yaml), func(k string) string {
		if k == "EURODNS_API_KEY" {
			return "k"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(&logs, nil)), Options{Holder: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `team \"web\" is not declared`) {
		t.Fatalf("config warning not logged: %s", logs.String())
	}
	now := time.Now()
	if err := a.Store.Put(context.Background(), store.Ownership{Zone: "example.com", Host: "old", Type: "A", Owner: "legacy", State: store.StateActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	a.WarnUndeclaredOwners(context.Background())
	if !strings.Contains(logs.String(), "team=legacy") {
		t.Fatalf("store owner warning not logged: %s", logs.String())
	}
	for _, path := range []string{"/api/v1/transfers", "/api/v1/teams"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-APP-ID", "vk")
		req.Header.Set("X-API-KEY", "secret")
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

// A base file adding a teams block must be refused by --check while the
// active managed revision names an undeclared team.
func TestCheckManagedPolicy(t *testing.T) {
	db := filepath.Join(t.TempDir(), "g.db")
	yaml := `
providers:
  - {id: eurodns, kind: eurodns, eurodns: {base_url: "http://127.0.0.1:1", app_id: app, max_retries: 0}}
zones: [example.com]
store: {type: sqlite, sqlite: {path: ` + db + `}}
issuers:
  - {name: ci, issuer: "https://token.example.net", audiences: [dns-gate]}
roles:
  reader:
    rules: [{zones: [example.com], actions: [dns.read, ui.read]}]
policy:
  editable: true
  bounds: {zones: [example.com], actions: [dns.read, ui.read]}
`
	parse := func(doc string) *config.Config {
		cfg, err := config.Parse([]byte(doc), func(k string) string {
			if k == "EURODNS_API_KEY" {
				return "k"
			}
			return ""
		})
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	ctx := context.Background()
	st, err := store.NewSQLite(ctx, store.SQLiteConfig{Path: db})
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"groups":{},"roles":{"r":{"rules":[{"zones":["example.com"],"actions":["dns.read"]}]}},` +
		`"bindings":[{"role":"r","team":"web","subjects":[{"issuer":"ci","claims":{"sub":["repo:acme/*"]}}]}],"virtual_keys":[]}`
	if err := st.CreateRevision(ctx, store.PolicyRevision{ID: "rev-00000001", Document: []byte(doc), Status: "proposed", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.Activate(ctx, "rev-00000001", "", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = st.(io.Closer).Close()
	if problems, err := CheckManagedPolicy(ctx, parse(yaml)); err != nil || len(problems) != 0 {
		t.Fatalf("valid revision: %v %v", problems, err)
	}
	problems, err := CheckManagedPolicy(ctx, parse(yaml+"teams: {}\n"))
	if err != nil || len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), `team "web" is not declared`) {
		t.Fatalf("revision invalid against the new base not reported: %v %v", problems, err)
	}
}
