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
)

// The binary must expose adoption, the Terraform export and MCP writes:
// they are wired here and nowhere else.
func TestNewWiresOperations(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	keyHash := hex.EncodeToString(sum[:])
	yaml := `
upstream: {base_url: "http://127.0.0.1:1", app_id: app, max_retries: 0}
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

// zones_discovery: the account listing goes through the shared upstream
// transport and discovered zones are served read-only.
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
upstream: {base_url: "` + up.URL + `", app_id: app, rate: {every: 1ms, burst: 10}}
zones: [example.com]
zones_discovery: {enabled: true}
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
	if rec := get("/api/v1/zones"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"zone":"other.org","unmanaged":true`) {
		t.Fatalf("zones: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/v1/zones/other.org/rrsets"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"unmanaged":true`) {
		t.Fatalf("rrsets: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/dns-zones/other.org"); rec.Code != http.StatusForbidden {
		t.Fatalf("EuroDNS API on an unmanaged zone: %d", rec.Code)
	}
}
