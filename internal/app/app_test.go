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
	"testing"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
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
