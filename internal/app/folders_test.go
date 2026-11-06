package app

import (
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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// folderAccount fakes a EuroDNS account whose domains are in folders.
type folderAccount struct {
	mu      sync.Mutex
	domains [][2]string // name, folderFullPath ("" for null)
}

func (f *folderAccount) move(name, folder string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.domains {
		if f.domains[i][0] == name {
			f.domains[i][1] = folder
		}
	}
}

func (f *folderAccount) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-KEY") != "k" {
		http.Error(w, "no key", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/domains/search":
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for _, d := range f.domains {
			item := map[string]any{"domainName": d[0], "folderFullPath": nil}
			if d[1] != "" {
				item["folderFullPath"] = d[1]
			}
			out = append(out, item)
		}
		w.Header().Set("pagination-count", strconv.Itoa(len(out)))
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dns-zones/"):
		name := strings.TrimPrefix(r.URL.Path, "/dns-zones/")
		_, _ = w.Write([]byte(`{"name":"` + name + `","records":[{"id":1,"type":"A","host":"www","ttl":3600,"rdata":"192.0.2.1"}]}`))
	default:
		http.NotFound(w, r)
	}
}

// EuroDNS folders: discovery keeps the folder of each domain, the provider
// folder filter selects the served zones, role rules select zones by folder
// with the folder known at decision time, and a folder change is audited.
func TestFolderRules(t *testing.T) {
	acct := &folderAccount{domains: [][2]string{
		{"example.es", "/ES"}, {"madrid.example.es", "/ES/Madrid"}, {"example.fr", "/FR"}, {"example.com", ""}, {"example.it", "/IT"},
	}}
	up := httptest.NewServer(acct)
	defer up.Close()
	key := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	yaml := `
providers:
  - id: eurodns
    kind: eurodns
    zones: {folders: ["/", "/ES", "/ES/**", "/FR"]}
    eurodns: {base_url: "` + up.URL + `", app_id: app, rate: {every: 1ms, burst: 50}}
zones: [example.es, example.fr]
virtual_keys:
  - {id: es, app_id: vk-es, key_sha256: ` + key("es-secret") + `, roles: [es-reader], expires_at: 2099-01-01T00:00:00Z}
  - {id: all, app_id: vk-all, key_sha256: ` + key("all-secret") + `, roles: [reader], expires_at: 2099-01-01T00:00:00Z}
roles:
  es-reader:
    rules: [{folders: ["/ES", "/ES/**"], actions: [dns.read, ui.read]}]
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
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditOut, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer auditOut.Close()
	ctx := context.Background()
	a, err := New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Holder: "t", AuditOutput: auditOut})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Discovery.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	get := func(appID, secret, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-APP-ID", appID)
		req.Header.Set("X-API-KEY", secret)
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		return rec
	}
	zones := func(appID, secret, path string) map[string]string {
		t.Helper()
		rec := get(appID, secret, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		var zs []uiapi.ZoneSummary
		if err := json.Unmarshal(rec.Body.Bytes(), &zs); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, z := range zs {
			out[z.Zone] = z.Folder
		}
		return out
	}

	all := zones("vk-all", "all-secret", "/api/v1/zones")
	want := map[string]string{"example.es": "/ES", "madrid.example.es": "/ES/Madrid", "example.fr": "/FR", "example.com": "/"}
	if len(all) != len(want) {
		t.Fatalf("zones = %v (example.it is outside the provider folders)", all)
	}
	for z, f := range want {
		if all[z] != f {
			t.Fatalf("zones = %v", all)
		}
	}
	if got := zones("vk-all", "all-secret", "/api/v1/zones?folder=/ES/**"); len(got) != 1 || got["madrid.example.es"] != "/ES/Madrid" {
		t.Fatalf("folder filter: %v", got)
	}
	if rec := get("vk-all", "all-secret", "/api/v1/zones?folder=ES"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid folder filter: %d", rec.Code)
	}
	if got := zones("vk-es", "es-secret", "/api/v1/zones"); len(got) != 2 || got["example.es"] != "/ES" || got["madrid.example.es"] != "/ES/Madrid" {
		t.Fatalf("zones of the /ES reader: %v", got)
	}
	if rec := get("vk-es", "es-secret", "/api/v1/zones/example.es/rrsets"); rec.Code != http.StatusOK {
		t.Fatalf("read by folder: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("vk-es", "es-secret", "/api/v1/zones/example.fr/rrsets"); rec.Code != http.StatusForbidden {
		t.Fatalf("read outside the folder: %d", rec.Code)
	}

	acct.move("example.es", "/FR")
	acct.move("example.fr", "/ES/Barcelona")
	if err := a.Discovery.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := get("vk-es", "es-secret", "/api/v1/zones/example.es/rrsets"); rec.Code != http.StatusForbidden {
		t.Fatalf("read after the zone left the folder: %d", rec.Code)
	}
	if rec := get("vk-es", "es-secret", "/api/v1/zones/example.fr/rrsets"); rec.Code != http.StatusOK {
		t.Fatalf("read after the zone entered the folder: %d", rec.Code)
	}

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	moved := map[string]string{}
	var listed []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e struct {
			Action, Zone, Provider, Subject string
			RequestID                       string `json:"request_id"`
			Extra                           map[string]any
		}
		if json.Unmarshal([]byte(line), &e) != nil || !strings.HasPrefix(e.Action, "gate.zone.folder") {
			continue
		}
		if e.Provider != "eurodns" || e.Subject != "gate:discovery" || e.RequestID == "" {
			t.Fatalf("event: %s", line)
		}
		switch e.Action {
		case ActionZoneFolderChanged:
			moved[e.Zone] = fmt.Sprint(e.Extra["old"]) + " -> " + fmt.Sprint(e.Extra["new"])
		case ActionZoneFoldersListed:
			listed = append(listed, e.Extra)
		case ActionZoneFolderSeen:
			t.Fatalf("one summary per first listing, not one event per zone: %s", line)
		}
	}
	if len(listed) != 1 || listed[0]["count"] != float64(5) || len(fmt.Sprint(listed[0]["digest"])) != 64 {
		t.Fatalf("first listing summary: %v", listed)
	}
	if len(moved) != 2 || moved["example.es"] != "/ES -> /FR" || moved["example.fr"] != "/FR -> /ES/Barcelona" {
		t.Fatalf("folder change events: %v\n%s", moved, raw)
	}
}
