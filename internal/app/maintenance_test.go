package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

type fakeUpstream struct {
	searches  atomic.Int32
	zoneReads atomic.Int32
	failZones atomic.Bool
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/domains/search":
		f.searches.Add(1)
		w.Header().Set("pagination-count", "2")
		_, _ = w.Write([]byte(`[{"domainName":"example.com"},{"domainName":"other.org"}]`))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dns-zones/"):
		f.zoneReads.Add(1)
		if f.failZones.Load() {
			http.Error(w, `{"error":"down"}`, http.StatusBadRequest)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/dns-zones/")
		_, _ = w.Write([]byte(`{"name":"` + name + `","records":[{"id":1,"type":"A","host":"www","ttl":3600,"rdata":"192.0.2.1"}]}`))
	default:
		http.NotFound(w, r)
	}
}

type countingStore struct {
	store.Store
	active atomic.Int32
}

func (c *countingStore) ActiveRevision(ctx context.Context) (*store.PolicyRevision, error) {
	c.active.Add(1)
	return c.Store.ActiveRevision(ctx)
}

func newMaintenanceApp(t *testing.T, up string, opts Options) *App {
	t.Helper()
	sum := sha256.Sum256([]byte("secret"))
	yaml := `
providers:
  - id: eurodns
    kind: eurodns
    eurodns: {base_url: "` + up + `", app_id: app, max_retries: 0, rate: {every: 1ms, burst: 10}}
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
	if opts.Holder == "" {
		opts.Holder = "t"
	}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), opts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMaintenanceOnePass(t *testing.T) {
	fu := &fakeUpstream{}
	up := httptest.NewServer(fu)
	defer up.Close()
	a := newMaintenanceApp(t, up.URL, Options{})
	var gcCalls atomic.Int32
	a.PlanGC = func(context.Context) error { gcCalls.Add(1); return nil }
	ctx := context.Background()

	if err := a.Maintenance(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.Discovery.Loaded() || fu.searches.Load() != 1 {
		t.Fatalf("discovery not refreshed (%d searches)", fu.searches.Load())
	}
	if fu.zoneReads.Load() == 0 {
		t.Fatal("managed zone not reconciled")
	}
	if gcCalls.Load() != 1 {
		t.Fatalf("plan GC called %d times", gcCalls.Load())
	}

	reads := fu.zoneReads.Load()
	if err := a.Maintenance(ctx); err != nil {
		t.Fatal(err)
	}
	if fu.searches.Load() != 1 {
		t.Errorf("a fresh zone list must not be listed again (%d searches)", fu.searches.Load())
	}
	if fu.zoneReads.Load() == reads || gcCalls.Load() != 2 {
		t.Errorf("each pass must reconcile and collect plans (reads %d -> %d, gc %d)", reads, fu.zoneReads.Load(), gcCalls.Load())
	}

	fu.failZones.Store(true)
	gcErr := errors.New("gc down")
	a.PlanGC = func(context.Context) error { return gcErr }
	err := a.Maintenance(ctx)
	if err == nil || !strings.Contains(err.Error(), "reconcile example.com") || !errors.Is(err, gcErr) {
		t.Fatalf("errors of every step expected, got %v", err)
	}
}

func TestMaintenanceWithoutPlanGC(t *testing.T) {
	up := httptest.NewServer(&fakeUpstream{})
	defer up.Close()
	a := newMaintenanceApp(t, up.URL, Options{})
	if err := a.Maintenance(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLambdaHandlerRefreshesLazily(t *testing.T) {
	fu := &fakeUpstream{}
	up := httptest.NewServer(fu)
	defer up.Close()
	a := newMaintenanceApp(t, up.URL, Options{PolicyReloadInterval: time.Hour})
	cs := &countingStore{Store: a.Store}
	a.Store = cs
	h := a.LambdaHandler()
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-APP-ID", "vk")
		req.Header.Set("X-API-KEY", "secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := get("/api/v1/zones")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"zone":"other.org"`) {
		t.Fatalf("discovered zones must be listed on the first request: %d %s", rec.Code, rec.Body.String())
	}
	if fu.searches.Load() != 1 {
		t.Fatalf("%d searches", fu.searches.Load())
	}
	get("/api/v1/zones")
	if fu.searches.Load() != 1 {
		t.Errorf("fresh discovery listed again (%d searches)", fu.searches.Load())
	}
	if n := cs.active.Load(); n != 0 {
		t.Errorf("policy loaded by New must not be reloaded before the interval (%d reads)", n)
	}
	a.opts.PolicyReloadInterval = time.Nanosecond
	get("/api/v1/zones")
	if n := cs.active.Load(); n != 1 {
		t.Errorf("stale policy must be reloaded before the request (%d reads)", n)
	}
}
