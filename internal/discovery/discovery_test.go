package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFilter(t *testing.T) {
	names := []string{"Example.COM.", "example.com", "b.example.org", "internal.example.org", "bad_name", "single", "", "other.net"}
	got := strings.Join(Filter(names, []string{"*.com", "*.example.org"}, []string{"internal.*"}), ",")
	if got != "b.example.org,example.com" {
		t.Fatalf("filter = %s", got)
	}
	if got := strings.Join(Filter(names, nil, nil), ","); got != "b.example.org,example.com,internal.example.org,other.net" {
		t.Fatalf("no filter = %s", got)
	}
}

type fakeLister struct {
	mu    sync.Mutex
	names []string
	err   error
	calls int
}

func (f *fakeLister) ListDomains(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.names, f.err
}

func TestRefreshKeepsListOnError(t *testing.T) {
	l := &fakeLister{names: []string{"example.com", "example.net"}}
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{Lister: l, Include: []string{"*"}, Exclude: []string{"example.net"}, Now: func() time.Time { return now }})
	if d.Loaded() || d.Discovered("example.com") {
		t.Fatal("nothing before the first listing")
	}
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.Discovered("Example.com.") || d.Discovered("example.net") || strings.Join(d.DiscoveredZones(), ",") != "example.com" {
		t.Fatalf("zones = %v", d.DiscoveredZones())
	}
	l.err = errors.New("upstream down")
	if err := d.Refresh(context.Background()); err == nil {
		t.Fatal("error expected")
	}
	st := d.Status()
	if !st.Loaded || st.Count != 1 || st.Err == nil || !st.LastRefreshAt.Equal(now) || !d.Discovered("example.com") {
		t.Fatalf("status after error = %+v", st)
	}
}

func TestRefreshIfOlder(t *testing.T) {
	l := &fakeLister{names: []string{"example.com"}}
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{Lister: l, Now: func() time.Time { return now }})
	ctx := context.Background()
	_ = d.RefreshIfOlder(ctx, 0)
	_ = d.RefreshIfOlder(ctx, 0) // within MinOnDemand: no listing
	now = now.Add(30 * time.Second)
	_ = d.RefreshIfOlder(ctx, time.Second) // age raised to MinOnDemand
	if l.calls != 1 {
		t.Fatalf("calls = %d, want 1", l.calls)
	}
	now = now.Add(MinOnDemand)
	_ = d.RefreshIfOlder(ctx, 0)
	if l.calls != 2 {
		t.Fatalf("calls = %d, want 2", l.calls)
	}
	// A failed attempt also counts: no hammering while upstream fails.
	l.err = errors.New("down")
	now = now.Add(2 * MinOnDemand)
	_ = d.RefreshIfOlder(ctx, 0)
	_ = d.RefreshIfOlder(ctx, 0)
	if l.calls != 3 {
		t.Fatalf("calls = %d, want 3", l.calls)
	}
}

func TestRunStops(t *testing.T) {
	l := &fakeLister{names: []string{"example.com"}}
	d := New(Config{Lister: l, Refresh: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for !d.Loaded() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	if !d.Discovered("example.com") {
		t.Fatal("first listing at start")
	}
}

// searchServer fakes POST /domains/search with pagination headers.
func searchServer(t *testing.T, domains []string, ignorePages bool, requests *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		if r.Method != http.MethodPost || r.URL.Path != "/domains/search" || r.Header.Get("X-API-KEY") != "k" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		page, _ := strconv.Atoi(r.Header.Get("pagination-page"))
		size, _ := strconv.Atoi(r.Header.Get("pagination-size"))
		if page < 1 || size < 1 {
			http.Error(w, "pagination", http.StatusBadRequest)
			return
		}
		if ignorePages {
			page = 1
		}
		start := min((page-1)*size, len(domains))
		end := min(start+size, len(domains))
		var out []map[string]any
		for _, d := range domains[start:end] {
			out = append(out, map[string]any{"domainName": d, "tldName": d[strings.LastIndex(d, ".")+1:]})
		}
		w.Header().Set("pagination-count", strconv.Itoa(len(domains)))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
}

type keyRT struct{}

func (keyRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-API-KEY", "k")
	return http.DefaultTransport.RoundTrip(r)
}

func TestEuroDNSListerPagination(t *testing.T) {
	var domains []string
	for i := range 7 {
		domains = append(domains, "d"+strconv.Itoa(i)+".example")
	}
	n := 0
	srv := searchServer(t, domains, false, &n)
	defer srv.Close()
	l := &EuroDNSLister{BaseURL: srv.URL + "/", Transport: keyRT{}, PageSize: 3}
	got, err := l.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(domains, ",") || n != 3 {
		t.Fatalf("got %v in %d requests", got, n)
	}
	// Exactly a multiple of the page size: pagination-count stops the loop.
	n = 0
	srv2 := searchServer(t, domains[:6], false, &n)
	defer srv2.Close()
	l.BaseURL = srv2.URL
	if got, err := l.ListDomains(context.Background()); err != nil || len(got) != 6 || n != 2 {
		t.Fatalf("got %v, %v in %d requests", got, err, n)
	}
}

func TestEuroDNSListerStopsWhenPaginationIgnored(t *testing.T) {
	n := 0
	srv := searchServer(t, []string{"a.example", "b.example", "c.example", "d.example"}, true, &n)
	defer srv.Close()
	l := &EuroDNSLister{BaseURL: srv.URL, Transport: keyRT{}, PageSize: 2}
	if _, err := l.ListDomains(context.Background()); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatalf("err = %v", err)
	}
	if n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
}

func TestEuroDNSListerHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	l := &EuroDNSLister{BaseURL: srv.URL, Transport: http.DefaultTransport}
	if _, err := l.ListDomains(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
