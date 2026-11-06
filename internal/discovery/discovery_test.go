package discovery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/provider"
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
	provider.Provider
	id    string
	mu    sync.Mutex
	names []string
	err   error
	calls int
}

func (f *fakeLister) ID() string {
	if f.id == "" {
		return "p"
	}
	return f.id
}

func (f *fakeLister) Kind() string { return "fake" }

func (f *fakeLister) ListZones(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.names, f.err
}

func one(l *fakeLister, include, exclude []string, refresh time.Duration) []Source {
	return []Source{{Provider: l, Include: include, Exclude: exclude, Refresh: refresh}}
}

func TestRefreshKeepsListOnError(t *testing.T) {
	l := &fakeLister{names: []string{"example.com", "example.net"}}
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{Sources: one(l, []string{"*"}, []string{"example.net"}, 0), Now: func() time.Time { return now }})
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
	d := New(Config{Sources: one(l, nil, nil, 0), Now: func() time.Time { return now }})
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
	d := New(Config{Sources: one(l, nil, nil, time.Hour)})
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

func TestProviderResolution(t *testing.T) {
	a := &fakeLister{id: "a", names: []string{"shared.com", "a.com"}}
	b := &fakeLister{id: "b", names: []string{"b.com", "x.fr"}}
	c := &fakeLister{id: "c", names: []string{"shared.com", "only-c.fr"}}
	d := New(Config{Sources: []Source{
		{Provider: a, Include: []string{"*.com"}},
		{Provider: b, Include: []string{"*"}, Exclude: []string{"*.fr"}},
		{Provider: c, Include: []string{"*.fr", "shared.com"}},
	}})
	ctx := context.Background()
	if _, err := d.Provider("x.org"); err != nil {
		t.Fatalf("single filter match before listing: %v", err)
	}
	if _, err := d.Provider("a.com"); err == nil {
		t.Fatal("ambiguous before listing")
	}
	if err := d.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for zone, want := range map[string]string{"a.com": "a", "b.com": "b", "x.org": "b", "only-c.fr": "c", "x.fr": "c"} {
		p, err := d.Provider(zone)
		if err != nil || p.ID() != want {
			t.Errorf("%s: %v %v, want %s", zone, p, err, want)
		}
	}
	if _, err := d.Provider("shared.com"); err == nil || !strings.Contains(err.Error(), "several providers") {
		t.Fatalf("zone listed twice: %v", err)
	}
	if _, err := d.Provider("new.com"); err == nil {
		t.Fatal("zone selected by a and b, listed by none")
	}
	if !d.Discovered("only-c.fr") || d.Discovered("x.fr") {
		t.Fatal("discovered")
	}
	b.err = errors.New("down")
	_ = d.Refresh(ctx)
	st := d.Status()
	if !st.Loaded || st.Err == nil || len(st.Providers) != 3 || st.Providers[1].Err == nil || st.Count != 4 {
		t.Fatalf("status %+v", st)
	}
}
