package discovery

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
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

// folderLister is a provider with folders (provider.FolderLister).
type folderLister struct {
	fakeLister
	folders map[string]string
}

func (f *folderLister) ListZoneFolders(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	out := make(map[string]string, len(f.folders))
	for z, fo := range f.folders {
		out[z] = fo
	}
	return out, f.err
}

func (f *folderLister) move(zone, folder string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.folders[zone] = folder
}

func TestFolders(t *testing.T) {
	l := &folderLister{fakeLister: fakeLister{id: "eu"}, folders: map[string]string{
		"example.es": "/ES", "madrid.example.es": "/ES/Madrid", "example.fr": "/FR", "example.com": "/", "excluded.net": "/ES",
	}}
	plain := &fakeLister{id: "r53", names: []string{"example.org"}}
	var changes []FolderChange
	ids := map[string]bool{}
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{
		Sources: []Source{
			{Provider: l, Exclude: []string{"*.net"}, Folders: []string{"/ES", "/ES/**", "/"}, Refresh: time.Hour},
			{Provider: plain, Include: []string{"*.org"}},
		},
		Now: func() time.Time { return now },
		OnFolderChange: func(ctx context.Context, c FolderChange) {
			if ctx.Err() != nil || requestid.From(ctx) == "" {
				t.Errorf("event context: err %v, request id %q", ctx.Err(), requestid.From(ctx))
			}
			ids[requestid.From(ctx)] = true
			changes = append(changes, c)
		},
	})
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.DiscoveredZones(), ","); got != "example.com,example.es,example.org,madrid.example.es" {
		t.Fatalf("zones = %s", got)
	}
	for zone, want := range map[string]string{"example.es": "/ES", "Madrid.Example.ES.": "/ES/Madrid", "example.com": "/", "example.fr": "", "example.org": "", "absent.com": ""} {
		if got := d.Folder(zone); got != want {
			t.Errorf("Folder(%s) = %q, want %q", zone, got, want)
		}
	}
	if p, err := d.Provider("example.es"); err != nil || p.ID() != "eu" {
		t.Fatalf("provider of a zone in a selected folder: %v %v", p, err)
	}
	if _, err := d.Provider("example.fr"); err == nil {
		t.Fatal("a zone outside the selected folders must not be served")
	}
	if st := d.Status(); strings.Join(st.Providers[0].Folders, ",") != "/ES,/ES/**,/" {
		t.Fatalf("status = %+v", st.Providers[0])
	}
	sorted := func() []FolderChange {
		sort.Slice(changes, func(i, j int) bool { return changes[i].Zone < changes[j].Zone })
		out := changes
		changes = nil
		return out
	}
	first := sorted()
	if len(first) != 1 || len(ids) != 1 {
		t.Fatalf("first listing: one summary expected, got %+v (request ids %v)", first, ids)
	}
	sum := first[0]
	if sum.Kind != FolderListed || sum.Provider != "eu" || sum.Zone != "" || sum.Count != 4 ||
		sum.Digest != FolderDigest(map[string]string{"example.es": "/ES", "madrid.example.es": "/ES/Madrid", "example.fr": "/FR", "example.com": "/"}) {
		t.Fatalf("first listing summary: %+v", sum)
	}

	l.move("example.es", "/FR")
	l.move("example.fr", "/ES/Barcelona")
	l.move("excluded.net", "/FR")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Refresh(cancelled); err != nil {
		t.Fatal(err)
	}
	moved := sorted()
	want := []FolderChange{{Kind: FolderChanged, Provider: "eu", Zone: "example.es", Old: "/ES", New: "/FR"}, {Kind: FolderChanged, Provider: "eu", Zone: "example.fr", Old: "/FR", New: "/ES/Barcelona"}}
	if len(moved) != 2 || moved[0] != want[0] || moved[1] != want[1] || len(ids) != 2 {
		t.Fatalf("changes = %+v", moved)
	}
	if d.Discovered("example.es") || !d.Discovered("example.fr") || d.Folder("example.fr") != "/ES/Barcelona" {
		t.Fatalf("zones after the move = %v", d.DiscoveredZones())
	}

	l.mu.Lock()
	delete(l.folders, "example.com")
	l.folders["late.example.es"] = "/ES"
	l.mu.Unlock()
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ev := sorted(); len(ev) != 2 || ev[0].Kind != FolderGone || ev[0].Zone != "example.com" || ev[0].Old != "/" ||
		ev[1].Kind != FolderSeen || ev[1].Zone != "late.example.es" || ev[1].New != "/ES" {
		t.Fatalf("zone removed from and added to the account: %+v", ev)
	}

	// A failed listing keeps the folders of the previous one, for three
	// refresh periods (default FolderMaxAge): then folder rules close.
	l.err = errors.New("upstream down")
	now = now.Add(3 * time.Hour)
	if err := d.Refresh(context.Background()); err == nil || d.Folder("example.fr") != "/ES/Barcelona" || d.Status().Providers[0].FoldersStale {
		t.Fatalf("folders after a failed listing: %v %q", err, d.Folder("example.fr"))
	}
	now = now.Add(time.Minute)
	if d.Folder("example.fr") != "" || !d.Discovered("example.fr") {
		t.Fatalf("stale folder still served: %q", d.Folder("example.fr"))
	}
	st := d.Status().Providers[0]
	if !st.FoldersStale || st.FolderMaxAge != 3*time.Hour {
		t.Fatalf("status of stale folders: %+v", st)
	}
}

func TestFolderOfZoneListedTwice(t *testing.T) {
	a := &folderLister{fakeLister: fakeLister{id: "eu-a"}, folders: map[string]string{"example.es": "/ES"}}
	b := &folderLister{fakeLister: fakeLister{id: "eu-b"}, folders: map[string]string{"example.es": "/FR", "other.es": "/FR"}}
	d := New(Config{Sources: []Source{{Provider: a}, {Provider: b}}})
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := d.Folder("example.es"); got != "" {
		t.Fatalf("folder of a zone listed by two providers = %q", got)
	}
	if got := d.Folder("other.es"); got != "/FR" {
		t.Fatalf("folder = %q", got)
	}
}

// slowLister takes listDuration of the fake clock per listing.
type slowLister struct {
	folderLister
	clock *time.Time
	took  time.Duration
}

func (s *slowLister) ListZoneFolders(ctx context.Context) (map[string]string, error) {
	*s.clock = s.clock.Add(s.took)
	return s.folderLister.ListZoneFolders(ctx)
}

func TestFolderAgeFromTheEndOfTheListing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := &slowLister{folderLister: folderLister{fakeLister: fakeLister{id: "eu"}, folders: map[string]string{"example.es": "/ES"}}, clock: &now, took: 10 * time.Minute}
	d := New(Config{Sources: []Source{{Provider: l, Refresh: time.Hour, FolderMaxAge: 2 * time.Hour}}, Now: func() time.Time { return now }})
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if got := d.Folder("example.es"); got != "/ES" {
		t.Fatalf("folder 2h after the end of a 10 minute listing = %q", got)
	}
}
