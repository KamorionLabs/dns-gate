// Package discovery lists the zones of every provider account, so that zones
// the gate does not manage are visible read-only and can be brought under
// management through the managed policy, and resolves the provider serving
// each zone.
//
// The lists are held in memory and refreshed periodically; they are never
// read upstream on a request path, except for one refresh at most every
// MinOnDemand when a policy proposal names a zone not seen yet.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

// MinOnDemand is the minimum age of a list before an on-demand refresh.
const MinOnDemand = time.Minute

// retryAfterError is the delay before retrying a failed listing.
const retryAfterError = 5 * time.Minute

// Source is one provider account and the zones of it the gate serves.
type Source struct {
	Provider provider.Provider
	Include  []string // zone globs, empty means every zone
	Exclude  []string // zone globs, win over Include
	// Folders, when set, keeps only the zones whose folder matches one of
	// these folder globs (providers implementing provider.FolderLister).
	Folders []string
	Refresh time.Duration
}

// FolderChange is a zone that moved to another folder between two listings
// of its provider.
type FolderChange struct {
	Provider string
	Zone     string
	Old, New string
}

// Config configures a Discoverer.
type Config struct {
	Sources []Source
	Now     func() time.Time
	Logger  *slog.Logger
	// OnFolderChange, when set, is called after a listing for every zone
	// (selected by include and exclude) whose folder changed since the
	// previous listing of its provider.
	OnFolderChange func(context.Context, FolderChange)
}

// Status describes the last listings. LastRefreshAt is the oldest of the
// last successful listings, Err the first listing error.
type Status struct {
	Loaded        bool
	Count         int
	LastRefreshAt time.Time
	Err           error
	Providers     []ProviderStatus
}

// ProviderStatus describes the last listing of one provider.
type ProviderStatus struct {
	ID            string
	Kind          string
	Include       []string
	Exclude       []string
	Folders       []string
	Refresh       time.Duration
	Loaded        bool
	Count         int
	LastRefreshAt time.Time
	Err           error
}

type source struct {
	Source
	zones map[string]bool
	// folders are the folders of the zones selected by include and
	// exclude (before the folder filter), nil for providers without
	// folders.
	folders map[string]string
	sorted  []string
	loaded  bool
	lastAt  time.Time
	tried   time.Time
	err     error
}

// Discoverer caches the filtered zone lists of the providers and resolves the
// provider of a zone (provider.Resolver). Safe for concurrent use.
type Discoverer struct {
	cfg Config

	refreshMu sync.Mutex // one listing at a time

	mu   sync.RWMutex
	srcs []*source
}

var _ provider.Resolver = (*Discoverer)(nil)

// New builds a Discoverer; nothing is listed until Refresh or Run.
func New(cfg Config) *Discoverer {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	d := &Discoverer{cfg: cfg}
	for _, s := range cfg.Sources {
		if s.Refresh <= 0 {
			s.Refresh = time.Hour
		}
		d.srcs = append(d.srcs, &source{Source: s, zones: map[string]bool{}})
	}
	return d
}

// Filter normalizes zone names and keeps the valid ones matching include
// (every name when empty) and no exclude glob, sorted and deduplicated.
func Filter(names, include, exclude []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range names {
		n = dns.NormalizeZone(n)
		if seen[n] || !config.ValidFQDN(n) || !selects(include, exclude, n) {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func selects(include, exclude []string, zone string) bool {
	return (len(include) == 0 || glob.Any(include, zone)) && !glob.Any(exclude, zone)
}

// Refresh lists every provider now. On error the previous list of that
// provider is kept.
func (d *Discoverer) Refresh(ctx context.Context) error {
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()
	var errs []error
	for _, s := range d.srcs {
		errs = append(errs, d.refreshLocked(ctx, s))
	}
	return errors.Join(errs...)
}

func (d *Discoverer) refreshLocked(ctx context.Context, s *source) error {
	changes, err := d.list(ctx, s)
	if d.cfg.OnFolderChange != nil {
		for _, c := range changes {
			d.cfg.OnFolderChange(ctx, c)
		}
	}
	return err
}

// listZones lists the zones of a provider, with their folders when it has
// some (nil otherwise).
func listZones(ctx context.Context, p provider.Provider) ([]string, map[string]string, error) {
	fl, ok := p.(provider.FolderLister)
	if !ok {
		names, err := p.ListZones(ctx)
		return names, nil, err
	}
	folders, err := fl.ListZoneFolders(ctx)
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(folders))
	for n := range folders {
		names = append(names, n)
	}
	return names, folders, nil
}

func (d *Discoverer) list(ctx context.Context, s *source) ([]FolderChange, error) {
	now := d.cfg.Now()
	names, listed, err := listZones(ctx, s.Provider)
	d.mu.Lock()
	defer d.mu.Unlock()
	s.tried = now
	if err != nil {
		s.err = fmt.Errorf("provider %s: %w", s.Provider.ID(), err)
		return nil, s.err
	}
	zones := Filter(names, s.Include, s.Exclude)
	var folders map[string]string
	var changes []FolderChange
	if listed != nil {
		folders = make(map[string]string, len(zones))
		for _, z := range zones {
			f := listed[z]
			if f == "" {
				f = glob.RootFolder
			}
			folders[z] = f
			if old, ok := s.folders[z]; ok && s.loaded && old != f {
				changes = append(changes, FolderChange{Provider: s.Provider.ID(), Zone: z, Old: old, New: f})
			}
		}
	}
	s.folders = folders
	if len(s.Folders) > 0 {
		kept := []string{}
		for _, z := range zones {
			if glob.AnyFolder(s.Folders, folders[z]) {
				kept = append(kept, z)
			}
		}
		zones = kept
	}
	s.zones = make(map[string]bool, len(zones))
	for _, z := range zones {
		s.zones[z] = true
	}
	s.sorted, s.loaded, s.lastAt, s.err = zones, true, now, nil
	for _, o := range d.srcs {
		if o == s {
			continue
		}
		for _, z := range zones {
			if o.zones[z] {
				d.cfg.Logger.Error("zone listed by two providers, it is served by neither", "zone", z,
					"providers", []string{o.Provider.ID(), s.Provider.ID()})
			}
		}
	}
	return changes, nil
}

// RefreshIfOlder lists again the providers whose last attempt is older than
// age (at least MinOnDemand), so that a zone added to an account shortly
// before can be found without waiting for the next period.
func (d *Discoverer) RefreshIfOlder(ctx context.Context, age time.Duration) error {
	if age < MinOnDemand {
		age = MinOnDemand
	}
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()
	var errs []error
	for _, s := range d.srcs {
		d.mu.RLock()
		fresh := !s.tried.IsZero() && d.cfg.Now().Sub(s.tried) < age
		d.mu.RUnlock()
		if !fresh {
			errs = append(errs, d.refreshLocked(ctx, s))
		}
	}
	return errors.Join(errs...)
}

// RefreshDue lists again the providers whose period has elapsed (5 minutes
// after a failure): the one-pass equivalent of Run for runtimes without
// background loops.
func (d *Discoverer) RefreshDue(ctx context.Context) error {
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()
	var errs []error
	for _, s := range d.srcs {
		d.mu.RLock()
		wait := s.Refresh
		if s.err != nil {
			wait = min(wait, retryAfterError)
		}
		due := s.tried.IsZero() || d.cfg.Now().Sub(s.tried) >= wait
		d.mu.RUnlock()
		if due {
			errs = append(errs, d.refreshLocked(ctx, s))
		}
	}
	return errors.Join(errs...)
}

// Run lists every provider at once, then each one every Refresh (every 5
// minutes after a failure) until ctx is done.
func (d *Discoverer) Run(ctx context.Context) {
	for {
		now := d.cfg.Now()
		next := time.Duration(-1)
		for _, s := range d.srcs {
			d.mu.RLock()
			wait := s.Refresh
			if s.err != nil {
				wait = min(wait, retryAfterError)
			}
			elapsed := now.Sub(s.tried)
			due := s.tried.IsZero() || elapsed >= wait
			d.mu.RUnlock()
			if due {
				d.refreshMu.Lock()
				err := d.refreshLocked(ctx, s)
				d.refreshMu.Unlock()
				wait = s.Refresh
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					d.cfg.Logger.Warn("zone discovery failed", "provider", s.Provider.ID(), "error", err)
					wait = min(s.Refresh, retryAfterError)
				}
			} else {
				wait -= elapsed
			}
			if next < 0 || wait < next {
				next = wait
			}
		}
		if next < 0 {
			next = time.Hour
		}
		t := time.NewTimer(next)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Discovered reports whether zone is in the filtered list of a provider.
func (d *Discoverer) Discovered(zone string) bool {
	zone = dns.NormalizeZone(zone)
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, s := range d.srcs {
		if s.zones[zone] {
			return true
		}
	}
	return false
}

// Folder returns the folder of a discovered zone at its last listing ("/"
// for a zone in no folder), "" when the zone is not discovered or its
// provider has no folders.
func (d *Discoverer) Folder(zone string) string {
	zone = dns.NormalizeZone(zone)
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, s := range d.srcs {
		if s.zones[zone] {
			return s.folders[zone]
		}
	}
	return ""
}

// DiscoveredZones returns the filtered zones of every provider, sorted.
func (d *Discoverer) DiscoveredZones() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.zonesLocked()
}

func (d *Discoverer) zonesLocked() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range d.srcs {
		for _, z := range s.sorted {
			if !seen[z] {
				seen[z] = true
				out = append(out, z)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Loaded reports whether every provider has been listed successfully at
// least once.
func (d *Discoverer) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, s := range d.srcs {
		if !s.loaded {
			return false
		}
	}
	return len(d.srcs) > 0
}

// Status returns the state of the last listings.
func (d *Discoverer) Status() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	st := Status{Loaded: len(d.srcs) > 0, Count: len(d.zonesLocked())}
	for _, s := range d.srcs {
		st.Providers = append(st.Providers, ProviderStatus{ID: s.Provider.ID(), Kind: s.Provider.Kind(),
			Include: append([]string{}, s.Include...), Exclude: append([]string{}, s.Exclude...),
			Folders: append([]string{}, s.Folders...), Refresh: s.Refresh,
			Loaded: s.loaded, Count: len(s.sorted), LastRefreshAt: s.lastAt, Err: s.err})
		st.Loaded = st.Loaded && s.loaded
		if s.loaded && (st.LastRefreshAt.IsZero() || s.lastAt.Before(st.LastRefreshAt)) {
			st.LastRefreshAt = s.lastAt
		}
		if st.Err == nil {
			st.Err = s.err
		}
	}
	return st
}

// Provider returns the provider serving zone: the only provider whose zone
// filter selects it or, when several do, the only one of them whose account
// lists it. A provider with a folder filter selects only the zones its last
// listing found in a selected folder.
func (d *Discoverer) Provider(zone string) (provider.Provider, error) {
	zone = dns.NormalizeZone(zone)
	d.mu.RLock()
	defer d.mu.RUnlock()
	var matched, listed []*source
	for _, s := range d.srcs {
		if !selects(s.Include, s.Exclude, zone) || (len(s.Folders) > 0 && !s.zones[zone]) {
			continue
		}
		matched = append(matched, s)
		if s.zones[zone] {
			listed = append(listed, s)
		}
	}
	switch {
	case len(matched) == 0:
		return nil, fmt.Errorf("zone %s is selected by no provider: %w", zone, provider.ErrZoneNotFound)
	case len(matched) == 1:
		return matched[0].Provider, nil
	case len(listed) == 1:
		return listed[0].Provider, nil
	case len(listed) > 1:
		return nil, fmt.Errorf("zone %s is listed by several providers (%s): exclude it from all but one", zone, ids(listed))
	}
	return nil, fmt.Errorf("zone %s is selected by several providers (%s) and listed by none of them", zone, ids(matched))
}

func ids(srcs []*source) string {
	out := make([]string, 0, len(srcs))
	for _, s := range srcs {
		out = append(out, s.Provider.ID())
	}
	return strings.Join(out, ", ")
}
