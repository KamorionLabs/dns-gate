// Package discovery lists the domains of the EuroDNS account
// (zones_discovery), so that zones the gate does not manage are visible
// read-only and can be brought under management through the managed policy.
//
// The list is held in memory and refreshed periodically; it is never read
// on a request path, except for one refresh at most every MinOnDemand when a
// policy proposal names a zone not seen yet.
package discovery

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/glob"
)

// MinOnDemand is the minimum age of the list before an on-demand refresh.
const MinOnDemand = time.Minute

// retryAfterError is the delay before retrying a failed listing.
const retryAfterError = 5 * time.Minute

// Lister returns the domain names of the account.
type Lister interface {
	ListDomains(ctx context.Context) ([]string, error)
}

// Config configures a Discoverer.
type Config struct {
	Lister  Lister
	Include []string // zone globs, empty means every domain
	Exclude []string // zone globs, win over Include
	Refresh time.Duration
	Now     func() time.Time
	Logger  *slog.Logger
}

// Status describes the last listing.
type Status struct {
	Loaded        bool
	Count         int
	LastRefreshAt time.Time
	Err           error
}

// Discoverer caches the filtered list of account zones. Safe for concurrent use.
type Discoverer struct {
	cfg Config

	refreshMu sync.Mutex // one listing at a time

	mu     sync.RWMutex
	zones  map[string]bool
	sorted []string
	loaded bool
	lastAt time.Time
	tried  time.Time
	err    error
}

// New builds a Discoverer; nothing is listed until Refresh or Run.
func New(cfg Config) *Discoverer {
	if cfg.Refresh <= 0 {
		cfg.Refresh = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Discoverer{cfg: cfg, zones: map[string]bool{}}
}

// Filter normalizes domain names and keeps the valid ones matching include
// (every name when empty) and no exclude glob, sorted and deduplicated.
func Filter(names, include, exclude []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if seen[n] || !config.ValidFQDN(n) {
			continue
		}
		if len(include) > 0 && !glob.Any(include, n) {
			continue
		}
		if glob.Any(exclude, n) {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Refresh lists the account now. On error the previous list is kept.
func (d *Discoverer) Refresh(ctx context.Context) error {
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()
	return d.refreshLocked(ctx)
}

func (d *Discoverer) refreshLocked(ctx context.Context) error {
	now := d.cfg.Now()
	names, err := d.cfg.Lister.ListDomains(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tried = now
	if err != nil {
		d.err = err
		return err
	}
	zones := Filter(names, d.cfg.Include, d.cfg.Exclude)
	d.zones = make(map[string]bool, len(zones))
	for _, z := range zones {
		d.zones[z] = true
	}
	d.sorted, d.loaded, d.lastAt, d.err = zones, true, now, nil
	return nil
}

// RefreshIfOlder lists the account again when the last attempt is older
// than age (at least MinOnDemand), so that a zone added to the account
// shortly before can be found without waiting for the next period.
func (d *Discoverer) RefreshIfOlder(ctx context.Context, age time.Duration) error {
	if age < MinOnDemand {
		age = MinOnDemand
	}
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()
	d.mu.RLock()
	fresh := !d.tried.IsZero() && d.cfg.Now().Sub(d.tried) < age
	d.mu.RUnlock()
	if fresh {
		return nil
	}
	return d.refreshLocked(ctx)
}

// Run lists the account at once, then every Refresh (every 5 minutes after
// a failure) until ctx is done.
func (d *Discoverer) Run(ctx context.Context) {
	for {
		wait := d.cfg.Refresh
		if err := d.Refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			d.cfg.Logger.Warn("zone discovery failed", "error", err)
			wait = min(wait, retryAfterError)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Discovered reports whether zone is in the filtered account list.
func (d *Discoverer) Discovered(zone string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.zones[strings.TrimSuffix(strings.ToLower(zone), ".")]
}

// DiscoveredZones returns the filtered account zones, sorted.
func (d *Discoverer) DiscoveredZones() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]string(nil), d.sorted...)
}

// Loaded reports whether a listing succeeded at least once.
func (d *Discoverer) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded
}

// Status returns the state of the last listing.
func (d *Discoverer) Status() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return Status{Loaded: d.loaded, Count: len(d.sorted), LastRefreshAt: d.lastAt, Err: d.err}
}
