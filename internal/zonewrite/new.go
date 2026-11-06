package zonewrite

import (
	"context"
	"log/slog"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

// Config wires the engine.
type Config struct {
	// Providers resolves the provider serving each zone.
	Providers provider.Resolver
	Store     store.Store
	Authz     policy.Authorizer
	Audit     audit.Logger
	Zones     []string // managed zones when ZoneSet is nil; any other zone is refused
	// ZoneSet, when set, replaces Zones: the managed zones follow the
	// policy (base and managed layers) and discovered zones of the account
	// are readable without being managed.
	ZoneSet ZoneSet
	// UnmanagedTTL is how long the content of an unmanaged zone is reused
	// before the next view reads it again (default 15m). Managed zones are
	// refreshed by reconcile and writes instead.
	UnmanagedTTL time.Duration
	Holder       string        // lock holder id (pod name)
	LockTTL      time.Duration // default 60s
	LockWait     time.Duration // default 30s
	CheckOnWrite bool          // run the provider check (provider.Checker) before every write
	// EphemeralLifetimeFactor bounds the life of an ephemeral RRset to its
	// creation plus this many ephemeral TTLs, however often values are
	// added to it (default 4).
	EphemeralLifetimeFactor int
	// Guard, when set, may refuse a change of one RRset by a subject, after
	// RBAC and before ownership; a non-*Error refusal is forbidden.
	Guard func(ctx context.Context, s *identity.Subject, zone string, key dns.Key) error
	// TombstoneTTL is how long a deleted RRset stays reserved for its team
	// (0 disables tombstones). Ephemeral RRsets leave no tombstone.
	TombstoneTTL time.Duration
	// TransferTTL is how long a transfer request waits for approval
	// (default 7 days).
	TransferTTL time.Duration
	// RequireSecondApprover makes transfers and renames need the approval
	// of a second person (PersonClaims, PersonIssuers); without it the
	// requester may approve its own request, every other check applying.
	RequireSecondApprover bool
	// MachineApprovers lets pipelines and virtual keys approve transfers;
	// by default only humans may.
	MachineApprovers bool
	// PersonClaims identify the person behind a token: requester and
	// approver of a transfer must share none of their values ("tid+oid"
	// joins several claims; default tid+oid, email, preferred_username,
	// upn).
	PersonClaims []string
	// PersonIssuers, when set, are the issuers whose human subjects may
	// request and approve transfers; the subject itself then identifies the
	// person too.
	PersonIssuers []string
	// UntrustedEmail lists the issuers whose email claim does not identify
	// a person.
	UntrustedEmail map[string]bool
	// Rebinder binds the approver of a transfer again with the current
	// policy before a retried apply; without it the subject recorded at
	// the approval is used.
	Rebinder Rebinder
	// Teams tells which teams may own RRsets; any valid team name when nil.
	Teams  TeamDirectory
	Now    func() time.Time
	Logger *slog.Logger
}

// Rebinder binds a subject recorded earlier with the current policy
// (authn.Authenticator implements it).
type Rebinder interface {
	Rebind(s *identity.Subject) (*identity.Subject, error)
}

// TeamDirectory knows the teams of the policy (policy.Engine implements it).
type TeamDirectory interface {
	// KnownTeam reports whether a team may own RRsets.
	KnownTeam(name string) bool
}

// ZoneSet tells which zones the engine serves (policy.Engine implements it).
type ZoneSet interface {
	// Managed reports whether a zone is managed: readable and writable
	// within RBAC and ownership.
	Managed(zone string) bool
	ManagedZones() []string
	// IsUnmanaged reports whether a zone exists in a provider account but
	// is not managed: readable only.
	IsUnmanaged(zone string) bool
	UnmanagedZones() []string
}

type staticZones struct {
	set   map[string]bool
	order []string
}

func (z *staticZones) Managed(zone string) bool { return z.set[normZone(zone)] }
func (z *staticZones) ManagedZones() []string   { return z.order }
func (z *staticZones) IsUnmanaged(string) bool  { return false }
func (z *staticZones) UnmanagedZones() []string { return nil }

// New builds the engine.
func New(cfg Config) (Engine, error) { return newEngine(cfg) }

// RunReconciler calls Reconcile for every zone returned by zones (the
// managed zones, read at each round) every interval until ctx is done,
// staying within the upstream rate limit.
func RunReconciler(ctx context.Context, e Engine, zones func() []string, every time.Duration, log *slog.Logger) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		for _, z := range zones() {
			if ctx.Err() != nil {
				return
			}
			if err := e.Reconcile(ctx, z); err != nil {
				log.Warn("reconcile failed", "zone", z, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
