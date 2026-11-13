// Package provider is the contract between the gate core and the DNS
// providers it fronts. One Provider instance is configured per upstream
// account (an EuroDNS account, an AWS account for Route53...).
package provider

import (
	"context"
	"errors"

	"github.com/KamorionLabs/dns-gate/internal/dns"
)

// Capabilities tell the core how a provider writes, so it can choose its
// safety measures.
type Capabilities struct {
	// FullZoneWrite: Apply rewrites the whole zone (EuroDNS).
	FullZoneWrite bool
	// AtomicBatch: the changes of one Apply succeed or fail together.
	AtomicBatch bool
	// ConditionalWrite: Apply fails with ErrConflict when the upstream
	// content of an Old RRset differs from the one given (compare and swap).
	ConditionalWrite bool
	// Alias: alias RRsets (dns.Alias) can be written.
	Alias bool
	// Forwards: URL forwards (dns.Forward, key type dns.TypeURLForward) are
	// read and written. Without it the core refuses every forward.
	Forwards bool
	// Types are the writable record types, uppercase.
	Types []string
	// TTLs, when not empty, is the closed list of accepted TTLs; otherwise
	// any TTL in [MinTTL, MaxTTL].
	TTLs   []int
	MinTTL int
	MaxTTL int
}

// Provider is implemented by every provider adapter.
type Provider interface {
	// ID is the instance id from the configuration (unique in a gate).
	ID() string
	// Kind is the adapter kind ("eurodns", "route53", "ovh", "scaleway",
	// "infomaniak", "azure").
	Kind() string
	Capabilities() Capabilities
	// ListZones returns the normalized names of the zones of the account.
	ListZones(ctx context.Context) ([]string, error)
	// ReadZone returns the current content of a zone, RRsets sorted by key.
	ReadZone(ctx context.Context, zone string) (*dns.Zone, error)
	// Normalize validates a desired RRset and returns it in the canonical
	// form of ReadZone, so that a desired RRset and the one read back after
	// the write compare and hash equal. Invalid input is an *InvalidError.
	Normalize(zone string, set dns.RRset) (dns.RRset, error)
	// Apply writes changes computed against cur (as returned by ReadZone).
	Apply(ctx context.Context, zone string, cur *dns.Zone, changes []dns.Change) error
}

// Checker is implemented by providers with a server-side dry run (EuroDNS).
// It returns the problems found on the zone as it would be after changes.
type Checker interface {
	Check(ctx context.Context, zone string, cur *dns.Zone, changes []dns.Change) ([]Problem, error)
}

// FolderLister is implemented by providers that organise the zones of an
// account in folders (EuroDNS). Discovery lists them with ListZoneFolders
// instead of ListZones.
type FolderLister interface {
	// ListZoneFolders returns the normalized names of the zones of the
	// account with the folder of each, normalized by glob.NormalizeFolder
	// ("/" for the zones in no folder, "" when the provider does not tell).
	ListZoneFolders(ctx context.Context) (map[string]string, error)
}

// Snapshotter is implemented by providers that keep zone snapshots
// (EuroDNS). The id is recorded in the audit event of each write.
type Snapshotter interface {
	LatestSnapshot(ctx context.Context, zone string) (string, error)
}

// HTTPSRedirecter is implemented by providers whose forwards answer HTTPS
// requests only with a separate per-domain subscription (EuroDNS HTTPS
// redirect). Forwards are written either way; without the subscription the
// forward host answers plain HTTP only.
type HTTPSRedirecter interface {
	HTTPSRedirect(ctx context.Context, zone string) (HTTPSRedirect, error)
}

// HTTPS redirect states.
const (
	HTTPSActive      = "active"      // HTTPS requests to forward hosts are redirected
	HTTPSPending     = "pending"     // subscription ordered, certificate not issued yet
	HTTPSNoForward   = "no_forward"  // subscription active, no forward in the zone yet
	HTTPSInactive    = "inactive"    // no active subscription: plain HTTP only
	HTTPSUnsupported = "unsupported" // the provider has no forwards
	HTTPSUnknown     = "unknown"     // the status could not be read
)

// HTTPSRedirect is the HTTPS status of the forwards of a zone.
type HTTPSRedirect struct {
	Status string `json:"status"`
	// Subscription is the provider subscription id, when there is one.
	Subscription string `json:"subscription,omitempty"`
	// ExpiresAt is the subscription expiration date as given by the provider.
	ExpiresAt string `json:"expires_at,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Problem is one validation problem reported by a Checker.
type Problem struct {
	Key     *dns.Key `json:"key,omitempty"`
	Message string   `json:"message"`
	// Blocking problems refuse the write.
	Blocking bool `json:"blocking"`
}

var (
	// ErrConflict: the upstream content changed under a conditional write.
	ErrConflict = errors.New("provider: upstream content changed")
	// ErrZoneNotFound: the zone does not exist in the provider account.
	ErrZoneNotFound = errors.New("provider: zone not found")
)

// InvalidError is returned by Normalize for a desired RRset the provider
// cannot write.
type InvalidError struct {
	Key     dns.Key
	Message string
	// Code is an optional machine-readable reason (for example
	// "relative_target"), reported to adoption candidates.
	Code string
}

func (e *InvalidError) Error() string { return "invalid " + e.Key.String() + ": " + e.Message }

// ErrNotApplied wraps a provider error known to have written nothing (a
// request the provider refused), so that the core can roll back its claims.
var ErrNotApplied = errors.New("provider: request refused, nothing written")

// RejectedError is returned when the provider refuses a write or a read as
// invalid (EuroDNS 400 with a validation report). Nothing was written.
type RejectedError struct {
	Message string
	// Details is the provider report, returned to the client as is.
	Details any
}

func (e *RejectedError) Error() string { return "rejected: " + e.Message }

// Is makes a RejectedError match ErrNotApplied.
func (e *RejectedError) Is(target error) bool { return target == ErrNotApplied }

// Resolver returns the provider serving a zone. A zone is served by exactly
// one provider; an error is returned when none or several match.
type Resolver interface {
	Provider(zone string) (Provider, error)
}

// Single is a Resolver serving every zone with one provider.
func Single(p Provider) Resolver { return single{p} }

type single struct{ p Provider }

func (s single) Provider(string) (Provider, error) { return s.p, nil }
