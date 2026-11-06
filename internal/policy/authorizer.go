// Package policy evaluates RBAC rules (roles, bindings, protected records).
package policy

import (
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
)

// Actions.
const (
	ActionDNSRead     = "dns.read"
	ActionRecordWrite = "dns.record.write"
	ActionRecordAdopt = "dns.record.adopt"
	ActionZoneAdmin   = "dns.zone.admin" // DNSSEC sign/unsign, zone settings (EuroDNS forwards)
	// ActionZoneProfile manages the zone profiles of a EuroDNS account
	// (templates applied to domains on arrival). Profiles are account-wide
	// objects: the action counts only when granted on every zone ("*").
	ActionZoneProfile = "dns.zone.profile"
	ActionDomainRead  = "domain.read"
	ActionUIRead      = "ui.read" // read-only UI and /api/v1
)

// Authorizer is implemented by the policy engine and consumed by the HTTP
// layer and the zone write engine.
type Authorizer interface {
	// Allow checks an action on a zone (no record scope).
	Allow(s *identity.Subject, action, zone string) bool
	// AllowRRset checks an action on one RRset (zone, host, type), including
	// the protected-records list (protected wins over any role).
	AllowRRset(s *identity.Subject, action, zone string, key dns.Key) bool
	// OwnerTeam returns the team that will own an RRset created by s in this
	// zone (first of s.Teams allowed for the zone), false if none.
	OwnerTeam(s *identity.Subject, zone string) (string, bool)
	// MaxChangesPerRequest returns the blast-radius limit for s (0 = unlimited).
	MaxChangesPerRequest(s *identity.Subject) int
	// RebaseOnSave: on a full-zone PUT, ignore out-of-scope differences
	// instead of refusing them (stale zones from ACME clients such as lego).
	RebaseOnSave(s *identity.Subject) bool
	// EphemeralTTL: RRsets created by s expire and are garbage-collected after
	// this duration (0 = permanent). Used for ACME challenge records.
	EphemeralTTL(s *identity.Subject) time.Duration
	// IsProtected reports whether an RRset is in the protected list.
	IsProtected(zone string, key dns.Key) bool
}

// FolderGrants is implemented by authorizers whose rules select zones by
// provider folder. AllowRRsetFolder is AllowRRset that also returns the
// folder through which the action is granted ("" when granted otherwise);
// the write engine records it in the audit of the request it authorized.
type FolderGrants interface {
	AllowRRsetFolder(s *identity.Subject, action, zone string, key dns.Key) (bool, string)
}
