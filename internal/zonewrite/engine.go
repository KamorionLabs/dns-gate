package zonewrite

import (
	"context"
	"errors"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// Error reasons, mapped to HTTP statuses by the HTTP layer and returned in
// the error body {"reason": "...", "message": "..."}.
type Reason string

const (
	ReasonForbidden     Reason = "forbidden"        // 403 RBAC, protected or read-only record
	ReasonForeignRRset  Reason = "foreign_rrset"    // 409 RRset exists and is not owned by the gate
	ReasonNotOwner      Reason = "not_owner"        // 403 owned by another team
	ReasonTainted       Reason = "tainted"          // 409 changed outside the gate
	ReasonPrecondition  Reason = "precondition"     // 412 If-Match, expected hash or upstream conflict
	ReasonTooMany       Reason = "too_many_changes" // 403 blast radius
	ReasonInvalid       Reason = "invalid_zone"     // 400 refused by the provider or its validation
	ReasonLocked        Reason = "zone_locked"      // 423/503 lock not acquired in time
	ReasonUpstream      Reason = "upstream"         // 502
	ReasonNotFound      Reason = "not_found"        // 404 zone not managed, record id or RRset absent
	ReasonAdoptConflict Reason = "adopt_conflict"   // 409 adoption preview no longer matches upstream
)

// Error is returned by Engine methods.
type Error struct {
	Reason  Reason
	Message string
	Details any
	Err     error
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Message }
func (e *Error) Unwrap() error { return e.Err }

// AsError extracts an *Error.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// Plan is a write computed against the current zone, under the zone lock.
type Plan struct {
	// Changes are the RRset changes. The engine takes Old and Op from the
	// current zone and replaces New with its provider.Normalize form.
	Changes []dns.Change
	// Ignored lists out-of-scope differences skipped by a rebase (audited).
	Ignored []string
	// Settings marks a change of provider zone settings besides RRsets
	// (EuroDNS forwards); it requires dns.zone.admin.
	Settings bool
	// Base, when set, replaces the current zone as the zone the changes are
	// applied onto (checked and written): it carries the new settings.
	Base *dns.Zone
	// Committed, when set, runs after the write succeeded, still under the
	// zone lock: state that must follow the zone is persisted there, never
	// for a refused or failed write nor when there was nothing to write. Its
	// error is logged, the write having happened.
	Committed func(context.Context) error
}

// BuildFunc turns a request into a Plan against the current zone. The zone
// must not be modified.
type BuildFunc func(cur *dns.Zone) (*Plan, error)

// Engine is implemented by this package (New) and consumed by the HTTP
// layer, the MCP server and the provider API facades.
type Engine interface {
	// Authorize checks that zone is managed and that s may perform action on
	// it, auditing a refusal as op, and returns the provider of the zone.
	Authorize(ctx context.Context, s *identity.Subject, zone, action, op string) (provider.Provider, error)
	// ReadZone reads a managed zone upstream (dns.read, a refusal audited as
	// op) and returns it with the gate zone version. The zone is shared with
	// the cache and must not be modified.
	ReadZone(ctx context.Context, s *identity.Subject, zone, op string) (*dns.Zone, int64, error)
	// Write runs the write pipeline under the zone lock: build computes the
	// changes against the current zone, every business rule applies, then
	// the provider writes. ifMatch is checked against the zone version. It
	// returns the zone read back after the write (nil when that read failed)
	// and the zone version after it. action names the write in the audit.
	Write(ctx context.Context, s *identity.Subject, zone, ifMatch, action string, build BuildFunc) (*dns.Zone, int64, error)
	// Adopt brings existing RRsets under the ownership of owner (a team of
	// s; s's team by default). Adopting an RRset s's team already owns, with
	// the same content, is a no-op needing write access only.
	Adopt(ctx context.Context, s *identity.Subject, zone string, refs []uiapi.RRsetRef, owner string) error
	// Reconcile compares stored ownership with upstream for one zone: marks
	// drifted RRsets tainted, resolves pending claims, GCs expired ephemeral
	// RRsets. Called periodically by the server.
	Reconcile(ctx context.Context, zone string) error

	// Zones and Inventory serve the read-only UI (action ui.read). They read
	// the cached upstream zone merged with ownership; upstream is called
	// only when the cache of a zone is empty.
	Zones(ctx context.Context, s *identity.Subject) ([]uiapi.ZoneSummary, error)
	Inventory(ctx context.Context, s *identity.Subject, zone string) (*uiapi.ZoneInventory, error)
	// RRset returns one RRset with its ownership, from the same cache as
	// Inventory (upstream is read only when the cache of the zone is empty)
	// and one ownership lookup: it serves frequent single-RRset reads (a
	// Terraform plan). It requires dns.read or ui.read (dns.read on an
	// unmanaged zone); not_found when the RRset is neither upstream nor
	// owned. Writes check freshness themselves (ExpectedHash under the lock).
	RRset(ctx context.Context, s *identity.Subject, zone string, key dns.Key) (*uiapi.RRset, error)

	// PreviewAdopt evaluates foreign RRsets for adoption (fresh upstream read,
	// no lock, no write). AdoptMany adopts all of req.RRsets or none, provided
	// they still match the preview token; it requires a comment.
	PreviewAdopt(ctx context.Context, s *identity.Subject, zone string, sel uiapi.AdoptSelection) (*uiapi.AdoptPreview, error)
	AdoptMany(ctx context.Context, s *identity.Subject, zone string, req uiapi.AdoptApply) (*uiapi.AdoptResult, error)

	// PlanRRsets is a dry run of desired RRset states (no lock, no write):
	// business refusals come back as Allowed=false with Reason/Message.
	// ApplyRRsets writes them, refusing with precondition when the zone
	// version is not expectedZoneVersion; expectedZoneVersion <= 0 means no
	// zone version check (REST PUT/DELETE of one RRset). The per-RRset
	// preconditions are enforced by both, under the zone lock against a
	// fresh upstream read for ApplyRRsets: MustNotExist on an existing RRset
	// is foreign_rrset (409) when the gate does not own it and precondition
	// (412) when it does; an ExpectedHash mismatch (or a missing RRset) is
	// precondition (412).
	PlanRRsets(ctx context.Context, s *identity.Subject, zone string, changes []uiapi.RRsetChange) (*uiapi.PlanResult, error)
	ApplyRRsets(ctx context.Context, s *identity.Subject, zone string, changes []uiapi.RRsetChange, expectedZoneVersion int64) (*uiapi.PlanResult, error)
}

type requestIDKey struct{}

// WithRequestID attaches the request id used in ownership entries and audit.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request id set by WithRequestID, "" if none.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
