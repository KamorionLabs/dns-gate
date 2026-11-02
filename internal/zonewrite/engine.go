package zonewrite

import (
	"context"
	"errors"

	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// Error reasons, mapped to HTTP statuses by the HTTP layer and returned in
// the error body {"reason": "...", "message": "..."}.
type Reason string

const (
	ReasonForbidden     Reason = "forbidden"        // 403 RBAC or protected record
	ReasonForeignRRset  Reason = "foreign_rrset"    // 409 RRset exists and is not owned by the gate
	ReasonNotOwner      Reason = "not_owner"        // 403 owned by another team
	ReasonTainted       Reason = "tainted"          // 409 changed outside the gate
	ReasonPrecondition  Reason = "precondition"     // 412 If-Match mismatch
	ReasonTooMany       Reason = "too_many_changes" // 403 blast radius
	ReasonInvalid       Reason = "invalid_zone"     // 400 EuroDNS check failed
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

// Engine is implemented by this package (New) and consumed by the HTTP layer.
type Engine interface {
	// GetZone returns the upstream zone with ETag set to the gate zone version.
	GetZone(ctx context.Context, s *identity.Subject, zone string) (*eurodns.Zone, error)
	AddRecords(ctx context.Context, s *identity.Subject, zone string, recs []eurodns.Record, ifMatch string) (*eurodns.Zone, error)
	DeleteRecord(ctx context.Context, s *identity.Subject, zone string, id int64, ifMatch string) (*eurodns.Zone, error)
	// SaveZone handles a full-zone PUT: delta computed against the current
	// zone under lock; out-of-scope differences are refused, except for
	// subjects whose role sets rebase (ACME clients), where they are ignored.
	SaveZone(ctx context.Context, s *identity.Subject, zone string, z *eurodns.Zone, ifMatch string) error
	CheckZone(ctx context.Context, s *identity.Subject, zone string, z *eurodns.Zone) (*eurodns.Zone, error)
	Adopt(ctx context.Context, s *identity.Subject, zone string, req eurodns.AdoptRequest) error
	// Reconcile compares stored ownership with upstream for one zone: marks
	// drifted RRsets tainted, resolves pending claims, GCs expired ephemeral
	// RRsets. Called periodically by the server.
	Reconcile(ctx context.Context, zone string) error

	// Zones and Inventory serve the read-only UI (action ui.read). They read
	// the cached upstream zone merged with ownership; upstream is called
	// only when the cache of a zone is empty.
	Zones(ctx context.Context, s *identity.Subject) ([]uiapi.ZoneSummary, error)
	Inventory(ctx context.Context, s *identity.Subject, zone string) (*uiapi.ZoneInventory, error)

	// PreviewAdopt evaluates foreign RRsets for adoption (fresh upstream read,
	// no lock, no write). AdoptMany adopts all of req.RRsets or none, provided
	// they still match the preview token; it requires a comment.
	PreviewAdopt(ctx context.Context, s *identity.Subject, zone string, sel uiapi.AdoptSelection) (*uiapi.AdoptPreview, error)
	AdoptMany(ctx context.Context, s *identity.Subject, zone string, req uiapi.AdoptApply) (*uiapi.AdoptResult, error)

	// PlanRRsets is a dry run of desired RRset states (no lock, no write):
	// business refusals come back as Allowed=false with Reason/Message.
	// ApplyRRsets writes them through the SaveZone path, refusing with
	// precondition when the zone version is not expectedZoneVersion.
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
