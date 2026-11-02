package store

import (
	"context"
	"errors"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/audit"
)

// State of an ownership entry.
type State string

const (
	StatePending State = "pending" // claim written before the upstream write
	StateActive  State = "active"
	StateTainted State = "tainted" // changed outside the gate; writes blocked
)

// Ownership is one owned RRset.
type Ownership struct {
	Zone              string
	Host              string
	Type              string
	Owner             string // team
	CreatedBy         string // issuer:id
	CreatedByName     string
	CreatedByCategory string
	UpdatedBy         string // issuer:id of the last gate write or adoption
	UpdatedByName     string
	UpdatedByCategory string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	RequestID         string
	ContentHash       string // rrset.ContentHash at the last gate write
	PendingHash       string // expected hash while State == pending
	State             State
	Adopted           bool
	ExpiresAt         *time.Time // ephemeral records (ACME), GC after this time
	Version           int64      // optimistic concurrency
}

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: version conflict")
	ErrLockHeld = errors.New("store: lock held")
	// ErrInvalidTransition: a status change that only Activate may perform, or
	// activating a revision that is not proposed or approved.
	ErrInvalidTransition = errors.New("store: invalid policy revision transition")
)

// Store is implemented by memory and DynamoDB backends.
type Store interface {
	PolicyStore

	Get(ctx context.Context, zone, host, typ string) (*Ownership, error)
	List(ctx context.Context, zone string) ([]Ownership, error)
	// Put creates (Version 0) or updates (Version must match) an entry.
	Put(ctx context.Context, o Ownership) error
	Delete(ctx context.Context, zone, host, typ string, version int64) error

	// ZoneVersion is a monotonic counter bumped on every gate write; used as ETag.
	ZoneVersion(ctx context.Context, zone string) (int64, error)
	BumpZoneVersion(ctx context.Context, zone string, expected int64) (int64, error)

	// Lock acquires a per-zone lease (owner id, ttl). Returns ErrLockHeld.
	Lock(ctx context.Context, zone, holder string, ttl time.Duration) error
	Unlock(ctx context.Context, zone, holder string) error

	// AppendAudit stores an audit event (kept for the configured retention).
	AppendAudit(ctx context.Context, e audit.Event) error
	// ListAudit returns events newest first and an opaque cursor for the next
	// page ("" when there is none).
	ListAudit(ctx context.Context, q AuditQuery) ([]audit.Event, string, error)
}

// AuditQuery filters ListAudit. Host and Type match any change of the event;
// Subject is a case-insensitive substring of the subject id or display name. Limit defaults to 50,
// capped at 500.
type AuditQuery struct {
	Zone, Host, Type, Subject, Category, Decision string
	Since, Until                                  time.Time
	Limit                                         int
	Cursor                                        string
}

// PolicyRevision is one immutable managed-policy revision. Document is the
// JSON of uiapi.PolicyDocument; only Status, Approvals and activation fields
// change after creation.
type PolicyRevision struct {
	ID          string
	ParentID    string
	Document    []byte
	Author      string // issuer:id
	AuthorName  string
	AuthorCat   string
	CreatedAt   time.Time
	Comment     string
	Status      string // uiapi.Revision*
	Approvals   []PolicyApproval
	ActivatedAt *time.Time
	ActivatedBy string
	Version     int64
}

// PolicyApproval is one decision on a revision.
type PolicyApproval struct {
	By, ByName, ByCategory string
	At                     time.Time
	Decision               string // approve | reject
	Comment                string
}

// PolicyStore persists managed-policy revisions. Implemented by every Store
// backend.
type PolicyStore interface {
	CreateRevision(ctx context.Context, r PolicyRevision) error
	GetRevision(ctx context.Context, id string) (*PolicyRevision, error)
	// ListRevisions returns newest first; status "" means all.
	ListRevisions(ctx context.Context, status string, limit int, cursor string) ([]PolicyRevision, string, error)
	// UpdateRevision writes status/approvals; r.Version must match.
	UpdateRevision(ctx context.Context, r PolicyRevision) error
	// ActiveRevision returns the active revision, ErrNotFound if none.
	ActiveRevision(ctx context.Context) (*PolicyRevision, error)
	// Activate atomically makes id active if the current active id equals
	// expectedActiveID ("" = none), marking the previous one superseded;
	// ErrConflict otherwise.
	Activate(ctx context.Context, id, expectedActiveID, by string, at time.Time) error
}
