// Package audit emits structured audit events.
package audit

import (
	"context"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
)

// Event is one audit record (JSON line).
type Event struct {
	Time            time.Time      `json:"time"`
	RequestID       string         `json:"request_id"`
	Subject         string         `json:"subject"` // issuer:id
	SubjectName     string         `json:"subject_name,omitempty"`
	SubjectCategory string         `json:"subject_category,omitempty"` // human | pipeline | key
	Teams           []string       `json:"teams,omitempty"`
	Action          string         `json:"action"` // operationId or gate action
	Zone            string         `json:"zone,omitempty"`
	Decision        string         `json:"decision"` // allow | deny | error
	Reason          string         `json:"reason,omitempty"`
	Changes         []uiapi.Change `json:"changes,omitempty"`
	SnapshotID      *int64         `json:"snapshot_id,omitempty"`
	Extra           map[string]any `json:"extra,omitempty"`
}

// Logger records events. Implementations must be safe for concurrent use.
type Logger interface {
	Log(ctx context.Context, e Event)
}
