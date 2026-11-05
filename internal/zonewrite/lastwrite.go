package zonewrite

import (
	"context"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

const (
	// lastWriteTTL bounds how often the zone list reads the journal for the
	// latest write of a zone.
	lastWriteTTL = 30 * time.Second
	// lastWriteScan bounds the journal events read per zone to find it.
	lastWriteScan = 1000
)

// journalWrite is the latest gate write of a zone found in the journal.
type journalWrite struct {
	at      *time.Time
	checked time.Time
}

// isWrite reports whether an audit event is a successful upstream write:
// reads, dry runs, refusals, adoptions and drift detection are not. An
// expiry is a write when the gate deleted the RRset upstream (old values set).
func isWrite(ev audit.Event) bool {
	if ev.Decision != "allow" {
		return false
	}
	for _, c := range ev.Changes {
		switch zonediff.Op(c.Op) {
		case zonediff.OpCreate, zonediff.OpUpdate, zonediff.OpDelete:
			return true
		case "expire":
			if len(c.OldValues) > 0 {
				return true
			}
		}
	}
	return false
}

// lastWrite is the time of the latest successful gate write on zone. The
// journal in the store is the source of truth: it survives restarts and is
// shared by replicas, unlike the in-memory mark of this replica (local),
// which only covers writes newer than the last journal read.
func (e *engine) lastWrite(ctx context.Context, zone string, local *time.Time) *time.Time {
	e.mu.Lock()
	w, ok := e.writes[zone]
	e.mu.Unlock()
	if !ok || e.now().Sub(w.checked) > lastWriteTTL {
		at, err := e.journalLastWrite(ctx, zone)
		if err != nil {
			e.log.Warn("journal read for the last write failed", "zone", zone, "error", err)
		} else {
			w = journalWrite{at: at, checked: e.now()}
			e.mu.Lock()
			e.writes[zone] = w
			e.mu.Unlock()
		}
	}
	return latest(w.at, local)
}

func (e *engine) journalLastWrite(ctx context.Context, zone string) (*time.Time, error) {
	q := store.AuditQuery{Zone: zone, Decision: "allow", Limit: 200}
	for scanned := 0; scanned < lastWriteScan; {
		events, next, err := e.cfg.Store.ListAudit(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, ev := range events {
			if isWrite(ev) {
				t := ev.Time
				return &t, nil
			}
		}
		scanned += len(events)
		if next == "" || len(events) == 0 {
			break
		}
		q.Cursor = next
	}
	return nil, nil
}

func latest(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil || a.After(*b):
		return a
	}
	return b
}
