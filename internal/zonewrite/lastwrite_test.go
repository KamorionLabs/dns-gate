package zonewrite

import (
	"context"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// The last gate write of a zone comes from the journal, so it survives a
// restart (or a request served by another replica) and ignores reads,
// refusals, adoptions and drift detection.
func TestZonesLastWriteFromJournal(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryWithClock(func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) })
	first := newEnvWith(t, eurodnstest.Options{}, st)
	first.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	wrote := first.clock.Now().UTC()
	// The production audit logger tees every event into the store.
	for _, ev := range first.audit.events {
		if err := st.AppendAudit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	later := func(d time.Duration, ev audit.Event) {
		ev.Time, ev.Zone, ev.RequestID = wrote.Add(d), zoneName, "noise-"+d.String()
		if err := st.AppendAudit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	later(time.Hour, audit.Event{Action: "mcp.list_rrsets", Decision: "allow", Subject: "idp:alice"})
	later(2*time.Hour, audit.Event{Action: "saveDnsZone", Decision: "deny", Reason: "forbidden",
		Changes: []uiapi.Change{{Op: "create", Host: "api", Type: "A", NewTTL: 3600, NewValues: []string{"192.0.2.9"}}}})
	later(3*time.Hour, audit.Event{Action: "gate.adopt", Decision: "allow",
		Changes: []uiapi.Change{{Op: "adopt", Host: "legacy", Type: "CNAME"}}})
	later(4*time.Hour, audit.Event{Action: "gate.taint", Decision: "allow",
		Changes: []uiapi.Change{{Op: "taint", Host: "www", Type: "A"}}})
	later(5*time.Hour, audit.Event{Action: "gate.expire", Decision: "allow",
		Changes: []uiapi.Change{{Op: "expire", Host: "_acme-challenge", Type: "TXT"}}}) // already gone upstream

	// A fresh engine on the same store: nothing in memory.
	restarted := newEnvWith(t, eurodnstest.Options{}, st)
	sums, err := restarted.eng.Zones(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 1 || sums[0].LastWriteAt == nil || !sums[0].LastWriteAt.Equal(wrote) {
		t.Fatalf("last write = %v, want %v", sums[0].LastWriteAt, wrote)
	}

	// A write on this replica shows at once, without waiting for the journal.
	restarted.clock.Add(10 * time.Hour)
	restarted.mustAdd(alice, rec("A", "app", "192.0.2.2"))
	sums, err = restarted.eng.Zones(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if want := restarted.clock.Now(); sums[0].LastWriteAt == nil || !sums[0].LastWriteAt.Equal(want) {
		t.Fatalf("last write = %v, want %v", sums[0].LastWriteAt, want)
	}
}

func TestIsWrite(t *testing.T) {
	for _, tc := range []struct {
		ev   audit.Event
		want bool
	}{
		{audit.Event{Decision: "allow", Changes: []uiapi.Change{{Op: "update"}}}, true},
		{audit.Event{Decision: "allow", Changes: []uiapi.Change{{Op: "delete"}}}, true},
		{audit.Event{Decision: "allow", Changes: []uiapi.Change{{Op: "expire", OldValues: []string{"x"}}}}, true},
		{audit.Event{Decision: "allow", Changes: []uiapi.Change{{Op: "expire"}}}, false},
		{audit.Event{Decision: "deny", Changes: []uiapi.Change{{Op: "create"}}}, false},
		{audit.Event{Decision: "allow", Changes: []uiapi.Change{{Op: "adopt"}}}, false},
		{audit.Event{Decision: "allow", Action: "mcp.apply_rrset_change"}, false},
	} {
		if got := isWrite(tc.ev); got != tc.want {
			t.Errorf("isWrite(%+v) = %v", tc.ev, got)
		}
	}
}
