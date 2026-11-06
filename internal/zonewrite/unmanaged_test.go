package zonewrite

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

const otherZone = "other.org"

// mutableZones is a ZoneSet whose managed zones a test can change, like a
// policy activation does.
type mutableZones struct {
	mu        sync.Mutex
	managed   map[string]bool
	discovery map[string]bool
}

func (m *mutableZones) Managed(z string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.managed[z]
}

func (m *mutableZones) list(f func(string) bool, set map[string]bool) []string {
	var out []string
	for z := range set {
		if f(z) {
			out = append(out, z)
		}
	}
	sort.Strings(out)
	return out
}

func (m *mutableZones) ManagedZones() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.list(func(string) bool { return true }, m.managed)
}

func (m *mutableZones) IsUnmanaged(z string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.managed[z] && m.discovery[z]
}

func (m *mutableZones) UnmanagedZones() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.list(func(z string) bool { return !m.managed[z] }, m.discovery)
}

func (m *mutableZones) manage(z string) {
	m.mu.Lock()
	m.managed[z] = true
	m.mu.Unlock()
}

// noReadAuthz denies dns.read to carol.
type noReadAuthz struct{ fakeAuthz }

func (a *noReadAuthz) Allow(s *identity.Subject, action, zone string) bool {
	if s.ID == "carol" && action == policy.ActionDNSRead {
		return false
	}
	return a.fakeAuthz.Allow(s, action, zone)
}

var carol = &identity.Subject{Issuer: "idp", ID: "carol", Roles: []string{"reader"}}

func unmanagedEnv(t *testing.T) (*env, *mutableZones) {
	t.Helper()
	e := newEnv(t, eurodnstest.Options{})
	e.srv.Seed(&eurodns.Zone{Name: otherZone, Records: []eurodns.Record{
		{Type: "A", Host: "www", TTL: 3600, RData: "192.0.2.80"},
		{Type: "TXT", Host: "@", TTL: 3600, RData: "\"hello\""},
	}})
	zs := &mutableZones{managed: map[string]bool{zoneName: true}, discovery: map[string]bool{zoneName: true, otherZone: true, "cold.org": true}}
	var err error
	e.eng, err = New(Config{Providers: provider.Single(e.prov), Store: e.st, Authz: &noReadAuthz{}, Audit: e.audit, ZoneSet: zs,
		UnmanagedTTL: 10 * time.Minute, Holder: "test", LockWait: 2 * time.Second, CheckOnWrite: true, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return e, zs
}

func TestUnmanagedZoneReadOnly(t *testing.T) {
	e, zs := unmanagedEnv(t)
	ctx := context.Background()

	// Listing never reads unmanaged zones upstream.
	n := e.srv.Requests()
	sums, err := e.eng.Zones(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.srv.Requests() - n; got != 1 { // the managed zone's cold cache only
		t.Fatalf("listing made %d upstream requests, want 1", got)
	}
	if len(sums) != 3 || sums[0].Zone != zoneName || sums[0].Unmanaged || !sums[1].Unmanaged || sums[1].Zone != "cold.org" ||
		sums[2].Zone != otherZone || sums[2].RRsets != 0 || sums[2].LastSyncedAt != nil {
		t.Fatalf("summaries %+v", sums)
	}

	// Reading the zone: one upstream GET, then cached for UnmanagedTTL.
	n = e.srv.Requests()
	inv, err := e.eng.Inventory(ctx, alice, otherZone)
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Unmanaged || len(inv.RRsets) != 4 || inv.RRsets[3].Host != "www" || inv.RRsets[3].Status != uiapi.StatusForeign { // + fake SOA and NS
		t.Fatalf("inventory %+v", inv)
	}
	for range 3 {
		if _, err := e.eng.Inventory(ctx, alice, otherZone); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.srv.Requests() - n; got != 1 {
		t.Fatalf("%d upstream reads, want 1 within the TTL", got)
	}
	sums, _ = e.eng.Zones(ctx, alice)
	if sums[2].RRsets != 4 || sums[2].Foreign != 4 || sums[2].LastSyncedAt == nil {
		t.Fatalf("summary after a read %+v", sums[2])
	}
	e.clock.Add(11 * time.Minute)
	if _, err := e.eng.Inventory(ctx, alice, otherZone); err != nil || e.srv.Requests()-n != 2 {
		t.Fatalf("stale cache not refreshed (%v, %d requests)", err, e.srv.Requests()-n)
	}

	// dns.read is required.
	_, err = e.eng.Inventory(ctx, carol, otherZone)
	e.wantReason(err, ReasonForbidden)

	// No write, adoption, plan or zone read through the EuroDNS API.
	e.wantReason(e.add(alice, otherZone, rec("A", "api", "192.0.2.1")), ReasonNotFound)
	_, _, err = e.eng.ReadZone(ctx, alice, otherZone, "getDnsZone")
	e.wantReason(err, ReasonNotFound)
	_, err = e.eng.PreviewAdopt(ctx, admin, otherZone, uiapi.AdoptSelection{Hosts: []string{"www"}})
	e.wantReason(err, ReasonNotFound)
	_, err = e.eng.PlanRRsets(ctx, alice, otherZone, []uiapi.RRsetChange{{Host: "api", Type: "A", TTL: 3600, Values: []string{"192.0.2.1"}}})
	e.wantReason(err, ReasonNotFound)
	if err := e.eng.Reconcile(ctx, otherZone); reasonOf(err) != ReasonNotFound {
		t.Fatalf("reconcile of an unmanaged zone: %v", err)
	}
	// Undiscovered zone: unknown.
	_, err = e.eng.Inventory(ctx, alice, "absent.org")
	e.wantReason(err, ReasonNotFound)

	// Once managed (policy activation), the zone accepts writes and adoption.
	zs.manage(otherZone)
	if err := e.add(alice, otherZone, rec("A", "api", "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	p, err := e.eng.PreviewAdopt(ctx, admin, otherZone, uiapi.AdoptSelection{Hosts: []string{"www"}, Types: []string{"A"}})
	if err != nil || len(p.Candidates) != 1 || !p.Candidates[0].Adoptable {
		t.Fatalf("adoption preview after management: %+v %v", p, err)
	}
	inv, err = e.eng.Inventory(ctx, alice, otherZone)
	if err != nil || inv.Unmanaged {
		t.Fatalf("inventory after management: %+v %v", inv, err)
	}
}
