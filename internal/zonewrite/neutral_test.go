package zonewrite

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// memProvider is an in-memory provider with alias support and conditional,
// non-atomic writes (one change at a time, like an API without batches).
type memProvider struct {
	mu      sync.Mutex
	sets    map[dns.Key]dns.RRset
	atomic  bool
	failAt  int   // fail the change with this index (1-based), 0 = never
	failErr error // error returned by the failing change
	applies int
	reads   int
}

func newMemProvider() *memProvider {
	return &memProvider{sets: map[dns.Key]dns.RRset{
		{Host: dns.Apex, Type: "SOA"}: {Key: dns.Key{Host: dns.Apex, Type: "SOA"}, TTL: 900, Values: []string{"ns. host. 1 2 3 4 5"}, ReadOnly: "server_managed"},
		{Host: "w", Type: "A"}:        {Key: dns.Key{Host: "w", Type: "A"}, TTL: 60, Values: []string{"192.0.2.1"}, ReadOnly: "routing_policy"},
		{Host: "legacy", Type: "A"}:   {Key: dns.Key{Host: "legacy", Type: "A"}, TTL: 300, Values: []string{"192.0.2.9"}},
	}}
}

func (m *memProvider) ID() string   { return "mem-1" }
func (m *memProvider) Kind() string { return "mem" }
func (m *memProvider) Capabilities() provider.Capabilities {
	return provider.Capabilities{AtomicBatch: m.atomic, ConditionalWrite: true, Alias: true, MinTTL: 0, MaxTTL: 86400}
}
func (m *memProvider) ListZones(context.Context) ([]string, error) { return []string{zoneName}, nil }

func (m *memProvider) ReadZone(_ context.Context, zone string) (*dns.Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	z := &dns.Zone{Name: zone, Provider: m.ID()}
	for _, s := range m.sets {
		s.Values = slices.Clone(s.Values)
		z.RRsets = append(z.RRsets, s)
	}
	sort.Slice(z.RRsets, func(i, j int) bool { return z.RRsets[i].Key.Less(z.RRsets[j].Key) })
	return z, nil
}

func (m *memProvider) Normalize(zone string, s dns.RRset) (dns.RRset, error) {
	if s.Alias != nil {
		a := *s.Alias
		a.Target = strings.TrimSuffix(strings.ToLower(a.Target), ".") + "."
		s.Alias, s.TTL, s.Values = &a, 0, nil
		return s, nil
	}
	if s.TTL > 86400 {
		return s, &provider.InvalidError{Key: s.Key, Message: "TTL too high"}
	}
	s.Values = slices.Clone(s.Values)
	sort.Strings(s.Values)
	return s, nil
}

func (m *memProvider) Apply(_ context.Context, _ string, _ *dns.Zone, changes []dns.Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applies++
	for i, c := range changes {
		if m.failAt == i+1 {
			return m.failErr
		}
		if cur, ok := m.sets[c.Key]; (c.Old == nil) == ok || (ok && dns.ContentHash(cur) != dns.ContentHash(*c.Old)) {
			return provider.ErrConflict
		}
		if c.New == nil {
			delete(m.sets, c.Key)
		} else {
			m.sets[c.Key] = *c.New
		}
	}
	return nil
}

func (m *memProvider) set(s dns.RRset) {
	m.mu.Lock()
	m.sets[s.Key] = s
	m.mu.Unlock()
}

func memEnv(t *testing.T) (*env, *memProvider) {
	t.Helper()
	c := &clock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	p := newMemProvider()
	e := &env{t: t, st: store.NewMemoryWithClock(c.Now), authz: &fakeAuthz{}, audit: &recorder{}, clock: c}
	var err error
	e.eng, err = New(Config{Providers: provider.Single(p), Store: e.st, Authz: e.authz, Audit: e.audit, Zones: []string{zoneName},
		Holder: "test", LockWait: 2 * time.Second, CheckOnWrite: true, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return e, p
}

func TestAliasRRsets(t *testing.T) {
	e, p := memEnv(t)
	ctx := context.Background()
	alias := &dns.Alias{Target: "LB.example.net", HostedZoneID: "Z1"}
	res, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "app", Type: "A", Alias: alias}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 1 || res.Changes[0].NewAlias == nil || res.Changes[0].NewAlias.Target != "lb.example.net." {
		t.Fatalf("result %+v", res)
	}
	s, _ := p.ReadZone(ctx, zoneName)
	app, _ := s.Set(dns.Key{Host: "app", Type: "A"})
	if o := e.own("app", "A"); o == nil || o.State != store.StateActive || o.ContentHash != dns.ContentHash(app) {
		t.Fatalf("ownership %+v", o)
	}
	inv, err := e.eng.Inventory(ctx, alice, zoneName)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Provider != "mem-1" {
		t.Fatalf("inventory provider %q", inv.Provider)
	}
	for _, r := range inv.RRsets {
		switch r.Host + " " + r.Type {
		case "app A":
			if r.Alias == nil || r.Hash != dns.ContentHash(app) || r.Status != uiapi.StatusManaged {
				t.Fatalf("alias RRset %+v", r)
			}
		case "w A":
			if r.ReadOnly != "routing_policy" {
				t.Fatalf("read-only RRset %+v", r)
			}
		}
	}
	sums, _ := e.eng.Zones(ctx, alice)
	if len(sums) != 1 || sums[0].Provider != "mem-1" {
		t.Fatalf("summaries %+v", sums)
	}
	ev := e.audit.find("applyRRsets", "allow")
	if len(ev) != 1 || ev[0].Provider != "mem-1" || ev[0].SnapshotID != "" {
		t.Fatalf("audit %+v", ev)
	}
}

func TestAliasRefusedWithoutCapability(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	p, err := e.eng.PlanRRsets(context.Background(), alice, zoneName, []uiapi.RRsetChange{{Host: "app", Type: "A", Alias: &dns.Alias{Target: "x."}}})
	if err != nil || p.Allowed || p.Reason != string(ReasonInvalid) || !strings.Contains(p.Message, "alias") {
		t.Fatalf("plan %+v %v", p, err)
	}
}

func TestReadOnlyRRsetsRefused(t *testing.T) {
	e, _ := memEnv(t)
	ctx := context.Background()
	for _, c := range []uiapi.RRsetChange{
		{Host: "w", Type: "A", Values: []string{"192.0.2.2"}},
		{Host: "@", Type: "SOA", Values: []string{"x. y. 1 2 3 4 5"}},
		{Host: "w", Type: "A", Delete: true},
	} {
		_, err := e.eng.ApplyRRsets(ctx, admin, zoneName, []uiapi.RRsetChange{c}, -1)
		e.wantReason(err, ReasonForbidden)
	}
	e.wantReason(e.eng.Adopt(ctx, admin, zoneName, adoptRefs("w A"), ""), ReasonForbidden)
	pv, err := e.eng.PreviewAdopt(ctx, admin, zoneName, uiapi.AdoptSelection{RRsets: adoptRefs("w A", "legacy A")})
	if err != nil || len(pv.Candidates) != 2 || pv.Candidates[0].Reason != "routing_policy" || !pv.Candidates[1].Adoptable {
		t.Fatalf("preview %+v %v", pv, err)
	}
}

func TestRRsetPreconditions(t *testing.T) {
	e, p := memEnv(t)
	ctx := context.Background()
	legacy, _ := p.ReadZone(ctx, zoneName)
	l, _ := legacy.Set(dns.Key{Host: "legacy", Type: "A"})
	hash := dns.ContentHash(l)

	plan, err := e.eng.PlanRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "legacy", Type: "A", Values: []string{"192.0.2.1"}, MustNotExist: true}})
	if err != nil || plan.Allowed || plan.Reason != string(ReasonForeignRRset) {
		t.Fatalf("must not exist %+v %v", plan, err)
	}
	plan, _ = e.eng.PlanRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "legacy", Type: "A", Values: []string{"192.0.2.1"}, ExpectedHash: "nope"}})
	if plan.Reason != string(ReasonPrecondition) {
		t.Fatalf("expected hash %+v", plan)
	}
	plan, _ = e.eng.PlanRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "legacy", Type: "A", Values: []string{"192.0.2.1"}, ExpectedHash: hash}})
	if plan.Reason != string(ReasonForeignRRset) {
		t.Fatalf("a matching hash goes on to the ownership rules: %+v", plan)
	}

	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "new", Type: "TXT", Values: []string{"a"}, MustNotExist: true}}, -1); err != nil {
		t.Fatal(err)
	}
	_, err = e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "new", Type: "TXT", Values: []string{"b"}, MustNotExist: true}}, -1)
	e.wantReason(err, ReasonPrecondition)
	z, _ := p.ReadZone(ctx, zoneName)
	n, _ := z.Set(dns.Key{Host: "new", Type: "TXT"})
	_, err = e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "new", Type: "TXT", Values: []string{"b"}, ExpectedHash: "stale"}}, -1)
	e.wantReason(err, ReasonPrecondition)
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "new", Type: "TXT", Values: []string{"b"}, ExpectedHash: dns.ContentHash(n)}}, -1); err != nil {
		t.Fatal(err)
	}
	if ev := e.audit.find("applyRRsets", "deny"); len(ev) != 2 || ev[0].Reason != string(ReasonPrecondition) {
		t.Fatalf("refusals not audited %+v", ev)
	}
}

func TestUpstreamConflictIsPrecondition(t *testing.T) {
	e, p := memEnv(t)
	p.atomic = true
	ctx := context.Background()
	p.failAt, p.failErr = 1, provider.ErrConflict
	_, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "a", Type: "TXT", Values: []string{"x"}}}, -1)
	e.wantReason(err, ReasonPrecondition)
	if e.own("a", "TXT") != nil {
		t.Fatal("claim of an atomic write known not applied must be reverted")
	}
}

// A provider without atomic batches may apply part of a write: the claims
// are settled against a fresh read at once.
func TestNonAtomicPartialWriteSettled(t *testing.T) {
	e, p := memEnv(t)
	ctx := context.Background()
	p.failAt, p.failErr = 2, errors.New("throttled")
	_, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{
		{Host: "a", Type: "TXT", Values: []string{"x"}},
		{Host: "b", Type: "TXT", Values: []string{"y"}},
	}, -1)
	e.wantReason(err, ReasonUpstream)
	if o := e.own("a", "TXT"); o == nil || o.State != store.StateActive {
		t.Fatalf("applied change not confirmed: %+v", o)
	}
	if o := e.own("b", "TXT"); o != nil {
		t.Fatalf("change not applied must leave no claim: %+v", o)
	}
	p.failAt = 0
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "b", Type: "TXT", Values: []string{"y"}}}, -1); err != nil {
		t.Fatal(err)
	}
	// Drift on an owned RRset is still detected.
	p.set(dns.RRset{Key: dns.Key{Host: "b", Type: "TXT"}, TTL: 3600, Values: []string{"z"}})
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	if o := e.own("b", "TXT"); o.State != store.StateTainted {
		t.Fatalf("drift %+v", o)
	}
}

func TestRRsetFromCache(t *testing.T) {
	e, p := memEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "app", Type: "TXT", Values: []string{"v"}}}, 0); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	reads := p.reads
	p.mu.Unlock()
	for range 5 {
		r, err := e.eng.RRset(ctx, alice, zoneName, dns.Key{Host: "APP.example.com.", Type: "txt"})
		if err != nil || r.Status != uiapi.StatusManaged || r.Owner != "team-a" || r.Hash == "" || r.Values[0] != "v" {
			t.Fatalf("rrset %+v %v", r, err)
		}
	}
	if r, err := e.eng.RRset(ctx, alice, zoneName, dns.Key{Host: "w", Type: "A"}); err != nil || r.ReadOnly != "routing_policy" || r.Status != uiapi.StatusForeign {
		t.Fatalf("read-only rrset %+v %v", r, err)
	}
	_, err := e.eng.RRset(ctx, alice, zoneName, dns.Key{Host: "nope", Type: "A"})
	e.wantReason(err, ReasonNotFound)
	_, err = e.eng.RRset(ctx, alice, "other.org", dns.Key{Host: "www", Type: "A"})
	e.wantReason(err, ReasonNotFound)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reads != reads {
		t.Fatalf("single RRset reads hit upstream %d times", p.reads-reads)
	}
}
