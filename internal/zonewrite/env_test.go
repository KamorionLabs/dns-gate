package zonewrite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

const zoneName = "example.com"

var (
	alice = &identity.Subject{Issuer: "idp", ID: "alice", Name: "alice@example.com", Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-a"}}
	bob   = &identity.Subject{Issuer: "idp", ID: "bob", Name: "bob@example.com", Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-b"}}
	admin = &identity.Subject{Issuer: "idp", ID: "root", Name: "root@example.com", Category: identity.CategoryHuman, Roles: []string{"writer", "admin"}, Teams: []string{"team-a"}}
)

// fakeAuthz: writer = any RRset; acme = TXT under _acme-challenge (rebase,
// ephemeral); admin = adopt and zone admin; protected = NS/MX at apex.
type fakeAuthz struct{ max int }

func has(s *identity.Subject, role string) bool { return slices.Contains(s.Roles, role) }

func (f *fakeAuthz) IsProtected(_ string, k dns.Key) bool {
	return k.Host == dns.Apex && (k.Type == "NS" || k.Type == "MX")
}

func (f *fakeAuthz) Allow(s *identity.Subject, action, _ string) bool {
	switch action {
	case policy.ActionDNSRead, policy.ActionUIRead:
		return true
	case policy.ActionRecordWrite:
		return has(s, "writer") || has(s, "acme")
	case policy.ActionRecordAdopt:
		return has(s, "admin") || has(s, "adopter")
	default:
		return has(s, "admin")
	}
}

func (f *fakeAuthz) AllowRRset(s *identity.Subject, action, zone string, k dns.Key) bool {
	if f.IsProtected(zone, k) {
		return false
	}
	if action == policy.ActionRecordWrite {
		if has(s, "writer") {
			return true
		}
		return has(s, "acme") && k.Type == "TXT" && strings.HasPrefix(k.Host, "_acme-challenge")
	}
	if action == policy.ActionRecordAdopt && has(s, "adopter") {
		return true
	}
	return has(s, "admin")
}

func (f *fakeAuthz) OwnerTeam(s *identity.Subject, _ string) (string, bool) {
	if len(s.Teams) == 0 {
		return "", false
	}
	return s.Teams[0], true
}

func (f *fakeAuthz) MaxChangesPerRequest(*identity.Subject) int { return f.max }
func (f *fakeAuthz) RebaseOnSave(s *identity.Subject) bool      { return has(s, "acme") }
func (f *fakeAuthz) EphemeralTTL(s *identity.Subject) time.Duration {
	if has(s, "acme") {
		return time.Hour
	}
	return 0
}

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Log(_ context.Context, e audit.Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) find(action, decision string) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, e := range r.events {
		if e.Action == action && e.Decision == decision {
			out = append(out, e)
		}
	}
	return out
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type env struct {
	t     *testing.T
	srv   *eurodnstest.Server
	prov  *eurodnsprov.Provider
	st    store.Store
	authz *fakeAuthz
	audit *recorder
	clock *clock
	eng   Engine
}

func baseZone() *eurodns.Zone {
	return &eurodns.Zone{
		Name: zoneName,
		Records: []eurodns.Record{
			{Type: "NS", Host: "@", TTL: 86400, RData: "ns1.example.net."},
			{Type: "MX", Host: "@", TTL: 3600, RData: "10 mx.example.net."},
			{Type: "CNAME", Host: "legacy", TTL: 3600, RData: "old.example.net."},
			{Type: "TXT", Host: "@", TTL: 3600, RData: "\"v=spf1 -all\""},
		},
		URLForwards:  []json.RawMessage{json.RawMessage(`{"host":"go","target":"https://example.net/","type":"PERMANENT"}`)},
		MailForwards: []json.RawMessage{},
	}
}

func newProvider(t *testing.T, base string) *eurodnsprov.Provider {
	t.Helper()
	client, err := eurodns.New(eurodns.WithBaseURL(base), eurodns.WithAuth(eurodns.APIKeyAuth{AppID: "app", APIKey: "key"}),
		eurodns.WithRateLimit(time.Microsecond, 1000))
	if err != nil {
		t.Fatal(err)
	}
	return eurodnsprov.NewWithClient("eurodns", base, client)
}

func newEnv(t *testing.T, opts eurodnstest.Options) *env {
	t.Helper()
	return newEnvWith(t, opts, nil)
}

func newEnvWith(t *testing.T, opts eurodnstest.Options, st store.Store) *env {
	t.Helper()
	return newEnvConfig(t, opts, st, nil)
}

func newEnvConfig(t *testing.T, opts eurodnstest.Options, st store.Store, mut func(*Config)) *env {
	t.Helper()
	opts.AppID, opts.APIKey = "app", "key"
	srv := eurodnstest.NewServer(opts)
	t.Cleanup(srv.Close)
	srv.Seed(baseZone())
	c := &clock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	if st == nil {
		st = store.NewMemoryWithClock(c.Now)
	}
	e := &env{t: t, srv: srv, prov: newProvider(t, srv.URL), st: st, authz: &fakeAuthz{}, audit: &recorder{}, clock: c}
	var err error
	cfg := Config{Providers: provider.Single(e.prov), Store: e.st, Authz: e.authz, Audit: e.audit, Zones: []string{zoneName},
		Holder: "test", LockWait: 2 * time.Second, CheckOnWrite: true, Now: c.Now}
	if mut != nil {
		mut(&cfg)
	}
	e.eng, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func rec(typ, host, rdata string) eurodns.Record {
	return eurodns.Record{Type: typ, Host: host, TTL: 3600, RData: rdata}
}

func reasonOf(err error) Reason {
	if ze, ok := AsError(err); ok {
		return ze.Reason
	}
	return Reason(fmt.Sprintf("not a zonewrite error: %v", err))
}

func (e *env) wantReason(err error, want Reason) {
	e.t.Helper()
	if got := reasonOf(err); got != want {
		e.t.Fatalf("reason = %s, want %s (err %v)", got, want, err)
	}
}

// add merges records into their RRsets through Write, like the EuroDNS
// addDnsRecords operation.
func (e *env) add(s *identity.Subject, zone string, recs ...eurodns.Record) error {
	_, _, err := e.eng.Write(context.Background(), s, zone, "", "addRecords", func(cur *dns.Zone) (*Plan, error) {
		sets := index(cur)
		want := map[dns.Key]*dns.RRset{}
		var keys []dns.Key
		for _, r := range recs {
			k := dns.Key{Host: dns.NormalizeHost(r.Host, zone), Type: strings.ToUpper(r.Type)}
			n, ok := want[k]
			if !ok {
				n = &dns.RRset{Key: k, TTL: r.TTL}
				if old, found := sets[k]; found {
					n.Values = slices.Clone(old.Values)
				}
				want[k] = n
				keys = append(keys, k)
			}
			if !slices.Contains(n.Values, r.RData) {
				n.Values = append(n.Values, r.RData)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
		plan := &Plan{}
		for _, k := range keys {
			plan.Changes = append(plan.Changes, dns.Change{Key: k, New: want[k]})
		}
		return plan, nil
	})
	return err
}

func (e *env) mustAdd(s *identity.Subject, recs ...eurodns.Record) {
	e.t.Helper()
	if err := e.add(s, zoneName, recs...); err != nil {
		e.t.Fatalf("add: %v", err)
	}
}

func (e *env) own(host, typ string) *store.Ownership {
	o, err := e.st.Get(context.Background(), zoneName, host, typ)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return o
}

func (e *env) upstream(host, typ string) []string {
	return rrset.Group(zoneName, e.srv.Zone(zoneName).Records)[rrset.Key{Host: host, Type: typ}].Values
}

func adoptRefs(refs ...string) []uiapi.RRsetRef {
	var out []uiapi.RRsetRef
	for _, r := range refs {
		f := strings.Fields(r)
		out = append(out, uiapi.RRsetRef{Host: f[0], Type: f[1]})
	}
	return out
}

func withSOA(z *eurodns.Zone, serial int) *eurodns.Zone {
	locked := true
	z.Records = append([]eurodns.Record{{Type: "SOA", Host: "@", TTL: 86400, Locked: &locked,
		RData: fmt.Sprintf("ns1.example.net. hostmaster.example.com. %d 10800 3600 604800 3600", serial)}}, z.Records...)
	for i := range z.Records {
		if z.Records[i].Type == "NS" {
			z.Records[i].Locked = &locked
		}
	}
	return z
}
func TestIfMatchAcceptsQuotedAndBareTags(t *testing.T) {
	for _, h := range []string{`"v3"`, `v3`, `W/"v3"`, `"v1", "v3"`, `*`, ``} {
		if !ifMatchOK(h, 3) {
			t.Errorf("ifMatchOK(%q, 3) = false", h)
		}
	}
	for _, h := range []string{`"v2"`, `v4`, `W/v30`} {
		if ifMatchOK(h, 3) {
			t.Errorf("ifMatchOK(%q, 3) = true", h)
		}
	}
}
