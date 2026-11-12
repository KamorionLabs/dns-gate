package eurodnsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

const zoneName = "example.com"

var (
	alice = &identity.Subject{Issuer: "idp", ID: "alice", Name: "alice@example.com", Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-a"}}
	bob   = &identity.Subject{Issuer: "idp", ID: "bob", Name: "bob@example.com", Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-b"}}
	acme  = &identity.Subject{Issuer: "keys", ID: "acme-1", Name: "acme-1", Category: identity.CategoryKey, Roles: []string{"acme"}, Teams: []string{"team-acme"}}
	admin = &identity.Subject{Issuer: "idp", ID: "root", Name: "root@example.com", Category: identity.CategoryHuman, Roles: []string{"writer", "admin"}, Teams: []string{"team-a"}}
)

// fakeAuthz: writer = any RRset; acme = TXT under _acme-challenge (rebase,
// ephemeral); forwarder = any URL forward; admin = adopt and zone admin;
// protected = NS/MX at apex.
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
	case policy.ActionForwardWrite:
		return has(s, "forwarder")
	default:
		return has(s, "admin")
	}
}

func (f *fakeAuthz) AllowRRset(s *identity.Subject, action, zone string, k dns.Key) bool {
	if f.IsProtected(zone, k) {
		return false
	}
	if action == policy.ActionForwardWrite {
		return has(s, "forwarder")
	}
	if action == policy.ActionRecordWrite {
		if has(s, "writer") {
			return true
		}
		return has(s, "acme") && k.Type == "TXT" && strings.HasPrefix(k.Host, "_acme-challenge")
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
	st    store.Store
	authz *fakeAuthz
	audit *recorder
	clock *clock
	eng   zonewrite.Engine
	api   *Facade
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
		URLForwards:  []json.RawMessage{json.RawMessage(`{"id":41,"host":"go","forwardType":"HTTP301","url":"https://example.net/","updated":false}`)},
		MailForwards: []json.RawMessage{},
	}
}

func newEnv(t *testing.T, opts eurodnstest.Options) *env {
	t.Helper()
	return newEnvWith(t, opts, nil)
}

func newEnvWith(t *testing.T, opts eurodnstest.Options, st store.Store) *env {
	t.Helper()
	return newEnvFull(t, opts, st, nil)
}

// checkProxy fronts the fake and lets a test rewrite check responses (the
// fake does not emit warnings).
func checkProxy(t *testing.T, upstream string, hook func(*eurodns.Zone)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, upstream+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if strings.HasSuffix(r.URL.Path, "/check") && resp.StatusCode == http.StatusOK {
			var z eurodns.Zone
			if json.Unmarshal(body, &z) == nil {
				hook(&z)
				body, _ = json.Marshal(&z)
			}
		}
		for k, v := range resp.Header {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newEnvFull(t *testing.T, opts eurodnstest.Options, st store.Store, checkHook func(*eurodns.Zone)) *env {
	t.Helper()
	opts.AppID, opts.APIKey = "app", "key"
	srv := eurodnstest.NewServer(opts)
	t.Cleanup(srv.Close)
	srv.Seed(baseZone())
	base := srv.URL
	if checkHook != nil {
		base = checkProxy(t, srv.URL, checkHook)
	}
	client, err := eurodns.New(eurodns.WithBaseURL(base), eurodns.WithAuth(eurodns.APIKeyAuth{AppID: "app", APIKey: "key"}),
		eurodns.WithRateLimit(time.Microsecond, 1000))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	if st == nil {
		st = store.NewMemoryWithClock(c.Now)
	}
	e := &env{t: t, srv: srv, st: st, authz: &fakeAuthz{}, audit: &recorder{}, clock: c}
	providers := provider.Single(eurodnsprov.NewWithClient("eurodns", base, client))
	e.eng, err = zonewrite.New(zonewrite.Config{Providers: providers, Store: e.st, Authz: e.authz, Audit: e.audit, Zones: []string{zoneName},
		Holder: "test", LockWait: 2 * time.Second, CheckOnWrite: true, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.api = New(Config{Engine: e.eng, Authz: e.authz, Providers: providers})
	return e
}

func rec(typ, host, rdata string) eurodns.Record {
	return eurodns.Record{Type: typ, Host: host, TTL: 3600, RData: rdata}
}

func reasonOf(err error) zonewrite.Reason {
	if ze, ok := zonewrite.AsError(err); ok {
		return ze.Reason
	}
	return zonewrite.Reason(fmt.Sprintf("not a zonewrite error: %v", err))
}

func (e *env) wantReason(err error, want zonewrite.Reason) {
	e.t.Helper()
	if got := reasonOf(err); got != want {
		e.t.Fatalf("reason = %s, want %s (err %v)", got, want, err)
	}
}

func (e *env) add(s *identity.Subject, recs ...eurodns.Record) (*eurodns.Zone, error) {
	return e.api.AddRecords(context.Background(), s, zoneName, recs, "")
}

func (e *env) mustAdd(s *identity.Subject, recs ...eurodns.Record) *eurodns.Zone {
	e.t.Helper()
	z, err := e.add(s, recs...)
	if err != nil {
		e.t.Fatalf("add: %v", err)
	}
	return z
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

func (e *env) recordID(host, typ, rdata string) int64 {
	for _, r := range e.srv.Zone(zoneName).Records {
		if rrset.NormalizeHost(r.Host, zoneName) == host && r.Type == typ && r.RData == rdata {
			return *r.ID
		}
	}
	e.t.Fatalf("record %s %s %s not found", host, typ, rdata)
	return 0
}

// foreignJSON serializes everything the gate must never touch here (the SOA
// serial is bumped by EuroDNS on every write, so it is left out).
func (e *env) foreignJSON() string {
	z := e.srv.Zone(zoneName)
	var keep []eurodns.Record
	for _, r := range z.Records {
		if r.Type == "SOA" {
			continue
		}
		if h := rrset.NormalizeHost(r.Host, zoneName); h == "legacy" || h == rrset.Apex {
			keep = append(keep, r)
		}
	}
	b, _ := json.Marshal(struct {
		R []eurodns.Record
		U []json.RawMessage
		M []json.RawMessage
	}{keep, z.URLForwards, z.MailForwards})
	return string(b)
}

func TestCreateUpdateDeleteOwned(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	before := e.foreignJSON()

	z := e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	if z.ETag != `"v1"` {
		t.Fatalf("etag %q", z.ETag)
	}
	o := e.own("www", "A")
	if o == nil || o.State != store.StateActive || o.Owner != "team-a" || o.CreatedByName != "alice@example.com" || o.ExpiresAt != nil {
		t.Fatalf("ownership %+v", o)
	}
	e.mustAdd(alice, rec("A", "www", "192.0.2.2"))
	if got := e.upstream("www", "A"); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("values %v", got)
	}
	id := e.recordID("www", "A", "192.0.2.1")
	if _, err := e.api.DeleteRecord(context.Background(), alice, zoneName, id, ""); err != nil {
		t.Fatal(err)
	}
	if got := e.upstream("www", "A"); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Fatalf("after delete %v", got)
	}
	id = e.recordID("www", "A", "192.0.2.2")
	if _, err := e.api.DeleteRecord(context.Background(), alice, zoneName, id, ""); err != nil {
		t.Fatal(err)
	}
	if e.own("www", "A") != nil || len(e.upstream("www", "A")) != 0 {
		t.Fatal("RRset or ownership left after deleting the last value")
	}
	if after := e.foreignJSON(); after != before {
		t.Fatalf("foreign records changed:\n%s\n%s", before, after)
	}
	ev := e.audit.find("addDnsRecords", "allow")
	if len(ev) != 2 || ev[0].SubjectName != "alice@example.com" || ev[0].SubjectCategory != "human" ||
		len(ev[0].Changes) != 1 || ev[0].Changes[0].Op != "create" || ev[1].SnapshotID == "" {
		t.Fatalf("audit %+v", ev)
	}
	if ch := ev[1].Changes[0]; ch.Op != "update" || len(ch.OldValues) != 1 || len(ch.NewValues) != 2 {
		t.Fatalf("update change %+v", ch)
	}
	del := e.audit.find("deleteDnsRecord", "allow")
	if len(del) != 2 || del[1].Changes[0].Op != "delete" || !slices.Equal(del[1].Changes[0].OldValues, []string{"192.0.2.2"}) || del[1].Changes[0].OldTTL != 3600 {
		t.Fatalf("delete must keep old values in the audit: %+v", del)
	}
}

func TestForeignRRsetIsUntouchable(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	before := e.foreignJSON()
	_, err := e.add(alice, rec("CNAME", "legacy", "new.example.net."))
	e.wantReason(err, zonewrite.ReasonForeignRRset)
	_, err = e.api.DeleteRecord(context.Background(), alice, zoneName, e.recordID("legacy", "CNAME", "old.example.net."), "")
	e.wantReason(err, zonewrite.ReasonForeignRRset)
	z := e.srv.Zone(zoneName)
	z.Records = slices.DeleteFunc(z.Records, func(r eurodns.Record) bool { return r.Host == "legacy" })
	e.wantReason(e.api.SaveZone(context.Background(), alice, zoneName, z, ""), zonewrite.ReasonForeignRRset)
	_, err = e.add(alice, rec("NS", "@", "ns2.example.net."))
	e.wantReason(err, zonewrite.ReasonForbidden)
	if after := e.foreignJSON(); after != before {
		t.Fatal("foreign records changed")
	}
	if len(e.audit.find("addDnsRecords", "deny")) != 2 {
		t.Fatal("denials not audited")
	}
}

func TestNotOwner(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	_, err := e.add(bob, rec("A", "www", "192.0.2.9"))
	e.wantReason(err, zonewrite.ReasonNotOwner)
	_, err = e.api.DeleteRecord(context.Background(), bob, zoneName, e.recordID("www", "A", "192.0.2.1"), "")
	e.wantReason(err, zonewrite.ReasonNotOwner)
}

func TestConsoleChangeTaintsThenAdoptRehabilitates(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	z := e.srv.Zone(zoneName)
	for i := range z.Records {
		if z.Records[i].Host == "www" {
			z.Records[i].RData = "198.51.100.7"
		}
	}
	e.srv.Seed(z)

	_, err := e.add(alice, rec("A", "www", "192.0.2.2"))
	e.wantReason(err, zonewrite.ReasonTainted)
	if o := e.own("www", "A"); o.State != store.StateTainted {
		t.Fatalf("state %s", o.State)
	}
	_, err = e.add(alice, rec("A", "www", "192.0.2.2"))
	e.wantReason(err, zonewrite.ReasonTainted)
	if len(e.audit.find("gate.taint", "allow")) != 1 {
		t.Fatal("taint not audited")
	}

	e.wantReason(e.api.Adopt(context.Background(), alice, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "www", Type: "A"}}}), zonewrite.ReasonForbidden)
	if err := e.api.Adopt(context.Background(), admin, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "www", Type: "a"}}}); err != nil {
		t.Fatal(err)
	}
	if o := e.own("www", "A"); o.State != store.StateActive || !o.Adopted || o.UpdatedByName != "root@example.com" {
		t.Fatalf("after adopt %+v", o)
	}
	e.mustAdd(alice, rec("A", "www", "192.0.2.2"))
}

func TestReconcileDetectsDrift(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"), rec("A", "api", "192.0.2.5"))
	z := e.srv.Zone(zoneName)
	z.Records = slices.DeleteFunc(z.Records, func(r eurodns.Record) bool { return r.Host == "api" })
	for i := range z.Records {
		if z.Records[i].Host == "www" {
			z.Records[i].TTL = 600
		}
	}
	e.srv.Seed(z)
	if err := e.eng.Reconcile(context.Background(), zoneName); err != nil {
		t.Fatal(err)
	}
	if e.own("www", "A").State != store.StateTainted || e.own("api", "A").State != store.StateTainted {
		t.Fatal("drift not tainted")
	}
	ev := e.audit.find("gate.taint", "allow")
	if len(ev) != 2 || ev[0].Subject != "gate:reconciler" || ev[0].SubjectCategory != identity.CategorySystem || ev[0].Changes[0].Op != "taint" {
		t.Fatalf("taint events %+v", ev)
	}
	// The owner team may recreate an RRset deleted outside the gate.
	e.mustAdd(alice, rec("A", "api", "192.0.2.6"))
	if o := e.own("api", "A"); o.State != store.StateActive {
		t.Fatalf("recreate %+v", o)
	}
}

func TestIfMatch(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	z, err := e.api.GetZone(ctx, alice, zoneName)
	if err != nil || z.ETag != `"v0"` {
		t.Fatalf("get %v %q", err, z.ETag)
	}
	if _, err := e.api.AddRecords(ctx, alice, zoneName, []eurodns.Record{rec("A", "www", "192.0.2.1")}, `"v0"`); err != nil {
		t.Fatal(err)
	}
	_, err = e.api.AddRecords(ctx, alice, zoneName, []eurodns.Record{rec("A", "api", "192.0.2.1")}, `"v0"`)
	e.wantReason(err, zonewrite.ReasonPrecondition)
	if _, err := e.api.AddRecords(ctx, alice, zoneName, []eurodns.Record{rec("A", "api", "192.0.2.1")}, `W/"v1", "v9"`); err != nil {
		t.Fatal(err)
	}
	stale := z
	stale.Records = append(stale.Records, rec("A", "new", "192.0.2.3"))
	e.wantReason(e.api.SaveZone(ctx, alice, zoneName, stale, `"v0"`), zonewrite.ReasonPrecondition)
}

func TestRebaseForACMEStaleZone(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	stale, err := e.api.GetZone(ctx, acme, zoneName)
	if err != nil {
		t.Fatal(err)
	}
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))

	// lego-style write: stale zone + challenge, no If-Match.
	stale.Records = append(stale.Records, eurodns.Record{Type: "TXT", Host: "_acme-challenge.www", TTL: 600, RData: "token-1"})
	stale.URLForwards = nil
	if err := e.api.SaveZone(ctx, acme, zoneName, stale, ""); err != nil {
		t.Fatal(err)
	}
	if len(e.upstream("www", "A")) != 1 || len(e.upstream("_acme-challenge.www", "TXT")) != 1 {
		t.Fatal("rebase lost a record")
	}
	if len(e.srv.Zone(zoneName).URLForwards) != 1 {
		t.Fatal("rebase changed forwards")
	}
	o := e.own("_acme-challenge.www", "TXT")
	if o == nil || o.Owner != "team-acme" || o.ExpiresAt == nil || !o.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) {
		t.Fatalf("challenge ownership %+v", o)
	}
	ev := e.audit.find("saveDnsZone", "allow")
	if len(ev) != 1 || ev[0].Extra["ignored_out_of_scope"] == nil {
		t.Fatalf("ignored differences not audited: %+v", ev)
	}

	// Without rebase the same stale write is refused.
	stale2, _ := e.api.GetZone(ctx, bob, zoneName)
	e.mustAdd(alice, rec("A", "api", "192.0.2.2"))
	stale2.Records = append(stale2.Records, rec("A", "bob", "192.0.2.3"))
	e.wantReason(e.api.SaveZone(ctx, bob, zoneName, stale2, ""), zonewrite.ReasonNotOwner)
}

func TestMaxChanges(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	e.authz.max = 1
	_, err := e.add(alice, rec("A", "a", "192.0.2.1"), rec("A", "b", "192.0.2.2"))
	e.wantReason(err, zonewrite.ReasonTooMany)
	e.mustAdd(alice, rec("A", "a", "192.0.2.1"))
}

func TestForwardsThroughFullZonePut(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	fa := &identity.Subject{Issuer: "idp", ID: "fa", Name: "fa@example.com", Category: identity.CategoryHuman, Roles: []string{"writer", "forwarder"}, Teams: []string{"team-a"}}
	fb := &identity.Subject{Issuer: "idp", ID: "fb", Name: "fb@example.com", Category: identity.CategoryHuman, Roles: []string{"writer", "forwarder"}, Teams: []string{"team-b"}}
	with := func(raws ...string) *eurodns.Zone {
		z := e.srv.Zone(zoneName)
		z.URLForwards = []json.RawMessage{}
		for _, r := range raws {
			z.URLForwards = append(z.URLForwards, json.RawMessage(r))
		}
		return z
	}
	goRaw := string(e.srv.Zone(zoneName).URLForwards[0])
	www := `{"host":"www","forwardType":"HTTP302","url":"https://example.org/"}`

	e.wantReason(e.api.SaveZone(ctx, alice, zoneName, with(), ""), zonewrite.ReasonForbidden)
	e.wantReason(e.api.SaveZone(ctx, fa, zoneName, with(), ""), zonewrite.ReasonForeignRRset)
	if err := e.api.SaveZone(ctx, fa, zoneName, with(goRaw, www), ""); err != nil {
		t.Fatal(err)
	}
	if o := e.own("www", dns.TypeURLForward); o == nil || o.Owner != "team-a" {
		t.Fatalf("created forward not owned: %+v", o)
	}
	if got := e.srv.Zone(zoneName).URLForwards; len(got) != 2 || string(got[0]) != goRaw {
		t.Fatalf("forwards %s", got)
	}
	e.wantReason(e.api.SaveZone(ctx, fb, zoneName, with(goRaw), ""), zonewrite.ReasonNotOwner)
	e.wantReason(e.api.SaveZone(ctx, fa, zoneName, with(goRaw, www, www), ""), zonewrite.ReasonInvalid)

	if err := e.api.SaveZone(ctx, admin, zoneName, with(string(e.srv.Zone(zoneName).URLForwards[1])), ""); err != nil {
		t.Fatal(err)
	}
	if got := e.srv.Zone(zoneName).URLForwards; len(got) != 1 || e.own("go", dns.TypeURLForward) != nil {
		t.Fatalf("admin delete of a foreign forward: %s", got)
	}

	z := e.srv.Zone(zoneName)
	z.MailForwards = []json.RawMessage{json.RawMessage(`{"source":"info","destination":"x@example.net"}`)}
	e.wantReason(e.api.SaveZone(ctx, fa, zoneName, z, ""), zonewrite.ReasonForbidden)
	if err := e.api.SaveZone(ctx, admin, zoneName, z, ""); err != nil {
		t.Fatal(err)
	}
	if len(e.srv.Zone(zoneName).MailForwards) != 1 {
		t.Fatal("admin mail forwards change not applied")
	}
}

func TestAdopt(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	req := eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "legacy.example.com.", Type: "CNAME"}}}
	e.wantReason(e.api.Adopt(ctx, bob, zoneName, req), zonewrite.ReasonForbidden)
	if err := e.api.Adopt(ctx, admin, zoneName, req); err != nil {
		t.Fatal(err)
	}
	o := e.own("legacy", "CNAME")
	if o == nil || !o.Adopted || o.Owner != "team-a" || o.CreatedByName != "root@example.com" {
		t.Fatalf("adopted %+v", o)
	}
	if err := e.api.Adopt(ctx, admin, zoneName, req); err != nil {
		t.Fatalf("second adopt must be a no-op: %v", err)
	}
	if len(e.audit.find("gate.adopt", "allow")) != 1 {
		t.Fatal("adopt audit")
	}
	e.wantReason(e.api.Adopt(ctx, admin, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "nope", Type: "A"}}}), zonewrite.ReasonNotFound)
	e.wantReason(e.api.Adopt(ctx, admin, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "@", Type: "MX"}}}), zonewrite.ReasonForbidden)

	_, err := e.add(alice, rec("CNAME", "legacy", "new.example.net."))
	if err == nil {
		t.Fatal("a CNAME RRset cannot hold two values; fake should reject")
	}
	z := e.srv.Zone(zoneName)
	for i := range z.Records {
		if z.Records[i].Host == "legacy" {
			z.Records[i].RData = "new.example.net."
		}
	}
	if err := e.api.SaveZone(ctx, alice, zoneName, z, ""); err != nil {
		t.Fatalf("owner team update of adopted RRset: %v", err)
	}
	other := &identity.Subject{Issuer: "idp", ID: "carol", Roles: []string{"writer", "admin"}, Teams: []string{"team-c"}}
	e.wantReason(e.api.Adopt(ctx, other, zoneName, req), zonewrite.ReasonNotOwner)
}

func TestEphemeralGC(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	if _, err := e.add(acme, eurodns.Record{Type: "TXT", Host: "_acme-challenge", TTL: 600, RData: "tok"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.add(acme, eurodns.Record{Type: "TXT", Host: "_acme-challenge.api", TTL: 600, RData: "tok2"}); err != nil {
		t.Fatal(err)
	}
	// One challenge is cleaned up by its client, the other is forgotten.
	if _, err := e.api.DeleteRecord(ctx, acme, zoneName, e.recordID("_acme-challenge.api", "TXT", "tok2"), ""); err != nil {
		t.Fatal(err)
	}
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	if len(e.upstream("_acme-challenge", "TXT")) != 1 {
		t.Fatal("challenge removed before expiry")
	}
	e.clock.Add(2 * time.Hour)
	before := e.foreignJSON()
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	if len(e.upstream("_acme-challenge", "TXT")) != 0 || e.own("_acme-challenge", "TXT") != nil {
		t.Fatal("expired challenge not collected")
	}
	if e.foreignJSON() != before {
		t.Fatal("GC touched foreign records")
	}
	ev := e.audit.find("gate.expire", "allow")
	if len(ev) != 1 || ev[0].Subject != "gate:reconciler" || ev[0].SubjectCategory != identity.CategorySystem || ev[0].Changes[0].Op != "expire" {
		t.Fatalf("expire audit %+v", ev)
	}
}

func TestPendingRecovery(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	www := e.own("www", "A")

	// Interrupted update that did reach EuroDNS.
	z := e.srv.Zone(zoneName)
	for i := range z.Records {
		if z.Records[i].Host == "www" {
			z.Records[i].RData = "192.0.2.50"
		}
	}
	e.srv.Seed(z)
	newHash := rrset.ContentHash(rrset.Group(zoneName, z.Records)[rrset.Key{Host: "www", Type: "A"}])
	p := *www
	p.State, p.PendingHash = store.StatePending, newHash
	if err := e.st.Put(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Interrupted creation that did not reach EuroDNS.
	if err := e.st.Put(ctx, store.Ownership{Zone: zoneName, Host: "ghost", Type: "A", Owner: "team-a", State: store.StatePending, PendingHash: "x"}); err != nil {
		t.Fatal(err)
	}
	// Interrupted creation that did reach EuroDNS (server normalized the value).
	z.Records = append(z.Records, rec("A", "late", "192.0.2.77"))
	e.srv.Seed(z)
	if err := e.st.Put(ctx, store.Ownership{Zone: zoneName, Host: "late", Type: "A", Owner: "team-a", State: store.StatePending, PendingHash: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	if o := e.own("www", "A"); o.State != store.StateActive || o.ContentHash != newHash {
		t.Fatalf("www %+v", o)
	}
	if e.own("ghost", "A") != nil {
		t.Fatal("failed creation claim kept")
	}
	if o := e.own("late", "A"); o == nil || o.State != store.StateActive {
		t.Fatalf("late %+v", o)
	}
	// Interrupted update that never reached EuroDNS reverts to active.
	o := e.own("www", "A")
	o.State, o.PendingHash = store.StatePending, "never-written"
	if err := e.st.Put(ctx, *o); err != nil {
		t.Fatal(err)
	}
	e.mustAdd(alice, rec("A", "www", "192.0.2.51"))
	if got := e.upstream("www", "A"); len(got) != 2 {
		t.Fatalf("write after revert %v", got)
	}
}

func TestReassignedIDs(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{ReassignIDsOnSave: true})
	ctx := context.Background()
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"), rec("A", "api", "192.0.2.2"))
	e.mustAdd(alice, rec("A", "www", "192.0.2.3"))
	id := e.recordID("api", "A", "192.0.2.2")
	if _, err := e.api.DeleteRecord(ctx, alice, zoneName, id, ""); err != nil {
		t.Fatal(err)
	}
	if e.own("api", "A") != nil || e.own("www", "A").State != store.StateActive {
		t.Fatal("ownership lost track after id renumbering")
	}
	_, err := e.api.DeleteRecord(ctx, alice, zoneName, id, "")
	e.wantReason(err, zonewrite.ReasonNotFound)
}

func TestUnmanagedZone(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	_, err := e.api.AddRecords(context.Background(), alice, "other.org", []eurodns.Record{rec("A", "www", "192.0.2.1")}, "")
	e.wantReason(err, zonewrite.ReasonNotFound)
}

func TestConcurrentWritersNoLostUpdate(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := e.add(alice, rec("A", fmt.Sprintf("h%d", i), "192.0.2.1"))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		if len(e.upstream(fmt.Sprintf("h%d", i), "A")) != 1 {
			t.Fatalf("h%d lost", i)
		}
	}
	if v, _ := e.st.ZoneVersion(context.Background(), zoneName); v != 8 {
		t.Fatalf("zone version %d", v)
	}
}

func TestInventoryAndZones(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"), rec("A", "api", "192.0.2.2"))
	z := e.srv.Zone(zoneName)
	z.Records = slices.DeleteFunc(z.Records, func(r eurodns.Record) bool { return r.Host == "api" })
	e.srv.Seed(z)
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	reqs := e.srv.Requests()
	inv, err := e.eng.Inventory(ctx, alice, zoneName)
	if err != nil {
		t.Fatal(err)
	}
	sums, err := e.eng.Zones(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if e.srv.Requests() != reqs {
		t.Fatal("UI reads called EuroDNS with a warm cache")
	}
	status := map[string]uiapi.RRset{}
	for _, r := range inv.RRsets {
		status[r.Host+" "+r.Type] = r
	}
	if r := status["www A"]; r.Status != uiapi.StatusManaged || r.Owner != "team-a" || r.CreatedBy == nil || r.CreatedBy.Name != "alice@example.com" {
		t.Fatalf("www %+v", r)
	}
	if status["api A"].Status != uiapi.StatusMissing || status["legacy CNAME"].Status != uiapi.StatusForeign {
		t.Fatalf("statuses %+v", status)
	}
	if !status["@ NS"].Protected || status["legacy CNAME"].Protected {
		t.Fatal("protected flag")
	}
	// Tainted counts the missing RRset "api A".
	if len(sums) != 1 || *sums[0].Managed != 1 || *sums[0].Tainted != 1 || *sums[0].Foreign != 6 || *sums[0].RRsets != 7 || sums[0].LastWriteAt == nil {
		t.Fatalf("summary %+v", sums)
	}

	// Cold cache: one upstream read, then served from cache.
	e2 := newEnv(t, eurodnstest.Options{})
	if _, err := e2.eng.Inventory(ctx, alice, zoneName); err != nil {
		t.Fatal(err)
	}
	n := e2.srv.Requests()
	if _, err := e2.eng.Zones(ctx, alice); err != nil || e2.srv.Requests() != n {
		t.Fatalf("second UI read hit upstream (%v)", err)
	}
}

func TestRunReconcilerStops(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		zonewrite.RunReconciler(ctx, e.eng, func() []string { return []string{zoneName} }, 10*time.Millisecond, nil)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reconciler did not stop")
	}
}

func TestEngineOnSQLite(t *testing.T) {
	st, err := store.NewSQLite(context.Background(), store.SQLiteConfig{Path: t.TempDir() + "/gate.db"})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, eurodnstest.Options{}, st)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := e.add(alice, rec("A", fmt.Sprintf("s%d", i), "192.0.2.1")); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	_, err = e.add(bob, rec("A", "s0", "192.0.2.9"))
	e.wantReason(err, zonewrite.ReasonNotOwner)
	if o := e.own("s3", "A"); o == nil || o.State != store.StateActive {
		t.Fatalf("ownership %+v", o)
	}
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

func bumpSOA(e *env) {
	z := e.srv.Zone(zoneName)
	for i := range z.Records {
		if z.Records[i].Type == "SOA" {
			f := strings.Fields(z.Records[i].RData)
			var n int
			fmt.Sscan(f[2], &n)
			f[2] = fmt.Sprint(n + 1)
			z.Records[i].RData = strings.Join(f, " ")
		}
	}
	e.srv.Seed(z)
}

func TestServerManagedRecordsIgnored(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	e.srv.Seed(withSOA(baseZone(), 2026060101))
	ctx := context.Background()
	stale, err := e.api.GetZone(ctx, alice, zoneName)
	if err != nil {
		t.Fatal(err)
	}
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	bumpSOA(e)
	e.mustAdd(alice, rec("A", "www", "192.0.2.2"))
	bumpSOA(e)
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	if o := e.own("www", "A"); o.State != store.StateActive {
		t.Fatalf("SOA serial change tainted www: %+v", o)
	}
	if len(e.audit.find("gate.taint", "allow")) != 0 {
		t.Fatal("server-managed change audited as drift")
	}
	// Stale SOA (and stale view of www) from a rebase client: not refused for the SOA.
	stale.Records = append(stale.Records, eurodns.Record{Type: "TXT", Host: "_acme-challenge", TTL: 600, RData: "tok"})
	if err := e.api.SaveZone(ctx, acme, zoneName, stale, ""); err != nil {
		t.Fatalf("stale SOA refused: %v", err)
	}
	// Same for a regular owner sending its full zone with an old serial.
	full, _ := e.api.GetZone(ctx, alice, zoneName)
	bumpSOA(e)
	full.Records = append(full.Records, rec("A", "api", "192.0.2.3"))
	if err := e.api.SaveZone(ctx, alice, zoneName, full, ""); err != nil {
		t.Fatalf("owner save with old serial: %v", err)
	}
	soaID := int64(0)
	for _, r := range e.srv.Zone(zoneName).Records {
		if r.Type == "SOA" {
			soaID = *r.ID
		}
	}
	_, err = e.api.DeleteRecord(ctx, admin, zoneName, soaID, "")
	e.wantReason(err, zonewrite.ReasonForbidden)
	_, err = e.add(admin, eurodns.Record{Type: "SOA", Host: "@", TTL: 86400, RData: "x. y. 1 2 3 4 5"})
	e.wantReason(err, zonewrite.ReasonForbidden)
	e.wantReason(e.api.Adopt(ctx, admin, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "@", Type: "SOA"}}}), zonewrite.ReasonForbidden)
}

// Targets are read like Route53 and the dnsgate Terraform provider do: a
// name of several labels is absolute, a single label is refused. An RRset
// stored with a relative target is read-only until fixed at EuroDNS.
func TestRelativeTargets(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	for _, r := range []eurodns.Record{
		rec("CNAME", "app", "target.example.net"),
		rec("MX", "mail", "10 mx.example.net"),
		rec("SRV", "_sip._tcp", "10 5 5060 sip.example.net"),
	} {
		e.mustAdd(alice, r)
		if got := e.upstream(rrset.NormalizeHost(r.Host, zoneName), r.Type); len(got) != 1 || got[0] != r.RData+"." {
			t.Fatalf("%s stored as %v", r.Type, got)
		}
		if o := e.own(r.Host, r.Type); o == nil || o.State != store.StateActive {
			t.Fatalf("%s ownership %+v", r.Type, o)
		}
	}
	_, err := e.add(alice, rec("CNAME", "short", "internal"))
	e.wantReason(err, zonewrite.ReasonInvalid)
	if !strings.Contains(err.Error(), "single label") {
		t.Fatalf("message %q", err)
	}
	e.mustAdd(alice, rec("TXT", "note", "no dot needed"))

	z := e.srv.Zone(zoneName)
	z.Records = append(z.Records, rec("MX", "sub", "10 mail"))
	e.srv.Seed(z)
	e.wantReason(e.api.Adopt(ctx, admin, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "sub", Type: "MX"}}}), zonewrite.ReasonForbidden)
	_, err = e.add(admin, rec("MX", "sub", "20 mx2.example.net."))
	e.wantReason(err, zonewrite.ReasonForbidden)
	if !strings.Contains(err.Error(), "relative_target") {
		t.Fatalf("expected the read-only reason, got %q", err)
	}
	if got := e.upstream("sub", "MX"); len(got) != 1 || got[0] != "10 mail" {
		t.Fatalf("relative value rewritten: %v", got)
	}
}

func warning(host, typ, msg string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"messages":[%q],"record":{"type":%q,"host":%q,"ttl":3600,"rdata":"x"},"severity":"WARNING"}`, msg, typ, host))
}

func TestCheckWarningsOnChangedRRsets(t *testing.T) {
	var mu sync.Mutex
	var inject []json.RawMessage
	e := newEnvFull(t, eurodnstest.Options{}, nil, func(z *eurodns.Zone) {
		mu.Lock()
		defer mu.Unlock()
		if len(inject) > 0 {
			z.Report.RecordErrors = append(z.Report.RecordErrors, inject...)
		}
	})
	set := func(r ...json.RawMessage) { mu.Lock(); inject = r; mu.Unlock() }

	set(warning("www", "A", "record shadows a wildcard"))
	_, err := e.add(alice, rec("A", "www", "192.0.2.1"))
	e.wantReason(err, zonewrite.ReasonInvalid)
	if !strings.Contains(err.Error(), "record shadows a wildcard") {
		t.Fatalf("message %q", err)
	}
	if e.own("www", "A") != nil || len(e.upstream("www", "A")) != 0 {
		t.Fatal("refused write left a claim or a record")
	}

	set(warning("legacy.example.com.", "CNAME", "unrelated warning"))
	e.mustAdd(alice, rec("A", "api", "192.0.2.1"))

	set(json.RawMessage(`{"messages":["zone is broken"],"severity":"ERROR"}`))
	_, err = e.add(alice, rec("A", "web", "192.0.2.1"))
	e.wantReason(err, zonewrite.ReasonInvalid)
}

type otherProvider struct{ provider.Provider }

func (otherProvider) ID() string   { return "route53-x" }
func (otherProvider) Kind() string { return "route53" }

// The EuroDNS API only serves the zones of a EuroDNS provider.
func TestOtherProviderZonesRefused(t *testing.T) {
	f := New(Config{Providers: provider.Single(otherProvider{})})
	if f.Serves(zoneName) {
		t.Fatal("a route53 zone served by the EuroDNS API")
	}
	ctx := context.Background()
	_, err := f.GetZone(ctx, alice, zoneName)
	if ze, ok := zonewrite.AsError(err); !ok || ze.Reason != zonewrite.ReasonNotFound || !strings.Contains(ze.Message, "route53-x") {
		t.Fatalf("get zone: %v", err)
	}
	if err := f.Adopt(ctx, admin, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "www", Type: "A"}}}); err == nil {
		t.Fatal("adopt through the EuroDNS extension on a route53 zone")
	}
	if _, err := f.Do(ctx, alice, Call{Op: "addDnsRecords", Zone: zoneName, Body: json.RawMessage(`[]`)}); err == nil {
		t.Fatal("empty add accepted")
	}
}

func TestFullZonePutWithDuplicateForwards(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	z := baseZone()
	z.URLForwards = append(z.URLForwards,
		json.RawMessage(`{"host":"@","forwardType":"HTTP301","url":"https://a.example.net/"}`),
		json.RawMessage(`{"host":"example.com.","forwardType":"HTTP302","url":"https://b.example.net/"}`),
		json.RawMessage(`{"forwardType":"HTTP302","url":"https://c.example.net/"}`))
	e.srv.Seed(z)
	fa := &identity.Subject{Issuer: "idp", ID: "fa", Name: "fa@example.com", Category: identity.CategoryHuman, Roles: []string{"writer", "forwarder"}, Teams: []string{"team-a"}}

	cur := e.srv.Zone(zoneName)
	cur.Records = append(cur.Records, eurodns.Record{Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"})
	if err := e.api.SaveZone(ctx, alice, zoneName, cur, ""); err != nil {
		t.Fatalf("unchanged duplicate forwards block the save: %v", err)
	}
	stale := e.srv.Zone(zoneName)
	stale.URLForwards = stale.URLForwards[:1]
	stale.Records = append(stale.Records, eurodns.Record{Type: "TXT", Host: "_acme-challenge", TTL: 600, RData: "token"})
	if err := e.api.SaveZone(ctx, acme, zoneName, stale, ""); err != nil {
		t.Fatalf("rebase with stale duplicate forwards: %v", err)
	}
	if len(e.srv.Zone(zoneName).URLForwards) != 4 {
		t.Fatal("rebase changed the duplicate forwards")
	}
	changed := e.srv.Zone(zoneName)
	changed.URLForwards[1] = json.RawMessage(`{"host":"@","forwardType":"HTTP301","url":"https://evil.example.net/"}`)
	e.wantReason(e.api.SaveZone(ctx, fa, zoneName, changed, ""), zonewrite.ReasonInvalid)
}

func TestZoneAdminDoesNotCreateOwnedForwards(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	fa := &identity.Subject{Issuer: "idp", ID: "fa", Name: "fa@example.com", Category: identity.CategoryHuman, Roles: []string{"writer", "forwarder"}, Teams: []string{"team-a"}}
	with := func(raws ...string) *eurodns.Zone {
		z := e.srv.Zone(zoneName)
		z.URLForwards = nil
		for _, r := range raws {
			z.URLForwards = append(z.URLForwards, json.RawMessage(r))
		}
		return z
	}
	goRaw := string(e.srv.Zone(zoneName).URLForwards[0])
	promo := `{"host":"promo","forwardType":"HTTP301","url":"https://example.org/"}`
	e.wantReason(e.api.SaveZone(ctx, admin, zoneName, with(goRaw, promo), ""), zonewrite.ReasonForbidden)
	if e.own("promo", dns.TypeURLForward) != nil || len(e.srv.Zone(zoneName).URLForwards) != 1 {
		t.Fatal("zone admin created a forward")
	}
	if err := e.api.SaveZone(ctx, fa, zoneName, with(goRaw, promo), ""); err != nil {
		t.Fatal(err)
	}
	e.wantReason(e.api.SaveZone(ctx, admin, zoneName, with(goRaw, `{"host":"promo","forwardType":"HTTP302","url":"https://example.org/"}`), ""), zonewrite.ReasonForbidden)
	if err := e.api.SaveZone(ctx, admin, zoneName, with(`{"id":41,"host":"go","forwardType":"HTTP302","url":"https://example.org/"}`, promo), ""); err != nil {
		t.Fatalf("zone admin change of an unowned forward: %v", err)
	}
	ev := e.audit.find("saveDnsZone", "allow")
	last := ev[len(ev)-1]
	if fmt.Sprint(last.Extra["zone_admin_forwards"]) != "[go URLFWD]" || e.own("go", dns.TypeURLForward) != nil {
		t.Fatalf("zone admin change not marked or owned: %+v", last.Extra)
	}
}

func TestUnwrittenForwardFieldsAreAudited(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	before := string(e.srv.Zone(zoneName).URLForwards[0])
	z := e.srv.Zone(zoneName)
	z.URLForwards = []json.RawMessage{json.RawMessage(`{"id":99,"host":"go","forwardType":"HTTP301","url":"https://example.net/","updated":true,"x":1}`)}
	if err := e.api.SaveZone(ctx, alice, zoneName, z, ""); err != nil {
		t.Fatal(err)
	}
	if got := string(e.srv.Zone(zoneName).URLForwards[0]); got != before {
		t.Fatalf("unwritten fields saved: %s", got)
	}
	ev := e.audit.find("saveDnsZone", "allow")
	if len(ev) != 1 || !strings.Contains(fmt.Sprint(ev[0].Extra["ignored_out_of_scope"]), "forward go") {
		t.Fatalf("ignored change not audited: %+v", ev)
	}
}
