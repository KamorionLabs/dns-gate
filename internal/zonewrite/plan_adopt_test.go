package zonewrite

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

func candidate(p *uiapi.AdoptPreview, host, typ string) uiapi.AdoptCandidate {
	for _, c := range p.Candidates {
		if c.Host == host && c.Type == typ {
			return c
		}
	}
	return uiapi.AdoptCandidate{Reason: "absent from preview"}
}

func TestPreviewAndAdoptMany(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	e.srv.Seed(withSOA(baseZone(), 1))
	z := e.srv.Zone(zoneName)
	z.Records = append(z.Records, rec("A", "shop", "192.0.2.20"), rec("A", "blog", "192.0.2.21"), rec("MX", "sub", "10 mail"))
	e.srv.Seed(z)
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	e.mustAdd(bob, rec("A", "api", "192.0.2.2"))

	if _, err := e.eng.PreviewAdopt(ctx, alice, zoneName, uiapi.AdoptSelection{}); reasonOf(err) != ReasonForbidden {
		t.Fatalf("non-admin preview: %v", err)
	}
	reqs := e.srv.Requests()
	p, err := e.eng.PreviewAdopt(ctx, admin, zoneName, uiapi.AdoptSelection{
		RRsets: []uiapi.RRsetRef{{Host: "@", Type: "SOA"}, {Host: "@", Type: "NS"}, {Host: "missing", Type: "A"}},
		Types:  []string{"a", "cname", "mx"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Owner != "team-a" || e.own("shop", "A") != nil {
		t.Fatalf("preview wrote or wrong owner: %+v", p)
	}
	for _, want := range []struct{ host, typ, reason string }{
		{"@", "SOA", adoptServerManaged}, {"@", "NS", adoptServerManaged}, {"missing", "A", adoptNotFound},
		{"www", "A", adoptAlreadyOwned}, {"api", "A", adoptOtherTeam}, {"sub", "MX", ""},
		{"@", "MX", adoptProtected}, {"shop", "A", ""}, {"blog", "A", ""}, {"legacy", "CNAME", ""},
	} {
		c := candidate(p, want.host, want.typ)
		if c.Reason != want.reason || c.Adoptable != (want.reason == "") {
			t.Errorf("%s %s: %+v, want reason %q", want.host, want.typ, c, want.reason)
		}
	}
	if c := candidate(p, "shop", "A"); c.Status != uiapi.StatusForeign || !slices.Equal(c.Values, []string{"192.0.2.20"}) {
		t.Fatalf("shop %+v", c)
	}
	if e.srv.Requests()-reqs != 1 {
		t.Fatalf("preview made %d upstream calls", e.srv.Requests()-reqs)
	}

	refs := []uiapi.RRsetRef{{Host: "shop", Type: "A"}, {Host: "legacy", Type: "CNAME"}}
	_, err = e.eng.AdoptMany(ctx, admin, zoneName, uiapi.AdoptApply{RRsets: refs, PreviewToken: p.PreviewToken})
	e.wantReason(err, ReasonInvalid)
	_, err = e.eng.AdoptMany(ctx, admin, zoneName, uiapi.AdoptApply{RRsets: append(refs, uiapi.RRsetRef{Host: "api", Type: "A"}),
		PreviewToken: p.PreviewToken, Comment: "import"})
	e.wantReason(err, ReasonAdoptConflict)
	if e.own("shop", "A") != nil {
		t.Fatal("partial adoption")
	}
	_, err = e.eng.AdoptMany(ctx, admin, zoneName, uiapi.AdoptApply{RRsets: refs, PreviewToken: p.PreviewToken, Comment: "import", Owner: "team-b"})
	e.wantReason(err, ReasonAdoptConflict)

	// A console change after the preview invalidates it.
	z = e.srv.Zone(zoneName)
	for i := range z.Records {
		if z.Records[i].Host == "blog" {
			z.Records[i].RData = "192.0.2.99"
		}
	}
	e.srv.Seed(z)
	_, err = e.eng.AdoptMany(ctx, admin, zoneName, uiapi.AdoptApply{RRsets: []uiapi.RRsetRef{{Host: "blog", Type: "A"}},
		PreviewToken: p.PreviewToken, Comment: "import"})
	e.wantReason(err, ReasonAdoptConflict)
	if !strings.Contains(err.Error(), "changed since the preview") {
		t.Fatalf("message %q", err)
	}

	// A subset of the preview is accepted.
	res, err := e.eng.AdoptMany(ctx, admin, zoneName, uiapi.AdoptApply{RRsets: refs, PreviewToken: p.PreviewToken, Comment: "import legacy records"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Adopted) != 2 || res.Owner != "team-a" || res.RequestID == "" {
		t.Fatalf("result %+v", res)
	}
	if o := e.own("legacy", "CNAME"); o == nil || !o.Adopted || o.State != store.StateActive || o.Owner != "team-a" || o.UpdatedByName != "root@example.com" {
		t.Fatalf("ownership %+v", o)
	}
	ev := e.audit.find("gate.adopt", "allow")
	if len(ev) != 1 || ev[0].Extra["comment"] != "import legacy records" || len(ev[0].Changes) != 2 || ev[0].Changes[0].Op != "adopt" || len(ev[0].Changes[0].NewValues) != 1 {
		t.Fatalf("audit %+v", ev)
	}
	// Adopted RRsets are now writable by the owner team.
	e.mustAdd(alice, rec("A", "shop", "192.0.2.30"))
}

func TestAdoptCandidateRelativeTarget(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	eng := e.eng.(*engine)
	cur := &eurodns.Zone{Name: zoneName, Records: []eurodns.Record{rec("MX", "sub", "10 mail"), rec("CNAME", "ok", "t.example.net.")}}
	cands := eng.adoptCandidates(admin, zoneName, cur, nil, nil, nil, nil)
	if len(cands) != 2 || cands[0].Host != "ok" || !cands[0].Adoptable || cands[1].Reason != adoptRelative {
		t.Fatalf("%+v", cands)
	}
}

func TestAdoptManyRehabilitatesTainted(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	z := e.srv.Zone(zoneName)
	for i := range z.Records {
		if z.Records[i].Host == "www" {
			z.Records[i].RData = "192.0.2.77"
		}
	}
	e.srv.Seed(z)
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	p, err := e.eng.PreviewAdopt(ctx, admin, zoneName, uiapi.AdoptSelection{Hosts: []string{"w*"}})
	if err != nil {
		t.Fatal(err)
	}
	if c := candidate(p, "www", "A"); !c.Adoptable || c.Status != uiapi.StatusTainted {
		t.Fatalf("tainted candidate %+v", c)
	}
	if _, err := e.eng.AdoptMany(ctx, admin, zoneName, uiapi.AdoptApply{RRsets: []uiapi.RRsetRef{{Host: "www", Type: "A"}},
		PreviewToken: p.PreviewToken, Comment: "accept console change"}); err != nil {
		t.Fatal(err)
	}
	if o := e.own("www", "A"); o.State != store.StateActive || o.CreatedByName != "alice@example.com" {
		t.Fatalf("rehabilitated %+v", o)
	}
}

func TestPlanAndApplyRRsets(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	reqs := e.srv.Requests()

	changes := []uiapi.RRsetChange{
		{Host: "www", Type: "A", Values: []string{"192.0.2.2", "192.0.2.1", "192.0.2.2"}},
		{Host: "new", Type: "cname", Values: []string{"target.example.net."}},
		{Host: "gone", Type: "A", Delete: true},
	}
	p, err := e.eng.PlanRRsets(ctx, alice, zoneName, changes)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed || p.ZoneVersion != 1 || len(p.Changes) != 2 || p.Changes[0].Op != "create" || p.Changes[0].NewTTL != 3600 ||
		p.Changes[1].Op != "update" || !slices.Equal(p.Changes[1].NewValues, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("plan %+v", p)
	}
	if v, _ := e.st.ZoneVersion(ctx, zoneName); v != 1 || e.own("new", "CNAME") != nil {
		t.Fatal("plan wrote something")
	}
	if n := e.srv.Requests() - reqs; n != 2 {
		t.Fatalf("plan made %d upstream calls, want GET + check", n)
	}

	for _, tc := range []struct {
		s      []uiapi.RRsetChange
		reason Reason
	}{
		{[]uiapi.RRsetChange{{Host: "legacy", Type: "CNAME", Values: []string{"x.example.net."}}}, ReasonForeignRRset},
		{[]uiapi.RRsetChange{{Host: "app", Type: "CNAME", Values: []string{"relative"}}}, ReasonInvalid},
		{[]uiapi.RRsetChange{{Host: "app", Type: "A", TTL: 1234, Values: []string{"192.0.2.3"}}}, ReasonInvalid},
		{[]uiapi.RRsetChange{{Host: "@", Type: "NS", Values: []string{"ns9.example.net."}}}, ReasonForbidden},
		{[]uiapi.RRsetChange{{Host: "a", Type: "A", Values: []string{"192.0.2.3"}}, {Host: "a.example.com.", Type: "A", Delete: true}}, ReasonInvalid},
	} {
		p, err := e.eng.PlanRRsets(ctx, alice, zoneName, tc.s)
		if err != nil || p.Allowed || p.Reason != string(tc.reason) || p.Message == "" {
			t.Errorf("%+v: %+v %v, want %s", tc.s, p, err, tc.reason)
		}
	}
	if p, _ := e.eng.PlanRRsets(ctx, bob, zoneName, changes); p.Allowed || p.Reason != string(ReasonNotOwner) {
		t.Fatalf("bob plan %+v", p)
	}
	e.authz.max = 1
	if p, _ := e.eng.PlanRRsets(ctx, alice, zoneName, changes); p.Reason != string(ReasonTooMany) {
		t.Fatalf("max %+v", p)
	}
	e.authz.max = 0

	// Drift is reported by the dry run without tainting.
	z := e.srv.Zone(zoneName)
	for i := range z.Records {
		if z.Records[i].Host == "www" {
			z.Records[i].TTL = 600
		}
	}
	saved := e.srv.Zone(zoneName)
	e.srv.Seed(z)
	if p, _ := e.eng.PlanRRsets(ctx, alice, zoneName, changes); p.Reason != string(ReasonTainted) || e.own("www", "A").State != store.StateActive {
		t.Fatalf("dry-run drift %+v", p)
	}
	e.srv.Seed(saved)

	_, err = e.eng.ApplyRRsets(ctx, alice, zoneName, changes, 0)
	e.wantReason(err, ReasonPrecondition)
	res, err := e.eng.ApplyRRsets(ctx, alice, zoneName, changes, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.ZoneVersion != 2 || len(res.Changes) != 2 || !res.Allowed {
		t.Fatalf("apply %+v", res)
	}
	if got := e.upstream("www", "A"); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) || len(e.upstream("new", "CNAME")) != 1 {
		t.Fatalf("upstream %v", got)
	}
	if o := e.own("new", "CNAME"); o == nil || o.State != store.StateActive {
		t.Fatalf("ownership %+v", o)
	}
	if ev := e.audit.find("applyRRsets", "allow"); len(ev) != 1 || len(ev[0].Changes) != 2 {
		t.Fatalf("audit %+v", ev)
	}
	res, err = e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: "www", Type: "A", Delete: true}, {Host: "new", Type: "CNAME"}}, 2)
	if err != nil || len(res.Changes) != 2 || e.own("www", "A") != nil || e.own("new", "CNAME") != nil {
		t.Fatalf("delete apply %+v %v", res, err)
	}
}

func TestAdoptOwnRRsetNeedsOnlyWrite(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	own := eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "www", Type: "A"}}}
	if err := e.eng.Adopt(ctx, alice, zoneName, own); err != nil {
		t.Fatalf("import of an owned RRset by a writer: %v", err)
	}
	if len(e.audit.find("gate.adopt", "allow")) != 0 {
		t.Fatal("no-op adopt audited as a change")
	}
	// Still refused: someone else's RRset, a foreign one, or no write access.
	e.mustAdd(bob, rec("A", "api", "192.0.2.2"))
	e.wantReason(e.eng.Adopt(ctx, alice, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "api", Type: "A"}}}), ReasonForbidden)
	e.wantReason(e.eng.Adopt(ctx, alice, zoneName, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "legacy", Type: "CNAME"}}}), ReasonForbidden)
	reader := &identity.Subject{Issuer: "idp", ID: "ro", Teams: []string{"team-a"}}
	e.wantReason(e.eng.Adopt(ctx, reader, zoneName, own), ReasonForbidden)
}
