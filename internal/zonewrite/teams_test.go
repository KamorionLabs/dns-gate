package zonewrite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

func withRecords(z *eurodns.Zone, recs ...eurodns.Record) *eurodns.Zone {
	z.Records = append(z.Records, recs...)
	return z
}

var (
	teamMate = bound(&identity.Subject{Issuer: "idp", ID: "carol", Name: "carol@example.com", Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-a"}})
	adopter  = bound(&identity.Subject{Issuer: "idp", ID: "dave", Name: "dave@example.com", Category: identity.CategoryHuman, Roles: []string{"writer", "adopter"}, Teams: []string{"team-a"}})
	auditor  = bound(&identity.Subject{Issuer: "idp", ID: "erin", Name: "erin@example.com", Category: identity.CategoryHuman, Roles: []string{"admin"}, Teams: []string{"team-c"}})
)

type teamList map[string]bool

func (l teamList) KnownTeam(name string) bool { return l[name] }

func newTeamsEnv(t *testing.T) *env {
	t.Helper()
	return newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) {
		c.TombstoneTTL = 7 * 24 * time.Hour
		c.TransferTTL = 24 * time.Hour
		c.RequireSecondApprover = true
		c.Teams = teamList{"team-a": true, "team-b": true, "team-c": true}
	})
}

func put(host string, values ...string) []uiapi.RRsetChange {
	return []uiapi.RRsetChange{{Host: host, Type: "A", TTL: 600, Values: values}}
}

func del(host string) []uiapi.RRsetChange {
	return []uiapi.RRsetChange{{Host: host, Type: "A", Delete: true}}
}

func TestAdoptOwnerRestrictedToCallerTeams(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	e.srv.Seed(withRecords(baseZone(), rec("A", "free", "192.0.2.10"), rec("A", "free2", "192.0.2.11")))
	sel := uiapi.AdoptSelection{RRsets: adoptRefs("free A"), Owner: "team-b"}
	e.wantReason(previewErr(e.eng.PreviewAdopt(ctx, adopter, zoneName, sel)), ReasonForbidden)
	e.wantReason(e.eng.Adopt(ctx, adopter, zoneName, adoptRefs("free A"), "team-b"), ReasonForbidden)
	if _, err := e.eng.PreviewAdopt(ctx, adopter, zoneName, uiapi.AdoptSelection{RRsets: adoptRefs("free A"), Owner: "team-a"}); err != nil {
		t.Fatalf("own team: %v", err)
	}
	e.wantReason(previewErr(e.eng.PreviewAdopt(ctx, admin, zoneName, uiapi.AdoptSelection{RRsets: adoptRefs("free A"), Owner: "ghost"})), ReasonInvalid)
	p, err := e.eng.PreviewAdopt(ctx, admin, zoneName, sel)
	if err != nil {
		t.Fatalf("approver adopts for another team: %v", err)
	}
	if _, err := e.eng.AdoptMany(ctx, admin, zoneName, uiapi.AdoptApply{RRsets: sel.RRsets, Owner: "team-b", Comment: "hand over", PreviewToken: p.PreviewToken}); err != nil {
		t.Fatal(err)
	}
	if o := e.own("free", "A"); o == nil || o.Owner != "team-b" {
		t.Fatalf("owner %+v", o)
	}
	if err := e.eng.Adopt(ctx, adopter, zoneName, adoptRefs("free2 A"), "team-a"); err != nil {
		t.Fatalf("legacy adopt for an own team: %v", err)
	}
}

func previewErr(_ *uiapi.AdoptPreview, err error) error { return err }

func TestTombstoneReservesDeletedRRset(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("api", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, del("api"), 0); err != nil {
		t.Fatal(err)
	}
	tb, err := e.st.GetTombstone(ctx, zoneName, "api", "A")
	if err != nil || tb.Team != "team-a" || tb.DeletedBy != alice.String() || tb.ContentHash == "" || !tb.ExpiresAt.Equal(e.clock.Now().Add(7*24*time.Hour)) {
		t.Fatalf("tombstone %+v %v", tb, err)
	}
	res, err := e.eng.PlanRRsets(ctx, bob, zoneName, put("api", "192.0.2.2"))
	if err != nil || res.Allowed || res.Reason != string(ReasonNotOwner) || !strings.Contains(res.Message, "reserved for it") {
		t.Fatalf("plan by another team: %+v %v", res, err)
	}
	_, err = e.eng.ApplyRRsets(ctx, bob, zoneName, put("api", "192.0.2.2"), 0)
	e.wantReason(err, ReasonNotOwner)

	both := bound(&identity.Subject{Issuer: "idp", ID: "both", Roles: []string{"writer"}, Teams: []string{"team-b", "team-a"}})
	if _, err := e.eng.ApplyRRsets(ctx, both, zoneName, put("api", "192.0.2.3"), 0); err != nil {
		t.Fatalf("member of the previous team: %v", err)
	}
	if o := e.own("api", "A"); o == nil || o.Owner != "team-a" {
		t.Fatalf("re-created for the previous team: %+v", o)
	}
	if _, err := e.st.GetTombstone(ctx, zoneName, "api", "A"); err != store.ErrNotFound {
		t.Fatalf("tombstone kept after re-creation: %v", err)
	}

	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, del("api"), 0); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(7*24*time.Hour + time.Minute)
	if _, err := e.eng.ApplyRRsets(ctx, bob, zoneName, put("api", "192.0.2.4"), 0); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if o := e.own("api", "A"); o.Owner != "team-b" {
		t.Fatalf("owner after expiry %+v", o)
	}
}

func TestEphemeralRRsetsLeaveNoTombstone(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	acme := bound(&identity.Subject{Issuer: "vk", ID: "acme", Roles: []string{"acme"}, Teams: []string{"team-a"}})
	ch := []uiapi.RRsetChange{{Host: "_acme-challenge", Type: "TXT", TTL: 600, Values: []string{`"token"`}}}
	if _, err := e.eng.ApplyRRsets(ctx, acme, zoneName, ch, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, acme, zoneName, []uiapi.RRsetChange{{Host: "_acme-challenge", Type: "TXT", Delete: true}}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.GetTombstone(ctx, zoneName, "_acme-challenge", "TXT"); err != store.ErrNotFound {
		t.Fatalf("ephemeral tombstone: %v", err)
	}
}

func TestTombstoneBlocksAdoptionForAnotherTeam(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("svc", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, del("svc"), 0); err != nil {
		t.Fatal(err)
	}
	e.srv.Seed(withRecords(e.srv.Zone(zoneName), rec("A", "svc", "192.0.2.9")))
	other := bound(&identity.Subject{Issuer: "idp", ID: "frank", Roles: []string{"writer", "adopter"}, Teams: []string{"team-b"}})
	p, err := e.eng.PreviewAdopt(ctx, other, zoneName, uiapi.AdoptSelection{RRsets: adoptRefs("svc A")})
	if err != nil || len(p.Candidates) != 1 || p.Candidates[0].Adoptable || p.Candidates[0].Reason != adoptReserved {
		t.Fatalf("preview %+v %v", p, err)
	}
	e.wantReason(e.eng.Adopt(ctx, other, zoneName, adoptRefs("svc A"), ""), ReasonNotOwner)
	if err := e.eng.Adopt(ctx, adopter, zoneName, adoptRefs("svc A"), ""); err != nil {
		t.Fatalf("previous team adopts: %v", err)
	}
	if _, err := e.st.GetTombstone(ctx, zoneName, "svc", "A"); err != store.ErrNotFound {
		t.Fatalf("tombstone kept after adoption: %v", err)
	}
}

func TestAdoptForAnotherTeamChecksEachRRset(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	e.srv.Seed(withRecords(baseZone(), rec("A", "free", "192.0.2.10"), rec("A", "www", "192.0.2.11")))
	partial := bound(&identity.Subject{Issuer: "idp", ID: "pia", Category: identity.CategoryHuman, Roles: []string{"adopter", "approver-www"}, Teams: []string{"team-a"}})
	p, err := e.eng.PreviewAdopt(ctx, partial, zoneName, uiapi.AdoptSelection{RRsets: adoptRefs("free A", "www A"), Owner: "team-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Candidates) != 2 || p.Candidates[0].Adoptable || p.Candidates[0].Reason != adoptForbidden || !p.Candidates[1].Adoptable {
		t.Fatalf("approval checked per RRset: %+v", p.Candidates)
	}
	e.wantReason(e.eng.Adopt(ctx, partial, zoneName, adoptRefs("free A"), "team-b"), ReasonForbidden)
	if err := e.eng.Adopt(ctx, partial, zoneName, adoptRefs("www A"), "team-b"); err != nil {
		t.Fatalf("approval on the RRset: %v", err)
	}
}

func TestAdoptionNeverLiftsAnotherTeamTombstone(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("kept", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, del("kept"), 0); err != nil {
		t.Fatal(err)
	}
	e.srv.Seed(withRecords(e.srv.Zone(zoneName), rec("A", "kept", "192.0.2.9")))
	p, err := e.eng.PreviewAdopt(ctx, admin, zoneName, uiapi.AdoptSelection{RRsets: adoptRefs("kept A"), Owner: "team-b"})
	if err != nil || p.Candidates[0].Adoptable || p.Candidates[0].Reason != adoptReserved {
		t.Fatalf("an approver lifted the tombstone of team-a: %+v %v", p, err)
	}
	e.wantReason(e.eng.Adopt(ctx, admin, zoneName, adoptRefs("kept A"), "team-b"), ReasonNotOwner)
}

type tombstoneFailStore struct {
	store.Store
	fail bool
}

func (f *tombstoneFailStore) PutTombstone(ctx context.Context, t store.Tombstone) error {
	if f.fail {
		return errors.New("tombstone write failed")
	}
	return f.Store.PutTombstone(ctx, t)
}

func (f *tombstoneFailStore) DeleteWithTombstone(ctx context.Context, zone, host, typ string, version int64, t store.Tombstone) error {
	if f.fail {
		return errors.New("tombstone write failed")
	}
	return f.Store.DeleteWithTombstone(ctx, zone, host, typ, version, t)
}

func TestTombstoneFailureKeepsOwnership(t *testing.T) {
	c := &clock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	fs := &tombstoneFailStore{Store: store.NewMemoryWithClock(c.Now)}
	e := newEnvConfig(t, eurodnstest.Options{}, fs, func(cfg *Config) {
		cfg.TombstoneTTL = 7 * 24 * time.Hour
	})
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("fragile", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	fs.fail = true
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, del("fragile"), 0); err != nil {
		t.Fatal(err)
	}
	if o := e.own("fragile", "A"); o == nil || o.Owner != "team-a" {
		t.Fatalf("ownership dropped without its tombstone: %+v", o)
	}
	_, err := e.eng.ApplyRRsets(ctx, bob, zoneName, put("fragile", "192.0.2.2"), 0)
	e.wantReason(err, ReasonNotOwner)
	fs.fail = false
	if err := e.eng.Reconcile(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
	if o := e.own("fragile", "A"); o != nil {
		t.Fatalf("reconcile kept the deleted RRset: %+v", o)
	}
	if tb, err := fs.GetTombstone(ctx, zoneName, "fragile", "A"); err != nil || tb.Team != "team-a" {
		t.Fatalf("tombstone after retry: %+v %v", tb, err)
	}
}
