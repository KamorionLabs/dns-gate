package zonewrite

import (
	"context"
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
