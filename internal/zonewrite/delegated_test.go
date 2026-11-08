package zonewrite

import (
	"context"
	"testing"
	"time"

	"github.com/KamorionLabs/eurodns-go/eurodnstest"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/policy"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/scope"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func delegatedAs(s *identity.Subject, scopes ...string) *identity.Subject {
	c := *s
	c.Client, c.Scopes = &identity.Client{ID: "agent", Surfaces: []string{scope.SurfaceAPI}}, scopes
	return &c
}

type scopedAuthz struct{ policy.Authorizer }

func (a scopedAuthz) Allow(s *identity.Subject, action, zone string) bool {
	return scope.Permits(s, action, zone) && a.Authorizer.Allow(s, action, zone)
}

func (a scopedAuthz) AllowRRset(s *identity.Subject, action, zone string, k dns.Key) bool {
	return scope.Permits(s, action, zone) && a.Authorizer.AllowRRset(s, action, zone, k)
}

func TestTransferByDelegatedClient(t *testing.T) {
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) {
		c.TombstoneTTL = 7 * 24 * time.Hour
		c.TransferTTL = 24 * time.Hour
		c.RequireSecondApprover = true
		c.Teams = teamList{"team-a": true, "team-b": true, "team-c": true}
		c.Authz = scopedAuthz{c.Authz}
	})
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("d1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	req := uiapi.TransferProposal{RRsets: adoptRefs("d1 A"), ToTeam: "team-b", Comment: "move"}
	if _, err := tr.ProposeTransfer(ctx, delegatedAs(bob, scope.DNSRead), zoneName, req); reasonOf(err) != ReasonForbidden {
		t.Fatalf("propose with dns.read: %v", err)
	}
	if _, err := tr.ProposeTransfer(ctx, delegatedAs(bob, scope.DNSWrite), zoneName, req); err != nil {
		t.Fatalf("propose with dns.write: %v", err)
	}
	v, err := tr.ProposeTransfer(ctx, delegatedAs(bob, scope.DNSTransfer, scope.DNSRead), zoneName, uiapi.TransferProposal{RRsets: adoptRefs("d1 A"), ToTeam: "team-b", Comment: "move again"})
	if err != nil {
		t.Fatalf("propose with dns.transfer: %v", err)
	}
	if _, err := tr.DecideTransfer(ctx, delegatedAs(teamMate, scope.DNSRead), v.ID, true, ""); reasonOf(err) != ReasonForbidden {
		t.Fatalf("approve with dns.read: %v", err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, delegatedAs(alice, scope.DNSTransfer), zoneName, put("d1", "192.0.2.9"), 0); err == nil {
		t.Fatal("dns.transfer does not write records")
	}
	if _, err := tr.DecideTransfer(ctx, delegatedAs(teamMate, scope.DNSTransfer, scope.DNSRead), v.ID, true, "ok"); reasonOf(err) != ReasonForbidden {
		t.Fatalf("a delegated client is not the second person: %v", err)
	}
	done, err := tr.DecideTransfer(ctx, teamMate, v.ID, true, "ok")
	if err != nil || done.Status != uiapi.TransferApplied {
		t.Fatalf("approve: %+v %v", done, err)
	}
}

func TestSubjectRecordKeepsClient(t *testing.T) {
	s := delegatedAs(alice, scope.DNSTransfer)
	s.Client.Zones, s.Client.Name = []string{"example.com"}, "Agent"
	r := recordSubject(*subjectRecord(s))
	if r.ClientID() != "agent" || r.ClientName() != "Agent" || len(r.Scopes) != 1 || len(r.Client.Zones) != 1 {
		t.Fatalf("record: %+v", r)
	}
	if recordSubject(*subjectRecord(alice)).Client != nil {
		t.Fatal("direct subject")
	}
}

func TestTransferClientZones(t *testing.T) {
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) {
		c.TombstoneTTL = 7 * 24 * time.Hour
		c.TransferTTL = 24 * time.Hour
		c.Teams = teamList{"team-a": true, "team-b": true, "team-c": true}
		c.Authz = scopedAuthz{c.Authz}
	})
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("z1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("z1 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	other := delegatedAs(alice, scope.DNSRead, scope.DNSTransfer)
	other.Client.Zones = []string{"other.example"}
	if _, err := tr.GetTransfer(ctx, other, v.ID); reasonOf(err) != ReasonNotFound {
		t.Fatalf("get outside the client zones: %v", err)
	}
	if page, err := tr.ListTransfers(ctx, other, store.TransferQuery{}); err != nil || len(page.Transfers) != 0 {
		t.Fatalf("list outside the client zones: %+v %v", page, err)
	}
	if _, err := tr.DecideTransfer(ctx, other, v.ID, false, "no"); reasonOf(err) != ReasonNotFound {
		t.Fatalf("requester rejecting through a client of other zones: %v", err)
	}
	same := delegatedAs(alice, scope.DNSRead, scope.DNSTransfer)
	same.Client.Zones = []string{"*.com"}
	if _, err := tr.GetTransfer(ctx, same, v.ID); err != nil {
		t.Fatalf("get inside the client zones: %v", err)
	}
	rename := store.Transfer{Kind: uiapi.TransferKindRename, Requester: alice.String(), FromTeam: "team-a", ToTeam: "team-c"}
	if clientZoneAllowed(same, rename) {
		t.Fatal("a rename spans every zone: hidden from clients with zones")
	}
	if !clientZoneAllowed(delegatedAs(alice, scope.DNSRead), rename) {
		t.Fatal("a client without zones sees renames as its user")
	}
	got, err := tr.DecideTransfer(ctx, same, v.ID, false, "no")
	if err != nil || got.Status != uiapi.TransferRejected {
		t.Fatalf("requester rejecting through a client of the zone: %+v %v", got, err)
	}
	ev := e.audit.find("gate.transfer.reject", "allow")
	if len(ev) != 1 || ev[0].ClientID != "agent" || ev[0].Actor == nil || ev[0].Actor.ID != "agent" {
		t.Fatalf("engine events carry the client of their subject: %+v", ev)
	}
	if ev := e.audit.find("gate.transfer.propose", "allow"); len(ev) != 1 || ev[0].ClientID != "" {
		t.Fatalf("direct subject: %+v", ev)
	}
}

func TestDelegatedApproverIsNotAPerson(t *testing.T) {
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) {
		c.TransferTTL = 24 * time.Hour
		c.Teams = teamList{"team-a": true, "team-b": true, "team-c": true}
		c.Authz = scopedAuthz{c.Authz}
	})
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("h1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeTransfer(ctx, bob, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("h1 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DecideTransfer(ctx, delegatedAs(teamMate, scope.DNSTransfer, scope.DNSRead), v.ID, true, ""); reasonOf(err) != ReasonForbidden {
		t.Fatalf("delegated approver without machine_approvers: %v", err)
	}
	if !human(teamMate) || human(delegatedAs(teamMate, scope.DNSTransfer)) {
		t.Fatal("human")
	}
}
