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
	done, err := tr.DecideTransfer(ctx, delegatedAs(teamMate, scope.DNSTransfer, scope.DNSRead), v.ID, true, "ok")
	if err != nil || done.Status != uiapi.TransferApplied {
		t.Fatalf("approve with dns.transfer: %+v %v", done, err)
	}
}

func TestSubjectRecordKeepsClient(t *testing.T) {
	s := delegatedAs(alice, scope.DNSTransfer)
	s.Client.Zones = []string{"example.com"}
	r := recordSubject(*subjectRecord(s))
	if r.ClientID() != "agent" || len(r.Scopes) != 1 || len(r.Client.Zones) != 1 {
		t.Fatalf("record: %+v", r)
	}
	if recordSubject(*subjectRecord(alice)).Client != nil {
		t.Fatal("direct subject")
	}
}
