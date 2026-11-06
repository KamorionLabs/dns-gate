package zonewrite

import (
	"context"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func TestTransferLifecycle(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	for _, h := range []string{"a1", "a2"} {
		if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put(h, "192.0.2.1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("gone", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, del("gone"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	req := uiapi.TransferProposal{RRsets: adoptRefs("a1 A", "a2 A", "gone A"), ToTeam: "team-b", Comment: "reorganisation"}

	if _, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: req.RRsets, ToTeam: "ghost", Comment: "x"}); reasonOf(err) != ReasonInvalid {
		t.Fatalf("unknown team: %v", err)
	}
	if _, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: req.RRsets, ToTeam: "team-b"}); reasonOf(err) != ReasonInvalid {
		t.Fatalf("comment required: %v", err)
	}
	outsider := &identity.Subject{Issuer: "idp", ID: "gus", Roles: []string{"writer"}, Teams: []string{"team-c"}}
	if _, err := tr.ProposeTransfer(ctx, outsider, zoneName, req); reasonOf(err) != ReasonNotOwner {
		t.Fatalf("outsider: %v", err)
	}
	v, err := tr.ProposeTransfer(ctx, bob, zoneName, req)
	if err != nil {
		t.Fatal(err)
	}
	if v.FromTeam != "team-a" || v.Status != uiapi.TransferProposed || len(v.RRsets) != 3 || !v.RRsets[2].Tombstone || v.CanDecide {
		t.Fatalf("proposal %+v", v)
	}
	if len(e.audit.find("gate.transfer.propose", "allow")) != 1 {
		t.Fatal("propose not audited")
	}
	_, err = tr.DecideTransfer(ctx, bob, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	_, err = tr.DecideTransfer(ctx, outsider, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	got, err := tr.GetTransfer(ctx, teamMate, v.ID)
	if err != nil || !got.CanDecide {
		t.Fatalf("owner team member sees it decidable: %+v %v", got, err)
	}
	done, err := tr.DecideTransfer(ctx, teamMate, v.ID, true, "ok")
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != uiapi.TransferApplied || done.Moved != 3 || done.DecidedBy == nil || done.DecidedBy.Subject != teamMate.String() {
		t.Fatalf("applied %+v", done)
	}
	for _, h := range []string{"a1", "a2"} {
		if o := e.own(h, "A"); o.Owner != "team-b" || o.UpdatedBy != teamMate.String() {
			t.Fatalf("%s: %+v", h, o)
		}
	}
	if tb, _ := e.st.GetTombstone(ctx, zoneName, "gone", "A"); tb.Team != "team-b" {
		t.Fatalf("tombstone %+v", tb)
	}
	ap := e.audit.find("gate.transfer.apply", "allow")
	if len(ap) != 1 || ap[0].Extra["requester"] != bob.String() || ap[0].Subject != teamMate.String() || len(ap[0].Changes) != 3 {
		t.Fatalf("apply audit %+v", ap)
	}
	if _, err := e.eng.ApplyRRsets(ctx, bob, zoneName, put("a1", "192.0.2.7"), 0); err != nil {
		t.Fatalf("new owner writes: %v", err)
	}
	_, err = tr.DecideTransfer(ctx, teamMate, v.ID, true, "")
	e.wantReason(err, ReasonPrecondition)
}

func TestTransferRefusedWhenChanged(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("c1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("c1 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("c1", "192.0.2.2"), 0); err != nil {
		t.Fatal(err)
	}
	res, err := tr.DecideTransfer(ctx, auditor, v.ID, true, "")
	e.wantReason(err, ReasonPrecondition)
	if res == nil || res.Status != uiapi.TransferFailed || res.Error == "" {
		t.Fatalf("failed transfer %+v", res)
	}
	if o := e.own("c1", "A"); o.Owner != "team-a" {
		t.Fatalf("moved despite the change: %+v", o)
	}
	if len(e.audit.find("gate.transfer.apply", "deny")) != 1 {
		t.Fatal("refused apply not audited")
	}
}

func TestTransferRejectAndExpiry(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("r1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	req := uiapi.TransferProposal{RRsets: adoptRefs("r1 A"), ToTeam: "team-b", Comment: "move"}
	v, err := tr.ProposeTransfer(ctx, bob, zoneName, req)
	if err != nil {
		t.Fatal(err)
	}
	rej, err := tr.DecideTransfer(ctx, bob, v.ID, false, "withdrawn")
	if err != nil || rej.Status != uiapi.TransferRejected {
		t.Fatalf("withdraw %+v %v", rej, err)
	}
	v, err = tr.ProposeTransfer(ctx, bob, zoneName, req)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Add(25 * time.Hour)
	page, err := tr.ListTransfers(ctx, teamMate, store.TransferQuery{Status: uiapi.TransferExpired})
	if err != nil || len(page.Transfers) != 1 || page.Transfers[0].ID != v.ID {
		t.Fatalf("expired list %+v %v", page, err)
	}
	_, err = tr.DecideTransfer(ctx, teamMate, v.ID, true, "")
	e.wantReason(err, ReasonExpired)
	if got, _ := e.st.GetTransfer(ctx, v.ID); got.Status != uiapi.TransferExpired {
		t.Fatalf("stored status %s", got.Status)
	}
}

func TestTeamRename(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	for _, h := range []string{"n1", "n2", "n3"} {
		if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put(h, "192.0.2.1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, del("n3"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, bob, zoneName, put("b1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	if _, err := tr.ProposeRename(ctx, alice, "team-a", uiapi.TeamRenameRequest{To: "team-c", Comment: "rename"}); reasonOf(err) != ReasonForbidden {
		t.Fatalf("rename without policy.propose: %v", err)
	}
	v, err := tr.ProposeRename(ctx, admin, "team-a", uiapi.TeamRenameRequest{To: "team-c", Comment: "rename"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.DecideTransfer(ctx, admin, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	_, err = tr.DecideTransfer(ctx, alice, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	done, err := tr.DecideTransfer(ctx, auditor, v.ID, true, "ok")
	if err != nil || done.Status != uiapi.TransferApplied || done.Moved != 3 {
		t.Fatalf("rename %+v %v", done, err)
	}
	for _, k := range []dns.Key{{Host: "n1", Type: "A"}, {Host: "n2", Type: "A"}} {
		if o := e.own(k.Host, k.Type); o.Owner != "team-c" {
			t.Fatalf("%v: %+v", k, o)
		}
	}
	if o := e.own("b1", "A"); o.Owner != "team-b" {
		t.Fatalf("other team renamed: %+v", o)
	}
	if tb, _ := e.st.GetTombstone(ctx, zoneName, "n3", "A"); tb.Team != "team-c" {
		t.Fatalf("tombstone not renamed: %+v", tb)
	}
	if ap := e.audit.find("gate.transfer.apply", "allow"); len(ap) != 1 || ap[0].Zone != zoneName || len(ap[0].Changes) != 3 {
		t.Fatalf("rename audit %+v", ap)
	}
}
