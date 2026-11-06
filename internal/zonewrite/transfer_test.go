package zonewrite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
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
	outsider := bound(&identity.Subject{Issuer: "idp", ID: "gus", Roles: []string{"writer"}, Teams: []string{"team-c"}})
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

func TestTransferAppliedLaterWhenZoneLocked(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("l1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("l1 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Lock(ctx, zoneName, "another-replica", time.Hour); err != nil {
		t.Fatal(err)
	}
	lockedCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := tr.DecideTransfer(lockedCtx, teamMate, v.ID, true, "")
	e.wantReason(err, ReasonLocked)
	if res == nil || res.Status != uiapi.TransferApplying || res.DecidedBy == nil {
		t.Fatalf("a locked zone must leave the approved transfer applying: %+v", res)
	}
	if err := e.st.Unlock(ctx, zoneName, "another-replica"); err != nil {
		t.Fatal(err)
	}
	if n, err := e.eng.(TransferRetrier).RetryTransfers(ctx); err != nil || n != 1 {
		t.Fatalf("retry: %d %v", n, err)
	}
	if got, _ := tr.GetTransfer(ctx, teamMate, v.ID); got.Status != uiapi.TransferApplied {
		t.Fatalf("after retry: %+v", got)
	}
	if o := e.own("l1", "A"); o.Owner != "team-b" {
		t.Fatalf("owner %+v", o)
	}
}

func TestTransferApprovalNeedsTeamWriteOnEachRRset(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("@", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ApplyRRsets(ctx, bob, zoneName, put("b9", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeTransfer(ctx, bob, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("@ A"), ToTeam: "team-b", Comment: "take the apex"})
	if err != nil {
		t.Fatal(err)
	}
	acmeKey := bound(&identity.Subject{Issuer: "idp", ID: "acme-key", Category: identity.CategoryHuman, Roles: []string{"acme"}, Teams: []string{"team-a"}})
	if got, _ := tr.GetTransfer(ctx, acmeKey, v.ID); got.CanDecide {
		t.Fatal("an identity of the team limited to ACME challenges may decide on the apex")
	}
	_, err = tr.DecideTransfer(ctx, acmeKey, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)

	mixed := &identity.Subject{Issuer: "idp", ID: "mixed", Category: identity.CategoryHuman, Roles: []string{"writer", "reader"},
		Teams: []string{"team-a", "team-b"}, TeamRoles: map[string][]string{"team-a": {"writer"}, "team-b": {"reader"}}}
	w, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("b9 A"), ToTeam: "team-a", Comment: "take b9"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.DecideTransfer(ctx, mixed, w.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	if _, err := tr.ProposeTransfer(ctx, mixed, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("b9 A"), ToTeam: "team-c", Comment: "x"}); reasonOf(err) != ReasonNotOwner {
		t.Fatalf("a member of the owner team without write on the RRset proposes a transfer to a third team: %v", err)
	}
	if done, err := tr.DecideTransfer(ctx, teamMate, v.ID, true, ""); err != nil || done.Status != uiapi.TransferApplied {
		t.Fatalf("a writer of the owner team approves: %+v %v", done, err)
	}
}

func TestRenameApprovalNeedsOwnershipApproveOnEveryRRset(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("@", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeRename(ctx, admin, "team-a", uiapi.TeamRenameRequest{To: "team-b", Comment: "merge"})
	if err != nil {
		t.Fatal(err)
	}
	padmin := bound(&identity.Subject{Issuer: "idp", ID: "pat", Category: identity.CategoryHuman, Roles: []string{"policy-admin"}, Teams: []string{"team-c"}})
	_, err = tr.DecideTransfer(ctx, padmin, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	if o := e.own("@", "A"); o.Owner != "team-a" {
		t.Fatalf("renamed without the right on the RRset: %+v", o)
	}
}

func TestTransferApprovalRequiresAnotherPerson(t *testing.T) {
	e := newTeamsEnv(t)
	ctx := context.Background()
	for _, h := range []string{"p1", "p2"} {
		if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put(h, "192.0.2.1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	tr := e.eng.(Transfers)
	requester := bound(&identity.Subject{Issuer: "idp", ID: "alice", Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-a"},
		Claims: map[string]any{"email": "alice@example.com"}})
	v, err := tr.ProposeTransfer(ctx, requester, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("p1 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	pipeline := bound(&identity.Subject{Issuer: "ci", ID: "deploy", Category: identity.CategoryPipeline, Roles: []string{"writer"}, Teams: []string{"team-a"}})
	_, err = tr.DecideTransfer(ctx, pipeline, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	sameHuman := bound(&identity.Subject{Issuer: "other-idp", ID: "a-1", Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-a"},
		Claims: map[string]any{"preferred_username": "Alice@Example.com"}})
	_, err = tr.DecideTransfer(ctx, sameHuman, v.ID, true, "")
	e.wantReason(err, ReasonForbidden)
	if done, err := tr.DecideTransfer(ctx, teamMate, v.ID, true, ""); err != nil || done.Status != uiapi.TransferApplied {
		t.Fatalf("another person approves: %+v %v", done, err)
	}

	m := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) {
		c.Teams, c.MachineApprovers = teamList{"team-a": true, "team-b": true}, true
	})
	if _, err := m.eng.ApplyRRsets(ctx, alice, zoneName, put("p3", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	w, err := m.eng.(Transfers).ProposeTransfer(ctx, requester, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("p3 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	if done, err := m.eng.(Transfers).DecideTransfer(ctx, pipeline, w.ID, true, ""); err != nil || done.Status != uiapi.TransferApplied {
		t.Fatalf("machine approvers allowed: %+v %v", done, err)
	}
}

type reassignFailStore struct {
	store.Store
	commit, fail bool
}

func (f *reassignFailStore) Reassign(ctx context.Context, from string, owns []store.Ownership, tombs []store.Tombstone) error {
	if !f.fail {
		return f.Store.Reassign(ctx, from, owns, tombs)
	}
	if f.commit {
		if err := f.Store.Reassign(ctx, from, owns, tombs); err != nil {
			return err
		}
	}
	return errors.New("i/o timeout")
}

func newReassignEnv(t *testing.T) (*env, *reassignFailStore) {
	c := &clock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	fs := &reassignFailStore{Store: store.NewMemoryWithClock(c.Now)}
	e := newEnvConfig(t, eurodnstest.Options{}, fs, func(cfg *Config) {
		cfg.TombstoneTTL, cfg.TransferTTL = 7*24*time.Hour, 24*time.Hour
		cfg.Teams = teamList{"team-a": true, "team-b": true, "team-c": true}
		cfg.Now = c.Now
	})
	e.clock = c
	return e, fs
}

func TestTransferCommittedDespiteStoreError(t *testing.T) {
	e, fs := newReassignEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("t1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("t1 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	fs.fail, fs.commit = true, true
	done, err := tr.DecideTransfer(ctx, teamMate, v.ID, true, "")
	if err != nil || done.Status != uiapi.TransferApplied || done.Moved != 1 {
		t.Fatalf("a committed move must be reported applied: %+v %v", done, err)
	}
	if len(e.audit.find("gate.transfer.apply", "allow")) != 1 {
		t.Fatal("committed move not audited")
	}
}

func TestTransferRetriedAfterCrash(t *testing.T) {
	e, fs := newReassignEnv(t)
	ctx := context.Background()
	for _, h := range []string{"c1", "c2"} {
		if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put(h, "192.0.2.1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("c1 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	fs.fail = true
	res, err := tr.DecideTransfer(ctx, teamMate, v.ID, true, "")
	e.wantReason(err, ReasonUpstream)
	if res.Status != uiapi.TransferApplying {
		t.Fatalf("transient failure: %+v", res)
	}
	fs.fail = false
	retry := e.eng.(TransferRetrier)
	if n, err := retry.RetryTransfers(ctx); err != nil || n != 1 {
		t.Fatalf("retry: %d %v", n, err)
	}
	if o := e.own("c1", "A"); o.Owner != "team-b" {
		t.Fatalf("owner %+v", o)
	}

	w, err := tr.ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("c2 A"), ToTeam: "team-b", Comment: "move"})
	if err != nil {
		t.Fatal(err)
	}
	stuck, _ := e.st.GetTransfer(ctx, w.ID)
	at := e.clock.Now()
	stuck.Status, stuck.DecidedBy, stuck.DecidedAt = uiapi.TransferApplying, teamMate.String(), &at
	if err := e.st.UpdateTransfer(ctx, *stuck); err != nil {
		t.Fatal(err)
	}
	fs.fail = true
	e.clock.Add(25 * time.Hour)
	if _, err := retry.RetryTransfers(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.st.GetTransfer(ctx, w.ID); got.Status != uiapi.TransferFailed || got.Error == "" {
		t.Fatalf("an apply that never succeeds fails after its deadline: %+v", got)
	}
}

func TestRenameCoversStoreZonesAndRetries(t *testing.T) {
	e, fs := newReassignEnv(t)
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("m1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	now := e.clock.Now()
	if err := e.st.Put(ctx, store.Ownership{Zone: "released.example.com", Host: "old", Type: "A", Owner: "team-a", State: store.StateActive, ContentHash: "h", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	tr := e.eng.(Transfers)
	v, err := tr.ProposeRename(ctx, admin, "team-a", uiapi.TeamRenameRequest{To: "team-c", Comment: "rename"})
	if err != nil {
		t.Fatal(err)
	}
	fs.fail = true
	res, err := tr.DecideTransfer(ctx, auditor, v.ID, true, "")
	if err == nil || res.Status != uiapi.TransferApplying {
		t.Fatalf("a transient store error keeps the rename retryable: %+v %v", res, err)
	}
	fs.fail = false
	if _, err := e.eng.(TransferRetrier).RetryTransfers(ctx); err != nil {
		t.Fatal(err)
	}
	if o, _ := e.st.Get(ctx, "released.example.com", "old", "A"); o.Owner != "team-c" {
		t.Fatalf("an RRset of a zone no longer managed kept the old team: %+v", o)
	}
	if o := e.own("m1", "A"); o.Owner != "team-c" {
		t.Fatalf("managed zone: %+v", o)
	}
}

func TestTransferPersonRules(t *testing.T) {
	ctx := context.Background()
	person := func(issuer, id string, claims map[string]any) *identity.Subject {
		return bound(&identity.Subject{Issuer: issuer, ID: id, Category: identity.CategoryHuman, Roles: []string{"writer"}, Teams: []string{"team-a"}, Claims: claims})
	}
	run := func(t *testing.T, mut func(*Config), requester, approver *identity.Subject) error {
		t.Helper()
		e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) {
			c.Teams = teamList{"team-a": true, "team-b": true}
			if mut != nil {
				mut(c)
			}
		})
		if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("pk", "192.0.2.1"), 0); err != nil {
			t.Fatal(err)
		}
		tr := e.eng.(Transfers)
		v, err := tr.ProposeTransfer(ctx, requester, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("pk A"), ToTeam: "team-b", Comment: "move"})
		if err != nil {
			return err
		}
		_, err = tr.DecideTransfer(ctx, approver, v.ID, true, "")
		return err
	}
	key := &identity.Subject{Issuer: "virtual-key", ID: "deploy", Category: identity.CategoryKey, Roles: []string{"writer"}, Teams: []string{"team-a"}}
	bound(key)
	other := person("idp", "carol", map[string]any{"email": "carol@example.com"})
	cases := map[string]struct {
		mut                 func(*Config)
		requester, approver *identity.Subject
		allowed             bool
	}{
		"requester without person claims": {nil, key, other, false},
		"approver without person claims":  {nil, person("idp", "alice", map[string]any{"email": "alice@example.com"}), person("idp2", "x", map[string]any{"sub": "x"}), false},
		"same person on another claim": {nil, person("idp", "alice", map[string]any{"preferred_username": "alice@example.com"}),
			person("idp2", "a-2", map[string]any{"upn": "Alice@Example.com"}), false},
		"same immutable id": {nil, person("idp", "alice", map[string]any{"tid": "t1", "oid": "o1", "email": "alice@example.com"}),
			person("idp2", "a-3", map[string]any{"tid": "t1", "oid": "o1", "email": "alias@example.com"}), false},
		"unverified email ignored": {nil, person("idp", "alice", map[string]any{"tid": "t1", "oid": "o1", "email": "carol@example.com", "email_verified": false}),
			other, true},
		"untrusted issuer email ignored": {func(c *Config) { c.UntrustedEmail = map[string]bool{"idp2": true} },
			person("idp", "alice", map[string]any{"tid": "t1", "oid": "o1"}), person("idp2", "c-2", map[string]any{"tid": "t2", "oid": "o2", "email": "x@example.com"}), true},
		"approver outside the person issuers": {func(c *Config) { c.PersonIssuers = []string{"idp"} },
			person("idp", "alice", map[string]any{"email": "alice@example.com"}), person("idp2", "c-2", map[string]any{"email": "carol@example.com"}), false},
		"requester outside the person issuers": {func(c *Config) { c.PersonIssuers = []string{"idp2"} },
			person("idp", "alice", map[string]any{"email": "alice@example.com"}), person("idp2", "c-2", map[string]any{"email": "carol@example.com"}), false},
		"two people of the person issuer": {func(c *Config) { c.PersonIssuers = []string{"idp"} },
			person("idp", "alice", map[string]any{"email": "alice@example.com"}), other, true},
		"machines with machine_approvers": {func(c *Config) { c.MachineApprovers = true }, key, other, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(t, tc.mut, tc.requester, tc.approver)
			if tc.allowed != (err == nil) {
				t.Fatalf("allowed=%v, got %v", tc.allowed, err)
			}
		})
	}
}
