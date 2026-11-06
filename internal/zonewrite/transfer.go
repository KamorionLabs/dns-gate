package zonewrite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// ReasonExpired is returned when a transfer request expired (410).
const ReasonExpired Reason = "expired"

// Transfers moves RRsets between teams with a second approver. The engine
// returned by New implements it.
type Transfers interface {
	// ProposeTransfer requests the transfer of RRsets of a zone (owned, or
	// reserved by a tombstone, by one team) to req.ToTeam. The caller needs
	// dns.record.write or dns.ownership.approve on the zone and must be a
	// member of either team unless it holds dns.ownership.approve.
	ProposeTransfer(ctx context.Context, s *identity.Subject, zone string, req uiapi.TransferProposal) (*uiapi.Transfer, error)
	// ProposeRename requests moving every RRset and tombstone of team from
	// to req.To, in every managed zone (policy.propose).
	ProposeRename(ctx context.Context, s *identity.Subject, from string, req uiapi.TeamRenameRequest) (*uiapi.Transfer, error)
	// GetTransfer and ListTransfers return the requests the caller may see.
	GetTransfer(ctx context.Context, s *identity.Subject, id string) (*uiapi.Transfer, error)
	ListTransfers(ctx context.Context, s *identity.Subject, q store.TransferQuery) (*uiapi.TransferPage, error)
	// DecideTransfer approves (and applies) or rejects a proposed request.
	// The requester may only reject (withdraw) it.
	DecideTransfer(ctx context.Context, s *identity.Subject, id string, approve bool, comment string) (*uiapi.Transfer, error)
}

var _ Transfers = (*engine)(nil)

const (
	maxTransferRRsets  = store.MaxReassign
	maxTransferComment = 2000
)

// Audit actions of transfers.
const (
	actionTransferPropose = "gate.transfer.propose"
	actionTransferApprove = "gate.transfer.approve"
	actionTransferReject  = "gate.transfer.reject"
	actionTransferApply   = "gate.transfer.apply"
	actionTransferExpire  = "gate.transfer.expire"
)

func newTransferID(e *engine) string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("tr-%013d-%s", e.now().UnixMilli(), hex.EncodeToString(b[:]))
}

func checkComment(c string) error {
	switch {
	case strings.TrimSpace(c) == "":
		return fail(ReasonInvalid, "a comment is required")
	case len(c) > maxTransferComment:
		return fail(ReasonInvalid, "comment too long (%d characters at most)", maxTransferComment)
	}
	return nil
}

func (e *engine) ProposeTransfer(ctx context.Context, s *identity.Subject, zoneIn string, req uiapi.TransferProposal) (*uiapi.Transfer, error) {
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, err
	}
	if !e.cfg.Authz.Allow(s, policy.ActionOwnershipApprove, zone) && !e.cfg.Authz.Allow(s, policy.ActionRecordWrite, zone) {
		return nil, e.deny(ctx, s, actionTransferPropose, zone, fail(ReasonForbidden, "%s or %s is required on %s", policy.ActionRecordWrite, policy.ActionOwnershipApprove, zone))
	}
	if err := checkComment(req.Comment); err != nil {
		return nil, err
	}
	if len(req.RRsets) == 0 || len(req.RRsets) > maxTransferRRsets {
		return nil, fail(ReasonInvalid, "between 1 and %d RRsets are required", maxTransferRRsets)
	}
	if !e.knownTeam(req.ToTeam) {
		return nil, fail(ReasonInvalid, "unknown team %q", req.ToTeam)
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, err
	}
	tombs, err := e.liveTombstones(ctx, zone)
	if err != nil {
		return nil, err
	}
	t := store.Transfer{
		ID: newTransferID(e), Kind: uiapi.TransferKindRRsets, Zone: zone, ToTeam: req.ToTeam, Comment: req.Comment,
		Status: uiapi.TransferProposed, Requester: s.String(), RequesterName: s.Name, RequesterCategory: s.Category,
		CreatedAt: e.now().UTC(), ExpiresAt: e.now().UTC().Add(e.cfg.TransferTTL),
	}
	seen := map[dns.Key]bool{}
	for _, r := range req.RRsets {
		k := refKey(zone, r)
		if k.Type == "" {
			return nil, fail(ReasonInvalid, "type is required for host %q", r.Host)
		}
		if seen[k] {
			return nil, fail(ReasonInvalid, "%s appears twice in the request", keyString(k))
		}
		seen[k] = true
		var team string
		item := store.TransferItem{Host: k.Host, Type: k.Type}
		if o, ok := owns[k]; ok {
			if o.State != store.StateActive {
				return nil, fail(ReasonTainted, "%s is %s: it must be settled (adopted again) before a transfer", keyString(k), o.State)
			}
			team, item.ContentHash = o.Owner, o.ContentHash
		} else if tb, ok := tombs[k]; ok {
			team, item.ContentHash, item.Tombstone = tb.Team, tb.ContentHash, true
		} else {
			return nil, fail(ReasonNotFound, "%s is not owned by a team in %s", keyString(k), zone)
		}
		if t.FromTeam == "" {
			t.FromTeam = team
		} else if team != t.FromTeam {
			return nil, fail(ReasonInvalid, "the RRsets of a transfer must belong to one team (%s and %s)", t.FromTeam, team)
		}
		t.Items = append(t.Items, item)
	}
	if t.FromTeam == t.ToTeam {
		return nil, fail(ReasonInvalid, "the RRsets already belong to team %s", t.ToTeam)
	}
	for _, it := range t.Items {
		k := dns.Key{Host: it.Host, Type: it.Type}
		if !e.approves(s, zone, k) && !e.teamWrites(s, t.FromTeam, zone, k) && !e.teamWrites(s, t.ToTeam, zone, k) {
			return nil, e.deny(ctx, s, actionTransferPropose, zone, fail(ReasonNotOwner,
				"%s: only a member of team %s or %s allowed to write it through that team (or a %s holder on it) may request this transfer",
				keyString(k), t.FromTeam, t.ToTeam, policy.ActionOwnershipApprove))
		}
	}
	if err := e.cfg.Store.CreateTransfer(ctx, t); err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store transfer failed", Err: err}
	}
	e.emit(ctx, s, actionTransferPropose, zone, "allow", "", transferChanges(t), "", transferExtra(t))
	return e.transferView(s, t), nil
}

func (e *engine) ProposeRename(ctx context.Context, s *identity.Subject, from string, req uiapi.TeamRenameRequest) (*uiapi.Transfer, error) {
	ctx = WithRequestID(ctx, requestID(ctx))
	if !e.cfg.Authz.Allow(s, uiapi.ActionPolicyPropose, "") {
		return nil, e.deny(ctx, s, actionTransferPropose, "", fail(ReasonForbidden, "%s is required to rename a team", uiapi.ActionPolicyPropose))
	}
	if err := checkComment(req.Comment); err != nil {
		return nil, err
	}
	if !teamNameRe.MatchString(from) {
		return nil, fail(ReasonInvalid, "invalid team %q", from)
	}
	if req.To == from || !e.knownTeam(req.To) {
		return nil, fail(ReasonInvalid, "unknown or unchanged target team %q", req.To)
	}
	now := e.now().UTC()
	t := store.Transfer{
		ID: newTransferID(e), Kind: uiapi.TransferKindRename, FromTeam: from, ToTeam: req.To, Comment: req.Comment,
		Status: uiapi.TransferProposed, Requester: s.String(), RequesterName: s.Name, RequesterCategory: s.Category,
		CreatedAt: now, ExpiresAt: now.Add(e.cfg.TransferTTL),
	}
	if err := e.cfg.Store.CreateTransfer(ctx, t); err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store transfer failed", Err: err}
	}
	e.emit(ctx, s, actionTransferPropose, "", "allow", "", nil, "", transferExtra(t))
	return e.transferView(s, t), nil
}

func (e *engine) GetTransfer(ctx context.Context, s *identity.Subject, id string) (*uiapi.Transfer, error) {
	t, err := e.cfg.Store.GetTransfer(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail(ReasonNotFound, "unknown transfer %s", id)
	}
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store transfer failed", Err: err}
	}
	if !e.canSeeTransfer(s, *t) {
		return nil, fail(ReasonNotFound, "unknown transfer %s", id)
	}
	return e.transferView(s, *t), nil
}

func (e *engine) ListTransfers(ctx context.Context, s *identity.Subject, q store.TransferQuery) (*uiapi.TransferPage, error) {
	want := q.Status
	if want == uiapi.TransferExpired {
		q.Status = uiapi.TransferProposed
	}
	list, next, err := e.cfg.Store.ListTransfers(ctx, q)
	if err != nil {
		return nil, &Error{Reason: ReasonInvalid, Message: "invalid transfer query", Err: err}
	}
	page := &uiapi.TransferPage{Transfers: []uiapi.Transfer{}, NextCursor: next}
	for _, t := range list {
		if !e.canSeeTransfer(s, t) {
			continue
		}
		v := e.transferView(s, t)
		if want != "" && v.Status != want {
			continue
		}
		page.Transfers = append(page.Transfers, *v)
	}
	return page, nil
}

func (e *engine) DecideTransfer(ctx context.Context, s *identity.Subject, id string, approve bool, comment string) (*uiapi.Transfer, error) {
	ctx = WithRequestID(ctx, requestID(ctx))
	t, err := e.cfg.Store.GetTransfer(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !e.canSeeTransfer(s, *t)) {
		return nil, fail(ReasonNotFound, "unknown transfer %s", id)
	}
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store transfer failed", Err: err}
	}
	action := actionTransferReject
	if approve {
		action = actionTransferApprove
	}
	if len(comment) > maxTransferComment {
		return nil, fail(ReasonInvalid, "comment too long (%d characters at most)", maxTransferComment)
	}
	if t.Status != uiapi.TransferProposed {
		return nil, fail(ReasonPrecondition, "transfer %s is %s", id, t.Status)
	}
	if !e.now().Before(t.ExpiresAt) {
		t.Status = uiapi.TransferExpired
		if err := e.cfg.Store.UpdateTransfer(ctx, *t); err == nil {
			e.emit(ctx, s, actionTransferExpire, t.Zone, "allow", "", nil, "", transferExtra(*t))
		}
		return nil, fail(ReasonExpired, "transfer %s expired at %s", id, t.ExpiresAt.Format(time.RFC3339))
	}
	self := s.String() == t.Requester
	switch {
	case approve && self:
		return nil, e.deny(ctx, s, action, t.Zone, fail(ReasonForbidden, "the requester cannot approve its own transfer: a second person must"))
	case !self && !e.mayDecide(s, *t):
		return nil, e.deny(ctx, s, action, t.Zone, fail(ReasonForbidden, "%s", e.decideRule(*t)))
	}
	if approve && t.Kind == uiapi.TransferKindRename {
		if err := e.renameAllowed(ctx, s, *t); err != nil {
			return nil, e.deny(ctx, s, action, t.Zone, err)
		}
	}
	now := e.now().UTC()
	t.DecidedBy, t.DecidedByName, t.DecidedByCategory, t.DecidedAt, t.DecisionComment = s.String(), s.Name, s.Category, &now, comment
	if !approve {
		t.Status = uiapi.TransferRejected
		if err := e.updateTransfer(ctx, t); err != nil {
			return nil, err
		}
		e.emit(ctx, s, action, t.Zone, "allow", "", transferChanges(*t), "", transferExtra(*t))
		return e.transferView(s, *t), nil
	}
	t.Status = uiapi.TransferApproved
	if err := e.updateTransfer(ctx, t); err != nil {
		return nil, err
	}
	e.emit(ctx, s, action, t.Zone, "allow", "", transferChanges(*t), "", transferExtra(*t))
	var moved int
	var applyErr error
	if t.Kind == uiapi.TransferKindRename {
		moved, applyErr = e.applyRename(ctx, s, *t)
	} else {
		moved, applyErr = e.applyTransfer(ctx, s, *t)
	}
	t.Moved, t.Status = moved, uiapi.TransferApplied
	if applyErr != nil {
		t.Status, t.Error = uiapi.TransferFailed, applyErr.Error()
		if ze, ok := AsError(applyErr); ok {
			t.Error = ze.Message
		}
		if retryable(applyErr) && moved == 0 {
			t.Status, t.Error = uiapi.TransferProposed, ""
			t.DecidedBy, t.DecidedByName, t.DecidedByCategory, t.DecidedAt, t.DecisionComment = "", "", "", nil, ""
		}
	}
	if err := e.updateTransfer(ctx, t); err != nil {
		e.log.Error("transfer status update failed", "transfer", t.ID, "status", t.Status, "error", err)
	}
	if applyErr != nil {
		if t.Kind == uiapi.TransferKindRRsets {
			e.emit(ctx, s, actionTransferApply, t.Zone, "deny", reasonText(applyErr), nil, "", withMessage(transferExtra(*t), applyErr))
		}
		return e.transferView(s, *t), applyErr
	}
	if t.Kind == uiapi.TransferKindRRsets {
		e.emit(ctx, s, actionTransferApply, t.Zone, "allow", "", transferChanges(*t), "", transferExtra(*t))
	}
	return e.transferView(s, *t), nil
}

// retryable tells whether an apply failed before changing anything for a
// transient reason (zone locked, store or provider unavailable): the
// request then stays proposed.
func retryable(err error) bool {
	ze, ok := AsError(err)
	return ok && (ze.Reason == ReasonLocked || ze.Reason == ReasonUpstream)
}

// updateTransfer writes t and bumps its version; a concurrent decision is a
// precondition failure.
func (e *engine) updateTransfer(ctx context.Context, t *store.Transfer) error {
	err := e.cfg.Store.UpdateTransfer(ctx, *t)
	switch {
	case err == nil:
		t.Version++
		return nil
	case errors.Is(err, store.ErrConflict):
		return fail(ReasonPrecondition, "transfer %s was decided concurrently", t.ID)
	}
	return &Error{Reason: ReasonUpstream, Message: "store transfer failed", Err: err}
}

// applyTransfer moves the RRsets of an approved request, under the zone
// lock, if none changed since the request: same owner team, active, same
// content hash in the store and upstream (same team for tombstones).
func (e *engine) applyTransfer(ctx context.Context, s *identity.Subject, t store.Transfer) (int, error) {
	zone, err := e.managed(t.Zone)
	if err != nil {
		return 0, err
	}
	p, err := e.provider(zone)
	if err != nil {
		return 0, err
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return 0, err
	}
	defer unlock()
	cur, err := e.fetch(ctx, p, zone)
	if err != nil {
		return 0, err
	}
	sets := index(cur)
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return 0, err
	}
	e.resolvePending(ctx, zone, sets, owns)
	tombs, err := e.liveTombstones(ctx, zone)
	if err != nil {
		return 0, err
	}
	now, rid := e.now(), RequestID(ctx)
	var moveOwns []store.Ownership
	var moveTombs []store.Tombstone
	for _, it := range t.Items {
		k := dns.Key{Host: it.Host, Type: it.Type}
		if it.Tombstone {
			tb, ok := tombs[k]
			if !ok || tb.Team != t.FromTeam {
				return 0, fail(ReasonPrecondition, "%s is no longer reserved for team %s", keyString(k), t.FromTeam)
			}
			tb.Team = t.ToTeam
			moveTombs = append(moveTombs, tb)
			continue
		}
		o, ok := owns[k]
		set, _, present := findSet(sets, k)
		switch {
		case !ok || o.Owner != t.FromTeam:
			return 0, fail(ReasonPrecondition, "%s is no longer owned by team %s", keyString(k), t.FromTeam)
		case o.State != store.StateActive || o.ContentHash != it.ContentHash:
			return 0, fail(ReasonPrecondition, "%s changed since the request", keyString(k))
		case !present || dns.ContentHash(set) != it.ContentHash:
			return 0, fail(ReasonPrecondition, "%s changed upstream since the request", keyString(k))
		}
		o.Owner = t.ToTeam
		setActor(&o, s, rid, now)
		moveOwns = append(moveOwns, o)
	}
	if err := e.cfg.Store.Reassign(ctx, t.FromTeam, moveOwns, moveTombs); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return 0, fail(ReasonPrecondition, "an RRset of the transfer changed during the apply")
		}
		return 0, &Error{Reason: ReasonUpstream, Message: "store reassign failed", Err: err}
	}
	return len(moveOwns) + len(moveTombs), nil
}

// applyRename moves every RRset and tombstone of a team in every managed
// zone, zone by zone under its lock, in batches of store.MaxReassign. A
// failure stops it: the RRsets already moved stay with the new team and a
// new rename moves the rest.
func (e *engine) applyRename(ctx context.Context, s *identity.Subject, t store.Transfer) (int, error) {
	moved := 0
	now, rid := e.now(), RequestID(ctx)
	for _, zone := range e.zones.ManagedZones() {
		n, changes, err := e.renameZone(ctx, s, t, zone, now, rid)
		moved += n
		if len(changes) > 0 {
			e.emit(ctx, s, actionTransferApply, zone, "allow", "", changes, "", transferExtra(t))
		}
		if err != nil {
			e.emit(ctx, s, actionTransferApply, zone, "error", reasonText(err), nil, "", withMessage(transferExtra(t), err))
			return moved, err
		}
	}
	return moved, nil
}

func (e *engine) renameZone(ctx context.Context, s *identity.Subject, t store.Transfer, zone string, now time.Time, rid string) (int, []uiapi.Change, error) {
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return 0, nil, err
	}
	defer unlock()
	list, err := e.cfg.Store.List(ctx, zone)
	if err != nil {
		return 0, nil, &Error{Reason: ReasonUpstream, Message: "store list failed", Err: err}
	}
	tlist, err := e.cfg.Store.ListTombstones(ctx, zone)
	if err != nil {
		return 0, nil, &Error{Reason: ReasonUpstream, Message: "store tombstones failed", Err: err}
	}
	var owns []store.Ownership
	var tombs []store.Tombstone
	for _, o := range list {
		if o.Owner == t.FromTeam {
			o.Owner = t.ToTeam
			setActor(&o, s, rid, now)
			owns = append(owns, o)
		}
	}
	for _, tb := range tlist {
		if tb.Team == t.FromTeam {
			tb.Team = t.ToTeam
			tombs = append(tombs, tb)
		}
	}
	moved := 0
	var changes []uiapi.Change
	for len(owns)+len(tombs) > 0 {
		no := min(len(owns), store.MaxReassign)
		nt := min(len(tombs), store.MaxReassign-no)
		if err := e.cfg.Store.Reassign(ctx, t.FromTeam, owns[:no], tombs[:nt]); err != nil {
			return moved, changes, &Error{Reason: ReasonPrecondition, Message: fmt.Sprintf("rename stopped in %s after %d RRsets: %v", zone, moved, err), Err: err}
		}
		for _, o := range owns[:no] {
			changes = append(changes, uiapi.Change{Op: "transfer", Host: o.Host, Type: o.Type})
		}
		for _, tb := range tombs[:nt] {
			changes = append(changes, uiapi.Change{Op: "transfer", Host: tb.Host, Type: tb.Type})
		}
		moved += no + nt
		owns, tombs = owns[no:], tombs[nt:]
	}
	return moved, changes, nil
}

// renameZones returns the zones a rename covers.
func (e *engine) renameZones(ctx context.Context) ([]string, error) {
	return e.zones.ManagedZones(), nil
}

// renameAllowed checks that the approver of a rename holds
// dns.ownership.approve on every RRset and tombstone of the team.
func (e *engine) renameAllowed(ctx context.Context, s *identity.Subject, t store.Transfer) error {
	zones, err := e.renameZones(ctx)
	if err != nil {
		return err
	}
	for _, zone := range zones {
		list, err := e.cfg.Store.List(ctx, zone)
		if err != nil {
			return &Error{Reason: ReasonUpstream, Message: "store list failed", Err: err}
		}
		tlist, err := e.cfg.Store.ListTombstones(ctx, zone)
		if err != nil {
			return &Error{Reason: ReasonUpstream, Message: "store tombstones failed", Err: err}
		}
		var keys []dns.Key
		for _, o := range list {
			if o.Owner == t.FromTeam {
				keys = append(keys, dns.Key{Host: o.Host, Type: o.Type})
			}
		}
		for _, tb := range tlist {
			if tb.Team == t.FromTeam {
				keys = append(keys, dns.Key{Host: tb.Host, Type: tb.Type})
			}
		}
		for _, k := range keys {
			if !e.approves(s, zone, k) {
				return fail(ReasonForbidden, "approving this rename requires %s on every RRset of team %s, not on %s in %s", policy.ActionOwnershipApprove, t.FromTeam, keyString(k), zone)
			}
		}
	}
	return nil
}

// canSeeTransfer: the readers of its zone (ui.read or dns.read), the
// members of both teams; for a rename, policy.read holders and the members
// of both teams.
func (e *engine) canSeeTransfer(s *identity.Subject, t store.Transfer) bool {
	if s.String() == t.Requester || slices.Contains(s.Teams, t.FromTeam) || slices.Contains(s.Teams, t.ToTeam) {
		return true
	}
	if t.Kind == uiapi.TransferKindRename {
		return e.cfg.Authz.Allow(s, uiapi.ActionPolicyRead, "")
	}
	return e.cfg.Authz.Allow(s, policy.ActionUIRead, t.Zone) || e.cfg.Authz.Allow(s, policy.ActionDNSRead, t.Zone)
}

// mayDecide tells whether s may approve t (anyone but the requester): for
// every RRset, a member of the owner team allowed to write it through the
// bindings of that team, or a holder of dns.ownership.approve on it;
// another policy.approve holder for a rename.
func (e *engine) mayDecide(s *identity.Subject, t store.Transfer) bool {
	if t.Kind == uiapi.TransferKindRename {
		return e.cfg.Authz.Allow(s, uiapi.ActionPolicyApprove, "")
	}
	for _, it := range t.Items {
		k := dns.Key{Host: it.Host, Type: it.Type}
		if !e.teamWrites(s, t.FromTeam, t.Zone, k) && !e.approves(s, t.Zone, k) {
			return false
		}
	}
	return len(t.Items) > 0
}

// teamWrites reports whether s may write an RRset through the roles of its
// bindings for team (not through the roles it holds for another team).
func (e *engine) teamWrites(s *identity.Subject, team, zone string, k dns.Key) bool {
	roles := s.RolesFor(team)
	if len(roles) == 0 {
		return false
	}
	c := *s
	c.Roles = roles
	return e.cfg.Authz.AllowRRset(&c, policy.ActionRecordWrite, zone, k)
}

// approves reports whether s holds dns.ownership.approve on an RRset.
func (e *engine) approves(s *identity.Subject, zone string, k dns.Key) bool {
	return e.cfg.Authz.AllowRRset(s, policy.ActionOwnershipApprove, zone, k)
}

func (e *engine) decideRule(t store.Transfer) string {
	if t.Kind == uiapi.TransferKindRename {
		return "a team rename is approved by another " + uiapi.ActionPolicyApprove + " holder"
	}
	return fmt.Sprintf("for every RRset, a member of team %s allowed to write it through that team, or a %s holder on it, must approve this transfer", t.FromTeam, policy.ActionOwnershipApprove)
}

func (e *engine) transferView(s *identity.Subject, t store.Transfer) *uiapi.Transfer {
	v := &uiapi.Transfer{
		ID: t.ID, Kind: t.Kind, Zone: t.Zone, FromTeam: t.FromTeam, ToTeam: t.ToTeam, RRsets: []uiapi.TransferRRset{},
		Status: t.Status, Comment: t.Comment, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		Requester: uiapi.Actor{Subject: t.Requester, Name: t.RequesterName, Category: t.RequesterCategory},
		DecidedAt: t.DecidedAt, DecisionComment: t.DecisionComment, Moved: t.Moved, Error: t.Error,
	}
	for _, it := range t.Items {
		v.RRsets = append(v.RRsets, uiapi.TransferRRset{Host: it.Host, Type: it.Type, Hash: it.ContentHash, Tombstone: it.Tombstone})
	}
	if t.DecidedBy != "" {
		v.DecidedBy = &uiapi.Actor{Subject: t.DecidedBy, Name: t.DecidedByName, Category: t.DecidedByCategory}
	}
	if t.Status == uiapi.TransferProposed && !e.now().Before(t.ExpiresAt) {
		v.Status = uiapi.TransferExpired
	}
	v.CanDecide = v.Status == uiapi.TransferProposed && s.String() != t.Requester && e.mayDecide(s, t)
	return v
}

func transferChanges(t store.Transfer) []uiapi.Change {
	out := make([]uiapi.Change, 0, len(t.Items))
	for _, it := range t.Items {
		out = append(out, uiapi.Change{Op: "transfer", Host: it.Host, Type: it.Type})
	}
	return out
}

func transferExtra(t store.Transfer) map[string]any {
	x := map[string]any{
		"transfer_id": t.ID, "kind": t.Kind, "from_team": t.FromTeam, "to_team": t.ToTeam,
		"requester": t.Requester, "requester_name": t.RequesterName,
	}
	if t.DecidedBy != "" {
		x["decided_by"], x["decided_by_name"] = t.DecidedBy, t.DecidedByName
	}
	if t.Comment != "" {
		x["comment"] = t.Comment
	}
	if t.Moved > 0 {
		x["moved"] = t.Moved
	}
	return x
}

func withMessage(x map[string]any, err error) map[string]any {
	x["message"] = err.Error()
	return x
}

func reasonText(err error) string {
	if ze, ok := AsError(err); ok {
		return string(ze.Reason)
	}
	return "error"
}
