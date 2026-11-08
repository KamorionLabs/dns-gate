package zonewrite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
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
	// DecideTransfer approves (and applies, in the background for a
	// rename) or rejects a proposed request. The requester may withdraw it,
	// and approve it only when no second approver is required.
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
	if err := e.checkRequester(s); err != nil {
		return nil, e.deny(ctx, s, actionTransferPropose, zone, err)
	}
	if req.Apply && e.cfg.RequireSecondApprover {
		return nil, fail(ReasonInvalid, "apply: a second approver is required (ownership.require_second_approver)")
	}
	if !e.cfg.Authz.Allow(s, policy.ActionOwnershipApprove, zone) && !e.writesIn(s.WithIntent(identity.IntentTransfer), zone) {
		return nil, e.deny(ctx, s, actionTransferPropose, zone, fail(ReasonForbidden, "%s, %s or %s is required on %s", policy.ActionRecordWrite, policy.ActionForwardWrite, policy.ActionOwnershipApprove, zone))
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
		Status: uiapi.TransferProposed, Requester: s.String(), RequesterName: s.Name, RequesterCategory: s.Category, RequesterPersons: e.personKeys(s),
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
	var g grants
	for _, it := range t.Items {
		k := dns.Key{Host: it.Host, Type: it.Type}
		if !e.approves(&g, s, zone, k) && !e.teamWrites(&g, s, t.FromTeam, zone, k) && !e.teamWrites(&g, s, t.ToTeam, zone, k) {
			return nil, e.deny(ctx, s, actionTransferPropose, zone, fail(ReasonNotOwner,
				"%s: only a member of team %s or %s allowed to write it through that team (or a %s holder on it) may request this transfer",
				keyString(k), t.FromTeam, t.ToTeam, policy.ActionOwnershipApprove))
		}
	}
	if req.Apply {
		if err := e.selfDecision(s, t); err != nil {
			return nil, e.deny(ctx, s, actionTransferApprove, zone, err)
		}
	}
	if err := e.cfg.Store.CreateTransfer(ctx, t); err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store transfer failed", Err: err}
	}
	e.emit(ctx, s, actionTransferPropose, zone, "allow", "", transferChanges(t), "", g.extra(transferExtra(t)))
	if req.Apply {
		return e.DecideTransfer(ctx, s, t.ID, true, req.Comment)
	}
	return e.transferView(s, t), nil
}

func (e *engine) ProposeRename(ctx context.Context, s *identity.Subject, from string, req uiapi.TeamRenameRequest) (*uiapi.Transfer, error) {
	ctx = WithRequestID(ctx, requestID(ctx))
	if !e.cfg.Authz.Allow(s, uiapi.ActionPolicyPropose, "") {
		return nil, e.deny(ctx, s, actionTransferPropose, "", fail(ReasonForbidden, "%s is required to rename a team", uiapi.ActionPolicyPropose))
	}
	if err := e.checkRequester(s); err != nil {
		return nil, e.deny(ctx, s, actionTransferPropose, "", err)
	}
	if req.Apply && e.cfg.RequireSecondApprover {
		return nil, fail(ReasonInvalid, "apply: a second approver is required (ownership.require_second_approver)")
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
		RequesterPersons: e.personKeys(s), CreatedAt: now, ExpiresAt: now.Add(e.cfg.TransferTTL),
	}
	if req.Apply {
		if err := e.selfDecision(s, t); err != nil {
			return nil, e.deny(ctx, s, actionTransferApprove, "", err)
		}
	}
	if err := e.cfg.Store.CreateTransfer(ctx, t); err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store transfer failed", Err: err}
	}
	e.emit(ctx, s, actionTransferPropose, "", "allow", "", nil, "", transferExtra(t))
	if req.Apply {
		return e.DecideTransfer(ctx, s, t.ID, true, req.Comment)
	}
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
	if approve {
		if err := e.checkApprover(s, *t); err != nil {
			return nil, e.deny(ctx, s, action, t.Zone, err)
		}
	}
	var g grants
	if (approve || !self) && !e.mayDecide(&g, s, *t) {
		return nil, e.deny(ctx, s, action, t.Zone, fail(ReasonForbidden, "%s", e.decideRule(*t)))
	}
	if approve && t.Kind == uiapi.TransferKindRename && !e.cfg.Authz.Allow(s, uiapi.ActionPolicyApprove, "") {
		return nil, e.deny(ctx, s, action, t.Zone, fail(ReasonForbidden, "%s", e.decideRule(*t)))
	}
	now := e.now().UTC()
	t.DecidedBy, t.DecidedByName, t.DecidedByCategory, t.DecidedAt, t.DecisionComment = s.String(), s.Name, s.Category, &now, comment
	if !approve {
		t.Status = uiapi.TransferRejected
		if err := e.updateTransfer(ctx, t); err != nil {
			return nil, err
		}
		e.emit(ctx, s, action, t.Zone, "allow", "", transferChanges(*t), "", g.extra(transferExtra(*t)))
		return e.transferView(s, *t), nil
	}
	t.Status, t.Approver = uiapi.TransferApplying, subjectRecord(s)
	if t.Kind == uiapi.TransferKindRRsets {
		until := now.Add(transferLease)
		t.LeaseHolder, t.LeaseUntil = e.cfg.Holder, &until
	}
	if err := e.updateTransfer(ctx, t); err != nil {
		return nil, err
	}
	e.emit(ctx, s, action, t.Zone, "allow", "", transferChanges(*t), "", g.extra(transferExtra(*t)))
	if t.Kind == uiapi.TransferKindRename {
		return e.transferView(s, *t), nil
	}
	err = e.runApply(ctx, s, t)
	return e.transferView(s, *t), err
}

// selfDecision checks, before a request proposed with apply is stored, that
// its requester may approve it, so that a refusal leaves nothing behind.
func (e *engine) selfDecision(s *identity.Subject, t store.Transfer) error {
	if err := e.checkApprover(s, t); err != nil {
		return err
	}
	if !e.mayDecide(nil, s, t) {
		return fail(ReasonForbidden, "%s", e.decideRule(t))
	}
	return nil
}

// TransferRetrier applies the approved transfers in the background: team
// renames, and transfers whose apply did not run to its end (the engine
// returned by New implements it).
type TransferRetrier interface {
	// RetryTransfers applies the transfers left applying, and fails those
	// approved more than transferApplyDeadline ago or whose approver lost
	// its rights. It returns how many were applied.
	RetryTransfers(ctx context.Context) (int, error)
}

var _ TransferRetrier = (*engine)(nil)

const (
	// transferApplyDeadline is how long an approved transfer is retried.
	transferApplyDeadline = 24 * time.Hour
	// transferRetryDelay leaves a transfer just approved to the replica
	// applying it.
	transferRetryDelay = 2 * time.Minute
	// transferLease is how long a replica keeps a transfer it applies.
	transferLease = 5 * time.Minute
)

func (e *engine) RetryTransfers(ctx context.Context) (int, error) {
	list, _, err := e.cfg.Store.ListTransfers(ctx, store.TransferQuery{Status: uiapi.TransferApplying, Limit: 500})
	if err != nil {
		return 0, err
	}
	applied := 0
	for i := range list {
		t := &list[i]
		if ctx.Err() != nil {
			return applied, ctx.Err()
		}
		ctx := WithRequestID(ctx, newID())
		now := e.now()
		if t.DecidedAt != nil && now.Sub(*t.DecidedAt) < transferRetryDelay {
			continue
		}
		if t.LeaseHolder != "" && t.LeaseHolder != e.cfg.Holder && t.LeaseUntil != nil && now.Before(*t.LeaseUntil) {
			continue
		}
		if t.DecidedAt != nil && now.Sub(*t.DecidedAt) > transferApplyDeadline {
			msg := "not applied within " + transferApplyDeadline.String() + " of the approval"
			if t.Error != "" {
				msg += ": " + t.Error
			}
			e.failTransfer(ctx, t, fail(ReasonExpired, "%s", msg))
			continue
		}
		until := now.Add(transferLease)
		t.LeaseHolder, t.LeaseUntil = e.cfg.Holder, &until
		if err := e.updateTransfer(ctx, t); err != nil {
			continue
		}
		approver, err := e.approverNow(*t)
		if err != nil {
			e.failTransfer(ctx, t, err)
			continue
		}
		if err := e.runApply(ctx, approver, t); err == nil {
			applied++
		}
	}
	return applied, nil
}

// approverNow binds the approver of t again and checks that it may still
// approve the transfer.
func (e *engine) approverNow(t store.Transfer) (*identity.Subject, error) {
	if t.Approver == nil {
		return nil, fail(ReasonForbidden, "the approver of transfer %s is unknown", t.ID)
	}
	s := recordSubject(*t.Approver)
	if e.cfg.Rebinder != nil {
		b, err := e.cfg.Rebinder.Rebind(s)
		if err != nil {
			return nil, fail(ReasonForbidden, "the approver %s is no longer bound: %v", s.String(), err)
		}
		s = b
	}
	if !e.mayDecide(nil, s, t) {
		return nil, fail(ReasonForbidden, "the approver %s lost the right to approve this transfer: %s", s.String(), e.decideRule(t))
	}
	if err := e.checkApprover(s, t); err != nil {
		return nil, err
	}
	return s, nil
}

// failTransfer records a transfer the gate gave up applying.
func (e *engine) failTransfer(ctx context.Context, t *store.Transfer, cause error) {
	t.Status, t.Error, t.LeaseHolder, t.LeaseUntil = uiapi.TransferFailed, errorText(cause), "", nil
	if err := e.updateTransfer(ctx, t); err == nil {
		e.emit(ctx, reconcilerSubject, actionTransferApply, t.Zone, "deny", reasonText(cause), nil, "", withMessage(transferExtra(*t), cause))
	}
}

// runApply applies an approved transfer and records the outcome: applied,
// failed when its RRsets changed, still applying after a transient error
// (retried by RetryTransfers). The move is audited when it commits,
// whatever happens to the status update.
func (e *engine) runApply(ctx context.Context, actor *identity.Subject, t *store.Transfer) error {
	var moved int
	var applyErr error
	if t.Kind == uiapi.TransferKindRename {
		moved, applyErr = e.applyRename(ctx, actor, *t)
		t.Moved += moved
	} else {
		moved, applyErr = e.applyTransfer(ctx, actor, *t)
		t.Moved = moved
	}
	t.Error, t.LeaseHolder, t.LeaseUntil = "", "", nil
	switch {
	case applyErr == nil:
		t.Status = uiapi.TransferApplied
	case retryable(applyErr):
		t.Error = errorText(applyErr)
	default:
		t.Status, t.Error = uiapi.TransferFailed, errorText(applyErr)
	}
	if applyErr != nil && t.Kind == uiapi.TransferKindRRsets {
		decision := "deny"
		if retryable(applyErr) {
			decision = "error"
		}
		e.emit(ctx, actor, actionTransferApply, t.Zone, decision, reasonText(applyErr), nil, "", withMessage(transferExtra(*t), applyErr))
	}
	if err := e.updateTransfer(ctx, t); err != nil {
		if applyErr == nil && e.finishApplied(ctx, t) {
			return nil
		}
		e.log.Warn("transfer status update failed", "transfer", t.ID, "status", t.Status, "error", err)
		if applyErr == nil {
			return err
		}
	}
	return applyErr
}

// finishApplied records an applied transfer after its status update lost
// a race: it reads the transfer again and marks it applied once more.
func (e *engine) finishApplied(ctx context.Context, t *store.Transfer) bool {
	cur, err := e.cfg.Store.GetTransfer(ctx, t.ID)
	if err != nil {
		return false
	}
	if cur.Status != uiapi.TransferApplied {
		cur.Status, cur.Moved, cur.Error, cur.LeaseHolder, cur.LeaseUntil = uiapi.TransferApplied, t.Moved, "", "", nil
		if err := e.updateTransfer(ctx, cur); err != nil {
			return false
		}
	}
	*t = *cur
	return true
}

func subjectRecord(s *identity.Subject) *store.SubjectRecord {
	r := &store.SubjectRecord{Kind: string(s.Kind), Issuer: s.Issuer, ID: s.ID, Name: s.Name, Category: s.Category,
		Claims: s.Claims, Roles: s.Roles, Teams: s.Teams, TeamRoles: s.TeamRoles}
	if s.Client != nil {
		r.ClientID, r.ClientZones, r.Scopes = s.Client.ID, s.Client.Zones, s.Scopes
	}
	return r
}

func recordSubject(r store.SubjectRecord) *identity.Subject {
	s := &identity.Subject{Kind: identity.Kind(r.Kind), Issuer: r.Issuer, ID: r.ID, Name: r.Name, Category: r.Category,
		Claims: r.Claims, Roles: r.Roles, Teams: r.Teams, TeamRoles: r.TeamRoles}
	if r.ClientID != "" {
		s.Client, s.Scopes = &identity.Client{ID: r.ClientID, Name: r.ClientID, Zones: r.ClientZones}, r.Scopes
	}
	return s
}

func errorText(err error) string {
	if ze, ok := AsError(err); ok {
		return ze.Message
	}
	return err.Error()
}

// retryable tells whether an apply failed for a transient reason (zone
// locked, store or provider unavailable): the transfer stays applying.
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
			switch {
			case ok && tb.Team == t.ToTeam:
			case ok && tb.Team == t.FromTeam:
				tb.Team = t.ToTeam
				moveTombs = append(moveTombs, tb)
			case !ok && owns[k].Owner == t.ToTeam:
			default:
				return 0, fail(ReasonPrecondition, "%s is no longer reserved for team %s", keyString(k), t.FromTeam)
			}
			continue
		}
		o, ok := owns[k]
		if ok && o.Owner == t.ToTeam && (o.TransferID == t.ID || (o.State == store.StateActive && o.ContentHash == it.ContentHash)) {
			continue
		}
		set, _, present := findSet(sets, k)
		switch {
		case !ok || o.Owner != t.FromTeam:
			return 0, fail(ReasonPrecondition, "%s is no longer owned by team %s", keyString(k), t.FromTeam)
		case o.State != store.StateActive || o.ContentHash != it.ContentHash:
			return 0, fail(ReasonPrecondition, "%s changed since the request", keyString(k))
		case !present || dns.ContentHash(set) != it.ContentHash:
			return 0, fail(ReasonPrecondition, "%s changed upstream since the request", keyString(k))
		}
		o.Owner, o.TransferID = t.ToTeam, t.ID
		setActor(&o, s, rid, now)
		moveOwns = append(moveOwns, o)
	}
	if len(moveOwns)+len(moveTombs) == 0 {
		return len(t.Items), nil
	}
	err = e.cfg.Store.Reassign(ctx, t.FromTeam, moveOwns, moveTombs)
	switch {
	case err == nil:
		e.emit(ctx, s, actionTransferApply, zone, "allow", "", transferChanges(t), "", transferExtra(t))
		return len(t.Items), nil
	case errors.Is(err, store.ErrConflict):
		return 0, fail(ReasonPrecondition, "an RRset of the transfer changed during the apply")
	}
	if e.transferDone(ctx, zone, t) {
		e.emit(ctx, s, actionTransferApply, zone, "allow", "", transferChanges(t), "", transferExtra(t))
		return len(t.Items), nil
	}
	return 0, &Error{Reason: ReasonUpstream, Message: "store reassign failed: " + err.Error(), Err: err}
}

// transferDone reports whether every RRset of t already belongs to its
// target team: a reassignment that returned an error may have committed.
func (e *engine) transferDone(ctx context.Context, zone string, t store.Transfer) bool {
	for _, it := range t.Items {
		if it.Tombstone {
			tb, err := e.cfg.Store.GetTombstone(ctx, zone, it.Host, it.Type)
			if err == nil && tb.Team == t.ToTeam {
				continue
			}
			if o, oerr := e.cfg.Store.Get(ctx, zone, it.Host, it.Type); err == nil || oerr != nil || o.Owner != t.ToTeam {
				return false
			}
			continue
		}
		o, err := e.cfg.Store.Get(ctx, zone, it.Host, it.Type)
		if err != nil || o.Owner != t.ToTeam {
			return false
		}
	}
	return true
}

// applyRename moves every RRset and tombstone of a team in every managed
// zone, zone by zone under its lock, in batches of store.MaxReassign. A
// failure stops it: the RRsets already moved stay with the new team and a
// new rename moves the rest.
func (e *engine) applyRename(ctx context.Context, s *identity.Subject, t store.Transfer) (int, error) {
	moved := 0
	now, rid := e.now(), RequestID(ctx)
	zones, err := e.renameZones(ctx)
	if err != nil {
		return 0, err
	}
	if err := e.renameAllowed(ctx, s, t, zones); err != nil {
		return 0, err
	}
	for _, zone := range zones {
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
			if !e.approves(nil, s, zone, dns.Key{Host: o.Host, Type: o.Type}) {
				return 0, nil, fail(ReasonForbidden, "the approver lacks %s on %s %s in %s", policy.ActionOwnershipApprove, o.Host, o.Type, zone)
			}
			o.Owner, o.TransferID = t.ToTeam, t.ID
			setActor(&o, s, rid, now)
			owns = append(owns, o)
		}
	}
	for _, tb := range tlist {
		if tb.Team == t.FromTeam {
			if !e.approves(nil, s, zone, dns.Key{Host: tb.Host, Type: tb.Type}) {
				return 0, nil, fail(ReasonForbidden, "the approver lacks %s on %s %s in %s", policy.ActionOwnershipApprove, tb.Host, tb.Type, zone)
			}
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
			return moved, changes, &Error{Reason: ReasonUpstream, Message: fmt.Sprintf("rename interrupted in %s after %d RRsets (retried): %v", zone, moved, err), Err: err}
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

// renameZones returns the zones a rename covers: the managed zones and
// every zone where the store holds ownership entries or tombstones.
func (e *engine) renameZones(ctx context.Context) ([]string, error) {
	stored, err := e.cfg.Store.ListOwnedZones(ctx)
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store zone listing failed", Err: err}
	}
	set := map[string]bool{}
	var out []string
	for _, list := range [][]string{e.zones.ManagedZones(), stored} {
		for _, z := range list {
			if !set[z] {
				set[z] = true
				out = append(out, z)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// renameAllowed checks that the approver of a rename holds
// dns.ownership.approve on every RRset and tombstone of the team.
func (e *engine) renameAllowed(ctx context.Context, s *identity.Subject, t store.Transfer, zones []string) error {
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
			if !e.approves(nil, s, zone, k) {
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

// mayDecide tells whether s has the rights to approve t: for every RRset,
// write through the bindings of the owner team, or dns.ownership.approve on
// it; policy.approve for a rename. checkApprover adds the rules on persons.
func (e *engine) mayDecide(g *grants, s *identity.Subject, t store.Transfer) bool {
	if t.Kind == uiapi.TransferKindRename {
		return e.cfg.Authz.Allow(s, uiapi.ActionPolicyApprove, "")
	}
	for _, it := range t.Items {
		k := dns.Key{Host: it.Host, Type: it.Type}
		if !e.teamWrites(g, s, t.FromTeam, t.Zone, k) && !e.approves(g, s, t.Zone, k) {
			return false
		}
	}
	return len(t.Items) > 0
}

// personKeys identifies the person behind s: the subject itself when its
// issuer is one of the person issuers, and the values of the person claims
// ("tid+oid" joins several claims), lowercased. email is left out when the
// issuer is not trusted for it or email_verified is false. Two subjects
// sharing any key are the same person; a subject without keys cannot be
// told apart from another one.
func (e *engine) personKeys(s *identity.Subject) []string {
	var out []string
	add := func(k string) {
		if k != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	if e.personIssuer(s) {
		add("subject " + strings.ToLower(s.String()))
	}
	for _, c := range e.cfg.PersonClaims {
		if c == "email" && (e.cfg.UntrustedEmail[s.Issuer] || unverifiedEmail(s.Claims["email_verified"])) {
			continue
		}
		var parts []string
		for _, name := range strings.Split(c, "+") {
			v, ok := s.Claims[name].(string)
			if !ok || strings.TrimSpace(v) == "" {
				parts = nil
				break
			}
			parts = append(parts, strings.ToLower(strings.TrimSpace(v)))
		}
		add(strings.Join(parts, "/"))
	}
	return out
}

func unverifiedEmail(v any) bool {
	switch x := v.(type) {
	case bool:
		return !x
	case string:
		return strings.EqualFold(x, "false")
	}
	return false
}

// personIssuer reports whether s is a human of one of the person issuers.
func (e *engine) personIssuer(s *identity.Subject) bool {
	return s.Category == identity.CategoryHuman && slices.Contains(e.cfg.PersonIssuers, s.Issuer)
}

// checkRequester applies ownership.person_issuers to the requester of a
// transfer or rename when a second approver is required.
func (e *engine) checkRequester(s *identity.Subject) error {
	if e.cfg.RequireSecondApprover && len(e.cfg.PersonIssuers) > 0 && !e.personIssuer(s) {
		return fail(ReasonForbidden, "transfers are requested by people signed in with %s (ownership.person_issuers)", strings.Join(e.cfg.PersonIssuers, ", "))
	}
	return nil
}

// checkApprover enforces the rules on persons: a human unless
// ownership.machine_approvers and, with ownership.require_second_approver,
// not the requester under any identity, a human of the person issuers when
// they are set, both identified by person keys unless machine approvers.
func (e *engine) checkApprover(s *identity.Subject, t store.Transfer) error {
	if !e.cfg.RequireSecondApprover {
		if !e.cfg.MachineApprovers && s.Category != identity.CategoryHuman {
			return fail(ReasonForbidden, "transfers are approved by a person, not by a %s identity (ownership.machine_approvers)", s.Category)
		}
		return nil
	}
	if s.String() == t.Requester {
		return fail(ReasonForbidden, "the requester cannot approve its own transfer: a second person must")
	}
	if err := e.checkRequester(s); err != nil {
		return fail(ReasonForbidden, "transfers are approved by people signed in with %s (ownership.person_issuers)", strings.Join(e.cfg.PersonIssuers, ", "))
	}
	keys := e.personKeys(s)
	if !e.cfg.MachineApprovers {
		switch {
		case s.Category != identity.CategoryHuman:
			return fail(ReasonForbidden, "transfers are approved by a person, not by a %s identity (ownership.machine_approvers)", s.Category)
		case len(t.RequesterPersons) == 0:
			return fail(ReasonForbidden, "the requester cannot be identified as a person (no ownership.person_claims, not a person issuer): this transfer cannot get a second approver")
		case len(keys) == 0:
			return fail(ReasonForbidden, "your token carries none of ownership.person_claims: the gate cannot tell you apart from the requester")
		}
	}
	for _, k := range keys {
		if slices.Contains(t.RequesterPersons, k) {
			return fail(ReasonForbidden, "the requester cannot approve its own transfer, with this identity or another one: a second person must")
		}
	}
	return nil
}

// teamWrites reports whether s may write an RRset through the roles of its
// bindings for team (not through the roles it holds for another team).
func (e *engine) teamWrites(g *grants, s *identity.Subject, team, zone string, k dns.Key) bool {
	roles := s.RolesFor(team)
	if len(roles) == 0 {
		return false
	}
	c := *s
	c.Roles, c.Intent = roles, identity.IntentTransfer
	return e.allowRRset(g, &c, policy.WriteAction(k), zone, k)
}

// approves reports whether s holds dns.ownership.approve on an RRset.
func (e *engine) approves(g *grants, s *identity.Subject, zone string, k dns.Key) bool {
	return e.allowRRset(g, s, policy.ActionOwnershipApprove, zone, k)
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
	v.CanDecide = v.Status == uiapi.TransferProposed && e.mayDecide(nil, s, t) && e.checkApprover(s, t) == nil
	v.SelfApproved = t.Approver != nil && t.DecidedBy == t.Requester
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
	if t.Approver != nil {
		x["approval"] = "second"
		if t.DecidedBy == t.Requester {
			x["approval"] = "self"
		}
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
