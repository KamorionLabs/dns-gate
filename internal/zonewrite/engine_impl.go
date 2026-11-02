package zonewrite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/audit"
	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/store"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

// pendingDelete is the PendingHash of a claim whose RRset is being deleted.
const pendingDelete = "-"

var reconcilerSubject = &identity.Subject{Issuer: "gate", ID: "reconciler", Name: "gate:reconciler", Category: identity.CategorySystem}

type cachedZone struct {
	zone     *eurodns.Zone
	syncedAt time.Time
	writeAt  *time.Time
}

type engine struct {
	cfg    Config
	zones  map[string]bool
	order  []string
	now    func() time.Time
	log    *slog.Logger
	mu     sync.Mutex
	cache  map[string]*cachedZone
	locals map[string]chan struct{}
}

type noopAudit struct{}

func (noopAudit) Log(context.Context, audit.Event) {}

func newEngine(cfg Config) (*engine, error) {
	if cfg.Client == nil || cfg.Store == nil || cfg.Authz == nil {
		return nil, errors.New("zonewrite: Client, Store and Authz are required")
	}
	if cfg.Audit == nil {
		cfg.Audit = noopAudit{}
	}
	if cfg.LockTTL <= 0 {
		cfg.LockTTL = 60 * time.Second
	}
	if cfg.LockWait <= 0 {
		cfg.LockWait = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Holder == "" {
		host, _ := os.Hostname()
		cfg.Holder = host + "-" + newID()[:8]
	}
	e := &engine{
		cfg: cfg, zones: map[string]bool{}, now: cfg.Now, log: cfg.Logger,
		cache: map[string]*cachedZone{}, locals: map[string]chan struct{}{},
	}
	for _, z := range cfg.Zones {
		z = normZone(z)
		if z != "" && !e.zones[z] {
			e.zones[z] = true
			e.order = append(e.order, z)
		}
	}
	sort.Strings(e.order)
	return e, nil
}

func normZone(z string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".") }

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func etag(v int64) string { return fmt.Sprintf("\"v%d\"", v) }

func ifMatchOK(header string, v int64) bool {
	if strings.TrimSpace(header) == "" {
		return true
	}
	want := strings.Trim(etag(v), `"`)
	for _, t := range strings.Split(header, ",") {
		t = strings.Trim(strings.TrimPrefix(strings.TrimSpace(t), "W/"), `"`)
		if t == "*" || t == want {
			return true
		}
	}
	return false
}

func fail(r Reason, format string, args ...any) *Error {
	return &Error{Reason: r, Message: fmt.Sprintf(format, args...)}
}

func requestID(ctx context.Context) string {
	if id := RequestID(ctx); id != "" {
		return id
	}
	return newID()
}

func keyString(k rrset.Key) string { return k.Host + " " + k.Type }

func (e *engine) managed(zone string) (string, error) {
	zone = normZone(zone)
	if !e.zones[zone] {
		return zone, fail(ReasonNotFound, "zone %s is not managed by this gate", zone)
	}
	return zone, nil
}

// lock serializes writers on a zone: an in-process semaphore, then the store lease.
func (e *engine) lock(ctx context.Context, zone string) (func(), error) {
	e.mu.Lock()
	ch, ok := e.locals[zone]
	if !ok {
		ch = make(chan struct{}, 1)
		e.locals[zone] = ch
	}
	e.mu.Unlock()
	timer := time.NewTimer(e.cfg.LockWait)
	defer timer.Stop()
	select {
	case ch <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fail(ReasonLocked, "zone %s is locked by another write", zone)
	}
	for {
		err := e.cfg.Store.Lock(ctx, zone, e.cfg.Holder, e.cfg.LockTTL)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrLockHeld) {
			<-ch
			return nil, &Error{Reason: ReasonUpstream, Message: "store lock failed", Err: err}
		}
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			<-ch
			return nil, ctx.Err()
		case <-timer.C:
			<-ch
			return nil, fail(ReasonLocked, "zone %s is locked by another gate replica", zone)
		}
	}
	return func() {
		if err := e.cfg.Store.Unlock(context.WithoutCancel(ctx), zone, e.cfg.Holder); err != nil {
			e.log.Warn("zone unlock failed", "zone", zone, "error", err)
		}
		<-ch
	}, nil
}

func upstreamError(op string, err error) *Error {
	var api *eurodns.APIError
	if errors.As(err, &api) {
		switch {
		case api.StatusCode == http.StatusNotFound:
			return &Error{Reason: ReasonNotFound, Message: op + ": not found upstream", Err: err}
		case api.StatusCode == http.StatusBadRequest:
			return &Error{Reason: ReasonInvalid, Message: op + ": rejected by EuroDNS", Details: api.Report, Err: err}
		}
	}
	return &Error{Reason: ReasonUpstream, Message: op + ": EuroDNS call failed", Err: err}
}

// definiteFailure reports whether an upstream write is known not to have been applied.
func definiteFailure(err error) bool {
	var api *eurodns.APIError
	return errors.As(err, &api) && api.StatusCode >= 400 && api.StatusCode < 500
}

func (e *engine) fetch(ctx context.Context, zone string) (*eurodns.Zone, error) {
	z, err := e.cfg.Client.GetZone(ctx, zone)
	if err != nil {
		return nil, upstreamError("get zone", err)
	}
	e.remember(zone, z, false)
	return z, nil
}

func (e *engine) remember(zone string, z *eurodns.Zone, written bool) {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.cache[zone]
	if !ok {
		c = &cachedZone{}
		e.cache[zone] = c
	}
	if z != nil {
		c.zone, c.syncedAt = z, now
	}
	if written {
		c.writeAt = &now
	}
}

func (e *engine) ownerships(ctx context.Context, zone string) (map[rrset.Key]store.Ownership, error) {
	list, err := e.cfg.Store.List(ctx, zone)
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store list failed", Err: err}
	}
	m := make(map[rrset.Key]store.Ownership, len(list))
	for _, o := range list {
		m[rrset.Key{Host: o.Host, Type: o.Type}] = o
	}
	return m, nil
}

func findSet(sets map[rrset.Key]rrset.Set, k rrset.Key) (rrset.Set, rrset.Key, bool) {
	if s, ok := sets[k]; ok {
		return s, k, true
	}
	for key, s := range sets {
		if key.Host == k.Host && strings.EqualFold(key.Type, k.Type) {
			return s, key, true
		}
	}
	return rrset.Set{}, k, false
}

// newSet builds an RRset from records, forcing a uniform TTL.
func newSet(key rrset.Key, ttl int, recs []eurodns.Record) rrset.Set {
	out := rrset.Set{Key: key, TTL: ttl}
	for _, r := range recs {
		r.TTL = ttl
		out.Records = append(out.Records, r)
		out.Values = append(out.Values, r.RData)
	}
	sort.Strings(out.Values)
	return out
}

func setValues(s *rrset.Set) (int, []string) {
	if s == nil {
		return 0, nil
	}
	return s.TTL, slices.Clone(s.Values)
}

func uiChange(op string, key rrset.Key, old, new *rrset.Set) uiapi.Change {
	c := uiapi.Change{Op: op, Host: key.Host, Type: key.Type}
	c.OldTTL, c.OldValues = setValues(old)
	c.NewTTL, c.NewValues = setValues(new)
	return c
}

func (e *engine) emit(ctx context.Context, s *identity.Subject, action, zone, decision, reason string, changes []uiapi.Change, snapshot *int64, extra map[string]any) {
	e.cfg.Audit.Log(ctx, audit.Event{
		Time: e.now().UTC(), RequestID: requestID(ctx), Subject: s.String(), SubjectName: s.Name,
		SubjectCategory: s.Category, Teams: s.Teams, Action: action, Zone: zone, Decision: decision,
		Reason: reason, Changes: changes, SnapshotID: snapshot, Extra: extra,
	})
}

// deny audits a refusal and returns err unchanged.
func (e *engine) deny(ctx context.Context, s *identity.Subject, action, zone string, err error) error {
	reason, decision := "error", "error"
	if ze, ok := AsError(err); ok {
		reason = string(ze.Reason)
		switch ze.Reason {
		case ReasonForbidden, ReasonForeignRRset, ReasonNotOwner, ReasonTainted, ReasonPrecondition, ReasonTooMany:
			decision = "deny"
		}
	}
	e.emit(ctx, s, action, zone, decision, reason, nil, nil, map[string]any{"message": err.Error()})
	return err
}

func setActor(o *store.Ownership, s *identity.Subject, rid string, now time.Time) {
	o.UpdatedBy, o.UpdatedByName, o.UpdatedByCategory = s.String(), s.Name, s.Category
	o.UpdatedAt, o.RequestID = now, rid
}

// taint marks an ownership tainted and audits it.
func (e *engine) taint(ctx context.Context, o store.Ownership, current *rrset.Set, why string) {
	key := rrset.Key{Host: o.Host, Type: o.Type}
	o.State, o.PendingHash = store.StateTainted, ""
	o.UpdatedAt = e.now()
	if err := e.cfg.Store.Put(ctx, o); err != nil {
		e.log.Warn("taint failed", "zone", o.Zone, "rrset", keyString(key), "error", err)
		return
	}
	e.emit(ctx, reconcilerSubject, "gate.taint", o.Zone, "allow", string(ReasonTainted),
		[]uiapi.Change{uiChange("taint", key, nil, current)}, nil, map[string]any{"message": why})
}

// resolvePending settles claims left by an interrupted write, against the
// current upstream RRsets. owns is updated in place.
func (e *engine) resolvePending(ctx context.Context, zone string, sets map[rrset.Key]rrset.Set, owns map[rrset.Key]store.Ownership) {
	for key, o := range owns {
		if o.State != store.StatePending {
			continue
		}
		set, _, present := findSet(sets, key)
		var hash string
		if present {
			hash = rrset.ContentHash(set)
		}
		next := o
		next.PendingHash = ""
		switch {
		case o.ContentHash == "" && present, o.PendingHash != pendingDelete && present && hash == o.PendingHash:
			next.State, next.ContentHash = store.StateActive, hash
		case o.ContentHash == "" || (o.PendingHash == pendingDelete && !present):
			if err := e.cfg.Store.Delete(ctx, zone, o.Host, o.Type, o.Version); err != nil {
				e.log.Warn("pending cleanup failed", "zone", zone, "rrset", keyString(key), "error", err)
				continue
			}
			delete(owns, key)
			continue
		case present && hash == o.ContentHash:
			next.State = store.StateActive
		default:
			var cur *rrset.Set
			if present {
				cur = &set
			}
			e.taint(ctx, next, cur, "pending write left an unexpected state")
			if fresh, err := e.cfg.Store.Get(ctx, zone, o.Host, o.Type); err == nil {
				owns[key] = *fresh
			}
			continue
		}
		if err := e.cfg.Store.Put(ctx, next); err != nil {
			e.log.Warn("pending resolution failed", "zone", zone, "rrset", keyString(key), "error", err)
			continue
		}
		next.Version++
		owns[key] = next
	}
}

// userSets groups the records the gate may reason about: SOA and locked
// records are managed by EuroDNS (the SOA serial changes on every write) and
// never take part in deltas, hashes or drift detection.
func userSets(zone string, recs []eurodns.Record) map[rrset.Key]rrset.Set {
	user := make([]eurodns.Record, 0, len(recs))
	for _, r := range recs {
		if !rrset.ServerManaged(r) {
			user = append(user, r)
		}
	}
	return rrset.Group(zone, user)
}

// managedKeys returns the RRset keys holding server-managed records.
func managedKeys(zone string, recs []eurodns.Record) map[rrset.Key]bool {
	out := map[rrset.Key]bool{}
	for _, r := range recs {
		if rrset.ServerManaged(r) {
			out[rrset.KeyOf(zone, r)] = true
		}
	}
	return out
}

// relativeTargets lists new values whose target EuroDNS would store relative
// to the zone (no ending dot).
func relativeTargets(c zonediff.Change) []string {
	if c.New == nil || !rrset.NeedsFQDN(c.Key.Type) {
		return nil
	}
	var old []string
	if c.Old != nil {
		old = c.Old.Values
	}
	var bad []string
	for _, v := range c.New.Values {
		if slices.Contains(old, v) {
			continue
		}
		if t := rrset.TargetOf(c.Key.Type, v); t != "" && !strings.HasSuffix(t, ".") {
			bad = append(bad, v)
		}
	}
	return bad
}

// blockingProblems returns the validation problems that refuse a write:
// every error, and warnings on an RRset the request changes.
func blockingProblems(zone string, rep *eurodns.ValidationReport, changed map[rrset.Key]bool) []string {
	if rep == nil {
		return nil
	}
	var out []string
	for _, p := range rep.Problems() {
		if p.Severity != eurodns.SeverityWarning {
			out = append(out, p.String())
			continue
		}
		if p.Host == "" && p.Type == "" {
			continue
		}
		k := rrset.Key{Host: rrset.NormalizeHost(p.Host, zone), Type: strings.ToUpper(strings.TrimSpace(p.Type))}
		if changed[k] {
			out = append(out, p.String())
		}
	}
	if len(out) == 0 && rep.IsValid != nil && !*rep.IsValid {
		out = append(out, "zone rejected by EuroDNS validation")
	}
	return out
}

type plan struct {
	changes  []zonediff.Change
	ignored  []string
	forwards bool
	desired  *eurodns.Zone
}

type claim struct {
	change zonediff.Change
	prev   *store.Ownership
	cur    store.Ownership
}

// mutate runs the common write pipeline; build turns the request into RRset changes.
func (e *engine) mutate(ctx context.Context, s *identity.Subject, zoneIn, ifMatch, action string,
	build func(cur *eurodns.Zone, sets map[rrset.Key]rrset.Set) (*plan, error)) (*eurodns.Zone, error) {
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	if !e.cfg.Authz.Allow(s, policy.ActionRecordWrite, zone) {
		return nil, e.deny(ctx, s, action, zone, fail(ReasonForbidden, "not allowed to write in zone %s", zone))
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	defer unlock()

	cur, err := e.fetch(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	sets := userSets(zone, cur.Records)
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	e.resolvePending(ctx, zone, sets, owns)
	version, err := e.cfg.Store.ZoneVersion(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, &Error{Reason: ReasonUpstream, Message: "store zone version failed", Err: err})
	}
	if !ifMatchOK(ifMatch, version) {
		return nil, e.deny(ctx, s, action, zone, fail(ReasonPrecondition, "zone changed: current ETag is %s", etag(version)))
	}
	p, err := build(cur, sets)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	if len(p.ignored) > 0 {
		e.log.Info("rebase ignored out-of-scope differences", "zone", zone, "subject", s.String(), "ignored", p.ignored)
	}
	if len(p.changes) == 0 && !p.forwards {
		cur.ETag = etag(version)
		return cur, nil
	}
	claims, err := e.validate(ctx, s, zone, cur, owns, p, false)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	now := e.now()
	rid := RequestID(ctx)

	written := 0
	revert := func() {
		for _, cl := range claims[:written] {
			var err error
			if cl.prev == nil {
				err = e.cfg.Store.Delete(ctx, zone, cl.cur.Host, cl.cur.Type, cl.cur.Version)
			} else {
				restored := *cl.prev
				restored.Version = cl.cur.Version
				err = e.cfg.Store.Put(ctx, restored)
			}
			if err != nil {
				e.log.Warn("claim revert failed, reconcile will settle it", "zone", zone, "rrset", keyString(cl.change.Key), "error", err)
			}
		}
	}
	for i := range claims {
		cl := &claims[i]
		cl.cur.State = store.StatePending
		if cl.change.New == nil {
			cl.cur.PendingHash = pendingDelete
		} else {
			cl.cur.PendingHash = rrset.ContentHash(*cl.change.New)
		}
		setActor(&cl.cur, s, rid, now)
		if err := e.cfg.Store.Put(ctx, cl.cur); err != nil {
			revert()
			return nil, e.deny(ctx, s, action, zone, &Error{Reason: ReasonUpstream, Message: "store claim failed", Err: err})
		}
		cl.cur.Version++
		written++
	}

	desired := zonediff.Apply(zone, cur, p.changes)
	if p.forwards && p.desired != nil {
		desired.URLForwards, desired.MailForwards = p.desired.URLForwards, p.desired.MailForwards
		desired.DomainConnect, desired.Extra = p.desired.DomainConnect, p.desired.Extra
	}
	if e.cfg.CheckOnWrite {
		checked, err := e.cfg.Client.CheckZone(ctx, zone, desired)
		if err != nil {
			revert()
			return nil, e.deny(ctx, s, action, zone, upstreamError("check zone", err))
		}
		changed := make(map[rrset.Key]bool, len(p.changes))
		for _, c := range p.changes {
			changed[c.Key] = true
		}
		if checked != nil {
			if problems := blockingProblems(zone, checked.Report, changed); len(problems) > 0 {
				revert()
				return nil, e.deny(ctx, s, action, zone, &Error{Reason: ReasonInvalid,
					Message: "EuroDNS validation: " + strings.Join(problems, "; "), Details: checked.Report})
			}
		}
	}
	snapshot := e.latestSnapshot(ctx, zone)
	if err := e.cfg.Client.SaveZone(ctx, zone, desired); err != nil {
		if definiteFailure(err) {
			revert()
		}
		return nil, e.deny(ctx, s, action, zone, upstreamError("save zone", err))
	}
	result := desired
	if after, err := e.fetch(ctx, zone); err != nil {
		e.log.Warn("confirmation read failed, reconcile will settle the claims", "zone", zone, "error", err)
	} else {
		result = after
		e.confirm(ctx, zone, claims, userSets(zone, after.Records))
	}
	e.remember(zone, nil, true)
	newVersion, err := e.cfg.Store.BumpZoneVersion(ctx, zone, version)
	if err != nil {
		e.log.Warn("zone version bump failed", "zone", zone, "error", err)
		newVersion = version
	}
	changes := make([]uiapi.Change, 0, len(p.changes))
	for _, c := range p.changes {
		changes = append(changes, uiChange(string(c.Op), c.Key, c.Old, c.New))
	}
	var extra map[string]any
	if len(p.ignored) > 0 {
		extra = map[string]any{"ignored_out_of_scope": p.ignored}
	}
	e.emit(ctx, s, action, zone, "allow", "", changes, snapshot, extra)
	result.ETag = etag(newVersion)
	return result, nil
}

// validate applies every business rule to a plan and returns the claims to
// write. With dry set it has no side effect (drift is reported, not tainted).
func (e *engine) validate(ctx context.Context, s *identity.Subject, zone string, cur *eurodns.Zone,
	owns map[rrset.Key]store.Ownership, p *plan, dry bool) ([]claim, error) {
	if max := e.cfg.Authz.MaxChangesPerRequest(s); max > 0 && len(p.changes) > max {
		return nil, fail(ReasonTooMany, "%d RRset changes exceed the limit of %d", len(p.changes), max)
	}
	if p.forwards && !e.cfg.Authz.Allow(s, policy.ActionZoneAdmin, zone) {
		return nil, fail(ReasonForbidden, "URL/mail forwards and zone settings require %s", policy.ActionZoneAdmin)
	}

	now := e.now()
	serverManaged := managedKeys(zone, cur.Records)
	claims := make([]claim, 0, len(p.changes))
	for _, c := range p.changes {
		if !e.cfg.Authz.AllowRRset(s, policy.ActionRecordWrite, zone, c.Key) {
			return nil, fail(ReasonForbidden, "not allowed to write %s in %s", keyString(c.Key), zone)
		}
		if serverManaged[c.Key] || c.Key.Type == "SOA" {
			return nil, fail(ReasonForbidden, "%s is managed by EuroDNS (SOA or locked record)", keyString(c.Key))
		}
		if bad := relativeTargets(c); len(bad) > 0 {
			return nil, fail(ReasonInvalid,
				"%s: target of %q must end with a dot, otherwise EuroDNS stores it relative to %s", keyString(c.Key), bad[0], zone)
		}
		o, owned := owns[c.Key]
		if c.Old == nil {
			cl := claim{change: c}
			if owned {
				// Owned but absent upstream: the owner team may recreate it.
				if !slices.Contains(s.Teams, o.Owner) {
					return nil, fail(ReasonNotOwner, "%s is owned by team %s", keyString(c.Key), o.Owner)
				}
				prev := o
				cl.prev = &prev
				cl.cur = o
			} else {
				team, ok := e.cfg.Authz.OwnerTeam(s, zone)
				if !ok {
					return nil, fail(ReasonForbidden, "no owner team for %s in %s", s.String(), zone)
				}
				cl.cur = store.Ownership{
					Zone: zone, Host: c.Key.Host, Type: c.Key.Type, Owner: team,
					CreatedBy: s.String(), CreatedByName: s.Name, CreatedByCategory: s.Category, CreatedAt: now,
				}
			}
			cl.cur.ContentHash, cl.cur.Adopted = "", false
			if ttl := e.cfg.Authz.EphemeralTTL(s); ttl > 0 {
				exp := now.Add(ttl)
				cl.cur.ExpiresAt = &exp
			} else {
				cl.cur.ExpiresAt = nil
			}
			claims = append(claims, cl)
			continue
		}
		if !owned {
			return nil, fail(ReasonForeignRRset, "%s exists and is not managed by the gate", keyString(c.Key))
		}
		if !slices.Contains(s.Teams, o.Owner) {
			return nil, fail(ReasonNotOwner, "%s is owned by team %s", keyString(c.Key), o.Owner)
		}
		if o.State == store.StateTainted {
			return nil, fail(ReasonTainted, "%s was changed outside the gate; an admin must adopt it again", keyString(c.Key))
		}
		if o.State == store.StatePending {
			return nil, fail(ReasonLocked, "%s has an unsettled previous write; retry shortly", keyString(c.Key))
		}
		if rrset.ContentHash(*c.Old) != o.ContentHash {
			if !dry {
				e.taint(ctx, o, c.Old, "changed outside the gate")
			}
			return nil, fail(ReasonTainted, "%s was changed outside the gate; an admin must adopt it again", keyString(c.Key))
		}
		prev := o
		claims = append(claims, claim{change: c, prev: &prev, cur: o})
	}

	return claims, nil
}

// confirm turns pending claims into their final state after a successful save.
func (e *engine) confirm(ctx context.Context, zone string, claims []claim, after map[rrset.Key]rrset.Set) {
	for _, cl := range claims {
		set, _, present := findSet(after, cl.change.Key)
		o := cl.cur
		o.PendingHash = ""
		var err error
		switch {
		case cl.change.New == nil && !present:
			err = e.cfg.Store.Delete(ctx, zone, o.Host, o.Type, o.Version)
		case cl.change.New != nil && present:
			o.State, o.ContentHash = store.StateActive, rrset.ContentHash(set)
			err = e.cfg.Store.Put(ctx, o)
		default:
			var cur *rrset.Set
			if present {
				cur = &set
			}
			e.taint(ctx, o, cur, "upstream state differs from the saved zone")
		}
		if err != nil {
			e.log.Warn("claim confirmation failed, reconcile will settle it", "zone", zone, "rrset", keyString(cl.change.Key), "error", err)
		}
	}
}

func (e *engine) latestSnapshot(ctx context.Context, zone string) *int64 {
	snaps, err := e.cfg.Client.ListSnapshots(ctx, zone)
	if err != nil || len(snaps) == 0 {
		return nil
	}
	best := snaps[0]
	for _, sn := range snaps[1:] {
		if sn.CreatedAt > best.CreatedAt || (sn.CreatedAt == best.CreatedAt && sn.ID > best.ID) {
			best = sn
		}
	}
	return &best.ID
}

func (e *engine) GetZone(ctx context.Context, s *identity.Subject, zoneIn string) (*eurodns.Zone, error) {
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, err
	}
	if !e.cfg.Authz.Allow(s, policy.ActionDNSRead, zone) {
		return nil, e.deny(ctx, s, "getDnsZone", zone, fail(ReasonForbidden, "not allowed to read zone %s", zone))
	}
	z, err := e.fetch(ctx, zone)
	if err != nil {
		return nil, err
	}
	v, err := e.cfg.Store.ZoneVersion(ctx, zone)
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store zone version failed", Err: err}
	}
	z.ETag = etag(v)
	return z, nil
}

func (e *engine) CheckZone(ctx context.Context, s *identity.Subject, zoneIn string, z *eurodns.Zone) (*eurodns.Zone, error) {
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, err
	}
	if !e.cfg.Authz.Allow(s, policy.ActionDNSRead, zone) {
		return nil, e.deny(ctx, s, "checkDnsZone", zone, fail(ReasonForbidden, "not allowed to read zone %s", zone))
	}
	out, err := e.cfg.Client.CheckZone(ctx, zone, z)
	if err != nil {
		return nil, upstreamError("check zone", err)
	}
	return out, nil
}

func (e *engine) SaveZone(ctx context.Context, s *identity.Subject, zone string, z *eurodns.Zone, ifMatch string) error {
	if z == nil {
		return fail(ReasonInvalid, "empty zone")
	}
	rebase := e.cfg.Authz.RebaseOnSave(s)
	_, err := e.mutate(ctx, s, zone, ifMatch, "saveDnsZone", func(cur *eurodns.Zone, _ map[rrset.Key]rrset.Set) (*plan, error) {
		zn := normZone(zone)
		d := zonediff.Diff(zn, cur, z)
		p := &plan{desired: z, forwards: d.ForwardsChanged || d.OtherChanged}
		for _, c := range d.Changes {
			if e.cfg.Authz.AllowRRset(s, policy.ActionRecordWrite, zn, c.Key) {
				p.changes = append(p.changes, c)
				continue
			}
			if !rebase {
				return nil, fail(ReasonForbidden, "not allowed to write %s in %s", keyString(c.Key), zn)
			}
			p.ignored = append(p.ignored, string(c.Op)+" "+keyString(c.Key))
		}
		if rebase && p.forwards {
			p.ignored = append(p.ignored, "forwards/zone settings")
			p.forwards = false
		}
		return p, nil
	})
	return err
}

func (e *engine) AddRecords(ctx context.Context, s *identity.Subject, zone string, recs []eurodns.Record, ifMatch string) (*eurodns.Zone, error) {
	if len(recs) == 0 {
		return nil, fail(ReasonInvalid, "no records")
	}
	return e.mutate(ctx, s, zone, ifMatch, "addDnsRecords", func(_ *eurodns.Zone, sets map[rrset.Key]rrset.Set) (*plan, error) {
		zn := normZone(zone)
		clean := make([]eurodns.Record, 0, len(recs))
		for _, r := range recs {
			clean = append(clean, eurodns.Record{Type: r.Type, Host: r.Host, TTL: r.TTL, RData: r.RData, IsDynDNS: r.IsDynDNS, Proxy: r.Proxy, Extra: r.Extra})
		}
		requested := rrset.Group(zn, clean)
		keys := make([]rrset.Key, 0, len(requested))
		for k := range requested {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keyString(keys[i]) < keyString(keys[j]) })
		p := &plan{}
		for _, k := range keys {
			req := requested[k]
			old, key, exists := findSet(sets, k)
			if !exists {
				n := newSet(k, req.TTL, req.Records)
				p.changes = append(p.changes, zonediff.Change{Op: zonediff.OpCreate, Key: k, New: &n})
				continue
			}
			merged := slices.Clone(old.Records)
			added := false
			for _, r := range req.Records {
				if !slices.Contains(old.Values, r.RData) {
					merged = append(merged, r)
					added = true
				}
			}
			if !added && req.TTL == old.TTL {
				continue
			}
			o := old
			n := newSet(key, req.TTL, merged)
			p.changes = append(p.changes, zonediff.Change{Op: zonediff.OpUpdate, Key: key, Old: &o, New: &n})
		}
		return p, nil
	})
}

func (e *engine) DeleteRecord(ctx context.Context, s *identity.Subject, zone string, id int64, ifMatch string) (*eurodns.Zone, error) {
	return e.mutate(ctx, s, zone, ifMatch, "deleteDnsRecord", func(cur *eurodns.Zone, sets map[rrset.Key]rrset.Set) (*plan, error) {
		zn := normZone(zone)
		var target *eurodns.Record
		for i := range cur.Records {
			if r := cur.Records[i]; r.ID != nil && *r.ID == id {
				target = &cur.Records[i]
				break
			}
		}
		if target == nil {
			return nil, fail(ReasonNotFound, "record %d not found in %s", id, zn)
		}
		if rrset.ServerManaged(*target) {
			return nil, fail(ReasonForbidden, "record %d is managed by EuroDNS (SOA or locked record)", id)
		}
		old, key, ok := findSet(sets, rrset.Key{Host: rrset.NormalizeHost(target.Host, zn), Type: target.Type})
		if !ok {
			return nil, fail(ReasonNotFound, "record %d not found in %s", id, zn)
		}
		var rest []eurodns.Record
		for _, r := range old.Records {
			if r.ID == nil || *r.ID != id {
				rest = append(rest, r)
			}
		}
		o := old
		if len(rest) == 0 {
			return &plan{changes: []zonediff.Change{{Op: zonediff.OpDelete, Key: key, Old: &o}}}, nil
		}
		n := newSet(key, old.TTL, rest)
		return &plan{changes: []zonediff.Change{{Op: zonediff.OpUpdate, Key: key, Old: &o, New: &n}}}, nil
	})
}

func (e *engine) Adopt(ctx context.Context, s *identity.Subject, zoneIn string, req eurodns.AdoptRequest) error {
	const action = "gate.adopt"
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	if len(req.RRsets) == 0 {
		return e.deny(ctx, s, action, zone, fail(ReasonInvalid, "no RRsets to adopt"))
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	defer unlock()
	cur, err := e.fetch(ctx, zone)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	sets := userSets(zone, cur.Records)
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	e.resolvePending(ctx, zone, sets, owns)

	now := e.now()
	rid := RequestID(ctx)
	var writes []store.Ownership
	var changes []uiapi.Change
	for _, r := range req.RRsets {
		want := rrset.Key{Host: rrset.NormalizeHost(r.Host, zone), Type: strings.ToUpper(r.Type)}
		set, key, ok := findSet(sets, want)
		o, owned := owns[key]
		// Importing an RRset the caller's team already owns (terraform import
		// in gate mode) is a no-op that only needs write access on it.
		if ok && owned && o.State == store.StateActive && o.ContentHash == rrset.ContentHash(set) && slices.Contains(s.Teams, o.Owner) {
			if !e.cfg.Authz.AllowRRset(s, policy.ActionRecordWrite, zone, key) && !e.cfg.Authz.AllowRRset(s, policy.ActionRecordAdopt, zone, key) {
				return e.deny(ctx, s, action, zone, fail(ReasonForbidden, "not allowed to manage %s in %s", keyString(key), zone))
			}
			continue
		}
		if !e.cfg.Authz.AllowRRset(s, policy.ActionRecordAdopt, zone, key) {
			return e.deny(ctx, s, action, zone, fail(ReasonForbidden, "not allowed to adopt %s in %s", keyString(key), zone))
		}
		if !ok {
			return e.deny(ctx, s, action, zone, fail(ReasonNotFound, "%s does not exist in %s", keyString(want), zone))
		}
		hash := rrset.ContentHash(set)
		switch {
		case owned && !slices.Contains(s.Teams, o.Owner):
			return e.deny(ctx, s, action, zone, fail(ReasonNotOwner, "%s is owned by team %s", keyString(key), o.Owner))
		case owned:
			o.State, o.ContentHash, o.PendingHash, o.Adopted = store.StateActive, hash, "", true
		default:
			owner, err := e.adoptOwner(s, zone, req.Owner)
			if err != nil {
				return e.deny(ctx, s, action, zone, err)
			}
			o = store.Ownership{
				Zone: zone, Host: key.Host, Type: key.Type, Owner: owner, State: store.StateActive,
				ContentHash: hash, Adopted: true, CreatedAt: now,
				CreatedBy: s.String(), CreatedByName: s.Name, CreatedByCategory: s.Category,
			}
		}
		setActor(&o, s, rid, now)
		writes = append(writes, o)
		cp := set
		changes = append(changes, uiChange("adopt", key, nil, &cp))
	}
	for _, o := range writes {
		if err := e.cfg.Store.Put(ctx, o); err != nil {
			return e.deny(ctx, s, action, zone, &Error{Reason: ReasonUpstream, Message: "store adopt failed", Err: err})
		}
	}
	if len(writes) > 0 {
		e.emit(ctx, s, action, zone, "allow", "", changes, nil, nil)
	}
	return nil
}

func (e *engine) Reconcile(ctx context.Context, zoneIn string) error {
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return err
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := e.fetch(ctx, zone)
	if err != nil {
		return err
	}
	sets := userSets(zone, cur.Records)
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return err
	}
	e.resolvePending(ctx, zone, sets, owns)

	now := e.now()
	var gc []zonediff.Change
	gcOwn := map[rrset.Key]store.Ownership{}
	var expired []uiapi.Change
	keys := make([]rrset.Key, 0, len(owns))
	for k := range owns {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keyString(keys[i]) < keyString(keys[j]) })
	for _, key := range keys {
		o := owns[key]
		set, skey, present := findSet(sets, key)
		isExpired := o.ExpiresAt != nil && now.After(*o.ExpiresAt)
		if o.State == store.StateActive && present && rrset.ContentHash(set) != o.ContentHash {
			cp := set
			e.taint(ctx, o, &cp, "changed outside the gate")
			continue
		}
		if !present && isExpired {
			if err := e.cfg.Store.Delete(ctx, zone, o.Host, o.Type, o.Version); err == nil {
				expired = append(expired, uiChange("expire", key, nil, nil))
			}
			continue
		}
		if !present && o.State == store.StateActive {
			e.taint(ctx, o, nil, "deleted outside the gate")
			continue
		}
		if present && isExpired && o.State == store.StateActive {
			cp := set
			gc = append(gc, zonediff.Change{Op: zonediff.OpDelete, Key: skey, Old: &cp})
			gcOwn[skey] = o
		}
	}
	if len(gc) > 0 {
		version, err := e.cfg.Store.ZoneVersion(ctx, zone)
		if err != nil {
			return err
		}
		snapshot := e.latestSnapshot(ctx, zone)
		desired := zonediff.Apply(zone, cur, gc)
		if err := e.cfg.Client.SaveZone(ctx, zone, desired); err != nil {
			e.emit(ctx, reconcilerSubject, "gate.expire", zone, "error", string(ReasonUpstream), nil, nil, map[string]any{"message": err.Error()})
			return upstreamError("save zone", err)
		}
		e.remember(zone, nil, true)
		if after, err := e.fetch(ctx, zone); err == nil {
			afterSets := userSets(zone, after.Records)
			for key, o := range gcOwn {
				if _, _, still := findSet(afterSets, key); !still {
					if err := e.cfg.Store.Delete(ctx, zone, o.Host, o.Type, o.Version); err != nil {
						e.log.Warn("expired ownership cleanup failed", "zone", zone, "rrset", keyString(key), "error", err)
					}
				}
			}
		}
		if _, err := e.cfg.Store.BumpZoneVersion(ctx, zone, version); err != nil {
			e.log.Warn("zone version bump failed", "zone", zone, "error", err)
		}
		for _, c := range gc {
			expired = append(expired, uiChange("expire", c.Key, c.Old, nil))
		}
		e.emit(ctx, reconcilerSubject, "gate.expire", zone, "allow", "", expired, snapshot, nil)
	} else if len(expired) > 0 {
		e.emit(ctx, reconcilerSubject, "gate.expire", zone, "allow", "", expired, nil, nil)
	}
	return nil
}
