package zonewrite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"golang.org/x/sync/singleflight"
)

// pendingDelete is the PendingHash of a claim whose RRset is being deleted.
const pendingDelete = "-"

// readOnlySOA is the read-only reason of server-managed RRsets (SOA, and
// any RRset a provider flags so): they are left out of adoption filters.
const readOnlySOA = "server_managed"

var reconcilerSubject = &identity.Subject{Issuer: "gate", ID: "reconciler", Name: "gate:reconciler", Category: identity.CategorySystem}

type cachedZone struct {
	zone     *dns.Zone
	syncedAt time.Time
	writeAt  *time.Time
}

type engine struct {
	cfg    Config
	zones  ZoneSet
	now    func() time.Time
	log    *slog.Logger
	mu     sync.Mutex
	cache  map[string]*cachedZone
	reads  singleflight.Group // coalesces cache fills
	locals map[string]chan struct{}
	writes map[string]journalWrite // latest write per zone, read from the journal
}

type noopAudit struct{}

func (noopAudit) Log(context.Context, audit.Event) {}

func newEngine(cfg Config) (*engine, error) {
	if cfg.Providers == nil || cfg.Store == nil || cfg.Authz == nil {
		return nil, errors.New("zonewrite: Providers, Store and Authz are required")
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
	if cfg.EphemeralLifetimeFactor <= 0 {
		cfg.EphemeralLifetimeFactor = DefaultEphemeralLifetimeFactor
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
	if cfg.UnmanagedTTL <= 0 {
		cfg.UnmanagedTTL = 15 * time.Minute
	}
	e := &engine{
		cfg: cfg, zones: cfg.ZoneSet, now: cfg.Now, log: cfg.Logger,
		cache: map[string]*cachedZone{}, locals: map[string]chan struct{}{}, writes: map[string]journalWrite{},
	}
	if e.zones == nil {
		st := &staticZones{set: map[string]bool{}}
		for _, z := range cfg.Zones {
			z = normZone(z)
			if z != "" && !st.set[z] {
				st.set[z] = true
				st.order = append(st.order, z)
			}
		}
		sort.Strings(st.order)
		e.zones = st
	}
	return e, nil
}

func normZone(z string) string { return dns.NormalizeZone(z) }

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

func keyString(k dns.Key) string { return k.Host + " " + k.Type }

func (e *engine) managed(zone string) (string, error) {
	zone = normZone(zone)
	if !e.zones.Managed(zone) {
		return zone, fail(ReasonNotFound, "zone %s is not managed by this gate", zone)
	}
	return zone, nil
}

// provider returns the provider serving zone.
func (e *engine) provider(zone string) (provider.Provider, error) {
	p, err := e.cfg.Providers.Provider(zone)
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "no provider for zone " + zone + ": " + err.Error(), Err: err}
	}
	return p, nil
}

// providerID is the id of the provider of zone, "" when unknown.
func (e *engine) providerID(zone string) string {
	if zone == "" {
		return ""
	}
	p, err := e.cfg.Providers.Provider(zone)
	if err != nil {
		return ""
	}
	return p.ID()
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

// upstreamError maps a provider error to an engine error.
func upstreamError(op string, err error) *Error {
	var ie *provider.InvalidError
	var re *provider.RejectedError
	switch {
	case errors.As(err, &ie):
		return &Error{Reason: ReasonInvalid, Message: keyString(ie.Key) + ": " + ie.Message, Err: err}
	case errors.As(err, &re):
		return &Error{Reason: ReasonInvalid, Message: re.Message, Details: re.Details, Err: err}
	case errors.Is(err, provider.ErrZoneNotFound):
		return &Error{Reason: ReasonNotFound, Message: op + ": not found upstream", Err: err}
	case errors.Is(err, provider.ErrConflict):
		return &Error{Reason: ReasonPrecondition, Message: op + ": the upstream content changed during the write; retry", Err: err}
	}
	return &Error{Reason: ReasonUpstream, Message: op + ": provider call failed", Err: err}
}

// notApplied reports whether a provider write is known not to have been applied.
func notApplied(err error) bool {
	var ie *provider.InvalidError
	return errors.Is(err, provider.ErrNotApplied) || errors.Is(err, provider.ErrZoneNotFound) ||
		errors.Is(err, provider.ErrConflict) || errors.As(err, &ie)
}

func (e *engine) fetch(ctx context.Context, p provider.Provider, zone string) (*dns.Zone, error) {
	z, err := p.ReadZone(ctx, zone)
	if err != nil {
		return nil, upstreamError("get zone", err)
	}
	if z.Provider == "" {
		z.Provider = p.ID()
	}
	e.remember(zone, z, false)
	return z, nil
}

func (e *engine) remember(zone string, z *dns.Zone, written bool) {
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

func (e *engine) ownerships(ctx context.Context, zone string) (map[dns.Key]store.Ownership, error) {
	list, err := e.cfg.Store.List(ctx, zone)
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store list failed", Err: err}
	}
	m := make(map[dns.Key]store.Ownership, len(list))
	for _, o := range list {
		m[dns.Key{Host: o.Host, Type: o.Type}] = o
	}
	return m, nil
}

// index returns the RRsets of a zone by key.
func index(z *dns.Zone) map[dns.Key]dns.RRset {
	out := make(map[dns.Key]dns.RRset, len(z.RRsets))
	for _, s := range z.RRsets {
		out[s.Key] = s
	}
	return out
}

func findSet(sets map[dns.Key]dns.RRset, k dns.Key) (dns.RRset, dns.Key, bool) {
	if s, ok := sets[k]; ok {
		return s, k, true
	}
	for key, s := range sets {
		if key.Host == k.Host && strings.EqualFold(key.Type, k.Type) {
			return s, key, true
		}
	}
	return dns.RRset{}, k, false
}

// readOnly returns why an RRset is never written, "" if it may be.
func readOnly(k dns.Key, s *dns.RRset) string {
	if s != nil && s.ReadOnly != "" {
		return s.ReadOnly
	}
	if strings.EqualFold(k.Type, "SOA") {
		return readOnlySOA
	}
	return ""
}

func setValues(s *dns.RRset) (int, []string, *dns.Alias) {
	if s == nil {
		return 0, nil, nil
	}
	return s.TTL, slices.Clone(s.Values), s.Alias
}

func uiChange(op string, key dns.Key, old, new *dns.RRset) uiapi.Change {
	c := uiapi.Change{Op: op, Host: key.Host, Type: key.Type}
	c.OldTTL, c.OldValues, c.OldAlias = setValues(old)
	c.NewTTL, c.NewValues, c.NewAlias = setValues(new)
	return c
}

func uiChanges(changes []dns.Change) []uiapi.Change {
	out := make([]uiapi.Change, 0, len(changes))
	for _, c := range changes {
		out = append(out, uiChange(string(c.Op), c.Key, c.Old, c.New))
	}
	return out
}

func (e *engine) emit(ctx context.Context, s *identity.Subject, action, zone, decision, reason string, changes []uiapi.Change, snapshot string, extra map[string]any) {
	e.cfg.Audit.Log(ctx, audit.Event{
		Time: e.now().UTC(), RequestID: requestID(ctx), Subject: s.String(), SubjectName: s.Name,
		SubjectCategory: s.Category, Teams: s.Teams, Action: action, Zone: zone, Provider: e.providerID(zone),
		Decision: decision, Reason: reason, Changes: changes, SnapshotID: uiapi.SnapshotID(snapshot), Extra: extra,
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
	e.emit(ctx, s, action, zone, decision, reason, nil, "", map[string]any{"message": err.Error()})
	return err
}

func setActor(o *store.Ownership, s *identity.Subject, rid string, now time.Time) {
	o.UpdatedBy, o.UpdatedByName, o.UpdatedByCategory = s.String(), s.Name, s.Category
	o.UpdatedAt, o.RequestID = now, rid
}

// taint marks an ownership tainted and audits it.
func (e *engine) taint(ctx context.Context, o store.Ownership, current *dns.RRset, why string) {
	key := dns.Key{Host: o.Host, Type: o.Type}
	o.State, o.PendingHash = store.StateTainted, ""
	o.UpdatedAt = e.now()
	if err := e.cfg.Store.Put(ctx, o); err != nil {
		e.log.Warn("taint failed", "zone", o.Zone, "rrset", keyString(key), "error", err)
		return
	}
	e.emit(ctx, reconcilerSubject, "gate.taint", o.Zone, "allow", string(ReasonTainted),
		[]uiapi.Change{uiChange("taint", key, nil, current)}, "", map[string]any{"message": why})
}

// resolvePending settles claims left by an interrupted write, against the
// current upstream RRsets. owns is updated in place.
func (e *engine) resolvePending(ctx context.Context, zone string, sets map[dns.Key]dns.RRset, owns map[dns.Key]store.Ownership) {
	for key, o := range owns {
		if o.State != store.StatePending {
			continue
		}
		set, _, present := findSet(sets, key)
		var hash string
		if present {
			hash = dns.ContentHash(set)
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
			var cur *dns.RRset
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

// settle rebases plan changes on the current RRsets: Old is the current
// RRset, Op follows from Old and New, changes with neither are dropped.
func settle(sets map[dns.Key]dns.RRset, changes []dns.Change) []dns.Change {
	out := make([]dns.Change, 0, len(changes))
	for _, c := range changes {
		key := dns.Key{Host: c.Key.Host, Type: strings.ToUpper(strings.TrimSpace(c.Key.Type))}
		var old *dns.RRset
		if s, k, ok := findSet(sets, key); ok {
			cp := s
			old, key = &cp, k
		}
		n := c.New
		if n != nil {
			cp := *n
			cp.Key = key
			n = &cp
		}
		switch {
		case old == nil && n == nil:
			continue
		case old == nil:
			c = dns.Change{Op: dns.OpCreate, Key: key, New: n}
		case n == nil:
			c = dns.Change{Op: dns.OpDelete, Key: key, Old: old}
		default:
			c = dns.Change{Op: dns.OpUpdate, Key: key, Old: old, New: n}
		}
		out = append(out, c)
	}
	return out
}

type claim struct {
	change dns.Change
	prev   *store.Ownership
	cur    store.Ownership
}

// Write runs the common write pipeline; build turns the request into RRset changes.
func (e *engine) Write(ctx context.Context, s *identity.Subject, zoneIn, ifMatch, action string, build BuildFunc) (*dns.Zone, int64, error) {
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, err)
	}
	if !e.cfg.Authz.Allow(s, policy.ActionRecordWrite, zone) {
		return nil, 0, e.deny(ctx, s, action, zone, fail(ReasonForbidden, "not allowed to write in zone %s", zone))
	}
	p, err := e.provider(zone)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, err)
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, err)
	}
	defer unlock()

	cur, err := e.fetch(ctx, p, zone)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, err)
	}
	sets := index(cur)
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, err)
	}
	e.resolvePending(ctx, zone, sets, owns)
	version, err := e.cfg.Store.ZoneVersion(ctx, zone)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, &Error{Reason: ReasonUpstream, Message: "store zone version failed", Err: err})
	}
	if !ifMatchOK(ifMatch, version) {
		return nil, 0, e.deny(ctx, s, action, zone, fail(ReasonPrecondition, "zone changed: current ETag is %s", etag(version)))
	}
	plan, err := build(cur)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, err)
	}
	if plan == nil {
		plan = &Plan{}
	}
	plan.Changes = settle(sets, plan.Changes)
	if len(plan.Ignored) > 0 {
		e.log.Info("rebase ignored out-of-scope differences", "zone", zone, "subject", s.String(), "ignored", plan.Ignored)
	}
	if len(plan.Changes) == 0 && !plan.Settings {
		return cur, version, nil
	}
	claims, err := e.validate(ctx, s, p, zone, sets, owns, plan, false)
	if err != nil {
		return nil, 0, e.deny(ctx, s, action, zone, err)
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
			cl.cur.PendingHash = dns.ContentHash(*cl.change.New)
		}
		setActor(&cl.cur, s, rid, now)
		if err := e.cfg.Store.Put(ctx, cl.cur); err != nil {
			revert()
			return nil, 0, e.deny(ctx, s, action, zone, &Error{Reason: ReasonUpstream, Message: "store claim failed", Err: err})
		}
		cl.cur.Version++
		written++
	}

	base := cur
	if plan.Base != nil {
		base = plan.Base
	}
	if err := e.check(ctx, p, zone, base, plan.Changes); err != nil {
		revert()
		return nil, 0, e.deny(ctx, s, action, zone, err)
	}
	snapshot := e.latestSnapshot(ctx, p, zone)
	if err := p.Apply(ctx, zone, base, plan.Changes); err != nil {
		switch {
		case !p.Capabilities().AtomicBatch:
			e.settleClaims(ctx, p, zone)
		case notApplied(err):
			revert()
		}
		return nil, 0, e.deny(ctx, s, action, zone, upstreamError("write zone", err))
	}
	var result *dns.Zone
	if after, err := e.fetch(ctx, p, zone); err != nil {
		e.log.Warn("confirmation read failed, reconcile will settle the claims", "zone", zone, "error", err)
	} else {
		result = after
		e.confirm(ctx, zone, claims, index(after))
	}
	e.remember(zone, nil, true)
	newVersion, err := e.cfg.Store.BumpZoneVersion(ctx, zone, version)
	if err != nil {
		e.log.Warn("zone version bump failed", "zone", zone, "error", err)
		newVersion = version
	}
	var extra map[string]any
	if len(plan.Ignored) > 0 {
		extra = map[string]any{"ignored_out_of_scope": plan.Ignored}
	}
	e.emit(ctx, s, action, zone, "allow", "", uiChanges(plan.Changes), snapshot, extra)
	e.committed(ctx, zone, plan)
	return result, newVersion, nil
}

// committed runs the Committed hook of a plan.
func (e *engine) committed(ctx context.Context, zone string, plan *Plan) {
	if plan.Committed == nil {
		return
	}
	if err := plan.Committed(ctx); err != nil {
		e.log.Warn("post-write hook failed", "zone", zone, "error", err)
	}
}

// check runs the provider dry run when enabled and refuses blocking problems.
func (e *engine) check(ctx context.Context, p provider.Provider, zone string, base *dns.Zone, changes []dns.Change) error {
	c, ok := p.(provider.Checker)
	if !e.cfg.CheckOnWrite || !ok {
		return nil
	}
	problems, err := c.Check(ctx, zone, base, changes)
	if err != nil {
		return upstreamError("check zone", err)
	}
	var blocking []string
	for _, pb := range problems {
		if pb.Blocking {
			blocking = append(blocking, pb.Message)
		}
	}
	if len(blocking) > 0 {
		return &Error{Reason: ReasonInvalid, Message: p.ID() + " validation: " + strings.Join(blocking, "; "), Details: problems}
	}
	return nil
}

// settleClaims resolves the pending claims of zone against a fresh read,
// after a failed write of a provider without atomic batches.
func (e *engine) settleClaims(ctx context.Context, p provider.Provider, zone string) {
	after, err := e.fetch(ctx, p, zone)
	if err != nil {
		e.log.Warn("read after a failed write failed, reconcile will settle the claims", "zone", zone, "error", err)
		return
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return
	}
	e.resolvePending(ctx, zone, index(after), owns)
}

// validate applies every business rule to a plan and returns the claims to
// write; plan.Changes get their normalized New. With dry set it has no side
// effect (drift is reported, not tainted).
func (e *engine) validate(ctx context.Context, s *identity.Subject, p provider.Provider, zone string, sets map[dns.Key]dns.RRset,
	owns map[dns.Key]store.Ownership, plan *Plan, dry bool) ([]claim, error) {
	if max := e.cfg.Authz.MaxChangesPerRequest(s); max > 0 && len(plan.Changes) > max {
		return nil, fail(ReasonTooMany, "%d RRset changes exceed the limit of %d", len(plan.Changes), max)
	}
	if plan.Settings && !e.cfg.Authz.Allow(s, policy.ActionZoneAdmin, zone) {
		return nil, fail(ReasonForbidden, "zone settings (EuroDNS URL/mail forwards) require %s", policy.ActionZoneAdmin)
	}
	caps := p.Capabilities()

	now := e.now()
	claims := make([]claim, 0, len(plan.Changes))
	for i := range plan.Changes {
		c := &plan.Changes[i]
		if !e.cfg.Authz.AllowRRset(s, policy.ActionRecordWrite, zone, c.Key) {
			return nil, fail(ReasonForbidden, "not allowed to write %s in %s", keyString(c.Key), zone)
		}
		cur, exists := sets[c.Key]
		var curp *dns.RRset
		if exists {
			curp = &cur
		}
		if ro := readOnly(c.Key, curp); ro != "" {
			return nil, fail(ReasonForbidden, "%s is read-only at provider %s (%s)", keyString(c.Key), p.ID(), ro)
		}
		if c.New != nil {
			if c.New.Alias != nil && !caps.Alias {
				return nil, fail(ReasonInvalid, "%s: provider %s does not support alias records", keyString(c.Key), p.ID())
			}
			n, err := p.Normalize(zone, *c.New)
			if err != nil {
				return nil, upstreamError("normalize", err)
			}
			n.Key = c.Key
			c.New = &n
		}
		o, owned := owns[c.Key]
		if c.Old == nil {
			cl := claim{change: *c}
			if owned {
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
		if dns.ContentHash(*c.Old) != o.ContentHash {
			if !dry {
				e.taint(ctx, o, c.Old, "changed outside the gate")
			}
			return nil, fail(ReasonTainted, "%s was changed outside the gate; an admin must adopt it again", keyString(c.Key))
		}
		prev := o
		cl := claim{change: *c, prev: &prev, cur: o}
		if ttl := e.cfg.Authz.EphemeralTTL(s); ttl > 0 && o.ExpiresAt != nil && addsValues(c.Old, c.New) {
			exp := now.Add(ttl)
			if limit := o.CreatedAt.Add(time.Duration(e.cfg.EphemeralLifetimeFactor) * ttl); exp.After(limit) {
				exp = limit
			}
			if exp.After(*o.ExpiresAt) {
				cl.cur.ExpiresAt = &exp
			}
		}
		claims = append(claims, cl)
	}
	return claims, nil
}

// DefaultEphemeralLifetimeFactor is the default of
// Config.EphemeralLifetimeFactor.
const DefaultEphemeralLifetimeFactor = 4

// addsValues reports whether a change adds a value to an RRset.
func addsValues(old, new *dns.RRset) bool {
	if old == nil || new == nil {
		return new != nil
	}
	for _, v := range new.Values {
		if !slices.Contains(old.Values, v) {
			return true
		}
	}
	return false
}

// confirm turns pending claims into their final state after a successful write.
func (e *engine) confirm(ctx context.Context, zone string, claims []claim, after map[dns.Key]dns.RRset) {
	for _, cl := range claims {
		set, _, present := findSet(after, cl.change.Key)
		o := cl.cur
		o.PendingHash = ""
		var err error
		switch {
		case cl.change.New == nil && !present:
			err = e.cfg.Store.Delete(ctx, zone, o.Host, o.Type, o.Version)
		case cl.change.New != nil && present:
			o.State, o.ContentHash = store.StateActive, dns.ContentHash(set)
			err = e.cfg.Store.Put(ctx, o)
		default:
			var cur *dns.RRset
			if present {
				cur = &set
			}
			e.taint(ctx, o, cur, "upstream state differs from the written zone")
		}
		if err != nil {
			e.log.Warn("claim confirmation failed, reconcile will settle it", "zone", zone, "rrset", keyString(cl.change.Key), "error", err)
		}
	}
}

func (e *engine) latestSnapshot(ctx context.Context, p provider.Provider, zone string) string {
	sn, ok := p.(provider.Snapshotter)
	if !ok {
		return ""
	}
	id, err := sn.LatestSnapshot(ctx, zone)
	if err != nil {
		return ""
	}
	return id
}

func (e *engine) Authorize(ctx context.Context, s *identity.Subject, zoneIn, action, op string) (provider.Provider, error) {
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, err
	}
	if !e.cfg.Authz.Allow(s, action, zone) {
		return nil, e.deny(ctx, s, op, zone, fail(ReasonForbidden, "%s is not allowed on zone %s", action, zone))
	}
	return e.provider(zone)
}

func (e *engine) ReadZone(ctx context.Context, s *identity.Subject, zoneIn, op string) (*dns.Zone, int64, error) {
	p, err := e.Authorize(ctx, s, zoneIn, policy.ActionDNSRead, op)
	if err != nil {
		return nil, 0, err
	}
	zone := normZone(zoneIn)
	z, err := e.fetch(ctx, p, zone)
	if err != nil {
		return nil, 0, err
	}
	v, err := e.cfg.Store.ZoneVersion(ctx, zone)
	if err != nil {
		return nil, 0, &Error{Reason: ReasonUpstream, Message: "store zone version failed", Err: err}
	}
	return z, v, nil
}

func (e *engine) Adopt(ctx context.Context, s *identity.Subject, zoneIn string, refs []uiapi.RRsetRef, owner string) error {
	const action = "gate.adopt"
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	if len(refs) == 0 {
		return e.deny(ctx, s, action, zone, fail(ReasonInvalid, "no RRsets to adopt"))
	}
	p, err := e.provider(zone)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	defer unlock()
	cur, err := e.fetch(ctx, p, zone)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	sets := index(cur)
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return e.deny(ctx, s, action, zone, err)
	}
	e.resolvePending(ctx, zone, sets, owns)

	now := e.now()
	rid := RequestID(ctx)
	var writes []store.Ownership
	var changes []uiapi.Change
	for _, r := range refs {
		want := refKey(zone, r)
		set, key, ok := findSet(sets, want)
		o, owned := owns[key]
		if ok && owned && o.State == store.StateActive && o.ContentHash == dns.ContentHash(set) && slices.Contains(s.Teams, o.Owner) {
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
		if ro := readOnly(key, &set); ro != "" {
			return e.deny(ctx, s, action, zone, fail(ReasonForbidden, "%s is read-only at provider %s (%s)", keyString(key), p.ID(), ro))
		}
		hash := dns.ContentHash(set)
		switch {
		case owned && !slices.Contains(s.Teams, o.Owner):
			return e.deny(ctx, s, action, zone, fail(ReasonNotOwner, "%s is owned by team %s", keyString(key), o.Owner))
		case owned:
			o.State, o.ContentHash, o.PendingHash, o.Adopted = store.StateActive, hash, "", true
		default:
			team, err := e.adoptOwner(s, zone, owner)
			if err != nil {
				return e.deny(ctx, s, action, zone, err)
			}
			o = store.Ownership{
				Zone: zone, Host: key.Host, Type: key.Type, Owner: team, State: store.StateActive,
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
		e.emit(ctx, s, action, zone, "allow", "", changes, "", nil)
	}
	return nil
}

func (e *engine) Reconcile(ctx context.Context, zoneIn string) error {
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return err
	}
	p, err := e.provider(zone)
	if err != nil {
		return err
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := e.fetch(ctx, p, zone)
	if err != nil {
		return err
	}
	sets := index(cur)
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return err
	}
	e.resolvePending(ctx, zone, sets, owns)

	now := e.now()
	var gc []dns.Change
	gcOwn := map[dns.Key]store.Ownership{}
	var expired []uiapi.Change
	keys := make([]dns.Key, 0, len(owns))
	for k := range owns {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keyString(keys[i]) < keyString(keys[j]) })
	for _, key := range keys {
		o := owns[key]
		set, skey, present := findSet(sets, key)
		isExpired := o.ExpiresAt != nil && now.After(*o.ExpiresAt)
		if o.State == store.StateActive && present && dns.ContentHash(set) != o.ContentHash {
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
		if present && isExpired && o.State == store.StateActive && readOnly(skey, &set) == "" {
			cp := set
			gc = append(gc, dns.Change{Op: dns.OpDelete, Key: skey, Old: &cp})
			gcOwn[skey] = o
		}
	}
	if len(gc) > 0 {
		version, err := e.cfg.Store.ZoneVersion(ctx, zone)
		if err != nil {
			return err
		}
		snapshot := e.latestSnapshot(ctx, p, zone)
		if err := p.Apply(ctx, zone, cur, gc); err != nil {
			e.emit(ctx, reconcilerSubject, "gate.expire", zone, "error", string(ReasonUpstream), nil, "", map[string]any{"message": err.Error()})
			return upstreamError("write zone", err)
		}
		e.remember(zone, nil, true)
		if after, err := e.fetch(ctx, p, zone); err == nil {
			afterSets := index(after)
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
		e.emit(ctx, reconcilerSubject, "gate.expire", zone, "allow", "", expired, "", nil)
	}
	return nil
}

// ProviderError maps an error of a provider call made outside the engine
// (a provider API facade) to an engine error.
func ProviderError(op string, err error) *Error { return upstreamError(op, err) }
