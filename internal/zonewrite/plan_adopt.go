package zonewrite

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// Adoption refusal reasons (uiapi.AdoptCandidate.Reason).
const (
	adoptProtected     = "protected"
	adoptServerManaged = "server_managed"
	adoptOtherTeam     = "owned_by_other_team"
	adoptReserved      = "reserved_for_other_team" // tombstone of another team
	adoptAlreadyOwned  = "already_owned"
	adoptForbidden     = "forbidden"
	adoptInvalid       = "invalid"
	adoptNotFound      = "not_found"
)

const defaultTTL = 3600

var teamNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

func refKey(zone string, r uiapi.RRsetRef) dns.Key {
	return dns.Key{Host: dns.NormalizeHost(r.Host, zone), Type: strings.ToUpper(strings.TrimSpace(r.Type))}
}

// rrsetPlan turns desired RRset states into changes against the current
// sets, enforcing the per-RRset preconditions: MustNotExist on an existing
// RRset is foreign_rrset when the gate does not own it, precondition when it
// does; an ExpectedHash mismatch is precondition.
func rrsetPlan(zone string, p provider.Provider, sets map[dns.Key]dns.RRset, owns map[dns.Key]store.Ownership, changes []uiapi.RRsetChange) (*Plan, error) {
	plan := &Plan{}
	seen := map[dns.Key]bool{}
	caps := p.Capabilities()
	for _, c := range changes {
		key := refKey(zone, uiapi.RRsetRef{Host: c.Host, Type: c.Type})
		if key.Type == "" {
			return nil, fail(ReasonInvalid, "type is required for host %q", c.Host)
		}
		if seen[key] {
			return nil, fail(ReasonInvalid, "%s appears twice in the request", keyString(key))
		}
		seen[key] = true
		old, key, exists := findSet(sets, key)
		if c.MustNotExist && exists {
			if _, owned := owns[key]; !owned {
				return nil, fail(ReasonForeignRRset, "%s exists and is not managed by the gate", keyString(key))
			}
			return nil, fail(ReasonPrecondition, "%s already exists", keyString(key))
		}
		if c.ExpectedHash != "" && (!exists || dns.ContentHash(old) != c.ExpectedHash) {
			return nil, fail(ReasonPrecondition, "%s changed: its content hash is no longer %s", keyString(key), c.ExpectedHash)
		}
		if c.Delete || (len(c.Values) == 0 && c.Alias == nil && c.Forward == nil) {
			if exists {
				o := old
				plan.Changes = append(plan.Changes, dns.Change{Op: dns.OpDelete, Key: key, Old: &o})
			}
			continue
		}
		if c.Alias != nil && !caps.Alias {
			return nil, fail(ReasonInvalid, "%s: provider %s does not support alias records", keyString(key), p.ID())
		}
		if key.IsForward() != (c.Forward != nil) {
			return nil, fail(ReasonInvalid, "%s: a forward is written as type %s with a forward and nothing else", keyString(key), dns.TypeURLForward)
		}
		if key.IsForward() && !caps.Forwards {
			return nil, fail(ReasonInvalid, "%s: provider %s has no URL forwards", keyString(key), p.ID())
		}
		ttl := c.TTL
		if ttl == 0 && c.Alias == nil && c.Forward == nil {
			ttl = defaultTTL
			if exists {
				ttl = old.TTL
			}
		}
		n := dns.RRset{Key: key, TTL: ttl, Alias: c.Alias, Forward: c.Forward}
		if c.Forward != nil {
			f := *c.Forward
			n.Forward, n.TTL = &f, 0
		}
		if c.Alias == nil && c.Forward == nil {
			n.Values = slices.Clone(c.Values)
			sort.Strings(n.Values)
			n.Values = slices.Compact(n.Values)
		}
		norm, err := p.Normalize(zone, n)
		if err != nil {
			return nil, upstreamError("normalize", err)
		}
		norm.Key = key
		if !exists {
			plan.Changes = append(plan.Changes, dns.Change{Op: dns.OpCreate, Key: key, New: &norm})
			continue
		}
		if dns.ContentHash(old) == dns.ContentHash(norm) {
			continue
		}
		o := old
		plan.Changes = append(plan.Changes, dns.Change{Op: dns.OpUpdate, Key: key, Old: &o, New: &norm})
	}
	sort.Slice(plan.Changes, func(i, j int) bool { return plan.Changes[i].Key.Less(plan.Changes[j].Key) })
	return plan, nil
}

func (e *engine) PlanRRsets(ctx context.Context, s *identity.Subject, zoneIn string, changes []uiapi.RRsetChange) (*uiapi.PlanResult, error) {
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, err
	}
	res := &uiapi.PlanResult{Zone: zone, Changes: []uiapi.Change{}}
	if res.ZoneVersion, err = e.cfg.Store.ZoneVersion(ctx, zone); err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store zone version failed", Err: err}
	}
	refuse := func(err error) (*uiapi.PlanResult, error) {
		ze, ok := AsError(err)
		if !ok || ze.Reason == ReasonUpstream {
			return nil, err
		}
		res.Allowed, res.Reason, res.Message = false, string(ze.Reason), ze.Message
		return res, nil
	}
	if !e.writesIn(s, zone) {
		return refuse(fail(ReasonForbidden, "not allowed to write in zone %s", zone))
	}
	p, err := e.provider(zone)
	if err != nil {
		return nil, err
	}
	cur, err := e.fetch(ctx, p, zone)
	if err != nil {
		return nil, err
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, err
	}
	sets := index(cur)
	if err := e.requireHTTPS(ctx, p, zone, changes); err != nil {
		return refuse(err)
	}
	plan, err := rrsetPlan(zone, p, sets, owns, changes)
	if err != nil {
		return refuse(err)
	}
	res.Changes = uiChanges(plan.Changes)
	if len(plan.Changes) == 0 {
		res.Allowed = true
		return res, nil
	}
	if _, err := e.validate(ctx, s, p, zone, sets, owns, plan, true); err != nil {
		return refuse(err)
	}
	res.Changes = uiChanges(plan.Changes)
	if err := e.check(ctx, p, zone, cur, plan.Changes); err != nil {
		return refuse(err)
	}
	res.Allowed = true
	return res, nil
}

func (e *engine) ApplyRRsets(ctx context.Context, s *identity.Subject, zoneIn string, changes []uiapi.RRsetChange, expectedZoneVersion int64) (*uiapi.PlanResult, error) {
	var plan *Plan
	ifMatch := ""
	if expectedZoneVersion > 0 {
		ifMatch = etag(expectedZoneVersion)
	}
	zone := normZone(zoneIn)
	_, version, err := e.Write(ctx, s, zone, ifMatch, "applyRRsets", func(cur *dns.Zone) (*Plan, error) {
		p, err := e.provider(zone)
		if err != nil {
			return nil, err
		}
		owns, err := e.ownerships(ctx, zone)
		if err != nil {
			return nil, err
		}
		if err := e.requireHTTPS(ctx, p, zone, changes); err != nil {
			return nil, err
		}
		plan, err = rrsetPlan(zone, p, index(cur), owns, changes)
		return plan, err
	})
	if err != nil {
		return nil, err
	}
	var applied []dns.Change
	if plan != nil {
		applied = plan.Changes
	}
	return &uiapi.PlanResult{Zone: zone, Allowed: true, Changes: uiChanges(applied), ZoneVersion: version}, nil
}

// httpsStatus is the HTTPS status of the forwards of a zone at p.
func httpsStatus(ctx context.Context, p provider.Provider, zone string) provider.HTTPSRedirect {
	if !p.Capabilities().Forwards {
		return provider.HTTPSRedirect{Status: provider.HTTPSUnsupported, Message: "provider " + p.ID() + " has no URL forwards"}
	}
	h, ok := p.(provider.HTTPSRedirecter)
	if !ok {
		return provider.HTTPSRedirect{Status: provider.HTTPSActive}
	}
	st, err := h.HTTPSRedirect(ctx, zone)
	if err != nil {
		return provider.HTTPSRedirect{Status: provider.HTTPSUnknown, Message: err.Error()}
	}
	return st
}

// requireHTTPS refuses forward changes asking for HTTPS when the forwards
// of the zone answer plain HTTP only, or when that cannot be told.
func (e *engine) requireHTTPS(ctx context.Context, p provider.Provider, zone string, changes []uiapi.RRsetChange) error {
	var host string
	for _, c := range changes {
		if c.RequireHTTPS && !c.Delete && c.Forward != nil {
			host = dns.NormalizeHost(c.Host, zone)
			break
		}
	}
	if host == "" {
		return nil
	}
	switch st := httpsStatus(ctx, p, zone); st.Status {
	case provider.HTTPSActive, provider.HTTPSPending, provider.HTTPSNoForward:
		return nil
	default:
		msg := "the forwards of " + zone + " do not answer HTTPS (" + st.Status + ")"
		if st.Message != "" {
			msg += ": " + st.Message
		}
		return &Error{Reason: ReasonHTTPS, Message: keyString(dns.ForwardKey(host)) + ": require_https: " + msg +
			"; an HTTPS redirect subscription is ordered at the provider, not through the gate", Details: st}
	}
}

func (e *engine) HTTPSRedirect(ctx context.Context, s *identity.Subject, zoneIn string) (provider.HTTPSRedirect, error) {
	zone, err := e.managed(zoneIn)
	if err != nil {
		return provider.HTTPSRedirect{}, err
	}
	if !e.cfg.Authz.Allow(s, policy.ActionDNSRead, zone) && !e.cfg.Authz.Allow(s, policy.ActionUIRead, zone) {
		return provider.HTTPSRedirect{}, fail(ReasonForbidden, "dns.read or ui.read is required on %s", zone)
	}
	p, err := e.provider(zone)
	if err != nil {
		return provider.HTTPSRedirect{}, err
	}
	return httpsStatus(ctx, p, zone), nil
}

type adoptCandidate struct {
	uiapi.AdoptCandidate
	key  dns.Key
	hash string
}

// adoptCandidates evaluates the selected RRsets: explicit refs first, then
// filter matches over the RRsets that are not server-managed (everything
// when nothing is selected); other read-only RRsets are listed with their
// reason.
func (e *engine) adoptCandidates(g *grants, s *identity.Subject, p provider.Provider, zone, owner string, cur *dns.Zone, owns map[dns.Key]store.Ownership,
	tombs map[dns.Key]store.Tombstone, refs []uiapi.RRsetRef, hosts, types []string) []adoptCandidate {
	all := index(cur)
	var keys []dns.Key
	picked := map[dns.Key]bool{}
	pick := func(k dns.Key) {
		if !picked[k] {
			picked[k] = true
			keys = append(keys, k)
		}
	}
	for _, r := range refs {
		pick(refKey(zone, r))
	}
	if len(hosts) > 0 || len(types) > 0 || len(refs) == 0 {
		var filtered []dns.Key
		for k, set := range all {
			if readOnly(k, &set) == readOnlySOA {
				continue
			}
			hostOK := len(hosts) == 0 || slices.ContainsFunc(hosts, func(h string) bool { return glob.MatchHost(dns.NormalizeHost(h, zone), k.Host) })
			typeOK := len(types) == 0 || slices.ContainsFunc(types, func(t string) bool { return strings.EqualFold(strings.TrimSpace(t), k.Type) })
			if hostOK && typeOK {
				filtered = append(filtered, k)
			}
		}
		sort.Slice(filtered, func(i, j int) bool { return keyString(filtered[i]) < keyString(filtered[j]) })
		for _, k := range filtered {
			pick(k)
		}
	}
	out := make([]adoptCandidate, 0, len(keys))
	for _, k := range keys {
		set, exists := all[k]
		c := adoptCandidate{key: k, AdoptCandidate: uiapi.AdoptCandidate{Host: k.Host, Type: k.Type}}
		if !exists {
			c.Reason = adoptNotFound
			out = append(out, c)
			continue
		}
		c.TTL, c.Values, c.Alias, c.Forward, c.hash = set.TTL, append([]string{}, set.Values...), set.Alias, set.Forward, dns.ContentHash(set)
		o, owned := owns[k]
		c.Status = statusOf(o, owned, set, true)
		ro := readOnly(k, &set)
		switch {
		case ro != "":
			c.Reason = ro
		case e.cfg.Authz.IsProtected(zone, k):
			c.Reason = adoptProtected
		case owned && !slices.Contains(s.Teams, o.Owner):
			c.Reason = adoptOtherTeam
		case owned && o.State != store.StateTainted:
			c.Reason = adoptAlreadyOwned
		case !owned && reserved(owner, tombs, k):
			c.Reason = adoptReserved
		case !owned && !e.adoptsFor(s, zone, owner, k):
			c.Reason = adoptForbidden
		case !e.allowRRset(g, s, policy.ActionRecordAdopt, zone, k):
			c.Reason = adoptForbidden
		case invalidReason(p, zone, set) != "":
			c.Reason = invalidReason(p, zone, set)
		default:
			c.Adoptable = true
		}
		out = append(out, c)
	}
	return out
}

// invalidReason tells why the provider would refuse to write set back as
// is ("" when it would accept it): such an RRset could never be changed by
// its owner, so it is not adoptable.
func invalidReason(p provider.Provider, zone string, set dns.RRset) string {
	_, err := p.Normalize(zone, set)
	if err == nil {
		return ""
	}
	var ie *provider.InvalidError
	if errors.As(err, &ie) && ie.Code != "" {
		return ie.Code
	}
	return adoptInvalid
}

// previewToken binds an apply to the previewed owner and the content of every
// adoptable candidate: base64url("<zone>\n<owner>\n" + "<host>\t<type>\t<hash>" lines).
// It is not a secret: it only proves which content the caller has seen.
func previewToken(zone, owner string, cands []adoptCandidate) string {
	var lines []string
	for _, c := range cands {
		if c.Adoptable {
			lines = append(lines, c.key.Host+"\t"+c.key.Type+"\t"+c.hash[:16])
		}
	}
	sort.Strings(lines)
	return base64.RawURLEncoding.EncodeToString([]byte(zone + "\n" + owner + "\n" + strings.Join(lines, "\n")))
}

func parsePreviewToken(tok string) (zone, owner string, hashes map[dns.Key]string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return "", "", nil, false
	}
	parts := strings.Split(string(raw), "\n")
	if len(parts) < 2 {
		return "", "", nil, false
	}
	hashes = map[dns.Key]string{}
	for _, l := range parts[2:] {
		f := strings.Split(l, "\t")
		if len(f) != 3 {
			continue
		}
		hashes[dns.Key{Host: f[0], Type: f[1]}] = f[2]
	}
	return parts[0], parts[1], hashes, true
}

// adoptOwner returns the team adopted RRsets go to: the caller's team by
// default, another of its teams, or a known team when the caller holds
// dns.ownership.approve in the zone (checked again on each RRset).
func (e *engine) adoptOwner(s *identity.Subject, zone, owner string) (string, error) {
	if owner == "" {
		team, ok := e.cfg.Authz.OwnerTeam(s, zone)
		if !ok {
			return "", fail(ReasonForbidden, "no owner team for %s in %s", s.String(), zone)
		}
		return team, nil
	}
	if slices.Contains(s.Teams, owner) {
		return owner, nil
	}
	if !e.cfg.Authz.Allow(s, policy.ActionOwnershipApprove, zone) {
		return "", fail(ReasonForbidden, "team %s is not one of your teams: adopting for another team requires %s on %s", owner, policy.ActionOwnershipApprove, zone)
	}
	if !e.knownTeam(owner) {
		return "", fail(ReasonInvalid, "unknown team %q", owner)
	}
	return owner, nil
}

// knownTeam reports whether a team may own RRsets.
func (e *engine) knownTeam(team string) bool {
	if e.cfg.Teams != nil {
		return e.cfg.Teams.KnownTeam(team)
	}
	return teamNameRe.MatchString(team)
}

// reserved tells whether a tombstone keeps an unowned RRset from going to
// owner: it belongs to another team. Adoption never lifts it, whoever the
// caller is: the RRset changes team through a transfer (a second person).
func reserved(owner string, tombs map[dns.Key]store.Tombstone, k dns.Key) bool {
	t, ok := tombs[k]
	return ok && t.Team != owner
}

// adoptsFor reports whether s may adopt an RRset for owner: one of its
// teams, or another team with dns.ownership.approve on that RRset.
func (e *engine) adoptsFor(s *identity.Subject, zone, owner string, k dns.Key) bool {
	return slices.Contains(s.Teams, owner) || e.approves(nil, s, zone, k)
}

func (e *engine) PreviewAdopt(ctx context.Context, s *identity.Subject, zoneIn string, sel uiapi.AdoptSelection) (*uiapi.AdoptPreview, error) {
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, err
	}
	if !e.cfg.Authz.Allow(s, policy.ActionRecordAdopt, zone) {
		return nil, fail(ReasonForbidden, "not allowed to adopt in zone %s", zone)
	}
	owner, err := e.adoptOwner(s, zone, sel.Owner)
	if err != nil {
		return nil, err
	}
	p, err := e.provider(zone)
	if err != nil {
		return nil, err
	}
	cur, err := e.fetch(ctx, p, zone)
	if err != nil {
		return nil, err
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, err
	}
	tombs, err := e.liveTombstones(ctx, zone)
	if err != nil {
		return nil, err
	}
	cands := e.adoptCandidates(nil, s, p, zone, owner, cur, owns, tombs, sel.RRsets, sel.Hosts, sel.Types)
	out := &uiapi.AdoptPreview{Zone: zone, Owner: owner, Candidates: make([]uiapi.AdoptCandidate, 0, len(cands)),
		PreviewToken: previewToken(zone, owner, cands)}
	for _, c := range cands {
		out.Candidates = append(out.Candidates, c.AdoptCandidate)
	}
	return out, nil
}

func (e *engine) AdoptMany(ctx context.Context, s *identity.Subject, zoneIn string, req uiapi.AdoptApply) (*uiapi.AdoptResult, error) {
	const action = "gate.adopt"
	ctx = WithRequestID(ctx, requestID(ctx))
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	if strings.TrimSpace(req.Comment) == "" {
		return nil, e.deny(ctx, s, action, zone, fail(ReasonInvalid, "a comment is required to adopt records"))
	}
	if len(req.RRsets) == 0 {
		return nil, e.deny(ctx, s, action, zone, fail(ReasonInvalid, "no RRsets to adopt"))
	}
	if !e.cfg.Authz.Allow(s, policy.ActionRecordAdopt, zone) {
		return nil, e.deny(ctx, s, action, zone, fail(ReasonForbidden, "not allowed to adopt in zone %s", zone))
	}
	owner, err := e.adoptOwner(s, zone, req.Owner)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	p, err := e.provider(zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	defer unlock()
	cur, err := e.fetch(ctx, p, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	sets := index(cur)
	e.resolvePending(ctx, zone, sets, owns)

	tokZone, tokOwner, hashes, ok := parsePreviewToken(req.PreviewToken)
	if !ok || tokZone != zone || tokOwner != owner {
		return nil, e.deny(ctx, s, action, zone, fail(ReasonAdoptConflict, "the preview token does not match this zone and owner; preview again"))
	}
	tombs, err := e.liveTombstones(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	var g grants
	cands := e.adoptCandidates(&g, s, p, zone, owner, cur, owns, tombs, req.RRsets, nil, nil)
	var conflicts []string
	for _, c := range cands {
		switch {
		case !c.Adoptable:
			conflicts = append(conflicts, keyString(c.key)+": "+c.Reason)
		case hashes[c.key] != c.hash[:16]:
			conflicts = append(conflicts, keyString(c.key)+": changed since the preview")
		}
	}
	if len(conflicts) > 0 {
		return nil, e.deny(ctx, s, action, zone, &Error{Reason: ReasonAdoptConflict,
			Message: "nothing adopted: " + strings.Join(conflicts, "; "), Details: conflicts})
	}

	now := e.now()
	rid := RequestID(ctx)
	type write struct {
		prev *store.Ownership
		next store.Ownership
	}
	writes := make([]write, 0, len(cands))
	for _, c := range cands {
		o, owned := owns[c.key]
		w := write{}
		if owned {
			prev := o
			w.prev = &prev
		} else {
			o = store.Ownership{Zone: zone, Host: c.key.Host, Type: c.key.Type, Owner: owner, CreatedAt: now,
				CreatedBy: s.String(), CreatedByName: s.Name, CreatedByCategory: s.Category}
		}
		o.State, o.ContentHash, o.PendingHash, o.Adopted, o.ExpiresAt = store.StateActive, c.hash, "", true, nil
		setActor(&o, s, rid, now)
		w.next = o
		writes = append(writes, w)
	}
	for i, w := range writes {
		if err := e.cfg.Store.Put(ctx, w.next); err != nil {
			for _, done := range writes[:i] {
				var rerr error
				if done.prev == nil {
					rerr = e.cfg.Store.Delete(ctx, zone, done.next.Host, done.next.Type, 1)
				} else {
					restored := *done.prev
					restored.Version = done.next.Version + 1
					rerr = e.cfg.Store.Put(ctx, restored)
				}
				if rerr != nil {
					e.log.Warn("adopt rollback failed", "zone", zone, "rrset", done.next.Host+" "+done.next.Type, "error", rerr)
				}
			}
			return nil, e.deny(ctx, s, action, zone, &Error{Reason: ReasonUpstream, Message: "store adopt failed", Err: err})
		}
	}
	for _, c := range cands {
		if _, ok := tombs[c.key]; ok {
			e.dropTombstone(ctx, zone, c.key)
		}
	}
	res := &uiapi.AdoptResult{Zone: zone, Owner: owner, Adopted: make([]uiapi.RRsetRef, 0, len(cands)), RequestID: rid}
	changes := make([]uiapi.Change, 0, len(cands))
	for _, c := range cands {
		set := sets[c.key]
		res.Adopted = append(res.Adopted, uiapi.RRsetRef{Host: c.key.Host, Type: c.key.Type})
		changes = append(changes, uiChange("adopt", c.key, nil, &set))
	}
	e.emit(ctx, s, action, zone, "allow", "", changes, "", g.extra(map[string]any{"comment": req.Comment, "owner": owner}))
	return res, nil
}
