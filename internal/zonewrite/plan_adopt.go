package zonewrite

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

// Adoption refusal reasons (uiapi.AdoptCandidate.Reason).
const (
	adoptProtected     = "protected"
	adoptServerManaged = "server_managed"
	adoptOtherTeam     = "owned_by_other_team"
	adoptAlreadyOwned  = "already_owned"
	adoptForbidden     = "forbidden"
	adoptRelative      = "relative_target"
	adoptNotFound      = "not_found"
)

const defaultTTL = 3600

func refKey(zone string, r uiapi.RRsetRef) rrset.Key {
	return rrset.Key{Host: rrset.NormalizeHost(r.Host, zone), Type: strings.ToUpper(strings.TrimSpace(r.Type))}
}

func uiChanges(changes []zonediff.Change) []uiapi.Change {
	out := make([]uiapi.Change, 0, len(changes))
	for _, c := range changes {
		out = append(out, uiChange(string(c.Op), c.Key, c.Old, c.New))
	}
	return out
}

// rrsetPlan turns desired RRset states into changes against the current sets.
func rrsetPlan(zone string, sets map[rrset.Key]rrset.Set, changes []uiapi.RRsetChange) (*plan, error) {
	p := &plan{}
	seen := map[rrset.Key]bool{}
	for _, c := range changes {
		key := refKey(zone, uiapi.RRsetRef{Host: c.Host, Type: c.Type})
		if key.Type == "" {
			return nil, fail(ReasonInvalid, "type is required for host %q", c.Host)
		}
		if seen[key] {
			return nil, fail(ReasonInvalid, "%s appears twice in the request", keyString(key))
		}
		seen[key] = true
		old, exists := sets[key]
		if c.Delete || len(c.Values) == 0 {
			if exists {
				o := old
				p.changes = append(p.changes, zonediff.Change{Op: zonediff.OpDelete, Key: key, Old: &o})
			}
			continue
		}
		ttl := c.TTL
		if ttl == 0 {
			ttl = defaultTTL
			if exists {
				ttl = old.TTL
			}
		}
		if !slices.Contains(eurodns.AllowedTTLs, ttl) {
			return nil, fail(ReasonInvalid, "%s: TTL %d is not accepted by EuroDNS (allowed: %v)", keyString(key), ttl, eurodns.AllowedTTLs)
		}
		values := slices.Clone(c.Values)
		sort.Strings(values)
		values = slices.Compact(values)
		n := &rrset.Set{Key: key, TTL: ttl, Values: values}
		if !exists {
			p.changes = append(p.changes, zonediff.Change{Op: zonediff.OpCreate, Key: key, New: n})
			continue
		}
		if old.TTL == ttl && slices.Equal(old.Values, values) {
			continue
		}
		o := old
		p.changes = append(p.changes, zonediff.Change{Op: zonediff.OpUpdate, Key: key, Old: &o, New: n})
	}
	sort.Slice(p.changes, func(i, j int) bool { return keyString(p.changes[i].Key) < keyString(p.changes[j].Key) })
	return p, nil
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
	if !e.cfg.Authz.Allow(s, policy.ActionRecordWrite, zone) {
		return refuse(fail(ReasonForbidden, "not allowed to write in zone %s", zone))
	}
	cur, err := e.fetch(ctx, zone)
	if err != nil {
		return nil, err
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, err
	}
	p, err := rrsetPlan(zone, userSets(zone, cur.Records), changes)
	if err != nil {
		return refuse(err)
	}
	res.Changes = uiChanges(p.changes)
	if len(p.changes) == 0 {
		res.Allowed = true
		return res, nil
	}
	if _, err := e.validate(ctx, s, zone, cur, owns, p, true); err != nil {
		return refuse(err)
	}
	if e.cfg.CheckOnWrite {
		checked, err := e.cfg.Client.CheckZone(ctx, zone, zonediff.Apply(zone, cur, p.changes))
		if err != nil {
			return refuse(upstreamError("check zone", err))
		}
		changed := map[rrset.Key]bool{}
		for _, c := range p.changes {
			changed[c.Key] = true
		}
		if checked != nil {
			if problems := blockingProblems(zone, checked.Report, changed); len(problems) > 0 {
				return refuse(fail(ReasonInvalid, "EuroDNS validation: %s", strings.Join(problems, "; ")))
			}
		}
	}
	res.Allowed = true
	return res, nil
}

func parseETag(tag string) int64 {
	var v int64
	_, _ = fmt.Sscanf(strings.TrimPrefix(tag, "W/"), "\"v%d\"", &v)
	return v
}

func (e *engine) ApplyRRsets(ctx context.Context, s *identity.Subject, zoneIn string, changes []uiapi.RRsetChange, expectedZoneVersion int64) (*uiapi.PlanResult, error) {
	var applied []zonediff.Change
	z, err := e.mutate(ctx, s, zoneIn, etag(expectedZoneVersion), "applyRRsets", func(_ *eurodns.Zone, sets map[rrset.Key]rrset.Set) (*plan, error) {
		p, err := rrsetPlan(normZone(zoneIn), sets, changes)
		if err == nil {
			applied = p.changes
		}
		return p, err
	})
	if err != nil {
		return nil, err
	}
	return &uiapi.PlanResult{Zone: normZone(zoneIn), Allowed: true, Changes: uiChanges(applied), ZoneVersion: parseETag(z.ETag)}, nil
}

type adoptCandidate struct {
	uiapi.AdoptCandidate
	key  rrset.Key
	hash string
}

// adoptCandidates evaluates the selected RRsets: explicit refs first, then
// filter matches over user RRsets (everything when nothing is selected).
func (e *engine) adoptCandidates(s *identity.Subject, zone string, cur *eurodns.Zone, owns map[rrset.Key]store.Ownership,
	refs []uiapi.RRsetRef, hosts, types []string) []adoptCandidate {
	all := rrset.Group(zone, cur.Records)
	managed := managedKeys(zone, cur.Records)
	var keys []rrset.Key
	picked := map[rrset.Key]bool{}
	pick := func(k rrset.Key) {
		if !picked[k] {
			picked[k] = true
			keys = append(keys, k)
		}
	}
	for _, r := range refs {
		pick(refKey(zone, r))
	}
	if len(hosts) > 0 || len(types) > 0 || len(refs) == 0 {
		user := userSets(zone, cur.Records)
		var filtered []rrset.Key
		for k := range user {
			hostOK := len(hosts) == 0 || slices.ContainsFunc(hosts, func(h string) bool { return rrset.MatchHost(rrset.NormalizeHost(h, zone), k.Host) })
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
		c.TTL, c.Values, c.hash = set.TTL, slices.Clone(set.Values), rrset.ContentHash(set)
		o, owned := owns[k]
		c.Status = statusOf(o, owned, set, true)
		switch {
		case managed[k] || k.Type == "SOA":
			c.Reason = adoptServerManaged
		case e.cfg.Authz.IsProtected(zone, k):
			c.Reason = adoptProtected
		case owned && !slices.Contains(s.Teams, o.Owner):
			c.Reason = adoptOtherTeam
		case owned && o.State != store.StateTainted:
			c.Reason = adoptAlreadyOwned
		case !e.cfg.Authz.AllowRRset(s, policy.ActionRecordAdopt, zone, k):
			c.Reason = adoptForbidden
		case len(relativeTargets(zonediff.Change{Key: k, New: &set})) > 0:
			c.Reason = adoptRelative
		default:
			c.Adoptable = true
		}
		out = append(out, c)
	}
	return out
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

func parsePreviewToken(tok string) (zone, owner string, hashes map[rrset.Key]string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return "", "", nil, false
	}
	parts := strings.Split(string(raw), "\n")
	if len(parts) < 2 {
		return "", "", nil, false
	}
	hashes = map[rrset.Key]string{}
	for _, l := range parts[2:] {
		f := strings.Split(l, "\t")
		if len(f) != 3 {
			continue
		}
		hashes[rrset.Key{Host: f[0], Type: f[1]}] = f[2]
	}
	return parts[0], parts[1], hashes, true
}

func (e *engine) adoptOwner(s *identity.Subject, zone, owner string) (string, error) {
	if owner != "" {
		return owner, nil
	}
	team, ok := e.cfg.Authz.OwnerTeam(s, zone)
	if !ok {
		return "", fail(ReasonForbidden, "no owner team for %s in %s", s.String(), zone)
	}
	return team, nil
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
	cur, err := e.fetch(ctx, zone)
	if err != nil {
		return nil, err
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, err
	}
	cands := e.adoptCandidates(s, zone, cur, owns, sel.RRsets, sel.Hosts, sel.Types)
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
	unlock, err := e.lock(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	defer unlock()
	cur, err := e.fetch(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, e.deny(ctx, s, action, zone, err)
	}
	e.resolvePending(ctx, zone, userSets(zone, cur.Records), owns)

	tokZone, tokOwner, hashes, ok := parsePreviewToken(req.PreviewToken)
	if !ok || tokZone != zone || tokOwner != owner {
		return nil, e.deny(ctx, s, action, zone, fail(ReasonAdoptConflict, "the preview token does not match this zone and owner; preview again"))
	}
	cands := e.adoptCandidates(s, zone, cur, owns, req.RRsets, nil, nil)
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
	sets := rrset.Group(zone, cur.Records)
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
	res := &uiapi.AdoptResult{Zone: zone, Owner: owner, Adopted: make([]uiapi.RRsetRef, 0, len(cands)), RequestID: rid}
	changes := make([]uiapi.Change, 0, len(cands))
	for _, c := range cands {
		set := sets[c.key]
		res.Adopted = append(res.Adopted, uiapi.RRsetRef{Host: c.key.Host, Type: c.key.Type})
		changes = append(changes, uiChange("adopt", c.key, nil, &set))
	}
	e.emit(ctx, s, action, zone, "allow", "", changes, nil, map[string]any{"comment": req.Comment, "owner": owner})
	return res, nil
}
