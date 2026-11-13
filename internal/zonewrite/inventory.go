package zonewrite

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// cached returns the cached zone, reading upstream only when the cache is
// empty or, when maxAge > 0, older than maxAge. Concurrent reads of the same
// zone share one upstream request.
func (e *engine) cached(ctx context.Context, zone string, maxAge time.Duration) (cachedZone, error) {
	if c, ok := e.peek(zone, maxAge); ok {
		return c, nil
	}
	if e.unmanaged(zone) && e.knownNoZone(zone, true) {
		// Refused recently: not asked again before UnmanagedTTL.
		return cachedZone{}, noZoneError(zone, provider.ErrZoneNotFound)
	}
	_, err, _ := e.reads.Do(zone, func() (any, error) {
		if _, ok := e.peek(zone, maxAge); ok {
			return nil, nil
		}
		p, err := e.provider(zone)
		if err != nil {
			return nil, err
		}
		return e.fetch(context.WithoutCancel(ctx), p, zone)
	})
	if err != nil {
		return cachedZone{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return *e.cache[zone], nil
}

// peek returns the cached zone if present and fresh enough (any age when
// maxAge is 0).
func (e *engine) peek(zone string, maxAge time.Duration) (cachedZone, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.cache[zone]
	if !ok || c.zone == nil || (maxAge > 0 && e.now().Sub(c.syncedAt) > maxAge) {
		return cachedZone{}, false
	}
	return *c, true
}

func actor(subject, name, category string) *uiapi.Actor {
	if subject == "" {
		return nil
	}
	return &uiapi.Actor{Subject: subject, Name: name, Category: category}
}

func (e *engine) inventory(ctx context.Context, zone string, maxAge time.Duration) (*uiapi.ZoneInventory, cachedZone, error) {
	c, err := e.cached(ctx, zone, maxAge)
	if err != nil {
		return nil, c, err
	}
	owns, err := e.ownerships(ctx, zone)
	if err != nil {
		return nil, c, err
	}
	synced := c.syncedAt
	inv := &uiapi.ZoneInventory{Zone: zone, Provider: c.zone.Provider, LastSyncedAt: &synced}
	seen := map[dns.Key]bool{}
	for _, set := range c.zone.RRsets {
		key := set.Key
		r := uiapi.RRset{Host: key.Host, Type: key.Type, TTL: set.TTL, Values: append([]string{}, set.Values...),
			Alias: set.Alias, Forward: set.Forward, ReadOnly: readOnly(key, &set), Hash: dns.ContentHash(set),
			Status: uiapi.StatusForeign, Protected: e.cfg.Authz.IsProtected(zone, key)}
		o, owned := owns[key]
		if !owned {
			for ok, ov := range owns {
				if ok.Host == key.Host && strings.EqualFold(ok.Type, key.Type) {
					o, owned = ov, true
					key = ok
					break
				}
			}
		}
		if owned {
			seen[key] = true
			r.Status = statusOf(o, true, set, true)
			fillOwnership(&r, o)
		}
		inv.RRsets = append(inv.RRsets, r)
	}
	for key, o := range owns {
		if seen[key] {
			continue
		}
		r := uiapi.RRset{Host: key.Host, Type: key.Type, Values: []string{}, Status: uiapi.StatusMissing, Protected: e.cfg.Authz.IsProtected(zone, key)}
		if o.State == store.StatePending {
			r.Status = uiapi.StatusPending
		}
		fillOwnership(&r, o)
		inv.RRsets = append(inv.RRsets, r)
	}
	sort.Slice(inv.RRsets, func(i, j int) bool {
		if inv.RRsets[i].Host != inv.RRsets[j].Host {
			return inv.RRsets[i].Host < inv.RRsets[j].Host
		}
		return inv.RRsets[i].Type < inv.RRsets[j].Type
	})
	return inv, c, nil
}

// statusOf is the inventory status of an RRset.
func statusOf(o store.Ownership, owned bool, set dns.RRset, present bool) string {
	switch {
	case !owned:
		return uiapi.StatusForeign
	case o.State == store.StatePending:
		return uiapi.StatusPending
	case !present:
		return uiapi.StatusMissing
	case o.State == store.StateTainted || dns.ContentHash(set) != o.ContentHash:
		return uiapi.StatusTainted
	}
	return uiapi.StatusManaged
}

func fillOwnership(r *uiapi.RRset, o store.Ownership) {
	r.Owner, r.Adopted, r.LastRequestID = o.Owner, o.Adopted, o.RequestID
	r.CreatedBy = actor(o.CreatedBy, o.CreatedByName, o.CreatedByCategory)
	r.UpdatedBy = actor(o.UpdatedBy, o.UpdatedByName, o.UpdatedByCategory)
	if !o.CreatedAt.IsZero() {
		t := o.CreatedAt
		r.CreatedAt = &t
	}
	if !o.UpdatedAt.IsZero() {
		t := o.UpdatedAt
		r.UpdatedAt = &t
	}
	if o.ExpiresAt != nil {
		t := *o.ExpiresAt
		r.ExpiresAt = &t
	}
}

func (e *engine) Inventory(ctx context.Context, s *identity.Subject, zoneIn string) (*uiapi.ZoneInventory, error) {
	zone := normZone(zoneIn)
	if !e.zones.Managed(zone) && e.zones.IsUnmanaged(zone) {
		// Discovered, not managed: readable with dns.read, read on demand
		// and reused for UnmanagedTTL (no reconcile runs on these zones).
		if !e.cfg.Authz.Allow(s, policy.ActionDNSRead, zone) {
			return nil, fail(ReasonForbidden, "dns.read is required to view the unmanaged zone %s", zone)
		}
		inv, _, err := e.inventory(ctx, zone, e.cfg.UnmanagedTTL)
		if err != nil {
			return nil, err
		}
		inv.Unmanaged = true
		return inv, nil
	}
	zone, err := e.managed(zoneIn)
	if err != nil {
		return nil, err
	}
	if !e.cfg.Authz.Allow(s, policy.ActionUIRead, zone) {
		return nil, fail(ReasonForbidden, "not allowed to view zone %s", zone)
	}
	inv, _, err := e.inventory(ctx, zone, 0)
	if err != nil {
		return nil, err
	}
	e.addTombstones(ctx, inv)
	return inv, nil
}

// addTombstones lists the live tombstones of a managed zone in its
// inventory; a store failure leaves them out.
func (e *engine) addTombstones(ctx context.Context, inv *uiapi.ZoneInventory) {
	tombs, err := e.liveTombstones(ctx, inv.Zone)
	if err != nil {
		e.log.Warn("inventory tombstones", "zone", inv.Zone, "error", err)
		return
	}
	for _, t := range tombs {
		inv.Tombstones = append(inv.Tombstones, uiapi.Tombstone{
			Host: t.Host, Type: t.Type, Team: t.Team, DeletedBy: actor(t.DeletedBy, t.DeletedByName, t.DeletedByCategory),
			DeletedAt: t.DeletedAt, ExpiresAt: t.ExpiresAt,
		})
	}
	sort.Slice(inv.Tombstones, func(i, j int) bool {
		if inv.Tombstones[i].Host != inv.Tombstones[j].Host {
			return inv.Tombstones[i].Host < inv.Tombstones[j].Host
		}
		return inv.Tombstones[i].Type < inv.Tombstones[j].Type
	})
}

// unmanagedSummary describes a discovered zone from the cache only: listing
// zones never reads an unmanaged zone upstream. Its counts stay unknown (nil)
// until the zone has been read once; NoZone tells a read refused for lack of
// a DNS zone at the provider.
func (e *engine) unmanagedSummary(zone string) uiapi.ZoneSummary {
	sum := uiapi.ZoneSummary{Zone: zone, Provider: e.providerID(zone), Unmanaged: true}
	if c, ok := e.peek(zone, 0); ok {
		synced := c.syncedAt
		sum.LastSyncedAt = &synced
		n := len(c.zone.RRsets)
		sum.RRsets, sum.Foreign = uiapi.Count(n), uiapi.Count(n)
		sum.Managed, sum.Tainted, sum.Pending = uiapi.Count(0), uiapi.Count(0), uiapi.Count(0)
		return sum
	}
	sum.NoZone = e.knownNoZone(zone, false)
	return sum
}

func (e *engine) Zones(ctx context.Context, s *identity.Subject) ([]uiapi.ZoneSummary, error) {
	out := []uiapi.ZoneSummary{}
	for _, zone := range e.zones.ManagedZones() {
		if !e.cfg.Authz.Allow(s, policy.ActionUIRead, zone) {
			continue
		}
		inv, c, err := e.inventory(ctx, zone, 0)
		if err != nil {
			return nil, err
		}
		sum := uiapi.ZoneSummary{Zone: zone, Provider: inv.Provider, LastSyncedAt: inv.LastSyncedAt, LastWriteAt: e.lastWrite(ctx, zone, c.writeAt)}
		var total, managed, tainted, pending, foreign int
		for _, r := range inv.RRsets {
			if r.Status != uiapi.StatusMissing {
				total++
			}
			switch r.Status {
			case uiapi.StatusManaged:
				managed++
			case uiapi.StatusTainted, uiapi.StatusMissing:
				tainted++
			case uiapi.StatusPending:
				pending++
			case uiapi.StatusForeign:
				foreign++
			}
		}
		sum.RRsets, sum.Managed, sum.Tainted = uiapi.Count(total), uiapi.Count(managed), uiapi.Count(tainted)
		sum.Pending, sum.Foreign = uiapi.Count(pending), uiapi.Count(foreign)
		out = append(out, sum)
	}
	for _, zone := range e.zones.UnmanagedZones() {
		if e.cfg.Authz.Allow(s, policy.ActionUIRead, zone) {
			out = append(out, e.unmanagedSummary(zone))
		}
	}
	return out, nil
}

func (e *engine) RRset(ctx context.Context, s *identity.Subject, zoneIn string, key dns.Key) (*uiapi.RRset, error) {
	zone := normZone(zoneIn)
	var maxAge time.Duration
	switch {
	case e.zones.Managed(zone):
		if !e.cfg.Authz.Allow(s, policy.ActionDNSRead, zone) && !e.cfg.Authz.Allow(s, policy.ActionUIRead, zone) {
			return nil, fail(ReasonForbidden, "not allowed to read zone %s", zone)
		}
	case e.zones.IsUnmanaged(zone):
		if !e.cfg.Authz.Allow(s, policy.ActionDNSRead, zone) {
			return nil, fail(ReasonForbidden, "dns.read is required to read the unmanaged zone %s", zone)
		}
		maxAge = e.cfg.UnmanagedTTL
	default:
		return nil, fail(ReasonNotFound, "zone %s is not managed by this gate", zone)
	}
	key = dns.Key{Host: dns.NormalizeHost(key.Host, zone), Type: strings.ToUpper(strings.TrimSpace(key.Type))}
	c, err := e.cached(ctx, zone, maxAge)
	if err != nil {
		return nil, err
	}
	var set *dns.RRset
	for i := range c.zone.RRsets {
		if k := c.zone.RRsets[i].Key; k.Host == key.Host && strings.EqualFold(k.Type, key.Type) {
			set = &c.zone.RRsets[i]
			break
		}
	}
	o, err := e.cfg.Store.Get(ctx, zone, key.Host, key.Type)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, &Error{Reason: ReasonUpstream, Message: "store get failed", Err: err}
	}
	owned := err == nil
	if set == nil && !owned {
		return nil, fail(ReasonNotFound, "%s not found in %s", keyString(key), zone)
	}
	r := &uiapi.RRset{Host: key.Host, Type: key.Type, Values: []string{}, Status: uiapi.StatusForeign, Protected: e.cfg.Authz.IsProtected(zone, key)}
	if set != nil {
		r.TTL, r.Values, r.Alias, r.Forward = set.TTL, append([]string{}, set.Values...), set.Alias, set.Forward
		r.ReadOnly, r.Hash = readOnly(set.Key, set), dns.ContentHash(*set)
	}
	if owned {
		var cur dns.RRset
		if set != nil {
			cur = *set
		}
		r.Status = statusOf(*o, true, cur, set != nil)
		fillOwnership(r, *o)
	}
	return r, nil
}
