package zonewrite

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/store"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

// cached returns the cached zone, reading upstream only when the cache is
// empty or, when maxAge > 0, older than maxAge. Concurrent reads of the same
// zone share one upstream request.
func (e *engine) cached(ctx context.Context, zone string, maxAge time.Duration) (cachedZone, error) {
	if c, ok := e.peek(zone, maxAge); ok {
		return c, nil
	}
	_, err, _ := e.reads.Do(zone, func() (any, error) {
		if _, ok := e.peek(zone, maxAge); ok {
			return nil, nil
		}
		return e.fetch(context.WithoutCancel(ctx), zone)
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
	sets := rrset.Group(zone, c.zone.Records)
	synced := c.syncedAt
	inv := &uiapi.ZoneInventory{Zone: zone, LastSyncedAt: &synced}
	seen := map[rrset.Key]bool{}
	for key, set := range sets {
		r := uiapi.RRset{Host: key.Host, Type: key.Type, TTL: set.TTL, Values: append([]string(nil), set.Values...),
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
		r := uiapi.RRset{Host: key.Host, Type: key.Type, Status: uiapi.StatusMissing, Protected: e.cfg.Authz.IsProtected(zone, key)}
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
func statusOf(o store.Ownership, owned bool, set rrset.Set, present bool) string {
	switch {
	case !owned:
		return uiapi.StatusForeign
	case o.State == store.StatePending:
		return uiapi.StatusPending
	case !present:
		return uiapi.StatusMissing
	case o.State == store.StateTainted || rrset.ContentHash(set) != o.ContentHash:
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
	return inv, err
}

// unmanagedSummary describes a discovered zone from the cache only: listing
// zones never reads an unmanaged zone upstream.
func (e *engine) unmanagedSummary(zone string) uiapi.ZoneSummary {
	sum := uiapi.ZoneSummary{Zone: zone, Unmanaged: true}
	if c, ok := e.peek(zone, 0); ok {
		synced := c.syncedAt
		sum.LastSyncedAt = &synced
		n := len(rrset.Group(zone, c.zone.Records))
		sum.RRsets, sum.Foreign = n, n
	}
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
		sum := uiapi.ZoneSummary{Zone: zone, LastSyncedAt: inv.LastSyncedAt, LastWriteAt: e.lastWrite(ctx, zone, c.writeAt)}
		for _, r := range inv.RRsets {
			if r.Status != uiapi.StatusMissing {
				sum.RRsets++
			}
			switch r.Status {
			case uiapi.StatusManaged:
				sum.Managed++
			case uiapi.StatusTainted, uiapi.StatusMissing:
				sum.Tainted++
			case uiapi.StatusPending:
				sum.Pending++
			case uiapi.StatusForeign:
				sum.Foreign++
			}
		}
		out = append(out, sum)
	}
	for _, zone := range e.zones.UnmanagedZones() {
		if e.cfg.Authz.Allow(s, policy.ActionUIRead, zone) {
			out = append(out, e.unmanagedSummary(zone))
		}
	}
	return out, nil
}
