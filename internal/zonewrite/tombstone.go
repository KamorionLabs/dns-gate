package zonewrite

import (
	"context"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

// deleteOwned removes the ownership entry of a deleted RRset and, unless
// tombstones are disabled or the RRset was ephemeral (ACME challenges),
// writes its tombstone in the same store transaction: if the tombstone
// cannot be written the entry stays, pending, and the next reconcile
// retries. o is the entry of the delete claim: its actor is the subject
// that deleted the RRset.
func (e *engine) deleteOwned(ctx context.Context, o store.Ownership) error {
	if e.cfg.TombstoneTTL <= 0 || o.ExpiresAt != nil || o.Owner == "" || o.ContentHash == "" {
		return e.cfg.Store.Delete(ctx, o.Zone, o.Host, o.Type, o.Version)
	}
	now := e.now()
	t := store.Tombstone{
		Zone: o.Zone, Host: o.Host, Type: o.Type, Team: o.Owner, ContentHash: o.ContentHash,
		DeletedBy: o.UpdatedBy, DeletedByName: o.UpdatedByName, DeletedByCategory: o.UpdatedByCategory,
		DeletedAt: now, ExpiresAt: now.Add(e.cfg.TombstoneTTL), RequestID: o.RequestID,
	}
	return e.cfg.Store.DeleteWithTombstone(ctx, o.Zone, o.Host, o.Type, o.Version, t)
}

func (e *engine) dropTombstone(ctx context.Context, zone string, k dns.Key) {
	if err := e.cfg.Store.DeleteTombstone(ctx, zone, k.Host, k.Type); err != nil {
		e.log.Warn("tombstone removal failed", "zone", zone, "rrset", keyString(k), "error", err)
	}
}

// liveTombstones returns the unexpired tombstones of a zone, none when
// tombstones are disabled.
func (e *engine) liveTombstones(ctx context.Context, zone string) (map[dns.Key]store.Tombstone, error) {
	out := map[dns.Key]store.Tombstone{}
	if e.cfg.TombstoneTTL <= 0 {
		return out, nil
	}
	list, err := e.cfg.Store.ListTombstones(ctx, zone)
	if err != nil {
		return nil, &Error{Reason: ReasonUpstream, Message: "store tombstones failed", Err: err}
	}
	now := e.now()
	for _, t := range list {
		if now.Before(t.ExpiresAt) {
			out[dns.Key{Host: t.Host, Type: t.Type}] = t
		}
	}
	return out, nil
}
