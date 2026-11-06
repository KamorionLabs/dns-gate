package zonewrite

import (
	"context"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

// tombstone reserves a deleted RRset for its team. o is the ownership entry
// of the delete claim: its actor is the subject that deleted it. Ephemeral
// RRsets (ACME challenges) leave no tombstone.
func (e *engine) tombstone(ctx context.Context, o store.Ownership) {
	if e.cfg.TombstoneTTL <= 0 || o.ExpiresAt != nil || o.Owner == "" {
		return
	}
	now := e.now()
	t := store.Tombstone{
		Zone: o.Zone, Host: o.Host, Type: o.Type, Team: o.Owner, ContentHash: o.ContentHash,
		DeletedBy: o.UpdatedBy, DeletedByName: o.UpdatedByName, DeletedByCategory: o.UpdatedByCategory,
		DeletedAt: now, ExpiresAt: now.Add(e.cfg.TombstoneTTL), RequestID: o.RequestID,
	}
	if err := e.cfg.Store.PutTombstone(ctx, t); err != nil {
		e.log.Warn("tombstone failed", "zone", o.Zone, "rrset", o.Host+" "+o.Type, "error", err)
	}
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
