// Shapes journal entries for display: type changes read as one change, and
// reads can be told apart from writes.
import type { AuditEntry, Change } from './types';

/** A change as shown: a delete and a create of the same host in one request become one change of type. */
export interface ShownChange extends Change {
  /** Previous type when the request replaced the record set with another type. */
  old_type?: string;
}

/**
 * Merges, per host, a delete and a create of different types in the same
 * request (a zone save turning an A into a CNAME) into one update carrying
 * old_type. Other changes keep their order.
 */
export function mergeTypeChanges(changes: Change[]): ShownChange[] {
  const out: ShownChange[] = [];
  const used = new Set<number>();
  changes.forEach((c, i) => {
    if (used.has(i)) return;
    if (c.op === 'delete' || c.op === 'create') {
      const want = c.op === 'delete' ? 'create' : 'delete';
      const j = changes.findIndex(
        (d, k) => k !== i && !used.has(k) && d.op === want && d.host === c.host && d.type.toUpperCase() !== c.type.toUpperCase(),
      );
      if (j >= 0) {
        const del = c.op === 'delete' ? c : changes[j]!;
        const add = c.op === 'create' ? c : changes[j]!;
        used.add(i).add(j);
        out.push({
          op: 'update',
          host: add.host,
          type: add.type,
          old_type: del.type,
          old_ttl: del.old_ttl,
          old_values: del.old_values,
          new_ttl: add.new_ttl,
          new_values: add.new_values,
        });
        return;
      }
    }
    used.add(i);
    out.push(c);
  });
  return out;
}

// Successful requests that change nothing: lookups, searches and dry runs.
const READ_ACTIONS = new Set([
  'mcp.list_zones',
  'mcp.list_rrsets',
  'mcp.get_rrset',
  'mcp.search_audit',
  'mcp.explain',
  'mcp.who_can',
  'mcp.plan_rrset_change',
  'mcp.adopt_preview',
  'mcp.transfer_list',
  'checkDnsZone',
  'checkZoneProfile',
  'zone_profile.get',
  'zone_profile.list',
  'zone_profile.check',
  'mcp.check_zone_profile',
]);

/** Whether an entry is a successful read or dry run (hidden by default in the journal). */
export function isRead(e: AuditEntry): boolean {
  if (e.decision !== 'allow' || e.changes?.length) return false;
  return READ_ACTIONS.has(e.action) || /^(mcp\.)?(get|list|search)[A-Z_]/.test(e.action);
}
