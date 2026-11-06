// Whether the signed-in user may change a record set, computed from /me and
// the inventory so the console only offers what the gate would accept. The
// gate stays the authority: it checks everything again at plan and apply.
import type { Me, RRset } from './types';
import { hostMatch } from './glob';
import { ruleCovers } from './folders';

export const WRITE = 'dns.record.write';

export type Blocker =
  | 'zone_unmanaged'
  | 'server_managed'
  | 'routing_policy'
  | 'locked'
  | 'read_only'
  | 'alias'
  | 'protected'
  | 'foreign'
  | 'tainted'
  | 'missing'
  | 'pending'
  | 'not_owner'
  | 'forbidden'
  | 'unsupported_type';

export type Verdict = { ok: true } | { ok: false; why: Blocker; text: string };

/** Types the console can edit; others (SOA, NS, PTR, provider types) are shown read-only. */
export const EDITABLE_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA'];

/** Whether a rule of the user grants writes on this name and type (unknown permissions: assume yes, the gate decides). */
export function rbacAllows(me: Me | null, zone: string, host: string, type: string): boolean {
  if (!me?.permissions) return true;
  return me.permissions.some(
    (p) =>
      p.actions.includes(WRITE) &&
      ruleCovers(p, zone) &&
      (p.hosts.length === 0 || p.hosts.some((h) => hostMatch(h, host))) &&
      (p.types.length === 0 || p.types.includes('*') || p.types.includes(type)),
  );
}

/** Whether the user may write anything in the zone: decides whether "Add record" is offered. */
export function canWriteZone(me: Me | null, zone: string): boolean {
  if (!me) return false;
  if (!me.permissions) return true;
  return me.permissions.some((p) => p.actions.includes(WRITE) && ruleCovers(p, zone));
}

/** Record types the user may create in the zone (some rule may restrict hosts further). */
export function writableTypes(me: Me | null, zone: string): string[] {
  if (!me?.permissions) return EDITABLE_TYPES;
  const rules = me.permissions.filter((p) => p.actions.includes(WRITE) && ruleCovers(p, zone));
  return EDITABLE_TYPES.filter((t) => rules.some((p) => p.types.length === 0 || p.types.includes('*') || p.types.includes(t)));
}

/** Host patterns the user may write in the zone for a type; empty list: any host. */
export function writableHosts(me: Me | null, zone: string, type: string): string[] {
  if (!me?.permissions) return [];
  const rules = me.permissions.filter(
    (p) => p.actions.includes(WRITE) && ruleCovers(p, zone) && (p.types.length === 0 || p.types.includes('*') || p.types.includes(type)),
  );
  if (rules.some((p) => p.hosts.length === 0)) return [];
  return [...new Set(rules.flatMap((p) => p.hosts))];
}

const readOnlyText: Record<string, string> = {
  server_managed: 'Managed by the DNS provider itself (SOA, name servers or a locked record): nobody changes it through the gate.',
  routing_policy: 'Uses a routing policy (weighted, latency, failover or geolocation): the gate does not edit these, change it at the provider.',
  locked: 'Locked at the DNS provider: unlock it there first.',
};

export const blockerText: Record<Blocker, string> = {
  zone_unmanaged: 'This zone is not managed by the gate: it is shown read-only.',
  server_managed: readOnlyText.server_managed!,
  routing_policy: readOnlyText.routing_policy!,
  locked: readOnlyText.locked!,
  read_only: 'The gate does not write this record set.',
  alias: 'An alias of the DNS provider: shown with its target, edited at the provider (or in Terraform).',
  protected: 'Protected by the base policy: no role can change it through the gate.',
  foreign: 'Not managed by the gate: it must be adopted by an administrator before anyone can change it here.',
  tainted: 'Changed outside the gate (drifted): writes are blocked until an administrator adopts it again.',
  missing: 'Deleted outside the gate: an administrator must review it before it can be written again.',
  pending: 'A change is being confirmed: wait for the next read of the zone (a few minutes).',
  not_owner: 'Owned by another team: only that team can change it.',
  forbidden: 'Your roles do not allow changing this record set.',
  unsupported_type: 'This type of record cannot be edited from the console.',
};

const no = (why: Blocker, text = blockerText[why]): Verdict => ({ ok: false, why, text });

/** Whether the user may edit or delete a record set, with the first reason why not. */
export function canChange(me: Me | null, zone: string, rr: RRset, unmanaged = false): Verdict {
  if (unmanaged) return no('zone_unmanaged');
  if (rr.read_only) {
    const known = rr.read_only === 'server_managed' || rr.read_only === 'routing_policy' || rr.read_only === 'locked';
    return known ? no(rr.read_only as Blocker) : no('read_only', `The gate does not write this record set (${rr.read_only.replaceAll('_', ' ')}).`);
  }
  if (rr.protected) return no('protected');
  if (rr.status === 'foreign') return no('foreign');
  if (rr.status === 'tainted') return no('tainted');
  if (rr.status === 'missing') return no('missing');
  if (rr.status === 'pending') return no('pending');
  if (rr.alias) return no('alias');
  if (!EDITABLE_TYPES.includes(rr.type)) return no('unsupported_type');
  if (!me) return no('forbidden');
  if (rr.owner && !me.teams.includes(rr.owner)) return no('not_owner', `Owned by team ${rr.owner}: only that team can change it.`);
  if (!rbacAllows(me, zone, rr.host, rr.type)) return no('forbidden');
  return { ok: true };
}

/** A short label for a read-only record set, shown in the table. */
export function readOnlyLabel(rr: RRset): string | null {
  if (rr.read_only === 'server_managed') return 'Provider';
  if (rr.read_only === 'routing_policy') return 'Routing policy';
  if (rr.read_only === 'locked') return 'Locked';
  if (rr.read_only) return 'Read-only';
  return null;
}
