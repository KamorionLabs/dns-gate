import type { Category, ChangeOp, Decision, Status } from './types';

// One vocabulary for the whole console and the "How the gate works" guide.
// The API keeps its own values (managed, tainted, pending, foreign, missing).
export const statusLabel: Record<Status, string> = {
  managed: 'Managed',
  tainted: 'Drifted',
  pending: 'Pending',
  foreign: 'Not managed',
  missing: 'Missing',
};

export const statusHelp: Record<Status, string> = {
  managed: 'Managed by the gate: created or adopted through it, and changed only by the team that owns it.',
  tainted: 'Managed by the gate, but changed outside it. Writes on it are blocked until it is adopted again.',
  pending: 'Written by the gate, waiting for the next read of the zone to confirm it.',
  foreign: 'Not managed by the gate (read-only): it exists at the DNS provider and the gate leaves it untouched until someone adopts it.',
  missing: 'Managed by the gate, but deleted outside it.',
};

/** Record sets that need someone to look at them. */
export const needsAttention = (s: Status) => s === 'tainted' || s === 'missing' || s === 'pending';

export const categoryLabel: Record<Category, string> = {
  human: 'Human',
  pipeline: 'Pipeline',
  key: 'API key',
  system: 'Gate',
};

export const decisionLabel: Record<Decision, string> = {
  allow: 'Applied',
  deny: 'Refused',
  error: 'Failed',
};

export const opLabel: Record<ChangeOp, string> = {
  create: 'Created',
  update: 'Changed',
  delete: 'Deleted',
  adopt: 'Adopted',
  taint: 'Drift detected',
  expire: 'Expired',
  transfer: 'Transferred',
};

const reasons: Record<string, string> = {
  forbidden: 'Not allowed by policy (role scope or protected record)',
  foreign_rrset: 'Record is not managed by the gate',
  not_owner: 'Record is owned by another team',
  not_team_member: 'Not a member of the selected team',
  tainted: 'Record changed outside the gate',
  precondition: 'Zone changed since it was read (If-Match)',
  too_many_changes: 'Too many changes in one request',
  invalid_zone: 'Rejected by the DNS provider validation',
  zone_locked: 'Zone busy, lock not acquired in time',
  upstream: 'The DNS provider returned an error',
  zone_not_managed: 'Zone not managed by the gate',
  operation_denied: 'Operation not allowed through the gate',
  unauthenticated: 'Not signed in',
};

export const reasonLabel = (r: string | undefined) => (r ? (reasons[r] ?? r.replaceAll('_', ' ')) : '');

const actions: Record<string, string> = {
  saveDnsZone: 'Zone save',
  addDnsRecords: 'Add records',
  deleteDnsRecord: 'Delete record',
  checkDnsZone: 'Zone check',
  getDnsZone: 'Zone read',
  applyRRsets: 'Apply changes',
  adopt: 'Adoption',
  'gate.adopt': 'Adoption',
  'gate.taint': 'Drift check',
  'gate.expire': 'Expiry',
  reconcile: 'Reconcile',
  'mcp.list_zones': 'List zones',
  'mcp.list_rrsets': 'List record sets',
  'mcp.get_rrset': 'Read a record set',
  'mcp.search_audit': 'Search the journal',
  'mcp.explain': 'Explain a decision',
  'mcp.who_can': 'Who can',
  'mcp.plan_rrset_change': 'Plan a change',
  'mcp.apply_rrset_change': 'Apply a plan',
  'mcp.adopt_preview': 'Preview an adoption',
  'mcp.adopt_apply': 'Adoption',
  mcp: 'Assistant sign-in',
};

/** Readable action; MCP tools are marked as coming from an assistant. */
export const actionLabel = (a: string) => {
  const l = actions[a];
  if (l) return a.startsWith('mcp.') ? `${l} (assistant)` : l;
  return a.startsWith('mcp.') ? `${a.slice(4).replaceAll('_', ' ')} (assistant)` : a;
};

const adoptReasons: Record<string, string> = {
  protected: 'Protected by the base policy',
  server_managed: 'Managed by the DNS provider (SOA, name servers or locked record)',
  routing_policy: 'Uses a routing policy of the DNS provider',
  owned_by_other_team: 'Already owned by another team',
  already_owned: 'Already managed by the gate',
  forbidden: 'Outside your adoption scope',
  relative_target: 'Target is relative to the zone (no trailing dot): fix it at the DNS provider first',
};

export const adoptReasonLabel = (r: string | undefined) => (r ? (adoptReasons[r] ?? r.replaceAll('_', ' ')) : '');

const providers: Record<string, string> = { eurodns: 'EuroDNS', route53: 'Route53' };

/** Display name of a DNS provider: "route53" → "Route53". */
export const providerLabel = (p: string | undefined) => (p ? (providers[p.toLowerCase()] ?? p) : '');

// Refusals of a DNS write (plan or apply), for people who do not read reason codes.
const writeReasons: Record<string, string> = {
  precondition: 'Someone changed these records since you loaded the zone. Reload the zone, check your changes and review them again.',
  not_found: 'A record set you change no longer exists, or the zone is not managed by the gate.',
  forbidden: 'Your roles do not allow this change, or a record set is protected by the base policy.',
  not_owner: 'A record set you change belongs to another team: only that team can change it.',
  foreign_rrset: 'A record set with this name and type already exists and is not managed by the gate. Ask an administrator to adopt it, then edit it.',
  tainted: 'A record set was changed outside the gate. An administrator must adopt it again before it can be changed.',
  zone_locked: 'Another change is being written to this zone. Try again in a minute.',
  upstream: 'The DNS provider returned an error. Nothing was changed: try again later.',
  invalid: 'The gate rejected the request as invalid.',
  invalid_zone: 'The DNS provider rejected the change as invalid.',
  too_many_changes: 'Too many changes at once for your role. Apply them in smaller batches.',
  plan_expired: 'This review expired before it was applied. Review the changes again.',
  plan_not_found: 'This review is no longer valid. Review the changes again.',
  zone_not_managed: 'This zone is not managed by the gate.',
  reauth_required: 'Confirm your identity: you are sent to sign in again, your changes are kept.',
  read_only: 'A record set is read-only for the gate (managed by the provider, routing policy or locked).',
};

/** A write refusal in plain words; the gate message is added when it says more. */
export const writeReasonText = (reason: string | undefined) =>
  (reason && writeReasons[reason]) || 'The gate refused the change.';
