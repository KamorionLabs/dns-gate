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
  foreign: 'Not managed by the gate (read-only): it exists at EuroDNS and the gate leaves it untouched until someone adopts it.',
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
};

const reasons: Record<string, string> = {
  forbidden: 'Not allowed by policy (role scope or protected record)',
  foreign_rrset: 'Record is not managed by the gate',
  not_owner: 'Record is owned by another team',
  tainted: 'Record changed outside the gate',
  precondition: 'Zone changed since it was read (If-Match)',
  too_many_changes: 'Too many changes in one request',
  invalid_zone: 'Rejected by EuroDNS validation',
  zone_locked: 'Zone busy, lock not acquired in time',
  upstream: 'EuroDNS returned an error',
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
  server_managed: 'Managed by EuroDNS (SOA or locked record)',
  owned_by_other_team: 'Already owned by another team',
  already_owned: 'Already managed by the gate',
  forbidden: 'Outside your adoption scope',
  relative_target: 'Target is relative to the zone (no trailing dot): fix it at EuroDNS first',
};

export const adoptReasonLabel = (r: string | undefined) => (r ? (adoptReasons[r] ?? r.replaceAll('_', ' ')) : '');
