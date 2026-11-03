import type { Category, ChangeOp, Decision, Status } from './types';

export const statusLabel: Record<Status, string> = {
  managed: 'Managed',
  tainted: 'Drifted',
  pending: 'Pending',
  foreign: 'Foreign',
  missing: 'Missing',
};

export const statusHelp: Record<Status, string> = {
  managed: 'Created or adopted by the gate: the only records it changes, and only for the team that owns them.',
  tainted: 'Changed outside the gate. Writes on it are blocked until it is re-adopted.',
  pending: 'Written by the gate, waiting for the next read of the zone to confirm it.',
  foreign: 'Exists at EuroDNS, but the gate leaves it untouched until someone adopts it.',
  missing: 'Owned by the gate but gone from the zone (deleted outside the gate).',
};

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
  foreign_rrset: 'Record exists but was not created by the gate',
  not_owner: 'Record is owned by another team',
  tainted: 'Record changed outside the gate',
  precondition: 'Zone changed since it was read (If-Match)',
  too_many_changes: 'Too many changes in one request',
  invalid_zone: 'Rejected by EuroDNS validation',
  zone_locked: 'Zone busy, lock not acquired in time',
  upstream: 'EuroDNS returned an error',
};

export const reasonLabel = (r: string | undefined) => (r ? (reasons[r] ?? r.replaceAll('_', ' ')) : '');

const actions: Record<string, string> = {
  saveDnsZone: 'Zone save',
  addDnsRecords: 'Add records',
  deleteDnsRecord: 'Delete record',
  checkDnsZone: 'Zone check',
  adopt: 'Adoption',
  reconcile: 'Reconcile',
};

export const actionLabel = (a: string) => actions[a] ?? a;

const adoptReasons: Record<string, string> = {
  protected: 'Protected by the base policy',
  server_managed: 'Managed by EuroDNS (SOA or locked record)',
  owned_by_other_team: 'Already owned by another team',
  already_owned: 'Already held by the gate',
  forbidden: 'Outside your adoption scope',
  relative_target: 'Target is relative to the zone (no trailing dot): fix it in the registrar console first',
};

export const adoptReasonLabel = (r: string | undefined) => (r ? (adoptReasons[r] ?? r.replaceAll('_', ' ')) : '');
