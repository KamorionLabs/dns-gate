// Display helpers of the DNS propagation panel.
import type { Me, PlanChange, Propagation, PropagationAnswer, PropagationStatus } from './types';
import { hostMatch } from './glob';
import { ruleCovers } from './folders';

/** Refresh period of a running check, and how long it keeps refreshing. */
export const POLL_MS = 5_000;
export const POLL_FOR_MS = 120_000;

export const statusText: Record<PropagationStatus, string> = {
  match: 'Up to date',
  stale: 'Old answer',
  missing: 'No record',
  error: 'No answer',
  indeterminate: 'Not comparable',
};

export const statusHelp: Record<PropagationStatus, string> = {
  match: 'Answers the content read from the DNS provider.',
  stale: 'Answers other values: usually the previous content, cached until its TTL runs out.',
  missing: 'Answers that the name or the type does not exist, possibly a cached negative answer.',
  error: 'Did not answer usefully (timeout, refusal, server failure, filtered): not counted against propagation.',
  indeterminate: 'Alias: the addresses could not be tied to the target (a CDN answers per location). Not counted as up to date.',
};

const REGIONS: Record<string, string> = {
  anycast: 'Anycast resolvers',
  europe: 'Europe',
  'north-america': 'North America',
  'south-america': 'South America',
  asia: 'Asia',
  oceania: 'Oceania',
  africa: 'Africa',
};
const ORDER = ['anycast', 'europe', 'north-america', 'south-america', 'asia', 'oceania', 'africa'];

export function regionLabel(region: string | undefined): string {
  if (!region) return 'Other resolvers';
  return REGIONS[region] ?? region.charAt(0).toUpperCase() + region.slice(1).replace(/-/g, ' ');
}

export interface AnswerGroup {
  key: string;
  label: string;
  note?: string;
  answers: PropagationAnswer[];
}

/** Authoritative name servers first, then the resolvers by region, in a fixed order. */
export function groupAnswers(answers: PropagationAnswer[]): AnswerGroup[] {
  const groups = new Map<string, AnswerGroup>();
  const auth = answers.filter((a) => a.kind === 'authoritative');
  if (auth.length) groups.set('authoritative', { key: 'authoritative', label: 'Authoritative name servers', answers: auth });
  const rank = (r: string) => (ORDER.includes(r) ? ORDER.indexOf(r) : ORDER.length);
  const regions = [...new Set(answers.filter((a) => a.kind !== 'authoritative').map((a) => a.region ?? ''))].sort(
    (a, b) => rank(a) - rank(b) || a.localeCompare(b),
  );
  for (const r of regions) {
    groups.set('region:' + r, {
      key: 'region:' + r,
      label: regionLabel(r),
      note: r === 'anycast' ? 'answer from their site nearest to the gate' : undefined,
      answers: answers.filter((a) => a.kind !== 'authoritative' && (a.region ?? '') === r),
    });
  }
  return [...groups.values()];
}

/** Whether a running check asks again: not converged yet, for at most POLL_FOR_MS. */
export function keepPolling(p: Propagation | null, startedAt: number, now: number): boolean {
  return now - startedAt < POLL_FOR_MS && !p?.summary.converged;
}

/** "14 of 19 up to date" over the servers that answered; errors are counted apart. */
export function summaryLine(p: Propagation): string {
  const s = p.summary;
  const answered = s.total - s.error;
  const parts = [`${s.match} of ${answered} up to date`];
  if (s.indeterminate) parts.push(`${s.indeterminate} not comparable`);
  if (s.error) parts.push(`${s.error} without answer`);
  return parts.join(' · ');
}

/** What a check right after an apply expects: the hash written, or no record after a deletion. */
export function expectOf(c: Pick<PlanChange, 'op' | 'new_hash'>): string | undefined {
  return c.op === 'delete' ? 'absent' : c.new_hash;
}

/** Whether the user holds dns.read on the record set (unknown permissions: assume yes, the gate decides). */
export function canCheckPropagation(me: Me | null, zone: string, host: string, type: string): boolean {
  if (!me) return false;
  if (!me.permissions) return true;
  return me.permissions.some(
    (p) =>
      p.actions.includes('dns.read') &&
      ruleCovers(p, zone) &&
      (p.hosts.length === 0 || p.hosts.some((h) => hostMatch(h, host))) &&
      (p.types.length === 0 || p.types.includes('*') || p.types.includes(type)),
  );
}

/** What the answers are compared with. */
export function expectedLine(p: Propagation): string {
  const e = p.expected;
  if (!e.exists) return 'No record: the record set does not exist';
  if (e.alias_target) return `Addresses of ${e.alias_target}`;
  return e.values.join(', ');
}

/** "Paris · FR", "Anycast · US". */
export function placeLine(a: PropagationAnswer): string {
  return [a.location, a.country].filter(Boolean).join(' · ');
}
