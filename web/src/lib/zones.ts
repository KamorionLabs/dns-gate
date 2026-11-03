// Zone summaries in plain words, shared by the zones page and a zone page.
import type { ZoneSummary } from './types';

/** A managed zone needs attention when record sets drifted or wait for confirmation. */
export const zoneNeedsAttention = (z: ZoneSummary) => !z.unmanaged && (z.tainted > 0 || z.pending > 0);

/** "16 managed · 1535 not managed": only the counts that are not zero. */
export function managedSplit(z: Pick<ZoneSummary, 'managed' | 'foreign'>): string {
  const parts: string[] = [];
  if (z.managed) parts.push(`${z.managed.toLocaleString('en')} managed`);
  if (z.foreign) parts.push(`${z.foreign.toLocaleString('en')} not managed`);
  return parts.join(' · ') || 'No record sets';
}

export const plural = (n: number, one: string, many = one + 's') => `${n.toLocaleString('en')} ${n === 1 ? one : many}`;

/** A sync older than this is reported on the home page. */
export const STALE_SYNC_MS = 30 * 60_000;

export const zoneFilters = ['all', 'managed', 'unmanaged', 'attention'] as const;
export type ZoneFilter = (typeof zoneFilters)[number];
