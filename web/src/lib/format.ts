const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 86400],
  ['month', 30 * 86400],
  ['week', 7 * 86400],
  ['day', 86400],
  ['hour', 3600],
  ['minute', 60],
];
const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'short' });
const abs = new Intl.DateTimeFormat('en-GB', {
  year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short',
});
const day = new Intl.DateTimeFormat('en-GB', { weekday: 'long', day: 'numeric', month: 'long' });
const hm = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' });

export function relative(iso: string | undefined, now: number): string {
  if (!iso) return '—';
  const diff = (new Date(iso).getTime() - now) / 1000;
  const a = Math.abs(diff);
  if (a < 45) return diff < 0 ? 'just now' : 'in a moment';
  for (const [unit, s] of units) {
    if (a >= s) return rtf.format(Math.round(diff / s), unit);
  }
  return rtf.format(Math.round(diff / 60), 'minute');
}

export const absolute = (iso: string | undefined) => (iso ? abs.format(new Date(iso)) : '');
export const dayLabel = (iso: string) => day.format(new Date(iso));
export const clockTime = (iso: string) => hm.format(new Date(iso));

export function ttl(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** Splits a relative host into its own label and the zone suffix for display. */
export function fqdn(host: string, zone: string): { name: string; suffix: string } {
  if (host === '@' || host === '') return { name: '@', suffix: zone };
  return { name: host, suffix: '.' + zone };
}
