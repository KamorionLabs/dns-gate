// Human-friendly durations: "1 h", "15 min", "10 s" instead of Go duration
// strings ("1h0m0s") or bare seconds.

const UNITS: [number, string][] = [
  [86400, 'd'],
  [3600, 'h'],
  [60, 'min'],
  [1, 's'],
];

/** Seconds as at most two units: 90 → "1 min 30 s", 86400 → "1 d", 0 → "0 s". */
export function humanSeconds(total: number): string {
  if (!Number.isFinite(total) || total < 0) return '';
  if (total > 0 && total < 1) return `${Math.round(total * 1000)} ms`;
  let rest = Math.round(total);
  const parts: string[] = [];
  for (const [size, unit] of UNITS) {
    if (rest >= size && parts.length < 2) {
      const n = Math.floor(rest / size);
      rest -= n * size;
      parts.push(`${n} ${unit}`);
    } else if (parts.length) break;
  }
  return parts.length ? parts.join(' ') : '0 s';
}

const GO_UNIT: Record<string, number> = { ns: 1e-9, us: 1e-6, 'µs': 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };

/** Seconds of a Go duration string ("1h30m", "15m", "500ms"), undefined when it does not parse. */
export function parseGoDuration(s: string): number | undefined {
  const t = s.trim();
  if (!t) return undefined;
  if (t === '0') return 0;
  const re = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/gy;
  let total = 0;
  let m: RegExpExecArray | null;
  let end = 0;
  while ((m = re.exec(t))) {
    total += Number(m[1]) * (GO_UNIT[m[2]!] ?? 0);
    end = re.lastIndex;
  }
  return end === t.length && end > 0 ? total : undefined;
}

/** A Go duration as text for people; the input itself when it does not parse. */
export function humanDuration(s: string | undefined): string {
  if (!s) return '';
  const secs = parseGoDuration(s);
  return secs === undefined ? s : humanSeconds(secs);
}
