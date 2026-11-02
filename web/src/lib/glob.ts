/** Claim glob: "*" matches any run of characters. */
export function claimMatch(pattern: string, value: string): boolean {
  const re = new RegExp('^' + pattern.split('*').map(escape).join('.*') + '$');
  return re.test(value);
}

/** Host glob (DNS labels): "*" is one label, "**" one or more, "@" the apex. */
export function hostMatch(pattern: string, host: string): boolean {
  const p = pattern.split('.');
  const h = host === '@' ? ['@'] : host.split('.');
  const go = (i: number, j: number): boolean => {
    if (i === p.length) return j === h.length;
    const seg = p[i];
    if (seg === '**') {
      for (let k = j + 1; k <= h.length; k++) if (go(i + 1, k)) return true;
      return false;
    }
    if (j >= h.length) return false;
    const label = h[j] ?? '';
    return (seg === '*' ? label !== '@' : claimMatch(seg ?? '', label)) && go(i + 1, j + 1);
  };
  return go(0, 0);
}

export function zoneMatch(pattern: string, zone: string): boolean {
  return claimMatch(pattern, zone);
}

function escape(s: string): string {
  return s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}
