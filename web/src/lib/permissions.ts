// Plain sentences for the effective permissions of /api/v1/me.
import type { Permission } from './types';

const recordVerbs: [string, string][] = [
  ['dns.read', 'read'],
  ['dns.record.write', 'write'],
  ['dns.record.adopt', 'adopt'],
];

const meta: Record<string, string> = {
  'policy.read': 'View the policy and simulate decisions',
  'policy.propose': 'Propose policy revisions',
  'policy.approve': 'Approve policy revisions',
};

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function list(items: string[]): string {
  if (items.length < 2) return items.join('');
  return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
}

function where(zones: string[]): string {
  if (zones.includes('*')) return 'every zone';
  const exact = zones.filter((z) => !/[*?]/.test(z));
  const globs = zones.filter((z) => /[*?]/.test(z));
  return list([...exact, ...(globs.length ? ['zones matching ' + globs.join(', ')] : [])]);
}

function what(p: Permission): string {
  const types = p.types.filter((t) => t !== '*');
  const hosts = p.hosts.filter((h) => h !== '**');
  return (types.length ? types.join(', ') + ' records' : 'records') + (hosts.length ? ' matching ' + hosts.join(', ') : '');
}

/** One sentence per grant, deduplicated, record grants before policy grants. */
export function describePermissions(perms: Permission[]): string[] {
  const zone: string[] = [];
  const policy: string[] = [];
  for (const p of perms) {
    const scoped = p.hosts.length > 0 || p.types.some((t) => t !== '*');
    const verbs = recordVerbs.filter(([a]) => p.actions.includes(a)).map(([, v]) => v);
    const at = where(p.zones);
    if (verbs.length === 1 && verbs[0] === 'read' && !scoped) zone.push(`Read ${at}`);
    else if (verbs.length) zone.push(`${capital(list(verbs))} ${what(p)} in ${at}`);
    else if (p.actions.includes('ui.read')) zone.push(`Browse ${at} in this console`);
    if (p.actions.includes('dns.zone.admin')) zone.push(`Manage DNSSEC and zone settings of ${at}`);
    if (p.actions.includes('domain.read')) zone.push(`Read domain details of ${at}`);
    if (p.actions.includes('gate.apikey.manage')) zone.push(`Manage the API keys of your teams for ${at}`);
    for (const a of p.actions) if (meta[a]) policy.push(meta[a]);
  }
  return [...new Set([...zone, ...policy])];
}
