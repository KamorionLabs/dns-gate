// The simple view of the policy: who (a group, an identity or an API key) may
// do what, in plain words, resolved from the bindings of every layer.
import type { Binding, EffectivePolicy, Issuer, Role, SubjectMatcher } from './types';
import { bindingsOf, rolesOf, type Layer } from './access';
import { serviceConnectionName, pipelineName } from './identity';
import { zoneMatch } from './glob';

export type AudienceKind = 'people' | 'pipeline' | 'key';

/** One write grant: which records, where, with which verbs. */
export interface WriteGrant {
  zones: string[];
  hosts: string[];
  types: string[];
  /** Can create, change and delete records it owns. */
  write: boolean;
  /** Can take over records created outside the gate. */
  adopt: boolean;
}

export interface Audience {
  id: string;
  kind: AudienceKind;
  /** Main label, e.g. "Gate.Operator" or "corporate-cloudfront-prd". */
  title: string;
  /** What the title stands for, e.g. "Entra ID app role". */
  subtitle: string;
  /** Who is in it, in plain words (members of a group, the identity itself). */
  members: string[];
  /** Zones it can see ("*" for all). */
  read: string[];
  writes: WriteGrant[];
  /** Policy rights in plain words. */
  policy: string[];
  teams: string[];
  roles: string[];
  layers: Layer[];
}

const policyVerbs: [string, string][] = [
  ['policy.read', 'see the policy'],
  ['policy.propose', 'propose changes'],
  ['policy.approve', 'approve changes'],
];

const issuerKind = (issuers: Issuer[], name: string): AudienceKind => {
  const c = issuers.find((i) => i.name === name)?.category;
  return c === 'human' ? 'people' : 'pipeline';
};

/** A subject matcher in plain words. */
export function memberLabel(m: SubjectMatcher): string {
  const claims = Object.entries(m.claims ?? {});
  if (!claims.length) return `anyone signed in with ${m.issuer}`;
  return claims
    .map(([k, vs]) => {
      const v = vs.map((x) => serviceConnectionName(x) ?? pipelineName(x) ?? x).join(' or ');
      if (k === 'roles') return `${m.issuer} app role ${v}`;
      if (k === 'groups') return `${m.issuer} group ${v}`;
      if (['preferred_username', 'upn', 'email'].includes(k)) return v;
      if (k === 'sub' && vs.some((x) => serviceConnectionName(x))) return `pipeline ${v}`;
      if (k === 'sub') return v;
      return `${k} ${v}`;
    })
    .join(', ');
}

/** Title of a group named after what it maps to, when it maps to one app role or group. */
function groupTitle(name: string, members: SubjectMatcher[]): { title: string; subtitle: string } {
  const only = members.length === 1 ? members[0] : undefined;
  const claims = Object.entries(only?.claims ?? {});
  if (only && claims.length === 1) {
    const [k, vs] = claims[0]!;
    if (k === 'roles' && vs.length === 1) return { title: vs[0]!, subtitle: `${only.issuer} app role · group ${name}` };
    if (k === 'groups' && vs.length === 1) return { title: name, subtitle: `${only.issuer} group ${vs[0]}` };
  }
  return { title: name, subtitle: 'group of ' + members.map(memberLabel).join(', ') };
}

function subjectTitle(m: SubjectMatcher): { title: string; subtitle: string } {
  const sub = m.claims?.sub ?? [];
  const sc = sub.map((s) => serviceConnectionName(s)).find(Boolean);
  if (sc) return { title: sc.replace(/^eurodns-gate-/, ''), subtitle: `${m.issuer} pipeline · ${sc}` };
  const pn = sub.map((s) => pipelineName(s)).find(Boolean);
  if (pn) return { title: pn, subtitle: `${m.issuer} pipeline` };
  return { title: memberLabel(m), subtitle: `${m.issuer} identity` };
}

const key = (w: WriteGrant) => [w.hosts.join(','), w.types.join(','), w.write, w.adopt].join('|');

/** Merges the write grants that cover the same records, so each line lists its zones once. */
function mergeWrites(ws: WriteGrant[]): WriteGrant[] {
  const by = new Map<string, WriteGrant>();
  for (const w of ws) {
    const k = key(w);
    const cur = by.get(k);
    if (cur) cur.zones = [...new Set([...cur.zones, ...w.zones])];
    else by.set(k, { ...w, zones: [...w.zones] });
  }
  return [...by.values()];
}

function grant(a: Audience, b: Binding, role: Role | undefined, layer: Layer) {
  a.roles.push(b.role);
  a.teams.push(b.team || (b.team_from ? `per ${b.team_from.claim}` : ''));
  a.layers.push(layer);
  for (const r of role?.rules ?? []) {
    if (r.actions.includes('dns.read') || r.actions.includes('ui.read')) a.read.push(...r.zones);
    const write = r.actions.includes('dns.record.write');
    const adopt = r.actions.includes('dns.record.adopt');
    if (write || adopt) a.writes.push({ zones: r.zones, hosts: r.records?.hosts ?? [], types: r.records?.types ?? [], write, adopt });
    for (const [act, verb] of policyVerbs) if (r.actions.includes(act)) a.policy.push(verb);
  }
}

const finish = (a: Audience): Audience => ({
  ...a,
  read: a.read.includes('*') ? ['*'] : [...new Set(a.read)].sort(),
  writes: mergeWrites(a.writes),
  policy: policyVerbs.map(([, v]) => v).filter((v) => a.policy.includes(v)),
  teams: [...new Set(a.teams.filter(Boolean))],
  roles: [...new Set(a.roles)],
  layers: [...new Set(a.layers)],
});

const kindOrder: Record<AudienceKind, number> = { people: 0, pipeline: 1, key: 2 };

/** Every audience of the effective policy with what it may do. */
export function audiencesOf(p: EffectivePolicy): Audience[] {
  const roles = rolesOf(p);
  const groups = { ...p.base.document.groups, ...(p.managed?.groups ?? {}) };
  const out = new Map<string, Audience>();
  const get = (id: string, init: () => Omit<Audience, 'read' | 'writes' | 'policy' | 'teams' | 'roles' | 'layers'>) => {
    let a = out.get(id);
    if (!a) out.set(id, (a = { ...init(), read: [], writes: [], policy: [], teams: [], roles: [], layers: [] }));
    return a;
  };
  for (const { binding: b, layer } of bindingsOf(p)) {
    for (const g of b.groups ?? []) {
      const members = groups[g]?.members ?? [];
      const kinds = new Set(members.map((m) => issuerKind(p.base.issuers, m.issuer)));
      const kind: AudienceKind = kinds.has('people') ? 'people' : 'pipeline';
      const a = get('group:' + g, () => ({ id: 'group:' + g, kind, ...groupTitle(g, members), members: members.map(memberLabel) }));
      grant(a, b, roles[b.role], layer);
    }
    for (const m of b.subjects ?? []) {
      const id = 'subject:' + JSON.stringify(m);
      const a = get(id, () => ({ id, kind: issuerKind(p.base.issuers, m.issuer), ...subjectTitle(m), members: [memberLabel(m)] }));
      grant(a, b, roles[b.role], layer);
    }
  }
  const keys = [
    ...p.base.document.virtual_keys.map((k) => ({ k, layer: 'base' as const })),
    ...(p.managed?.virtual_keys ?? []).map((k) => ({ k, layer: 'managed' as const })),
  ];
  for (const { k, layer } of keys) {
    const a = get('key:' + k.id, () => ({ id: 'key:' + k.id, kind: 'key', title: k.description || k.app_id, subtitle: `API key ${k.app_id}`, members: [] }));
    k.roles.forEach((r, i) => grant(a, { role: r, team: k.teams[i] ?? k.teams[0] ?? '' }, roles[r], layer));
  }
  return [...out.values()].map(finish).sort((x, y) => kindOrder[x.kind] - kindOrder[y.kind] || x.title.localeCompare(y.title));
}

/** The audience restricted to one zone; undefined when it can do nothing there. */
export function inZone(a: Audience, zone: string): Audience | undefined {
  const writes = a.writes.filter((w) => w.zones.some((z) => zoneMatch(z, zone))).map((w) => ({ ...w, zones: [zone] }));
  const read = a.read.some((z) => zoneMatch(z, zone)) ? [zone] : [];
  if (!writes.length && !read.length) return undefined;
  return { ...a, read, writes };
}

export interface ZoneGrants {
  /** A zone, or "*" for every zone. */
  zone: string;
  grants: Omit<WriteGrant, 'zones'>[];
}

/** The write grants of an audience, one entry per zone ("*" first), each with what it may change there. */
export function writesByZone(a: Audience): ZoneGrants[] {
  const by = new Map<string, Omit<WriteGrant, 'zones'>[]>();
  for (const { zones, ...g } of a.writes) for (const z of zones) by.set(z, [...(by.get(z) ?? []), g]);
  return [...by.entries()]
    .sort(([x], [y]) => (x === '*' ? -1 : y === '*' ? 1 : x.localeCompare(y)))
    .map(([zone, grants]) => ({ zone, grants }));
}

/** "any name", "@ (the domain)", "validation names (_…)", or the list. */
export function hostsText(hosts: string[]): string {
  if (!hosts.length || hosts.includes('**')) return 'any name';
  const valid = hosts.every((h) => h.startsWith('_'));
  if (valid) return 'validation names (_…)';
  return hosts.map((h) => (h === '@' ? '@ (the domain)' : h)).join(', ');
}

export function typesText(types: string[]): string {
  return !types.length || types.includes('*') ? 'any type' : types.join(', ');
}
