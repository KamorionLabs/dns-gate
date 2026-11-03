// Editable form model of a managed PolicyDocument (maps become ordered lists
// so names can be renamed in place).
import type { PolicyDocument, SubjectMatcher } from './types';

export interface EClaim {
  key: string;
  values: string[];
}
export interface EMatcher {
  issuer: string;
  claims: EClaim[];
}
export interface EGroup {
  uid: number;
  name: string;
  description: string;
  members: EMatcher[];
}
export interface ERule {
  zones: string[];
  actions: string[];
  hosts: string[];
  types: string[];
}
export interface ERole {
  uid: number;
  name: string;
  description: string;
  rules: ERule[];
  rebase_on_save: boolean;
  ephemeral_ttl: string;
  max_changes: string;
}
export interface EBinding {
  uid: number;
  role: string;
  /** fixed: team below; claim: team derived from a claim (team_from). */
  team_mode: 'fixed' | 'claim';
  team: string;
  tf_claim: string;
  tf_regex: string;
  tf_prefix: string;
  groups: string[];
  subjects: EMatcher[];
}
export interface EKey {
  uid: number;
  id: string;
  app_id: string;
  key_sha256: string;
  description: string;
  roles: string[];
  teams: string[];
  expires: string; // yyyy-mm-dd or ''
  cidrs: string[];
}
export interface EModel {
  zones: string[];
  groups: EGroup[];
  roles: ERole[];
  bindings: EBinding[];
  keys: EKey[];
}

let uid = 0;
export const nextUid = () => ++uid;

const toEMatcher = (m: SubjectMatcher): EMatcher => ({
  issuer: m.issuer,
  claims: Object.entries(m.claims ?? {}).map(([key, values]) => ({ key, values: [...values] })),
});

const fromEMatcher = (m: EMatcher): SubjectMatcher => {
  const claims: Record<string, string[]> = {};
  for (const c of m.claims) if (c.key.trim() && c.values.length) claims[c.key.trim()] = c.values;
  return Object.keys(claims).length ? { issuer: m.issuer, claims } : { issuer: m.issuer };
};

export function fromDoc(d: PolicyDocument | undefined): EModel {
  const doc = d ?? { groups: {}, roles: {}, bindings: [], virtual_keys: [] };
  return {
    zones: [...(doc.zones ?? [])],
    groups: Object.entries(doc.groups).map(([name, g]) => ({
      uid: nextUid(), name, description: g.description ?? '', members: g.members.map(toEMatcher),
    })),
    roles: Object.entries(doc.roles).map(([name, r]) => ({
      uid: nextUid(),
      name,
      description: r.description ?? '',
      rules: r.rules.map((x) => ({ zones: [...x.zones], actions: [...x.actions], hosts: [...(x.records?.hosts ?? [])], types: [...(x.records?.types ?? [])] })),
      rebase_on_save: !!r.rebase_on_save,
      ephemeral_ttl: r.ephemeral_ttl ?? '',
      max_changes: r.max_changes_per_request ? String(r.max_changes_per_request) : '',
    })),
    bindings: doc.bindings.map((b) => ({
      uid: nextUid(),
      role: b.role,
      team_mode: b.team_from ? ('claim' as const) : ('fixed' as const),
      team: b.team,
      tf_claim: b.team_from?.claim ?? 'sub',
      tf_regex: b.team_from?.regex ?? '',
      tf_prefix: b.team_from?.prefix ?? '',
      groups: [...(b.groups ?? [])],
      subjects: (b.subjects ?? []).map(toEMatcher),
    })),
    keys: doc.virtual_keys.map((k) => ({
      uid: nextUid(),
      id: k.id,
      app_id: k.app_id,
      key_sha256: k.key_sha256,
      description: k.description ?? '',
      roles: [...k.roles],
      teams: [...k.teams],
      expires: k.expires_at ? k.expires_at.slice(0, 10) : '',
      cidrs: [...(k.allowed_cidrs ?? [])],
    })),
  };
}

export function toDoc(m: EModel): PolicyDocument {
  const doc: PolicyDocument = { groups: {}, roles: {}, bindings: [], virtual_keys: [] };
  const zones = [...new Set(m.zones.map((z) => z.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean))];
  if (zones.length) doc.zones = zones;
  for (const g of m.groups) {
    doc.groups[g.name.trim()] = {
      ...(g.description.trim() ? { description: g.description.trim() } : {}),
      members: g.members.map(fromEMatcher),
    };
  }
  for (const r of m.roles) {
    doc.roles[r.name.trim()] = {
      ...(r.description.trim() ? { description: r.description.trim() } : {}),
      rules: r.rules.map((x) => ({
        zones: x.zones,
        actions: x.actions,
        ...(x.hosts.length || x.types.length
          ? { records: { ...(x.hosts.length ? { hosts: x.hosts } : {}), ...(x.types.length ? { types: x.types } : {}) } }
          : {}),
      })),
      ...(r.rebase_on_save ? { rebase_on_save: true } : {}),
      ...(r.ephemeral_ttl.trim() ? { ephemeral_ttl: r.ephemeral_ttl.trim() } : {}),
      ...(Number(r.max_changes) > 0 ? { max_changes_per_request: Number(r.max_changes) } : {}),
    };
  }
  doc.bindings = m.bindings.map((b) => ({
    role: b.role,
    team: b.team_mode === 'claim' ? '' : b.team.trim(),
    ...(b.team_mode === 'claim'
      ? { team_from: { claim: b.tf_claim.trim(), regex: b.tf_regex, ...(b.tf_prefix.trim() ? { prefix: b.tf_prefix.trim() } : {}) } }
      : {}),
    ...(b.groups.length ? { groups: b.groups } : {}),
    ...(b.subjects.length ? { subjects: b.subjects.map(fromEMatcher) } : {}),
  }));
  doc.virtual_keys = m.keys.map((k) => ({
    id: k.id.trim(),
    app_id: k.app_id,
    key_sha256: k.key_sha256,
    ...(k.description.trim() ? { description: k.description.trim() } : {}),
    roles: k.roles,
    teams: k.teams,
    ...(k.expires ? { expires_at: new Date(k.expires + 'T23:59:59Z').toISOString() } : {}),
    ...(k.cidrs.length ? { allowed_cidrs: k.cidrs } : {}),
  }));
  return doc;
}
