// "What does this binding allow" and "who can do what in this zone",
// resolved from the policy documents (base and managed layers).
import type { Binding, DelegatedOwner, EffectivePolicy, Permission, Role } from './types';
import { describePermissions } from './permissions';
import { zoneMatch } from './glob';

/** base: configuration file; managed: reviewed revisions; delegated: owned by a policy delegation. */
export type Layer = 'base' | 'managed' | 'delegated';

export interface LayeredBinding {
  layer: Layer;
  rev?: string;
  /** Name of a delegated binding. */
  name?: string;
  owner?: DelegatedOwner;
  binding: Binding;
}

/** Roles visible to a binding: base, managed and delegated roles. */
export function rolesOf(p: EffectivePolicy): Record<string, Role> {
  return { ...p.base.document.roles, ...(p.managed?.roles ?? {}), ...(p.managed?.delegated?.roles ?? {}) };
}

export function bindingsOf(p: EffectivePolicy): LayeredBinding[] {
  const rev = p.active?.id;
  return [
    ...p.base.document.bindings.map((binding) => ({ layer: 'base' as const, binding })),
    ...(p.managed?.bindings ?? []).map((binding) => ({ layer: 'managed' as const, rev, binding })),
    // Evaluated after the other managed bindings, sorted by name (as the gate does).
    ...Object.entries(p.managed?.delegated?.bindings ?? {})
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, binding]) => ({ layer: 'delegated' as const, rev, name, owner: binding.owner, binding })),
  ];
}

/** The rules of a role as permissions, optionally restricted to the rules covering zone. */
export function rolePermissions(roleName: string, role: Role | undefined, zone?: string): Permission[] {
  if (!role) return [];
  return role.rules
    .filter((r) => !zone || r.zones.some((z) => zoneMatch(z, zone)))
    .map((r) => ({
      role: roleName,
      zones: zone ? [zone] : r.zones,
      actions: r.actions,
      hosts: r.records?.hosts ?? [],
      types: r.records?.types ?? [],
    }));
}

/**
 * Plain sentences for what a binding allows. With a zone, only what applies
 * to that zone: policy.* grants are global and left out.
 */
export function bindingAllows(b: Binding, roles: Record<string, Role>, zone?: string): string[] {
  let perms = rolePermissions(b.role, roles[b.role], zone);
  if (zone) perms = perms.map((p) => ({ ...p, actions: p.actions.filter((a) => !a.startsWith('policy.')) })).filter((p) => p.actions.length);
  return describePermissions(perms);
}

export interface ZoneAccess {
  zone: string;
  entries: { lb: LayeredBinding; allows: string[] }[];
}

/** For each zone, the bindings whose role grants something there, with what they allow. */
export function whoCanDoWhat(p: EffectivePolicy, zones: string[]): ZoneAccess[] {
  const roles = rolesOf(p);
  const all = bindingsOf(p);
  return zones.map((zone) => ({
    zone,
    entries: all
      .map((lb) => ({ lb, allows: bindingAllows(lb.binding, roles, zone) }))
      .filter((e) => e.allows.length > 0),
  }));
}
