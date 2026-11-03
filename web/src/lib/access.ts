// "What does this binding allow" and "who can do what in this zone",
// resolved from the policy documents (base and managed layers).
import type { Binding, EffectivePolicy, Permission, Role } from './types';
import { describePermissions } from './permissions';
import { zoneMatch } from './glob';

export interface LayeredBinding {
  layer: 'base' | 'managed';
  rev?: string;
  binding: Binding;
}

/** Roles visible to a binding of the managed layer: base roles and managed roles. */
export function rolesOf(p: EffectivePolicy): Record<string, Role> {
  return { ...p.base.document.roles, ...(p.managed?.roles ?? {}) };
}

export function bindingsOf(p: EffectivePolicy): LayeredBinding[] {
  return [
    ...p.base.document.bindings.map((binding) => ({ layer: 'base' as const, binding })),
    ...(p.managed?.bindings ?? []).map((binding) => ({ layer: 'managed' as const, rev: p.active?.id, binding })),
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
