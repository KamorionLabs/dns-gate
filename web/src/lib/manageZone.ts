// "Manage this zone": a policy proposal adding a discovered zone to the
// managed layer. It then goes through the usual approve and activate flow.
import { api, ApiError } from './api';
import type { Me, PolicyDocument, ValidationError } from './types';

/** Whether the user may propose policy revisions (policy.propose, base layer only). */
export const canPropose = (me: Me | null): boolean =>
  !!me?.permissions?.some((p) => p.actions.includes('policy.propose'));

export interface ManageOutcome {
  id?: string;
  error?: string;
  errors?: ValidationError[];
}

export async function proposeManagedZone(zone: string): Promise<ManageOutcome> {
  try {
    const p = await api.policy();
    if (!p.settings.editable) return { error: 'The managed policy layer is disabled in this deployment.' };
    const base: PolicyDocument = p.managed ?? { groups: {}, roles: {}, bindings: [], virtual_keys: [] };
    const zones = [...new Set([...(base.zones ?? []), zone])];
    const r = await api.propose({
      parent_id: p.active?.id ?? '',
      document: { ...base, zones },
      comment: `Manage zone ${zone}`,
    });
    return { id: r.id };
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.reason === 'reauth_required') return {};
      if (e.reason === 'stale_revision') return { error: 'The policy changed while the proposal was prepared. Try again.' };
      if (e.reason === 'invalid_policy') return { error: e.message, errors: e.errors };
      if (e.status === 403) return { error: 'You are not allowed to propose policy revisions.' };
    }
    return { error: (e as Error).message };
  }
}
