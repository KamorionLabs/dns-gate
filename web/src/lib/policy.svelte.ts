import { api, ApiError } from './api';
import type { EffectivePolicy } from './types';

// Shared, refreshable view of GET /api/v1/policy and the pending count.
class PolicyState {
  data = $state<EffectivePolicy | null>(null);
  error = $state<ApiError | Error | null>(null);
  pending = $state(0);
  private loading: Promise<void> | null = null;

  load(force = false): Promise<void> {
    if (this.loading && !force) return this.loading;
    this.loading = (async () => {
      try {
        this.data = await api.policy();
        this.error = null;
        const page = await api.revisions({ status: 'proposed', limit: 50 });
        const approved = await api.revisions({ status: 'approved', limit: 50 });
        this.pending = page.revisions.length + approved.revisions.length;
      } catch (e) {
        this.error = e as Error;
      }
    })();
    return this.loading;
  }
}

export const policyState = new PolicyState();

export const forbidden = (e: unknown) => e instanceof ApiError && e.status === 403;
