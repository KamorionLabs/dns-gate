<script lang="ts">
  import type { Me, ValidationError } from '../lib/types';
  import { canPropose, proposeManagedZone } from '../lib/manageZone';
  import { proposalHref } from '../lib/router.svelte';
  import { policyState } from '../lib/policy.svelte';
  import Icon from './Icon.svelte';

  // Action (policy admins) or hint (everyone else) to bring a discovered zone
  // under management through a reviewed policy revision.
  let { zone, me, compact = false }: { zone: string; me: Me | null; compact?: boolean } = $props();

  let busy = $state(false);
  let error = $state<string | null>(null);
  let errors = $state<ValidationError[]>([]);

  const admin = $derived(canPropose(me));

  async function manage() {
    busy = true;
    error = null;
    errors = [];
    const r = await proposeManagedZone(zone);
    busy = false;
    if (r.id) {
      void policyState.load(true);
      window.location.hash = proposalHref(r.id);
      return;
    }
    error = r.error ?? null;
    errors = r.errors ?? [];
  }
</script>

<div class="manage" class:compact>
  {#if admin}
    <button class="btn primary" type="button" disabled={busy} onclick={manage}>
      <Icon name="shield" size={13} />{busy ? 'Preparing proposal…' : 'Manage this zone'}
    </button>
    {#if !compact}
      <p class="hint">Creates a policy proposal adding {zone} to the managed zones. Once another approver approves it and it is activated, the zone behaves like any managed zone and its records can be adopted.</p>
    {/if}
  {:else}
    <p class="hint">
      <Icon name="lock" size={12} />
      Only a policy administrator (policy.propose) can bring this zone under management. Once a revision adding it is approved and activated, it behaves like any managed zone.
    </p>
  {/if}
  {#if error}
    <div class="err" role="alert">
      <b>{error}</b>
      {#if errors.length}<ul>{#each errors as e, i (i)}<li><span class="mono">{e.path || 'document'}</span> {e.message}</li>{/each}</ul>{/if}
    </div>
  {/if}
</div>

<style>
  .manage {
    display: grid;
    gap: var(--s2);
    justify-items: start;
  }
  .manage.compact {
    justify-items: end;
  }
  .hint {
    display: flex;
    align-items: baseline;
    gap: 6px;
    margin: 0;
    color: var(--ink-3);
    font-size: 12.5px;
    max-width: 60ch;
  }
  .compact .hint {
    font-size: 12px;
    text-align: right;
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .btn.primary:hover {
    border-color: transparent;
    filter: brightness(1.08);
  }
  .err {
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--wax-wash);
    color: var(--wax);
    font-size: 12.5px;
  }
  .err ul {
    margin: var(--s1) 0 0;
    padding-left: var(--s4);
  }
</style>
