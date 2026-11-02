<script lang="ts">
  import type { Snippet } from 'svelte';
  import { policyState, forbidden } from '../../lib/policy.svelte';
  import PolicyNav from './PolicyNav.svelte';
  import type { EffectivePolicy } from '../../lib/types';

  let { tab, title, children }: { tab: string; title: string; children: Snippet<[EffectivePolicy]> } = $props();

  $effect(() => {
    policyState.load();
  });

  const p = $derived(policyState.data);
  const s = $derived(p?.settings);
</script>

<header class="head">
  <p class="eyebrow">Policy</p>
  <h1>{title}</h1>
  {#if s}
    <p class="meta">
      {#if !s.editable}Managed layer disabled: the policy comes from the configuration file only.
      {:else}
        {s.require_approval ? 'Every revision needs approval by another policy approver' : 'Revisions can be activated by their author'}
        · {`edits need a sign-in within ${s.edit_max_age}${s.require_amr?.length ? ' with ' + s.require_amr.join(', ').toUpperCase() : ''}`}
      {/if}
    </p>
  {/if}
</header>

{#if policyState.error}
  <div class="empty">
    {#if forbidden(policyState.error)}
      <strong>You cannot read the policy</strong>Ask a policy administrator for the policy.read action.
    {:else}
      <strong>The policy could not be loaded</strong>{policyState.error.message}
    {/if}
  </div>
{:else if p}
  <PolicyNav active={tab} canPropose={p.me.can_propose && p.settings.editable} pending={policyState.pending} />
  {@render children(p)}
{:else}
  <div class="skeleton bar"></div>
{/if}

<style>
  .head {
    display: grid;
    gap: var(--s2);
    margin-bottom: var(--s5);
  }
  h1 {
    font-size: var(--t-h2);
    letter-spacing: -0.015em;
  }
  .meta {
    color: var(--ink-3);
  }
  .bar {
    height: 120px;
  }
</style>
