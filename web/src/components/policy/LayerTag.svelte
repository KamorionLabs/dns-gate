<script lang="ts">
  import type { DelegatedOwner } from '../../lib/types';
  import Icon from '../Icon.svelte';
  let { layer, rev, owner }: { layer: string; rev?: string; owner?: DelegatedOwner } = $props();
</script>

{#if layer === 'base'}
  <span class="tag base" title="Base layer: loaded from the configuration file, not editable here"><Icon name="lock" size={12} />base</span>
{:else if layer === 'delegated'}
  <span
    class="tag delegated"
    title={`Delegated to ${owner?.delegation ?? 'a policy delegation'}${owner?.managed_by ? `, managed by ${owner.managed_by}` : ''}: changed by its owner, not through revisions${owner?.updated_by ? ` (last by ${owner.updated_by})` : ''}`}
  >delegated{#if owner}<span class="rev mono">{owner.delegation}{#if owner.managed_by} · {owner.managed_by}{/if}</span>{/if}</span>
{:else}
  <span class="tag managed" title="Managed layer: editable through reviewed revisions">managed{#if rev}<span class="rev mono">{rev}</span>{/if}</span>
{/if}

<style>
  .tag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 18px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.01em;
    white-space: nowrap;
    flex: none;
  }
  .base {
    color: var(--ink-3);
    box-shadow: inset 0 0 0 1px var(--rule-strong);
  }
  .managed {
    color: var(--seal-ink);
    background: var(--seal-ink-wash);
  }
  .delegated {
    color: var(--pencil);
    background: var(--pencil-wash);
  }
  .rev {
    text-transform: none;
    letter-spacing: 0;
    font-weight: 500;
    font-size: 11px;
    opacity: 0.85;
  }
</style>
