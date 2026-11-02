<script lang="ts">
  import Icon from '../Icon.svelte';
  let { layer, rev }: { layer: string; rev?: string } = $props();
</script>

{#if layer === 'base'}
  <span class="tag base" title="Base layer: loaded from the configuration file, not editable here"><Icon name="lock" size={11} />base</span>
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
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
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
  .rev {
    text-transform: none;
    letter-spacing: 0;
    font-weight: 500;
    font-size: 10.5px;
    opacity: 0.85;
  }
</style>
