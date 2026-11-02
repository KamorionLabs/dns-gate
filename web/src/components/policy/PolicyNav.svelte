<script lang="ts">
  import { policyHref } from '../../lib/router.svelte';
  import Icon from '../Icon.svelte';
  let { active, canPropose, pending = 0 }: { active: string; canPropose: boolean; pending?: number } = $props();
</script>

<nav class="pnav" aria-label="Policy">
  <a href={policyHref()} aria-current={active === 'overview' ? 'page' : undefined}><Icon name="shield" size={14} />Effective policy</a>
  {#if canPropose}<a href={policyHref('edit')} aria-current={active === 'edit' ? 'page' : undefined}><Icon name="doc" size={14} />Draft</a>{/if}
  <a href={policyHref('proposals')} aria-current={active === 'proposals' ? 'page' : undefined}>
    <Icon name="history" size={14} />Revisions{#if pending}<span class="count num">{pending}</span>{/if}
  </a>
  <a href={policyHref('simulate')} aria-current={active === 'simulate' ? 'page' : undefined}><Icon name="flask" size={14} />Simulator</a>
</nav>

<style>
  .pnav {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s1);
    margin-bottom: var(--s6);
    border-bottom: 1px solid var(--rule);
  }
  a {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: var(--s2) var(--s3);
    margin-bottom: -1px;
    border-bottom: 2px solid transparent;
    color: var(--ink-3);
    text-decoration: none;
    font-weight: 500;
  }
  a:hover {
    color: var(--ink);
  }
  a[aria-current='page'] {
    color: var(--ink);
    border-bottom-color: var(--seal-ink);
  }
  .count {
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: 9px;
    background: var(--brass-wash);
    color: var(--brass);
    font-size: 11px;
    font-weight: 600;
    display: inline-grid;
    place-items: center;
  }
</style>
