<script lang="ts">
  import { teamsHref, transfersHref } from '../../lib/router.svelte';
  import { inbox } from '../../lib/inbox.svelte';
  import Icon from '../Icon.svelte';
  let { active }: { active: 'teams' | 'transfers' } = $props();

  $effect(() => {
    void inbox.load();
  });
</script>

<nav class="tnav" aria-label="Teams">
  <a href={teamsHref()} aria-current={active === 'teams' ? 'page' : undefined}><Icon name="team" size={14} />Teams</a>
  <a href={transfersHref()} aria-current={active === 'transfers' ? 'page' : undefined} title="Ownership transfers between teams">
    <Icon name="transfer" size={14} />Transfers{#if inbox.count}<span class="count num" title="{inbox.count} waiting for your decision">{inbox.count}</span>{/if}
  </a>
</nav>

<style>
  .tnav {
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
