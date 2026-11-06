<script lang="ts">
  import { api } from '../lib/api';
  import type { Me, Transfer, TransferStatus } from '../lib/types';
  import { router } from '../lib/router.svelte';
  import TeamsNav from '../components/teams/TeamsNav.svelte';
  import TransferItem from '../components/teams/TransferItem.svelte';
  import { renameRule } from '../lib/teams';

  const tabs: { key: TransferStatus | ''; label: string }[] = [
    { key: 'proposed', label: 'Waiting for approval' },
    { key: 'applying', label: 'Being applied' },
    { key: 'applied', label: 'Applied' },
    { key: 'rejected', label: 'Rejected' },
    { key: 'failed', label: 'Failed' },
    { key: 'expired', label: 'Expired' },
    { key: '', label: 'All' },
  ];
  const raw = $derived(router.params.get('status') ?? 'proposed');
  const status = $derived((raw === 'all' ? '' : raw) as TransferStatus | '');
  const zone = $derived(router.params.get('zone') ?? '');

  let list = $state<Transfer[] | null>(null);
  let next = $state<string | undefined>(undefined);
  let error = $state<string | null>(null);
  let me = $state<Me | null>(null);
  let more = $state(false);

  $effect(() => {
    api.me().then((m) => (me = m)).catch(() => (me = null));
  });

  $effect(() => {
    const q = { status: status || undefined, zone: zone || undefined, limit: 50 };
    list = null;
    error = null;
    api
      .transfers(q)
      .then((p) => {
        list = p.transfers;
        next = p.next_cursor;
      })
      .catch((e: Error) => (error = e.message));
  });

  async function loadMore() {
    if (!next) return;
    more = true;
    try {
      const p = await api.transfers({ status: status || undefined, zone: zone || undefined, limit: 50, cursor: next });
      list = [...(list ?? []), ...p.transfers];
      next = p.next_cursor;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      more = false;
    }
  }

  // The requests the user may decide come first in the inbox.
  const shown = $derived(status === 'proposed' && list ? [...list.filter((t) => t.can_decide), ...list.filter((t) => !t.can_decide)] : (list ?? []));
  const mine = $derived(list?.filter((t) => t.can_decide).length ?? 0);
</script>

<header class="head">
  <p class="eyebrow">Teams</p>
  <h1>Ownership transfers</h1>
  <p class="meta">
    Moving record sets to another team takes two people: someone asks, then another person approves who, for every record set of the request, may
    write it through the roles of the owner team or holds dns.ownership.approve on it. Nobody approves their own request, even under another
    identity, and only people approve, not pipelines. A team rename needs {renameRule}.
  </p>
</header>

<TeamsNav active="transfers" />

<div class="toolbar">
  <div class="tabs" role="tablist" aria-label="Transfer status">
    {#each tabs as t (t.key)}
      <button role="tab" type="button" aria-selected={status === t.key} onclick={() => router.setParams({ status: t.key === 'proposed' ? undefined : t.key || 'all' })}>{t.label}</button>
    {/each}
  </div>
  {#if zone}
    <span class="zf">Zone <span class="mono">{zone}</span> <button class="btn quiet small" type="button" onclick={() => router.setParams({ zone: undefined })}>Show every zone</button></span>
  {/if}
</div>

{#if error}
  <div class="empty"><strong>Transfers could not be loaded</strong>{error}</div>
{:else if !list}
  <div class="skeleton bar"></div>
{:else if list.length === 0}
  <div class="empty">
    <strong>Nothing here</strong>
    {status === 'proposed' ? 'No transfer is waiting for approval. Ask for one from a zone: select record sets of a team, then Transfer.' : 'No transfer with this status.'}
  </div>
{:else}
  {#if status === 'proposed'}
    <p class="lead">{mine ? `${mine} waiting for your decision.` : 'None of them waits for your decision.'}</p>
  {/if}
  <ol class="list">
    {#each shown as t (t.id)}<TransferItem {t} {me} />{/each}
  </ol>
  {#if next}<button class="btn more" type="button" disabled={more} onclick={loadMore}>{more ? 'Loading…' : 'Show older transfers'}</button>{/if}
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
    max-width: 80ch;
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s3);
    margin-bottom: var(--s4);
  }
  .tabs {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    border-radius: var(--r-lg);
    background: var(--well);
    border: 1px solid var(--rule-soft);
  }
  .tabs button {
    height: 28px;
    padding: 0 12px;
    border: 0;
    border-radius: 7px;
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    font-weight: 500;
  }
  .tabs button[aria-selected='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .zf {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--ink-2);
  }
  .btn.small {
    height: 26px;
    padding: 0 var(--s2);
    font-size: 12px;
  }
  .lead {
    color: var(--ink-2);
    margin-bottom: var(--s2);
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--rule);
    max-width: 980px;
  }
  .more {
    margin-top: var(--s4);
  }
  .bar {
    height: 200px;
  }
</style>
