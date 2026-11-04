<script lang="ts">
  import { identityLabel } from '../lib/identity';
  import { api } from '../lib/api';
  import type { RevisionSummary } from '../lib/types';
  import { router, proposalHref } from '../lib/router.svelte';
  import { policyState } from '../lib/policy.svelte';
  import PolicyFrame from '../components/policy/PolicyFrame.svelte';
  import RevisionBadge from '../components/policy/RevisionBadge.svelte';
  import ActorChip from '../components/ActorChip.svelte';
  import RelTime from '../components/RelTime.svelte';
  import Icon from '../components/Icon.svelte';

  const tabs = [
    { key: 'proposed', label: 'Awaiting review' },
    { key: 'approved', label: 'Approved' },
    { key: 'active', label: 'Active' },
    { key: 'superseded', label: 'History' },
    { key: 'rejected', label: 'Rejected' },
    { key: '', label: 'All' },
  ];
  const raw = $derived(router.params.get('status') ?? 'proposed');
  const status = $derived(raw === 'all' ? '' : raw);

  let list = $state<RevisionSummary[] | null>(null);
  let error = $state<string | null>(null);
  let busy = $state<string | null>(null);

  $effect(() => {
    const s = status;
    list = null;
    api
      .revisions({ status: s || undefined, limit: 50 })
      .then((p) => (list = p.revisions))
      .catch((e: Error) => (error = e.message));
  });

  const activeId = $derived(policyState.data?.active?.id);
  const stale = (r: RevisionSummary) => (r.status === 'proposed' || r.status === 'approved') && !!activeId && r.parent_id !== activeId;

  async function rollback(id: string) {
    busy = id;
    try {
      const r = await api.rollback(id);
      await policyState.load(true);
      window.location.hash = proposalHref(r.id);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      busy = null;
    }
  }
</script>

<PolicyFrame tab="proposals" title="Revisions of the managed policy">
  {#snippet children(p)}
    <div class="tabs" role="tablist" aria-label="Revision status">
      {#each tabs as t (t.key)}
        <button role="tab" type="button" aria-selected={status === t.key} onclick={() => router.setParams({ status: t.key === 'proposed' ? undefined : t.key || 'all' })}>{t.label}</button>
      {/each}
    </div>

    {#if error}
      <div class="empty"><strong>Revisions could not be loaded</strong>{error}</div>
    {:else if !list}
      <div class="skeleton bar"></div>
    {:else if list.length === 0}
      <div class="empty"><strong>Nothing here</strong>{status === 'proposed' ? 'No revision is waiting for review.' : 'No revision with this status.'}</div>
    {:else}
      <ol class="revs">
        {#each list as r (r.id)}
          <li class={r.status}>
            <a class="cover" href={proposalHref(r.id)} aria-label="Open {r.id}"></a>
            <div class="id">
              <span class="mono">{r.id}</span>
              <RevisionBadge status={r.status} stale={stale(r)} />
            </div>
            <p class="comment">{r.comment ?? 'No comment'}</p>
            <div class="meta">
              <ActorChip actor={r.author} quiet />
              <RelTime iso={r.created_at} />
              {#if r.approvals?.length}
                <span class="appr">
                  {#each r.approvals as a, i (i)}<span class="dot {a.decision}" title="{a.decision} by {identityLabel(a.by).label}"></span>{/each}
                  {r.approvals.length} decision{r.approvals.length > 1 ? 's' : ''}
                </span>
              {/if}
              {#if r.status === 'superseded' && p.me.can_propose && p.settings.editable}
                <button class="btn quiet roll" type="button" disabled={busy === r.id} onclick={() => rollback(r.id)}><Icon name="undo" size={14} />Roll back to this</button>
              {/if}
            </div>
          </li>
        {/each}
      </ol>
    {/if}
  {/snippet}
</PolicyFrame>

<style>
  .tabs {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    margin-bottom: var(--s4);
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
  .revs {
    list-style: none;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--rule);
    max-width: 980px;
  }
  .revs li {
    position: relative;
    display: grid;
    gap: 6px;
    padding: var(--s4) var(--s4);
    border-bottom: 1px solid var(--rule);
    transition: background-color 100ms var(--ease-out);
  }
  .revs li:hover {
    background: var(--sheet);
  }
  .revs li.proposed,
  .revs li.approved {
    box-shadow: inset 3px 0 0 var(--brass);
  }
  .revs li.active {
    box-shadow: inset 3px 0 0 var(--seal-ink);
  }
  .cover {
    position: absolute;
    inset: 0;
  }
  .revs li > :not(.cover) {
    position: relative;
    pointer-events: none;
  }
  .revs li button {
    pointer-events: auto;
  }
  .id {
    display: flex;
    align-items: center;
    gap: var(--s2);
    font-weight: 600;
  }
  .comment {
    color: var(--ink);
    font-size: var(--t-lead);
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2) var(--s4);
    color: var(--ink-3);
    font-size: 13px;
  }
  .appr {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--stamp);
  }
  .dot.reject {
    background: var(--wax);
  }
  .roll {
    margin-left: auto;
    height: 28px;
  }
  .bar {
    height: 200px;
  }
</style>
