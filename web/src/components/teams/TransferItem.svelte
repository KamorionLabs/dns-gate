<script lang="ts">
  import type { Me, Transfer } from '../../lib/types';
  import { transferHref } from '../../lib/router.svelte';
  import { decisionRule } from '../../lib/teams';
  import { inbox } from '../../lib/inbox.svelte';
  import ActorChip from '../ActorChip.svelte';
  import RelTime from '../RelTime.svelte';
  import Icon from '../Icon.svelte';
  import TransferBadge from './TransferBadge.svelte';

  // One transfer request in a list: what moves, from and to which team, who asked, and what happens next.
  let { t, me }: { t: Transfer; me: Me | null } = $props();
  const n = $derived(t.rrsets.length);
  const what = $derived(t.kind === 'rename' ? 'Rename: every record set, every zone' : `${n} record set${n === 1 ? '' : 's'} in ${t.zone}`);
</script>

<li class={t.status} class:todo={t.can_decide}>
  <a class="cover" href={transferHref(t.id)} aria-label="Open transfer {t.id}"></a>
  <div class="line">
    <span class="teams mono"><span>{t.from_team}</span><Icon name="arrow" size={12} /><span>{t.to_team}</span></span>
    <TransferBadge status={t.status} />
    {#if t.self_approved}<span class="self" title="Approved by the person who asked for it: the gate does not require a second approver">Self-approved</span>{/if}
    <span class="what">{what}</span>
  </div>
  {#if t.comment}<p class="comment">{t.comment}</p>{/if}
  <div class="meta">
    <ActorChip actor={t.requester} quiet /> asked <RelTime iso={t.created_at} />
    {#if t.decided_by}· <ActorChip actor={t.decided_by} quiet /> {t.status === 'rejected' ? 'rejected' : 'decided'} <RelTime iso={t.decided_at} />{/if}
    {#if t.status === 'proposed'}· expires <RelTime iso={t.expires_at} />{/if}
    {#if t.status === 'failed' && t.error}· <span class="err">{t.error}</span>{/if}
    {#if t.status === 'applying' && t.error}· <span class="retry">retrying: {t.error}</span>{/if}
  </div>
  {#if t.status === 'proposed' || t.status === 'applying'}<p class="rule" class:you={t.can_decide}>{decisionRule(t, me, inbox.secondApprover)}</p>{/if}
</li>

<style>
  li {
    position: relative;
    display: grid;
    gap: 6px;
    padding: var(--s4);
    border-bottom: 1px solid var(--rule);
    transition: background-color 100ms var(--ease-out);
  }
  li:hover {
    background: var(--sheet);
  }
  li.proposed {
    box-shadow: inset 3px 0 0 var(--rule-strong);
  }
  li.todo {
    box-shadow: inset 3px 0 0 var(--brass);
  }
  .cover {
    position: absolute;
    inset: 0;
  }
  li > :not(.cover) {
    position: relative;
    pointer-events: none;
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2) var(--s3);
  }
  .teams {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
    font-size: var(--t-lead);
  }
  .teams :global(svg) {
    color: var(--ink-3);
  }
  .what {
    color: var(--ink-2);
  }
  .comment {
    color: var(--ink);
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 6px;
    color: var(--ink-3);
    font-size: 13px;
  }
  .err {
    color: var(--wax);
  }
  .retry {
    color: var(--brass);
  }
  .self {
    font-size: 12px;
    padding: 1px 7px;
    border-radius: 5px;
    background: var(--pencil-wash);
    color: var(--ink-2);
  }
  .rule {
    color: var(--ink-3);
    font-size: 12px;
  }
  .rule.you {
    color: var(--brass);
    font-weight: 500;
  }
</style>
