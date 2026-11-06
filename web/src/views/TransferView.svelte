<script lang="ts">
  import { api, ApiError } from '../lib/api';
  import type { Me, Transfer } from '../lib/types';
  import { teamHref, transfersHref, zoneHref } from '../lib/router.svelte';
  import { canReject, decisionRule, isRequester } from '../lib/teams';
  import { inbox } from '../lib/inbox.svelte';
  import TeamsNav from '../components/teams/TeamsNav.svelte';
  import TransferBadge from '../components/teams/TransferBadge.svelte';
  import ActorChip from '../components/ActorChip.svelte';
  import RelTime from '../components/RelTime.svelte';
  import CopyText from '../components/CopyText.svelte';
  import Icon from '../components/Icon.svelte';

  let { id }: { id: string } = $props();

  let t = $state<Transfer | null>(null);
  let me = $state<Me | null>(null);
  let error = $state<string | null>(null);
  let note = $state('');
  let busy = $state<'approve' | 'reject' | null>(null);
  let actionError = $state<string | null>(null);

  $effect(() => {
    api.transfer(id).then((x) => (t = x)).catch((e: Error) => (error = e.message));
    api.me().then((m) => (me = m)).catch(() => (me = null));
  });

  const mine = $derived(!!t && isRequester(t, me));
  const rule = $derived(t ? decisionRule(t, me) : '');

  async function decide(approve: boolean) {
    if (!t) return;
    if (!approve && !mine && !note.trim()) {
      actionError = 'Say why you reject it: the requester will read it.';
      return;
    }
    busy = approve ? 'approve' : 'reject';
    actionError = null;
    try {
      t = await api.decideTransfer(t.id, approve, note.trim());
      note = '';
    } catch (e) {
      if (e instanceof ApiError && e.reason === 'reauth_required') return;
      actionError = decideError(e);
      t = await api.transfer(id).catch(() => t);
    } finally {
      busy = null;
      void inbox.load(true);
    }
  }

  function decideError(e: unknown): string {
    if (!(e instanceof ApiError)) return (e as Error).message;
    switch (e.reason) {
      case 'precondition':
        return `Not applied: ${e.message}. Nothing moved; ask for a new transfer if it is still needed.`;
      case 'expired':
        return 'This request expired before it was decided: ask for a new one.';
      case 'forbidden':
        return e.message;
      case 'zone_locked':
        return 'Another change is being written to this zone: try again in a minute. The request is still waiting.';
      default:
        return e.message;
    }
  }
</script>

<header class="head">
  <p class="eyebrow">Teams</p>
  <h1>Transfer</h1>
</header>

<TeamsNav active="transfers" />

{#if error}
  <div class="empty"><strong>This transfer could not be loaded</strong>{error}</div>
{:else if !t}
  <div class="skeleton bar"></div>
{:else}
  <a class="back" href={transfersHref()}><Icon name="arrow" size={12} /> All transfers</a>
  <div class="layout">
    <div class="main">
      <header class="thead">
        <div class="line">
          <a class="team mono" href={teamHref(t.from_team)}>{t.from_team}</a>
          <Icon name="arrow" size={14} />
          <a class="team mono" href={teamHref(t.to_team)}>{t.to_team}</a>
          <TransferBadge status={t.status} />
        </div>
        <p class="sub">
          {#if t.kind === 'rename'}Rename: every record set and reservation of team {t.from_team}, in every managed zone, moves to {t.to_team}.
          {:else}<span class="num">{t.rrsets.length}</span> record set{t.rrsets.length === 1 ? '' : 's'} in <a class="mono" href={zoneHref(t.zone ?? '', { owner: t.status === 'applied' ? t.to_team : t.from_team, status: 'all' })}>{t.zone}</a>{/if}
          · <CopyText text={t.id} label="transfer id" />
        </p>
        {#if t.comment}<blockquote>{t.comment}</blockquote>{/if}
      </header>

      {#if t.kind === 'rrsets'}
        <section>
          <h2 class="eyebrow">Record sets</h2>
          <ul class="rrsets">
            {#each t.rrsets as r (r.host + '/' + r.type)}
              <li>
                <a class="mono" href={zoneHref(t.zone ?? '', { rr: `${r.host}/${r.type}`, status: 'all' })}>{r.host}</a>
                <span class="type mono">{r.type}</span>
                {#if r.tombstone}<span class="tomb" title="Deleted recently: the reservation for the team moves">Reservation</span>{/if}
              </li>
            {/each}
          </ul>
          {#if t.status === 'proposed'}<p class="dim small">Approval moves them at once, if none changed since the request; otherwise the transfer fails and nothing moves.</p>{/if}
        </section>
      {/if}
      {#if t.kind === 'rename'}
        <p class="dim small">The policy still names team {t.from_team}: change its bindings in a policy revision too.</p>
      {/if}
    </div>

    <aside class="side">
      <h2>Decision</h2>
      <ol class="trail">
        <li class="done"><span class="node"></span><div><ActorChip actor={t.requester} quiet /> asked <RelTime iso={t.created_at} /></div></li>
        {#if t.decided_by}
          <li class={t.status === 'rejected' ? 'reject' : 'done'}>
            <span class="node"></span>
            <div>
              <ActorChip actor={t.decided_by} quiet /> {t.status === 'rejected' ? (t.decided_by.subject === t.requester.subject ? 'withdrew it' : 'rejected it') : 'approved it'} <RelTime iso={t.decided_at} />
              {#if t.decision_comment}<p class="say">“{t.decision_comment}”</p>{/if}
            </div>
          </li>
        {/if}
        {#if t.status === 'applied'}
          <li class="done"><span class="node"></span><div>Applied: {t.moved ?? 0} moved to team {t.to_team}</div></li>
        {:else if t.status === 'failed'}
          <li class="reject"><span class="node"></span><div>Not applied: {t.error ?? 'the record sets changed since the request'}</div></li>
        {:else if t.status === 'expired'}
          <li class="reject"><span class="node"></span><div>Expired <RelTime iso={t.expires_at} /> without a decision</div></li>
        {:else if t.status === 'proposed'}
          <li class="wait"><span class="node"></span><div class="dim">Waiting for approval · expires <RelTime iso={t.expires_at} /></div></li>
        {/if}
      </ol>

      {#if t.status === 'proposed'}
        <p class="rule" class:you={t.can_decide}>{rule}</p>
        {#if t.can_decide || mine}
          <label class="lbl" for="note">Comment {#if t.can_decide}<span class="dim">(required to reject)</span>{/if}</label>
          <textarea id="note" class="in" rows="3" bind:value={note} placeholder={t.can_decide ? 'What you checked, or why not' : 'Why you withdraw it'}></textarea>
          <div class="actions">
            {#if t.can_decide}
              <button class="btn approve" type="button" disabled={!!busy} onclick={() => decide(true)}><Icon name="check" size={14} />{busy === 'approve' ? 'Approving…' : 'Approve and move'}</button>
            {/if}
            {#if canReject(t, me)}
              <button class="btn reject" type="button" disabled={!!busy} onclick={() => decide(false)}>{busy === 'reject' ? 'Sending…' : mine && !t.can_decide ? 'Withdraw' : 'Reject'}</button>
            {/if}
          </div>
        {/if}
      {/if}
      {#if actionError}<p class="fail" role="alert">{actionError}</p>{/if}
    </aside>
  </div>
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
  .bar {
    height: 160px;
  }
  .back {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-bottom: var(--s4);
    color: var(--ink-3);
    text-decoration: none;
    font-size: 13px;
  }
  .back :global(svg) {
    transform: scaleX(-1);
  }
  .back:hover {
    color: var(--seal-ink);
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    gap: var(--s8);
    align-items: start;
  }
  @media (max-width: 900px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }
  .main {
    display: grid;
    gap: var(--s6);
    min-width: 0;
  }
  .thead {
    display: grid;
    gap: var(--s2);
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2) var(--s3);
  }
  .line :global(svg) {
    color: var(--ink-3);
  }
  .team {
    font-size: var(--t-h3);
    font-weight: 600;
    color: var(--ink);
    text-decoration: none;
  }
  .team:hover {
    color: var(--seal-ink);
  }
  .sub {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 6px;
    color: var(--ink-3);
  }
  .sub a {
    color: var(--ink-2);
  }
  blockquote {
    margin: 0;
    padding-left: var(--s3);
    border-left: 2px solid var(--rule-strong);
    color: var(--ink);
    font-size: var(--t-lead);
  }
  section {
    display: grid;
    gap: var(--s2);
  }
  .rrsets {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
  }
  .rrsets li {
    display: flex;
    align-items: center;
    gap: var(--s3);
    padding: var(--s2) var(--s3);
    border-bottom: 1px solid var(--rule-soft);
  }
  .rrsets li:last-child {
    border-bottom: 0;
  }
  .rrsets a {
    color: var(--ink);
    text-decoration: none;
    font-weight: 500;
  }
  .rrsets a:hover {
    color: var(--seal-ink);
  }
  .type {
    font-size: 12px;
    color: var(--ink-3);
  }
  .tomb {
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 5px;
    background: var(--pencil-wash);
    color: var(--ink-2);
  }
  .dim {
    color: var(--ink-3);
  }
  .small {
    font-size: 12px;
  }
  .side {
    display: grid;
    gap: var(--s3);
    padding: var(--s4);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
  }
  .side h2 {
    font-size: var(--t-lead);
    font-weight: 600;
  }
  .trail {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s3);
  }
  .trail li {
    display: grid;
    grid-template-columns: 10px minmax(0, 1fr);
    gap: var(--s2);
    align-items: baseline;
    color: var(--ink-2);
    font-size: 13px;
  }
  .node {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--stamp);
  }
  .reject .node {
    background: var(--wax);
  }
  .wait .node {
    background: transparent;
    box-shadow: inset 0 0 0 1.5px var(--brass);
  }
  .say {
    margin-top: 2px;
    color: var(--ink);
  }
  .rule {
    color: var(--ink-3);
    font-size: 12px;
  }
  .rule.you {
    color: var(--brass);
    font-weight: 500;
  }
  .lbl {
    font-weight: 500;
    font-size: 12px;
  }
  .in {
    width: 100%;
    padding: var(--s2);
    border: 1px solid var(--rule-strong);
    border-radius: var(--r-md);
    background: var(--sheet-raised);
    color: var(--ink);
    font: inherit;
    resize: vertical;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s2);
  }
  .btn.approve {
    background: var(--stamp);
    color: var(--sheet);
    border-color: transparent;
  }
  .btn.reject {
    color: var(--wax);
  }
  .fail {
    color: var(--wax);
    font-size: 13px;
  }
</style>
