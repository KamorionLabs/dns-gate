<script lang="ts">
  import { api, ApiError } from '../../lib/api';
  import type { Me, RRsetRef, TeamInfo, Transfer } from '../../lib/types';
  import { transferHref, transfersHref } from '../../lib/router.svelte';
  import { canSelfApply, decisionOutcome, transferAllowed, transferRule, transferTargets } from '../../lib/teams';
  import { transferOf } from '../../lib/http';
  import SidePanel from '../SidePanel.svelte';
  import Icon from '../Icon.svelte';

  // Request to move record sets of one team to another; a second person approves it.
  let {
    zone,
    picked,
    from,
    me,
    onclose,
    ondone,
  }: {
    zone: string;
    picked: RRsetRef[];
    /** Team that owns every picked record set. */
    from: string;
    me: Me | null;
    onclose: () => void;
    ondone: (t: Transfer) => void;
  } = $props();

  let teams = $state<TeamInfo[] | null>(null);
  let second = $state<boolean | undefined>(undefined);
  let to = $state('');
  let comment = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let done = $state<Transfer | null>(null);

  $effect(() => {
    api
      .teams()
      .then((l) => {
        teams = l.teams;
        second = l.require_second_approver;
      })
      .catch(() => (teams = []));
  });

  const allowed = $derived(transferAllowed(me, zone, from));
  const selfApply = $derived(canSelfApply(me, zone, from, second));
  const targets = $derived(teams ? transferTargets(me, zone, from, teams) : []);
  $effect(() => {
    if (!to && targets.length) to = targets[0]!;
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    const apply = (e.submitter as HTMLButtonElement | null)?.value === 'apply';
    error = null;
    if (!to || !comment.trim()) {
      error = apply ? 'Choose the team and say why: the journal keeps it.' : 'Choose the team and say why: the approver reads it.';
      return;
    }
    busy = true;
    try {
      done = await api.proposeTransfer(zone, { rrsets: picked, to_team: to, comment: comment.trim(), apply: apply || undefined });
      ondone(done);
    } catch (err) {
      if (err instanceof ApiError && err.reason === 'reauth_required') return;
      if (!(err instanceof ApiError)) {
        error = (err as Error).message;
        return;
      }
      const returned = transferOf(err);
      if (returned) {
        done = returned;
        ondone(returned);
      }
      const o = decisionOutcome(err, returned);
      error = apply && !returned && err.reason === 'forbidden' ? `${err.message}. The request may have been created without being approved: check the transfers of this zone.` : o.text;
    } finally {
      busy = false;
    }
  }
</script>

<SidePanel title="Transfer record sets" {onclose} width={560}>
  {#snippet head()}
    <p class="eyebrow">Transfer to another team</p>
    <h2 class="mono">{zone}</h2>
  {/snippet}

  {#if done}
    <section class="done">
      {#if done.status === 'applied'}
        <p class="big"><Icon name="check" size={16} /> Transferred</p>
        <p>{done.moved ?? done.rrsets.length} moved to team <b>{done.to_team}</b>{done.self_approved ? ', approved by you (self-approved)' : ''}. The journal keeps the request and its approval.</p>
      {:else if done.status === 'applying'}
        <p class="big wait"><Icon name="clock" size={16} /> Approved, being applied</p>
        <p>{error ?? 'The gate applies it on its own as soon as the zone is free.'}</p>
      {:else if done.status === 'failed'}
        <p class="big fail"><Icon name="alert" size={16} /> Not applied</p>
        <p>{error}</p>
      {:else}
        <p class="big"><Icon name="check" size={16} /> Request sent</p>
        <p>Nothing moved yet. It must be approved by {transferRule(from, second)}. It expires if nobody decides in time.</p>
        {#if error}<p class="err" role="alert">{error}</p>{/if}
      {/if}
      <p><a href={transferHref(done.id)}>Open the request</a>{done.status === 'proposed' ? ' to follow it or withdraw it.' : '.'}</p>
      <button class="btn" type="button" onclick={onclose}>Close</button>
    </section>
  {:else}
    <form class="form" onsubmit={submit} novalidate>
      <div class="row">
        <span class="lbl">From team</span>
        <p class="from mono">{from}</p>
      </div>
      <div class="row">
        <span class="lbl">{picked.length} record set{picked.length === 1 ? '' : 's'}</span>
        <ul class="picked">
          {#each picked as r (r.host + '/' + r.type)}<li><span class="mono">{r.host}</span> <span class="mono t">{r.type}</span></li>{/each}
        </ul>
      </div>
      <div class="row">
        <label class="lbl" for="tr-to">To team</label>
        {#if !teams}
          <div class="skeleton line"></div>
        {:else if targets.length === 0}
          <p class="err">No team to move them to: you can only move them to one of your teams, and you have no other.</p>
        {:else}
          <span class="field sel">
            <select id="tr-to" bind:value={to}>
              {#each targets as t (t)}<option value={t}>{t}{me?.teams.includes(t) ? ' (your team)' : ''}</option>{/each}
            </select>
            <span class="chev"><Icon name="chevron" size={12} /></span>
          </span>
        {/if}
        {#if allowed.text}<p class="hint">{allowed.text}</p>{/if}
      </div>
      <div class="row">
        <label class="lbl" for="tr-why">Why</label>
        <textarea id="tr-why" class="in" rows="3" bind:value={comment} placeholder="The site moves to its own pipeline, records first adopted by the wrong team…"></textarea>
      </div>
      <p class="hint">
        Approval comes from {transferRule(from, second)}. On approval the record sets move at once, if none changed since this request.
        {#if selfApply}The gate does not require a second approver: you may apply it yourself now.{/if}
      </p>
      {#if error}<p class="err" role="alert">{error}{#if error.includes('check the transfers')} <a href={transfersHref({ zone })}>Transfers of {zone}</a>{/if}</p>{/if}
      <div class="actions">
        {#if selfApply}
          <button class="btn primary" type="submit" value="apply" disabled={busy || !allowed.ok || targets.length === 0}><Icon name="check" size={14} />{busy ? 'Sending…' : 'Propose and apply'}</button>
          <button class="btn" type="submit" value="ask" disabled={busy || !allowed.ok || targets.length === 0}>Ask for approval</button>
        {:else}
          <button class="btn primary" type="submit" value="ask" disabled={busy || !allowed.ok || targets.length === 0}><Icon name="transfer" size={14} />{busy ? 'Sending…' : 'Ask for the transfer'}</button>
        {/if}
        <button class="btn quiet" type="button" onclick={onclose}>Cancel</button>
      </div>
    </form>
  {/if}
</SidePanel>

<style>
  h2 {
    font-size: var(--t-h3);
  }
  .form,
  .done {
    display: grid;
    gap: var(--s4);
  }
  .row {
    display: grid;
    gap: 6px;
  }
  .lbl {
    font-weight: 500;
  }
  .from {
    font-weight: 600;
    font-size: var(--t-lead);
  }
  .picked {
    list-style: none;
    margin: 0;
    padding: var(--s2) var(--s3);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    max-height: 220px;
    overflow: auto;
    display: grid;
    gap: 2px;
  }
  .t {
    color: var(--ink-3);
    font-size: 12px;
  }
  .sel {
    justify-self: start;
    min-width: 220px;
  }
  .sel select {
    flex: 1;
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
  .hint {
    color: var(--ink-3);
    font-size: 12px;
  }
  .err {
    color: var(--wax);
    font-size: 13px;
  }
  .actions {
    display: flex;
    gap: var(--s2);
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .big {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--t-lead);
    font-weight: 600;
    color: var(--stamp);
  }
  .done .btn {
    justify-self: start;
  }
  .big.wait {
    color: var(--brass);
  }
  .big.fail {
    color: var(--wax);
  }
  .line {
    height: 32px;
    width: 220px;
  }
</style>
