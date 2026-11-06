<script lang="ts">
  import { untrack } from 'svelte';
  import { api, ApiError } from '../lib/api';
  import type { Me, PlanResult, Tombstone } from '../lib/types';
  import { planTeam } from '../lib/teams';
  import { kindVerb, shownPlanChange, shownStaged, stagedKey, toRequest, type StagedChange } from '../lib/staging';
  import { reasonLabel, writeReasonText } from '../lib/labels';
  import { journalHref } from '../lib/router.svelte';
  import SidePanel from './SidePanel.svelte';
  import ChangeDiff from './ChangeDiff.svelte';
  import CopyText from './CopyText.svelte';
  import Seal from './Seal.svelte';
  import Icon from './Icon.svelte';
  import PropagationPanel from './PropagationPanel.svelte';

  let {
    zone,
    staged,
    me = null,
    tombstones = [],
    onclose,
    onunstage,
    onapplied,
    onreload,
  }: {
    zone: string;
    staged: StagedChange[];
    me?: Me | null;
    tombstones?: Tombstone[];
    onclose: () => void;
    onunstage: (key: string) => void;
    onapplied: (r: PlanResult) => void;
    /** Reads the zone again; returns the staged changes dropped because their record set moved. */
    onreload: () => Promise<StagedChange[]>;
  } = $props();

  type Phase = 'planning' | 'plan' | 'refused' | 'applying' | 'done';
  let phase = $state<Phase>('planning');
  let plan = $state<PlanResult | null>(null);
  let result = $state<PlanResult | null>(null);
  let refusal = $state<{ reason?: string; message?: string; stale: boolean } | null>(null);
  let dropped = $state<StagedChange[]>([]);
  let reloading = $state(false);
  let propIndex = $state(0);

  // With several teams, the team the changes are made for (new record sets go to it).
  let chosen = $state<string | undefined>(undefined);
  const choice = $derived(planTeam(me, staged, chosen, tombstones));

  const STALE = new Set(['precondition', 'plan_expired', 'plan_not_found', 'tainted', 'foreign_rrset', 'not_found']);

  function refuse(reason?: string, message?: string) {
    refusal = { reason, message, stale: !!reason && STALE.has(reason) };
    phase = 'refused';
  }

  async function runPlan() {
    if (!staged.length) {
      plan = null;
      phase = 'plan';
      return;
    }
    phase = 'planning';
    refusal = null;
    try {
      const p = await api.plan(zone, toRequest(staged), choice.team);
      plan = p;
      if (p.allowed && p.plan_id) phase = 'plan';
      else refuse(p.reason, p.message);
    } catch (e) {
      if (e instanceof ApiError && e.reason === 'reauth_required') return;
      if (e instanceof ApiError) refuse(e.reason, e.message);
      else refuse(undefined, (e as Error).message);
    }
  }

  // A new plan whenever the staged list changes (a change removed from here).
  $effect(() => {
    void staged.map(stagedKey).join();
    void choice.team;
    // once applied, the staged list is emptied: the result stays on screen
    untrack(() => phase !== 'done' && phase !== 'applying' && runPlan());
  });

  async function apply() {
    if (!plan?.plan_id) return;
    phase = 'applying';
    try {
      const r = await api.apply(zone, plan.plan_id, plan.team ?? choice.team);
      if (!r.allowed) {
        plan = r;
        refuse(r.reason, r.message);
        return;
      }
      result = r;
      phase = 'done';
      onapplied(r);
    } catch (e) {
      if (e instanceof ApiError && e.reason === 'reauth_required') return;
      if (e instanceof ApiError) refuse(e.reason, e.message);
      else refuse(undefined, (e as Error).message);
    }
  }

  async function reload() {
    reloading = true;
    try {
      dropped = await onreload();
    } finally {
      reloading = false;
    }
    // a shorter staged list plans again on its own
    if (!dropped.length) await runPlan();
  }

  const planned = $derived((plan?.changes ?? []).map((c) => ({ c, shown: shownPlanChange(c) })));
  const n = $derived(staged.length);
  const opVerb = (op: string) => (op === 'create' || op === 'update' || op === 'delete' ? kindVerb[op] : undefined);
  const changesWord = (k: number) => `${k} change${k === 1 ? '' : 's'}`;
</script>

<SidePanel title="Review changes" {onclose} width={640}>
  {#snippet head()}
    <p class="eyebrow">{phase === 'done' ? 'Applied' : 'Review changes'}</p>
    <h2 class="mono">{zone}</h2>
  {/snippet}

  {#if phase === 'done' && result}
    <section class="done">
      <div class="donehead">
        <span class="mark"><Seal status="managed" size={26} /></span>
        <div>
          <p class="big">{changesWord(result.changes.length)} applied</p>
          <p class="dim">
            The zone is up to date at the DNS provider.
            {#if result.request_id}Request <CopyText text={result.request_id} label="request id" /> ·{/if}
            <a href={journalHref({ zone })}>journal</a>
          </p>
        </div>
      </div>
      <div class="diffs">
        {#each result.changes as c, i (i)}<div class="diff"><ChangeDiff change={shownPlanChange(c)} {zone} /></div>{/each}
      </div>
      <p class="dim small">Resolvers may keep the old answer for up to its previous TTL.</p>
      {#if result.changes.length}
        {@const c = result.changes[Math.min(propIndex, result.changes.length - 1)]}
        <section class="prop">
          <h3 class="eyebrow">Propagation</h3>
          {#if result.changes.length > 1}
            <div class="pick" role="group" aria-label="Record set to check">
              {#each result.changes as p, i (i)}
                <button class="btn small" class:on={propIndex === i} type="button" aria-pressed={propIndex === i} onclick={() => (propIndex = i)}>
                  <span class="mono">{p.host} {p.type}</span>
                </button>
              {/each}
            </div>
          {/if}
          {#if c}<PropagationPanel {zone} host={c.host} type={c.type} auto />{/if}
        </section>
      {/if}
      <button class="btn" type="button" onclick={onclose}>Close</button>
    </section>
  {:else}
    {#if dropped.length}
      <div class="notice warn" role="status">
        <Icon name="alert" size={16} />
        <div>
          <b>{changesWord(dropped.length)} removed from the review:</b> the record set changed since you staged it.
          <ul class="plain">{#each dropped as d (stagedKey(d))}<li class="mono">{kindVerb[d.kind]} {d.host} {d.type}</li>{/each}</ul>
          Check the zone and stage them again if they are still needed.
        </div>
      </div>
    {/if}

    {#if n > 0 && choice.options.length > 1}
      <div class="teampick">
        {#if choice.choose}
          <label for="plan-team">Owner team of the new record sets</label>
          <span class="field sel">
            <select id="plan-team" value={choice.team} disabled={phase === 'applying'} onchange={(e) => (chosen = e.currentTarget.value)}>
              {#each choice.options as t (t)}<option value={t}>{t}{t === me?.default_team ? ' (default)' : ''}</option>{/each}
            </select>
            <span class="chev"><Icon name="chevron" size={12} /></span>
          </span>
          <p class="dim small">You are a member of several teams: only members of this team will be able to change them.</p>
        {:else}
          <p class="dim small"><Icon name="team" size={13} /> {choice.note}</p>
        {/if}
      </div>
    {/if}

    {#if n === 0}
      <p class="dim">No change staged.</p>
      <button class="btn close" type="button" onclick={onclose}>Close</button>
    {:else if phase === 'planning'}
      <p class="status"><span class="spinner" aria-hidden="true"></span>The gate is checking {changesWord(n)}…</p>
      <div class="diffs">
        {#each staged as c (stagedKey(c))}<div class="diff"><ChangeDiff change={shownStaged(c)} {zone} link={false} applied={false} verb={kindVerb[c.kind]} /></div>{/each}
      </div>
    {:else if phase === 'refused' && refusal}
      <div class="notice refuse" role="alert">
        <Icon name="lock" size={16} />
        <div>
          <b>The gate refuses {n === 1 ? 'this change' : 'these changes'}.</b>
          {writeReasonText(refusal.reason)}
          {#if refusal.message}<span class="detail">Details: {refusal.message}</span>{/if}
          <span class="detail">Nothing was written.</span>
        </div>
      </div>
      <div class="refuse-actions">
        {#if refusal.stale}
          <button class="btn" type="button" disabled={reloading} onclick={reload}><Icon name="undo" size={14} />{reloading ? 'Reloading…' : 'Reload the zone and review again'}</button>
        {:else}
          <button class="btn" type="button" onclick={runPlan}><Icon name="undo" size={14} />Review again</button>
        {/if}
      </div>
      <h3>Staged changes</h3>
      <p class="dim small">Remove the change that is refused, then review again.</p>
      <ul class="staged">
        {#each staged as c (stagedKey(c))}
          {@const why = planned.find((p) => p.c.host === c.host && p.c.type === c.type)?.c}
          <li>
            <ChangeDiff change={shownStaged(c)} {zone} link={false} applied={false} verb={kindVerb[c.kind]} />
            {#if why?.reason}<p class="why">{reasonLabel(why.reason)}{why.message ? `: ${why.message}` : ''}</p>{/if}
            <button class="btn quiet small" type="button" onclick={() => onunstage(stagedKey(c))}><Icon name="trash" size={13} />Remove</button>
          </li>
        {/each}
      </ul>
    {:else if plan}
      <div class="notice ok" role="status">
        <Seal status="managed" size={16} />
        <div><b>The gate accepts {n === 1 ? 'this change' : `these ${n} changes`}.</b> Check the differences below, then apply.</div>
      </div>
      {#if planned.length === 0}
        <p class="dim">Nothing would change: the zone already has these values.</p>
      {:else}
        <div class="diffs">
          {#each planned as p, i (i)}<div class="diff"><ChangeDiff change={p.shown} {zone} link={false} applied={false} verb={opVerb(p.c.op)} /></div>{/each}
        </div>
      {/if}
      <section class="confirm">
        <button class="btn primary" type="button" disabled={phase === 'applying' || planned.length === 0} onclick={apply}>
          <Seal status="managed" size={14} />
          {phase === 'applying' ? 'Applying…' : `Apply ${changesWord(planned.length)}`}
        </button>
        <p class="dim small">All together or nothing: if the zone changed since this review, nothing is written and you are asked to review again. Every change goes to the journal with your name.</p>
      </section>
    {/if}
  {/if}
</SidePanel>

<style>
  h2 {
    font-size: var(--t-h3);
  }
  h3 {
    font-size: 13px;
    font-weight: 600;
  }
  .dim {
    color: var(--ink-3);
  }
  .dim a {
    color: var(--ink-2);
  }
  .small {
    font-size: 12px;
  }
  .diffs {
    display: grid;
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    overflow: hidden;
  }
  .diff {
    padding: var(--s2) var(--s3);
    border-bottom: 1px solid var(--rule-soft);
    background: var(--sheet);
  }
  .diff:last-child {
    border-bottom: 0;
  }
  .status {
    display: flex;
    align-items: center;
    gap: var(--s2);
    color: var(--ink-2);
  }
  .spinner {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--rule-strong);
    border-top-color: var(--seal-ink);
    animation: spin 800ms linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .notice {
    display: flex;
    align-items: flex-start;
    gap: var(--s3);
    padding: var(--s3) var(--s4);
    border-radius: var(--r-md);
    background: var(--well);
    color: var(--ink-2);
  }
  .notice :global(svg) {
    flex: none;
    margin-top: 2px;
  }
  .notice.ok {
    background: var(--stamp-wash);
  }
  .notice.ok :global(.seal) {
    color: var(--stamp);
  }
  .notice.refuse,
  .notice.warn {
    background: var(--wax-wash);
  }
  .notice.refuse b,
  .notice.refuse :global(svg) {
    color: var(--wax);
  }
  .notice.warn b,
  .notice.warn :global(svg) {
    color: var(--brass);
  }
  .notice.warn {
    background: var(--brass-wash);
  }
  .detail {
    display: block;
    margin-top: 4px;
    color: var(--ink-3);
    font-size: 12px;
  }
  .plain {
    margin: 4px 0;
    padding-left: var(--s4);
  }
  .refuse-actions {
    display: flex;
    gap: var(--s2);
  }
  .staged {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  .staged li {
    display: grid;
    gap: 4px;
    padding: var(--s2) var(--s3);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
  }
  .staged .btn {
    justify-self: start;
  }
  .btn.small {
    height: 26px;
    padding: 0 var(--s2);
    font-size: 12px;
  }
  .why {
    color: var(--wax);
    font-size: 12px;
  }
  .teampick {
    display: grid;
    gap: 6px;
    padding: var(--s3) var(--s4);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    background: var(--sheet);
  }
  .teampick label {
    font-weight: 500;
  }
  .teampick p {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .sel {
    justify-self: start;
    min-width: 200px;
  }
  .sel select {
    flex: 1;
  }
  .confirm {
    display: grid;
    gap: var(--s2);
    padding-top: var(--s4);
    border-top: 1px solid var(--rule);
  }
  .btn.primary {
    height: 38px;
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .btn.primary :global(.seal) {
    color: var(--sheet);
  }
  .donehead {
    display: flex;
    align-items: center;
    gap: var(--s3);
    margin-bottom: var(--s3);
  }
  .done {
    display: grid;
    gap: var(--s3);
  }
  .done .btn,
  .btn.close {
    justify-self: start;
  }
  .mark {
    display: grid;
    place-items: center;
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: var(--seal-ink-wash);
    flex: none;
  }
  .big {
    font-size: var(--t-lead);
    font-weight: 600;
  }
  .prop {
    display: grid;
    gap: var(--s2);
    padding-top: var(--s2);
    border-top: 1px solid var(--rule-soft);
  }
  .prop h3 {
    font-weight: 500;
  }
  .pick {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s1);
  }
  .pick .btn.on {
    border-color: var(--seal-ink);
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .pick .mono {
    font-size: 12px;
  }
</style>
