<script lang="ts">
  import { untrack } from 'svelte';
  import { api, ApiError } from '../lib/api';
  import type { Propagation } from '../lib/types';
  import { POLL_FOR_MS, POLL_MS, expectedLine, groupAnswers, keepPolling, placeLine, statusHelp, statusText, summaryLine } from '../lib/propagation';
  import { ttl as fmtTTL } from '../lib/format';
  import Icon from './Icon.svelte';

  let {
    zone,
    host,
    type,
    auto = false,
    expect,
  }: {
    zone: string;
    host: string;
    type: string;
    /** Starts checking at once (right after an apply) instead of offering a button. */
    auto?: boolean;
    /** Content hash just written, or "absent" after a deletion. */
    expect?: string;
  } = $props();

  let result = $state<Propagation | null>(null);
  let error = $state<string | null>(null);
  let running = $state(false);
  let busy = $state(false);
  let startedAt = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let generation = 0;

  const STOP = new Set([400, 403, 404, 412, 501]);

  function stop() {
    clearTimeout(timer);
    timer = undefined;
    running = false;
  }

  function start() {
    stop();
    generation++;
    startedAt = Date.now();
    running = true;
    error = null;
    void tick(generation);
  }

  async function tick(gen: number) {
    busy = true;
    try {
      const r = await api.propagation(zone, host, type, expect);
      if (gen !== generation) return;
      result = r;
      error = null;
    } catch (e) {
      if (gen !== generation) return;
      error = (e as Error).message;
      if (e instanceof ApiError && STOP.has(e.status)) {
        stop();
        return;
      }
    } finally {
      if (gen === generation) busy = false;
    }
    if (running && keepPolling(result, startedAt, Date.now())) timer = setTimeout(() => tick(gen), POLL_MS);
    else running = false;
  }

  $effect(() => {
    void zone;
    void host;
    void type;
    untrack(() => {
      result = null;
      error = null;
      stop();
      if (auto) start();
    });
    return () => {
      generation++;
      stop();
    };
  });

  const groups = $derived(result ? groupAnswers(result.answers) : []);
  const answered = $derived(result ? result.summary.total - result.summary.error : 0);
  const pct = (n: number) => (result && result.summary.total ? (100 * n) / result.summary.total : 0);
  const phase = $derived(!result ? 'idle' : result.summary.converged ? 'done' : running ? 'running' : 'stopped');
</script>

<div class="prop" aria-busy={busy}>
  {#if !result && !running && !error}
    <div class="intro">
      <p class="dim">Asks the name servers of the zone and public resolvers around the world whether they already answer this content.</p>
      <button class="btn" type="button" onclick={start}><Icon name="search" size={14} />Check propagation</button>
    </div>
  {:else}
    <div class="head">
      {#if result}
        <div class="sum">
          <p class="line"><b class="num">{summaryLine(result)}</b></p>
          <div class="meter" role="img" aria-label="{result.summary.match} of {answered} servers up to date">
            <span class="seg match" style:width="{pct(result.summary.match)}%"></span>
            <span class="seg stale" style:width="{pct(result.summary.stale)}%"></span>
            <span class="seg missing" style:width="{pct(result.summary.missing)}%"></span>
            <span class="seg indeterminate" style:width="{pct(result.summary.indeterminate)}%"></span>
            <span class="seg error" style:width="{pct(result.summary.error)}%"></span>
          </div>
        </div>
      {:else}
        <div class="sum"><div class="skeleton line"></div></div>
      {/if}
      {#if running}
        <button class="btn quiet small" type="button" onclick={stop}>Stop</button>
      {:else}
        <button class="btn small" type="button" onclick={start}>Check again</button>
      {/if}
    </div>

    <p class="state {phase}" role="status">
      {#if phase === 'done'}
        <Icon name="check" size={13} /> Every server that answered has the new content.
      {:else if phase === 'running'}
        <span class="pulse" aria-hidden="true"></span> Checking every {POLL_MS / 1000} s, for up to {POLL_FOR_MS / 60_000} min.
      {:else if phase === 'stopped'}
        <Icon name="clock" size={13} /> Stopped.
        {#if result && result.summary.max_ttl_left > 0}Old answers expire within {fmtTTL(result.summary.max_ttl_left)} at the latest.{/if}
      {:else}
        Asking the servers…
      {/if}
      {#if phase === 'running' && result && result.summary.max_ttl_left > 0}
        <span class="dim">Old answers expire within {fmtTTL(result.summary.max_ttl_left)} at the latest.</span>
      {/if}
    </p>

    {#if error}
      <p class="err"><Icon name="alert" size={13} /> {error}</p>
    {/if}

    {#if result}
      <p class="expected"><span class="eyebrow">Expected</span> <span class:mono={result.expected.exists}>{expectedLine(result)}</span></p>
      {#each groups as g (g.key)}
        <section class="group">
          <h4 class="eyebrow">{g.label}{#if g.note}<span class="note">{g.note}</span>{/if}</h4>
          <ul>
            {#each g.answers as a (a.kind + a.name + a.address)}
              <li class="row {a.status}">
                <span class="dot" title={statusHelp[a.status]} aria-hidden="true"></span>
                <span class="who">
                  <span class="name">{a.name}</span>
                  {#if placeLine(a)}<span class="dim small">{placeLine(a)}</span>{/if}
                  {#if a.filtering}<span class="dim small" title="Blocks some names by policy: a negative answer may be a filter decision.">filtering</span>{/if}
                </span>
                <span class="st" title={statusHelp[a.status]}>{statusText[a.status]}</span>
                <span class="what mono" title={a.address}>
                  {#if a.status === 'error' || (a.status === 'indeterminate' && !a.values.length)}{a.error ?? a.rcode ?? 'no answer'}
                  {:else if a.values.length}{#if a.cnames?.length}<span class="dim">→ {a.cnames.join(' → ')} · </span>{/if}{a.values.join(', ')}{#if a.truncated}<span class="dim"> …</span>{/if}
                  {:else}{a.rcode === 'NXDOMAIN' ? 'NXDOMAIN' : 'no record'}{/if}
                </span>
                <span class="meta dim small num">
                  {#if a.ttl_left !== undefined}<span title="Time this answer stays cached">TTL {fmtTTL(a.ttl_left)}</span>{/if}
                  {#if a.status !== 'error' || a.latency_ms}<span>{a.latency_ms} ms{#if a.tcp} · TCP{/if}</span>{/if}
                </span>
              </li>
            {/each}
          </ul>
        </section>
      {/each}
      <p class="dim small">
        Public resolvers keep an answer until its TTL runs out; anycast ones answer from their site nearest to the gate. Checked
        {new Date(result.checked_at).toLocaleTimeString()}{#if result.cached} (cached){/if}.
      </p>
    {/if}
  {/if}
</div>

<style>
  .prop {
    display: grid;
    gap: var(--s3);
  }
  .intro {
    display: grid;
    gap: var(--s2);
    justify-items: start;
  }
  .dim {
    color: var(--ink-3);
  }
  .small {
    font-size: 12px;
  }
  .btn.small {
    height: 26px;
    padding: 0 var(--s2);
    font-size: 12px;
  }
  .head {
    display: flex;
    align-items: center;
    gap: var(--s3);
  }
  .sum {
    flex: 1;
    display: grid;
    gap: 6px;
    min-width: 0;
  }
  .line {
    font-size: var(--t-lead);
  }
  .meter {
    display: flex;
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
    background: var(--rule-soft);
  }
  .seg {
    transition: width 400ms var(--ease-out);
  }
  .seg.match {
    background: var(--stamp);
  }
  .seg.stale {
    background: var(--brass);
  }
  .seg.missing {
    background: var(--wax);
  }
  .seg.indeterminate {
    background: var(--pencil);
  }
  .seg.error {
    background: var(--pencil-wash);
  }
  .state {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 6px;
    color: var(--ink-2);
    font-size: 12px;
  }
  .state.done {
    color: var(--stamp);
  }
  .pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--seal-ink);
    animation: pulse 1.2s var(--ease-out) infinite;
  }
  @keyframes pulse {
    50% {
      opacity: 0.3;
    }
  }
  .err {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--wax-wash);
    color: var(--wax);
  }
  .expected {
    display: flex;
    align-items: baseline;
    gap: var(--s2);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
    min-width: 0;
  }
  .expected span:last-child {
    word-break: break-all;
  }
  .group {
    display: grid;
    gap: var(--s1);
  }
  h4 {
    margin: 0;
    font-weight: 500;
  }
  .note {
    color: var(--ink-4);
  }
  .note::before {
    content: ' · ';
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    border-top: 1px solid var(--rule-soft);
  }
  .row {
    display: grid;
    grid-template-columns: 10px minmax(0, 1fr) auto;
    grid-template-areas:
      'dot who st'
      '. what meta';
    gap: 2px var(--s2);
    align-items: baseline;
    padding: 6px 0;
    border-bottom: 1px solid var(--rule-soft);
  }
  .dot {
    grid-area: dot;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    align-self: center;
    background: var(--pencil);
  }
  .who {
    grid-area: who;
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0 var(--s2);
    min-width: 0;
  }
  .name {
    font-weight: 500;
  }
  .st {
    grid-area: st;
    justify-self: end;
    font-size: 12px;
    font-weight: 500;
    color: var(--ink-3);
    white-space: nowrap;
  }
  .what {
    grid-area: what;
    font-size: 12px;
    color: var(--ink-2);
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .meta {
    grid-area: meta;
    justify-self: end;
    display: flex;
    gap: var(--s2);
    white-space: nowrap;
  }
  .row.match .dot {
    background: var(--stamp);
  }
  .row.match .st {
    color: var(--stamp);
  }
  .row.stale .dot {
    background: var(--brass);
  }
  .row.stale .st {
    color: var(--brass);
  }
  .row.missing .dot {
    background: var(--wax);
  }
  .row.missing .st {
    color: var(--wax);
  }
  .row.indeterminate .dot {
    background: var(--pencil);
  }
  .row.indeterminate .st {
    color: var(--ink-2);
  }
  .row.error .dot {
    background: transparent;
    box-shadow: inset 0 0 0 1.5px var(--pencil);
  }
  .row.error .what {
    color: var(--ink-3);
  }
  .skeleton.line {
    height: 14px;
  }
</style>
