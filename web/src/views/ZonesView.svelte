<script lang="ts">
  import { api } from '../lib/api';
  import type { ZoneSummary } from '../lib/types';
  import { zoneHref, journalHref, connectHref } from '../lib/router.svelte';
  import { statusHelp, statusLabel } from '../lib/labels';
  import CustodyStrip from '../components/CustodyStrip.svelte';
  import Seal from '../components/Seal.svelte';
  import RelTime from '../components/RelTime.svelte';
  import Icon from '../components/Icon.svelte';

  let zones = $state<ZoneSummary[] | null>(null);
  let error = $state<string | null>(null);

  const legend = ['managed', 'foreign', 'pending', 'tainted'] as const;
  const GUIDE_KEY = 'eurodns-gate.guide-dismissed';
  let guide = $state(readGuide());

  function readGuide(): boolean {
    try {
      return localStorage.getItem(GUIDE_KEY) !== '1';
    } catch {
      return true;
    }
  }

  function setGuide(show: boolean) {
    guide = show;
    try {
      if (show) localStorage.removeItem(GUIDE_KEY);
      else localStorage.setItem(GUIDE_KEY, '1');
    } catch {
      // storage unavailable (private mode): the choice lasts for this page
    }
  }

  // Next steps point at a zone where they apply: foreign records to adopt,
  // managed records to export.
  const adoptZone = $derived(zones?.find((z) => z.foreign > 0) ?? zones?.[0]);
  const exportZone = $derived(zones?.find((z) => z.managed > 0));

  $effect(() => {
    api
      .zones()
      .then((z) => (zones = [...z].sort((a, b) => b.tainted - a.tainted || a.zone.localeCompare(b.zone))))
      .catch((e: Error) => (error = e.message));
  });

  const totals = $derived(
    (zones ?? []).reduce(
      (t, z) => ({
        managed: t.managed + z.managed,
        tainted: t.tainted + z.tainted,
        pending: t.pending + z.pending,
        foreign: t.foreign + z.foreign,
        rrsets: t.rrsets + z.rrsets,
      }),
      { managed: 0, tainted: 0, pending: 0, foreign: 0, rrsets: 0 },
    ),
  );
</script>

<section class="hero">
  <p class="eyebrow">Custody register</p>
  {#if zones}
    <h1>
      <span class="num big">{totals.managed}</span>
      <span class="of">record sets held by the gate, across {zones.length} {zones.length === 1 ? 'zone' : 'zones'}</span>
    </h1>
    <ul class="totals" aria-label="Totals">
      <li class:alarm={totals.tainted > 0} title={statusHelp.tainted}>
        <Seal status="tainted" />
        <span class="num">{totals.tainted}</span> drifted outside the gate
      </li>
      <li title={statusHelp.pending}><Seal status="pending" /> <span class="num">{totals.pending}</span> pending</li>
      <li title={statusHelp.foreign}><Seal status="foreign" /> <span class="num">{totals.foreign}</span> foreign, read-only</li>
      {#if !guide}<li><button class="reopen" type="button" onclick={() => setGuide(true)}>How the gate works</button></li>{/if}
    </ul>
  {:else if !error}
    <div class="skeleton" style:height="34px" style:width="420px"></div>
  {/if}
</section>

{#if guide}
  <aside class="guide" aria-labelledby="guide-title">
    <div class="guide-head">
      <h2 id="guide-title">How the gate works</h2>
      <button class="btn quiet icon" type="button" aria-label="Dismiss" title="Dismiss" onclick={() => setGuide(false)}><Icon name="x" size={14} /></button>
    </div>
    <p class="lead">The gate holds the EuroDNS key and changes DNS records for teams, under their permissions. Each record set has a status:</p>
    <dl class="legend">
      {#each legend as st (st)}
        <div><dt><Seal status={st} size={12} />{statusLabel[st]}</dt><dd>{statusHelp[st]}</dd></div>
      {/each}
    </dl>
    <ul class="next" aria-label="Next steps">
      {#if adoptZone}<li><a href={zoneHref(adoptZone.zone, { status: 'foreign' })}>Open a zone to adopt existing records <Icon name="arrow" size={13} /></a></li>{/if}
      {#if exportZone}<li><a href={zoneHref(exportZone.zone, { export: 'terraform' })}>Export Terraform for adopted records <Icon name="arrow" size={13} /></a></li>{/if}
      <li><a href={connectHref()}>Connect your tools <Icon name="arrow" size={13} /></a></li>
    </ul>
  </aside>
{/if}

{#if error}
  <div class="empty"><strong>Zones could not be loaded</strong>{error}</div>
{:else if zones && zones.length === 0}
  <div class="empty"><strong>No managed zones</strong>Add zones to the gate configuration to see them here.</div>
{:else}
  <ol class="register">
    {#each zones ?? [null, null, null] as z, i (z?.zone ?? i)}
      <li class="row" class:drift={!!z && z.tainted > 0} style:animation-delay="{i * 40}ms">
        {#if z}
          <a class="cover" href={zoneHref(z.zone)} aria-label="Open {z.zone}"></a>
          <div class="ident">
            <h2 class="mono">{z.zone}</h2>
            <span class="meta">
              <span class="num">{z.rrsets}</span> record sets · synced <RelTime iso={z.last_synced_at} />
            </span>
          </div>

          <div class="custody">
            <CustodyStrip {z} />
            <dl class="counts">
              <div><dt title={statusHelp.managed}><Seal status="managed" size={12} />Managed</dt><dd class="num" class:zero={z.managed === 0}>{z.managed}</dd></div>
              <div class:hot={z.pending > 0}><dt title={statusHelp.pending}><Seal status="pending" size={12} />Pending</dt><dd class="num" class:zero={z.pending === 0}>{z.pending}</dd></div>
              <div class:hot={z.tainted > 0}><dt title={statusHelp.tainted}><Seal status="tainted" size={12} />Drifted</dt><dd class="num" class:zero={z.tainted === 0}>{z.tainted}</dd></div>
              <div><dt title={statusHelp.foreign}><Seal status="foreign" size={12} />Foreign</dt><dd class="num" class:zero={z.foreign === 0}>{z.foreign}</dd></div>
            </dl>
          </div>

          <div class="last">
            <span class="eyebrow">Last gate write</span>
            {#if z.last_write_at}<RelTime iso={z.last_write_at} />{:else}<span class="never">never</span>{/if}
            <a class="journal" href={journalHref({ zone: z.zone })}><Icon name="history" size={13} /> Journal</a>
          </div>

          {#if z.tainted > 0}
            <a class="alert" href={zoneHref(z.zone, { status: 'tainted' })}>
              <Icon name="alert" size={14} />
              {z.tainted} {z.tainted === 1 ? 'record set was' : 'record sets were'} changed outside the gate. Writes on them are blocked until re-adopted.
              <span class="go">Review <Icon name="arrow" size={13} /></span>
            </a>
          {/if}
        {:else}
          <div class="skeleton" style:height="18px" style:width="180px"></div>
          <div class="skeleton" style:height="8px"></div>
        {/if}
      </li>
    {/each}
  </ol>
{/if}

<style>
  .hero {
    margin-bottom: var(--s8);
    display: grid;
    gap: var(--s3);
  }
  h1 {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: var(--s3);
    font-weight: 500;
    letter-spacing: -0.015em;
  }
  .big {
    font-size: 44px;
    line-height: 1;
    font-weight: 600;
    letter-spacing: -0.03em;
    color: var(--seal-ink);
  }
  .of {
    font-size: var(--t-h3);
    color: var(--ink-2);
  }
  .totals {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: var(--s2) var(--s6);
    color: var(--ink-3);
  }
  .totals li {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .totals .num {
    color: var(--ink);
    font-weight: 600;
  }
  .totals .alarm,
  .totals .alarm .num {
    color: var(--wax);
  }

  .reopen {
    padding: 0;
    border: 0;
    background: none;
    color: var(--seal-ink);
    cursor: pointer;
  }
  .reopen:hover {
    text-decoration: underline;
  }

  .guide {
    display: grid;
    gap: var(--s3);
    margin-bottom: var(--s6);
    padding: var(--s4) var(--s5);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
    animation: rise 260ms var(--ease-out) both;
  }
  .guide-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s3);
    margin: -4px -8px -4px 0;
  }
  .guide h2 {
    font-size: var(--t-lead);
    letter-spacing: -0.01em;
  }
  .guide .lead {
    color: var(--ink-2);
  }
  .legend {
    margin: 0;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: var(--s3) var(--s6);
  }
  .legend div {
    display: grid;
    align-content: start;
    gap: 2px;
  }
  .legend dt {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
  }
  .legend dd {
    margin: 0;
    color: var(--ink-3);
    font-size: 12.5px;
  }
  .next {
    list-style: none;
    margin: 0;
    padding: var(--s3) 0 0;
    border-top: 1px solid var(--rule-soft);
    display: flex;
    flex-wrap: wrap;
    gap: var(--s2) var(--s6);
  }
  .next a {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--seal-ink);
    font-weight: 500;
    text-decoration: none;
  }
  .next a:hover {
    text-decoration: underline;
  }

  .register {
    list-style: none;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--rule);
  }
  .row {
    position: relative;
    display: grid;
    grid-template-columns: minmax(220px, 1.1fr) minmax(280px, 1.6fr) minmax(150px, 0.6fr);
    gap: var(--s4) var(--s8);
    align-items: center;
    padding: var(--s5) var(--s4);
    border-bottom: 1px solid var(--rule);
    animation: rise 260ms var(--ease-out) both;
    transition: background-color 120ms var(--ease-out);
  }
  .row:hover {
    background: var(--sheet);
  }
  .row.drift {
    box-shadow: inset 3px 0 0 var(--wax);
  }
  .cover {
    position: absolute;
    inset: 0;
    z-index: 0;
  }
  .row > :not(.cover) {
    position: relative;
    z-index: 1;
    pointer-events: none;
  }
  .row a:not(.cover) {
    pointer-events: auto;
  }
  .ident {
    display: grid;
    gap: 2px;
    min-width: 0;
  }
  h2 {
    font-size: var(--t-lead);
    font-weight: 600;
    letter-spacing: -0.01em;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .meta {
    color: var(--ink-3);
    font-size: 12px;
  }
  .custody {
    display: grid;
    gap: var(--s3);
  }
  .counts {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    gap: var(--s1) var(--s5);
  }
  .counts div {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--ink-3);
    font-size: 12px;
  }
  .counts dt {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    pointer-events: auto;
    cursor: help;
  }
  .counts dd {
    margin: 0;
    color: var(--ink);
    font-weight: 600;
  }
  .counts dd.zero {
    color: var(--ink-4);
    font-weight: 500;
  }
  .counts .hot:nth-child(3) dd,
  .counts .hot:nth-child(3) dt {
    color: var(--wax);
  }
  .counts .hot:nth-child(2) dd {
    color: var(--brass);
  }
  .last {
    display: grid;
    justify-items: end;
    gap: 2px;
    color: var(--ink-2);
  }
  .never {
    color: var(--ink-4);
  }
  .journal {
    margin-top: var(--s1);
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--ink-3);
    font-size: 12px;
    text-decoration: none;
  }
  .journal:hover {
    color: var(--seal-ink);
  }
  .alert {
    grid-column: 1 / -1;
    display: flex;
    align-items: center;
    gap: var(--s2);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--wax-wash);
    color: var(--wax);
    text-decoration: none;
    font-weight: 500;
  }
  .alert .go {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    white-space: nowrap;
  }
  .alert:hover .go {
    text-decoration: underline;
  }
  @media (max-width: 900px) {
    .row {
      grid-template-columns: 1fr;
      gap: var(--s3);
    }
    .last {
      justify-items: start;
      grid-auto-flow: column;
      justify-content: start;
      gap: var(--s3);
      align-items: center;
    }
    .journal {
      margin: 0;
    }
  }
</style>
