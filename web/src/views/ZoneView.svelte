<script lang="ts">
  import { api } from '../lib/api';
  import type { AdoptResult, Me, RRset, RRsetRef, Status, ZoneInventory } from '../lib/types';
  import { takeAdopt, type StoredAdopt } from '../lib/adoptDraft';
  import AdoptPanel from '../components/AdoptPanel.svelte';
  import TerraformPanel from '../components/TerraformPanel.svelte';
  import { router, href, journalHref } from '../lib/router.svelte';
  import { statusLabel } from '../lib/labels';
  import { ttl as fmtTTL } from '../lib/format';
  import Seal from '../components/Seal.svelte';
  import Host from '../components/Host.svelte';
  import ActorChip from '../components/ActorChip.svelte';
  import RelTime from '../components/RelTime.svelte';
  import RRsetDrawer from '../components/RRsetDrawer.svelte';
  import CustodyStrip from '../components/CustodyStrip.svelte';
  import Icon from '../components/Icon.svelte';

  let { zone }: { zone: string } = $props();

  let inv = $state<ZoneInventory | null>(null);
  let error = $state<string | null>(null);

  let me = $state<Me | null>(null);
  let selecting = $state(false);
  let picked = $state<string[]>([]);
  let adoptOpen = $state(false);
  let tfOpen = $state(false);
  let canAdopt = $state(true);
  let restored = $state<StoredAdopt | null>(null);

  const load = () =>
    api
      .inventory(zone)
      .then((z) => (inv = z))
      .catch((e: Error) => (error = e.message));

  $effect(() => {
    load();
    api.me().then((m) => (me = m)).catch(() => (me = null));
    const r = takeAdopt(zone);
    if (r) {
      restored = r;
      picked = (r.selection.rrsets ?? []).map((x) => `${x.host}/${x.type}`);
      adoptOpen = true;
    }
  });

  const keyOf = (r: { host: string; type: string }) => `${r.host}/${r.type}`;
  const pickedRefs = $derived(
    picked.map((k): RRsetRef => {
      const i = k.lastIndexOf('/');
      return { host: k.slice(0, i), type: k.slice(i + 1) };
    }),
  );
  const togglePick = (r: RRset) =>
    (picked = picked.includes(keyOf(r)) ? picked.filter((k) => k !== keyOf(r)) : [...picked, keyOf(r)]);

  function onAdopted(_r: AdoptResult) {
    picked = [];
    selecting = false;
    load();
  }

  const q = $derived(router.params.get('q') ?? '');
  const statusF = $derived(router.params.get('status') ?? '');
  const typeF = $derived(router.params.get('type') ?? '');
  const ownerF = $derived(router.params.get('owner') ?? '');
  const selectedKey = $derived(router.params.get('rr') ?? '');

  // Zone-file order: sort by reversed labels so children sit under their parents.
  const sortKey = (r: RRset) => (r.host === '@' ? '' : r.host.split('.').reverse().join('.')) + ' ' + r.type;
  const rrsets = $derived(inv ? [...inv.rrsets].sort((a, b) => sortKey(a).localeCompare(sortKey(b))) : []);

  const bucket = (s: Status) => (s === 'missing' ? 'tainted' : s);
  const counts = $derived(
    rrsets.reduce<Record<string, number>>((c, r) => ((c[bucket(r.status)] = (c[bucket(r.status)] ?? 0) + 1), c), {}),
  );
  const types = $derived([...new Set(rrsets.map((r) => r.type))].sort());
  const owners = $derived([...new Set(rrsets.map((r) => r.owner).filter((o): o is string => !!o))].sort());

  const shown = $derived(
    rrsets.filter((r) => {
      if (statusF && bucket(r.status) !== statusF) return false;
      if (typeF && r.type !== typeF) return false;
      if (ownerF && r.owner !== ownerF) return false;
      if (q) {
        const n = q.toLowerCase();
        const hay = [r.host, r.type, r.owner ?? '', r.created_by?.name ?? '', r.updated_by?.name ?? '', ...r.values]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(n)) return false;
      }
      return true;
    }),
  );

  const selected = $derived(rrsets.find((r) => `${r.host}/${r.type}` === selectedKey) ?? null);
  const summary = $derived(
    inv
      ? {
          zone,
          rrsets: rrsets.length,
          managed: counts.managed ?? 0,
          tainted: counts.tainted ?? 0,
          pending: counts.pending ?? 0,
          foreign: counts.foreign ?? 0,
        }
      : null,
  );

  const tabs: { key: string; label: string }[] = [
    { key: '', label: 'All' },
    { key: 'managed', label: statusLabel.managed },
    { key: 'tainted', label: 'Drifted' },
    { key: 'pending', label: statusLabel.pending },
    { key: 'foreign', label: statusLabel.foreign },
  ];

  const open = (r: RRset) => {
    if (selecting) {
      if (r.status === 'foreign') togglePick(r);
      return;
    }
    router.setParams({ rr: `${r.host}/${r.type}` }, true);
  };
  const shownForeign = $derived(shown.filter((r) => r.status === 'foreign'));
  const close = () => router.setParams({ rr: undefined });
  const rowKey = (e: KeyboardEvent, r: RRset) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      open(r);
    }
  };
  const lastActor = (r: RRset) => r.updated_by ?? r.created_by;
  const lastAt = (r: RRset) => r.updated_at ?? r.created_at;
</script>

<nav class="crumbs" aria-label="Breadcrumb"><a href={href('/')}>Zones</a><span aria-hidden="true">/</span></nav>

<header class="head">
  <div class="title">
    <h1 class="mono">{zone}</h1>
    <p class="meta">
      {#if inv}
        <span class="num">{rrsets.length}</span> record sets · synced <RelTime iso={inv.last_synced_at} /> ·
        <a href={journalHref({ zone })}>journal</a>
      {:else if !error}loading…{/if}
    </p>
  </div>
  {#if summary}<div class="strip"><CustodyStrip z={summary} height={10} /></div>{/if}
</header>

{#if error}
  <div class="empty"><strong>This zone could not be loaded</strong>{error}</div>
{:else}
  <div class="filters">
    <div class="tabs" role="tablist" aria-label="Filter by status">
      {#each tabs as t (t.key)}
        <button
          role="tab"
          type="button"
          aria-selected={statusF === t.key}
          class="tab {t.key}"
          onclick={() => router.setParams({ status: t.key || undefined })}
        >
          {#if t.key}<Seal status={t.key as Status} size={12} />{/if}
          {t.label}
          <span class="count num">{t.key ? (counts[t.key] ?? 0) : rrsets.length}</span>
        </button>
      {/each}
    </div>
    <div class="right">
      <label class="field search">
        <Icon name="search" size={14} />
        <span class="sr-only">Search records</span>
        <input
          type="search"
          placeholder="Host, value, owner, actor…"
          value={q}
          oninput={(e) => router.setParams({ q: e.currentTarget.value || undefined })}
        />
      </label>
      <label class="field">
        <span class="sr-only">Type</span>
        <select value={typeF} onchange={(e) => router.setParams({ type: e.currentTarget.value || undefined })}>
          <option value="">All types</option>
          {#each types as t (t)}<option value={t}>{t}</option>{/each}
        </select>
        <span class="chev"><Icon name="chevron" size={12} /></span>
      </label>
      <label class="field">
        <span class="sr-only">Owner team</span>
        <select value={ownerF} onchange={(e) => router.setParams({ owner: e.currentTarget.value || undefined })}>
          <option value="">All owners</option>
          {#each owners as o (o)}<option value={o}>{o}</option>{/each}
        </select>
        <span class="chev"><Icon name="chevron" size={12} /></span>
      </label>
      {#if canAdopt && (counts.foreign ?? 0) > 0}
        <button class="btn" class:on={selecting} type="button" aria-pressed={selecting} onclick={() => { selecting = !selecting; if (!selecting) picked = []; }}>
          <Seal status="managed" size={13} />{selecting ? 'Selecting…' : 'Adopt…'}
        </button>
      {/if}
      <button class="btn" type="button" onclick={() => (tfOpen = true)}><Icon name="download" size={13} />Export Terraform</button>
    </div>
  </div>

  <div class="sheet">
    <table>
      <thead>
        <tr>
          <th class="c-seal"><span class="sr-only">Status</span></th>
          <th>Name</th>
          <th class="c-type">Type</th>
          <th>Values</th>
          <th class="c-ttl">TTL</th>
          <th class="c-owner">Owner</th>
          <th class="c-custody">Custody</th>
        </tr>
      </thead>
      <tbody>
        {#if !inv}
          {#each [0, 1, 2, 3, 4] as i (i)}
            <tr class="loading"><td colspan="7"><div class="skeleton bar"></div></td></tr>
          {/each}
        {:else}
          {#each shown as r (r.host + '/' + r.type)}
            <tr
              class={r.status}
              class:selected={selected === r || (selecting && picked.includes(keyOf(r)))}
              class:inert={selecting && r.status !== 'foreign'}
              tabindex="0"
              onclick={() => open(r)}
              onkeydown={(e) => rowKey(e, r)}
              aria-label="{r.host} {r.type}, {statusLabel[r.status]}"
            >
              <td class="c-seal">
                {#if selecting && r.status === 'foreign'}
                  <input type="checkbox" class="pick" checked={picked.includes(keyOf(r))} onclick={(e) => e.stopPropagation()} onchange={() => togglePick(r)} aria-label="Select {r.host} {r.type}" />
                {:else}
                  <Seal status={r.status} title={statusLabel[r.status]} />
                {/if}
              </td>
              <td class="c-name">
                <div class="name">
                  <Host host={r.host} {zone} showZone={false} />
                  {#if r.protected}<span class="ico" title="Protected: no role may change it"><Icon name="lock" size={12} /></span>{/if}
                  {#if r.expires_at}<span class="ephemeral" title="Ephemeral record, removed automatically"><Icon name="clock" size={12} /><RelTime iso={r.expires_at} /></span>{/if}
                </div>
              </td>
              <td class="c-type"><span class="type mono">{r.type}</span></td>
              <td class="c-values">
                <ul class="mono">
                  {#each r.values.slice(0, 3) as v (v)}<li>{v}</li>{/each}
                  {#if r.values.length > 3}<li class="more">+{r.values.length - 3} more</li>{/if}
                </ul>
              </td>
              <td class="c-ttl mono num">{fmtTTL(r.ttl)}</td>
              <td class="c-owner">{#if r.owner}<span class="team">{r.owner}</span>{:else}<span class="ro">read-only</span>{/if}</td>
              <td class="c-custody">
                {#if lastActor(r)}
                  {@const a = lastActor(r)}
                  {#if a}<ActorChip actor={a} quiet />{/if}
                  <span class="when"><RelTime iso={lastAt(r)} /></span>
                {:else}
                  <span class="ro">registrar console</span>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="7"><div class="empty"><strong>No record sets match</strong>Clear the filters to see the whole zone.</div></td></tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if selecting}
  <div class="pickbar" role="region" aria-label="Adoption selection">
    <span class="n"><b class="num">{picked.length}</b> foreign record set{picked.length === 1 ? '' : 's'} selected</span>
    <button class="btn quiet" type="button" disabled={!shownForeign.length} onclick={() => (picked = [...new Set([...picked, ...shownForeign.map(keyOf)])])}>Select all foreign shown ({shownForeign.length})</button>
    {#if picked.length}<button class="btn quiet" type="button" onclick={() => (picked = [])}>Clear</button>{/if}
    <span class="sp"></span>
    <button class="btn quiet" type="button" onclick={() => { selecting = false; picked = []; }}>Cancel</button>
    <button class="btn primary" type="button" onclick={() => (adoptOpen = true)}>{picked.length ? 'Adopt…' : 'Adopt by filter…'}</button>
  </div>
{/if}

{#if adoptOpen && inv}
  <AdoptPanel
    {zone}
    selected={pickedRefs}
    teams={me?.teams ?? []}
    types={types}
    initialComment={restored?.comment ?? ''}
    initialFilter={restored ? { hosts: restored.selection.hosts ?? [], types: restored.selection.types ?? [], owner: restored.selection.owner } : undefined}
    onclose={() => { adoptOpen = false; restored = null; }}
    onadopted={onAdopted}
    onforbidden={() => { canAdopt = false; selecting = false; picked = []; }}
  />
{/if}

{#if tfOpen}
  <TerraformPanel {zone} teams={me?.teams ?? []} {owners} onclose={() => (tfOpen = false)} />
{/if}

{#if selected && !selecting}
  {#key selectedKey}<RRsetDrawer {zone} rr={selected} onclose={close} />{/key}
{/if}

<style>
  .crumbs {
    display: flex;
    gap: var(--s2);
    color: var(--ink-4);
    font-size: 12px;
    margin-bottom: var(--s2);
  }
  .crumbs a {
    color: var(--ink-3);
    text-decoration: none;
  }
  .crumbs a:hover {
    color: var(--seal-ink);
  }
  .head {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(200px, 360px);
    align-items: end;
    gap: var(--s4) var(--s8);
    margin-bottom: var(--s6);
  }
  h1 {
    font-size: var(--t-h1);
    letter-spacing: -0.02em;
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .meta {
    color: var(--ink-3);
    margin-top: var(--s1);
  }
  .meta a {
    color: var(--ink-3);
    text-decoration-color: var(--rule-strong);
    text-underline-offset: 3px;
  }
  .meta a:hover {
    color: var(--seal-ink);
  }
  .strip {
    padding-bottom: 6px;
  }

  .filters {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: var(--s3);
    margin-bottom: var(--s3);
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
  .tab {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border: 0;
    border-radius: 7px;
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    font-weight: 500;
    transition:
      background-color 120ms var(--ease-out),
      color 120ms var(--ease-out);
  }
  .tab:hover {
    color: var(--ink);
  }
  .tab[aria-selected='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .count {
    font-size: 11.5px;
    color: var(--ink-4);
  }
  .tab.tainted .count {
    color: var(--wax);
  }
  .right {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s2);
  }
  .search input {
    width: 220px;
  }

  .sheet {
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
    overflow-x: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 860px;
  }
  th {
    text-align: left;
    font-size: var(--t-caption);
    font-weight: 500;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--ink-3);
    padding: var(--s2) var(--s3);
    border-bottom: 1px solid var(--rule);
    white-space: nowrap;
  }
  td {
    padding: 10px var(--s3);
    border-bottom: 1px solid var(--rule-soft);
    vertical-align: top;
  }
  tbody tr:last-child td {
    border-bottom: 0;
  }
  tbody tr[tabindex] {
    cursor: pointer;
    transition: background-color 100ms var(--ease-out);
  }
  tbody tr[tabindex]:hover {
    background: var(--rule-soft);
  }
  tbody tr.selected {
    background: var(--seal-ink-wash);
  }
  tbody tr:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: -2px;
  }
  .c-seal {
    width: 36px;
    padding-right: 0;
  }
  .c-seal :global(svg) {
    margin-top: 2px;
  }
  .c-type {
    width: 70px;
  }
  .c-ttl {
    width: 60px;
    color: var(--ink-3);
  }
  .c-owner {
    width: 110px;
  }
  .c-custody {
    width: 230px;
  }
  .name {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .ico {
    color: var(--ink-4);
  }
  .ephemeral {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    font-size: 11.5px;
    color: var(--brass);
  }
  .type {
    font-size: 11.5px;
    font-weight: 600;
    color: var(--ink-2);
  }
  .c-values ul {
    list-style: none;
    margin: 0;
    padding: 0;
    color: var(--ink-2);
  }
  .c-values li {
    overflow-wrap: anywhere;
  }
  .c-values .more {
    color: var(--ink-4);
    font-family: var(--font-ui);
    font-size: 12px;
  }
  .team {
    font-weight: 500;
  }
  .ro {
    color: var(--ink-4);
    font-size: 12px;
  }
  .c-custody {
    font-size: 12.5px;
  }
  .when {
    display: block;
    margin: 2px 0 0 26px;
    color: var(--ink-4);
    font-size: 11.5px;
  }
  tr.foreign td {
    color: var(--ink-3);
  }
  tr.foreign :global(.label),
  tr.foreign .type {
    color: var(--ink-3);
  }
  tr.tainted .c-name :global(.label),
  tr.missing .c-name :global(.label) {
    color: var(--wax);
  }
  tr.missing .c-values li {
    text-decoration: line-through;
    text-decoration-color: var(--rule-strong);
  }
  .bar {
    height: 16px;
  }
  .btn.on {
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
    border-color: color-mix(in srgb, var(--seal-ink) 30%, transparent);
  }
  tbody tr.inert {
    opacity: 0.4;
    cursor: default;
  }
  .pick {
    width: 15px;
    height: 15px;
    margin: 1px 0 0;
    accent-color: var(--seal-ink);
    cursor: pointer;
  }
  .pickbar {
    position: sticky;
    bottom: var(--s4);
    z-index: 5;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
    margin-top: var(--s4);
    padding: var(--s2) var(--s2) var(--s2) var(--s4);
    border-radius: var(--r-lg);
    background: var(--sheet-raised);
    border: 1px solid var(--rule);
    box-shadow: var(--lift);
    animation: rise 200ms var(--ease-out);
  }
  .pickbar .n {
    color: var(--ink-2);
  }
  .pickbar .sp {
    flex: 1;
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  @media (max-width: 900px) {
    .head {
      grid-template-columns: 1fr;
    }
    .search input {
      width: 160px;
    }
  }
  @media (max-width: 720px) {
    .search {
      flex: 1 1 100%;
    }
    .search input {
      width: 100%;
    }
    table {
      min-width: 0;
    }
    thead {
      display: none;
    }
    tbody tr {
      display: grid;
      grid-template-columns: 24px minmax(0, 1fr) 56px;
      grid-template-areas:
        'seal name type'
        '. values values'
        '. owner custody';
      gap: 6px var(--s2);
      padding: var(--s3);
      border-bottom: 1px solid var(--rule-soft);
    }
    tbody tr:last-child {
      border-bottom: 0;
    }
    td {
      display: block;
      padding: 0;
      border: 0;
      width: auto;
    }
    .c-seal {
      grid-area: seal;
      width: auto;
    }
    .c-name {
      grid-area: name;
    }
    .c-type {
      grid-area: type;
      width: auto;
      text-align: right;
    }
    .c-values {
      grid-area: values;
    }
    .c-ttl {
      display: none;
    }
    .c-owner {
      grid-area: owner;
      width: auto;
      font-size: 12px;
    }
    .c-custody {
      grid-area: custody;
      width: auto;
      justify-self: end;
      text-align: right;
    }
    .when {
      margin-left: 0;
    }
    tr.loading,
    tr:not([tabindex]) {
      display: block;
    }
  }
</style>
