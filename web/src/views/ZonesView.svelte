<script lang="ts">
  import { api } from '../lib/api';
  import type { Me, ZoneSummary } from '../lib/types';
  import { canPropose } from '../lib/manageZone';
  import ManageZone from '../components/ManageZone.svelte';
  import { router, zoneHref, journalHref, connectHref } from '../lib/router.svelte';
  import { statusHelp, statusLabel } from '../lib/labels';
  import { managedSplit, plural, zoneFilters, zoneNeedsAttention, type ZoneFilter } from '../lib/zones';
  import HealthSummary from '../components/HealthSummary.svelte';
  import Seal from '../components/Seal.svelte';
  import RelTime from '../components/RelTime.svelte';
  import Icon from '../components/Icon.svelte';
  import ProviderBadge from '../components/ProviderBadge.svelte';
  import { providerLabel } from '../lib/labels';
  import { folderLabel, folderOptions, inFolder } from '../lib/folders';

  let all = $state<ZoneSummary[] | null>(null);
  let error = $state<string | null>(null);
  let me = $state<Me | null>(null);

  const admin = $derived(canPropose(me));

  const legend = ['managed', 'foreign', 'pending', 'tainted'] as const;
  const GUIDE_KEY = 'dns-gate.guide-dismissed';
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

  $effect(() => {
    api
      .zones()
      .then((z) => (all = z))
      .catch((e: Error) => (error = e.message));
    api.me().then((m) => (me = m)).catch(() => (me = null));
  });

  // Managed zones first, those that need attention on top; zones that are not
  // managed are listed apart, compact, read-only.
  const byAttention = (a: ZoneSummary, b: ZoneSummary) =>
    b.tainted - a.tainted || b.pending - a.pending || a.zone.localeCompare(b.zone);
  const managed = $derived((all ?? []).filter((z) => !z.unmanaged).sort(byAttention));
  const unmanaged = $derived((all ?? []).filter((z) => z.unmanaged).sort((a, b) => a.zone.localeCompare(b.zone)));
  const attention = $derived(managed.filter(zoneNeedsAttention));

  const q = $derived((router.params.get('q') ?? '').trim().toLowerCase());
  const filter = $derived<ZoneFilter>(
    (zoneFilters as readonly string[]).includes(router.params.get('filter') ?? '') ? (router.params.get('filter') as ZoneFilter) : 'all',
  );
  // EuroDNS folders: the filter is a folder glob, read as ?folder= of the API
  // ("/ES" that folder only, "/ES/**" every folder below it).
  const folders = $derived(folderOptions(all ?? []));
  const folderSel = $derived(router.params.get('folder') ?? '');
  const match = (z: ZoneSummary) => (!q || z.zone.includes(q)) && inFolder(folderSel, z.folder);
  const shownManaged = $derived(filter === 'unmanaged' ? [] : (filter === 'attention' ? attention : managed).filter(match));
  const shownUnmanaged = $derived(filter === 'all' || filter === 'unmanaged' ? unmanaged.filter(match) : []);

  const tabs = $derived([
    { key: 'all', label: 'All', n: (all ?? []).length },
    { key: 'managed', label: 'Managed', n: managed.length },
    { key: 'unmanaged', label: 'Not managed', n: unmanaged.length },
    { key: 'attention', label: 'Needs attention', n: attention.length },
  ]);

  // Hundreds of zones that are not managed: shown a page at a time.
  const STEP = 60;
  let limit = $state(STEP);
  $effect(() => {
    void q;
    void filter;
    void folderSel;
    limit = STEP;
  });
  const pageUnmanaged = $derived(shownUnmanaged.slice(0, limit));

  // "Manage…" unfolds the proposal step inside the row, one zone at a time.
  let managing = $state<string | null>(null);

  let searchInput = $state(router.params.get('q') ?? '');
  let debounce: ReturnType<typeof setTimeout> | undefined;
  function onSearch(v: string) {
    searchInput = v;
    clearTimeout(debounce);
    debounce = setTimeout(() => router.setParams({ q: v.trim() || undefined }), 150);
  }

  const providers = $derived([...new Set((all ?? []).map((z) => z.provider).filter((p): p is string => !!p))].sort());
  const multiProvider = $derived(providers.length > 1);
  const totals = $derived(managed.reduce((t, z) => ({ managed: t.managed + z.managed, rrsets: t.rrsets + z.rrsets }), { managed: 0, rrsets: 0 }));
  const adoptZone = $derived(managed.find((z) => z.foreign > 0) ?? managed[0]);
  const exportZone = $derived(managed.find((z) => z.managed > 0));
</script>

<header class="head">
  <h1>Zones</h1>
  {#if all}
    <p class="split">
      <span><b class="num">{managed.length.toLocaleString('en')}</b> managed by the gate</span>
      <span class="sep" aria-hidden="true">·</span>
      <span><b class="num">{unmanaged.length.toLocaleString('en')}</b> not managed (read-only)</span>
      {#if managed.length}
        <span class="sep" aria-hidden="true">·</span>
        <span class="dim">{plural(totals.managed, 'record set')} managed across them</span>
      {/if}
      {#if !guide}<button class="reopen" type="button" onclick={() => setGuide(true)}>How the gate works</button>{/if}
    </p>
  {:else if !error}
    <div class="skeleton" style:height="18px" style:width="min(420px, 100%)"></div>
  {/if}
</header>

{#if all}
  <div class="top" class:with-guide={guide}>
    <HealthSummary zones={all} />
    {#if guide}
      <aside class="guide" aria-labelledby="guide-title">
        <div class="guide-head">
          <h2 id="guide-title">How the gate works</h2>
          <button class="btn quiet icon" type="button" aria-label="Dismiss the guide" title="Dismiss" onclick={() => setGuide(false)}><Icon name="x" size={14} /></button>
        </div>
        <p class="lead">
          The gate holds the keys of the DNS {providers.length > 1 ? 'providers' : 'provider'}{providers.length ? ` (${providers.map(providerLabel).join(', ')})` : ''} and changes DNS records for teams, within their permissions. A zone is either
          <b>managed by the gate</b> (changes go through it) or <b>not managed</b> (shown read-only). In a managed zone, each record set has a status:
        </p>
        <dl class="legend">
          {#each legend as st (st)}
            <div><dt><Seal status={st} size={12} />{statusLabel[st]}</dt><dd>{statusHelp[st]}</dd></div>
          {/each}
        </dl>
        <ul class="next" aria-label="Next steps">
          {#if adoptZone}<li><a href={zoneHref(adoptZone.zone, { status: 'foreign' })}>Adopt existing records <Icon name="arrow" size={14} /></a></li>{/if}
          {#if exportZone}<li><a href={zoneHref(exportZone.zone, { export: 'terraform' })}>Export Terraform <Icon name="arrow" size={14} /></a></li>{/if}
          <li><a href={connectHref()}>Connect your tools <Icon name="arrow" size={14} /></a></li>
        </ul>
      </aside>
    {/if}
  </div>
{/if}

{#if error}
  <div class="empty"><strong>Zones could not be loaded</strong>{error}</div>
{:else}
  <div class="toolbar">
    <label class="field search">
      <Icon name="search" size={14} />
      <span class="sr-only">Search zones</span>
      <input type="search" placeholder="Search zones" value={searchInput} oninput={(e) => onSearch(e.currentTarget.value)} />
    </label>
    {#if folders.length || folderSel}
      <label class="field folder">
        <Icon name="folder" size={14} />
        <span class="sr-only">Folder</span>
        <select value={folderSel} onchange={(e) => router.setParams({ folder: e.currentTarget.value || undefined })}>
          <option value="">All folders</option>
          {#each folders.includes(folderSel) || !folderSel ? folders : [folderSel, ...folders] as f (f)}<option value={f}>{folderLabel(f)}</option>{/each}
        </select>
        <span class="chev"><Icon name="chevron" size={12} /></span>
      </label>
    {/if}
    <div class="tabs" role="radiogroup" aria-label="Show zones">
      {#each tabs as t (t.key)}
        <button
          type="button"
          role="radio"
          aria-checked={filter === t.key}
          class:hot={t.key === 'attention' && t.n > 0}
          onclick={() => router.setParams({ filter: t.key === 'all' ? undefined : t.key })}
        >
          {t.label}<span class="count num">{all ? t.n.toLocaleString('en') : '…'}</span>
        </button>
      {/each}
    </div>
  </div>

  {#if !all}
    <ol class="register">
      {#each [0, 1, 2] as i (i)}<li class="row"><div class="skeleton" style:height="18px" style:width="200px"></div><div class="skeleton" style:height="12px"></div></li>{/each}
    </ol>
  {:else}
    {#if filter !== 'unmanaged'}
      <section aria-labelledby="managed-title">
        <h2 class="sec" id="managed-title">
          {filter === 'attention' ? 'Needs attention' : 'Managed by the gate'}
          <span class="count num">{shownManaged.length}</span>
        </h2>
        {#if shownManaged.length === 0}
          <p class="none">
            {#if q || folderSel}No managed zone matches {q ? `“${q}”` : ''}{q && folderSel ? ' in ' : ''}{folderSel ? `folder ${folderSel}` : ''}.
            {:else if filter === 'attention'}Nothing needs attention: no drifted or pending record set.
            {:else if unmanaged.length}No zone is managed yet. Bring a zone of the account under management below, or add it to the gate configuration.
            {:else}No zone is managed yet. Add zones to the gate configuration to see them here.{/if}
          </p>
        {:else}
          <ol class="register">
            {#each shownManaged as z (z.zone)}
              <li class="row">
                <a class="cover" href={zoneHref(z.zone)} aria-label="Open {z.zone}"></a>
                <div class="ident">
                  <h3 class="mono">{z.zone} <ProviderBadge provider={z.provider} /></h3>
                  <span class="meta"><span class="num">{z.rrsets.toLocaleString('en')}</span> record sets · synced <RelTime iso={z.last_synced_at} />{#if z.folder} · <span class="fold mono" title="Folder at the DNS provider"><Icon name="folder" size={12} />{z.folder}</span>{/if}</span>
                </div>
                <div class="state">
                  <span class="splitz">{managedSplit(z)}</span>
                  {#if z.tainted > 0}
                    <a class="chip wax" href={zoneHref(z.zone, { status: 'tainted' })} title={statusHelp.tainted}><Seal status="tainted" size={12} />{z.tainted} drifted</a>
                  {/if}
                  {#if z.pending > 0}
                    <a class="chip brass" href={zoneHref(z.zone, { status: 'pending' })} title={statusHelp.pending}><Seal status="pending" size={12} />{z.pending} pending</a>
                  {/if}
                </div>
                <div class="last">
                  {#if z.last_write_at}<span class="lbl">Last write</span> <RelTime iso={z.last_write_at} />{:else}<span class="never">No gate write yet</span>{/if}
                </div>
                <a class="journal" href={journalHref({ zone: z.zone })} aria-label="Journal of {z.zone}"><Icon name="history" size={14} /><span>Journal</span></a>
              </li>
            {/each}
          </ol>
        {/if}
      </section>
    {/if}

    {#if (filter === 'all' || filter === 'unmanaged') && unmanaged.length}
      <section class="discovered" aria-labelledby="discovered-title">
        <div class="dhead">
          <h2 class="sec" id="discovered-title">Not managed (read-only) <span class="count num">{shownUnmanaged.length.toLocaleString('en')}</span></h2>
          <p class="hint">
            Found at the DNS {providers.length > 1 ? 'providers' : 'provider'}. The gate shows them read-only: no write and no adoption until a zone is managed. Their records are read when you open them.
            {#if !admin}Only a policy administrator can bring a zone under management.{/if}
          </p>
        </div>
        {#if shownUnmanaged.length === 0}
          <p class="none">No zone matches {q ? `“${q}”` : ''}{q && folderSel ? ' in ' : ''}{folderSel ? `folder ${folderSel}` : ''}.</p>
        {:else}
          <ul class="compact">
            {#each pageUnmanaged as z (z.zone)}
              <li class="mini" class:open={managing === z.zone}>
                <a class="zname mono" href={zoneHref(z.zone)}>{z.zone}</a>
                {#if multiProvider}<ProviderBadge provider={z.provider} />{/if}
                {#if z.folder}<span class="mmeta fold mono" title="Folder at the DNS provider"><Icon name="folder" size={12} />{z.folder}</span>{/if}
                {#if z.last_synced_at}<span class="mmeta">{plural(z.rrsets, 'record set')}</span>{/if}
                {#if admin && managing !== z.zone}
                  <button class="btn quiet small manage" type="button" onclick={() => (managing = z.zone)} aria-label="Manage {z.zone}…">Manage…</button>
                {/if}
                {#if managing === z.zone}
                  <div class="unfold">
                    <ManageZone zone={z.zone} {me} />
                    <button class="btn quiet small" type="button" onclick={() => (managing = null)}>Cancel</button>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
          <div class="pager">
            <span class="dim">Showing <span class="num">{pageUnmanaged.length.toLocaleString('en')}</span> of <span class="num">{shownUnmanaged.length.toLocaleString('en')}</span></span>
            {#if pageUnmanaged.length < shownUnmanaged.length}
              <button class="btn" type="button" onclick={() => (limit += STEP)}>Show {Math.min(STEP, shownUnmanaged.length - pageUnmanaged.length)} more</button>
              <button class="btn quiet" type="button" onclick={() => (limit = shownUnmanaged.length)}>Show all</button>
            {/if}
          </div>
        {/if}
      </section>
    {/if}
  {/if}
{/if}

<style>
  .head {
    display: grid;
    gap: var(--s2);
    margin-bottom: var(--s5);
  }
  h1 {
    font-size: var(--t-h1);
    letter-spacing: -0.02em;
  }
  .split {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: var(--s1) var(--s2);
    color: var(--ink-2);
    font-size: var(--t-lead);
  }
  .split b {
    color: var(--ink);
    font-weight: 600;
  }
  .sep,
  .dim {
    color: var(--ink-3);
  }
  .reopen {
    margin-left: var(--s2);
    padding: 0;
    border: 0;
    background: none;
    color: var(--seal-ink);
    cursor: pointer;
    font-size: var(--t-body);
  }
  .reopen:hover {
    text-decoration: underline;
    text-underline-offset: 3px;
  }

  .top {
    display: grid;
    gap: var(--s4);
    margin-bottom: var(--s8);
    align-items: start;
  }
  @media (min-width: 1200px) {
    .top.with-guide {
      grid-template-columns: minmax(0, 5fr) minmax(0, 7fr);
    }
  }

  .guide {
    display: grid;
    gap: var(--s3);
    padding: var(--s4) var(--s5);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
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
  }
  .guide .lead {
    color: var(--ink-2);
    max-width: 75ch;
  }
  .guide .lead b {
    font-weight: 600;
    color: var(--ink);
  }
  .legend {
    margin: 0;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
    font-size: 13px;
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
    text-underline-offset: 3px;
  }

  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2) var(--s3);
    margin-bottom: var(--s5);
  }
  .search input {
    width: 260px;
  }
  .folder select {
    max-width: 220px;
  }
  .fold {
    display: inline-flex;
    align-items: center;
    gap: 3px;
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
  .tabs button:hover {
    color: var(--ink);
  }
  .tabs button[aria-checked='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .count {
    font-size: 12px;
    color: var(--ink-4);
    font-weight: 500;
  }
  .tabs .hot .count {
    color: var(--wax);
    font-weight: 600;
  }

  section {
    display: grid;
    gap: var(--s3);
  }
  .sec {
    display: flex;
    align-items: baseline;
    gap: var(--s2);
    font-size: var(--t-h3);
    letter-spacing: -0.01em;
  }
  .sec .count {
    font-size: var(--t-body);
  }
  .none {
    color: var(--ink-3);
    padding: var(--s4) 0;
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
    grid-template-columns: minmax(220px, 1.2fr) minmax(240px, 1.6fr) minmax(130px, auto) auto;
    gap: var(--s3) var(--s6);
    align-items: center;
    padding: var(--s4);
    border-bottom: 1px solid var(--rule);
    transition: background-color 120ms var(--ease-out);
  }
  .row:hover {
    background: var(--sheet);
  }
  .cover {
    position: absolute;
    inset: 0;
    z-index: 0;
    border-radius: var(--r-sm);
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
  h3 {
    font-size: var(--t-lead);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta {
    color: var(--ink-3);
    font-size: 12px;
  }
  .state {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
    min-width: 0;
  }
  .splitz {
    color: var(--ink-2);
    margin-right: var(--s1);
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 0;
    font-size: 12px;
    font-weight: 500;
    text-decoration: none;
  }
  .chip.wax {
    color: var(--wax);
  }
  .chip.brass {
    color: var(--brass);
  }
  .chip:hover {
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .last {
    display: flex;
    justify-content: flex-end;
    align-items: baseline;
    gap: 4px;
    color: var(--ink-2);
    font-size: 12px;
    white-space: nowrap;
  }
  .lbl {
    font-size: 12px;
    color: var(--ink-4);
  }
  .never {
    color: var(--ink-4);
  }
  .journal {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 6px;
    margin: -4px -6px;
    border-radius: var(--r-sm);
    color: var(--ink-3);
    font-size: 12px;
    text-decoration: none;
  }
  .journal:hover {
    color: var(--seal-ink);
    background: var(--rule-soft);
  }

  .discovered {
    margin-top: var(--s10);
  }
  .dhead {
    display: grid;
    gap: var(--s1);
  }
  .dhead .hint {
    color: var(--ink-3);
    max-width: 80ch;
  }
  .compact {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr));
    column-gap: var(--s6);
    border-top: 1px solid var(--rule-soft);
  }
  .mini {
    position: relative;
    display: flex;
    flex-wrap: nowrap;
    align-items: center;
    gap: 2px var(--s2);
    min-height: 40px;
    padding: 6px var(--s2);
    border-bottom: 1px solid var(--rule-soft);
  }
  .mini:hover,
  .mini:focus-within {
    background: var(--sheet);
  }
  .zname {
    min-width: 0;
    flex: 0 1 auto;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--ink-2);
    text-decoration: none;
  }
  .zname:hover {
    color: var(--seal-ink);
    text-decoration: underline;
    text-underline-offset: 3px;
  }
  .mmeta {
    flex: none;
    color: var(--ink-4);
    font-size: 12px;
    white-space: nowrap;
  }
  .btn.small {
    height: 26px;
    padding: 0 var(--s2);
    font-size: 13px;
  }
  /* Shown on hover or focus, over the end of the row: it reserves no room. */
  .manage {
    position: absolute;
    right: var(--s1);
    top: 50%;
    translate: 0 -50%;
    color: var(--seal-ink);
    background: var(--sheet);
    opacity: 0;
    transition: opacity 120ms var(--ease-out);
  }
  .mini:hover .manage,
  .mini:focus-within .manage {
    opacity: 1;
  }
  @media (hover: none) {
    .manage {
      position: static;
      translate: none;
      margin-left: auto;
      opacity: 1;
    }
  }
  .mini.open {
    grid-column: 1 / -1;
    flex-wrap: wrap;
    background: var(--sheet);
  }
  .unfold {
    flex: 1 1 100%;
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--s2) var(--s4);
    padding: var(--s2) 0 var(--s1);
  }
  .pager {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2) var(--s3);
    padding-top: var(--s2);
  }

  @media (max-width: 900px) {
    .row {
      grid-template-columns: minmax(0, 1fr) auto;
      gap: var(--s2) var(--s4);
    }
    .state {
      grid-column: 1 / -1;
      grid-row: 2;
    }
    .last {
      grid-row: 1;
      grid-column: 2;
    }
    .journal {
      grid-column: 1 / -1;
      justify-self: start;
    }
  }
  @media (max-width: 480px) {
    .search {
      flex: 1 1 100%;
    }
    .search input {
      width: 100%;
    }
    .compact {
      grid-template-columns: minmax(0, 1fr);
    }
    .row {
      padding: var(--s3) var(--s2);
    }
  }
</style>
