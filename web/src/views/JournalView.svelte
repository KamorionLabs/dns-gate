<script lang="ts">
  import { api } from '../lib/api';
  import type { AuditEntry, AuditQuery, ZoneSummary } from '../lib/types';
  import { router } from '../lib/router.svelte';
  import { dayLabel } from '../lib/format';
  import { isRead } from '../lib/journal';
  import AuditItem from '../components/AuditItem.svelte';
  import Icon from '../components/Icon.svelte';

  const periods: { key: string; label: string; minutes?: number }[] = [
    { key: '24h', label: 'Last 24 hours', minutes: 24 * 60 },
    { key: '7d', label: 'Last 7 days', minutes: 7 * 24 * 60 },
    { key: '30d', label: 'Last 30 days', minutes: 30 * 24 * 60 },
    { key: '', label: 'All time' },
  ];
  const categories = [
    { key: '', label: 'Everyone' },
    { key: 'pipeline', label: 'Pipelines' },
    { key: 'human', label: 'Humans' },
    { key: 'key', label: 'API keys' },
  ];
  const decisions = [
    { key: '', label: 'All' },
    { key: 'allow', label: 'Applied' },
    { key: 'deny', label: 'Refused' },
    { key: 'error', label: 'Failed' },
  ];

  const PAGE = 25;
  let zones = $state<ZoneSummary[]>([]);
  let entries = $state<AuditEntry[] | null>(null);
  let cursor = $state<string | undefined>(undefined);
  let loadingMore = $state(false);
  let error = $state<string | null>(null);
  let subjectInput = $state(router.params.get('subject') ?? '');

  $effect(() => {
    api.zones().then((z) => (zones = z)).catch(() => (zones = []));
  });

  const p = (k: string) => router.params.get(k) ?? '';
  const filters = $derived({
    zone: p('zone'),
    subject: p('subject'),
    category: p('category'),
    decision: p('decision'),
    period: p('period'),
  });

  function buildQuery(): AuditQuery {
    const period = periods.find((x) => x.key === filters.period);
    return {
      zone: filters.zone || undefined,
      subject: filters.subject || undefined,
      category: filters.category || undefined,
      decision: filters.decision || undefined,
      since: period?.minutes ? new Date(Date.now() - period.minutes * 60_000).toISOString() : undefined,
      limit: PAGE,
    };
  }

  // Reads and dry runs are hidden unless asked for; pages are fetched until
  // enough writes, refusals and drift events show (or a few pages were read).
  const includeReads = $derived(p('reads') === '1');
  let generation = 0;

  async function fill(q: AuditQuery, from: string | undefined, gen: number, start: AuditEntry[]) {
    let got = start;
    let next = from;
    let pages = 0;
    const wanted = start.filter((e) => includeReads || !isRead(e)).length + PAGE;
    do {
      const page = await api.audit({ ...q, cursor: next });
      if (gen !== generation) return;
      got = [...got, ...page.entries];
      next = page.next_cursor;
      pages++;
    } while (next && !includeReads && pages < 6 && got.filter((e) => !isRead(e)).length < wanted - PAGE / 2);
    entries = got;
    cursor = next;
  }

  $effect(() => {
    const q = buildQuery();
    void includeReads;
    const gen = ++generation;
    entries = null;
    error = null;
    fill(q, undefined, gen, []).catch((e: Error) => gen === generation && (error = e.message));
  });

  async function loadMore() {
    if (!cursor) return;
    loadingMore = true;
    const gen = generation;
    try {
      await fill(buildQuery(), cursor, gen, entries ?? []);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loadingMore = false;
    }
  }

  let debounce: ReturnType<typeof setTimeout> | undefined;
  function onSubject(v: string) {
    subjectInput = v;
    clearTimeout(debounce);
    debounce = setTimeout(() => router.setParams({ subject: v.trim() || undefined }), 250);
  }

  const groups = $derived.by(() => {
    const out: { day: string; label: string; items: AuditEntry[] }[] = [];
    const today = new Date().toDateString();
    const yesterday = new Date(Date.now() - 86_400_000).toDateString();
    for (const e of shown) {
      const d = new Date(e.time).toDateString();
      let g = out[out.length - 1];
      if (!g || g.day !== d) {
        g = { day: d, label: d === today ? 'Today' : d === yesterday ? 'Yesterday' : dayLabel(e.time), items: [] };
        out.push(g);
      }
      g.items.push(e);
    }
    return out;
  });

  const shown = $derived((entries ?? []).filter((e) => includeReads || !isRead(e)));
  const hiddenReads = $derived((entries?.length ?? 0) - shown.length);
  const refused = $derived(shown.filter((e) => e.decision !== 'allow').length);
  const active = $derived(Object.values(filters).some(Boolean));
</script>

<header class="head">
  <p class="eyebrow">Journal</p>
  <h1>Every write, refusal and drift, newest first</h1>
  {#if entries}
    <p class="meta">
      <span class="num">{shown.length}</span>{cursor ? '+' : ''} events{#if refused}, <span class="num refused">{refused}</span> refused or failed{/if}{#if hiddenReads}<span class="sep" aria-hidden="true">{' · '}</span><span class="num">{hiddenReads}</span> {hiddenReads === 1 ? 'read' : 'reads'} hidden{/if}
    </p>
  {/if}
</header>

<div class="filters">
  <label class="field">
    <span class="sr-only">Zone</span>
    <select value={filters.zone} onchange={(e) => router.setParams({ zone: e.currentTarget.value || undefined })}>
      <option value="">All zones</option>
      {#each zones as z (z.zone)}<option value={z.zone}>{z.zone}</option>{/each}
    </select>
    <span class="chev"><Icon name="chevron" size={12} /></span>
  </label>
  <label class="field who">
    <Icon name="search" size={14} />
    <span class="sr-only">Actor</span>
    <input type="search" placeholder="Actor: role, repo, email, key…" value={subjectInput} oninput={(e) => onSubject(e.currentTarget.value)} />
  </label>
  <div class="seg" role="radiogroup" aria-label="Actor category">
    {#each categories as c (c.key)}
      <button type="button" role="radio" aria-checked={filters.category === c.key} onclick={() => router.setParams({ category: c.key || undefined })}>{c.label}</button>
    {/each}
  </div>
  <div class="seg" role="radiogroup" aria-label="Decision">
    {#each decisions as d (d.key)}
      <button type="button" role="radio" class={d.key} aria-checked={filters.decision === d.key} onclick={() => router.setParams({ decision: d.key || undefined })}>{d.label}</button>
    {/each}
  </div>
  <label class="field">
    <span class="sr-only">Period</span>
    <select value={filters.period} onchange={(e) => router.setParams({ period: e.currentTarget.value || undefined })}>
      {#each periods as pr (pr.key)}<option value={pr.key}>{pr.label}</option>{/each}
    </select>
    <span class="chev"><Icon name="chevron" size={12} /></span>
  </label>
  <label class="toggle" title="Also show lookups and dry runs: lists, reads, plans and adoption previews">
    <input type="checkbox" checked={includeReads} onchange={(e) => router.setParams({ reads: e.currentTarget.checked ? '1' : undefined })} />
    Include reads
  </label>
  {#if active}
    <button
      class="btn quiet"
      type="button"
      onclick={() => {
        subjectInput = '';
        router.setParams({ zone: undefined, subject: undefined, category: undefined, decision: undefined, period: undefined, reads: undefined });
      }}>Clear</button
    >
  {/if}
</div>

{#if error}
  <div class="empty"><strong>The journal could not be loaded</strong>{error}</div>
{:else if !entries}
  <div class="loading">
    {#each [0, 1, 2] as i (i)}<div class="skeleton row"></div>{/each}
  </div>
{:else if shown.length === 0}
  <div class="empty">
    <strong>Nothing recorded</strong>
    {#if hiddenReads}Only reads match these filters: turn on Include reads to see them.{:else}No event matches these filters.{/if}
  </div>
{:else}
  <div class="timeline">
    {#each groups as g (g.day)}
      <section>
        <h2 class="day">{g.label} <span class="dcount num">{g.items.length} {g.items.length === 1 ? 'event' : 'events'}</span></h2>
        {#each g.items as e (e.request_id + e.time)}<AuditItem entry={e} />{/each}
      </section>
    {/each}
  </div>
  {#if cursor}
    <div class="more">
      <button class="btn" type="button" onclick={loadMore} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load older events'}</button>
    </div>
  {/if}
{/if}

<style>
  .head {
    display: grid;
    gap: var(--s2);
    margin-bottom: var(--s6);
  }
  h1 {
    font-size: var(--t-h2);
    letter-spacing: -0.015em;
  }
  .meta {
    color: var(--ink-3);
  }
  .refused {
    color: var(--wax);
    font-weight: 600;
  }
  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
    padding-bottom: var(--s5);
    margin-bottom: var(--s6);
    border-bottom: 1px solid var(--rule);
  }
  .who input {
    width: 220px;
  }
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 32px;
    padding: 0 var(--s2);
    color: var(--ink-2);
    cursor: pointer;
    user-select: none;
  }
  .toggle input {
    width: 15px;
    height: 15px;
    margin: 0;
    accent-color: var(--seal-ink);
  }
  .seg {
    display: inline-flex;
    padding: 2px;
    gap: 2px;
    border-radius: var(--r-md);
    background: var(--well);
    border: 1px solid var(--rule-soft);
  }
  .seg button {
    height: 26px;
    padding: 0 10px;
    border: 0;
    border-radius: 5px;
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    font-weight: 500;
    font-size: 13px;
  }
  .seg button:hover {
    color: var(--ink);
  }
  .seg button[aria-checked='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .seg button.deny[aria-checked='true'] {
    color: var(--wax);
  }
  .seg button.allow[aria-checked='true'] {
    color: var(--stamp);
  }
  .seg button.error[aria-checked='true'] {
    color: var(--brass);
  }
  .timeline {
    max-width: 920px;
  }
  section + section {
    margin-top: var(--s2);
  }
  .dcount {
    margin-left: var(--s2);
    font-weight: 400;
    color: var(--ink-4);
  }
  .day {
    position: sticky;
    top: 52px;
    z-index: 2;
    padding: var(--s2) 0 var(--s3) 84px;
    font-size: 12px;
    font-weight: 600;
    color: var(--ink-2);
    background: linear-gradient(var(--paper) 70%, transparent);
  }
  .more {
    max-width: 920px;
    padding-left: 84px;
  }
  .loading {
    display: grid;
    gap: var(--s4);
    max-width: 920px;
  }
  .row {
    height: 64px;
  }
  @media (max-width: 640px) {
    .day,
    .more {
      padding-left: 56px;
    }
    .who input {
      width: 100%;
    }
    .who {
      flex: 1 1 100%;
    }
  }
</style>
