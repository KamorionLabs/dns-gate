<script lang="ts">
  import { untrack } from 'svelte';
  import { api, onBeforeReauth } from '../lib/api';
  import type { AdoptResult, HTTPSRedirect, Me, RRset, RRsetRef, Status, Tombstone, Transfer, ZoneInventory } from '../lib/types';
  import { takeAdopt, type StoredAdopt } from '../lib/adoptDraft';
  import AdoptPanel from '../components/AdoptPanel.svelte';
  import TerraformPanel from '../components/TerraformPanel.svelte';
  import { router, href, journalHref, teamHref, transferHref, transfersHref } from '../lib/router.svelte';
  import { ownership, pickable, reservation, selectionTeam, transferAllowed } from '../lib/teams';
  import { inbox } from '../lib/inbox.svelte';
  import TransferPanel from '../components/teams/TransferPanel.svelte';
  import { needsAttention, statusHelp, statusLabel } from '../lib/labels';
  import { shortHashes, ttl as fmtTTL } from '../lib/format';
  import { identityLabel } from '../lib/identity';
  import { managedSplit } from '../lib/zones';
  import { ruleCovers } from '../lib/folders';
  import { whoCanDoWhat } from '../lib/access';
  import { forbidden, policyState } from '../lib/policy.svelte';
  import Seal from '../components/Seal.svelte';
  import Host from '../components/Host.svelte';
  import ActorChip from '../components/ActorChip.svelte';
  import RelTime from '../components/RelTime.svelte';
  import RRsetDrawer from '../components/RRsetDrawer.svelte';
  import Icon from '../components/Icon.svelte';
  import ManageZone from '../components/ManageZone.svelte';
  import ZoneAccessView from '../components/policy/ZoneAccess.svelte';
  import RecordForm from '../components/RecordForm.svelte';
  import ReviewPanel from '../components/ReviewPanel.svelte';
  import ProviderBadge from '../components/ProviderBadge.svelte';
  import ForwardsSection from '../components/ForwardsSection.svelte';
  import ForwardForm from '../components/ForwardForm.svelte';
  import { canChange, canWriteForwards, canWriteZone, readOnlyLabel } from '../lib/rights';
  import { URLFWD, filterForwards, forwardsVisible, isForward, splitForwards, typeLabel } from '../lib/forwards';
  import { keysAfter, rebase, stage, stagedFor, stagedKey, unstage, valuesOf, type StagedChange } from '../lib/staging';
  import { saveStaged, takeStaged } from '../lib/stagedDraft';
  import { providerLabel } from '../lib/labels';

  let { zone }: { zone: string } = $props();

  let inv = $state<ZoneInventory | null>(null);
  let error = $state<string | null>(null);

  let me = $state<Me | null>(null);
  let selecting = $state(false);
  let picked = $state<string[]>([]);
  let adoptOpen = $state(false);
  let tfOpen = $state(false);
  let adoptForbidden = $state(false);
  let restored = $state<StoredAdopt | null>(null);

  // Record sets of one team selected for a transfer to another team.
  let transferring = $state(false);
  let tpicked = $state<string[]>([]);
  let transferOpen = $state(false);
  let sentTransfer = $state<Transfer | null>(null);

  // DNS changes staged in this zone, reviewed and applied together.
  let staged = $state<StagedChange[]>([]);
  let formFor = $state<{ rr?: RRset; staged?: StagedChange } | null>(null);
  let fwdFormFor = $state<{ rr?: RRset; staged?: StagedChange } | null>(null);
  let reviewOpen = $state(false);
  let provider = $state<string | undefined>(undefined);
  // Whether the URL forwards of the zone answer HTTPS (GET /forwards), when known.
  let https = $state<HTTPSRedirect | undefined>(undefined);

  const loadHTTPS = () =>
    api
      .forwards(zone)
      .then((l) => (https = l.https))
      .catch(() => (https = undefined));

  const load = () =>
    api
      .inventory(zone)
      .then((z) => {
        inv = z;
        // a zone that is not managed has nothing to adopt, export or change
        if (z.unmanaged) tfOpen = adoptOpen = selecting = false;
        if (z.unmanaged) staged = [];
        if (!z.unmanaged && z.provider?.toLowerCase() !== 'route53') void loadHTTPS();
        if (z.provider) provider = z.provider;
        else if (!provider)
          api
            .zones()
            .then((zs) => (provider = zs.find((x) => x.zone === zone)?.provider))
            .catch(() => {});
      })
      .catch((e: Error) => (error = e.message));

  const unmanaged = $derived(!!inv?.unmanaged);

  // Once per zone (the view is keyed by zone): reading the zone prop would
  // otherwise run this again on every change of the URL parameters.
  $effect(() =>
    untrack(() => {
      load();
      api.me().then((m) => (me = m)).catch(() => (me = null));
      // #/zones/<zone>?export=terraform opens the export (link from the zones page).
      if (router.params.get('export') === 'terraform') tfOpen = true;
      staged = takeStaged(zone);
      const r = takeAdopt(zone);
      if (r) {
        restored = r;
        picked = (r.selection.rrsets ?? []).map((x) => `${x.host}/${x.type}`);
        adoptOpen = true;
      }
    }),
  );

  // Adoption needs dns.record.adopt on this zone. Without the effective
  // permissions in /me, the button stays and the gate answers.
  const adoptAllowed = $derived(
    !adoptForbidden &&
      (!me?.permissions || me.permissions.some((p) => p.actions.includes('dns.record.adopt') && ruleCovers(p, zone))),
  );
  const adoptWhyNot = 'Adopting needs the dns.record.adopt permission on this zone. Ask a policy administrator.';

  // A plan or apply may ask for a fresh sign-in: the staged changes come back after it.
  $effect(() => onBeforeReauth(() => saveStaged(zone, staged)));

  const canAdd = $derived(!!inv && !unmanaged && canWriteZone(me, zone));
  const canAddForward = $derived(!!inv && !unmanaged && https?.status !== 'unsupported' && canWriteForwards(me, zone));
  const verdict = (r: RRset) => canChange(me, zone, r, unmanaged);
  const tombstones = $derived<Tombstone[]>(inv?.tombstones ?? []);
  const reservedFor = (r: RRset) => (r.status === 'foreign' ? reservation(tombstones, r.host, r.type) : undefined);
  const owns = (r: RRset) => ownership(me, zone, r, unmanaged, reservedFor(r));
  const split = $derived(splitForwards(inv?.rrsets ?? []));
  const existingAfter = $derived(keysAfter(split.records, staged.filter((c) => !isForward(c))));
  const forwardsAfter = $derived(keysAfter(split.forwards, staged.filter(isForward)));

  function onstage(c: StagedChange) {
    staged = stage(staged, c);
    formFor = fwdFormFor = null;
  }
  function edit(r: RRset) {
    router.setParams({ rr: undefined });
    const f = { rr: r, staged: stagedFor(staged, r.host, r.type) };
    if (isForward(r)) fwdFormFor = f;
    else formFor = f;
  }
  function remove(r: RRset) {
    staged = stage(staged, { kind: 'delete', host: r.host, type: r.type, before: r });
  }
  const undo = (k: string) => (staged = unstage(staged, k));
  function openForm() {
    router.setParams({ rr: undefined });
    formFor = {};
  }
  function openForwardForm() {
    router.setParams({ rr: undefined });
    fwdFormFor = {};
  }
  function editStaged(c: StagedChange) {
    const rr = c.kind === 'create' ? undefined : inv?.rrsets.find((r) => r.host === c.host && r.type === c.type);
    if (isForward(c)) fwdFormFor = { rr, staged: c };
    else formFor = { rr, staged: c };
  }
  async function reloadForReview(): Promise<StagedChange[]> {
    const z = await api.inventory(zone);
    inv = z;
    const { kept, dropped } = rebase(staged, z.rrsets);
    staged = kept;
    return dropped;
  }
  const stageSign = { create: '+', update: '~', delete: '−' } as const;

  const keyOf = (r: { host: string; type: string }) => `${r.host}/${r.type}`;
  const pickedRefs = $derived(
    picked.map((k): RRsetRef => {
      const i = k.lastIndexOf('/');
      return { host: k.slice(0, i), type: k.slice(i + 1) };
    }),
  );
  const togglePick = (r: RRset) =>
    (picked = picked.includes(keyOf(r)) ? picked.filter((k) => k !== keyOf(r)) : [...picked, keyOf(r)]);

  const transferRefs = $derived(
    tpicked.map((k): RRsetRef => {
      const i = k.lastIndexOf('/');
      return { host: k.slice(0, i), type: k.slice(i + 1) };
    }),
  );
  const transferSel = $derived(selectionTeam(transferRefs, inv?.rrsets ?? [], tombstones));
  const transferFrom = $derived(transferSel.from);
  const transferGate = $derived(transferAllowed(me, zone));
  const toggleTransfer = (k: string) => (tpicked = tpicked.includes(k) ? tpicked.filter((x) => x !== k) : [...tpicked, k]);
  const tombPickable = (t: Tombstone) => !transferFrom || t.team === transferFrom;
  function stopTransfer() {
    transferring = false;
    tpicked = [];
  }
  /** Opens the transfer selection with one record set selected. */
  function transferOne(r: RRset) {
    router.setParams({ rr: undefined });
    selecting = false;
    picked = [];
    transferring = true;
    tpicked = [keyOf(r)];
    transferOpen = true;
  }
  function onTransferSent(t: Transfer) {
    sentTransfer = t;
    void inbox.load(true);
    if (t.status === 'applied') load();
  }
  function closeTransfer() {
    transferOpen = false;
    if (sentTransfer) stopTransfer();
  }

  function onAdopted(_r: AdoptResult) {
    picked = [];
    selecting = false;
    load();
  }

  /** Opens the adoption flow with one record set selected. */
  function adoptOne(r: RRset) {
    if (!adoptAllowed || r.protected || r.type === 'SOA' || r.read_only) return;
    router.setParams({ rr: undefined });
    picked = [keyOf(r)];
    adoptOpen = true;
  }

  const q = $derived(router.params.get('q') ?? '');
  const typeF = $derived(router.params.get('type') ?? '');
  const ownerF = $derived(router.params.get('owner') ?? '');
  const selectedKey = $derived(router.params.get('rr') ?? '');

  // Zone-file order: sort by reversed labels so children sit under their parents.
  const sortKey = (r: RRset) => (r.host === '@' ? '' : r.host.split('.').reverse().join('.')) + ' ' + r.type;
  const sorted = (l: RRset[]) => [...l].sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
  // The record table holds the record sets; the URL forwards have their own section.
  const rrsets = $derived(sorted(split.records));
  const forwardSets = $derived(sorted(split.forwards));

  const bucket = (s: Status) => (s === 'missing' ? 'tainted' : s);
  const counts = $derived(
    rrsets.reduce<Record<string, number>>((c, r) => ((c[bucket(r.status)] = (c[bucket(r.status)] ?? 0) + 1), c), {}),
  );
  const attentionCount = $derived((counts.tainted ?? 0) + (counts.pending ?? 0));
  const types = $derived([...new Set(rrsets.map((r) => r.type))].sort());
  const owners = $derived([...new Set((inv?.rrsets ?? []).map((r) => r.owner).filter((o): o is string => !!o))].sort());
  const foreignAll = $derived((inv?.rrsets ?? []).filter((r) => r.status === 'foreign').length);
  const managedAll = $derived((inv?.rrsets ?? []).filter((r) => r.status === 'managed').length);
  const adoptTypes = $derived(forwardSets.length ? [...types, URLFWD] : types);

  // Status filter, always visible in the URL: when absent, the zone's needs
  // decide (attention, then managed, then all) and the URL is updated.
  const statusKeys = ['all', 'attention', 'managed', 'tainted', 'pending', 'foreign'] as const;
  type StatusKey = (typeof statusKeys)[number];
  const defaultStatus = $derived<StatusKey>(attentionCount > 0 ? 'attention' : (counts.managed ?? 0) > 0 ? 'managed' : 'all');
  const rawStatus = $derived(router.params.get('status') ?? '');
  const statusF = $derived<StatusKey>((statusKeys as readonly string[]).includes(rawStatus) ? (rawStatus as StatusKey) : defaultStatus);
  $effect(() => {
    if (inv && !(statusKeys as readonly string[]).includes(rawStatus)) untrack(() => router.setParams({ status: defaultStatus }));
  });

  const inStatus = (r: RRset, s: StatusKey) =>
    s === 'all' || (s === 'attention' ? needsAttention(r.status) : bucket(r.status) === s);

  const shown = $derived(
    rrsets.filter((r) => {
      if (!inStatus(r, statusF)) return false;
      if (typeF && r.type !== typeF) return false;
      if (ownerF && r.owner !== ownerF) return false;
      if (q) {
        const n = q.toLowerCase();
        const who = [r.created_by, r.updated_by].flatMap((a) => (a ? [a.name, identityLabel(a).label] : []));
        const hay = [r.host, r.type, r.owner ?? '', ...who, ...valuesOf(r)].join(' ').toLowerCase();
        if (!hay.includes(n)) return false;
      }
      return true;
    }),
  );

  // Thousands of record sets: one page at a time, page number in the URL.
  const PAGE = 100;
  const pages = $derived(Math.max(1, Math.ceil(shown.length / PAGE)));
  const page = $derived(Math.min(pages, Math.max(1, Number(router.params.get('page')) || 1)));
  const pageRows = $derived(shown.slice((page - 1) * PAGE, page * PAGE));
  const setFilter = (u: Record<string, string | undefined>) => router.setParams({ ...u, page: undefined });
  const goPage = (n: number) => router.setParams({ page: n > 1 ? String(n) : undefined });

  const selected = $derived((inv?.rrsets ?? []).find((r) => `${r.host}/${r.type}` === selectedKey) ?? null);
  const selectedVerdict = $derived(selected ? verdict(selected) : null);

  const tabs = $derived(
    [
      { key: 'all' as const, label: 'All', n: rrsets.length, always: true },
      { key: 'attention' as const, label: 'Needs attention', n: attentionCount, always: false },
      { key: 'managed' as const, label: statusLabel.managed, n: counts.managed ?? 0, always: true },
      { key: 'tainted' as const, label: statusLabel.tainted, n: counts.tainted ?? 0, always: false },
      { key: 'pending' as const, label: statusLabel.pending, n: counts.pending ?? 0, always: false },
      { key: 'foreign' as const, label: statusLabel.foreign, n: counts.foreign ?? 0, always: true },
    ].filter((t) => t.always || t.n > 0 || statusF === t.key),
  );
  const tabHelp: Partial<Record<StatusKey, string>> = {
    attention: 'Drifted, missing or pending record sets',
    managed: statusHelp.managed,
    tainted: statusHelp.tainted,
    pending: statusHelp.pending,
    foreign: statusHelp.foreign,
  };

  const open = (r: RRset) => {
    if (selecting) {
      if (r.status === 'foreign') togglePick(r);
      return;
    }
    if (transferring) {
      if (pickable(r, transferFrom) || tpicked.includes(keyOf(r))) toggleTransfer(keyOf(r));
      return;
    }
    router.setParams({ rr: `${r.host}/${r.type}` }, true);
  };
  const shownForeign = $derived(shown.filter((r) => r.status === 'foreign' && !r.protected));

  const showForwards = $derived(!!inv && forwardsVisible({ count: forwardSets.length, provider, https, unmanaged }));
  const shownForwards = $derived(filterForwards(forwardSets, q, ownerF));
  // While selecting for an adoption or a transfer, forwards are picked like record sets.
  const forwardPick = $derived.by(() => {
    if (selecting)
      return (r: RRset) => ({ show: r.status === 'foreign' && !r.protected, checked: picked.includes(keyOf(r)), inert: r.status !== 'foreign' || r.protected });
    if (transferring)
      return (r: RRset) => {
        const on = tpicked.includes(keyOf(r));
        const ok = pickable(r, transferFrom);
        return { show: ok || on, checked: on, inert: !ok && !on };
      };
    return undefined;
  });
  const shownTransferable = $derived(shown.filter((r) => pickable(r, transferFrom ?? (ownerF || undefined))));
  const close = () => router.setParams({ rr: undefined });
  const rowKey = (e: KeyboardEvent, r: RRset) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      open(r);
    }
  };
  const lastActor = (r: RRset) => r.updated_by ?? r.created_by;
  const lastAt = (r: RRset) => r.updated_at ?? r.created_at;
  const owned = (r: RRset) => r.status !== 'foreign';
  const fullName = (r: RRset) => (r.host === '@' ? zone : `${r.host}.${zone}`);

  // Long values stay on one line; "+N more" unfolds the rest in place.
  let expanded = $state<string[]>([]);
  const toggleValues = (r: RRset) =>
    (expanded = expanded.includes(keyOf(r)) ? expanded.filter((k) => k !== keyOf(r)) : [...expanded, keyOf(r)]);

  let copiedKey = $state<string | null>(null);
  async function copyName(r: RRset) {
    try {
      await navigator.clipboard.writeText(fullName(r));
      copiedKey = keyOf(r);
      setTimeout(() => (copiedKey = null), 1400);
    } catch {
      copiedKey = null;
    }
  }

  // Who can do what here, from the policy (hidden without policy.read).
  let accessOpen = $state(false);
  $effect(() => {
    if (accessOpen) void policyState.load();
  });
  const access = $derived(policyState.data ? whoCanDoWhat(policyState.data, [zone])[0] : undefined);
  const stop = (e: Event) => e.stopPropagation();
</script>

<nav class="crumbs" aria-label="Breadcrumb"><a href={href('/')}>Zones</a><span aria-hidden="true">/</span></nav>

<header class="head">
  <div class="title">
    <h1 class="mono">{zone}</h1>
    <p class="meta">
      {#if provider}<ProviderBadge {provider} />{/if}
      {#if inv}
        <span class="num">{rrsets.length.toLocaleString('en')}</span> record sets{#if forwardSets.length}{' '}· <span class="num">{forwardSets.length.toLocaleString('en')}</span> URL forward{forwardSets.length === 1 ? '' : 's'}{/if} · synced <RelTime iso={inv.last_synced_at} /> ·
        <a href={journalHref({ zone })}>journal</a>
      {:else if !error}loading…{/if}
    </p>
  </div>
  {#if inv && !unmanaged}
    <div class="summary">
      <span class="split">{managedSplit({ managed: counts.managed ?? 0, foreign: counts.foreign ?? 0 })}</span>
      {#if counts.tainted}<button class="chip wax" type="button" title={statusHelp.tainted} onclick={() => setFilter({ status: 'tainted' })}><Seal status="tainted" size={12} />{counts.tainted} drifted</button>{/if}
      {#if counts.pending}<button class="chip brass" type="button" title={statusHelp.pending} onclick={() => setFilter({ status: 'pending' })}><Seal status="pending" size={12} />{counts.pending} pending</button>{/if}
    </div>
  {/if}
</header>

{#if unmanaged}
  <aside class="unmanaged" aria-label="Zone not managed">
    <div class="utext">
      <h2><Icon name="lock" size={14} /> Not managed by the gate</h2>
      <p>This zone was found at {provider ? providerLabel(provider) : 'the DNS provider'} and is shown read-only: the gate writes nothing here, and changes, adoption and Terraform export are unavailable until the zone is managed.</p>
    </div>
    <ManageZone {zone} {me} />
  </aside>
{:else if inv && !forbidden(policyState.error)}
  <details class="access" bind:open={accessOpen}>
    <summary>Who can do what in this zone</summary>
    {#if policyState.error}
      <p class="dim">{policyState.error.message}</p>
    {:else if access}
      <ZoneAccessView {access} showZone={false} />
    {:else}
      <div class="skeleton bar"></div>
    {/if}
  </details>
{/if}

{#if error}
  <div class="empty"><strong>This zone could not be loaded</strong>{error}</div>
{:else}
  <div class="filters">
    <div class="tabs" role="radiogroup" aria-label="Filter by status">
      {#each tabs as t (t.key)}
        <button
          role="radio"
          type="button"
          aria-checked={statusF === t.key}
          title={tabHelp[t.key]}
          class="tab {t.key}"
          onclick={() => setFilter({ status: t.key })}
        >
          {#if t.key !== 'all' && t.key !== 'attention'}<Seal status={t.key} size={12} />{/if}
          {t.label}
          <span class="count num">{inv ? t.n.toLocaleString('en') : '…'}</span>
        </button>
      {/each}
    </div>
    <div class="right">
      {#if canAdd}
        <button class="btn primary" type="button" onclick={openForm}><Icon name="plus" size={14} />Add record</button>
      {/if}
      <label class="field search">
        <Icon name="search" size={14} />
        <span class="sr-only">Search records</span>
        <input
          type="search"
          placeholder="Host, value, owner, actor…"
          value={q}
          oninput={(e) => setFilter({ q: e.currentTarget.value || undefined })}
        />
      </label>
      <label class="field">
        <span class="sr-only">Type</span>
        <select value={typeF} onchange={(e) => setFilter({ type: e.currentTarget.value || undefined })}>
          <option value="">All types</option>
          {#each types as t (t)}<option value={t}>{t}</option>{/each}
        </select>
        <span class="chev"><Icon name="chevron" size={12} /></span>
      </label>
      {#if owners.length}
        <label class="field">
          <span class="sr-only">Owner team</span>
          <select value={ownerF} onchange={(e) => setFilter({ owner: e.currentTarget.value || undefined })}>
            <option value="">All owners</option>
            {#each owners as o (o)}<option value={o}>{o}</option>{/each}
          </select>
          <span class="chev"><Icon name="chevron" size={12} /></span>
        </label>
      {/if}
      {#if inv && !unmanaged && foreignAll > 0}
        <button
          class="btn"
          class:on={selecting}
          type="button"
          aria-pressed={selecting}
          aria-disabled={!adoptAllowed}
          title={adoptAllowed ? 'Select record sets that are not managed and adopt them' : adoptWhyNot}
          onclick={() => {
            if (!adoptAllowed) return;
            stopTransfer();
            selecting = !selecting;
            if (!selecting) picked = [];
          }}
        >
          <Seal status="managed" size={13} />{selecting ? 'Selecting…' : 'Adopt…'}
        </button>
      {/if}
      {#if inv && !unmanaged && managedAll + tombstones.length > 0 && transferGate.ok}
        <button
          class="btn"
          class:on={transferring}
          type="button"
          aria-pressed={transferring}
          title="Select record sets of one team and ask for their transfer to another team"
          onclick={() => {
            if (transferring) stopTransfer();
            else {
              selecting = false;
              picked = [];
              transferring = true;
            }
          }}
        >
          <Icon name="transfer" size={14} />{transferring ? 'Selecting…' : 'Transfer…'}
        </button>
      {/if}
      {#if inv && !unmanaged}<button class="btn" type="button" onclick={() => (tfOpen = true)}><Icon name="download" size={14} />Export Terraform</button>{/if}
    </div>
  </div>

  {#if inv && !unmanaged && !adoptAllowed && foreignAll > 0 && (statusF === 'foreign' || statusF === 'all')}
    <p class="note"><Icon name="lock" size={12} /> {adoptWhyNot}</p>
  {/if}
  {#if sentTransfer}
    <p class="note sent" role="status">
      <Icon name="transfer" size={12} />
      {#if sentTransfer.status === 'applied'}
        {sentTransfer.moved ?? sentTransfer.rrsets.length} record set{(sentTransfer.moved ?? sentTransfer.rrsets.length) === 1 ? '' : 's'} transferred from team {sentTransfer.from_team} to {sentTransfer.to_team}{sentTransfer.self_approved ? ' (self-approved)' : ''}.
      {:else if sentTransfer.status === 'applying'}
        Transfer from team {sentTransfer.from_team} to {sentTransfer.to_team} approved: the gate applies it as soon as the zone is free.
      {:else}
        Transfer of {sentTransfer.rrsets.length} record set{sentTransfer.rrsets.length === 1 ? '' : 's'} from team {sentTransfer.from_team} to {sentTransfer.to_team} requested: nothing moves until it is approved.
      {/if}
      <a href={transferHref(sentTransfer.id)}>Open the request</a>
      <button class="btn quiet small" type="button" aria-label="Dismiss" onclick={() => (sentTransfer = null)}><Icon name="x" size={12} /></button>
    </p>
  {/if}

  <div class="sheet">
    <table class:ro={unmanaged}>
      <colgroup>
        <col class="w-seal" />
        <col class="w-name" />
        <col class="w-type" />
        <col />
        <col class="w-ttl" />
        <col class="w-owner" />
        <col class="w-last" />
        {#if !unmanaged}<col class="w-act" />{/if}
      </colgroup>
      <thead>
        <tr>
          <th class="c-seal"><span class="sr-only">Status</span></th>
          <th>Name</th>
          <th class="c-type">Type</th>
          <th>Values</th>
          <th class="c-ttl">TTL</th>
          <th class="c-owner">Owner</th>
          <th class="c-custody">Last change</th>
          {#if !unmanaged}<th class="c-act"><span class="sr-only">Actions</span></th>{/if}
        </tr>
      </thead>
      <tbody>
        {#if !inv}
          {#each [0, 1, 2, 3, 4] as i (i)}
            <tr class="loading"><td colspan="8"><div class="skeleton bar"></div></td></tr>
          {/each}
        {:else}
          {#each pageRows as r (r.host + '/' + r.type)}
            {@const k = keyOf(r)}
            {@const isOpen = expanded.includes(k)}
            {@const st = stagedFor(staged, r.host, r.type)}
            {@const v = verdict(r)}
            {@const roTag = readOnlyLabel(r)}
            {@const vals = valuesOf(r)}
            <tr
              class="{r.status}{st ? ' staged-' + st.kind : ''}"
              class:owned={owned(r)}
              class:selected={selected === r || (selecting && picked.includes(k)) || (transferring && tpicked.includes(k))}
              class:inert={(selecting && (r.status !== 'foreign' || r.protected)) || (transferring && !pickable(r, transferFrom) && !tpicked.includes(k))}
              tabindex="0"
              onclick={() => open(r)}
              onkeydown={(e) => rowKey(e, r)}
              aria-label="{fullName(r)} {r.type}, {statusLabel[r.status]}{r.owner ? ', owned by ' + r.owner : ''}"
            >
              <td class="c-seal">
                {#if selecting && r.status === 'foreign' && !r.protected}
                  <input type="checkbox" class="pick" checked={picked.includes(k)} onclick={stop} onchange={() => togglePick(r)} aria-label="Select {r.host} {r.type}" />
                {:else if transferring && (pickable(r, transferFrom) || tpicked.includes(k))}
                  <input type="checkbox" class="pick" checked={tpicked.includes(k)} onclick={stop} onchange={() => toggleTransfer(k)} aria-label="Select {r.host} {r.type} for a transfer" />
                {:else}
                  <Seal status={r.status} title={statusLabel[r.status]} />
                {/if}
              </td>
              <td class="c-name">
                <div class="name" title={fullName(r)}>
                  <Host host={r.host} {zone} showZone={false} short />
                  {#if r.protected}
                    <span class="ico" role="img" aria-label="Protected" title="Protected by the base policy: no role can change it through the gate, even after adoption."><Icon name="lock" size={12} /></span>
                  {/if}
                  {#if roTag}<span class="rotag" title={v.ok ? undefined : v.text}>{roTag}</span>{/if}
                  {#if r.expires_at}<span class="ephemeral" title="Ephemeral record, removed automatically"><Icon name="clock" size={12} /><RelTime iso={r.expires_at} /></span>{/if}
                  <button class="copyname" type="button" onclick={(e) => { stop(e); void copyName(r); }} aria-label="Copy {fullName(r)}" title="Copy {fullName(r)}">
                    <Icon name={copiedKey === k ? 'check' : 'copy'} size={12} />
                  </button>
                </div>
              </td>
              <td class="c-type"><span class="type mono">{r.type}</span></td>
              <td class="c-values">
                <ul class="mono" class:open={isOpen} class:alias={!!r.alias}>
                  {#each isOpen ? vals : vals.slice(0, 1) as val (val)}<li title={r.alias ? `Alias of ${r.alias.target} (hosted zone ${r.alias.hosted_zone_id})` : val}>{shortHashes(val)}</li>{/each}
                </ul>
                {#if vals.length > 1}
                  <button class="more" type="button" aria-expanded={isOpen} onclick={(e) => { stop(e); toggleValues(r); }}>
                    {isOpen ? 'Show less' : `+${vals.length - 1} more`}
                  </button>
                {/if}
                {#if st}
                  <span class="stagedtag {st.kind}">{st.kind === 'delete' ? 'Will be deleted' : `Will change to ${(st.values ?? []).length === 1 ? st.values?.[0] : (st.values ?? []).length + ' values'}${st.ttl !== r.ttl ? ` · TTL ${fmtTTL(st.ttl ?? 0)}` : ''}`}</span>
                {/if}
              </td>
              <td class="c-ttl mono num">{fmtTTL(r.ttl)}</td>
              <td class="c-owner">
                {#if r.owner}
                  {@const own = owns(r)}
                  <a class="team" class:mine={own.mine} href={teamHref(r.owner)} onclick={stop} title={own.text}><Seal status="managed" size={11} />{r.owner}</a>
                {:else if reservedFor(r)}
                  {@const tb = reservedFor(r)}
                  {#if tb}<a class="team reserved" href={teamHref(tb.team)} onclick={stop} title={owns(r).text}><Icon name="clock" size={11} />{tb.team}</a>{/if}
                {:else}<span class="ro" aria-label="No owner">—</span>{/if}
              </td>
              <td class="c-custody">
                {#if owned(r) && lastActor(r)}
                  {@const a = lastActor(r)}
                  {#if a}<ActorChip actor={a} quiet />{/if}
                  <span class="when"><RelTime iso={lastAt(r)} /></span>
                {:else if owned(r)}
                  <span class="ro">—</span>
                {:else}
                  <span class="ro">Not managed by the gate</span>
                {/if}
              </td>
              {#if !unmanaged}
                <td class="c-act">
                  {#if st}
                    <button class="btn quiet small act" type="button" onclick={(e) => { stop(e); undo(k); }} aria-label="Undo the staged change of {r.host} {r.type}"><Icon name="undo" size={13} />Undo</button>
                  {:else if owned(r) && v.ok}
                    <span class="acts">
                      <button class="btn quiet small act" type="button" onclick={(e) => { stop(e); edit(r); }} aria-label="Edit {r.host} {r.type}">Edit</button>
                      <button class="btn quiet small icon act del" type="button" onclick={(e) => { stop(e); remove(r); }} aria-label="Delete {r.host} {r.type}" title="Delete (staged, applied after review)"><Icon name="trash" size={14} /></button>
                    </span>
                  {:else if owned(r)}
                    <span class="acts">
                      {#if !v.ok}<span class="ico" role="img" aria-label="Read-only: {owns(r).text}" title={owns(r).text}><Icon name="lock" size={12} /></span>{/if}
                      <button class="btn quiet small act" type="button" onclick={(e) => { stop(e); open(r); }} aria-label="Details of {r.host} {r.type}">Details</button>
                    </span>
                  {:else if adoptAllowed && (r.protected || r.type === 'SOA' || r.read_only)}
                    {@const why = r.protected ? 'Protected by the base policy: it cannot be adopted.' : 'Managed by the DNS provider: it cannot be adopted.'}
                    <button class="btn quiet small act" type="button" aria-disabled="true" onclick={stop} title={why} aria-label="Adopt {r.host} {r.type}: not possible. {why}">Adopt</button>
                  {:else if adoptAllowed}
                    <button
                      class="btn quiet small act adopt"
                      type="button"
                      title="Adopt this record set: the gate manages it for a team"
                      onclick={(e) => { stop(e); adoptOne(r); }}
                      aria-label="Adopt {r.host} {r.type}"
                    >Adopt</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {:else}
            <tr class="none">
              <td colspan="8">
                <div class="empty">
                  <strong>No record sets match</strong>
                  {#if statusF !== 'all' || q || typeF || ownerF}
                    <button class="btn" type="button" onclick={() => setFilter({ status: 'all', q: undefined, type: undefined, owner: undefined })}>Show the whole zone</button>
                  {/if}
                </div>
              </td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>

  {#if inv && shown.length > PAGE}
    <nav class="pager" aria-label="Pages">
      <span class="dim"><span class="num">{((page - 1) * PAGE + 1).toLocaleString('en')}–{Math.min(page * PAGE, shown.length).toLocaleString('en')}</span> of <span class="num">{shown.length.toLocaleString('en')}</span></span>
      <button class="btn" type="button" disabled={page <= 1} onclick={() => goPage(page - 1)}>Previous</button>
      <span class="num pos">Page {page} of {pages}</span>
      <button class="btn" type="button" disabled={page >= pages} onclick={() => goPage(page + 1)}>Next</button>
    </nav>
  {/if}

  {#if showForwards}
    <ForwardsSection
      {zone}
      forwards={shownForwards}
      total={forwardSets.length}
      {https}
      loading={!inv}
      {unmanaged}
      canAdd={canAddForward}
      filtered={!!q || !!ownerF}
      {staged}
      {selectedKey}
      {verdict}
      {owns}
      {reservedFor}
      {adoptAllowed}
      pick={forwardPick}
      onopen={open}
      onadd={openForwardForm}
      onedit={edit}
      onremove={remove}
      onundo={undo}
      onadopt={adoptOne}
      onclearfilter={() => setFilter({ q: undefined, owner: undefined })}
    />
  {/if}
{/if}

{#if inv && !unmanaged && tombstones.length}
  <details class="tombs" open={transferring}>
    <summary>Deleted recently, reserved for their team <span class="count num">{tombstones.length}</span></summary>
    <p class="dim small">Until a reservation expires, only that team can create or adopt the record set again; another team asks for a transfer of the reservation.</p>
    <ul>
      {#each tombstones as t (t.host + '/' + t.type)}
        {@const k = `${t.host}/${t.type}`}
        <li class:mine={!!me?.teams.includes(t.team)}>
          {#if transferring}
            <input type="checkbox" class="pick" checked={tpicked.includes(k)} disabled={!tombPickable(t) && !tpicked.includes(k)} onchange={() => toggleTransfer(k)} aria-label="Select the reservation of {t.host} {t.type} for a transfer" />
          {/if}
          <span class="mono">{t.host === '@' ? zone : t.host}</span>
          <span class="mono t">{t.type}</span>
          <a class="team" href={teamHref(t.team)}>{t.team}</a>
          <span class="dim">
            deleted {#if t.deleted_by}by <ActorChip actor={t.deleted_by} quiet />{/if} <RelTime iso={t.deleted_at} /> · reserved until <RelTime iso={t.expires_at} />
          </span>
        </li>
      {/each}
    </ul>
  </details>
{/if}

{#if transferring}
  <div class="pickbar" role="region" aria-label="Transfer selection">
    <span class="n"><b class="num">{tpicked.length}</b> selected{#if transferFrom}{' '}from team <b>{transferFrom}</b>{/if}</span>
    {#if transferSel.error}<span class="selerr">{transferSel.error}</span>
    {:else if !tpicked.length}<span class="dim">Select record sets of one team</span>{/if}
    {#if transferFrom || ownerF}
      <button class="btn quiet" type="button" disabled={!shownTransferable.length} onclick={() => (tpicked = [...new Set([...tpicked, ...shownTransferable.map(keyOf)])])}>Select all shown ({shownTransferable.length})</button>
    {/if}
    {#if tpicked.length}<button class="btn quiet" type="button" onclick={() => (tpicked = [])}>Clear</button>{/if}
    <span class="sp"></span>
    <a class="btn quiet link" href={transfersHref({ zone })}>Transfers of this zone</a>
    <button class="btn quiet" type="button" onclick={stopTransfer}>Cancel</button>
    <button class="btn primary" type="button" disabled={!tpicked.length || !!transferSel.error} onclick={() => (transferOpen = true)}><Icon name="transfer" size={14} />Transfer…</button>
  </div>
{/if}

{#if selecting}
  <div class="pickbar" role="region" aria-label="Adoption selection">
    <span class="n"><b class="num">{picked.length}</b> record set{picked.length === 1 ? '' : 's'} selected</span>
    <button class="btn quiet" type="button" disabled={!shownForeign.length} onclick={() => (picked = [...new Set([...picked, ...shownForeign.map(keyOf)])])}>Select all shown ({shownForeign.length})</button>
    {#if picked.length}<button class="btn quiet" type="button" onclick={() => (picked = [])}>Clear</button>{/if}
    <span class="sp"></span>
    <button class="btn quiet" type="button" onclick={() => { selecting = false; picked = []; }}>Cancel</button>
    <button class="btn primary" type="button" onclick={() => (adoptOpen = true)}>{picked.length ? 'Adopt…' : 'Adopt by filter…'}</button>
  </div>
{/if}

{#if staged.length && !selecting && !transferring}
  <div class="tray" role="region" aria-label="Changes not applied yet">
    <span class="n"><b class="num">{staged.length}</b> change{staged.length === 1 ? '' : 's'} not applied yet</span>
    <ul class="pending">
      {#each staged as c (stagedKey(c))}
        <li class={c.kind}>
          <button class="pick-staged" type="button" disabled={c.kind === 'delete'} onclick={() => editStaged(c)} title={c.kind === 'delete' ? 'Will be deleted' : 'Edit this change'}>
            <span class="sign" aria-hidden="true">{stageSign[c.kind]}</span><span class="mono">{c.host}</span><span class="t" class:mono={!isForward(c)}>{typeLabel(c.type)}</span>
          </button>
          <button class="x" type="button" aria-label="Remove the change of {c.host} {c.type}" title="Remove this change" onclick={() => undo(stagedKey(c))}><Icon name="x" size={12} /></button>
        </li>
      {/each}
    </ul>
    <span class="sp"></span>
    <button class="btn quiet" type="button" onclick={() => (staged = [])}>Discard all</button>
    <button class="btn primary" type="button" onclick={() => { router.setParams({ rr: undefined }); reviewOpen = true; }}>Review and apply…</button>
  </div>
{/if}

{#if formFor && inv && !unmanaged}
  <RecordForm {zone} {me} existing={existingAfter} editing={formFor.rr} staged={formFor.staged} {tombstones} {onstage} onclose={() => (formFor = null)} />
{/if}

{#if fwdFormFor && inv && !unmanaged}
  <ForwardForm {zone} {me} existing={forwardsAfter} editing={fwdFormFor.rr} staged={fwdFormFor.staged} {tombstones} {https} {onstage} onclose={() => (fwdFormFor = null)} />
{/if}

{#if reviewOpen && inv && !unmanaged}
  <ReviewPanel
    {zone}
    {staged}
    {me}
    {tombstones}
    onclose={() => (reviewOpen = false)}
    onunstage={undo}
    onapplied={() => { staged = []; load(); }}
    onreload={reloadForReview}
  />
{/if}

{#if adoptOpen && inv && !unmanaged}
  <AdoptPanel
    {zone}
    selected={pickedRefs}
    teams={me?.teams ?? []}
    types={adoptTypes}
    initialComment={restored?.comment ?? ''}
    initialFilter={restored ? { hosts: restored.selection.hosts ?? [], types: restored.selection.types ?? [], owner: restored.selection.owner } : undefined}
    onclose={() => { adoptOpen = false; restored = null; if (!selecting) picked = []; }}
    onadopted={onAdopted}
    onforbidden={() => { adoptForbidden = true; selecting = false; picked = []; }}
  />
{/if}

{#if tfOpen && !unmanaged}
  <TerraformPanel {zone} teams={me?.teams ?? []} {owners} onclose={() => { tfOpen = false; router.setParams({ export: undefined }); }} />
{/if}

{#if transferOpen && inv && !unmanaged && transferFrom}
  <TransferPanel {zone} picked={transferRefs} from={transferFrom} {me} onclose={closeTransfer} ondone={onTransferSent} />
{/if}

{#if selected && !selecting && !transferring && !adoptOpen && !formFor && !fwdFormFor && !reviewOpen && !transferOpen}
  {#key selectedKey}
    <RRsetDrawer
      {zone}
      rr={selected}
      onclose={close}
      {unmanaged}
      writable={selectedVerdict?.ok ?? false}
      readOnlyWhy={selectedVerdict && !selectedVerdict.ok ? selectedVerdict.text : ''}
      stagedKind={stagedFor(staged, selected.host, selected.type)?.kind}
      onedit={() => edit(selected)}
      ondelete={() => { remove(selected); close(); }}
      canAdopt={adoptAllowed}
      adoptHint={adoptWhyNot}
      onadopt={() => adoptOne(selected)}
      ownership={owns(selected)}
      ontransfer={selected.owner && pickable(selected) && transferGate.ok ? () => transferOne(selected) : undefined}
    />
  {/key}
{/if}

<style>
  .unmanaged {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--s3) var(--s6);
    margin-bottom: var(--s5);
    padding: var(--s4) var(--s5);
    border: 1px dashed var(--rule-strong);
    border-radius: var(--r-lg);
    background: var(--sheet);
  }
  .utext {
    display: grid;
    gap: var(--s1);
    max-width: 70ch;
  }
  .utext h2 {
    display: inline-flex;
    align-items: center;
    gap: var(--s2);
    font-size: var(--t-lead);
    font-weight: 600;
  }
  .utext p {
    margin: 0;
    color: var(--ink-2);
  }
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
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--s3) var(--s8);
    margin-bottom: var(--s5);
  }
  .title {
    min-width: 0;
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
  .summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
    padding-bottom: 4px;
  }
  .split {
    color: var(--ink-2);
    font-size: var(--t-lead);
    margin-right: var(--s1);
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 0;
    border: 0;
    background: none;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
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

  .access {
    margin-bottom: var(--s5);
    padding: var(--s2) var(--s4);
    border: 1px solid var(--rule-soft);
    border-radius: var(--r-lg);
  }
  .access[open] {
    padding-bottom: var(--s4);
    background: var(--sheet);
  }
  .access summary {
    cursor: pointer;
    color: var(--ink-2);
    font-weight: 500;
    border-radius: var(--r-sm);
  }
  .access[open] summary {
    margin-bottom: var(--s3);
  }
  .dim {
    color: var(--ink-3);
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
  .tab[aria-checked='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .count {
    font-size: 12px;
    color: var(--ink-4);
  }
  .tab.tainted .count,
  .tab.attention .count {
    color: var(--wax);
    font-weight: 600;
  }
  .tab.pending .count {
    color: var(--brass);
    font-weight: 600;
  }
  .right {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s2);
  }
  .search input {
    width: 220px;
  }
  .btn[aria-disabled='true'] {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn[aria-disabled='true']:active {
    transform: none;
  }

  .note {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: var(--s2);
    color: var(--ink-3);
    font-size: 13px;
  }
  .note.sent {
    flex-wrap: wrap;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--brass-wash);
    color: var(--ink-2);
  }
  .note.sent .btn {
    margin-left: auto;
    height: 24px;
    padding: 0 6px;
  }
  .tombs {
    margin-top: var(--s4);
    padding: var(--s2) var(--s4);
    border: 1px solid var(--rule-soft);
    border-radius: var(--r-lg);
  }
  .tombs[open] {
    padding-bottom: var(--s3);
    background: var(--sheet);
  }
  .tombs summary {
    cursor: pointer;
    color: var(--ink-2);
    font-weight: 500;
  }
  .tombs .count {
    margin-left: 4px;
    color: var(--ink-3);
    font-weight: 400;
  }
  .tombs .small {
    margin: var(--s2) 0;
    font-size: 12px;
  }
  .tombs ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 2px;
  }
  .tombs li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px var(--s3);
    padding: 4px 0;
    border-bottom: 1px solid var(--rule-soft);
  }
  .tombs li:last-child {
    border-bottom: 0;
  }
  .tombs .t {
    color: var(--ink-3);
    font-size: 12px;
  }
  .tombs .dim {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    font-size: 12px;
  }
  .btn.link {
    text-decoration: none;
  }
  .selerr {
    color: var(--wax);
    font-size: 12px;
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
    table-layout: fixed;
    min-width: 960px;
  }
  .w-seal {
    width: 36px;
  }
  .w-name {
    width: 30%;
  }
  .w-type {
    width: 76px;
  }
  .w-ttl {
    width: 72px;
  }
  .w-owner {
    width: 124px;
  }
  .w-last {
    width: 200px;
  }
  .w-act {
    width: 124px;
  }
  th {
    text-align: left;
    font-size: var(--t-caption);
    font-weight: 500;
    letter-spacing: 0.01em;
    color: var(--ink-3);
    padding: var(--s2) var(--s3);
    border-bottom: 1px solid var(--rule);
    white-space: nowrap;
  }
  td {
    padding: 9px var(--s3);
    border-bottom: 1px solid var(--rule-soft);
    vertical-align: top;
    min-width: 0;
    overflow: hidden;
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
  tbody tr.owned {
    background: color-mix(in srgb, var(--seal-ink-wash) 45%, transparent);
  }
  tbody tr.owned:hover {
    background: var(--seal-ink-wash);
  }
  tbody tr.selected {
    background: var(--seal-ink-wash);
  }
  tbody tr:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: -2px;
  }
  .c-seal {
    padding-right: 0;
  }
  .c-seal :global(svg) {
    margin-top: 3px;
  }
  .c-ttl {
    color: var(--ink-3);
  }
  .name {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .name :global(.host) {
    min-width: 0;
    flex: 0 1 auto;
  }
  .ico {
    flex: none;
    color: var(--ink-4);
    cursor: help;
  }
  .ephemeral {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 3px;
    font-size: 12px;
    color: var(--brass);
  }
  .copyname {
    flex: none;
    display: grid;
    place-items: center;
    width: 22px;
    height: 22px;
    margin: -2px 0;
    padding: 0;
    border: 0;
    border-radius: var(--r-sm);
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    opacity: 0;
    transition: opacity 120ms var(--ease-out);
  }
  .copyname:hover {
    background: var(--rule-soft);
    color: var(--ink);
  }
  tr:hover .copyname,
  tr:focus-within .copyname,
  .copyname:focus-visible {
    opacity: 1;
  }
  .type {
    font-size: 12px;
    font-weight: 600;
    color: var(--ink-2);
  }
  .c-values ul {
    list-style: none;
    margin: 0;
    padding: 0;
    color: var(--ink-2);
    min-width: 0;
  }
  .c-values li {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .more {
    padding: 0;
    border: 0;
    background: none;
    color: var(--seal-ink);
    font-size: 12px;
    cursor: pointer;
    border-radius: var(--r-sm);
  }
  .more:hover {
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .team {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    max-width: 100%;
    height: 20px;
    padding: 0 7px 0 5px;
    border-radius: 6px;
    background: var(--pencil-wash);
    color: var(--ink-2);
    font-size: 12px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    text-decoration: none;
  }
  .team.mine {
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .team.reserved {
    background: transparent;
    box-shadow: inset 0 0 0 1px var(--rule-strong);
    color: var(--ink-3);
    font-weight: 500;
  }
  a.team:hover {
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .ro {
    color: var(--ink-4);
    font-size: 12px;
  }
  .c-custody {
    font-size: 13px;
  }
  .when {
    display: block;
    margin: 2px 0 0 26px;
    color: var(--ink-4);
    font-size: 12px;
  }
  .c-act {
    text-align: right;
    padding-top: 5px;
    padding-bottom: 5px;
  }
  .btn.small {
    height: 26px;
    padding: 0 var(--s2);
    font-size: 13px;
  }
  .act {
    color: var(--ink-3);
  }
  tr:hover .act,
  tr:focus-within .act {
    color: var(--seal-ink);
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
  tr.none td,
  tr.loading td {
    overflow: visible;
  }
  .empty .btn {
    margin-top: var(--s3);
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
  .pager {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
    gap: var(--s2) var(--s3);
    margin-top: var(--s3);
  }
  .pager .dim {
    margin-right: auto;
  }
  .pos {
    color: var(--ink-3);
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
  .acts {
    display: inline-flex;
    align-items: center;
    justify-content: flex-end;
    gap: 2px;
  }
  .acts .ico {
    margin-right: 4px;
  }
  .btn.small.icon {
    width: 26px;
    padding: 0;
  }
  tr:hover .act.del,
  tr:focus-within .act.del {
    color: var(--wax);
  }
  .rotag {
    flex: none;
    height: 17px;
    padding: 0 5px;
    border-radius: 4px;
    background: var(--pencil-wash);
    color: var(--ink-3);
    font-size: 11px;
    line-height: 17px;
    cursor: help;
  }
  .c-values ul.alias li {
    color: var(--ink-3);
  }
  .stagedtag {
    display: inline-block;
    max-width: 100%;
    margin-top: 3px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 500;
    line-height: 18px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    background: var(--brass-wash);
    color: var(--brass);
  }
  .stagedtag.delete {
    background: var(--wax-wash);
    color: var(--wax);
  }
  tr.staged-delete .c-values li,
  tr.staged-delete .c-name :global(.label) {
    text-decoration: line-through;
    text-decoration-color: color-mix(in srgb, var(--wax) 55%, transparent);
  }
  tbody tr.staged-update,
  tbody tr.staged-delete {
    box-shadow: inset 3px 0 0 var(--brass);
  }
  tbody tr.staged-delete {
    box-shadow: inset 3px 0 0 var(--wax);
  }
  .tray {
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
    border: 1px solid color-mix(in srgb, var(--brass) 35%, var(--rule));
    box-shadow: var(--lift);
    animation: rise 200ms var(--ease-out);
  }
  .tray .n {
    color: var(--ink-2);
  }
  .tray .sp {
    flex: 1;
  }
  .tray .pending {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin: 0;
    padding: 0;
    list-style: none;
    min-width: 0;
  }
  .tray .pending li {
    display: inline-flex;
    align-items: center;
    height: 24px;
    border-radius: 6px;
    background: var(--well);
    border: 1px solid var(--rule-soft);
    font-size: 12px;
    max-width: 260px;
  }
  .pick-staged {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    min-width: 0;
    height: 100%;
    padding: 0 4px 0 7px;
    border: 0;
    background: none;
    color: var(--ink-2);
    cursor: pointer;
  }
  .pick-staged:disabled {
    cursor: default;
  }
  .pick-staged .mono {
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .pick-staged .t {
    flex: none;
    color: var(--ink-3);
    font-weight: 600;
  }
  .sign {
    font-weight: 700;
    color: var(--stamp);
  }
  .update .sign {
    color: var(--brass);
  }
  .delete .sign {
    color: var(--wax);
  }
  .tray .pending .x {
    display: grid;
    place-items: center;
    width: 20px;
    height: 100%;
    padding: 0;
    border: 0;
    background: none;
    color: var(--ink-4);
    cursor: pointer;
  }
  .tray .pending .x:hover {
    color: var(--ink);
  }
  @media (max-width: 900px) {
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
      table-layout: auto;
    }
    colgroup,
    thead {
      display: none;
    }
    tbody tr {
      display: grid;
      grid-template-columns: 22px minmax(0, 1fr) auto;
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
    }
    .c-name {
      grid-area: name;
    }
    .c-type {
      grid-area: type;
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
      font-size: 12px;
    }
    .c-custody {
      grid-area: custody;
      justify-self: end;
      text-align: right;
      min-width: 0;
    }
    /* the row opens the details, where adoption is offered too */
    .c-act {
      display: none;
    }
    .copyname {
      opacity: 1;
    }
    .when {
      margin-left: 0;
    }
    tr.loading,
    tr.none {
      display: block;
    }
  }
</style>
