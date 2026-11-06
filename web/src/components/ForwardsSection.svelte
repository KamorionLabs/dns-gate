<script lang="ts">
  import type { HTTPSRedirect, RRset, Tombstone } from '../lib/types';
  import type { Verdict } from '../lib/rights';
  import { readOnlyLabel } from '../lib/rights';
  import type { StagedChange } from '../lib/staging';
  import { stagedFor, stagedKey } from '../lib/staging';
  import { forwardText, httpsNote, isKnownMode, modeLabel, modeSpecs } from '../lib/forwards';
  import { statusLabel } from '../lib/labels';
  import { dateText } from '../lib/teams';
  import { teamHref } from '../lib/router.svelte';
  import Seal from './Seal.svelte';
  import Host from './Host.svelte';
  import ActorChip from './ActorChip.svelte';
  import RelTime from './RelTime.svelte';
  import Icon from './Icon.svelte';

  let {
    zone,
    forwards,
    total,
    https,
    loading = false,
    unmanaged = false,
    canAdd = false,
    filtered = false,
    staged,
    selectedKey = '',
    verdict,
    owns,
    reservedFor,
    adoptAllowed = false,
    pick,
    onopen,
    onadd,
    onedit,
    onremove,
    onundo,
    onadopt,
    onclearfilter,
  }: {
    zone: string;
    /** The forwards shown (after the search and owner filters). */
    forwards: RRset[];
    /** Every forward of the zone. */
    total: number;
    https?: HTTPSRedirect;
    loading?: boolean;
    unmanaged?: boolean;
    canAdd?: boolean;
    /** A search or owner filter hides some forwards. */
    filtered?: boolean;
    staged: StagedChange[];
    selectedKey?: string;
    verdict: (r: RRset) => Verdict;
    owns: (r: RRset) => { mine: boolean; text: string };
    reservedFor: (r: RRset) => Tombstone | undefined;
    adoptAllowed?: boolean;
    /** While selecting for an adoption or a transfer: whether the row has a checkbox, and its state. */
    pick?: (r: RRset) => { show: boolean; checked: boolean; inert: boolean } | null;
    onopen: (r: RRset) => void;
    onadd: () => void;
    onedit: (r: RRset) => void;
    onremove: (r: RRset) => void;
    onundo: (key: string) => void;
    onadopt: (r: RRset) => void;
    onclearfilter: () => void;
  } = $props();

  const note = $derived(httpsNote(https, dateText));
  const keyOf = (r: RRset) => `${r.host}/${r.type}`;
  const owned = (r: RRset) => r.status !== 'foreign';
  const lastActor = (r: RRset) => r.updated_by ?? r.created_by;
  const lastAt = (r: RRset) => r.updated_at ?? r.created_at;
  const fullName = (r: RRset) => (r.host === '@' ? zone : `${r.host}.${zone}`);
  const stop = (e: Event) => e.stopPropagation();
  const rowKey = (e: KeyboardEvent, r: RRset) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onopen(r);
    }
  };
  const stagedText = (c: StagedChange) => (c.kind === 'delete' ? 'Will be deleted' : c.forward ? `Will change to ${forwardText(c.forward)}` : 'Will change');
  const newOnes = $derived(staged.filter((c) => c.kind === 'create' && c.type === 'URLFWD'));
</script>

<section class="fwd" aria-labelledby="fwd-title">
  <header class="fhead">
    <div class="ftitle">
      <h2 id="fwd-title">URL forwards <span class="count num">{loading ? '…' : total.toLocaleString('en')}</span></h2>
      <p class="sub">HTTP redirects answered by the DNS provider for names of this zone, owned by teams like record sets.</p>
      {#if note}<p class="https {note.tone}"><Icon name={note.tone === 'ok' ? 'check' : 'alert'} size={12} /> {note.text}</p>{/if}
    </div>
    {#if canAdd}<button class="btn" type="button" onclick={onadd}><Icon name="plus" size={14} />Add forward</button>{/if}
  </header>

  {#if forwards.length || newOnes.length}
    <div class="sheet">
      <table class:ro={unmanaged}>
        <colgroup>
          <col class="w-seal" />
          <col class="w-name" />
          <col class="w-kind" />
          <col />
          <col class="w-owner" />
          <col class="w-last" />
          {#if !unmanaged}<col class="w-act" />{/if}
        </colgroup>
        <thead>
          <tr>
            <th class="c-seal"><span class="sr-only">Status</span></th>
            <th>Name</th>
            <th class="c-kind">Kind</th>
            <th>Target</th>
            <th class="c-owner">Owner</th>
            <th class="c-custody">Last change</th>
            {#if !unmanaged}<th class="c-act"><span class="sr-only">Actions</span></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each forwards as r (keyOf(r))}
            {@const k = keyOf(r)}
            {@const st = stagedFor(staged, r.host, r.type)}
            {@const v = verdict(r)}
            {@const roTag = readOnlyLabel(r)}
            {@const p = pick?.(r) ?? null}
            {@const f = r.forward}
            <tr
              class="{r.status}{st ? ' staged-' + st.kind : ''}"
              class:owned={owned(r)}
              class:selected={selectedKey === k || !!p?.checked}
              class:inert={!!p?.inert}
              tabindex="0"
              onclick={() => onopen(r)}
              onkeydown={(e) => rowKey(e, r)}
              aria-label="URL forward of {fullName(r)}, {statusLabel[r.status]}{r.owner ? ', owned by ' + r.owner : ''}"
            >
              <td class="c-seal">
                {#if p?.show}
                  <input type="checkbox" class="pick" checked={p.checked} onclick={stop} onchange={() => onopen(r)} aria-label="Select the forward of {r.host}" />
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
                </div>
              </td>
              <td class="c-kind">
                {#if f}<span class="kind" class:odd={!isKnownMode(f.type)} title={isKnownMode(f.type) ? modeSpecs[f.type].help : modeLabel(f.type)}>{f.type === 'frame' ? 'Frame' : f.type}</span>{/if}
              </td>
              <td class="c-target">
                {#if f}
                  <span class="url mono" title={f.url}>{f.url}</span>
                  {#if f.title}<span class="ftitle-line" title={f.description || f.title}>{f.title}</span>{/if}
                {/if}
                {#if st}<span class="stagedtag {st.kind}">{stagedText(st)}</span>{/if}
              </td>
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
                    <button class="btn quiet small act" type="button" onclick={(e) => { stop(e); onundo(k); }} aria-label="Undo the staged change of the forward of {r.host}"><Icon name="undo" size={13} />Undo</button>
                  {:else if owned(r) && v.ok}
                    <span class="acts">
                      <button class="btn quiet small act" type="button" onclick={(e) => { stop(e); onedit(r); }} aria-label="Edit the forward of {r.host}">Edit</button>
                      <button class="btn quiet small icon act del" type="button" onclick={(e) => { stop(e); onremove(r); }} aria-label="Delete the forward of {r.host}" title="Delete (staged, applied after review)"><Icon name="trash" size={14} /></button>
                    </span>
                  {:else if owned(r)}
                    <span class="acts">
                      {#if !v.ok}<span class="ico" role="img" aria-label="Read-only: {owns(r).text}" title={owns(r).text}><Icon name="lock" size={12} /></span>{/if}
                      <button class="btn quiet small act" type="button" onclick={(e) => { stop(e); onopen(r); }} aria-label="Details of the forward of {r.host}">Details</button>
                    </span>
                  {:else if adoptAllowed && (r.protected || r.read_only)}
                    {@const why = r.protected ? 'Protected by the base policy: it cannot be adopted.' : v.ok ? 'It cannot be adopted.' : v.text}
                    <button class="btn quiet small act" type="button" aria-disabled="true" onclick={stop} title={why} aria-label="Adopt the forward of {r.host}: not possible. {why}">Adopt</button>
                  {:else if adoptAllowed}
                    <button class="btn quiet small act adopt" type="button" title="Adopt this forward: the gate manages it for a team" onclick={(e) => { stop(e); onadopt(r); }} aria-label="Adopt the forward of {r.host}">Adopt</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
          {#each newOnes as c (stagedKey(c))}
            <tr class="new staged-create">
              <td class="c-seal"><span class="plus" aria-hidden="true">+</span></td>
              <td class="c-name"><div class="name"><Host host={c.host} {zone} showZone={false} short /></div></td>
              <td class="c-kind">{#if c.forward}<span class="kind">{c.forward.type === 'frame' ? 'Frame' : c.forward.type}</span>{/if}</td>
              <td class="c-target">
                {#if c.forward}<span class="url mono" title={c.forward.url}>{c.forward.url}</span>{/if}
                <span class="stagedtag create">Will be added</span>
              </td>
              <td class="c-owner"><span class="ro">—</span></td>
              <td class="c-custody"><span class="ro">Not applied yet</span></td>
              {#if !unmanaged}
                <td class="c-act">
                  <button class="btn quiet small act" type="button" onclick={() => onundo(stagedKey(c))} aria-label="Remove the new forward of {c.host}"><Icon name="undo" size={13} />Undo</button>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else if !loading}
    <div class="none">
      {#if filtered && total > 0}
        <span>No URL forward matches the search.</span>
        <button class="btn quiet small" type="button" onclick={onclearfilter}>Show every forward</button>
      {:else}
        <span>No URL forward in this zone.</span>
        {#if canAdd}<span class="dim">Add one to send visitors of a name to another address.</span>{/if}
      {/if}
    </div>
  {/if}
</section>

<style>
  .fwd {
    display: grid;
    gap: var(--s3);
    margin-top: var(--s6);
  }
  .fhead {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--s2) var(--s4);
  }
  .ftitle {
    display: grid;
    gap: 2px;
    min-width: 0;
  }
  h2 {
    display: flex;
    align-items: baseline;
    gap: var(--s2);
    font-size: var(--t-lead);
    font-weight: 600;
  }
  .count {
    font-size: 12px;
    font-weight: 400;
    color: var(--ink-4);
  }
  .sub {
    color: var(--ink-3);
    font-size: 13px;
  }
  .https {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--ink-3);
  }
  .https.ok :global(svg) {
    color: var(--stamp);
  }
  .https.warn :global(svg) {
    color: var(--brass);
  }
  .dim {
    color: var(--ink-3);
  }
  .none {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s1) var(--s3);
    padding: var(--s3) var(--s4);
    border: 1px dashed var(--rule);
    border-radius: var(--r-lg);
    color: var(--ink-2);
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
    min-width: 900px;
  }
  .w-seal {
    width: 36px;
  }
  .w-name {
    width: 24%;
  }
  .w-kind {
    width: 84px;
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
  tbody tr.owned:hover,
  tbody tr.selected {
    background: var(--seal-ink-wash);
  }
  tbody tr:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: -2px;
  }
  tbody tr.inert {
    opacity: 0.4;
    cursor: default;
  }
  .c-seal {
    padding-right: 0;
  }
  .c-seal :global(svg) {
    margin-top: 3px;
  }
  .plus {
    font-weight: 700;
    color: var(--stamp);
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
  .kind {
    display: inline-block;
    height: 20px;
    padding: 0 6px;
    border-radius: 5px;
    background: var(--well);
    box-shadow: inset 0 0 0 1px var(--rule-soft);
    color: var(--ink-2);
    font-size: 12px;
    font-weight: 600;
    line-height: 20px;
    font-variant-numeric: tabular-nums;
    cursor: help;
  }
  .kind.odd {
    color: var(--ink-4);
    font-weight: 500;
  }
  .url {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--ink-2);
  }
  .ftitle-line {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--ink-3);
    font-size: 12px;
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
  .btn.small.icon {
    width: 26px;
    padding: 0;
  }
  .btn[aria-disabled='true'] {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .act {
    color: var(--ink-3);
  }
  tr:hover .act,
  tr:focus-within .act {
    color: var(--seal-ink);
  }
  tr:hover .act.del,
  tr:focus-within .act.del {
    color: var(--wax);
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
  tr.foreign td,
  tr.foreign :global(.label) {
    color: var(--ink-3);
  }
  tr.tainted .c-name :global(.label),
  tr.missing .c-name :global(.label) {
    color: var(--wax);
  }
  tr.missing .url {
    text-decoration: line-through;
    text-decoration-color: var(--rule-strong);
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
  .stagedtag.create {
    background: var(--stamp-wash);
    color: var(--stamp);
  }
  tr.staged-delete .url,
  tr.staged-delete .c-name :global(.label) {
    text-decoration: line-through;
    text-decoration-color: color-mix(in srgb, var(--wax) 55%, transparent);
  }
  tbody tr.staged-update {
    box-shadow: inset 3px 0 0 var(--brass);
  }
  tbody tr.staged-delete {
    box-shadow: inset 3px 0 0 var(--wax);
  }
  tbody tr.staged-create {
    box-shadow: inset 3px 0 0 var(--stamp);
  }
  .pick {
    width: 15px;
    height: 15px;
    margin: 1px 0 0;
    accent-color: var(--seal-ink);
    cursor: pointer;
  }
  @media (max-width: 720px) {
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
        'seal name kind'
        '. target target'
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
    .c-kind {
      grid-area: kind;
      text-align: right;
    }
    .c-target {
      grid-area: target;
      display: block;
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
    .c-act {
      display: none;
    }
    tr.new .c-act {
      display: block;
      grid-column: 2 / -1;
      text-align: left;
    }
    .when {
      margin-left: 0;
    }
  }
</style>
