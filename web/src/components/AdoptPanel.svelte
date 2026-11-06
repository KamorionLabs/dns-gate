<script lang="ts">
  import { untrack } from 'svelte';
  import { api, ApiError, onBeforeReauth } from '../lib/api';
  import type { AdoptCandidate, AdoptPreview, AdoptResult, AdoptSelection, RRsetRef } from '../lib/types';
  import { adoptReasonLabel } from '../lib/labels';
  import { saveAdopt } from '../lib/adoptDraft';
  import { ttl as fmtTTL } from '../lib/format';
  import { journalHref } from '../lib/router.svelte';
  import { forwardText, isForward } from '../lib/forwards';
  import SidePanel from './SidePanel.svelte';
  import Seal from './Seal.svelte';
  import Host from './Host.svelte';
  import ChipsInput from './ChipsInput.svelte';
  import ToggleChips from './ToggleChips.svelte';
  import CopyText from './CopyText.svelte';
  import HclBlock from './HclBlock.svelte';
  import Icon from './Icon.svelte';

  let {
    zone,
    selected,
    teams,
    types: typeOptions,
    initialComment = '',
    initialFilter,
    onclose,
    onadopted,
    onforbidden,
  }: {
    zone: string;
    selected: RRsetRef[];
    teams: string[];
    types: string[];
    initialComment?: string;
    initialFilter?: { hosts: string[]; types: string[]; owner?: string };
    onclose: () => void;
    onadopted: (r: AdoptResult) => void;
    onforbidden: () => void;
  } = $props();

  type Phase = 'loading' | 'preview' | 'forbidden' | 'error' | 'applying' | 'done';
  let phase = $state<Phase>('loading');
  // Props seed the form once; later edits belong to the panel.
  const seed = untrack(() => ({ selected, initialFilter, teams, initialComment }));
  let mode = $state<'selection' | 'filter'>(seed.selected.length ? 'selection' : 'filter');
  let hosts = $state<string[]>(seed.initialFilter?.hosts ?? []);
  let types = $state<string[]>(seed.initialFilter?.types ?? []);
  let owner = $state(seed.initialFilter?.owner ?? seed.teams[0] ?? '');
  let comment = $state(seed.initialComment);

  $effect(() => {
    if (!owner && teams[0]) owner = teams[0];
  });
  let preview = $state<AdoptPreview | null>(null);
  let excluded = $state<string[]>([]);
  let conflict = $state(false);
  let error = $state<string | null>(null);
  let commentError = $state(false);
  let result = $state<AdoptResult | null>(null);
  let hcl = $state<string | null>(null);
  let hclError = $state<string | null>(null);

  const key = (c: { host: string; type: string }) => `${c.host}/${c.type}`;
  /** Short type for the narrow column: a URL forward reads "Forward". */
  const shortType = (t: string) => (isForward({ type: t }) ? 'Forward' : t);
  /** What a candidate holds: its values, the target of an alias, or the redirect of a forward. */
  const content = (c: AdoptCandidate) =>
    c.forward ? forwardText(c.forward) : c.alias ? `alias → ${c.alias.target}` : (c.values ?? []).join('  ');
  const selection = (): AdoptSelection =>
    mode === 'selection'
      ? { rrsets: selected, owner }
      : { hosts: hosts.length ? hosts : undefined, types: types.length ? types : undefined, owner };

  async function runPreview() {
    phase = 'loading';
    error = null;
    try {
      preview = await api.adoptPreview(zone, selection());
      excluded = excluded.filter((k) => preview!.candidates.some((c) => c.adoptable && key(c) === k));
      phase = 'preview';
    } catch (e) {
      if (e instanceof ApiError && e.status === 403 && e.reason !== 'reauth_required') {
        phase = 'forbidden';
        onforbidden();
      } else if (!(e instanceof ApiError && e.reason === 'reauth_required')) {
        error = (e as Error).message;
        phase = 'error';
      }
    }
  }

  $effect(() => {
    void owner;
    void mode;
    untrack(runPreview);
  });

  $effect(() =>
    onBeforeReauth(() => saveAdopt(zone, { selection: { ...selection(), hosts, types }, comment })),
  );

  const adoptable = $derived((preview?.candidates ?? []).filter((c) => c.adoptable));
  const blocked = $derived((preview?.candidates ?? []).filter((c) => !c.adoptable));
  const chosen = $derived(adoptable.filter((c) => !excluded.includes(key(c))));

  function toggle(c: AdoptCandidate) {
    const k = key(c);
    excluded = excluded.includes(k) ? excluded.filter((x) => x !== k) : [...excluded, k];
  }

  async function apply() {
    if (!preview) return;
    if (!comment.trim()) {
      commentError = true;
      return;
    }
    commentError = false;
    conflict = false;
    error = null;
    phase = 'applying';
    try {
      result = await api.adopt(zone, {
        rrsets: chosen.map((c) => ({ host: c.host, type: c.type })),
        owner,
        comment: comment.trim(),
        preview_token: preview.preview_token,
      });
      phase = 'done';
      onadopted(result);
      loadHcl(result);
    } catch (e) {
      if (e instanceof ApiError && e.reason === 'adopt_conflict') {
        conflict = true;
        phase = 'preview';
      } else if (!(e instanceof ApiError && e.reason === 'reauth_required')) {
        error = (e as Error).message;
        phase = 'preview';
      }
    }
  }

  async function loadHcl(r: AdoptResult) {
    try {
      hcl = await api.terraform(zone, {
        team: r.owner,
        hosts: [...new Set(r.adopted.map((a) => a.host))],
        types: [...new Set(r.adopted.map((a) => a.type))],
      });
    } catch (e) {
      hclError = (e as Error).message;
    }
  }

  async function reviewAgain() {
    conflict = false;
    await runPreview();
  }
</script>

<SidePanel title="Adopt record sets" {onclose} width={640}>
  {#snippet head()}
    <p class="eyebrow">Adopt into the gate</p>
    <h2 class="mono">{zone}</h2>
  {/snippet}

  {#if phase === 'forbidden'}
    <div class="notice">
      <Icon name="lock" size={16} />
      <div><b>You cannot adopt record sets in this zone.</b> Adoption needs the dns.record.adopt action; ask a policy administrator, or check in the policy simulator.</div>
    </div>
  {:else if phase === 'done' && result}
    <section class="done">
      <div class="donehead">
        <span class="mark"><Seal status="managed" size={26} /></span>
        <div>
          <p class="big">{result.adopted.length} record set{result.adopted.length > 1 ? 's' : ''} now managed by the gate</p>
          <p class="dim">Owner team <b>{result.owner}</b> · request <CopyText text={result.request_id} label="request id" /> · <a href={journalHref({ zone })}>journal</a></p>
        </div>
      </div>
      <ul class="cands">
        {#each result.adopted as a (key(a))}<li><Seal status="managed" size={13} /><Host host={a.host} {zone} showZone={false} /><span class="type mono">{shortType(a.type)}</span></li>{/each}
      </ul>
    </section>
    <section class="tf">
      <h3>Manage them with Terraform</h3>
      <p class="dim">Paste into your stack, the first plan should be empty: the import blocks bind the existing record sets, nothing is created or changed.</p>
      {#if hcl}<HclBlock {hcl} filename="{zone.replaceAll('.', '_')}_{result.owner}.tf" />
      {:else if hclError}<p class="fail">{hclError}</p>
      {:else}<div class="skeleton line"></div>{/if}
    </section>
  {:else}
    <section class="scope">
      <div class="seg" role="tablist" aria-label="What to adopt">
        <button role="tab" type="button" aria-selected={mode === 'selection'} disabled={!selected.length} onclick={() => (mode = 'selection')}>Selected ({selected.length})</button>
        <button role="tab" type="button" aria-selected={mode === 'filter'} onclick={() => (mode = 'filter')}>By filter</button>
      </div>
      {#if mode === 'filter'}
        <div class="filter">
          <div><span class="lbl">Hosts <span class="dim">(globs: * one label, ** several, @ apex)</span></span><ChipsInput bind:values={hosts} label="Hosts" placeholder="*.legacy, vpn" /></div>
          <div><span class="lbl">Types <span class="dim">(none = any)</span></span><ToggleChips options={typeOptions} bind:values={types} label="Types" /></div>
          <button class="btn" type="button" onclick={runPreview}><Icon name="filter" size={14} />Preview this filter</button>
        </div>
      {/if}
      <label class="owner">
        <span class="lbl">Owner team</span>
        {#if teams.length > 1}
          <span class="field"><select bind:value={owner}>{#each teams as t (t)}<option value={t}>{t}</option>{/each}</select><span class="chev"><Icon name="chevron" size={12} /></span></span>
        {:else}<b>{owner || 'your team'}</b>{/if}
        <span class="dim">Only this team will be able to change them through the gate.</span>
      </label>
    </section>

    {#if conflict}
      <div class="notice warn" role="alert">
        <Icon name="alert" size={16} />
        <div><b>The zone changed since the preview.</b> Nothing was adopted. Review the record sets again before confirming.</div>
        <button class="btn" type="button" onclick={reviewAgain}>Review again</button>
      </div>
    {/if}

    {#if phase === 'loading'}
      <div class="skeleton line"></div><div class="skeleton line short"></div>
    {:else if phase === 'error'}
      <p class="fail">{error}</p>
    {:else if preview}
      <section>
        <h3>Will be adopted <span class="num count">{chosen.length}</span></h3>
        {#if adoptable.length === 0}
          <p class="dim">Nothing in this selection can be adopted.</p>
        {:else}
          <ul class="cands">
            {#each adoptable as c (key(c))}
              <li class="ok" class:off={excluded.includes(key(c))}>
                <input type="checkbox" checked={!excluded.includes(key(c))} onchange={() => toggle(c)} aria-label="Adopt {c.host} {c.type}" />
                <Host host={c.host} {zone} showZone={false} />
                <span class="type mono">{shortType(c.type)}</span>
                <span class="vals mono" title={c.forward?.title ? `${content(c)} (${c.forward.title})` : content(c)}>{content(c)}</span>
                <span class="ttl mono">{c.forward ? '' : fmtTTL(c.ttl)}</span>
              </li>
            {/each}
          </ul>
        {/if}
      </section>
      {#if blocked.length}
        <section>
          <h3>Cannot be adopted <span class="num count">{blocked.length}</span></h3>
          <ul class="cands">
            {#each blocked as c (key(c))}
              <li class="no">
                <Seal status={c.status} size={13} />
                <Host host={c.host} {zone} showZone={false} />
                <span class="type mono">{shortType(c.type)}</span>
                <span class="why" class:neutral={c.reason === 'already_owned'}>{adoptReasonLabel(c.reason)}</span>
              </li>
            {/each}
          </ul>
        </section>
      {/if}

      <section class="confirm">
        <label>
          <span class="lbl">Why <span class="req">required</span></span>
          <textarea class="in" rows="3" bind:value={comment} class:invalid={commentError} placeholder="e.g. Bring the VPN and CRM records under the infra stack"></textarea>
        </label>
        {#if commentError}<p class="fail">Explain why: it goes to the journal with the adoption.</p>{/if}
        {#if error}<p class="fail">{error}</p>{/if}
        <button class="btn primary" type="button" disabled={!chosen.length || phase === 'applying' || conflict} onclick={apply}>
          <Seal status="managed" size={14} />
          {phase === 'applying' ? 'Adopting…' : `Adopt ${chosen.length} record set${chosen.length === 1 ? '' : 's'} for ${owner}`}
        </button>
        <p class="dim small">All or nothing: if any of them changed since this preview, nothing is adopted. Their content is not modified.</p>
      </section>
    {/if}
  {/if}
</SidePanel>

<style>
  h2 {
    font-size: var(--t-h3);
    letter-spacing: -0.01em;
  }
  h3 {
    font-size: 13px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: var(--s2);
  }
  .count {
    color: var(--ink-4);
    font-weight: 500;
  }
  .lbl {
    font-size: 12px;
    font-weight: 500;
    color: var(--ink-2);
  }
  .dim {
    color: var(--ink-3);
  }
  .dim b {
    color: var(--ink);
  }
  .small {
    font-size: 12px;
  }
  .scope {
    display: grid;
    gap: var(--s3);
  }
  .seg {
    display: inline-flex;
    justify-self: start;
    padding: 2px;
    gap: 2px;
    border-radius: var(--r-md);
    background: var(--well);
    border: 1px solid var(--rule-soft);
  }
  .seg button {
    height: 26px;
    padding: 0 12px;
    border: 0;
    border-radius: 5px;
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    font-weight: 500;
  }
  .seg button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .seg button[aria-selected='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .filter {
    display: grid;
    gap: var(--s3);
    padding: var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .filter :global(.chips) {
    background: var(--sheet-raised);
  }
  .filter .btn {
    justify-self: start;
  }
  .owner {
    display: grid;
    gap: 4px;
  }
  .owner .field {
    justify-self: start;
  }
  .cands {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    overflow: hidden;
  }
  .cands li {
    display: grid;
    grid-template-columns: 18px minmax(0, 1.1fr) 56px minmax(0, 2fr) auto;
    align-items: center;
    gap: var(--s2);
    padding: 7px var(--s3);
    border-bottom: 1px solid var(--rule-soft);
    font-size: 13px;
  }
  .cands li:last-child {
    border-bottom: 0;
  }
  .done .cands li {
    grid-template-columns: 18px minmax(0, 1fr) auto;
  }
  .ok {
    background: var(--sheet);
  }
  .ok.off {
    opacity: 0.5;
  }
  .ok.off :global(.label) {
    text-decoration: line-through;
  }
  .no {
    color: var(--ink-3);
  }
  .no :global(.label) {
    color: var(--ink-3);
  }
  .cands li.no {
    grid-template-columns: 18px minmax(0, 1.1fr) 56px minmax(0, 2fr);
  }
  .cands :global(.host) {
    min-width: 0;
  }
  .why.neutral {
    color: var(--ink-3);
  }
  .type {
    font-size: 12px;
    font-weight: 600;
    color: var(--ink-2);
  }
  .vals {
    font-size: 12px;
    color: var(--ink-3);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ttl {
    font-size: 12px;
    color: var(--ink-4);
  }
  .why {
    font-size: 12px;
    color: var(--wax);
  }
  input[type='checkbox'] {
    width: 15px;
    height: 15px;
    margin: 0;
    accent-color: var(--seal-ink);
  }
  .confirm {
    display: grid;
    gap: var(--s2);
    padding-top: var(--s4);
    border-top: 1px solid var(--rule);
  }
  .confirm label {
    display: grid;
    gap: 4px;
  }
  .in {
    padding: var(--s2) var(--s3);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    background: var(--well);
    resize: vertical;
  }
  .in.invalid {
    border-color: var(--wax);
  }
  .req {
    font-size: 11px;
    color: var(--wax);
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
  .fail {
    color: var(--wax);
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
  .notice.warn {
    background: var(--wax-wash);
    color: var(--wax);
    align-items: center;
  }
  .notice.warn b {
    color: var(--wax);
  }
  .notice .btn {
    flex: none;
  }
  .notice :global(svg) {
    margin-top: 2px;
    flex: none;
  }
  .donehead {
    display: flex;
    align-items: center;
    gap: var(--s3);
    margin-bottom: var(--s3);
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
  .dim a {
    color: var(--ink-2);
  }
  .tf {
    display: grid;
    gap: var(--s2);
  }
  .line {
    height: 14px;
  }
  .short {
    width: 60%;
  }
  @media (max-width: 560px) {
    .cands li {
      grid-template-columns: 18px minmax(0, 1fr) auto;
    }
    .vals,
    .ttl {
      display: none;
    }
    .why {
      grid-column: 2 / -1;
    }
  }
</style>
