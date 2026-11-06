<script lang="ts">
  import { untrack } from 'svelte';
  import type { Me, RRset, Tombstone } from '../lib/types';
  import { reservation, reservationText } from '../lib/teams';
  import {
    TTL_PRESETS,
    checkDraft,
    displayName,
    draftFromRRset,
    draftValues,
    emptyValue,
    isRecordType,
    newDraft,
    normalizeHost,
    parseValue,
    typeSpecs,
    type RecordDraft,
    type RecordType,
  } from '../lib/records';
  import type { Neighbour } from '../lib/records';
  import type { StagedChange } from '../lib/staging';
  import { writableHosts, writableTypes } from '../lib/rights';
  import { hostMatch } from '../lib/glob';
  import { ttl as fmtTTL } from '../lib/format';
  import SidePanel from './SidePanel.svelte';
  import Icon from './Icon.svelte';

  let {
    zone,
    me,
    existing,
    editing,
    staged,
    tombstones = [],
    onstage,
    onclose,
  }: {
    zone: string;
    me: Me | null;
    /** Every record set of the zone after the staged changes. */
    existing: Neighbour[];
    /** The record set being edited; absent to add one. */
    editing?: RRset;
    /** What is already staged for it (edits of a staged change start from there). */
    staged?: StagedChange;
    /** Record sets deleted recently, reserved for their team. */
    tombstones?: Tombstone[];
    onstage: (c: StagedChange) => void;
    onclose: () => void;
  } = $props();

  const seed = untrack(() => ({ editing, staged }));
  const isEdit = !!seed.editing || seed.staged?.kind === 'create';
  const types = $derived(isEdit ? [] : (writableTypes(me, zone) as RecordType[]));

  function initial(): RecordDraft {
    const s = seed.staged;
    if (s && s.kind !== 'delete' && isRecordType(s.type)) {
      const t = s.type;
      return { host: s.host, type: t, ttl: s.ttl ?? 3600, values: (s.values ?? []).map((v) => parseValue(t, v)) };
    }
    if (seed.editing) return draftFromRRset(seed.editing);
    const first = writableTypes(me, zone)[0];
    return newDraft(first && isRecordType(first) ? first : 'A');
  }

  let draft = $state<RecordDraft>(initial());
  let tried = $state(false);
  let customTTL = $state(!TTL_PRESETS.some((p) => p.seconds === untrack(() => draft.ttl)));

  const editKey = $derived(isEdit ? { host: draft.host, type: draft.type } : undefined);
  const check = $derived(checkDraft(draft, zone, existing, editKey));
  const host = $derived(normalizeHost(draft.host, zone));
  const spec = $derived(typeSpecs[draft.type]);
  const values = $derived(draftValues(draft));

  // Names the user's roles allow for this type: a warning, the gate decides.
  const allowedHosts = $derived(writableHosts(me, zone, draft.type));
  // A name deleted recently stays reserved for its team: a warning, the gate decides.
  const reserved = $derived(isEdit || !draft.host.trim() ? undefined : reservation(tombstones, host, draft.type));
  const reservedOther = $derived(!!reserved && !me?.teams.includes(reserved.team));

  const outOfScope = $derived(!!draft.host.trim() && !check.host && allowedHosts.length > 0 && !allowedHosts.some((h) => hostMatch(h, host)));

  function setType(t: RecordType) {
    if (t === draft.type) return;
    draft.type = t;
    draft.values = [emptyValue(t)];
  }

  const addValue = () => draft.values.push(emptyValue(draft.type));
  const removeValue = (i: number) => draft.values.splice(i, 1);

  function onTTL(v: string) {
    if (v === 'custom') {
      customTTL = true;
      return;
    }
    customTTL = false;
    draft.ttl = Number(v);
  }

  function submit(e: SubmitEvent) {
    e.preventDefault();
    tried = true;
    if (!check.ok) return;
    const kind = seed.staged?.kind === 'create' || !seed.editing ? 'create' : 'update';
    onstage({ kind, host, type: draft.type, ttl: draft.ttl, values, before: seed.editing });
  }

  const err = (i: number, k: string) => (tried ? check.values[i]?.[k] : undefined);
  const title = isEdit ? 'Edit record set' : 'Add a record';
</script>

<SidePanel {title} {onclose} width={600}>
  {#snippet head()}
    <p class="eyebrow">{title}</p>
    <h2 class="mono">{isEdit ? displayName(draft.host, zone) : zone}</h2>
  {/snippet}

  <form class="form" onsubmit={submit} novalidate>
    {#if !isEdit}
      <div class="row">
        <label class="lbl" for="rf-host">Name</label>
        <div class="hostline">
          <span class="field host"><input id="rf-host" class="mono" bind:value={draft.host} placeholder="www" autocomplete="off" spellcheck="false" aria-invalid={tried && !!check.host} /></span>
          <span class="suffix mono">.{zone}</span>
        </div>
        <p class="hint">The part before the zone, for example <span class="mono">www</span> or <span class="mono">api.staging</span>. Type <span class="mono">@</span> for <span class="mono">{zone}</span> itself.</p>
        {#if tried && check.host}<p class="err">{check.host}</p>{/if}
        {#if reserved}<p class="warn" class:block={reservedOther}><Icon name={reservedOther ? 'lock' : 'team'} size={12} /> {reservationText(me, reserved)}{reservedOther ? ' The gate will refuse it.' : ''}</p>{/if}
        {#if outOfScope}<p class="warn"><Icon name="alert" size={12} /> Your roles allow {draft.type} records only at names matching <span class="mono">{allowedHosts.join(', ')}</span>: the gate will refuse this one.</p>{/if}
      </div>

      <div class="row">
        <span class="lbl" id="rf-type">Type</span>
        {#if types.length === 0}
          <p class="err">Your roles do not allow adding records in this zone.</p>
        {:else}
          <div class="types" role="radiogroup" aria-labelledby="rf-type">
            {#each types as t (t)}
              <button type="button" role="radio" aria-checked={draft.type === t} onclick={() => setType(t)}>
                <span class="mono t">{t}</span><span class="tt">{typeSpecs[t].title}</span>
              </button>
            {/each}
          </div>
        {/if}
      </div>
    {:else}
      <p class="fixed"><span class="type mono">{draft.type}</span><span class="dim">{spec.title}</span></p>
    {/if}

    <p class="help">{spec.help}</p>

    <fieldset class="row">
      <legend class="lbl">{spec.single ? 'Value' : 'Values'}</legend>
      <ol class="values">
        {#each draft.values as v, i (i)}
          <li>
            <div class="vfields" style:--cols={spec.fields.map((f) => (f.narrow ? '84px' : 'minmax(0, 1fr)')).join(' ')}>
              {#each spec.fields as f (f.key)}
                <label class="vf">
                  <span class="vl">{f.label}</span>
                  {#if f.options}
                    <span class="field"><select bind:value={v[f.key]}>{#each f.options as o (o)}<option value={o}>{o}</option>{/each}</select><span class="chev"><Icon name="chevron" size={12} /></span></span>
                  {:else}
                    <span class="field"><input class="mono" bind:value={v[f.key]} placeholder={f.placeholder} autocomplete="off" spellcheck="false" inputmode={f.narrow ? 'numeric' : undefined} aria-invalid={!!err(i, f.key)} /></span>
                  {/if}
                  {#if err(i, f.key)}<span class="err">{err(i, f.key)}</span>{/if}
                </label>
              {/each}
              {#if draft.values.length > 1}
                <button class="btn quiet icon rm" type="button" aria-label="Remove this {spec.noun}" title="Remove" onclick={() => removeValue(i)}><Icon name="x" size={14} /></button>
              {/if}
            </div>
            {#if err(i, '_')}<span class="err">{err(i, '_')}</span>{/if}
          </li>
        {/each}
      </ol>
      {#if !spec.single}
        <button class="btn quiet add" type="button" onclick={addValue}><Icon name="plus" size={14} />Add another {spec.noun}</button>
      {/if}
    </fieldset>

    <div class="row">
      <label class="lbl" for="rf-ttl">TTL <span class="dim">(how long resolvers keep the answer)</span></label>
      <div class="ttlline">
        <span class="field">
          <select id="rf-ttl" value={customTTL ? 'custom' : String(draft.ttl)} onchange={(e) => onTTL(e.currentTarget.value)}>
            {#each TTL_PRESETS as p (p.seconds)}<option value={String(p.seconds)}>{p.label}</option>{/each}
            <option value="custom">Other…</option>
          </select>
          <span class="chev"><Icon name="chevron" size={12} /></span>
        </span>
        {#if customTTL}
          <span class="field secs"><input type="number" min="1" max="604800" bind:value={draft.ttl} aria-label="TTL in seconds" /></span><span class="dim">seconds ({fmtTTL(draft.ttl || 0)})</span>
        {/if}
      </div>
      {#if tried && check.ttl}<p class="err">{check.ttl}</p>{/if}
    </div>

    {#if tried && check.form.length}
      <div class="problems" role="alert">
        {#each check.form as f (f)}<p><Icon name="alert" size={13} /> {f}</p>{/each}
      </div>
    {/if}

    {#if values.some((v) => v.trim())}
      <section class="result">
        <span class="eyebrow">Will be written as</span>
        <pre class="mono">{values.map((v) => `${displayName(host, zone)}.  ${draft.ttl}  ${draft.type}  ${v}`).join('\n')}</pre>
      </section>
    {/if}

    <div class="actions">
      <button class="btn primary" type="submit" disabled={!isEdit && types.length === 0}><Icon name="check" size={14} />{isEdit ? 'Keep this change' : 'Add to the changes'}</button>
      <button class="btn quiet" type="button" onclick={onclose}>Cancel</button>
    </div>
    <p class="dim small">Nothing is written yet: changes are reviewed together, then applied.</p>
  </form>
</SidePanel>

<style>
  h2 {
    font-size: var(--t-h3);
    overflow-wrap: anywhere;
  }
  .form {
    display: grid;
    gap: var(--s4);
  }
  .row {
    display: grid;
    gap: 6px;
    min-width: 0;
    margin: 0;
    padding: 0;
    border: 0;
  }
  .lbl {
    font-size: 12px;
    font-weight: 500;
    color: var(--ink-2);
    padding: 0;
  }
  .dim {
    color: var(--ink-3);
    font-weight: 400;
  }
  .small {
    font-size: 12px;
  }
  .hint,
  .help {
    color: var(--ink-3);
    font-size: 12px;
  }
  .help {
    margin-top: -6px;
    font-size: 13px;
    color: var(--ink-2);
  }
  .hostline {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
  }
  .field {
    min-width: 0;
  }
  .field input {
    width: 100%;
  }
  .host {
    flex: 0 1 220px;
  }
  .suffix {
    color: var(--ink-3);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .types {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 6px;
  }
  .types button {
    display: grid;
    gap: 1px;
    justify-items: start;
    padding: 7px 10px;
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    background: var(--sheet);
    cursor: pointer;
    text-align: left;
  }
  .types button:hover {
    border-color: var(--rule-strong);
  }
  .types button[aria-checked='true'] {
    border-color: color-mix(in srgb, var(--seal-ink) 45%, transparent);
    background: var(--seal-ink-wash);
    box-shadow: 0 0 0 1px color-mix(in srgb, var(--seal-ink) 45%, transparent);
  }
  .t {
    font-weight: 600;
    font-size: 12px;
  }
  .tt {
    font-size: 12px;
    color: var(--ink-3);
  }
  .fixed {
    display: flex;
    align-items: baseline;
    gap: var(--s2);
  }
  .type {
    font-weight: 600;
    font-size: 12px;
    color: var(--ink-2);
  }
  .values {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  .values li {
    display: grid;
    gap: 4px;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .values .field {
    background: var(--sheet-raised);
  }
  .vfields {
    display: grid;
    grid-template-columns: var(--cols) auto;
    align-items: start;
    gap: var(--s2);
  }
  .vf {
    display: grid;
    gap: 3px;
    min-width: 0;
  }
  .vl {
    font-size: 11px;
    color: var(--ink-3);
  }
  .rm {
    align-self: end;
    width: 28px;
    height: 32px;
  }
  .add {
    justify-self: start;
    color: var(--seal-ink);
  }
  .ttlline {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
  }
  .secs {
    width: 110px;
  }
  .err {
    color: var(--wax);
    font-size: 12px;
  }
  .warn {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--brass);
    font-size: 12px;
  }
  .warn.block {
    color: var(--wax);
  }
  .problems {
    display: grid;
    gap: 4px;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--wax-wash);
    color: var(--wax);
  }
  .problems p {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .result {
    display: grid;
    gap: 4px;
  }
  .result pre {
    margin: 0;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
    color: var(--ink-2);
    font-size: 12px;
    overflow-x: auto;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s2);
    padding-top: var(--s3);
    border-top: 1px solid var(--rule);
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  @media (max-width: 560px) {
    .vfields {
      grid-template-columns: 1fr auto;
    }
    .vf {
      grid-column: 1;
    }
    .rm {
      grid-column: 2;
      grid-row: 1;
    }
  }
</style>
