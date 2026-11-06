<script lang="ts">
  import { untrack } from 'svelte';
  import type { HTTPSRedirect, Me, RRset, Tombstone } from '../lib/types';
  import { reservation, reservationText } from '../lib/teams';
  import { displayName, normalizeHost } from '../lib/records';
  import {
    FORWARD_MODES,
    URLFWD,
    checkForward,
    draftFromForward,
    forwardOf,
    forwardPreview,
    httpsNote,
    httpsServes,
    modeSpecs,
    newForwardDraft,
    type ForwardDraft,
    type KnownMode,
  } from '../lib/forwards';
  import type { StagedChange } from '../lib/staging';
  import { writableHosts } from '../lib/rights';
  import { hostMatch } from '../lib/glob';
  import SidePanel from './SidePanel.svelte';
  import Icon from './Icon.svelte';

  let {
    zone,
    me,
    existing,
    editing,
    staged,
    tombstones = [],
    https,
    onstage,
    onclose,
  }: {
    zone: string;
    me: Me | null;
    /** Every forward of the zone after the staged changes. */
    existing: { host: string; type: string }[];
    /** The forward being edited; absent to add one. */
    editing?: RRset;
    /** What is already staged for it (edits of a staged change start from there). */
    staged?: StagedChange;
    /** Record sets deleted recently, reserved for their team. */
    tombstones?: Tombstone[];
    /** Whether the forwards of the zone answer HTTPS, when known. */
    https?: HTTPSRedirect;
    onstage: (c: StagedChange) => void;
    onclose: () => void;
  } = $props();

  const seed = untrack(() => ({ editing, staged }));
  const isEdit = !!seed.editing || seed.staged?.kind === 'create';

  function initial(): ForwardDraft {
    const s = seed.staged;
    if (s && s.kind !== 'delete') return draftFromForward(s.host, s.forward, !!s.requireHttps);
    if (seed.editing) return draftFromForward(seed.editing.host, seed.editing.forward);
    return newForwardDraft();
  }

  let draft = $state<ForwardDraft>(initial());
  let tried = $state(false);

  const host = $derived(normalizeHost(draft.host, zone));
  const check = $derived(checkForward(draft, zone, existing, isEdit ? host : undefined));
  const forward = $derived(forwardOf(draft));

  const allowedHosts = $derived(writableHosts(me, zone, URLFWD));
  const outOfScope = $derived(!!draft.host.trim() && !check.host && allowedHosts.length > 0 && !allowedHosts.some((h) => hostMatch(h, host)));
  const reserved = $derived(isEdit || !draft.host.trim() ? undefined : reservation(tombstones, host, URLFWD));
  const reservedOther = $derived(!!reserved && !me?.teams.includes(reserved.team));

  const note = $derived(httpsNote(https));
  const serves = $derived(httpsServes(https?.status));

  function setMode(m: KnownMode) {
    draft.mode = m;
  }

  function submit(e: SubmitEvent) {
    e.preventDefault();
    tried = true;
    if (!check.ok) return;
    const kind = seed.staged?.kind === 'create' || !seed.editing ? 'create' : 'update';
    onstage({ kind, host, type: URLFWD, forward, requireHttps: draft.requireHttps || undefined, before: seed.editing });
  }

  const title = isEdit ? 'Edit URL forward' : 'Add a URL forward';
</script>

<SidePanel {title} {onclose} width={600}>
  {#snippet head()}
    <p class="eyebrow">{title}</p>
    <h2 class="mono">{isEdit ? displayName(host, zone) : zone}</h2>
  {/snippet}

  <form class="form" onsubmit={submit} novalidate>
    {#if !isEdit}
      <div class="row">
        <label class="lbl" for="ff-host">Name</label>
        <div class="hostline">
          <span class="field host"><input id="ff-host" class="mono" bind:value={draft.host} placeholder="www" autocomplete="off" spellcheck="false" aria-invalid={tried && !!check.host} /></span>
          <span class="suffix mono">.{zone}</span>
        </div>
        <p class="hint">Visitors of this name are sent to the URL. Type <span class="mono">@</span> for <span class="mono">{zone}</span> itself.</p>
        {#if tried && check.host}<p class="err">{check.host}</p>{/if}
        {#if reserved}<p class="warn" class:block={reservedOther}><Icon name={reservedOther ? 'lock' : 'team'} size={12} /> {reservationText(me, reserved)}{reservedOther ? ' The gate will refuse it.' : ''}</p>{/if}
        {#if outOfScope}<p class="warn"><Icon name="alert" size={12} /> Your roles allow forwards only at names matching <span class="mono">{allowedHosts.join(', ')}</span>: the gate will refuse this one.</p>{/if}
      </div>
    {/if}

    <div class="row">
      <span class="lbl" id="ff-mode">Kind</span>
      <div class="modes" role="radiogroup" aria-labelledby="ff-mode">
        {#each FORWARD_MODES as m (m)}
          <button type="button" role="radio" aria-checked={draft.mode === m} onclick={() => setMode(m)}>
            <span class="t">{modeSpecs[m].title}</span><span class="tt mono">{m === 'frame' ? 'frame' : `HTTP ${m}`}</span>
          </button>
        {/each}
      </div>
      <p class="help">{modeSpecs[draft.mode].help}</p>
    </div>

    <div class="row">
      <label class="lbl" for="ff-url">Target URL</label>
      <span class="field wide"><input id="ff-url" class="mono" type="url" bind:value={draft.url} placeholder="https://www.example.com/" autocomplete="off" spellcheck="false" aria-invalid={tried && !!check.url} /></span>
      {#if tried && check.url}<p class="err">{check.url}</p>{/if}
    </div>

    {#if draft.mode === 'frame'}
      <fieldset class="row frame">
        <legend class="lbl">Framing page <span class="dim">(optional)</span></legend>
        <label class="vf"><span class="vl">Title</span><span class="field wide"><input bind:value={draft.title} placeholder="Example shop" autocomplete="off" /></span></label>
        <label class="vf"><span class="vl">Keywords</span><span class="field wide"><input bind:value={draft.keywords} placeholder="shop, gifts" autocomplete="off" /></span></label>
        <label class="vf"><span class="vl">Description</span><span class="field wide"><input bind:value={draft.description} placeholder="Gifts delivered in 48 hours" autocomplete="off" /></span></label>
      </fieldset>
    {/if}

    <div class="row">
      <label class="check"><input type="checkbox" bind:checked={draft.requireHttps} /> Require HTTPS</label>
      <p class="hint">The gate refuses the change unless the forwards of this zone answer HTTPS too. It is checked when the change is applied, not stored. The target URL may start with https:// either way.</p>
      {#if note}<p class="https {note.tone}"><Icon name={note.tone === 'ok' ? 'check' : 'alert'} size={12} /> {note.text}</p>{/if}
      {#if draft.requireHttps && serves === false}<p class="warn block"><Icon name="lock" size={12} /> The gate will refuse it: forwards of this zone answer plain HTTP only.</p>{/if}
    </div>

    {#if tried && check.form.length}
      <div class="problems" role="alert">
        {#each check.form as f (f)}<p><Icon name="alert" size={13} /> {f}</p>{/each}
      </div>
    {/if}

    {#if forward.url && !check.url && !check.host && draft.host.trim()}
      <section class="result">
        <span class="eyebrow">Will be written as</span>
        <pre class="mono">{forwardPreview(host, zone, forward)}{#if forward.title}{'\n'}title: {forward.title}{/if}{#if forward.keywords}{'\n'}keywords: {forward.keywords}{/if}{#if forward.description}{'\n'}description: {forward.description}{/if}</pre>
      </section>
    {/if}

    <div class="actions">
      <button class="btn primary" type="submit"><Icon name="check" size={14} />{isEdit ? 'Keep this change' : 'Add to the changes'}</button>
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
  .hint {
    color: var(--ink-3);
    font-size: 12px;
  }
  .help {
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
  .wide {
    display: flex;
    width: 100%;
  }
  .suffix {
    color: var(--ink-3);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .modes {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 6px;
  }
  .modes button {
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
  .modes button:hover {
    border-color: var(--rule-strong);
  }
  .modes button[aria-checked='true'] {
    border-color: color-mix(in srgb, var(--seal-ink) 45%, transparent);
    background: var(--seal-ink-wash);
    box-shadow: 0 0 0 1px color-mix(in srgb, var(--seal-ink) 45%, transparent);
  }
  .t {
    font-weight: 600;
    font-size: 12px;
  }
  .tt {
    font-size: 11px;
    color: var(--ink-3);
  }
  .frame {
    padding: var(--s2) var(--s3) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .frame .field {
    background: var(--sheet-raised);
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
  .check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    justify-self: start;
    color: var(--ink-2);
    font-weight: 500;
    cursor: pointer;
  }
  .check input {
    accent-color: var(--seal-ink);
  }
  .https {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--ink-3);
  }
  .https.ok {
    color: var(--stamp);
  }
  .https.warn {
    color: var(--brass);
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
</style>
