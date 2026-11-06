<script lang="ts">
  import { api } from '../lib/api';
  import type { AuditEntry, RRset, WhoCanResponse } from '../lib/types';
  import { ApiError } from '../lib/api';
  import LayerTag from './policy/LayerTag.svelte';
  import Matcher from './policy/Matcher.svelte';
  import { statusHelp } from '../lib/labels';
  import { ttl as fmtTTL } from '../lib/format';
  import { journalHref, teamHref } from '../lib/router.svelte';
  import Seal from './Seal.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import Host from './Host.svelte';
  import ActorChip from './ActorChip.svelte';
  import RelTime from './RelTime.svelte';
  import CopyText from './CopyText.svelte';
  import AuditItem from './AuditItem.svelte';
  import Icon from './Icon.svelte';
  import { teamFromText, teamLabel } from '../lib/team';
  import HclBlock from './HclBlock.svelte';
  import PropagationPanel from './PropagationPanel.svelte';
  import { readOnlyLabel, writeAction } from '../lib/rights';
  import { isForward, modeLabel, typeLabel } from '../lib/forwards';
  import type { StagedKind } from '../lib/staging';

  let {
    zone,
    rr,
    onclose,
    unmanaged = false,
    canAdopt = false,
    adoptHint = '',
    onadopt,
    writable = false,
    readOnlyWhy = '',
    stagedKind,
    onedit,
    ondelete,
    ownership,
    ontransfer,
    canCheckPropagation = false,
  }: {
    zone: string;
    rr: RRset;
    onclose: () => void;
    unmanaged?: boolean;
    canAdopt?: boolean;
    adoptHint?: string;
    onadopt?: () => void;
    writable?: boolean;
    readOnlyWhy?: string;
    stagedKind?: StagedKind;
    onedit?: () => void;
    ondelete?: () => void;
    /** Who owns the record set and what it means for the user. */
    ownership?: { mine: boolean; text: string };
    /** Opens a transfer request with this record set. */
    ontransfer?: () => void;
    /** The viewer holds dns.read on the record set: the propagation check is offered. */
    canCheckPropagation?: boolean;
  } = $props();
  const roTag = $derived(readOnlyLabel(rr));
  const isFwd = $derived(isForward(rr));
  const owned = $derived(rr.status !== 'foreign');

  let dialog: HTMLDialogElement;
  let panel: HTMLDivElement;
  let history = $state<AuditEntry[] | null>(null);
  let historyError = $state<string | null>(null);
  let whoCan = $state<WhoCanResponse | null>(null);
  let whoCanHidden = $state(false);

  $effect(() => {
    dialog.showModal();
    panel.focus();
    return () => dialog.close();
  });

  $effect(() => {
    history = null;
    historyError = null;
    api
      .audit({ zone, host: rr.host, type: rr.type, limit: 20 })
      .then((p) => (history = p.entries))
      .catch((e: Error) => (historyError = e.message));
  });

  $effect(() => {
    whoCan = null;
    whoCanHidden = false;
    if (unmanaged) {
      // nobody writes in a zone the gate does not manage
      whoCanHidden = true;
      return;
    }
    api
      .whoCan({ zone, host: rr.host, type: rr.type, action: writeAction(rr.type) })
      .then((w) => (whoCan = w))
      .catch((e: unknown) => {
        // without policy.read the section is simply not shown
        whoCanHidden = e instanceof ApiError && (e.status === 403 || e.status === 404);
        if (!whoCanHidden) whoCan = { protected: false, entries: [] };
      });
  });

  // Terraform snippet of a managed record set (same export as the zone's).
  let hcl = $state<string | null>(null);
  let hclError = $state<string | null>(null);
  $effect(() => {
    hcl = null;
    hclError = null;
    if (!owned || unmanaged || rr.status === 'missing') return;
    api
      .terraform(zone, { team: rr.owner, hosts: [rr.host], types: [rr.type] })
      .then((h) => (hcl = h))
      .catch((e: Error) => (hclError = e.message));
  });

  function backdrop(e: MouseEvent) {
    if (e.target === dialog) onclose();
  }
</script>

<dialog bind:this={dialog} class="drawer" aria-labelledby="rr-title" onclose={onclose} onclick={backdrop}>
  <div class="panel" bind:this={panel} tabindex="-1">
    <header>
      <div class="seal-mark {rr.status}"><Seal status={rr.status} size={28} /></div>
      <div class="title">
        <h2 id="rr-title"><Host host={rr.host} {zone} /></h2>
        <div class="sub">
          <span class="type" class:mono={!isFwd}>{typeLabel(rr.type)}</span>
          <StatusBadge status={rr.status} />
          {#if rr.protected}<span class="flag" title="Protected by the base policy: no role can change it through the gate, even after adoption."><Icon name="lock" size={12} /> Protected</span>{/if}
          {#if rr.adopted}<span class="flag">Adopted</span>{/if}
          {#if roTag}<span class="flag">{roTag}</span>{/if}
          {#if rr.alias}<span class="flag">Alias</span>{/if}
        </div>
      </div>
      <button class="btn quiet icon close" type="button" aria-label="Close" onclick={onclose}><Icon name="x" /></button>
    </header>

    <div class="scroll">
      <p class="help {rr.status}">{statusHelp[rr.status]}</p>

      {#if stagedKind}
        <div class="change staged">
          <p><b>{stagedKind === 'delete' ? 'Staged for deletion.' : 'A change of this record set is staged.'}</b> It is written after you review and apply the zone's changes.</p>
          {#if stagedKind !== 'delete' && onedit}<button class="btn" type="button" onclick={onedit}>Edit the change</button>{/if}
        </div>
      {:else if writable && (onedit || ondelete)}
        <div class="change">
          {#if onedit}<button class="btn primary" type="button" onclick={onedit}>Edit…</button>{/if}
          {#if ondelete}<button class="btn danger" type="button" onclick={ondelete}><Icon name="trash" size={14} />Delete</button>{/if}
          <p class="dim small">Changes are staged first, then reviewed and applied together.</p>
        </div>
      {:else if readOnlyWhy && !unmanaged && (owned || rr.read_only || rr.alias)}
        <p class="ro-why"><Icon name="lock" size={13} /> {ownership && rr.owner && !ownership.mine ? ownership.text : readOnlyWhy}</p>
      {/if}

      {#if !owned && !unmanaged && onadopt && !rr.read_only}
        <div class="adopt">
          {#if rr.protected}
            <p class="dim"><Icon name="lock" size={12} /> Protected by the base policy: it cannot be adopted.</p>
          {:else if canAdopt}
            <button class="btn primary" type="button" onclick={onadopt}><Seal status="managed" size={13} />Adopt this record set…</button>
            <p class="dim small">Opens the adoption with this record set selected: you choose the owner team and review it before anything changes.</p>
          {:else}
            <p class="dim">{adoptHint}</p>
          {/if}
        </div>
      {/if}

      {#if rr.forward}
        <section>
          <h3 class="eyebrow">Redirect</h3>
          <dl class="fwd">
            <dt>Kind</dt><dd>{modeLabel(rr.forward.type)}</dd>
            <dt>Target URL</dt><dd><CopyText text={rr.forward.url} label="target URL" /></dd>
            {#if rr.forward.title}<dt>Title</dt><dd>{rr.forward.title}</dd>{/if}
            {#if rr.forward.keywords}<dt>Keywords</dt><dd>{rr.forward.keywords}</dd>{/if}
            {#if rr.forward.description}<dt>Description</dt><dd>{rr.forward.description}</dd>{/if}
          </dl>
          <p class="dim small">Answered by the DNS provider for <span class="mono">http://{rr.host === '@' ? zone : `${rr.host}.${zone}`}/</span>; HTTPS needs a redirect subscription on the domain.</p>
        </section>
      {:else if rr.alias}
        <section>
          <h3 class="eyebrow">Alias target</h3>
          <ul class="values">
            <li><CopyText text={rr.alias.target} label="alias target" /></li>
          </ul>
          <p class="dim small">Hosted zone <span class="mono">{rr.alias.hosted_zone_id}</span> · target health {rr.alias.evaluate_target_health ? 'evaluated' : 'not evaluated'}</p>
        </section>
      {:else}
        <section>
          <h3 class="eyebrow">Values</h3>
          <ul class="values">
            {#each rr.values as v (v)}<li><CopyText text={v} label="value" /></li>{/each}
          </ul>
        </section>
      {/if}

      {#if ownership && !unmanaged && (rr.owner || ownership.text.includes('reserved'))}
        <div class="ownnote" class:mine={ownership.mine}>
          <p><Icon name="team" size={13} /> {ownership.text}</p>
          {#if ontransfer}<button class="btn quiet small" type="button" onclick={ontransfer}><Icon name="transfer" size={13} />Request a transfer…</button>{/if}
        </div>
      {/if}

      <section class="facts">
        {#if !isFwd}<div><span class="eyebrow">TTL</span><span class="mono num">{fmtTTL(rr.ttl)} <span class="dim">({rr.ttl}s)</span></span></div>{/if}
        <div>
          <span class="eyebrow">Owner team</span>
          {#if rr.owner}<a class="team" href={teamHref(rr.owner)}>{rr.owner}</a>{#if ownership?.mine}<span class="dim small">your team</span>{/if}
          {:else}<span class="dim">— (not managed by the gate)</span>{/if}
        </div>
        {#if rr.expires_at}
          <div><span class="eyebrow">Expires</span><span class="expire"><Icon name="clock" size={14} /> <RelTime iso={rr.expires_at} /></span></div>
        {/if}
        {#if rr.last_request_id}
          <div><span class="eyebrow">Last request</span><CopyText text={rr.last_request_id} label="request id" /></div>
        {/if}
      </section>

      {#if !unmanaged && !isFwd && canCheckPropagation}
        <section>
          <h3 class="eyebrow">Propagation</h3>
          <PropagationPanel {zone} host={rr.host} type={rr.type} />
        </section>
      {/if}

      {#if rr.created_by || rr.updated_by}
        <section>
          <h3 class="eyebrow">Who changed it</h3>
          <ol class="chain">
            {#if rr.created_by}
              <li>
                <span class="step">{rr.adopted ? 'Adopted by' : 'Created by'}</span>
                <ActorChip actor={rr.created_by} />
                <RelTime iso={rr.created_at} />
                <span class="subject"><CopyText text={rr.created_by.subject} label="subject" /></span>
              </li>
            {/if}
            {#if rr.updated_by}
              <li>
                <span class="step">Last changed by</span>
                <ActorChip actor={rr.updated_by} />
                <RelTime iso={rr.updated_at} />
                <span class="subject"><CopyText text={rr.updated_by.subject} label="subject" /></span>
              </li>
            {/if}
            {#if rr.status === 'tainted' || rr.status === 'missing'}
              <li class="broken">
                <span class="step">Then</span>
                <span>changed outside the gate</span>
              </li>
            {/if}
          </ol>
        </section>
      {/if}

      {#if !whoCanHidden}
        <section>
          <h3 class="eyebrow">Who can change this {isFwd ? 'forward' : 'record'}</h3>
          {#if !whoCan}
            <div class="skeleton line"></div>
          {:else if whoCan.protected}
            <p class="who-prot"><Icon name="lock" size={14} /> Protected by the base policy: no role can change it through the gate.</p>
          {:else if whoCan.entries.length === 0}
            <p class="dim">No binding grants write on this record set.</p>
          {:else}
            <ul class="whocan">
              {#each whoCan.entries as w, i (i)}
                <li>
                  <div class="wc-head">
                    <span class="mono wc-role">{w.role}</span><span class="dim">@</span><span class="wc-team" title={w.team_from ? teamFromText(w.team_from) : undefined}>{teamLabel(w.team, w.team_from)}</span>
                    <LayerTag layer={w.layer} />
                  </div>
                  <div class="wc-who">
                    {#each w.groups ?? [] as g (g)}<span class="wc-grp mono">{g}</span>{/each}
                    {#each w.subjects ?? [] as m, k (k)}<Matcher {m} />{/each}
                    {#each w.virtual_keys ?? [] as kid (kid)}<span class="wc-key mono"><Icon name="key" size={12} />{kid}</span>{/each}
                  </div>
                </li>
              {/each}
            </ul>
            {#if rr.owner}<p class="dim small">Ownership still applies: only team <b>{rr.owner}</b> can modify it once created.</p>{/if}
          {/if}
        </section>
      {/if}

      {#if owned && !unmanaged && rr.status !== 'missing'}
        <section>
          <h3 class="eyebrow">Terraform</h3>
          {#if hclError}
            <p class="dim">{hclError}</p>
          {:else if hcl}
            <HclBlock {hcl} filename="{rr.host === '@' ? 'apex' : rr.host}_{rr.type.toLowerCase()}.tf" />
          {:else}
            <div class="skeleton line"></div>
          {/if}
        </section>
      {/if}

      <section>
        <div class="hist-head">
          <h3 class="eyebrow">History</h3>
          <a href={journalHref({ zone })} class="more">Zone journal <Icon name="arrow" size={12} /></a>
        </div>
        {#if historyError}
          <p class="dim">{historyError}</p>
        {:else if !history}
          <div class="skeleton line"></div>
          <div class="skeleton line short"></div>
        {:else if history.length === 0}
          <p class="dim">No gate activity on this record set.</p>
        {:else}
          <div class="history">
            {#each history as e (e.request_id)}<AuditItem entry={e} compact />{/each}
          </div>
        {/if}
      </section>
    </div>
  </div>
</dialog>

<style>
  .change {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
  }
  .change p {
    flex: 1 1 100%;
  }
  .change.staged {
    padding: var(--s3);
    border-radius: var(--r-md);
    background: var(--brass-wash);
    color: var(--ink-2);
  }
  .change .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .btn.danger {
    color: var(--wax);
  }
  .btn.danger:hover {
    border-color: color-mix(in srgb, var(--wax) 40%, transparent);
  }
  .ro-why {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
    color: var(--ink-2);
  }
  .ro-why :global(svg) {
    flex: none;
    margin-top: 3px;
  }
  .drawer {
    margin: 0 0 0 auto;
    padding: 0;
    border: 0;
    width: min(520px, 100vw);
    max-width: 100vw;
    height: 100dvh;
    max-height: 100dvh;
    background: transparent;
    color: var(--ink);
  }
  .drawer::backdrop {
    background: var(--scrim);
    animation: fade 200ms var(--ease-out);
  }
  .panel {
    outline: none;
    height: 100%;
    display: grid;
    grid-template-rows: auto minmax(0, 1fr);
    background: var(--sheet-raised);
    border-left: 1px solid var(--rule);
    animation: slide 260ms var(--ease-out);
  }
  @keyframes slide {
    from {
      transform: translateX(24px);
      opacity: 0;
    }
  }
  @keyframes fade {
    from {
      opacity: 0;
    }
  }
  header {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    gap: var(--s3);
    align-items: start;
    padding: var(--s5) var(--s5) var(--s4);
    border-bottom: 1px solid var(--rule-soft);
  }
  .seal-mark {
    display: grid;
    place-items: center;
    width: 44px;
    height: 44px;
    border-radius: 50%;
    background: var(--seal-ink-wash);
  }
  .seal-mark.tainted,
  .seal-mark.missing {
    background: var(--wax-wash);
  }
  .seal-mark.pending {
    background: var(--brass-wash);
  }
  .seal-mark.foreign {
    background: transparent;
    box-shadow: inset 0 0 0 1px var(--rule);
  }
  .title {
    display: grid;
    gap: var(--s2);
    min-width: 0;
  }
  h2 {
    font-size: var(--t-lead);
    display: flex;
    min-width: 0;
  }
  h2 :global(.mono) {
    font-size: 15px;
  }
  .sub {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
  }
  .type {
    font-size: 12px;
    font-weight: 600;
    color: var(--ink-2);
    padding: 1px 6px;
    border-radius: var(--r-sm);
    background: var(--rule-soft);
  }
  .flag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
    color: var(--ink-3);
  }
  .scroll {
    overflow-y: auto;
    padding: var(--s4) var(--s5) var(--s8);
    display: grid;
    align-content: start;
    gap: var(--s6);
  }
  .help {
    color: var(--ink-2);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .help.tainted,
  .help.missing {
    background: var(--wax-wash);
    color: var(--wax);
  }
  section {
    display: grid;
    gap: var(--s2);
  }
  h3 {
    font-weight: 500;
  }
  .values {
    list-style: none;
    margin: 0;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
    display: grid;
    gap: var(--s1);
  }
  .values :global(.copy) {
    color: var(--ink);
    font-size: 13px;
    word-break: break-all;
    text-align: left;
  }
  .fwd {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: var(--s1) var(--s3);
    margin: 0;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .fwd dt {
    color: var(--ink-3);
    font-size: 12px;
    line-height: 20px;
  }
  .fwd dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
    color: var(--ink);
  }
  .fwd :global(.copy) {
    font-size: 13px;
    word-break: break-all;
    text-align: left;
  }
  .facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--s4);
  }
  .facts div {
    display: grid;
    gap: 2px;
    align-content: start;
  }
  .dim {
    color: var(--ink-3);
  }
  .team {
    font-weight: 600;
    color: var(--ink);
    text-decoration: none;
  }
  a.team:hover {
    color: var(--seal-ink);
  }
  .ownnote {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--s2) var(--s3);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
    color: var(--ink-2);
    font-size: 13px;
  }
  .ownnote.mine {
    background: var(--seal-ink-wash);
  }
  .ownnote p {
    display: flex;
    align-items: baseline;
    gap: 6px;
    margin: 0;
  }
  .ownnote :global(svg) {
    flex: none;
    transform: translateY(2px);
  }
  .ownnote .btn {
    height: 26px;
    padding: 0 var(--s2);
    font-size: 12px;
  }
  .expire {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--brass);
  }
  .chain {
    list-style: none;
    margin: 0;
    padding: 0 0 0 var(--s4);
    display: grid;
    gap: var(--s3);
    border-left: 2px solid var(--seal-ink-wash);
  }
  .chain li {
    position: relative;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s1) var(--s2);
    color: var(--ink-3);
  }
  .chain li::before {
    content: '';
    position: absolute;
    left: calc(var(--s4) * -1 - 6px);
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--sheet-raised);
    box-shadow: 0 0 0 2px var(--seal-ink);
  }
  .chain li.broken {
    color: var(--wax);
  }
  .chain li.broken::before {
    box-shadow: 0 0 0 2px var(--wax);
    background: var(--wax);
  }
  .step {
    width: 104px;
    flex: none;
    font-size: 12px;
  }
  .hist-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
  }
  .more {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--ink-3);
    font-size: 12px;
    text-decoration: none;
  }
  .more:hover {
    color: var(--seal-ink);
  }
  .history {
    padding-top: var(--s2);
  }
  .line {
    height: 14px;
  }
  .short {
    width: 60%;
  }
  .close {
    margin: -4px -8px 0 0;
  }
  .who-prot {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--ink-2);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .whocan {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  .whocan li {
    display: grid;
    gap: 4px;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    border: 1px solid var(--rule-soft);
  }
  .wc-head {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .wc-head :global(.tag) {
    margin-left: auto;
  }
  .wc-role {
    font-weight: 600;
    font-size: 13px;
  }
  .wc-team {
    font-weight: 600;
    color: var(--seal-ink);
  }
  .wc-who {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 8px;
    align-items: baseline;
  }
  .wc-grp {
    font-size: 12px;
    padding: 0 6px;
    border-radius: 6px;
    box-shadow: inset 0 0 0 1px var(--rule-strong);
  }
  .wc-key {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    font-size: 12px;
    color: var(--brass);
  }
  .small {
    font-size: 12px;
  }
  .adopt {
    display: grid;
    gap: var(--s2);
    justify-items: start;
  }
  .adopt .dim {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .subject {
    flex: 1 1 100%;
    padding-left: 112px;
    min-width: 0;
  }
  .subject :global(.copy) {
    max-width: 100%;
    text-align: left;
    word-break: break-all;
  }
  @media (max-width: 560px) {
    .subject {
      padding-left: 0;
    }
  }
  @media (max-width: 560px) {
    .facts {
      grid-template-columns: 1fr;
    }
  }
</style>
