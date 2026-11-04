<script lang="ts">
  import type { AuditEntry } from '../lib/types';
  import { actionLabel, decisionLabel, reasonLabel } from '../lib/labels';
  import { clockTime } from '../lib/format';
  import { mergeTypeChanges } from '../lib/journal';
  import { zoneHref } from '../lib/router.svelte';
  import ActorChip from './ActorChip.svelte';
  import ChangeDiff from './ChangeDiff.svelte';
  import CopyText from './CopyText.svelte';
  import RelTime from './RelTime.svelte';

  let { entry, compact = false }: { entry: AuditEntry; compact?: boolean } = $props();
  const applied = $derived(entry.decision === 'allow');
  const changes = $derived(mergeTypeChanges(entry.changes ?? []));
</script>

<article class="item {entry.decision}" class:compact>
  <div class="when">
    {#if compact}<RelTime iso={entry.time} />{:else}<time class="num mono" datetime={entry.time}>{clockTime(entry.time)}</time>{/if}
  </div>
  <div class="rail" aria-hidden="true"><span class="node"></span></div>
  <div class="body">
    <header>
      <ActorChip actor={entry.actor} />
      <span class="what">
        {actionLabel(entry.action)}
        {#if entry.zone && !compact}
          <span class="on">on</span> <a class="zone mono" href={zoneHref(entry.zone)}>{entry.zone}</a>
        {/if}
      </span>
      <span class="decision {entry.decision}">{decisionLabel[entry.decision]}</span>
    </header>

    {#if entry.reason}
      <p class="reason"><span class="code mono">{entry.reason}</span> {reasonLabel(entry.reason)}</p>
    {/if}

    {#if changes.length}
      <div class="changes">
        {#each changes as c, i (i)}
          <ChangeDiff change={c} zone={entry.zone} {applied} link={!compact} />
        {/each}
      </div>
    {/if}

    <footer>
      {#if entry.teams?.length && !compact}<span class="teams">as {entry.teams.join(', ')}</span>{/if}
      <details class="ids">
        <summary>Details</summary>
        <dl>
          <dt>Identity</dt><dd><CopyText text={entry.actor.subject} label="subject" /></dd>
          <dt>Request</dt><dd><CopyText text={entry.request_id} label="request id" /></dd>
          {#if entry.snapshot_id}<dt>Snapshot before</dt><dd><CopyText text={String(entry.snapshot_id)} label="EuroDNS snapshot id" /></dd>{/if}
          {#if entry.action !== actionLabel(entry.action)}<dt>Action</dt><dd class="mono">{entry.action}</dd>{/if}
        </dl>
      </details>
    </footer>
  </div>
</article>

<style>
  .item {
    display: grid;
    grid-template-columns: 56px 20px minmax(0, 1fr);
    column-gap: var(--s2);
  }
  .item.compact {
    grid-template-columns: 76px 16px minmax(0, 1fr);
  }
  .when {
    padding-top: 3px;
    text-align: right;
    color: var(--ink-3);
    font-size: 12px;
  }
  .rail {
    position: relative;
    display: flex;
    justify-content: center;
  }
  .rail::before {
    content: '';
    position: absolute;
    top: 0;
    bottom: 0;
    width: 1px;
    background: var(--rule);
  }
  .node {
    position: relative;
    margin-top: 6px;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--paper);
    box-shadow: 0 0 0 2px var(--stamp);
  }
  .deny .node {
    box-shadow: 0 0 0 2px var(--wax);
    background: var(--wax);
  }
  .error .node {
    box-shadow: 0 0 0 2px var(--brass);
  }
  .body {
    display: grid;
    gap: var(--s2);
    padding-bottom: var(--s6);
    min-width: 0;
  }
  header {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--s1) var(--s2);
    min-width: 0;
  }
  .what {
    color: var(--ink-2);
  }
  .on {
    color: var(--ink-4);
  }
  .zone {
    color: var(--ink-2);
    text-decoration: none;
  }
  .zone:hover {
    color: var(--seal-ink);
  }
  .decision {
    margin-left: auto;
    font-size: 12px;
    font-weight: 500;
  }
  .decision.allow {
    color: var(--stamp);
  }
  .decision.deny {
    color: var(--wax);
  }
  .decision.error {
    color: var(--brass);
  }
  .reason {
    color: var(--ink-2);
  }
  .deny .reason {
    color: var(--wax);
  }
  .code {
    font-size: 12px;
    padding: 0 6px;
    border-radius: var(--r-sm);
    background: var(--rule-soft);
    color: var(--ink-2);
    margin-right: 4px;
  }
  .changes {
    display: grid;
    gap: var(--s3);
  }
  footer {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--s1) var(--s4);
    font-size: 12px;
    color: var(--ink-4);
  }
  .ids[open] {
    flex-basis: 100%;
  }
  .ids summary {
    width: max-content;
    cursor: pointer;
    color: var(--ink-4);
    list-style-position: inside;
    border-radius: var(--r-sm);
  }
  .ids summary:hover {
    color: var(--ink-2);
  }
  .ids dl {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 2px var(--s3);
    margin: var(--s1) 0 0;
    align-items: center;
  }
  .ids dt {
    color: var(--ink-4);
  }
  .ids dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .ids :global(.copy) {
    max-width: 100%;
    text-align: left;
    word-break: break-all;
  }
  .compact .body {
    padding-bottom: var(--s5);
  }
  @media (max-width: 640px) {
    .item {
      grid-template-columns: 40px 16px minmax(0, 1fr);
    }
    .decision {
      margin-left: 0;
    }
  }
</style>
