<script lang="ts">
  import type { AuditEntry } from '../lib/types';
  import { actionLabel, decisionLabel, reasonLabel } from '../lib/labels';
  import { clockTime } from '../lib/format';
  import { zoneHref } from '../lib/router.svelte';
  import ActorChip from './ActorChip.svelte';
  import ChangeDiff from './ChangeDiff.svelte';
  import CopyText from './CopyText.svelte';
  import RelTime from './RelTime.svelte';

  let { entry, compact = false }: { entry: AuditEntry; compact?: boolean } = $props();
  const applied = $derived(entry.decision === 'allow');
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

    {#if entry.changes?.length}
      <div class="changes">
        {#each entry.changes as c, i (i)}
          <ChangeDiff change={c} zone={entry.zone} {applied} link={!compact} />
        {/each}
      </div>
    {/if}

    <footer>
      <CopyText text={entry.request_id} label="request id" />
      {#if entry.snapshot_id}<span class="mono snap">snapshot #{entry.snapshot_id}</span>{/if}
      {#if entry.teams?.length && !compact}<span class="teams">as {entry.teams.join(', ')}</span>{/if}
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
    font-size: 11.5px;
    font-weight: 600;
    padding: 1px 8px;
    border-radius: 10px;
  }
  .decision.allow {
    color: var(--stamp);
    background: var(--stamp-wash);
  }
  .decision.deny {
    color: var(--wax);
    background: var(--wax-wash);
  }
  .decision.error {
    color: var(--brass);
    background: var(--brass-wash);
  }
  .reason {
    color: var(--ink-2);
  }
  .deny .reason {
    color: var(--wax);
  }
  .code {
    font-size: 11.5px;
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
    align-items: center;
    gap: var(--s1) var(--s4);
    font-size: 11.5px;
    color: var(--ink-4);
  }
  .snap {
    font-size: 11.5px;
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
