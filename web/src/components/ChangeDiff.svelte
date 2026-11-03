<script lang="ts">
  import type { ShownChange } from '../lib/journal';
  import { opLabel } from '../lib/labels';
  import { ttl as fmtTTL } from '../lib/format';
  import { zoneHref } from '../lib/router.svelte';
  import Host from './Host.svelte';

  let { change, zone, link = true, applied = true }: { change: ShownChange; zone?: string; link?: boolean; applied?: boolean } =
    $props();
  // A record set replaced by one of another type (A to CNAME) reads as one change.
  const retyped = $derived(!!change.old_type && change.old_type !== change.type);

  const oldV = $derived(change.old_values ?? []);
  const newV = $derived(change.new_values ?? []);
  const lines = $derived.by(() => {
    const out: { kind: 'add' | 'del' | 'keep'; v: string }[] = [];
    for (const v of oldV) if (!newV.includes(v)) out.push({ kind: 'del', v });
    for (const v of newV) out.push({ kind: oldV.includes(v) ? 'keep' : 'add', v });
    return out;
  });
  const ttlChanged = $derived(
    change.old_ttl !== undefined && change.new_ttl !== undefined && change.old_ttl !== change.new_ttl,
  );
</script>

<div class="change {change.op}" class:proposed={!applied}>
  <div class="head">
    <span class="op">{applied ? opLabel[change.op] : 'Proposed'}{#if retyped}<span class="retype">(type {change.old_type} → {change.type})</span>{/if}</span>
    {#if link && zone}
      <a href={zoneHref(zone, { rr: `${change.host}/${change.type}` })}><Host host={change.host} {zone} showZone={false} /></a>
    {:else}
      <Host host={change.host} zone={zone ?? ''} showZone={false} />
    {/if}
    <span class="type mono">{change.type}</span>
    {#if ttlChanged}
      <span class="ttl mono num">TTL {fmtTTL(change.old_ttl ?? 0)} → {fmtTTL(change.new_ttl ?? 0)}</span>
    {:else if change.new_ttl ?? change.old_ttl}
      <span class="ttl mono num">TTL {fmtTTL(change.new_ttl ?? change.old_ttl ?? 0)}</span>
    {/if}
  </div>
  {#if lines.length}
    <ul class="values mono">
      {#each lines as l, i (i)}
        <li class={l.kind}><span class="sign" aria-hidden="true">{l.kind === 'add' ? '+' : l.kind === 'del' ? '−' : ' '}</span><span class="sr-only">{l.kind === 'add' ? 'added' : l.kind === 'del' ? 'removed' : 'unchanged'}</span>{l.v}</li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .change {
    display: grid;
    gap: var(--s1);
    min-width: 0;
  }
  .head {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: var(--s1) var(--s2);
    min-width: 0;
  }
  .head a {
    text-decoration: none;
    min-width: 0;
    display: inline-flex;
  }
  .head a:hover :global(.label) {
    text-decoration: underline;
    text-decoration-color: var(--rule-strong);
    text-underline-offset: 3px;
  }
  .op {
    font-size: var(--t-caption);
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--ink-3);
  }
  .taint .op,
  .delete .op,
  .expire .op {
    color: var(--wax);
  }
  .adopt .op {
    color: var(--seal-ink);
  }
  .type {
    color: var(--ink-3);
    font-size: 11.5px;
  }
  .retype {
    margin-left: 0.4em;
    text-transform: none;
    letter-spacing: 0;
    font-weight: 500;
    color: var(--ink-2);
  }
  .ttl {
    color: var(--ink-4);
    font-size: 11.5px;
  }
  .values {
    list-style: none;
    margin: 0;
    padding: var(--s1) 0;
    border-radius: var(--r-sm);
    background: var(--well);
    overflow-x: auto;
  }
  .values li {
    padding: 1px var(--s3) 1px var(--s2);
    white-space: pre;
    color: var(--ink-2);
  }
  .sign {
    display: inline-block;
    width: 14px;
    color: var(--ink-4);
  }
  .add {
    background: var(--stamp-wash);
    color: var(--ink);
  }
  .add .sign {
    color: var(--stamp);
  }
  .del {
    background: var(--wax-wash);
    color: var(--ink-3);
    text-decoration: line-through;
    text-decoration-color: color-mix(in srgb, var(--wax) 50%, transparent);
  }
  .del .sign {
    color: var(--wax);
    text-decoration: none;
  }
  .proposed .add {
    background: var(--rule-soft);
  }
  .proposed .add .sign {
    color: var(--ink-3);
  }
</style>
