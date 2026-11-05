<script lang="ts">
  import { api } from '../lib/api';
  import type { ZoneSummary } from '../lib/types';
  import { href, journalHref, policyHref, zoneHref } from '../lib/router.svelte';
  import { clock } from '../lib/clock.svelte';
  import { relative } from '../lib/format';
  import { plural, STALE_SYNC_MS } from '../lib/zones';
  import { forbidden, policyState } from '../lib/policy.svelte';
  import Icon from './Icon.svelte';
  import Seal from './Seal.svelte';

  // "All good" or what needs attention, each item linking to the view that shows it.
  let { zones }: { zones: ZoneSummary[] } = $props();

  type Count = { n: number; more: boolean };
  let refused = $state<Count | null>(null);
  let failed = $state<Count | null>(null);
  let journalHidden = $state(false);

  $effect(() => {
    const since = new Date(Date.now() - 24 * 3600_000).toISOString();
    const count = (decision: string) =>
      api.audit({ decision, since, limit: 100 }).then((p) => ({ n: p.entries.length, more: !!p.next_cursor }));
    count('deny')
      .then((c) => (refused = c))
      .catch(() => (journalHidden = true));
    count('error')
      .then((c) => (failed = c))
      .catch(() => (journalHidden = true));
    void policyState.load();
  });

  const managed = $derived(zones.filter((z) => !z.unmanaged));
  const drifted = $derived(managed.filter((z) => z.tainted > 0));
  const pending = $derived(managed.filter((z) => z.pending > 0));
  const stale = $derived(
    managed.filter((z) => !z.last_synced_at || clock.now - new Date(z.last_synced_at).getTime() > STALE_SYNC_MS),
  );
  const discovery = $derived(forbidden(policyState.error) ? undefined : policyState.data?.base.zones_discovery);
  const oldestSync = $derived(
    managed
      .map((z) => z.last_synced_at)
      .filter((t): t is string => !!t)
      .sort()[0],
  );

  const sum = (list: ZoneSummary[], k: 'tainted' | 'pending') => list.reduce((n, z) => n + z[k], 0);
  // One zone: open it filtered; several: the zones page filtered.
  const where = (list: ZoneSummary[], status: string) =>
    list.length === 1 ? zoneHref(list[0]!.zone, { status }) : href('/', { filter: 'attention' });
  const inZones = (list: ZoneSummary[]) => (list.length === 1 ? `in ${list[0]!.zone}` : `in ${list.length} zones`);
  const n = (c: Count) => (c.more ? `${c.n}+` : String(c.n));

  type Item = { key: string; tone: 'wax' | 'brass'; text: string; href: string; action: string };
  const items = $derived.by((): Item[] => {
    const out: Item[] = [];
    if (drifted.length) {
      const k = sum(drifted, 'tainted');
      out.push({ key: 'drift', tone: 'wax', text: `${plural(k, 'record set')} drifted ${inZones(drifted)}`, href: where(drifted, 'attention'), action: 'Review' });
    }
    if (pending.length) {
      const k = sum(pending, 'pending');
      out.push({ key: 'pending', tone: 'brass', text: `${plural(k, 'write')} pending confirmation ${inZones(pending)}`, href: where(pending, 'attention'), action: 'Review' });
    }
    if (refused && refused.n > 0)
      out.push({ key: 'deny', tone: 'wax', text: `${n(refused)} refused ${refused.n === 1 && !refused.more ? 'request' : 'requests'} in the last 24 hours`, href: journalHref({ decision: 'deny', period: '24h' }), action: 'Open the journal' });
    if (failed && failed.n > 0)
      out.push({ key: 'error', tone: 'brass', text: `${n(failed)} failed ${failed.n === 1 && !failed.more ? 'request' : 'requests'} in the last 24 hours`, href: journalHref({ decision: 'error', period: '24h' }), action: 'Open the journal' });
    if (discovery?.enabled && discovery.error)
      out.push({ key: 'discovery', tone: 'brass', text: `Zone discovery failed: ${discovery.error}`, href: policyHref(), action: 'See the policy' });
    if (stale.length)
      out.push({
        key: 'stale',
        tone: 'brass',
        text: stale.length === 1 ? `${stale[0]!.zone} not synced for over 30 minutes` : `${stale.length} zones not synced for over 30 minutes`,
        href: stale.length === 1 ? zoneHref(stale[0]!.zone) : href('/', { filter: 'managed' }),
        action: 'Open',
      });
    return out;
  });
  const settled = $derived((refused !== null && failed !== null) || journalHidden);
</script>

<section class="health" class:ok={settled && items.length === 0} class:warn={items.length > 0} aria-labelledby="health-title" aria-live="polite">
  <span class="mark" aria-hidden="true">
    {#if items.length}<Seal status="tainted" size={22} />{:else}<Seal status="managed" size={22} />{/if}
  </span>
  <div class="text">
    {#if items.length}
      <h2 id="health-title">{items.length === 1 ? '1 thing needs attention' : `${items.length} things need attention`}</h2>
      <ul>
        {#each items as it (it.key)}
          <li class={it.tone}>
            <span class="dot" aria-hidden="true"></span>
            <span class="what">{it.text} <a href={it.href}>{it.action}<Icon name="arrow" size={12} /></a></span>
          </li>
        {/each}
      </ul>
    {:else if settled}
      <h2 id="health-title">All good</h2>
      <p>
        Every managed record set matches the DNS provider{journalHidden ? '' : ', and nothing was refused or failed in the last 24 hours'}.
        {#if oldestSync}Oldest zone sync: {relative(oldestSync, clock.now)}.{/if}
      </p>
    {:else}
      <h2 id="health-title" class="sr-only">Checking</h2>
      <div class="skeleton line"></div>
    {/if}
  </div>
</section>

<style>
  .health {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: var(--s3) var(--s4);
    align-items: start;
    padding: var(--s4) var(--s5);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
  }
  .health.ok {
    background: color-mix(in srgb, var(--stamp-wash) 60%, var(--sheet));
    border-color: color-mix(in srgb, var(--stamp) 22%, transparent);
  }
  .health.ok .mark {
    color: var(--stamp);
  }
  .health.ok .mark :global(.seal) {
    color: var(--stamp);
  }
  .mark {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: var(--sheet-raised);
    box-shadow: inset 0 0 0 1px var(--rule);
  }
  .text {
    display: grid;
    gap: var(--s2);
    min-width: 0;
    padding-top: 6px;
  }
  h2 {
    font-size: var(--t-lead);
  }
  p {
    color: var(--ink-2);
    max-width: 75ch;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s1);
  }
  li {
    display: grid;
    grid-template-columns: 7px minmax(0, 1fr);
    align-items: baseline;
    gap: var(--s2);
    color: var(--ink);
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    transform: translateY(-1px);
  }
  .wax .dot {
    background: var(--wax);
  }
  .brass .dot {
    background: var(--brass);
  }
  .what {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  li a {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    margin-left: var(--s1);
    color: var(--seal-ink);
    font-weight: 500;
    text-decoration: none;
    white-space: nowrap;
  }
  li a:hover {
    text-decoration: underline;
    text-underline-offset: 3px;
  }
  .line {
    height: 14px;
    width: min(420px, 100%);
  }
</style>
