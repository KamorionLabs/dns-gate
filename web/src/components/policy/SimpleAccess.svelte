<script lang="ts">
  import type { EffectivePolicy } from '../../lib/types';
  import { audiencesOf, hostsText, inZone, typesText, writesByZone, type Audience, type ZoneGrants } from '../../lib/audience';
  import Icon from '../Icon.svelte';

  // Who may do what, at a glance: people (directory roles and groups), then
  // pipelines, then API keys, each with what it can see, decide and change,
  // zone by zone.
  let { policy, zones }: { policy: EffectivePolicy; zones: string[] } = $props();

  let zone = $state('');

  const all = $derived(audiencesOf(policy));
  const shown = $derived(zone ? all.map((a) => inZone(a, zone)).filter((a): a is Audience => !!a) : all);
  const people = $derived(shown.filter((a) => a.kind === 'people'));
  const pipelines = $derived(shown.filter((a) => a.kind === 'pipeline'));
  const keys = $derived(shown.filter((a) => a.kind === 'key'));

  const readText = (read: string[]) => (read.includes('*') ? 'every zone' : read.join(', '));
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  const zoneLabel = (z: string) => (z === '*' ? 'every zone' : z);
</script>

{#snippet grants(zg: ZoneGrants)}
  <ul class="grants">
    {#each zg.grants as g, i (i)}
      <li>
        {#if !g.write}<span class="adopt">Adopt only</span>{/if}
        <b>{typesText(g.types)}</b> on <b>{hostsText(g.hosts)}</b>
        {#if g.write && g.adopt}<span class="note" title="Can also take over records created outside the gate">+ adopt</span>{/if}
      </li>
    {/each}
  </ul>
{/snippet}

{#snippet changes(a: Audience)}
  {@const rows = writesByZone(a)}
  {#if rows.length}
    <table class="zt">
      <thead><tr><th>Zone</th><th>Can change</th></tr></thead>
      <tbody>
        {#each rows as zg (zg.zone)}
          <tr>
            <td class="zn mono" class:all={zg.zone === '*'}>{zoneLabel(zg.zone)}</td>
            <td>{@render grants(zg)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="ro">Changes nothing</p>
  {/if}
{/snippet}

<div class="simple">
  <div class="bar">
    <p class="intro">Who can do what through the gate. Anyone not listed here is refused, and a team only changes the records it owns</p>
    <label class="field zonepick">
      <span class="lbl">Zone</span>
      <select bind:value={zone}>
        <option value="">All zones</option>
        {#each zones as z (z)}<option value={z}>{z}</option>{/each}
      </select>
      <span class="chev"><Icon name="chevron" size={12} /></span>
    </label>
  </div>

  <p class="summary num">
    <span>{plural(people.length, 'group of people', 'groups of people')}</span>
    <span>{plural(pipelines.length, 'pipeline', 'pipelines')}</span>
    <span>{plural(keys.length, 'API key', 'API keys')}</span>
    {#if zone}<button class="clear" type="button" onclick={() => (zone = '')}><Icon name="x" size={12} />Show all zones</button>{/if}
  </p>

  <section>
    <h2 class="sec">People</h2>
    {#if people.length}
      <div class="rows">
        {#each people as a (a.id)}
          <article class="person">
            <div class="id">
              <h3>{a.title}</h3>
              <p class="sub">{a.subtitle}</p>
              <dl>
                {#if a.read.length}<dt>Sees</dt><dd>{readText(a.read)}</dd>{/if}
                {#if a.policy.length}<dt>Policy</dt><dd>Can {a.policy.join(', ')}</dd>{/if}
                {#if a.teams.length}<dt>Acts as</dt><dd>team <b>{a.teams.join(', ')}</b></dd>{/if}
              </dl>
            </div>
            <div class="perm">{@render changes(a)}</div>
          </article>
        {/each}
      </div>
    {:else}
      <p class="dim">No group of people has access{zone ? ' to ' + zone : ''}</p>
    {/if}
  </section>

  <section>
    <h2 class="sec">Pipelines</h2>
    {#if pipelines.length}
      <table class="plist">
        <thead><tr><th>Pipeline</th><th>Zone</th><th>Can change</th></tr></thead>
        <tbody>
          {#each pipelines as a (a.id)}
            {@const rows = writesByZone(a)}
            {#each rows.length ? rows : [undefined] as zg, i (i)}
              <tr class:first={i === 0}>
                {#if i === 0}
                  <td rowspan={Math.max(rows.length, 1)} class="who">
                    <span class="pname mono">{a.title}</span>
                    <span class="sub">{a.subtitle}{a.layers.includes('delegated') ? ' · set by a delegation' : ''}</span>
                  </td>
                {/if}
                {#if zg}
                  <td class="zn mono" class:all={zg.zone === '*'}>{zoneLabel(zg.zone)}</td>
                  <td>{@render grants(zg)}</td>
                {:else}
                  <td colspan="2" class="dim">{a.read.length ? 'Read-only: ' + readText(a.read) : 'Nothing'}</td>
                {/if}
              </tr>
            {/each}
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="dim">No pipeline has access{zone ? ' to ' + zone : ''}</p>
    {/if}
  </section>

  {#if keys.length}
    <section>
      <h2 class="sec">API keys</h2>
      <div class="rows">
        {#each keys as a (a.id)}
          <article class="person">
            <div class="id">
              <h3>{a.title}</h3>
              <p class="sub">{a.subtitle}</p>
              <dl>{#if a.read.length}<dt>Sees</dt><dd>{readText(a.read)}</dd>{/if}</dl>
            </div>
            <div class="perm">{@render changes(a)}</div>
          </article>
        {/each}
      </div>
    </section>
  {/if}
</div>

<style>
  .simple {
    display: grid;
    gap: var(--s6);
  }
  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--s3);
  }
  .intro {
    color: var(--ink-2);
    margin: 0;
    max-width: 70ch;
  }
  .zonepick {
    min-width: 240px;
  }
  .zonepick .lbl {
    color: var(--ink-3);
    font-size: 12px;
  }
  .zonepick select {
    flex: 1;
    font-size: 13px;
  }
  .summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s4);
    margin: calc(-1 * var(--s3)) 0 0;
    color: var(--ink-3);
    font-size: 12px;
  }
  .clear {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 0;
    background: none;
    padding: 0;
    color: var(--seal-ink);
    cursor: pointer;
    font-size: 12px;
  }
  .clear:hover {
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  section {
    display: grid;
    gap: var(--s3);
  }
  .sec {
    font-size: var(--t-lead);
  }
  .rows {
    display: grid;
    gap: var(--s3);
  }
  .person {
    display: grid;
    grid-template-columns: 260px minmax(0, 1fr);
    gap: var(--s6);
    padding: var(--s4) var(--s5);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
  }
  .person h3 {
    font-size: 15px;
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .sub {
    margin: 2px 0 0;
    color: var(--ink-3);
    font-size: 12px;
    overflow-wrap: anywhere;
  }
  .id dl {
    display: grid;
    grid-template-columns: 56px minmax(0, 1fr);
    gap: 4px var(--s2);
    margin: var(--s3) 0 0;
    font-size: 13px;
  }
  .id dt {
    color: var(--ink-3);
  }
  .id dd {
    margin: 0;
    color: var(--ink-2);
  }
  .id dd b {
    font-weight: 600;
    color: var(--ink);
  }
  .zt,
  .plist {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    text-align: left;
    font-size: 12px;
    font-weight: 500;
    color: var(--ink-3);
    padding: 0 var(--s3) var(--s2) 0;
    border-bottom: 1px solid var(--rule);
  }
  td {
    padding: var(--s2) var(--s3) var(--s2) 0;
    vertical-align: top;
    border-bottom: 1px solid var(--rule-soft);
  }
  .zt tr:last-child td {
    border-bottom: 0;
  }
  .zn {
    width: 220px;
    color: var(--ink);
    white-space: nowrap;
  }
  .zn.all {
    color: var(--brass);
    font-family: var(--font-ui);
  }
  .grants {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 2px;
    color: var(--ink-2);
  }
  .grants b {
    font-weight: 600;
    color: var(--ink);
  }
  .note {
    margin-left: 6px;
    font-size: 12px;
    color: var(--ink-3);
  }
  .adopt {
    margin-right: 6px;
    font-size: 12px;
    color: var(--brass);
  }
  .ro {
    margin: 0;
    color: var(--ink-3);
  }
  .plist .who {
    width: 280px;
  }
  .pname {
    display: block;
    font-weight: 600;
    color: var(--ink);
  }
  .dim {
    color: var(--ink-3);
  }
  @media (max-width: 860px) {
    .person {
      grid-template-columns: 1fr;
      gap: var(--s3);
    }
    .zn {
      width: auto;
    }
  }
  @media (max-width: 720px) {
    .plist thead {
      display: none;
    }
    .plist tr,
    .plist td {
      display: block;
      border: 0;
      padding: 2px 0;
    }
    .plist tr.first {
      border-top: 1px solid var(--rule-soft);
      padding-top: var(--s2);
    }
  }
</style>
