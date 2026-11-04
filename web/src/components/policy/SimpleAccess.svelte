<script lang="ts">
  import type { EffectivePolicy } from '../../lib/types';
  import { audiencesOf, hostsText, inZone, typesText, type Audience, type WriteGrant } from '../../lib/audience';
  import Icon from '../Icon.svelte';

  // Who may do what, at a glance: people (directory roles and groups), then
  // pipelines, then API keys, each with what it can see, change and decide.
  let { policy, zones }: { policy: EffectivePolicy; zones: string[] } = $props();

  let zone = $state('');

  const all = $derived(audiencesOf(policy));
  const shown = $derived(zone ? all.map((a) => inZone(a, zone)).filter((a): a is Audience => !!a) : all);
  const people = $derived(shown.filter((a) => a.kind === 'people'));
  const pipelines = $derived(shown.filter((a) => a.kind === 'pipeline'));
  const keys = $derived(shown.filter((a) => a.kind === 'key'));

  const readText = (read: string[]) => (read.includes('*') ? 'every zone' : read.join(', '));
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
</script>

{#snippet zonesOf(w: WriteGrant)}
  {#if w.zones.includes('*')}<span class="zchip all">every zone</span>
  {:else}{#each w.zones as z (z)}<span class="zchip mono">{z}</span>{/each}{/if}
{/snippet}

{#snippet records(w: WriteGrant)}
  <span class="rec"><b>{typesText(w.types)}</b> records on <b>{hostsText(w.hosts)}</b></span>
  {#if w.write && w.adopt}<span class="note" title="Can also take over records created outside the gate">+ adopt existing</span>{/if}
{/snippet}

<div class="simple">
  <div class="bar">
    <p class="intro">
      Who can do what through the gate. Anyone not listed here is refused, and a team only changes the records it owns.
    </p>
    <label class="filter">
      <Icon name="filter" size={13} />
      <select bind:value={zone} aria-label="Show one zone">
        <option value="">All zones</option>
        {#each zones as z (z)}<option value={z}>{z}</option>{/each}
      </select>
    </label>
  </div>

  <p class="summary">
    <span><Icon name="shield" size={13} />{plural(people.length, 'group of people', 'groups of people')}</span>
    <span><Icon name="flask" size={13} />{plural(pipelines.length, 'pipeline', 'pipelines')}</span>
    {#if keys.length || !zone}<span><Icon name="key" size={13} />{plural(keys.length, 'API key', 'API keys')}</span>{/if}
  </p>

  <section>
    <h2 class="sec">People</h2>
    {#if people.length}
      <div class="cards">
        {#each people as a (a.id)}
          <article class="card">
            <header>
              <h3>{a.title}</h3>
              <p class="sub">{a.subtitle}</p>
            </header>
            <ul class="caps">
              {#if a.read.length}<li><span class="verb see">Sees</span><span>{readText(a.read)}</span></li>{/if}
              {#each a.writes as w, i (i)}
                <li class="w">
                  <span class="verb change">{w.write ? 'Changes' : 'Adopts'}</span>
                  <span class="what">{@render records(w)}<span class="zones">in {@render zonesOf(w)}</span></span>
                </li>
              {/each}
              {#if a.policy.length}<li><span class="verb decide">Policy</span><span>Can {a.policy.join(', ')}</span></li>{/if}
              {#if !a.writes.length && !a.policy.length}<li class="ro">Read-only</li>{/if}
            </ul>
            {#if a.teams.length}<footer>Acts as team <b>{a.teams.join(', ')}</b></footer>{/if}
          </article>
        {/each}
      </div>
    {:else}
      <p class="dim">No group of people has access{zone ? ' to ' + zone : ''}.</p>
    {/if}
  </section>

  <section>
    <h2 class="sec">Pipelines</h2>
    {#if pipelines.length}
      <table class="plist">
        <thead><tr><th>Pipeline</th><th>Can change</th><th>In</th></tr></thead>
        <tbody>
          {#each pipelines as a (a.id)}
            {#each a.writes.length ? a.writes : [undefined] as w, i (i)}
              <tr class:first={i === 0}>
                {#if i === 0}
                  <td rowspan={Math.max(a.writes.length, 1)} class="who">
                    <span class="pname mono">{a.title}</span>
                    <span class="sub">{a.subtitle}{a.layers.includes('delegated') ? ' · set by a delegation' : ''}</span>
                  </td>
                {/if}
                {#if w}
                  <td>{@render records(w)}</td>
                  <td class="zcell">{@render zonesOf(w)}</td>
                {:else}
                  <td colspan="2" class="dim">{a.read.length ? 'Read-only: ' + readText(a.read) : 'Nothing'}</td>
                {/if}
              </tr>
            {/each}
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="dim">No pipeline has access{zone ? ' to ' + zone : ''}.</p>
    {/if}
  </section>

  {#if keys.length}
    <section>
      <h2 class="sec">API keys</h2>
      <div class="cards">
        {#each keys as a (a.id)}
          <article class="card">
            <header><h3>{a.title}</h3><p class="sub">{a.subtitle}</p></header>
            <ul class="caps">
              {#if a.read.length}<li><span class="verb see">Sees</span><span>{readText(a.read)}</span></li>{/if}
              {#each a.writes as w, i (i)}
                <li class="w"><span class="verb change">{w.write ? 'Changes' : 'Adopts'}</span><span class="what">{@render records(w)}<span class="zones">in {@render zonesOf(w)}</span></span></li>
              {/each}
            </ul>
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
  .filter {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--ink-3);
  }
  .summary {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s4);
    margin: calc(-1 * var(--s3)) 0 0;
    color: var(--ink-3);
    font-size: 12.5px;
  }
  .summary span {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  section {
    display: grid;
    gap: var(--s3);
  }
  .sec {
    font-size: var(--t-lead);
  }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr));
    gap: var(--s4);
    align-items: start;
  }
  .card {
    display: grid;
    gap: var(--s3);
    padding: var(--s4) var(--s5);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
    min-width: 0;
  }
  .card h3 {
    font-size: 15px;
    font-weight: 650;
    overflow-wrap: anywhere;
  }
  .sub {
    margin: 2px 0 0;
    color: var(--ink-3);
    font-size: 12px;
    overflow-wrap: anywhere;
  }
  .caps {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  .caps li {
    display: grid;
    grid-template-columns: 68px minmax(0, 1fr);
    gap: var(--s2);
    align-items: baseline;
    color: var(--ink-2);
  }
  .caps li.ro {
    display: block;
    color: var(--ink-3);
    font-style: italic;
  }
  .verb {
    justify-self: start;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    padding: 1px 6px;
    border-radius: var(--r-sm);
  }
  .verb.see {
    color: var(--ink-3);
    background: var(--rule-soft);
  }
  .verb.change {
    color: var(--seal-ink);
    background: var(--seal-ink-wash);
  }
  .verb.decide {
    color: var(--brass);
    background: var(--brass-wash);
  }
  .what {
    display: grid;
    gap: 4px;
    min-width: 0;
  }
  .rec b {
    font-weight: 600;
    color: var(--ink);
  }
  .note {
    margin-left: 6px;
    font-size: 11.5px;
    color: var(--ink-3);
  }
  .zones {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    color: var(--ink-3);
    font-size: 12px;
  }
  .zchip {
    font-size: 11.5px;
    padding: 0 7px;
    border-radius: 10px;
    color: var(--ink);
    box-shadow: inset 0 0 0 1px var(--rule-strong);
  }
  .zchip.all {
    color: var(--brass);
    box-shadow: inset 0 0 0 1px var(--brass);
  }
  footer {
    color: var(--ink-3);
    font-size: 12px;
    border-top: 1px solid var(--rule-soft);
    padding-top: var(--s2);
  }
  footer b {
    color: var(--ink-2);
    font-weight: 600;
  }
  .plist {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  .plist th {
    text-align: left;
    font-size: 11.5px;
    font-weight: 600;
    color: var(--ink-3);
    padding: 0 var(--s3) var(--s2);
    border-bottom: 1px solid var(--rule);
  }
  .plist td {
    padding: var(--s2) var(--s3);
    vertical-align: top;
    border-bottom: 1px solid var(--rule-soft);
  }
  .plist .who {
    display: table-cell;
    min-width: 200px;
  }
  .pname {
    display: block;
    font-weight: 600;
    color: var(--ink);
  }
  .zcell {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .dim {
    color: var(--ink-3);
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
