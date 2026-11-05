<script lang="ts">
  import type { Binding, EffectivePolicy, Group, Role, VirtualKey } from '../lib/types';
  import { proposalHref } from '../lib/router.svelte';
  import PolicyFrame from '../components/policy/PolicyFrame.svelte';
  import DocItems from '../components/policy/DocItems.svelte';
  import LayerTag from '../components/policy/LayerTag.svelte';
  import ActorChip from '../components/ActorChip.svelte';
  import RelTime from '../components/RelTime.svelte';
  import CopyText from '../components/CopyText.svelte';
  import Icon from '../components/Icon.svelte';
  import ZoneAccessView from '../components/policy/ZoneAccess.svelte';
  import { humanDuration } from '../lib/duration';
  import { bindingsOf, rolesOf, whoCanDoWhat, type Layer } from '../lib/access';
  import Matcher from '../components/policy/Matcher.svelte';
  import { teamFromText } from '../lib/team';
  import type { DelegatedOwner } from '../lib/types';
  import SimpleAccess from '../components/policy/SimpleAccess.svelte';

  // Simple view by default; the expert view lists every layer and object.
  const VIEW_KEY = 'dns-gate.policy.view';
  let view = $state<'simple' | 'expert'>(
    (() => {
      try {
        return localStorage.getItem(VIEW_KEY) === 'expert' ? 'expert' : 'simple';
      } catch {
        return 'simple';
      }
    })(),
  );
  function setView(v: 'simple' | 'expert') {
    view = v;
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      // private mode: the choice lasts for this page only
    }
  }

  type L<T> = { layer: Layer; rev?: string; name?: string; owner?: DelegatedOwner; item: T };

  function layered(p: EffectivePolicy) {
    const rev = p.active?.id;
    const g: L<[string, Group]>[] = [
      ...Object.entries(p.base.document.groups).map((item) => ({ layer: 'base' as const, item })),
      ...Object.entries(p.managed?.groups ?? {}).map((item) => ({ layer: 'managed' as const, rev, item })),
    ];
    const r: L<[string, Role]>[] = [
      ...Object.entries(p.base.document.roles).map((item) => ({ layer: 'base' as const, item })),
      ...Object.entries(p.managed?.roles ?? {}).map((item) => ({ layer: 'managed' as const, rev, item })),
      ...Object.entries(p.managed?.delegated?.roles ?? {})
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, role]) => ({ layer: 'delegated' as const, rev, owner: role.owner, item: [name, role] as [string, Role] })),
    ];
    const b: L<Binding>[] = bindingsOf(p).map(({ binding, ...rest }) => ({ ...rest, item: binding }));
    const k: L<VirtualKey>[] = [
      ...p.base.document.virtual_keys.map((item) => ({ layer: 'base' as const, item })),
      ...(p.managed?.virtual_keys ?? []).map((item) => ({ layer: 'managed' as const, rev, item })),
    ];
    return { g, r, b, k };
  }

  const sections = [
    ['layers', 'Layers'],
    ['zones', 'Zones'],
    ['who', 'Who can do what'],
    ['bindings', 'Bindings'],
    ['delegations', 'Delegations'],
    ['groups', 'Groups'],
    ['roles', 'Roles'],
    ['keys', 'Virtual keys'],
    ['protected', 'Protected records'],
    ['bounds', 'Bounds'],
    ['issuers', 'Issuers'],
  ] as const;
</script>

<PolicyFrame tab="overview" title="Who may change what">
  {#snippet children(p)}
    {@const L = layered(p)}
    {@const zones = [...new Set([...p.base.zones, ...(p.managed?.zones ?? [])])].sort()}
    <div class="viewswitch" role="group" aria-label="View">
      <button type="button" aria-pressed={view === 'simple'} onclick={() => setView('simple')}>Simple</button>
      <button type="button" aria-pressed={view === 'expert'} onclick={() => setView('expert')}>Expert</button>
    </div>
    {#if view === 'simple'}
      <SimpleAccess policy={p} {zones} />
    {:else}
    <div class="page">
      <aside class="toc" aria-label="On this page">
        {#each sections as [id, label] (id)}<a href={'#/policy'} onclick={(e) => { e.preventDefault(); document.getElementById('sec-' + id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }}>{label}</a>{/each}
      </aside>

      <div class="content">
        <section id="sec-layers" class="layers">
          <article class="layer base">
            <header><Icon name="lock" size={16} /><h2>Base layer</h2><LayerTag layer="base" /></header>
            <p class="lead">Loaded from the configuration file. Changes go through Git and a redeploy, never through this console. Issuers, protected records, bounds and every policy.* grant live here.</p>
            <dl>
              <dt>Config hash</dt><dd><CopyText text={p.base.config_hash.replace(/^sha256:/, '').slice(0, 16)} label="config hash" /></dd>
              <dt>Loaded</dt><dd><RelTime iso={p.base.loaded_at} /></dd>
              <dt>Zones</dt><dd class="mono">{p.base.zones.join(', ') || 'none'}</dd>
            </dl>
          </article>
          <article class="layer managed">
            <header><Icon name="shield" size={16} /><h2>Managed layer</h2>{#if p.active}<LayerTag layer="managed" rev={p.active.id} />{/if}</header>
            {#if p.active}
              <p class="lead">“{p.active.comment}”</p>
              <dl>
                <dt>Proposed by</dt><dd><ActorChip actor={p.active.author} /> <RelTime iso={p.active.created_at} /></dd>
                {#if p.active.activated_by}<dt>Activated by</dt><dd><ActorChip actor={p.active.activated_by} /> <RelTime iso={p.active.activated_at} /></dd>{/if}
                <dt>Revision</dt><dd><a class="rev mono" href={proposalHref(p.active.id)}>{p.active.id} <Icon name="arrow" size={12} /></a></dd>
                {#if p.managed?.zones?.length}<dt>Zones</dt><dd class="mono">{p.managed.zones.join(', ')}</dd>{/if}
              </dl>
            {:else}
              <p class="lead">No managed revision is active: only the base layer applies.</p>
            {/if}
          </article>
        </section>

        <section id="sec-zones">
          <h2 class="sec">Managed zones <span class="count num">{p.base.zones.length + (p.managed?.zones?.length ?? 0)}</span></h2>
          <p class="hint">Only these zones can be written through the gate. Base zones come from the configuration file; the managed layer can add zones of the account, within the bounds.</p>
          <div class="bounds">
            <div><span class="eyebrow">Base <LayerTag layer="base" /></span><div class="chips">{#each p.base.zones as z (z)}<span class="chip mono">{z}</span>{:else}<span class="dim">none</span>{/each}</div></div>
            <div><span class="eyebrow">Managed {#if p.active}<LayerTag layer="managed" rev={p.active.id} />{/if}</span><div class="chips">{#each p.managed?.zones ?? [] as z (z)}<span class="chip mono">{z}</span>{:else}<span class="dim">none</span>{/each}</div></div>
          </div>
          {#if p.base.zones_discovery}
            {@const d = p.base.zones_discovery}
            <div class="discovery">
              <span class="eyebrow">Zone discovery <LayerTag layer="base" /></span>
              {#if d.enabled}
                <p>
                  {#if d.loaded}<span class="num">{d.count}</span> {d.count === 1 ? 'zone' : 'zones'} found in the account{#if d.last_refresh_at}, listed <RelTime iso={d.last_refresh_at} />{/if}.{:else}Not listed yet.{/if}
                  Refreshed every {humanDuration(d.refresh)}. Zones found but not managed are shown read-only on the zones page.
                </p>
                <dl>
                  <dt>include</dt><dd class="mono">{d.include.join(', ') || '*'}</dd>
                  {#if d.exclude.length}<dt>exclude</dt><dd class="mono">{d.exclude.join(', ')}</dd>{/if}
                </dl>
                {#if d.error}<p class="derr"><Icon name="alert" size={12} /> Last listing failed: {d.error}</p>{/if}
              {:else}
                <p class="dim">Disabled: only the zones above are visible, and the managed layer cannot add zones.</p>
              {/if}
            </div>
          {/if}
        </section>

        <section id="sec-who">
          <h2 class="sec">Who can do what <span class="count num">{zones.length} {zones.length === 1 ? 'zone' : 'zones'}</span></h2>
          <p class="hint">Per managed zone, the teams that can act there, who they are and what they may do, from the roles of every binding. Ownership still applies: a team only changes the records it owns.</p>
          <div class="who-grid">
            {#each whoCanDoWhat(p, zones) as a (a.zone)}<ZoneAccessView access={a} />{/each}
          </div>
        </section>

        <section id="sec-bindings">
          <h2 class="sec">Bindings <span class="count num">{L.b.length}</span></h2>
          <p class="hint">A binding grants a role, acting for a team, to groups or subjects. The team owns what it creates.</p>
          <DocItems kind="bindings" bindings={L.b} roleDefs={rolesOf(p)} />
        </section>

        <section id="sec-delegations">
          <h2 class="sec">Delegations <LayerTag layer="base" /> <span class="count num">{p.base.delegations?.length ?? 0}</span></h2>
          <p class="hint">A delegation lets a trusted identity, typically the pipeline that creates other pipelines, manage its own roles and bindings within the limits below. Its changes apply at once and show here with a <span class="mono">delegated</span> tag; they are not edited through revisions.</p>
          {#if p.base.delegations?.length}
            <ul class="delegations">
              {#each p.base.delegations as d (d.name)}
                {@const owned = [...Object.values(p.managed?.delegated?.roles ?? {}), ...Object.values(p.managed?.delegated?.bindings ?? {})].filter((o) => o.owner.delegation === d.name).length}
                <li>
                  <div class="dhead"><span class="name mono">{d.name}</span><span class="count num">{owned} / {d.allow.max_objects} objects</span></div>
                  {#if d.description}<p class="desc">{d.description}</p>{/if}
                  <dl>
                    <dt>Used by</dt><dd>{#each d.subjects as m, k (k)}<Matcher {m} />{/each}</dd>
                    <dt>Zones</dt><dd class="chips">{#each d.allow.zones as z (z)}<span class="chip mono">{z}</span>{/each}</dd>
                    <dt>Actions</dt><dd class="chips">{#each d.allow.actions as a (a)}<span class="chip mono">{a}</span>{/each}</dd>
                    {#if d.allow.records}
                      <dt>Records</dt><dd class="mono">{(d.allow.records.hosts ?? []).join(', ') || 'any host'} · {(d.allow.records.types ?? []).join(', ') || 'any type'}</dd>
                    {/if}
                    <dt>May bind</dt><dd>{#each d.allow.binding_subjects as m, k (k)}<Matcher {m} />{/each}{#each d.allow.groups ?? [] as g (g)}<span class="chip mono">{g}</span>{/each}</dd>
                    <dt>Teams</dt><dd class="mono">{[...(d.allow.teams.names ?? []), ...(d.allow.teams.from_subject ? [teamFromText(d.allow.teams.from_subject)] : [])].join(' · ')}</dd>
                  </dl>
                </li>
              {/each}
            </ul>
          {:else}
            <p class="dim">No delegation in the configuration file.</p>
          {/if}
        </section>

        <section id="sec-groups">
          <h2 class="sec">Groups <span class="count num">{L.g.length}</span></h2>
          <DocItems kind="groups" groups={L.g} />
        </section>

        <section id="sec-roles">
          <h2 class="sec">Roles <span class="count num">{L.r.length}</span></h2>
          <DocItems kind="roles" roles={L.r} />
        </section>

        <section id="sec-keys">
          <h2 class="sec">Virtual keys <span class="count num">{L.k.length}</span></h2>
          <p class="hint">For clients that only speak the EuroDNS API. Only a hash of each key is stored.</p>
          <DocItems kind="keys" keys={L.k} />
        </section>

        <section id="sec-protected">
          <h2 class="sec">Protected records <LayerTag layer="base" /></h2>
          <p class="hint">No role can change these, whatever the bindings say.</p>
          <ul class="plain">
            {#each p.base.protected as pr, i (i)}
              <li class="mono"><Icon name="lock" size={12} /> zones <b>{pr.zones.join(', ')}</b> · hosts <b>{pr.hosts.join(', ')}</b> · types <b>{pr.types.join(', ')}</b></li>
            {/each}
          </ul>
        </section>

        <section id="sec-bounds">
          <h2 class="sec">Bounds of the managed layer <LayerTag layer="base" /></h2>
          <p class="hint">A managed rule may only target these zones and grant these actions.</p>
          <div class="bounds">
            <div><span class="eyebrow">Zones</span><div class="chips">{#each p.base.bounds.zones as z (z)}<span class="chip mono">{z}</span>{/each}</div></div>
            <div><span class="eyebrow">Actions</span><div class="chips">{#each p.base.bounds.actions as a (a)}<span class="chip mono">{a}</span>{/each}</div></div>
          </div>
        </section>

        <section id="sec-issuers">
          <h2 class="sec">Issuers <LayerTag layer="base" /></h2>
          <div class="issuers">
            {#each p.base.issuers as iss (iss.name)}
              <article class="issuer">
                <div class="ihead"><span class="name mono">{iss.name}</span>{#if iss.category}<span class="cat">{iss.category}</span>{/if}</div>
                <p class="url mono">{iss.issuer}</p>
                <dl>
                  <dt>audience</dt><dd class="mono">{iss.audiences.join(', ')}</dd>
                  {#if iss.subject_claim}<dt>subject</dt><dd class="mono">{iss.subject_claim}</dd>{/if}
                  {#each Object.entries(iss.bound_claims ?? {}) as [k, v] (k)}<dt>requires</dt><dd class="mono">{k} = {v.join(' | ')}</dd>{/each}
                </dl>
              </article>
            {/each}
          </div>
        </section>
      </div>
    </div>
    {/if}
  {/snippet}
</PolicyFrame>

<style>
  .viewswitch {
    display: inline-flex;
    justify-self: start;
    margin: calc(-1 * var(--s3)) 0 var(--s5);
    padding: 2px;
    border-radius: var(--r-md);
    background: var(--rule-soft);
  }
  .viewswitch button {
    border: 0;
    background: none;
    padding: 4px var(--s3);
    border-radius: var(--r-sm);
    color: var(--ink-3);
    font: inherit;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }
  .viewswitch button[aria-pressed='true'] {
    background: var(--sheet);
    color: var(--ink);
    box-shadow: 0 1px 2px var(--rule-strong);
  }
  .discovery {
    display: grid;
    gap: var(--s2);
    padding: var(--s3) var(--s4);
    border: 1px dashed var(--rule-strong);
    border-radius: var(--r-md);
  }
  .discovery p {
    margin: 0;
    color: var(--ink-2);
  }
  .discovery dl {
    margin: 0;
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 2px var(--s3);
    font-size: 13px;
  }
  .discovery dt {
    color: var(--ink-3);
  }
  .discovery dd {
    margin: 0;
  }
  .discovery .derr {
    color: var(--wax);
    font-size: 13px;
  }
  .dim {
    color: var(--ink-4);
  }
  .page {
    display: grid;
    grid-template-columns: 160px minmax(0, 1fr);
    gap: var(--s8);
  }
  .toc {
    position: sticky;
    top: 76px;
    align-self: start;
    display: grid;
    gap: 2px;
  }
  .toc a {
    padding: 4px var(--s2);
    border-radius: var(--r-sm);
    color: var(--ink-3);
    text-decoration: none;
    font-size: 13px;
  }
  .toc a:hover {
    color: var(--ink);
    background: var(--rule-soft);
  }
  .content {
    display: grid;
    gap: var(--s8);
    min-width: 0;
  }
  section {
    display: grid;
    gap: var(--s3);
    scroll-margin-top: 72px;
  }
  .layers {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--s4);
  }
  .delegations {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s3);
  }
  .delegations li {
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    padding: var(--s3) var(--s4);
    background: var(--sheet);
  }
  .delegations .dhead {
    display: flex;
    justify-content: space-between;
    gap: var(--s3);
  }
  .delegations .name {
    font-weight: 600;
  }
  .delegations .desc {
    color: var(--ink-3);
    margin: var(--s1) 0 var(--s2);
  }
  .delegations dl {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: var(--s1) var(--s3);
    font-size: 13px;
  }
  .delegations dt {
    color: var(--ink-3);
  }
  .delegations dd {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .layer {
    display: grid;
    align-content: start;
    gap: var(--s3);
    padding: var(--s4) var(--s5);
    border-radius: var(--r-lg);
  }
  .layer.base {
    border: 1px dashed var(--rule-strong);
    background: repeating-linear-gradient(135deg, transparent 0 10px, var(--rule-soft) 10px 11px);
  }
  .layer.managed {
    border: 1px solid var(--rule);
    background: var(--sheet);
    box-shadow: inset 3px 0 0 var(--seal-ink);
  }
  .layer header {
    display: flex;
    align-items: center;
    gap: var(--s2);
    color: var(--ink-3);
  }
  .layer.managed header {
    color: var(--seal-ink);
  }
  .layer h2 {
    font-size: var(--t-lead);
    color: var(--ink);
    margin-right: auto;
  }
  .lead {
    color: var(--ink-2);
  }
  .layer dl {
    display: grid;
    grid-template-columns: 100px minmax(0, 1fr);
    gap: 6px var(--s3);
    margin: 0;
    align-items: center;
  }
  .layer dt {
    color: var(--ink-4);
    font-size: 12px;
  }
  .layer dd {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    color: var(--ink-3);
    min-width: 0;
  }
  .rev {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--seal-ink);
    text-decoration: none;
  }
  .sec {
    display: flex;
    align-items: center;
    gap: var(--s2);
    font-size: var(--t-lead);
  }
  .count {
    color: var(--ink-4);
    font-weight: 500;
    font-size: 13px;
  }
  .hint {
    color: var(--ink-3);
    margin-top: -6px;
  }
  .plain {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  .plain li {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--ink-3);
  }
  .plain b {
    color: var(--ink);
    font-weight: 500;
  }
  .bounds {
    display: grid;
    gap: var(--s3);
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 4px;
  }
  .chip {
    font-size: 12px;
    padding: 1px 8px;
    border-radius: 6px;
    box-shadow: inset 0 0 0 1px var(--rule-strong);
  }
  .who-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 380px), 1fr));
    gap: var(--s5) var(--s6);
    align-items: start;
  }
  .issuers {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: var(--s3);
  }
  .issuer {
    display: grid;
    gap: 6px;
    padding: var(--s3) var(--s4);
    border-radius: var(--r-md);
    border: 1px dashed var(--rule-strong);
  }
  .ihead {
    display: flex;
    align-items: center;
    gap: var(--s2);
  }
  .name {
    font-weight: 600;
  }
  .cat {
    font-size: 12px;
    color: var(--ink-3);
  }
  .url {
    font-size: 12px;
    color: var(--ink-3);
    overflow-wrap: anywhere;
  }
  .issuer dl {
    display: grid;
    grid-template-columns: 70px minmax(0, 1fr);
    gap: 2px var(--s2);
    margin: 0;
    font-size: 12px;
  }
  .issuer dt {
    color: var(--ink-4);
  }
  .issuer dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  @media (max-width: 1000px) {
    .page {
      grid-template-columns: 1fr;
    }
    .toc {
      display: none;
    }
    .layers {
      grid-template-columns: 1fr;
    }
  }
</style>
