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

  type L<T> = { layer: 'base' | 'managed'; rev?: string; item: T };

  function layered(p: EffectivePolicy) {
    const rev = p.active?.id;
    const g: L<[string, Group]>[] = [
      ...Object.entries(p.base.document.groups).map((item) => ({ layer: 'base' as const, item })),
      ...Object.entries(p.managed?.groups ?? {}).map((item) => ({ layer: 'managed' as const, rev, item })),
    ];
    const r: L<[string, Role]>[] = [
      ...Object.entries(p.base.document.roles).map((item) => ({ layer: 'base' as const, item })),
      ...Object.entries(p.managed?.roles ?? {}).map((item) => ({ layer: 'managed' as const, rev, item })),
    ];
    const b: L<Binding>[] = [
      ...p.base.document.bindings.map((item) => ({ layer: 'base' as const, item })),
      ...(p.managed?.bindings ?? []).map((item) => ({ layer: 'managed' as const, rev, item })),
    ];
    const k: L<VirtualKey>[] = [
      ...p.base.document.virtual_keys.map((item) => ({ layer: 'base' as const, item })),
      ...(p.managed?.virtual_keys ?? []).map((item) => ({ layer: 'managed' as const, rev, item })),
    ];
    return { g, r, b, k };
  }

  const sections = [
    ['layers', 'Layers'],
    ['bindings', 'Bindings'],
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
    <div class="page">
      <aside class="toc" aria-label="On this page">
        {#each sections as [id, label] (id)}<a href={'#/policy'} onclick={(e) => { e.preventDefault(); document.getElementById('sec-' + id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }}>{label}</a>{/each}
      </aside>

      <div class="content">
        <section id="sec-layers" class="layers">
          <article class="layer base">
            <header><Icon name="lock" size={15} /><h2>Base layer</h2><LayerTag layer="base" /></header>
            <p class="lead">Loaded from the configuration file. Changes go through Git and a redeploy, never through this console. Issuers, protected records, bounds and every policy.* grant live here.</p>
            <dl>
              <dt>Config hash</dt><dd><CopyText text={p.base.config_hash.replace(/^sha256:/, '').slice(0, 16)} label="config hash" /></dd>
              <dt>Loaded</dt><dd><RelTime iso={p.base.loaded_at} /></dd>
              <dt>Zones</dt><dd class="mono">{p.base.zones.join(', ')}</dd>
            </dl>
          </article>
          <article class="layer managed">
            <header><Icon name="shield" size={15} /><h2>Managed layer</h2>{#if p.active}<LayerTag layer="managed" rev={p.active.id} />{/if}</header>
            {#if p.active}
              <p class="lead">“{p.active.comment}”</p>
              <dl>
                <dt>Proposed by</dt><dd><ActorChip actor={p.active.author} /> <RelTime iso={p.active.created_at} /></dd>
                {#if p.active.activated_by}<dt>Activated by</dt><dd><ActorChip actor={p.active.activated_by} /> <RelTime iso={p.active.activated_at} /></dd>{/if}
                <dt>Revision</dt><dd><a class="rev mono" href={proposalHref(p.active.id)}>{p.active.id} <Icon name="arrow" size={12} /></a></dd>
              </dl>
            {:else}
              <p class="lead">No managed revision is active: only the base layer applies.</p>
            {/if}
          </article>
        </section>

        <section id="sec-bindings">
          <h2 class="sec">Bindings <span class="count num">{L.b.length}</span></h2>
          <p class="hint">A binding grants a role, acting for a team, to groups or subjects. The team owns what it creates.</p>
          <DocItems kind="bindings" bindings={L.b} />
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
  {/snippet}
</PolicyFrame>

<style>
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
    font-size: 12.5px;
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
    border-radius: 10px;
    box-shadow: inset 0 0 0 1px var(--rule-strong);
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
    font-size: 11.5px;
    color: var(--ink-3);
  }
  .url {
    font-size: 11.5px;
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
