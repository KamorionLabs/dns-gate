<script lang="ts">
  import type { Binding, Group, Role, VirtualKey } from '../../lib/types';
  import LayerTag from './LayerTag.svelte';
  import Matcher from './Matcher.svelte';
  import RuleLine from './RuleLine.svelte';
  import RelTime from '../RelTime.svelte';

  type Layered<T> = { layer: 'base' | 'managed'; rev?: string; item: T };
  let {
    kind,
    groups = [],
    roles = [],
    bindings = [],
    keys = [],
  }: {
    kind: 'groups' | 'roles' | 'bindings' | 'keys';
    groups?: Layered<[string, Group]>[];
    roles?: Layered<[string, Role]>[];
    bindings?: Layered<Binding>[];
    keys?: Layered<VirtualKey>[];
  } = $props();

  const shortHash = (h: string) => (h.length > 16 ? h.slice(0, 8) + '…' + h.slice(-6) : h);
</script>

<ul class="items">
  {#if kind === 'groups'}
    {#each groups as { layer, rev, item: [name, g] } (layer + name)}
      <li class={layer}>
        <div class="head"><span class="name mono">{name}</span><LayerTag {layer} {rev} /></div>
        {#if g.description}<p class="desc">{g.description}</p>{/if}
        <ul class="members">{#each g.members as m, i (i)}<li><Matcher {m} /></li>{/each}</ul>
      </li>
    {:else}<li class="none">No groups.</li>{/each}
  {:else if kind === 'roles'}
    {#each roles as { layer, rev, item: [name, r] } (layer + name)}
      <li class={layer}>
        <div class="head">
          <span class="name mono">{name}</span><LayerTag {layer} {rev} />
          <span class="flags">
            {#if r.rebase_on_save}<span class="flag">rebase on save</span>{/if}
            {#if r.ephemeral_ttl}<span class="flag">ephemeral {r.ephemeral_ttl}</span>{/if}
            {#if r.max_changes_per_request}<span class="flag">≤ {r.max_changes_per_request} changes / request</span>{/if}
          </span>
        </div>
        {#if r.description}<p class="desc">{r.description}</p>{/if}
        <div class="rules">{#each r.rules as rule, i (i)}<RuleLine {rule} />{/each}</div>
      </li>
    {:else}<li class="none">No roles.</li>{/each}
  {:else if kind === 'bindings'}
    {#each bindings as { layer, rev, item: b }, i (layer + i)}
      <li class="{layer} binding">
        <div class="grant">
          <span class="role mono">{b.role}</span><span class="at">@</span><span class="team">{b.team}</span>
          <span class="arrow" aria-label="granted to">←</span>
          <span class="who">
            {#each b.groups ?? [] as g (g)}<span class="grp mono">{g}</span>{/each}
            {#each b.subjects ?? [] as m, k (k)}<Matcher {m} />{/each}
          </span>
        </div>
        <LayerTag {layer} {rev} />
      </li>
    {:else}<li class="none">No bindings.</li>{/each}
  {:else}
    {#each keys as { layer, rev, item: k } (layer + k.id)}
      <li class={layer}>
        <div class="head">
          <span class="name mono">{k.id}</span><LayerTag {layer} {rev} />
          <span class="flags">
            {#if k.expires_at}<span class="flag">expires <RelTime iso={k.expires_at} /></span>{:else}<span class="flag warn">never expires</span>{/if}
          </span>
        </div>
        {#if k.description}<p class="desc">{k.description}</p>{/if}
        <dl class="kv">
          <dt>app id</dt><dd class="mono">{k.app_id}</dd>
          <dt>key hash</dt><dd class="mono" title={k.key_sha256}>sha256:{shortHash(k.key_sha256)}</dd>
          <dt>grants</dt><dd class="mono">{k.roles.join(', ')} @ {k.teams.join(', ')}</dd>
          {#if k.allowed_cidrs?.length}<dt>from</dt><dd class="mono">{k.allowed_cidrs.join(', ')}</dd>{/if}
        </dl>
      </li>
    {:else}<li class="none">No virtual keys.</li>{/each}
  {/if}
</ul>

<style>
  .items {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  .items > li {
    position: relative;
    display: grid;
    gap: var(--s2);
    padding: var(--s3) var(--s4) var(--s3) var(--s5);
    border-radius: var(--r-md);
    background: var(--sheet);
    border: 1px solid var(--rule-soft);
  }
  .items > li::before {
    content: '';
    position: absolute;
    left: 0;
    top: 8px;
    bottom: 8px;
    width: 3px;
    border-radius: 0 2px 2px 0;
  }
  .items > li.managed::before {
    background: var(--seal-ink);
  }
  .items > li.base {
    background: transparent;
  }
  .items > li.base::before {
    background: repeating-linear-gradient(180deg, var(--ink-4) 0 3px, transparent 3px 6px);
  }
  .items > li.none {
    color: var(--ink-4);
    background: transparent;
    border-style: dashed;
  }
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
  }
  .name {
    font-weight: 600;
    font-size: 13px;
  }
  .desc {
    color: var(--ink-3);
    margin-top: -4px;
  }
  .flags {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-left: auto;
  }
  .flag {
    font-size: 11.5px;
    color: var(--ink-3);
    padding: 0 6px;
    border-radius: 3px;
    background: var(--rule-soft);
  }
  .flag.warn {
    color: var(--brass);
    background: var(--brass-wash);
  }
  .members {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  .rules {
    display: grid;
    gap: 4px;
  }
  .binding {
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
  }
  .grant {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 4px 6px;
  }
  .role {
    font-weight: 600;
  }
  .at {
    color: var(--ink-4);
  }
  .team {
    font-weight: 600;
    color: var(--seal-ink);
  }
  .arrow {
    color: var(--ink-4);
    padding: 0 4px;
  }
  .who {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px 8px;
    align-items: baseline;
  }
  .grp {
    font-size: 12px;
    padding: 0 6px;
    border-radius: 10px;
    box-shadow: inset 0 0 0 1px var(--rule-strong);
  }
  .kv {
    display: grid;
    grid-template-columns: 80px minmax(0, 1fr);
    gap: 2px var(--s3);
    margin: 0;
    font-size: 12px;
  }
  .kv dt {
    color: var(--ink-4);
  }
  .kv dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
</style>
