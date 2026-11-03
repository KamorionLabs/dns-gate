<script lang="ts">
  import type { Binding, DelegatedOwner, Group, Role, VirtualKey } from '../../lib/types';
  import LayerTag from './LayerTag.svelte';
  import Matcher from './Matcher.svelte';
  import RuleLine from './RuleLine.svelte';
  import RelTime from '../RelTime.svelte';
  import { teamFromText, teamLabel } from '../../lib/team';
  import { humanDuration } from '../../lib/duration';
  import { bindingAllows, type Layer } from '../../lib/access';

  type Layered<T> = { layer: Layer; rev?: string; name?: string; owner?: DelegatedOwner; item: T };
  let {
    kind,
    groups = [],
    roles = [],
    bindings = [],
    keys = [],
    roleDefs = {},
  }: {
    kind: 'groups' | 'roles' | 'bindings' | 'keys';
    groups?: Layered<[string, Group]>[];
    roles?: Layered<[string, Role]>[];
    bindings?: Layered<Binding>[];
    keys?: Layered<VirtualKey>[];
    /** Roles a binding can refer to (base and managed), to say what it allows. */
    roleDefs?: Record<string, Role>;
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
    {#each roles as { layer, rev, owner, item: [name, r] } (layer + name)}
      <li class={layer}>
        <div class="head">
          <span class="name mono">{name}</span><LayerTag {layer} {rev} {owner} />
          <span class="flags">
            {#if r.rebase_on_save}<span class="flag">rebase on save</span>{/if}
            {#if r.ephemeral_ttl}<span class="flag" title="Records it creates are removed after {humanDuration(r.ephemeral_ttl)}">ephemeral, {humanDuration(r.ephemeral_ttl)}</span>{/if}
            {#if r.max_changes_per_request}<span class="flag">≤ {r.max_changes_per_request} changes / request</span>{/if}
          </span>
        </div>
        {#if r.description}<p class="desc">{r.description}</p>{/if}
        <div class="rules">{#each r.rules as rule, i (i)}<RuleLine {rule} />{/each}</div>
      </li>
    {:else}<li class="none">No roles.</li>{/each}
  {:else if kind === 'bindings'}
    {#each bindings as { layer, rev, name, owner, item: b }, i (layer + i)}
      <li class="{layer} binding">
        <div class="bmain">
        {#if name}<div class="bname mono">{name}</div>{/if}
        <div class="grant">
          <span class="role mono">{b.role}</span><span class="at">@</span><span class="team" class:derived={!!b.team_from} title={b.team_from ? teamFromText(b.team_from) : undefined}>{teamLabel(b.team, b.team_from)}</span>
          <span class="arrow" aria-label="granted to">←</span>
          <span class="who">
            {#each b.groups ?? [] as g (g)}<span class="grp mono">{g}</span>{/each}
            {#each b.subjects ?? [] as m, k (k)}<Matcher {m} />{/each}
          </span>
        </div>
        {#if b.team_from}<p class="desc mono derive">{teamFromText(b.team_from)}</p>{/if}
        {#if roleDefs[b.role]}
          {@const allows = bindingAllows(b, roleDefs)}
          <details class="allows">
            <summary>What it allows</summary>
            {#if allows.length}
              <ul>{#each allows as a (a)}<li>{a}</li>{/each}</ul>
            {:else}
              <p class="desc">Nothing: the role has no rule with an action this console knows.</p>
            {/if}
            <p class="desc small">Records created through it are owned by team <b>{teamLabel(b.team, b.team_from)}</b>{#if roleDefs[b.role]?.ephemeral_ttl} and removed after {humanDuration(roleDefs[b.role]?.ephemeral_ttl)}{/if}.</p>
          </details>
        {:else}
          <p class="desc small">Role <span class="mono">{b.role}</span> is not defined.</p>
        {/if}
        </div>
        <LayerTag {layer} {rev} {owner} />
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
  .bname {
    font-size: 11.5px;
    color: var(--ink-3);
    margin-bottom: 2px;
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
  .team.derived {
    font-family: var(--font-record);
    cursor: help;
  }
  .bmain {
    display: grid;
    gap: 2px;
    min-width: 0;
  }
  .derive {
    margin-top: 0;
    font-size: 11.5px;
    overflow-wrap: anywhere;
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
  .binding {
    align-items: start;
  }
  .allows {
    margin-top: 4px;
  }
  .allows summary {
    width: max-content;
    cursor: pointer;
    color: var(--seal-ink);
    font-size: 12.5px;
    font-weight: 500;
    border-radius: var(--r-sm);
  }
  .allows ul {
    margin: var(--s1) 0;
    padding-left: var(--s4);
    color: var(--ink-2);
  }
  .small {
    font-size: 12px;
    margin-top: 0;
  }
  .small b {
    color: var(--ink-2);
    font-weight: 600;
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
