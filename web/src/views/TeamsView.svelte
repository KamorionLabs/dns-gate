<script lang="ts">
  import { api } from '../lib/api';
  import type { Me, TeamList } from '../lib/types';
  import { router, teamHref } from '../lib/router.svelte';
  import { teamLabel } from '../lib/team';
  import { teamOrigin } from '../lib/teams';
  import TeamsNav from '../components/teams/TeamsNav.svelte';
  import TeamKindBadge from '../components/teams/TeamKindBadge.svelte';
  import Icon from '../components/Icon.svelte';

  let list = $state<TeamList | null>(null);
  let me = $state<Me | null>(null);
  let error = $state<string | null>(null);

  $effect(() => {
    api.teams().then((l) => (list = l)).catch((e: Error) => (error = e.message));
    api.me().then((m) => (me = m)).catch(() => (me = null));
  });

  const q = $derived((router.params.get('q') ?? '').toLowerCase());
  const mineOnly = $derived(router.params.get('mine') === '1');
  const linkable = (name: string) => !name.endsWith('*');
  const shown = $derived(
    (list?.teams ?? []).filter(
      (t) =>
        (!mineOnly || me?.teams.includes(t.name)) &&
        (!q || [t.name, t.description ?? '', ...t.roles].join(' ').toLowerCase().includes(q)),
    ),
  );
  const total = $derived((list?.teams ?? []).reduce((n, t) => n + t.rrsets, 0));
</script>

<header class="head">
  <p class="eyebrow">Teams</p>
  <h1>Who owns the record sets</h1>
  <p class="meta">
    Every record set written or adopted through the gate belongs to a team, and only its members change it.
    {#if list}
      {list.strict ? 'Teams are declared in the policy.' : 'The policy has no teams block yet: the teams it names are declared on their own.'}
    {/if}
  </p>
</header>

<TeamsNav active="teams" />

{#if error}
  <div class="empty"><strong>Teams could not be loaded</strong>{error}</div>
{:else}
  <div class="toolbar">
    <label class="field search">
      <Icon name="search" size={14} />
      <span class="sr-only">Search teams</span>
      <input type="search" placeholder="Team, description, role" value={router.params.get('q') ?? ''} oninput={(e) => router.setParams({ q: e.currentTarget.value || undefined })} />
    </label>
    {#if me?.teams.length}
      <label class="check">
        <input type="checkbox" checked={mineOnly} onchange={(e) => router.setParams({ mine: e.currentTarget.checked ? '1' : undefined })} />
        My teams only
      </label>
    {/if}
    {#if list}<span class="sum dim"><span class="num">{list.teams.length}</span> teams · <span class="num">{total.toLocaleString('en')}</span> record sets owned in the zones you can read</span>{/if}
  </div>

  {#if !list}
    <div class="skeleton bar"></div>
  {:else if shown.length === 0}
    <div class="empty"><strong>No team matches</strong>{mineOnly ? 'You are not a member of a team matching this search.' : 'Try another search.'}</div>
  {:else}
    <ol class="teams">
      {#each shown as t (t.kind + t.name + (t.issuer ?? ''))}
        {@const mine = !!me?.teams.includes(t.name)}
        <li class={t.kind} class:mine>
          {#if linkable(t.name)}<a class="cover" href={teamHref(t.name)} aria-label="Open team {t.name}"></a>{/if}
          <div class="ident">
            <h2 class="mono">{t.kind === 'family' && t.family ? teamLabel(t.name, t.family) : t.name}</h2>
            <TeamKindBadge kind={t.kind} />
            {#if mine}<span class="yours" title="You are a member of this team">{me?.default_team === t.name ? 'Your default team' : 'Your team'}</span>{/if}
          </div>
          <p class="desc">{t.description || teamOrigin(t)}</p>
          <div class="meta">
            {#if t.description}<span>{teamOrigin(t)}</span>{/if}
            {#if t.roles.length}
              <span class="roles">{#each t.roles as r (r)}<span class="tag mono">{r}</span>{/each}</span>
            {:else}
              <span class="dim">No role</span>
            {/if}
            {#if t.virtual_keys?.length}<span class="dim">{t.virtual_keys.length} API key{t.virtual_keys.length === 1 ? '' : 's'}</span>{/if}
          </div>
          <div class="owned">
            {#if t.rrsets}<span class="num big">{t.rrsets.toLocaleString('en')}</span><span class="dim">record set{t.rrsets === 1 ? '' : 's'}</span>
            {:else}<span class="dim">No record set</span>{/if}
          </div>
          {#if t.warning}<p class="warn"><Icon name="alert" size={13} />{t.warning}</p>{/if}
        </li>
      {/each}
    </ol>
  {/if}
{/if}

<style>
  .head {
    display: grid;
    gap: var(--s2);
    margin-bottom: var(--s5);
  }
  h1 {
    font-size: var(--t-h2);
    letter-spacing: -0.015em;
  }
  .meta,
  .dim {
    color: var(--ink-3);
  }
  .head .meta {
    max-width: 80ch;
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s3) var(--s5);
    margin-bottom: var(--s4);
  }
  .search {
    width: min(320px, 100%);
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--ink-2);
    cursor: pointer;
  }
  .sum {
    margin-left: auto;
    font-size: 12px;
  }
  .bar {
    height: 200px;
  }
  .teams {
    list-style: none;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--rule);
  }
  .teams li {
    position: relative;
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    grid-template-areas: 'ident owned' 'desc owned' 'meta owned' 'warn warn';
    gap: 4px var(--s6);
    padding: var(--s4);
    border-bottom: 1px solid var(--rule);
    transition: background-color 100ms var(--ease-out);
  }
  .teams li:hover {
    background: var(--sheet);
  }
  .teams li.mine {
    box-shadow: inset 3px 0 0 var(--seal-ink);
  }
  .teams li.store {
    box-shadow: inset 3px 0 0 var(--brass);
  }
  .cover {
    position: absolute;
    inset: 0;
  }
  .teams li > :not(.cover) {
    position: relative;
    pointer-events: none;
  }
  .ident {
    grid-area: ident;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
  }
  h2 {
    font-size: var(--t-lead);
    font-weight: 600;
  }
  .yours {
    font-size: 12px;
    color: var(--seal-ink);
    font-weight: 500;
  }
  .desc {
    grid-area: desc;
    color: var(--ink-2);
  }
  .teams .meta {
    grid-area: meta;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s1) var(--s4);
    font-size: 12px;
  }
  .roles {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .tag {
    font-size: 12px;
    padding: 1px 7px;
    border-radius: 5px;
    background: var(--rule-soft);
    color: var(--ink-2);
  }
  .owned {
    grid-area: owned;
    display: grid;
    justify-items: end;
    align-content: center;
    font-size: 12px;
  }
  .big {
    font-size: var(--t-h3);
    font-weight: 600;
    color: var(--ink);
  }
  .warn {
    grid-area: warn;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--brass);
    font-size: 12px;
  }
  @media (max-width: 720px) {
    .teams li {
      grid-template-columns: 1fr;
      grid-template-areas: 'ident' 'desc' 'meta' 'owned' 'warn';
    }
    .owned {
      justify-items: start;
      grid-auto-flow: column;
      gap: 6px;
      justify-content: start;
    }
    .sum {
      margin-left: 0;
    }
  }
</style>
