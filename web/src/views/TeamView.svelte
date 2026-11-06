<script lang="ts">
  import { api, ApiError } from '../lib/api';
  import type { Me, TeamDetail, TeamInfo } from '../lib/types';
  import { teamsHref, transferHref, transfersHref, zoneHref } from '../lib/router.svelte';
  import { describePermissions } from '../lib/permissions';
  import { concreteTeams, renameRule, teamOrigin } from '../lib/teams';
  import { policyState } from '../lib/policy.svelte';
  import { teamFromText } from '../lib/team';
  import TeamsNav from '../components/teams/TeamsNav.svelte';
  import TeamKindBadge from '../components/teams/TeamKindBadge.svelte';
  import TransferItem from '../components/teams/TransferItem.svelte';
  import Matcher from '../components/policy/Matcher.svelte';
  import Icon from '../components/Icon.svelte';

  let { team }: { team: string } = $props();

  let d = $state<TeamDetail | null>(null);
  let me = $state<Me | null>(null);
  let teams = $state<TeamInfo[]>([]);
  let error = $state<string | null>(null);

  $effect(() => {
    api.team(team).then((x) => (d = x)).catch((e: Error) => (error = e instanceof ApiError && e.status === 404 ? `No team is named ${team}.` : e.message));
    api.me().then((m) => (me = m)).catch(() => (me = null));
    api.teams().then((l) => (teams = l.teams)).catch(() => (teams = []));
    void policyState.load();
  });

  const mine = $derived(!!me?.teams.includes(team));
  const total = $derived(d?.owned.reduce((n, z) => n + z.rrsets, 0) ?? 0);
  const reserved = $derived(d?.owned.reduce((n, z) => n + z.tombstones, 0) ?? 0);
  const byRole = $derived(
    (d?.roles ?? []).map((r) => ({ role: r, allows: d?.permissions ? describePermissions(d.permissions.filter((p) => p.role === r)) : [] })),
  );

  // Rename, for policy proposers: approved by another policy approver holding dns.ownership.approve on the team's record sets.
  const canRename = $derived(!!policyState.data?.me.can_propose);
  let renameOpen = $state(false);
  let renameTo = $state('');
  let renameNote = $state('');
  let renaming = $state(false);
  let renameError = $state<string | null>(null);
  const targets = $derived(concreteTeams(teams).filter((t) => t.kind !== 'store' && t.name !== team).map((t) => t.name).sort());

  async function rename() {
    renameError = null;
    if (!renameTo.trim() || !renameNote.trim()) {
      renameError = 'Choose the new team and say why: the approver reads it.';
      return;
    }
    renaming = true;
    try {
      const t = await api.renameTeam(team, renameTo.trim().toLowerCase(), renameNote.trim());
      window.location.hash = transferHref(t.id);
    } catch (e) {
      if (!(e instanceof ApiError && e.reason === 'reauth_required')) renameError = (e as Error).message;
    } finally {
      renaming = false;
    }
  }
</script>

<header class="head">
  <a class="back" href={teamsHref()}><Icon name="arrow" size={12} /> All teams</a>
  <p class="eyebrow">Team</p>
  <div class="title">
    <h1 class="mono">{team}</h1>
    {#if d}<TeamKindBadge kind={d.kind} />{/if}
    {#if mine}<span class="yours">{me?.default_team === team ? 'Your default team' : 'Your team'}</span>{/if}
  </div>
  {#if d}
    <p class="meta">{d.description ? d.description + ' · ' : ''}{teamOrigin(d)}{#if d.family} · {teamFromText(d.family)}{/if}</p>
    {#if d.warning}<p class="warn"><Icon name="alert" size={13} />{d.warning}</p>{/if}
  {/if}
</header>

<TeamsNav active="teams" />

{#if error}
  <div class="empty"><strong>This team could not be loaded</strong>{error}</div>
{:else if !d}
  <div class="skeleton bar"></div>
{:else}
  <div class="layout">
    <div class="main">
      <section>
        <h2>Record sets</h2>
        {#if d.owned.length === 0}
          <p class="dim">The team owns no record set in the zones you can read.</p>
        {:else}
          <p class="dim"><span class="num">{total.toLocaleString('en')}</span> record set{total === 1 ? '' : 's'}{#if reserved}, and <span class="num">{reserved}</span> deleted recently and still reserved for the team{/if}.</p>
          <table class="owned">
            <thead><tr><th>Zone</th><th class="n">Record sets</th><th class="n">Reserved</th></tr></thead>
            <tbody>
              {#each d.owned as z (z.zone)}
                <tr>
                  <td><a class="mono" href={zoneHref(z.zone, { owner: team, status: 'all' })}>{z.zone}</a></td>
                  <td class="n num">{z.rrsets.toLocaleString('en')}</td>
                  <td class="n num" title="Deleted recently: only this team may create them again until the reservation expires">{z.tombstones || '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </section>

      <section>
        <h2>Roles</h2>
        {#if byRole.length === 0}
          <p class="dim">No binding or API key names this team: its members get no role from it.</p>
        {:else}
          <ul class="roles">
            {#each byRole as r (r.role)}
              <li>
                <span class="tag mono">{r.role}</span>
                {#if r.allows.length}<ul class="allows">{#each r.allows as a (a)}<li>{a}</li>{/each}</ul>{/if}
              </li>
            {/each}
          </ul>
          {#if !d.permissions}<p class="dim small">What each role allows per zone is shown to the team's members and to policy readers.</p>{/if}
        {/if}
        {#if d.virtual_keys?.length}
          <p class="dim small">API keys acting for the team: {#each d.virtual_keys as k, i (k)}<span class="mono">{k}</span>{i < d.virtual_keys.length - 1 ? ', ' : ''}{/each}</p>
        {/if}
      </section>

      <section>
        <h2>Members</h2>
        {#if d.members}
          {#if d.members.groups?.length}
            <p class="lbl">Groups</p>
            <p class="chips">{#each d.members.groups as g (g)}<span class="tag mono">{g}</span>{/each}</p>
          {/if}
          {#if d.members.subjects?.length}
            <p class="lbl">Identities</p>
            <ul class="subjects">{#each d.members.subjects as m, i (i)}<li><Matcher {m} /></li>{/each}</ul>
          {/if}
          {#if !d.members.groups?.length && !d.members.subjects?.length}<p class="dim">The team declares no member.</p>{/if}
        {:else if d.kind === 'declared'}
          <p class="dim">Members are shown to policy readers.</p>
        {:else}
          <p class="dim">{d.kind === 'store' ? 'Nobody: no binding, API key or declaration names this team.' : 'Members come from the bindings and claims that name the team.'}</p>
        {/if}
      </section>
    </div>

    <aside class="side">
      <section>
        <div class="sh">
          <h2>Pending transfers</h2>
          <a class="small" href={transfersHref()}>All transfers</a>
        </div>
        {#if d.transfers.length === 0}
          <p class="dim small">No transfer from or to this team is waiting.</p>
        {:else}
          <ol class="tlist">{#each d.transfers as t (t.id)}<TransferItem {t} {me} />{/each}</ol>
        {/if}
        <p class="dim small">To move record sets of this team, select them in their zone, then Transfer.</p>
      </section>

      {#if canRename}
        <section class="rename">
          <h2>Rename</h2>
          <p class="dim small">
            Moves every record set and reservation of team {team}, in every zone, to another team. It must be approved by {renameRule}. The policy
            still names {team}: change its bindings in a policy revision too.
          </p>
          {#if !renameOpen}
            <button class="btn" type="button" onclick={() => (renameOpen = true)}><Icon name="transfer" size={14} />Rename {team}…</button>
          {:else}
            <label class="lbl" for="rename-to">New team</label>
            <input id="rename-to" class="in mono" list="rename-teams" bind:value={renameTo} placeholder="team name" autocomplete="off" />
            <datalist id="rename-teams">{#each targets as t (t)}<option value={t}></option>{/each}</datalist>
            <label class="lbl" for="rename-note">Why</label>
            <textarea id="rename-note" class="in" rows="3" bind:value={renameNote} placeholder="Reorganisation, pipeline replaced…"></textarea>
            <div class="actions">
              <button class="btn primary" type="button" disabled={renaming} onclick={rename}>{renaming ? 'Sending…' : 'Ask for the rename'}</button>
              <button class="btn quiet" type="button" onclick={() => { renameOpen = false; renameError = null; }}>Cancel</button>
            </div>
            {#if renameError}<p class="fail" role="alert">{renameError}</p>{/if}
          {/if}
        </section>
      {/if}
    </aside>
  </div>
{/if}

<style>
  .head {
    display: grid;
    gap: var(--s2);
    margin-bottom: var(--s5);
  }
  .back {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--ink-3);
    text-decoration: none;
    font-size: 13px;
  }
  .back :global(svg) {
    transform: scaleX(-1);
  }
  .back:hover {
    color: var(--seal-ink);
  }
  .title {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s3);
  }
  h1 {
    font-size: var(--t-h2);
    letter-spacing: -0.015em;
  }
  .yours {
    font-size: 13px;
    color: var(--seal-ink);
    font-weight: 500;
  }
  .meta,
  .dim {
    color: var(--ink-3);
  }
  .warn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--brass);
  }
  .bar {
    height: 200px;
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 360px;
    gap: var(--s8);
    align-items: start;
  }
  @media (max-width: 960px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }
  .main,
  .side {
    display: grid;
    gap: var(--s8);
    min-width: 0;
  }
  section {
    display: grid;
    gap: var(--s2);
    align-content: start;
  }
  h2 {
    font-size: var(--t-lead);
    font-weight: 600;
  }
  .sh {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: var(--s3);
  }
  .small {
    font-size: 12px;
  }
  a.small {
    color: var(--ink-3);
  }
  .owned {
    width: 100%;
    max-width: 640px;
    border-collapse: collapse;
  }
  .owned th {
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    color: var(--ink-3);
    text-transform: none;
    padding: var(--s1) var(--s2);
    border-bottom: 1px solid var(--rule);
  }
  .owned td {
    padding: var(--s2);
    border-bottom: 1px solid var(--rule-soft);
  }
  .owned .n {
    text-align: right;
    width: 110px;
  }
  .owned a {
    color: var(--ink);
    text-decoration: none;
    font-weight: 500;
  }
  .owned a:hover {
    color: var(--seal-ink);
  }
  .roles {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s3);
  }
  .allows {
    margin: 4px 0 0;
    padding-left: var(--s5);
    color: var(--ink-2);
  }
  .tag {
    display: inline-block;
    font-size: 12px;
    padding: 1px 7px;
    border-radius: 5px;
    background: var(--rule-soft);
    color: var(--ink-2);
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .subjects {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  .lbl {
    font-weight: 500;
    font-size: 12px;
    color: var(--ink-2);
  }
  .tlist {
    list-style: none;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--rule);
  }
  .rename {
    padding: var(--s4);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
  }
  .rename .btn {
    justify-self: start;
  }
  .in {
    width: 100%;
    padding: var(--s2);
    border: 1px solid var(--rule-strong);
    border-radius: var(--r-md);
    background: var(--sheet-raised);
    color: var(--ink);
    font: inherit;
  }
  .in.mono {
    font-family: var(--font-record);
  }
  .actions {
    display: flex;
    gap: var(--s2);
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .fail {
    color: var(--wax);
    font-size: 13px;
  }
</style>
