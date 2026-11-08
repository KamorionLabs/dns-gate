<script lang="ts">
  import { api, ApiError } from '../lib/api';
  import { scopeLabel, sortGrants } from '../lib/http';
  import type { OAuthGrant } from '../lib/types';
  import RelTime from './RelTime.svelte';
  import Icon from './Icon.svelte';

  let grants = $state<OAuthGrant[] | null>(null);
  let manage = $state(false);
  let error = $state<string | null>(null);
  let busy = $state<string | null>(null);
  let filterKind = $state<'client' | 'subject'>('client');
  let filterValue = $state('');
  let filtered = $state(false);
  let notice = $state<string | null>(null);

  function load(filter = false) {
    error = null;
    const f = filter && filterValue.trim() ? { [filterKind]: filterValue.trim() } : {};
    api
      .oauthGrants(f)
      .then((l) => {
        grants = sortGrants(l.grants);
        manage = l.manage;
        filtered = Object.keys(f).length > 0;
      })
      .catch((e: Error) => (error = e.message));
  }

  $effect(() => load());

  async function revoke(g: OAuthGrant) {
    if (!confirm(`Revoke the access of ${g.client_name}${filtered ? ' for ' + (g.subject_name || g.subject) : ''}? It stops working within a minute.`)) return;
    busy = g.id;
    try {
      await api.revokeGrant(g.id);
      notice = `${g.client_name} no longer has access.`;
      load(filtered);
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = null;
    }
  }

  async function revokeAll() {
    const value = filterValue.trim();
    if (!value || !confirm(`Revoke every grant of the ${filterKind} ${value}?`)) return;
    busy = 'all';
    try {
      const r = await api.revokeGrants({ [filterKind]: value });
      notice = `${r.revoked} grant${r.revoked === 1 ? '' : 's'} revoked.`;
      load(true);
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = null;
    }
  }
</script>

<p class="lead">Applications you allowed to act for you on this gate, with your permissions limited to what you accepted. Revoke one to cut its access.</p>

{#if manage}
  <form class="admin" onsubmit={(e) => { e.preventDefault(); load(true); }}>
    <label for="grant-filter">Administration</label>
    <select bind:value={filterKind} aria-label="Filter by">
      <option value="client">Client id</option>
      <option value="subject">User (issuer:id)</option>
    </select>
    <input id="grant-filter" class="mono" bind:value={filterValue} placeholder={filterKind === 'client' ? 'skopea-acme' : 'identity-center:alice@example.com'} />
    <button type="submit" class="btn">Show</button>
    {#if filtered}
      <button type="button" class="btn danger" disabled={busy !== null} onclick={revokeAll}><Icon name="trash" size={14} />Revoke all</button>
      <button type="button" class="btn" onclick={() => { filterValue = ''; load(); }}>Mine</button>
    {/if}
  </form>
{/if}

{#if notice}<p class="notice" role="status">{notice}</p>{/if}

{#if error}
  <div class="empty"><strong>Connected applications could not be loaded</strong>{error}</div>
{:else if !grants}
  <div class="skeleton block"></div>
{:else if grants.length === 0}
  <div class="empty"><strong>No connected application</strong>{filtered ? 'No grant matches.' : 'You have not allowed any application yet.'}</div>
{:else}
  <ul class="grants">
    {#each grants as g (g.id)}
      <li class:inactive={g.status !== 'active'}>
        <div class="who">
          <strong>{g.client_name}</strong>
          <span class="mono id">{g.client_id}</span>
          {#if filtered}<span class="user">{g.subject_name || g.subject}</span>{/if}
        </div>
        <ul class="scopes">
          {#each g.scopes as s (s)}<li title={s}>{scopeLabel(s)}</li>{/each}
        </ul>
        <div class="when">
          {#if g.status === 'active'}
            Used <RelTime iso={g.last_used_at} />, expires <RelTime iso={g.expires_at} />
          {:else if g.status === 'revoked'}
            Revoked <RelTime iso={g.revoked_at} />
          {:else}
            Expired <RelTime iso={g.expires_at} />
          {/if}
        </div>
        {#if g.status === 'active'}
          <button type="button" class="btn danger" disabled={busy !== null} onclick={() => revoke(g)}><Icon name="x" size={14} />Revoke</button>
        {/if}
      </li>
    {/each}
  </ul>
{/if}

<style>
  .lead {
    color: var(--ink-2);
    font-size: var(--t-lead);
  }
  .block {
    height: 120px;
  }
  .admin {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
  }
  .admin label {
    color: var(--ink-3);
    font-size: 13px;
    margin-right: var(--s2);
  }
  .admin input {
    flex: 1 1 220px;
    min-width: 0;
  }
  .notice {
    color: var(--stamp);
  }
  .grants {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s3);
  }
  .grants > li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: var(--s2) var(--s4);
    padding: var(--s3) var(--s4);
    border: 1px solid var(--rule-soft);
    border-radius: var(--r-md);
    background: var(--sheet-raised);
  }
  .grants > li.inactive {
    opacity: 0.7;
  }
  .who {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: var(--s2);
  }
  .id,
  .user,
  .when {
    color: var(--ink-3);
    font-size: 13px;
  }
  .scopes {
    grid-column: 1;
    margin: 0;
    padding: 0;
    list-style: none;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .scopes li {
    font-size: 12px;
    padding: 1px 8px;
    border-radius: 6px;
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .when {
    grid-column: 1;
  }
  .grants > li > .btn {
    grid-column: 2;
    grid-row: 1 / span 3;
    align-self: center;
  }
  .btn.danger {
    color: var(--wax);
  }
  .btn.danger:hover {
    border-color: color-mix(in srgb, var(--wax) 40%, transparent);
  }
  @media (max-width: 560px) {
    .grants > li {
      grid-template-columns: minmax(0, 1fr);
    }
    .grants > li > .btn {
      grid-column: 1;
      grid-row: auto;
      justify-self: start;
    }
  }
</style>
