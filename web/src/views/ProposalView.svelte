<script lang="ts">
  import { api, ApiError, exportURL } from '../lib/api';
  import type { EffectivePolicy, ImpactItem, Me, RevisionDetail } from '../lib/types';
  import { policyHref, proposalHref } from '../lib/router.svelte';
  import { policyState } from '../lib/policy.svelte';
  import { toYAML } from '../lib/yaml';
  import PolicyFrame from '../components/policy/PolicyFrame.svelte';
  import RevisionBadge from '../components/policy/RevisionBadge.svelte';
  import DiffView from '../components/policy/DiffView.svelte';
  import ActorChip from '../components/ActorChip.svelte';
  import RelTime from '../components/RelTime.svelte';
  import Icon from '../components/Icon.svelte';

  let { id }: { id: string } = $props();

  let rev = $state<RevisionDetail | null>(null);
  let error = $state<string | null>(null);
  let me = $state<Me | null>(null);
  let note = $state('');
  let busy = $state<string | null>(null);
  let actionError = $state<string | null>(null);
  let showDoc = $state(false);

  $effect(() => {
    api.revision(id).then((r) => (rev = r)).catch((e: Error) => (error = e.message));
    api.me().then((m) => (me = m)).catch(() => (me = null));
  });

  const order: ImpactItem['kind'][] = ['loss', 'warning', 'gain'];
  const impact = $derived(rev ? [...rev.impact].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind)) : []);
  const mine = $derived(!!rev && !!me && rev.author.subject === me.subject);

  function can(p: EffectivePolicy) {
    const r = rev;
    if (!r || !p.settings.editable) return { decide: false, activate: false, rollback: false };
    return {
      decide: p.me.can_approve && r.status === 'proposed' && !mine,
      activate:
        (r.status === 'approved' && p.me.can_approve) ||
        (r.status === 'proposed' && !p.settings.require_approval && p.me.can_propose),
      rollback: r.status === 'superseded' && p.me.can_propose,
    };
  }

  async function act(kind: 'approve' | 'reject' | 'activate' | 'rollback') {
    if (!rev) return;
    if (kind === 'reject' && !note.trim()) {
      actionError = 'Say why you reject it: the author will read it.';
      return;
    }
    busy = kind;
    actionError = null;
    try {
      const r =
        kind === 'approve' ? await api.approve(rev.id, note.trim())
        : kind === 'reject' ? await api.reject(rev.id, note.trim())
        : kind === 'activate' ? await api.activate(rev.id)
        : await api.rollback(rev.id);
      note = '';
      await policyState.load(true);
      if (kind === 'rollback') window.location.hash = proposalHref(r.id);
      else rev = r;
    } catch (e) {
      if (!(e instanceof ApiError && e.reason === 'reauth_required')) actionError = (e as Error).message;
    } finally {
      busy = null;
    }
  }
</script>

<PolicyFrame tab="proposals" title="Revision {id}">
  {#snippet children(p)}
    {#if error}
      <div class="empty"><strong>This revision could not be loaded</strong>{error}</div>
    {:else if !rev}
      <div class="skeleton bar"></div>
    {:else}
      {@const c = can(p)}
      <a class="back" href={policyHref('proposals')}><Icon name="arrow" size={12} /> All revisions</a>

      <div class="layout">
        <div class="main">
          <header class="rhead">
            <div class="line">
              <span class="mono id">{rev.id}</span>
              <RevisionBadge status={rev.status} stale={rev.stale} />
            </div>
            <blockquote>{rev.comment ?? 'No comment'}</blockquote>
            <div class="by">
              <ActorChip actor={rev.author} /> proposed <RelTime iso={rev.created_at} />
              {#if rev.parent_id}<span class="dim">· based on <a class="mono" href={proposalHref(rev.parent_id)}>{rev.parent_id}</a></span>{/if}
            </div>
            {#if rev.stale}
              <p class="stale"><Icon name="alert" size={14} /> The policy changed since this revision was drafted (active is now {p.active?.id ?? 'none'}). The diff and impact below are computed against the active revision; check nothing is undone by accident.</p>
            {/if}
          </header>

          <section>
            <h2>Impact</h2>
            {#if impact.length === 0}
              <p class="dim">No change in effective permissions.</p>
            {:else}
              <ul class="impact">
                {#each impact as it, i (i)}
                  <li class={it.kind}>
                    <span class="sign" aria-hidden="true">{it.kind === 'gain' ? '+' : it.kind === 'loss' ? '−' : '!'}</span>
                    <div>
                      <p class="msg">{it.message}</p>
                      <p class="detail mono">
                        {it.who}{#if it.role} · {it.role}{/if}{#if it.zones?.length} · {it.zones.join(', ')}{/if}{#if it.actions?.length} · {it.actions.join(', ')}{/if}
                      </p>
                    </div>
                    <span class="kind">{it.kind === 'gain' ? 'gains' : it.kind === 'loss' ? 'loses' : 'warning'}</span>
                  </li>
                {/each}
              </ul>
            {/if}
          </section>

          <section>
            <div class="sh">
              <h2>Changes</h2>
              <a class="dl" href={exportURL(rev.id)} download="{rev.id}.yaml"><Icon name="download" size={14} />Export YAML</a>
            </div>
            {#if rev.diff_yaml.trim()}<DiffView diff={rev.diff_yaml} />{:else}<p class="dim">Identical to its parent.</p>{/if}
            <button class="link" type="button" onclick={() => (showDoc = !showDoc)}>{showDoc ? 'Hide' : 'Show'} the full managed document</button>
            {#if showDoc}<pre class="yaml mono">{toYAML(rev.document)}</pre>{/if}
          </section>
        </div>

        <aside class="side">
          <section class="decisions">
            <h2>Review</h2>
            <ol class="trail">
              <li class="done"><span class="node"></span><div><ActorChip actor={rev.author} quiet /> proposed <RelTime iso={rev.created_at} /></div></li>
              {#each rev.approvals ?? [] as a, i (i)}
                <li class={a.decision}>
                  <span class="node"></span>
                  <div>
                    <ActorChip actor={a.by} quiet /> {a.decision === 'approve' ? 'approved' : 'rejected'} <RelTime iso={a.at} />
                    {#if a.comment}<p class="say">“{a.comment}”</p>{/if}
                  </div>
                </li>
              {/each}
              {#if rev.activated_at && rev.activated_by}
                <li class="activated"><span class="node"></span><div><ActorChip actor={rev.activated_by} quiet /> activated <RelTime iso={rev.activated_at} /></div></li>
              {:else if rev.status === 'proposed'}
                <li class="wait"><span class="node"></span><div class="dim">{p.settings.require_approval ? 'Waiting for another policy approver' : 'Waiting for activation'}</div></li>
              {:else if rev.status === 'approved'}
                <li class="wait"><span class="node"></span><div class="dim">Approved, not active yet</div></li>
              {/if}
            </ol>

            {#if c.decide}
              <label class="lbl" for="note">Comment <span class="dim">(required to reject)</span></label>
              <textarea id="note" class="in" rows="3" bind:value={note} placeholder="What you checked, or what must change"></textarea>
              <div class="actions">
                <button class="btn approve" type="button" disabled={!!busy} onclick={() => act('approve')}><Icon name="check" size={14} />{busy === 'approve' ? 'Approving…' : 'Approve'}</button>
                <button class="btn reject" type="button" disabled={!!busy} onclick={() => act('reject')}>{busy === 'reject' ? 'Rejecting…' : 'Reject'}</button>
              </div>
            {:else if mine && rev.status === 'proposed' && p.settings.require_approval}
              <p class="dim small">You wrote this revision: another policy approver has to review it.</p>
            {/if}
            {#if c.activate}
              <button class="btn primary wide" type="button" disabled={!!busy} onclick={() => act('activate')}><Icon name="shield" size={14} />{busy === 'activate' ? 'Activating…' : 'Activate now'}</button>
              <p class="dim small">Takes effect on the next request; the current active revision becomes history.</p>
            {/if}
            {#if c.rollback}
              <button class="btn wide" type="button" disabled={!!busy} onclick={() => act('rollback')}><Icon name="undo" size={14} />Roll back to this revision</button>
              <p class="dim small">Creates a new proposal with this document; it goes through review like any other.</p>
            {/if}
            {#if actionError}<p class="fail">{actionError}</p>{/if}
          </section>
        </aside>
      </div>
    {/if}
  {/snippet}
</PolicyFrame>

<style>
  .back {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-bottom: var(--s4);
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
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    gap: var(--s8);
    align-items: start;
  }
  .main {
    display: grid;
    gap: var(--s6);
    min-width: 0;
  }
  .rhead {
    display: grid;
    gap: var(--s2);
  }
  .line {
    display: flex;
    align-items: center;
    gap: var(--s2);
  }
  .id {
    font-weight: 600;
  }
  blockquote {
    margin: 0;
    font-size: var(--t-h3);
    line-height: 1.4;
    color: var(--ink);
    text-wrap: pretty;
  }
  .by {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    color: var(--ink-3);
  }
  .by a {
    color: var(--ink-2);
  }
  .stale {
    display: flex;
    gap: var(--s2);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--wax-wash);
    color: var(--wax);
  }
  .stale :global(svg) {
    margin-top: 2px;
  }
  section {
    display: grid;
    gap: var(--s3);
  }
  h2 {
    font-size: var(--t-lead);
  }
  .sh {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .dl {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--ink-3);
    font-size: 13px;
    text-decoration: none;
  }
  .dl:hover {
    color: var(--seal-ink);
  }
  .impact {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  .impact li {
    display: grid;
    grid-template-columns: 24px minmax(0, 1fr) auto;
    gap: var(--s3);
    align-items: start;
    padding: var(--s3);
    border-radius: var(--r-md);
  }
  .impact .sign {
    display: grid;
    place-items: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    font-weight: 600;
    font-family: var(--font-record);
  }
  .gain {
    background: var(--stamp-wash);
  }
  .gain .sign {
    background: var(--stamp);
    color: var(--sheet);
  }
  .loss {
    background: var(--wax-wash);
  }
  .loss .sign {
    background: var(--wax);
    color: var(--sheet);
  }
  .warning {
    background: var(--wax-wash);
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--wax) 30%, transparent);
    background: transparent;
  }
  .warning .sign {
    color: var(--wax);
    box-shadow: inset 0 0 0 1.5px var(--wax);
  }
  .msg {
    color: var(--ink);
    font-weight: 500;
  }
  .loss .msg,
  .warning .msg {
    color: var(--wax);
  }
  .detail {
    color: var(--ink-3);
    font-size: 12px;
    margin-top: 2px;
  }
  .kind {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.01em;
    color: var(--ink-3);
  }
  .gain .kind {
    color: var(--stamp);
  }
  .loss .kind,
  .warning .kind {
    color: var(--wax);
  }
  .link {
    justify-self: start;
    border: 0;
    background: none;
    padding: 0;
    color: var(--seal-ink);
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
  }
  .yaml {
    margin: 0;
    padding: var(--s4);
    border-radius: var(--r-md);
    background: var(--well);
    overflow-x: auto;
    font-size: 12px;
    line-height: 1.6;
  }
  .side {
    position: sticky;
    top: 76px;
  }
  .decisions {
    padding: var(--s4);
    border-radius: var(--r-lg);
    background: var(--sheet-raised);
    border: 1px solid var(--rule);
  }
  .trail {
    list-style: none;
    margin: 0;
    padding: 0 0 0 var(--s4);
    display: grid;
    gap: var(--s3);
    border-left: 2px solid var(--rule);
  }
  .trail li {
    position: relative;
    color: var(--ink-3);
    font-size: 13px;
  }
  .trail li > div {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 6px;
  }
  .node {
    position: absolute;
    left: calc(var(--s4) * -1 - 6px);
    top: 5px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--sheet-raised);
    box-shadow: 0 0 0 2px var(--ink-4);
  }
  .approve .node {
    background: var(--stamp);
    box-shadow: 0 0 0 2px var(--stamp);
  }
  .reject .node {
    background: var(--wax);
    box-shadow: 0 0 0 2px var(--wax);
  }
  .activated .node {
    background: var(--seal-ink);
    box-shadow: 0 0 0 2px var(--seal-ink);
  }
  .wait .node {
    box-shadow: 0 0 0 2px var(--brass);
  }
  .say {
    flex-basis: 100%;
    color: var(--ink-2);
  }
  .lbl {
    font-size: 12px;
    font-weight: 500;
    color: var(--ink-2);
  }
  .in {
    padding: var(--s2) var(--s3);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    background: var(--well);
    resize: vertical;
  }
  .actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--s2);
  }
  .btn.approve {
    background: var(--stamp);
    color: var(--sheet);
    border-color: transparent;
  }
  .btn.reject {
    color: var(--wax);
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .wide {
    width: 100%;
    height: 36px;
  }
  .dim {
    color: var(--ink-4);
  }
  .small {
    font-size: 12px;
  }
  .fail {
    color: var(--wax);
  }
  .bar {
    height: 200px;
  }
  @media (max-width: 1000px) {
    .layout {
      grid-template-columns: 1fr;
    }
    .side {
      position: static;
    }
  }
</style>
