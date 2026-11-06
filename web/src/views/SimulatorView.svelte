<script lang="ts">
  import { api, ApiError } from '../lib/api';
  import type { EClaim } from '../lib/editor';
  import type { ExplainResponse, RevisionSummary } from '../lib/types';
  import { policyState } from '../lib/policy.svelte';
  import PolicyFrame from '../components/policy/PolicyFrame.svelte';
  import LayerTag from '../components/policy/LayerTag.svelte';
  import ChipsInput from '../components/ChipsInput.svelte';
  import Seal from '../components/Seal.svelte';
  import Icon from '../components/Icon.svelte';

  const ACTIONS = ['dns.record.write', 'dns.forward.write', 'dns.read', 'dns.record.adopt', 'ui.read', 'policy.read', 'policy.propose', 'policy.approve'];
  const TYPES = ['', 'A', 'AAAA', 'CNAME', 'APEX', 'TXT', 'MX', 'NS', 'SRV', 'CAA', 'URLFWD'];
  const presets: { label: string; issuer: string; claims: EClaim[] }[] = [
    { label: 'AWS role', issuer: 'aws', claims: [{ key: 'sub', values: ['arn:aws:iam::111111111111:role/ci-app'] }] },
    { label: 'GitHub workflow', issuer: 'github', claims: [{ key: 'repository', values: ['acme/web'] }, { key: 'ref', values: ['refs/heads/main'] }] },
    { label: 'Person', issuer: 'entra', claims: [{ key: 'preferred_username', values: ['bob@example.com'] }, { key: 'groups', values: [] }] },
  ];

  let issuer = $state('');
  let claims = $state<EClaim[]>([{ key: 'sub', values: [] }]);
  let action = $state('dns.record.write');
  let zone = $state('');
  let host = $state('');
  let type = $state('CNAME');
  let revisionId = $state('');
  let candidates = $state<RevisionSummary[]>([]);
  let result = $state<ExplainResponse | null>(null);
  let asked = $state<string>('');
  let busy = $state(false);
  let error = $state<string | null>(null);

  $effect(() => {
    Promise.all([api.revisions({ status: 'proposed' }), api.revisions({ status: 'approved' })])
      .then(([a, b]) => (candidates = [...a.revisions, ...b.revisions]))
      .catch(() => (candidates = []));
  });

  $effect(() => {
    const p = policyState.data;
    if (!p) return;
    if (!issuer) issuer = p.base.issuers[0]?.name ?? '';
    if (!zone) zone = p.base.zones[0] ?? '';
  });

  function usePreset(pr: (typeof presets)[number]) {
    issuer = pr.issuer;
    claims = pr.claims.map((c) => ({ key: c.key, values: [...c.values] }));
  }

  async function run() {
    busy = true;
    error = null;
    try {
      const c: Record<string, string[]> = {};
      for (const x of claims) if (x.key.trim() && x.values.length) c[x.key.trim()] = x.values;
      result = await api.explain({
        subject: { issuer, claims: c },
        action,
        zone,
        host: host.trim() || undefined,
        type: type || undefined,
        revision_id: revisionId || undefined,
      });
      asked = `${action} on ${host.trim() ? host.trim() + ' ' : ''}${type ? type + ' ' : ''}in ${zone}`;
    } catch (e) {
      if (!(e instanceof ApiError && e.reason === 'reauth_required')) error = (e as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

<PolicyFrame tab="simulate" title="Would this identity be allowed?">
  {#snippet children(p)}
    <div class="layout">
      <form class="form" onsubmit={(e) => { e.preventDefault(); run(); }}>
        <div class="presets"><span class="lbl">Start from</span>{#each presets as pr (pr.label)}<button class="btn quiet" type="button" onclick={() => usePreset(pr)}>{pr.label}</button>{/each}</div>

        <fieldset>
          <legend>Token</legend>
          <label><span class="lbl">Issuer</span>
            <span class="field"><select bind:value={issuer}>{#each p.base.issuers as is (is.name)}<option value={is.name}>{is.name}</option>{/each}</select><span class="chev"><Icon name="chevron" size={12} /></span></span>
          </label>
          <span class="lbl">Claims <span class="dim">(concrete values, as in the token)</span></span>
          {#each claims as c, i (i)}
            <div class="claim">
              <input class="in mono" aria-label="Claim name" placeholder="claim" bind:value={c.key} />
              <ChipsInput bind:values={c.values} label="Values of {c.key}" placeholder="value, Enter to add" />
              <button class="btn quiet icon" type="button" aria-label="Remove claim" onclick={() => (claims = claims.filter((_, k) => k !== i))}><Icon name="x" size={12} /></button>
            </div>
          {/each}
          <button class="link" type="button" onclick={() => (claims = [...claims, { key: '', values: [] }])}><Icon name="plus" size={12} /> claim</button>
        </fieldset>

        <fieldset>
          <legend>Request</legend>
          <div class="grid">
            <label><span class="lbl">Action</span><span class="field"><select bind:value={action}>{#each ACTIONS as a (a)}<option value={a}>{a}</option>{/each}</select><span class="chev"><Icon name="chevron" size={12} /></span></span></label>
            <label><span class="lbl">Zone</span><span class="field"><select bind:value={zone}>{#each p.base.zones as z (z)}<option value={z}>{z}</option>{/each}</select><span class="chev"><Icon name="chevron" size={12} /></span></span></label>
            <label><span class="lbl">Host <span class="dim">(@ for apex)</span></span><input class="in mono" bind:value={host} placeholder="www" /></label>
            <label><span class="lbl">Type</span><span class="field"><select bind:value={type}>{#each TYPES as t (t)}<option value={t}>{t || 'any'}</option>{/each}</select><span class="chev"><Icon name="chevron" size={12} /></span></span></label>
          </div>
          <label><span class="lbl">Evaluate against</span>
            <span class="field"><select bind:value={revisionId}>
              <option value="">Active policy{p.active ? ` (${p.active.id})` : ''}</option>
              {#each candidates as r (r.id)}<option value={r.id}>{r.id} · {r.status} · {r.comment?.slice(0, 40) ?? ''}</option>{/each}
            </select><span class="chev"><Icon name="chevron" size={12} /></span></span>
          </label>
        </fieldset>

        <button class="btn primary" type="submit" disabled={busy || !issuer || !zone}><Icon name="flask" size={14} />{busy ? 'Evaluating…' : 'Explain decision'}</button>
        {#if error}<p class="fail">{error}</p>{/if}
      </form>

      <div class="result" aria-live="polite">
        {#if result}
          <article class="verdict" class:allowed={result.allowed}>
            <div class="vhead">
              <span class="mark">{#if result.allowed}<Seal status="managed" size={30} />{:else}<Seal status="tainted" size={30} />{/if}</span>
              <div>
                <p class="v">{result.allowed ? 'Allowed' : 'Refused'}</p>
                <p class="asked mono">{asked}{revisionId ? ` · with ${revisionId}` : ''}</p>
              </div>
            </div>
            {#if result.allowed && result.matched}
              <div class="why"><span class="lbl">Granted by</span><span class="mono">{result.matched}</span>{#if result.layer}<LayerTag layer={result.layer} />{/if}</div>
              {#if result.folder}<div class="why"><span class="lbl">Through the folder</span><span class="mono">{result.folder}</span><span class="dim">the zone is in this EuroDNS folder, which the rule selects</span></div>{/if}
            {/if}
            {#if result.denied}
              <div class="why deny"><span class="lbl">Reason</span><span class="mono">{result.denied}</span>{#if result.layer}<LayerTag layer={result.layer} />{/if}</div>
            {/if}
            <div class="why">
              <span class="lbl">Groups</span>
              <span class="chips">{#each result.groups as g (g)}<span class="chip mono">{g}</span>{:else}<span class="dim">none: no group matches this token</span>{/each}</span>
            </div>
            <div class="why">
              <span class="lbl">Bindings</span>
              <span class="chips">{#each result.bindings as b (b)}<span class="chip mono role">{b}</span>{:else}<span class="dim">none</span>{/each}</span>
            </div>
          </article>
        {:else}
          <div class="placeholder">
            <Icon name="flask" size={22} />
            <p>Describe a token and a request. The gate evaluates them with the same code as live traffic, without calling the DNS provider.</p>
          </div>
        {/if}
      </div>
    </div>
  {/snippet}
</PolicyFrame>

<style>
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: var(--s8);
    align-items: start;
  }
  .form {
    display: grid;
    gap: var(--s5);
  }
  .presets {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s1);
  }
  fieldset {
    display: grid;
    gap: var(--s2);
    margin: 0;
    padding: var(--s4);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
  }
  legend {
    padding: 0 6px;
    font-size: var(--t-caption);
    font-weight: 600;
    letter-spacing: 0.01em;
    color: var(--ink-3);
  }
  label {
    display: grid;
    gap: 4px;
  }
  label .field {
    display: flex;
  }
  label .field select {
    flex: 1;
  }
  .lbl {
    font-size: 12px;
    font-weight: 500;
    color: var(--ink-2);
  }
  .dim {
    color: var(--ink-4);
    font-weight: 400;
  }
  .claim {
    display: grid;
    grid-template-columns: 150px minmax(0, 1fr) auto;
    gap: var(--s2);
    align-items: center;
  }
  .in {
    height: 32px;
    padding: 0 var(--s3);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    background: var(--well);
    min-width: 0;
    font-size: 13px;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--s3);
  }
  .link {
    justify-self: start;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 0;
    background: none;
    color: var(--seal-ink);
    cursor: pointer;
    font-weight: 500;
    font-size: 13px;
  }
  .btn.primary {
    justify-self: start;
    height: 36px;
    padding: 0 var(--s4);
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .fail {
    color: var(--wax);
  }
  .result {
    position: sticky;
    top: 76px;
  }
  .placeholder {
    display: grid;
    justify-items: center;
    gap: var(--s3);
    padding: var(--s10) var(--s6);
    border: 1px dashed var(--rule-strong);
    border-radius: var(--r-lg);
    color: var(--ink-3);
    text-align: center;
  }
  .verdict {
    display: grid;
    gap: var(--s4);
    padding: var(--s5);
    border-radius: var(--r-lg);
    background: var(--wax-wash);
    border: 1px solid color-mix(in srgb, var(--wax) 30%, transparent);
    animation: rise 220ms var(--ease-out);
  }
  .verdict.allowed {
    background: var(--seal-ink-wash);
    border-color: color-mix(in srgb, var(--seal-ink) 25%, transparent);
  }
  .vhead {
    display: flex;
    align-items: center;
    gap: var(--s3);
  }
  .mark {
    display: grid;
    place-items: center;
    width: 52px;
    height: 52px;
    border-radius: 50%;
    background: var(--sheet-raised);
  }
  .v {
    font-size: var(--t-h2);
    font-weight: 600;
    letter-spacing: -0.015em;
    color: var(--wax);
  }
  .allowed .v {
    color: var(--seal-ink);
  }
  .asked {
    font-size: 12px;
    color: var(--ink-3);
  }
  .why {
    display: grid;
    grid-template-columns: 90px minmax(0, 1fr) auto;
    gap: var(--s2);
    align-items: baseline;
  }
  .why .mono {
    font-size: 13px;
    overflow-wrap: anywhere;
  }
  .why.deny .mono {
    color: var(--wax);
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .chip {
    font-size: 12px;
    padding: 1px 8px;
    border-radius: 6px;
    background: var(--sheet-raised);
    box-shadow: inset 0 0 0 1px var(--rule);
  }
  .chip.role {
    color: var(--seal-ink);
  }
  @media (max-width: 1000px) {
    .layout {
      grid-template-columns: 1fr;
    }
    .result {
      position: static;
    }
  }
  @media (max-width: 640px) {
    .grid {
      grid-template-columns: 1fr;
    }
    .claim {
      grid-template-columns: minmax(0, 1fr) auto;
    }
    .claim :global(.chips) {
      grid-column: 1 / -1;
    }
  }
</style>
