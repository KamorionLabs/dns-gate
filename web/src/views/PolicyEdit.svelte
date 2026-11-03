<script lang="ts">
  import { api, ApiError, onBeforeReauth } from '../lib/api';
  import type { EffectivePolicy, GeneratedKey, PolicyDocument, ValidationError } from '../lib/types';
  import { fromDoc, nextUid, toDoc, type EModel } from '../lib/editor';
  import { clearDraft, loadDraft, saveDraft } from '../lib/draft';
  import { policyState } from '../lib/policy.svelte';
  import { proposalHref } from '../lib/router.svelte';
  import { toYAML } from '../lib/yaml';
  import { teamLabel } from '../lib/team';
  import PolicyFrame from '../components/policy/PolicyFrame.svelte';
  import MatcherEditor from '../components/policy/MatcherEditor.svelte';
  import LayerTag from '../components/policy/LayerTag.svelte';
  import ChipsInput from '../components/ChipsInput.svelte';
  import ToggleChips from '../components/ToggleChips.svelte';
  import FieldError from '../components/FieldError.svelte';
  import CopyText from '../components/CopyText.svelte';
  import RelTime from '../components/RelTime.svelte';
  import Icon from '../components/Icon.svelte';

  const TYPES = ['A', 'AAAA', 'CNAME', 'APEX', 'TXT', 'MX', 'SRV', 'CAA', 'HTTPS', 'SVCB', 'TLSA'];

  let model = $state<EModel | null>(null);
  let parentId = $state('');
  let comment = $state('');
  let restoredAt = $state<string | null>(null);
  let view = $state<'form' | 'yaml'>('form');
  let errors = $state<ValidationError[]>([]);
  let failure = $state<string | null>(null);
  let submitting = $state(false);
  let revealed = $state<(GeneratedKey & { uid: number }) | null>(null);
  let generating = $state<number | null>(null);

  function init(p: EffectivePolicy) {
    if (model) return;
    const stored = loadDraft();
    if (stored) {
      model = fromDoc(stored.document);
      parentId = stored.parent_id;
      comment = stored.comment;
      restoredAt = stored.saved_at;
    } else {
      model = fromDoc(p.managed);
      parentId = p.active?.id ?? '';
    }
  }

  $effect(() => {
    if (policyState.data) init(policyState.data);
  });

  // Autosave so a step-up sign-in (or an accidental reload) keeps the work.
  const persist = () => model && saveDraft({ parent_id: parentId, document: toDoc(model), comment });
  $effect(() => {
    if (!model) return;
    JSON.stringify(model);
    void comment;
    const t = setTimeout(persist, 400);
    return () => clearTimeout(t);
  });
  $effect(() => onBeforeReauth(persist));

  function discard(p: EffectivePolicy) {
    clearDraft();
    model = fromDoc(p.managed);
    parentId = p.active?.id ?? '';
    comment = '';
    restoredAt = null;
    errors = [];
    failure = null;
  }

  function diffCount(a: Record<string, unknown>, b: Record<string, unknown>) {
    let add = 0;
    let del = 0;
    let mod = 0;
    for (const k of Object.keys(b)) if (!(k in a)) add++;
    else if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) mod++;
    for (const k of Object.keys(a)) if (!(k in b)) del++;
    return { add, del, mod };
  }
  function listToMap<T>(l: T[], key: (x: T) => string) {
    return Object.fromEntries(l.map((x, i) => [key(x) || `#${i}`, x]));
  }
  function summary(p: EffectivePolicy, doc: PolicyDocument) {
    const a = p.managed ?? { groups: {}, roles: {}, bindings: [], virtual_keys: [] };
    const zoneMap = (z: string[] | undefined) => Object.fromEntries((z ?? []).map((x) => [x, true]));
    const bkey = (b: PolicyDocument['bindings'][number]) => `${b.role}@${teamLabel(b.team, b.team_from)}`;
    return [
      ['Managed zones', diffCount(zoneMap(a.zones), zoneMap(doc.zones))],
      ['Groups', diffCount(a.groups, doc.groups)],
      ['Roles', diffCount(a.roles, doc.roles)],
      ['Bindings', diffCount(listToMap(a.bindings, bkey), listToMap(doc.bindings, bkey))],
      ['Virtual keys', diffCount(listToMap(a.virtual_keys, (k) => k.id), listToMap(doc.virtual_keys, (k) => k.id))],
    ] as const;
  }

  async function generate(uid: number) {
    if (!model) return;
    generating = uid;
    failure = null;
    try {
      const g = await api.generateKey();
      const k = model.keys.find((x) => x.uid === uid);
      if (k) {
        k.app_id = g.app_id;
        k.key_sha256 = g.key_sha256;
      }
      revealed = { ...g, uid };
    } catch (e) {
      if (!(e instanceof ApiError && e.reason === 'reauth_required')) failure = (e as Error).message;
    } finally {
      generating = null;
    }
  }

  async function submit() {
    if (!model) return;
    errors = [];
    failure = null;
    if (!comment.trim()) {
      errors = [{ path: 'comment', message: 'Explain why this change is needed: reviewers read it first.' }];
      return;
    }
    submitting = true;
    try {
      const r = await api.propose({ parent_id: parentId, document: toDoc(model), comment: comment.trim() });
      clearDraft();
      await policyState.load(true);
      window.location.hash = proposalHref(r.id);
    } catch (e) {
      if (e instanceof ApiError && e.reason === 'invalid_policy') {
        errors = e.errors.length ? e.errors : [{ path: '', message: e.message }];
        view = 'form';
      } else if (!(e instanceof ApiError && e.reason === 'reauth_required')) {
        failure = (e as Error).message;
      }
    } finally {
      submitting = false;
    }
  }

  function jump(path: string) {
    document.getElementById('err-' + path)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  const has = (prefix: string) => errors.some((e) => e.path === prefix || e.path.startsWith(prefix + '.') || e.path.startsWith(prefix + '['));
</script>

<PolicyFrame tab="edit" title="Draft a policy change">
  {#snippet children(p)}
    {#if !p.me.can_propose || !p.settings.editable}
      <div class="empty"><strong>Drafting is not available</strong>{p.settings.editable ? 'You need the policy.propose action.' : 'The managed layer is disabled in this deployment.'}</div>
    {:else if model}
      {@const doc = toDoc(model)}
      {@const issuers = p.base.issuers.map((i) => i.name)}
      {@const metaRoles = Object.entries(p.base.document.roles).filter(([, r]) => r.rules.some((x) => x.actions.some((a) => a.startsWith('policy.')))).map(([n]) => n)}
      {@const roleNames = [...new Set([...Object.keys(p.base.document.roles).filter((n) => !metaRoles.includes(n)), ...model.roles.map((r) => r.name).filter(Boolean)])]}
      {@const groupNames = [...new Set([...Object.keys(p.base.document.groups), ...model.groups.map((g) => g.name).filter(Boolean)])]}

      <div class="banner">
        <Icon name="doc" size={14} />
        <span>
          Draft based on {#if parentId}<span class="mono">{parentId}</span>{:else}an empty managed layer{/if}.
          {#if restoredAt}Restored from this browser session, saved <RelTime iso={restoredAt} />.{:else}Saved in this browser session as you type.{/if}
          {#if p.active && parentId && parentId !== p.active.id}<b class="stale">The active revision is now {p.active.id}: reviewers will see this draft as stale.</b>{/if}
        </span>
        <button class="btn quiet" type="button" onclick={() => discard(p)}>Discard draft</button>
      </div>

      <div class="layout">
        <div class="main">
          <div class="viewtabs" role="tablist" aria-label="Draft view">
            <button role="tab" type="button" aria-selected={view === 'form'} onclick={() => (view = 'form')}>Form</button>
            <button role="tab" type="button" aria-selected={view === 'yaml'} onclick={() => (view = 'yaml')}>YAML</button>
          </div>

          {#if view === 'yaml'}
            <pre class="yaml mono">{toYAML(doc)}</pre>
          {:else}
            <p class="note"><LayerTag layer="base" /> items (issuers, protected records, bounds, policy.* grants and base groups, roles, bindings) are not editable here; base names cannot be reused.</p>

            <!-- Managed zones -->
            <section>
              <div class="sh"><h2>Managed zones</h2></div>
              <article class="card" class:bad={has('zones')}>
                <span class="lbl">Zones brought under management by this layer <span class="dim">(added to the base zones; each must exist in the account and match the bounds)</span></span>
                <ChipsInput bind:values={model.zones} label="Managed zones" placeholder="example.net" invalid={has('zones')} />
                <FieldError {errors} path="zones" prefix />
                <p class="dim small">
                  Base zones: <span class="mono">{p.base.zones.join(', ') || 'none'}</span> · bounds: <span class="mono">{p.base.bounds.zones.join(', ')}</span>
                  {#if p.base.zones_discovery && !p.base.zones_discovery.enabled} · zone discovery is disabled, so no zone can be added here.{/if}
                </p>
                <p class="dim small">Removing a zone where teams own record sets leaves them read-only through the gate: check the impact before approving.</p>
              </article>
            </section>

            <!-- Groups -->
            <section>
              <div class="sh"><h2>Groups</h2><button class="btn" type="button" onclick={() => model!.groups.push({ uid: nextUid(), name: '', description: '', members: [{ issuer: issuers[0] ?? '', claims: [{ key: 'sub', values: [] }] }] })}><Icon name="plus" size={14} />Group</button></div>
              {#each model.groups as g, gi (g.uid)}
                {@const path = `groups.${g.name.trim()}`}
                <article class="card" class:bad={has(path)}>
                  <div class="grid2">
                    <label><span class="lbl">Name</span><input class="in mono" bind:value={g.name} placeholder="web-pipelines" /></label>
                    <label><span class="lbl">Description</span><input class="in" bind:value={g.description} placeholder="optional" /></label>
                  </div>
                  <FieldError {errors} {path} />
                  <span class="lbl">Members <span class="dim">(a token matching any member is in the group)</span></span>
                  <MatcherEditor bind:matchers={g.members} {issuers} path="{path}.members" {errors} />
                  <button class="rm" type="button" onclick={() => model!.groups.splice(gi, 1)}><Icon name="trash" size={13} />Remove group</button>
                </article>
              {/each}
            </section>

            <!-- Roles -->
            <section>
              <div class="sh"><h2>Roles</h2><button class="btn" type="button" onclick={() => model!.roles.push({ uid: nextUid(), name: '', description: '', rules: [{ zones: [], actions: ['dns.read'], hosts: [], types: [] }], rebase_on_save: false, ephemeral_ttl: '', max_changes: '' })}><Icon name="plus" size={14} />Role</button></div>
              {#each model.roles as r, ri (r.uid)}
                {@const path = `roles.${r.name.trim()}`}
                <article class="card" class:bad={has(path)}>
                  <div class="grid2">
                    <label><span class="lbl">Name</span><input class="in mono" bind:value={r.name} placeholder="app-cname-writer" /></label>
                    <label><span class="lbl">Description</span><input class="in" bind:value={r.description} placeholder="optional" /></label>
                  </div>
                  <FieldError {errors} {path} />
                  {#each r.rules as rule, k (k)}
                    {@const rp = `${path}.rules[${k}]`}
                    <div class="rule">
                      <div class="rhead"><span class="eyebrow">Rule {k + 1}</span>{#if r.rules.length > 1}<button class="btn quiet icon" type="button" aria-label="Remove rule" onclick={() => r.rules.splice(k, 1)}><Icon name="x" size={12} /></button>{/if}</div>
                      <span class="lbl">Zones</span>
                      <ToggleChips options={p.base.bounds.zones} bind:values={rule.zones} label="Zones" invalid={has(rp + '.zones')} />
                      <FieldError {errors} path="{rp}.zones" prefix />
                      <span class="lbl">Actions</span>
                      <ToggleChips options={p.base.bounds.actions} bind:values={rule.actions} label="Actions" danger={['dns.record.adopt']} invalid={has(rp + '.actions')} />
                      <FieldError {errors} path="{rp}.actions" prefix />
                      <div class="grid2">
                        <div><span class="lbl">Hosts <span class="dim">(empty = any; * one label, ** several)</span></span><ChipsInput bind:values={rule.hosts} label="Hosts" placeholder="*.staging, _acme-challenge.**" /></div>
                        <div><span class="lbl">Types <span class="dim">(none = any)</span></span><ToggleChips options={TYPES} bind:values={rule.types} label="Record types" /></div>
                      </div>
                    </div>
                  {/each}
                  <button class="link" type="button" onclick={() => r.rules.push({ zones: [], actions: [], hosts: [], types: [] })}><Icon name="plus" size={12} /> rule</button>
                  <div class="opts">
                    <label class="check"><input type="checkbox" bind:checked={r.rebase_on_save} /> Rebase full-zone saves <span class="dim">(ACME clients)</span></label>
                    <label class="inline"><span class="lbl">Ephemeral TTL</span><input class="in mono short" bind:value={r.ephemeral_ttl} placeholder="24h" /></label>
                    <label class="inline"><span class="lbl">Max changes / request</span><input class="in mono short" type="number" min="0" bind:value={r.max_changes} placeholder="∞" /></label>
                  </div>
                  <FieldError {errors} path="{path}.ephemeral_ttl" />
                  <button class="rm" type="button" onclick={() => model!.roles.splice(ri, 1)}><Icon name="trash" size={13} />Remove role</button>
                </article>
              {/each}
            </section>

            <!-- Bindings -->
            <section>
              <div class="sh"><h2>Bindings</h2><button class="btn" type="button" onclick={() => model!.bindings.push({ uid: nextUid(), role: roleNames[0] ?? '', team_mode: 'fixed', team: '', tf_claim: 'sub', tf_regex: '', tf_prefix: '', groups: [], subjects: [] })}><Icon name="plus" size={14} />Binding</button></div>
              {#each model.bindings as b, bi (b.uid)}
                {@const path = `bindings[${bi}]`}
                <article class="card" class:bad={has(path)}>
                  <div class="grant">
                    <label><span class="lbl">Role</span>
                      <span class="field"><select bind:value={b.role}>{#each roleNames as n (n)}<option value={n}>{n}</option>{/each}{#if b.role && !roleNames.includes(b.role)}<option value={b.role}>{b.role}</option>{/if}</select><span class="chev"><Icon name="chevron" size={12} /></span></span>
                    </label>
                    <span class="at">@</span>
                    {#if b.team_mode === 'fixed'}
                      <label><span class="lbl">Acting for team</span><input class="in" bind:value={b.team} placeholder="web" /></label>
                    {:else}
                      <span class="derived"><span class="lbl">Acting for team</span><span class="mono">{teamLabel('', { claim: b.tf_claim || 'claim', regex: b.tf_regex, prefix: b.tf_prefix })}</span></span>
                    {/if}
                  </div>
                  <FieldError {errors} path="{path}.role" />
                  <FieldError {errors} path="{path}.team" />
                  <div class="teammode" role="radiogroup" aria-label="Owner team">
                    <label class="check"><input type="radio" value="fixed" bind:group={b.team_mode} /> Fixed team</label>
                    <label class="check"><input type="radio" value="claim" bind:group={b.team_mode} /> Team from a claim <span class="dim">(one team per identity)</span></label>
                  </div>
                  {#if b.team_mode === 'claim'}
                    <div class="grid3">
                      <label><span class="lbl">Claim</span><input class="in mono" bind:value={b.tf_claim} placeholder="sub" /></label>
                      <label><span class="lbl">Regex <span class="dim">(^…$, one capture group)</span></span><input class="in mono" bind:value={b.tf_regex} placeholder="^repo:acme/([^:]+):environment:production$" /></label>
                      <label><span class="lbl">Prefix <span class="dim">(optional)</span></span><input class="in mono" bind:value={b.tf_prefix} placeholder="ci-" /></label>
                    </div>
                    <FieldError {errors} path="{path}.team_from" prefix />
                    <p class="dim small">Team = prefix + lowercased capture. Each matching identity owns its own record sets; it may also create any name its role allows that does not exist yet.</p>
                  {/if}
                  <span class="lbl">Groups</span>
                  <ToggleChips options={groupNames} bind:values={b.groups} label="Groups" invalid={has(path + '.groups')} />
                  <FieldError {errors} path="{path}.groups" prefix />
                  <span class="lbl">Individual subjects</span>
                  <MatcherEditor bind:matchers={b.subjects} {issuers} path="{path}.subjects" {errors} noun="subject" />
                  <FieldError {errors} {path} />
                  <button class="rm" type="button" onclick={() => model!.bindings.splice(bi, 1)}><Icon name="trash" size={13} />Remove binding</button>
                </article>
              {/each}
            </section>

            <!-- Virtual keys -->
            <section>
              <div class="sh"><h2>Virtual keys</h2><button class="btn" type="button" onclick={() => model!.keys.push({ uid: nextUid(), id: '', app_id: '', key_sha256: '', description: '', roles: [], teams: [], expires: '', cidrs: [] })}><Icon name="plus" size={14} />Key</button></div>
              {#each model.keys as k, ki (k.uid)}
                {@const path = `virtual_keys[${ki}]`}
                <article class="card" class:bad={has(path)}>
                  <div class="grid2">
                    <label><span class="lbl">Id</span><input class="in mono" bind:value={k.id} placeholder="caddy-intranet" /></label>
                    <label><span class="lbl">Description</span><input class="in" bind:value={k.description} placeholder="optional" /></label>
                  </div>
                  <FieldError {errors} path="{path}.id" />
                  <div class="secret">
                    {#if k.key_sha256}
                      <span class="mono dim">app id <b>{k.app_id}</b> · sha256 {k.key_sha256.slice(0, 10)}…</span>
                      <button class="btn" type="button" disabled={generating === k.uid} onclick={() => generate(k.uid)}>Regenerate</button>
                    {:else}
                      <span class="dim">No key yet. The gate generates it; you see it once, the policy stores only its hash.</span>
                      <button class="btn primary" type="button" disabled={generating === k.uid} onclick={() => generate(k.uid)}><Icon name="key" size={14} />{generating === k.uid ? 'Generating…' : 'Generate key'}</button>
                    {/if}
                  </div>
                  {#if revealed && revealed.uid === k.uid}
                    <div class="reveal" role="alert">
                      <p><Icon name="alert" size={14} /> <b>Copy this key now.</b> It will not be shown again and is not saved in the draft. Store it in the client's secret store.</p>
                      <div class="pair"><span class="lbl">X-APP-ID</span><CopyText text={revealed.app_id} label="app id" /></div>
                      <div class="pair"><span class="lbl">X-API-KEY</span><CopyText text={revealed.key} label="API key" /></div>
                      <button class="btn" type="button" onclick={() => (revealed = null)}>I have stored it</button>
                    </div>
                  {/if}
                  <FieldError {errors} path="{path}.key_sha256" />
                  <span class="lbl">Roles</span>
                  <ToggleChips options={roleNames} bind:values={k.roles} label="Roles" invalid={has(path + '.roles')} />
                  <FieldError {errors} path="{path}.roles" prefix />
                  <div class="grid2">
                    <div><span class="lbl">Teams</span><ChipsInput bind:values={k.teams} label="Teams" placeholder="security" mono={false} /></div>
                    <label><span class="lbl">Expires</span><input class="in" type="date" bind:value={k.expires} /></label>
                  </div>
                  <span class="lbl">Allowed source CIDRs</span>
                  <ChipsInput bind:values={k.cidrs} label="Allowed CIDRs" placeholder="10.0.0.0/8" />
                  <button class="rm" type="button" onclick={() => model!.keys.splice(ki, 1)}><Icon name="trash" size={13} />Remove key</button>
                </article>
              {/each}
            </section>
          {/if}
        </div>

        <aside class="submit">
          <h2>Propose</h2>
          <dl class="sum">
            {#each summary(p, doc) as [label, c] (label)}
              <dt>{label}</dt>
              <dd class="num">
                {#if c.add}<span class="add">+{c.add}</span>{/if}
                {#if c.mod}<span class="mod">~{c.mod}</span>{/if}
                {#if c.del}<span class="del">−{c.del}</span>{/if}
                {#if !c.add && !c.mod && !c.del}<span class="dim">unchanged</span>{/if}
              </dd>
            {/each}
          </dl>
          <label>
            <span class="lbl">Why <span class="req">required</span></span>
            <textarea class="in" rows="4" bind:value={comment} placeholder="What changes, for whom, and why. Reviewers read this first." class:invalid={errors.some((e) => e.path === 'comment')}></textarea>
          </label>
          <FieldError {errors} path="comment" />
          {#if errors.length && !(errors.length === 1 && errors[0]?.path === 'comment')}
            <div class="errsum" role="alert">
              <b>{errors.length} problem{errors.length > 1 ? 's' : ''} to fix</b>
              <ul>{#each errors as e, i (i)}<li><button type="button" onclick={() => jump(e.path)}><span class="mono">{e.path || 'document'}</span> {e.message}</button></li>{/each}</ul>
            </div>
          {/if}
          {#if failure}<p class="fail">{failure}</p>{/if}
          <button class="btn primary wide" type="button" disabled={submitting} onclick={submit}>{submitting ? 'Sending…' : p.settings.require_approval ? 'Send for review' : 'Propose'}</button>
          <p class="dim small">{p.settings.require_approval ? 'Another policy approver must approve it before it can be activated.' : 'You can activate it yourself once proposed.'}</p>
        </aside>
      </div>
    {/if}
  {/snippet}
</PolicyFrame>

<style>
  .teammode {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s2) var(--s5);
  }
  .grid3 {
    display: grid;
    grid-template-columns: minmax(0, 0.6fr) minmax(0, 2fr) minmax(0, 0.7fr);
    gap: var(--s3);
  }
  .derived {
    display: grid;
    gap: 4px;
    align-content: start;
  }
  .derived .mono {
    display: inline-flex;
    align-items: center;
    height: 32px;
    color: var(--ink-2);
  }
  .banner {
    display: flex;
    align-items: center;
    gap: var(--s2);
    padding: var(--s2) var(--s3);
    margin-bottom: var(--s5);
    border-radius: var(--r-md);
    background: var(--seal-ink-wash);
    color: var(--ink-2);
  }
  .banner span {
    flex: 1;
  }
  .stale {
    display: block;
    color: var(--wax);
    font-weight: 500;
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 300px;
    gap: var(--s6);
    align-items: start;
  }
  .main {
    display: grid;
    gap: var(--s6);
    min-width: 0;
  }
  .viewtabs {
    display: inline-flex;
    justify-self: start;
    padding: 2px;
    gap: 2px;
    border-radius: var(--r-md);
    background: var(--well);
    border: 1px solid var(--rule-soft);
  }
  .viewtabs button {
    height: 26px;
    padding: 0 12px;
    border: 0;
    border-radius: 5px;
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    font-weight: 500;
  }
  .viewtabs button[aria-selected='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .yaml {
    margin: 0;
    padding: var(--s4);
    border-radius: var(--r-md);
    background: var(--well);
    border: 1px solid var(--rule-soft);
    overflow-x: auto;
    font-size: 12px;
    line-height: 1.6;
  }
  .note {
    display: flex;
    align-items: center;
    gap: var(--s2);
    color: var(--ink-3);
    font-size: 12.5px;
  }
  section {
    display: grid;
    gap: var(--s3);
  }
  .sh {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .sh h2 {
    font-size: var(--t-lead);
  }
  .card {
    position: relative;
    display: grid;
    gap: var(--s2);
    padding: var(--s4);
    border-radius: var(--r-lg);
    background: var(--sheet);
    border: 1px solid var(--rule);
    box-shadow: inset 3px 0 0 var(--seal-ink);
  }
  .card.bad {
    box-shadow: inset 3px 0 0 var(--wax);
    border-color: color-mix(in srgb, var(--wax) 35%, var(--rule));
  }
  .grid2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--s3);
  }
  label {
    display: grid;
    gap: 4px;
    min-width: 0;
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
  .in {
    height: 32px;
    padding: 0 var(--s3);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    background: var(--well);
    min-width: 0;
  }
  .in:focus {
    outline: 2px solid var(--focus);
    outline-offset: 1px;
    border-color: var(--rule-strong);
  }
  .in.mono {
    font-family: var(--font-record);
    font-size: 12.5px;
  }
  textarea.in {
    height: auto;
    padding: var(--s2) var(--s3);
    resize: vertical;
  }
  .in.invalid {
    border-color: var(--wax);
  }
  .short {
    width: 90px;
  }
  .rule {
    display: grid;
    gap: 6px;
    padding: var(--s3);
    border-radius: var(--r-md);
    background: var(--paper);
    border: 1px solid var(--rule-soft);
  }
  .rhead {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .opts {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s4);
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    grid-auto-flow: column;
    color: var(--ink-2);
  }
  .inline {
    display: inline-flex;
    align-items: center;
    gap: var(--s2);
  }
  .grant {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: var(--s2);
  }
  .grant .field {
    display: inline-flex;
  }
  .at {
    padding-bottom: 6px;
    color: var(--ink-4);
    font-size: var(--t-lead);
  }
  .rm {
    justify-self: end;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 0;
    background: none;
    color: var(--ink-4);
    cursor: pointer;
    font-size: 12px;
  }
  .rm:hover {
    color: var(--wax);
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
    font-size: 12.5px;
  }
  .secret {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s3);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .secret b {
    color: var(--ink);
    font-weight: 500;
  }
  .reveal {
    display: grid;
    gap: var(--s2);
    padding: var(--s3) var(--s4);
    border-radius: var(--r-md);
    background: var(--brass-wash);
    border: 1px solid color-mix(in srgb, var(--brass) 40%, transparent);
    color: var(--ink);
  }
  .reveal p {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--brass);
  }
  .reveal p b {
    color: var(--ink);
  }
  .pair {
    display: grid;
    grid-template-columns: 90px minmax(0, 1fr);
    align-items: center;
  }
  .pair :global(.copy) {
    color: var(--ink);
    font-size: 12.5px;
    word-break: break-all;
    text-align: left;
  }
  .reveal .btn {
    justify-self: start;
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .btn.primary:hover {
    border-color: transparent;
    filter: brightness(1.08);
  }
  .submit {
    position: sticky;
    top: 76px;
    display: grid;
    gap: var(--s3);
    padding: var(--s4);
    border-radius: var(--r-lg);
    background: var(--sheet-raised);
    border: 1px solid var(--rule);
  }
  .submit h2 {
    font-size: var(--t-lead);
  }
  .sum {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 4px var(--s3);
    margin: 0;
    font-size: 12.5px;
  }
  .sum dt {
    color: var(--ink-3);
  }
  .sum dd {
    margin: 0;
    display: flex;
    gap: 6px;
    justify-content: end;
    font-weight: 600;
  }
  .add {
    color: var(--stamp);
  }
  .mod {
    color: var(--brass);
  }
  .del {
    color: var(--wax);
  }
  .req {
    font-size: 11px;
    color: var(--wax);
    font-weight: 500;
  }
  .errsum {
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--wax-wash);
    color: var(--wax);
    font-size: 12.5px;
  }
  .errsum ul {
    margin: 4px 0 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 2px;
  }
  .errsum button {
    border: 0;
    background: none;
    padding: 0;
    text-align: left;
    color: inherit;
    cursor: pointer;
  }
  .errsum button:hover {
    text-decoration: underline;
  }
  .errsum .mono {
    font-size: 11.5px;
    color: var(--ink-2);
  }
  .fail {
    color: var(--wax);
  }
  .wide {
    width: 100%;
    height: 36px;
  }
  .small {
    font-size: 12px;
  }
  @media (max-width: 1000px) {
    .layout {
      grid-template-columns: 1fr;
    }
    .submit {
      position: static;
    }
  }
  @media (max-width: 640px) {
    .grid2,
    .grid3 {
      grid-template-columns: 1fr;
    }
  }
</style>
