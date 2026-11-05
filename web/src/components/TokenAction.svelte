<script lang="ts">
  import { api, ApiError } from '../lib/api';
  import type { Connect, IssuedToken } from '../lib/types';
  import { TOKEN_ENV, tokenSnippets } from '../lib/connect';
  import { absolute } from '../lib/format';
  import HclBlock from './HclBlock.svelte';
  import RelTime from './RelTime.svelte';
  import Icon from './Icon.svelte';

  // "Get an API token": a gate token of this browser session, shown once,
  // for curl and Terraform. The parent keeps it while the page is open.
  let { info, zone, token = $bindable(null) }: { info: Connect; zone: string; token?: IssuedToken | null } = $props();

  let busy = $state(false);
  let error = $state<string | null>(null);
  let copied = $state(false);

  async function issue() {
    busy = true;
    error = null;
    try {
      token = await api.issueToken();
    } catch (e) {
      // reauth_required: the client already sends the user to sign in again
      if (e instanceof ApiError && e.reason === 'reauth_required') return;
      if (e instanceof ApiError && e.reason === 'session_required') error = 'Tokens are issued to people signed in to this console only.';
      else if (e instanceof ApiError && e.status === 404) error = 'This gate does not issue tokens.';
      else error = (e as Error).message;
    } finally {
      busy = false;
    }
  }

  async function copy() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token.access_token);
      copied = true;
      setTimeout(() => (copied = false), 1400);
    } catch {
      copied = false;
    }
  }

  const snippets = $derived(token ? tokenSnippets(info, token.access_token, zone) : null);
</script>

<section class="token" aria-labelledby="token-title">
  <div class="head">
    <div>
      <h2 id="token-title"><Icon name="key" size={14} /> API token</h2>
      <p class="dim">A token for curl and Terraform, signed by the gate, valid up to one hour and never beyond your session. It acts as you: your permissions, nothing more.</p>
    </div>
    {#if !token}
      <button class="btn primary" type="button" disabled={busy} onclick={issue}><Icon name="key" size={14} />{busy ? 'Getting a token…' : 'Get an API token'}</button>
    {/if}
  </div>

  {#if error}<p class="fail" role="alert">{error}</p>{/if}

  {#if token && snippets}
    <div class="value">
      <code class="mono">{token.access_token}</code>
      <button class="btn" type="button" onclick={copy}><Icon name={copied ? 'check' : 'copy'} size={14} />{copied ? 'Copied' : 'Copy'}</button>
    </div>
    <p class="meta">
      <span class="exp" title={absolute(token.expires_at)}><Icon name="clock" size={12} /> Expires <RelTime iso={token.expires_at} /></span>
      <span class="dim">Shown once: copy it now, the gate does not keep it. Treat it like a password.</span>
    </p>
    <div class="snips">
      <div>
        <span class="eyebrow">Terraform (the provider reads <span class="mono">{TOKEN_ENV}</span>)</span>
        <HclBlock hcl={snippets.terraform} filename="shell" download={false} wrap />
      </div>
      <div>
        <span class="eyebrow">curl</span>
        <HclBlock hcl={snippets.curl} filename="shell" download={false} wrap />
      </div>
    </div>
    <div class="again">
      <button class="btn quiet" type="button" onclick={() => (token = null)}>Hide the token</button>
      <button class="btn quiet" type="button" disabled={busy} onclick={issue}>Get a new one</button>
    </div>
  {/if}
</section>

<style>
  .token {
    display: grid;
    gap: var(--s3);
    max-width: 880px;
    margin-bottom: var(--s5);
    padding: var(--s4) var(--s5);
    border: 1px solid var(--rule);
    border-radius: var(--r-lg);
    background: var(--sheet);
  }
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--s3) var(--s5);
  }
  .head > div {
    display: grid;
    gap: 4px;
    max-width: 62ch;
  }
  h2 {
    display: inline-flex;
    align-items: center;
    gap: var(--s2);
    font-size: var(--t-lead);
    font-weight: 600;
  }
  .dim {
    color: var(--ink-3);
  }
  .fail {
    color: var(--wax);
  }
  .btn.primary {
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
  }
  .value {
    display: flex;
    align-items: flex-start;
    gap: var(--s2);
  }
  .value code {
    flex: 1;
    min-width: 0;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
    font-size: 12px;
    overflow-wrap: anywhere;
    user-select: all;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s1) var(--s4);
    font-size: 12px;
  }
  .exp {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--brass);
    font-weight: 500;
  }
  .snips {
    display: grid;
    gap: var(--s3);
  }
  .snips > div {
    display: grid;
    gap: 4px;
    min-width: 0;
  }
  .again {
    display: flex;
    gap: var(--s2);
  }
</style>
