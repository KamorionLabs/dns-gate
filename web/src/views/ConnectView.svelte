<script lang="ts">
  import { api } from '../lib/api';
  import type { Connect, IssuedToken, Me, ZoneSummary } from '../lib/types';
  import TokenAction from '../components/TokenAction.svelte';
  import { canWriteZone } from '../lib/rights';
  import { router } from '../lib/router.svelte';
  import {
    CLAUDE_DESKTOP_EXTENSION_PATH,
    TOKEN_COMMAND_PLACEHOLDER,
    claudeCodeCommand,
    curlCommand,
    desktopConfig,
    loginCommand,
    TOKEN_ENV,
    terraformProvider,
    tokenCommand,
  } from '../lib/connect';
  import CopyText from '../components/CopyText.svelte';
  import HclBlock from '../components/HclBlock.svelte';
  import Icon from '../components/Icon.svelte';
  import ConnectedApps from '../components/ConnectedApps.svelte';

  let info = $state<Connect | null>(null);
  let error = $state<string | null>(null);

  // The examples use a zone the user can write in, when there is one.
  let zones = $state<ZoneSummary[]>([]);
  // A token issued here stays shown while the page is open, across tabs.
  let token = $state<IssuedToken | null>(null);
  let me = $state<Me | null>(null);

  $effect(() => {
    api
      .connect()
      .then((c) => (info = c))
      .catch((e: Error) => (error = e.message));
    api.zones().then((z) => (zones = z)).catch(() => {});
    api.me().then((m) => (me = m)).catch(() => {});
  });

  const managedZones = $derived(zones.filter((z) => !z.unmanaged));
  const exampleZone = $derived(
    (managedZones.find((z) => canWriteZone(me, z.zone) && !!me?.permissions) ?? managedZones[0])?.zone ?? 'example.com',
  );

  // Claude Desktop first: the extension is the easiest path for most people.
  const tabs = [
    { key: 'desktop', label: 'Claude Desktop' },
    { key: 'claude-code', label: 'Claude Code' },
    { key: 'terraform', label: 'Terraform / OpenTofu' },
    { key: 'api', label: 'API' },
    { key: 'apps', label: 'Connected applications' },
  ] as const;
  const tab = $derived(tabs.find((t) => t.key === router.params.get('tab'))?.key ?? 'desktop');
  const entra = $derived(info?.issuer?.kind === 'entra');
  const mcpState = $derived(!info?.mcp.enabled ? 'Disabled' : info.mcp.allow_writes ? 'Read and write' : 'Read-only');
</script>

<header class="head">
  <p class="eyebrow">Connect</p>
  <h1>Use the gate from your assistant, Terraform or scripts</h1>
  <p class="meta">Every snippet below is filled in for this gate. You sign in as yourself: the gate applies your permissions, nothing more.</p>
</header>

{#if error}
  <div class="empty"><strong>Connection details could not be loaded</strong>{error}</div>
{:else if !info}
  <div class="skeleton block"></div>
{:else}
  <div class="tabs" role="tablist" aria-label="Tool">
    {#each tabs as t (t.key)}
      <button role="tab" type="button" aria-selected={tab === t.key} onclick={() => router.setParams({ tab: t.key === 'desktop' ? undefined : t.key })}>
        {t.label}{#if t.key === 'desktop'}<span class="rec">Recommended</span>{/if}
      </button>
    {/each}
  </div>

  {#if info.tokens_url && (tab === 'terraform' || tab === 'api')}
    <TokenAction {info} zone={exampleZone} bind:token />
  {/if}

  <section class="panel" role="tabpanel">
    {#if tab === 'claude-code' || tab === 'desktop'}
      {#if !info.mcp.enabled}
        <p class="note off"><Icon name="lock" size={14} /><span>The MCP server is disabled on this gate. Administrators enable it with <span class="mono">mcp.enabled</span>.</span></p>
      {:else if !info.mcp.allow_writes}
        <p class="note"><Icon name="shield" size={14} /><span>Read-only: assistants can look up zones, records and the journal, not change them.</span></p>
      {:else}
        <p class="note"><Icon name="shield" size={14} /><span>Assistants can change records, always through a plan then an apply, and only records your teams own.</span></p>
      {/if}
    {/if}

    {#if tab === 'claude-code' && info.mcp.enabled}
      <p class="lead">One command. Claude Code runs the helper on every connection and again on a 401 or 403, so the token never goes stale.</p>
      <ol class="steps">
        {#if entra}
          <li>Install the <a href="https://learn.microsoft.com/cli/azure/install-azure-cli" target="_blank" rel="noreferrer">Azure CLI</a> and <a href="https://jqlang.org/download/" target="_blank" rel="noreferrer">jq</a>.</li>
          <li>Sign in to the gate's tenant: <CopyText text={loginCommand(info)} label="login command" /></li>
        {:else}
          <li>Install <a href="https://jqlang.org/download/" target="_blank" rel="noreferrer">jq</a> and a command that prints an access token of <span class="mono">{info.issuer?.url ?? 'the gate issuer'}</span> on stdout.</li>
        {/if}
        <li>
          Add the server{#if !entra}, replacing <span class="mono">{TOKEN_COMMAND_PLACEHOLDER}</span>{/if}:
          <HclBlock hcl={claudeCodeCommand(info)} filename="shell" download={false} wrap />
        </li>
        <li>In Claude Code, <span class="mono">/mcp</span> lists <span class="mono">dns-gate</span> as connected.</li>
      </ol>
      {#if entra}
        <p class="hint">If <span class="mono">az</span> answers that consent is required (AADSTS65001), the gate application does not trust the Azure CLI yet: ask the gate administrators to pre-authorize it.</p>
      {/if}
    {:else if tab === 'desktop' && info.mcp.enabled}
      {#if info.claude_desktop_extension_url}
        <p class="lead"><strong>Recommended for most people.</strong> Add the gate to Claude Desktop as an extension: no terminal, nothing else to install, you sign in with your usual account.</p>
        <p><a class="btn primary" href={CLAUDE_DESKTOP_EXTENSION_PATH} download><Icon name="download" size={14} />Download the Claude Desktop extension</a></p>
        <ol class="steps">
          <li>Download the extension with the button above.</li>
          <li>Double-click the downloaded file, or drag it into Claude Desktop under <strong>Settings</strong>, <strong>Extensions</strong>. Then click <strong>Install</strong>.</li>
          <li>Your browser then opens: sign in once. The gate's tools appear in Claude as soon as you are signed in, and Claude stays signed in after that.</li>
          <li>Start a <strong>new conversation</strong>: a conversation opened before the sign-in does not pick up the gate's tools.</li>
        </ol>
        <p class="hint">If Claude Desktop refuses to install it, your organization may only allow approved extensions: ask your Claude administrators.</p>
      {/if}
      <details class="advanced" open={!info.claude_desktop_extension_url}>
        <summary>Advanced: <span class="mono">mcp-remote</span> and other MCP clients</summary>
        <p class="lead">Claude Desktop and most other MCP clients only start local servers: <span class="mono">mcp-remote</span> (Node.js, run with npx) bridges them to the gate.</p>
        <ol class="steps">
          <li>Get a token: <CopyText text={tokenCommand(info)} label="token command" /></li>
          <li>
            Add the server to <span class="mono">claude_desktop_config.json</span> (Settings, Developer, Edit config) and paste the token after <span class="mono">Bearer </span>:
            <HclBlock hcl={desktopConfig(info)} filename="claude_desktop_config.json" download={false} />
          </li>
          <li>Restart the client.</li>
        </ol>
        <p class="hint">The token lasts about an hour. To refresh it, run the token command again, replace <span class="mono">AUTH_HEADER</span> and restart the client; the extension and Claude Code refresh it on their own. Clients that speak Streamable HTTP and accept custom headers can use the endpoint directly with an <span class="mono">Authorization: Bearer</span> header.</p>
      </details>
    {:else if tab === 'terraform'}
      <p class="lead">The <span class="mono">KamorionLabs/dnsgate</span> provider talks to the gate, whatever the DNS provider behind a zone: the gate holds the provider credentials, Terraform only proves who runs it.</p>
      <HclBlock hcl={terraformProvider(info, exampleZone)} filename="main.tf" />
      <p class="hint">
        {#if info.tokens_url}Terraform reads its token from <span class="mono">{TOKEN_ENV}</span>: get one with <strong>Get an API token</strong> above (valid up to one hour).
        {:else}Terraform signs in with a token of the gate's issuer{#if entra} (locally, your <span class="mono">az login</span>: <span class="mono">{tokenCommand(info)}</span>){/if}; the provider documentation lists the supported sign-in methods.{/if}
        To move records the gate already holds into a stack, open a zone and use Export Terraform.
      </p>
    {:else if tab === 'apps'}
      <ConnectedApps />
    {:else if tab === 'api'}
      <p class="lead">The REST API under <span class="mono">/api/v1</span> is the same for every DNS provider and accepts bearer tokens. A change is planned first, then that exact plan is applied:</p>
      <HclBlock hcl={curlCommand(info, exampleZone)} filename="shell" download={false} />
      <p class="hint">
        Also <span class="mono">PUT</span> and <span class="mono">DELETE /api/v1/zones/&lbrace;zone&rbrace;/rrsets/&lbrace;host&rbrace;/&lbrace;type&rbrace;</span> for one record set, and <span class="mono">/api/v1/audit</span> for the journal.
        A plan is valid for a few minutes, for the identity that made it, and only while the zone is unchanged.
      </p>
    {/if}
  </section>

  <details class="tech">
    <summary>Technical details</summary>
    <dl class="facts">
      <div><dt>Gate URL</dt><dd><CopyText text={info.base_url} label="gate URL" /></dd></div>
      <div>
        <dt>MCP endpoint</dt>
        <dd>
          {#if info.mcp.enabled}<CopyText text={info.mcp.url} label="MCP endpoint" />{/if}
          <span class="state" class:off={!info.mcp.enabled} class:ro={info.mcp.enabled && !info.mcp.allow_writes}>{mcpState}</span>
        </dd>
      </div>
      {#if info.issuer}
        <div>
          <dt>Sign-in</dt>
          <dd>
            {#if entra && info.issuer.tenant_id}Entra ID tenant <CopyText text={info.issuer.tenant_id} label="tenant id" />
            {:else}<CopyText text={info.issuer.url} label="issuer URL" />{/if}
          </dd>
        </div>
        {#if entra && info.issuer.tenant_id}
          <div><dt>Issuer</dt><dd><CopyText text={info.issuer.url} label="issuer URL" /></dd></div>
        {/if}
      {/if}
      {#if info.client_id}
        <div><dt>Application (client) id</dt><dd><CopyText text={info.client_id} label="client id" /></dd></div>
      {/if}
      {#if info.cli_scope}
        <div><dt>Token scope</dt><dd><CopyText text={info.cli_scope} label="token scope" /></dd></div>
      {/if}
      {#if info.claude_desktop_extension_url}
        <div><dt>Extension download</dt><dd><CopyText text={info.claude_desktop_extension_url} label="extension URL" /></dd></div>
      {/if}
    </dl>
  </details>
{/if}

<style>
  .head {
    display: grid;
    gap: var(--s2);
    margin-bottom: var(--s6);
  }
  h1 {
    font-size: var(--t-h2);
    letter-spacing: -0.015em;
  }
  .meta {
    color: var(--ink-3);
    max-width: 72ch;
  }
  .block {
    height: 160px;
  }
  .tech {
    max-width: 880px;
    margin-top: var(--s8);
    padding-top: var(--s4);
    border-top: 1px solid var(--rule-soft);
  }
  .tech summary {
    width: max-content;
    cursor: pointer;
    color: var(--ink-2);
    font-weight: 500;
    border-radius: var(--r-sm);
  }
  .tech[open] summary {
    margin-bottom: var(--s4);
  }
  .facts {
    margin: 0;
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: var(--s2) var(--s5);
    align-items: center;
  }
  .facts div {
    display: contents;
  }
  .facts dt {
    color: var(--ink-3);
    font-size: 13px;
  }
  .lead strong {
    color: var(--ink);
    font-weight: 600;
  }
  .facts dd {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
    color: var(--ink-2);
  }
  .state {
    font-size: 12px;
    padding: 1px 8px;
    border-radius: 6px;
    background: var(--stamp-wash);
    color: var(--stamp);
    font-weight: 500;
  }
  .state.ro {
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .state.off {
    background: var(--pencil-wash);
    color: var(--ink-3);
  }
  .tabs {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    margin-bottom: var(--s5);
    border-radius: var(--r-lg);
    background: var(--well);
    border: 1px solid var(--rule-soft);
  }
  .tabs button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 12px;
    border: 0;
    border-radius: 7px;
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    font-weight: 500;
  }
  .tabs button[aria-selected='true'] {
    background: var(--sheet-raised);
    color: var(--ink);
    box-shadow: 0 0 0 1px var(--rule);
  }
  .rec {
    font-size: var(--t-caption);
    padding: 0 6px;
    border-radius: 8px;
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .panel {
    display: grid;
    gap: var(--s4);
    max-width: 880px;
  }
  .note {
    display: flex;
    align-items: center;
    gap: var(--s2);
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
    font-weight: 500;
  }
  .note.off {
    background: var(--pencil-wash);
    color: var(--ink-2);
  }
  .lead {
    color: var(--ink-2);
    font-size: var(--t-lead);
  }
  .steps {
    margin: 0;
    padding-left: var(--s5);
    display: grid;
    gap: var(--s3);
    color: var(--ink-2);
  }
  .steps li {
    padding-left: var(--s1);
  }
  .steps :global(.hcl) {
    margin-top: var(--s2);
  }
  .panel :global(.hcl pre) {
    max-height: none;
  }
  .facts :global(.copy),
  .steps :global(.copy) {
    text-align: left;
  }
  @media (max-width: 560px) {
    .facts {
      grid-template-columns: minmax(0, 1fr);
      gap: 2px;
    }
    .facts dd {
      margin-bottom: var(--s2);
    }
  }
  @media (max-width: 720px) {
    .facts :global(.copy),
    .steps :global(.copy) {
      max-width: 100%;
      word-break: break-all;
    }
  }
  .hint {
    color: var(--ink-3);
  }
  .btn.primary {
    height: 38px;
    padding: 0 var(--s4);
    background: var(--seal-ink);
    color: var(--sheet);
    border-color: transparent;
    text-decoration: none;
  }
  .advanced {
    display: grid;
    gap: var(--s4);
    padding-top: var(--s4);
    border-top: 1px solid var(--rule-soft);
  }
  .advanced summary {
    cursor: pointer;
    color: var(--ink-2);
    font-weight: 500;
  }
  .advanced[open] summary {
    margin-bottom: var(--s4);
  }
  a {
    color: var(--seal-ink);
  }
</style>
