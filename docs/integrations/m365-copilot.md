# Microsoft 365 Copilot

A Microsoft 365 Copilot **declarative agent** can use the gate MCP endpoint as a
plugin. Copilot obtains an Entra token for the signed-in user through the Microsoft
Enterprise token store and calls `/mcp` with it. The gate declares that token store
as a [delegated client](../config/authentication.md#delegated-clients): the agent
holds the rights of the user **capped by the scopes you give it**, read-only by
default, and the audit records that Copilot acted.

Requirements:

- The gate signs users in with **Entra ID** (an `issuers` entry for your tenant). Gates
  whose users sign in with SAML (IAM Identity Center) cannot use this path yet: they
  need declared OAuth clients on the gate authorization server (static registration
  with the redirect `https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect`),
  tracked in [issue #89](https://github.com/KamorionLabs/dns-gate/issues/89).
- The gate MCP endpoint is reachable **from Microsoft's cloud** over HTTPS (public
  endpoint, or an ingress that allows Microsoft 365 egress). A gate on a private
  network only is not reachable by Copilot.
- API keys are not an option: Microsoft 365 Copilot does not support API key
  authentication for MCP plugins.

## 1. Entra SSO registration

1. In the [Teams developer portal](https://dev.teams.microsoft.com/tools), open
   **Tools** > **Microsoft Entra SSO client ID registration** and register:
   *Base URL* `https://<gate>/mcp`, *Client ID* the application (client) id of the
   gate app registration, the scope of the gate API (for example
   `api://dns-gate/access_as_user`), restricted to your organization. It returns a
   **Microsoft Entra SSO registration ID** (the `reference_id` of the plugin) and an
   **Application ID URI**. The Microsoft 365 Agents Toolkit can create the same
   registration when you pick *Microsoft Entra SSO* for the MCP action.
2. On the **gate app registration** (Entra admin center):
    - manifest: add the generated Application ID URI to `identifierUris` (keep the
      existing ones; the portal UI only shows the first one);
    - **Authentication**, platform **Web**: add the redirect URI
      `https://teams.microsoft.com/api/platform/v1.0/oAuthConsentRedirect`;
    - **Expose an API** > **Add a client application**: authorize
      `ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b` (Microsoft Enterprise token store) on the
      gate API scope.
3. Audiences: with v2 access tokens (`accessTokenAcceptedVersion: 2` in the manifest,
   as the gate recommends) the `aud` of the token stays the **client id** of the gate
   app, whatever URI Copilot asked for, so `audiences` needs no change when it already
   lists that GUID, and the token store is in the `azp` claim. With v1 tokens
   (issuer `https://sts.windows.net/<tenant-id>/`) the `aud` is the URI that was
   requested: add the generated Application ID URI to the issuer `audiences`; the
   token store is then in the `appid` claim, which the same `client_ids` entry
   matches.

## 2. Declare Copilot on the gate

```yaml
issuers:
  - name: entra
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    audiences: ["<gate-application-id>"]
    subject_template: "{{tid}}/{{oid}}"
    category_claim: idtyp
    category_map: {app: pipeline, user: human}
    name_claim: name
    delegated_clients:
      - id: m365-copilot
        name: Microsoft 365 Copilot
        client_ids: [ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b]   # azp (v2) or appid (v1), any case
        scopes: [dns.read]          # or [dns.read, dns.plan] to let it prepare plans
        surfaces: [mcp]
        # zones: ["*.example.com"]  # optional ceiling on the zones
mcp:
  enabled: true
```

- The user keeps its bindings, teams and roles; Copilot gets their intersection with
  `dns.read` (and `dns.plan` if set): `tools/list` returns the read tools only, write
  tools are refused (`scope_insufficient`), and the REST API is closed to it
  (`surfaces: [mcp]`). Policy, API keys, tokens and zone profiles are never
  delegable.
- With `dns.plan`, Copilot can call `plan_rrset_change` to show a change; it cannot
  apply it, and no other client can apply its plan either.
- `dns.read` opens eight read tools (`transfer_list` when ownership transfers are
  enabled), which keeps the agent under the tool count Microsoft recommends for a
  plugin. The example package pins seven; add `transfer_list` if you use transfers.
- Audit events of the agent carry `client_id: m365-copilot`,
  `actor: {type: oauth_client, id: m365-copilot, name: Microsoft 365 Copilot}` and
  `auth_method: oauth-delegated`, the subject being the user.
- `require_known_client: true` on the issuer refuses every token whose client is not
  declared. Declare then every application that calls the gate with tokens of this
  issuer (Azure CLI for Claude Code, the managed identities of pipelines are clients
  too): a declared client is always capped to delegable scopes.

## 3. The agent package

[`examples/m365-copilot`](../../examples/m365-copilot/README.md) holds a minimal
package: `manifest.json`, `declarativeAgent.json` and `ai-plugin.json` (plugin
manifest v2.4, runtime `RemoteMCPServer` on `https://<gate>/mcp`, auth
`OAuthPluginVault` with the registration ID as `reference_id`, the read tools pinned).

```json
"runtimes": [
  {
    "type": "RemoteMCPServer",
    "spec": {
      "url": "https://dns.example.com/mcp",
      "mcp_tool_description": { "file": "mcp-tools.json" }
    },
    "auth": { "type": "OAuthPluginVault", "reference_id": "<Microsoft Entra SSO registration ID>" },
    "run_for_functions": ["list_zones", "list_rrsets", "get_rrset", "search_audit", "list_teams", "get_team", "check_propagation"]
  }
]
```

Replace the gate URL and the registration ID, zip `appPackage/` and upload it
(Teams admin center, or Agents Toolkit for a development tenant). Dynamic tool
discovery (`run_for_functions: ["*"]`, no `functions`) also works: the gate returns
to each client only the tools of its scopes.

In the audit journal of the UI, calls of the agent show the client next to the
user.

References: [Build a plugin from an MCP server](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/build-mcp-plugins),
[Configure Microsoft Entra SSO authentication](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-entra-sso).
