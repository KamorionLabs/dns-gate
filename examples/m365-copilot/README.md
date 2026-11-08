# Microsoft 365 Copilot declarative agent for dns-gate

A minimal, read-only declarative agent package that reaches the dns-gate MCP
endpoint through Microsoft Entra SSO. Setup of the gate and of Entra:
[docs/integrations/m365-copilot.md](../../docs/integrations/m365-copilot.md).

| File | Content |
|---|---|
| `appPackage/manifest.json` | Microsoft 365 app manifest declaring the agent. |
| `appPackage/declarativeAgent.json` | Agent name, instructions and conversation starters; one action. |
| `appPackage/ai-plugin.json` | Plugin manifest v2.4: `RemoteMCPServer` runtime on `https://<gate>/mcp`, `OAuthPluginVault` auth, the read tools pinned. |
| `appPackage/mcp-tools.json` | Definitions of the pinned tools, as `tools/list` returns them to a `dns.read` client. |

Before packaging:

1. Replace `dns.example.com` with the public origin of your gate (`spec.url` of
   `ai-plugin.json`, the developer URLs of `manifest.json`).
2. Set `reference_id` to the **Microsoft Entra SSO registration ID** given by the
   Teams developer portal (or let the Microsoft 365 Agents Toolkit fill it).
3. Give the app a new GUID (`id`) and add `color.png` (192x192) and `outline.png`
   (32x32, transparent) icons.
4. Zip the content of `appPackage/` and upload it (Teams admin center, or Agents
   Toolkit **Provision** for a development tenant).

The gate declares the agent as a delegated client with `scopes: [dns.read]` and
`surfaces: [mcp]`, so even a modified package cannot call write tools: the gate only
lists and runs the tools of the scopes. To refresh `mcp-tools.json` after a gate
upgrade, use **ATK: Fetch action from MCP** in Agents Toolkit, or remove
`functions`, `mcp_tool_description` and set `run_for_functions` to `["*"]` for
dynamic tool discovery: the gate already returns only the tools the client may use.
