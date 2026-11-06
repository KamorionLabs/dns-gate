# MCP and Claude

The gate serves the Model Context Protocol at `/mcp` (Streamable HTTP). An assistant
such as Claude gets the same identity, RBAC, ownership and audit as any other client:
it can only do what the signed-in person may do.

```yaml
mcp:
  enabled: true
  allow_writes: false        # read-only tools unless enabled
  public_url: https://dns-gate.example.com
```

## What Claude can do

| Ask | Tools |
|---|---|
| "Which zones can I read? What does team web own in example.com?" | `list_zones`, `list_rrsets`, `list_teams`, `get_team` |
| "Who owns www CNAME, and could I change it? What happened to it last week?" | `get_rrset`, `search_audit` |
| "Has my change of app CNAME propagated?" | `check_propagation` |
| "Who may write `_acme-challenge` TXT records in example.com?" | `explain`, `who_can` (`policy.read`) |
| "Add api A 192.0.2.20, show me the plan first." | `plan_rrset_change`, then `apply_rrset_change` |
| "Adopt the existing records of shop.example.com for team shop." | `adopt_preview`, `adopt_apply` |
| "Move docs CNAME to team shop." / "What transfers wait for me?" | `transfer_propose`, `transfer_approve`, `transfer_reject`, `transfer_list` |
| "Prepare a zone profile for the domain we are transferring." | `*_zone_profile` (EuroDNS, `dns.zone.profile`) |

Writes (with `mcp.allow_writes`) always go through a **plan** the assistant shows,
then an **apply** bound to that exact plan, its author and the zone version. There
is no policy tool: policy changes stay with people in the web UI.

## Connect

The **Connect** page of the web UI (`/ui/#/connect`) shows every setup below already
filled in for your gate.

=== "Claude Desktop"

    Download the **Claude Desktop extension** from the Connect page and open it: Claude
    Desktop installs it, and the first tool call opens the browser to sign in (OIDC or
    SAML through the gate). No terminal or runtime to install. Start a new
    conversation after the first sign-in.

    The identity provider must accept the UI client as a public client with a
    loopback redirect: see [Claude Desktop extension](../config/ui-mcp.md#claude-desktop-extension).

=== "Claude Code"

    A `headersHelper` fetches a fresh token on each connection. With Entra ID and the
    Azure CLI:

    ```sh
    claude mcp add-json dns-gate '{"type":"http","url":"https://dns-gate.example.com/mcp","headersHelper":"az account get-access-token --scope api://<client-id>/.default --query accessToken -o tsv | jq -Rc \"{Authorization: (\\\"Bearer \\\" + .)}\""}' --scope user
    ```

    It needs the Azure CLI signed in to the gate's tenant (`az login --tenant <tenant-id>`)
    and `jq`. The helper must print `{"Authorization":"Bearer <token>"}`; any command
    printing a token for the gate works.

=== "Other MCP clients"

    Clients that only start local servers go through `mcp-remote`:

    ```json
    {
      "mcpServers": {
        "dns-gate": {
          "command": "npx",
          "args": ["-y", "mcp-remote", "https://dns-gate.example.com/mcp", "--header", "Authorization:${AUTH_HEADER}"],
          "env": { "AUTH_HEADER": "Bearer <access token>" }
        }
      }
    }
    ```

    The token is static there: renew it when it expires.

Every tool call is audited as `mcp.<tool>` with the client name. Rate limit:
`mcp.requests_per_minute` (120) per subject. Reference:
[MCP configuration](../config/ui-mcp.md#mcp).
