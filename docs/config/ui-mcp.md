# Web UI and MCP

The web console and its login (OIDC or SAML), and the MCP endpoint for AI assistants. Guides: [Web UI](../features/ui.md), [MCP and Claude](../integrations/mcp.md), [SAML with IAM Identity Center](../IDENTITY-CENTER.md).

## UI

Read-only web UI under `/ui/` and its JSON API under `/api/v1` (action `ui.read`; the API also accepts bearer tokens and virtual keys).

| Field | Default | Description |
|---|---|---|
| `ui.enabled` | `false` | Enables `/ui/`, `/auth/*` and session cookies. |
| `ui.issuer` | (required for OIDC) | Name of a configured issuer used for the login. |
| `ui.client_id` | (required for OIDC) | OIDC client id registered at the IdP. |
| `ui.redirect_url` | (required for OIDC) | `https://<gate>/auth/callback`, registered at the IdP. |
| `ui.saml` | | SAML 2.0 login instead of OIDC, see [SAML login](#saml-login). |
| `ui.scopes` | `openid profile email` | Must include `openid`; add the scope that carries the claims used in bindings (for example `groups`). |
| `ui.session_ttl` | `8h` | Session lifetime (1m to 24h). |
| `ui.cli_scope` | `api://<client_id>/.default` with an Entra v2 issuer, else empty | OAuth scope a command-line tool requests to get a token for the gate, shown on the Connect page (`az account get-access-token --scope ...`, Terraform `azure_identity.scope`). One scope of letters, digits and `. _ ~ : / % -`, so it can be pasted into shell commands as is. Set it when the Application ID URI of the gate is not `api://<client_id>`. |

Login is the authorization code flow with PKCE (S256), `state` and `nonce` checked. The ID token is verified with the issuer keys and `aud = client_id`; issuer `bound_claims` apply. The session cookie (`__Host-` prefixed when the redirect URL is HTTPS) is encrypted with AES-256-GCM, `HttpOnly`, `Secure`, `SameSite=Lax`. It keeps the identity claims of the ID token (protocol claims dropped) plus `auth_time` and `amr`; roles, groups and teams are recomputed on every request, so a policy change applies immediately. A login whose claims do not fit in a cookie fails with `session_too_large`: reduce the emitted claims (Entra: app roles rather than groups). `POST /auth/logout` clears it.

The policy page opens on a **simple** view: one card per group of people (named after the app role or directory group it maps to), one row per pipeline and one card per API key, each with what it sees, which records it can change in which zones, and its policy rights, with a filter on one zone. The **expert** view, kept as the last choice in the browser, lists the layers, bindings, delegations, groups, roles, keys, protected records, bounds and issuers.

With [zone discovery](providers.md#zone-discovery), the zones view also lists the unmanaged zones the user can read, with a "Manage this zone" action for holders of `policy.propose` (it creates a proposal adding the zone to the managed layer) and a hint for the others.

Audit events of zones the user cannot read are filtered out; events without a zone (authentication failures) are shown only to users who can read every managed zone.

### SAML login

`ui.saml` replaces the OIDC login with SAML 2.0 (HTTP-Redirect or HTTP-POST request, HTTP-POST response); `ui.issuer`, `ui.client_id` and `ui.redirect_url` must then be empty. Setup with AWS IAM Identity Center: [IDENTITY-CENTER.md](../IDENTITY-CENTER.md).

```yaml
ui:
  enabled: true
  saml:
    issuer: identity-center             # name used in bindings and groups
    entity_id: dns-gate                 # SP entity id = audience of the assertions
    acs_url: https://dns.example.com/auth/saml/acs
    idp_metadata_url: https://portal.sso.eu-west-3.amazonaws.com/saml/metadata/<id>
    # idp_metadata: |                   # or the metadata XML inline
    name_id_format: email
    attributes: {email: email, name: name, groups: groups}
    groups_from_identity_store:
      identity_store_id: d-1234567890
      region: eu-west-3
      assume_role_arn: arn:aws:iam::111111111111:role/dns-gate-identity-store
bindings:
  - role: dns-admin
    team: platform
    subjects:
      - issuer: identity-center
        claims: {groups: [DNS-Admins]}
```

| Field | Default | Description |
|---|---|---|
| `ui.saml.issuer` | (required) | Name under which SAML users are bound (`<issuer>:<NameID>` in the audit log). Not the name of a token issuer. |
| `ui.saml.entity_id` | (required) | SP entity id, which the IdP puts in the assertion audience. |
| `ui.saml.acs_url` | (required) | `https://<gate>/auth/saml/acs`; its origin is the origin of the UI (CSRF checks, cookies). |
| `ui.saml.idp_metadata_url`, `ui.saml.idp_metadata` | (one required) | IdP metadata, fetched over HTTPS (cached per instance for 24 h, the previous copy kept when a refresh fails) or inline XML. It gives the IdP entity id, its signing certificates and its single sign-on URL. |
| `ui.saml.name_id_format` | `unspecified` | `unspecified`, `email`, `persistent` or `transient`, requested in the AuthnRequest. The NameID is the subject id (`sub`): avoid `transient`, whose value changes at each login. Without an `email` attribute, a NameID the IdP sends with the `emailAddress` format is the [email](authentication.md#email-of-the-subject) of `GET /api/v1/me`. |
| `ui.saml.attributes` | `{email: email, name: name, groups: groups}` | Claim to SAML attribute (`Name` or `FriendlyName`) mapping; the given entries are added to the defaults. A single value becomes a string claim, several a list; `groups` is always a list. An `amr` entry feeds the authentication methods instead of a claim. Unmapped attributes are dropped. |
| `ui.saml.team_claim`, `ui.saml.team_claim_prefix` | | As `issuers[].team_claim` and `team_claim_prefix`. |
| `ui.saml.groups_from_identity_store.identity_store_id` | | Identity store (`d-xxxxxxxxxx`) whose groups are looked up at login. |
| `...region` | (required) | Region of the IAM Identity Center instance. |
| `...assume_role_arn` | | Role assumed for the lookup (the identity store lives in the management or delegated administrator account); the gate's own credentials otherwise. |
| `...user_attribute` | `userName` | `userName` or `email`: identity store attribute matched with the value of `user_claim`. |
| `...user_claim` | `sub` | Claim holding that value (the NameID by default). |
| `...cache_ttl` | `5m` | Per-instance cache of the groups of a user and of group names (at most `1h`). |

The display name of every group the user belongs to (`identitystore:GetUserId`, `ListGroupMembershipsForMember`, `DescribeGroup`) is added to the `groups` claim, together with the `groups` attribute of the assertion if the IdP sends one. A user missing from the identity store just gets no extra group; any other lookup error fails the login (`502 groups_unavailable`). Groups are resolved at login and kept in the session: a membership change applies at the next login.


How the gate validates a SAML response, and its replay protection: [design](../design/authentication.md#94-saml-users-and-gate-issued-tokens).

- The login state cookie must come back on the cross-site POST of the IdP: it is `SameSite=None; Secure` when `acs_url` is HTTPS (plain HTTP only works with an IdP on the same site, for tests). A response posted without it is refused (`400 login_state`), except an unsolicited one (no `InResponseTo`, an IdP-initiated login from a portal), which is answered with a redirect to `/auth/login` so that a proper SP-initiated login starts.
- Step-up: `/auth/login?reauth=1` sends `ForceAuthn="true"`. The `AuthnInstant` returned by the IdP is what counts for `policy.edit_max_age`: an IdP that ignores `ForceAuthn` and returns an older instant keeps the user out of policy mutations until they sign in again at the IdP. Identity Center reports `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`-style context classes rather than `mfa`: set `policy.require_amr` only to values the IdP actually sends.
- With `DNS_GATE_SAML_SP_KEY` and `DNS_GATE_SAML_SP_CERT`, requests are signed (RSA-SHA256 or ECDSA-SHA256) and the metadata lists the certificate; without them, requests are unsigned, which Identity Center accepts.
- `GET /auth/saml/metadata` serves the SP metadata (entity id, ACS URL, NameID format, certificate) to import at the IdP.

## MCP

`/mcp` exposes the gate to AI assistants with the Model Context Protocol (Streamable HTTP transport, stateless).

| Field | Default | Description |
|---|---|---|
| `mcp.enabled` | `false` | Serves `/mcp` and `/.well-known/oauth-protected-resource`. |
| `mcp.allow_writes` | `false` | Adds the write tools (plan/apply, adoption, transfer requests and decisions, zone profiles). Without it, the server is read-only. |
| `mcp.plan_ttl` | `10m` | Lifetime of a plan returned by `plan_rrset_change` or `POST /api/v1/zones/{zone}/plan` (1m to 1h). |
| `mcp.requests_per_minute` | `120` | Rate limit per subject (`429` beyond). |
| `mcp.public_url` | UI origin, else the request host | Public base URL of the gate, advertised in the protected resource metadata and shown on the Connect page. |

Authentication is the same as the API: an OIDC bearer token of a configured issuer, or a virtual key (`X-APP-ID` / `X-API-KEY`); cookies are ignored. Without credentials the answer is `401` with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource"`, and that document (RFC 9728) names the UI issuer as authorization server. Every tool runs with the RBAC and ownership rules of the caller and is audited (`mcp.<tool>`, with `via: mcp` and the client name), except `check_propagation`.

Tools:

| Tool | Kind | Description |
|---|---|---|
| `list_zones` | read | Readable zones with their counts and [EuroDNS folder](providers.md#eurodns-folders) (optional `folder` glob filter); zones discovered in the account but not managed are flagged `unmanaged`. |
| `list_rrsets` | read | RRsets of a zone (managed, or unmanaged with `dns.read`) with their owner team, and the tombstones (deleted RRsets still reserved for their team); filters on status, host glob, type, owner. `compact: true` returns `records` (host, type, ttl, values, status, owner) instead of `rrsets`, without hashes, actors and dates; `limit` (up to 1000) and `cursor` page through large zones (`next_cursor`, tombstones on the first page only). |
| `search_records` | read | RRsets across every readable zone, or one `folder` glob or `zone`, matching globs on `value` (values, alias targets, forward URLs), `host` and `type`, in compact form (default 500, `limit` up to 5000, `truncated`). Zones are read four at a time through the inventory cache within 25 seconds; the zones not read in time or unreadable are in `zones_skipped` with their reason, and a later call finds them in the cache. Same as `GET /api/v1/records`. |
| `export_records` | read | Bulk export of the same scope and filters, as TSV (default; one line per value: zone, host, type, ttl, value, status, owner) or zone files (`format: zone`, one `$ORIGIN` block per zone, URL forwards and aliases as comments), at most 50000 records. The export is the text content; the structured result counts records and skipped zones. Same as `GET /api/v1/records/export`. |
| `get_rrset` | read | One RRset, its tombstone, why the caller may or may not change it (`ownership`), and its recent audit history. |
| `check_propagation` | read | [Propagation check](../CONFIG.md#propagation-check) of an RRset (`dns.read` on it, managed zones only), with an optional `expect` hash; not audited, like the REST endpoint. Absent when `propagation.enabled` is `false`. |
| `search_audit` | read | Audit search, same visibility as the UI. |
| `explain`, `who_can` | read | Policy simulation (`policy.read`); `explain` adds the teams and default team of the simulated subject and, for an RRset, its owner team or reservation; both tell when a rule applied through the folder of the zone (`folder`, `by_folder`). |
| `list_teams`, `get_team` | read | Teams as `GET /api/v1/teams[/{team}]`, plus the caller's teams (`my_teams`). |
| `transfer_list` | read | Transfer requests the caller may see (`status=proposed` is the inbox, `can_decide`). |
| `plan_rrset_change` | dry run | Desired state of RRsets, checked without writing; returns a `plan_id` bound to the caller, the zone, the changes, the zone version and the optional `team` (one of the caller's teams). |
| `apply_rrset_change` | write | Applies a plan exactly as planned, for its team; refused when expired, used, owned by another caller, planned for another team (`team_mismatch`), or when the zone changed since (`precondition`). |
| `adopt_preview`, `adopt_apply` | dry run, write | Adoption as above, with an optional `team`. |
| `list_zone_profiles`, `get_zone_profile`, `check_zone_profile` | read | [Zone profiles](providers.md#zone-profiles) of a EuroDNS provider (`provider` optional with one EuroDNS provider); `check_zone_profile` validates with EuroDNS without saving. `dns.zone.profile` on `*`. |
| `create_zone_profile`, `update_zone_profile`, `delete_zone_profile` | write | Zone profile writes, audited with the profile content; humans need a recent login. `update_zone_profile` keeps the forwards it is not given (`[]` removes them). |
| `transfer_propose`, `transfer_approve`, `transfer_reject` | write | Ownership transfers with the REST rules ([transfers](policy.md#ownership)): one owner team per request, approved by someone who may write every RRset through the owner team or holds `dns.ownership.approve` on it (humans only unless `ownership.machine_approvers`), another person with `ownership.require_second_approver`, otherwise possibly the requester (`transfer_propose` with `apply: true`); the requester may reject (withdraw) it. An approval the gate cannot complete at once, and every rename, leaves the transfer `applying`, applied in the background. |

There is no policy tool: policy changes stay with humans in the UI, with step-up. Plans are kept in the store, shared by every replica, and taken once: a plan made on one replica can be applied on another. The same plans back `POST /api/v1/zones/{zone}/plan` and `/apply` ([API.md](../API.md)). Expired plans are purged every 15 minutes by the gate (SQL stores) or by the DynamoDB TTL.

### Connecting an assistant

The **Connect** page of the UI (`/ui/#/connect`, data from `GET /api/v1/connect`) shows the commands below already filled in with the gate URL, the tenant and the token scope (`ui.cli_scope`), the Claude Desktop extension download, plus the Terraform provider block and a `curl` example. The gate only needs an access token of a configured issuer whose audience is the gate; with Entra ID, the Azure CLI gets one for the signed-in user.

Setups for Claude Code, Claude Desktop and other MCP clients: [MCP and Claude](../integrations/mcp.md#connect). This section covers what the identity provider must allow.

#### Claude Desktop extension

For Claude Desktop, the Connect page offers a **Claude Desktop extension**: the user downloads it, double-clicks it (or drags it into Claude Desktop, Settings, Extensions) and clicks Install. No terminal, Azure CLI, `jq` or Node.js is needed: the extension runs on the Node.js runtime shipped with Claude Desktop.

With a [SAML UI login](#saml-login), the extension signs in at the gate itself: the bundle carries the [gate issuer](authentication.md#gate-issued-tokens) URL and the client id `dns-gate-relay`, the relay is unchanged (OIDC discovery on the gate, authorization code with PKCE on a loopback redirect, refresh token), and the browser goes through the SAML login and a consent page. The extension is then offered only when an issuer with `self: true` is configured. Nothing has to be registered at the identity provider for it.

The file comes from `GET /api/v1/connect/claude-desktop.mcpb` (same authentication as `/api/v1/connect`), offered when `mcp.enabled` and the UI login are both on; `/api/v1/connect` then returns its URL in `claude_desktop_extension_url` (empty otherwise, and the download answers `404`). It is an [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) (manifest `0.3`, `dns-gate-<host>.mcpb`) generated on the fly with the MCP URL, the UI issuer, `ui.client_id` and the token scope (from `ui.cli_scope`, see Entra ID below) baked in. It holds no secret and is the same for every user of the gate.

The extension relays every MCP message to `/mcp` with the user's token, signs in through the system browser and keeps its tokens in `~/.dns-gate/<host>.json` (mode `0600`): [how it works](../design/onboarding-mcp.md#174-claude-desktop-extension).

The identity provider must accept `ui.client_id` as a **public client** for this flow:

- the loopback redirect URI `http://localhost`, with any port and no path (RFC 8252, section 7.3): the relay sends `http://localhost:<ephemeral port>`; a provider that does not ignore the port of loopback redirects needs a wildcard such as `http://localhost:*`;
- the authorization code flow with PKCE and no client secret;
- refresh tokens for `offline_access`;
- an access token the gate accepts: issuer configured, audience listed in `audiences`.

With Entra ID, on the gate app registration (the one of `ui.client_id`):

- add the platform **Mobile and desktop applications** with the redirect URI exactly `http://localhost`: Entra ignores the port of loopback redirects but not the path, so do not add `/callback` or a trailing slash; in Terraform (`azuread_application`), `public_client { redirect_uris = ["http://localhost"] }`. The web redirect `https://<gate>/auth/callback` of the UI stays as it is;
- set **Allow public client flows** to *Yes* (`fallback_public_client_enabled = true`), so Entra treats the code and refresh token requests, which carry no client secret, as coming from a public client;
- the token is requested for `ui.cli_scope` (`api://<client_id>/.default` by default). The extension signs in as `ui.client_id` itself, and Entra refuses a token an application requests for itself through its App ID URI (`AADSTS90009`): the bundle therefore carries a `ui.cli_scope` of the form `api://<client_id>/<scope>` as `<client_id>/<scope>`, the GUID form Entra requires; other scopes are kept as they are, and `ui.cli_scope` itself is unchanged for the Azure CLI. A custom App ID URI of the same application (`api://dns-gate/.default`) is not rewritten and hits the same error: keep `ui.cli_scope` under `api://<client_id>/` for the extension. The application must expose a delegated scope that users may consent to, or that an administrator consented to tenant-wide, and the issuer must list the application id in `audiences` with `accessTokenAcceptedVersion: 2`, as for the Azure CLI below. *Assignment required* applies as for the UI.

The bundle is not signed (`mcpb sign`): organizations that restrict Claude Desktop to approved or signed extensions must allow it.

#### Azure CLI tokens and other MCP clients

Clients that only start local servers go through the `mcp-remote` bridge with a static token, renewed by hand when it expires ([example](../integrations/mcp.md#connect)).

With Entra ID, `az account get-access-token` for the gate scope requires the gate application to expose that scope and to trust the Azure CLI: add the Azure CLI client id (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) to the authorized client applications of the gate app registration, or grant tenant-wide admin consent; otherwise `az` answers `AADSTS65001` (consent required). The token the CLI receives must then be accepted by a configured issuer (audience and token version, see `accessTokenAcceptedVersion`).

MCP clients that implement the OAuth flow discover the issuer through the resource metadata, but Entra ID does not support OAuth dynamic client registration: register the MCP client as an application in Entra, or pass a token as above.
