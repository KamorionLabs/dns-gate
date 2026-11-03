# Configuration reference

eurodns-gate reads one YAML file (`-config`, default `/etc/eurodns-gate/config.yaml`, or `EURODNS_GATE_CONFIG`). Decoding is strict: an unknown field stops the gate at startup. `eurodns-gate -check -config file.yaml` validates a file and exits.

A complete example is in [`examples/config.yaml`](../examples/config.yaml).

## Secrets

Secrets never live in the YAML file. Each one is read from an environment variable, or from the file named by the same variable with a `_FILE` suffix (the form to use with Kubernetes Secret volumes).

| Variable | Used for | Required |
|---|---|---|
| `EURODNS_API_KEY` | EuroDNS `X-API-KEY` | yes |
| `EURODNS_APP_ID` | EuroDNS `X-APP-ID`, overrides `upstream.app_id` | if `upstream.app_id` is empty |
| `EURODNS_GATE_POSTGRES_DSN` | Postgres connection string | with `store.type: postgres` |
| `EURODNS_GATE_SESSION_KEY` | 32-byte key (hex or base64) encrypting UI cookies | with `ui.enabled` |
| `EURODNS_GATE_UI_CLIENT_SECRET` | OIDC client secret of the UI | no (public client with PKCE) |

Other environment variables: `POD_NAME` (lock holder id, defaults to the hostname) and `EURODNS_GATE_REPLICAS` (only used to warn when a single-replica store runs with several replicas).

Generate a session key with `openssl rand -hex 32`.

## Top level

| Field | Default | Description |
|---|---|---|
| `listen.address` | `:8080` | HTTP listen address. TLS is terminated in front of the gate. |
| `listen.trusted_proxies` | `[]` | CIDRs of reverse proxies allowed to set `X-Forwarded-For`. The rightmost untrusted hop is the client address (used by `virtual_keys[].allowed_cidrs`). |
| `upstream.base_url` | `https://rest-api.eurodns.com` | EuroDNS API. HTTPS is required (loopback excepted, for tests). |
| `upstream.app_id` | | EuroDNS application id. |
| `upstream.rate.every`, `upstream.rate.burst` | `1.1s`, `5` | Client-side limiter shared by every upstream call. EuroDNS allows 10 requests per 10 seconds per IP and bans progressively: keep the default unless EuroDNS raised your quota. |
| `upstream.max_retries` | `3` | Retries on 429, 5xx and network errors (idempotent requests). |
| `zones` | (required) | Managed zones. Requests for any other zone are refused before authorization. |
| `check_on_write` | `true` | Validate every zone with EuroDNS `check` before saving it. |
| `reconcile_interval` | `15m` | Drift detection period per zone (minimum `1m`). |
| `limits.max_body_bytes` | `1048576` | Request body limit. |
| `limits.max_changes_per_request` | `20` | Default blast-radius limit (RRset changes per request). |
| `lock.ttl`, `lock.wait` | `60s`, `30s` | Per-zone write lease and how long a request waits for it (then `503 zone_locked`). |

## Store

| Field | Default | Description |
|---|---|---|
| `store.type` | `memory` | `memory`, `sqlite`, `postgres` or `dynamodb`. |
| `store.audit_retention` | `9600h` (400 days) | Audit events older than this are purged (minimum `24h`). |
| `store.sqlite.path` | | Database file, on a persistent volume. |
| `store.postgres.max_conns` | `5` | Pool size (1 to 100). The DSN comes from `EURODNS_GATE_POSTGRES_DSN`. |
| `store.dynamodb.table`, `region`, `endpoint` | | Single-table backend; credentials from the default AWS chain (EKS Pod Identity, IRSA, environment). |

`memory` loses ownership on restart: tests only. `memory` and `sqlite` support **one replica** (the chart refuses `replicaCount > 1` with them); use `postgres` or `dynamodb` to run several replicas.

## Issuers

Trusted OIDC token issuers, for bearer tokens (`Authorization: Bearer <JWT>`) and for the UI login.

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Identifier used by bindings and in subjects (`<name>:<sub>`). |
| `issuer` | (required) | Expected `iss`, HTTPS. |
| `jwks_url` | discovery | JWKS URL; empty means `<issuer>/.well-known/openid-configuration`. |
| `audiences` | (required) | Accepted `aud` values. Use a gate-specific audience so tokens minted for other services are refused. |
| `bound_claims` | `{}` | Claim globs every token of this issuer must match (`claim: pattern` or a list, any match). |
| `subject_claim` | `sub` | Claim used as subject id (`<name>:<id>` in the audit log). |
| `subject_template` | | Composite subject id instead of `subject_claim`, e.g. `"{{tid}}/{{oid}}"`; every referenced claim must be a non-empty string. |
| `team_claim` | | Claim (string or list) whose values are added to the subject teams. |
| `name_claim` | subject id | Claim shown as display name in the UI and the audit log. |
| `category` | `pipeline` | `human` or `pipeline`, static. UI sessions are always `human`. |
| `category_claim`, `category_map` | | Derive the category from a claim value, e.g. `idtyp` with `{app: pipeline, user: human}`; unmapped values fall back to `category`. |
| `algorithms` | all asymmetric | Allowed `alg`; HMAC algorithms are refused. |
| `clock_skew` | `60s` | Leeway on `exp`, `nbf`, `iat` (maximum `5m`). |

Tokens must carry `exp` and the subject claim(s). Keys are cached and refetched on an unknown `kid` (at most every 30 s).

Claim matching (`bound_claims`, `bindings[].subjects[].claims`): a string claim must match one of the globs; an array claim (Entra `roles`, `groups`) matches when **it contains** a value matching one of the globs. Booleans and numbers are compared as text; other types never match.

Examples: AWS IAM outbound identity federation (`sts:GetWebIdentityToken`, the issuer URL is given by `aws iam get-outbound-web-identity-federation-info`, `sub` is the role ARN), GitHub Actions (`https://token.actions.githubusercontent.com`), Kubernetes projected service account tokens (cluster OIDC issuer, custom audience), any corporate IdP.

### Entra ID

Azure Managed Identity, AKS Workload Identity and Azure DevOps service connections using workload identity federation all end with an Entra **access token** whose audience is the gate app registration. Configure one issuer for the tenant:

```yaml
issuers:
  - name: entra
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    audiences: ["api://eurodns-gate", "<gate-application-id>"]
    subject_template: "{{tid}}/{{oid}}"
    bound_claims: {tid: "<tenant-id>"}
    category_claim: idtyp
    category_map: {app: pipeline, user: human}
    name_claim: name
```

- Issuers are fixed tenants only: `/common`, `/organizations` and `/consumers` are refused (their `iss` is not fixed). v2 (`https://login.microsoftonline.com/<tid>/v2.0`) and v1 (`https://sts.windows.net/<tid>/`) are accepted when configured explicitly; for v1 the JWKS URL defaults to the tenant keys (`https://login.microsoftonline.com/<tid>/discovery/v2.0/keys`). Entra audiences must be the application id (GUID) or an `api://` URI.
- App registration of the gate: expose an Application ID URI (`api://eurodns-gate`), set `accessTokenAcceptedVersion: 2` in the manifest (tokens then carry the v2 issuer), declare **app roles** (for example `DNS.Write`, `DNS.Read` for applications, `DNS.Admin` for users) and set *Assignment required* on the enterprise application so only assigned identities obtain a token.
- Bind on `oid` (object id of the managed identity or service principal, stable) or on `roles` (app roles assigned in Entra). `sub` is pairwise per application and `appid`/`azp` identify the client application, not the identity.

```yaml
bindings:
  - role: web-cname-writer          # Azure Managed Identity (VM, Function, Container App)
    team: web
    subjects:
      - issuer: entra
        claims: {oid: "<managed-identity-object-id>", idtyp: app}
  - role: acme-solver               # AKS Workload Identity: federated credential on a user-assigned identity
    team: platform
    subjects:
      - issuer: entra
        claims: {oid: "<workload-identity-object-id>"}
  - role: acm-validation            # Azure DevOps pipeline (service connection, workload identity federation)
    team: platform
    subjects:
      - issuer: entra
        claims: {roles: ["DNS.Write"], idtyp: app}
```

Azure DevOps step:

```yaml
- task: AzureCLI@2
  inputs:
    azureSubscription: dns-gate          # workload identity federation service connection
    scriptType: bash
    scriptLocation: inlineScript
    inlineScript: |
      export EURODNS_GATE_TOKEN=$(az account get-access-token --scope api://eurodns-gate/.default --query accessToken -o tsv)
      terraform apply -auto-approve
```

### Azure DevOps OIDC

Azure DevOps also issues its own OIDC token for a service connection (issuer `https://vstoken.dev.azure.com/<organization-id>`, `sub` = `sc://<organization>/<project>/<service connection>`), which the Terraform provider requests with `gate.auth.azure_devops` without any cloud login. Its audience is fixed to `api://AzureADTokenExchange` for every service connection of the organization and is also what Entra ID and cloud identity federations (AWS, GCP) accept, so a token accepted by the gate could be replayed there and the other way round. Only trust it for **dedicated** service connections:

- one service connection per pipeline, used for nothing but the gate (a generic service connection without credentials is enough), authorized for that pipeline only;
- no Entra federated credential, AWS role or other federation trusts its subject (check the trust policies match subjects exactly, not with wildcards);
- the issuer is bound to those exact subjects.

```yaml
issuers:
  - name: azure-devops
    issuer: https://vstoken.dev.azure.com/<organization-id>
    audiences: ["api://AzureADTokenExchange"]
    bound_claims:
      sub:
        - sc://<organization>/<project>/eurodns-gate-certificates-prd
    category: pipeline
bindings:
  - role: acm-validation
    team: platform
    subjects:
      - issuer: azure-devops
        claims: {sub: [sc://<organization>/<project>/eurodns-gate-certificates-prd]}
```

The step running Terraform must expose `SYSTEM_ACCESSTOKEN: $(System.AccessToken)`. When the pipeline already logs in to Azure, the Entra token above (audience = the gate application) needs no such precautions and is preferable.

## Virtual keys

Gate-issued credentials for clients that only speak the EuroDNS `X-APP-ID` / `X-API-KEY` scheme (Caddy, lego). Point the client at the gate URL and give it the virtual key: it never sees the EuroDNS key.

| Field | Description |
|---|---|
| `id` | Identifier, shown as `virtual-key:<id>`. |
| `app_id` | Value expected in `X-APP-ID`. |
| `key_sha256` | Lowercase hex SHA-256 of the key (`printf %s "$KEY" \| sha256sum`). Generate keys with `openssl rand -base64 32`. |
| `roles`, `teams` | Granted directly (no binding). |
| `expires_at` | RFC 3339 expiry. Strongly recommended. |
| `allowed_cidrs` | Source addresses allowed to use the key. |

Virtual keys are the weakest credential: restrict them to narrow roles such as `acme-solver`, with an expiry and source CIDRs.

## Roles

A map of named roles. Deny by default: an action is allowed only if a rule of one of the subject's roles matches.

| Field | Description |
|---|---|
| `rules[].zones` | Zone globs (`*` matches any sequence, `*` alone any managed zone). |
| `rules[].actions` | `dns.read`, `dns.record.write`, `dns.record.adopt`, `dns.zone.admin`, `domain.read`, `ui.read`. |
| `rules[].records.hosts` | Host patterns relative to the zone, `@` is the apex. `*` matches one label, `**` one or more labels (a bare `**` matches every host, apex included). |
| `rules[].records.types` | Record types, `*` for any. Omit `records` to cover the whole zone. |
| `rebase_on_save` | On a full-zone PUT, ignore differences outside the role's scope instead of refusing them (stale zones sent by ACME clients). Granted if any role of the subject enables it. |
| `ephemeral_ttl` | RRsets created by the role expire and are garbage-collected after this duration (ACME challenges). Applies only if every write role of the subject is ephemeral. |
| `max_changes_per_request` | `0` = global default, `-1` = unlimited, otherwise a limit. The most permissive role of the subject wins. |

`dns.record.write` and `dns.record.adopt` are further limited by ownership: the gate only modifies or deletes RRsets it created or adopted, owned by one of the subject's teams.

## Groups

`groups` maps a name to a description and member matchers. A subject belongs to a group when **one** of its matchers matches (all claims of that matcher must match; an array claim matches when one element matches the glob).

```yaml
groups:
  dns-operators:
    description: Entra app role Gate.Operator
    members:
      - issuer: entra
        claims: {roles: [Gate.Operator]}
  release-pipelines:
    members:
      - issuer: github
        claims: {sub: ["repo:acme/web:environment:production"]}
```

With Entra ID, prefer **app roles** (`roles` claim) assigned to Entra groups. If you match Entra group object ids (`groups` claim), set `groupMembershipClaims: ApplicationGroup` on the gate app registration so only groups assigned to the application are emitted and tokens never hit the groups overage (more than 200 groups replaces the claim by a link the gate does not follow).

## Bindings

| Field | Description |
|---|---|
| `role` | Role granted. |
| `team` | Owner team of the RRsets created through this binding. Required to write. |
| `groups` | Groups whose members get the role. |
| `subjects[].issuer` | Issuer name. |
| `subjects[].claims` | Claim globs, all must match (at least one claim, typically `sub`). |

A binding needs `groups`, `subjects` or both (a subject matching either is bound). A subject collects every matching binding (roles and teams, base bindings first in file order, then managed ones; the first team owns new RRsets). A valid token with no binding gets `403 no_binding`.

## Protected records

`protected[]` entries (`zones`, `hosts`, `types`, same patterns as rules) are never writable nor adoptable, whatever the role. They stay readable.

## Managed policy (editing from the UI)

The policy has two layers, merged at evaluation:

- **base**: this file (GitOps). Issuers, UI, store, protected records, `policy.bounds` and every `policy.*` grant live only here.
- **managed**: a document of groups, roles, bindings and virtual keys stored as immutable **revisions** in the store and edited from the UI (or the API).

Rules of the managed layer:

- a managed role or group cannot reuse a base name;
- managed rules cannot grant `policy.*` actions and must stay within `policy.bounds` (zone globs, actions); a managed binding may reuse a base role only if that role also stays within the bounds;
- protected records still win over everything;
- managed virtual keys must have `expires_at`, and only their SHA-256 is stored (`POST /api/v1/policy/virtual-keys/generate` returns a random key once);
- `max_changes_per_request: -1` (unlimited) is reserved to the base.

| Field | Default | Description |
|---|---|---|
| `policy.editable` | `false` | Enables the managed layer. Without it, only the base applies and the policy API is read-only. |
| `policy.require_approval` | `true` | Activation requires an approval by an approver other than the author. |
| `policy.edit_max_age` | `15m` | Humans must have authenticated at the IdP within this delay to change the policy. |
| `policy.require_amr` | `[]` | Authentication methods required for changes, e.g. `["mfa"]` (the IdP must emit the `amr` claim). |
| `policy.bounds.zones` | (required if editable) | Zone globs managed rules may target (`*` wildcards only). |
| `policy.bounds.actions` | (required if editable) | Actions managed rules may grant (`policy.*` refused). |

Meta actions, granted only by base roles: `policy.read` (view the policy, revisions, diff, explain, who-can), `policy.propose` (create revisions, rollback, generate virtual keys), `policy.approve` (approve, reject, activate). Virtual keys cannot hold them.

Workflow: **propose** (validated, based on the active revision `parent_id`; `409 stale_revision` if another revision was activated meanwhile) → **approve** / **reject** (an author cannot approve their own revision; an author may reject it to withdraw it) → **activate** (atomic: `409 conflict` when another activation won the race; the document is re-validated against the current base) → **rollback** (a new proposal copying an older revision). Each revision shows a unified YAML diff against its parent and an impact analysis (permissions gained and lost per binding, group and key, and a warning when a team that owns RRsets loses write on their zone). Every step is audited (`policy.propose`, `policy.approve`, `policy.reject`, `policy.activate`, with the revision id).

Each replica checks the active revision every 10 seconds and recompiles; evaluation never calls the store. If the base file changes so that the active revision no longer validates, the replica keeps the previous policy and logs an error.

Security of UI mutations: every `POST` authenticated by the session cookie must carry `X-Gate-CSRF` equal to the `gate_csrf` cookie (set at login) and an `Origin` equal to the gate origin. Humans (session or bearer token of category `human`) need a recent authentication (`auth_time` within `policy.edit_max_age`, and `amr` containing `policy.require_amr`), otherwise `403 reauth_required`; the UI then sends them to `/auth/login?reauth=1&return_to=...`, which forces `prompt=login` and `max_age`. Pipelines (bearer tokens of category `pipeline`) may propose when a base binding grants `policy.propose`, without step-up, but can never approve their own proposal.

## Adoption and Terraform export

Adoption brings RRsets created outside the gate (foreign) under the ownership of a team, so that the gate can then manage them. It requires `dns.record.adopt` on each RRset and never applies to protected or server-managed (SOA, locked) records.

1. `POST /api/v1/zones/{zone}/adopt/preview` with a selection (`rrsets`, or `hosts` globs and `types`, plus an optional `owner` team): returns the candidates, whether each is adoptable (or why not: `protected`, `server_managed`, `owned_by_other_team`, `already_owned`, `forbidden`, `relative_target`) and a `preview_token` bound to the exact upstream content.
2. `POST /api/v1/zones/{zone}/adopt` with the chosen `rrsets`, the `preview_token` and a mandatory `comment`. All or nothing: if any RRset changed since the preview or is no longer adoptable, nothing is adopted and the answer is `409 adopt_conflict`.

Both are mutations for CSRF (cookie sessions) and the apply requires the same recent authentication as policy changes for humans.

`GET /api/v1/zones/{zone}/terraform?team=&hosts=&types=` (`ui.read`) downloads the **managed** RRsets of a zone as Terraform/OpenTofu configuration for the `kamorionlabs/eurodns` provider: one `eurodns_record_set` per RRset plus `import` blocks, so a team can move what it adopted into its own stack. `hosts` (host globs) and `types` accept comma-separated values or repeated parameters; `rrsets=www/A,@/MX` exports exactly that selection (for example what was just adopted) and takes precedence over `hosts` and `types`.

## MCP

`/mcp` exposes the gate to AI assistants with the Model Context Protocol (Streamable HTTP transport, stateless).

| Field | Default | Description |
|---|---|---|
| `mcp.enabled` | `false` | Serves `/mcp` and `/.well-known/oauth-protected-resource`. |
| `mcp.allow_writes` | `false` | Adds the write tools (plan/apply, adoption). Without it, the server is read-only. |
| `mcp.plan_ttl` | `10m` | Lifetime of a plan returned by `plan_rrset_change` (1m to 1h). |
| `mcp.requests_per_minute` | `120` | Rate limit per subject (`429` beyond). |
| `mcp.public_url` | UI origin, else the request host | Public base URL of the gate, advertised in the protected resource metadata and shown on the Connect page. |

Authentication is the same as the API: an OIDC bearer token of a configured issuer, or a virtual key (`X-APP-ID` / `X-API-KEY`); cookies are ignored. Without credentials the answer is `401` with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource"`, and that document (RFC 9728) names the UI issuer as authorization server. Every tool runs with the RBAC and ownership rules of the caller and is audited (`mcp.<tool>`, with `via: mcp` and the client name).

Tools:

| Tool | Kind | Description |
|---|---|---|
| `list_zones` | read | Readable zones with their counts. |
| `list_rrsets` | read | RRsets of a zone, filters on status, host glob, type, owner. |
| `get_rrset` | read | One RRset and its recent audit history. |
| `search_audit` | read | Audit search, same visibility as the UI. |
| `explain`, `who_can` | read | Policy simulation (`policy.read`). |
| `plan_rrset_change` | dry run | Desired state of RRsets, checked without writing; returns a `plan_id` bound to the caller, the zone, the changes and the zone version. |
| `apply_rrset_change` | write | Applies a plan exactly as planned; refused when expired, used, owned by another caller, or when the zone changed since (`precondition`). |
| `adopt_preview`, `adopt_apply` | dry run, write | Adoption as above. |

There is no policy tool: policy changes stay with humans in the UI, with step-up. Plans live in the memory of the replica that created them: with several replicas, route `/mcp` to a single replica or accept that a plan must be applied where it was made.

### Connecting an assistant

The **Connect** page of the UI (`/ui/#/connect`, data from `GET /api/v1/connect`) shows the commands below already filled in with the gate URL, the tenant and the token scope (`ui.cli_scope`), plus the Terraform provider block and a `curl` example. The gate only needs an access token of a configured issuer whose audience is the gate; with Entra ID, the Azure CLI gets one for the signed-in user.

Claude Code, with a `headersHelper` that Claude Code runs again on each connection and on a `401` or `403`, so the token never goes stale (needs the Azure CLI signed in to the gate's tenant, `az login --tenant <tenant-id>`, and `jq`):

```sh
claude mcp add-json eurodns-gate '{"type":"http","url":"https://gate.example.com/mcp","headersHelper":"az account get-access-token --scope api://<client-id>/.default --query accessToken -o tsv | jq -Rc \"{Authorization: (\\\"Bearer \\\" + .)}\""}' --scope user
```

The helper must print `{"Authorization":"Bearer <token>"}`. With another issuer, replace the `az` command by any command printing an access token.

Claude Desktop and other clients that only start local servers go through the [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) bridge (Node.js) in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "eurodns-gate": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://gate.example.com/mcp", "--header", "Authorization:${AUTH_HEADER}"],
      "env": { "AUTH_HEADER": "Bearer <access token>" }
    }
  }
}
```

The token is static there: an Entra access token lasts about an hour, after which it must be fetched again (`az account get-access-token --scope api://<client-id>/.default --query accessToken -o tsv`), pasted into `AUTH_HEADER` and the client restarted.

With Entra ID, `az account get-access-token` for the gate scope requires the gate application to expose that scope and to trust the Azure CLI: add the Azure CLI client id (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) to the authorized client applications of the gate app registration, or grant tenant-wide admin consent; otherwise `az` answers `AADSTS65001` (consent required). The token the CLI receives must then be accepted by a configured issuer (audience and token version, see `accessTokenAcceptedVersion`).

MCP clients that implement the OAuth flow discover the issuer through the resource metadata, but Entra ID does not support OAuth dynamic client registration: register the MCP client as an application in Entra, or pass a token as above.

## UI

Read-only web UI under `/ui/` and its JSON API under `/api/v1` (action `ui.read`; the API also accepts bearer tokens and virtual keys).

| Field | Default | Description |
|---|---|---|
| `ui.enabled` | `false` | Enables `/ui/`, `/auth/*` and session cookies. |
| `ui.issuer` | (required) | Name of a configured issuer used for the login. |
| `ui.client_id` | (required) | OIDC client id registered at the IdP. |
| `ui.redirect_url` | (required) | `https://<gate>/auth/callback`, registered at the IdP. |
| `ui.scopes` | `openid profile email` | Must include `openid`; add the scope that carries the claims used in bindings (for example `groups`). |
| `ui.session_ttl` | `8h` | Session lifetime (1m to 24h). |
| `ui.cli_scope` | `api://<client_id>/.default` with an Entra v2 issuer, else empty | OAuth scope a command-line tool requests to get a token for the gate, shown on the Connect page (`az account get-access-token --scope ...`, Terraform `azure_identity.scope`). One scope of letters, digits and `. _ ~ : / % -`, so it can be pasted into shell commands as is. Set it when the Application ID URI of the gate is not `api://<client_id>`. |

Login is the authorization code flow with PKCE (S256), `state` and `nonce` checked. The ID token is verified with the issuer keys and `aud = client_id`; issuer `bound_claims` apply. The session cookie (`__Host-` prefixed when the redirect URL is HTTPS) is encrypted with AES-256-GCM, `HttpOnly`, `Secure`, `SameSite=Lax`. It keeps the identity claims of the ID token (protocol claims dropped) plus `auth_time` and `amr`; roles, groups and teams are recomputed on every request, so a policy change applies immediately. A login whose claims do not fit in a cookie fails with `session_too_large`: reduce the emitted claims (Entra: app roles rather than groups). `POST /auth/logout` clears it.

Audit events of zones the user cannot read are filtered out; events without a zone (authentication failures) are shown only to users who can read every managed zone.

## Endpoints

| Path | Description |
|---|---|
| EuroDNS API paths | Opened operations: `getDnsZone`, `saveDnsZone`, `checkDnsZone`, `addDnsRecords`, `deleteDnsRecord` (zone engine), `listDnsZoneSnapshots`, `getSnapShot`, `getDnssecStatus`, `getDomain` (proxied). Every other operation returns `403 operation_denied`. Query strings, encoded separators and dot segments are refused. |
| `GET /.well-known/eurodns-gate` | Version and features (`if-match`, `ownership`, `adopt`), unauthenticated. |
| `POST /.well-known/eurodns-gate/zones/{zone}/adopt` | Adopt RRsets (used by the Terraform provider on import). Foreign RRsets need `dns.record.adopt`; RRsets already owned by one of the caller's teams are a no-op and only need `dns.record.write` on the zone. |
| `/api/v1/me`, `/api/v1/connect`, `/api/v1/zones`, `/api/v1/zones/{zone}/rrsets`, `/api/v1/audit` | UI API (`ui.read`; `/me` for any bound subject, with its groups and effective permissions; `/connect` returns the public URL, the MCP state, the login issuer and `ui.cli_scope` for the Connect page). |
| `/api/v1/policy`, `/api/v1/policy/revisions[/{id}[/approve\|reject\|activate\|rollback\|export]]`, `/api/v1/policy/explain`, `/api/v1/policy/who-can`, `/api/v1/policy/virtual-keys/generate` | Policy API, see `internal/uiapi/policy.go`. |
| `/auth/login`, `/auth/callback`, `/auth/logout` | UI login. |
| `/healthz`, `/readyz` | Probes. |

`GET` on a zone returns an `ETag`; send it back in `If-Match` on writes to get `412 precondition` instead of overwriting a concurrent change. Errors are JSON `{"reason": "...", "message": "..."}`: `forbidden`, `not_owner`, `too_many_changes` (403), `foreign_rrset`, `tainted` (409), `precondition` (412), `invalid_zone` (400), `zone_locked` (503, `Retry-After`), `upstream` (502).
