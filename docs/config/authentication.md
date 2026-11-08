# Issuers and keys

Who may call the gate: OIDC issuers, the gate's own tokens, the token exchange, and static virtual keys. Background: [Identities](../concepts/identities.md); API keys are issued at runtime, see [API keys](../API.md#api-keys).

## Issuers

Trusted OIDC token issuers, for bearer tokens (`Authorization: Bearer <JWT>`) and for the UI login.

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Identifier used by bindings and in subjects (`<name>:<sub>`). `api-key`, `virtual-key` and `gate` are reserved for subjects of the gate itself (the gate issuer may be named `gate`). |
| `issuer` | (required) | Expected `iss`, HTTPS. |
| `jwks_url` | discovery | JWKS URL; empty means `<issuer>/.well-known/openid-configuration`. |
| `audiences` | (required) | Accepted `aud` values. Use a gate-specific audience so tokens minted for other services are refused. |
| `bound_claims` | `{}` | Claim globs every token of this issuer must match (`claim: pattern` or a list, any match). |
| `subject_claim` | `sub` | Claim used as subject id (`<name>:<id>` in the audit log). |
| `subject_template` | | Composite subject id instead of `subject_claim`, e.g. `"{{tid}}/{{oid}}"`; every referenced claim must be a non-empty string. |
| `team_claim` | | Claim (string or list) whose values are added to the subject teams, after `team_claim_prefix`. |
| `team_claim_prefix` | | Prepended to every `team_claim` value: the teams of the claim form the family `<prefix>*` of this issuer, and only that family. Required once a [`teams`](policy.md#teams) block exists. |
| `email_trusted` | `true` | Whether the `email` claim of this issuer identifies a person for the [two-person rule](policy.md#ownership) of transfers (an `email_verified: false` claim always excludes it). |
| `name_claim` | subject id | Claim shown as display name in the UI and the audit log. |
| `category` | `pipeline` | `human` or `pipeline`, static. UI sessions are always `human`. |
| `category_claim`, `category_map` | | Derive the category from a claim value, e.g. `idtyp` with `{app: pipeline, user: human}`; unmapped values fall back to `category`. |
| `algorithms` | all asymmetric | Allowed `alg`; HMAC algorithms are refused. |
| `clock_skew` | `60s` | Leeway on `exp`, `nbf`, `iat` (maximum `5m`). |
| `self` | `false` | This issuer is the gate itself, see [Gate-issued tokens](#gate-issued-tokens). |
| `token_ttl` | `1h` | Lifetime of gate-issued tokens (`self: true` only, 1m to 24h). |
| `token_exchange` | `false` | Tokens of this issuer can be exchanged for gate tokens, see [Token exchange](#token-exchange). Needs a gate issuer; refused on it. |
| `max_exchanged_ttl` | `15m` | Longest lifetime of a gate token exchanged for a token of this issuer (`token_exchange` only, 1m to 24h). |
| `delegated_clients` | `[]` | Applications acting for the users of this issuer with capped rights, see [Delegated clients](#delegated-clients). Not on the gate issuer. |
| `require_known_client` | `false` | Refuse the tokens whose `azp` / `appid` matches no delegated client (`403 unknown_client`). Needs `delegated_clients`. |

Tokens must carry `exp` and the subject claim(s). Keys are cached and refetched on an unknown `kid` (at most every 30 s).

Claim matching (`bound_claims`, `bindings[].subjects[].claims`): a string claim must match one of the globs; an array claim (Entra `roles`, `groups`) matches when **it contains** a value matching one of the globs. Booleans and numbers are compared as text; other types never match.

Examples: AWS IAM outbound identity federation (`sts:GetWebIdentityToken`, the issuer URL is given by `aws iam get-outbound-web-identity-federation-info`, `sub` is the role ARN), GitHub Actions (`https://token.actions.githubusercontent.com`), Kubernetes projected service account tokens (cluster OIDC issuer, custom audience), any corporate IdP.

### Gate-issued tokens

Humans signed in to the UI with [SAML](ui-mcp.md#saml-login) have no access token of their own for the API, the MCP endpoint or Terraform. The gate then issues its own: declare one issuer with `self: true`.

```yaml
issuers:
  - name: gate
    self: true
    issuer: https://dns.example.com   # public origin of the gate, no path
    # audiences: [https://dns.example.com]   (default: the issuer URL)
    # token_ttl: 1h
```

- The signing key comes from `DNS_GATE_TOKEN_SIGNING_KEY` (or `_FILE`): EC P-256 (`ES256`) or Ed25519 (`EdDSA`), PEM (SEC 1 or PKCS #8). Every instance of the gate (replicas, Lambda) uses the same key. The public key is published at `GET /.well-known/jwks.json` (`kid` = RFC 7638 thumbprint). Changing the key invalidates the tokens in circulation, which last `token_ttl` at most.
- A token has `iss` = `issuer`, `aud` = the first audience, `exp` = `token_ttl` from issuance but never after the end of the session it comes from, a `jti`, and the claims of that session: `sub`, the mapped claims (`email`, `name`, `groups`...), `auth_time` and `amr`, plus `gate_iss` (the issuer of the session, e.g. `identity-center`) and `gate_cat` (`human`).
- The gate verifies its tokens with its own key (no JWKS fetch) and **binds them as the issuer of the session** (`gate_iss`): the subject is `identity-center:alice@example.com`, the bindings and groups of `identity-center` apply, with that issuer's `bound_claims`, `team_claim` and `name_claim`. The `gate` issuer itself is never named in bindings or groups (refused at load). Since roles are recomputed at every request, a binding removed takes effect on the next request of a token.
- Step-up (`policy.edit_max_age`, `policy.require_amr`) uses the `auth_time` and `amr` of the session, so a token obtained right after a re-authentication can mutate the policy, as the session itself.
- Every issuance is audited (`token.issue`, with `jti`, expiry, `via`: `api`, `authorization_code` or `refresh_token`, and `client_id`).

Tokens are obtained:

- by a signed-in browser session: `POST /api/v1/tokens` (session cookie, `X-Gate-CSRF` header and same-origin `Origin`, as every UI mutation) answers `{"access_token", "token_type": "Bearer", "expires_in", "expires_at", "issuer"}`. Bearer tokens and virtual keys cannot get one (`403 session_required`): a token never extends itself;
- by the [Claude Desktop extension](ui-mcp.md#claude-desktop-extension) and other native clients, through the gate authorization server: `GET /.well-known/openid-configuration` (also `/.well-known/oauth-authorization-server`) describes `/oauth/authorize` and `/oauth/token`. Only the public client `dns-gate-relay` with a loopback redirect `http://localhost:<port>` or `http://127.0.0.1:<port>` (no path) is accepted, with PKCE S256 required. `/oauth/authorize` sends a user without session through the UI login (SAML or OIDC), then shows a consent page ("Allow" posts back with the CSRF token and the origin checked). The authorization code (2 minutes) and the refresh token (until the end of the session) are sealed with the session key: nothing is stored, any instance redeems them. A code is not single-use within its 2 minutes, but it is useless without the PKCE verifier that only the client holds. The refresh grant re-checks the bindings of the subject before signing a new token.

The authorization server also works with an OIDC UI login, but the Claude Desktop extension keeps signing in with the OIDC issuer in that case.

### Token exchange

`POST /api/v1/token-exchange` (OAuth 2.0 token exchange, RFC 8693) turns a token of an issuer with `token_exchange: true` into a gate token with the same identity. It serves tools that hold one credential for a whole run while the CI or workload token lives a few minutes (acme.sh, see [ACME.md](../ACME.md#1-choose-your-credential)).

```yaml
issuers:
  - name: github
    issuer: https://token.actions.githubusercontent.com
    audiences: [dns-gate]
    token_exchange: true
  - name: gate
    self: true
    issuer: https://dns.example.com
```

```sh
curl -fsS https://dns.example.com/api/v1/token-exchange \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode "subject_token=$OIDC_TOKEN"
# {"access_token": "…", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "expires_in": 900}
```

- The subject token is validated exactly as a bearer token of its issuer: signature, audiences, `bound_claims`, and the identity must be bound (`no_binding` otherwise). `subject_token_type` is `…:jwt`, `…:id_token` or `…:access_token`; `actor_token` (delegation) is refused.
- The gate token carries the claims of the subject token, `gate_iss` (its issuer), `gate_cat` and `gate_xchg` (the `jti` of the exchanged token). It is bound as that issuer, like every gate token: same subject, bindings, teams and category.
- Lifetime: 15 minutes, or `expires_in` (seconds, at least 60), capped by the issuer's `max_exchanged_ttl`, the gate issuer's `token_ttl`, and the expiry of the subject token plus 5 minutes.
- An exchanged token is refused once its issuer no longer has `token_exchange` (after a configuration change).
- Gate tokens and API keys are never exchanged: no chaining. Errors follow RFC 6749 (`400 invalid_grant` with a description); without a gate issuer or an opted-in issuer the endpoint answers `404 token_exchange_disabled`.
- Every exchange is audited (`gate.token.exchange`, with the new `jti` and the exchanged one); refusals too.

### Delegated clients

A token of a trusted issuer carries the rights of its user, whatever application obtained it. A **delegated client** caps them: when the client a token was issued to (`azp` claim, Entra v2; `appid` when the token has no `azp`, Entra v1) is one of the `client_ids` of a client declared on the issuer (compared without case), the request holds the RBAC of the user **intersected** with the actions of the client scopes and with its zones, on the surfaces it may use.

```yaml
issuers:
  - name: entra
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    audiences: ["<gate-application-id>"]
    subject_template: "{{tid}}/{{oid}}"
    # require_known_client: true        # refuse every other client of the issuer
    delegated_clients:
      - id: m365-copilot                 # shown in the audit (client_id)
        name: Microsoft 365 Copilot
        client_ids: [ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b]
        scopes: [dns.read]
        surfaces: [mcp]
      - id: skopea
        client_ids: [11111111-2222-3333-4444-555555555555]
        scopes: [dns.read, dns.plan]
        zones: ["*.example.com"]
```

| Field | Default | Description |
|---|---|---|
| `id` | (required) | Lowercase identifier, recorded as `client_id` in the audit. |
| `name` | `id` | Display name (audit `actor.name`). |
| `client_ids` | (required) | Client ids (string or list), exact but compared without case, matched against the `azp` claim of the token or, without `azp`, its `appid` claim: one entry covers v1 and v2 tokens. A value matches one client only. `azp` and `appid` are accepted as aliases (same meaning). |
| `scopes` | (required) | Ceiling of the client, below. An unknown scope fails the load. |
| `zones` | every zone | Zone globs the client may act on (`*` wildcards), on top of the zones of the user. |
| `surfaces` | `[api]` | `api` (`/api/v1`) and/or `mcp` (`/mcp`). |

| Scope | RBAC actions | Opens |
|---|---|---|
| `dns.read` | `ui.read`, `dns.read`, `domain.read` | Zones, RRsets, forwards, propagation, Terraform export, teams, transfers (list), audit journal; MCP read tools. |
| `dns.plan` | write actions **in a plan only** | `POST …/plan`, `POST …/adopt/preview`; MCP `plan_rrset_change`, `adopt_preview`. |
| `dns.write` | `dns.record.write`, `dns.forward.write` | RRset and forward `PUT` / `DELETE`, plan and `POST …/apply`; MCP `plan_rrset_change`, `apply_rrset_change`. |
| `dns.adopt` | `dns.record.adopt` | `POST …/adopt` (and its preview); MCP `adopt_preview`, `adopt_apply`. |
| `dns.transfer` | `dns.ownership.approve`, and the write rights of the user as proof of ownership of a transfer | Ownership transfers: propose, approve, reject (REST and MCP). |
| `policy.read` | `policy.read` | `POST /api/v1/policy/explain`, `GET /api/v1/policy/who-can`; MCP `explain`, `who_can`. |

- **Never delegable**, whatever the scopes: policy writes and the policy document, delegated policy, API keys (`gate.apikey.manage`), zone administration (`dns.zone.admin`) and zone profiles, `/api/v1/tokens`, the token exchange, `/acme/*`, the EuroDNS-compatible API (whole-zone `PUT` included) and its adopt extension. Every endpoint not listed in the table above answers `403 not_delegable` to a delegated client (deny by default), as does a surface outside `surfaces`.
- A request outside the scopes answers `403 scope_insufficient` with `required_scope` (one scope that would open it); RBAC then applies as usual. On MCP, `tools/list` only returns the tools the scopes open (a `dns.read` client sees the read tools only) and the other tools are refused.
- `GET /api/v1/me` returns `client`, `scopes` and the permissions after the intersection.
- A plan made through a client is applied only by the same user **through the same client**; a plan made without client is never applied through one, and the other way round.
- Tokens of clients that are not declared keep today's behaviour, unless `require_known_client: true`: they are then refused with `403 unknown_client` (tokens without `azp` nor `appid` too), and the refusal is audited.
- Delegated requests are audited with `auth_method: oauth-delegated`, `client_id` and `actor: {type: oauth_client, id, name}` (see [AUDIT.md](../AUDIT.md#fields)); the subject stays the user. The id and name come from this configuration, never from token claims.
- A delegated subject is never a person for the rules on approvers: it cannot approve a transfer unless `ownership.machine_approvers`, nor be the second person of `require_second_approver`. The step-up of humans still applies to it: actions behind the step-up (adoption) answer `reauth_required` unless its token carries a recent `auth_time`.
- `GET /api/v1/me` (roles, groups) and `GET /api/v1/teams/{team}` (roles and permissions of the team) still show the roles of the user and of its teams, for information: what the client may do is given by `client`, `scopes` and the clipped `permissions` of `/me`.
- When an issuer has delegated clients, the gate logs a warning once per undeclared client id it sees: such a token holds the full rights of its user.
- UI logins are not affected: the UI is the gate itself.

Setting up Microsoft 365 Copilot: [Microsoft 365 Copilot](../integrations/m365-copilot.md).

### Entra ID

Azure Managed Identity, AKS Workload Identity and Azure DevOps service connections using workload identity federation all end with an Entra **access token** whose audience is the gate app registration. Configure one issuer for the tenant:

```yaml
issuers:
  - name: entra
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    audiences: ["api://dns-gate", "<gate-application-id>"]
    subject_template: "{{tid}}/{{oid}}"
    bound_claims: {tid: "<tenant-id>"}
    category_claim: idtyp
    category_map: {app: pipeline, user: human}
    name_claim: name
```

- Issuers are fixed tenants only: `/common`, `/organizations` and `/consumers` are refused (their `iss` is not fixed). v2 (`https://login.microsoftonline.com/<tid>/v2.0`) and v1 (`https://sts.windows.net/<tid>/`) are accepted when configured explicitly; for v1 the JWKS URL defaults to the tenant keys (`https://login.microsoftonline.com/<tid>/discovery/v2.0/keys`). Entra audiences must be the application id (GUID) or an `api://` URI.
- App registration of the gate: expose an Application ID URI (`api://dns-gate`), set `accessTokenAcceptedVersion: 2` in the manifest (tokens then carry the v2 issuer), declare **app roles** (for example `DNS.Write`, `DNS.Read` for applications, `DNS.Admin` for users) and set *Assignment required* on the enterprise application so only assigned identities obtain a token.
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
      export DNS_GATE_TOKEN=$(az account get-access-token --scope api://dns-gate/.default --query accessToken -o tsv)
      terraform apply -auto-approve
```

### Azure DevOps OIDC

Azure DevOps also issues its own OIDC token for a service connection (issuer `https://vstoken.dev.azure.com/<organization-id>`, `sub` = `sc://<organization>/<project>/<service connection>`), which the Terraform provider requests with `gate.auth.azure_devops` without any cloud login. Its audience is fixed to `api://AzureADTokenExchange` for every service connection of the organization and is also what Entra ID and cloud identity federations (AWS, GCP) accept, so a token accepted by the gate could be replayed there and the other way round. Only trust it for **dedicated** service connections:

- one service connection per pipeline, used for nothing but the gate (a generic service connection without credentials is enough), authorized for that pipeline only;
- no Entra federated credential, AWS role or other federation trusts its subject (check the trust policies match subjects exactly, not with wildcards);
- the issuer is bound to those exact subjects, or, to bind every gate service connection with one rule ([team derived from a claim](policy.md#team-derived-from-a-claim)), to a subject prefix dedicated to the gate that no other federation trusts either.

```yaml
issuers:
  - name: azure-devops
    issuer: https://vstoken.dev.azure.com/<organization-id>
    audiences: ["api://AzureADTokenExchange"]
    bound_claims:
      sub:
        - sc://<organization>/<project>/dns-gate-certificates-prd
    category: pipeline
bindings:
  - role: acm-validation
    team: platform
    subjects:
      - issuer: azure-devops
        claims: {sub: [sc://<organization>/<project>/dns-gate-certificates-prd]}
```

In the pipeline:

- the step running Terraform must expose `SYSTEM_ACCESSTOKEN: $(System.AccessToken)`;
- a task of the **same job** must reference the service connection, otherwise Azure DevOps answers `HTTP 400 There is no explicit reference to service connection`. A skipped step is enough, in the plan job and in the apply job:

  ```yaml
  - task: cURLUploader@2
    displayName: Reference the dns-gate service connection
    condition: false
    inputs:
      files: none
      authType: ServiceEndpoint
      serviceEndpoint: dns-gate-certificates-prd
  ```
- the provider takes the connection id from `service_connection_id`, or from `DNS_GATE_ADO_SERVICE_CONNECTION_ID`, which a variable group named after the pipeline can carry so that nothing holds an id.

One binding for every dedicated service connection, each one owning its records (team = service connection name), so that a new pipeline needs a service connection but no gate change:

```yaml
issuers:
  - name: azure-devops
    issuer: https://vstoken.dev.azure.com/<organization-id>
    audiences: ["api://AzureADTokenExchange"]
    bound_claims:
      sub: ["sc://<organization>/<project>/dns-gate-*"]   # prefix dedicated to the gate
    category: pipeline
bindings:
  - role: pipeline-writer
    team_from:
      claim: sub
      regex: "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"   # team dns-gate-<name>
    subjects:
      - issuer: azure-devops
        claims: {sub: ["sc://<organization>/<project>/dns-gate-*"]}
```

The glob turns the right to create service connections into the right to mint gate identities: see the trade-off under [Team derived from a claim](policy.md#team-derived-from-a-claim).

When the pipeline already logs in to Azure, the Entra token above (audience = the gate application) needs no such precautions and is preferable.

## Virtual keys

Static credentials, declared in the file, for clients that only speak the EuroDNS `X-APP-ID` / `X-API-KEY` scheme, on the EuroDNS-compatible API. Point the client at the gate URL and give it the virtual key: it never sees the EuroDNS key. ACME clients have better options on every provider: see [ACME.md](../ACME.md).

| Field | Description |
|---|---|
| `id` | Identifier, shown as `virtual-key:<id>`. |
| `app_id` | Value expected in `X-APP-ID`. |
| `key_sha256` | Lowercase hex SHA-256 of the key (`printf %s "$KEY" \| sha256sum`). Generate keys with `openssl rand -base64 32`. |
| `roles`, `teams` | Granted directly (no binding). The teams must be declared once a [`teams`](policy.md#teams) block exists. |
| `expires_at` | RFC 3339 expiry. Strongly recommended. |
| `allowed_cidrs` | Source addresses allowed to use the key. |

Virtual keys are the weakest credential: restrict them to narrow roles such as `acme-solver`, with an expiry and source CIDRs.

Virtual keys are static: changing one means a configuration change. Keys issued at runtime, rotated with an overlap and revoked through the API are [API keys](../API.md#api-keys) (`gate.apikey.manage`), stored hashed in the store and accepted everywhere virtual keys are, plus the neutral API and the [ACME endpoints](../ACME.md). The `dgk_` prefix is reserved to API keys.
