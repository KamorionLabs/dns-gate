# Configuration reference

dns-gate reads one YAML file (`-config`, default `/etc/dns-gate/config.yaml`, or `DNS_GATE_CONFIG_URI` / `DNS_GATE_CONFIG`): a file path, `s3://bucket/key` or `ssm:/parameter/name`. Decoding is strict: an unknown field stops the gate at startup. `dns-gate -check -config file.yaml` validates a file and exits.

A complete example is in [`examples/config.yaml`](../examples/config.yaml).

## Secrets

Secrets never live in the YAML file. Each one is read from an environment variable, or from the file named by the same variable with a `_FILE` suffix (the form to use with Kubernetes Secret volumes).

| Variable | Used for | Required |
|---|---|---|
| `EURODNS_<ID>_API_KEY`, else `EURODNS_API_KEY` | EuroDNS `X-API-KEY` of the provider `<ID>` | with a `eurodns` provider |
| `EURODNS_<ID>_APP_ID`, else `EURODNS_APP_ID` | EuroDNS `X-APP-ID`, overrides `eurodns.app_id` | if `eurodns.app_id` is empty |
| `DNS_GATE_POSTGRES_DSN` | Postgres connection string | with `store.type: postgres` |
| `DNS_GATE_SESSION_KEY` | 32-byte key (hex or base64) encrypting UI cookies | with `ui.enabled` |
| `DNS_GATE_UI_CLIENT_SECRET` | OIDC client secret of the UI | no (public client with PKCE) |
| `DNS_GATE_SAML_SP_KEY`, `DNS_GATE_SAML_SP_CERT` | PEM key (RSA or ECDSA) and certificate of the SAML service provider, signing the AuthnRequests | no (unsigned requests) |
| `DNS_GATE_TOKEN_SIGNING_KEY` | PEM key (EC P-256 or Ed25519) signing [gate-issued tokens](#gate-issued-tokens) | with an issuer `self: true` |

`<ID>` is the provider id in upper case, every character other than a letter or a digit replaced by `_` (`eu-2` gives `EURODNS_EU_2_API_KEY`); the unprefixed variables serve every EuroDNS provider without its own. Route53 providers use the default AWS credential chain (IRSA, Pod Identity, instance role, environment), optionally assuming a role.

`DNS_GATE_SECRETS_ARN` names a Secrets Manager secret holding a JSON object of these variables (`{"EURODNS_API_KEY":"…"}`), loaded into the environment at startup; a variable already set wins. See [DEPLOY-LAMBDA.md](DEPLOY-LAMBDA.md#configuration).

Other environment variables: `POD_NAME` (lock holder id, defaults to the hostname) and `DNS_GATE_REPLICAS` (only used to warn when a single-replica store runs with several replicas).

Generate a session key with `openssl rand -hex 32`, a token signing key with `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` (or `-algorithm ed25519`).

## Top level

| Field | Default | Description |
|---|---|---|
| `listen.address` | `:8080` | HTTP listen address. TLS is terminated in front of the gate. |
| `listen.trusted_proxies` | `[]` | CIDRs of reverse proxies allowed to set `X-Forwarded-For`. The rightmost untrusted hop is the client address (used by `virtual_keys[].allowed_cidrs`). |
| `providers` | (required) | The DNS accounts the gate fronts, see [Providers](#providers). |
| `zones` | `[]` | Managed zones of the base layer. Zones listed by the active [managed policy](#managed-policy-editing-from-the-ui) revision are added to them. Requests for any other zone are refused before authorization (zones found by [zone discovery](#zone-discovery) are readable only). Each zone must be selected by a provider. |
| `check_on_write` | `true` | Run the provider dry run (EuroDNS `check`) before every write; providers without one (Route53) are not affected. |
| `reconcile_interval` | `15m` | Drift detection period per zone (minimum `1m`). |
| `limits.max_body_bytes` | `1048576` | Request body limit. |
| `limits.max_changes_per_request` | `20` | Default blast-radius limit (RRset changes per request). |
| `limits.ephemeral_lifetime_factor` | `4` | An ephemeral RRset lives at most its creation plus this many `ephemeral_ttl`, however often values are added. |
| `acme.max_registrations` | `100` | acme-dns registrations and httpreq value ledgers per API key or token subject. |
| `acme.registration_idle` | `720h` | Registrations of token subjects and httpreq ledgers unused this long are purged (maintenance, DynamoDB TTL). |
| `acme.max_values` | `20` | Values of one challenge TXT RRset. |
| `acme.max_values_per_author` | `4` | Values one API key or token subject may hold in a challenge TXT RRset (at most `acme.max_values`). |
| `lock.ttl`, `lock.wait` | `60s`, `30s` | Per-zone write lease and how long a request waits for it (then `503 zone_locked`). |

## Providers

A provider is one DNS account: a EuroDNS account or an AWS account for Route53. The gate alone holds its credentials. Each zone is served by exactly one provider: the one whose `zones` filter selects it, or, when the filters of several providers select it, the only one of them whose account lists it. A zone listed by two providers that both select it is served by neither (an error is logged): exclude it from all but one. Ownership, locks and audit stay keyed by zone name.

| Field | Default | Description |
|---|---|---|
| `providers[].id` | (required) | Unique lowercase identifier, shown in the UI, the audit (`provider`) and zone summaries. |
| `providers[].kind` | (required) | `eurodns` or `route53` ([providers/route53.md](providers/route53.md)). |
| `providers[].zones.include` | `["*"]` | Zone globs (`*` wildcards) the provider serves. |
| `providers[].zones.exclude` | `[]` | Zone globs removed; they win over `include`. |
| `providers[].zones.folders` | `[]` | EuroDNS only: keep the zones whose [folder](#eurodns-folders) matches one of these folder globs (`/ES` the folder ES, `/ES/**` every folder below it, `/` the domains in no folder). Empty: every folder. |
| `providers[].zones.folder_expiry` | `3` | Refresh periods the [folders](#eurodns-folders) of a listing are trusted while listings fail. |
| `providers[].zones.refresh` | `1h` | Account listing period (minimum `5m`), see [Zone discovery](#zone-discovery). |
| `providers[].eurodns.base_url` | `https://rest-api.eurodns.com` | EuroDNS API. HTTPS is required (loopback excepted, for tests). |
| `providers[].eurodns.app_id` | | EuroDNS application id (or the variables of [Secrets](#secrets)). |
| `providers[].eurodns.rate.every`, `.burst` | `1.1s`, `5` | Client-side limiter shared by every call to this account (reads, writes, checks, listing, passthrough). EuroDNS allows 10 requests per 10 seconds per IP and bans progressively: keep the default unless EuroDNS raised your quota. |
| `providers[].eurodns.max_retries` | `3` | Retries on 429, 5xx and network errors (idempotent requests). |
| `providers[].eurodns.zone_profiles` | `false` | Serves the [zone profiles](#zone-profiles) of the account through the gate; off, they are refused (`403 zone_profiles_disabled`) even to holders of `dns.zone.profile`. |
| `providers[].route53.region` | SDK default | AWS region of the API calls. |
| `providers[].route53.assume_role_arn` | | IAM role assumed in the account holding the hosted zones. |
| `providers[].route53.external_id` | | External id of the assumed role (requires `assume_role_arn`). |
| `providers[].route53.hosted_zones` | `{}` | Zone name to hosted zone id, to pin a name with several hosted zones or skip the listing of the account. |
| `providers[].route53.include_private` | `false` | Serve private hosted zones too. |

```yaml
providers:
  - id: eurodns
    kind: eurodns
    zones: {include: ["*"], exclude: ["*.example.net"]}
    eurodns: {app_id: acme-gate}
  - id: route53-prod
    kind: route53
    zones: {include: ["*.example.net"]}
    route53:
      region: eu-west-3
      assume_role_arn: arn:aws:iam::123456789012:role/dns-gate
      hosted_zones: {"example.net": Z0123456789ABC}
```

What a provider can write is reported by the gate and enforced by the engine: alias RRsets only where the provider supports them (Route53), accepted TTLs (EuroDNS: a fixed list), read-only RRsets (`read_only` in the inventory: SOA and locked records at EuroDNS, `relative_target` for a EuroDNS RRset holding a target without ending dot, routing policies at Route53), which are never written nor adopted. The [EuroDNS-compatible API](#endpoints) only serves zones of a `eurodns` provider; the RRset API under `/api/v1` serves every zone.

Desired targets (CNAME, MX, NS, SRV, PTR) are read the same way for every provider: a name of several labels is absolute (`target.example.net` is written `target.example.net.`), a single label is refused as ambiguous. Values already stored are never rewritten.

### Zone discovery

The gate lists every provider account each `zones.refresh`, keeps the zones its `zones` filter selects, shows those it does not manage as **unmanaged** (in the UI and in the MCP `list_zones` tool) and lets policy administrators bring them under management from the UI, through a [managed policy](#managed-policy-editing-from-the-ui) revision, without a configuration change. The lists also tell which provider serves a zone selected by several filters.

- **Upstream load**: a EuroDNS listing costs one request per 100 domains (`POST /domains/search`), through the shared rate-limited transport, once per `refresh` and per replica (the lists are held in memory). When a policy proposal names a zone not seen yet, the gate lists the accounts once more, at most once a minute, so that a domain added just before is found. A failed listing is retried after 5 minutes and the previous list is kept.
- **Unmanaged zones are read-only.** Their RRsets are readable with `dns.read` on the zone (UI and MCP; the UI also requires `ui.read`), evaluated by RBAC as usual: the zone globs of the role rules apply, so `zones: ["*"]` in a read role covers every discovered zone. They are never writable nor adoptable, the EuroDNS-compatible API (`/dns-zones/...`), the Terraform export and adoption refuse them, and reconcile does not run on them. Their content is read on demand, when someone opens the zone, and reused for `reconcile_interval`; listing zones never reads them.
- **Bringing a zone under management**: add it to the `zones` list of the managed policy (the UI offers "Manage this zone" to policy administrators), then approve and activate as any revision. It must match `policy.bounds.zones` and be in a discovered list. Once active, the zone behaves as a base zone: writes within the roles, adoption, reconcile. The `zones` filters of the providers therefore also bound what can be managed from the UI.
- The EuroDNS listing uses the key of the provider: its EuroDNS user must be allowed to search domains. Domains whose DNS is not hosted at EuroDNS are listed too: exclude them, reading them fails upstream.

### EuroDNS folders

EuroDNS organises domains in folders (`folderFullPath` of `POST /domains/search`). The listing of a `eurodns` provider keeps the folder of each domain, at no extra cost: `/ES/Madrid`, and `/` for a domain in no folder (`null` or an empty path). Only slashes are normalized (leading `/`, no trailing or repeated `/`): `ES ` and `ES` stay distinct folders. When the field is absent or not a string, the folder is unknown (empty) and no folder selector matches the zone. The folder is shown in `GET /api/v1/zones` (`folder`, with a `?folder=` glob filter), in the zone inventory, in the Zones view of the UI (column, and a filter on the same globs: `/ES` that folder only, `/ES/**` the folders below it) and in the MCP `list_zones` tool. Route53 zones have no folder (empty): folder selectors never match them.

Folder globs use the segments of host patterns, matched case-sensitively: `*` matches one segment, `**` one or more segments, `*` inside a segment any run of characters. `/ES` is the folder ES only, `/ES/**` every folder below it (not ES itself: write both to cover the folder and its subfolders), `/` the domains in no folder. Segments with leading or trailing spaces are refused.

| Field | Default | Description |
|---|---|---|
| `providers[].zones.folders` | `[]` | Keep the domains of the selected folders only. |
| `providers[].zones.folder_expiry` | `3` | Refresh periods the folders of the last successful listing are trusted, counted from the end of that listing, while the following listings fail (2 to 100). Past it, folder rules match no zone of the provider until a listing succeeds (`folders_stale` in the discovery status of `GET /api/v1/policy`). |

- **Serving**: `providers[].zones.folders` keeps only the domains of the selected folders, after `include` and `exclude`. A zone of such a provider is served once a listing has seen it in a selected folder; until the first listing, or after it left the selected folders, it is served by no provider (writes fail, and a base `zones` entry outside them is an error at every write).
- **Rights**: role rules, `policy.bounds` and delegations accept `folders` next to `zones` ([Roles](#roles)). A folder selector never makes a zone managed: the zone must still be in the base or managed `zones`, or discovered to be readable. A zone listed by two providers has no folder.
- **Folders narrow the bounds, never widen them**: a managed rule that applies through its `folders` reaches a zone only if the zone also matches `policy.bounds.zones`, and a delegated one only if it also matches the `allow.zones` of its delegation. `bounds.zones` and `allow.zones` therefore stay required; use `["*"]` to let folders alone decide within the managed layer. Base rules are not bounded. `GET /api/v1/me` gives these zones with each narrowed permission (`folder_zones`), and the console applies them. For [API keys](API.md#api-keys), a folder pattern of the key role is covered by a managed rule of the issuer only when `bounds.zones` (and, for a delegated rule, `allow.zones`) cover every zone.
- **Moves**: the folder is the one of the last successful listing (`zones.refresh`, and the on-demand refresh of policy proposals). Moving a domain to another folder in the EuroDNS console changes the rights of folder rules at the next listing, without a policy revision. Listings are audited with subject `gate:discovery` and one request id per listing. The first listing of a provider by a process records one `gate.zone.folders_listed` summary (`extra.count`, and `extra.digest`: SHA-256 of the sorted `zone<TAB>folder` lines, equal on every instance that saw the same folders). Later listings record, per zone, `gate.zone.folder_changed` for a zone found in another folder, `gate.zone.folder_seen` for a new zone and `gate.zone.folder_gone` for a zone no longer listed (`extra.old`, `extra.new`). These events are per process, not compared across instances: a move while no instance runs only shows as a different digest. Writes, adoptions and transfer requests and decisions granted through a folder rule carry the `folder` of their authorization in the `extra` of their audit event.
- **Review**: the impact analysis of a revision flags each new or changed folder rule as a dynamic rule, with the zones it reaches currently, and warns when zone discovery has not listed the accounts yet. The configuration loads with a warning when folder selectors exist without a EuroDNS provider, or lie outside the `zones.folders` of every EuroDNS provider.

Whoever may move domains between folders in the EuroDNS account therefore controls folder-based rights: see the [threat model](THREAT-MODEL.md).

## Store

| Field | Default | Description |
|---|---|---|
| `store.type` | `memory` | `memory`, `sqlite`, `postgres` or `dynamodb`. |
| `store.audit_retention` | `9600h` (400 days) | Audit events older than this are purged (minimum `24h`). |
| `store.sqlite.path` | | Database file, on a persistent volume. |
| `store.postgres.max_conns` | `5` | Pool size (1 to 100). The DSN comes from `DNS_GATE_POSTGRES_DSN`. |
| `store.dynamodb.table`, `region`, `endpoint` | | Single-table backend; credentials from the default AWS chain (EKS Pod Identity, IRSA, environment). |

`memory` loses ownership on restart: tests only. `memory` and `sqlite` support **one replica** (the chart refuses `replicaCount > 1` with them); use `postgres` or `dynamodb` to run several replicas.

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
| `team_claim_prefix` | | Prepended to every `team_claim` value: the teams of the claim form the family `<prefix>*` of this issuer, and only that family. Required once a [`teams`](#teams) block exists. |
| `email_trusted` | `true` | Whether the `email` claim of this issuer identifies a person for the [two-person rule](#ownership) of transfers (an `email_verified: false` claim always excludes it). |
| `name_claim` | subject id | Claim shown as display name in the UI and the audit log. |
| `category` | `pipeline` | `human` or `pipeline`, static. UI sessions are always `human`. |
| `category_claim`, `category_map` | | Derive the category from a claim value, e.g. `idtyp` with `{app: pipeline, user: human}`; unmapped values fall back to `category`. |
| `algorithms` | all asymmetric | Allowed `alg`; HMAC algorithms are refused. |
| `clock_skew` | `60s` | Leeway on `exp`, `nbf`, `iat` (maximum `5m`). |
| `self` | `false` | This issuer is the gate itself, see [Gate-issued tokens](#gate-issued-tokens). |
| `token_ttl` | `1h` | Lifetime of gate-issued tokens (`self: true` only, 1m to 24h). |
| `token_exchange` | `false` | Tokens of this issuer can be exchanged for gate tokens, see [Token exchange](#token-exchange). Needs a gate issuer; refused on it. |
| `max_exchanged_ttl` | `15m` | Longest lifetime of a gate token exchanged for a token of this issuer (`token_exchange` only, 1m to 24h). |

Tokens must carry `exp` and the subject claim(s). Keys are cached and refetched on an unknown `kid` (at most every 30 s).

Claim matching (`bound_claims`, `bindings[].subjects[].claims`): a string claim must match one of the globs; an array claim (Entra `roles`, `groups`) matches when **it contains** a value matching one of the globs. Booleans and numbers are compared as text; other types never match.

Examples: AWS IAM outbound identity federation (`sts:GetWebIdentityToken`, the issuer URL is given by `aws iam get-outbound-web-identity-federation-info`, `sub` is the role ARN), GitHub Actions (`https://token.actions.githubusercontent.com`), Kubernetes projected service account tokens (cluster OIDC issuer, custom audience), any corporate IdP.

### Gate-issued tokens

Humans signed in to the UI with [SAML](#saml-login) have no access token of their own for the API, the MCP endpoint or Terraform. The gate then issues its own: declare one issuer with `self: true`.

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
- by the [Claude Desktop extension](#claude-desktop-extension) and other native clients, through the gate authorization server: `GET /.well-known/openid-configuration` (also `/.well-known/oauth-authorization-server`) describes `/oauth/authorize` and `/oauth/token`. Only the public client `dns-gate-relay` with a loopback redirect `http://localhost:<port>` or `http://127.0.0.1:<port>` (no path) is accepted, with PKCE S256 required. `/oauth/authorize` sends a user without session through the UI login (SAML or OIDC), then shows a consent page ("Allow" posts back with the CSRF token and the origin checked). The authorization code (2 minutes) and the refresh token (until the end of the session) are sealed with the session key: nothing is stored, any instance redeems them. A code is not single-use within its 2 minutes, but it is useless without the PKCE verifier that only the client holds. The refresh grant re-checks the bindings of the subject before signing a new token.

The authorization server also works with an OIDC UI login, but the Claude Desktop extension keeps signing in with the OIDC issuer in that case.

### Token exchange

`POST /api/v1/token-exchange` (OAuth 2.0 token exchange, RFC 8693) turns a token of an issuer with `token_exchange: true` into a gate token with the same identity. It serves tools that hold one credential for a whole run while the CI or workload token lives a few minutes (acme.sh, see [ACME.md](ACME.md#1-choose-your-credential)).

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
- the issuer is bound to those exact subjects, or, to bind every gate service connection with one rule ([team derived from a claim](#team-derived-from-a-claim)), to a subject prefix dedicated to the gate that no other federation trusts either.

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

The glob turns the right to create service connections into the right to mint gate identities: see the trade-off under [Team derived from a claim](#team-derived-from-a-claim).

When the pipeline already logs in to Azure, the Entra token above (audience = the gate application) needs no such precautions and is preferable.

## Virtual keys

Static credentials, declared in the file, for clients that only speak the EuroDNS `X-APP-ID` / `X-API-KEY` scheme, on the EuroDNS-compatible API. Point the client at the gate URL and give it the virtual key: it never sees the EuroDNS key. ACME clients have better options on every provider: see [ACME.md](ACME.md).

| Field | Description |
|---|---|
| `id` | Identifier, shown as `virtual-key:<id>`. |
| `app_id` | Value expected in `X-APP-ID`. |
| `key_sha256` | Lowercase hex SHA-256 of the key (`printf %s "$KEY" \| sha256sum`). Generate keys with `openssl rand -base64 32`. |
| `roles`, `teams` | Granted directly (no binding). The teams must be declared once a [`teams`](#teams) block exists. |
| `expires_at` | RFC 3339 expiry. Strongly recommended. |
| `allowed_cidrs` | Source addresses allowed to use the key. |

Virtual keys are the weakest credential: restrict them to narrow roles such as `acme-solver`, with an expiry and source CIDRs.

Virtual keys are static: changing one means a configuration change. Keys issued at runtime, rotated with an overlap and revoked through the API are [API keys](API.md#api-keys) (`gate.apikey.manage`), stored hashed in the store and accepted everywhere virtual keys are, plus the neutral API and the [ACME endpoints](ACME.md). The `dgk_` prefix is reserved to API keys.

## Roles

A map of named roles. Deny by default: an action is allowed only if a rule of one of the subject's roles matches.

| Field | Description |
|---|---|
| `rules[].zones` | Zone globs (`*` matches any sequence, `*` alone any managed zone, and for `dns.read` and `ui.read` any [discovered](#zone-discovery) zone). |
| `rules[].folders` | [EuroDNS folder](#eurodns-folders) globs: the rule also applies to the zones whose folder matches one (`/ES`, `/ES/**`, `/` for the domains in no folder), with the folder known at decision time. A rule needs `zones`, `folders` or both. |
| `rules[].actions` | `dns.read`, `dns.record.write`, `dns.forward.write` ([URL forwards](#url-forwards)), `dns.record.adopt`, `dns.zone.admin`, `dns.zone.profile` ([zone profiles](#zone-profiles), on `*` only), `dns.ownership.approve`, `domain.read`, `ui.read`, `gate.apikey.manage` (manage the [API keys](API.md#api-keys) of the subject's teams whose role zones it covers). |
| `rules[].records.hosts` | Host patterns relative to the zone, `@` is the apex. `*` matches one label, `**` one or more labels (a bare `**` matches every host, apex included). |
| `rules[].records.types` | Record types, `*` for any. Omit `records` to cover the whole zone. URL forwards have the type `URLFWD`; `records.types` does not apply to `dns.forward.write`. |
| `rebase_on_save` | On a full-zone PUT, ignore differences outside the role's scope instead of refusing them (stale zones sent by ACME clients). Granted if any role of the subject enables it. |
| `ephemeral_ttl` | RRsets created by the role expire and are garbage-collected after this duration (ACME challenges); a write adding a value pushes the expiry back, never beyond the creation plus `limits.ephemeral_lifetime_factor` TTLs. Applies only if every write role of the subject is ephemeral. Required by the [ACME endpoints](ACME.md). |
| `max_changes_per_request` | `0` = global default, `-1` = unlimited, otherwise a limit. The most permissive role of the subject wins. |

```yaml
roles:
  spain-dns:
    rules:
      - folders: ["/ES", "/ES/**"]          # every domain of the ES folder and its subfolders
        zones: ["example.es"]               # plus this zone, wherever it is
        actions: [dns.read, dns.record.write, ui.read]
```

`dns.record.write` and `dns.record.adopt` are further limited by ownership: the gate only modifies or deletes RRsets it created or adopted, owned by one of the subject's teams. `dns.ownership.approve` lets a subject adopt RRsets for a team it is not a member of and approve the [ownership transfers](#ownership) of the zone: give it to the people who arbitrate between teams.

### URL forwards

`dns.forward.write` creates, changes and deletes the [URL forwards](API.md#url-forwards) (HTTP redirects) of the zones whose provider has them (EuroDNS), under the same ownership rules (tombstones, transfers, audit). It is scoped by `records.hosts` only, and is separate from `dns.record.write`: a role writing records does not write forwards. Forwards are adopted with `dns.record.adopt` on the host and type `URLFWD` (`types` empty, `*` or listing `URLFWD`). Through the EuroDNS-compatible full-zone PUT, forward changes are forward writes as well. A `dns.zone.admin` holder may also change or delete the forwards the gate does not own, which stay unowned (the event lists them under `zone_admin_forwards`), as before forwards were owned; creating a forward, or changing one owned by a team, always requires `dns.forward.write`. Mail forwards, DomainConnect and the other zone settings changed by a full-zone PUT still require `dns.zone.admin`. A host holding several forwards is read-only: sent back unchanged it is no change, changed it is refused (ignored for `rebase_on_save` roles). Changes of fields the gate does not write (`id`, `updated`, unknown fields) are ignored and listed under `ignored_out_of_scope` in the audit.

A forward replaces the `A`, `AAAA`, `CNAME` and `APEX` records of its host: a forward is created only where those records are absent or owned by one of the caller's teams, and such a record only where the forward of the host is absent or owned by one of the caller's teams (`409 foreign_rrset` or `403 not_owner` otherwise). An RRset owned by another team but missing at the provider, or reserved for another team by a tombstone, counts as present: a deleted record cannot be taken over through a forward on its host, nor the reverse. A [protected entry](#protected-records) listing one of those types protects the forward of its hosts too. Since `records.types` does not apply to `dns.forward.write`, a rule granting it with `records.types` and no `records.hosts` grants the forwards of every host: the gate warns at load and in the impact analysis of managed revisions.

```yaml
roles:
  marketing-redirects:
    rules:
      - zones: [example.com]
        actions: [dns.read, dns.forward.write, ui.read]
        records: {hosts: [go, "*.go", promo]}
```

### Zone profiles

A EuroDNS zone profile is a template of the account (records, URL and mail forwards) that EuroDNS applies to a domain when it arrives on its nameservers: a domain transferred to EuroDNS, or a Premium DNS subscription ordered with the profile's id. Preparing a transfer means creating the profile and checking it before the domain arrives. The gate serves the zone profile operations of every `eurodns` provider ([API.md](API.md#zone-profiles), MCP tools below, and the EuroDNS-compatible `/zone-profiles` routes) under the action `dns.zone.profile`.

Each EuroDNS provider opts in with `providers[].eurodns.zone_profiles: true` (off by default): a grant then covers the profiles of every opted-in account, and only of those.

A profile names no domain (its hosts are relative to whatever domain it is applied to) and the domain it prepares is not in the account yet, so zone globs cannot scope it: **`dns.zone.profile` only counts in a rule whose `zones` cover every zone (`"*"`, `"**"`) and that has no `records` scope**; granted on narrower zones it has no effect, and the gate warns at load (base file) and in the impact analysis (managed revisions), and also when no provider opts in. Every operation needs it, reads included (a profile may hold verification tokens), and a write applies to any profile of the account: there is no ownership by team. Give it to the administrators of the EuroDNS account only:

```yaml
roles:
  dns-account-admin:
    rules:
      - zones: ["*"]
        actions: [dns.zone.profile]
bindings:
  - role: dns-account-admin
    team: platform
    subjects: [{issuer: entra, claims: {groups: ["<dns admins group id>"]}}]
```

Writes (create, update, delete) need a recent login from humans, like policy changes (`policy.edit_max_age`, `policy.require_amr`; `403 reauth_required`), on every channel: the UI session, bearer tokens (their `auth_time`) on the REST and EuroDNS routes, and MCP. A profile holding a record of the [protected list](#protected-records) is refused (`403 protected`) on create, update and check, whatever the zones of the protected entry, since the profile may be applied to any domain; its mail forwards count as the apex `MX`, its URL forwards as `A`, `AAAA` and `CNAME` records of their host. Each subject may run 60 zone profile operations per minute, all channels together (`429 rate_limited`), as they share the EuroDNS rate limit of the account; listings are capped at 100 profiles per page and 2000 in all. Updates are audited with the previous content (`previous`) and, like creations and deletions, the host, type and operation of each changed record in `changes` (no values: the content stays in the audit sink). The journal (`/api/v1/audit`, `search_audit`) shows zone profile events only to holders of `dns.zone.profile` on `*`.

The records EuroDNS applies from a profile are created outside the gate: the domain then shows them as foreign RRsets, adopted by the teams that will manage them once the zone is managed ([adoption](#adoption-and-terraform-export)). The managed policy can grant `dns.zone.profile` only when `policy.bounds` allow it on `"*"`.

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

## Teams

A team owns RRsets: only its members may change or delete them. `teams` declares each team with the people and the pipelines that act for it, so that a team matches a project (the web shop with its developers and its deployment pipelines, the corporate sites with theirs):

```yaml
teams:
  web:
    description: Web shop, people and pipelines
    members:
      groups: [dns-web]
      subjects:
        - issuer: azure-devops
          claims: {sub: ["sc://org/project/dns-gate-web-*"]}
  corporate:
    description: Corporate sites
    members:
      groups: [dns-corporate]

bindings:
  - role: web-records
    team: web            # the members of web get web-records, acting for web
  - role: corporate-records
    team: corporate
```

| Field | Description |
|---|---|
| `description` | Free text, up to 500 characters. |
| `members.groups` | Groups whose members belong to the team. |
| `members.subjects` | Subject matchers (issuer and claim globs, as in bindings). |

A binding that names a team **without** `groups` or `subjects` grants its role to the members of the team. A binding with its own `groups` or `subjects` binds those only (they act for the team without being listed as its members), as before; a team without members is only named by such bindings.

**Strict references.** Once the file has a `teams` block (even `teams: {}`), every team named by a binding, a virtual key, an [API key](API.md#api-keys) or a delegation (`allow.teams.names` without wildcard, and the fixed team of delegated bindings) must be declared, in the file or in the managed layer: a typo is refused instead of silently creating a new team. Teams derived from claims are accepted as members of their family: `team_from` (and `allow.teams.from_subject` of a delegation) declares the family `<prefix>*`. Derived teams stay apart from the declared ones: once the block exists, every family (`team_from`, `from_subject`, an issuer `team_claim` with its `team_claim_prefix`) needs a non-empty prefix, the prefixes of different families must not overlap (none starts with another), a family derives teams from the subjects of one issuer only (give each issuer its own prefix), no declared team, binding team, virtual key team or `allow.teams.names` entry may carry the prefix of a family, a binding whose derived team is the name of a declared team does not apply (logged once), and an issuer `team_claim` only yields teams of its own family. A managed revision whose new family would take over the RRsets of a team found in the store gets a warning in its impact analysis. Without a `teams` block, the referenced teams are declared automatically and the gate logs a warning for each (`dns-gate --check` prints them): see [MIGRATION-0.x.md](MIGRATION-0.x.md#teams-block).

**Several teams.** A subject collects the teams of its bindings in order (base bindings first, in file order). It writes for the first one, its **default team** (`default_team` of `GET /api/v1/me`), and may change the RRsets of all of them. On the gate API it can act for one of its teams only with the `X-DNS-Gate-Team` header or the `team` field of a plan (`403 not_team_member` when it is not a member); the EuroDNS-compatible API always uses the default team.

`GET /api/v1/teams` lists the teams (declared, referenced, families, claim issuers, and owners found in the store that nothing declares), `GET /api/v1/teams/{team}` what a team owns. Teams can also be declared in the [managed layer](#managed-policy-editing-from-the-ui).

## Ownership

| Field | Default | Description |
|---|---|---|
| `ownership.tombstone_ttl` | `168h` | How long a deleted RRset stays reserved for the team that owned it: meanwhile only that team may create it again (a member of several teams re-creates it for that team) or adopt it, other teams go through a transfer; adoption never lifts the tombstone of another team, whoever adopts. The ownership entry and its tombstone are written in one store transaction: if the tombstone cannot be written, the entry stays (pending) and the reconciler retries. `0s` disables tombstones. RRsets of ephemeral roles (ACME challenges) leave none. |
| `ownership.transfer_ttl` | `168h` | How long a transfer request waits for its approval (1h to 2160h). |
| `ownership.require_second_approver` | `false` | Ownership transfers and renames need a second person, as `policy.require_approval` does for policy revisions. With `false` the requester may approve its own request (or propose it with `"apply": true`), every other check still applying; the audit records `approval: self`. Recommended `true` as soon as two people administer the gate. |
| `ownership.person_issuers` | `[]` | With `require_second_approver`, required when several issuers yield human subjects (category `human`, a `category_map` to `human`, the UI login, SAML), and defaulting to the only one otherwise (`dns-gate --check` says which): only humans signed in with these issuers may request and approve transfers and renames, and the subject id identifies the person on top of the claims below. Recommended: the issuer of the UI login (SAML or OIDC); the gate issuer binds as the issuer of the session, name that one. Exclusive with `machine_approvers`. |
| `ownership.person_claims` | `[tid+oid, email, preferred_username, upn]` | With `require_second_approver`: claims identifying the person behind a token across issuers (`a+b` joins claims, e.g. the immutable `tid+oid` of Entra ID). Requester and approver must share no value, whatever the claim it comes from; `email` is ignored for an issuer with `email_trusted: false` or a token with `email_verified: false`. A requester or an approver none of them identifies cannot take part (fail closed). |
| `ownership.machine_approvers` | `false` | Let pipelines and virtual keys approve transfers and renames and, with `require_second_approver`, let a request nobody can identify as a person be approved: it **weakens** the two-person rule, keep it off unless pipelines must approve. |

**Transfers.** `POST /api/v1/zones/{zone}/transfers` asks to move RRsets of one team (owned, or reserved by a tombstone) to another; the caller needs `dns.record.write` or `dns.ownership.approve` on the zone and, for every RRset, must be allowed to write it through the bindings of one of the two teams, or hold `dns.ownership.approve` on it. The approver must, for every RRset, be allowed to write it through the bindings of the owner team (rights held through another team do not count, nor a role limited to other records such as ACME challenges) or hold `dns.ownership.approve` on it; it is a human unless `ownership.machine_approvers`, with the step-up of policy changes (recent login, `policy.require_amr`); with `require_second_approver` it must be another person (see `person_issuers`, `person_claims`), otherwise the requester may approve. The requester may always withdraw its request. The approval moves every RRset in one store transaction, under the zone lock, provided none changed since the request (owner, state, content hash in the store and upstream); moved entries keep the id of the transfer, so that a retry recognises them even after their new team changed them. When the zone is locked or the store or provider is unavailable the transfer stays `applying`: the gate retries it in the background (every minute, or each maintenance pass on AWS Lambda), never earlier than 2 minutes after the approval, under a lease so that one replica applies it, binding the approver again with the current policy and failing the transfer if it lost its rights; after 24 hours it is `failed`. `POST /api/v1/teams/{team}/rename` moves every RRset and tombstone of a team, in the managed zones and in every other zone where the store still holds some (a table scan on DynamoDB, see [#68](https://github.com/KamorionLabs/dns-gate/issues/68)), for migrations: proposed by a `policy.propose` holder and approved by a `policy.approve` holder (another person with `require_second_approver`); it is applied in the background, each RRset and tombstone needing `dns.ownership.approve` for the approver; change the bindings in a policy revision as well. Audit events: `gate.transfer.propose`, `gate.transfer.approve`, `gate.transfer.reject`, `gate.transfer.apply`, `gate.transfer.expire`, with the requester, the approver and `approval` (`self` or `second`). See [API.md](API.md#ownership-transfers).

## Bindings

| Field | Description |
|---|---|
| `role` | Role granted. |
| `team` | Owner team of the RRsets created through this binding. Required to write (or `team_from`). Must be [declared](#teams) once a `teams` block exists; without `groups` and `subjects`, the role goes to the members of the team. |
| `team_from.claim`, `team_from.regex`, `team_from.prefix` | Derive the owner team from a claim of each subject instead of a fixed `team`, see below. Exclusive with `team`. |
| `groups` | Groups whose members get the role. |
| `subjects[].issuer` | Issuer name. |
| `subjects[].claims` | Claim globs, all must match (at least one claim, typically `sub`). |

A binding needs `groups`, `subjects` or both (a subject matching either is bound), or a declared team with members. A subject collects every matching binding (roles and teams, base bindings first in file order, then managed ones; the first team owns new RRsets). A valid token with no binding gets `403 no_binding`.

### Team derived from a claim

Binding pipeline identities one by one is heavy when each pipeline should own its records. `team_from` gives each subject its own team, computed from one of its claims, so a single binding covers every pipeline whose identity matches a glob. With [Azure DevOps OIDC](#azure-devops-oidc) tokens, the team is the service connection name (`sc://<organization>/<project>/<service connection>`, example in that section). With GitHub Actions, the repository:

```yaml
issuers:
  - name: github
    issuer: https://token.actions.githubusercontent.com
    audiences: [dns-gate]
    bound_claims: {sub: ["repo:acme/*"]}         # globs: new repositories need no gate change

bindings:
  - role: pipeline-writer
    team_from:
      claim: sub
      regex: "^repo:acme/([a-z0-9-]+):environment:production$"
      prefix: gh-                                # team gh-<repository>
    subjects:
      - issuer: github
        claims: {sub: ["repo:acme/*:environment:production"]}
```

- `regex` is an RE2 expression anchored with `^` and `$`, with **exactly one** capture group (use `(?:...)` for the others). It is matched against the claim, which must be a string.
- The team is `prefix` followed by the **lowercased** capture. `prefix` is optional, up to 32 characters `[a-z0-9._-]`; use it to keep derived teams apart from hand-written ones.
- When the claim is missing, does not match, or the result is not a valid team name (lowercase identifier, at most 64 characters), the binding **does not apply** to that subject: it fails closed rather than writing under the team of another binding.
- Teams are collected in binding order as with a fixed `team` (base bindings first, in file order) and the first one owns new RRsets: give pipelines matched by a `team_from` binding no other team-bearing binding. The explain simulator shows the derived team (`role@team`), who-can and the impact analysis show the rule. The impact analysis cannot count RRsets owned by derived teams (they are only known per subject).
- Same rules in the managed layer (UI editor: "Team from a claim").

Other subjects that encode one pipeline per value: Kubernetes service accounts (`^system:serviceaccount:([a-z0-9-]+):dns-writer$`, team per namespace), AWS role ARNs (`^arn:aws:iam::111111111111:role/ci-([a-z0-9-]+)$`), any CI whose `sub` names the project. Entra ID access tokens (managed identities, Azure DevOps after the exchange for an Entra token) are different: their `sub` is a pairwise id and they carry no readable per-pipeline claim, so keep one binding per `oid` there.

**Trade-off.** Ownership isolates pipelines from each other: each one can only modify or delete the RRsets its own team created. But every identity matching the binding gets the role, so any of them can **create** any RRset that does not exist yet and that the role allows (hosts, types), and a new identity matching the glob is bound without a gate change. Keep the role narrow (hosts, types, zones), keep `protected` records for what must never change, and treat the right to create identities matching the glob (repositories, service connections, namespaces) as the right to write within that role. Two subjects whose captures differ only by case share a team.

With Azure DevOps, the glob means that anyone allowed to **create a service connection** in the project with a name under the prefix, and to **authorize it for a pipeline they control**, mints a new trusted gate identity. That identity gets its own team, so it cannot change or delete the records of other teams, but it can create any not-yet-existing name its role allows. Mitigations:

- keep the glob prefix (`dns-gate-*`) dedicated to the gate, and make sure no Entra federated credential, AWS role or other federation trusts subjects under it;
- restrict who may create service connections in the project (*Endpoint Creators* and *Endpoint Administrators* of the project, and organization-level service connection permissions) to the people who would otherwise change the gate configuration;
- require approvals and checks on the service connections (or on the environments the pipelines deploy to), so a new pipeline cannot use one unreviewed;
- watch the audit log: every write carries the subject (`azure-devops:sc://...`) and the derived team, and a team that appears for the first time is a new service connection.

## Protected records

`protected[]` entries (`zones`, `hosts`, `types`, same patterns as rules) are never writable nor adoptable, whatever the role. They stay readable.

## Managed policy (editing from the UI)

The policy has two layers, merged at evaluation:

- **base**: this file (GitOps). Issuers, UI, store, protected records, `policy.bounds` and every `policy.*` grant live only here.
- **managed**: a document of zones, teams, groups, roles, bindings and virtual keys stored as immutable **revisions** in the store and edited from the UI (or the API).

Rules of the managed layer:

- a managed role, group or team cannot reuse a base name;
- managed teams follow the revision cycle like the rest of the document; a proposal without a `teams` field keeps the teams of the active revision (`"teams": {}` removes them), and the impact analysis reports declared, removed and changed teams;
- managed rules cannot grant `policy.*` actions and must stay within `policy.bounds` (zone globs, folder globs, actions): their `zones` must be covered by `bounds.zones` and their `folders` by `bounds.folders`, and a rule applying through a folder only reaches zones matching `bounds.zones` ([EuroDNS folders](#eurodns-folders)); a managed binding may reuse a base role only if that role also stays within the bounds;
- protected records still win over everything;
- managed `zones` are brought under management in addition to the base `zones`: each must match `policy.bounds.zones` and, when it is not managed yet, exist in a provider account ([zone discovery](#zone-discovery) must be enabled); a zone already managed by the active revision is not checked again, so a domain removed from the account does not block unrelated changes;
- managed virtual keys must have `expires_at`, and only their SHA-256 is stored (`POST /api/v1/policy/virtual-keys/generate` returns a random key once);
- `max_changes_per_request: -1` (unlimited) is reserved to the base.

| Field | Default | Description |
|---|---|---|
| `policy.editable` | `false` | Enables the managed layer. Without it, only the base applies and the policy API is read-only. |
| `policy.require_approval` | `true` | Activation of a proposal requires an approval by an approver other than the author. With `false`, a `policy.propose` holder (a policy administrator included) activates their own proposal alone; approving one's own proposal stays refused. [Delegated changes](#policy-delegations) never require approval, whatever this setting. |
| `policy.edit_max_age` | `15m` | Humans must have authenticated at the IdP within this delay to change the policy. |
| `policy.require_amr` | `[]` | Authentication methods required for changes, e.g. `["mfa"]` (the IdP must emit the `amr` claim). |
| `policy.bounds.zones` | (required if editable) | Zone globs managed rules may target (`*` wildcards only), zones the managed layer may bring under management, and zones its folder rules may reach. |
| `policy.bounds.folders` | `[]` | [Folder](#eurodns-folders) globs managed rules may target (`/ES/**` covers `/ES/Madrid` and `/ES/*`, not `/ES`). It narrows `bounds.zones` for folder rules, never widens it. |
| `policy.bounds.actions` | (required if editable) | Actions managed rules may grant (`policy.*` refused). |
| `policy.delegations` | `[]` | Identities allowed to manage their own roles and bindings in the managed layer, within limits, see [Policy delegations](#policy-delegations). |

Meta actions, granted only by base roles: `policy.read` (view the policy, revisions, diff, explain, who-can), `policy.propose` (create revisions, rollback, generate virtual keys), `policy.approve` (approve, reject, activate). Virtual keys cannot hold them.

Workflow: **propose** (validated, based on the active revision `parent_id`; `409 stale_revision` if another revision was activated meanwhile) → **approve** / **reject** (an author cannot approve their own revision; an author may reject it to withdraw it) → **activate** (atomic: `409 conflict` when another activation won the race; the document is re-validated against the current base) → **rollback** (a new proposal copying an older revision). Each revision shows a unified YAML diff against its parent and an impact analysis (permissions gained and lost per binding, group and key, zones that become managed or are released, a warning when a team that owns RRsets loses write on their zone, and a warning when a released zone still has RRsets owned by the gate: they stay in the store but become read-only until the zone is managed again). Every step is audited (`policy.propose`, `policy.approve`, `policy.reject`, `policy.activate`, with the revision id).

Each replica checks the active revision every 10 seconds and recompiles; evaluation never calls the store. If the base file changes so that the active revision no longer validates, the replica keeps the previous policy and logs an error.

Security of UI mutations: every `POST`, `PUT` and `DELETE` authenticated by the session cookie must carry `X-Gate-CSRF` equal to the `gate_csrf` cookie (set at login) and an `Origin` equal to the gate origin. Humans (session or bearer token of category `human`) need a recent authentication (`auth_time` within `policy.edit_max_age`, and `amr` containing `policy.require_amr`), otherwise `403 reauth_required`; the UI then sends them to `/auth/login?reauth=1&return_to=...`, which forces `prompt=login` and `max_age`. Pipelines (bearer tokens of category `pipeline`) may propose when a base binding grants `policy.propose`, without step-up, but can never approve their own proposal. To let a pipeline manage roles and bindings on its own, without approval and within limits, use a [policy delegation](#policy-delegations) rather than `policy.propose`.

## Policy delegations

A delegation lets a trusted identity, typically the CI pipeline whose Terraform stack creates other pipelines, manage **its own** roles and bindings in the managed layer, within limits written in the base file, without approval. The pattern it serves: one stack creates, for each pipeline, its CI service connection and, in the same apply, the gate role and binding that let that service connection write only its own DNS names, the way it creates each pipeline's cloud role and scoped policy. The Terraform provider `KamorionLabs/dnsgate` exposes the API below as `dnsgate_role` and `dnsgate_binding`.

```yaml
policy:
  editable: true
  require_approval: true              # human proposals; delegated changes never need approval
  bounds:
    zones: ["example.com"]
    actions: [dns.read, dns.record.write, ui.read]
  delegations:
    - name: workloads-pipelines
      description: Gate identities of the pipelines created by the workloads stack
      subjects:                       # who may use the delegation (issuer + claim globs, as in bindings)
        - issuer: azure-devops
          claims: {sub: ["sc://<organization>/<project>/workloads-pipelines"]}
      allow:
        zones: ["example.com"]        # zone globs delegated rules may target, within policy.bounds.zones
        actions: [dns.read, dns.record.write]   # within policy.bounds.actions, never policy.*
        records:                      # optional: delegated rules must name hosts and types covered here
          hosts: ["**.apps", "_acme-challenge.**.apps"]
          types: [CNAME, TXT]
        binding_subjects:             # identities a delegated binding may target
          - issuer: azure-devops
            claims: {sub: ["sc://<organization>/<project>/dns-gate-*"]}
        teams:
          from_subject:               # the team is derived from the bound subject
            claim: sub
            regex: "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"
          # names: ["shared-*"]       # and/or fixed team names (globs)
        roles: []                     # existing base or managed roles delegated bindings may also grant
        groups: []                    # groups delegated bindings may target
        max_objects: 100              # roles + bindings of the delegation
```

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Lowercase identifier, recorded as the owner of every object the delegation creates. |
| `description` | | Free text shown in the UI and the API. |
| `subjects[]` | (required) | Matchers (`issuer`, `claims` globs) of the identities that may use the delegation. A subject of a delegation needs no binding: it authenticates on the delegation API even if no role is bound to it (and gets nothing else). |
| `allow.zones` | (required) | Zone globs delegated role rules may target, and zones their folder rules may reach; each must be covered by `policy.bounds.zones`. |
| `allow.folders` | `[]` | [Folder](#eurodns-folders) globs delegated role rules may target; each must be covered by `policy.bounds.folders`. |
| `allow.actions` | (required) | Actions delegated role rules may grant; within `policy.bounds.actions`, `policy.*` refused. |
| `allow.records.hosts`, `allow.records.types` | | When set, every delegated rule must name hosts (types) and each must be covered by these patterns (same host syntax as rules; `*` for any type). Without it, a delegated rule may cover whole zones. |
| `allow.binding_subjects[]` | (required) | Every subject of a delegated binding must be covered by one of these matchers: same issuer, and each claim of the matcher constrained by the binding with patterns it covers (`sc://o/p/dns-gate-web` and `sc://o/p/dns-gate-*` are covered by `sc://o/p/dns-gate-*`; `sc://o/*` is not). `*` alone is refused. |
| `allow.teams.from_subject` | | The "team from the subject" rule (`claim`, `regex`, `prefix`, as [`team_from`](#team-derived-from-a-claim)). A delegated binding either sets exactly this `team_from`, or a fixed `team` equal to the team this rule derives from its subject (each subject must then carry exactly one literal value of the claim, and the binding no groups). |
| `allow.teams.names` | | Team globs a delegated binding may set as a fixed `team` (`*` alone refused). At least one of `from_subject` and `names`. |
| `allow.roles` | `[]` | Base or managed roles a delegated binding may grant besides the roles of the delegation; each of their rules must still be within `allow`. |
| `allow.groups` | `[]` | Groups a delegated binding may target. |
| `allow.max_objects` | `100` | Maximum roles plus bindings owned by the delegation (1 to 1000). |

Delegations require `policy.editable`. With [Azure DevOps OIDC](#azure-devops-oidc), the issuer's `bound_claims.sub` must accept the delegation subject as well as the pipelines' service connections; give the stack its own dedicated service connection, trusted by no other federation. Delegations are part of the base file: who may delegate, and how far, is decided by a pull request on the configuration, like every `policy.*` grant.

### Delegated objects

Delegated roles and bindings live in the managed document, in its `delegated` section, keyed by a stable name (bindings get a name there; role names are unique across base, managed and delegated roles). Each records its owner:

```yaml
delegated:
  roles:
    dns-gate-web:
      rules: [{zones: [example.com], actions: [dns.read, dns.record.write], records: {hosts: [web.apps], types: [CNAME]}}]
      owner: {delegation: workloads-pipelines, managed_by: terraform, created_by: "azure-devops:sc://...", created_at: ..., updated_by: ..., updated_at: ...}
  bindings:
    dns-gate-web:
      role: dns-gate-web
      team: dns-gate-web
      subjects: [{issuer: azure-devops, claims: {sub: ["sc://<organization>/<project>/dns-gate-web"]}}]
      owner: {...}
```

Validation is the one of the managed layer (bounds, no `policy.*`, issuers, matchers, team syntax, ...) plus the limits of the owner delegation. A delegated role can only be bound by delegated bindings of the same delegation; managed bindings and keys cannot use it, so deleting a delegated object never breaks a human one.

Delegated bindings are evaluated after the other managed bindings, sorted by name. At evaluation, a delegated rule outside its delegation (or whose delegation is no longer in the file) grants nothing.

### Delegation API

Authenticated like the rest of `/api/v1` (bearer token; cookie sessions need the CSRF header on `PUT` and `DELETE`). Pipelines need no step-up; humans matching a delegation need the same recent login as for policy changes.

| Route | Description |
|---|---|
| `GET /api/v1/policy/delegated` | Delegations of the caller (all of them for `policy.read` holders) and their objects. |
| `GET /api/v1/policy/delegated/roles/{name}`, `.../bindings/{name}` | One object with its owner and `etag` (also in the `ETag` header). `404` when it does not exist or is not delegated (taken over). |
| `PUT /api/v1/policy/delegated/roles/{name}` | Create or replace a role. Body: the role (`description`, `rules`, `rebase_on_save`, `ephemeral_ttl`, `max_changes_per_request`), optional `delegation` (needed when the caller matches several) and `managed_by` (client label, for example `terraform`). |
| `PUT /api/v1/policy/delegated/bindings/{name}` | Create or replace a binding: `role`, `team` or `team_from`, `subjects`, `groups`, plus `delegation` and `managed_by`. |
| `DELETE /api/v1/policy/delegated/roles/{name}`, `.../bindings/{name}` | Delete (`?delegation=` optional). |

- **Preconditions**: `If-None-Match: *` creates only (`412 precondition` if the name exists); `If-Match: <etag>` updates or deletes only that version (`412` otherwise). The ETag is per object: changes to other objects never invalidate it.
- **Idempotent**: a `PUT` identical to the current object answers `200` with `"changed": false` and creates no revision.
- **Ownership**: an existing object is changed only by subjects of its owner delegation (`403 not_owner`). A role name used by the base or by a managed role edited by humans is refused (`409 name_taken`).
- **Activation**: each change is applied to the active revision, validated, stored as a new revision authored by the caller (comment `delegation <name>: put role <name>`) and activated at once, **without approval**, whatever `policy.require_approval`. The answer carries the revision id and the impact analysis (`{"object", "changed", "revision_id", "impact"}`); validation errors are `400 invalid_policy` with the same `errors` as proposals.
- **Concurrency**: writes are serialized per replica; when another replica activates a revision at the same time, the change is applied again on the new active revision (preconditions included), up to 5 times, then `409 policy_busy` (the Terraform provider retries). Concurrent writes on different objects never lose an update.
- **Audit**: `policy.delegated.put_role`, `policy.delegated.delete_role`, `policy.delegated.put_binding`, `policy.delegated.delete_binding` (allowed and denied, with the delegation, the object and the impact), plus `policy.activate` for each activated revision.

### Humans and delegated objects

- Humans see delegated objects: in `GET /api/v1/policy` (`managed.delegated`, and the delegations in `base.delegations`), in revision diffs and exports, in explain and who-can.
- A proposal (UI or API) does not edit them: when it omits `document.delegated` (as the UI does), the delegated objects of the active revision are kept; when it sends the section, it must be unchanged, otherwise `403 delegated_object`. A rollback restores the human-edited objects and keeps the delegated ones as they are.
- **Taking over**: a policy administrator (`policy.approve`) may take delegated objects back with `take_over` in the proposal (`["roles/<name>", "bindings/<name>"]`, API only for now): they leave the delegated section, and the proposal may redefine them in `roles` and `bindings` as ordinary managed objects. The proposal is reviewed as any other (`require_approval`), and audited as `policy.delegated.take_over`. Once active, the delegation no longer sees the objects (`404`) and cannot recreate a taken over role (`409 name_taken`).
- A delegated change activates a new revision: proposals open at that moment become stale and must be proposed again.

### Changing a delegation

The limits are checked when an object is written and again on every later revision and policy reload. Narrowing or removing a delegation in the file while objects exceed it makes the active revision invalid against the new base: replicas keep their previous policy and log an error, and a replica that starts with that file serves the base layer only. Delete the objects (or take them over) **before** narrowing or removing the delegation.

## Adoption and Terraform export

Adoption brings RRsets created outside the gate (foreign) under the ownership of a team, so that the gate can then manage them. It requires `dns.record.adopt` on each RRset and never applies to protected or server-managed (SOA, locked) records.

1. `POST /api/v1/zones/{zone}/adopt/preview` with a selection (`rrsets`, or `hosts` globs and `types`, plus an optional `owner` team: one of the caller's teams, or another team for the RRsets on which the caller holds `dns.ownership.approve`, the others being `forbidden`): returns the candidates, whether each is adoptable (or why not: `protected`, `owned_by_other_team`, `reserved_for_other_team` (deleted recently by another team, see [tombstones](#ownership)), `already_owned`, `forbidden`, `not_found`, the read-only reason of the RRset such as `server_managed` or `relative_target`, or `invalid` when the provider would refuse its content) and a `preview_token` bound to the exact upstream content.
2. `POST /api/v1/zones/{zone}/adopt` with the chosen `rrsets`, the `preview_token` and a mandatory `comment`. All or nothing: if any RRset changed since the preview or is no longer adoptable, nothing is adopted and the answer is `409 adopt_conflict`.

Both are mutations for CSRF (cookie sessions) and the apply requires the same recent authentication as policy changes for humans.

`GET /api/v1/zones/{zone}/terraform?team=&hosts=&types=&provider=` (`ui.read`) downloads the **managed** RRsets of a zone as Terraform/OpenTofu configuration: one resource per RRset plus `import` blocks (id `<zone>/<host>/<type>`), so a team can move what it adopted into its own stack. By default the resources are `dnsgate_record_set` of the `KamorionLabs/dnsgate` provider, which talks to the gate REST API and works for every DNS provider behind the gate (attributes `zone`, `name`, `type`, `ttl`, `values`, or an `alias` block `{name, zone_id, evaluate_target_health}`); `provider=eurodns` exports `eurodns_record_set` of the `kamorionlabs/eurodns` provider instead (EuroDNS-compatible API, alias RRsets skipped). `hosts` (host globs) and `types` accept comma-separated values or repeated parameters; `rrsets=www/A,@/MX` exports exactly that selection (for example what was just adopted) and takes precedence over `hosts` and `types`.

## Propagation check

`GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation` ([API.md](API.md#dns-propagation)), the `check_propagation` MCP tool and the *Propagation* panel of the UI (RRset drawer when the viewer holds `dns.read` on the RRset, and right after an apply) ask the authoritative name servers of a managed zone and a list of public resolvers for one RRset, and compare their answers with the RRset as read from the provider.

| Field | Default | Description |
|---|---|---|
| `propagation.enabled` | `true`, `false` on AWS Lambda | Serves the check (`501 not_implemented` and no MCP tool when `false`). On Lambda it must be enabled explicitly, see [DEPLOY-LAMBDA.md](DEPLOY-LAMBDA.md). |
| `propagation.resolvers` | the list below | Public resolvers asked, replacing the default list: `name`, `address` (an IP address with an optional port, never a host name), `filtering` (`true` for a resolver that blocks names by policy), and for display `location`, `country` (ISO code) and `region` (the UI groups by region: `anycast`, `europe`, `north-america`, `south-america`, `asia`, `oceania`, `africa`, or free text). At most 64. |
| `propagation.allow_private_resolvers` | `false` | Accepts resolver addresses outside the public unicast space (private, loopback, link-local, shared, documentation and the other IANA special-purpose blocks, also when embedded in IPv6). Such a resolver may answer internal names of a split-horizon DNS: anyone allowed to check an RRset would learn its internal answer. |
| `propagation.query_timeout` | `1.5s` | Timeout of one query (100ms to 10s, at most `timeout`). |
| `propagation.timeout` | `4s` | Deadline of a whole check (`query_timeout` to 5s): servers that did not answer by then are reported as `error` (`timeout`). |
| `propagation.concurrency` | `16` | Servers one check asks at once (1 to 64). |
| `propagation.max_in_flight` | `3` | Checks running at once in one process (1 to 64, `503 busy` beyond). |
| `propagation.cache_ttl` | `10s` | A result is reused for the same RRset content during this time (1s to 5m), whoever asks. |
| `propagation.requests_per_minute` | `30` | Checks of one subject that are not served from the cache (1 to 600, `429` beyond). The UI asks every 5 seconds while a panel is open, for at most 2 minutes. |

**Per instance.** The cache, the per-subject limit (the 4096 most recently seen subjects) and `max_in_flight` are kept in memory by each process: with several replicas or Lambda instances, a subject can run `requests_per_minute` checks on each of them, and a load balancer spreading the polls of one panel over replicas finds a cold cache on each.

```yaml
propagation:
  resolvers:
    - {name: Cloudflare, address: 1.1.1.1, location: Anycast, country: US, region: anycast}
    - {name: Quad9, address: 9.9.9.9, location: Anycast, country: CH, region: anycast, filtering: true}
```

Network: the gate needs outbound **UDP and TCP port 53** to the resolvers and to the name servers of its zones (TCP when an answer is truncated or UDP fails). AWS Lambda functions outside a VPC have it; in a VPC, the security group and the network ACLs must allow it through a NAT gateway. The name servers of a zone are its apex NS as read from the provider (looked up with the system resolver when the gate has none), resolved with the system resolver; those whose address is not public (same check as `allow_private_resolvers`, never overridable) are skipped. The default resolvers are IPv4, as Lambda functions outside a VPC have no IPv6 egress.

Default resolvers, all documented open resolvers needing no account, unfiltered services where the operator offers one (*filtering* marks those that block malware or phishing domains):

| Resolver | Address | Location |
|---|---|---|
| Cloudflare | `1.1.1.1` | Anycast (US) |
| Google Public DNS | `8.8.8.8` | Anycast (US) |
| Quad9 (filtering) | `9.9.9.9` | Anycast (CH) |
| OpenDNS (Cisco, filtering) | `208.67.222.222` | Anycast (US) |
| AdGuard DNS, unfiltered | `94.140.14.140` | Anycast (CY) |
| Control D, unfiltered | `76.76.2.0` | Anycast (CA) |
| CleanBrowsing, security filter (filtering) | `185.228.168.9` | Anycast (US) |
| UltraDNS Public | `64.6.64.6` | Anycast (US) |
| NextDNS | `45.90.28.0` | Anycast (US) |
| DNS.SB | `185.222.222.222` | Anycast (DE) |
| Hurricane Electric | `74.82.42.42` | Anycast (US) |
| DNS4EU, unfiltered | `86.54.11.100` | European Union |
| FDN | `80.67.169.12` | Paris, FR |
| Yandex DNS | `77.88.8.8` | Moscow, RU |
| CIRA Canadian Shield, private | `149.112.121.10` | Canada |
| AliDNS (Alibaba) | `223.5.5.5` | Hangzhou, CN |
| DNSPod (Tencent) | `119.29.29.29` | Shenzhen, CN |
| 114DNS | `114.114.114.114` | Nanjing, CN |
| Quad101 (TWNIC) | `101.101.101.101` | Taipei, TW |

Keep in mind when reading a check:

- **Anycast resolvers answer from their site nearest to the gate**: they show the caches near the gate, not those of another continent. The resolvers with a fixed location give the regional view.
- **Resolvers answer from their cache**: one keeps the previous answer (`stale`) or a negative answer (`missing`, for the SOA minimum) until its TTL runs out; `ttl_left` and `max_ttl_left` tell how long at most. Asking again does not refresh their cache.
- Some resolvers refuse some clients: OpenDNS refuses queries from France (court order, `refused (censored)`), and a resolver may be unreachable from a given network. Errors do not count against convergence.

How answers are compared:

- Values are normalized on both sides: sorted, names absolute and lowercase (a EuroDNS target stored relative to the zone is completed with it), TXT on their content whatever the splitting in strings or the quoting, hexadecimal and base64 fields as a server prints them. The CNAME chain of an answer is followed and shown; a name answering a CNAME where another type is expected is `stale`.
- **TTL**: an authoritative answer must carry the expected TTL, and a cached answer may not have more TTL left than it, so a TTL-only change is not reported up to date at once.
- **Alias** RRsets (Route53) and EuroDNS `APEX` RRsets have no values: every address answered must be one of the target's, resolved by the gate (system resolver) for the authoritative servers and asked from the same resolver otherwise. Anything else, including a target that could not be resolved, is `indeterminate`: a CDN answers per location, so sharing an edge address proves nothing. Indeterminate answers never count as up to date.
- **Deletions** (`expect=absent`): an empty answer is a match. An answer section holding records of another name or type, or an answer the resolver flags as its own decision (extended DNS errors Blocked, Censored, Filtered), is an `error`; negative answers of resolvers marked `filtering` are flagged.
- **Converged** needs at least one authoritative answer that matches, and no `stale`, `missing` or `indeterminate` answer.
- **Size**: an answer reports at most 32 values of at most 512 bytes (`truncated`), and a result at most 1 MiB of values.
- **expect**: the inventory a check compares with is the cache of the instance that answers. With `expect` (the `new_hash` of an apply result, the ETag of a `PUT`, or `absent`), an inventory that differs is refreshed from the provider first, at most 6 times a minute per subject; `412 precondition` if it still differs.

A check is a read: no audit event, a debug log line (`propagation`). A refused provider re-read on `expect` is audited as `api.propagation`.

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
| `list_zones` | read | Readable zones with their counts and [EuroDNS folder](#eurodns-folders) (optional `folder` glob filter); zones discovered in the account but not managed are flagged `unmanaged`. |
| `list_rrsets` | read | RRsets of a zone (managed, or unmanaged with `dns.read`) with their owner team, and the tombstones (deleted RRsets still reserved for their team); filters on status, host glob, type, owner. |
| `get_rrset` | read | One RRset, its tombstone, why the caller may or may not change it (`ownership`), and its recent audit history. |
| `check_propagation` | read | [Propagation check](#propagation-check) of an RRset (`dns.read` on it, managed zones only), with an optional `expect` hash; not audited, like the REST endpoint. Absent when `propagation.enabled` is `false`. |
| `search_audit` | read | Audit search, same visibility as the UI. |
| `explain`, `who_can` | read | Policy simulation (`policy.read`); `explain` adds the teams and default team of the simulated subject and, for an RRset, its owner team or reservation; both tell when a rule applied through the folder of the zone (`folder`, `by_folder`). |
| `list_teams`, `get_team` | read | Teams as `GET /api/v1/teams[/{team}]`, plus the caller's teams (`my_teams`). |
| `transfer_list` | read | Transfer requests the caller may see (`status=proposed` is the inbox, `can_decide`). |
| `plan_rrset_change` | dry run | Desired state of RRsets, checked without writing; returns a `plan_id` bound to the caller, the zone, the changes, the zone version and the optional `team` (one of the caller's teams). |
| `apply_rrset_change` | write | Applies a plan exactly as planned, for its team; refused when expired, used, owned by another caller, planned for another team (`team_mismatch`), or when the zone changed since (`precondition`). |
| `adopt_preview`, `adopt_apply` | dry run, write | Adoption as above, with an optional `team`. |
| `list_zone_profiles`, `get_zone_profile`, `check_zone_profile` | read | [Zone profiles](#zone-profiles) of a EuroDNS provider (`provider` optional with one EuroDNS provider); `check_zone_profile` validates with EuroDNS without saving. `dns.zone.profile` on `*`. |
| `create_zone_profile`, `update_zone_profile`, `delete_zone_profile` | write | Zone profile writes, audited with the profile content; humans need a recent login. `update_zone_profile` keeps the forwards it is not given (`[]` removes them). |
| `transfer_propose`, `transfer_approve`, `transfer_reject` | write | Ownership transfers with the REST rules ([transfers](#ownership)): one owner team per request, approved by someone who may write every RRset through the owner team or holds `dns.ownership.approve` on it (humans only unless `ownership.machine_approvers`), another person with `ownership.require_second_approver`, otherwise possibly the requester (`transfer_propose` with `apply: true`); the requester may reject (withdraw) it. An approval the gate cannot complete at once, and every rename, leaves the transfer `applying`, applied in the background. |

There is no policy tool: policy changes stay with humans in the UI, with step-up. Plans are kept in the store, shared by every replica, and taken once: a plan made on one replica can be applied on another. The same plans back `POST /api/v1/zones/{zone}/plan` and `/apply` ([API.md](API.md)). Expired plans are purged every 15 minutes by the gate (SQL stores) or by the DynamoDB TTL.

### Connecting an assistant

The **Connect** page of the UI (`/ui/#/connect`, data from `GET /api/v1/connect`) shows the commands below already filled in with the gate URL, the tenant and the token scope (`ui.cli_scope`), the Claude Desktop extension download, plus the Terraform provider block and a `curl` example. The gate only needs an access token of a configured issuer whose audience is the gate; with Entra ID, the Azure CLI gets one for the signed-in user.

Claude Code, with a `headersHelper` that Claude Code runs again on each connection and on a `401` or `403`, so the token never goes stale (needs the Azure CLI signed in to the gate's tenant, `az login --tenant <tenant-id>`, and `jq`):

```sh
claude mcp add-json dns-gate '{"type":"http","url":"https://gate.example.com/mcp","headersHelper":"az account get-access-token --scope api://<client-id>/.default --query accessToken -o tsv | jq -Rc \"{Authorization: (\\\"Bearer \\\" + .)}\""}' --scope user
```

The helper must print `{"Authorization":"Bearer <token>"}`. With another issuer, replace the `az` command by any command printing an access token.

#### Claude Desktop extension

For Claude Desktop, the Connect page offers a **Claude Desktop extension**: the user downloads it, double-clicks it (or drags it into Claude Desktop, Settings, Extensions) and clicks Install. No terminal, Azure CLI, `jq` or Node.js is needed: the extension runs on the Node.js runtime shipped with Claude Desktop.

With a [SAML UI login](#saml-login), the extension signs in at the gate itself: the bundle carries the [gate issuer](#gate-issued-tokens) URL and the client id `dns-gate-relay`, the relay is unchanged (OIDC discovery on the gate, authorization code with PKCE on a loopback redirect, refresh token), and the browser goes through the SAML login and a consent page. The extension is then offered only when an issuer with `self: true` is configured. Nothing has to be registered at the identity provider for it.

The file comes from `GET /api/v1/connect/claude-desktop.mcpb` (same authentication as `/api/v1/connect`), offered when `mcp.enabled` and the UI login are both on; `/api/v1/connect` then returns its URL in `claude_desktop_extension_url` (empty otherwise, and the download answers `404`). It is an [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) (manifest `0.3`, `dns-gate-<host>.mcpb`) generated on the fly with the MCP URL, the UI issuer, `ui.client_id` and the token scope (from `ui.cli_scope`, see Entra ID below) baked in. It holds no secret and is the same for every user of the gate.

Its local server, `internal/mcpb/relay.js` (one file, Node.js 18 or later, no dependency), forwards every MCP message to `/mcp` over Streamable HTTP (JSON and SSE answers, `Mcp-Session-Id`, messages the gate sends on its own) with the user's access token:

- Sign-in uses the system browser on the issuer (authorization code with PKCE S256, `state` and `nonce`, scopes `openid offline_access <scope>`, see below), back to a loopback redirect `http://localhost:<ephemeral port>`, without a path. Without a usable token, `initialize` and the list requests (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`) are answered at once, the lists empty, since Claude Desktop gives up on a request after about a minute; the sign-in then runs in the background and the relay sends `notifications/tools/list_changed` once signed in, so Claude fetches the tools again. Conversations already open keep the tool list they started with: start a new conversation after the first sign-in. A tool call made before that waits for the sign-in. A sign-in not completed within 5 minutes, or refused, fails the waiting requests with a JSON-RPC error; asking again starts a new one. With a usable token, every message goes straight to the gate.
- The tokens are kept in `~/.dns-gate/<host>.json` (mode `0600`). The access token is refreshed silently with the refresh token; the browser opens again only when the refresh is refused (expired or revoked session).
- Tokens are never written to the logs (Claude Desktop keeps the server's stderr in its MCP logs). When the browser cannot be opened, the sign-in URL is in those logs.

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

#### mcp-remote and other MCP clients

Claude Desktop without the extension, and other clients that only start local servers, go through the [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) bridge (Node.js) in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-gate": {
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
| `ui.issuer` | (required for OIDC) | Name of a configured issuer used for the login. |
| `ui.client_id` | (required for OIDC) | OIDC client id registered at the IdP. |
| `ui.redirect_url` | (required for OIDC) | `https://<gate>/auth/callback`, registered at the IdP. |
| `ui.saml` | | SAML 2.0 login instead of OIDC, see [SAML login](#saml-login). |
| `ui.scopes` | `openid profile email` | Must include `openid`; add the scope that carries the claims used in bindings (for example `groups`). |
| `ui.session_ttl` | `8h` | Session lifetime (1m to 24h). |
| `ui.cli_scope` | `api://<client_id>/.default` with an Entra v2 issuer, else empty | OAuth scope a command-line tool requests to get a token for the gate, shown on the Connect page (`az account get-access-token --scope ...`, Terraform `azure_identity.scope`). One scope of letters, digits and `. _ ~ : / % -`, so it can be pasted into shell commands as is. Set it when the Application ID URI of the gate is not `api://<client_id>`. |

Login is the authorization code flow with PKCE (S256), `state` and `nonce` checked. The ID token is verified with the issuer keys and `aud = client_id`; issuer `bound_claims` apply. The session cookie (`__Host-` prefixed when the redirect URL is HTTPS) is encrypted with AES-256-GCM, `HttpOnly`, `Secure`, `SameSite=Lax`. It keeps the identity claims of the ID token (protocol claims dropped) plus `auth_time` and `amr`; roles, groups and teams are recomputed on every request, so a policy change applies immediately. A login whose claims do not fit in a cookie fails with `session_too_large`: reduce the emitted claims (Entra: app roles rather than groups). `POST /auth/logout` clears it.

The policy page opens on a **simple** view: one card per group of people (named after the app role or directory group it maps to), one row per pipeline and one card per API key, each with what it sees, which records it can change in which zones, and its policy rights, with a filter on one zone. The **expert** view, kept as the last choice in the browser, lists the layers, bindings, delegations, groups, roles, keys, protected records, bounds and issuers.

With [zone discovery](#zone-discovery), the zones view also lists the unmanaged zones the user can read, with a "Manage this zone" action for holders of `policy.propose` (it creates a proposal adding the zone to the managed layer) and a hint for the others.

Audit events of zones the user cannot read are filtered out; events without a zone (authentication failures) are shown only to users who can read every managed zone.

### SAML login

`ui.saml` replaces the OIDC login with SAML 2.0 (HTTP-Redirect or HTTP-POST request, HTTP-POST response); `ui.issuer`, `ui.client_id` and `ui.redirect_url` must then be empty. Setup with AWS IAM Identity Center: [IDENTITY-CENTER.md](IDENTITY-CENTER.md).

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
| `ui.saml.name_id_format` | `unspecified` | `unspecified`, `email`, `persistent` or `transient`, requested in the AuthnRequest. The NameID is the subject id (`sub`): avoid `transient`, whose value changes at each login. |
| `ui.saml.attributes` | `{email: email, name: name, groups: groups}` | Claim to SAML attribute (`Name` or `FriendlyName`) mapping; the given entries are added to the defaults. A single value becomes a string claim, several a list; `groups` is always a list. An `amr` entry feeds the authentication methods instead of a claim. Unmapped attributes are dropped. |
| `ui.saml.team_claim`, `ui.saml.team_claim_prefix` | | As `issuers[].team_claim` and `team_claim_prefix`. |
| `ui.saml.groups_from_identity_store.identity_store_id` | | Identity store (`d-xxxxxxxxxx`) whose groups are looked up at login. |
| `...region` | (required) | Region of the IAM Identity Center instance. |
| `...assume_role_arn` | | Role assumed for the lookup (the identity store lives in the management or delegated administrator account); the gate's own credentials otherwise. |
| `...user_attribute` | `userName` | `userName` or `email`: identity store attribute matched with the value of `user_claim`. |
| `...user_claim` | `sub` | Claim holding that value (the NameID by default). |
| `...cache_ttl` | `5m` | Per-instance cache of the groups of a user and of group names (at most `1h`). |

The display name of every group the user belongs to (`identitystore:GetUserId`, `ListGroupMembershipsForMember`, `DescribeGroup`) is added to the `groups` claim, together with the `groups` attribute of the assertion if the IdP sends one. A user missing from the identity store just gets no extra group; any other lookup error fails the login (`502 groups_unavailable`). Groups are resolved at login and kept in the session: a membership change applies at the next login.

Validation of the response posted to `/auth/saml/acs`: XML signature of the response or of the assertion with a certificate of the IdP metadata (unsigned responses refused, encrypted assertions decrypted with the SP key when configured), response `Destination` and assertion `Recipient` equal to `acs_url`, `InResponseTo` equal to the id of the AuthnRequest kept in the sealed login cookie, `RelayState` equal to the random state of that cookie, issuer equal to the IdP entity id, every `AudienceRestriction` equal to `entity_id` (at least one required), `IssueInstant` at most 90 s old, `NotBefore`/`NotOnOrAfter` with 3 minutes of clock skew, a bearer `SubjectConfirmation` and a non-empty NameID. The session then follows the OIDC rules: `sub` = NameID, mapped claims, `auth_time` = `AuthnInstant`, `amr` = the `AuthnContextClassRef` (and the `amr` attribute if mapped), lifetime `ui.session_ttl` capped by `SessionNotOnOrAfter`.

- The login state cookie must come back on the cross-site POST of the IdP: it is `SameSite=None; Secure` when `acs_url` is HTTPS (plain HTTP only works with an IdP on the same site, for tests). A response posted without it is refused (`400 login_state`), except an unsolicited one (no `InResponseTo`, an IdP-initiated login from a portal), which is answered with a redirect to `/auth/login` so that a proper SP-initiated login starts.
- Replay: the gate keeps no record of the assertions it consumed (it runs stateless, also on Lambda). A response is only accepted with the login cookie of the browser that started that very login, which is cleared on first use, and within 90 s of its issuance. Someone who captured both the cookie and the response within those 90 s could replay them; TLS and the `HttpOnly` cookie make that a browser or proxy compromise.
- Step-up: `/auth/login?reauth=1` sends `ForceAuthn="true"`. The `AuthnInstant` returned by the IdP is what counts for `policy.edit_max_age`: an IdP that ignores `ForceAuthn` and returns an older instant keeps the user out of policy mutations until they sign in again at the IdP. Identity Center reports `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`-style context classes rather than `mfa`: set `policy.require_amr` only to values the IdP actually sends.
- With `DNS_GATE_SAML_SP_KEY` and `DNS_GATE_SAML_SP_CERT`, requests are signed (RSA-SHA256 or ECDSA-SHA256) and the metadata lists the certificate; without them, requests are unsigned, which Identity Center accepts.
- `GET /auth/saml/metadata` serves the SP metadata (entity id, ACS URL, NameID format, certificate) to import at the IdP.

## Endpoints

| Path | Description |
|---|---|
| EuroDNS API paths | Opened operations, for zones of a `eurodns` provider only (`404 zone_not_eurodns` otherwise): `getDnsZone`, `saveDnsZone`, `checkDnsZone`, `addDnsRecords`, `deleteDnsRecord` (zone engine), `listDnsZoneSnapshots`, `getSnapShot`, `getDnssecStatus`, `getDomain` (proxied to the account of the zone), and the [zone profiles](#zone-profiles) of the account (`listZoneProfiles`, `createZoneProfile`, `checkZoneProfile`, `getProfile`, `updateUserAPiZoneProfile`, `deleteZoneProfile`: the only EuroDNS provider, or the one named by the `X-DNS-Gate-Provider` header). Every other operation returns `403 operation_denied`. Query strings, encoded separators and dot segments are refused. |
| `GET /.well-known/dns-gate` | Version and features (`if-match`, `ownership`, `adopt`, `policy-delegation`, `plans`, `rrset-api`, `acme-httpreq`, and when enabled `api-keys`, `acme-dns`, `token-exchange`), unauthenticated. |
| `POST /.well-known/dns-gate/zones/{zone}/adopt` | Adopt RRsets of a EuroDNS zone (used by the `eurodns` Terraform provider on import; other providers adopt through `/api/v1/zones/{zone}/adopt`). Foreign RRsets need `dns.record.adopt`; RRsets already owned by one of the caller's teams are a no-op and only need `dns.record.write` on the zone. |
| `GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation` | [Propagation check](#propagation-check) of an RRset of a managed zone (`dns.read` on that RRset). |
| `/api/v1/me`, `/api/v1/connect`, `/api/v1/zones`, `/api/v1/zones/{zone}/rrsets`, `/api/v1/audit` | UI API (`ui.read`; `/zones` lists managed zones then unmanaged ones (`"unmanaged": true`), whose `rrsets` need `dns.read`; `/me` for any bound subject, with its groups and effective permissions; `/connect` returns the public URL, the MCP state, the login issuer and `ui.cli_scope` for the Connect page). |
| `GET /api/v1/connect/claude-desktop.mcpb` | Claude Desktop extension of the gate (`ui.read`), when MCP and the UI login are enabled, see [Claude Desktop extension](#claude-desktop-extension). |
| `/api/v1/policy`, `/api/v1/policy/revisions[/{id}[/approve\|reject\|activate\|rollback\|export]]`, `/api/v1/policy/explain`, `/api/v1/policy/who-can`, `/api/v1/policy/virtual-keys/generate` | Policy API, see `internal/uiapi/policy.go`. |
| `/api/v1/policy/delegated[/roles\|bindings/{name}]` | [Delegation API](#delegation-api) (`GET`, `PUT`, `DELETE`). |
| `GET /api/v1/teams[/{team}]`, `POST /api/v1/teams/{team}/rename` | [Teams](#teams) and team renames. |
| `POST /api/v1/zones/{zone}/transfers`, `GET /api/v1/transfers[/{id}]`, `POST /api/v1/transfers/{id}/approve\|reject` | [Ownership transfers](#ownership). |
| `/api/v1/providers/{provider}/zone-profiles[/check\|/{id}]` | [Zone profiles](#zone-profiles) of a EuroDNS provider (`dns.zone.profile` on `*`), see [API.md](API.md#zone-profiles). |
| `/auth/login`, `/auth/callback`, `/auth/logout` | UI login (`/auth/callback` with OIDC only). |
| `POST /auth/saml/acs`, `GET /auth/saml/metadata` | SAML assertion consumer service and SP metadata, with `ui.saml`. |
| `POST /api/v1/tokens` | Gate token for the UI session, see [Gate-issued tokens](#gate-issued-tokens). |
| `POST /api/v1/token-exchange` | Gate token for a token of an opted-in issuer, see [Token exchange](#token-exchange). |
| `GET /.well-known/jwks.json` | Public key of the gate issuer. |
| `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `POST /oauth/token` | Gate authorization server for native clients (Claude Desktop extension), with a gate issuer and the UI login. |
| `/api/v1/api-keys[/{id}[/rotate]]` | [API keys](API.md#api-keys) (`gate.apikey.manage`). |
| `POST /acme/httpreq/present`, `/acme/httpreq/cleanup` | lego `httpreq` DNS-01 provider, see [ACME.md](ACME.md). |
| `POST /acme/acme-dns/update`, `/acme/acme-dns/register` | acme-dns API for acme.sh, certbot, cert-manager and Caddy, see [ACME.md](ACME.md). |
| `/healthz`, `/readyz` | Probes. |

`GET` on a zone returns an `ETag`; send it back in `If-Match` on writes to get `412 precondition` instead of overwriting a concurrent change. Errors are JSON `{"reason": "...", "message": "..."}`: `forbidden`, `not_owner`, `too_many_changes` (403), `not_found`, `zone_not_eurodns` (404), `foreign_rrset`, `tainted` (409), `precondition` (412), `invalid_zone` (400), `zone_locked` (503, `Retry-After`), `upstream` (502).
