# Authentication

## 9. Authentication

### 9.1 OIDC (JWT)

Modelled on Vault's JWT auth roles. Each trusted issuer is configured with its
issuer URL (discovery) or explicit JWKS URL. Bindings match tokens on
`bound_audiences` and `bound_claims` (glob) and map them to roles and teams.

| Issuer | Typical subject | Use |
|---|---|---|
| AWS IAM outbound identity federation (`sts:GetWebIdentityToken`) | IAM role ARN | Any AWS workload: EKS Pod Identity, Lambda, CI assuming a role. Stable subject, Kubernetes only talks to AWS. |
| GitHub Actions (`token.actions.githubusercontent.com`) | `repo:org/repo:ref:...` | CI on GitHub |
| GitLab CI | project path, ref | CI on GitLab |
| Kubernetes service account (cluster issuer) | `system:serviceaccount:ns:sa` | in-cluster workloads (when AWS federation is not used) |
| Entra ID (see 9.2) | `tid` + `oid`, app roles | Azure workloads (Managed Identity, AKS Workload Identity), Azure DevOps pipelines, humans |

Checks: signature, `iss`, `exp`/`nbf` (small leeway), `aud` must equal the gate's
configured audience (prevents replay of tokens issued for another service), maximum
token lifetime.

A binding normally acts for a fixed team. With `team_from` it derives the team of
each subject from a claim (anchored regex, one capture group, optional prefix), so
one binding with a subject glob covers many pipelines while ownership keeps them
apart: each pipeline only changes the RRsets its own team created. A subject whose
claim yields no valid team is not bound by that binding (fail closed). Any matching
identity can still create RRsets that do not exist yet within the role, which is the
trade-off of binding by glob (THREAT-MODEL T29).

### 9.2 Entra ID

Azure workloads authenticate with an **Entra ID access token issued for the gate's
app registration** (audience = the gate's application id URI or client id):

| Workload | How it gets the token |
|---|---|
| Azure resource with a Managed Identity | IMDS / `DefaultAzureCredential`, scope `api://<gate-app>/.default` |
| AKS pod with Workload Identity | federated credential on a user-assigned identity, then the same scope |
| Azure DevOps pipeline | service connection in **workload identity federation** mode, then `az account get-access-token --scope api://<gate-app>/.default` (or the SDK) |

Rules:

- **Bindings on app roles** (`roles` claim), defined on the gate's app registration
  and assigned to the identities. Not on groups: the `groups` claim is dropped above
  a size limit (overage) and replaced by a Graph lookup the gate does not perform.
- **Stable subject** = `tid` + `oid` (tenant and object id). `sub` is pairwise per
  application, and `appid`/`azp` identify the client app, not the identity.
- **Actor category** from `idtyp` (`app` → pipeline/workload, `user` → human).
- The issuer must be tenant-specific
  (`https://login.microsoftonline.com/<tenant-id>/v2.0`, or the v1
  `https://sts.windows.net/<tenant-id>/`). Multi-tenant endpoints (`/common`,
  `/organizations`, `/consumers`) are refused in configuration.
- **Do not trust the raw Azure DevOps OIDC token.** The token ADO issues for a
  service connection has a fixed audience, `api://AzureADTokenExchange`, meant for
  the exchange with Entra. Accepting it would let any service receiving such a token
  replay it against the gate. The gate only accepts the Entra access token obtained
  after the exchange, whose audience is the gate itself.

### 9.3 Virtual keys

Static keys declared in the policy (`virtual_keys`, base file or managed layer) for
existing EuroDNS clients that only know `X-APP-ID`/`X-API-KEY`: `X-APP-ID` = key id,
`X-API-KEY` = high-entropy secret stored hashed. Each key grants roles and teams
directly, has an expiry, and can be bound to source CIDRs. Changing one is a policy
change; API keys (9.5) are issued, rotated and revoked at runtime instead, and work on
the same headers.

### 9.4 SAML users and gate-issued tokens

Humans may sign in to the UI with SAML 2.0 instead of OIDC (`ui.saml`, e.g. an AWS
IAM Identity Center custom application). The validated assertion becomes a session
exactly like an ID token: `sub` = NameID, mapped attributes as claims, bound under a
configured issuer name (`identity-center`), with optional group names looked up in
the Identity Center identity store.

Those users have no bearer token for the API, MCP or Terraform, so the gate can be its
own issuer (`issuers[].self`): it signs short-lived JWTs (ES256 or EdDSA, JWKS at
`/.well-known/jwks.json`) carrying the session claims plus `gate_iss`, and binds them
back as that issuer, so one set of bindings covers the session and its tokens. Tokens
come from `POST /api/v1/tokens` (session + CSRF) or from a stateless OAuth
authorization server (`/oauth/authorize`, `/oauth/token`, PKCE, loopback redirects
only, consent page) used by the Claude Desktop extension. Codes and refresh tokens
are sealed with the session key; nothing is stored, so the gate stays stateless
across instances (Lambda).

SAML response validation (`/auth/saml/acs`). Validation of the response posted to `/auth/saml/acs`: XML signature of the response or of the assertion with a certificate of the IdP metadata (unsigned responses refused, encrypted assertions decrypted with the SP key when configured), response `Destination` and assertion `Recipient` equal to `acs_url`, `InResponseTo` equal to the id of the AuthnRequest kept in the sealed login cookie, `RelayState` equal to the random state of that cookie, issuer equal to the IdP entity id, every `AudienceRestriction` equal to `entity_id` (at least one required), `IssueInstant` at most 90 s old, `NotBefore`/`NotOnOrAfter` with 3 minutes of clock skew, a bearer `SubjectConfirmation` and a non-empty NameID. The session then follows the OIDC rules: `sub` = NameID, mapped claims, `auth_time` = `AuthnInstant`, `amr` = the `AuthnContextClassRef` (and the `amr` attribute if mapped), lifetime `ui.session_ttl` capped by `SessionNotOnOrAfter`.

Replay: the gate keeps no record of the assertions it consumed (it runs stateless, also on Lambda). A response is only accepted with the login cookie of the browser that started that very login, which is cleared on first use, and within 90 s of its issuance. Someone who captured both the cookie and the response within those 90 s could replay them; TLS and the `HttpOnly` cookie make that a browser or proxy compromise.

### 9.5 API keys

For third parties with no OIDC identity (a hosting provider renewing certificates,
an appliance), the gate issues API keys at runtime (`/api/v1/api-keys`, guide in
[API.md](../API.md)). OIDC stays the first choice; a key is a long-lived secret held
outside the organization.

- **Format**: `dgk_<id>_<secret>`, `id` 16 hex characters (the public key id, also
  the user name of basic authentication and of acme-dns), `secret` 32 random bytes
  in base64url. Only the SHA-256 of the whole key is stored; the key is returned
  once, at creation and at each rotation.
- **Presentation**: `Authorization: Bearer dgk_…`, basic authentication (user = key
  id), or `X-Api-Key` (with `X-App-Id` or `X-Api-User` = key id when sent), so the
  same key serves the neutral API, the ACME endpoints and EuroDNS-header clients.
- **Scope**: one team (owner of the RRsets it creates) and one role, optional expiry
  and source CIDRs. The role may not grant `policy.*` or `gate.*` actions, checked at
  creation and again at each use: a key whose role disappeared or gained such an
  action stops working.
- **Management**: `gate.apikey.manage`, held by a token or session identity, never
  by an API key or a virtual key. The key's team must be one of the caller's teams (unless the caller holds
  the action on `*`), and the caller must hold the action on every zone of the key's
  role, plus every action of that role on the same records: a key never exceeds its
  issuer.
- **Rotation and revocation**: a rotation issues a new secret and keeps the previous
  one valid for an overlap (default 24 h, at most 30 days, `0s` for none); a
  revocation is immediate. Team and role never change. Requests made with a key are
  audited as `api-key:<id>`; refused keys and every management call are audited
  too, with the key id, never the key.
- **ACME**: a key may carry acme-dns registrations, one per domain, mapping an
  acme-dns subdomain to the `_acme-challenge` TXT RRset of the managed zone
  ([ACME.md](../ACME.md)).

### 9.6 Token exchange

Some clients keep a credential for minutes or hours (certbot and acme.sh hooks,
long scripts), longer than the CI or workload token they start with. Instead of an
API key, they exchange that token for a gate token (OAuth 2.0 token exchange,
RFC 8693, `POST /api/v1/token-exchange`, configuration in
[configuration](../config/authentication.md#token-exchange)):

- opt-in per issuer (`token_exchange: true`), and only with a gate issuer
  (`self: true`, 9.4) to sign the result. Gate tokens and API keys are never
  exchanged;
- the subject token is checked exactly as a bearer token of its issuer (signature,
  audience, bound claims, bindings); the gate token carries its claims, binds back as
  that issuer and records the exchanged `jti` (`gate_xchg`), so bindings and audit
  see the same identity;
- lifetime 15 minutes by default, `expires_in` (at least 60 s) to ask for another,
  capped by the gate issuer's `token_ttl`. Roles are recomputed at every request, so
  a removed binding takes effect at once;
- every exchange, and every refused subject token, is audited
  (`gate.token.exchange`).

### 9.7 Delegated clients and scopes

A token of a trusted issuer says who the user is, and its `azp` (Entra v2) or
`appid` (v1) says which application obtained it. Without more, an assistant such as
a Microsoft 365 Copilot agent holds every right of its user. A **delegated client**
(`issuers[].delegated_clients`, [configuration](../config/authentication.md#delegated-clients))
names an application and caps it:

- **Scopes** are allowlists of RBAC actions (`dns.read`, `dns.plan`, `dns.write`,
  `dns.adopt`, `dns.transfer`, `policy.read`). Effective rights = RBAC of the user ∩
  actions of the scopes ∩ zones of the client. The definitions and the intersection
  live in one package (`internal/scope`), used by the policy engine for every
  decision (`Allow`, `AllowRRset`, `AllowMeta`, `/api/v1/me` permissions), so no
  handler can forget it. Policy writes, API key management, zone administration and
  zone profiles are granted by no scope.
- **Intents.** `dns.plan` grants the write actions only on a copy of the subject
  marked for a plan (plan and adoption preview handlers); `dns.transfer` grants them
  only as proof of ownership inside the transfer checks. The subject of the apply is
  never marked.
- **Surfaces and endpoints.** `Authenticate` refuses delegated tokens
  (`not_delegable`); only `/api/v1` and `/mcp` call `AuthenticateFor` with their
  surface. The `/api/v1` router and the MCP tool list carry an explicit table of what
  each scope opens; a route or tool missing from it is refused to every delegated
  client (deny by default), before the handler runs, with `scope_insufficient` and
  `required_scope` or `not_delegable`. The MCP middleware filters `tools/list`
  (cache scope `private`) and refuses hidden tools.
- **Plans** are keyed by the subject and its client: a plan is applied only through
  the client that made it, and a plan made without client never through one.
- **Identity.** `identity.Subject` keeps the user (`String()` unchanged) and gains
  `Client` and `Scopes`; a transfer approver is recorded with them and rebound from
  the current client configuration on retries.
- **Audit.** The authenticator records the client in the request context; every event
  of the request carries `client_id`, `actor {type: oauth_client, id, name}` and
  `auth_method: oauth-delegated`, from the configuration only.
- Tokens of undeclared clients keep the full rights of the user unless
  `require_known_client` refuses them. Gate tokens are not delegated yet: declared
  OAuth clients of the gate authorization server will carry `client_id` and `scope`
  in gate tokens and reuse the same `Subject.Client`, `Subject.Scopes` and checks.
