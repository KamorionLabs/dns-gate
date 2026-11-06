# dns-gate API

The gate's own API, under `/api/v1`, is the same whatever the DNS provider behind
a zone (EuroDNS, Route53). The reference is the OpenAPI 3.1 document
[`api/dns-gate.openapi.yaml`](../api/dns-gate.openapi.yaml), rendered on the
[project site](https://kamorionlabs.github.io/dns-gate/api.html). Every other path
of the gate is the EuroDNS-compatible API, documented by
[EuroDNS](https://docapi.eurodns.com/).

## Detecting a gate

`GET /.well-known/dns-gate` (no authentication) is the only detection path:

```json
{"version": "<gate version>", "features": ["if-match", "ownership", "adopt", "policy-delegation", "plans", "rrset-api"]}
```

`rrset-api` means the single RRset endpoints below are served, `plans` the REST
plan/apply, `policy-delegation` the delegated policy API, `api-keys` the API key
endpoints, `acme-httpreq` and `acme-dns` the [ACME endpoints](ACME.md),
`token-exchange` the token exchange.

## Authentication

| Client | Credentials |
|---|---|
| Pipelines, CLIs, Terraform | `Authorization: Bearer <JWT>` from an issuer of the gate configuration (GitHub Actions, GitLab, Azure DevOps, Entra ID, any OIDC issuer), audience the gate |
| Tools that keep one credential for a run (acme.sh) | a gate token from the [token exchange](#token-exchange) of such a JWT, as a bearer token |
| Third parties without OIDC (ACME clients, appliances) | [API key](#api-keys) `dgk_<id>_<secret>`: `Authorization: Bearer dgk_…`, or basic authentication with the key id as user name and the key as password, or `X-Api-Key: dgk_…` (with `X-App-Id` or `X-Api-User` set to the key id, if sent) |
| Tools without OIDC, static | virtual key from the configuration: `X-App-Id` + `X-Api-Key` |
| Web UI | session cookie; every request other than GET also sends `X-Gate-CSRF` (the `gate_csrf` cookie) and a same-origin `Origin`, and humans need a recent login for writes (`403 reauth_required`) |

Permissions are the policy actions: `ui.read` or `dns.read` to read, and
`dns.record.write` on the zone, host and type to write. Writes also require
ownership: a team only changes RRsets it created through the gate or adopted, and
creates new ones in its scope.

```sh
GATE=https://dns-gate.example.com
TOKEN=$(cat /var/run/secrets/tokens/dns-gate)
auth=(-H "Authorization: Bearer $TOKEN")
```

## Reading

```sh
curl -sS "${auth[@]}" "$GATE/api/v1/zones"
curl -sS "${auth[@]}" "$GATE/api/v1/zones/example.com/rrsets"
curl -sS -i "${auth[@]}" "$GATE/api/v1/zones/example.com/rrsets/www/CNAME"
```

Hosts are relative to the zone, `@` is the apex, `*` is allowed as the first label
(`*.app`); the type is case-insensitive. An RRset:

```json
{
  "host": "www", "type": "CNAME", "ttl": 3600, "values": ["site.example.net."],
  "hash": "9f2c…", "status": "managed", "owner": "web", "protected": false, "adopted": false
}
```

Alias RRsets (Route53) have `"alias": {"target", "hosted_zone_id",
"evaluate_target_health"}` and no values. `read_only` explains why the gate never
writes an RRset (`server_managed`, `routing_policy`, `relative_target`…).

The single-RRset read is served from the gate's inventory cache (refreshed by
every write and every reconcile), not from the provider: a Terraform plan reading
hundreds of RRsets costs no provider request. Writes never rely on it.

## ETags and preconditions

- `GET …/rrsets/{host}/{type}` returns `ETag: "<hash>"`, the content hash of the RRset
  (TTL and values, or alias). It is also the `hash` field of every RRset.
- `GET …/rrsets` returns `ETag: "v<n>"`, the gate version of the zone, bumped by every
  write through the gate.
- `PUT` with `If-None-Match: *` creates only: `409 foreign_rrset` if an RRset
  created outside the gate exists, `412 precondition` if the gate owns one.
- `PUT` or `DELETE` with `If-Match: "<hash>"` acts only if the RRset still has that
  content: `412 precondition` otherwise. Only one hash, no `*`.

The engine checks the preconditions under the zone lock, against the zone read
from the provider, so two writers never overwrite each other silently. A single
RRset write carries no zone version: a write to another RRset of the zone in
between does not refuse it.

## Writing one RRset

```sh
# create, refused if it already exists
curl -sS -i "${auth[@]}" -X PUT "$GATE/api/v1/zones/example.com/rrsets/app/CNAME" \
  -H "Content-Type: application/json" -H "If-None-Match: *" \
  -d '{"ttl": 3600, "values": ["site.example.net."]}'

# replace, only if unchanged since it was read
curl -sS -i "${auth[@]}" -X PUT "$GATE/api/v1/zones/example.com/rrsets/app/CNAME" \
  -H "Content-Type: application/json" -H 'If-Match: "9f2c…"' \
  -d '{"ttl": 600, "values": ["other.example.net."]}'

# alias (Route53)
curl -sS "${auth[@]}" -X PUT "$GATE/api/v1/zones/example.com/rrsets/@/A" \
  -H "Content-Type: application/json" \
  -d '{"alias": {"target": "d111111abcdef8.cloudfront.net.", "hosted_zone_id": "Z2FDTNDATAQYW2"}}'

# delete (204, also when the RRset does not exist)
curl -sS -i "${auth[@]}" -X DELETE "$GATE/api/v1/zones/example.com/rrsets/app/CNAME" -H 'If-Match: "5d1e…"'
```

The body is the full desired state: `ttl` and `values`, or `alias`. The answer is
the RRset as written, with its new `ETag`.

Values are in zone file presentation format. TXT values are the text itself,
unquoted, at any length (`"v=spf1 include:_spf.example.net -all"` in JSON): the gate
or the provider splits them in 255-byte strings, and they read back as sent.
Targets without a trailing dot are absolute (`site.example.net` is
`site.example.net.`); a single-label target is refused with `400 relative_target`.

## Plan, then apply

For several RRsets at once, or to review a change before it happens:

```sh
curl -sS "${auth[@]}" -X POST "$GATE/api/v1/zones/example.com/plan" \
  -H "Content-Type: application/json" -d '{
  "changes": [
    {"host": "app", "type": "CNAME", "ttl": 3600, "values": ["site.example.net."], "must_not_exist": true},
    {"host": "old", "type": "A", "delete": true, "expected_hash": "5d1e…"}
  ]}'
```

The plan checks RBAC, ownership, preconditions and the provider validation
without writing. A refusal is `200` with `"allowed": false` and a `reason`; an
allowed plan has a `plan_id`:

```json
{"zone": "example.com", "allowed": true, "zone_version": 42, "plan_id": "plan-3f9a…",
 "changes": [{"op": "create", "host": "app", "type": "CNAME", "new_ttl": 3600, "new_values": ["site.example.net."]}]}
```

```sh
curl -sS "${auth[@]}" -X POST "$GATE/api/v1/zones/example.com/apply" \
  -H "Content-Type: application/json" -d '{"plan_id": "plan-3f9a…"}'
```

A plan is stored by the gate (shared by every instance), bound to its author, the
zone and the zone version, and valid once for `mcp.plan_ttl` (10 minutes by
default). The apply writes exactly what was planned, or fails with
`412 precondition` if the zone changed since the plan, `410 plan_expired`, or
`404 plan_not_found` (unknown, already applied, or planned for another zone): plan
again. The MCP tools
`plan_rrset_change` and `apply_rrset_change` use the same plans.

## Token exchange

`POST /api/v1/token-exchange` (RFC 8693, form-encoded, no other authentication)
trades a token of an issuer with `token_exchange: true` for a gate token with the
same identity, valid 15 minutes (`expires_in` for another lifetime, within the
issuer's `max_exchanged_ttl`, the gate issuer's `token_ttl` and 5 minutes past the
expiry of the exchanged token). Gate tokens and API keys are never exchanged.

```sh
GATE_TOKEN=$(curl -fsS "$GATE/api/v1/token-exchange" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode "subject_token=$TOKEN" | jq -r .access_token)
```

Configuration and details: [CONFIG.md](CONFIG.md#token-exchange).

## API keys

API keys are issued by the gate at runtime, for third parties that have no OIDC
identity: a hosting provider renewing certificates, an appliance. A key is bound
to one team (the owner of the RRsets it creates) and one role, with an optional
expiry and source CIDRs. Only its SHA-256 is stored; the key is shown once, at
creation and at each rotation. The same key works on this API, on the
[ACME endpoints](ACME.md) and on the EuroDNS-compatible API (`X-App-Id: <id>`,
`X-Api-Key: dgk_…`).

Managing keys needs the `gate.apikey.manage` action, from an OIDC identity (a key
never manages keys):

- the key's team must be one of the caller's teams, unless the caller holds
  `gate.apikey.manage` on `*` (gate-wide managers);
- the caller must hold `gate.apikey.manage` on every zone of the key's role, and
  every action of the role on the same zones and records: a key never has more
  rights than its issuer;
- the role may not grant `policy.*` or `gate.*` actions, nor be less ephemeral
  (longer `ephemeral_ttl`, or permanent) or less capped (`max_changes_per_request`)
  than the caller's own write rights.

The key records what its role declared at issuance (rules, `ephemeral_ttl`,
`max_changes_per_request`, 0 meaning "inherit the global default"); if the role later
declares more, the key is refused (`403 role_widened`) until a new key is issued; a
role that shrinks is fine, and changing the global limits or `policy.bounds` never
invalidates keys. A key without a recorded grant is refused. The creator of a key and the
members of its team holding `gate.apikey.manage` anywhere can always see and revoke
it, even when they no longer manage the zones of its role.

```sh
# create (201); the answer carries "key", shown once
curl -sS "${auth[@]}" -X POST "$GATE/api/v1/api-keys" -H "Content-Type: application/json" -d '{
  "name": "web certificates", "team": "web", "role": "acme-solver",
  "expires_at": "2027-06-30T00:00:00Z", "allowed_cidrs": ["192.0.2.0/24"],
  "acme_domains": ["www.example.com", "example.com"]}'

curl -sS "${auth[@]}" "$GATE/api/v1/api-keys"                    # list, with last use
curl -sS "${auth[@]}" "$GATE/api/v1/api-keys/3f9a0c1b2d4e5f60"   # one key

# rotate: the previous key stays valid during the overlap (default 24h, "0s" for none)
curl -sS "${auth[@]}" -X POST "$GATE/api/v1/api-keys/3f9a0c1b2d4e5f60/rotate" \
  -H "Content-Type: application/json" -d '{"overlap": "1h"}'

# replace the mutable fields (name, description, expiry, CIDRs, ACME domains);
# without acme_domains the acme-dns registrations stay as they are, with it only
# those created through the API are synced (never those of clients, "origin": "client")
curl -sS "${auth[@]}" -X PUT "$GATE/api/v1/api-keys/3f9a0c1b2d4e5f60" \
  -H "Content-Type: application/json" -d '{"name": "web certificates", "acme_domains": ["www.example.com"]}'

# revoke (204): the key stops working at once, it stays listed with ?include_revoked=true
curl -sS "${auth[@]}" -X DELETE "$GATE/api/v1/api-keys/3f9a0c1b2d4e5f60"
```

A listed key:

```json
{"id": "3f9a0c1b2d4e5f60", "name": "web certificates", "team": "web", "role": "acme-solver",
 "status": "active", "expires_at": "2027-06-30T00:00:00Z", "allowed_cidrs": ["192.0.2.0/24"],
 "acme_domains": ["example.com", "www.example.com"],
 "acme_dns": [{"subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a", "domain": "www.example.com", "allowfrom": []}],
 "created_at": "…", "created_by": "github:repo:example/dns:ref:refs/heads/main",
 "last_used_at": "…", "last_used_ip": "192.0.2.10"}
```

The creation and rotation answers add `key` and `acme_dns_accounts` (the acme-dns
accounts of the key by domain, see [ACME.md](ACME.md)). Team and role never change
(`409 immutable` on `PUT`): create another key. Humans need a recent login to
create, change or rotate keys. Refused key uses are audited
(`apikey.authenticate`, with the key id, never the key), as are creations,
changes, rotations and revocations (`apikey.*`).

## Errors

Errors are JSON, with a stable `reason` for programs:

```json
{"reason": "not_owner", "message": "www CNAME is owned by team api"}
```

| Status | Reasons |
|---|---|
| 400 | `invalid` (request or provider validation), `relative_target` (single-label target), `bad_request` |
| 401 | `unauthenticated` (also an unknown, revoked, expired or rotated API key) |
| 403 | `forbidden` (RBAC, protected record, plan of another caller), `not_owner` (another team), `too_many_changes`, `reauth_required`, `csrf`, `session_required`, `source_ip` (key used outside its CIDRs), `role_widened` (API key whose role grew), `ephemeral_required` (ACME endpoints) |
| 404 | `not_found` (zone not managed, RRset unknown), `plan_not_found`, `zone_not_eurodns` (EuroDNS-compatible API on a zone of another provider) |
| 409 | `foreign_rrset` (created outside the gate: adopt it first), `tainted` (changed outside the gate), `adopt_conflict`, `immutable`, `revoked` (API keys), `too_many_values`, `too_many_registrations`, `value_taken` (ACME endpoints) |
| 410 | `plan_expired` |
| 412 | `precondition` (If-Match, If-None-Match, `expected_hash`, `must_not_exist`, zone changed since the plan) |
| 423 | `zone_locked`, with `Retry-After` |
| 502 | `upstream` (provider error) |

The full list is in the `Error` schema of the OpenAPI document.

## Other endpoints

- `GET /api/v1/audit` — audit log, newest first, filtered to the zones the caller
  can read.
- `POST /api/v1/tokens` — a gate-issued bearer token for the signed-in UI user
  (session cookie and CSRF header only), the *Get an API token* action of the
  Connect page ([IDENTITY-CENTER.md](IDENTITY-CENTER.md)); its keys are at
  `/.well-known/jwks.json`.
- `POST /api/v1/zones/{zone}/adopt/preview` and `/adopt` — take over RRsets created
  outside the gate ([ONBOARDING.md](ONBOARDING.md)).
- `GET /api/v1/zones/{zone}/terraform` — managed RRsets as `dnsgate_record_set`
  resources with `import` blocks (`provider=eurodns` for `eurodns_record_set`).
- `/api/v1/policy/delegated/…` — roles and bindings managed by pipelines within a
  delegation ([CONFIG.md](CONFIG.md)).
- `/api/v1/policy/…` — the policy editor of the web UI.
- `/acme/httpreq/present`, `/acme/httpreq/cleanup`, `/acme/acme-dns/update`,
  `/acme/acme-dns/register` — DNS-01 challenges for certbot, acme.sh, lego,
  win-acme, cert-manager and Caddy, with an OIDC token, a gate token or an API key
  ([ACME.md](ACME.md)).
