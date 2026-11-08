# API guide

The rules behind the gate's API. The operations and schemas are in the
[API reference](https://kamorionlabs.github.io/dns-gate/api.html) (OpenAPI 3.1,
[`api/dns-gate.openapi.yaml`](../api/dns-gate.openapi.yaml)); runnable examples in
several languages are in [API by example](api/index.md).

The gate's own API lives under `/api/v1` and is the same whatever the provider of a
zone (Route 53, EuroDNS). For EuroDNS zones the gate also serves the
EuroDNS-compatible API, documented by [EuroDNS](https://docapi.eurodns.com/): an
existing EuroDNS client changes its base URL and credentials only.

## Detecting a gate

`GET /.well-known/dns-gate` (no authentication) is the only detection path:

```json
{"version": "0.9.0", "features": ["if-match", "ownership", "adopt", "policy-delegation", "plans", "rrset-api", "forwards", "token-exchange", "api-keys", "acme-httpreq", "acme-dns"]}
```

| Feature | Meaning |
|---|---|
| `rrset-api` | the single-RRset endpoints |
| `forwards` | the [URL forward](#url-forwards) endpoints |
| `plans` | REST plan and apply |
| `policy-delegation` | the [delegation API](config/managed-policy.md#delegation-api) |
| `api-keys`, `token-exchange` | [API keys](#api-keys), the [token exchange](#token-exchange), when enabled |
| `acme-httpreq`, `acme-dns` | the [ACME endpoints](ACME.md) |

## Authentication

| Client | Credentials |
|---|---|
| Pipelines, CLIs, Terraform | `Authorization: Bearer <JWT>` from an issuer of the configuration, audience the gate |
| Tools that keep one credential for a run (acme.sh) | a gate token from the [token exchange](#token-exchange), as a bearer token |
| Third parties without OIDC | an [API key](#api-keys) `dgk_<id>_<secret>`: `Authorization: Bearer dgk_…`, or basic authentication (key id as user name, key as password), or `X-Api-Key: dgk_…` (with `X-App-Id` or `X-Api-User` set to the key id, if sent) |
| Static tools without OIDC | a virtual key of the configuration: `X-App-Id` + `X-Api-Key` |
| Web UI | the session cookie; every request other than `GET` also sends `X-Gate-CSRF` (the `gate_csrf` cookie) and a same-origin `Origin`; people need a recent login for writes (`403 reauth_required`) |

Permissions are the [policy actions](concepts/policy.md#rules): `ui.read` or
`dns.read` to read, `dns.record.write` on the zone, host and type to write records,
`dns.forward.write` on the zone and host for URL forwards. Writes also require
ownership: a team only changes RRsets it created through the gate or adopted.

## RRsets

Hosts are relative to the zone, `@` is the apex, `*` is allowed as the first label
(`*.app`); types are case-insensitive. An RRset:

```json
{"host": "www", "type": "CNAME", "ttl": 3600, "values": ["site.example.net."],
 "hash": "9f2c…", "status": "managed", "owner": "web", "protected": false, "adopted": false}
```

- **Status**: `managed`, `foreign`, `tainted`, `missing` or `pending`, see
  [record states](concepts/ownership.md#record-states). `read_only` explains why the
  gate never writes an RRset (`server_managed`, `routing_policy`, `relative_target`…).
- **Alias** RRsets (Route 53) have `"alias": {"target", "hosted_zone_id",
  "evaluate_target_health"}` and no values.
- **Values** are in zone file presentation format. TXT values are the text itself,
  unquoted, at any length: the gate or the provider splits them in 255-byte strings
  and they read back as sent. Targets without a trailing dot are absolute; a
  single-label target is refused (`400 relative_target`).
- **Reads** of single RRsets come from the gate's inventory cache, refreshed by every
  write and every reconcile: a Terraform plan reading hundreds of RRsets costs no
  provider request. Writes never rely on it.
- A `PUT` body is the full desired state: `ttl` and `values`, or `alias`. The answer
  is the RRset as written, with its new `ETag`. `DELETE` answers `204`, also when the
  RRset does not exist.

## Preconditions

| Request | Effect |
|---|---|
| `GET …/rrsets/{host}/{type}` | `ETag: "<hash>"`, the content hash (TTL and values, or alias), also the `hash` field |
| `GET …/rrsets` | `ETag: "v<n>"`, the gate version of the zone, bumped by every write through the gate |
| `PUT` with `If-None-Match: *` | creates only: `409 foreign_rrset` if an RRset exists outside the gate, `412 precondition` if the gate owns one |
| `PUT` or `DELETE` with `If-Match: "<hash>"` | acts only if the RRset still has that content, `412 precondition` otherwise (one hash, no `*`) |

The engine checks preconditions under the zone lock, against the zone read from the
provider. A single-RRset write carries no zone version: a write to another RRset of
the zone in between does not refuse it.

## Plan and apply

`POST /api/v1/zones/{zone}/plan` checks RBAC, ownership, preconditions and the
provider validation for up to 100 changes, without writing. A change is the desired
state of an RRset (`ttl`, `values` or `alias`), or `"delete": true`, guarded by
`"expected_hash"` or `"must_not_exist"`; a forward change has `"type": "URLFWD"` and
a `forward` object.

- A refusal is `200` with `"allowed": false`, a `reason` and a `message`. An allowed
  plan has a `plan_id`.
- The plan is stored by the gate (shared by every instance), bound to its author, the
  zone, the zone version and its team, valid once for `mcp.plan_ttl` (10 minutes).
- `POST …/apply` with the `plan_id` writes exactly what was planned, or fails:
  `412 precondition` (the zone changed), `410 plan_expired`, `404 plan_not_found`
  (unknown, applied, or for another zone). The result carries `new_hash` for every
  created or updated RRset.
- The MCP tools `plan_rrset_change` and `apply_rrset_change` use the same plans.

## URL forwards

A forward is the RRset of type `URLFWD` of its host: owned, adopted, transferred and
audited like any RRset, with no TTL nor values and a `forward` object. Endpoints:
`GET /api/v1/zones/{zone}/forwards`, `GET|PUT|DELETE …/forwards/{host}`, with the same
preconditions. Only providers with forwards (EuroDNS) have them; elsewhere a write is
`400 invalid`.

| Field | Rules |
|---|---|
| `type` | `301`, `302` or `frame` |
| `url` | absolute `http://` or `https://`, at most 2048 bytes, no user information, spaces, control characters nor unencoded ``< > " ' ` \ { } | ^``, host in punycode, canonical form (as Go's `net/url` prints it) |
| `title`, `keywords`, `description` | frames only, plain text of at most 200, 500 and 1000 characters, without control or format characters nor ``< > " ' ` ``: EuroDNS shows them in the page it serves on the host |
| `require_https` | refuses the write (`409 https_unavailable`) unless the forwards of the zone answer HTTPS; checked after authorization, before the zone lock, nothing stored |

A forward cannot be created over `A`, `AAAA`, `CNAME` or `APEX` records of its host
owned by another team or by nobody, nor those records over another team's forward.

**HTTPS.** The forward host answers HTTPS only when the domain has an EuroDNS *HTTPS
redirect* subscription, a paid product ordered outside the gate. The gate reads it
(cached 10 minutes) and reports `https.status`: `active`, `pending` (certificate being
issued), `no_forward` (active, issued once the zone has a forward), `inactive` (plain
HTTP only, or past its expiry), `unknown` (read failed, or a key without access to
subscriptions; kept 30 seconds) or `unsupported`. `require_https` accepts `active`
and `no_forward` only. The gate never orders, renews nor cancels a subscription.

## DNS propagation

`GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation` asks the authoritative
name servers of the zone and public resolvers for one RRset and compares their
answers with the RRset as read from the provider. Guide:
[Propagation check](features/propagation.md).

```json
{
  "zone": "example.com", "host": "app", "type": "CNAME", "name": "app.example.com.", "query_type": "CNAME",
  "expected": {"exists": true, "hash": "9f2c…", "ttl": 3600, "values": ["site.example.net."]},
  "checked_at": "2026-11-06T10:00:00Z", "cached": false,
  "summary": {"total": 21, "match": 17, "stale": 2, "missing": 0, "error": 2, "converged": false, "max_ttl_left": 1740},
  "answers": [
    {"kind": "authoritative", "name": "ns1.example-dns.net", "address": "192.0.2.53", "status": "match",
     "values": ["site.example.net."], "ttl_left": 3600, "rcode": "NOERROR", "latency_ms": 12},
    {"kind": "resolver", "name": "Cloudflare", "address": "1.1.1.1", "location": "Anycast", "country": "US",
     "region": "anycast", "status": "stale", "values": ["old.example.net."], "ttl_left": 1740, "rcode": "NOERROR", "latency_ms": 9}
  ]
}
```

| Answer status | Meaning |
|---|---|
| `match` | the expected content (and, for authoritative answers, the expected TTL) |
| `stale` | other values: the previous content, cached until `ttl_left` runs out |
| `missing` | NXDOMAIN or no record of the type, possibly a cached negative answer |
| `error` | timeout, `SERVFAIL`, `REFUSED`, no authority, records of another name, an answer filtered by the resolver |
| `indeterminate` | alias RRsets: addresses that are not all the target's (a CDN answers per location) |

`summary.converged` is true when every server that answered matches, with at least
one authoritative server, and none is indeterminate; `max_ttl_left` bounds when stale
caches expire.

- `?expect=<hash>` after a write (the `ETag` of a `PUT`, the `new_hash` of an apply)
  or `?expect=absent` after a delete: an instance whose inventory differs reads the
  zone again first, and answers `412 precondition` if it still differs.
- Requires `dns.read` on the RRset, in a managed zone. Results are cached a few
  seconds per RRset content; `429` per caller and `503 busy` per instance, both with
  `Retry-After`; `501 not_implemented` when `propagation.enabled` is false.
- Not audited (a read). The MCP tool `check_propagation` does the same.

## Token exchange

`POST /api/v1/token-exchange` (RFC 8693, form-encoded, no other authentication)
trades a token of an issuer with `token_exchange: true` for a gate token with the
same identity.

- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, and
  `subject_token_type` `…:jwt`, `…:id_token` or `…:access_token`; `actor_token` is
  refused.
- The subject token is validated as a bearer token of its issuer (signature,
  audiences, `bound_claims`) and its identity must be bound (`no_binding`).
- Lifetime 15 minutes, or `expires_in` (at least 60 seconds), capped by the issuer's
  `max_exchanged_ttl`, the gate issuer's `token_ttl` and the subject token's expiry
  plus 5 minutes.
- Gate tokens and API keys are never exchanged. Errors follow RFC 6749
  (`400 invalid_grant`); without an opted-in issuer the endpoint answers
  `404 token_exchange_disabled`.

Configuration: [token exchange](config/authentication.md#token-exchange).

## API keys

Keys are issued at runtime for third parties without an OIDC identity, one team and
one role each, with an optional expiry and source CIDRs. Only their SHA-256 is
stored; the key is shown once, at creation and at each rotation. A key works on this
API, the [ACME endpoints](ACME.md) and the EuroDNS-compatible API (`X-App-Id: <id>`,
`X-Api-Key: dgk_…`).

| Route | Effect |
|---|---|
| `POST /api/v1/api-keys` | create (`201`): `name`, `team`, `role`, `expires_at`, `allowed_cidrs`, `acme_domains`; the answer adds `key` and `acme_dns_accounts` |
| `GET /api/v1/api-keys[/{id}]` | list (with last use, `?include_revoked=true`), one key |
| `POST /api/v1/api-keys/{id}/rotate` | new key; the previous one stays valid for `overlap` (default `24h`, `"0s"` for none) |
| `PUT /api/v1/api-keys/{id}` | replace name, description, expiry, CIDRs, ACME domains; team and role never change (`409 immutable`) |
| `DELETE /api/v1/api-keys/{id}` | revoke (`204`) at once |

Managing keys needs `gate.apikey.manage`, from an OIDC identity (a key never manages
keys):

- the key's team must be one of the caller's teams, unless the caller holds
  `gate.apikey.manage` on `*`;
- the caller must hold `gate.apikey.manage` on every zone and folder pattern of the
  key's role, and every action of the role on the same zones, folders and records: a
  key never has more rights than its issuer (a managed or delegated rule of the
  caller covers a folder pattern only when `policy.bounds.zones`, and the
  `allow.zones` of its delegation, cover every zone);
- the role may not grant `policy.*` or `gate.*`, nor be less ephemeral or less
  capped (`max_changes_per_request`) than the caller's own write rights;
- with a `teams` block, the team must be declared.

The key records its role as issued; if the role later grants more, the key is refused
(`403 role_widened`) until a new key is issued. The creator and the members of its
team holding `gate.apikey.manage` can always see and revoke it. People need a recent
login to create, change or rotate keys. Every refused use and every change is
audited (`apikey.*`, with the key id, never the key).

## Teams and transfers

A caller bound to several teams writes for its **default team** (`default_team` of
`GET /api/v1/me`). `X-DNS-Gate-Team: <team>` on a write, or `team` in a plan, acts for
another of its teams (`403 not_team_member` otherwise; an apply naming another team
than its plan is `400 team_mismatch`). The EuroDNS-compatible API always uses the
default team.

- `GET /api/v1/teams` lists the teams (declared, referenced, derived from claims, and
  owners found in the store), with RRset counts in the zones the caller can read;
  `GET /api/v1/teams/{team}` adds what the team owns per zone, its pending transfers
  and, for `policy.read` holders and members, the rules of its roles.
- A deleted RRset stays reserved for its team for `ownership.tombstone_ttl` (7 days):
  another team gets `403 not_owner`. Live tombstones are in the `tombstones` of
  `GET /api/v1/zones/{zone}/rrsets`.

**Transfers.** `POST /api/v1/zones/{zone}/transfers` with `rrsets` (of one team),
`to_team`, `comment`, optionally `"apply": true`; then
`POST /api/v1/transfers/{id}/approve` or `/reject`.

- The requester is a member of either team allowed to write the RRsets through it,
  or holds `dns.ownership.approve`. The approver may write every RRset through the
  owner team, or holds `dns.ownership.approve` on it; a human with a recent login
  (unless `ownership.machine_approvers`); another person with
  `ownership.require_second_approver`, otherwise possibly the requester
  (`approval: self`). The requester can always withdraw (`/reject`).
- Approval applies at once, under the zone lock, if every RRset still has the team and
  content hash of the request (store and provider), else `412 precondition` and the
  transfer is `failed`. A locked zone or an unavailable store or provider leaves it
  `applying` (`423` or `502`), retried in the background for 24 hours with the
  approver's rights checked again. Without a decision within
  `ownership.transfer_ttl` (7 days) it expires (`410 expired`).
- `GET /api/v1/transfers?status=proposed` is the inbox; `can_decide` marks what the
  caller may approve.
- `POST /api/v1/teams/{team}/rename` (`policy.propose`, approved by a
  `policy.approve` holder) moves every RRset and tombstone of a team in every zone,
  in the background; change the bindings in a policy revision too.

## Zone profiles

`/api/v1/providers/{provider}/zone-profiles` (`GET`, `POST`), `…/check` (`POST`,
validate without saving), `…/{id}` (`GET`, `PUT`, `DELETE`): the EuroDNS
`ZoneProfilePage`, hosts relative to the domain. See
[Zone profiles](features/zone-profiles.md).

- `dns.zone.profile` granted on `*`; the provider must set `eurodns.zone_profiles:
  true` (`403 zone_profiles_disabled`) and be a EuroDNS provider
  (`400 invalid_provider`).
- People need a recent login for writes; a protected record is refused (`403
  protected`, on check too); 60 operations per minute per subject (`429`).
- EuroDNS refusals are `400 rejected`, with the EuroDNS report in `details`.
- EuroDNS clients can use the EuroDNS routes (`/zone-profiles`…) on the gate, naming
  the provider in `X-DNS-Gate-Provider` when there are several.

## Errors

Errors are JSON, with a stable `reason` for programs:

```json
{"reason": "not_owner", "message": "www CNAME is owned by team api"}
```

| Status | Reasons |
|---|---|
| 400 | `invalid` (request or provider validation), `relative_target`, `bad_request`, `team_mismatch`, `rejected` (zone profile refused by EuroDNS), `invalid_provider` |
| 401 | `unauthenticated` (also an unknown, revoked, expired or rotated API key) |
| 403 | `forbidden` (RBAC, protected record, plan of another caller), `protected`, `zone_profiles_disabled`, `not_owner`, `too_many_changes`, `reauth_required`, `csrf`, `session_required`, `source_ip`, `role_widened`, `ephemeral_required` (ACME), `not_team_member`, `no_binding` |
| 404 | `not_found` (zone not managed, RRset unknown), `plan_not_found`, `zone_not_eurodns` |
| 409 | `foreign_rrset` (adopt it first), `tainted`, `adopt_conflict`, `https_unavailable`, `immutable`, `revoked`, `too_many_values`, `too_many_registrations`, `value_taken` (ACME) |
| 410 | `plan_expired`, `expired` (transfer request) |
| 412 | `precondition` (`If-Match`, `If-None-Match`, `expected_hash`, `must_not_exist`, zone changed since the plan, transfer already decided or RRsets changed, `expect` of a propagation check) |
| 423 | `zone_locked`, with `Retry-After` (`503` on the EuroDNS-compatible API) |
| 429 | `rate_limited` (MCP, zone profiles, propagation checks), with `Retry-After` |
| 501 | `not_implemented` (feature disabled in the configuration) |
| 502 | `upstream` (provider error) |
| 503 | `busy` (too many propagation checks running), with `Retry-After` |

The full list is in the `Error` schema of the OpenAPI document.

## Endpoints

| Path | Description |
|---|---|
| `GET /.well-known/dns-gate` | version and features, unauthenticated |
| `/api/v1/me`, `/api/v1/connect`, `/api/v1/zones`, `/api/v1/zones/{zone}/rrsets` | identity and effective permissions, Connect page data, zones (managed, then unmanaged with `"unmanaged": true`), inventory; `ui.read` (`dns.read` for unmanaged zones) |
| `/api/v1/zones/{zone}/rrsets/{host}/{type}`, `…/forwards[/{host}]` | single RRsets and URL forwards |
| `…/rrsets/{host}/{type}/propagation` | [propagation check](#dns-propagation) |
| `POST /api/v1/zones/{zone}/plan`, `/apply` | [plan and apply](#plan-and-apply) |
| `POST /api/v1/zones/{zone}/adopt/preview`, `/adopt` | [adoption](api/ownership.md#adopt-existing-records) |
| `GET /api/v1/zones/{zone}/terraform` | managed RRsets as `dnsgate_record_set` and forwards as `dnsgate_url_forward`, with `import` blocks (`provider=eurodns` for `eurodns_record_set`) |
| `/api/v1/teams[/{team}[/rename]]`, `/api/v1/zones/{zone}/transfers`, `/api/v1/transfers[/{id}[/approve\|reject]]` | [teams and transfers](#teams-and-transfers) |
| `GET /api/v1/audit` | the [audit journal](integrations/siem.md#pull-get-apiv1audit), newest first, filtered to readable zones; `source_ip` and `user_agent` for `policy.read` holders only |
| `/api/v1/api-keys[/{id}[/rotate]]` | [API keys](#api-keys) |
| `POST /api/v1/tokens` | gate token for the UI session (cookie and CSRF only), the Connect page |
| `POST /api/v1/token-exchange` | [token exchange](#token-exchange) |
| `/api/v1/providers/{provider}/zone-profiles[/check\|/{id}]` | [zone profiles](#zone-profiles) |
| `/api/v1/policy[/…]` | policy editor of the UI: revisions, approve, reject, activate, rollback, export, `explain`, `who-can`, virtual key generation |
| `/api/v1/policy/delegated[/roles\|bindings/{name}]` | [delegation API](config/managed-policy.md#delegation-api) |
| `GET /api/v1/connect/claude-desktop.mcpb` | the [Claude Desktop extension](config/ui-mcp.md#claude-desktop-extension) |
| `/mcp`, `/.well-known/oauth-protected-resource` | [MCP](config/ui-mcp.md#mcp) |
| `/auth/login`, `/auth/callback`, `/auth/logout`, `POST /auth/saml/acs`, `GET /auth/saml/metadata` | UI login, OIDC or SAML |
| `GET /.well-known/jwks.json`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke` | the gate issuer's keys and its authorization server for native clients and [declared OAuth clients](config/authentication.md#oauth-clients) |
| `GET`, `DELETE /api/v1/oauth/grants`, `DELETE /api/v1/oauth/grants/{id}` | connected applications of the caller; of a client or user with `gate.oauth.manage` |
| `POST /acme/httpreq/present`, `/cleanup`, `/acme/acme-dns/update`, `/register` | [ACME endpoints](ACME.md) |
| `POST /.well-known/dns-gate/zones/{zone}/adopt` | adoption for the `eurodns` Terraform provider on import (RRsets already owned by the caller's team: a no-op needing `dns.record.write`) |
| EuroDNS API paths | for zones of a `eurodns` provider only (`404 zone_not_eurodns` otherwise): `getDnsZone`, `saveDnsZone`, `checkDnsZone`, `addDnsRecords`, `deleteDnsRecord` through the zone engine; `listDnsZoneSnapshots`, `getSnapShot`, `getDnssecStatus`, `getDomain` proxied; the zone profile operations. Every other operation is `403 operation_denied`; query strings, encoded separators and dot segments are refused |
| `/healthz`, `/readyz` | probes |
