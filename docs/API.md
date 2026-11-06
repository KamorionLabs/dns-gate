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
curl -sS "${auth[@]}" "$GATE/api/v1/zones?folder=/ES/**"
curl -sS "${auth[@]}" "$GATE/api/v1/zones/example.com/rrsets"
curl -sS -i "${auth[@]}" "$GATE/api/v1/zones/example.com/rrsets/www/CNAME"
```

A zone summary carries the provider `folder` of the zone for EuroDNS accounts
(`"/ES/Madrid"`, `"/"` for a domain in no folder; absent for Route53), and
`?folder=` keeps the zones whose folder matches a folder glob (`/ES` the folder
ES only, `/ES/**` every folder below it, not ES itself; the Zones view filters
the same way), see
[EuroDNS folders](CONFIG.md#eurodns-folders).

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
to one team (the owner of the RRsets it creates; a declared team once a
[`teams`](CONFIG.md#teams) block exists, otherwise the key is refused at creation and
in use) and one role, with an optional
expiry and source CIDRs. Only its SHA-256 is stored; the key is shown once, at
creation and at each rotation. The same key works on this API, on the
[ACME endpoints](ACME.md) and on the EuroDNS-compatible API (`X-App-Id: <id>`,
`X-Api-Key: dgk_…`).

Managing keys needs the `gate.apikey.manage` action, from an OIDC identity (a key
never manages keys):

- the key's team must be one of the caller's teams, unless the caller holds
  `gate.apikey.manage` on `*` (gate-wide managers);
- the caller must hold `gate.apikey.manage` on every zone and folder pattern of
  the key's role, and every action of the role on the same zones, folders and
  records (a folder pattern is covered by a rule whose `folders` cover it, or by
  a rule on every zone, `*`; a managed or delegated rule of the caller covers it
  only when `policy.bounds.zones`, and the `allow.zones` of its delegation, cover
  every zone, since they narrow its folders): a key never has more rights than
  its issuer;
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

## Teams

Every RRset written or adopted through the gate is owned by a team, and only the
team's members may change or delete it. A caller bound to several teams writes
for its **default team** (the first one, `default_team` in `GET /api/v1/me`) and may
change the RRsets of all its teams. To act for one of them only, send the
`X-DNS-Gate-Team` header on any `/api/v1` write, or the `team` field of a plan:

```sh
curl -sS "${auth[@]}" -X PUT "$GATE/api/v1/zones/example.com/rrsets/app/CNAME" \
  -H "X-DNS-Gate-Team: corporate" -H "Content-Type: application/json" \
  -d '{"ttl": 3600, "values": ["site.example.net."]}'

curl -sS "${auth[@]}" -X POST "$GATE/api/v1/zones/example.com/plan" \
  -H "Content-Type: application/json" -d '{"team": "corporate", "changes": [...]}'
```

A team the caller is not a member of is `403 not_team_member`. A plan keeps its
team: the apply writes for it (`400 team_mismatch` if the apply names another one).
The EuroDNS-compatible API always writes for the default team.

`GET /api/v1/teams` lists the teams: declared in the `teams` block (with their
members for `policy.read` holders), referenced without being declared (migration),
derived from claims (`team_from` families, issuer `team_claim`), and the owners
found in the store that nothing declares, with the number of RRsets each owns in the
zones the caller can read; `require_second_approver` tells whether transfers and
renames need another person's approval. `GET /api/v1/teams/{team}` adds what the team owns per
zone, its pending transfers and, for `policy.read` holders and the team's members,
the rules of its roles (`permissions`).

A deleted RRset stays reserved for its team for `ownership.tombstone_ttl` (7 days):
another team creating or adopting it gets `403 not_owner` and must ask for a
transfer, whoever the caller is. The live tombstones of a managed zone are listed in
the `tombstones` of `GET /api/v1/zones/{zone}/rrsets`.

### Ownership transfers

```sh
# a member of either team allowed to write the RRsets through it (or a dns.ownership.approve holder) asks
curl -sS "${auth[@]}" -X POST "$GATE/api/v1/zones/example.com/transfers" \
  -H "Content-Type: application/json" -d '{
  "rrsets": [{"host": "www", "type": "CNAME"}, {"host": "@", "type": "TXT"}],
  "to_team": "corporate", "comment": "the corporate site moves to its own pipeline"}'

# someone allowed to write every RRset through the owner team, or holding dns.ownership.approve on it, approves it
curl -sS "${auth[@]}" -X POST "$GATE/api/v1/transfers/tr-1780000000000-0a1b2c3d4e/approve" \
  -H "Content-Type: application/json" -d '{"comment": "ok"}'
```

The RRsets of a request belong to one team. The approver is a human (unless
`ownership.machine_approvers`) with a recent login. With
`ownership.require_second_approver: true` it must be another person than the
requester, under any identity (`ownership.person_issuers`, `ownership.person_claims`);
with the default `false` the requester may approve its own request, or propose and
apply it at once with `"apply": true` (refused before anything is stored when the
requester could not approve it) (`self_approved` in the answer, `approval:
self` in the audit). The requester can always withdraw it (`/reject`).

Approval applies it at once, under the zone lock, if every RRset still belongs to the
team with the content hash it had when requested (store and provider); otherwise the
transfer is `failed` and the answer is `412 precondition` with the transfer. When the
zone is locked or the store or the provider is unavailable, the transfer stays
`applying` (`423` or `502` with the transfer) and the gate retries it in the
background for 24 hours, checking the rights of the approver again. A request not
decided within `ownership.transfer_ttl` (7 days) expires (`410 expired`).
`GET /api/v1/transfers?status=proposed` is the inbox: `can_decide` marks the requests
the caller may approve. Every step is audited (`gate.transfer.propose`, `.approve`,
`.reject`, `.apply`, with the requester, the approver and `approval`).

`POST /api/v1/teams/{team}/rename` (`policy.propose`; approved by a `policy.approve`
holder, another person with `require_second_approver`, or `"apply": true`) moves
every RRset and tombstone of a team, in every zone of the store, for migrations. The
approval answers `applying`: the gate applies the rename in the background within a
few minutes, the approver needing `dns.ownership.approve` on every RRset of the team.
The policy itself still names the old team: change the bindings in a policy revision
too.

The MCP server has the same operations: `list_teams`, `get_team` and
`transfer_list` always, `transfer_propose`, `transfer_approve` and
`transfer_reject` with `mcp.allow_writes`, and an optional `team` argument on
`plan_rrset_change`, `apply_rrset_change`, `adopt_preview` and `adopt_apply`.
`get_rrset` tells why the caller may or may not change an RRset ([CONFIG.md](CONFIG.md#mcp)).

## Zone profiles

A EuroDNS zone profile is an account-wide template (records, URL and mail
forwards) that EuroDNS applies to a domain when it arrives on its nameservers,
for example after a transfer: create and check it before the domain arrives.
Profiles name no domain, so every operation needs `dns.zone.profile` granted on
`*` ([CONFIG.md](CONFIG.md#zone-profiles)); each one is audited (`zone_profile.*`,
with the profile content for writes; a delete reads the profile first). The body
is the EuroDNS `ZoneProfilePage`, hosts relative to the domain.

```sh
P="$GATE/api/v1/providers/eurodns/zone-profiles"
# validate without saving: the answer carries the EuroDNS report
curl -sS "${auth[@]}" -H 'Content-Type: application/json' -X POST "$P/check" -d '{
  "name": "transfer-example.org",
  "records": [
    {"type": "A",  "host": "@",   "ttl": 3600, "rdata": "192.0.2.10"},
    {"type": "MX", "host": "@",   "ttl": 3600, "rdata": "10 mx.example.net."},
    {"type": "CNAME", "host": "www", "ttl": 3600, "rdata": "web.example.net."}
  ],
  "urlForwards": [], "mailForwards": []}'
# create (201, with its id), list, read, replace, delete
curl -sS "${auth[@]}" -H 'Content-Type: application/json' -X POST "$P" -d @profile.json
curl -sS "${auth[@]}" "$P"
curl -sS "${auth[@]}" "$P/42"
curl -sS "${auth[@]}" -H 'Content-Type: application/json' -X PUT "$P/42" -d @profile.json
curl -sS "${auth[@]}" -X DELETE "$P/42"
```

`{provider}` is a provider id of the configuration with
`eurodns.zone_profiles: true` (`403 zone_profiles_disabled` otherwise); a
provider of another kind answers `400 invalid_provider`. Writes need a recent
login from humans (`403 reauth_required`); a record of the protected list is
refused (`403 protected`), on check too; each subject may run 60 zone profile
operations per minute (`429 rate_limited`). An update is audited with the
previous content and the changed records (host, type and operation only in the
journal, which shows zone profile events to `dns.zone.profile` holders only). EuroDNS refusals are `400 rejected`, with the
EuroDNS report or errors in `details`. EuroDNS clients can also use the
EuroDNS routes (`/zone-profiles`, `/zone-profiles/check`, `/zone-profiles/{id}`,
pagination headers passed through) on the gate, with the same rule; when the gate
has several EuroDNS providers, they name one in `X-DNS-Gate-Provider`.

## Errors

Errors are JSON, with a stable `reason` for programs:

```json
{"reason": "not_owner", "message": "www CNAME is owned by team api"}
```

| Status | Reasons |
|---|---|
| 400 | `invalid` (request or provider validation), `relative_target` (single-label target), `bad_request`, `team_mismatch`, `rejected` (zone profile refused by EuroDNS), `invalid_provider` (zone profiles on a provider that is not EuroDNS) |
| 401 | `unauthenticated` (also an unknown, revoked, expired or rotated API key) |
| 403 | `forbidden` (RBAC, protected record, plan of another caller), `protected`, `zone_profiles_disabled` (zone profiles), `not_owner` (another team), `too_many_changes`, `reauth_required`, `csrf`, `session_required`, `source_ip` (key used outside its CIDRs), `role_widened` (API key whose role grew), `ephemeral_required` (ACME endpoints), `not_team_member` |
| 404 | `not_found` (zone not managed, RRset unknown), `plan_not_found`, `zone_not_eurodns` (EuroDNS-compatible API on a zone of another provider) |
| 409 | `foreign_rrset` (created outside the gate: adopt it first), `tainted` (changed outside the gate), `adopt_conflict`, `immutable`, `revoked` (API keys), `too_many_values`, `too_many_registrations`, `value_taken` (ACME endpoints) |
| 410 | `plan_expired`, `expired` (transfer request) |
| 412 | `precondition` (If-Match, If-None-Match, `expected_hash`, `must_not_exist`, zone changed since the plan, transfer already decided or RRsets changed since the request) |
| 423 | `zone_locked`, with `Retry-After` |
| 429 | `rate_limited` (zone profiles, with `Retry-After`) |
| 502 | `upstream` (provider error) |

The full list is in the `Error` schema of the OpenAPI document.

## Other endpoints

- `GET /api/v1/audit` — audit log, newest first, filtered to the zones the caller
  can read; `since`/`until` and `next_cursor` for pull-based collectors
  ([AUDIT.md](AUDIT.md#pull-get-apiv1audit)). `source_ip` and `user_agent` are
  shown to `policy.read` holders only.
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
- `/api/v1/policy/…` — the policy editor of the web UI. `explain` returns the
  `folder` of the zone when the matching rule applied through its `folders`;
  `who-can` returns the `folder` of the zone and flags `by_folder` the grants that
  come from a folder selector.
- `/acme/httpreq/present`, `/acme/httpreq/cleanup`, `/acme/acme-dns/update`,
  `/acme/acme-dns/register` — DNS-01 challenges for certbot, acme.sh, lego,
  win-acme, cert-manager and Caddy, with an OIDC token, a gate token or an API key
  ([ACME.md](ACME.md)).
