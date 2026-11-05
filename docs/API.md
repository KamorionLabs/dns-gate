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
plan/apply, `policy-delegation` the delegated policy API.

## Authentication

| Client | Credentials |
|---|---|
| Pipelines, CLIs, Terraform | `Authorization: Bearer <JWT>` from an issuer of the gate configuration (GitHub Actions, GitLab, Azure DevOps, Entra ID, any OIDC issuer), audience the gate |
| Tools without OIDC | virtual key: `X-App-Id` + `X-Api-Key` |
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
writes an RRset (`server_managed`, `routing_policy`…).

## ETags and preconditions

- `GET …/rrsets/{host}/{type}` returns `ETag: "<hash>"`, the content hash of the RRset
  (TTL and values, or alias). It is also the `hash` field of every RRset.
- `GET …/rrsets` returns `ETag: "v<n>"`, the gate version of the zone, bumped by every
  write through the gate.
- `PUT` with `If-None-Match: *` creates only: `412 precondition` if the RRset exists.
- `PUT` or `DELETE` with `If-Match: "<hash>"` acts only if the RRset still has that
  content: `412 precondition` otherwise. Only one hash, no `*`.

The engine checks the preconditions under the zone lock, against the zone read
from the provider, so two writers never overwrite each other silently.

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
`412 precondition` if the zone changed since the plan: plan again. The MCP tools
`plan_rrset_change` and `apply_rrset_change` use the same plans.

## Errors

Errors are JSON, with a stable `reason` for programs:

```json
{"reason": "not_owner", "message": "www CNAME is owned by team api"}
```

| Status | Reasons |
|---|---|
| 400 | `invalid` (request or provider validation), `bad_request` |
| 401 | `unauthenticated` |
| 403 | `forbidden` (RBAC, protected record), `not_owner` (another team), `too_many_changes`, `reauth_required`, `csrf` |
| 404 | `not_found` (zone not managed, RRset or plan unknown) |
| 409 | `foreign_rrset` (created outside the gate: adopt it first), `tainted` (changed outside the gate), `adopt_conflict` |
| 410 | `plan_expired` |
| 412 | `precondition` (If-Match, If-None-Match, `expected_hash`, `must_not_exist`, zone changed since the plan) |
| 423 | `zone_locked`, with `Retry-After` |
| 502 | `upstream` (provider error) |

The full list is in the `Error` schema of the OpenAPI document.

## Other endpoints

- `GET /api/v1/audit` — audit log, newest first, filtered to the zones the caller
  can read.
- `POST /api/v1/zones/{zone}/adopt/preview` and `/adopt` — take over RRsets created
  outside the gate ([ONBOARDING.md](ONBOARDING.md)).
- `GET /api/v1/zones/{zone}/terraform` — managed RRsets as `dnsgate_record_set`
  resources with `import` blocks (`provider=eurodns` for `eurodns_record_set`).
- `/api/v1/policy/delegated/…` — roles and bindings managed by pipelines within a
  delegation ([CONFIG.md](CONFIG.md)).
- `/api/v1/policy/…` — the policy editor of the web UI.
