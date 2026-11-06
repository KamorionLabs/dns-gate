# Audit events

Every request that reaches an authorization decision, every write and every
background change (drift, expiry, transfers) produces one audit event. Each
event goes to two places:

- **stdout**: one JSON line with `"type": "audit"`, next to the application logs
  (JSON lines without `type`). This is the stream to ship to a SIEM. On AWS Lambda
  it lands in the CloudWatch log group of the function.
- **the store** (memory, SQLite, PostgreSQL or DynamoDB), kept for
  `store.audit_retention`. The UI Journal, the MCP `search_audit` tool and
  `GET /api/v1/audit` read it.

Both copies carry the same `event_id`. The store always keeps the native event
described below. The stdout line can be rewritten in a standard schema
(`audit.format: ecs | ocsf`) and can carry a hash chain (`audit.hash_chain: true`).

```yaml
audit:
  format: native      # native (default) | ecs | ocsf
  hash_chain: false   # instance_id, seq, prev_hash, hash_alg and hash on every stdout line
```

`DNS_GATE_AUDIT_CHAIN_KEY` (or `DNS_GATE_AUDIT_CHAIN_KEY_FILE`, 32 bytes as hex or
base64, from the deployment secret) is `audit.hash_chain_key`: it makes the chain
an HMAC, see [Tamper evidence](#tamper-evidence).

Contents:

- [Schema](#schema): fields, authentication methods, actions, decisions and reasons, `extra`
- [Examples](#examples)
- [ECS and OCSF](#ecs-and-ocsf)
- [Tamper evidence](#tamper-evidence)
- [Export recipes](#export-recipes)
- [Not audited](#not-audited)

## Schema

The JSON Schema of a native stdout line is
[`api/audit-event.schema.json`](../api/audit-event.schema.json) (draft 2020-12).
The test suite validates real events against it.

`schema_version` is `"1"`. Adding an optional field or a new action or reason
keeps the version. Renaming or removing a field, or changing its meaning or type,
increments it. Consumers should ignore actions, reasons and `extra` keys they do
not know.

### Fields

| Field | Type | Presence | Description |
|---|---|---|---|
| `type` | `"audit"` | stdout only | Discriminator. It is present in every format, so `{ $.type = "audit" }` selects audit lines. |
| `schema_version` | string | always | `"1"`. |
| `event_id` | string | always | UUIDv7 (RFC 9562). It is unique per event, the same on stdout and in the store, and sorts by time to the millisecond. Use it to deduplicate. |
| `time` | string | always | RFC 3339, UTC, up to nanoseconds. |
| `request_id` | string | always | `X-Request-ID` of the HTTP request, which the client may supply (8 to 64 of `[A-Za-z0-9._-]`), otherwise random. Background work gets its own id. Several events can share one request id (see [Actions](#actions)). |
| `subject` | string | always | `<issuer>:<id>` of the caller (`api-key:<key id>`, `virtual-key:<id>`, `gate:reconciler` for background work). Empty when authentication failed. |
| `subject_name` | string | optional | Display name (`name_claim`, e-mail, key id). |
| `subject_category` | string | optional | `human`, `pipeline`, `key` or `system`. |
| `auth_method` | string | requests with a credential | How the request authenticated, or tried to. See [Authentication methods](#authentication-methods). |
| `source_ip` | string | requests | Client address. `X-Forwarded-For` is honoured only from `listen.trusted_proxies`: every `X-Forwarded-For` line of the request is read as one list, and the rightmost untrusted hop wins. On Lambda it is `requestContext.http.sourceIp`. |
| `user_agent` | string | requests | `User-Agent` without control characters, truncated to 256 bytes. |
| `teams` | string[] | optional | Teams the subject acts for. |
| `action` | string | always | See [Actions](#actions). |
| `zone` | string | optional | Zone concerned, lowercase, no trailing dot. |
| `provider` | string | optional | Provider id (`providers[].id`) of the zone, on engine events. |
| `decision` | string | always | `allow`, `deny` (refused by the gate) or `error` (accepted but failed: upstream, lock, validation). |
| `reason` | string | optional | Machine-readable reason. It is set on `deny` and `error`, and on two kinds of `allow` (see [Reasons](#reasons)). |
| `changes` | object[] | optional | RRset changes: `op` (`create`, `update`, `delete`, `adopt`, `taint`, `expire`, `transfer`), `host`, `type`, `old_ttl`, `old_values`, `old_alias`, `old_forward`, `new_ttl`, `new_values`, `new_alias`, `new_forward`. `host` is relative to the zone (`@` for the apex). URL forwards are changes of type `URLFWD` whose `old_forward`/`new_forward` hold `type` (`301`, `302`, `frame`), `url` and, for frames, `title`, `keywords`, `description`. |
| `snapshot_id` | string | optional | Provider snapshot taken before a write (EuroDNS). It is a rollback pointer. |
| `extra` | object | optional | Action-specific details, see [Extra](#extra). |
| `instance_id`, `seq`, `prev_hash`, `hash_alg`, `hash` | | stdout, `hash_chain` | See [Tamper evidence](#tamper-evidence). |
| `render_error` | string | rare | The event could not be rendered as configured (for example a value JSON cannot encode): the line keeps only `schema_version`, `event_id`, `time`, `request_id`, `subject`, `action`, `zone`, `decision`, `reason` and the error, still in the chain, and the gate logs an error. |

"Requests" means every event produced while serving an HTTP request (API,
EuroDNS-compatible API, UI, MCP, ACME, OAuth). Background events (reconciler,
expiry, transfer retries) have no `source_ip`, `user_agent` or `auth_method`,
nor do events of system actors (`gate:*`, category `system`) produced while a
request is served, such as a discovery refresh. Aggregated API key refusals
(`apikey.authenticate`) keep the client of the refused request, even when the
count is written later.

Secrets never appear in events. That covers tokens, API keys, virtual key
secrets, cookies, the `Authorization` header and request bodies. Token events
carry the token id (`jti`). Virtual key generation carries the SHA-256 of the
secret.

### Authentication methods

| `auth_method` | Credential |
|---|---|
| `oidc` | Bearer JWT of a configured issuer (CI, workload, Entra, ...). Also the value for a bearer JWT whose issuer is not trusted. |
| `oidc-session` | UI session cookie after an OIDC login. |
| `saml-session` | UI session cookie after a SAML login. |
| `gate-token` | Bearer JWT signed by the gate issuer (`self: true`), obtained from the UI or the OAuth authorization endpoint. |
| `token-exchange` | Requests to `/api/v1/token-exchange` (the presented subject token), and bearer gate tokens that the exchange issued (claim `gate_xchg`). |
| `api-key` | Gate API key (`dgk_...`) as bearer, basic password, `X-Api-Key` or acme-dns credentials. |
| `virtual-key` | `X-App-Id` / `X-Api-Key` virtual key from the configuration. |

The method is recorded when the credential is read, before it is verified, so a
refused attempt still says which kind of credential was presented. A request
without credentials has no `auth_method`, nor do the grants of the OAuth token
endpoint (`token.issue` with `via` `authorization_code` or `refresh_token`): the
code or refresh token is the credential, issued to a UI session.

### Actions

Actions are stable identifiers. One HTTP request can produce several events:
a front-door event plus the engine event, for example `api.apply` and
`applyRRsets`, or `mcp.adopt_apply` and `gate.adopt`. These events share the
`request_id`.

**EuroDNS-compatible API.** The action is the EuroDNS `operationId` of the
route (`internal/routes`, generated from the EuroDNS OpenAPI document).

| Action | Events |
|---|---|
| `saveDnsZone`, `addDnsRecords`, `deleteDnsRecord` | Writes, through the engine: allow (with `changes`, `snapshot_id`, `provider`), deny, error. |
| `getDnsZone`, `checkDnsZone` | Only refusals are audited; reads are not. |
| `listDnsZoneSnapshots`, `getSnapShot`, `getDnssecStatus`, `getDomain` | Passthrough reads: allow and deny. |
| any other operation id (`getPrepaidAccountBalance`, `deleteContactProfile`, ...) | deny `operation_denied`. |

Refused authentications on this API carry the operation id of the request.

**Gate actions.**

| Action | Meaning | Decisions | Zone |
|---|---|---|---|
| `applyRRsets` | Engine write of RRset changes (REST, MCP, UI). | allow, deny, error | yes |
| `api.plan` | REST dry run (`POST /api/v1/zones/{zone}/plan`). `extra.allowed` false with a `reason` when the plan would be refused. | allow | yes |
| `api.apply` | REST apply of a plan. | allow, deny, error | yes |
| `api.rrset.put`, `api.rrset.delete` | REST single-RRset write refused before the engine (step-up). | deny | yes |
| `api.forward.put`, `api.forward.delete` | REST URL forward write refused before the engine (step-up), with `extra.host` and `extra.type` (`URLFWD`). The write itself is `applyRRsets` with a `URLFWD` change. | deny | yes |
| `adopt` | Adoption entry point refused (authentication, RBAC). | deny | yes |
| `gate.adopt` | RRsets created outside the gate taken over. | allow, deny, error | yes |
| `gate.taint` | The reconciler found an owned RRset changed or deleted outside the gate. | allow (reason `tainted`) | yes |
| `gate.expire` | Ephemeral RRsets or ownerships removed at expiry. | allow, error | yes |
| `gate.transfer.propose`, `.approve`, `.reject`, `.apply`, `.expire` | Ownership transfers and team renames (renames have no zone). | allow, deny, error | yes |
| `acme.present`, `acme.cleanup` | lego httpreq challenge TXT value added or removed. | allow, deny, error | yes |
| `acme.register`, `acme.update` | acme-dns registration and TXT update. | allow, deny, error | yes |
| `apikey.authenticate` | Refused gate API key uses, aggregated per key or source per minute (`extra.count`). | deny | no |
| `apikey.manage` | Access to `/api/v1/api-keys` refused. | deny | no |
| `apikey.create`, `.update`, `.revoke`, `.rotate` | Gate API key lifecycle. | allow, deny | no |
| `token.issue` | Gate token issued (UI, OAuth code or refresh grant). | allow | no |
| `gate.token.exchange` | Token exchange (RFC 8693). | allow, deny | no |
| `policy.propose`, `.approve`, `.reject`, `.activate` | Managed policy revisions. | allow, deny | no |
| `policy.generate_key` | Virtual key generated from the UI. | allow | no |
| `policy.delegated.put_role`, `.put_binding`, `.delete_role`, `.delete_binding` | Delegated objects written by pipelines. Each write is followed by `policy.activate`. | allow, deny | no |
| `policy.delegated.take_over` | A proposal takes delegated objects back. | allow | no |
| `zone_profile.list`, `.get`, `.check`, `.create`, `.update`, `.delete` | EuroDNS zone profiles via the REST API. The EuroDNS-compatible API uses its operation ids (`listZoneProfiles`, `createZoneProfile`, ...), MCP uses `mcp.*_zone_profile(s)`. `provider` is the EuroDNS provider, `changes` lists host, type and op without values, and `extra` has `via`, `profile_id`, `profile` and `previous` (content), and `valid` (check). The journal shows them only to holders of `dns.zone.profile` on `*`. | allow, deny, error | no |
| `gate.zone.folders_listed` | Discovery: first listing of a EuroDNS provider by a process. Subject `gate:discovery`, category `system`; `extra.count` (zones) and `extra.digest` (SHA-256 of the sorted `zone<TAB>folder` lines). | allow | no |
| `gate.zone.folder_changed`, `gate.zone.folder_seen`, `gate.zone.folder_gone` | Discovery: a zone found in another folder, a new zone, a zone no longer listed (`extra.old`, `extra.new`). Same subject, one request id per listing. | allow | yes |
| `mcp` | MCP endpoint authentication refused. | deny | no |
| `mcp.<tool>` | MCP tool calls: `list_zones`, `list_rrsets`, `get_rrset`, `plan_rrset_change`, `apply_rrset_change`, `adopt_preview`, `adopt_apply`, `list_teams`, `get_team`, `transfer_list`, `transfer_propose`, `transfer_approve`, `transfer_reject`. `extra.via` is `mcp` and `extra.mcp_client` names the client. | allow, deny, error | per tool |

### Reasons

**Authentication**, with an empty `subject` (`apikey.authenticate` names the
key, `api-key:<id>`, when the id was readable):

| Reason | Meaning |
|---|---|
| `unauthenticated` | Missing, malformed, expired, revoked or unknown credential, untrusted issuer, bad signature. |
| `bound_claims` | Token claims do not match the `bound_claims` of the issuer. |
| `no_binding` | No role is bound to the identity (or to the API key's team and role). |
| `source_ip` | Key used from an address outside its CIDRs, or acme-dns `allowfrom`. |
| `role_widened` | The role of an API key now grants more than when it was issued. |
| `unavailable` | API key store lookup failed. |
| `not_exchangeable` | Token exchange refused: gate token, or exchange disabled for the issuer. |
| `registration_requires_api_key` | acme-dns `/register` without credentials. |
| `forbidden` | acme-dns credentials missing or not an API key. |

**Authorization, engine and workflow:**

| Reason | Decision | Meaning |
|---|---|---|
| `forbidden` | deny | RBAC refused the action (also protected and read-only records, ACME guard, approver rules, plan owned by another subject). |
| `operation_denied` | deny | EuroDNS operation not opened by the gate. |
| `zone_not_managed` | deny | Zone absent or not managed. |
| `zone_not_eurodns` | deny | EuroDNS-compatible API used for a zone of another provider. |
| `foreign_rrset` | deny | RRset exists and is not owned by the gate. |
| `not_owner` | deny | Owned by, or reserved for, another team; delegated object of another delegation. |
| `tainted` | deny, or allow on `gate.taint` | RRset changed outside the gate. |
| `precondition` | deny | `If-Match`, zone version, expected hash or upstream conflict. |
| `too_many_changes` | deny | Blast-radius limit. |
| `reauth_required` | deny | Step-up: a recent login (or the required AMR) is needed. |
| `plan_not_found`, `plan_expired`, `store_unavailable`, `team_mismatch` | deny | Plan apply refused. |
| `not_team_member` | deny | Requested team is not one of the subject's teams. |
| `invalid_zone` | error | Provider or validation refusal of the content. |
| `https_unavailable` | error | `require_https` on a URL forward of a zone whose forwards answer plain HTTP only. |
| `zone_locked` | error | Zone lock not acquired, or a previous write not settled. |
| `upstream` | error | Provider or store failure. |
| `not_found` | error | Zone, RRset or record absent. |
| `adopt_conflict` | error | Adoption preview no longer matches. |
| `expired` | error, deny | Transfer expired or not applied in time. |
| `error` | error | Any other failure, with the detail in `extra.message`. |
| `rate_limited`, `zone_profiles_disabled`, `protected`, `bad_request` | deny | Zone profiles: per-subject limit, profiles not enabled on the provider, protected record in the profile, invalid request. |
| `rejected`, `timeout`, `upstream_<status>` | error | Zone profile refused by EuroDNS, timed out, or another EuroDNS HTTP status. |
| `self_approval`, `conflict`, `invalid_policy`, `delegated_object`, `delegation_required`, `name_taken`, `policy_busy`, `bad_request` | deny | Policy workflow refusals (see [CONFIG.md](CONFIG.md#managed-policy-editing-from-the-ui)). |

`api.plan` and `mcp.plan_rrset_change` are `allow` events. When the plan would
be refused, they carry the engine reason with `extra.allowed: false`.

### Extra

| Key | Actions | Meaning |
|---|---|---|
| `remote_addr` | refused authentications, `apikey.authenticate` | Client address. It predates `source_ip` and is kept for compatibility. On `apikey.authenticate` it is the IPv4 address or the IPv6 /64 of the aggregated refusals. |
| `message` | deny, error, `gate.taint` | Human-readable detail. |
| `count` | `apikey.authenticate` | Refusals aggregated in the window. |
| `via` | REST, MCP, ACME, `token.issue` | Entry point: `api`, `mcp`; for `token.issue` the grant: `api`, `authorization_code`, `refresh_token`. |
| `mcp_client` | `mcp.*` | MCP client name, or User-Agent. |
| `plan_id`, `allowed` | plans and applies | Plan id; whether the dry run would apply. |
| `team`, `to_team`, `from_team` | MCP, API keys, transfers | Acting, target and source teams. |
| `host`, `type` | `api.rrset.*` | RRset of the request. |
| `domain`, `subdomain` | `acme.*` | ACME domain, acme-dns subdomain. |
| `key_id`, `role`, `acme_domains`, `overlap` | `apikey.*` | API key id, role, ACME domains, rotation overlap. |
| `jti`, `expires_at`, `subject_token_jti`, `client_id` | `token.issue`, `gate.token.exchange` | Issued token id and expiry, exchanged token id, OAuth client. |
| `revision_id`, `previous_revision_id`, `take_over`, `rollback_of` | `policy.*` | Revisions concerned. |
| `delegation`, `kind`, `name`, `impact`, `managed_by` | `policy.delegated.*` | Delegated object and the impact of the change. `kind` is `role` or `binding` here; on `gate.transfer.*` it is `rrsets` or `rename`. |
| `app_id`, `key_sha256` | `policy.generate_key` | Virtual key id and SHA-256 of its secret. |
| `transfer_id`, `requester`, `requester_name`, `decided_by`, `decided_by_name`, `approval`, `moved`, `comment`, `status`, `apply` | `gate.transfer.*`, `mcp.transfer_*` | Transfer request, who decided it, `approval` `self` or `second`, RRsets moved. |
| `comment`, `owner`, `adopted` | `gate.adopt`, `mcp.adopt_apply` | Adoption comment, owner team, count. |
| `ignored_out_of_scope` | writes | Out-of-scope differences skipped by a rebase, and changes of forward fields the gate does not write (`id`, `updated`, unknown fields) in a full-zone PUT. |
| `zone_admin_forwards` | writes (EuroDNS full-zone PUT) | Unowned URL forwards a `dns.zone.admin` holder changed or deleted (`<host> URLFWD`); they stay unowned. |
| `folder` | writes, adoptions, transfers | EuroDNS folder whose role rule granted the action. |
| `old`, `new`, `count`, `digest` | `gate.zone.folder_*` | Folder before and after; zone count and digest of a first listing. |

## Examples

A write, native format, with the hash chain (one line on stdout, wrapped here):

```json
{"type":"audit","schema_version":"1","event_id":"01a1b0d2-9a40-7d3e-8b1f-6c2a4e9d0f13",
 "time":"2026-11-06T09:14:03.512Z","request_id":"4f1c2a9be0d34c7a9d1e5b0c3a2f6e18",
 "subject":"github:repo:acme/infra:ref:refs/heads/main","subject_name":"acme/infra",
 "subject_category":"pipeline","auth_method":"oidc","source_ip":"203.0.113.7",
 "user_agent":"Terraform/1.9.8 terraform-provider-dnsgate/0.3.0","teams":["web"],
 "action":"applyRRsets","zone":"example.com","provider":"eurodns","decision":"allow",
 "changes":[{"op":"update","host":"www","type":"A","old_ttl":300,"old_values":["192.0.2.10"],
   "new_ttl":300,"new_values":["192.0.2.20"]}],"snapshot_id":"884301",
 "instance_id":"dns-gate-7c9f8-xk2lp/01a1b0d2-8f3e-7a51-9c2d-3e4f5a6b7c8d","seq":1,
 "prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash_alg":"sha256",
 "hash":"fdc289572ce0f6e2f313a1db1f023e312a97d8a4b99de2c93d1780df4d713dac"}
```

A refused authentication:

```json
{"type":"audit","schema_version":"1","event_id":"01a1b0d3-0c11-7f20-a4b5-9e8d7c6b5a41",
 "time":"2026-11-06T09:15:10.004Z","request_id":"9b0e1d2c3f4a5b6c7d8e9f0a1b2c3d4e","subject":"",
 "subject_category":"key","auth_method":"api-key","source_ip":"198.51.100.23","user_agent":"lego/4.19",
 "action":"apikey.authenticate","decision":"deny","reason":"unauthenticated",
 "extra":{"message":"unknown or malformed API keys","remote_addr":"198.51.100.23","count":1}}
```

The same write in the `ecs` format (abridged: `dns_gate` repeats `changes`,
`teams`, `provider`, `snapshot_id`, `subject_category`, `auth_method`):

```json
{"type":"audit","@timestamp":"2026-11-06T09:14:03.512Z","message":"allow applyRRsets on example.com by acme/infra",
 "ecs":{"version":"8.11.0"},
 "event":{"id":"01a1b0d2-9a40-7d3e-8b1f-6c2a4e9d0f13","kind":"event","action":"applyRRsets","outcome":"success",
   "category":["api","configuration"],"type":["change","allowed"],"dataset":"dns_gate.audit","provider":"dns-gate","module":"dns_gate"},
 "user":{"id":"github:repo:acme/infra:ref:refs/heads/main","name":"acme/infra","group":{"name":"web"}},
 "source":{"ip":"203.0.113.7"},"user_agent":{"original":"Terraform/1.9.8 terraform-provider-dnsgate/0.3.0"},
 "http":{"request":{"id":"4f1c2a9be0d34c7a9d1e5b0c3a2f6e18"}},"dns":{"question":{"name":"example.com"}},
 "related":{"user":["github:repo:acme/infra:ref:refs/heads/main","acme/infra"],"ip":["203.0.113.7"],"hosts":["example.com","www.example.com"]},
 "service":{"name":"dns-gate","type":"dns-gate","version":"0.9.0"},
 "dns_gate":{"schema_version":"1","decision":"allow","request_id":"4f1c2a9be0d34c7a9d1e5b0c3a2f6e18","...":"..."}}
```

And in the `ocsf` format (abridged the same way under `unmapped.dns_gate`):

```json
{"type":"audit","class_uid":6003,"class_name":"API Activity","category_uid":6,"category_name":"Application Activity",
 "activity_id":3,"activity_name":"Update","type_uid":600303,"type_name":"API Activity: Update",
 "time":1793956443512,"severity_id":1,"severity":"Informational","status_id":1,"status":"Success",
 "message":"allow applyRRsets on example.com by acme/infra",
 "metadata":{"version":"1.3.0","uid":"01a1b0d2-9a40-7d3e-8b1f-6c2a4e9d0f13","correlation_uid":"4f1c2a9be0d34c7a9d1e5b0c3a2f6e18",
   "log_name":"audit","product":{"name":"dns-gate","vendor_name":"KamorionLabs","version":"0.9.0"}},
 "actor":{"user":{"uid":"github:repo:acme/infra:ref:refs/heads/main","name":"acme/infra","type_id":99,"type":"pipeline",
   "groups":[{"name":"web"}]},"authorizations":[{"decision":"allow"}]},
 "api":{"operation":"applyRRsets","service":{"name":"dns-gate"},"request":{"uid":"4f1c2a9be0d34c7a9d1e5b0c3a2f6e18"}},
 "src_endpoint":{"ip":"203.0.113.7"},"http_request":{"user_agent":"Terraform/1.9.8 terraform-provider-dnsgate/0.3.0","uid":"4f1c2a9be0d34c7a9d1e5b0c3a2f6e18"},
 "cloud":{"provider":"eurodns"},
 "resources":[{"type":"dns_zone","name":"example.com"},{"type":"dns_record","name":"www.example.com"}],
 "unmapped":{"dns_gate":{"schema_version":"1","decision":"allow","auth_method":"oidc","...":"..."}}}
```

## ECS and OCSF

`audit.format` changes only the stdout lines. The store, the UI and
`GET /api/v1/audit` keep the native event. Both formats keep `type: "audit"`. The
fields they cannot map are kept whole under a product namespace (`dns_gate` in
ECS, `unmapped.dns_gate` in OCSF), so no information is lost.

### ECS (`ecs`, ECS 8.11)

| ECS field | Source |
|---|---|
| `@timestamp` | `time` |
| `event.id` | `event_id` |
| `event.action` | `action` |
| `event.outcome` | `success` for `allow`; `failure` for `deny` and `error` |
| `event.reason` | `reason` |
| `event.kind`, `event.dataset`, `event.provider`, `event.module` | `event`, `dns_gate.audit`, `dns-gate`, `dns_gate` |
| `event.category`, `event.type` | Per class, see below. |
| `user.id`, `user.name`, `user.group.name` | `subject`, `subject_name`, the team when there is exactly one |
| `source.ip` | `source_ip` |
| `user_agent.original` | `user_agent` |
| `http.request.id` | `request_id` |
| `dns.question.name` | `zone` |
| `related.user`, `related.ip`, `related.hosts` | Subject and name; source address; zone and the FQDNs of `changes` |
| `service.name`, `service.version` | `dns-gate` and the gate version |
| `message` | `<decision> <action> on <zone> by <name>: <reason>` |
| `dns_gate.*` | `schema_version`, `decision`, `request_id`, `subject_category`, `auth_method`, `teams`, `provider`, `changes`, `snapshot_id`, `extra` |

Categorization:

| Events | `event.category` | `event.type` |
|---|---|---|
| Authentications: `apikey.authenticate`, `token.issue`, `gate.token.exchange`, any `deny` without a subject | `authentication` | `start` |
| API key lifecycle `apikey.*` (and `apikey.manage`, the refused access to the key list) | `iam` | `user` and `creation`, `deletion`, `change` or `info` |
| Policy `policy.*` | `iam`, `configuration` | `creation`, `deletion`, `change` or `info` |
| Discovery `gate.zone.folder_*` | `configuration` | `creation` (seen), `deletion` (gone), `change` (moved), `info` (first listing) |
| Reads (`get*`, `list*`, plans, previews, ...) | `api` | `access`, plus `allowed` or `denied` |
| Every other action | `api`, `configuration` | `creation`, `deletion` or `change`, plus `allowed` or `denied` |

Every `event.type` is one ECS expects for one of the categories of the event.
`error` events are `event.outcome: failure` with the reason in `event.reason`.
Whether an action creates, changes or deletes is taken from the `op` of its
`changes` when present (all `create`: creation; all `delete` or `expire`:
deletion; otherwise change), else from the words of the action name.

### OCSF (`ocsf`, OCSF 1.3)

Three classes are used, chosen by what the event is about:

| Class | `class_uid` | Events | Activities |
|---|---|---|---|
| Authentication | 3002 | `apikey.authenticate`, any `deny` without a subject (refused credentials), `token.issue`, `gate.token.exchange` | `1` Logon (credential checks), `3` Authentication Ticket (token issuance and exchange). `user` is the subject, or `{"name": "unknown"}`. `auth_protocol_id` is `99` (Other), with `auth_protocol` set to the `auth_method`. |
| Account Change | 3001 | `apikey.*` (gate API key lifecycle: an API key is a credential account) | `1` Create, `6` Delete (revoke), `99` Other (update, rotate). `user` is the key (`uid` = `extra.key_id`). |
| API Activity | 6003 | Every other action: DNS operations, adoption, ownership, ACME, policy, MCP, discovery | `1` Create, `2` Read, `3` Update, `4` Delete, as for ECS. `api.operation` is the action. `cloud.provider` is the provider id of the zone (`dns-gate` when none). `resources` lists the zone (`dns_zone`) and the changed names (`dns_record`). |

Policy changes are API Activity rather than Account Change, because they change
the gate's own authorization model, not an account.

Common members: `time` (epoch milliseconds), `metadata.uid` = `event_id`,
`metadata.correlation_uid` = `request_id`, `metadata.product`, `actor.user`
(`uid` = subject, `type_id` 1 for humans, 3 for system actors, 99 otherwise, and
`groups` = teams), `actor.authorizations[].decision` = decision, `src_endpoint.ip`,
`http_request.user_agent`, `status_id`/`status` (1 Success for `allow`,
2 Failure otherwise), `status_detail` = reason, `severity_id` (1 for `allow`,
2 for `deny`, 3 for `error`). `type_uid` is `class_uid × 100 + activity_id`.

## Tamper evidence

With `audit.hash_chain: true`, every stdout line also carries:

| Field | Description |
|---|---|
| `instance_id` | Id of the chain: one per process. It is `<pod name or Lambda log stream>/<UUIDv7>`, or the UUIDv7 alone. It is logged at startup (`audit hash chain started`). |
| `seq` | Position in the chain, from 1, with no hole. |
| `prev_hash` | `hash` of the previous line of the chain. The first line uses 64 zeros. |
| `hash_alg` | `sha256`, or `hmac-sha256` with a chain key. |
| `hash` | SHA-256, or HMAC-SHA256 with the chain key, (hex) of the canonical form of the line without `hash`. |

The canonical form is the line re-encoded with object keys sorted, no
whitespace, no HTML escaping, and numbers normalized (integers without a
fraction, other numbers in shortest form). A pipeline that re-orders keys,
re-indents or re-escapes the JSON does not break the chain. A pipeline that
drops, adds or renames fields does break it, so keep the line intact. The hash
covers the formatted line, so ECS and OCSF lines are chained as well. An object
with the same member twice, at any depth, never verifies: JSON decoders disagree
on which value counts.

**Keyed chain.** Without a key, anyone who can rewrite the stream can recompute
the chain. With `DNS_GATE_AUDIT_CHAIN_KEY` set (`audit.hash_chain_key`, 32
random bytes, `openssl rand -hex 32`, kept in the deployment secret and not
readable by the operators of the sink), `hash` is an HMAC-SHA256 and
`hash_alg` is `hmac-sha256`: forged or recomputed lines fail without the key.
Verification needs the key (`-key-file`, or the same variables). With a key,
plain `sha256` lines are refused (`unkeyed`), so a chain cannot be downgraded.

Check an export with `dns-gate audit verify`:

```sh
dns-gate audit verify export.jsonl            # or: ... | dns-gate audit verify
dns-gate audit verify -json a.jsonl b.jsonl   # machine-readable report
dns-gate audit verify -key-file chain.key -require-genesis export.jsonl
```

| Flag | Effect |
|---|---|
| `-json` | Machine-readable report. |
| `-key-file` | Chain key of keyed chains (else `DNS_GATE_AUDIT_CHAIN_KEY` or `DNS_GATE_AUDIT_CHAIN_KEY_FILE`). |
| `-allow-unchained` | Accept audit lines without chain members next to chained ones. By default they fail: with `hash_chain` on, an unchained audit line is an injected line. |
| `-require-genesis` | Fail a chain whose first event in the input is not `seq` 1, for exports that must hold whole chains. |

It accepts the gate's JSON lines mixed with application logs, lines wrapped by
container log collectors (`{"log": "<line>"}` or `{"message": "<line>"}`), and
CloudWatch Logs documents (subscription payloads with `logEvents`, decompressed,
and `aws logs filter-log-events` output with `events`). Lines may come in any
order and from any number of instances. For each chain it reports:

- **gaps**: missing `seq` ranges (events deleted, or not exported);
- **altered**: an event whose content does not match its `hash`;
- **broken_link**: an event whose `prev_hash` is not the `hash` of the previous
  one, which is what a forged event with a recomputed hash produces;
- **seq_conflict**: two different events with the same `seq`;
- **bad_genesis**: a chain whose first event does not start from zeros;
- **key_required**, **unkeyed**: a keyed chain checked without the key, or a
  plain line checked with one;
- **no_genesis**: with `-require-genesis`, a chain that starts after `seq` 1.

Without `-require-genesis`, a chain whose first event in the export is not
`seq` 1 is reported as starting mid-chain. That is expected for an export
limited to a time window, and is not a failure. The command exits 1 when a
chain has a gap or a problem, when unchained audit lines are mixed with chained
ones (unless `-allow-unchained`), or when the input has no chained event.

Limits:

- **Per process.** Each replica, and each Lambda execution environment, writes
  its own chain. A restart, a scale-out or a new Lambda environment starts a new
  chain at `seq` 1. Nothing links consecutive chains, so a whole chain that
  disappears (all the events of one instance) is not detected. Compare the
  `instance_id` values with the `audit hash chain started` log lines, which are
  part of the same stream.
- **Truncation at the end** of a chain is not detectable from the chain itself.
  Ship the logs continuously, and alert on gaps in delivery.
- **Not a signature without a key.** Anyone who can rewrite the whole stream
  from a given point can recompute every plain hash after it; a chain key
  limits that to holders of the key, which the gate itself holds. The chain proves the integrity of
  what reached the sink, so make the sink append-only: S3 Object Lock,
  CloudWatch Logs with no `DeleteLogStream`/`PutRetentionPolicy` rights for
  operators, or a SIEM with immutable storage. The gate itself cannot protect
  events it never wrote (gate compromise, [THREAT-MODEL.md](THREAT-MODEL.md) T14).
- The store copy has no chain. It is the operational copy for the UI; the stdout
  stream is the evidence.

## Export recipes

### AWS Lambda / CloudWatch Logs

The function writes audit lines to its log group. Platform lines (`START`,
`END`, `REPORT`) and application logs share the group. A subscription filter
keeps only the audit lines:

```
{ $.type = "audit" }
```

With the Terraform module
([terraform-aws-dns-gate](https://github.com/KamorionLabs/terraform-aws-dns-gate)),
set `audit_export` to create the subscription filter towards a Kinesis Data
Firehose stream, a Kinesis data stream or a Lambda function:

```hcl
module "dns_gate" {
  source = "github.com/KamorionLabs/terraform-aws-dns-gate"
  # ...
  audit_export = {
    destination_arn = aws_kinesis_firehose_delivery_stream.audit.arn
  }
}
```

The module creates the IAM role CloudWatch Logs needs for Firehose and Kinesis,
or the invoke permission for a Lambda destination. By hand:

```sh
aws logs put-subscription-filter \
  --log-group-name /aws/lambda/dns-gate \
  --filter-name dns-gate-audit \
  --filter-pattern '{ $.type = "audit" }' \
  --destination-arn arn:aws:firehose:eu-west-3:111122223333:deliverystream/dns-gate-audit \
  --role-arn arn:aws:iam::111122223333:role/dns-gate-audit-subscription
```

Typical destinations:

- **Firehose to S3** for retention: enable the Firehose decompression and
  "message extraction" processors so that objects contain the original JSON
  lines. Then `dns-gate audit verify` and Athena read them directly. Put Object
  Lock (compliance mode) on the bucket.
- **Firehose to a SIEM** (Splunk HEC, Datadog, Elastic, Sumo Logic, or an HTTP
  endpoint): use `audit.format: ecs` for Elastic, or `ocsf` for Amazon Security
  Lake and OCSF-native tools.
- **Kinesis data stream** for your own consumers, or a cross-account
  CloudWatch Logs destination (`aws_cloudwatch_log_destination`) of a central
  logging account.

Without a subscription, `aws logs filter-log-events --log-group-name ...
--filter-pattern '{ $.type = "audit" }' > export.json` gives a document that
`dns-gate audit verify` reads as-is.

### Kubernetes

The gate writes to stdout, and the node's log agent collects it. Route the audit
lines on `type`. With Fluent Bit (Helm chart `fluent/fluent-bit`):

```ini
[INPUT]
    Name              tail
    Path              /var/log/containers/dns-gate-*_dns-gate_*.log
    multiline.parser  cri
    Tag               dnsgate.*

[FILTER]
    Name          parser
    Match         dnsgate.*
    Key_Name      log
    Parser        json
    Reserve_Data  On

[FILTER]
    Name    rewrite_tag
    Match   dnsgate.*
    Rule    $type ^audit$ audit.dnsgate false

[OUTPUT]
    Name   s3
    Match  audit.dnsgate
    bucket dns-gate-audit
    region eu-west-3
    total_file_size 50M
    upload_timeout  5m
    s3_key_format   /audit/%Y/%m/%d/$UUID.jsonl
```

The `parser` filter lifts the gate's JSON to the record root. `rewrite_tag`
moves audit lines to their own tag, which is shipped separately from
application logs: S3, `es`/`opensearch` (with `audit.format: ecs`), `splunk`,
`http`, or `forward` to a central aggregator. Keep the record intact (no
`modify` or `nest` on audit records) if you use the hash chain. To verify
records Fluent Bit stored with its own metadata, pass them as `{"log": ...}`
objects, or extract the original lines first. Vector, Promtail/Alloy and the
OpenTelemetry Collector `filelog` receiver work the same way: parse the JSON,
then route on `type == "audit"`.

### Pull: `GET /api/v1/audit`

For collectors that poll an API. Authenticate as a pipeline or an API key with
`ui.read` on every managed zone. Without it, events of unreadable zones and
events without a zone (authentication failures) are filtered out.

- Results are newest first. `limit` is 1 to 500 (default 50), and `next_cursor`
  continues to older events until it is absent.
- `since` and `until` (RFC 3339, fractional seconds accepted) bound the window.
  Also available: `zone`, `decision`, `category`, `subject`, `host`, `type`.
- Entries carry `event_id` and `auth_method` besides the UI fields (actor,
  teams, action, zone, decision, reason, changes, provider, snapshot).
  `source_ip` and `user_agent` are served only to holders of `policy.read`
  (also in the MCP `search_audit` and `get_rrset` history): other journal
  readers do not see the addresses of other users. `extra` is not served: it
  can hold content, such as zone profile records, that only the audit sink
  keeps. The stdout stream always has every field.

A polling loop: keep a high-water mark `T` (the newest `time` seen). On each
poll, request `since=T - 5m` and follow `next_cursor` until it is absent.
Deduplicate on `event_id`, then move `T` forward. The overlap absorbs clock skew
between replicas and events written while you page. The store keeps events for
`store.audit_retention`.

```sh
since=$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ)
url="https://dns-gate.example.com/api/v1/audit?limit=500&since=$since"
while [ -n "$url" ]; do
  page=$(curl -fsS -H "Authorization: Bearer $TOKEN" "$url")
  echo "$page" | jq -c '.entries[]'
  next=$(echo "$page" | jq -r '.next_cursor // empty')
  url=${next:+"https://dns-gate.example.com/api/v1/audit?limit=500&since=$since&cursor=$next"}
done
```

Pulled entries have no hash chain. Use the stdout stream for tamper evidence.

## Not audited

These requests produce no event:

- Successful reads of the EuroDNS-compatible API (`getDnsZone`, `checkDnsZone`),
  REST inventory reads, adoption previews and the Terraform export.
- Requests refused before routing: unknown path, wrong method, malformed
  parameters.
- The MCP endpoint rate limit (`429`); the zone profile limit is audited.
- DNS propagation checks (`GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation`
  and the MCP tool `check_propagation`), allowed or refused, including their
  rate limit (`429`) and in-flight cap (`503`): they only read the inventory and
  ask DNS servers. The provider re-read an `expect` may trigger runs only for
  callers holding `dns.read` on the zone, so it never produces a refusal event;
  `extra` and `changes` of audited applies never carry the `new_hash` of the
  apply result.
- Some workflow refusals answered before the decision point, such as
  `policy_not_editable`, `stale_revision`, `approval_required`, ACME request
  validation errors, and step-up refusals outside DNS writes.

Application logs (`slog` JSON lines without `type`) describe these requests
for troubleshooting. They are not part of the audit schema.
