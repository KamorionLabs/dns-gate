# dns-gate — Design

Status: beta. The design below has run in production against the live EuroDNS API
since November 2026; the roadmap and the points of the provider APIs still worth an
explicit test are tracked in [GitHub issues](https://github.com/KamorionLabs/dns-gate/issues).

## 1. Problem

DNS provider APIs hand automation coarse credentials: they are scoped to an account
or a hosted zone at best, know nothing of teams or of who created a record, and leave
concurrency and rate limits to each client. EuroDNS, the first provider behind the
gate, is the extreme case; Route 53 IAM policies can restrict record names and types,
but not ownership, and only for AWS identities.

EuroDNS exposes a REST API (`https://rest-api.eurodns.com`, spec published at
`https://docapi.eurodns.com/openapi.json`, OpenAPI 3.0.1, 92 operations). Using it
from automation (Terraform, CI pipelines, ACME clients) raises several problems:

| Fact (from the spec) | Consequence |
|---|---|
| Authentication is two headers, `X-APP-ID` and `X-API-KEY`. Keys carry no scope at the API level. | A key reaches everything the user can reach: DNS zones, but also registrant contact profiles, nameserver profiles, subscription auto-renew, SSL revocation, DNSSEC. A leaked key is a domain hijack, not just a DNS change. |
| Rate limit: 10 requests per 10 seconds **per source IP**, progressive ban (each violation during a ban extends it). No `429`/`Retry-After` documented. | A naive Terraform run (one read per record, parallelism 10) gets banned. Since the ban is per IP, one misbehaving client blocks every other client sharing that egress IP. |
| No record update endpoint: `POST /dns-zones/{d}/dns-records` adds, `DELETE /dns-zones/{d}/dns-records/{id}` deletes, otherwise `PUT /dns-zones/{d}` saves the **whole zone**. | Every modification is a full-zone write. Being allowed to `PUT /dns-zones/example.com` means being allowed to wipe `example.com`. |
| No `ETag`, no `If-Match`. | Two concurrent read-modify-write cycles silently overwrite each other (lost update). |
| `POST /dns-zones/{d}/check` validates a zone without saving it; `GET /dns-zones/{d}/snapshots` lists zone snapshots. | Usable as a mandatory dry run and as a rollback pointer. |
| TTLs restricted to a fixed list; records can be `locked`. | Must be validated client-side to fail early. |
| No sandbox environment. | Tests run against a fake (`eurodnstest`) plus one real test domain. |

The ecosystem has no Terraform provider and no external-dns webhook for EuroDNS.
Existing clients (lego, `EuroDNS/libdns-eurodns`) do GET → modify → PUT of the
whole zone, with no concurrency control.

## 2. Goals and non-goals

Goals:

- One **provider-neutral API** (`/api/v1`, used by the UI, MCP and the `dnsgate`
  Terraform provider) whatever the provider of a zone.
- For EuroDNS zones, keep the **EuroDNS API contract**: an existing EuroDNS client
  works against the gate by changing only its base URL (and credentials).
- The gate is the **only holder** of the provider credentials.
- Clients authenticate with **short-lived OIDC tokens**; gate-issued API keys only
  for third parties that have no OIDC identity.
- Fine-grained authorization: zone, host pattern, record type.
- **Ownership**: the gate only modifies or deletes RRsets it created (or that an
  admin explicitly adopted), and only for the owning team.
- Respect the upstream rate limit for all clients combined; serialize writes per zone.
- Full audit trail.
- Generic: nothing specific to one organization or provider; each provider is an
  adapter behind the neutral model (section 4.1).

Non-goals (v0.x):

- Re-implementing or extending the EuroDNS API beyond a few headers and a
  reserved `/.well-known/dns-gate` prefix.
- Domain lifecycle (registration, transfers, contacts, billing): denied by default.
- Providers other than EuroDNS and Route53 (the provider contract of section 4.1
  leaves room for them; requests are tracked in [GitHub issues](https://github.com/KamorionLabs/dns-gate/issues)).

## 3. Three layers of protection

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Layer 1 — Provider credential scope (upstream)                       │
 │   The gate's provider credentials are restricted to DNS management   │
 │   of the zones it serves. Protects against a compromised gate.       │
 │ ┌──────────────────────────────────────────────────────────────────┐ │
 │ │ Layer 2 — RBAC (gate)                                            │ │
 │ │   Who may read/write which zone, host pattern, record type.      │ │
 │ │   Protected records (apex NS/MX/SOA/CAA...) win over any role.   │ │
 │ │ ┌──────────────────────────────────────────────────────────────┐ │ │
 │ │ │ Layer 3 — Ownership (gate)                                   │ │ │
 │ │ │   Only RRsets created/adopted by the gate, owned by one of   │ │ │
 │ │ │   the caller's teams, unchanged since the last gate write.   │ │ │
 │ │ └──────────────────────────────────────────────────────────────┘ │ │
 │ └──────────────────────────────────────────────────────────────────┘ │
 └──────────────────────────────────────────────────────────────────────┘
```

Layer 1 is configured at the provider: the permissions of the gate's EuroDNS user
(granularity to be confirmed), an IAM policy for Route 53
([providers/route53.md](providers/route53.md#iam)). Layers 2 and 3 are enforced by
the gate on every request.

## 4. Architecture

```
  Terraform, CI, MCP     ACME clients, appliances       humans
  Bearer JWT (OIDC)      gate API key (dgk_…)           UI session (OIDC, SAML)
          │                      │                        │
          └──────────────────────┼────────────────────────┘
                                 ▼
   ┌──────────────────────────────────────────────────────────┐
   │ dns-gate                                                 │
   │                                                          │
   │ 1. authn     multi-issuer JWT (JWKS), audience; API keys │
   │ 2. routing   operationId → action, deny by default       │
   │ 3. authz     RBAC zone / host / type                     │
   │ 4. engine    ownership, delta, protected, blast radius   │
   │ 5. writes    per-zone lock, If-Match, check before save  │
   │ 6. upstream  shared transport, ~1 req/s, retries         │
   │ 7. audit     JSON: subject, delta, snapshot before write │
   └─────────────────────────────┬────────────────────────────┘
                                 │ provider credentials (sole holder)
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       EuroDNS (X-APP-ID / X-API-KEY,     Route53 (AWS credentials,
       allowlisted IP)                    optional assumed role)

   store (memory | sqlite | postgres | DynamoDB): ownership, zone versions, zone locks,
   audit, policy revisions, plans, API keys
```

Repositories:

| Repository | Content |
|---|---|
| `KamorionLabs/eurodns-go` | Go client (`eurodns`), RRset helpers (`rrset`), zone delta (`zonediff`), fake server (`eurodnstest`). Shared by the gate and the provider. |
| `KamorionLabs/dns-gate` | The gate (this repository), Helm chart, container image. |
| `KamorionLabs/terraform-provider-dnsgate` | Terraform/OpenTofu provider of the gate API (`dnsgate_record_set`, delegated roles and bindings), for every provider behind the gate. |
| `KamorionLabs/terraform-provider-eurodns` | Terraform/OpenTofu provider of the EuroDNS API: direct to EuroDNS, or through the gate's EuroDNS-compatible API. |

Main packages of the gate:

| Package | Role |
|---|---|
| `internal/identity` | `Subject` (issuer, id, claims, roles, teams). |
| `internal/authn` | Authentication: OIDC issuers (JWKS), gate-issued tokens and the token exchange, API keys (format in `internal/apikey`), virtual keys. |
| `internal/dns` | Provider-neutral model: `Zone`, `RRset` (values or alias, read-only reason), `Change`, `ContentHash`. |
| `internal/provider` | Provider contract (`Provider`, `Checker`, `Snapshotter`, `Resolver`, capabilities, errors); `provider/eurodns` and `provider/route53` adapters. |
| `internal/eurodnsapi` | EuroDNS-compatible API facade (full-zone PUT, record ids, forwards, passthrough) over the neutral engine, for EuroDNS zones only. |
| `internal/policy` | RBAC engine implementing `Authorizer`. |
| `internal/routes` | Route table generated from `api/eurodns.openapi.json`, plus the hand-written operation → action mapping. |
| `internal/zonewrite` | `Engine`: every DNS zone read/write on behalf of a subject on the neutral model, provider resolved per zone, ownership enforcement, reconcile. |
| `internal/store` | `Store`: ownership entries, zone versions, zone locks, persisted RRset plans, API keys and their acme-dns registrations (memory, SQLite, Postgres, DynamoDB). |
| `internal/audit` | Structured audit events (stdout and store). |
| `internal/discovery` | Listing of the zones of every provider account, filtered and cached in memory; resolves the provider of a zone. |
| `internal/uiapi` | JSON types of the `/api/v1` API (inventory, RRsets, plans, audit, policy revisions, adoption, Terraform export). |
| MCP server | `/mcp` endpoint for LLM agents (section 17). |

### 4.1 Providers

A provider is one upstream account (`providers[]` in the configuration). The core
(RBAC, ownership, audit, UI, MCP, REST API) only sees the neutral model; each adapter
converts its records to RRsets and back:

| Method | Contract |
|---|---|
| `ReadZone` | Current RRsets sorted by key; `ReadOnly` set on RRsets the gate never writes; `Native` keeps the provider payload (the EuroDNS zone with its forwards). |
| `Normalize` | Validates a desired RRset and returns it in the canonical form of `ReadZone`, so that the hash stored at write time is the hash read back. |
| `Apply` | Writes RRset changes computed against the zone read under the lock. |
| `Check` (optional) | Server-side dry run (EuroDNS `check`), blocking problems refuse the write. |
| `LatestSnapshot` (optional) | Snapshot id recorded in the audit (EuroDNS). |

`Capabilities` tell the engine how to write: `FullZoneWrite` (EuroDNS rewrites the
whole zone), `AtomicBatch` (a failed write known not applied rolls the claims back;
otherwise the claims are settled against a fresh read at once), `ConditionalWrite`
(the provider fails with `ErrConflict` when an RRset changed since the read, mapped to
`412 precondition`), `Alias` (alias RRsets are refused elsewhere), types and TTLs.

A zone is served by exactly one provider: the only one whose `zones` include/exclude
globs select it, or, when several do, the only one of them whose account lists it
(`internal/discovery`). Ownership, locks and the audit stay keyed by zone name.

**EuroDNS adapter.** One rate-limited transport per account carries every call
(reads, writes, checks, snapshots, listing, passthrough). RRsets are grouped with
`eurodns-go/rrset`; `dns.ContentHash` equals `rrset.ContentHash` byte for byte, so the
ownership entries written before the neutral model stay valid. SOA and locked records
make their RRset read-only (`server_managed`), and so does a target stored relative to
the zone (`relative_target`): the gate cannot write it back without changing its
meaning. Writes are a full-zone save of the current zone with the changes applied
(`zonediff.Apply`), forwards and unknown fields kept byte for byte. Desired targets of
several labels without an ending dot are written absolute, like Route53 and the
dnsgate Terraform provider read them; a single label is refused as ambiguous.

**Route53 adapter.** One AWS client per account (default credential chain,
optionally an assumed role); see [providers/route53.md](providers/route53.md).

**Not planned.** Two families of existing provider code were considered as
backends and are not used:

- lego DNS providers only implement the ACME TXT `Present`/`CleanUp` pair, in
  internal packages: no reads, no other record types. lego stays a client of the
  gate, through its `httpreq` provider ([ACME.md](ACME.md)).
- DNSControl providers are not a supported library: they pull heavy dependencies,
  and they compute their own opaque corrections for a whole zone, which cannot be
  checked change by change against ownership before they run.

## 5. Request pipeline

```
request
  │
  ├─ normalize path (reject encoded slashes, dot segments, unknown query params)
  ├─ authenticate ── Bearer JWT ─────► issuer match, signature (JWKS), exp/nbf, aud,
  │                                    bound claims → Subject{roles, teams}
  │                └─ API key dgk_… ─► key lookup (hashed), expiry, CIDRs → Subject (9.5)
  │                └─ X-APP-ID/X-API-KEY ─► virtual key lookup (hashed) → Subject
  │                └─ none ──────────► 401
  ├─ route lookup (method + path template → operationId)
  │       unknown operation ─────────► 403 (deny by default)
  ├─ action = mapping[operationId]  (e.g. getDnsZone → dns.read)
  ├─ zone check: {domain-name} must be a managed zone (base or managed layer) ──► else 403
  ├─ Authorizer.Allow(subject, action, zone) ──► else 403
  ├─ dispatch (EuroDNS API paths: only for zones of a eurodns provider, else 404)
  │     passthrough-read  → reverse proxy with the credentials of the zone's account
  │     engine            → eurodnsapi facade → zonewrite.Engine
  │     gate extension    → /.well-known/dns-gate[...]
  └─ audit event (allow | deny | error)
```

Client credential headers (`Authorization`, `X-APP-ID`, `X-API-KEY`) are never
forwarded upstream; the upstream credentials are injected by the shared transport.

The tree above is the EuroDNS-compatible API. The neutral API under `/api/v1` and the
ACME endpoints (`/acme/...`) authenticate the same way, check the action of their
route on the zone, host and type, and write through the same `zonewrite.Engine`:
ownership, zone locks and the audit do not depend on the entry point.

### 5.1 Route table

`api/eurodns.openapi.json` is the EuroDNS document, fetched by `make spec` (it is not
redistributed). A `go generate` step produces the list of
`(method, path template, operationId)`. A hand-written table maps each
operationId to an action and a handler kind. Any operation absent from the mapping
is denied, so a new EuroDNS endpoint is never exposed by accident.

The gate's own API (`/.well-known/dns-gate`, `/api/v1`) is described by
`api/dns-gate.openapi.yaml` (OpenAPI 3.1, rendered on the project site); a test
fails when a route served under `/api/v1` is missing from it or the other way round.
Guide: [API.md](API.md).

| operationId | Action | Handler |
|---|---|---|
| `getDnsZone` | `dns.read` | engine (adds ETag) |
| `checkDnsZone` | `dns.read` | engine |
| `saveDnsZone` | `dns.record.write` | engine (delta) |
| `addDnsRecords` | `dns.record.write` | engine |
| `deleteDnsRecord` | `dns.record.write` | engine |
| `listDnsZoneSnapshots`, `getSnapShot`, `getDnssecStatus` | `dns.read` | passthrough |
| `signZone`, `unsignZone`, zone profiles | `dns.zone.admin` | passthrough |
| `getDomain`, `searchDomains` | `domain.read` | passthrough |
| everything else (contacts, nameserver profiles, subscriptions, SSL, invoices, orders…) | — | denied |

## 6. Ownership model

### 6.1 Unit of ownership: the RRset

Providers offer no free-form field on records (a EuroDNS record only has `id`,
`type`, `host`, `ttl`, `rdata`, `updated`, `locked`, `isDynDns`, `proxy`), so
ownership cannot be stored on the record. It lives in the gate's store, keyed by
**RRset** = `(zone, host, type)`, with `host` normalized (`dns.NormalizeHost`:
lowercase, no trailing dot, zone suffix stripped, apex = `@`).

An ownership entry (`store.Ownership`):

| Field | Meaning |
|---|---|
| `Zone`, `Host`, `Type` | RRset key |
| `Owner` | team (not the individual identity, which may rotate) |
| `CreatedBy`, `CreatedAt`, `RequestID` | provenance |
| `ContentHash` | `dns.ContentHash` (TTL + sorted values, or the alias target) after the last gate write |
| `PendingHash` | expected hash while a write is in flight |
| `State` | `pending`, `active`, `tainted` |
| `Adopted` | true when the RRset pre-existed and was adopted |
| `ExpiresAt` | ephemeral RRsets (ACME challenges), garbage-collected after this time |
| `Version` | optimistic concurrency on the entry |

### 6.2 Rules

| Situation | Result | Reason code / HTTP |
|---|---|---|
| Create an RRset that does not exist upstream | allowed if RBAC allows; claim written for the caller's team (`Authorizer.OwnerTeam`, the default team or the one selected with `X-DNS-Gate-Team`) | — |
| Create an RRset deleted less than `ownership.tombstone_ttl` ago by a team the caller is not a member of | refused, the RRset is reserved for that team (tombstone); a transfer moves it | `not_owner` / 403 |
| Create/modify an RRset that exists upstream but has no ownership entry | refused, never mixed with foreign records | `foreign_rrset` / 409 |
| Modify/delete an RRset owned by another team | refused | `not_owner` / 403 |
| Modify/delete an owned RRset whose upstream content no longer matches `ContentHash` | refused, entry marked `tainted` | `tainted` / 409 |
| Any change on a protected RRset | refused, even for admins | `forbidden` / 403 |
| Any change or adoption of a read-only RRset (SOA, EuroDNS locked or relative target, Route53 routing policy) | refused | `forbidden` / 403 |
| `MustNotExist` on an existing RRset (RRset API) | refused | `foreign_rrset` / 409 if not owned, `precondition` / 412 if owned |
| `ExpectedHash` differs from the upstream content (RRset API) | refused | `precondition` / 412 |
| Alias RRset on a provider without alias support, value or TTL refused by `Normalize` | refused | `invalid_zone` / 400 |
| More changes than `Authorizer.MaxChangesPerRequest` | refused | `too_many_changes` / 403 |
| `If-Match` does not match the zone version | refused | `precondition` / 412 |
| The provider check (EuroDNS `check`) reports a blocking problem | refused | `invalid_zone` / 400 |
| Zone lock not acquired within `LockWait` | refused, client retries | `zone_locked` / 423 |

The CNAME exclusivity rule falls out naturally: creating a CNAME where foreign
records exist at the same host is a foreign collision.

### 6.3 Adoption

Records that existed before the gate are foreign and read-only through the gate.
`POST /.well-known/dns-gate/zones/{domain}/adopt` (action `dns.record.adopt`,
admin role) creates ownership entries for listed RRsets, with their current content
hash and `Adopted = true`. Adopting an RRset already owned by the caller's team is
a no-op. The owner is one of the caller's teams; another team requires
`dns.ownership.approve` on the zone, as does adopting an RRset reserved for another
team by a tombstone. In gate mode, `terraform import` of an `eurodns_record_set` calls adopt.
Bulk adoption with preview, Terraform export and onboarding of whole zones are
described in section 16.

### 6.3.1 Teams, tombstones and transfers

Teams are declared in the `teams` block (base file or managed layer) with their
members; a binding naming a team without groups or subjects grants its role to the
members. Once the block exists, references to undeclared teams are refused; before,
they are declared automatically with a warning (migration).

Deleting an owned RRset (gate write, or a pending delete settled by the reconciler)
writes a tombstone (`ZONE#<zone>`/`TOMB#<host>#<type>` in DynamoDB, table
`ownership_tombstone` in SQL) with the team, the deleter and an expiry. Until it
expires, only that team may create or adopt the RRset again; ephemeral RRsets leave
no tombstone.

A transfer request lists RRsets of one team (owned or tombstoned) and a target team,
with their content hash. The approval, by a member of the owner team allowed to
write in the zone or a holder of `dns.ownership.approve` on it, and never by the
requester, takes the zone lock, reads the zone, checks that every entry still has
the team, the state and the content hash of the request (store and upstream), then
changes them all in one store transaction (`Store.Reassign`: SQL transaction,
DynamoDB `TransactWriteItems` with a version or team condition per item, at most 100
items). A team rename does the same for every RRset and tombstone of a team, zone by
zone, approved by a second policy approver.

### 6.4 Rebase on full-zone PUT

`PUT /dns-zones/{d}` carries a whole zone, often stale (the client read it earlier).
The EuroDNS facade computes `zonediff.Diff(current, desired)` against the **current**
zone, read under the zone lock by the engine.

- Default: any difference outside the caller's scope (RBAC or ownership) is refused.
- Roles with `rebase_on_save` (ACME clients such as lego): out-of-scope differences are
  ignored and logged; only in-scope changes are applied on top of the current zone
  (`zonediff.Apply`). This avoids both silent overwrites and spurious failures when
  another writer changed the zone after the client's read.

Residual race: two rebasing clients changing the **same** in-scope RRset
concurrently without `If-Match`. Acceptable for ACME (distinct challenge values,
a failed challenge is retried).

### 6.5 Ephemeral RRsets

Roles may set an ephemeral TTL (`Authorizer.EphemeralTTL`). RRsets they create get
`ExpiresAt`; the reconciler deletes expired ones. This cleans up ACME challenge
records left behind by clients that do not clean up; the ACME endpoints refuse
callers whose role has no ephemeral TTL ([ACME.md](ACME.md)).

### 6.6 Reconcile

`zonewrite.RunReconciler` calls `Engine.Reconcile(zone)` for every managed zone at a
configurable interval (one GET per zone, within the rate budget):

- owned RRset whose upstream content differs from `ContentHash` → `tainted`, alert;
- owned RRset missing upstream → `tainted` (deleted outside the gate);
- `pending` entry → resolved: `active` if upstream matches `PendingHash`, otherwise
  rolled back to the previous state (the write did not happen);
- expired ephemeral RRset → deleted upstream and from the store;
- side product: inventory of foreign RRsets per zone.

A tainted RRset stays blocked until an admin re-adopts it.

## 7. Write flow

```
client            gate (engine)                         store            EuroDNS
  │ write          │                                       │                 │
  │──────────────► │ authn + RBAC (zone)                   │                 │
  │                │ Lock(zone, holder, ttl) ────────────► │                 │
  │                │ ZoneVersion == If-Match ? ──────────► │ (else 412)      │
  │                │ GET zone ────────────────────────────────────────────► │
  │                │ desired = request applied to current                    │
  │                │ delta = zonediff.Diff(current, desired)                 │
  │                │ per change: RBAC RRset, protected, ownership,           │
  │                │             content hash, blast radius                  │
  │                │ GET snapshots (latest id, for audit) ─────────────────► │
  │                │ Put(ownership: pending, PendingHash) ► │                 │
  │                │ POST check (optional) ────────────────────────────────► │
  │                │ PUT zone (current + allowed changes) ─────────────────► │
  │                │ GET zone (confirm, ids, hashes) ──────────────────────► │
  │                │ Put(ownership: active, ContentHash) ► │                 │
  │                │ BumpZoneVersion ────────────────────► │                 │
  │                │ Unlock ─────────────────────────────► │                 │
  │                │ audit(delta, snapshot id)             │                 │
  │ ◄──────────────│ response (EuroDNS shape, ETag)        │                 │
```

Notes:

- All writes (`POST dns-records`, `DELETE dns-records/{id}`, `PUT dns-zones`) are
  turned into one atomic upstream `PUT` of `current + allowed changes`. A `DELETE`
  by id is resolved against the current zone to find the RRset it belongs to.
- Cost at EuroDNS: 4 to 5 upstream requests per write (about 5 seconds at 1 request per
  second). DNS writes are low volume; this is the price of atomicity and ownership
  checks.
- The flow is the same for every provider, through `Provider.ReadZone`, `Check`,
  `Apply`. A provider without atomic batches may apply part of a write: its claims are
  settled at once against a fresh read, and reconcile settles any left.
- A crash between the pending claim and the confirmation is resolved by reconcile.

## 8. Store

`store.Store` holds ownership entries, a monotonic zone version (used as ETag) and a
per-zone lease lock. It also holds the inventory cache, the audit events used by the UI, and
the managed policy revisions with the pointer to the active one (section 15).

It also persists the RRset plans of MCP and of the REST API (section 17.3), taken
once, and the gate-issued API keys with their acme-dns registrations (9.5).

- **Memory**: single replica and tests.
- **SQLite**: single replica with a persistent volume.
- **Postgres**: several replicas.
- **DynamoDB**: single-table design, conditional writes for entry versions, zone
  version counter and lock lease (holder + expiry). Credentials from the default AWS
  chain (EKS Pod Identity, IRSA, Lambda role, environment). Point-in-time recovery
  recommended. Expired plans are deleted by the table TTL (attribute `ttl`), the SQL
  stores purge them every 15 minutes (or in each Lambda maintenance pass): no Scan.

The ETag returned on `GET /dns-zones/{d}` is `"v<zone version>"`. Every gate write
bumps it. Writes made outside the gate (console) do not bump it, but are detected
by the ownership content hash.

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

### 9.5 API keys

For third parties with no OIDC identity (a hosting provider renewing certificates,
an appliance), the gate issues API keys at runtime (`/api/v1/api-keys`, guide in
[API.md](API.md)). OIDC stays the first choice; a key is a long-lived secret held
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
  ([ACME.md](ACME.md)).

### 9.6 Token exchange

Some clients keep a credential for minutes or hours (certbot and acme.sh hooks,
long scripts), longer than the CI or workload token they start with. Instead of an
API key, they exchange that token for a gate token (OAuth 2.0 token exchange,
RFC 8693, `POST /api/v1/token-exchange`, configuration in
[CONFIG.md](CONFIG.md#token-exchange)):

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

## 10. Extensions to the EuroDNS contract

Kept minimal and invisible to plain EuroDNS clients:

| Extension | Behaviour |
|---|---|
| `ETag` on `GET /dns-zones/{d}` | zone version |
| `If-Match` on writes | `412` if the zone version changed. EuroDNS ignores the header, so clients can always send it. |
| `GET /.well-known/dns-gate` | `{"version": "...", "features": [...]}`: `if-match`, `ownership`, `adopt`, `policy-delegation`, `plans`, `rrset-api`, `acme-httpreq`, plus `api-keys`, `acme-dns` and `token-exchange` when served ([API.md](API.md)). Plain EuroDNS returns 404: this is how clients detect a gate. |
| `POST /.well-known/dns-gate/zones/{d}/adopt` | adoption (see 6.3) |
| Error body | `{"reason": "<code>", "message": "..."}` with the reason codes of 6.2 |

## 11. Rate limit and high availability

- The EuroDNS budget (10 requests per 10 seconds per IP) is global. The shared
  transport of each EuroDNS account (`eurodns.Transport`) waits rather than drops (default one request per
  1.1 s, small burst), and retries on 429/5xx with backoff.
- The gate must be the only caller from its egress IP.
- Zone GETs are coalesced (singleflight) and cached briefly; the cache is
  invalidated on every write.
- Zone discovery costs one EuroDNS request per 100 domains per
  `providers[].zones.refresh` and per replica.
- v0.1 runs a single replica: an IaC call tolerates a short unavailability, and the
  EuroDNS console remains the break-glass path. With the DynamoDB store, locks and
  zone versions already work across replicas; a shared rate limiter is the remaining
  piece for multi-replica ([GitHub issues](https://github.com/KamorionLabs/dns-gate/issues)).

## 12. Policy (overview)

Roles, bindings, protected records and limits are declared in YAML, versioned in git
(a permission change is a pull request). A second, managed layer can be edited from
the UI within bounds set in the file (section 15). The full reference is in
[CONFIG.md](CONFIG.md).

```yaml
roles:
  app-cname-writer:
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["*.staging", "_*.staging"], types: [CNAME, TXT] }
  acme-solver:
    rebase_on_save: true
    ephemeral_ttl: 24h
    rules:
      - zones: ["*"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT] }
protected:
  - { zones: ["*"], hosts: ["@"], types: [NS, MX, SOA, CAA] }
bindings:
  - role: app-cname-writer
    team: app-team
    subjects:
      - issuer: aws
        claims: { sub: ["arn:aws:iam::111111111111:role/ci-app"] }
```

Host patterns are relative to the zone: `*` matches exactly one label, `**` one or
more labels (`glob.MatchHost`).

## 13. Audit

One event per request (`audit.Event`): time, request id, subject (`issuer:id`),
teams, action, zone, provider id, decision (`allow`/`deny`/`error`), reason, RRset
changes (old and new TTL, values or alias), id (a string) of the latest provider
snapshot taken before the write (EuroDNS; events recorded with a numeric id still
decode).

Events go to two places:

- stdout as JSON lines, for collection in an external, append-only sink;
- the store (DynamoDB with a TTL attribute for retention), so the web UI can query
  them by zone, RRset, subject and time. Reconcile also records events
  (`taint`, `expire`, pending resolution), so drift shows up in the same history.

## 14. Web UI

A web interface for operators and teams. It answers "what is in this zone, who owns
it, who changed it and when", lets people with write rights stage RRset changes and
apply them through a reviewed plan, and lets designated people edit the managed
policy layer (section 15).

### 14.1 Views

- **Zones**: managed zones with counters (RRsets, managed, tainted, pending,
  foreign), last upstream sync, last gate write (latest successful write found
  in the journal, so it survives restarts and is the same on every replica); with zone discovery (15.7), the
  zones of the provider accounts that are not managed, flagged unmanaged, with a
  "Manage this zone" action for policy proposers.
- **Inventory of a zone**: every RRset with its status, owner team, protected flag,
  created by / updated by (actor and category: `human`, `pipeline` or `key`),
  timestamps, adoption flag, expiry for ephemeral RRsets, last request id.

  | Status | UI label | Meaning |
  |---|---|---|
  | `managed` | Managed | owned by the gate, upstream content matches |
  | `pending` | Pending | write in flight or interrupted, resolved by reconcile |
  | `tainted` | Drifted | owned, changed outside the gate; writes blocked |
  | `missing` | Missing | owned, deleted outside the gate |
  | `foreign` | Not managed | exists upstream, not owned; read-only for the gate |

  The UI groups `tainted`, `missing` and `pending` as *Needs attention*, and calls
  zones found by discovery but not managed *Not managed (read-only)*.

- **Audit log**: filterable by zone, host, type, subject, actor category, decision,
  time range; each entry shows the RRset diff (old → new TTL and values), the
  reason of a denial and the snapshot id taken before the write.
- **DNS writes**: in a zone, the record sets the user may change (computed from
  `/api/v1/me`) offer edit and delete, and a form adds new ones. Changes are staged
  in the browser, then sent as one `POST /api/v1/zones/{zone}/plan` whose result
  (diff, refusal reasons) is shown for review; *Apply* sends `POST
  /api/v1/zones/{zone}/apply` with the `plan_id`. Each staged change carries the
  hash of the RRset as displayed (`expected_hash`, or `must_not_exist` for a new
  one), so a record changed since is refused instead of overwritten.
- **Connect**: ready-to-paste setups for Claude Code, Claude Desktop, Terraform
  (`dnsgate` provider) and the API, and *Get an API token* (section 9.4).

### 14.2 API

The UI is a static single-page application served by the gate, backed by the JSON
API under `/api/v1` (contract in `internal/uiapi`, reference in
[`api/dns-gate.openapi.yaml`](../api/dns-gate.openapi.yaml), guide in
[API.md](API.md)):

| Route | Returns |
|---|---|
| `GET /api/v1/me` | logged-in subject, category, roles, teams, permissions |
| `GET /api/v1/zones` | zone summaries |
| `GET /api/v1/zones/{zone}/rrsets` | zone inventory |
| `GET /api/v1/audit?zone=&host=&type=&subject=&category=&decision=&since=&until=&limit=&cursor=` | audit page, newest first, cursor pagination |
| `POST /api/v1/zones/{zone}/plan`, `/apply` | RRset plan, then its application |
| `POST /api/v1/tokens` | gate-issued token of the session (9.4) |
| `/api/v1/api-keys` | API key management (9.5) |
| `POST /api/v1/token-exchange` | gate token for an OIDC token (9.6) |

The same API accepts bearer tokens, for scripts and the Terraform provider, with
`GET`/`PUT`/`DELETE /api/v1/zones/{zone}/rrsets/{host}/{type}` for single RRsets.
Read routes require `ui.read` (or `dns.read`) on the zone; writes go through the
engine like any other write (RBAC, ownership, lock, audit).

### 14.3 Data path

The inventory is a cache in the store, filled by reconcile (one GET per zone per
interval) and refreshed by every gate write. When a zone's cache is empty (first
start), the inventory performs **one** provider read for that zone to fill it; after
that, UI requests never call the provider. Single-RRset reads (`Engine.RRset`, the
RRset API read by a Terraform plan) use the same cache and one ownership lookup:
writes do not rely on it, they check `ExpectedHash` under the lock against a fresh
read. This keeps the UI out of the upstream rate
budget: browsing cannot get the gate banned. `last_synced_at` tells how fresh the
view is.

### 14.4 Login and session

- OIDC authorization code flow with PKCE against a configured issuer (e.g. Entra ID,
  any OIDC provider), or SAML 2.0 (9.4); the same bindings map the user to roles and
  teams.
- Session in an encrypted, `HttpOnly`, `Secure`, `SameSite=Strict` cookie, short
  lifetime, no token stored in the browser's JavaScript-accessible storage.
- Strict Content Security Policy (no inline script, `default-src 'self'`,
  `frame-ancestors 'none'`).
- The mutations reachable from the browser are DNS writes through plan/apply, gate
  tokens, API keys and policy revisions (section 15). Every one requires the CSRF
  token and a same-origin `Origin`; DNS applies, single-RRset writes, API key
  creations, changes and rotations, and policy changes also require step-up
  authentication (a login more recent than `policy.edit_max_age`, and the
  `policy.require_amr` methods), otherwise `403 reauth_required` and the UI sends
  the user through `/auth/login?reauth=1`. The plan itself is a dry run and
  needs no step-up.

## 15. Editable policy

The policy can be edited from the UI by designated people, without giving up GitOps
for what matters most.

### 15.1 Two layers

| Layer | Where | Content | Who changes it |
|---|---|---|---|
| **base** | YAML config file (git, deployed by CD) | issuers, UI and store settings, managed zones, protected records, **bounds**, every `policy.*` grant, plus base groups, roles, bindings and keys | pull request on the config repository |
| **managed** | store, as immutable **revisions** | zones, groups, roles, bindings, virtual keys (`PolicyDocument`) | proposed and approved in the UI |

At evaluation the active managed revision is merged with base. Constraints on the
managed layer, checked at proposal and again at activation:

- it cannot reuse a base group or role name;
- it cannot grant any `policy.*` action: `policy.read`, `policy.propose` and
  `policy.approve` are granted **only by base bindings**, so the editor can never
  extend who controls the editor;
- every managed rule must stay within the **bounds** declared in base
  (`bounds.zones` globs, `bounds.actions` list);
- protected records (base) win over any managed grant;
- zones it brings under management must match `bounds.zones` and exist in a
  provider account (15.7).

Validation errors come back as `400 {"reason":"invalid_policy","errors":[{"path","message"}]}`.

### 15.2 Lifecycle of a revision

```
            propose (policy.propose)
  (none) ───────────────────────────► proposed ──reject──► rejected
                                         │
                       approve (another policy.approve holder)
                                         ▼
                                      approved
                                         │ activate
                                         ▼
           previous active ◄─superseded─ active
```

- **Approval by someone else**: with `policy.require_approval: true` (default), a
  revision must be approved by a `policy.approve` holder **other than its author**.
  Without required approval, the proposer may activate directly.
- **Stale revisions**: each proposal records its `parent_id` (the active revision it
  was based on). If another revision was activated since, the proposal is marked
  `stale` and cannot be activated; it must be re-proposed on the current active one.
- **Atomic activation**: activation is one conditional write in the store (expected
  active revision → new revision). All replicas pick up the new revision; a
  request is evaluated against exactly one revision.
- **Rollback**: `rollback` on an old revision creates a **new proposal** copying it,
  which goes through the same approval. History is never rewritten.
- **Export**: any revision's managed document can be exported as YAML, to keep a
  copy in git or to move it into the base layer.
- Every proposal, decision, activation and rollback is an audit event.

### 15.3 Review aids

- **Diff**: unified YAML diff of the proposed document against its parent.
- **Impact analysis**: permissions gained or lost per group, team, matcher or
  virtual key (e.g. "team web loses write on owned RRsets (12)"), with warnings
  (empty groups, rules shadowed by protected records, keys without expiry).
- **Explain**: simulate a decision for a concrete subject (issuer + claim values),
  action, zone, host and type, against the active policy or a proposed revision;
  returns the groups, bindings, matching rule, denying rule and layer.
- **Who can**: list the roles, teams, groups, subjects and virtual keys allowed to
  perform an action on an RRset.

### 15.4 Groups and matchers

A **group** is a named set of subject matchers. A matcher is an issuer plus claims
that must all match (glob; an array claim matches when one element matches). Groups
make bindings readable: an Entra app role, a GitHub repository, a list of users.
Bindings grant a role, acting for a team, to groups and/or individual matchers.

```yaml
groups:
  dns-operators:
    members:
      - issuer: entra
        claims: { roles: ["Gate.Operator"] }
  web-ci:
    members:
      - issuer: aws
        claims: { sub: ["arn:aws:iam::111111111111:role/ci-web-*"] }
bindings:
  - role: web-writer
    team: web
    groups: [web-ci]
```

### 15.5 Humans with Entra ID SSO

For the UI, define **app roles** on the gate's app registration and assign them to
Entra **groups** (assignment to groups needs Entra ID P1 or higher), then match them
in base groups through the `roles` claim:

| App role | Typical base grant |
|---|---|
| `Gate.Reader` | `ui.read`, `policy.read` |
| `Gate.Operator` | `ui.read`, `policy.read`, `policy.propose` |
| `Gate.PolicyAdmin` | `ui.read`, `policy.read`, `policy.propose`, `policy.approve` |

Alternative: `groupMembershipClaims: ApplicationGroup` in the app manifest, which
emits in `groups` only the groups assigned to the application (avoids overage), and
match on group object ids. App roles are preferred: names are readable and stable
across tenants.

### 15.6 Protection of policy mutations

- Session login with OIDC code + PKCE (14.4).
- **Step-up**: mutations by humans require a recent authentication
  (`policy.edit_max_age`, checked on `auth_time`) and, if configured, an MFA method
  in `amr` (`policy.require_amr`). Otherwise `403 {"reason":"reauth_required"}` and
  the UI sends the user through `/auth/login?reauth=1`.
- **CSRF**: every POST requires the `X-Gate-CSRF` header equal to the `gate_csrf`
  cookie and a same-origin `Origin` header.
- **Virtual keys** are generated server-side and shown once; only their hash goes
  into a proposal.

### 15.7 Managed zones and zone discovery

The managed zones are the union of the base `zones` and the `zones` of the active
managed revision. Every component reads them from the current policy snapshot: the
route table of the EuroDNS-compatible API, the write engine, reconcile (at each
round), the UI and MCP. Activating a revision that adds a zone is therefore enough
to manage it, on every replica within the reload interval.

`internal/discovery` lists the zones of every provider account (`ListZones`: EuroDNS
`searchDomains` through the shared rate-limited transport, Route 53
`ListHostedZones`, both paginated) at start and
every `providers[].zones.refresh`, filtered by the `include`/`exclude` globs of the
provider, and keeps the lists in memory. Discovered zones that are not managed are **unmanaged**:

| | Managed | Unmanaged |
|---|---|---|
| RBAC actions that can match | all | `dns.read`, `ui.read` only |
| EuroDNS-compatible API, plans, writes, adoption, Terraform export | yes | refused |
| Reconcile | every `reconcile_interval` | never |
| Inventory | cache filled by reconcile and writes | read on demand, reused for `reconcile_interval`; never read by the zone list |

A revision may add a zone only if it is discovered (one extra listing, at most once
a minute, when a proposal names a zone not seen yet). Removing a zone from the
managed layer is allowed; the impact analysis warns when the gate owns RRsets
there. Their ownership entries stay in the store, so managing the zone again
restores them.

### 15.8 Policy delegations

Some policy changes are mechanical: the Terraform stack that creates CI pipelines
creates, for each one, a cloud role scoped to that pipeline, and should create in the
same apply the gate role and binding that let the pipeline's identity write only its
own DNS names. Routing each of them through a human approval defeats the automation,
and granting the stack `policy.propose` with `require_approval: false` would let it
change anything within the bounds.

A **delegation** (`policy.delegations`, base file) is a narrower grant: its subjects
may create, change and delete roles and bindings they own, within `allow` limits
(zones, actions, record scope, the subjects a binding may target, the teams it may
use, a maximum number of objects), through a dedicated API
(`/api/v1/policy/delegated`, CRUD by stable name, ETag preconditions). The review
happens once, when the delegation is merged in the configuration; each delegated
change is then activated without approval.

- **Storage**: delegated objects live in the `delegated` section of the managed
  document, each with its owner (delegation, `managed_by`, created/updated by and
  at). A delegated change is an ordinary revision (author = the pipeline), created on
  the active one and activated at once, so history, diff, export, rollback, explain
  and who-can see it like any other.
- **Validation**: the managed-layer rules (15.1) plus the owner delegation's limits,
  checked at every write and on every later revision; delegated rules are re-checked
  against their delegation at evaluation (defense in depth).
- **Isolation from human edits**: proposals keep the delegated section of the
  active revision (the UI never sends it) and cannot change it; a policy
  administrator takes objects over explicitly (`take_over`), which goes through the
  normal review. Rollbacks keep the delegated objects. Managed bindings cannot use
  delegated roles, so a delegated delete never breaks a human object.
- **Concurrency**: delegated writes are serialized per replica; the activation is the
  conditional write of 15.2, and a lost race re-applies the change (and its
  preconditions) on the new active revision, a bounded number of times, before
  `409 policy_busy`. ETags are per object, so parallel Terraform resources do not
  invalidate each other.
- **Teams**: with `allow.teams.from_subject`, a delegated binding's team is the one
  derived from its own subject, so a pipeline created by the stack owns its records
  and cannot touch those of another pipeline, even though the stack wrote both
  bindings.

## 16. Onboarding and adoption

An existing zone is entirely **foreign** when the gate starts: read-only through the
gate. Taking it over is an explicit, reviewed operation, done team by team. The
step-by-step guide is [ONBOARDING.md](ONBOARDING.md).

### 16.1 Bulk adoption

| Route | Action | Purpose |
|---|---|---|
| `POST /api/v1/zones/{zone}/adopt/preview` | `dns.record.adopt` | dry run on a selection (explicit RRsets and/or host globs + types), for an owner team |
| `POST /api/v1/zones/{zone}/adopt` | `dns.record.adopt` | apply the adoptable candidates of a preview |
| `GET /api/v1/zones/{zone}/terraform?team=&hosts=&types=&provider=` | `ui.read` | Terraform HCL for the RRsets owned by a team |

- **Preview** lists every selected RRset with its TTL, values, current status and
  whether it is adoptable. Reasons for refusal: `protected`, `server_managed` (SOA,
  locked records), `owned_by_other_team`, `already_owned`, `forbidden` (RBAC),
  `relative_target` (a value that would not round-trip safely). It returns a
  `preview_token` bound to the exact upstream content previewed.
- **Apply** is **all-or-nothing** and must carry the `preview_token` and a
  **mandatory comment**. If any selected RRset changed or is no longer adoptable
  since the preview, nothing is adopted: `409 {"reason":"adopt_conflict"}`.
- Adopted entries get `Adopted = true`, the current content hash, the owner team and
  the adopter as `CreatedBy`; one audit event lists every adopted RRset with its
  values and the comment.
- `dns.record.adopt` is an **admin** permission: adoption turns a record nobody
  could touch into one a team can change or delete.

### 16.2 Terraform export

The export returns HCL for the team's RRsets: one `dnsgate_record_set` per RRset
(provider `KamorionLabs/dnsgate`, any DNS provider behind the gate, alias RRsets as an
`alias` block; `provider=eurodns` exports `eurodns_record_set` instead) and
one `import` block (Terraform and OpenTofu 1.5+) with the import id
`<zone>/<host>/<type>`. Applied as is, the **first plan must show only imports and
no changes**; any diff means the export and the zone disagree and must be
investigated before going further.

Two paths, same result:

1. adopt in the gate (UI or API), then export HCL and plan;
2. EuroDNS zones only: write or export the HCL first, then `terraform import` /
   `import` blocks with the `eurodns` provider in gate mode: the provider asks the
   gate to adopt each RRset (`/.well-known/dns-gate/zones/{d}/adopt`), which requires
   `dns.record.adopt` for the identity running the plan.

Path 1 keeps the adoption right with admins and lets pipelines run with write
permissions only; it is the recommended one, and the only one with the `dnsgate`
provider, which imports only RRsets the team already owns.

## 17. MCP server

The gate embeds a Model Context Protocol server at `/mcp` (Streamable HTTP, official
Go SDK), so LLM agents can inspect DNS and, if explicitly allowed, propose changes.

### 17.1 Same controls

- Same authentication (bearer tokens: OIDC, gate tokens, API keys), same RBAC, same
  ownership rules, same rate budget as the REST API. MCP is another entry point, not
  another privilege.
- The gate publishes OAuth 2.0 Protected Resource Metadata (RFC 9728,
  `/.well-known/oauth-protected-resource`) pointing to the configured authorization
  server.
- Entra ID does not support dynamic client registration, so MCP clients cannot
  register with it and log in on their own: the token is passed in the
  `Authorization` header by the client configuration, or obtained from the gate's
  own authorization server (9.4), as the Claude Desktop extension does.
- Every tool call is audited with `via=mcp`.
- No policy tool: the policy (section 15) cannot be read in full or changed through
  MCP.

### 17.2 Tools

| Tool | Kind | Equivalent |
|---|---|---|
| `list_zones` | read | `GET /api/v1/zones` |
| `list_rrsets` | read | zone inventory |
| `get_rrset` | read | one RRset with ownership and history |
| `search_audit` | read | audit search |
| `explain` | read | decision simulation for the caller |
| `who_can` | read | who may act on an RRset |
| `plan_rrset_change` | write (disabled by default) | dry run of desired RRset states; returns the changes, the decision and a `plan_id` |
| `apply_rrset_change` | write (disabled by default) | applies exactly one plan, by `plan_id` |
| `adopt_preview`, `adopt_apply` | write (disabled by default) | bulk adoption (16.1), with the same token and comment rules |

### 17.3 Plan then apply

Writes are **disabled by default** in the configuration. When enabled:

- `plan_rrset_change` takes desired states (`host`, `type`, `ttl`, `values`, or
  `delete`), evaluates them like a real write (RBAC, protected, ownership, blast
  radius) and returns the RRset diff and a `plan_id`.
- The `plan_id` is bound to the **subject** that planned and to the **zone version**
  at plan time, and expires. `apply_rrset_change(plan_id)` fails if another subject
  presents it, if the zone changed since, or if it expired. Plans are kept in the
  store and taken once with a conditional delete, so any replica (or Lambda
  instance) can apply a plan made by another, never twice; `POST
  /api/v1/zones/{zone}/plan` and `/apply` use the same plans.
- An agent therefore cannot apply anything that was not shown first as a diff, and
  a human in the loop can review the plan before approving the apply call in the
  MCP client.

## 18. Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Gate down | IaC and ACME DNS changes blocked | console is the break-glass path; readiness probe; single replica restarts fast |
| Upstream ban (rate limit) | all writes blocked for the ban duration | client-side limiter well below the limit, no other caller from the egress IP, alert on 429 |
| Crash after pending claim, before/after PUT | ownership uncertain | reconcile resolves pending entries from upstream content |
| Change made in the console on an owned RRset | ownership hash mismatch | RRset tainted, writes blocked, alert, admin re-adopts |
| Store unavailable | no writes (fail closed), reads may continue | DynamoDB PITR; writes require the store |
| Lock holder dies | lock held until lease expiry | lease TTL (default 60 s) |
| EuroDNS API change | new operations denied by default; changed schemas preserved through `Extra` raw fields | vendored spec diffed in CI |
| Lost store | ownership lost: every RRset becomes foreign (safe, fail closed) | restore from PITR, or re-adopt from audit trail; optional TXT markers later |
