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
| `internal/dns` | Provider-neutral model: `Zone`, `RRset` (values, alias or URL forward, read-only reason), `Change`, `ContentHash`. |
| `internal/provider` | Provider contract (`Provider`, `Checker`, `Snapshotter`, `Resolver`, capabilities, errors); `provider/eurodns` and `provider/route53` adapters. |
| `internal/eurodnsapi` | EuroDNS-compatible API facade (full-zone PUT, record ids, forwards, passthrough) over the neutral engine, for EuroDNS zones only. |
| `internal/policy` | RBAC engine implementing `Authorizer`. |
| `internal/routes` | Route table generated from `api/eurodns.openapi.json`, plus the hand-written operation → action mapping. |
| `internal/zonewrite` | `Engine`: every DNS zone read/write on behalf of a subject on the neutral model, provider resolved per zone, ownership enforcement, reconcile. |
| `internal/store` | `Store`: ownership entries, zone versions, zone locks, persisted RRset plans, API keys and their acme-dns registrations (memory, SQLite, Postgres, DynamoDB). |
| `internal/audit` | Structured audit events (stdout and store). |
| `internal/discovery` | Listing of the zones of every provider account, filtered and cached in memory; resolves the provider of a zone. |
| `internal/uiapi` | JSON types of the `/api/v1` API (inventory, RRsets, plans, audit, policy revisions, adoption, Terraform export). |
| `internal/propagation` | DNS propagation check of one RRset: authoritative name servers and public resolvers asked in parallel, answers compared with the provider content (section 19). |
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
`412 precondition`), `Alias` (alias RRsets are refused elsewhere), `Forwards` (URL
forwards are refused elsewhere), types and TTLs. A provider whose forwards answer
HTTPS only with a separate subscription implements `HTTPSRedirecter` (EuroDNS).

A zone is served by exactly one provider: the only one whose `zones` include/exclude
globs select it, or, when several do, the only one of them whose account lists it
(`internal/discovery`); a provider with a `zones.folders` filter selects only the
zones its last listing found in a selected folder. Ownership, locks and the audit
stay keyed by zone name.

Providers organising zones in folders (EuroDNS) also implement `FolderLister`:
`ListZoneFolders` returns each zone with its folder (`folderFullPath` of
`searchDomains`, normalized: leading `/`, no trailing `/`, `/` for a domain in no
folder). Discovery uses it instead of `ListZones`; it costs the same requests.

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
Each entry of `urlForwards` is the RRset `{host, URLFWD}` (see 6.1.1): a write
replaces only the entries of the forwards it changes, keeping their `id` and
unknown fields (as raw JSON, numbers untouched), every other entry byte for byte; a
host with several entries, or an entry of unknown `forwardType`, is read-only
(`duplicate_forward`, `unsupported_forward`), and so are `URL`/`MAIL` pseudo records
if EuroDNS lists any (`forward_record`). The EuroDNS spec lists `URL` and `MAIL` as
pseudo record types of forwards; whether `GET` returns them is **not verified
against the live API**: a write deleting a forward leaves out the `URL` pseudo
records of its host, so that the save neither resurrects nor refuses it. Forward errors of the `check` report are mapped to the
forward key. Mail forwards are not modelled: kept as read, changed only by a
full-zone PUT with `dns.zone.admin`.

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

## Other design pages

| Page | Sections |
|---|---|
| [Requests and writes](design/write-path.md) | 5 request pipeline, 7 write flow, 8 store, 10 extensions to the EuroDNS contract, 11 rate limit and high availability |
| [Ownership model](design/ownership.md) | 6 RRsets, URL forwards, rules, adoption, teams, tombstones, transfers, rebase, ephemeral RRsets, reconcile |
| [Authentication](design/authentication.md) | 9 OIDC, Entra ID, virtual keys, SAML and gate tokens, API keys, token exchange, delegated clients and scopes |
| [Policy, audit and web UI](design/policy.md) | 12 policy, 13 audit, 14 web UI, 15 editable policy, delegations, folders |
| [Onboarding, MCP and propagation](design/onboarding-mcp.md) | 16 onboarding, 17 MCP server and the Claude Desktop extension, 19 propagation check |

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
