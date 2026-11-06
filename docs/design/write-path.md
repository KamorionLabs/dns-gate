# Requests and writes

How a request goes through the gate, how a write is computed and applied, the store, the EuroDNS contract and the rate limits.

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
Guide: [API.md](../API.md).

| operationId | Action | Handler |
|---|---|---|
| `getDnsZone` | `dns.read` | engine (adds ETag) |
| `checkDnsZone` | `dns.read` | engine |
| `saveDnsZone` | `dns.record.write` (`dns.forward.write` for URL forwards, `dns.zone.admin` for mail forwards and zone settings) | engine (delta) |
| `addDnsRecords` | `dns.record.write` | engine |
| `deleteDnsRecord` | `dns.record.write` | engine |
| `listDnsZoneSnapshots`, `getSnapShot`, `getDnssecStatus` | `dns.read` | passthrough |
| `signZone`, `unsignZone` | `dns.zone.admin` | passthrough |
| `listZoneProfiles`, `createZoneProfile`, `checkZoneProfile`, `getProfile`, `updateUserAPiZoneProfile`, `deleteZoneProfile` | `dns.zone.profile` on `*` | account (5.2) |
| `getDomain`, `searchDomains` | `domain.read` | passthrough |
| everything else (contacts, nameserver profiles, subscriptions, SSL, invoices, orders…) | — | denied |

### 5.2 Account-wide operations: zone profiles

Most EuroDNS operations name a domain, which selects the provider and scopes
RBAC. Zone profiles do not: a profile is a template of the EuroDNS account
(records, URL and mail forwards) that EuroDNS applies to a domain when it arrives
on its nameservers (a transfer, a Premium DNS subscription created with its
`zoneProfileId`). The EuroDNS document gives a profile only an id, a name and its
content; nothing ties it to a domain, nor names a default profile.

- **Scope.** A narrower grant could not be enforced: the profile is not bound to
  the domain the caller has in mind, and that domain is not in the account (nor
  managed) before it arrives. `dns.zone.profile` therefore counts only when a rule
  grants it on `"*"` without a record scope (`GrantsPattern(roles, action, "*")`,
  the check of the account-wide API key administrators); a narrower grant has no
  effect and is flagged at load. Reads need it too: profiles may carry
  verification tokens.
- **Opt-in per account.** `providers[].eurodns.zone_profiles: true` opens the
  profiles of one EuroDNS account; the grant on `"*"` covers the opted-in
  accounts only.
- **Same guards as other sensitive writes.** Writes need a recent login from
  humans (`stepUp`, with the session or the token `auth_time`) on every channel;
  profile records matching the protected list are refused whatever the zones of
  the entry (the profile may land on any domain), on check too, mail forwards
  counting as the apex MX and URL forwards as A, AAAA and CNAME of their host; a per-subject
  limiter (60 operations a minute, all channels) keeps one caller from draining
  the account's EuroDNS budget, and listings stop at 20 pages of 100.
- **No ownership.** The gate cannot attribute a profile to the team of the domains
  it will serve, so it keeps no ownership for profiles and no state: any holder of
  the action may change any profile of the account. The action is meant for the
  administrators of the account.
- **Served by the gate, not proxied.** The routes are mapped with the handler kind
  `account` (no zone, no managed-zone check). The gate decodes the body as a
  `ZoneProfilePage` (only known fields reach EuroDNS), checks the name, calls
  EuroDNS on the shared rate-limited transport (`internal/provider/eurodns`), and
  re-encodes the answer; EuroDNS refusals (400, 404, 409, 422, 429) are returned
  as is on the EuroDNS-compatible routes and as `rejected` or `not_found` on
  `/api/v1`. The provider is the only `eurodns` provider, the one named by
  `X-DNS-Gate-Provider`, or `{provider}` of
  `/api/v1/providers/{provider}/zone-profiles`; any other kind is refused.
- **Audit.** Every operation is audited with the provider and the profile id,
  refusals included (malformed requests as `bad_request`); writes carry the
  profile content (an update and a delete read it first: `previous`), and the
  host, type and operation of each changed record in `changes`, without values;
  never credentials. The journal shows zone profile events only to holders of
  `dns.zone.profile` on `*`: ui.read on every zone is not enough.
- **After the arrival.** The records EuroDNS creates from a profile are foreign to
  the gate: they are adopted by their teams once the zone is managed (6.3).

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

## 10. Extensions to the EuroDNS contract

Kept minimal and invisible to plain EuroDNS clients:

| Extension | Behaviour |
|---|---|
| `ETag` on `GET /dns-zones/{d}` | zone version |
| `If-Match` on writes | `412` if the zone version changed. EuroDNS ignores the header, so clients can always send it. |
| `GET /.well-known/dns-gate` | `{"version": "...", "features": [...]}`: `if-match`, `ownership`, `adopt`, `policy-delegation`, `plans`, `rrset-api`, `acme-httpreq`, plus `api-keys`, `acme-dns` and `token-exchange` when served ([API.md](../API.md)). Plain EuroDNS returns 404: this is how clients detect a gate. |
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
