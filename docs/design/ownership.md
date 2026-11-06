# Ownership model

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

### 6.1.1 URL forwards

A URL forward (HTTP redirect) is owned like an RRset: it is modelled as the RRset of
the pseudo type `URLFWD` (never a DNS type) of its host, with `TTL` 0, no values and
a `dns.Forward` (`type` 301, 302 or frame, `url`, and `title`, `keywords`,
`description` for frames). Ownership entries, tombstones, transfers, adoption,
reconcile (drift taints it), plans, audit (`old_forward`/`new_forward`), the UI and
MCP all reuse the RRset machinery with that key. Its content hash is
`dns.ContentHash` of TTL 0 and the single value
`forward <type> <n>:<url> <n>:<title> <n>:<keywords> <n>:<description>` (each field
prefixed by its length in bytes, so no field can bleed into another); hashes of
other RRsets are unchanged. Writing requires `dns.forward.write`, scoped by
`records.hosts` (`policy.WriteAction`); providers without forwards (Route53) report
`Capabilities.Forwards` false and the engine refuses forward changes. A forward
shadows the `A`, `AAAA`, `CNAME` and `APEX` records of its host
(`policy.ForwardShadowTypes`): the engine creates one only where those records are
absent or owned by the caller's teams, and the reverse; a protected entry listing
one of those types protects the forward. Through the full-zone PUT,
`dns.zone.admin` only changes or deletes unowned forwards (audited as
`zone_admin_forwards`), never creates one. Frame fields are plain text with length
limits and URLs must be canonical http(s) URLs: EuroDNS serves frame forwards as a
page on the customer host.

HTTPS: a EuroDNS forward entry has no HTTPS setting; the forward host answers HTTPS
only with an *HTTPS redirect* subscription on the domain (a paid product: a
certificate for the forward hosts, state ACTIVE, PENDING or NO_FORWARD). The
adapter reads it (`GET /subscriptions?subscription-types=HTTPS_REDIRECT&domain-name=`
then `GET /https-redirect-subscriptions/{id}`, cached 10 minutes per zone, a failure
30 seconds; one lookup per zone at a time, with its own timeout, before the zone
lock) and the API reports it, an expired subscription as inactive;
`require_https` on a forward write is refused (`https_unavailable`) unless it is
active or no_forward. The gate never
orders, renews nor deletes subscriptions (orders are paid, and the passthrough
keeps denying the subscription operations).

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
`dns.ownership.approve` on each adopted RRset. An RRset reserved for another team by
a tombstone is never adopted for another team: it moves through a transfer. In gate mode, `terraform import` of an `eurodns_record_set` calls adopt.
Bulk adoption with preview, Terraform export and onboarding of whole zones are
described in section 16.

### 6.3.1 Teams, tombstones and transfers

Teams are declared in the `teams` block (base file or managed layer) with their
members; a binding naming a team without groups or subjects grants its role to the
members. Once the block exists, references to undeclared teams are refused; before,
they are declared automatically with a warning (migration). Derived teams never take
the name of a declared team: with the block, families (`team_from`, `from_subject`)
need a prefix that no declared or fixed team carries, `Snapshot.Resolve` drops a
binding whose derived team is declared, and a `team_claim` value is kept only for a
family member that is not declared. A subject records the roles of each of its teams
(`Subject.TeamRoles`): rights held through one team never count for another.

Deleting an owned RRset (gate write, or a pending delete settled by the reconciler)
writes a tombstone (`ZONE#<zone>`/`TOMB#<host>#<type>` in DynamoDB, table
`ownership_tombstone` in SQL) with the team, the deleter and an expiry, in the same
store transaction as the removal of the ownership entry
(`Store.DeleteWithTombstone`): when it fails the entry stays pending and the
reconciler retries. Until it expires, only that team may create or adopt the RRset
again; ephemeral RRsets leave no tombstone.

A transfer request lists RRsets of one team (owned or tombstoned) and a target team,
with their content hash. The approver may, for every RRset, write it through the
bindings of the owner team or holds `dns.ownership.approve` on it, and is a human
unless `ownership.machine_approvers`. With `ownership.require_second_approver` it is
another person: requester and approver share no person key (the subject for
`ownership.person_issuers`, and the values of `ownership.person_claims`, `email`
only when trusted and verified), and either without person keys fails closed;
without it, the requester may approve its own request (audited `approval: self`).
The transfer is then `applying`: the engine takes the zone lock, reads the zone,
checks that every entry still has the team, the state and the content hash of the
request (store and upstream) or already carries the transfer id, then changes them
all in one store transaction (`Store.Reassign`: SQL transaction, DynamoDB
`TransactWriteItems` with a version or team condition per item, at most 100 items)
and audits the move as soon as it commits. After an ambiguous store error it reads
the entries back to tell whether the transaction committed. A transfer left
`applying` (zone locked, store unavailable, crash) is retried in the background no
earlier than 2 minutes after the approval, by one replica at a time (a lease in the
transfer, taken with a version check), with the approver bound again (`Rebinder`,
the current policy) and its rights checked again; after 24 hours it fails. A team
rename is approved by a `policy.approve` holder and always applied in the
background: zone by zone, in the managed zones and every zone the store still holds
(`Store.ListOwnedZones`, a scan on DynamoDB, #68), each entry checked for
`dns.ownership.approve` of the approver under the zone lock.

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
callers whose role has no ephemeral TTL ([ACME.md](../ACME.md)).

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
