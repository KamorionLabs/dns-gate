# Migrating a 0.x configuration to providers

dns-gate now fronts several DNS accounts (EuroDNS and Route53). The
`upstream` and `zones_discovery` sections are replaced by a `providers` list. There is
no compatibility shim: a file still holding `upstream` or `zones_discovery` is refused
at startup (`field upstream not found`). Ownership entries, zone versions, locks and
the audit are unchanged and keep working: content hashes of EuroDNS RRsets are
computed exactly as before.

## Configuration

Before:

```yaml
upstream:
  base_url: https://rest-api.eurodns.com
  app_id: acme-gate
  rate: {every: 1.1s, burst: 5}
  max_retries: 3
zones: [example.com]
zones_discovery:
  enabled: true
  include: ["*"]
  exclude: ["*.internal.example"]
  refresh: 1h
```

After:

```yaml
providers:
  - id: eurodns
    kind: eurodns
    zones:
      include: ["*"]
      exclude: ["*.internal.example"]
      refresh: 1h
    eurodns:
      base_url: https://rest-api.eurodns.com
      app_id: acme-gate
      rate: {every: 1.1s, burst: 5}
      max_retries: 3
zones: [example.com]
```

- `upstream.*` moves to `providers[].eurodns.*`, same fields and defaults.
- `zones_discovery.include`, `exclude` and `refresh` move to `providers[].zones`.
  Discovery has no `enabled` switch any more: every provider account is listed, since
  the lists also tell which provider serves a zone. To keep a zone out of the UI,
  exclude it from the provider.
- `zones` (the managed zones of the base layer) is unchanged; it may now be empty
  (zones managed from the policy). Each zone must be selected by a provider.
- `check_on_write` is unchanged and now means "run the provider dry run" (EuroDNS
  `check`).

## Credentials

`EURODNS_API_KEY` and `EURODNS_APP_ID` (and their `_FILE` variants) keep working for
every EuroDNS provider. A second EuroDNS account reads `EURODNS_<ID>_API_KEY` and
`EURODNS_<ID>_APP_ID`, `<ID>` being its provider id in upper case with every other
character than letters and digits replaced by `_`. The Helm chart renders a default
`eurodns` provider and keeps mounting the same Secret.

The gate's own secrets (`DNS_GATE_SESSION_KEY`, `DNS_GATE_UI_CLIENT_SECRET`,
`DNS_GATE_POSTGRES_DSN`... and their `_FILE` variants) are still read under their
names from the time the project was called eurodns-gate (`EURODNS_GATE_*`) when the
`DNS_GATE_*` variable is not set. Rename them at your next change.

## Behaviour changes

- The EuroDNS-compatible API (`/dns-zones/...`) and the adopt extension only serve
  zones of a `eurodns` provider (`404 zone_not_eurodns` otherwise). Zones of every
  provider are served by the RRset API under `/api/v1`.
- Audit events carry `provider`; `snapshot_id` is now a JSON string (events stored
  with a number still decode). Zone summaries and inventories carry `provider`;
  inventory RRsets carry `hash`, `read_only` and `alias`.
- A EuroDNS RRset holding a target stored relative to the zone (no ending dot) is
  read-only (`read_only: relative_target`): it can be neither changed nor adopted until
  fixed at EuroDNS. It was already blocked by the EuroDNS check warning before.
- Desired targets of several labels without an ending dot (`target.example.net`) are
  now written absolute (`target.example.net.`) instead of being refused; a single label
  (`mail`) is still refused. Stored values are never rewritten.
- Adopting a SOA or locked RRset returns `403 forbidden` instead of `404 not_found`.

## Teams block

Teams used to be plain strings in `bindings[].team`, `virtual_keys[].teams`,
issuer `team_claim` and delegations. They are now declared in a
[`teams` block](config/policy.md#teams), with their members. The migration takes one minor
version:

- **A file without `teams` keeps working unchanged.** Every team it names is
  declared automatically, and the gate logs one warning per team at startup
  (`configuration accepted with a warning`; `dns-gate --check` prints them).
  Bindings, ownership and the audit behave as before. `GET /api/v1/teams` lists these
  teams as `auto`, and the teams found in the store that nothing names as `store`.
- **Adding a `teams` block makes references strict**: every team named by a binding,
  a virtual key, a delegation or the managed layer must be declared there (or in the
  managed layer), otherwise the file or the revision is refused. Families
  (`team_from`, `allow.teams.from_subject`) then need a non-empty `prefix`, and no
  declared or fixed team may carry the prefix of a family. Values of an issuer
  `team_claim` become teams of the issuer family `<team_claim_prefix><value>` (the
  prefix is then required), never a declared team: move such people and pipelines
  into `teams.<name>.members`. Families must not overlap (no prefix starts with
  another). Declare
  every team the warnings listed, the teams of the API keys, plus the store owners `GET /api/v1/teams` shows as
  `store`, before adding the block; or rename them with
  `POST /api/v1/teams/{team}/rename` (two policy administrators).
- A later version will refuse undeclared teams even without the block.
- **Check the active managed revision** before deploying a base file with a new
  `teams` block: a managed binding or key naming an undeclared team makes the active
  revision invalid against the new base, and the gate then serves the base policy
  only (managed grants missing: error logs and `load_error` of `GET /api/v1/policy` give the reason, `/healthz` and `/readyz` say that the managed policy is not served). Run
  `dns-gate --check` with the new file and access to the store: it validates the
  active revision and fails when it would be refused. Propose a revision that
  declares the teams first, or declare them in the file.

**Rolling deploy and rollback.** A gate older than this version refuses a managed
revision holding `teams` (unknown field): it keeps its previous policy while running,
and serves the base policy only after a restart. Upgrade every replica before
activating a revision that declares teams; before rolling back to an older binary,
activate a revision without `teams` (or the older binary loses the managed grants).
The store migration `0004` stays in place on a rollback and is harmless.

To declare the teams of an existing file, copy the team names from the warnings:

```yaml
teams:
  web: {description: Web shop}
  ops: {description: Operations}
```

Bindings keep their `groups` and `subjects`. Moving the people and pipelines of a
team into `teams.<name>.members` and removing them from the bindings (a binding with
a team and no groups or subjects applies to the team members) is optional.

Other changes of the same version:

- Adopting RRsets for another team than one's own (`owner` of the adopt endpoints and
  of the EuroDNS adopt extension) requires the new action `dns.ownership.approve` on
  each RRset; it was accepted from anyone allowed to adopt.
- Ownership transfers and renames are approved by a human by default
  (`ownership.machine_approvers: true` lets pipelines approve). By default
  (`ownership.require_second_approver: false`) the requester may approve its own
  request; set it to `true`, with `ownership.person_issuers` naming the UI login
  issuer, as soon as two people administer the gate.
  With `require_second_approver: true`, `ownership.person_issuers` is required when
  several issuers yield human subjects (the gate refuses to start otherwise; `dns-gate
  --check` names them) and defaults to the only human issuer otherwise.
- With a `teams` block, an issuer `team_claim` needs a `team_claim_prefix`: its values
  become `<prefix><value>` teams. Values that named declared teams no longer do: move
  those people into `teams.<name>.members`.
- A deleted RRset stays reserved for its team for `ownership.tombstone_ttl` (7 days by
  default): other teams can no longer re-create it at once (`403 not_owner`), they ask
  for a transfer. Set `ownership.tombstone_ttl: 0s` to keep the previous behaviour.
- SQL stores get migrations `0004` (tables `ownership_tombstone` and
  `ownership_transfer`, column `rrset_plan.team`) and `0006` (column
  `ownership.transfer_id`), applied at startup; on a database already at `0005` (API
  keys, 0.7.0), `0004` is applied then, migrations being recorded one by one. The DynamoDB
  table needs no change (new `TOMB#` and `TR#` items, the existing `ttl` attribute);
  the gate role needs `dynamodb:Scan` on it for team renames.

## URL forwards (0.9)

URL forwards (EuroDNS HTTP redirects) become owned objects, written with the new
action `dns.forward.write` ([configuration](config/policy.md#roles), [API.md](API.md#url-forwards)).

- Inventories, plans, adoption previews, the audit and the MCP tools list forwards
  as RRsets of type `URLFWD` (no TTL nor values, a `forward` object). Clients that
  list every RRset of a EuroDNS zone see them; the zone summary counts them.
- Through the EuroDNS-compatible full-zone PUT, a forward change used to require
  `dns.zone.admin` and ignored ownership. It is now a forward write: new forwards
  are owned by the caller's team, owned forwards follow the ownership rules
  (`403 not_owner` for another team), and `dns.zone.admin` still changes or deletes
  the forwards the gate does not own, which stay unowned, but no longer creates
  forwards (`dns.forward.write` is required). Clients that send the forwards back
  unchanged are not affected, hosts holding several forwards included; mail
  forwards and the other zone settings still require `dns.zone.admin`.
- New A, AAAA, CNAME and APEX records are refused on a host whose forward belongs
  to another team or to nobody, and a protected entry listing those types now
  protects the forward of its hosts too.
- Grant `dns.forward.write` to the roles that manage redirects (add it to
  `policy.bounds.actions` for managed roles and to delegations where needed), and
  adopt existing forwards with `dns.record.adopt` (type `URLFWD`).
- The HTTPS status of forwards is read from the EuroDNS subscriptions; with an API
  key not allowed to list them it is `unknown`.
