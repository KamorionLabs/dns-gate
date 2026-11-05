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
