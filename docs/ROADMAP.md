# Roadmap

## v0.1 — MVP

- `eurodns-go`: client, shared rate-limited transport, RRset helpers, zone delta,
  fake server for tests.
- Gate:
  - multi-issuer OIDC authentication, bound audiences and claims, roles and teams;
  - route table generated from the vendored OpenAPI spec, deny by default;
  - DNS zone read, `POST dns-records`, `DELETE dns-records/{id}`, `PUT dns-zones`
    through the write engine;
  - ownership per RRset (create, not_owner, foreign, tainted), protected records,
    blast-radius limit;
  - per-zone lock, zone version as `ETag`, `If-Match`;
  - adoption endpoint, reconcile loop (drift, pending claims, ephemeral GC);
  - memory and DynamoDB stores;
  - JSON audit to stdout and to the store (retention);
  - web UI: zone inventory with ownership status, filterable audit log with diffs,
    OIDC login (code + PKCE), served from the inventory cache;
  - editable managed policy layer: revisions, approval by another approver, atomic
    activation, rollback, YAML export, diff, impact analysis, explain and who-can;
    `policy.*` grants and bounds in the base file only;
  - bulk adoption (preview, all-or-nothing apply, mandatory comment) and Terraform
    HCL export with `import` blocks;
  - MCP server at `/mcp` (Streamable HTTP): read tools, writes disabled by default
    with plan then apply, no policy tools, bearer token in the header;
  - container image and Helm chart, single replica.
- Terraform provider: one provider, direct and gate modes; `eurodns_record_set`;
  `eurodns_zone` and `eurodns_record_set` data sources; token sources `token`,
  `token_file`, `token_command`, `aws_web_identity`.

## v0.2

- Virtual keys (scoped, hashed, expiring, CIDR-bound) for existing EuroDNS clients.
- `rebase` and `ephemeral_ttl` roles for ACME clients; upstream pull request to lego
  for a configurable API URL.
- Shared rate limiter in the store for multiple replicas.
- Prometheus metrics (upstream requests, waits, denials by reason, tainted RRsets).
- Bulk adoption command for migrating existing zones.
- Publication: GitHub releases, container registry, Terraform and OpenTofu registries.
- Policy delegations in the UI: badge and owner on delegated roles and bindings,
  takeover from the editor (API only today), and rebasing open proposals over
  delegated changes instead of marking them stale.

## Later

- Other registrars with all-or-nothing API keys, through upstream adapters (route
  table + zone semantics per upstream).
- external-dns webhook provider (Kubernetes ingresses → DNS records via the gate).
- `cert-manager-webhook-eurodns` DNS-01 solver.
- Optional ownership markers in the zone (opaque TXT records signed with HMAC), to
  rebuild the store if lost.
- Two-person approval for sensitive changes (apex, MX, NS, CAA).
- Response filtering on list endpoints (`POST /domains/search`) per subject.
- Postgres store.
- MCP login without a pre-configured token, once the authorization server supports
  dynamic client registration (not available with Entra ID).
- Pluggable policy engine (Cedar or OPA) behind the `Authorizer` interface.
- Optional: turn an approved policy revision into a pull request on the git
  repository holding the base config, instead of (or before) activating it in the
  store.

## To validate against the real API

Spike on a test domain before v0.1 is called usable:

1. **PUT semantics**: does `PUT /dns-zones/{d}` replace the whole zone (records
   absent from the body deleted)? Behaviour of URL and mail forwards when omitted.
2. **Record id stability**: are record ids kept or renumbered after a PUT? This
   decides whether ids can be cached between reads.
3. **Rate limit**: actual HTTP status and body when the limit is hit, ban duration,
   whether `check` and GETs count the same.
4. **EuroDNS user scopes**: granularity available in the console for users holding
   API keys (per domain? per kind of operation?), multiple keys per user, service
   accounts.
5. Apex host representation (`""` vs `@`) and case handling.
6. Behaviour of `locked` records and of the `proxy` field on PUT.
7. **Domain listing** (`zones_discovery`): `POST /domains/search` pagination (first
   page number, assumed `1`; maximum `pagination-size`, 100 used; `pagination-count`),
   and whether a DNS-scoped EuroDNS user may call it.
