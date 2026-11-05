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

## Shipped since v0.1 (up to v0.5)

- Virtual keys (scoped, hashed, expiring, CIDR-bound) for existing EuroDNS clients.
- `rebase_on_save` and `ephemeral_ttl` roles for ACME clients.
- Azure DevOps OIDC issuer, bound to dedicated service connections, and teams
  derived from a claim (`team_from`).
- Zone discovery: every zone of the account listed read-only, brought under
  management from the UI by a policy revision.
- Policy delegations: a pipeline stack manages its own roles and bindings within
  bounds, without approval; delegated objects shown with a badge in the UI.
- Web UI: Connect page, Claude Desktop extension for the MCP endpoint, simple and
  expert policy views.
- Publication: GitHub releases, multi-arch image and Helm chart on GHCR, Terraform
  provider on the OpenTofu registry.
- First production use (November 2026): 14 zones, OpenTofu pipelines writing
  certificate validation and site records, the web UI and the MCP server.

## v0.6 — dns-gate, multi-provider (in progress)

- Project renamed `dns-gate`; gate detection on `/.well-known/dns-gate` only.
- Provider-neutral core (`internal/dns`, `internal/provider`): EuroDNS and Route53
  adapters, `providers:` configuration, one provider per zone name.
- Route53: one atomic, conditional change batch per write (exact DELETE of the old
  content), alias records, routing-policy records read-only.
- Neutral REST API (`/api/v1/zones/{zone}/rrsets/{host}/{type}`, plan and apply)
  with a published OpenAPI spec and API docs on the project site.
- `terraform-provider-dnsgate`: `dnsgate_record_set`, `dnsgate_role`,
  `dnsgate_binding`; Terraform export in its format.
- DNS writes from the web UI (stage, plan, apply), with CSRF and step-up.
- SAML 2.0 login (IAM Identity Center), groups from the identity store,
  gate-issued tokens for the API, Terraform and the Claude Desktop extension.
- AWS Lambda runtime (API Gateway HTTP API, scheduled maintenance, plans in the
  store) and the `terraform-aws-dns-gate` module.

## Next

- Providers, first wave (credentials that cannot be scoped per record, or our
  users' clouds): Cloudflare (zone-scoped tokens, batch API), OVHcloud
  (application keys scoped by API path only), Azure DNS (record-set ETags).
- ACME front-ends independent of the provider: an endpoint compatible with lego's
  `httpreq` provider (`/present`, `/cleanup`, basic auth mapped to virtual keys) and
  an acme-dns compatible endpoint (cert-manager, Caddy, certbot).
- external-dns webhook provider protocol (`GET /records`, `POST /records`,
  `POST /adjustendpoints`), so Kubernetes clusters write DNS through the gate with
  its RBAC and ownership instead of TXT registry records.
- Signing key rotation for gate-issued tokens (several keys in the JWKS).
- Shared rate limiter in the store for multiple replicas.
- Prometheus metrics (upstream requests, waits, denials by reason, tainted RRsets).
- Terraform providers on the HashiCorp registry.
- Policy delegations in the UI: takeover from the editor (API only today), and
  rebasing open proposals over delegated changes instead of marking them stale.
- Upstream pull request to lego for a configurable EuroDNS API URL.

## Later

- Providers, second wave: Google Cloud DNS (atomic changes with exact deletions),
  Gandi LiveDNS, Infomaniak, Scaleway, IONOS, PowerDNS Authoritative (atomic
  RRset PATCH), RFC 2136 dynamic updates (BIND, Knot, Windows DNS; prerequisites as
  compare-and-swap, TSIG).
- Long tail through a generic libdns 1.x adapter (DigitalOcean, Hetzner, GoDaddy,
  Namecheap, Porkbun, deSEC...): no conditional writes upstream, so the zone lock
  plus reads before and after the write stand in for them.
- Route53 routing policies (weighted, latency, failover, geolocation) writable,
  keyed by set identifier.
- Zone names served by several providers (split horizon), keyed by provider and
  zone id instead of the zone name.
- `cert-manager` DNS-01 webhook solver.
- Optional ownership markers in the zone (opaque TXT records signed with HMAC), to
  rebuild the store if lost.
- Two-person approval for sensitive changes (apex, MX, NS, CAA).
- Response filtering on list endpoints per subject.
- MCP login without a pre-configured client, through dynamic client registration
  on the gate's authorization server.
- Pluggable policy engine (Cedar or OPA) behind the `Authorizer` interface.
- Optional: turn an approved policy revision into a pull request on the git
  repository holding the base config, instead of (or before) activating it in the
  store.

## Not planned

- lego as a provider backend: its DNS providers only present and clean up ACME TXT
  records (no zone listing, no other types, no update), and their API clients are
  internal packages. lego stays a client of the gate (`httpreq`).
- DNSControl providers as a library: not a supported API, heavy dependency tree,
  and opaque corrections that cannot be checked change by change for ownership.

## Open questions on Route53 and IAM Identity Center

1. Octal escapes inside TXT values as returned by `ListResourceRecordSets`, to
   confirm on a real account.
2. Whether Identity Center honours `ForceAuthn` (step-up), the AuthnContext it
   sends, and which user attribute to use for the identity store lookup.

## Open questions on the EuroDNS API

Production use has exercised full-zone saves through the gate, adoption of existing
records, apex records and zone discovery over a whole account without hitting the
points below, but none of them has had a dedicated test yet:

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
