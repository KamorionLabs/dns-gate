# Providers, discovery and folders

The DNS accounts the gate fronts, how it lists their zones, and the EuroDNS-only settings (folders, zone profiles). Provider pages: [Route 53](../providers/route53.md), [EuroDNS](../providers/eurodns.md).

## Providers

A provider is one DNS account: a EuroDNS account or an AWS account for Route53. The gate alone holds its credentials. Each zone is served by exactly one provider: the one whose `zones` filter selects it, or, when the filters of several providers select it, the only one of them whose account lists it. A zone listed by two providers that both select it is served by neither (an error is logged): exclude it from all but one. Ownership, locks and audit stay keyed by zone name.

| Field | Default | Description |
|---|---|---|
| `providers[].id` | (required) | Unique lowercase identifier, shown in the UI, the audit (`provider`) and zone summaries. |
| `providers[].kind` | (required) | `eurodns` or `route53` ([providers/route53.md](../providers/route53.md)). |
| `providers[].zones.include` | `["*"]` | Zone globs (`*` wildcards) the provider serves. |
| `providers[].zones.exclude` | `[]` | Zone globs removed; they win over `include`. |
| `providers[].zones.folders` | `[]` | EuroDNS only: keep the zones whose [folder](#eurodns-folders) matches one of these folder globs (`/ES` the folder ES, `/ES/**` every folder below it, `/` the domains in no folder). Empty: every folder. |
| `providers[].zones.folder_expiry` | `3` | Refresh periods the [folders](#eurodns-folders) of a listing are trusted while listings fail. |
| `providers[].zones.refresh` | `1h` | Account listing period (minimum `5m`), see [Zone discovery](#zone-discovery). |
| `providers[].eurodns.base_url` | `https://rest-api.eurodns.com` | EuroDNS API. HTTPS is required (loopback excepted, for tests). |
| `providers[].eurodns.app_id` | | EuroDNS application id (or the variables of [Secrets](../CONFIG.md#secrets)). |
| `providers[].eurodns.rate.every`, `.burst` | `1.1s`, `5` | Client-side limiter shared by every call to this account (reads, writes, checks, listing, passthrough). EuroDNS allows 10 requests per 10 seconds per IP and bans progressively: keep the default unless EuroDNS raised your quota. |
| `providers[].eurodns.max_retries` | `3` | Retries on 429, 5xx and network errors (idempotent requests). |
| `providers[].eurodns.zone_profiles` | `false` | Serves the [zone profiles](#zone-profiles) of the account through the gate; off, they are refused (`403 zone_profiles_disabled`) even to holders of `dns.zone.profile`. |
| `providers[].route53.region` | SDK default | AWS region of the API calls. |
| `providers[].route53.assume_role_arn` | | IAM role assumed in the account holding the hosted zones. |
| `providers[].route53.external_id` | | External id of the assumed role (requires `assume_role_arn`). |
| `providers[].route53.hosted_zones` | `{}` | Zone name to hosted zone id, to pin a name with several hosted zones or skip the listing of the account. |
| `providers[].route53.include_private` | `false` | Serve private hosted zones too. |

```yaml
providers:
  - id: eurodns
    kind: eurodns
    zones: {include: ["*"], exclude: ["*.example.net"]}
    eurodns: {app_id: acme-gate}
  - id: route53-prod
    kind: route53
    zones: {include: ["*.example.net"]}
    route53:
      region: eu-west-3
      assume_role_arn: arn:aws:iam::123456789012:role/dns-gate
      hosted_zones: {"example.net": Z0123456789ABC}
```

What a provider can write is reported by the gate and enforced by the engine: alias RRsets only where the provider supports them (Route53), accepted TTLs (EuroDNS: a fixed list), read-only RRsets (`read_only` in the inventory: SOA and locked records at EuroDNS, `relative_target` for a EuroDNS RRset holding a target without ending dot, routing policies at Route53), which are never written nor adopted. The [EuroDNS-compatible API](../API.md#endpoints) only serves zones of a `eurodns` provider; the RRset API under `/api/v1` serves every zone.

Desired targets (CNAME, MX, NS, SRV, PTR) are read the same way for every provider: a name of several labels is absolute (`target.example.net` is written `target.example.net.`), a single label is refused as ambiguous. Values already stored are never rewritten.

### Zone discovery

The gate lists every provider account each `zones.refresh`, keeps the zones its `zones` filter selects, shows those it does not manage as **unmanaged** (in the UI and in the MCP `list_zones` tool) and lets policy administrators bring them under management from the UI, through a [managed policy](managed-policy.md#managed-policy-editing-from-the-ui) revision, without a configuration change. The lists also tell which provider serves a zone selected by several filters.

- **Upstream load**: a EuroDNS listing costs one request per 100 domains (`POST /domains/search`), through the shared rate-limited transport, once per `refresh` and per replica (the lists are held in memory). When a policy proposal names a zone not seen yet, the gate lists the accounts once more, at most once a minute, so that a domain added just before is found. A failed listing is retried after 5 minutes and the previous list is kept.
- **Unmanaged zones are read-only.** Their RRsets are readable with `dns.read` on the zone (UI and MCP; the UI also requires `ui.read`), evaluated by RBAC as usual: the zone globs of the role rules apply, so `zones: ["*"]` in a read role covers every discovered zone. They are never writable nor adoptable, the EuroDNS-compatible API (`/dns-zones/...`), the Terraform export and adoption refuse them, and reconcile does not run on them. Their content is read on demand, when someone opens the zone, and reused for `reconcile_interval`; listing zones never reads them, so their counts are absent from the listings until they have been read once.
- **Bringing a zone under management**: add it to the `zones` list of the managed policy (the UI offers "Manage this zone" to policy administrators), then approve and activate as any revision. It must match `policy.bounds.zones` and be in a discovered list. Once active, the zone behaves as a base zone: writes within the roles, adoption, reconcile. The `zones` filters of the providers therefore also bound what can be managed from the UI.
- The EuroDNS listing uses the key of the provider: its EuroDNS user must be allowed to search domains. Domains of the account for which EuroDNS holds no DNS zone are listed too: a domain registered only (EuroDNS then answers a default parking zone from its name servers, but `GET /dns-zones/{domain}` returns 404), or whose DNS is hosted elsewhere. Reading one is refused with "has no DNS zone at its provider"; the zone is then flagged `no_zone` in the listings and not asked again upstream before `reconcile_interval`. Exclude them with the `zones` filter of the provider to keep them out of the listings.

### EuroDNS folders

EuroDNS organises domains in folders (`folderFullPath` of `POST /domains/search`). The listing of a `eurodns` provider keeps the folder of each domain, at no extra cost: `/ES/Madrid`, and `/` for a domain in no folder (`null` or an empty path). Only slashes are normalized (leading `/`, no trailing or repeated `/`): `ES ` and `ES` stay distinct folders. When the field is absent or not a string, the folder is unknown (empty) and no folder selector matches the zone. The folder is shown in `GET /api/v1/zones` (`folder`, with a `?folder=` glob filter), in the zone inventory, in the Zones view of the UI (column, and a filter on the same globs: `/ES` that folder only, `/ES/**` the folders below it) and in the MCP `list_zones` tool. Route53 zones have no folder (empty): folder selectors never match them.

Folder globs use the segments of host patterns, matched case-sensitively: `*` matches one segment, `**` one or more segments, `*` inside a segment any run of characters. `/ES` is the folder ES only, `/ES/**` every folder below it (not ES itself: write both to cover the folder and its subfolders), `/` the domains in no folder. Segments with leading or trailing spaces are refused.

| Field | Default | Description |
|---|---|---|
| `providers[].zones.folders` | `[]` | Keep the domains of the selected folders only. |
| `providers[].zones.folder_expiry` | `3` | Refresh periods the folders of the last successful listing are trusted, counted from the end of that listing, while the following listings fail (2 to 100). Past it, folder rules match no zone of the provider until a listing succeeds (`folders_stale` in the discovery status of `GET /api/v1/policy`). |

- **Serving**: `providers[].zones.folders` keeps only the domains of the selected folders, after `include` and `exclude`. A zone of such a provider is served once a listing has seen it in a selected folder; until the first listing, or after it left the selected folders, it is served by no provider (writes fail, and a base `zones` entry outside them is an error at every write).
- **Rights**: role rules, `policy.bounds` and delegations accept `folders` next to `zones` ([Roles](policy.md#roles)). A folder selector never makes a zone managed: the zone must still be in the base or managed `zones`, or discovered to be readable. A zone listed by two providers has no folder.
- **Folders narrow the bounds, never widen them**: a managed rule that applies through its `folders` reaches a zone only if the zone also matches `policy.bounds.zones`, and a delegated one only if it also matches the `allow.zones` of its delegation. `bounds.zones` and `allow.zones` therefore stay required; use `["*"]` to let folders alone decide within the managed layer. Base rules are not bounded. `GET /api/v1/me` gives these zones with each narrowed permission (`folder_zones`), and the console applies them. For [API keys](../API.md#api-keys), a folder pattern of the key role is covered by a managed rule of the issuer only when `bounds.zones` (and, for a delegated rule, `allow.zones`) cover every zone.
- **Moves**: the folder is the one of the last successful listing (`zones.refresh`, and the on-demand refresh of policy proposals). Moving a domain to another folder in the EuroDNS console changes the rights of folder rules at the next listing, without a policy revision. Listings are audited with subject `gate:discovery` and one request id per listing. The first listing of a provider by a process records one `gate.zone.folders_listed` summary (`extra.count`, and `extra.digest`: SHA-256 of the sorted `zone<TAB>folder` lines, equal on every instance that saw the same folders). Later listings record, per zone, `gate.zone.folder_changed` for a zone found in another folder, `gate.zone.folder_seen` for a new zone and `gate.zone.folder_gone` for a zone no longer listed (`extra.old`, `extra.new`). These events are per process, not compared across instances: a move while no instance runs only shows as a different digest. Writes, adoptions and transfer requests and decisions granted through a folder rule carry the `folder` of their authorization in the `extra` of their audit event.
- **Review**: the impact analysis of a revision flags each new or changed folder rule as a dynamic rule, with the zones it reaches currently, and warns when zone discovery has not listed the accounts yet. The configuration loads with a warning when folder selectors exist without a EuroDNS provider, or lie outside the `zones.folders` of every EuroDNS provider.

Whoever may move domains between folders in the EuroDNS account therefore controls folder-based rights: see the [threat model](../THREAT-MODEL.md).

### Zone profiles

A EuroDNS zone profile is a template of the account (records, URL and mail forwards) that EuroDNS applies to a domain when it arrives on its nameservers: a domain transferred to EuroDNS, or a Premium DNS subscription ordered with the profile's id. Preparing a transfer means creating the profile and checking it before the domain arrives. The gate serves the zone profile operations of every `eurodns` provider ([API.md](../API.md#zone-profiles), MCP tools below, and the EuroDNS-compatible `/zone-profiles` routes) under the action `dns.zone.profile`.

Each EuroDNS provider opts in with `providers[].eurodns.zone_profiles: true` (off by default): a grant then covers the profiles of every opted-in account, and only of those.

A profile names no domain (its hosts are relative to whatever domain it is applied to) and the domain it prepares is not in the account yet, so zone globs cannot scope it: **`dns.zone.profile` only counts in a rule whose `zones` cover every zone (`"*"`, `"**"`) and that has no `records` scope**; granted on narrower zones it has no effect, and the gate warns at load (base file) and in the impact analysis (managed revisions), and also when no provider opts in. Every operation needs it, reads included (a profile may hold verification tokens), and a write applies to any profile of the account: there is no ownership by team. Give it to the administrators of the EuroDNS account only:

```yaml
roles:
  dns-account-admin:
    rules:
      - zones: ["*"]
        actions: [dns.zone.profile]
bindings:
  - role: dns-account-admin
    team: platform
    subjects: [{issuer: entra, claims: {groups: ["<dns admins group id>"]}}]
```

Writes (create, update, delete) need a recent login from humans, like policy changes (`policy.edit_max_age`, `policy.require_amr`; `403 reauth_required`), on every channel: the UI session, bearer tokens (their `auth_time`) on the REST and EuroDNS routes, and MCP. A profile holding a record of the [protected list](policy.md#protected-records) is refused (`403 protected`) on create, update and check, whatever the zones of the protected entry, since the profile may be applied to any domain; its mail forwards count as the apex `MX`, its URL forwards as `A`, `AAAA` and `CNAME` records of their host. Each subject may run 60 zone profile operations per minute, all channels together (`429 rate_limited`), as they share the EuroDNS rate limit of the account; listings are capped at 100 profiles per page and 2000 in all. Updates are audited with the previous content (`previous`) and, like creations and deletions, the host, type and operation of each changed record in `changes` (no values: the content stays in the audit sink). The journal (`/api/v1/audit`, `search_audit`) shows zone profile events only to holders of `dns.zone.profile` on `*`.

The records EuroDNS applies from a profile are created outside the gate: the domain then shows them as foreign RRsets, adopted by the teams that will manage them once the zone is managed ([adoption](policy.md#adoption-and-terraform-export)). The managed policy can grant `dns.zone.profile` only when `policy.bounds` allow it on `"*"`.
