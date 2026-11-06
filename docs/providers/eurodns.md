# EuroDNS provider

The `eurodns` provider fronts one EuroDNS account. Declare one provider per account;
each zone is served by the provider whose `zones` filter selects it.

```yaml
providers:
  - id: eurodns
    kind: eurodns
    zones:
      include: ["*"]
      exclude: ["*.example.net"]
      folders: []              # e.g. ["/ES", "/ES/**"] to serve some folders only
      refresh: 1h              # account listing (zone discovery, folders)
    eurodns:
      app_id: my-app           # or EURODNS_APP_ID
      zone_profiles: false
```

| Secret | Variable |
|---|---|
| API key | `EURODNS_<ID>_API_KEY`, else `EURODNS_API_KEY` (or the `_FILE` variants) |
| Application id | `EURODNS_<ID>_APP_ID`, else `EURODNS_APP_ID`, else `eurodns.app_id` |

`<ID>` is the provider id in upper case, other characters replaced by `_`
(`eu-2` gives `EURODNS_EU_2_API_KEY`).

## What the gate adds

The EuroDNS API has no per-record update, no `ETag` and an account-wide key. The
gate:

- holds the key alone and enforces RBAC and ownership per record set;
- turns each change into a whole-zone write computed against the current zone, under
  a per-zone lock, after the EuroDNS **dry run** (`check_on_write`, on by default);
- respects the rate limit for every client together: 10 requests per 10 seconds **per
  source IP**, with progressive bans. One shared limiter per account
  (`eurodns.rate.every: 1.1s`, `burst: 5`) waits rather than fails; the gate must be
  the only EuroDNS client behind its egress IP;
- validates TTLs early: EuroDNS accepts a fixed list (600, 900, 1800, 3600, 7200...);
- keeps the **EuroDNS contract** for existing clients: point them at the gate with a
  virtual key or an API key, and the opened operations (zones, records, snapshots,
  DNSSEC status, zone profiles) behave as at EuroDNS. Every other operation, such as
  contacts or subscriptions, is refused.

## EuroDNS features

| Feature | Page |
|---|---|
| Folders: rights that follow the account's folders | [Roles and rules](../concepts/policy.md#folders) |
| URL forwards, owned like records | [URL forwards](../features/forwards.md) |
| Zone profiles, prepared before a transfer | [Zone profiles](../features/zone-profiles.md) |

Zone discovery lists the account's domains (one request per 100 domains per
`refresh`), shows the unmanaged ones read-only and lets policy administrators bring
them under management from the UI. The listing key must be allowed to search
domains. Every field: [providers configuration](../CONFIG.md#providers).

Run the gate as a container for EuroDNS, not on AWS Lambda:
[why](../DEPLOY-LAMBDA.md#why-not-in-front-of-eurodns).
