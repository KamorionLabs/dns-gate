# Scaleway provider

The `scaleway` provider fronts the DNS zones a Scaleway API key can see
(package `internal/provider/scaleway`, Domains and DNS API `domain/v2beta1`).

## Configuration

```yaml
providers:
  - id: scw
    kind: scaleway
    zones: {include: ["*.io"]}
    scaleway:
      project_id: 11111111-2222-3333-4444-555555555555
```

| Field | Default | Description |
|---|---|---|
| `project_id` | | Lists only the zones of this project. |
| `organization_id` | | Lists only the zones of this organization. |
| `max_retries` | `3` | Retries of a throttled request (429) and of a failed read. |

The whole `scaleway` block is optional. The secret key of the API key comes
from `SCALEWAY_<ID>_SECRET_KEY`, else `SCALEWAY_SECRET_KEY`, else
`SCW_SECRET_KEY` (or their `_FILE` variants, see
[Secrets](../CONFIG.md#secrets)). Give the key an IAM policy with the
`DomainsDNSFullAccess` permission set on the projects served
(`DomainsDNSReadOnly` is enough for zones that stay unmanaged).

### Zones

The listing returns the root zone of each domain (`example.com`) and its
sub-zones (`dev.example.com`), each as a zone of its own.

## Reading

`ReadZone` lists the records of the zone (100 per page) and groups them by
host and type.

| Upstream | RRset |
|---|---|
| Plain records | values in the [canonical form](route53.md#canonical-values); the `priority` field of `MX` and `SRV` records is the first field of the value |
| Apex `NS` | read-only `server_managed` |
| Records with a dynamic answer (geo IP, HTTP service, weighted, views) | read-only `routing_policy` |
| `ALIAS` records | read-only `alias`, the target as value |

## Writing

For each changed RRset, `Apply` lists its records again (filtered by name and
type) and compares TTL and values with the RRset the change was computed
against: a difference, or a create whose RRset exists, is a conflict and
nothing is sent. Every record change of the `Apply` then goes in **one**
`PATCH /dns-zones/{zone}/records`: deletes and rewrites by record id, then
additions, with `disallow_new_zone_creation`.

| Property | Value |
|---|---|
| Atomic | One request per write, but the gate does not rely on Scaleway applying it atomically: after a failed write it settles ownership on what it reads back. |
| Writable types | `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS` (not at the apex), `PTR`, `SRV`, `SSHFP`, `TLSA`, `TXT` |
| TTL | 60 seconds to 30 days (2592000) |
| `TXT` | Written quoted, cut in strings of 255 bytes |

## Limitations (v1)

- Dynamic records and `ALIAS` records are read-only.
- No URL forwards.
- The adapter is tested against a fake built from the Scaleway SDK and
  Terraform provider, not against a live account: validate it on a test zone
  first.
