# OVHcloud provider

The `ovh` provider fronts the DNS zones of one OVHcloud account (package
`internal/provider/ovh`, OVHcloud API `/domain/zone`). Declare one provider per
account.

## Configuration

```yaml
providers:
  - id: ovh-main
    kind: ovh
    zones: {include: ["*.fr"]}
    ovh:
      endpoint: ovh-eu
      application_key: 0123456789abcdef   # or a service account: client_id
```

| Field | Default | Description |
|---|---|---|
| `endpoint` | `ovh-eu` | `ovh-eu`, `ovh-ca` or `ovh-us`. |
| `application_key` | | Application key of an [API application](https://eu.api.ovh.com/createToken/). |
| `client_id` | | Client id of a [service account](https://help.ovhcloud.com/csm/en-manage-service-account?id=kb_article_view&sysparm_article=KB0059343) (OAuth2 client credentials), instead of an application. |
| `max_retries` | `3` | Retries of a throttled request (429) and of a failed read (network error, 5xx). |

Secrets come from the environment ([Secrets](../CONFIG.md#secrets)); `<ID>` is
the provider id in upper case:

| Variable | Used for |
|---|---|
| `OVH_<ID>_APPLICATION_KEY`, else `OVH_APPLICATION_KEY` | Application key, overrides `application_key` |
| `OVH_<ID>_APPLICATION_SECRET`, else `OVH_APPLICATION_SECRET` | Application secret |
| `OVH_<ID>_CONSUMER_KEY`, else `OVH_CONSUMER_KEY` | Consumer key |
| `OVH_<ID>_CLIENT_ID`, else `OVH_CLIENT_ID` | Service account id, overrides `client_id` |
| `OVH_<ID>_CLIENT_SECRET`, else `OVH_CLIENT_SECRET` | Service account secret |

Configure an application (three values) or a service account (two values), not
both.

### Rights

Limit the credentials to the zone routes. For an application, request these
rights when creating the consumer key:

```text
GET    /domain/zone
GET    /domain/zone/*
POST   /domain/zone/*/record
PUT    /domain/zone/*/record/*
DELETE /domain/zone/*/record/*
POST   /domain/zone/*/refresh
```

For a service account, an IAM policy with the `dnsZone:apiovh:*` actions the
routes above need (`get`, `export/get`, `soa/get`, `record/get`,
`record/create`, `record/edit`, `record/delete`, `refresh`) on the zones served.

## Reading

`ReadZone` reads the zone in one call, as the zone file OVHcloud exports
(`GET /domain/zone/{zone}/export`), and groups its records by host and type.
Records without their own TTL carry the default TTL of the zone. The apex `NS`
and the `SOA` are read-only `server_managed`. The OVHcloud field types `SPF`,
`DKIM` and `DMARC` are `TXT` records. A zone file the parser refuses is read
record by record instead (one request per record).

Values are in the [canonical form](route53.md#canonical-values) shared by every
provider: targets absolute with a trailing dot (a target OVHcloud stores
without one is relative to the zone and read qualified), `TXT` as its unquoted
content.

## Writing

OVHcloud stores one record per value and has no record set operation. For each
changed RRset, `Apply`:

1. lists and reads its records (`GET /record?fieldType=&subDomain=`, then each
   record) and compares their values with the RRset the change was computed
   against: a difference, or a create whose RRset exists, is a conflict and
   **nothing is written**;
2. deletes, rewrites in place (`PUT`) and creates (`POST`) records, touching
   only those that change;
3. refreshes the zone (`POST /refresh`) once every RRset is written.

| Property | Value |
|---|---|
| Atomic | No: a failure after the first write leaves the zone partially changed (and refreshed); the gate then settles ownership on what it reads back. |
| Conflict detection | Values only: OVHcloud does not return the default TTL of a record, so a TTL changed upstream between the read and the write is not detected. |
| Writable types | `A`, `AAAA`, `CAA`, `CNAME`, `DNAME`, `MX`, `NS` (not at the apex), `PTR`, `SRV`, `SSHFP`, `TLSA`, `TXT` |
| TTL | 60 seconds or more |
| `TXT` | Written quoted, cut in strings of 255 bytes. New records are of field type `TXT`; a rewritten `SPF`, `DKIM` or `DMARC` record keeps its field type. |

## Limitations (v1)

- No URL forwards (OVHcloud redirections are another API) and no alias.
- The cost of a write grows with the number of records of the changed RRsets
  (one read per record), not with the size of the zone.
- The adapter is tested against a fake of the OVHcloud API built from its
  published schema, not against a live account: validate it on a test zone
  before giving it production zones.
