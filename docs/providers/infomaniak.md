# Infomaniak provider

The `infomaniak` provider fronts the DNS zones of the domains an Infomaniak API
token can manage (package `internal/provider/infomaniak`, API v2
`/2/zones/{zone}/records`).

## Configuration

```yaml
providers:
  - id: ik
    kind: infomaniak
    zones: {include: ["*.ch"]}
    infomaniak:
      zones: [example.ch]        # optional
      rate: {every: 1s}
```

| Field | Default | Description |
|---|---|---|
| `zones` | `[]` | Zones served. Set: the account is not listed. Empty: the gate lists the domains of the account (`GET /1/product?service_name=domain`). |
| `rate.every` | `1s` | Minimum time between two requests to this account (Infomaniak limits a token to 60 requests per minute). `0` keeps the default. |
| `max_retries` | `3` | Retries of a throttled request (429) and of a failed read. |

The whole `infomaniak` block is optional. The API token comes from
`INFOMANIAK_<ID>_TOKEN`, else `INFOMANIAK_TOKEN` (or their `_FILE` variants,
see [Secrets](../CONFIG.md#secrets)). Create it in the
[Infomaniak manager](https://manager.infomaniak.com/v3/infomaniak-api) with the
scopes `domain:read`, `dns:read` and `dns:write`.

## Reading

`ReadZone` lists the records of the zone in one call and groups them by host
and type. The apex `NS` and the `SOA` are read-only `server_managed`. Values
are in the [canonical form](route53.md#canonical-values): the priority, weight,
port, flags and tag Infomaniak returns apart from the target
(`records_description`) are put back in the value, quoted `TXT` targets are
unquoted, targets get their trailing dot.

## Writing

Infomaniak stores one record per value and has no record set operation.
`Apply` reads the zone again and compares TTL and values of each changed RRset
with the one the change was computed against: a difference, or a create whose
RRset exists, is a conflict and **nothing is written**. It then deletes,
rewrites in place (`PUT`) and creates (`POST`) records, touching only those
that change, one request each at the pace of `rate.every`.

| Property | Value |
|---|---|
| Atomic | No: a failure after the first write leaves the zone partially changed; the gate then settles ownership on what it reads back. |
| Writable types | `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS` (not at the apex), `PTR`, `SRV`, `TXT` |
| TTL | 60 seconds or more |
| Targets | Written as Infomaniak shows them: names without trailing dot, `TXT` unquoted, `MX` as `10 mx.example.net`, the apex as source `.` |

## Limitations (v1)

- No URL forwards and no alias.
- **Not verified against the live API.** The Infomaniak developer portal could
  not be read while this adapter was written: endpoints and fields come from
  open-source clients (libdns, lego). The formats of written targets (apex
  source, `MX`, `SRV` and `CAA` targets) and the listing of domains are the
  least certain parts. Validate reads, then each record type you use, on a
  test zone before giving it production zones.
