# Route53 provider

The `route53` provider fronts the hosted zones of one AWS account (package
`internal/provider/route53`, AWS SDK for Go v2). Declare one provider per AWS
account.

## Configuration

```yaml
providers:
  - id: aws-prod
    kind: route53
    route53:
      region: us-east-1
      assume_role_arn: arn:aws:iam::222222222222:role/dns-gate
      external_id: dns-gate-prod
      hosted_zones:
        example.com: Z0123456789ABCDEFGHIJ
      include_private: false
```

| Field | Default | Description |
|---|---|---|
| `region` | environment, else `us-east-1` | Region of the AWS clients. Route53 is global; the region selects the STS endpoint used for `assume_role_arn`. |
| `assume_role_arn` | | Role assumed with the credentials of the default chain (Lambda or ECS task role, EKS Pod Identity, IRSA, environment). Empty: the default chain is used directly. |
| `external_id` | | `sts:ExternalId` of the assume role call. Requires `assume_role_arn`. |
| `hosted_zones` | `{}` | Pins zone names to hosted zone ids (`Z...` or `/hostedzone/Z...`). A pinned zone is always listed, even when private. Required for every name shared by several visible hosted zones. |
| `include_private` | `false` | Also expose private hosted zones. |

Credentials never live in the file: the gate uses the AWS default credential
chain, optionally followed by `sts:AssumeRole`. The SDK uses the adaptive
retry mode (10 attempts, backoff up to 20 s): `Throttling` and
`PriorRequestNotComplete` are retried with backoff and client-side rate
adaptation.

### Zones

`ListZones` lists the hosted zones (`ListHostedZones`, paginated), keeps the
public ones (and the private ones with `include_private`), and adds the pinned
ones. Two visible hosted zones with the same name (two public zones, or a
public and a private zone with `include_private`) make the listing fail until
the name is pinned in `hosted_zones`. A zone read before any listing is
resolved with `ListHostedZonesByName`, under the same rules. Resolved ids are
cached; a `NoSuchHostedZone` drops the cache entry and returns
`ErrZoneNotFound`.

## Reading

`ReadZone` lists every record set (`ListResourceRecordSets`, paginated, 300 per
page) and groups them by host and type into RRsets sorted by key.

| Upstream | RRset |
|---|---|
| Plain record set | values in canonical form (below), TTL of the set |
| Alias record set | `alias {target, hosted_zone_id, evaluate_target_health}`, TTL 0, no values |
| Apex `NS` and `SOA` | read-only `server_managed` |
| Record sets with `SetIdentifier` (weighted, latency, failover, geolocation, geoproximity, multivalue answer, IP-based), a `HealthCheckId` or a `TrafficPolicyInstanceId` | one read-only `routing_policy` RRset per host and type: union of the values and alias targets of the members, TTL of the first member |

Every RRset keeps the Route53 record sets it was built from in `Native`. They
are what an update or a delete removes, byte for byte.

## Canonical values

`Normalize` returns, and `ReadZone` reads back, the following forms, so that a
desired RRset and the RRset read after the write compare and hash equal.
Values are parsed and printed with [miekg/dns](https://github.com/miekg/dns).

| Type | Canonical value | Example |
|---|---|---|
| host | relative, lowercase, no trailing dot, `@` for the apex, `*` decoded from `\052` | `*.dev` |
| `A` | dotted quad | `192.0.2.1` |
| `AAAA` | RFC 5952 (lowercase, compressed) | `2001:db8::1` |
| `CNAME`, `NS`, `PTR` | lowercase absolute name with trailing dot | `target.example.net.` |
| `MX` | `<preference> <exchange.>` | `10 mail.example.com.` |
| `SRV` | `<priority> <weight> <port> <target.>` | `10 5 5060 sip.example.com.` |
| `CAA` | `<flags> <tag> "<value>"`, tag lowercase | `0 issue "letsencrypt.org"` |
| `DS` | `<key tag> <algorithm> <digest type> <DIGEST>`, digest uppercase | `12345 13 2 ABCD...` |
| `TXT`, `SPF` | unquoted content, one value per record | `v=spf1 -all` |
| alias | target lowercase absolute name, hosted zone id uppercase without `/hostedzone/` | `d111.cloudfront.net.`, `Z2FDTNDATAQYW2` |

- Values are sorted and duplicates removed.
- A name without trailing dot (`CNAME`, `MX`, alias targets...) is absolute,
  as in Route53: `target.example.net` and `target.example.net.` are the same.
- `TXT`: a value written as quoted strings (`"part one " "part two"`) is
  their concatenation. At write time the content is split into 255-byte
  strings, quoted and escaped; at read time the strings of a record are
  joined again, whatever chunking was used to create it. A content that
  itself starts and ends with a double quote cannot be written as such.
  Content can be any bytes; non-printable ones are escaped.
- Escapes inside canonical values follow RFC 1035 (`\DDD`, decimal). Route53
  uses octal escapes (`\052`); the adapter translates both ways.
- Each value is limited to 4000 characters once encoded (Route53 limit).
- TTL: any value in `[0, 2147483647]`. Alias RRsets have no TTL: the TTL
  given is ignored and set to 0.

Writable types: `A`, `AAAA`, `CAA`, `CNAME`, `DS`, `MX`, `NS`, `PTR`, `SPF`,
`SRV`, `TXT`. Refused: `SOA`, apex `NS`, `CNAME` and `DS` at the apex,
wildcard `NS`, a wildcard that is not the whole leftmost label, alias records
of other types than `A` and `AAAA`, a `CNAME` with several values.

## Writing

`Apply` sends one `ChangeResourceRecordSets` request per gate write. Route53
applies the batch atomically.

| Change | Batch |
|---|---|
| create | `CREATE` new |
| update | `DELETE` old exactly as read (`Native`) + `CREATE` new |
| delete | `DELETE` old exactly as read |

`UPSERT` is never used: the exact `DELETE` makes the write conditional.
Route53 rejects the whole batch when a record set to delete is missing or has
changed, or a record set to create already exists; the gate returns
`provider.ErrConflict`, with the Route53 messages. Other rejected batches
are `provider.InvalidError`.

A batch over the Route53 request limits (1000 records, 32000 characters of
values; an update counts its old and new values) is refused before any call
and never split, to stay atomic. Read-only RRsets (`server_managed`,
`routing_policy`) are never deleted or replaced.

`Apply` returns as soon as Route53 accepted the batch (`PENDING`). It does not
wait for `INSYNC`: the change is visible right away through
`ListResourceRecordSets`, and on the Route53 name servers usually within 60
seconds.

## IAM

### Gate role policy

Least privilege for the role the gate uses in the zone account. Hosted zone
ARNs have no account id.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListZones",
      "Effect": "Allow",
      "Action": ["route53:ListHostedZones", "route53:ListHostedZonesByName"],
      "Resource": "*"
    },
    {
      "Sid": "Changes",
      "Effect": "Allow",
      "Action": "route53:GetChange",
      "Resource": "arn:aws:route53:::change/*"
    },
    {
      "Sid": "GatedZones",
      "Effect": "Allow",
      "Action": [
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHIJ",
        "arn:aws:route53:::hostedzone/Z9876543210ABCDEFGHIJ"
      ]
    },
    {
      "Sid": "DenySOA",
      "Effect": "Deny",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringEquals": {"route53:ChangeResourceRecordSetsRecordTypes": ["SOA"]}
      }
    },
    {
      "Sid": "DenyUpsert",
      "Effect": "Deny",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringEquals": {"route53:ChangeResourceRecordSetsActions": ["UPSERT"]}
      }
    },
    {
      "Sid": "DenyApexNS",
      "Effect": "Deny",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringEquals": {
          "route53:ChangeResourceRecordSetsNormalizedRecordNames": ["example.com"],
          "route53:ChangeResourceRecordSetsRecordTypes": ["NS"]
        }
      }
    },
    {
      "Sid": "DenyReservedNames",
      "Effect": "Deny",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringLike": {
          "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
            "_amazonses.example.com",
            "*._domainkey.example.com"
          ]
        }
      }
    }
  ]
}
```

- `GetHostedZone` and `GetChange` are not called by this version; they are
  harmless read actions kept for diagnostics and a future wait for `INSYNC`.
  Remove them for the strictest policy.
- `ListHostedZones` and `ListHostedZonesByName` do not support resource-level
  permissions: the role sees the names and ids of every hosted zone of the
  account, but reads and writes only the listed ones. Pin the zones in
  `hosted_zones` and the gate never needs the listing for them.
- The deny statements are a second line of defense behind the gate policy.
  Normalized record names are lowercase without trailing dot (see the AWS
  documentation for the escaping of other characters). The condition keys
  are multi-valued and evaluated over the whole batch: `DenyApexNS` also
  refuses a batch that changes any apex record together with any `NS`
  delegation. Write them separately, or drop that statement and rely on the
  gate, which never writes the apex `NS`.
- `DenyUpsert` makes the exact-delete contract mandatory: the gate never
  sends `UPSERT`.

### Cross-account

The gate runs in its own account (task role, Pod Identity role...) and
assumes one role per zone account.

Gate role, in the gate account:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::222222222222:role/dns-gate"
}
```

Trust policy of `arn:aws:iam::222222222222:role/dns-gate`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:role/dns-gate-runtime"},
      "Action": "sts:AssumeRole",
      "Condition": {"StringEquals": {"sts:ExternalId": "dns-gate-prod"}}
    }
  ]
}
```

The session name is `dns-gate-<provider id>`, visible in CloudTrail next to
every change.

## Quota

Route53 allows 5 API requests per second per AWS account, shared by every
client of the account: Terraform, external-dns, cert-manager, the console and
the gate. A gate write costs one read of the zone (one request per 300 record
sets), one `ChangeResourceRecordSets` and one confirmation read; the
reconciler reads each managed zone once per interval. Throttled requests are
retried by the SDK with backoff; a write still throttled after 10 attempts
fails without having changed anything. Pinning zones in `hosted_zones` saves
the listing requests.

## Limitations (v1)

- Routing policies (weighted, latency, failover, geolocation, geoproximity,
  multivalue answer, IP-based), health-checked and traffic-policy record sets
  are read-only.
- Alias records are written for `A` and `AAAA` only. Aliases of other types
  are read but cannot be created.
- Writable types are those listed above; `NAPTR`, `SSHFP`, `TLSA`, `SVCB`,
  `HTTPS` can be read but not written.
- The chunking of an existing `TXT` record is not preserved when the gate
  rewrites it (the content is).
- No wait for `INSYNC`; DNSSEC signing and key management are out of scope.
