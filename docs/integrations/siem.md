# SIEM and audit export

Every decision of the gate is an audit event, written twice: as a JSON line on
**stdout** (`"type": "audit"`), the stream to ship to a SIEM, and in the **store**,
read by the UI journal, `GET /api/v1/audit` and the MCP `search_audit` tool. Both
copies carry the same `event_id`. The schema, actions and reasons are in the
[audit reference](../AUDIT.md).

```yaml
audit:
  format: ecs        # native (default), ecs (Elastic Common Schema 8.11) or ocsf (OCSF 1.3)
  hash_chain: true   # tamper evidence on every stdout line
```

| Setting | Use it for |
|---|---|
| `audit.format: native` | the gate's own schema ([JSON Schema](../../api/audit-event.schema.json)), any SIEM with a custom parser |
| `audit.format: ecs` | Elastic, OpenSearch and tools reading ECS |
| `audit.format: ocsf` | Amazon Security Lake and OCSF-native tools |
| `audit.hash_chain: true` | a SHA-256 chain per process (`instance_id`, `seq`, `prev_hash`, `hash`), checked by `dns-gate audit verify` |
| `DNS_GATE_AUDIT_CHAIN_KEY` | 32 random bytes (`openssl rand -hex 32`) in the deployment secret: the chain becomes an HMAC that nobody can recompute without the key |

The store and the API always keep the native event; only stdout changes format.

## Verify an export

```sh
dns-gate audit verify export.jsonl                    # or: ... | dns-gate audit verify
dns-gate audit verify -key-file chain.key export.jsonl
```

It reads raw JSON lines, lines wrapped by container log collectors
(`{"log": …}`, `{"message": …}`) and CloudWatch Logs exports, in any order, from any
number of instances, and reports per chain the gaps, altered events, broken links
and duplicates; it exits 1 on any problem. A chain is per process: what it can and
cannot prove is in [tamper evidence](../AUDIT.md#tamper-evidence). Make the sink
append-only (S3 Object Lock, a SIEM with immutable storage).

## AWS Lambda / CloudWatch Logs

`audit_export` exists from version 0.3.0 of the module.

The function writes audit lines to its log group. Platform lines (`START`,
`END`, `REPORT`) and application logs share the group. A subscription filter
keeps only the audit lines:

```
{ $.type = "audit" }
```

With the Terraform module
([terraform-aws-dns-gate](https://github.com/KamorionLabs/terraform-aws-dns-gate)),
set `audit_export` to create the subscription filter towards a Kinesis Data
Firehose stream, a Kinesis data stream or a Lambda function:

```hcl
module "dns_gate" {
  source = "github.com/KamorionLabs/terraform-aws-dns-gate"
  # ...
  audit_export = {
    destination_arn = aws_kinesis_firehose_delivery_stream.audit.arn
  }
}
```

The module creates the IAM role CloudWatch Logs needs for Firehose and Kinesis,
or the invoke permission for a Lambda destination. By hand:

```sh
aws logs put-subscription-filter \
  --log-group-name /aws/lambda/dns-gate \
  --filter-name dns-gate-audit \
  --filter-pattern '{ $.type = "audit" }' \
  --destination-arn arn:aws:firehose:eu-west-3:111122223333:deliverystream/dns-gate-audit \
  --role-arn arn:aws:iam::111122223333:role/dns-gate-audit-subscription
```

Typical destinations:

- **Firehose to S3** for retention: enable the Firehose decompression and
  "message extraction" processors so that objects contain the original JSON
  lines. Then `dns-gate audit verify` and Athena read them directly. Put Object
  Lock (compliance mode) on the bucket.
- **Firehose to a SIEM** (Splunk HEC, Datadog, Elastic, Sumo Logic, or an HTTP
  endpoint): use `audit.format: ecs` for Elastic, or `ocsf` for Amazon Security
  Lake and OCSF-native tools.
- **Kinesis data stream** for your own consumers, or a cross-account
  CloudWatch Logs destination (`aws_cloudwatch_log_destination`) of a central
  logging account.

Without a subscription, `aws logs filter-log-events --log-group-name ...
--filter-pattern '{ $.type = "audit" }' > export.json` gives a document that
`dns-gate audit verify` reads as-is.

## Kubernetes

The gate writes to stdout, and the node's log agent collects it. Route the audit
lines on `type`. With Fluent Bit (Helm chart `fluent/fluent-bit`):

```ini
[INPUT]
    Name              tail
    Path              /var/log/containers/dns-gate-*_dns-gate_*.log
    multiline.parser  cri
    Tag               dnsgate.*

[FILTER]
    Name          parser
    Match         dnsgate.*
    Key_Name      log
    Parser        json
    Reserve_Data  On

[FILTER]
    Name    rewrite_tag
    Match   dnsgate.*
    Rule    $type ^audit$ audit.dnsgate false

[OUTPUT]
    Name   s3
    Match  audit.dnsgate
    bucket dns-gate-audit
    region eu-west-3
    total_file_size 50M
    upload_timeout  5m
    s3_key_format   /audit/%Y/%m/%d/$UUID.jsonl
```

The `parser` filter lifts the gate's JSON to the record root. `rewrite_tag`
moves audit lines to their own tag, which is shipped separately from
application logs: S3, `es`/`opensearch` (with `audit.format: ecs`), `splunk`,
`http`, or `forward` to a central aggregator. Keep the record intact (no
`modify` or `nest` on audit records) if you use the hash chain. To verify
records Fluent Bit stored with its own metadata, pass them as `{"log": ...}`
objects, or extract the original lines first. Vector, Promtail/Alloy and the
OpenTelemetry Collector `filelog` receiver work the same way: parse the JSON,
then route on `type == "audit"`.

## Pull: `GET /api/v1/audit`

For collectors that poll an API. Authenticate as a pipeline or an API key with
`ui.read` on every managed zone. Without it, events of unreadable zones and
events without a zone (authentication failures) are filtered out.

- Results are newest first. `limit` is 1 to 500 (default 50), and `next_cursor`
  continues to older events until it is absent.
- `since` and `until` (RFC 3339, fractional seconds accepted) bound the window.
  Also available: `zone`, `decision`, `category`, `subject`, `host`, `type`.
- Entries carry `event_id` and `auth_method` besides the UI fields (actor,
  teams, action, zone, decision, reason, changes, provider, snapshot).
  `source_ip` and `user_agent` are served only to holders of `policy.read`
  (also in the MCP `search_audit` and `get_rrset` history): other journal
  readers do not see the addresses of other users. `extra` is not served: it
  can hold content, such as zone profile records, that only the audit sink
  keeps. The stdout stream always has every field.

A polling loop: keep a high-water mark `T` (the newest `time` seen). On each
poll, request `since=T - 5m` and follow `next_cursor` until it is absent.
Deduplicate on `event_id`, then move `T` forward. The overlap absorbs clock skew
between replicas and events written while you page. The store keeps events for
`store.audit_retention`.

```sh
since=$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ)
url="https://dns-gate.example.com/api/v1/audit?limit=500&since=$since"
while [ -n "$url" ]; do
  page=$(curl -fsS -H "Authorization: Bearer $TOKEN" "$url")
  echo "$page" | jq -c '.entries[]'
  next=$(echo "$page" | jq -r '.next_cursor // empty')
  url=${next:+"https://dns-gate.example.com/api/v1/audit?limit=500&since=$since&cursor=$next"}
done
```

Pulled entries have no hash chain. Use the stdout stream for tamper evidence.

