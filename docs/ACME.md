# ACME / certificates with dns-gate

Three cases, from the most static to the most dynamic.

## 1. Static validation CNAMEs (AWS ACM and similar)

AWS ACM (and other CAs using DNS validation with a fixed token) validates through a
CNAME that does not change between renewals. The Terraform provider covers it, in the
same stack as the certificate:

```hcl
resource "aws_acm_certificate" "www" {
  domain_name       = "www.example.com"
  validation_method = "DNS"
}

resource "eurodns_record_set" "www_validation" {
  for_each = {
    for o in aws_acm_certificate.www.domain_validation_options : o.domain_name => o
  }
  zone   = "example.com"
  host   = trimsuffix(each.value.resource_record_name, ".example.com.")
  type   = each.value.resource_record_type
  ttl    = 600
  values = [each.value.resource_record_value]
}

resource "aws_acm_certificate_validation" "www" {
  certificate_arn         = aws_acm_certificate.www.arn
  validation_record_fqdns = [for o in aws_acm_certificate.www.domain_validation_options : o.resource_record_name]
  depends_on              = [eurodns_record_set.www_validation]
}
```

A role allowing `CNAME` on `_*` and `_*.**` hosts is enough. ACM certificates are
validated through public DNS: the CNAME must be in the public zone.

## 2. Dynamic DNS-01 (Let's Encrypt and other ACME CAs)

### Role

```yaml
roles:
  acme-solver:
    rebase_on_save: true  # clients PUT stale full zones: ignore out-of-scope differences
    ephemeral_ttl: 24h    # challenge RRsets expire and are garbage-collected
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT] }
```

- `rebase_on_save`: clients such as lego read the zone, append a TXT, then PUT the whole zone.
  Without rebase, any change made by someone else in between would make the write
  fail (out-of-scope difference). With rebase, only the TXT change is applied on top
  of the current zone; nothing else can be touched.
- `ephemeral_ttl`: challenge RRsets left behind by a client that did not clean up
  are deleted by the reconciler.

### Clients

| Client | Status |
|---|---|
| **Caddy** (`EuroDNS/libdns-eurodns`) | Works: `api_url` is configurable. Use a virtual key (`app_id` = key id, `api_key` = secret). Note: libdns-eurodns `SetRecords` PUTs a zone containing only the given records; through the gate the deletion of everything else is refused (or ignored with rebase) instead of wiping the zone. |
| **lego** (and Traefik, which embeds it) | EuroDNS provider since v4.33, but no documented base URL override. Needs a small upstream change (e.g. `EURODNS_API_URL`). Then: virtual key + rebase role. |
| **cert-manager** | No EuroDNS support. Planned: `cert-manager-webhook-eurodns`, a webhook solver calling the gate with an OIDC token ([GitHub issues](https://github.com/KamorionLabs/dns-gate/issues)). |
| Other ACME clients | Any client able to call the EuroDNS API with a custom base URL. |

Virtual keys are the weakest credential the gate accepts: restrict them to the
`acme-solver` role, set an expiry and bind them to source CIDRs.

## 3. Recommended: delegate `_acme-challenge` with a CNAME

The least-privilege setup avoids touching the registrar zone at renewal time:

```
_acme-challenge.www.example.com.  CNAME  www.acme.example.net.
```

- The CNAME is created once, through the Terraform provider (or the gate).
- `acme.example.net` is a zone dedicated to challenges (Route 53 with a tightly
  scoped IAM policy, or acme-dns).
- ACME CAs follow the CNAME for DNS-01; cert-manager supports it
  (`cnameStrategy: Follow`), lego supports it natively.
- Renewals never call EuroDNS: no rate-limit pressure, no write access to the main
  zone for the ACME client.

Use the gate's `acme-solver` role when delegation is not possible.
