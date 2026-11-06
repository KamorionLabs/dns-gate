# ACME / certificates with dns-gate

Four cases, from the most static to the most dynamic.

1. [Static validation CNAMEs](#1-static-validation-cnames-aws-acm-and-similar) (AWS ACM): Terraform.
2. [DNS-01 through the gate](#2-dns-01-through-the-gate): certbot, acme.sh, lego,
   Traefik, win-acme, cert-manager and Caddy, unmodified, on any provider behind
   the gate (EuroDNS, Route 53), with no CNAME.
3. [EuroDNS-compatible clients](#3-eurodns-compatible-clients) (Caddy
   libdns-eurodns): API keys or virtual keys on the EuroDNS facade.
4. [Delegating `_acme-challenge` with a CNAME](#4-delegate-_acme-challenge-with-a-cname)
   to a dedicated zone.

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

## 2. DNS-01 through the gate

The gate serves two ACME DNS-01 APIs that existing clients already speak:

| Endpoint | Protocol | Clients |
|---|---|---|
| `POST /acme/httpreq/present`, `POST /acme/httpreq/cleanup` | lego `httpreq` provider (default and RAW modes) | lego, Traefik, certbot and win-acme with a small script |
| `POST /acme/acme-dns/update`, `POST /acme/acme-dns/register` | [acme-dns](https://github.com/joohoi/acme-dns) | acme.sh `dns_acmedns`, the certbot acme-dns hook, certbot-dns-acmedns, cert-manager, Caddy |

Both write the `_acme-challenge.<name>` TXT RRset **of the managed zone itself**:
acme-dns clients normally need a CNAME from `_acme-challenge.<name>` to an acme-dns
server; through the gate they need none, the gate maps the acme-dns subdomain to the
real record. Every write goes through the zone engine, as the caller: RBAC and the
record scope of its role, ownership by its team, the zone lock, protected records
and the audit log apply. Several challenges on one name (a name and its wildcard)
coexist in one TXT RRset; `cleanup` removes one value, the RRset goes with its last
value.

The caller is normally a gate **API key** ([API.md](API.md#api-keys)): no OIDC
needed, bound to a team and a role, revocable, with an expiry and source CIDRs.
OIDC tokens are also accepted on the httpreq endpoints. The endpoints work the same
way on AWS Lambda (API Gateway `$default` route).

### Step 1: roles

```yaml
roles:
  acme-solver:
    ephemeral_ttl: 1h     # required: challenge RRsets expire and are garbage-collected
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT] }

  # who issues keys: gate.apikey.manage on the zones, plus every right the keys get
  certificates-admin:
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write, ui.read, gate.apikey.manage]

bindings:
  - role: certificates-admin
    team: web
    subjects: [{issuer: github, claims: {sub: ["repo:example/certificates:*"]}}]
```

- `ephemeral_ttl` is mandatory for the ACME endpoints (`403 ephemeral_required`
  otherwise): acme-dns has no cleanup call, and a client may die before its cleanup.
  The expiry is pushed back by every write to the RRset, and the reconciler deletes
  expired RRsets (`reconcile_interval`, or the Lambda maintenance schedule).
- The record scope keeps keys on challenge records: a leaked key cannot touch
  anything else.
- A key's rights never exceed those of the identity that created it, which must hold
  `gate.apikey.manage` on the zones of the key role.

### Step 2: an API key

```sh
GATE=https://dns-gate.example.com
curl -sS -H "Authorization: Bearer $TOKEN" -X POST "$GATE/api/v1/api-keys" \
  -H "Content-Type: application/json" -d '{
    "name": "web01 certificates", "team": "web", "role": "acme-solver",
    "expires_at": "2027-06-30T00:00:00Z", "allowed_cidrs": ["192.0.2.10/32"],
    "acme_domains": ["example.com", "www.example.com"]}' > key.json
```

The answer (status 201) holds the key, shown once:

```json
{
  "id": "3f9a0c1b2d4e5f60", "name": "web01 certificates", "team": "web", "role": "acme-solver",
  "key": "dgk_3f9a0c1b2d4e5f60_q8Vx…",
  "acme_dns_accounts": {
    "example.com": {"username": "3f9a0c1b2d4e5f60", "password": "dgk_3f9a0c1b2d4e5f60_q8Vx…",
      "fulldomain": "_acme-challenge.example.com", "subdomain": "0c3e1d2a-…", "allowfrom": []},
    "www.example.com": {"username": "3f9a0c1b2d4e5f60", "password": "dgk_3f9a0c1b2d4e5f60_q8Vx…",
      "fulldomain": "_acme-challenge.www.example.com", "subdomain": "8e5700ea-…", "allowfrom": []}
  }
}
```

- `id` is the user name everywhere (basic authentication, acme-dns `X-Api-User`),
  `key` the password (`X-Api-Key`).
- `acme_domains` creates one acme-dns registration per domain (a wildcard shares the
  registration of its base name). `acme_dns_accounts` is, as is, the storage file of
  the certbot acme-dns hook, the registration file of certbot-dns-acmedns and the
  cert-manager secret.
- Renew the key before `expires_at` with `POST /api/v1/api-keys/{id}/rotate`: the old
  key keeps working during the overlap (24h by default) while clients are updated.

### certbot

Three ways, all with an unmodified certbot.

#### a. Manual hooks with curl (no dependency)

`/etc/letsencrypt/dns-gate.env` (mode 600):

```sh
DNS_GATE=https://dns-gate.example.com
DNS_GATE_KEY_ID=3f9a0c1b2d4e5f60
DNS_GATE_KEY=dgk_3f9a0c1b2d4e5f60_q8Vx…
```

`/etc/letsencrypt/dns-gate-hook.sh` (mode 700), used for both hooks:

```sh
#!/bin/sh
set -eu
. /etc/letsencrypt/dns-gate.env
case "$0" in *cleanup*) action=cleanup ;; *) action=present ;; esac
curl -fsS -u "$DNS_GATE_KEY_ID:$DNS_GATE_KEY" -H "Content-Type: application/json" \
  -d "{\"fqdn\": \"_acme-challenge.${CERTBOT_DOMAIN#\*.}.\", \"value\": \"$CERTBOT_VALIDATION\"}" \
  "$DNS_GATE/acme/httpreq/$action" > /dev/null
[ "$action" = present ] && sleep "${DNS_GATE_PROPAGATION:-30}"
exit 0
```

```sh
ln -s dns-gate-hook.sh /etc/letsencrypt/dns-gate-cleanup.sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook /etc/letsencrypt/dns-gate-hook.sh \
  --manual-cleanup-hook /etc/letsencrypt/dns-gate-cleanup.sh \
  -d example.com -d '*.example.com' -d www.example.com
```

The `sleep` leaves the provider time to serve the record on its name servers
(Route 53 is usually in sync within a minute). Renewals (`certbot renew`) reuse the
hooks.

#### b. The acme-dns hook (acme-dns-certbot-joohoi)

The hook [`acme-dns-auth.py`](https://github.com/joohoi/acme-dns-certbot-joohoi)
reads the account of each domain from a storage file and calls `/update`; it calls
`/register` only for a domain that has no account. The gate does not register
anonymously (`401 registration_requires_api_key`): seed the storage file from the
key instead.

1. Install the hook (it needs python3 and requests) and set its two constants:

   ```python
   ACMEDNS_URL = "https://dns-gate.example.com/acme/acme-dns"
   STORAGE_PATH = "/etc/letsencrypt/acmedns.json"
   ```

2. Create the key with every domain of the certificate in `acme_domains` (step 2),
   then write its accounts as the storage file:

   ```sh
   jq '.acme_dns_accounts' key.json > /etc/letsencrypt/acmedns.json
   chmod 600 /etc/letsencrypt/acmedns.json
   ```

3. Run certbot:

   ```sh
   certbot certonly --manual --preferred-challenges dns \
     --manual-auth-hook /etc/letsencrypt/acme-dns-auth.py \
     -d example.com -d '*.example.com' -d www.example.com
   ```

   For each name, the hook sends `POST /acme/acme-dns/update` with `X-Api-User`,
   `X-Api-Key` and `{"subdomain": "<registration>", "txt": "<value>"}`; the gate
   writes `_acme-challenge.<name>`. There is no CNAME to create.

4. Renewals: `certbot renew`, nothing else. After a key rotation, write the new
   `acme_dns_accounts` of the rotation answer to the storage file.

To add a domain later, add it to the key (`PUT /api/v1/api-keys/{id}` with the full
`acme_domains`, then copy the new subdomain from `GET /api/v1/api-keys/{id}`), or
add an entry whose subdomain is the domain itself, which needs no registration:

```json
"api.example.com": {"username": "3f9a0c1b2d4e5f60", "password": "dgk_…",
  "fulldomain": "_acme-challenge.api.example.com", "subdomain": "api.example.com", "allowfrom": []}
```

#### c. The certbot-dns-acmedns plugin

The [certbot-dns-acmedns](https://github.com/pan-net-security/certbot-dns-acmedns)
plugin reads the same accounts from its registration file:

```ini
# /etc/letsencrypt/acmedns.ini (mode 600)
dns_acmedns_api_url = https://dns-gate.example.com/acme/acme-dns
dns_acmedns_registration_file = /etc/letsencrypt/acmedns.json
```

```sh
jq '.acme_dns_accounts' key.json > /etc/letsencrypt/acmedns.json
certbot certonly -a dns-acmedns --dns-acmedns-credentials /etc/letsencrypt/acmedns.ini \
  --dns-acmedns-propagation-seconds 30 -d example.com -d '*.example.com'
```

### acme.sh

acme.sh's built-in `dns_acmedns` sends `POST $ACMEDNS_BASE_URL/update` with
`X-Api-User`, `X-Api-Key` and `{"subdomain":"$ACMEDNS_SUBDOMAIN", "txt": "<value>"}`,
and checks that the answer contains the value. Through the gate, the subdomain is
the domain of the certificate:

```sh
export ACMEDNS_BASE_URL=https://dns-gate.example.com/acme/acme-dns
export ACMEDNS_USERNAME=3f9a0c1b2d4e5f60
export ACMEDNS_PASSWORD='dgk_3f9a0c1b2d4e5f60_q8Vx…'
export ACMEDNS_SUBDOMAIN=example.com
acme.sh --issue --dns dns_acmedns -d example.com -d '*.example.com'
```

- acme.sh saves the four variables in the domain configuration: renewals need
  nothing else. After a key rotation, run `--issue --force` again with the new
  `ACMEDNS_PASSWORD`, or edit `~/.acme.sh/<domain>/<domain>.conf`.
- Always set `ACMEDNS_USERNAME` and `ACMEDNS_PASSWORD`: without them acme.sh tries an
  anonymous `/register`, which the gate refuses.
- `dns_acmedns` sends one subdomain for every name of the certificate. As with
  acme-dns, one certificate covers one name and its wildcard (both use
  `_acme-challenge.<name>`); issue one certificate per other name, each with its own
  `ACMEDNS_SUBDOMAIN`. A registration subdomain from `acme_dns_accounts` works too.
- As acme-dns does, the gate keeps the two most recent values of a subdomain: enough
  for a name and its wildcard validated together. acme.sh has no cleanup for
  acme-dns; the RRset expires with the `ephemeral_ttl` of the role.

### lego and Traefik

```sh
HTTPREQ_ENDPOINT=https://dns-gate.example.com/acme/httpreq \
HTTPREQ_USERNAME=3f9a0c1b2d4e5f60 \
HTTPREQ_PASSWORD='dgk_3f9a0c1b2d4e5f60_q8Vx…' \
lego --email ops@example.com --dns httpreq -d example.com -d '*.example.com' run
```

`HTTPREQ_MODE=RAW` also works: the gate computes the TXT value from `keyAuth`.
Traefik embeds lego: give it the same variables and
`certificatesResolvers.<name>.acme.dnsChallenge.provider=httpreq`.

### win-acme

win-acme's script validation calls a PowerShell script to create and delete the
record. `C:\ProgramData\dns-gate\dns-gate.ps1`:

```powershell
param([string]$Action, [string]$RecordName, [string]$Token)
$ErrorActionPreference = 'Stop'
$id  = (Get-Content 'C:\ProgramData\dns-gate\key-id.txt' -Raw).Trim()
$key = (Get-Content 'C:\ProgramData\dns-gate\key.txt' -Raw).Trim()
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${id}:${key}"))
$body = @{ fqdn = "$RecordName."; value = $Token } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://dns-gate.example.com/acme/httpreq/$Action" `
  -Headers @{ Authorization = "Basic $auth" } -ContentType 'application/json' -Body $body | Out-Null
if ($Action -eq 'present') { Start-Sleep -Seconds 30 }
```

Restrict the two key files to Administrators and SYSTEM, then:

```bat
wacs.exe --source manual --host example.com,*.example.com ^
  --validationmode dns-01 --validation script ^
  --dnscreatescript C:\ProgramData\dns-gate\dns-gate.ps1 --dnscreatescriptarguments "present {RecordName} {Token}" ^
  --dnsdeletescript C:\ProgramData\dns-gate\dns-gate.ps1 --dnsdeletescriptarguments "cleanup {RecordName} {Token}"
```

win-acme's own acme-dns plugin registers anonymously and expects a CNAME: use the
script validation instead.

### cert-manager

```sh
jq '.acme_dns_accounts' key.json > acmedns.json
kubectl -n cert-manager create secret generic dns-gate-acme-dns --from-file=acmedns.json
```

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef: {name: letsencrypt-account}
    solvers:
      - dns01:
          acmeDNS:
            host: https://dns-gate.example.com/acme/acme-dns
            accountSecretRef: {name: dns-gate-acme-dns, key: acmedns.json}
```

### Caddy

With the [caddy-dns/acmedns](https://github.com/caddy-dns/acmedns) module:

```caddyfile
example.com {
  tls {
    dns acmedns {
      username 3f9a0c1b2d4e5f60
      password {env.DNS_GATE_KEY}
      subdomain example.com
      server_url https://dns-gate.example.com/acme/acme-dns
    }
  }
}
```

### acme-dns compatibility notes

| acme-dns | Through the gate |
|---|---|
| `/register` creates an anonymous account | `401 registration_requires_api_key`. With a key (basic authentication, e.g. `https://<id>:<key>@dns-gate.example.com/acme/acme-dns`, or `X-Api-User`/`X-Api-Key`), `/register` accepts `{"domain": "<name>", "allowfrom": [...]}` (`domain` is a gate extension) and answers `201` with an account whose password is the key. Otherwise accounts come from `acme_domains`. |
| `_acme-challenge.<name>` CNAME to `<subdomain>.<acme-dns zone>` | No CNAME: the registration names the domain, the gate writes `_acme-challenge.<domain>` in its zone. `fulldomain` is that record. |
| `subdomain` is a registration UUID | A registration of the key, or the domain name itself. |
| Two most recent TXT values per subdomain | Same, per registration of the key. Values written by other means (httpreq) are left alone. |
| No cleanup | Same; the RRset expires with the role's `ephemeral_ttl`. |
| `allowfrom` per registration | Same, in addition to the key's `allowed_cidrs`. |
| `X-Api-User` / `X-Api-Key` | Key id / key. They win over basic authentication when both are sent (python requests sends basic authentication taken from the URL). |
| Errors `{"error": "..."}` | Same, with a `message`: `bad_subdomain`, `bad_txt`, `forbidden`, `ephemeral_required`… |

### Security

- A key is a bearer secret: store it like a password (mode 600 files, Kubernetes
  secrets, the Windows key files above). The gate keeps only its SHA-256, compares
  it in constant time and never logs it.
- Give each server its own key, with `allowed_cidrs`, an `expires_at` and a role
  limited to `_acme-challenge` TXT records. Revoke a key with
  `DELETE /api/v1/api-keys/{id}`: it stops working at once.
- Every refused use is audited (`apikey.authenticate`, with the key id and the source
  address), and every write is in the audit log as the key (`api-key:<id>`), with its
  team and the record.

## 3. EuroDNS-compatible clients

Clients of the EuroDNS API with a configurable base URL can use the EuroDNS facade
of the gate (EuroDNS zones only). A gate API key works there (`X-App-Id: <key id>`,
`X-Api-Key: <key>`), as do the static `virtual_keys` of the configuration. Clients
that read the zone, add a TXT and save the whole zone need `rebase_on_save`:

```yaml
roles:
  acme-solver:
    rebase_on_save: true  # clients PUT stale full zones: ignore out-of-scope differences
    ephemeral_ttl: 24h
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT] }
```

- `rebase_on_save`: only the TXT change is applied on top of the current zone;
  anything else the client sends back is ignored instead of refused.
- **Caddy** with `EuroDNS/libdns-eurodns` (`api_url` configurable): `app_id` = key id,
  `api_key` = key. libdns-eurodns `SetRecords` PUTs a zone containing only the given
  records; through the gate the deletion of everything else is refused (or ignored
  with rebase) instead of wiping the zone.

Prefer section 2 for new setups: it works on every provider.

## 4. Delegate `_acme-challenge` with a CNAME

When renewals must not touch the main zone at all:

```
_acme-challenge.www.example.com.  CNAME  www.acme.example.net.
```

- The CNAME is created once, through the Terraform provider (or the gate).
- `acme.example.net` is a zone dedicated to challenges (Route 53 with a tightly
  scoped IAM policy, an acme-dns server, or a zone behind the gate).
- ACME CAs follow the CNAME for DNS-01; cert-manager supports it
  (`cnameStrategy: Follow`), lego supports it natively.
