# Certificates (ACME DNS-01) through dns-gate

ACME clients prove control of a name with a TXT record at
`_acme-challenge.<name>`. dns-gate lets them write that record, and nothing else,
in any zone it manages (Route 53, EuroDNS), without a provider credential and
without a CNAME to a separate challenge server.

The gate speaks two protocols that existing clients already support:

| Endpoint | Protocol | Clients |
|---|---|---|
| `POST /acme/httpreq/present`, `POST /acme/httpreq/cleanup` | lego `httpreq` provider (default and RAW modes) | lego, Traefik, certbot and win-acme hooks (a few lines of curl or PowerShell) |
| `POST /acme/acme-dns/update`, `POST /acme/acme-dns/register` | [acme-dns](https://github.com/joohoi/acme-dns) | acme.sh `dns_acmedns`, the certbot acme-dns hook, certbot-dns-acmedns, cert-manager, Caddy |

Every write goes through the zone engine as the caller: the record scope of its
role, ownership by its team, the zone lock, protected records and the audit log
apply. A name and its wildcard are validated together: their values coexist in one
TXT RRset (at most `acme.max_values`, 10 by default), and each value belongs to the
caller that wrote it: only that caller removes it. The endpoints work the same way
on AWS Lambda.

Contents:

1. [Choose your credential](#1-choose-your-credential)
2. [Set up the gate](#2-set-up-the-gate)
3. [Recipes by platform](#3-recipes-by-platform): GitHub Actions, GitLab CI,
   Kubernetes, Azure, AWS
4. [Clients](#4-clients): acme.sh, certbot, lego and Traefik, win-acme, cert-manager,
   Caddy
5. [acme-dns compatibility](#5-acme-dns-compatibility)
6. [Security](#6-security)
7. [Other certificate setups](#7-other-certificate-setups): static validation
   CNAMEs (AWS ACM), EuroDNS API clients, CNAME delegation

## 1. Choose your credential

| The ACME client runs… | Credential | Why |
|---|---|---|
| in a CI job or a workload that can fetch an OIDC token for each request (certbot or win-acme hooks) | **the OIDC token, directly** (`Authorization: Bearer`) | Nothing to store, nothing to rotate. |
| with an identity, but the client takes one fixed password for the whole run (acme.sh `dns_acmedns`), or the run outlives the OIDC token | **token exchange**: trade the OIDC token for a gate token valid 15 minutes | Same identity and rights, a lifetime that fits the run, still nothing to store. |
| at a third party without an identity provider (hosting provider, appliance, a server outside your clouds), or in a client that reads a static secret (cert-manager, Caddy, lego) | **API key** | Bound to one team and one role, hashed, expiring, CIDR-bound, rotated and revoked through the API. |

OIDC tokens and gate tokens carry the identity of the job or workload: the subject
is bound to a role like any other caller, and the audit log names the repository,
service account or managed identity. Prefer them; API keys are the fallback for
parties that have no identity provider.

The token exchange, `POST /api/v1/token-exchange` (RFC 8693), takes a token of an
issuer with `token_exchange: true`, validates it exactly as a bearer token
(signature, audience, `bound_claims`, bindings) and answers a token signed by the
gate with the same identity, valid 15 minutes. `expires_in` asks for another
lifetime, within the issuer's `max_exchanged_ttl` (15 minutes by default), the gate
issuer's `token_ttl`, and 5 minutes past the expiry of the exchanged token. Gate
tokens and API keys are never exchanged, and an exchanged token stops working if its
issuer is no longer opted in.

```sh
GATE=https://dns-gate.example.com
GATE_TOKEN=$(curl -fsS "$GATE/api/v1/token-exchange" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode "subject_token=$OIDC_TOKEN" | jq -r .access_token)
```

## 2. Set up the gate

### A role for challenges

```yaml
roles:
  acme-solver:
    ephemeral_ttl: 1h     # required: challenge RRsets expire and are garbage-collected
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT] }
```

- `ephemeral_ttl` is required by the ACME endpoints (`403 ephemeral_required`
  otherwise): acme-dns has no cleanup call, and a client may die before its cleanup.
  Adding a value pushes the expiry back, never beyond the creation of the RRset plus
  `limits.ephemeral_lifetime_factor` (4) TTLs; the reconciler deletes expired RRsets
  (`reconcile_interval`, or the Lambda maintenance schedule). A caller that also
  holds a permanent write role is refused: bind the ACME identity to this role only.
- The record scope keeps the caller on challenge records: a leaked credential cannot
  touch anything else.

### For OIDC tokens and the token exchange

Declare the issuer, opt it in to the exchange, bind the identity to the role. The
exchange needs a gate issuer (`self: true`) and its signing key
(`DNS_GATE_TOKEN_SIGNING_KEY`, see [CONFIG.md](CONFIG.md#gate-issued-tokens)).

```yaml
issuers:
  - name: github
    issuer: https://token.actions.githubusercontent.com
    audiences: [dns-gate]
    token_exchange: true          # off by default
  - name: gate
    self: true
    issuer: https://dns-gate.example.com
    # token_ttl: 1h               # also caps exchanged tokens

bindings:
  - role: acme-solver
    team: web
    subjects:
      - issuer: github
        claims: {sub: ["repo:example/certificates:ref:refs/heads/main"]}
```

### For API keys

An identity holding `gate.apikey.manage` on the zones (and every right the key
gets) creates the key:

```yaml
roles:
  certificates-admin:
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write, ui.read, gate.apikey.manage]
bindings:
  - role: certificates-admin
    team: web
    subjects: [{issuer: github, claims: {sub: ["repo:example/dns-admin:*"]}}]
```

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" -X POST "$GATE/api/v1/api-keys" \
  -H "Content-Type: application/json" -d '{
    "name": "web01 certificates", "team": "web", "role": "acme-solver",
    "expires_at": "2027-06-30T00:00:00Z", "allowed_cidrs": ["192.0.2.10/32"],
    "acme_domains": ["example.com", "www.example.com"]}' > key.json
```

The answer holds the key, shown once:

```json
{
  "id": "3f9a0c1b2d4e5f60", "team": "web", "role": "acme-solver",
  "key": "dgk_3f9a0c1b2d4e5f60_q8Vx…",
  "acme_dns_accounts": {
    "www.example.com": {"username": "3f9a0c1b2d4e5f60", "password": "dgk_3f9a0c1b2d4e5f60_q8Vx…",
      "fulldomain": "_acme-challenge.www.example.com", "subdomain": "8e5700ea-…", "allowfrom": []}
  }
}
```

- `id` is the user name everywhere (basic authentication, acme-dns `X-Api-User`),
  `key` the password (`X-Api-Key`).
- `acme_domains` creates one acme-dns registration per domain (a wildcard shares the
  registration of its base name); `acme_dns_accounts` is, as is, the storage file of
  the certbot acme-dns hook, the registration file of certbot-dns-acmedns and the
  cert-manager secret.
- Rotate before `expires_at` with `POST /api/v1/api-keys/{id}/rotate`: the old key
  keeps working during the overlap (24h by default). Revoke with
  `DELETE /api/v1/api-keys/{id}`. See [API.md](API.md#api-keys).

## 3. Recipes by platform

Each recipe gets an OIDC token whose audience is the gate, then runs acme.sh with
the exchanged token and certbot with the [hook](#hooks-with-curl-tokens-and-api-keys)
reading `DNS_GATE_TOKEN`. Bind the token's subject to `acme-solver` as in
[section 2](#for-oidc-tokens-and-the-token-exchange); each recipe gives the issuer
and the subject to bind. `exchange` is the token exchange above as a shell function,
kept for instance in `scripts/exchange.sh`:

```sh
exchange() {
  curl -fsS "$GATE/api/v1/token-exchange" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
    --data-urlencode "subject_token=$1" | jq -r .access_token
}
```

Certificates issued by a job must be stored somewhere (a secret manager, a load
balancer); renewals are new runs of the job, on a schedule.

### GitHub Actions

Issuer `https://token.actions.githubusercontent.com`, subject
`repo:<owner>/<repo>:ref:refs/heads/<branch>` (or
`repo:<owner>/<repo>:environment:<name>` with environments).

```yaml
on:
  schedule: [{cron: "17 3 * * 1"}]
permissions:
  id-token: write
  contents: read
jobs:
  certificates:
    runs-on: ubuntu-latest
    env:
      GATE: https://dns-gate.example.com
    steps:
      - uses: actions/checkout@v4
      - name: OIDC token for the gate
        run: |
          token=$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=dns-gate" | jq -r .value)
          echo "::add-mask::$token"
          echo "OIDC_TOKEN=$token" >> "$GITHUB_ENV"
      - name: acme.sh
        run: |
          curl -fsS https://get.acme.sh | sh -s email=ops@example.com
          . scripts/exchange.sh
          export ACMEDNS_BASE_URL=$GATE/acme/acme-dns ACMEDNS_USERNAME=oidc ACMEDNS_SUBDOMAIN=example.com
          export ACMEDNS_PASSWORD=$(exchange "$OIDC_TOKEN")
          ~/.acme.sh/acme.sh --issue --dns dns_acmedns -d example.com -d '*.example.com'
      - name: certbot
        run: |
          sudo apt-get install -y certbot
          sudo DNS_GATE=$GATE DNS_GATE_TOKEN=$OIDC_TOKEN certbot certonly --manual \
            --preferred-challenges dns --non-interactive --agree-tos -m ops@example.com \
            --manual-auth-hook "$PWD/scripts/dns-gate-hook.sh" \
            --manual-cleanup-hook "$PWD/scripts/dns-gate-hook.sh" -d www.example.com
```

GitHub tokens are short-lived: for long certbot runs, exchange the token first
(`DNS_GATE_TOKEN=$(exchange "$OIDC_TOKEN")`).

### GitLab CI

Issuer `https://gitlab.com` (or your instance URL), subject
`project_path:<group>/<project>:ref_type:branch:ref:<branch>`.

```yaml
certificates:
  image: alpine:3.20
  id_tokens:
    OIDC_TOKEN:
      aud: dns-gate
  variables:
    GATE: https://dns-gate.example.com
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - apk add --no-cache curl jq openssl certbot
    - curl -fsS https://get.acme.sh | sh -s email=ops@example.com
    - . scripts/exchange.sh
    - export ACMEDNS_BASE_URL=$GATE/acme/acme-dns ACMEDNS_USERNAME=oidc ACMEDNS_SUBDOMAIN=example.com
    - export ACMEDNS_PASSWORD=$(exchange "$OIDC_TOKEN")
    - ~/.acme.sh/acme.sh --issue --dns dns_acmedns -d example.com -d '*.example.com'
    - >
      DNS_GATE=$GATE DNS_GATE_TOKEN=$OIDC_TOKEN certbot certonly --manual
      --preferred-challenges dns --non-interactive --agree-tos -m ops@example.com
      --manual-auth-hook "$PWD/scripts/dns-gate-hook.sh"
      --manual-cleanup-hook "$PWD/scripts/dns-gate-hook.sh" -d www.example.com
```

### Kubernetes (projected service account token)

Issuer: the cluster OIDC issuer (EKS: `https://oidc.eks.<region>.amazonaws.com/id/<id>`;
any cluster: `kubectl get --raw /.well-known/openid-configuration`), subject
`system:serviceaccount:<namespace>:<service account>`. A CronJob mounts a token for
the gate audience; kubelet renews the file.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: {name: certificates, namespace: certificates}
spec:
  schedule: "17 3 * * 1"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: certificates
          restartPolicy: Never
          containers:
            - name: acme
              image: registry.example.com/acme-tools:1.0   # acme.sh, certbot, curl, jq, the scripts
              env:
                - {name: GATE, value: https://dns-gate.example.com}
              command: ["/bin/sh", "-ec"]
              args:
                - |
                  . /scripts/exchange.sh
                  OIDC_TOKEN=$(cat /var/run/secrets/dns-gate/token)
                  ACMEDNS_BASE_URL=$GATE/acme/acme-dns ACMEDNS_USERNAME=oidc ACMEDNS_SUBDOMAIN=example.com \
                  ACMEDNS_PASSWORD=$(exchange "$OIDC_TOKEN") \
                    acme.sh --issue --dns dns_acmedns -d example.com -d '*.example.com'
                  DNS_GATE=$GATE DNS_GATE_TOKEN=$OIDC_TOKEN certbot certonly --manual \
                    --preferred-challenges dns --non-interactive --agree-tos -m ops@example.com \
                    --manual-auth-hook /scripts/dns-gate-hook.sh --manual-cleanup-hook /scripts/dns-gate-hook.sh \
                    -d www.example.com
              volumeMounts:
                - {name: dns-gate-token, mountPath: /var/run/secrets/dns-gate, readOnly: true}
          volumes:
            - name: dns-gate-token
              projected:
                sources:
                  - serviceAccountToken: {path: token, audience: dns-gate, expirationSeconds: 3600}
```

In a cluster, cert-manager is usually the better client; its acmeDNS solver reads a
static secret, so it uses an [API key](#cert-manager).

### Azure (managed identity, AKS workload identity)

Issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`, configured as in
[CONFIG.md](CONFIG.md#entra-id); bind on the `oid` of the managed identity. The
token audience is the gate app registration (`api://dns-gate`).

```sh
# VM, App Service, Container Apps, Functions (managed identity)
OIDC_TOKEN=$(curl -fsS -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://dns-gate" \
  | jq -r .access_token)

# AKS workload identity, Azure DevOps (workload identity federation), any az login
OIDC_TOKEN=$(az account get-access-token --scope api://dns-gate/.default --query accessToken -o tsv)

ACMEDNS_BASE_URL=$GATE/acme/acme-dns ACMEDNS_USERNAME=oidc ACMEDNS_SUBDOMAIN=example.com \
ACMEDNS_PASSWORD=$(exchange "$OIDC_TOKEN") \
  acme.sh --issue --dns dns_acmedns -d example.com -d '*.example.com'

DNS_GATE=$GATE DNS_GATE_TOKEN=$OIDC_TOKEN certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook /etc/letsencrypt/dns-gate-hook.sh --manual-cleanup-hook /etc/letsencrypt/dns-gate-hook.sh \
  -d www.example.com
```

On Windows servers with a managed identity, the [win-acme script](#win-acme) fetches
the token the same way.

### AWS (outbound identity federation)

IAM outbound identity federation signs tokens for the calling role
(`sts:GetWebIdentityToken`), from EC2, ECS, Lambda, CodeBuild: anything with an IAM
role allowed that action. Issuer: the URL given by
`aws iam get-outbound-web-identity-federation-info`; subject: the role ARN.

```yaml
issuers:
  - name: aws
    issuer: https://<id>.tokens.sts.global.api.aws   # from get-outbound-web-identity-federation-info
    audiences: [dns-gate]
    token_exchange: true
bindings:
  - role: acme-solver
    team: web
    subjects: [{issuer: aws, claims: {sub: ["arn:aws:iam::111122223333:role/certificates"]}}]
```

```sh
OIDC_TOKEN=$(aws sts get-web-identity-token --audience dns-gate --signing-algorithm ES384 \
  --query WebIdentityToken --output text)

ACMEDNS_BASE_URL=$GATE/acme/acme-dns ACMEDNS_USERNAME=oidc ACMEDNS_SUBDOMAIN=example.com \
ACMEDNS_PASSWORD=$(exchange "$OIDC_TOKEN") \
  acme.sh --issue --dns dns_acmedns -d example.com -d '*.example.com'

DNS_GATE=$GATE DNS_GATE_TOKEN=$OIDC_TOKEN certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook /etc/letsencrypt/dns-gate-hook.sh --manual-cleanup-hook /etc/letsencrypt/dns-gate-hook.sh \
  -d www.example.com
```

## 4. Clients

### acme.sh

The built-in `dns_acmedns` sends `POST $ACMEDNS_BASE_URL/update` with
`X-Api-User: $ACMEDNS_USERNAME`, `X-Api-Key: $ACMEDNS_PASSWORD` and
`{"subdomain":"$ACMEDNS_SUBDOMAIN", "txt": "<value>"}`, and checks that the answer
contains the value.

| Variable | With a token | With an API key |
|---|---|---|
| `ACMEDNS_BASE_URL` | `https://dns-gate.example.com/acme/acme-dns` | same |
| `ACMEDNS_USERNAME` | any non-empty value, e.g. `oidc` | the key id |
| `ACMEDNS_PASSWORD` | the exchanged gate token (or an OIDC token that outlives the run) | the key |
| `ACMEDNS_SUBDOMAIN` | the domain of the certificate (`example.com`) | the domain, or its registration from `acme_dns_accounts` |

```sh
acme.sh --issue --dns dns_acmedns -d example.com -d '*.example.com'
```

- `dns_acmedns` sends one subdomain for every name of a certificate. As with
  acme-dns, a certificate covers one name and its wildcard (both use
  `_acme-challenge.<name>`); issue one certificate per other name.
- The gate keeps the two most recent values per subdomain, as acme-dns does (per
  subject and domain with a token): enough for a name and its wildcard. acme.sh has
  no cleanup for acme-dns; the RRset expires with the role's `ephemeral_ttl`.
- Always set `ACMEDNS_USERNAME` and `ACMEDNS_PASSWORD`: without them acme.sh tries an
  anonymous `/register`, which the gate refuses.
- acme.sh saves the variables in the domain configuration. With an API key,
  renewals (`acme.sh --cron`) need nothing else; with a token, set them again at each
  run, the saved token having expired.

### certbot

#### Hooks with curl (tokens and API keys)

One script serves as `--manual-auth-hook` and `--manual-cleanup-hook` (certbot sets
`CERTBOT_AUTH_OUTPUT` for the cleanup only). It sends `DNS_GATE_TOKEN` when set,
else the API key of `/etc/letsencrypt/dns-gate.env` (mode 600: `DNS_GATE`,
`DNS_GATE_KEY_ID`, `DNS_GATE_KEY`). Save it as `dns-gate-hook.sh` (mode 700):

```sh
#!/bin/sh
set -eu
[ -f /etc/letsencrypt/dns-gate.env ] && . /etc/letsencrypt/dns-gate.env
action=present
[ -n "${CERTBOT_AUTH_OUTPUT+x}" ] && action=cleanup
if [ -n "${DNS_GATE_TOKEN:-}" ]; then
  auth="Authorization: Bearer $DNS_GATE_TOKEN"
else
  auth="Authorization: Basic $(printf %s "$DNS_GATE_KEY_ID:$DNS_GATE_KEY" | base64 | tr -d '\n')"
fi
curl -fsS -H "$auth" -H "Content-Type: application/json" \
  -d "{\"fqdn\": \"_acme-challenge.${CERTBOT_DOMAIN#\*.}.\", \"value\": \"$CERTBOT_VALIDATION\"}" \
  "$DNS_GATE/acme/httpreq/$action" > /dev/null
if [ "$action" = present ]; then sleep "${DNS_GATE_PROPAGATION:-30}"; fi
```

```sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook /etc/letsencrypt/dns-gate-hook.sh \
  --manual-cleanup-hook /etc/letsencrypt/dns-gate-hook.sh \
  -d example.com -d '*.example.com' -d www.example.com
```

The `sleep` leaves the provider time to serve the record on its name servers
(Route 53 is usually in sync within a minute). `certbot renew` reuses the hooks.

#### The acme-dns hook (API keys)

The hook [`acme-dns-auth.py`](https://github.com/joohoi/acme-dns-certbot-joohoi)
reads the account of each domain from a storage file and calls `/update`; it calls
`/register` only for a domain without account, which the gate refuses
(`401 registration_requires_api_key`). Seed the storage file from the key:

1. Install the hook (python3 and requests) and set its constants:
   `ACMEDNS_URL = "https://dns-gate.example.com/acme/acme-dns"`,
   `STORAGE_PATH = "/etc/letsencrypt/acmedns.json"`.
2. Create the key with every domain in `acme_domains`, then
   `jq '.acme_dns_accounts' key.json > /etc/letsencrypt/acmedns.json` (mode 600).
3. Run `certbot certonly --manual --preferred-challenges dns --manual-auth-hook /etc/letsencrypt/acme-dns-auth.py -d example.com -d '*.example.com'`.
   There is no CNAME to create.
4. After a rotation, write the new `acme_dns_accounts` to the storage file.

To add a domain, add it to the key's `acme_domains` (`PUT /api/v1/api-keys/{id}`)
and copy its subdomain from `GET /api/v1/api-keys/{id}`, or add an entry whose
subdomain is the domain itself, which needs no registration:

```json
"api.example.com": {"username": "3f9a0c1b2d4e5f60", "password": "dgk_…",
  "fulldomain": "_acme-challenge.api.example.com", "subdomain": "api.example.com", "allowfrom": []}
```

#### certbot-dns-acmedns (API keys)

The [certbot-dns-acmedns](https://github.com/pan-net-security/certbot-dns-acmedns)
plugin reads the same storage file:

```ini
# /etc/letsencrypt/acmedns.ini (mode 600)
dns_acmedns_api_url = https://dns-gate.example.com/acme/acme-dns
dns_acmedns_registration_file = /etc/letsencrypt/acmedns.json
```

```sh
certbot certonly -a dns-acmedns --dns-acmedns-credentials /etc/letsencrypt/acmedns.ini \
  --dns-acmedns-propagation-seconds 30 -d example.com -d '*.example.com'
```

### lego and Traefik

```sh
HTTPREQ_ENDPOINT=https://dns-gate.example.com/acme/httpreq \
HTTPREQ_USERNAME=3f9a0c1b2d4e5f60 HTTPREQ_PASSWORD='dgk_3f9a0c1b2d4e5f60_q8Vx…' \
lego --email ops@example.com --dns httpreq -d example.com -d '*.example.com' run
```

lego's httpreq provider sends basic authentication only, hence an API key.
`HTTPREQ_MODE=RAW` also works: the gate computes the TXT value from `keyAuth`.
Traefik embeds lego: give it the same variables and
`certificatesResolvers.<name>.acme.dnsChallenge.provider=httpreq`.

### win-acme

win-acme's script validation calls a PowerShell script to create and delete the
record. `C:\ProgramData\dns-gate\dns-gate.ps1`, with an API key:

```powershell
param([string]$Action, [string]$RecordName, [string]$Token)
$ErrorActionPreference = 'Stop'
$id  = (Get-Content 'C:\ProgramData\dns-gate\key-id.txt' -Raw).Trim()
$key = (Get-Content 'C:\ProgramData\dns-gate\key.txt' -Raw).Trim()
$auth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${id}:${key}"))
$body = @{ fqdn = "$RecordName."; value = $Token } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://dns-gate.example.com/acme/httpreq/$Action" `
  -Headers @{ Authorization = $auth } -ContentType 'application/json' -Body $body | Out-Null
if ($Action -eq 'present') { Start-Sleep -Seconds 30 }
```

Restrict the key files to Administrators and SYSTEM. On an Azure VM with a managed
identity, use a token instead of the key files:

```powershell
$mi = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://dns-gate'
$auth = 'Bearer ' + (Invoke-RestMethod -Headers @{ Metadata = 'true' } -Uri $mi).access_token
```

```bat
wacs.exe --source manual --host example.com,*.example.com ^
  --validationmode dns-01 --validation script ^
  --dnscreatescript C:\ProgramData\dns-gate\dns-gate.ps1 --dnscreatescriptarguments "present {RecordName} {Token}" ^
  --dnsdeletescript C:\ProgramData\dns-gate\dns-gate.ps1 --dnsdeletescriptarguments "cleanup {RecordName} {Token}"
```

win-acme's own acme-dns plugin registers anonymously and expects a CNAME: use the
script validation instead.

### cert-manager

cert-manager's acmeDNS solver reads its accounts from a secret, hence an API key:

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

With the [caddy-dns/acmedns](https://github.com/caddy-dns/acmedns) module and an API
key:

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

## 5. acme-dns compatibility

| acme-dns | Through the gate |
|---|---|
| `_acme-challenge.<name>` CNAME to `<subdomain>.<acme-dns zone>` | No CNAME: the gate writes `_acme-challenge.<domain>` in its zone. `fulldomain` is that record. |
| `subdomain` is a registration UUID | A registration of an API key, or the domain name itself (the only form with a token). |
| `X-Api-User` / `X-Api-Key` | Key id / key, or any value / a token. They win over basic authentication when both are sent (python requests sends basic authentication taken from the URL). `Authorization: Bearer` also works. |
| `/register` creates an anonymous account | `401 registration_requires_api_key`. With an API key (basic authentication, e.g. `https://<id>:<key>@dns-gate.example.com/acme/acme-dns`, or `X-Api-User`/`X-Api-Key`), `{"domain": "<name>", "allowfrom": [...]}` (`domain` is a gate extension) answers `201` with an account whose password is the key. Tokens cannot register (`403`). |
| Two most recent TXT values per subdomain | Same, per registration (per subject and domain with a token). Values written by other means (httpreq) are left alone. Registrations and their values are saved only once the record is written. |
| No cleanup | Same; the RRset expires with the role's `ephemeral_ttl`. |
| `allowfrom` per registration | Stricter: for a key and a domain, the address must be allowed by every registration of that key for that domain that has an `allowfrom`, whatever the subdomain used (a registration UUID or the domain name). On top of the key's `allowed_cidrs`. |
| Unlimited registrations | At most `acme.max_registrations` (100) per key or token subject (`409 too_many_registrations`); those of token subjects are purged after `acme.registration_idle` (30 days) without use. |
| Errors `{"error": "..."}` | Same, with a `message`: `bad_subdomain`, `bad_txt`, `forbidden`, `ephemeral_required`… |

## 6. Security

- Prefer tokens: nothing to store or rotate, and the audit log names the
  repository, service account or role. An exchanged token lasts 15 minutes at most
  by default, never much longer than the token it replaces, and only the issuers you
  opt in can be exchanged.
- An API key is a bearer secret: store it like a password (mode 600 files,
  Kubernetes secrets, the Windows key files above). The gate keeps only its
  SHA-256, compares it in constant time and never logs it. Give each server its own
  key, with `allowed_cidrs` and `expires_at`; revoke it with
  `DELETE /api/v1/api-keys/{id}`.
- Whatever the credential, the role limits it to `_acme-challenge` TXT records of
  the zones you list: enough to obtain certificates for those names, nothing else.
  A key never outgrows its issuer (rights, ephemeral TTL, change limit), and stops
  working if its role later grants more than at issuance (`403 role_widened`).
- Exchanges (`gate.token.exchange`), refused API keys (`apikey.authenticate`; unknown
  or malformed keys are counted per address and minute) and every write are in the
  audit log, with the subject, team and record.

## 7. Other certificate setups

### Static validation CNAMEs (AWS ACM)

AWS ACM (and other CAs using DNS validation with a fixed token) validates through a
CNAME that does not change between renewals: create it with the Terraform provider,
in the same stack as the certificate.

```hcl
resource "aws_acm_certificate" "www" {
  domain_name       = "www.example.com"
  validation_method = "DNS"
}

resource "dnsgate_record_set" "www_validation" {
  for_each = {
    for o in aws_acm_certificate.www.domain_validation_options : o.domain_name => o
  }
  zone   = "example.com"
  name   = trimsuffix(each.value.resource_record_name, ".example.com.")
  type   = each.value.resource_record_type
  ttl    = 600
  values = [each.value.resource_record_value]
}

resource "aws_acm_certificate_validation" "www" {
  certificate_arn         = aws_acm_certificate.www.arn
  validation_record_fqdns = [for o in aws_acm_certificate.www.domain_validation_options : o.resource_record_name]
  depends_on              = [dnsgate_record_set.www_validation]
}
```

A role allowing `CNAME` on `_*` and `_*.**` hosts is enough. ACM validates through
public DNS: the CNAME must be in the public zone.

### EuroDNS API clients

Clients of the EuroDNS API with a configurable base URL can use the
EuroDNS-compatible API of the gate, for EuroDNS zones only, with an API key
(`X-App-Id: <key id>`, `X-Api-Key: <key>`) or a static virtual key. Clients that
read the zone, add a TXT and save the whole zone (Caddy with `EuroDNS/libdns-eurodns`)
need `rebase_on_save: true` on their role: only the TXT change is applied on top of
the current zone, anything else they send back is ignored instead of refused.
Prefer the endpoints above: they work on every provider.

### Delegating `_acme-challenge` with a CNAME

When renewals must not touch the main zone at all, point
`_acme-challenge.www.example.com` to a zone dedicated to challenges (a Route 53 zone
with a narrow IAM policy, an acme-dns server, or a zone behind the gate). The CNAME
is created once, through Terraform or the gate; ACME CAs follow it, cert-manager
with `cnameStrategy: Follow`, lego natively.
