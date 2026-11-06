# Certificates and third parties

ACME clients prove control of a name with a TXT record at `_acme-challenge.<name>`.
The gate lets them write that record, and nothing else, in any zone it manages, on
any provider, without a provider credential and without a CNAME to a separate
challenge server. It speaks two protocols existing clients already support:

| Endpoint | Protocol | Clients |
|---|---|---|
| `POST /acme/httpreq/present`, `/cleanup` | lego `httpreq` | lego, Traefik, certbot and win-acme hooks |
| `POST /acme/acme-dns/update`, `/register` | acme-dns | acme.sh, certbot acme-dns hooks, cert-manager, Caddy |

## A role for challenges

```yaml
roles:
  acme-solver:
    ephemeral_ttl: 24h             # required: challenge records expire
    rules:
      - zones: ["*"]
        actions: [dns.read, dns.record.write]
        records: {hosts: [_acme-challenge, _acme-challenge.**], types: [TXT]}
```

A name and its wildcard share one TXT record set; each value belongs to the caller
that wrote it, so concurrent clients never remove each other's challenges.

## Pick the credential

| The client runs… | Credential |
|---|---|
| in CI or a workload able to fetch a token per request (certbot or win-acme hooks) | the platform's **OIDC token**, as a bearer token |
| with an identity, but takes one fixed password for the whole run (acme.sh) | a **gate token** from the [token exchange](../api/authenticate.md#exchange-a-token-for-a-gate-token), valid 15 minutes |
| at a third party without an identity provider, or reads a static secret (cert-manager, Caddy, lego) | an **API key** bound to one team and the `acme-solver` role, CIDR-bound, expiring |

## Example: cert-manager with an API key

An administrator (`gate.apikey.manage`) creates the key with the domains it will
validate; the answer carries the acme-dns accounts, shown once:

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" -X POST "$GATE/api/v1/api-keys" \
  -H "Content-Type: application/json" -d '{
    "name": "cluster certificates", "team": "platform", "role": "acme-solver",
    "expires_at": "2027-06-30T00:00:00Z", "allowed_cidrs": ["192.0.2.0/24"],
    "acme_domains": ["example.com", "www.example.com"]}' > key.json

jq '.acme_dns_accounts' key.json > acmedns.json
kubectl -n cert-manager create secret generic dns-gate-acme-dns --from-file=acmedns.json
rm key.json acmedns.json
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

Rotate before expiry (`POST /api/v1/api-keys/{id}/rotate`, the old key works during
an overlap), revoke with `DELETE`. Recipes for acme.sh, certbot, lego, Traefik,
win-acme and Caddy, per platform: the [ACME guide](../ACME.md).

## Other third parties

The same API keys serve any party without an identity provider (a hosting provider,
an appliance): give them a narrow role, an expiry and source CIDRs. A key works on
the gate API, the ACME endpoints and the EuroDNS-compatible API, never manages keys,
and never holds more rights than its creator. API keys are listed, rotated and
revoked by the members of its team holding `gate.apikey.manage`.

Legacy EuroDNS clients that only send `X-APP-ID` / `X-API-KEY` can keep a static
**virtual key** from the configuration instead: the weakest credential, restrict it
to a narrow role with an expiry and CIDRs ([virtual keys](../CONFIG.md#virtual-keys)).
