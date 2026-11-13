# Configuration reference

dns-gate reads one YAML file (`-config`, default `/etc/dns-gate/config.yaml`, or `DNS_GATE_CONFIG_URI` / `DNS_GATE_CONFIG`): a file path, `s3://bucket/key` or `ssm:/parameter/name`. Decoding is strict: an unknown field stops the gate at startup. Durations are Go durations (`90s`, `24h`) or a whole number of days (`14d`). `dns-gate -check -config file.yaml` validates a file and exits.

A complete example is in [`examples/config.yaml`](../examples/config.yaml); a small one runs the [Quickstart](quickstart.md).

| Page | Sections |
|---|---|
| This page | [secrets](#secrets), [top level and limits](#top-level), [store](#store), [audit](#audit), [propagation check](#propagation-check) |
| [Providers, discovery and folders](config/providers.md) | `providers`, zone discovery, EuroDNS folders, zone profiles |
| [Issuers and keys](config/authentication.md) | `issuers`, gate-issued tokens, token exchange, delegated clients and scopes, `oauth.clients`, Entra ID, Azure DevOps, `virtual_keys` |
| [Roles, teams and bindings](config/policy.md) | `roles`, URL forward rules, `groups`, `teams`, `ownership`, `bindings`, `team_from`, `protected`, adoption and Terraform export |
| [Managed policy and delegations](config/managed-policy.md) | `policy`: the UI-edited layer, `policy.delegations` and the delegation API |
| [Web UI and MCP](config/ui-mcp.md) | `ui`, SAML login, `mcp`, connecting assistants |

## Secrets

Secrets never live in the YAML file. Each one is read from an environment variable, or from the file named by the same variable with a `_FILE` suffix (the form to use with Kubernetes Secret volumes).

| Variable | Used for | Required |
|---|---|---|
| `EURODNS_<ID>_API_KEY`, else `EURODNS_API_KEY` | EuroDNS `X-API-KEY` of the provider `<ID>` | with a `eurodns` provider |
| `EURODNS_<ID>_APP_ID`, else `EURODNS_APP_ID` | EuroDNS `X-APP-ID`, overrides `eurodns.app_id` | if `eurodns.app_id` is empty |
| `OVH_<ID>_APPLICATION_KEY`, `OVH_<ID>_APPLICATION_SECRET`, `OVH_<ID>_CONSUMER_KEY`, or `OVH_<ID>_CLIENT_ID`, `OVH_<ID>_CLIENT_SECRET` (else without `_<ID>`) | OVHcloud application or service account ([providers/ovh.md](providers/ovh.md)) | with an `ovh` provider |
| `SCALEWAY_<ID>_SECRET_KEY`, else `SCALEWAY_SECRET_KEY`, else `SCW_SECRET_KEY` | Scaleway API secret key ([providers/scaleway.md](providers/scaleway.md)) | with a `scaleway` provider |
| `INFOMANIAK_<ID>_TOKEN`, else `INFOMANIAK_TOKEN` | Infomaniak API token ([providers/infomaniak.md](providers/infomaniak.md)) | with an `infomaniak` provider |
| `AZURE_<ID>_CLIENT_SECRET`, else `AZURE_CLIENT_SECRET` | Client secret of the Entra application ([providers/azure.md](providers/azure.md)) | with an `azure` provider without federated token nor managed identity |
| `DNS_GATE_POSTGRES_DSN` | Postgres connection string | with `store.type: postgres` |
| `DNS_GATE_SESSION_KEY` | 32-byte key (hex or base64) encrypting UI cookies | with `ui.enabled` |
| `DNS_GATE_UI_CLIENT_SECRET` | OIDC client secret of the UI | no (public client with PKCE) |
| `DNS_GATE_SAML_SP_KEY`, `DNS_GATE_SAML_SP_CERT` | PEM key (RSA or ECDSA) and certificate of the SAML service provider, signing the AuthnRequests | no (unsigned requests) |
| `DNS_GATE_TOKEN_SIGNING_KEY` | PEM key (EC P-256 or Ed25519) signing [gate-issued tokens](config/authentication.md#gate-issued-tokens) | with an issuer `self: true` |
| `DNS_GATE_OAUTH_CLIENT_<ID>_SECRET` | Secret of an [OAuth client](config/authentication.md#oauth-clients) with `client_secret_basic` or `client_secret_post` (at least 32 characters) | for those clients |

`<ID>` is the provider (or OAuth client) id in upper case, every character other than a letter or a digit replaced by `_` (`eu-2` gives `EURODNS_EU_2_API_KEY`); the unprefixed variables serve every EuroDNS provider without its own. Route53 providers use the default AWS credential chain (IRSA, Pod Identity, instance role, environment), optionally assuming a role.

`DNS_GATE_SECRETS_ARN` names a Secrets Manager secret holding a JSON object of these variables (`{"EURODNS_API_KEY":"…"}`), loaded into the environment at startup; a variable already set wins. See [DEPLOY-LAMBDA.md](DEPLOY-LAMBDA.md#configuration).

Other environment variables: `POD_NAME` (lock holder id, defaults to the hostname) and `DNS_GATE_REPLICAS` (only used to warn when a single-replica store runs with several replicas).

Generate a session key with `openssl rand -hex 32`, a token signing key with `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` (or `-algorithm ed25519`).

## Top level

| Field | Default | Description |
|---|---|---|
| `listen.address` | `:8080` | HTTP listen address. TLS is terminated in front of the gate. |
| `listen.trusted_proxies` | `[]` | CIDRs of reverse proxies allowed to set `X-Forwarded-For`. The rightmost untrusted hop is the client address (used by `virtual_keys[].allowed_cidrs`). |
| `providers` | (required) | The DNS accounts the gate fronts, see [Providers](config/providers.md#providers). |
| `zones` | `[]` | Managed zones of the base layer. Zones listed by the active [managed policy](config/managed-policy.md#managed-policy-editing-from-the-ui) revision are added to them. Requests for any other zone are refused before authorization (zones found by [zone discovery](config/providers.md#zone-discovery) are readable only). Each zone must be selected by a provider. |
| `check_on_write` | `true` | Run the provider dry run (EuroDNS `check`) before every write; providers without one (Route53) are not affected. |
| `reconcile_interval` | `15m` | Drift detection period per zone (minimum `1m`). |
| `limits.max_body_bytes` | `1048576` | Request body limit. |
| `limits.max_changes_per_request` | `20` | Default blast-radius limit (RRset changes per request). |
| `limits.ephemeral_lifetime_factor` | `4` | An ephemeral RRset lives at most its creation plus this many `ephemeral_ttl`, however often values are added. |
| `acme.max_registrations` | `100` | acme-dns registrations and httpreq value ledgers per API key or token subject. |
| `acme.registration_idle` | `720h` | Registrations of token subjects and httpreq ledgers unused this long are purged (maintenance, DynamoDB TTL). |
| `acme.max_values` | `20` | Values of one challenge TXT RRset. |
| `acme.max_values_per_author` | `4` | Values one API key or token subject may hold in a challenge TXT RRset (at most `acme.max_values`). |
| `lock.ttl`, `lock.wait` | `60s`, `30s` | Per-zone write lease and how long a request waits for it (then `503 zone_locked`). |

## Store

| Field | Default | Description |
|---|---|---|
| `store.type` | `memory` | `memory`, `sqlite`, `postgres` or `dynamodb`. |
| `store.audit_retention` | `9600h` (400 days) | Audit events older than this are purged (minimum `24h`). |
| `store.sqlite.path` | | Database file, on a persistent volume. |
| `store.postgres.max_conns` | `5` | Pool size (1 to 100). The DSN comes from `DNS_GATE_POSTGRES_DSN`. |
| `store.dynamodb.table`, `region`, `endpoint` | | Single-table backend; credentials from the default AWS chain (EKS Pod Identity, IRSA, environment). |

`memory` loses ownership on restart: tests only (refused with `oauth.clients`). `memory` and `sqlite` support **one replica** (the chart refuses `replicaCount > 1` with them); use `postgres` or `dynamodb` to run several replicas.

## Audit

| Field | Default | Description |
|---|---|---|
| `audit.format` | `native` | Format of the audit lines on stdout: `native`, `ecs` (Elastic Common Schema 8.x) or `ocsf` (OCSF 1.3). The store, the UI and `GET /api/v1/audit` always keep the native event. Every format keeps `"type": "audit"`. |
| `audit.hash_chain` | `false` | Adds `instance_id`, `seq`, `prev_hash`, `hash_alg` and `hash` (SHA-256 chain per process) to every stdout line, checked by `dns-gate audit verify`. |
| `audit.hash_chain_key` | | From `DNS_GATE_AUDIT_CHAIN_KEY` or `DNS_GATE_AUDIT_CHAIN_KEY_FILE` only (32 bytes, hex or base64): the chain becomes an HMAC-SHA256 that cannot be recomputed without the key. Requires `audit.hash_chain: true`. |

Schema, actions, reasons, mappings, the limits of the chain and export recipes
(CloudWatch subscription filter, Kubernetes collectors, API pull) are in
[AUDIT.md](AUDIT.md).


## Propagation check

`GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation` ([API.md](API.md#dns-propagation)), the `check_propagation` MCP tool and the *Propagation* panel of the UI (RRset drawer when the viewer holds `dns.read` on the RRset, and right after an apply) ask the authoritative name servers of a managed zone and a list of public resolvers for one RRset, and compare their answers with the RRset as read from the provider.

| Field | Default | Description |
|---|---|---|
| `propagation.enabled` | `true`, `false` on AWS Lambda | Serves the check (`501 not_implemented` and no MCP tool when `false`). On Lambda it must be enabled explicitly, see [DEPLOY-LAMBDA.md](DEPLOY-LAMBDA.md). |
| `propagation.resolvers` | the list below | Public resolvers asked, replacing the default list: `name`, `address` (an IP address with an optional port, never a host name), `filtering` (`true` for a resolver that blocks names by policy), and for display `location`, `country` (ISO code) and `region` (the UI groups by region: `anycast`, `europe`, `north-america`, `south-america`, `asia`, `oceania`, `africa`, or free text). At most 64. |
| `propagation.allow_private_resolvers` | `false` | Accepts resolver addresses outside the public unicast space (private, loopback, link-local, shared, documentation and the other IANA special-purpose blocks, also when embedded in IPv6). Such a resolver may answer internal names of a split-horizon DNS: anyone allowed to check an RRset would learn its internal answer. |
| `propagation.query_timeout` | `1.5s` | Timeout of one query (100ms to 10s, at most `timeout`). |
| `propagation.timeout` | `4s` | Deadline of a whole check (`query_timeout` to 5s): servers that did not answer by then are reported as `error` (`timeout`). |
| `propagation.concurrency` | `16` | Servers one check asks at once (1 to 64). |
| `propagation.max_in_flight` | `3` | Checks running at once in one process (1 to 64, `503 busy` beyond). |
| `propagation.cache_ttl` | `10s` | A result is reused for the same RRset content during this time (1s to 5m), whoever asks. |
| `propagation.requests_per_minute` | `30` | Checks of one subject that are not served from the cache (1 to 600, `429` beyond). The UI asks every 5 seconds while a panel is open, for at most 2 minutes. |

**Per instance.** The cache, the per-subject limit (the 4096 most recently seen subjects) and `max_in_flight` are kept in memory by each process: with several replicas or Lambda instances, a subject can run `requests_per_minute` checks on each of them, and a load balancer spreading the polls of one panel over replicas finds a cold cache on each.

```yaml
propagation:
  resolvers:
    - {name: Cloudflare, address: 1.1.1.1, location: Anycast, country: US, region: anycast}
    - {name: Quad9, address: 9.9.9.9, location: Anycast, country: CH, region: anycast, filtering: true}
```

Network: the gate needs outbound **UDP and TCP port 53** to the resolvers and to the name servers of its zones (TCP when an answer is truncated or UDP fails). AWS Lambda functions outside a VPC have it; in a VPC, the security group and the network ACLs must allow it through a NAT gateway. The name servers of a zone are its apex NS as read from the provider (looked up with the system resolver when the gate has none), resolved with the system resolver; those whose address is not public (same check as `allow_private_resolvers`, never overridable) are skipped. The default resolvers are IPv4, as Lambda functions outside a VPC have no IPv6 egress.

Default resolvers, all documented open resolvers needing no account, unfiltered services where the operator offers one (*filtering* marks those that block malware or phishing domains):

| Resolver | Address | Location |
|---|---|---|
| Cloudflare | `1.1.1.1` | Anycast (US) |
| Google Public DNS | `8.8.8.8` | Anycast (US) |
| Quad9 (filtering) | `9.9.9.9` | Anycast (CH) |
| OpenDNS (Cisco, filtering) | `208.67.222.222` | Anycast (US) |
| AdGuard DNS, unfiltered | `94.140.14.140` | Anycast (CY) |
| Control D, unfiltered | `76.76.2.0` | Anycast (CA) |
| CleanBrowsing, security filter (filtering) | `185.228.168.9` | Anycast (US) |
| UltraDNS Public | `64.6.64.6` | Anycast (US) |
| NextDNS | `45.90.28.0` | Anycast (US) |
| DNS.SB | `185.222.222.222` | Anycast (DE) |
| Hurricane Electric | `74.82.42.42` | Anycast (US) |
| DNS4EU, unfiltered | `86.54.11.100` | European Union |
| FDN | `80.67.169.12` | Paris, FR |
| Yandex DNS | `77.88.8.8` | Moscow, RU |
| CIRA Canadian Shield, private | `149.112.121.10` | Canada |
| AliDNS (Alibaba) | `223.5.5.5` | Hangzhou, CN |
| DNSPod (Tencent) | `119.29.29.29` | Shenzhen, CN |
| 114DNS | `114.114.114.114` | Nanjing, CN |
| Quad101 (TWNIC) | `101.101.101.101` | Taipei, TW |

How to read a result, and how answers are compared: [Propagation check](features/propagation.md).

A check is a read: no audit event, a debug log line (`propagation`). The provider re-read of `expect` runs only for callers holding `dns.read` on the whole zone (a record-scoped reader gets the `412`), so no refusal is audited either ([AUDIT.md](AUDIT.md#not-audited)).
