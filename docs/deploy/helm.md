# Kubernetes with Helm

The chart `charts/dns-gate` runs the gate as a Deployment with its configuration in a
ConfigMap and its secrets mounted from Secrets you create. It is published with each
release as an OCI artifact; chart and image share the version.

```sh
helm install dns-gate oci://ghcr.io/kamorionlabs/charts/dns-gate --version 0.8.1 \
  --namespace dns-gate --create-namespace -f values.yaml
```

What the chart gives you: a non-root, read-only container (distroless, user 65532,
all capabilities dropped, seccomp `RuntimeDefault`), readiness and liveness probes
on `/readyz` and `/healthz`, a pod restart whenever the configuration changes
(checksum annotation), an optional PersistentVolumeClaim for SQLite and an optional
NetworkPolicy. It has no Ingress: you expose the Service your way, below.

## 1. Choose a store

The store holds ownership, zone locks and versions, the audit journal, policy
revisions, plans and API keys.

| `config.store.type` | Replicas | Use it for | Chart values |
|---|---|---|---|
| `memory` | 1 | tests: everything is lost on restart | none |
| `sqlite` | 1 | a single gate, the simplest production setup | `persistence.*` (PVC, kept on uninstall) |
| `postgres` | several | high availability, existing database service | `postgres.existingSecret` (DSN) |
| `dynamodb` | several | AWS clusters | IRSA or Pod Identity on the ServiceAccount |

The chart refuses `replicaCount > 1` with `memory` and `sqlite`, and uses the
`Recreate` strategy for them so two pods never share the database file.

!!! warning "EuroDNS and replicas"
    EuroDNS allows 10 requests per 10 seconds **per source IP** and bans
    progressively. Each pod has its own rate limiter for an account, so with *N*
    replicas behind one egress IP set `eurodns.rate.every` to *N* × `1.1s`, or run
    one replica. The gate must be the only EuroDNS API client behind that IP.

## 2. Create the secrets

Secrets never go in the values: the chart mounts existing Secrets and points the gate
at the files.

```sh
kubectl -n dns-gate create secret generic dns-gate-eurodns \
  --from-literal=app-id=<eurodns app id> --from-literal=api-key=<eurodns api key>

kubectl -n dns-gate create secret generic dns-gate-ui \
  --from-literal=session-key="$(openssl rand -hex 32)" \
  --from-literal=client-secret=<oidc client secret, if the client is confidential>

kubectl -n dns-gate create secret generic dns-gate-postgres \
  --from-literal=dsn='postgres://dns_gate:<password>@db.example.internal:5432/dns_gate?sslmode=require'
```

| Values | Secret keys | Becomes |
|---|---|---|
| `eurodns.existingSecret` (always required) | `appIdKey` (`app-id`), `apiKeyKey` (`api-key`) | `EURODNS_APP_ID_FILE`, `EURODNS_API_KEY_FILE` |
| `ui.existingSecret` (with `config.ui.enabled`) | `sessionKeyKey` (`session-key`), `clientSecretKey` (empty: public client with PKCE) | `DNS_GATE_SESSION_KEY_FILE`, `DNS_GATE_UI_CLIENT_SECRET_FILE` |
| `postgres.existingSecret` (with `postgres`) | `dsnKey` (`dsn`) | `DNS_GATE_POSTGRES_DSN_FILE` |

Set `eurodns.appIdKey: ""` when every EuroDNS provider sets `eurodns.app_id` in the
configuration.

!!! note "Route 53 only"
    The chart currently requires `eurodns.existingSecret` even without a EuroDNS
    provider. Point it at an empty Secret
    (`kubectl create secret generic dns-gate-no-eurodns`): the gate only reads EuroDNS
    keys for `eurodns` providers.

Other secrets go through `extraEnv`, from Secrets you create:

```yaml
extraEnv:
  - name: DNS_GATE_TOKEN_SIGNING_KEY          # gate tokens: issuer with self: true
    valueFrom: {secretKeyRef: {name: dns-gate-keys, key: token-signing-key}}
  - name: DNS_GATE_SAML_SP_KEY                # optional: signed SAML requests
    valueFrom: {secretKeyRef: {name: dns-gate-keys, key: saml-sp-key}}
  - name: DNS_GATE_SAML_SP_CERT
    valueFrom: {secretKeyRef: {name: dns-gate-keys, key: saml-sp-cert}}
  - name: EURODNS_EU_2_API_KEY                # a second EuroDNS account, provider id eu-2
    valueFrom: {secretKeyRef: {name: dns-gate-eurodns-2, key: api-key}}
```

Generate the token signing key with
`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` (or `-algorithm ed25519`).

## 3. Write the configuration

`config` is the gate configuration, rendered as `config.yaml` (reference:
[Configuration](../CONFIG.md)). Decoding is strict: an unknown field stops the gate.
Check a file before deploying with the same version of the gate:

```sh
docker run --rm -v "$PWD/config.yaml:/c.yaml:ro" \
  ghcr.io/kamorionlabs/dns-gate:0.8.1 -check -config /c.yaml
```

### Store values

=== "SQLite"

    ```yaml
    config:
      store: {type: sqlite, sqlite: {path: /var/lib/dns-gate/gate.db}}
    persistence:
      enabled: true
      size: 1Gi
      storageClass: ""        # cluster default
      # existingClaim: dns-gate-data
    ```

=== "Postgres"

    ```yaml
    replicaCount: 2
    config:
      store: {type: postgres, postgres: {max_conns: 5}}
    postgres:
      existingSecret: dns-gate-postgres
    ```

=== "DynamoDB"

    ```yaml
    replicaCount: 2
    config:
      store: {type: dynamodb, dynamodb: {table: dns-gate, region: eu-west-3}}
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: arn:aws:iam::111111111111:role/dns-gate   # IRSA
    ```

    The role needs `GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`, `Query`,
    `TransactWriteItems` and `Scan` on the table (single table, keys `pk`/`sk`, TTL
    attribute `ttl`). With EKS Pod Identity, associate the role with the
    ServiceAccount instead of the annotation. The same role can carry the Route 53
    permissions.

## 4. Expose it with TLS

The gate listens in plain HTTP on 8080 (Service port 80): terminate TLS in front of
it, at an Ingress controller or a Gateway. Example with ingress-nginx and
cert-manager:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dns-gate
  namespace: dns-gate
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    nginx.ingress.kubernetes.io/proxy-read-timeout: "120"   # writes queue behind the provider rate limit
    nginx.ingress.kubernetes.io/proxy-body-size: 1m
spec:
  ingressClassName: nginx
  tls:
    - hosts: [dns-gate.example.com]
      secretName: dns-gate-tls
  rules:
    - host: dns-gate.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: dns-gate, port: {name: http}}}
```

Then in `config`:

```yaml
config:
  listen:
    address: ":8080"
    trusted_proxies: ["10.0.0.0/8"]     # the ingress controller pods, for X-Forwarded-For
```

The Service is named after the release (`dns-gate` for a release named `dns-gate`,
`<release>-dns-gate` otherwise).

## 5. Sign people in

The web UI, the Connect page and the Claude Desktop extension need a login: OIDC or
SAML, with `ui.existingSecret` holding the session key.

=== "OIDC (Entra ID)"

    ```yaml
    ui:
      existingSecret: dns-gate-ui
      clientSecretKey: ""                       # public client with PKCE
    config:
      issuers:
        - name: entra
          issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
          audiences: ["api://dns-gate", "<application-id>"]
          subject_template: "{{tid}}/{{oid}}"
          bound_claims: {tid: "<tenant-id>"}
          category_claim: idtyp
          category_map: {app: pipeline, user: human}
          name_claim: name
      ui:
        enabled: true
        issuer: entra
        client_id: <application-id>
        redirect_url: https://dns-gate.example.com/auth/callback
    ```

    Register `https://dns-gate.example.com/auth/callback` as a web redirect URI, and
    bind people through app roles (`roles` claim) assigned to Entra groups:
    [configuration](../config/authentication.md#entra-id).

=== "SAML (IAM Identity Center)"

    ```yaml
    ui:
      existingSecret: dns-gate-ui
    config:
      issuers:
        - name: gate
          self: true                            # gate tokens for SAML users
          issuer: https://dns-gate.example.com
      ui:
        enabled: true
        saml:
          issuer: identity-center
          entity_id: https://dns-gate.example.com/auth/saml/metadata
          acs_url: https://dns-gate.example.com/auth/saml/acs
          idp_metadata_url: https://portal.sso.eu-west-3.amazonaws.com/saml/metadata/<id>
          name_id_format: email
    extraEnv:
      - name: DNS_GATE_TOKEN_SIGNING_KEY
        valueFrom: {secretKeyRef: {name: dns-gate-keys, key: token-signing-key}}
    ```

    Full setup, including groups from the identity store:
    [SAML with IAM Identity Center](../IDENTITY-CENTER.md).

## 6. Restrict the network

```yaml
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: ingress-nginx}
  egressCIDRs: ["0.0.0.0/0"]   # HTTPS: EuroDNS API, OIDC issuers' keys, AWS endpoints
```

Ingress is limited to port 8080 from the listed sources; egress to DNS on any address (also the [propagation check](../features/propagation.md): public resolvers and the zones' name servers), HTTPS to
`egressCIDRs`, and 5432 with the `postgres` store. Plain NetworkPolicy has no
host-name rules: use your CNI (Cilium, Calico) to allow `rest-api.eurodns.com` and
your issuers only.

## 7. Ship the audit trail

Audit events are JSON lines with `"type": "audit"` on the gate's stdout, next to its
logs: route them from your log collector (Fluent Bit, Vector, the OpenTelemetry
Collector) to the SIEM or an archive. `audit.format: ecs` or `ocsf`, and
`audit.hash_chain: true` with `DNS_GATE_AUDIT_CHAIN_KEY` through `extraEnv`, are
described in [SIEM and audit export](../integrations/siem.md#kubernetes).

## 8. Upgrade

1. Read the release notes: configuration changes are listed there, and an unknown
   field stops the gate at startup.
2. Check the new configuration with `-check` and the new image (step 3).
3. `helm upgrade dns-gate oci://ghcr.io/kamorionlabs/charts/dns-gate --version <new> -n dns-gate -f values.yaml`.
4. Watch `/readyz` and the logs. The store schema migrates at startup; back up the
   SQLite volume or the Postgres database before crossing a store migration.

Pods restart on every configuration change. With SQLite the gate is briefly
unavailable during the restart (`Recreate`); Terraform and CI retry, and the
provider console stays the break-glass path.

## A complete example

One EuroDNS account with domains in folders per country, people signing in with
Entra ID, GitHub Actions pipelines owning their own records, cert-manager through an
API key, SQLite store:

```yaml
eurodns:
  existingSecret: dns-gate-eurodns
ui:
  existingSecret: dns-gate-ui
persistence:
  enabled: true
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ingress-nginx}}

config:
  listen: {address: ":8080", trusted_proxies: ["10.0.0.0/8"]}
  providers:
    - id: eurodns
      kind: eurodns
      zones: {include: ["*"], refresh: 1h}
      eurodns: {}
  zones: [example.com, example.es, example.de]
  store: {type: sqlite, sqlite: {path: /var/lib/dns-gate/gate.db}}

  issuers:
    - name: entra
      issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
      audiences: ["api://dns-gate", "<application-id>"]
      subject_template: "{{tid}}/{{oid}}"
      bound_claims: {tid: "<tenant-id>"}
      category_claim: idtyp
      category_map: {app: pipeline, user: human}
      name_claim: name
    - name: github
      issuer: https://token.actions.githubusercontent.com
      audiences: [dns-gate]
      bound_claims: {repository_owner: [example]}
      category: pipeline

  groups:
    dns-admins: {members: [{issuer: entra, claims: {roles: [DNS.Admin]}}]}
    spain-team: {members: [{issuer: entra, claims: {roles: [DNS.Spain]}}]}

  teams:
    platform: {description: DNS administrators}
    spain: {description: Spanish sites}

  roles:
    dns-admin:
      rules:
        - zones: ["*"]
          actions: [dns.read, dns.record.write, dns.record.adopt, dns.ownership.approve,
                    gate.apikey.manage, ui.read, policy.read, policy.propose, policy.approve]
    spain-dns:
      rules:
        - folders: ["/ES", "/ES/**"]
          actions: [dns.read, dns.record.write, dns.forward.write, ui.read]
    pipeline-writer:
      rules:
        - zones: [example.com]
          actions: [dns.read, dns.record.write]
          records: {hosts: ["*.apps"], types: [CNAME, TXT]}
    acme-solver:
      ephemeral_ttl: 24h
      rules:
        - zones: ["*"]
          actions: [dns.read, dns.record.write]
          records: {hosts: [_acme-challenge, _acme-challenge.**], types: [TXT]}

  bindings:
    - {role: dns-admin, team: platform, groups: [dns-admins]}
    - {role: spain-dns, team: spain, groups: [spain-team]}
    - role: pipeline-writer
      team_from: {claim: sub, regex: "^repo:example/([a-z0-9-]+):environment:production$", prefix: gh-}
      subjects: [{issuer: github, claims: {sub: ["repo:example/*:environment:production"]}}]

  protected:
    - {zones: ["*"], hosts: ["@"], types: [NS, SOA, MX, CAA]}
    - {zones: ["*"], hosts: ["_dmarc", "@"], types: [TXT]}

  policy:
    editable: true
    bounds: {zones: ["*"], actions: [dns.read, dns.record.write, ui.read]}

  mcp: {enabled: true, public_url: https://dns-gate.example.com}
  ui:
    enabled: true
    issuer: entra
    client_id: <application-id>
    redirect_url: https://dns-gate.example.com/auth/callback
```

cert-manager then gets an API key with the `acme-solver` role for team `platform`,
created by an administrator: see [Certificates and third parties](../integrations/certificates.md).
