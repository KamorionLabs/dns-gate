# dns-gate Helm chart

Runs [dns-gate](https://github.com/KamorionLabs/dns-gate), the security gateway in
front of DNS provider APIs, on Kubernetes.

```sh
helm install dns-gate oci://ghcr.io/kamorionlabs/charts/dns-gate --version <version> \
  --namespace dns-gate --create-namespace -f values.yaml
```

- `config`: the gate configuration, rendered as `config.yaml`
  ([reference](https://kamorionlabs.github.io/dns-gate/docs/CONFIG/)).
- Secrets come from existing Secrets: `eurodns.existingSecret` (required),
  `ui.existingSecret` with the UI, `postgres.existingSecret` with the Postgres store,
  anything else through `extraEnv`.
- `memory` and `sqlite` stores run one replica (enforced); `postgres` and `dynamodb`
  run several.
- No Ingress: expose the Service behind your Ingress controller or Gateway, which
  terminates TLS.

Guide (stores, secrets, TLS, OIDC and SAML login, NetworkPolicy, upgrades, a complete
example): <https://kamorionlabs.github.io/dns-gate/docs/deploy/helm/>. Every value
is commented in [values.yaml](values.yaml).
