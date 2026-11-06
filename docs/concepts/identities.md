# Identities

The gate never issues long-lived secrets to automation by default. Each caller proves
who it is with a credential it already has, and the gate turns that identity into
roles and teams.

| Who | How they authenticate | Subject in the audit |
|---|---|---|
| CI pipelines and workloads | OIDC token of their platform: GitHub Actions, GitLab CI, Azure DevOps, Entra ID (managed identity, AKS workload identity), AWS IAM outbound identity federation, Kubernetes service accounts | `github:repo:example/web:environment:production` |
| People | the web UI login, OIDC (Entra ID or any provider) or SAML 2.0 (for example AWS IAM Identity Center) | `entra:<tenant>/<object id>`, `identity-center:alice@example.com` |
| People, from a terminal or Claude | a gate token from the UI (Connect page), or the token of their OIDC provider (`az account get-access-token`) | as their UI login |
| Tools that keep one credential per run | a gate token from the **token exchange** of their OIDC token | as the exchanged token |
| Third parties without an identity provider | a gate-issued **API key** `dgk_…`, bound to one team and one role | `api-key:<id>` |
| Legacy EuroDNS clients | a static **virtual key** of the configuration (`X-App-Id`, `X-Api-Key`) | `virtual-key:<id>` |

## Issuers

An issuer is an OIDC provider the gate trusts. The gate checks the signature, the
expiry and the **audience**: tokens must be minted for the gate (`dns-gate`,
`api://dns-gate`), so a token meant for another service is refused.

```yaml
issuers:
  - name: github
    issuer: https://token.actions.githubusercontent.com
    audiences: [dns-gate]
    bound_claims: {repository_owner: [example]}   # every token must match
    category: pipeline
```

- `bound_claims` narrows the issuer to your organization before any binding.
- `category` (`human` or `pipeline`, or derived from a claim with `category_claim`)
  matters for step-up: humans need a recent login for sensitive changes.
- `subject_claim` or `subject_template` (`"{{tid}}/{{oid}}"` for Entra ID) picks the
  stable identifier.
- `self: true` declares the gate as its own issuer, for gate tokens (SAML users, the
  Claude Desktop extension, the token exchange).

Platform recipes: [CI pipelines](../integrations/ci.md). Every field:
[configuration](../config/authentication.md#issuers).

## From identity to rights

A **binding** maps subjects (issuer plus claim globs) or **groups** to a **role**,
for a **team**:

```yaml
bindings:
  - role: web-cname-writer
    team: web
    subjects:
      - issuer: github
        claims: {sub: "repo:example/web:environment:production"}
```

A valid token that matches no binding gets `403 no_binding`. Roles are recomputed on
every request: removing a binding takes effect immediately, even for tokens already
issued.

Next: [Roles and rules](policy.md).
