# CI pipelines

A pipeline authenticates with the OIDC token its platform already issues: nothing to
store, nothing to rotate, and the audit names the repository or service connection.
For each platform: the issuer to declare, a binding, and how the job gets its token.

=== "GitHub Actions"

    ```yaml
    # gate configuration
    issuers:
      - name: github
        issuer: https://token.actions.githubusercontent.com
        audiences: [dns-gate]
        bound_claims: {repository_owner: [example]}
        category: pipeline
    bindings:
      - role: web-cname-writer
        team: web
        subjects: [{issuer: github, claims: {sub: ["repo:example/web:environment:production"]}}]
    ```

    ```yaml
    # workflow
    permissions:
      id-token: write
    steps:
      - run: terraform apply -auto-approve   # provider: auth { github_actions {} }
      - name: or any HTTP call
        run: |
          TOKEN=$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=dns-gate" | jq -r .value)
          curl -fsS -H "Authorization: Bearer $TOKEN" https://dns-gate.example.com/api/v1/me
    ```

=== "GitLab CI"

    ```yaml
    # gate configuration
    issuers:
      - name: gitlab
        issuer: https://gitlab.com          # or your instance
        audiences: [dns-gate]
        category: pipeline
    bindings:
      - role: web-cname-writer
        team: web
        subjects: [{issuer: gitlab, claims: {sub: ["project_path:example/web:ref_type:branch:ref:main"]}}]
    ```

    ```yaml
    # .gitlab-ci.yml
    deploy:
      id_tokens:
        DNSGATE_TOKEN:
          aud: dns-gate
      script:
        - terraform apply -auto-approve      # the dnsgate provider reads DNSGATE_TOKEN
    ```

=== "Azure DevOps"

    The preferred path: an Entra ID access token for the gate application, from a
    workload identity federation service connection.

    ```yaml
    # gate configuration
    issuers:
      - name: entra
        issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
        audiences: ["api://dns-gate", "<application-id>"]
        subject_template: "{{tid}}/{{oid}}"
        bound_claims: {tid: "<tenant-id>"}
        category_claim: idtyp
        category_map: {app: pipeline, user: human}
    bindings:
      - role: acm-validation
        team: platform
        subjects: [{issuer: entra, claims: {roles: ["DNS.Write"], idtyp: app}}]
    ```

    ```yaml
    # azure-pipelines.yml
    - task: AzureCLI@2
      inputs:
        azureSubscription: dns-gate        # workload identity federation
        scriptType: bash
        scriptLocation: inlineScript
        inlineScript: |
          export DNSGATE_TOKEN=$(az account get-access-token --scope api://dns-gate/.default --query accessToken -o tsv)
          terraform apply -auto-approve
    ```

    Without any cloud login, the provider's `azure_devops {}` method uses the OIDC
    token Azure DevOps issues for a service connection. Its audience is shared by the
    whole organization: trust it only for **dedicated** service connections, as
    explained in [Azure DevOps OIDC](../CONFIG.md#azure-devops-oidc).

=== "AWS"

    IAM outbound identity federation signs a token for the calling role (CodeBuild,
    ECS, Lambda, EC2, EKS Pod Identity). Enable it once per account.

    ```yaml
    # gate configuration
    issuers:
      - name: aws
        issuer: https://<id>.tokens.sts.global.api.aws   # aws iam get-outbound-web-identity-federation-info
        audiences: [dns-gate]
        category: pipeline
    bindings:
      - role: web-cname-writer
        team: web
        subjects: [{issuer: aws, claims: {sub: "arn:aws:iam::111111111111:role/ci-web"}}]
    ```

    ```sh
    TOKEN=$(aws sts get-web-identity-token --audience dns-gate --signing-algorithm ES384 \
      --query WebIdentityToken --output text)
    # Terraform: auth { aws_web_identity { audience = "dns-gate" } }
    ```

=== "Kubernetes"

    A projected service account token with the gate as audience; the kubelet renews
    the file.

    ```yaml
    # gate configuration
    issuers:
      - name: k8s
        issuer: https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLE   # kubectl get --raw /.well-known/openid-configuration
        audiences: [dns-gate]
        category: pipeline
    bindings:
      - role: web-cname-writer
        team: web
        subjects: [{issuer: k8s, claims: {sub: "system:serviceaccount:web:dns-writer"}}]
    ```

    ```yaml
    # pod spec
    volumes:
      - name: dns-gate-token
        projected:
          sources:
            - serviceAccountToken: {path: token, audience: dns-gate, expirationSeconds: 3600}
    # Terraform: auth { token_file = "/var/run/secrets/dns-gate/token" }
    ```

## One binding for many pipelines

Binding pipelines one by one gets heavy. `team_from` derives the owner team from the
token, so every matching pipeline owns its own records:

```yaml
bindings:
  - role: pipeline-writer
    team_from:
      claim: sub
      regex: "^repo:example/([a-z0-9-]+):environment:production$"
      prefix: gh-                       # team gh-<repository>
    subjects:
      - issuer: github
        claims: {sub: ["repo:example/*:environment:production"]}
```

Each pipeline can only change what its team created, but any identity matching the
glob can **create** what the role allows: keep the role narrow. Details and the
trade-off: [team derived from a claim](../CONFIG.md#team-derived-from-a-claim).

## Long runs

Platform tokens can expire within minutes. Tools that keep one credential for a whole
run exchange it for a gate token first:
[token exchange](../api/authenticate.md#exchange-a-token-for-a-gate-token).
