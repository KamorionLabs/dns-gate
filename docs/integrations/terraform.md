# Terraform

Two providers talk to the gate. Both work with Terraform and OpenTofu.

| Provider | Talks to | Use it for |
|---|---|---|
| [`KamorionLabs/dnsgate`](https://registry.terraform.io/providers/KamorionLabs/dnsgate/latest) | the gate API (`/api/v1`) | every zone, Route 53 or EuroDNS: record sets, URL forwards, delegated roles and bindings |
| [`kamorionlabs/eurodns`](https://registry.terraform.io/providers/kamorionlabs/eurodns/latest) | the EuroDNS-compatible API of the gate, or EuroDNS directly | existing EuroDNS stacks, moved behind the gate by changing the base URL |

## dnsgate

```hcl
terraform {
  required_providers {
    dnsgate = { source = "KamorionLabs/dnsgate", version = "~> 0.3" }
  }
}

provider "dnsgate" {
  endpoint = "https://dns-gate.example.com"
  auth {
    github_actions {}                                  # in GitHub Actions
    azure_identity { scope = "api://dns-gate/.default" } # elsewhere: Entra ID, az login
  }
}

resource "dnsgate_record_set" "www" {
  zone   = "example.com"
  name   = "www"
  type   = "CNAME"
  ttl    = 300
  values = ["front.example.net"]
}

resource "dnsgate_record_set" "apex" {             # Route 53 alias
  zone = "example.com"
  name = "@"
  type = "A"
  alias {
    name                   = "d111111abcdef8.cloudfront.net"
    zone_id                = "Z2FDTNDATAQYW2"
    evaluate_target_health = false
  }
}
```

- **Authentication**: exactly one method, plus optionally one CI method used only
  inside its CI system (`github_actions`, `azure_devops`), so the same code runs in
  the pipeline and on a workstation. Methods: `aws_web_identity`, `azure_identity`,
  `azure_devops`, `github_actions`, `token_file`, `token_command`, `token`; without
  `auth`, `DNSGATE_TOKEN` or `DNSGATE_TOKEN_FILE`. See the provider's
  [authentication guide](https://github.com/KamorionLabs/terraform-provider-dnsgate/blob/main/docs/guides/authentication.md).
- **Safe by construction**: creates send `If-None-Match: *`, updates and deletes
  `If-Match` with the hash of the last refresh. A change made elsewhere since then
  fails with `412` instead of being overwritten. Locks, rate limits and 5xx are
  retried.
- **Teams**: `team` acts for one of your teams; changing it never moves ownership
  (that is a [transfer](../api/ownership.md#transfer-records-to-another-team)).
- **Other resources**: `dnsgate_url_forward`, `dnsgate_role` and `dnsgate_binding`
  (policy delegations), data sources `dnsgate_zones`, `dnsgate_record_sets`,
  `dnsgate_record_set`, `dnsgate_url_forward`, `dnsgate_me`, `dnsgate_teams`,
  `dnsgate_team`.

!!! note "OpenTofu"
    If `tofu init` does not find `KamorionLabs/dnsgate`, use the full source
    `registry.terraform.io/KamorionLabs/dnsgate`.

## Bring existing records under Terraform

1. An administrator adopts the records for the stack's team
   ([Adopt and transfer](../api/ownership.md)).
2. `GET /api/v1/zones/example.com/terraform?team=web` returns one resource per record
   set with its `import` block (the UI has a download button).
3. Paste, plan: the first plan must show imports only, **no change**. Apply.

Moving off `aws_route53_record`, record by record with `removed` blocks:
[migration guide](https://github.com/KamorionLabs/terraform-provider-dnsgate/blob/main/docs/guides/migrating-from-route53.md).
Whole zones: [onboarding guide](../ONBOARDING.md).

## Pipelines that create pipelines

A stack that creates CI pipelines can also give each of them its DNS rights, in the
same apply, through a [policy delegation](../CONFIG.md#policy-delegations): the base
file says how far the stack may go, and `dnsgate_role` / `dnsgate_binding` create the
role and binding of each pipeline without human approval.

## eurodns through the gate

An existing `kamorionlabs/eurodns` configuration works against the gate by changing
its base URL and credentials: the gate serves the EuroDNS contract for EuroDNS zones,
with RBAC, ownership and audit on top. `terraform import` of an
`eurodns_record_set` adopts the record set. New stacks should prefer `dnsgate`.
