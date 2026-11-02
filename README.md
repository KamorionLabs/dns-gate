# eurodns-gate

A security gateway in front of the [EuroDNS](https://www.eurodns.com) REST API.

EuroDNS API keys carry no scope: one key reaches every domain, contact, nameserver
profile, subscription and DNS zone of the account. eurodns-gate holds that key
alone, authenticates clients with short-lived OIDC tokens and enforces, on every
request:

- **RBAC**: which zone, host pattern and record type a caller may read or write;
- **ownership**: the gate only modifies or deletes RRsets it created (or that an
  admin explicitly adopted), and only for the team that owns them;
- **safe writes**: per-zone lock, `ETag`/`If-Match`, mandatory dry run, protected
  records, blast-radius limits;
- **the upstream rate limit** (10 requests per 10 seconds per IP, with progressive
  bans) for all clients combined;
- a full **audit trail**, browsable in a **web UI** (zone inventory with ownership
  status, filterable history with diffs);
- an **editable policy** from the UI for designated people: a managed layer of
  revisions on top of the git-managed base file, with approval by another approver,
  atomic activation, rollback, diff and impact analysis. Who may edit or approve is
  only ever decided by the base file, and human access uses Entra ID SSO with app
  roles (`Gate.Reader`, `Gate.Operator`, `Gate.PolicyAdmin`) assigned to groups.

The API contract stays the EuroDNS one: an existing EuroDNS client works through the
gate by changing its base URL and credentials.

> Status: **pre-alpha**. Not yet tested against the live EuroDNS API. Do not use in
> production.

Also included:

- **onboarding of existing zones**: bulk adoption team by team (preview, all-or-nothing
  apply, mandatory comment) and Terraform export with `import` blocks, whose first
  plan must be empty — see [docs/ONBOARDING.md](docs/ONBOARDING.md);
- an **MCP server** at `/mcp` for LLM agents, with the same authentication, RBAC and
  ownership: read tools by default, writes only if enabled and always through a plan
  then an apply bound to that plan.

## Related repositories

| Repository | Role |
|---|---|
| [eurodns-go](https://github.com/KamorionLabs/eurodns-go) | Go client, RRset helpers, zone delta, fake server. Used by the gate and the provider. |
| **eurodns-gate** | This gateway, container image, Helm chart. |
| [terraform-provider-eurodns](https://github.com/KamorionLabs/terraform-provider-eurodns) | One Terraform/OpenTofu provider, direct to EuroDNS or through the gate. |

## How it works

```
 Terraform / CI / ACME / humans ──(OIDC token or scoped key)──► eurodns-gate ──(EuroDNS key)──► rest-api.eurodns.com
                                                                     │
                                                         store: ownership, locks, audit
```

Three layers of protection: the EuroDNS user scope (upstream), RBAC and ownership
(gate). Details in [docs/DESIGN.md](docs/DESIGN.md).

## Authentication

Clients present a short-lived OIDC token whose audience is the gate. Supported
issuers include AWS IAM outbound identity federation (`sts:GetWebIdentityToken`),
GitHub Actions, GitLab CI, Kubernetes service accounts and **Entra ID**:

- Managed Identity, AKS Workload Identity, or an Azure DevOps service connection in
  workload identity federation mode obtain an Entra access token for the gate's app
  registration (`api://<gate-app>/.default`);
- bindings use app roles (`roles` claim, not groups), the subject is `tid`+`oid`,
  the actor category comes from `idtyp`;
- tenant-specific issuers only (`/common` is refused), and the raw Azure DevOps
  OIDC token (audience `api://AzureADTokenExchange`) is never accepted.

Existing EuroDNS clients (ACME) can use scoped virtual keys instead. Details in
[docs/DESIGN.md](docs/DESIGN.md#9-authentication).

## Quickstart (local)

```sh
export EURODNS_APP_ID=...   # EuroDNS credentials, held by the gate only
export EURODNS_API_KEY=...
go run ./cmd/eurodns-gate --config examples/config.yaml
```

Then point a client at `http://localhost:8080` with a token from one of the issuers
declared in the config. Configuration reference: [docs/CONFIG.md](docs/CONFIG.md).

Kubernetes: Helm chart in `charts/eurodns-gate`.

## Documentation

- [Design](docs/DESIGN.md)
- [Configuration reference](docs/CONFIG.md)
- [Threat model](docs/THREAT-MODEL.md)
- [ACME / certificates](docs/ACME.md)
- [Onboarding existing zones](docs/ONBOARDING.md)
- [Roadmap and points to validate](docs/ROADMAP.md)

## License

MIT — see [LICENSE](LICENSE).
