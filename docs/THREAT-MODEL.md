# eurodns-gate — Threat model

Scope: an eurodns-gate deployment in front of the EuroDNS API, used by CI pipelines
(Terraform), ACME clients and humans. See [DESIGN.md](DESIGN.md) for the mechanisms
referenced below.

## Assets

| Asset | Why it matters |
|---|---|
| EuroDNS API key | Upstream it carries no scope: domains, contacts, nameservers, subscriptions, DNS. Leak = possible domain hijack. |
| Public DNS zones | Availability and integrity of every service under the domains (web, mail, certificate validation). |
| Ownership store | Decides who may change what. Tampering grants write access to RRsets. |
| Policy (roles, bindings) | Same, at the RBAC level. |
| Audit trail | Detection and forensics; rollback pointers (snapshot ids). |
| Inventory and history (web UI) | Reveal zone contents, owners and pipeline identities. |
| Managed policy revisions | Editable from the UI; decide who may write which RRsets and which zones are managed. |
| MCP endpoint | Exposes inventory and, if enabled, DNS writes to LLM agents. |

## Actors

- Legitimate clients: CI pipelines, ACME clients, operators.
- LLM agents through MCP, possibly manipulated by content they read (prompt injection).
- Buggy clients: correct credentials, wrong behaviour (e.g. a library that PUTs a
  zone containing only its own records).
- External attacker without credentials.
- Attacker holding a client credential (stolen CI token, leaked virtual key).
- Insider or attacker with access to the gate's runtime (cluster, pod, secrets).
- Anyone with EuroDNS console access (changes outside the gate).

## Threats and mitigations

| # | Threat | Mitigations | Residual risk |
|---|---|---|---|
| T1 | **EuroDNS key leak** | Key held only by the gate (secret store → Kubernetes Secret, never sent to clients); client headers never forwarded; EuroDNS IP allowlist on the gate's egress IP; EuroDNS user scope restricted to DNS of served domains (layer 1); key rotation. | If the egress IP is shared with other workloads, the allowlist is weak and the key alone protects. Scope granularity of EuroDNS users to be confirmed. |
| T2 | **Gate compromise** (code execution in the pod) | Layer 1 limits the key to DNS of served domains; non-root distroless image, read-only filesystem; NetworkPolicy: only the gate egresses to `rest-api.eurodns.com`; audit to an external sink. | An attacker inside the gate can do whatever layer 1 allows. Layer 1 is the only control at that point. |
| T3 | **Token replay** (token issued for another service presented to the gate, or stolen token reused) | Audience must equal the gate's audience; short lifetimes and maximum token lifetime enforced; `exp`/`nbf`; bound claims per binding; TLS everywhere. | A stolen valid token is usable until expiry, within its role and team. |
| T4 | **Stolen client credential** (CI identity, virtual key) | Least-privilege roles per zone/host/type; ownership limits damage to the team's own RRsets; protected records; blast-radius limit per request; virtual keys restricted to `acme-solver`, expiring, CIDR-bound. | The attacker can alter the team's own RRsets within the role. |
| T5 | **SSRF / path tricks** (encoded slashes, `..`, absolute URLs, host header, unexpected query parameters to reach unmapped operations) | Path normalization and rejection of encoded slashes and dot segments; `{domain-name}` validated against a strict domain regex and the managed-zone list (discovered, unmanaged zones are refused); route lookup on the normalized path only; unknown operations denied; unknown query parameters rejected; fixed upstream base URL. | — |
| T6 | **Buggy client wiping a zone** (full-zone PUT built from a partial zone, e.g. libdns `SetRecords`) | Delta computed against the current zone; any deletion outside the caller's scope or ownership is refused (or ignored with `rebase`); blast-radius limit; protected records; snapshot id logged before every write. | Within its own scope a buggy client can still delete its own RRsets. |
| T7 | **Changes made in the console**, outside the gate | Ownership content hash; reconcile marks drifted RRsets tainted and blocks gate writes on them; alert; foreign inventory. | The gate cannot prevent console changes; it only detects them. |
| T8 | **Lost updates** (concurrent read-modify-write) | Per-zone lock; every write re-reads the current zone under the lock; `ETag`/`If-Match` for clients that send it; `rebase` for stale ACME clients. | Two rebasing clients on the same RRset without If-Match (see DESIGN 6.4). |
| T9 | **Upstream ban** via the rate limit (malicious or accidental flood) | Single upstream caller; waiting limiter well below 10 req/10 s; singleflight and short cache on zone reads; per-subject request limits; alerting on upstream 429. | A ban still blocks all writes for its duration; console remains available. |
| T10 | **Store tampering** (write access to the DynamoDB table) | Table only writable by the gate's IAM role; PITR; ownership changes are audited and can be cross-checked with the audit trail. | An attacker with table write access can grant ownership, but RBAC (layer 2) and layer 1 still apply. |
| T11 | **Policy tampering** | Policy in git, changed by reviewed pull requests, deployed through GitOps; config loaded read-only. | Compromised git/CD pipeline. |
| T12 | **Denial of service on the gate** | Request size limits, timeouts, per-subject limits; the gate is not on the DNS resolution path (only on the change path). | Changes blocked while the gate is unavailable. |
| T13 | **Information disclosure through list endpoints** (`POST /domains/search` returns every domain) | Restricted to a broad read role in v0.1. | Response filtering per subject is on the roadmap. |
| T14 | **Audit evasion** | Every request audited, including denials; stdout to an external, append-only sink in addition to the store copy used by the UI. | Gate compromise (T2) can suppress events. |
| T15 | **UI session theft or fixation** | OIDC code flow with PKCE and `state`/`nonce`; encrypted `HttpOnly`, `Secure`, `SameSite=Strict` cookie; short session lifetime; session key rotated with the deployment secret; no token in browser storage. | A stolen cookie gives read access until expiry. |
| T16 | **CSRF** | Inventory and audit routes are GET-only and side-effect free; `SameSite=Strict`; DNS writes are not reachable with the browser session (they require a bearer token or virtual key). Policy mutations: see T24. | — |
| T17 | **XSS** (record values, hostnames, subject names rendered in the UI are attacker-influenced: TXT content, claims) | Values rendered as text only, never as HTML; strict CSP (`default-src 'self'`, no inline script, `frame-ancestors 'none'`); JSON API with `Content-Type: application/json` and `X-Content-Type-Options: nosniff`. | — |
| T18 | **Inventory leak** (the UI exposes zone contents, owners, pipeline identities, internal hostnames) | `ui.read` action required; zone-level filtering by readable zones; UI not exposed publicly by default (internal ingress); audit of UI access. Discovered, unmanaged zones: listed with `ui.read` on the zone, contents only with `dns.read` as well; `zones_discovery.exclude` hides domains entirely. | Anyone with `ui.read` on a zone sees its full inventory and history. A read role on `zones: ["*"]` covers every domain of the account once discovery is enabled. |
| T19 | **UI as a rate-limit amplifier** | The UI reads the inventory cache filled by reconcile and writes; only an empty zone cache (first start) triggers one EuroDNS GET for that zone, never a UI request afterwards. Discovery: one listing per `zones_discovery.refresh` (one request per 100 domains), plus at most one per minute triggered by policy proposals; listing zones never reads unmanaged zones; opening one reads it once per `reconcile_interval`, concurrent views sharing the request. | One GET per zone at startup; one GET per opened unmanaged zone and interval. |
| T20 | **Token issued for another audience replayed** (raw Azure DevOps OIDC token with the fixed audience `api://AzureADTokenExchange`, Kubernetes token meant for the API server, token for another API on the same issuer) | `aud` must be one of the issuer's configured audiences, set to the gate's own audience whenever the issuer allows it; Entra issuers must be tenant-specific (`/common`, `/organizations`, `/consumers` refused); Entra bindings on app roles with `tid`+`oid` subjects. The raw Azure DevOps token, whose audience is shared, is accepted only from a dedicated issuer bound (`bound_claims.sub`) to service connections used for nothing but the gate, which no other federation trusts (CONFIG.md, Azure DevOps OIDC). | A shared-audience token of such a service connection is still valid at another relying party that trusts its subject: keep those subjects out of every other federation. |
| T21 | **Privilege escalation through the policy editor** (an editor grants themselves or others more rights) | `policy.*` actions granted only by base bindings (git); managed rules confined to base bounds (zones, actions); zones brought under management by the managed layer confined to `policy.bounds.zones` and to the discovered account zones (`zones_discovery` include/exclude); managed names cannot shadow base names; protected records win; validation at proposal and activation; impact analysis shown to the approver. | An approver who approves without reading can still grant anything within bounds. |
| T22 | **Self-approval** | Approval must come from a `policy.approve` holder other than the author; enforced server-side on the revision author's subject. | Two colluding approvers. |
| T23 | **Stolen UI session used to change the policy** | Step-up: recent `auth_time` (`policy.edit_max_age`) and MFA in `amr` (`policy.require_amr`) for every mutation, else `reauth_required`; short sessions; approval by a second person. | A session stolen right after a step-up, within `edit_max_age`. |
| T24 | **CSRF on policy mutations** | `X-Gate-CSRF` header must equal the `gate_csrf` cookie; same-origin `Origin` header required; `SameSite=Strict` cookie; JSON bodies only. | — |
| T25 | **Activating a stale revision** (approved on a parent that is no longer active, silently reverting a newer change) | `parent_id` recorded; stale revisions cannot be activated; activation is a conditional write on the expected active revision. | — |
| T26 | **Store compromise rewriting the policy** (direct write of revisions or of the active pointer, bypassing approval) | Store writable only by the gate's identity; bounds and `policy.*` grants live in the file, not the store, so a forged revision stays within bounds; alert on every activation (audit event); regular export of the active revision to git to detect divergence; PITR. | Within bounds, a forged revision is effective until detected. |
| T27 | **LLM agent tricked by prompt injection into writing DNS** (instructions hidden in a TXT value, a hostname, an audit comment or any content the agent reads) | MCP writes disabled by default; when enabled, every write goes through `plan_rrset_change` then `apply_rrset_change(plan_id)`, the plan being bound to the subject, the zone version and an expiry; RBAC, protected records, ownership and blast-radius limits unchanged (the agent's identity has only its own rights); no policy tools over MCP; `via=mcp` in audit. Give agents read-only identities by default. | An agent with write rights and a human who approves the apply call without reading the plan. |
| T28 | **Abusive adoption of a production record** (an admin or a stolen admin session adopts a foreign RRset for a team, which can then change or delete it) | `dns.record.adopt` reserved to admins (base policy); preview mandatory, apply all-or-nothing bound to `preview_token`; mandatory comment; protected and server-managed records never adoptable; step-up authentication for humans; audit event listing every adopted RRset and value; alert on adoption. | An admin acting in bad faith within the protected-record exclusions. |
| T29 | **Pipeline impersonating another through a shared binding** (one `team_from` binding for every identity matching a glob) | Team derived per subject from an anchored regex with one capture; a subject whose claim does not yield a valid team is not bound (fail closed, never the team of another binding); ownership confines each derived team to the RRsets it created; protected records; narrow role (hosts, types, zones). | Any identity matching the glob can create any not-yet-existing RRset allowed by the role, and whoever can create matching identities (repositories, namespaces, roles) gets that right. With Azure DevOps (`sub` = `sc://<org>/<project>/<service connection>`, team = service connection name), anyone allowed to create a service connection under the glob prefix and to authorize it for a pipeline they control mints a new trusted identity with its own team: no access to other teams' records, but any free name its role allows. Mitigations: prefix dedicated to the gate and trusted by no other federation, service connection creation restricted (project Endpoint Creators / Administrators), approvals and checks on service connections or environments, audit log (subject and team of every write; a new team is a new service connection). Captures differing only by case share a team. |
| T30 | **Unmanaged zone changed through the gate** (a discovered zone written to or adopted before review) | Unmanaged zones are read-only in RBAC (only `dns.read` and `ui.read` can match), refused by the EuroDNS-compatible API, adoption, Terraform export and plans; managing one is a policy revision with approval by a second admin, step-up and impact analysis; reconcile only runs on managed zones. | Same as T21 once a revision managing the zone is approved. |
| T31 | **Releasing a zone that holds owned RRsets** (a revision removing a managed zone) | Impact analysis warns with the number of owned RRsets; ownership entries stay in the store, so managing the zone again restores them. | While released, nobody can change those RRsets through the gate (fail closed). |

## Assumptions

- TLS terminates at or in front of the gate; the gate is not exposed without it.
- Trusted issuers' signing keys are not compromised.
- Only the gate calls the EuroDNS API from its egress IP.
- EuroDNS console access is controlled separately (MFA, named accounts).
