# Onboarding, MCP and propagation

## 16. Onboarding and adoption

An existing zone is entirely **foreign** when the gate starts: read-only through the
gate. Taking it over is an explicit, reviewed operation, done team by team. The
step-by-step guide is [ONBOARDING.md](../ONBOARDING.md).

### 16.1 Bulk adoption

| Route | Action | Purpose |
|---|---|---|
| `POST /api/v1/zones/{zone}/adopt/preview` | `dns.record.adopt` | dry run on a selection (explicit RRsets and/or host globs + types), for an owner team |
| `POST /api/v1/zones/{zone}/adopt` | `dns.record.adopt` | apply the adoptable candidates of a preview |
| `GET /api/v1/zones/{zone}/terraform?team=&hosts=&types=&provider=` | `ui.read` | Terraform HCL for the RRsets owned by a team |

- **Preview** lists every selected RRset with its TTL, values, current status and
  whether it is adoptable. Reasons for refusal: `protected`, `server_managed` (SOA,
  locked records), `owned_by_other_team`, `already_owned`, `forbidden` (RBAC),
  `relative_target` (a value that would not round-trip safely). It returns a
  `preview_token` bound to the exact upstream content previewed.
- **Apply** is **all-or-nothing** and must carry the `preview_token` and a
  **mandatory comment**. If any selected RRset changed or is no longer adoptable
  since the preview, nothing is adopted: `409 {"reason":"adopt_conflict"}`.
- Adopted entries get `Adopted = true`, the current content hash, the owner team and
  the adopter as `CreatedBy`; one audit event lists every adopted RRset with its
  values and the comment.
- `dns.record.adopt` is an **admin** permission: adoption turns a record nobody
  could touch into one a team can change or delete.

### 16.2 Terraform export

The export returns HCL for the team's RRsets: one `dnsgate_record_set` per RRset
(provider `KamorionLabs/dnsgate`, any DNS provider behind the gate, alias RRsets as an
`alias` block; `provider=eurodns` exports `eurodns_record_set` instead) and
one `import` block (Terraform and OpenTofu 1.5+) with the import id
`<zone>/<host>/<type>`. Applied as is, the **first plan must show only imports and
no changes**; any diff means the export and the zone disagree and must be
investigated before going further.

Two paths, same result:

1. adopt in the gate (UI or API), then export HCL and plan;
2. EuroDNS zones only: write or export the HCL first, then `terraform import` /
   `import` blocks with the `eurodns` provider in gate mode: the provider asks the
   gate to adopt each RRset (`/.well-known/dns-gate/zones/{d}/adopt`), which requires
   `dns.record.adopt` for the identity running the plan.

Path 1 keeps the adoption right with admins and lets pipelines run with write
permissions only; it is the recommended one, and the only one with the `dnsgate`
provider, which imports only RRsets the team already owns.

## 17. MCP server

The gate embeds a Model Context Protocol server at `/mcp` (Streamable HTTP, official
Go SDK), so LLM agents can inspect DNS and, if explicitly allowed, propose changes.

### 17.1 Same controls

- Same authentication (bearer tokens: OIDC, gate tokens, API keys), same RBAC, same
  ownership rules, same rate budget as the REST API. MCP is another entry point, not
  another privilege.
- The gate publishes OAuth 2.0 Protected Resource Metadata (RFC 9728,
  `/.well-known/oauth-protected-resource`) pointing to the configured authorization
  server.
- Entra ID does not support dynamic client registration, so MCP clients cannot
  register with it and log in on their own: the token is passed in the
  `Authorization` header by the client configuration, or obtained from the gate's
  own authorization server (9.4), as the Claude Desktop extension does.
- Every tool call is audited with `via=mcp`.
- No policy tool: the policy (section 15) cannot be read in full or changed through
  MCP.

### 17.2 Tools

| Tool | Kind | Equivalent |
|---|---|---|
| `list_zones` | read | `GET /api/v1/zones` |
| `list_rrsets` | read | zone inventory, with owner teams and tombstones |
| `get_rrset` | read | one RRset with ownership (and why the caller may change it), tombstone and history |
| `search_audit` | read | audit search |
| `explain` | read | decision simulation for the caller |
| `who_can` | read | who may act on an RRset |
| `list_teams`, `get_team` | read | `GET /api/v1/teams[/{team}]` |
| `transfer_list` | read | `GET /api/v1/transfers` |
| `check_propagation` | read (not audited) | `GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation` (section 19) |
| `plan_rrset_change` | write (disabled by default) | dry run of desired RRset states; returns the changes, the decision and a `plan_id` |
| `apply_rrset_change` | write (disabled by default) | applies exactly one plan, by `plan_id` |
| `adopt_preview`, `adopt_apply` | write (disabled by default) | bulk adoption (16.1), with the same token and comment rules |
| `transfer_propose`, `transfer_approve`, `transfer_reject` | write (disabled by default) | ownership transfers between teams, with a second approver |

The plan and adoption tools take an optional `team`, one of the caller's teams,
like the `X-DNS-Gate-Team` header of the REST API.

### 17.3 Plan then apply

Writes are **disabled by default** in the configuration. When enabled:

- `plan_rrset_change` takes desired states (`host`, `type`, `ttl`, `values`, or
  `delete`), evaluates them like a real write (RBAC, protected, ownership, blast
  radius) and returns the RRset diff and a `plan_id`.
- The `plan_id` is bound to the **subject** that planned and to the **zone version**
  at plan time, and expires. `apply_rrset_change(plan_id)` fails if another subject
  presents it, if the zone changed since, or if it expired. Plans are kept in the
  store and taken once with a conditional delete, so any replica (or Lambda
  instance) can apply a plan made by another, never twice; `POST
  /api/v1/zones/{zone}/plan` and `/apply` use the same plans.
- An agent therefore cannot apply anything that was not shown first as a diff, and
  a human in the loop can review the plan before approving the apply call in the
  MCP client.

### 17.4 Claude Desktop extension

The Connect page offers an [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) generated per gate ([configuration](../config/ui-mcp.md#claude-desktop-extension)). Its local server, `internal/mcpb/relay.js` (one file, Node.js 18 or later, no dependency), forwards every MCP message to `/mcp` over Streamable HTTP (JSON and SSE answers, `Mcp-Session-Id`, messages the gate sends on its own) with the user's access token:

- Sign-in uses the system browser on the issuer (authorization code with PKCE S256, `state` and `nonce`, scopes `openid offline_access <scope>`, see [the identity provider requirements](../config/ui-mcp.md#claude-desktop-extension)), back to a loopback redirect `http://localhost:<ephemeral port>`, without a path. Without a usable token, `initialize` and the list requests (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`) are answered at once, the lists empty, since Claude Desktop gives up on a request after about a minute; the sign-in then runs in the background and the relay sends `notifications/tools/list_changed` once signed in, so Claude fetches the tools again. Conversations already open keep the tool list they started with: start a new conversation after the first sign-in. A tool call made before that waits for the sign-in. A sign-in not completed within 5 minutes, or refused, fails the waiting requests with a JSON-RPC error; asking again starts a new one. With a usable token, every message goes straight to the gate.
- The tokens are kept in `~/.dns-gate/<host>.json` (mode `0600`). The access token is refreshed silently with the refresh token; the browser opens again only when the refresh is refused (expired or revoked session).
- Tokens are never written to the logs (Claude Desktop keeps the server's stderr in its MCP logs). When the browser cannot be opened, the sign-in URL is in those logs.

## 19. DNS propagation check

After a write the provider has the new content at once, but clients see it only
once the caches of the resolvers expire. `GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation`,
the `check_propagation` MCP tool and the *Propagation* panel of the UI (RRset drawer
for viewers holding `dns.read` on the RRset, and right after an apply) show where
the change is already visible, like the public propagation checkers but for the
RRsets of the gate only.

- **What is asked.** The authoritative name servers of the zone (its apex NS as read
  from the provider, resolved with the system resolver, one public address each,
  IPv4 first, recursion off, the answer must carry the AA flag) and the configured
  public resolvers (`propagation.resolvers`, a default list of 19 documented open
  resolvers: anycast services plus resolvers with a fixed location in Europe, North
  America and Asia). One query per server: UDP with EDNS0 (1232 bytes), again over
  TCP when the answer is truncated or UDP fails before the timeout; 1.5 s per query,
  4 s per check (at most 5 s), 16 servers at once (`internal/propagation`,
  `github.com/miekg/dns`).
- **What is compared.** The RRset of the gate inventory, the per-process cache the
  single-RRset read serves (refreshed by the writes and the reconciles of that
  process), against the records of the asked type at the end of the CNAME chain of
  each answer. Both sides are normalized the same way: the provider value is parsed
  relative to the zone (EuroDNS relative targets), packed and unpacked like a server
  answer (hex, base64, IPv6 forms), domain names lowercased, TXT reduced to their
  content, sets sorted. Authoritative answers must carry the expected TTL and cached
  answers may not have more TTL left than it (TTL-only changes). Statuses: `match`,
  `stale`, `missing`, `error`, `indeterminate`.
- **Which content.** The inventory of one process can lag behind a write made by
  another replica or Lambda instance, or a write whose read-back failed. An apply
  result carries `new_hash` per created or updated RRset, and the UI and clients pass
  it (or `absent` after a delete) as `expect`: when the inventory differs, the zone
  is read again from the provider (at most 6 times a minute per subject, only for
  subjects holding `dns.read` on the zone, so that no refusal is audited) and the
  check answers `412 precondition` only if it still differs. Without `expect` the
  check compares with whatever this process has.
- **Aliases.** Route53 alias and EuroDNS `APEX` RRsets have no values. Every address
  an authoritative server answers must be one of the target's as the gate resolves
  it, and every address a resolver answers one of the target's as that resolver
  answers it. Anything else is `indeterminate`, never a match: CDN edges are shared
  by many names, so an address in common proves nothing.
- **Deletions and filtering.** An RRset that does not exist matches empty answers.
  Records of another name or type, and answers flagged by the resolver as its own
  decision (extended DNS errors Blocked, Censored, Filtered), are errors; negative
  answers of resolvers marked `filtering` are flagged. `converged` needs at least one
  matching authoritative answer and no `stale`, `missing` or `indeterminate` one.
- **Cost and abuse.** Results are cached `propagation.cache_ttl` (10 s) per RRset
  content and shared by concurrent callers (one check in flight per key); checks
  that miss the cache are limited per subject (`requests_per_minute`, 30, buckets of
  the 4096 most recent subjects) and per process (`max_in_flight`, 3, then `503
  busy`). All of this is per process: each replica or Lambda instance has its own
  cache, buckets and in-flight count. An answer reports at most 32 values of 512
  bytes, a result 1 MiB of values. The UI refreshes every 5 s while a panel is open,
  until converged or 2 minutes. A check reads the inventory and asks DNS servers:
  no provider request unless `expect` forces a re-read, no audit event (a debug
  log line).
- **Safety.** Only names of zones managed by the gate are asked, built from a zone,
  host and type the gate validated, and only the configured resolvers and the name
  servers of the zone are contacted: the endpoint is not an open resolver and takes
  no address from the caller. Name server addresses and configured resolver
  addresses must be public unicast, outside the IANA special-purpose blocks,
  embedded IPv4 (NAT64, 6to4, IPv4-mapped) checked as IPv4; private resolvers need
  `propagation.allow_private_resolvers`.
- **Reading the result.** Anycast resolvers answer from their site nearest to the
  gate: the regional view comes from the resolvers with a fixed location. Resolvers
  answer from their cache: asking again does not refresh it, `ttl_left` says when it
  expires.
- **Deployment.** Outbound UDP and TCP port 53. AWS Lambda functions outside a VPC
  have it (IPv4 only, hence IPv4 default resolvers); in a VPC it goes through a NAT
  gateway. Off by default on Lambda, where a check holds an execution environment
  for up to 4 s.
