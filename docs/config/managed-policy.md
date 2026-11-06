# Managed policy and delegations

The policy layer edited from the UI or by delegated pipelines, within limits written in the base file.

## Managed policy (editing from the UI)

The policy has two layers, merged at evaluation:

- **base**: this file (GitOps). Issuers, UI, store, protected records, `policy.bounds` and every `policy.*` grant live only here.
- **managed**: a document of zones, teams, groups, roles, bindings and virtual keys stored as immutable **revisions** in the store and edited from the UI (or the API).

Rules of the managed layer:

- a managed role, group or team cannot reuse a base name;
- managed teams follow the revision cycle like the rest of the document; a proposal without a `teams` field keeps the teams of the active revision (`"teams": {}` removes them), and the impact analysis reports declared, removed and changed teams;
- managed rules cannot grant `policy.*` actions and must stay within `policy.bounds` (zone globs, folder globs, actions): their `zones` must be covered by `bounds.zones` and their `folders` by `bounds.folders`, and a rule applying through a folder only reaches zones matching `bounds.zones` ([EuroDNS folders](providers.md#eurodns-folders)); a managed binding may reuse a base role only if that role also stays within the bounds;
- protected records still win over everything;
- managed `zones` are brought under management in addition to the base `zones`: each must match `policy.bounds.zones` and, when it is not managed yet, exist in a provider account ([zone discovery](providers.md#zone-discovery) must be enabled); a zone already managed by the active revision is not checked again, so a domain removed from the account does not block unrelated changes;
- managed virtual keys must have `expires_at`, and only their SHA-256 is stored (`POST /api/v1/policy/virtual-keys/generate` returns a random key once);
- `max_changes_per_request: -1` (unlimited) is reserved to the base.

| Field | Default | Description |
|---|---|---|
| `policy.editable` | `false` | Enables the managed layer. Without it, only the base applies and the policy API is read-only. |
| `policy.require_approval` | `true` | Activation of a proposal requires an approval by an approver other than the author. With `false`, a `policy.propose` holder (a policy administrator included) activates their own proposal alone; approving one's own proposal stays refused. [Delegated changes](#policy-delegations) never require approval, whatever this setting. |
| `policy.edit_max_age` | `15m` | Humans must have authenticated at the IdP within this delay to change the policy. |
| `policy.require_amr` | `[]` | Authentication methods required for changes, e.g. `["mfa"]` (the IdP must emit the `amr` claim). |
| `policy.bounds.zones` | (required if editable) | Zone globs managed rules may target (`*` wildcards only), zones the managed layer may bring under management, and zones its folder rules may reach. |
| `policy.bounds.folders` | `[]` | [Folder](providers.md#eurodns-folders) globs managed rules may target (`/ES/**` covers `/ES/Madrid` and `/ES/*`, not `/ES`). It narrows `bounds.zones` for folder rules, never widens it. |
| `policy.bounds.actions` | (required if editable) | Actions managed rules may grant (`policy.*` refused). |
| `policy.delegations` | `[]` | Identities allowed to manage their own roles and bindings in the managed layer, within limits, see [Policy delegations](#policy-delegations). |

Meta actions, granted only by base roles: `policy.read` (view the policy, revisions, diff, explain, who-can), `policy.propose` (create revisions, rollback, generate virtual keys), `policy.approve` (approve, reject, activate). Virtual keys cannot hold them.

Workflow: **propose** (validated, based on the active revision `parent_id`; `409 stale_revision` if another revision was activated meanwhile) → **approve** / **reject** (an author cannot approve their own revision; an author may reject it to withdraw it) → **activate** (atomic: `409 conflict` when another activation won the race; the document is re-validated against the current base) → **rollback** (a new proposal copying an older revision). Each revision shows a unified YAML diff against its parent and an impact analysis (permissions gained and lost per binding, group and key, zones that become managed or are released, a warning when a team that owns RRsets loses write on their zone, and a warning when a released zone still has RRsets owned by the gate: they stay in the store but become read-only until the zone is managed again). Every step is audited (`policy.propose`, `policy.approve`, `policy.reject`, `policy.activate`, with the revision id).

Each replica checks the active revision every 10 seconds and recompiles; evaluation never calls the store. If the base file changes so that the active revision no longer validates, the replica keeps the previous policy and logs an error.

Changes from the UI need the CSRF header and a recent login, with `policy.require_amr` ([design](../design/policy.md#156-protection-of-policy-mutations)). Pipelines (bearer tokens of category `pipeline`) may propose when a base binding grants `policy.propose`, without step-up, but never approve their own proposal. To let a pipeline manage roles and bindings on its own, without approval and within limits, use a [policy delegation](#policy-delegations) rather than `policy.propose`.

## Policy delegations

A delegation lets a trusted identity, typically the CI pipeline whose Terraform stack creates other pipelines, manage **its own** roles and bindings in the managed layer, within limits written in the base file, without approval. The pattern it serves: one stack creates, for each pipeline, its CI service connection and, in the same apply, the gate role and binding that let that service connection write only its own DNS names, the way it creates each pipeline's cloud role and scoped policy. The Terraform provider `KamorionLabs/dnsgate` exposes the API below as `dnsgate_role` and `dnsgate_binding`.

```yaml
policy:
  editable: true
  require_approval: true              # human proposals; delegated changes never need approval
  bounds:
    zones: ["example.com"]
    actions: [dns.read, dns.record.write, ui.read]
  delegations:
    - name: workloads-pipelines
      description: Gate identities of the pipelines created by the workloads stack
      subjects:                       # who may use the delegation (issuer + claim globs, as in bindings)
        - issuer: azure-devops
          claims: {sub: ["sc://<organization>/<project>/workloads-pipelines"]}
      allow:
        zones: ["example.com"]        # zone globs delegated rules may target, within policy.bounds.zones
        actions: [dns.read, dns.record.write]   # within policy.bounds.actions, never policy.*
        records:                      # optional: delegated rules must name hosts and types covered here
          hosts: ["**.apps", "_acme-challenge.**.apps"]
          types: [CNAME, TXT]
        binding_subjects:             # identities a delegated binding may target
          - issuer: azure-devops
            claims: {sub: ["sc://<organization>/<project>/dns-gate-*"]}
        teams:
          from_subject:               # the team is derived from the bound subject
            claim: sub
            regex: "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"
          # names: ["shared-*"]       # and/or fixed team names (globs)
        roles: []                     # existing base or managed roles delegated bindings may also grant
        groups: []                    # groups delegated bindings may target
        max_objects: 100              # roles + bindings of the delegation
```

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Lowercase identifier, recorded as the owner of every object the delegation creates. |
| `description` | | Free text shown in the UI and the API. |
| `subjects[]` | (required) | Matchers (`issuer`, `claims` globs) of the identities that may use the delegation. A subject of a delegation needs no binding: it authenticates on the delegation API even if no role is bound to it (and gets nothing else). |
| `allow.zones` | (required) | Zone globs delegated role rules may target, and zones their folder rules may reach; each must be covered by `policy.bounds.zones`. |
| `allow.folders` | `[]` | [Folder](providers.md#eurodns-folders) globs delegated role rules may target; each must be covered by `policy.bounds.folders`. |
| `allow.actions` | (required) | Actions delegated role rules may grant; within `policy.bounds.actions`, `policy.*` refused. |
| `allow.records.hosts`, `allow.records.types` | | When set, every delegated rule must name hosts (types) and each must be covered by these patterns (same host syntax as rules; `*` for any type). Without it, a delegated rule may cover whole zones. |
| `allow.binding_subjects[]` | (required) | Every subject of a delegated binding must be covered by one of these matchers: same issuer, and each claim of the matcher constrained by the binding with patterns it covers (`sc://o/p/dns-gate-web` and `sc://o/p/dns-gate-*` are covered by `sc://o/p/dns-gate-*`; `sc://o/*` is not). `*` alone is refused. |
| `allow.teams.from_subject` | | The "team from the subject" rule (`claim`, `regex`, `prefix`, as [`team_from`](policy.md#team-derived-from-a-claim)). A delegated binding either sets exactly this `team_from`, or a fixed `team` equal to the team this rule derives from its subject (each subject must then carry exactly one literal value of the claim, and the binding no groups). |
| `allow.teams.names` | | Team globs a delegated binding may set as a fixed `team` (`*` alone refused). At least one of `from_subject` and `names`. |
| `allow.roles` | `[]` | Base or managed roles a delegated binding may grant besides the roles of the delegation; each of their rules must still be within `allow`. |
| `allow.groups` | `[]` | Groups a delegated binding may target. |
| `allow.max_objects` | `100` | Maximum roles plus bindings owned by the delegation (1 to 1000). |

Delegations require `policy.editable`. With [Azure DevOps OIDC](authentication.md#azure-devops-oidc), the issuer's `bound_claims.sub` must accept the delegation subject as well as the pipelines' service connections; give the stack its own dedicated service connection, trusted by no other federation. Delegations are part of the base file: who may delegate, and how far, is decided by a pull request on the configuration, like every `policy.*` grant.

### Delegated objects

Delegated roles and bindings live in the managed document, in its `delegated` section, keyed by a stable name (bindings get a name there; role names are unique across base, managed and delegated roles). Each records its owner:

```yaml
delegated:
  roles:
    dns-gate-web:
      rules: [{zones: [example.com], actions: [dns.read, dns.record.write], records: {hosts: [web.apps], types: [CNAME]}}]
      owner: {delegation: workloads-pipelines, managed_by: terraform, created_by: "azure-devops:sc://...", created_at: ..., updated_by: ..., updated_at: ...}
  bindings:
    dns-gate-web:
      role: dns-gate-web
      team: dns-gate-web
      subjects: [{issuer: azure-devops, claims: {sub: ["sc://<organization>/<project>/dns-gate-web"]}}]
      owner: {...}
```

Validation is the one of the managed layer (bounds, no `policy.*`, issuers, matchers, team syntax, ...) plus the limits of the owner delegation. A delegated role can only be bound by delegated bindings of the same delegation; managed bindings and keys cannot use it, so deleting a delegated object never breaks a human one.

Delegated bindings are evaluated after the other managed bindings, sorted by name. At evaluation, a delegated rule outside its delegation (or whose delegation is no longer in the file) grants nothing.

### Delegation API

Authenticated like the rest of `/api/v1` (bearer token; cookie sessions need the CSRF header on `PUT` and `DELETE`). Pipelines need no step-up; humans matching a delegation need the same recent login as for policy changes.

| Route | Description |
|---|---|
| `GET /api/v1/policy/delegated` | Delegations of the caller (all of them for `policy.read` holders) and their objects. |
| `GET /api/v1/policy/delegated/roles/{name}`, `.../bindings/{name}` | One object with its owner and `etag` (also in the `ETag` header). `404` when it does not exist or is not delegated (taken over). |
| `PUT /api/v1/policy/delegated/roles/{name}` | Create or replace a role. Body: the role (`description`, `rules`, `rebase_on_save`, `ephemeral_ttl`, `max_changes_per_request`), optional `delegation` (needed when the caller matches several) and `managed_by` (client label, for example `terraform`). |
| `PUT /api/v1/policy/delegated/bindings/{name}` | Create or replace a binding: `role`, `team` or `team_from`, `subjects`, `groups`, plus `delegation` and `managed_by`. |
| `DELETE /api/v1/policy/delegated/roles/{name}`, `.../bindings/{name}` | Delete (`?delegation=` optional). |

- **Preconditions**: `If-None-Match: *` creates only (`412 precondition` if the name exists); `If-Match: <etag>` updates or deletes only that version (`412` otherwise). The ETag is per object: changes to other objects never invalidate it.
- **Idempotent**: a `PUT` identical to the current object answers `200` with `"changed": false` and creates no revision.
- **Ownership**: an existing object is changed only by subjects of its owner delegation (`403 not_owner`). A role name used by the base or by a managed role edited by humans is refused (`409 name_taken`).
- **Activation**: each change is applied to the active revision, validated, stored as a new revision authored by the caller (comment `delegation <name>: put role <name>`) and activated at once, **without approval**, whatever `policy.require_approval`. The answer carries the revision id and the impact analysis (`{"object", "changed", "revision_id", "impact"}`); validation errors are `400 invalid_policy` with the same `errors` as proposals.
- **Concurrency**: writes are serialized per replica; when another replica activates a revision at the same time, the change is applied again on the new active revision (preconditions included), up to 5 times, then `409 policy_busy` (the Terraform provider retries). Concurrent writes on different objects never lose an update.
- **Audit**: `policy.delegated.put_role`, `policy.delegated.delete_role`, `policy.delegated.put_binding`, `policy.delegated.delete_binding` (allowed and denied, with the delegation, the object and the impact), plus `policy.activate` for each activated revision.

### Humans and delegated objects

- Humans see delegated objects: in `GET /api/v1/policy` (`managed.delegated`, and the delegations in `base.delegations`), in revision diffs and exports, in explain and who-can.
- A proposal (UI or API) does not edit them: when it omits `document.delegated` (as the UI does), the delegated objects of the active revision are kept; when it sends the section, it must be unchanged, otherwise `403 delegated_object`. A rollback restores the human-edited objects and keeps the delegated ones as they are.
- **Taking over**: a policy administrator (`policy.approve`) may take delegated objects back with `take_over` in the proposal (`["roles/<name>", "bindings/<name>"]`, API only for now): they leave the delegated section, and the proposal may redefine them in `roles` and `bindings` as ordinary managed objects. The proposal is reviewed as any other (`require_approval`), and audited as `policy.delegated.take_over`. Once active, the delegation no longer sees the objects (`404`) and cannot recreate a taken over role (`409 name_taken`).
- A delegated change activates a new revision: proposals open at that moment become stale and must be proposed again.

### Changing a delegation

The limits are checked when an object is written and again on every later revision and policy reload. Narrowing or removing a delegation in the file while objects exceed it makes the active revision invalid against the new base: replicas keep their previous policy and log an error, and a replica that starts with that file serves the base layer only. Delete the objects (or take them over) **before** narrowing or removing the delegation.
