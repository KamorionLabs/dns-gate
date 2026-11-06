# Policy, audit and web UI

## 12. Policy (overview)

Roles, bindings, protected records and limits are declared in YAML, versioned in git
(a permission change is a pull request). A second, managed layer can be edited from
the UI within bounds set in the file (section 15). The full reference is in
[CONFIG.md](../CONFIG.md).

```yaml
roles:
  app-cname-writer:
    rules:
      - zones: ["example.com"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["*.staging", "_*.staging"], types: [CNAME, TXT] }
  acme-solver:
    rebase_on_save: true
    ephemeral_ttl: 24h
    rules:
      - zones: ["*"]
        actions: [dns.read, dns.record.write]
        records: { hosts: ["_acme-challenge", "_acme-challenge.**"], types: [TXT] }
protected:
  - { zones: ["*"], hosts: ["@"], types: [NS, MX, SOA, CAA] }
bindings:
  - role: app-cname-writer
    team: app-team
    subjects:
      - issuer: aws
        claims: { sub: ["arn:aws:iam::111111111111:role/ci-app"] }
```

Host patterns are relative to the zone: `*` matches exactly one label, `**` one or
more labels (`glob.MatchHost`).

A rule applies to the zones matching its `zones` globs, and to the zones whose
provider folder matches its `folders` globs (EuroDNS folders, section 15.9).

## 13. Audit

One event per request (`audit.Event`): time, request id, subject (`issuer:id`),
teams, action, zone, provider id, decision (`allow`/`deny`/`error`), reason, RRset
changes (old and new TTL, values or alias), id (a string) of the latest provider
snapshot taken before the write (EuroDNS; events recorded with a numeric id still
decode).

Events go to two places:

- stdout as JSON lines, for collection in an external, append-only sink;
- the store (DynamoDB with a TTL attribute for retention), so the web UI can query
  them by zone, RRset, subject and time. Reconcile also records events
  (`taint`, `expire`, pending resolution), so drift shows up in the same history.

## 14. Web UI

A web interface for operators and teams. It answers "what is in this zone, who owns
it, who changed it and when", lets people with write rights stage RRset changes and
apply them through a reviewed plan, and lets designated people edit the managed
policy layer (section 15).

### 14.1 Views

- **Zones**: managed zones with their provider folder (EuroDNS, with a folder
  filter) and counters (RRsets, managed, tainted, pending,
  foreign), last upstream sync, last gate write (latest successful write found
  in the journal, so it survives restarts and is the same on every replica); with zone discovery (15.7), the
  zones of the provider accounts that are not managed, flagged unmanaged, with a
  "Manage this zone" action for policy proposers.
- **Inventory of a zone**: every RRset with its status, owner team, protected flag,
  created by / updated by (actor and category: `human`, `pipeline` or `key`),
  timestamps, adoption flag, expiry for ephemeral RRsets, last request id.

  | Status | UI label | Meaning |
  |---|---|---|
  | `managed` | Managed | owned by the gate, upstream content matches |
  | `pending` | Pending | write in flight or interrupted, resolved by reconcile |
  | `tainted` | Drifted | owned, changed outside the gate; writes blocked |
  | `missing` | Missing | owned, deleted outside the gate |
  | `foreign` | Not managed | exists upstream, not owned; read-only for the gate |

  The UI groups `tainted`, `missing` and `pending` as *Needs attention*, and calls
  zones found by discovery but not managed *Not managed (read-only)*.

- **Audit log**: filterable by zone, host, type, subject, actor category, decision,
  time range; each entry shows the RRset diff (old → new TTL and values), the
  reason of a denial and the snapshot id taken before the write.
- **DNS writes**: in a zone, the record sets the user may change (computed from
  `/api/v1/me`) offer edit and delete, and a form adds new ones. Changes are staged
  in the browser, then sent as one `POST /api/v1/zones/{zone}/plan` whose result
  (diff, refusal reasons) is shown for review; *Apply* sends `POST
  /api/v1/zones/{zone}/apply` with the `plan_id`. Each staged change carries the
  hash of the RRset as displayed (`expected_hash`, or `must_not_exist` for a new
  one), so a record changed since is refused instead of overwritten.
- **Connect**: ready-to-paste setups for Claude Code, Claude Desktop, Terraform
  (`dnsgate` provider) and the API, and *Get an API token* (section 9.4).

### 14.2 API

The UI is a static single-page application served by the gate, backed by the JSON
API under `/api/v1` (contract in `internal/uiapi`, reference in
[`api/dns-gate.openapi.yaml`](../../api/dns-gate.openapi.yaml), guide in
[API.md](../API.md)):

| Route | Returns |
|---|---|
| `GET /api/v1/me` | logged-in subject, category, roles, teams, permissions |
| `GET /api/v1/zones` | zone summaries |
| `GET /api/v1/zones/{zone}/rrsets` | zone inventory |
| `GET /api/v1/audit?zone=&host=&type=&subject=&category=&decision=&since=&until=&limit=&cursor=` | audit page, newest first, cursor pagination |
| `POST /api/v1/zones/{zone}/plan`, `/apply` | RRset plan, then its application |
| `POST /api/v1/tokens` | gate-issued token of the session (9.4) |
| `/api/v1/api-keys` | API key management (9.5) |
| `POST /api/v1/token-exchange` | gate token for an OIDC token (9.6) |

The same API accepts bearer tokens, for scripts and the Terraform provider, with
`GET`/`PUT`/`DELETE /api/v1/zones/{zone}/rrsets/{host}/{type}` for single RRsets.
Read routes require `ui.read` (or `dns.read`) on the zone; writes go through the
engine like any other write (RBAC, ownership, lock, audit).

### 14.3 Data path

The inventory is a cache in the store, filled by reconcile (one GET per zone per
interval) and refreshed by every gate write. When a zone's cache is empty (first
start), the inventory performs **one** provider read for that zone to fill it; after
that, UI requests never call the provider. Single-RRset reads (`Engine.RRset`, the
RRset API read by a Terraform plan) use the same cache and one ownership lookup:
writes do not rely on it, they check `ExpectedHash` under the lock against a fresh
read. This keeps the UI out of the upstream rate
budget: browsing cannot get the gate banned. `last_synced_at` tells how fresh the
view is.

### 14.4 Login and session

- OIDC authorization code flow with PKCE against a configured issuer (e.g. Entra ID,
  any OIDC provider), or SAML 2.0 (9.4); the same bindings map the user to roles and
  teams.
- Session in an encrypted, `HttpOnly`, `Secure`, `SameSite=Strict` cookie, short
  lifetime, no token stored in the browser's JavaScript-accessible storage.
- Strict Content Security Policy (no inline script, `default-src 'self'`,
  `frame-ancestors 'none'`).
- The mutations reachable from the browser are DNS writes through plan/apply, gate
  tokens, API keys and policy revisions (section 15). Every one requires the CSRF
  token and a same-origin `Origin`; DNS applies, single-RRset writes, API key
  creations, changes and rotations, and policy changes also require step-up
  authentication (a login more recent than `policy.edit_max_age`, and the
  `policy.require_amr` methods), otherwise `403 reauth_required` and the UI sends
  the user through `/auth/login?reauth=1`. The plan itself is a dry run and
  needs no step-up.

## 15. Editable policy

The policy can be edited from the UI by designated people, without giving up GitOps
for what matters most.

### 15.1 Two layers

| Layer | Where | Content | Who changes it |
|---|---|---|---|
| **base** | YAML config file (git, deployed by CD) | issuers, UI and store settings, managed zones, protected records, **bounds**, every `policy.*` grant, plus base groups, roles, bindings and keys | pull request on the config repository |
| **managed** | store, as immutable **revisions** | zones, groups, roles, bindings, virtual keys (`PolicyDocument`) | proposed and approved in the UI |

At evaluation the active managed revision is merged with base. Constraints on the
managed layer, checked at proposal and again at activation:

- it cannot reuse a base group or role name;
- it cannot grant any `policy.*` action: `policy.read`, `policy.propose` and
  `policy.approve` are granted **only by base bindings**, so the editor can never
  extend who controls the editor;
- every managed rule must stay within the **bounds** declared in base
  (`bounds.zones` globs, `bounds.actions` list);
- protected records (base) win over any managed grant;
- zones it brings under management must match `bounds.zones` and exist in a
  provider account (15.7).

Validation errors come back as `400 {"reason":"invalid_policy","errors":[{"path","message"}]}`.

### 15.2 Lifecycle of a revision

```
            propose (policy.propose)
  (none) ───────────────────────────► proposed ──reject──► rejected
                                         │
                       approve (another policy.approve holder)
                                         ▼
                                      approved
                                         │ activate
                                         ▼
           previous active ◄─superseded─ active
```

- **Approval by someone else**: with `policy.require_approval: true` (default), a
  revision must be approved by a `policy.approve` holder **other than its author**.
  Without required approval, the proposer may activate directly.
- **Stale revisions**: each proposal records its `parent_id` (the active revision it
  was based on). If another revision was activated since, the proposal is marked
  `stale` and cannot be activated; it must be re-proposed on the current active one.
- **Atomic activation**: activation is one conditional write in the store (expected
  active revision → new revision). All replicas pick up the new revision; a
  request is evaluated against exactly one revision.
- **Rollback**: `rollback` on an old revision creates a **new proposal** copying it,
  which goes through the same approval. History is never rewritten.
- **Export**: any revision's managed document can be exported as YAML, to keep a
  copy in git or to move it into the base layer.
- Every proposal, decision, activation and rollback is an audit event.

### 15.3 Review aids

- **Diff**: unified YAML diff of the proposed document against its parent.
- **Impact analysis**: permissions gained or lost per group, team, matcher or
  virtual key (e.g. "team web loses write on owned RRsets (12)"), with warnings
  (empty groups, rules shadowed by protected records, keys without expiry).
- **Explain**: simulate a decision for a concrete subject (issuer + claim values),
  action, zone, host and type, against the active policy or a proposed revision;
  returns the groups, bindings, matching rule, denying rule and layer.
- **Who can**: list the roles, teams, groups, subjects and virtual keys allowed to
  perform an action on an RRset.

### 15.4 Groups and matchers

A **group** is a named set of subject matchers. A matcher is an issuer plus claims
that must all match (glob; an array claim matches when one element matches). Groups
make bindings readable: an Entra app role, a GitHub repository, a list of users.
Bindings grant a role, acting for a team, to groups and/or individual matchers.

```yaml
groups:
  dns-operators:
    members:
      - issuer: entra
        claims: { roles: ["Gate.Operator"] }
  web-ci:
    members:
      - issuer: aws
        claims: { sub: ["arn:aws:iam::111111111111:role/ci-web-*"] }
bindings:
  - role: web-writer
    team: web
    groups: [web-ci]
```

### 15.5 Humans with Entra ID SSO

For the UI, define **app roles** on the gate's app registration and assign them to
Entra **groups** (assignment to groups needs Entra ID P1 or higher), then match them
in base groups through the `roles` claim:

| App role | Typical base grant |
|---|---|
| `Gate.Reader` | `ui.read`, `policy.read` |
| `Gate.Operator` | `ui.read`, `policy.read`, `policy.propose` |
| `Gate.PolicyAdmin` | `ui.read`, `policy.read`, `policy.propose`, `policy.approve` |

Alternative: `groupMembershipClaims: ApplicationGroup` in the app manifest, which
emits in `groups` only the groups assigned to the application (avoids overage), and
match on group object ids. App roles are preferred: names are readable and stable
across tenants.

### 15.6 Protection of policy mutations

- Session login with OIDC code + PKCE (14.4).
- **Step-up**: mutations by humans require a recent authentication
  (`policy.edit_max_age`, checked on `auth_time`) and, if configured, an MFA method
  in `amr` (`policy.require_amr`). Otherwise `403 {"reason":"reauth_required"}` and
  the UI sends the user through `/auth/login?reauth=1`.
- **CSRF**: every POST requires the `X-Gate-CSRF` header equal to the `gate_csrf`
  cookie and a same-origin `Origin` header.
- **Virtual keys** are generated server-side and shown once; only their hash goes
  into a proposal.

### 15.7 Managed zones and zone discovery

The managed zones are the union of the base `zones` and the `zones` of the active
managed revision. Every component reads them from the current policy snapshot: the
route table of the EuroDNS-compatible API, the write engine, reconcile (at each
round), the UI and MCP. Activating a revision that adds a zone is therefore enough
to manage it, on every replica within the reload interval.

`internal/discovery` lists the zones of every provider account (`ListZones`: EuroDNS
`searchDomains` through the shared rate-limited transport, Route 53
`ListHostedZones`, both paginated) at start and
every `providers[].zones.refresh`, filtered by the `include`/`exclude` globs of the
provider, and keeps the lists in memory. Discovered zones that are not managed are **unmanaged**:

| | Managed | Unmanaged |
|---|---|---|
| RBAC actions that can match | all | `dns.read`, `ui.read` only |
| EuroDNS-compatible API, plans, writes, adoption, Terraform export | yes | refused |
| Reconcile | every `reconcile_interval` | never |
| Inventory | cache filled by reconcile and writes | read on demand, reused for `reconcile_interval`; never read by the zone list |

A revision may add a zone only if it is discovered (one extra listing, at most once
a minute, when a proposal names a zone not seen yet). Removing a zone from the
managed layer is allowed; the impact analysis warns when the gate owns RRsets
there. Their ownership entries stay in the store, so managing the zone again
restores them.

### 15.8 Policy delegations

Some policy changes are mechanical: the Terraform stack that creates CI pipelines
creates, for each one, a cloud role scoped to that pipeline, and should create in the
same apply the gate role and binding that let the pipeline's identity write only its
own DNS names. Routing each of them through a human approval defeats the automation,
and granting the stack `policy.propose` with `require_approval: false` would let it
change anything within the bounds.

A **delegation** (`policy.delegations`, base file) is a narrower grant: its subjects
may create, change and delete roles and bindings they own, within `allow` limits
(zones, actions, record scope, the subjects a binding may target, the teams it may
use, a maximum number of objects), through a dedicated API
(`/api/v1/policy/delegated`, CRUD by stable name, ETag preconditions). The review
happens once, when the delegation is merged in the configuration; each delegated
change is then activated without approval.

- **Storage**: delegated objects live in the `delegated` section of the managed
  document, each with its owner (delegation, `managed_by`, created/updated by and
  at). A delegated change is an ordinary revision (author = the pipeline), created on
  the active one and activated at once, so history, diff, export, rollback, explain
  and who-can see it like any other.
- **Validation**: the managed-layer rules (15.1) plus the owner delegation's limits,
  checked at every write and on every later revision; delegated rules are re-checked
  against their delegation at evaluation (defense in depth).
- **Isolation from human edits**: proposals keep the delegated section of the
  active revision (the UI never sends it) and cannot change it; a policy
  administrator takes objects over explicitly (`take_over`), which goes through the
  normal review. Rollbacks keep the delegated objects. Managed bindings cannot use
  delegated roles, so a delegated delete never breaks a human object.
- **Concurrency**: delegated writes are serialized per replica; the activation is the
  conditional write of 15.2, and a lost race re-applies the change (and its
  preconditions) on the new active revision, a bounded number of times, before
  `409 policy_busy`. ETags are per object, so parallel Terraform resources do not
  invalidate each other.
- **Teams**: with `allow.teams.from_subject`, a delegated binding's team is the one
  derived from its own subject, so a pipeline created by the stack owns its records
  and cannot touch those of another pipeline, even though the stack wrote both
  bindings.

### 15.9 EuroDNS folders

Teams often map to EuroDNS folders (one per country or business unit), so rights can
follow a folder instead of a zone list to maintain. Discovery keeps the folder of
each EuroDNS zone (4.1); `Snapshot.Folder` reads it from the live discovery lists, so
the authorizer uses the folder known at decision time, without recompiling the
policy.

- **Selection**: a role rule applies to a zone listed in `zones` or whose folder
  matches `folders` (`glob.MatchFolder`: segments as host patterns, `/ES` exact,
  `/ES/**` below, `/` the root, case-sensitive). The decision records the folder when
  the rule applied through it (`Decision.Folder`), shown by `explain` (`folder`) and
  `who-can` (`by_folder`), and in the audit of the writes, adoptions and transfer
  requests and decisions it granted (`policy.FolderGrants.AllowRRsetFolder`: the
  folder of the authorization itself, recorded for the request, `extra.folder`). Zones without a known folder never match
  a folder selector, so folder rules fail closed: Route53 zones, zones not listed yet,
  a `folderFullPath` absent from the listing (a `null` one is the root), a zone listed
  by two providers, and the zones of a provider whose last successful listing is
  older than `zones.folder_expiry` refresh periods (at least 2, counted from the end
  of that listing).
- **Management**: a folder selector never makes a zone managed. Managed zones stay
  the base and managed `zones`; a discovered zone in a selected folder is only
  readable, as any unmanaged zone. `zones.folders` of a provider narrows what the
  provider serves and what discovery shows.
- **Bounds**: `policy.bounds.folders` and delegation `allow.folders` bound the
  `folders` of managed and delegated rules by static coverage
  (`glob.FolderCovered`), as zone globs; a zone glob of a managed rule is never
  covered by a folder bound, nor the reverse. At decision time, a managed rule that
  applies through a folder also needs the zone to match `policy.bounds.zones`, and a
  delegated one the `allow.zones` of its delegation (`Snapshot.ruleApplies`):
  folders narrow the bounds, never widen them, so moving a base zone kept out of the
  bounds into a selected folder grants the managed layer nothing. `Permissions`
  (`/me`) carries those zones as `folder_zones`. API keys and their recorded grants
  compare folders statically; a rule on every zone (`*`) covers any folder, and a
  managed or delegated rule of the issuer covers a folder pattern only when its
  bounds (and allow.zones) cover every zone (`Snapshot.roleRuleCovers`).
- **Changes**: each listing calls `discovery.Config.OnFolderChange`, with a context
  detached from the listing and one request id per listing: once with a summary for
  the first listing of a provider by the process (count and `FolderDigest`), then
  for each zone a later listing finds, finds in another folder, or no longer lists;
  the app records `gate.zone.folders_listed`, `gate.zone.folder_seen`,
  `gate.zone.folder_changed` and `gate.zone.folder_gone`. The previous folders are only in
  memory: instances do not compare their views, a new one records the folders it
  starts from. Folder-based rights are therefore delegated to whoever can move
  domains in the EuroDNS account ([THREAT-MODEL.md](../THREAT-MODEL.md)).
- **Review**: the impact analysis lists every new or changed folder rule as a
  dynamic rule with the zones it reaches currently, and warns while discovery has
  not listed the accounts. Loading the configuration warns about folder selectors
  without a EuroDNS provider or outside every provider's `zones.folders`.
