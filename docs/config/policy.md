# Roles, teams and bindings

The base policy: what each role allows, who gets it and for which team, what nobody may touch. Background: [Roles and rules](../concepts/policy.md), [Teams and ownership](../concepts/ownership.md).

## Roles

A map of named roles. Deny by default: an action is allowed only if a rule of one of the subject's roles matches.

| Field | Description |
|---|---|
| `rules[].zones` | Zone globs (`*` matches any sequence, `*` alone any managed zone, and for `dns.read` and `ui.read` any [discovered](providers.md#zone-discovery) zone). |
| `rules[].folders` | [EuroDNS folder](providers.md#eurodns-folders) globs: the rule also applies to the zones whose folder matches one (`/ES`, `/ES/**`, `/` for the domains in no folder), with the folder known at decision time. A rule needs `zones`, `folders` or both. |
| `rules[].actions` | `dns.read`, `dns.record.write`, `dns.forward.write` ([URL forwards](#url-forwards)), `dns.record.adopt`, `dns.zone.admin`, `dns.zone.profile` ([zone profiles](providers.md#zone-profiles), on `*` only), `dns.ownership.approve`, `domain.read`, `ui.read`, `gate.apikey.manage` (manage the [API keys](../API.md#api-keys) of the subject's teams whose role zones it covers), `gate.oauth.manage` (list and revoke the [OAuth grants](authentication.md#oauth-clients) of every user, people signed in directly only). |
| `rules[].records.hosts` | Host patterns relative to the zone, `@` is the apex. `*` matches one label, `**` one or more labels (a bare `**` matches every host, apex included). |
| `rules[].records.types` | Record types, `*` for any. Omit `records` to cover the whole zone. URL forwards have the type `URLFWD`; `records.types` does not apply to `dns.forward.write`. |
| `rebase_on_save` | On a full-zone PUT, ignore differences outside the role's scope instead of refusing them (stale zones sent by ACME clients). Granted if any role of the subject enables it. |
| `ephemeral_ttl` | RRsets created by the role expire and are garbage-collected after this duration (ACME challenges); a write adding a value pushes the expiry back, never beyond the creation plus `limits.ephemeral_lifetime_factor` TTLs. Applies only if every write role of the subject is ephemeral. Required by the [ACME endpoints](../ACME.md). |
| `max_changes_per_request` | `0` = global default, `-1` = unlimited, otherwise a limit. The most permissive role of the subject wins. |

```yaml
roles:
  spain-dns:
    rules:
      - folders: ["/ES", "/ES/**"]          # every domain of the ES folder and its subfolders
        zones: ["example.es"]               # plus this zone, wherever it is
        actions: [dns.read, dns.record.write, ui.read]
```

`dns.record.write` and `dns.record.adopt` are further limited by ownership: the gate only modifies or deletes RRsets it created or adopted, owned by one of the subject's teams. `dns.ownership.approve` lets a subject adopt RRsets for a team it is not a member of and approve the [ownership transfers](#ownership) of the zone: give it to the people who arbitrate between teams.

### URL forwards

`dns.forward.write` creates, changes and deletes the [URL forwards](../API.md#url-forwards) (HTTP redirects) of the zones whose provider has them (EuroDNS), under the same ownership rules (tombstones, transfers, audit). It is scoped by `records.hosts` only, and is separate from `dns.record.write`: a role writing records does not write forwards. Forwards are adopted with `dns.record.adopt` on the host and type `URLFWD` (`types` empty, `*` or listing `URLFWD`). Through the EuroDNS-compatible full-zone PUT, forward changes are forward writes as well. A `dns.zone.admin` holder may also change or delete the forwards the gate does not own, which stay unowned (the event lists them under `zone_admin_forwards`), as before forwards were owned; creating a forward, or changing one owned by a team, always requires `dns.forward.write`. Mail forwards, DomainConnect and the other zone settings changed by a full-zone PUT still require `dns.zone.admin`. A host holding several forwards is read-only: sent back unchanged it is no change, changed it is refused (ignored for `rebase_on_save` roles). Changes of fields the gate does not write (`id`, `updated`, unknown fields) are ignored and listed under `ignored_out_of_scope` in the audit.

A forward replaces the `A`, `AAAA`, `CNAME` and `APEX` records of its host: a forward is created only where those records are absent or owned by one of the caller's teams, and such a record only where the forward of the host is absent or owned by one of the caller's teams (`409 foreign_rrset` or `403 not_owner` otherwise). An RRset owned by another team but missing at the provider, or reserved for another team by a tombstone, counts as present: a deleted record cannot be taken over through a forward on its host, nor the reverse. A [protected entry](#protected-records) listing one of those types protects the forward of its hosts too. Since `records.types` does not apply to `dns.forward.write`, a rule granting it with `records.types` and no `records.hosts` grants the forwards of every host: the gate warns at load and in the impact analysis of managed revisions.

```yaml
roles:
  marketing-redirects:
    rules:
      - zones: [example.com]
        actions: [dns.read, dns.forward.write, ui.read]
        records: {hosts: [go, "*.go", promo]}
```

## Groups

`groups` maps a name to a description and member matchers. A subject belongs to a group when **one** of its matchers matches (all claims of that matcher must match; an array claim matches when one element matches the glob).

```yaml
groups:
  dns-operators:
    description: Entra app role Gate.Operator
    members:
      - issuer: entra
        claims: {roles: [Gate.Operator]}
  release-pipelines:
    members:
      - issuer: github
        claims: {sub: ["repo:acme/web:environment:production"]}
```

With Entra ID, prefer **app roles** (`roles` claim) assigned to Entra groups. If you match Entra group object ids (`groups` claim), set `groupMembershipClaims: ApplicationGroup` on the gate app registration so only groups assigned to the application are emitted and tokens never hit the groups overage (more than 200 groups replaces the claim by a link the gate does not follow).

## Teams

A team owns RRsets: only its members may change or delete them. `teams` declares each team with the people and the pipelines that act for it, so that a team matches a project (the web shop with its developers and its deployment pipelines, the corporate sites with theirs):

```yaml
teams:
  web:
    description: Web shop, people and pipelines
    members:
      groups: [dns-web]
      subjects:
        - issuer: azure-devops
          claims: {sub: ["sc://org/project/dns-gate-web-*"]}
  corporate:
    description: Corporate sites
    members:
      groups: [dns-corporate]

bindings:
  - role: web-records
    team: web            # the members of web get web-records, acting for web
  - role: corporate-records
    team: corporate
```

| Field | Description |
|---|---|
| `description` | Free text, up to 500 characters. |
| `members.groups` | Groups whose members belong to the team. |
| `members.subjects` | Subject matchers (issuer and claim globs, as in bindings). |

A binding that names a team **without** `groups` or `subjects` grants its role to the members of the team. A binding with its own `groups` or `subjects` binds those only (they act for the team without being listed as its members), as before; a team without members is only named by such bindings.

**Strict references.** Once the file has a `teams` block (even `teams: {}`), every team named by a binding, a virtual key, an [API key](../API.md#api-keys) or a delegation (`allow.teams.names` without wildcard, and the fixed team of delegated bindings) must be declared, in the file or in the managed layer: a typo is refused instead of silently creating a new team. Teams derived from claims are accepted as members of their family: `team_from` (and `allow.teams.from_subject` of a delegation) declares the family `<prefix>*`. Derived teams stay apart from the declared ones: once the block exists, every family (`team_from`, `from_subject`, an issuer `team_claim` with its `team_claim_prefix`) needs a non-empty prefix, the prefixes of different families must not overlap (none starts with another), a family derives teams from the subjects of one issuer only (give each issuer its own prefix), no declared team, binding team, virtual key team or `allow.teams.names` entry may carry the prefix of a family, a binding whose derived team is the name of a declared team does not apply (logged once), and an issuer `team_claim` only yields teams of its own family. A managed revision whose new family would take over the RRsets of a team found in the store gets a warning in its impact analysis. Without a `teams` block, the referenced teams are declared automatically and the gate logs a warning for each (`dns-gate --check` prints them): see [MIGRATION-0.x.md](../MIGRATION-0.x.md#teams-block).

**Several teams.** A subject collects the teams of its bindings in order (base bindings first, in file order). It writes for the first one, its **default team** (`default_team` of `GET /api/v1/me`), and may change the RRsets of all of them. On the gate API it can act for one of its teams only with the `X-DNS-Gate-Team` header or the `team` field of a plan (`403 not_team_member` when it is not a member); the EuroDNS-compatible API always uses the default team.

`GET /api/v1/teams` lists the teams (declared, referenced, families, claim issuers, and owners found in the store that nothing declares), `GET /api/v1/teams/{team}` what a team owns. Teams can also be declared in the [managed layer](managed-policy.md#managed-policy-editing-from-the-ui).

## Ownership

| Field | Default | Description |
|---|---|---|
| `ownership.tombstone_ttl` | `168h` | How long a deleted RRset stays reserved for the team that owned it: meanwhile only that team may create it again (a member of several teams re-creates it for that team) or adopt it, other teams go through a transfer; adoption never lifts the tombstone of another team, whoever adopts. The ownership entry and its tombstone are written in one store transaction: if the tombstone cannot be written, the entry stays (pending) and the reconciler retries. `0s` disables tombstones. RRsets of ephemeral roles (ACME challenges) leave none. |
| `ownership.transfer_ttl` | `168h` | How long a transfer request waits for its approval (1h to 2160h). |
| `ownership.require_second_approver` | `false` | Ownership transfers and renames need a second person, as `policy.require_approval` does for policy revisions. With `false` the requester may approve its own request (or propose it with `"apply": true`), every other check still applying; the audit records `approval: self`. Recommended `true` as soon as two people administer the gate. |
| `ownership.person_issuers` | `[]` | With `require_second_approver`, required when several issuers yield human subjects (category `human`, a `category_map` to `human`, the UI login, SAML), and defaulting to the only one otherwise (`dns-gate --check` says which): only humans signed in with these issuers may request and approve transfers and renames, and the subject id identifies the person on top of the claims below. Recommended: the issuer of the UI login (SAML or OIDC); the gate issuer binds as the issuer of the session, name that one. Exclusive with `machine_approvers`. |
| `ownership.person_claims` | `[tid+oid, email, preferred_username, upn]` | With `require_second_approver`: claims identifying the person behind a token across issuers (`a+b` joins claims, e.g. the immutable `tid+oid` of Entra ID). Requester and approver must share no value, whatever the claim it comes from; `email` is ignored for an issuer with `email_trusted: false` or a token with `email_verified: false`. A requester or an approver none of them identifies cannot take part (fail closed). |
| `ownership.machine_approvers` | `false` | Let pipelines and virtual keys approve transfers and renames and, with `require_second_approver`, let a request nobody can identify as a person be approved: it **weakens** the two-person rule, keep it off unless pipelines must approve. |

**Transfers and renames.** Who may request and approve a transfer or a team rename, how it is applied and retried, and its errors: [API guide](../API.md#teams-and-transfers); the mechanism (one store transaction under the zone lock, background retries under a lease for 24 hours): [design](../design/ownership.md#631-teams-tombstones-and-transfers). Rights held through another team, or a role limited to other records such as ACME challenges, never count for the approver. Audit events: `gate.transfer.propose`, `.approve`, `.reject`, `.apply`, `.expire`, with the requester, the approver and `approval` (`self` or `second`).

## Bindings

| Field | Description |
|---|---|
| `role` | Role granted. |
| `team` | Owner team of the RRsets created through this binding. Required to write (or `team_from`). Must be [declared](#teams) once a `teams` block exists; without `groups` and `subjects`, the role goes to the members of the team. |
| `team_from.claim`, `team_from.regex`, `team_from.prefix` | Derive the owner team from a claim of each subject instead of a fixed `team`, see below. Exclusive with `team`. |
| `groups` | Groups whose members get the role. |
| `subjects[].issuer` | Issuer name. |
| `subjects[].claims` | Claim globs, all must match (at least one claim, typically `sub`). |

A binding needs `groups`, `subjects` or both (a subject matching either is bound), or a declared team with members. A subject collects every matching binding (roles and teams, base bindings first in file order, then managed ones; the first team owns new RRsets). A valid token with no binding gets `403 no_binding`.

### Team derived from a claim

Binding pipeline identities one by one is heavy when each pipeline should own its records. `team_from` gives each subject its own team, computed from one of its claims, so a single binding covers every pipeline whose identity matches a glob. With [Azure DevOps OIDC](authentication.md#azure-devops-oidc) tokens, the team is the service connection name (`sc://<organization>/<project>/<service connection>`, example in that section). With GitHub Actions, the repository:

```yaml
issuers:
  - name: github
    issuer: https://token.actions.githubusercontent.com
    audiences: [dns-gate]
    bound_claims: {sub: ["repo:acme/*"]}         # globs: new repositories need no gate change

bindings:
  - role: pipeline-writer
    team_from:
      claim: sub
      regex: "^repo:acme/([a-z0-9-]+):environment:production$"
      prefix: gh-                                # team gh-<repository>
    subjects:
      - issuer: github
        claims: {sub: ["repo:acme/*:environment:production"]}
```

- `regex` is an RE2 expression anchored with `^` and `$`, with **exactly one** capture group (use `(?:...)` for the others). It is matched against the claim, which must be a string.
- The team is `prefix` followed by the **lowercased** capture. `prefix` is optional, up to 32 characters `[a-z0-9._-]`; use it to keep derived teams apart from hand-written ones.
- When the claim is missing, does not match, or the result is not a valid team name (lowercase identifier, at most 64 characters), the binding **does not apply** to that subject: it fails closed rather than writing under the team of another binding.
- Teams are collected in binding order as with a fixed `team` (base bindings first, in file order) and the first one owns new RRsets: give pipelines matched by a `team_from` binding no other team-bearing binding. The explain simulator shows the derived team (`role@team`), who-can and the impact analysis show the rule. The impact analysis cannot count RRsets owned by derived teams (they are only known per subject).
- Same rules in the managed layer (UI editor: "Team from a claim").

Other subjects that encode one pipeline per value: Kubernetes service accounts (`^system:serviceaccount:([a-z0-9-]+):dns-writer$`, team per namespace), AWS role ARNs (`^arn:aws:iam::111111111111:role/ci-([a-z0-9-]+)$`), any CI whose `sub` names the project. Entra ID access tokens (managed identities, Azure DevOps after the exchange for an Entra token) are different: their `sub` is a pairwise id and they carry no readable per-pipeline claim, so keep one binding per `oid` there.

**Trade-off.** Ownership isolates pipelines from each other: each one can only modify or delete the RRsets its own team created. But every identity matching the binding gets the role, so any of them can **create** any RRset that does not exist yet and that the role allows (hosts, types), and a new identity matching the glob is bound without a gate change. Keep the role narrow (hosts, types, zones), keep `protected` records for what must never change, and treat the right to create identities matching the glob (repositories, service connections, namespaces) as the right to write within that role. Two subjects whose captures differ only by case share a team.

With Azure DevOps, the glob means that anyone allowed to **create a service connection** in the project with a name under the prefix, and to **authorize it for a pipeline they control**, mints a new trusted gate identity. That identity gets its own team, so it cannot change or delete the records of other teams, but it can create any not-yet-existing name its role allows. Mitigations:

- keep the glob prefix (`dns-gate-*`) dedicated to the gate, and make sure no Entra federated credential, AWS role or other federation trusts subjects under it;
- restrict who may create service connections in the project (*Endpoint Creators* and *Endpoint Administrators* of the project, and organization-level service connection permissions) to the people who would otherwise change the gate configuration;
- require approvals and checks on the service connections (or on the environments the pipelines deploy to), so a new pipeline cannot use one unreviewed;
- watch the audit log: every write carries the subject (`azure-devops:sc://...`) and the derived team, and a team that appears for the first time is a new service connection.

## Protected records

`protected[]` entries (`zones`, `hosts`, `types`, same patterns as rules) are never writable nor adoptable, whatever the role. They stay readable.

## Adoption and Terraform export

Adoption brings RRsets created outside the gate (foreign) under the ownership of a team, so that the gate can then manage them. It requires `dns.record.adopt` on each RRset and never applies to protected or server-managed (SOA, locked) records.

1. `POST /api/v1/zones/{zone}/adopt/preview` with a selection (`rrsets`, or `hosts` globs and `types`, plus an optional `owner` team: one of the caller's teams, or another team for the RRsets on which the caller holds `dns.ownership.approve`, the others being `forbidden`): returns the candidates, whether each is adoptable (or why not: `protected`, `owned_by_other_team`, `reserved_for_other_team` (deleted recently by another team, see [tombstones](#ownership)), `already_owned`, `forbidden`, `not_found`, the read-only reason of the RRset such as `server_managed` or `relative_target`, or `invalid` when the provider would refuse its content) and a `preview_token` bound to the exact upstream content.
2. `POST /api/v1/zones/{zone}/adopt` with the chosen `rrsets`, the `preview_token` and a mandatory `comment`. All or nothing: if any RRset changed since the preview or is no longer adoptable, nothing is adopted and the answer is `409 adopt_conflict`.

Both are mutations for CSRF (cookie sessions) and the apply requires the same recent authentication as policy changes for humans.

`GET /api/v1/zones/{zone}/terraform?team=&hosts=&types=&provider=` (`ui.read`) downloads the **managed** RRsets of a zone as Terraform/OpenTofu configuration: one resource per RRset plus `import` blocks (id `<zone>/<host>/<type>`), so a team can move what it adopted into its own stack. By default the resources are `dnsgate_record_set` of the `KamorionLabs/dnsgate` provider, which talks to the gate REST API and works for every DNS provider behind the gate (attributes `zone`, `name`, `type`, `ttl`, `values`, or an `alias` block `{name, zone_id, evaluate_target_health}`); `provider=eurodns` exports `eurodns_record_set` of the `kamorionlabs/eurodns` provider instead (EuroDNS-compatible API, alias RRsets skipped). `hosts` (host globs) and `types` accept comma-separated values or repeated parameters; `rrsets=www/A,@/MX` exports exactly that selection (for example what was just adopted) and takes precedence over `hosts` and `types`.
