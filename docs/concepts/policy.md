# Roles and rules

Deny by default: an action is allowed only when a rule of one of the caller's roles
matches the zone, the host and the record type.

```yaml
roles:
  web-cname-writer:
    rules:
      - zones: [example.com]
        actions: [dns.read, dns.record.write, ui.read]
        records:
          hosts: ["*.staging", "app"]     # relative to the zone, @ is the apex
          types: [CNAME, TXT]
```

## Rules

| Field | Matches |
|---|---|
| `zones` | zone globs: `example.com`, `*.example.com`, `*` for every managed zone |
| `folders` | EuroDNS folders: `/ES` the folder ES, `/ES/**` every folder below it, `/` the domains in no folder |
| `records.hosts` | host patterns: `*` one label, `**` one or more labels, `@` the apex; omit `records` for the whole zone |
| `records.types` | record types, `*` for any |
| `actions` | what the rule grants, below |

| Action | Grants |
|---|---|
| `dns.read`, `ui.read` | read the zone through the API, the UI or MCP |
| `dns.record.write` | create records, and change or delete those your team owns |
| `dns.forward.write` | the same for [URL forwards](../features/forwards.md) |
| `dns.record.adopt` | take over existing (foreign) records for your team |
| `dns.ownership.approve` | adopt for another team, approve transfers: for the people who arbitrate between teams |
| `dns.zone.admin` | full-zone settings of the EuroDNS-compatible API |
| `dns.zone.profile` | EuroDNS [zone profiles](../features/zone-profiles.md), on `*` only |
| `gate.apikey.manage` | issue and revoke API keys for your teams, never with more rights than yours |
| `policy.read`, `policy.propose`, `policy.approve` | view and edit the policy from the UI (base file only) |

Role options: `ephemeral_ttl` makes created records expire (ACME challenges),
`max_changes_per_request` caps the blast radius, `rebase_on_save` tolerates the stale
full-zone writes of some ACME clients.

### Folders

With EuroDNS, a rule can follow the account's folders instead of listing zones:

```yaml
roles:
  spain-dns:
    rules:
      - folders: ["/ES", "/ES/**"]   # every domain of ES and its subfolders
        zones: [example.es]          # plus this zone, wherever it is
        actions: [dns.read, dns.record.write, ui.read]
```

Moving a domain to another folder in the EuroDNS console changes who may write it
at the next listing, without a policy change. Whoever may move domains between
folders therefore controls folder-based rights: see the
[threat model](../THREAT-MODEL.md).

## Groups

Groups name sets of people or pipelines once, to bind them together:

```yaml
groups:
  dns-operators:
    members:
      - issuer: entra
        claims: {roles: [Gate.Operator]}   # an Entra app role
```

## Protected records

Never writable nor adoptable, whatever the role, administrators included:

```yaml
protected:
  - zones: ["*"]
    hosts: ["@"]
    types: [NS, SOA, MX, CAA]
```

## Base file and managed layer

The configuration file is the **base** policy, reviewed in git. With
`policy.editable: true`, designated people also edit a **managed** layer from the UI:
zones, teams, groups, roles and bindings, as revisions proposed, approved by another
approver, activated atomically and rolled back, with a diff and an impact analysis.
The managed layer stays within `policy.bounds` (zones and actions written in the base
file) and never grants `policy.*`.

A **delegation** lets a trusted pipeline (the Terraform stack creating other
pipelines) manage its own roles and bindings within limits, without approval: the
`dnsgate_role` and `dnsgate_binding` resources. Details:
[managed policy](../CONFIG.md#managed-policy-editing-from-the-ui) and
[delegations](../CONFIG.md#policy-delegations).

Next: [Teams and ownership](ownership.md).
