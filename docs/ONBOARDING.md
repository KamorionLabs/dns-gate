# Onboarding an existing zone

When the gate starts managing `example.com`, every record already in the zone is
**foreign**: visible, but read-only through the gate. This guide takes such a zone
over, team by team, until Terraform manages it with an empty first plan.

Example used below: zone `example.com`, team `web` taking over `www`, `shop` and the
`_acme-challenge` delegation CNAMEs.

## 0. Prerequisites

- `example.com` is listed in the gate's managed zones: in the base config, or, with
  [zone discovery](CONFIG.md#zone-discovery), in the managed policy (open the
  unmanaged zone in the UI, "Manage this zone", then approve and activate the
  revision; `example.com` must match `policy.bounds.zones`).
- The provider credentials of the gate reach the zone (EuroDNS user, Route 53 IAM
  policy: see [providers/route53.md](providers/route53.md#iam)).
- An admin holds `dns.record.adopt` on the zone (base policy).
- Team `web` has a role allowing `dns.record.write` on the hosts it will own, bound
  to its pipeline identity (base or managed policy).
- Protected records (apex NS, MX, SOA, CAA…) are declared: they will never be
  adopted, and stay console-only.

## 1. Inventory

Open the zone in the web UI (or `GET /api/v1/zones/example.com/rrsets`). The first
read fills the inventory cache with one provider read; afterwards the view is
refreshed by reconcile.

All RRsets show as *Not managed* (status `foreign` in the API). Decide, with the teams, who owns what. Typical split:

| Hosts | Owner |
|---|---|
| `@` NS / MX / SOA / CAA | nobody: protected, console only |
| `www`, `shop`, `_acme-challenge.www`, `_acme-challenge.shop` | `web` |
| `mail`, `autodiscover`, SPF/DMARC TXT | `messaging` (or protected) |
| leftovers nobody claims | stay foreign; candidates for deletion in the console |

## 2. Preview the adoption

UI: select the RRsets (or a host glob and types), choose the owner team, click
*Preview*. API equivalent:

```sh
curl -sS -X POST "$GATE/api/v1/zones/example.com/adopt/preview" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"hosts": ["www", "shop", "_acme-challenge.*"], "owner": "web"}'
```

Check every candidate:

- `adoptable: true` — will be adopted with the shown TTL and values;
- otherwise read `reason`: `protected`, `server_managed`, `owned_by_other_team`,
  `already_owned`, `forbidden`, `relative_target`. Fix the selection or the policy,
  then preview again.

Keep the `preview_token`.

## 3. Apply the adoption

Apply is all-or-nothing and needs the token and a comment:

```sh
curl -sS -X POST "$GATE/api/v1/zones/example.com/adopt" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "rrsets": [
          {"host": "www", "type": "CNAME"},
          {"host": "shop", "type": "CNAME"},
          {"host": "_acme-challenge.www", "type": "CNAME"},
          {"host": "_acme-challenge.shop", "type": "CNAME"}
        ],
        "owner": "web",
        "preview_token": "<token from the preview>",
        "comment": "Hand over web hosts to team web (change request 1234)"
      }'
```

A `409 adopt_conflict` means something changed since the preview (someone edited the
zone in the console, or another adoption ran): preview again. On success the RRsets
show `managed`, owner `web`, adopted by you, and one audit event lists them.

## 4. Export Terraform

```sh
curl -sS "$GATE/api/v1/zones/example.com/terraform?team=web" \
  -H "Authorization: Bearer $TOKEN" > web-dns.tf
```

The export contains one resource and one `import` block per RRset:

```hcl
import {
  to = dnsgate_record_set.www_cname
  id = "example.com/www/CNAME"
}

resource "dnsgate_record_set" "www_cname" {
  zone   = "example.com"
  name   = "www"
  type   = "CNAME"
  ttl    = 3600
  values = ["web-lb.example.net."]
}
```

The resources target the `KamorionLabs/dnsgate` provider, which works for every
DNS provider behind the gate. Add `&provider=eurodns` to the URL to export
`eurodns_record_set` resources of the `kamorionlabs/eurodns` provider instead.

Move it into the team's stack, with the provider pointed at the gate (`endpoint`, see
the [provider README](https://github.com/KamorionLabs/terraform-provider-dnsgate))
and authenticated as the team's pipeline identity.

## 5. Import and first plan

```sh
terraform init
terraform plan
```

The first plan **must show only imports and no changes**:

```
Plan: 4 to import, 0 to add, 0 to change, 0 to destroy.
```

Any change means the HCL and the zone disagree (value edited in the console since
the export, normalization difference). Do not apply: re-export, or fix the HCL, until
the plan is empty. Then apply to record the imports in the state.

The `dnsgate` provider only imports RRsets the team already owns, so adopt first.
The `eurodns` provider in gate mode (EuroDNS zones only) can instead adopt during the
import, which requires `dns.record.adopt` for the pipeline identity: usually not
wanted, the adopt-then-export path keeps that right with admins.

## 6. After the takeover

- From now on, team `web` changes these RRsets through Terraform; the gate refuses
  changes by other teams (`not_owner`) and blocks RRsets edited in the console
  (`tainted`) until an admin re-adopts them.
- Repeat steps 2 to 5 for each team.
- Review what stays foreign: either protected on purpose, or to clean up in the
  console.
- Watch the zone summary: `tainted` and `missing` should stay at zero.
