# Zone profiles

A EuroDNS zone profile is an account-wide template (records, URL and mail forwards)
that EuroDNS applies to a domain when it arrives on its nameservers, typically after
a transfer. Preparing a transfer means creating the profile and checking it before
the domain arrives.

The gate serves the zone profiles of each EuroDNS provider that opts in, under one
action, `dns.zone.profile`:

```yaml
providers:
  - id: eurodns
    kind: eurodns
    eurodns: {zone_profiles: true}

roles:
  dns-account-admin:
    rules:
      - zones: ["*"]                 # a profile names no domain: only counts on "*"
        actions: [dns.zone.profile]
```

```sh
P="$GATE/api/v1/providers/eurodns/zone-profiles"
curl -sS "${auth[@]}" -H 'Content-Type: application/json' -X POST "$P/check" -d '{
  "name": "transfer-example.org",
  "records": [
    {"type": "A",     "host": "@",   "ttl": 3600, "rdata": "192.0.2.10"},
    {"type": "CNAME", "host": "www", "ttl": 3600, "rdata": "web.example.net."}],
  "urlForwards": [], "mailForwards": []}'
curl -sS "${auth[@]}" -H 'Content-Type: application/json' -X POST "$P" -d @profile.json   # create
curl -sS "${auth[@]}" "$P"                                                                # list
```

- Give it to the administrators of the EuroDNS account only: a write applies to any
  profile of the account, there is no ownership by team, and reads are restricted too
  (a profile may hold verification tokens).
- Writes need a recent login from people; a profile holding a protected record is
  refused; each subject may run 60 operations a minute.
- Every operation is audited, updates with the previous content.
- The records EuroDNS applies from a profile are created outside the gate: once the
  zone is managed, teams [adopt](../api/ownership.md) them.

Claude can do the same with the `*_zone_profile` MCP tools. Details:
[API guide](../API.md#zone-profiles), [configuration](../config/providers.md#zone-profiles).
