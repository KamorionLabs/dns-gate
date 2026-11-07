# Zones and records

The unit is the **RRset**: every record of one host and one type (`www CNAME`,
`@ TXT`). A write sends the full desired state of the RRset; the gate computes the
change against the zone as it is at the provider, under a per-zone lock.

## List zones

=== "Shell"

    ```sh
    curl -fsS "${auth[@]}" "$GATE/api/v1/zones" | jq -r '.[] | [.zone, .provider, .managed, .foreign] | @tsv'
    ```

=== "PowerShell"

    ```powershell
    Invoke-RestMethod "$Gate/api/v1/zones" -Headers $H | Format-Table zone, provider, managed, foreign
    ```

=== "Python"

    ```python
    for z in s.get(f"{GATE}/api/v1/zones").json():
        print(z["zone"], z["provider"], z["managed"], z["foreign"])
    ```

=== "Node.js"

    ```js
    const zones = await (await fetch(`${GATE}/api/v1/zones`, { headers: auth })).json();
    console.table(zones, ["zone", "provider", "managed", "foreign"]);
    ```

=== "Terraform"

    ```hcl
    data "dnsgate_zones" "all" {}
    ```

=== "MCP"

    > Which DNS zones can I read, and how many records does each have?

    Tool `list_zones` (optional `folder` glob for EuroDNS folders).

`?folder=/ES/**` keeps the EuroDNS zones of a folder. Zones of the provider accounts
that the gate does not manage are listed after the others with `"unmanaged": true`,
read-only.

## Read a record set

The `ETag` header (also the `hash` field) is the content hash of the RRset: send it
back in `If-Match` to change exactly what you read.

=== "Shell"

    ```sh
    curl -sS -i "${auth[@]}" "$GATE/api/v1/zones/example.com/rrsets/www/CNAME"
    ```

=== "PowerShell"

    ```powershell
    $RRset = Invoke-RestMethod "$Gate/api/v1/zones/example.com/rrsets/www/CNAME" -Headers $H `
      -ResponseHeadersVariable RH
    $ETag = $RH.ETag[0]
    ```

=== "Python"

    ```python
    r = s.get(f"{GATE}/api/v1/zones/example.com/rrsets/www/CNAME")
    rrset, etag = r.json(), r.headers["ETag"]
    ```

=== "Node.js"

    ```js
    const res = await fetch(`${GATE}/api/v1/zones/example.com/rrsets/www/CNAME`, { headers: auth });
    const rrset = await res.json();
    const etag = res.headers.get("ETag");
    ```

=== "Terraform"

    ```hcl
    data "dnsgate_record_set" "www" {
      zone = "example.com"
      name = "www"
      type = "CNAME"
    }
    ```

=== "MCP"

    > Who owns www CNAME in example.com, and could I change it?

    Tool `get_rrset`: the RRset, why you may or may not change it, and its recent
    history.

```json
{"host": "www", "type": "CNAME", "ttl": 3600, "values": ["web.example.net."],
 "hash": "21fd1d2e…", "status": "foreign", "protected": false, "adopted": false}
```

`status` is `managed` (owned through the gate), `foreign` (existed before the gate,
read-only until [adopted](ownership.md)), `tainted` (changed outside the gate),
`pending` or `missing`. The whole zone: `GET /api/v1/zones/example.com/rrsets`.

## Create, update, delete

- `If-None-Match: *` creates only: `409 foreign_rrset` if a record exists outside
  the gate, `412 precondition` if the gate already owns one.
- `If-Match: "<hash>"` changes or deletes only if the RRset still has that content:
  `412 precondition` otherwise, nothing is overwritten.

=== "Shell"

    ```sh
    U="$GATE/api/v1/zones/example.com/rrsets/app/CNAME"

    # create
    curl -sS "${auth[@]}" -X PUT "$U" -H "Content-Type: application/json" \
      -H "If-None-Match: *" -d '{"ttl": 3600, "values": ["web.example.net."]}'

    # update what was read
    ETAG=$(curl -fsS -o /dev/null -D - "${auth[@]}" "$U" |
      awk 'tolower($1)=="etag:" {print $2}' | tr -d '\r')
    curl -sS "${auth[@]}" -X PUT "$U" -H "Content-Type: application/json" \
      -H "If-Match: $ETAG" -d '{"ttl": 600, "values": ["web2.example.net."]}'

    # delete (204)
    ETAG=$(curl -fsS "${auth[@]}" "$U" | jq -r '"\"" + .hash + "\""')
    curl -sS "${auth[@]}" -X DELETE "$U" -H "If-Match: $ETAG"
    ```

=== "PowerShell"

    ```powershell
    $U = "$Gate/api/v1/zones/example.com/rrsets/app/CNAME"

    # create
    $Body = @{ ttl = 3600; values = @("web.example.net.") } | ConvertTo-Json
    Invoke-RestMethod $U -Method Put -Headers ($H + @{ "If-None-Match" = "*" }) `
      -ContentType "application/json" -Body $Body

    # update what was read
    $null = Invoke-RestMethod $U -Headers $H -ResponseHeadersVariable RH
    $Body = @{ ttl = 600; values = @("web2.example.net.") } | ConvertTo-Json
    Invoke-RestMethod $U -Method Put -Headers ($H + @{ "If-Match" = $RH.ETag[0] }) `
      -ContentType "application/json" -Body $Body

    # delete
    $null = Invoke-RestMethod $U -Headers $H -ResponseHeadersVariable RH
    Invoke-RestMethod $U -Method Delete -Headers ($H + @{ "If-Match" = $RH.ETag[0] })
    ```

=== "Python"

    ```python
    u = f"{GATE}/api/v1/zones/example.com/rrsets/app/CNAME"

    s.put(u, json={"ttl": 3600, "values": ["web.example.net."]},
          headers={"If-None-Match": "*"}).raise_for_status()

    etag = s.get(u).headers["ETag"]
    r = s.put(u, json={"ttl": 600, "values": ["web2.example.net."]}, headers={"If-Match": etag})
    if r.status_code == 412:
        print("changed since it was read:", r.json()["message"])

    s.delete(u, headers={"If-Match": s.get(u).headers["ETag"]}).raise_for_status()
    ```

=== "Node.js"

    ```js
    const u = `${GATE}/api/v1/zones/example.com/rrsets/app/CNAME`;

    await fetch(u, { method: "PUT", headers: { ...json, "If-None-Match": "*" },
      body: JSON.stringify({ ttl: 3600, values: ["web.example.net."] }) });

    let etag = (await fetch(u, { headers: auth })).headers.get("ETag");
    const res = await fetch(u, { method: "PUT", headers: { ...json, "If-Match": etag },
      body: JSON.stringify({ ttl: 600, values: ["web2.example.net."] }) });
    if (res.status === 412) console.log("changed since it was read");

    etag = (await fetch(u, { headers: auth })).headers.get("ETag");
    await fetch(u, { method: "DELETE", headers: { ...auth, "If-Match": etag } });
    ```

=== "Terraform"

    ```hcl
    resource "dnsgate_record_set" "app" {
      zone   = "example.com"
      name   = "app"
      type   = "CNAME"
      ttl    = 600
      values = ["web2.example.net"]
    }
    ```

    The provider sends `If-None-Match: *` on create and `If-Match` with the hash of
    the last refresh on update and delete.

The answer is the RRset as written, with its new `ETag`. Values use the zone file
format; TXT values are the text itself, unquoted, at any length. Route 53 alias
RRsets take `{"alias": {"target": …, "hosted_zone_id": …}}` instead of `ttl` and
`values`.

## Plan, then apply

For several RRsets at once, or to review before writing: the plan checks RBAC,
ownership, preconditions and the provider validation without writing anything, and
returns a single-use `plan_id` bound to you, the zone and its version.

=== "Shell"

    ```sh
    PLAN=$(curl -fsS "${auth[@]}" -X POST "$GATE/api/v1/zones/example.com/plan" \
      -H "Content-Type: application/json" -d '{"changes": [
        {"host": "api", "type": "A", "ttl": 600, "values": ["192.0.2.20"], "must_not_exist": true},
        {"host": "docs", "type": "CNAME", "ttl": 3600, "values": ["web.example.net."],
         "must_not_exist": true}]}')
    echo "$PLAN" | jq '{allowed, reason, changes}'

    PLAN_ID=$(echo "$PLAN" | jq -r .plan_id)
    curl -fsS "${auth[@]}" -X POST "$GATE/api/v1/zones/example.com/apply" \
      -H "Content-Type: application/json" -d "{\"plan_id\": \"$PLAN_ID\"}"
    ```

=== "PowerShell"

    ```powershell
    $Plan = Invoke-RestMethod "$Gate/api/v1/zones/example.com/plan" -Method Post -Headers $H `
      -ContentType "application/json" -Body (@{ changes = @(
        @{ host = "api"; type = "A"; ttl = 600; values = @("192.0.2.20"); must_not_exist = $true },
        @{ host = "docs"; type = "CNAME"; ttl = 3600; values = @("web.example.net.")
           must_not_exist = $true }
      ) } | ConvertTo-Json -Depth 5)
    $Plan.changes | Format-Table op, host, type, new_values

    Invoke-RestMethod "$Gate/api/v1/zones/example.com/apply" -Method Post -Headers $H `
      -ContentType "application/json" -Body (@{ plan_id = $Plan.plan_id } | ConvertTo-Json)
    ```

=== "Python"

    ```python
    plan = s.post(f"{GATE}/api/v1/zones/example.com/plan", json={"changes": [
        {"host": "api", "type": "A", "ttl": 600, "values": ["192.0.2.20"], "must_not_exist": True},
        {"host": "docs", "type": "CNAME", "ttl": 3600, "values": ["web.example.net."],
         "must_not_exist": True},
    ]}).json()
    if not plan["allowed"]:
        raise SystemExit(f'{plan["reason"]}: {plan["message"]}')
    s.post(f"{GATE}/api/v1/zones/example.com/apply", json={"plan_id": plan["plan_id"]}).raise_for_status()
    ```

=== "Node.js"

    ```js
    const plan = await (await fetch(`${GATE}/api/v1/zones/example.com/plan`, {
      method: "POST", headers: json, body: JSON.stringify({ changes: [
        { host: "api", type: "A", ttl: 600, values: ["192.0.2.20"], must_not_exist: true },
        { host: "docs", type: "CNAME", ttl: 3600, values: ["web.example.net."], must_not_exist: true },
      ] }) })).json();
    if (!plan.allowed) throw new Error(`${plan.reason}: ${plan.message}`);
    await fetch(`${GATE}/api/v1/zones/example.com/apply`, {
      method: "POST", headers: json, body: JSON.stringify({ plan_id: plan.plan_id }) });
    ```

=== "MCP"

    > In example.com, add api A 192.0.2.20 and docs CNAME web.example.net, TTL 600 and 3600. Show me the plan first.

    Tools `plan_rrset_change`, then `apply_rrset_change` with the `plan_id` once you
    confirm. Writes need `mcp.allow_writes`.

A refused plan is `200` with `"allowed": false`, a `reason` and a `message`. A change
deletes with `"delete": true`, and guards with `"expected_hash"` (the `If-Match` of a
plan) or `"must_not_exist"`. The apply fails with `412 precondition` if the zone
changed since the plan, `410 plan_expired` after `mcp.plan_ttl` (10 minutes): plan
again.

To act for another of your teams, send `X-DNS-Gate-Team: <team>` on a write, or
`"team"` in the plan.
