# Adopt and transfer

Records created before the gate are **foreign**: readable, changed by nobody. An
administrator **adopts** them for a team. Later, a team hands records to another
team with a **transfer**, approved by someone allowed to write them for the owner
team. Background: [Teams and ownership](../concepts/ownership.md).

## Adopt existing records

Two steps: a preview, bound to the exact content it saw, then the adoption, all or
nothing, with a mandatory comment. In the Quickstart, `admin` adopts `www CNAME` for
team `web`.

=== "Shell"

    ```sh
    ADMIN=$(curl -fsS "http://127.0.0.1:8090/mint?sub=admin")
    admin=(-H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json")

    PREVIEW=$(curl -fsS "${admin[@]}" -X POST "$GATE/api/v1/zones/example.com/adopt/preview" \
      -d '{"rrsets": [{"host": "www", "type": "CNAME"}], "owner": "web"}')
    echo "$PREVIEW" | jq '.candidates[] | {host, type, adoptable, reason}'

    curl -fsS "${admin[@]}" -X POST "$GATE/api/v1/zones/example.com/adopt" -d "$(jq -n \
      --arg t "$(echo "$PREVIEW" | jq -r .preview_token)" \
      '{rrsets: [{host: "www", type: "CNAME"}], owner: "web", preview_token: $t,
        comment: "www belongs to the web site"}')"
    ```

=== "PowerShell"

    ```powershell
    $Admin = Invoke-RestMethod "http://127.0.0.1:8090/mint?sub=admin"
    $AH = @{ Authorization = "Bearer $Admin" }
    $Sel = @(@{ host = "www"; type = "CNAME" })

    $Preview = Invoke-RestMethod "$Gate/api/v1/zones/example.com/adopt/preview" -Method Post -Headers $AH `
      -ContentType "application/json" -Body (@{ rrsets = $Sel; owner = "web" } | ConvertTo-Json -Depth 4)
    $Preview.candidates | Format-Table host, type, adoptable, reason

    Invoke-RestMethod "$Gate/api/v1/zones/example.com/adopt" -Method Post -Headers $AH `
      -ContentType "application/json" -Body (@{ rrsets = $Sel; owner = "web"
        preview_token = $Preview.preview_token
        comment = "www belongs to the web site" } | ConvertTo-Json -Depth 4)
    ```

=== "Python"

    ```python
    admin = requests.Session()
    admin.headers["Authorization"] = "Bearer " + requests.get(
        "http://127.0.0.1:8090/mint", params={"sub": "admin"}).text
    sel = [{"host": "www", "type": "CNAME"}]

    preview = admin.post(f"{GATE}/api/v1/zones/example.com/adopt/preview",
                         json={"rrsets": sel, "owner": "web"}).json()
    print([(c["host"], c["type"], c["adoptable"], c.get("reason")) for c in preview["candidates"]])

    admin.post(f"{GATE}/api/v1/zones/example.com/adopt", json={
        "rrsets": sel, "owner": "web", "preview_token": preview["preview_token"],
        "comment": "www belongs to the web site",
    }).raise_for_status()
    ```

=== "Node.js"

    ```js
    const adminToken = await (await fetch("http://127.0.0.1:8090/mint?sub=admin")).text();
    const admin = { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" };
    const sel = [{ host: "www", type: "CNAME" }];

    const preview = await (await fetch(`${GATE}/api/v1/zones/example.com/adopt/preview`, {
      method: "POST", headers: admin, body: JSON.stringify({ rrsets: sel, owner: "web" }) })).json();
    console.table(preview.candidates);

    await fetch(`${GATE}/api/v1/zones/example.com/adopt`, { method: "POST", headers: admin,
      body: JSON.stringify({ rrsets: sel, owner: "web", preview_token: preview.preview_token,
        comment: "www belongs to the web site" }) });
    ```

=== "MCP"

    > Preview adopting www CNAME in example.com for team web, then adopt it with the comment "www belongs to the web site".

    Tools `adopt_preview` and `adopt_apply`.

The selection is `rrsets`, or `hosts` globs with `types`. A candidate that is not
adoptable says why: `protected`, `owned_by_other_team`, `reserved_for_other_team`, a
read-only reason such as `server_managed`... `409 adopt_conflict` means something
changed since the preview: preview again.

Once a team owns its records, the gate exports them as Terraform with `import`
blocks: `GET /api/v1/zones/example.com/terraform?team=web`. The
[onboarding guide](../ONBOARDING.md) walks a whole zone through.

## Transfer records to another team

A member of the owner team (or of the target team) asks; someone allowed to write the
records through the **owner** team approves. With
`ownership.require_second_approver: true` the approver must be another person; the
Quickstart keeps the default, so `alice` may approve her own request (audited as
`approval: self`), or send `"apply": true` to do both at once.

=== "Shell"

    ```sh
    ID=$(curl -fsS "${auth[@]}" -X POST "$GATE/api/v1/zones/example.com/transfers" \
      -H "Content-Type: application/json" -d '{
        "rrsets": [{"host": "docs", "type": "CNAME"}], "to_team": "shop",
        "comment": "the shop team runs the docs site now"}' | jq -r .id)

    curl -fsS "${auth[@]}" -X POST "$GATE/api/v1/transfers/$ID/approve" \
      -H "Content-Type: application/json" -d '{"comment": "ok"}' | jq .status
    ```

=== "PowerShell"

    ```powershell
    $Transfer = Invoke-RestMethod "$Gate/api/v1/zones/example.com/transfers" -Method Post -Headers $H `
      -ContentType "application/json" -Body (@{
        rrsets = @(@{ host = "docs"; type = "CNAME" }); to_team = "shop"
        comment = "the shop team runs the docs site now" } | ConvertTo-Json -Depth 4)

    (Invoke-RestMethod "$Gate/api/v1/transfers/$($Transfer.id)/approve" -Method Post -Headers $H `
      -ContentType "application/json" -Body '{"comment": "ok"}').status
    ```

=== "Python"

    ```python
    transfer = s.post(f"{GATE}/api/v1/zones/example.com/transfers", json={
        "rrsets": [{"host": "docs", "type": "CNAME"}], "to_team": "shop",
        "comment": "the shop team runs the docs site now",
    }).json()
    print(s.post(f"{GATE}/api/v1/transfers/{transfer['id']}/approve",
                 json={"comment": "ok"}).json()["status"])
    ```

=== "Node.js"

    ```js
    const transfer = await (await fetch(`${GATE}/api/v1/zones/example.com/transfers`, {
      method: "POST", headers: json, body: JSON.stringify({
        rrsets: [{ host: "docs", type: "CNAME" }], to_team: "shop",
        comment: "the shop team runs the docs site now" }) })).json();
    const decided = await (await fetch(`${GATE}/api/v1/transfers/${transfer.id}/approve`, {
      method: "POST", headers: json, body: JSON.stringify({ comment: "ok" }) })).json();
    console.log(decided.status);
    ```

=== "MCP"

    > Ask to transfer docs CNAME in example.com to team shop, because the shop team runs the docs site now.

    Tools `transfer_propose`, then `transfer_approve` (or `transfer_list` with
    `status: proposed` for the inbox).

The answer is the transfer, `applied` once approved. It fails with `412 precondition`
if a record changed since the request, and expires after `ownership.transfer_ttl`
(7 days) without a decision. The requester can always withdraw it
(`POST /api/v1/transfers/{id}/reject`). `GET /api/v1/transfers?status=proposed` is the
approver's inbox. Terraform never transfers: changing `team` on a `dnsgate_record_set`
fails until the transfer is approved.
