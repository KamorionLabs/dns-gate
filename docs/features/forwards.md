# URL forwards

A URL forward makes the DNS provider answer HTTP requests for a host with a `301` or
`302` redirect to a URL, or with a page framing it. EuroDNS has them; Route 53 does
not (a write there is `400`).

The gate treats a forward like a record set of type `URLFWD` on its host: owned by a
team, with tombstones, transfers, adoption, preconditions and audit. Writing one
needs the action `dns.forward.write`, scoped by the `records.hosts` of the role
(separate from `dns.record.write`: a role writing records does not write forwards).

## Create, change, delete

=== "Shell"

    ```sh
    F="$GATE/api/v1/zones/example.com/forwards/go"
    curl -sS "${auth[@]}" -X PUT "$F" -H "Content-Type: application/json" \
      -H "If-None-Match: *" -d '{"type": "301", "url": "https://www.example.com/landing"}'

    curl -fsS "${auth[@]}" "$GATE/api/v1/zones/example.com/forwards" |
      jq '.https, [.forwards[] | {host, forward}]'

    ETAG=$(curl -fsS "${auth[@]}" "$F" | jq -r '"\"" + .hash + "\""')
    curl -sS "${auth[@]}" -X DELETE "$F" -H "If-Match: $ETAG"
    ```

=== "PowerShell"

    ```powershell
    $F = "$Gate/api/v1/zones/example.com/forwards/go"
    Invoke-RestMethod $F -Method Put -Headers ($H + @{ "If-None-Match" = "*" }) `
      -ContentType "application/json" `
      -Body (@{ type = "301"; url = "https://www.example.com/landing" } | ConvertTo-Json)

    $null = Invoke-RestMethod $F -Headers $H -ResponseHeadersVariable RH
    Invoke-RestMethod $F -Method Delete -Headers ($H + @{ "If-Match" = $RH.ETag[0] })
    ```

=== "Python"

    ```python
    f = f"{GATE}/api/v1/zones/example.com/forwards/go"
    s.put(f, json={"type": "301", "url": "https://www.example.com/landing"},
          headers={"If-None-Match": "*"}).raise_for_status()
    print(s.get(f"{GATE}/api/v1/zones/example.com/forwards").json()["https"])
    s.delete(f, headers={"If-Match": s.get(f).headers["ETag"]}).raise_for_status()
    ```

=== "Node.js"

    ```js
    const f = `${GATE}/api/v1/zones/example.com/forwards/go`;
    await fetch(f, { method: "PUT", headers: { ...json, "If-None-Match": "*" },
      body: JSON.stringify({ type: "301", url: "https://www.example.com/landing" }) });
    const etag = (await fetch(f, { headers: auth })).headers.get("ETag");
    await fetch(f, { method: "DELETE", headers: { ...auth, "If-Match": etag } });
    ```

=== "Terraform"

    ```hcl
    resource "dnsgate_url_forward" "go" {
      zone = "example.com"
      name = "go"
      type = "301" # or "302", or "frame" with optional title, keywords, description
      url  = "https://www.example.com/landing"
      # require_https = true  # fail unless the forwards of the zone answer HTTPS
    }
    ```

=== "MCP"

    > Plan a 301 redirect from go.example.com to https://www.example.com/landing.

    Tool `plan_rrset_change` with a change `{"host": "go", "type": "URLFWD",
    "forward": {"type": "301", "url": "https://www.example.com/landing"}}`, then
    `apply_rrset_change`.

`type` is `301`, `302` or `frame`; `title`, `keywords` and `description` apply to
frames only. In a plan, a forward change is
`{"host": "go", "type": "URLFWD", "forward": {...}}` or `"delete": true`.

## Rules worth knowing

- A forward replaces the `A`, `AAAA` and `CNAME` records of its host. It is created
  only where those are absent or owned by one of your teams, and the reverse; a
  protected entry for one of those types protects the forward too.
- **HTTPS**: the target may be `https://`, but `https://go.example.com` itself is
  answered only when the domain has an EuroDNS *HTTPS redirect* subscription, a paid
  product ordered outside the gate. The gate reports it in `https.status` (`active`,
  `pending`, `no_forward`, `inactive`, `unknown`) and `"require_https": true` refuses a
  write that would answer plain HTTP only (`409 https_unavailable`). The Quickstart
  sandbox has no subscriptions: the status is `unknown`.
- A role granting `dns.forward.write` with `records.types` but no `records.hosts`
  grants the forwards of every host: the gate warns at load.

Details: [API guide](../API.md#url-forwards), [configuration](../config/policy.md#url-forwards).
