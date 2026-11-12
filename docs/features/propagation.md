# Propagation check

After a change, the provider has the new content at once, but clients see it only
when the caches of the resolvers expire. The propagation check shows where a record
set is already visible: the gate asks the **authoritative name servers** of the zone
and about twenty **public resolvers** around the world, and compares each answer
with the record set as read from the provider.

It is in the web UI (the *Propagation* panel of a record set, opened by itself right
after an apply, refreshed every 5 seconds for up to 2 minutes), in the API and in
the MCP server.

=== "Shell"

    ```sh
    curl -fsS "${auth[@]}" "$GATE/api/v1/zones/example.com/rrsets/app/CNAME/propagation" |
      jq '.summary, [.answers[] | {kind, name, status, ttl_left}]'
    ```

=== "PowerShell"

    ```powershell
    $P = Invoke-RestMethod "$Gate/api/v1/zones/example.com/rrsets/app/CNAME/propagation" -Headers $H
    $P.summary
    $P.answers | Format-Table kind, name, location, status, ttl_left
    ```

=== "Python"

    ```python
    p = s.get(f"{GATE}/api/v1/zones/example.com/rrsets/app/CNAME/propagation").json()
    print(p["summary"])
    for a in p["answers"]:
        print(a["kind"], a["name"], a.get("location", ""), a["status"], a.get("ttl_left"))
    ```

=== "Node.js"

    ```js
    const url = `${GATE}/api/v1/zones/example.com/rrsets/app/CNAME/propagation`;
    const p = await (await fetch(url, { headers: auth })).json();
    console.log(p.summary);
    console.table(p.answers, ["kind", "name", "location", "status", "ttl_left"]);
    ```

=== "MCP"

    > Has the change of app CNAME in example.com propagated yet?

    Tool `check_propagation` (`zone`, `host`, `type`, optional `expect`).

Right after a write, pass what you wrote as `expect`: the `ETag` of a `PUT`, the
`new_hash` of an apply, or `absent` after a delete. A gate instance that has not
seen the write yet reads the zone again instead of comparing with an older content.

```json
{"summary": {"total": 21, "match": 17, "stale": 2, "missing": 0, "error": 2,
             "converged": false, "max_ttl_left": 1740}}
```

Each answer is `match`, `stale` (an older content, cached for `ttl_left` more
seconds), `missing`, `error` or, for alias records, `indeterminate`. `converged`
means every server that answered agrees, with at least one authoritative server;
`max_ttl_left` is the longest any stale cache can last.

!!! note "In the Quickstart"
    The sandbox zone `example.com` is not on the public DNS: its name servers
    (`ns1.example.net`...) answer nothing, so every answer is `missing` or `error`.

## Reading a result

- **Anycast resolvers answer from their site nearest to the gate**: they show the caches near the gate, not those of another continent. The resolvers with a fixed location give the regional view.
- **Resolvers answer from their cache**: one keeps the previous answer (`stale`) or a negative answer (`missing`, for the SOA minimum) until its TTL runs out; `ttl_left` and `max_ttl_left` tell how long at most. Asking again does not refresh their cache.
- Some resolvers refuse some clients: OpenDNS refuses queries from France (court order, `refused (censored)`), and a resolver may be unreachable from a given network. Errors do not count against convergence.

## How answers are compared

- Values are normalized on both sides: sorted, names absolute and lowercase (a EuroDNS target stored relative to the zone is completed with it), TXT on their content whatever the splitting in strings or the quoting, hexadecimal and base64 fields as a server prints them. The CNAME chain of an answer is followed and shown; a name answering a CNAME where another type is expected is `stale`.
- **TTL**: an authoritative answer must carry the expected TTL, and a cached answer may not have more TTL left than it, so a TTL-only change is not reported up to date at once.
- **Alias** RRsets (Route53) and EuroDNS `APEX` RRsets have no values: every address answered must be one of the target's, resolved by the gate (system resolver) for the authoritative servers and asked from the same resolver otherwise. Anything else, including a target that could not be resolved, is `indeterminate`: a CDN answers per location, so sharing an edge address proves nothing. Indeterminate answers never count as up to date.
- **Deletions** (`expect=absent`): an empty answer is a match. An answer section holding records of another name or type, or an answer the resolver flags as its own decision (extended DNS errors Blocked, Censored, Filtered), is an `error`; negative answers of resolvers marked `filtering` are flagged.
- **Converged** needs at least one authoritative answer that matches, and no `stale`, `missing` or `indeterminate` answer.
- **Size**: an answer reports at most 32 values of at most 512 bytes (`truncated`), and a result at most 1 MiB of values.
- **expect**: the inventory a check compares with is the cache of the instance that answers. With `expect` (the `new_hash` of an apply result, the ETag of a `PUT`, or `absent`), an inventory that differs is refreshed from the provider first, at most 6 times a minute per subject and only for subjects holding `dns.read` on the zone; `412 precondition` if it still differs.


## Configure it

On by default, except on AWS Lambda where it needs `propagation.enabled: true`. The
gate needs outbound UDP and TCP port 53 to the resolvers and to the zones' name
servers (the Helm chart's NetworkPolicy allows DNS to any address). The resolver list,
timeouts and limits: [propagation settings](../CONFIG.md#propagation-check). A check
only reads: it is not audited, and it never asks names outside the managed zones.

## Target resolution

`list_rrsets`, `get_rrset` (MCP) and `GET /api/v1/zones/{zone}/rrsets?resolve=true`
also resolve the **targets** of record sets: the name of a CNAME, an alias, a EuroDNS
APEX, an MX, NS, SRV or PTR. Each target is asked to the public resolvers of the check
(unfiltered ones first, a second one when the first fails), recursively, A then AAAA:

| Status | Meaning |
|---|---|
| `live` | resolves to addresses, directly or at the end of its CNAME `chain` |
| `nxdomain` | the target, or a name of its chain, does not exist |
| `nodata` | the name exists without address |
| `servfail` | the resolvers failed (SERVFAIL, REFUSED, filtered) |
| `timeout` | no answer in time |
| `skipped` | beyond 256 targets in one request: filter on host or type |

A target that does not resolve (`nxdomain`, `nodata`) on a service where anyone can
claim a released name (CloudFront, S3, Azure App Service, Traffic Manager, Blob
Storage, Heroku, GitHub Pages, Netlify, Vercel, Shopify...) carries `takeover_risk`
with the service: whoever creates that distribution, bucket or app again would
serve the host. Delete or repoint such records first. A target that still resolves
can be dangling too (an S3 website endpoint answers for any bucket name): DNS alone
does not tell.

> Which CNAMEs of example.com point to something that no longer exists?

Tool `list_rrsets` (`zone`, `type: CNAME`, `resolve: true`).

Resolutions are cached for one minute, whoever asks. A request that has to ask
anything counts once against `propagation.requests_per_minute` of its subject and
against `propagation.max_in_flight` (`429` with `Retry-After` beyond, the MCP tools
answer `rate_limited`); a request is bounded to 10 seconds. Only names read from the
zones of the gate are resolved, never a name given by the caller. Without the
propagation check, `resolve` answers `400 resolve_unavailable`.

Targets are labelled with who runs them by the [`target_owners`](../CONFIG.md#target-owners)
table of the configuration (`target_owner`), with or without `resolve`.

