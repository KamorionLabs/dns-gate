# Audit journal

Every decision of the gate is recorded: writes with their diff and the provider
snapshot taken before them, refusals with their reason, adoptions, transfers, API key
and policy changes, reconcile findings (drift, expired ACME challenges). The journal
is filtered to the zones the caller can read.

=== "Shell"

    ```sh
    curl -fsS "${auth[@]}" "$GATE/api/v1/audit?zone=example.com&decision=deny&limit=20" |
      jq -r '.entries[] | [.time, .actor.name, .action, .decision, (.reason // "")] | @tsv'
    ```

=== "PowerShell"

    ```powershell
    (Invoke-RestMethod "$Gate/api/v1/audit?zone=example.com&limit=20" -Headers $H).entries |
      Format-Table time, @{ n = "who"; e = { $_.actor.name } }, action, decision
    ```

=== "Python"

    ```python
    page = s.get(f"{GATE}/api/v1/audit", params={"zone": "example.com", "limit": 20}).json()
    for e in page["entries"]:
        print(e["time"], e["actor"]["name"], e["action"], e["decision"], e.get("changes", []))
    ```

=== "Node.js"

    ```js
    const page = await (await fetch(`${GATE}/api/v1/audit?zone=example.com&limit=20`, { headers: auth })).json();
    for (const e of page.entries) console.log(e.time, e.actor.name, e.action, e.decision);
    ```

=== "MCP"

    > What changed in example.com today, and who was refused?

    Tool `search_audit`.

```json
{"entries": [{
  "time": "2026-11-06T19:39:40Z", "request_id": "bec45cad…",
  "actor": {"subject": "local:alice", "name": "alice", "category": "human"}, "teams": ["web"],
  "action": "applyRRsets", "zone": "example.com", "decision": "allow",
  "changes": [{"op": "create", "host": "go", "type": "URLFWD",
               "new_forward": {"type": "301", "url": "https://www.example.com/landing"}}],
  "provider": "eurodns", "snapshot_id": "3"}],
 "next_cursor": "MjAy…"}
```

Filters: `zone`, `host`, `type`, `subject` (substring of the subject or its name),
`category` (`human`, `pipeline`, `key`), `decision` (`allow`, `deny`, `error`),
`since` and `until` (RFC 3339), `limit` (up to 500). Pass `next_cursor` back as
`cursor` for the next page, newest first.

The web UI shows the same journal with filters and diffs. Events are kept
`store.audit_retention` (400 days by default).
