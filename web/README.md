# eurodns-gate web UI

Console served by eurodns-gate under `/ui/`: managed zones, record sets with
their custody (owner team, who created or last changed them, who may change
them), drift, the journal of every write, refusal and reconciliation, a Connect page
(Claude Code, Claude Desktop with its extension download, Terraform and API setups
filled in for the gate),
and the policy: the read-only base layer, the managed layer with its reviewed revisions
(draft, impact, diff, approval, activation, rollback) and a decision simulator.

It consumes the JSON API under `/api/v1` (contract: `internal/uiapi/types.go`)
and signs in through the gate's `/auth/login` flow. The build output in `dist/`
is embedded in the Go binary by `web/embed.go`.

## Develop

```sh
npm ci
npm run dev:fixtures   # demo data, no backend needed (?as=reader: read-only user, ?mcp=readonly|off: MCP state)
npm run dev            # proxies /api and /auth to a gate on http://localhost:8080
```

## Build

```sh
npm run check   # svelte-check, fails on warnings
npm run build   # writes dist/ (base path /ui/)
```

Every POST carries `X-Gate-CSRF` (value of the `gate_csrf` cookie). A
`403 reauth_required` sends the user to `/auth/login?reauth=1`; the policy draft
is kept in `sessionStorage` and restored on return.

The bundle loads nothing from third-party origins and uses no inline scripts or
styles, so it runs under the gate's `default-src 'self'` Content Security Policy.
