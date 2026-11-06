# dns-gate web UI

Console served by dns-gate under `/ui/`: a health summary (drift, pending
writes, recent refusals and failures, discovery errors, stale syncs), the zones
managed by the gate and those that are not, with their DNS provider (EuroDNS,
Route53), record sets with their owner team, who created or last changed them and
why the viewer may or may not change them, the recently deleted record sets still
reserved for their team, record changes (add, edit and delete record sets of your
teams, staged together, reviewed as a plan with its diff, then applied), the
journal of every write, the teams (origin, roles, members for policy readers,
record sets owned per zone, pending transfers, rename for policy proposers) and the
ownership transfers between teams (request from a zone, inbox, approval by a
second person, history),
refusal and reconciliation (reads hidden by default), a Connect page (Claude
Desktop with its extension download, Claude Code, Terraform and API setups filled
in for the gate, and "Get an API token" for curl and Terraform when the gate issues
tokens),
and the policy: the read-only base layer, the managed layer with its reviewed revisions
(draft, impact, diff, approval, activation, rollback) and a decision simulator.

It consumes the JSON API under `/api/v1` (contract: `internal/uiapi/types.go`)
and signs in through the gate's `/auth/login` flow. The build output in `dist/`
is embedded in the Go binary by `web/embed.go`.

## Develop

```sh
npm ci
npm run dev:fixtures   # demo data, no backend needed (?as=reader: read-only user, ?mcp=readonly|off: MCP state,
                       # ?calm=1: nothing needs attention, ?discovery=error: failed zone listing,
                       # ?writeconflict=1: the first apply fails as if the zone changed meanwhile,
                       # ?tokens=off: no gate issuer, so no "Get an API token" on the Connect page;
                       # edge.example.org is a Route53 zone with alias and routing-policy records)
npm run dev            # proxies /api and /auth to a gate on http://localhost:8080
```

## Build

```sh
npm run check   # svelte-check, fails on warnings
npm test        # unit tests of the display helpers (node --test)
npm run build   # writes dist/ (base path /ui/)
```

Every mutation carries `X-Gate-CSRF` (value of the `gate_csrf` cookie). A
`403 reauth_required` sends the user to `/auth/login?reauth=1`; the policy draft,
an adoption in progress and the staged record changes are kept in
`sessionStorage` and restored on return.

Record changes go through `POST /api/v1/zones/{zone}/plan` (desired states with
`expected_hash` or `must_not_exist`) then `POST /api/v1/zones/{zone}/apply` with
the `plan_id`. Edit and delete are offered only on record sets the user's teams own
and their roles allow (computed from `/api/v1/me` and the inventory); the gate
checks everything again. A user of several teams sends the `team` of the plan: the
team of the record sets it changes, or, for new record sets only, the one it picks
in the review (its `default_team` first).

Teams come from `GET /api/v1/teams[/{team}]`, transfers from
`/api/v1/transfers` (`can_decide` marks those the user may approve) and
`POST /api/v1/zones/{zone}/transfers`; a transfer selects record sets (or
reservations) of one owner team in the zone view.

The bundle loads nothing from third-party origins and uses no inline scripts or
styles, so it runs under the gate's `default-src 'self'` Content Security Policy.
