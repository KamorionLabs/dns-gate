# Third-party applications (OAuth)

A SaaS that shows and changes the DNS of your gate **as each of its users**, never
with rights of its own (Skopea is the reference case), is an
[OAuth client](../config/authentication.md#oauth-clients) of the gate authorization
server. Each user links their account once: they sign in at the gate, read on the
consent page what the application asks for, and allow it. The application then
calls `/api/v1` with short-lived gate tokens holding the rights of that user capped by
the scopes you granted the client; the gate audit shows the user as subject and the
application as `client_id` and `actor`.

## Declare the client

The application gives you its redirect URI and, preferably, the URL of its public
keys (`private_key_jwt`: no shared secret to store). One client per application
tenant (organisation) keeps tenants apart: a code issued for one redirect URI is
never redeemed for another.

```yaml
oauth:
  clients:
    - id: skopea-acme
      name: "Skopea — organisation Acme"
      auth_method: private_key_jwt
      jwks_uri: https://app.skopea.io/api/v1/orgs/acme/dns/connections/c-7f3a/jwks.json
      redirect_uris: [https://app.skopea.io/api/v1/orgs/acme/dns/oauth/callback]
      scopes: [dns.read, dns.plan, dns.write]   # the ceiling; users consent per scope
      default_scopes: [dns.read]
      # zones: ["*.example.com"]
      write_max_age: 12h                        # dns.write needs a sign-in within 12 hours
```

Review it like a binding: a client is a security decision. With `client_secret_basic`
or `client_secret_post` instead, the secret comes from
`DNS_GATE_OAUTH_CLIENT_SKOPEA_ACME_SECRET`.

## What the application implements

- Discovery: `GET /.well-known/oauth-authorization-server`. Check that `issuer` is the
  gate URL you pinned for the connection.
- Link: redirect the user to `/oauth/authorize` with `response_type=code`, the
  registered `redirect_uri`, `state`, a PKCE S256 challenge and `scope`
  (`dns.read offline_access`). On the callback, check `state` and that `iss` equals
  the pinned issuer (RFC 9207, against mix-up between gates), then redeem the code at
  `/oauth/token` with the verifier and a client assertion (`iss` = `sub` = client id,
  `aud` = the token endpoint, `exp` ≤ 5 minutes, unique `jti`).
- Store the refresh token encrypted, per user and connection; use it from one place
  at a time. Each refresh returns a new one: a refresh token used twice revokes the
  grant (a 30 second grace window returns the same answer to a racing second call).
- Incremental consent: ask `dns.read` at the link, and send the user to
  `/oauth/authorize` with `scope=dns.read dns.plan dns.write` the first time they want
  to change something; the gate merges the scopes into the same grant.
- Errors: `403 scope_insufficient` with `required_scope` (ask for that scope),
  `403 reauth_required` (send the user to `/oauth/authorize?prompt=login`),
  `403 not_delegable` (the endpoint is never open to applications), `invalid_grant` on
  refresh (link again).
- `GET /api/v1/me` gives the client, the scopes and the permissions after the cap:
  what to enable in the interface.
- Unlink: `POST /oauth/revoke` with the refresh token.

Applications never reach policy writes, API keys, gate tokens, the token exchange,
ACME, zone administration or the EuroDNS-compatible API, whatever the scopes.

## Operations

- Users see and revoke their applications under *Connect* > *Connected
  applications*.
- `gate.oauth.manage` holders (people only) list and revoke the grants of a client or
  a user: `GET|DELETE /api/v1/oauth/grants?client=skopea-acme`,
  `?subject=identity-center:alice@example.com`.
- `disabled: true` on the client cuts every token at its next request.
- Audit: `oauth.authorize` (consent, with the scopes), `oauth.token` (code and
  refresh), `oauth.refresh_reuse`, `oauth.revoke`, `oauth.client_auth` (failed client
  authentications, aggregated per client, source and minute); every API call of the
  application carries `client_id`, `actor`, `extra.grant_id` and `extra.scopes`.
