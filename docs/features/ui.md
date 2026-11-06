# Web UI

The gate serves a web console under `/ui/` for operators and teams. People sign in
with OIDC or SAML; what they see and may do comes from the same policy as every other
client, recomputed on every request.

| View | What it answers |
|---|---|
| **Zones** | managed zones with their provider, EuroDNS folder and counters (managed, foreign, needing attention), last sync and last write; zones of the accounts not managed yet, with *Manage this zone* for policy proposers |
| **Zone** | every record set with its status, owner team, protected flag, who created and changed it and when; tombstones; staged changes reviewed as a plan, then applied |
| **Journal** | the audit journal, filtered by zone, host, type, subject, category, decision and time, with diffs and refusal reasons |
| **Teams** | teams, their members and what they own; the transfer inbox |
| **Policy** | who may do what, per group, pipeline and API key (simple view), or every layer, binding, role and bound (expert view); revisions with diff, impact analysis, approval and rollback |
| **Connect** | ready-to-paste setups for Claude Code, Claude Desktop, Terraform and curl, and a short-lived API token for the signed-in user |

## Changing DNS from the UI

In a zone, the records you may change offer *Edit* and *Delete*, and a form adds new
ones. Changes are staged in the browser, then sent as one plan whose result (diff,
refusal reasons) is shown before *Apply*. Each change carries the hash of the record
as displayed, so a record changed meanwhile is refused instead of overwritten.

Applying changes, issuing API keys and editing the policy need a recent login
(`policy.edit_max_age`, 15 minutes): the UI sends you through the identity provider
again when needed.

## Enabling it

```yaml
ui:
  enabled: true
  issuer: entra                     # an issuer of the configuration (OIDC)
  client_id: <application-id>
  redirect_url: https://dns-gate.example.com/auth/callback
```

The session cookie is encrypted with `DNS_GATE_SESSION_KEY` (32 bytes). SAML instead
of OIDC: `ui.saml`, see [SAML with IAM Identity Center](../IDENTITY-CENTER.md). Every
field: [UI configuration](../CONFIG.md#ui).

Browsing never calls the DNS provider: views are served from the gate's inventory,
refreshed by every write and every reconcile, so the UI cannot exhaust the provider's
rate limit.
