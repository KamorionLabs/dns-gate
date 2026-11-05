# AWS IAM Identity Center (SAML)

This guide signs the users of an AWS IAM Identity Center instance in to dns-gate through a **custom SAML 2.0 application**. It suits organizations whose users already live in Identity Center (for instance synchronized from Entra ID by SCIM) and where registering an OIDC application in the corporate IdP is not an option: everything is configured in the AWS organization.

What it gives:

- the web UI login (`ui.saml`), with bindings on the user's email or Identity Center groups;
- gate-issued tokens (`issuers[].self`) for the API, Terraform and the MCP endpoint, and the Claude Desktop extension, which signs in through the gate.

Field reference: [CONFIG.md, SAML login](CONFIG.md#saml-login) and [Gate-issued tokens](CONFIG.md#gate-issued-tokens).

## 1. Gate settings

Pick the public origin of the gate (here `https://dns.example.com`) and an SP entity id (here `dns-gate`; any string, it becomes the "Application SAML audience").

```yaml
issuers:
  - name: gate
    self: true
    issuer: https://dns.example.com

ui:
  enabled: true
  session_ttl: 8h
  saml:
    issuer: identity-center
    entity_id: dns-gate
    acs_url: https://dns.example.com/auth/saml/acs
    idp_metadata_url: https://portal.sso.eu-west-3.amazonaws.com/saml/metadata/<id>   # step 2
    name_id_format: email
    attributes: {email: email, name: name}
    groups_from_identity_store:                                                          # step 4
      identity_store_id: d-1234567890
      region: eu-west-3
      assume_role_arn: arn:aws:iam::111111111111:role/dns-gate-identity-store

mcp:
  enabled: true
```

Secrets (environment, or `_FILE` variants):

```sh
DNS_GATE_SESSION_KEY=$(openssl rand -hex 32)
DNS_GATE_TOKEN_SIGNING_KEY="$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256)"
# optional, to sign the AuthnRequests:
# DNS_GATE_SAML_SP_KEY=... DNS_GATE_SAML_SP_CERT=...
```

Every instance (replicas, Lambda functions) must share `DNS_GATE_SESSION_KEY` and `DNS_GATE_TOKEN_SIGNING_KEY`: login state, sessions, authorization codes and refresh tokens are sealed with the first, tokens signed with the second, and nothing else is kept between requests.

## 2. Custom SAML application

In the account that holds Identity Center (management account or delegated administrator), **IAM Identity Center, Applications, Add application, "I have an application I want to set up", SAML 2.0**:

| Setting | Value |
|---|---|
| Display name | `dns-gate` (shown in the AWS access portal) |
| Application start URL | `https://dns.example.com/auth/login` |
| IAM Identity Center metadata | copy the **IAM Identity Center SAML metadata file** URL into `ui.saml.idp_metadata_url` (or download the file and inline it in `ui.saml.idp_metadata`) |
| Application metadata | either upload `https://dns.example.com/auth/saml/metadata`, or type the two values below |
| Application ACS URL | `https://dns.example.com/auth/saml/acs` |
| Application SAML audience | `dns-gate` (= `ui.saml.entity_id`) |

The start URL makes the portal tile open `/auth/login`, an SP-initiated login. A tile that posts an unsolicited assertion to the ACS instead is redirected to `/auth/login` by the gate, which never accepts an assertion it did not ask for.

The application can be created with Terraform (`aws_ssoadmin_application` with `application_provider_arn = "arn:aws:sso::aws:applicationProvider/custom"`, `portal_options.sign_in_options { origin = "APPLICATION", application_url = "https://dns.example.com/auth/login" }`, and `aws_ssoadmin_application_assignment`), but the SAML settings (ACS URL, audience, attribute mappings) of a custom application are set in the console.

## 3. Attribute mappings

In the application, **Actions, Edit attribute mappings**:

| User attribute in the application | Maps to | Format |
|---|---|---|
| `Subject` | `${user:email}` | `emailAddress` |
| `email` | `${user:email}` | `unspecified` |
| `name` | `${user:name}` | `unspecified` |

- `Subject` is the NameID, the subject id at the gate (`identity-center:alice@example.com`) and the claim `sub`. With `${user:email}`, subjects are readable and bindings can use emails; set `name_id_format: email`. To survive email changes, map `Subject` to `${user:subject}` (the immutable Identity Center user id) with the `persistent` format and `name_id_format: persistent`, and keep `email` as an attribute for display and bindings.
- The attribute names (`email`, `name`) are the values of `ui.saml.attributes` (`claim: attribute`). Any other attribute (`${user:givenName}`, `${user:familyName}`, `${user:preferredUsername}`...) can be mapped and named there.
- Custom SAML applications do not give the user's group names: resolve them in the identity store (step 4). If your setup does send a `groups` attribute, it is merged with the looked up groups.

## 4. Groups from the identity store

The gate reads the groups of the user at login: `identitystore:GetUserId` (the user whose `userName`, or email with `user_attribute: email`, equals the NameID, or the claim named by `user_claim`), `identitystore:ListGroupMembershipsForMember`, then `identitystore:DescribeGroup` for each group. The **display names** of the groups become the `groups` claim:

```yaml
bindings:
  - role: dns-admin
    team: platform
    subjects:
      - issuer: identity-center
        claims: {groups: [DNS-Admins]}
  - role: dns-reader
    team: readers
    subjects:
      - issuer: identity-center
        claims: {email: ["*@example.com"]}
```

With users synchronized from Entra ID by SCIM, `userName` is normally the user principal name; use `user_attribute: email` when the NameID is the email and differs from it.

The identity store id and region come from `aws sso-admin list-instances` (`IdentityStoreId`, in the region of the instance). The store lives in the account of the Identity Center instance (management account, or the delegated administrator account). The gate usually runs elsewhere: create a role there, assumed by the gate (`assume_role_arn`):

Permissions of `dns-gate-identity-store`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "identitystore:GetUserId",
      "identitystore:ListGroupMembershipsForMember",
      "identitystore:DescribeGroup"
    ],
    "Resource": [
      "arn:aws:identitystore::111111111111:identitystore/d-1234567890",
      "arn:aws:identitystore:::user/*",
      "arn:aws:identitystore:::group/*",
      "arn:aws:identitystore:::membership/*"
    ]
  }]
}
```

Trust policy, for the role of the gate (Lambda execution role, EKS pod identity or IRSA role...):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::222222222222:role/dns-gate"},
    "Action": "sts:AssumeRole"
  }]
}
```

and `sts:AssumeRole` on that role in the policy of the gate's role. The gate uses the default AWS credential chain, assumes the role on the first lookup (session name `dns-gate-groups`) and caches the groups of a user and the group names per instance for `cache_ttl` (default 5 minutes). The role is read-only on the identity store, but it reveals the whole directory: keep it dedicated to the gate.

Without `groups_from_identity_store`, bind on the NameID or on the mapped attributes only.

## 5. Assignment

Only users assigned to the application, directly or through a group, can sign in (**Assigned users and groups**). The assignment opens the door; the bindings of the gate decide what each user may do: a user assigned but matched by no binding gets `403 no_binding` after the login.

## 6. Tokens for the API, Terraform and assistants

SAML users have no access token of their own: the gate issues its tokens (`issuer: gate, self: true`).

- **Claude Desktop**: the Connect page offers the extension. On first use it opens the browser on `https://dns.example.com/oauth/authorize`, which goes through the Identity Center login if needed, then asks the user to allow the extension. The extension keeps a refresh token valid until the end of the gate session (`ui.session_ttl`), then opens the browser again. Nothing to register in Identity Center.
- **Terraform, scripts, other MCP clients**: `POST /api/v1/tokens` from a signed-in UI session returns a token valid `token_ttl` (default 1 hour, never beyond the session). The gate accepts it as a bearer token, bound as `identity-center` with the same bindings.

## 7. Troubleshooting

| Symptom | Cause |
|---|---|
| `400 login_state` on `/auth/saml/acs` | The login cookie did not come back: the gate is not served over HTTPS (the cookie must be `SameSite=None; Secure`), the login took more than 10 minutes, or it was started on another host name than `acs_url`. |
| `401 invalid SAML response` | The gate log (`saml response rejected`) gives the reason: audience different from `entity_id`, ACS URL different from `acs_url` (scheme, host, path), metadata of another application, clock skew above 3 minutes, response older than 90 s. |
| `403 no_binding` | The login succeeded but no binding matches: check the subject and claims in the log, and that the group names are the display names. |
| `502 groups_unavailable` | The identity store lookup failed: credentials, `assume_role_arn` trust, permissions, region or store id. |
| `403 reauth_required` keeps coming back for policy changes | The IdP returned an `AuthnInstant` older than `policy.edit_max_age` although `ForceAuthn` was requested: sign out of the AWS access portal and sign in again. |
