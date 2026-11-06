# Authenticate

Three kinds of credentials, in order of preference:

| Caller | Credential | Lifetime |
|---|---|---|
| Pipelines, workloads, people with an identity provider | an **OIDC token** of an issuer the gate trusts, as `Authorization: Bearer` | minutes to an hour, nothing stored |
| Tools that keep one credential for a whole run (acme.sh, long scripts) | a **gate token** obtained by exchanging the OIDC token | 15 minutes by default |
| Third parties without an identity provider (hosting provider, appliance) | a gate-issued **API key** `dgk_…` | until it expires, is rotated or revoked |

The gate maps the identity to roles and teams through the bindings of its
[policy](../concepts/policy.md). `GET /api/v1/me` shows what it sees.

## Use an OIDC token

Any issuer declared in the configuration, with the gate as audience. The Quickstart
issuer stands in for GitHub Actions, GitLab, Entra ID, AWS or Kubernetes
([CI pipelines](../integrations/ci.md) shows each).

=== "Shell"

    ```sh
    curl -fsS "${auth[@]}" "$GATE/api/v1/me" | jq '{subject, teams, default_team}'
    ```

=== "PowerShell"

    ```powershell
    Invoke-RestMethod "$Gate/api/v1/me" -Headers $H | Select-Object subject, teams, default_team
    ```

=== "Python"

    ```python
    me = s.get(f"{GATE}/api/v1/me").json()
    print(me["subject"], me["teams"], me["default_team"])
    ```

=== "Node.js"

    ```js
    const me = await (await fetch(`${GATE}/api/v1/me`, { headers: auth })).json();
    console.log(me.subject, me.teams, me.default_team);
    ```

=== "Terraform"

    ```hcl
    data "dnsgate_me" "me" {}

    output "teams" {
      value = data.dnsgate_me.me.teams
    }
    ```

```json
{"subject": "local:alice", "teams": ["web"], "default_team": "web"}
```

## Exchange a token for a gate token

`POST /api/v1/token-exchange` (RFC 8693) trades a token of an issuer with
`token_exchange: true` for a gate token with the same identity, valid 15 minutes
(`expires_in` asks for another lifetime, within the limits of the
[configuration](../config/authentication.md#token-exchange)). No other authentication.

=== "Shell"

    ```sh
    GATE_TOKEN=$(curl -fsS "$GATE/api/v1/token-exchange" \
      -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
      -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
      --data-urlencode "subject_token=$TOKEN" | jq -r .access_token)
    ```

=== "PowerShell"

    ```powershell
    $GateToken = (Invoke-RestMethod "$Gate/api/v1/token-exchange" -Method Post -Body @{
      grant_type         = "urn:ietf:params:oauth:grant-type:token-exchange"
      subject_token_type = "urn:ietf:params:oauth:token-type:jwt"
      subject_token      = $Token
    }).access_token
    ```

=== "Python"

    ```python
    gate_token = requests.post(f"{GATE}/api/v1/token-exchange", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": token,
    }).json()["access_token"]
    ```

=== "Node.js"

    ```js
    const exchanged = await (await fetch(`${GATE}/api/v1/token-exchange`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        subject_token: token,
      }),
    })).json();
    const gateToken = exchanged.access_token;
    ```

```json
{"access_token": "eyJ…", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "expires_in": 900}
```

Gate tokens and API keys are never exchanged. A person signed in to the web UI gets
a gate token from the **Connect** page instead (`POST /api/v1/tokens`).

## Issue and use an API key

Keys are created by holders of `gate.apikey.manage` (here `admin`), for one team and
one role, never with more rights than their creator. The key is shown once.

=== "Shell"

    ```sh
    ADMIN=$(curl -fsS "http://127.0.0.1:8090/mint?sub=admin")
    KEY=$(curl -fsS -H "Authorization: Bearer $ADMIN" -X POST "$GATE/api/v1/api-keys" \
      -H "Content-Type: application/json" -d '{
        "name": "web certificates", "team": "web", "role": "acme-solver",
        "expires_at": "2027-06-30T00:00:00Z"}' | jq -r .key)

    # the key is a bearer token like any other
    curl -sS -H "Authorization: Bearer $KEY" -X PUT \
      "$GATE/api/v1/zones/example.com/rrsets/_acme-challenge/TXT" \
      -H "Content-Type: application/json" -d '{"ttl": 600, "values": ["challenge-value"]}'
    ```

=== "PowerShell"

    ```powershell
    $Admin = Invoke-RestMethod "http://127.0.0.1:8090/mint?sub=admin"
    $Key = (Invoke-RestMethod "$Gate/api/v1/api-keys" -Method Post `
      -Headers @{ Authorization = "Bearer $Admin" } -ContentType "application/json" -Body (@{
        name = "web certificates"; team = "web"; role = "acme-solver"; expires_at = "2027-06-30T00:00:00Z"
      } | ConvertTo-Json)).key

    Invoke-RestMethod "$Gate/api/v1/zones/example.com/rrsets/_acme-challenge/TXT" -Method Put `
      -Headers @{ Authorization = "Bearer $Key" } -ContentType "application/json" `
      -Body (@{ ttl = 600; values = @("challenge-value") } | ConvertTo-Json)
    ```

=== "Python"

    ```python
    admin = requests.get("http://127.0.0.1:8090/mint", params={"sub": "admin"}).text
    key = requests.post(f"{GATE}/api/v1/api-keys", headers={"Authorization": f"Bearer {admin}"}, json={
        "name": "web certificates", "team": "web", "role": "acme-solver",
        "expires_at": "2027-06-30T00:00:00Z",
    }).json()["key"]

    requests.put(f"{GATE}/api/v1/zones/example.com/rrsets/_acme-challenge/TXT",
                 headers={"Authorization": f"Bearer {key}"},
                 json={"ttl": 600, "values": ["challenge-value"]}).raise_for_status()
    ```

=== "Node.js"

    ```js
    const admin = await (await fetch("http://127.0.0.1:8090/mint?sub=admin")).text();
    const { key } = await (await fetch(`${GATE}/api/v1/api-keys`, {
      method: "POST",
      headers: { Authorization: `Bearer ${admin}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "web certificates", team: "web", role: "acme-solver", expires_at: "2027-06-30T00:00:00Z" }),
    })).json();

    await fetch(`${GATE}/api/v1/zones/example.com/rrsets/_acme-challenge/TXT`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ ttl: 600, values: ["challenge-value"] }),
    });
    ```

=== "Terraform"

    ```hcl
    provider "dnsgate" {
      endpoint = "https://dns-gate.example.com"
      auth {
        token = var.gate_api_key # dgk_…, from a secret store
      }
    }
    ```

The `acme-solver` role of the Quickstart only writes `_acme-challenge` TXT records,
and they expire after 24 hours. Rotation keeps the old key valid for an overlap
(`POST /api/v1/api-keys/{id}/rotate`), `DELETE /api/v1/api-keys/{id}` revokes at once:
see the [API guide](../API.md#api-keys). ACME clients use the same key on the
[ACME endpoints](../integrations/certificates.md).
