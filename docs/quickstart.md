# Quickstart

Run a gate on your machine, with nothing to sign up for: a **sandbox** plays the DNS
provider (an in-memory EuroDNS API holding `example.com`) and the identity provider
(a local OpenID issuer that signs a token for any name). The gate itself is the real
one, with the memory store.

You need Go 1.26 and a clone of the repository:

```sh
git clone https://github.com/KamorionLabs/dns-gate && cd dns-gate
```

## 1. Start the sandbox and the gate

In a first terminal:

```sh
go run ./examples/quickstart
```

It prints three `export` lines (the EuroDNS key of the sandbox and two keys the gate
generates for its UI sessions and its own tokens). Paste them in a second terminal,
then start the gate with [`examples/quickstart/config.yaml`](../examples/quickstart/config.yaml):

```sh
export EURODNS_API_KEY=quickstart
export DNS_GATE_SESSION_KEY_FILE=...
export DNS_GATE_TOKEN_SIGNING_KEY_FILE=...
go run ./cmd/dns-gate -config examples/quickstart/config.yaml | tee gate.log
```

The configuration declares three people, each with a role and a team:

| Subject | Team | May |
|---|---|---|
| `alice` | `web` | read and write records and URL forwards in `example.com` |
| `bob` | `shop` | the same, for the `shop` team |
| `admin` | `platform` | adopt existing records for any team, approve transfers, issue API keys |

Apex `NS`, `SOA`, `MX` and `CAA` records are protected: nobody may change them.

!!! tip "The web UI"
    `go run` serves a placeholder page under `/ui/`. Build the console once with
    `cd web && npm ci && npm run build && cd ..`, restart the gate and open
    <http://127.0.0.1:8080/ui/>: you are signed in as `alice`
    (`go run ./examples/quickstart -ui-user bob` for someone else).

## 2. Get a token and read the zone

The sandbox issuer signs a one-hour token for any name:

=== "Shell"

    ```sh
    GATE=http://127.0.0.1:8080
    TOKEN=$(curl -fsS "http://127.0.0.1:8090/mint?sub=alice")
    curl -sS -H "Authorization: Bearer $TOKEN" "$GATE/api/v1/zones/example.com/rrsets"
    ```

=== "PowerShell"

    ```powershell
    $Gate = "http://127.0.0.1:8080"
    $Token = Invoke-RestMethod "http://127.0.0.1:8090/mint?sub=alice"
    $H = @{ Authorization = "Bearer $Token" }
    $Zone = Invoke-RestMethod "$Gate/api/v1/zones/example.com/rrsets" -Headers $H
    $Zone.rrsets | Format-Table host, type, status, owner
    ```

=== "Python"

    ```python
    import requests

    GATE = "http://127.0.0.1:8080"
    token = requests.get("http://127.0.0.1:8090/mint", params={"sub": "alice"}).text
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    for r in s.get(f"{GATE}/api/v1/zones/example.com/rrsets").json()["rrsets"]:
        print(r["host"], r["type"], r["status"], r.get("owner", ""))
    ```

=== "Node.js"

    ```js
    const GATE = "http://127.0.0.1:8080";
    const token = await (await fetch("http://127.0.0.1:8090/mint?sub=alice")).text();
    const auth = { Authorization: `Bearer ${token}` };
    const zone = await (await fetch(`${GATE}/api/v1/zones/example.com/rrsets`, { headers: auth })).json();
    console.table(zone.rrsets.map(({ host, type, status, owner }) => ({ host, type, status, owner })));
    ```

Every record is `foreign`: it existed before the gate, so the gate shows it but
changes it for nobody until an administrator [adopts](concepts/ownership.md#adoption)
it for a team.

## 3. Create a record

`alice` creates `app CNAME`; it now belongs to her team, `web`:

=== "Shell"

    ```sh
    curl -sS -X PUT "$GATE/api/v1/zones/example.com/rrsets/app/CNAME" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -H "If-None-Match: *" -d '{"ttl": 3600, "values": ["web.example.net."]}'
    ```

=== "PowerShell"

    ```powershell
    $Body = @{ ttl = 3600; values = @("web.example.net.") } | ConvertTo-Json
    Invoke-RestMethod "$Gate/api/v1/zones/example.com/rrsets/app/CNAME" -Method Put `
      -Headers ($H + @{ "If-None-Match" = "*" }) -ContentType "application/json" -Body $Body
    ```

=== "Python"

    ```python
    r = s.put(f"{GATE}/api/v1/zones/example.com/rrsets/app/CNAME",
              json={"ttl": 3600, "values": ["web.example.net."]},
              headers={"If-None-Match": "*"})
    print(r.status_code, r.json()["owner"])
    ```

=== "Node.js"

    ```js
    const res = await fetch(`${GATE}/api/v1/zones/example.com/rrsets/app/CNAME`, {
      method: "PUT",
      headers: { ...auth, "Content-Type": "application/json", "If-None-Match": "*" },
      body: JSON.stringify({ ttl: 3600, values: ["web.example.net."] }),
    });
    console.log(res.status, (await res.json()).owner);
    ```

=== "Terraform"

    ```hcl
    terraform {
      required_providers {
        dnsgate = { source = "KamorionLabs/dnsgate", version = "~> 0.3" }
      }
    }

    provider "dnsgate" {
      endpoint = "http://127.0.0.1:8080"
      auth {
        token_command = ["curl", "-fsS", "http://127.0.0.1:8090/mint?sub=alice"]
      }
    }

    resource "dnsgate_record_set" "blog" {
      zone   = "example.com"
      name   = "blog"
      type   = "CNAME"
      ttl    = 3600
      values = ["web.example.net"]
    }
    ```

    `terraform init && terraform apply`, then a second `terraform plan` shows no change.

Now try the same `PUT` as `bob` (`sub=bob`): `403 not_owner`, the record belongs to
`web`. Try `@ MX` as anyone: `403`, protected. EuroDNS only accepts some TTLs (600,
900, 1800, 3600...): `ttl: 300` is refused before anything is written.

## 4. Check propagation and the audit trail

Ask where the new record is visible (in the sandbox, `example.com` is not on the
public DNS, so every answer is `missing` or `error`; on a real zone you watch the
resolvers catch up):

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$GATE/api/v1/zones/example.com/rrsets/app/CNAME/propagation" | jq .summary
```

Every decision is an audit event, in the journal (`GET /api/v1/audit`) and as a JSON
line on the gate's stdout. The Quickstart configuration chains those lines
(`audit.hash_chain: true`); check the log you kept with `tee`:

```sh
go run ./cmd/dns-gate audit verify gate.log
```

## 5. Connect Claude

The gate serves an [MCP](integrations/mcp.md) endpoint at `/mcp`. With Claude Code:

```sh
claude mcp add --transport http dns-gate-local http://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer $(curl -fsS 'http://127.0.0.1:8090/mint?sub=alice')"
```

The token lasts one hour; run the command again (after `claude mcp remove dns-gate-local`)
to renew it. A real gate uses a token helper instead, see [MCP and Claude](integrations/mcp.md).

Then ask: *"Which records of example.com does my team own? Plan adding `api A 192.0.2.20` with a TTL of 600."*
Claude plans the change, shows it, and applies it only when you confirm.

## Next

- [API by example](api/index.md): every operation (preconditions, plan and apply,
  adoption, transfers, URL forwards, API keys, propagation, audit) in your language,
  all runnable against this gate.
- [Concepts](concepts/identities.md): how identities, roles and ownership fit together.
- Deploy for real: [Kubernetes with Helm](deploy/helm.md) or [AWS Lambda](deploy/lambda.md).
