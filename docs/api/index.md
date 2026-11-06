# API by example

The gate's own API lives under `/api/v1`. It is the same whatever the DNS provider of
a zone, and it is what the web UI, the MCP server and the `dnsgate` Terraform provider
use. These pages show each task in several languages; pick yours once, the choice
follows you from page to page.

| Task | Page |
|---|---|
| Get a token, use an API key, exchange a CI token | [Authenticate](authenticate.md) |
| List zones, read, create, update and delete record sets, plan and apply | [Zones and records](records.md) |
| Adopt existing records, move records to another team | [Adopt and transfer](ownership.md) |
| Redirect a host to a URL | [URL forwards](../features/forwards.md) |
| Search the audit journal | [Audit journal](audit.md) |

Every example runs as is against the [Quickstart](../quickstart.md) gate. For your own
gate, change the address and how the token is obtained.

## Setup used on every page

=== "Shell"

    ```sh
    GATE=http://127.0.0.1:8080
    TOKEN=$(curl -fsS "http://127.0.0.1:8090/mint?sub=alice")
    auth=(-H "Authorization: Bearer $TOKEN")
    ```

    Bash or zsh, `curl` and `jq`.

=== "PowerShell"

    ```powershell
    $Gate = "http://127.0.0.1:8080"
    $Token = Invoke-RestMethod "http://127.0.0.1:8090/mint?sub=alice"
    $H = @{ Authorization = "Bearer $Token" }
    ```

    PowerShell 7 (`-ResponseHeadersVariable` is used to read `ETag`).

=== "Python"

    ```python
    import requests

    GATE = "http://127.0.0.1:8080"
    token = requests.get("http://127.0.0.1:8090/mint", params={"sub": "alice"}).text
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    ```

    Python 3 with `requests`.

=== "Node.js"

    ```js
    const GATE = "http://127.0.0.1:8080";
    const token = await (await fetch("http://127.0.0.1:8090/mint?sub=alice")).text();
    const auth = { Authorization: `Bearer ${token}` };
    const json = { ...auth, "Content-Type": "application/json" };
    ```

    Node.js 18 or later, in an ES module (`.mjs`) for top-level `await`.

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
    ```

    See [Terraform](../integrations/terraform.md) for the authentication methods of
    a real pipeline.

=== "MCP"

    ```sh
    claude mcp add --transport http dns-gate-local http://127.0.0.1:8080/mcp \
      --header "Authorization: Bearer $(curl -fsS 'http://127.0.0.1:8090/mint?sub=alice')"
    ```

    Claude calls the gate's tools; the examples show what to ask and the tool it
    uses. See [MCP and Claude](../integrations/mcp.md).

## Conventions

- Hosts are relative to the zone, `@` is the apex. Names inside values without a
  trailing dot are absolute (`web.example.net` is `web.example.net.`).
- Errors are JSON with a stable `reason` for programs:
  `{"reason": "not_owner", "message": "www CNAME is owned by team api"}`. The list is
  in the [API guide](../API.md#errors).
- `GET /.well-known/dns-gate` (no authentication) tells the gate version and its
  features.

## The reference

The [API reference](https://kamorionlabs.github.io/dns-gate/api.html) documents every
operation and schema of the OpenAPI document
([`api/dns-gate.openapi.yaml`](../../api/dns-gate.openapi.yaml)), with generated code
samples (curl, Python, Node.js, PowerShell, Go).

### Try it from the reference

The reference can send requests: choose *Your gate* (or *Quickstart gate*) under
*Server* and paste a token under *Authentication*. The token stays in the browser tab
unless you tick *Remember tokens in this browser*.

!!! warning "Cross-origin requests"
    The requests go from your browser, on `kamorionlabs.github.io`, to your gate. The
    gate does not send CORS headers, so browsers block those calls today: copy the
    generated sample to a terminal instead.
