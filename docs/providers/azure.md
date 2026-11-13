# Azure DNS provider

The `azure` provider fronts the public DNS zones of one Azure subscription,
optionally of one resource group (package `internal/provider/azure`, Azure
Resource Manager API `2018-05-01`). Declare one provider per subscription.

## Configuration

```yaml
providers:
  - id: azure-prod
    kind: azure
    zones: {include: ["*.example.net"]}
    azure:
      subscription_id: 00000000-0000-0000-0000-000000000001
      resource_group: rg-dns
      tenant_id: 11111111-1111-1111-1111-111111111111
      client_id: 22222222-2222-2222-2222-222222222222
```

| Field | Default | Description |
|---|---|---|
| `subscription_id` | `AZURE_SUBSCRIPTION_ID` | Subscription holding the zones (required). |
| `resource_group` | | Serves only the zones of this resource group. Required when two groups of the subscription hold a zone of the same name. |
| `tenant_id`, `client_id` | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | Microsoft Entra tenant and application (client) id. With `managed_identity`, `client_id` selects a user-assigned identity. |
| `federated_token_file` | `AZURE_FEDERATED_TOKEN_FILE` | File holding a token of an identity provider the application trusts (workload identity federation). Read at every token renewal. |
| `managed_identity` | `false` | Use the managed identity of the host (Azure VM, AKS, Container Apps), through the instance metadata service. |
| `max_retries` | `3` | Retries of a throttled request (429) and of a failed read. |

### Identity

The gate uses, in this order:

1. **a client secret**: `AZURE_<ID>_CLIENT_SECRET`, else `AZURE_CLIENT_SECRET`
   (or their `_FILE` variants, see [Secrets](../CONFIG.md#secrets));
2. **a federated token** (`federated_token_file`): no secret to store. On EKS,
   project a service account token with the audience
   `api://AzureADTokenExchange` and add a federated credential for the cluster
   OIDC issuer and the service account to the application;
3. **the managed identity** of the host (`managed_identity: true`).

Assign the identity the built-in role **DNS Zone Contributor** on the resource
group of the zones (or on each zone); **Reader** is enough for zones that stay
unmanaged. Only the public cloud endpoints are used.

## Reading

`ReadZone` lists the record sets of the zone (500 per page): an RRset is one
record set, kept with its etag.

| Upstream | RRset |
|---|---|
| Plain record set | values in the [canonical form](route53.md#canonical-values); the strings of a `TXT` record are joined |
| Apex `NS` and `SOA` | read-only `server_managed` |
| Alias record set (`targetResource`) | read-only `alias`, the resource id as value |
| Empty record set | not returned; a create replaces it |

Private DNS zones are another Azure service and are not listed.

## Writing

Each changed RRset is one conditional request, deletes first:

| Change | Request |
|---|---|
| create | `PUT` with `If-None-Match: *` |
| update | `PUT` with `If-Match: <etag read>`; the metadata of the record set is kept |
| delete | `DELETE` with `If-Match: <etag read>` |

A record set changed upstream since it was read answers 412: the write is
refused with `precondition` and the client retries on fresh content.

| Property | Value |
|---|---|
| Atomic | Per RRset only: the RRsets of one write are separate requests. A failure after the first one leaves the zone partially changed; the gate then settles ownership on what it reads back. |
| Writable types | `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS` (not at the apex), `PTR`, `SRV`, `TXT` |
| TTL | 1 second or more |
| `TXT` | Cut in strings of 255 bytes |

## Limitations (v1)

- Alias record sets are read-only; `DS`, `TLSA` and `NAPTR` (newer API
  versions) are not supported.
- Public cloud only (no sovereign clouds), public zones only.
- The adapter is tested against a fake of the Resource Manager API, not
  against a live subscription: validate it on a test zone first.
