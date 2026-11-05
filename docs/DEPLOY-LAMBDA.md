# Deploying on AWS Lambda

The same `dns-gate` binary runs as a long-lived container (Helm chart, ECS) or as an AWS
Lambda function. Lambda suits a low-volume deployment in front of **Route 53**: no
cluster, no load balancer, no NAT, a bill close to zero. It is **not recommended in
front of EuroDNS** (see [below](#why-not-in-front-of-eurodns)).

## Architecture

```
 clients (Terraform, CI, MCP, browser)
        │ HTTPS, Authorization: Bearer <OIDC token> / session cookie
        ▼
 API Gateway HTTP API ── custom domain (regional ACM certificate), $default stage
        │ $default route, Lambda proxy integration, payload format 2.0
        ▼
 Lambda dns-gate (provided.al2023, arm64, no VPC) ──► Route 53 API
        │        ▲                                 ──► Secrets Manager (init)
        │        │ {"dns_gate_task":"maintenance"}  ──► S3 / SSM config (init)
        │        │
        │   EventBridge Scheduler, rate(5 minutes)
        ▼
 DynamoDB table (on-demand, PITR, TTL on "ttl"):
 ownership, zone versions and locks, audit, policy revisions, MCP plans
```

- **API Gateway HTTP API** terminates TLS on the custom domain and invokes the function
  with the 2.0 payload. The gate does its own authentication (OIDC bearer tokens,
  virtual keys, UI session): no API Gateway authorizer. Use an empty API mapping key so
  that paths reach the gate unchanged.
- **Lambda**: one execution environment serves one request at a time. Nothing runs
  between invocations: the work the container does in background goroutines happens
  either lazily on requests or in the scheduled maintenance pass.
- **EventBridge Scheduler** invokes the function every 5 minutes with the constant input
  `{"dns_gate_task":"maintenance"}`.
- **DynamoDB** is the only supported store on Lambda (`store.type: dynamodb`, any other
  type is a configuration error when `AWS_LAMBDA_RUNTIME_API` is set): every instance
  shares ownership, zone locks and versions, the managed policy and the MCP plans.
- **No VPC, no NAT**: DynamoDB, Route 53, Secrets Manager, S3 and SSM are reached over
  their public endpoints with the function role.

### What happens where

| Work | Container (`Run`) | Lambda |
|---|---|---|
| Policy reload (active managed revision) | every 10 s | before a request when the last check is older than 10 s; every maintenance pass |
| Zone discovery (`zones_discovery`) | every `refresh`, 5 min after a failure | before a request and in the maintenance pass, when older than `refresh` (5 min after a failure) |
| Reconcile of the managed zones | every `reconcile_interval` | every maintenance pass (5 min) |
| Expired MCP plans | every 10 min | every maintenance pass |

The maintenance pass runs every step even when one fails and returns the joined errors:
the invocation then fails, which shows in the `Errors` metric and the logs. The next
schedule is 5 minutes away, so **disable retries**: `retry_policy { maximum_retry_attempts = 0 }`
on the schedule and `maximum_retry_attempts = 0` in the function event invoke config.

Zone lock holders are per execution environment (`lambda:<log stream name>`); a lock left
by a frozen or recycled environment expires after `lock.ttl`.

## Package

Each release attaches `dns-gate_<version>_lambda_arm64.zip` and its `.sha256` (version
without the leading `v`, e.g. `dns-gate_0.6.0_lambda_arm64.zip` for tag `v0.6.0`). The
zip holds a single executable `bootstrap` (mode 0755) for the `provided.al2023` runtime
on `arm64`, handler name unused. The `.sha256` is a `sha256sum` line; Terraform's
`source_code_hash` wants the base64 form (`filebase64sha256` of the downloaded zip).

Build it locally with `make lambda` (after `cd web && npm ci && npm run build`: the UI is
embedded in the binary). The zip is written by a small Go program, so `bootstrap` is 0755
even when built on a volume that reports 0700 (exFAT).

## Configuration

| Variable | Description |
|---|---|
| `DNS_GATE_CONFIG_URI` | The YAML configuration: a file path, `s3://bucket/key` or `ssm:/parameter/name` (SecureString decrypted). Also usable outside Lambda; `-config` accepts the same forms. |
| `DNS_GATE_SECRETS_ARN` | A Secrets Manager secret holding a JSON object whose keys are environment variable names, e.g. `{"DNS_GATE_SESSION_KEY":"…","DNS_GATE_UI_CLIENT_SECRET":"…"}`. Loaded into the environment at startup, before the configuration is parsed; a variable already set in the function environment wins. Also usable outside Lambda. |

Lambda mode is detected from `AWS_LAMBDA_RUNTIME_API`; nothing else to set.

The configuration is read once per execution environment, at init. After changing the S3
object or SSM parameter, force new environments, for example by putting the object ETag
or parameter version in an environment variable of the function so that Terraform updates
it.

Configuration notes for Lambda:

- `store: {type: dynamodb, dynamodb: {table: …}}`; the region comes from the function
  environment when `store.dynamodb.region` is empty.
- `listen.address` is ignored. Leave `listen.trusted_proxies` empty: the client address
  given to the gate is the `sourceIp` of the API Gateway event, not `X-Forwarded-For`.
- `lock.wait` at most 20 s: API Gateway HTTP API ends an integration after 30 s.
- `ui.redirect_url`, `mcp.public_url`: the custom domain.

Function settings: memory 512 MB (CPU grows with memory; JWT verification and TLS
handshakes are faster), timeout 120 s (the maintenance pass reconciles every managed
zone; API Gateway still cuts HTTP requests at 30 s).

IAM permissions of the function role:

- DynamoDB on the table: `GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`, `Query`,
  `TransactWriteItems`;
- `secretsmanager:GetSecretValue` on the secret, `s3:GetObject` on the configuration
  object or `ssm:GetParameter` on the parameter (plus `kms:Decrypt` for a customer key);
- the provider permissions (Route 53: read and change the managed hosted zones);
- CloudWatch Logs (`AWSLambdaBasicExecutionRole`).

## Cold start and concurrency

The binary is about 24 MB uncompressed (8.5 MB zipped). An init reads the secret, the
configuration, builds the AWS clients and loads the active policy revision: a few hundred
milliseconds on arm64, well within the 10 s init limit. With a 5-minute maintenance
schedule, one environment is usually warm; a burst of requests opens more environments,
each paying one cold start and fetching the issuers' JWKS once.

Correctness never depends on instance affinity: zone writes are serialized by the DynamoDB
lock and version, MCP plans and the login state live in the store or in sealed cookies.
Set a **reserved concurrency** (e.g. 10) to bound the load on DynamoDB and on the
provider API: Route 53 allows 5 requests per second per account, shared by every
instance.

## Why not a Function URL behind CloudFront

A Lambda Function URL behind CloudFront with Origin Access Control would avoid API
Gateway, but:

- OAC signs the origin request with SigV4, which uses the `Authorization` header. That
  header carries the clients' bearer token (Terraform provider, CI pipelines, MCP
  clients): the gate would no longer see it.
- For `POST` and `PUT`, Lambda OAC requires the viewer to send the payload hash
  (`x-amz-content-sha256`); CloudFront does not compute it, and no gate client sends it.
- A Function URL with `AuthType NONE` is reachable directly, around CloudFront, and has
  no custom domain of its own.

API Gateway HTTP API gives the custom domain, passes `Authorization` untouched and costs
cents at this volume.

## Why not in front of EuroDNS

EuroDNS allows 10 requests per 10 seconds **per source IP** and bans progressively. The
gate respects that limit with an in-process rate limiter, which only works when one
process owns the egress IP:

- each Lambda environment has its own limiter: N concurrent environments spend N times
  the budget and get the account banned;
- without a VPC, the egress IP is an AWS pool address, shared and changing: a ban can come
  from another tenant, and an IP allowlist on the EuroDNS account is impossible;
- a fixed, allowlisted egress IP needs a VPC and a NAT gateway (about 35 USD per month),
  which removes the point of Lambda.

Run the container (one replica, or a few behind a single NAT IP) for EuroDNS.

## Cost

Rough monthly cost for one organization (a few thousand requests per day), eu-west-3:

| Item | Lambda deployment | Container deployment |
|---|---|---|
| Compute | Lambda: ~0 (free tier covers 400 000 GB-s; 8 640 maintenance passes ≈ 1 000 GB-s) | Fargate ARM 0.25 vCPU / 0.5 GB: ~8 USD |
| Entry point | API Gateway HTTP API: a few cents (1 USD per million requests) | Application Load Balancer: ~18 USD (or a share of an existing one) |
| Store | DynamoDB on-demand + PITR: < 1 USD | same |
| Secrets | Secrets Manager: 0.40 USD per secret | same |
| Network | none (no VPC) | NAT or public IP depending on the VPC |
| **Total** | **~1.5 USD** | **~27 USD**, ~9 USD with a shared load balancer |

Logs are extra in both cases (CloudWatch ingestion, typically under 1 USD at this volume
with a 30-day retention).
