# QuantumGate

<div align="center">

### Crypto-agile security, designed around the applications you already run.

QuantumGate is an integration layer for inventorying security posture and adopting reviewed cryptographic policy changes while keeping your existing identity provider and application authorization.

**Go · PostgreSQL · OIDC · TLS 1.3 · Hybrid X25519 + ML-KEM-768**

</div>

> [!WARNING]
> **Active prototype — not for production protection.** Non-observe enforcement remains fail-closed until profiles have independent security approval. This repository does not claim “quantum-proof” security, compliance certification, or production readiness.

## What is in the prototype

- **A tenant-scoped control plane** for applications, identity adapters, policies, posture inventory, keys metadata, audit, and webhooks.
- **A Go service and administrator dashboard** with OIDC sign-in, server-side sessions, CSRF protection, strict request limits, and local static assets.
- **A TLS 1.3 gateway path** that can inspect the negotiated transport profile, validate configured identity context, evaluate policy, sanitize forwarded headers, and fail closed on errors.
- **Crypto-agile foundations** using Go's TLS implementation for the hybrid X25519 + ML-KEM-768 profile, typed profile metadata, and an internal key-provider boundary.
- **PostgreSQL security controls** including tenant row-level security, least-privilege runtime roles, append-only audit records, migration checksums, and transactional profile approval.
- **Integration surfaces** including a small Go SDK, observation ingestion, and an at-least-once webhook outbox.

## How it fits together

```mermaid
flowchart LR
    Admin[Administrator] -->|OIDC session| CP[QuantumGate control plane]
    App[Existing application] -->|SDK or TLS gateway| DP[Policy and identity checks]
    CP --> PG[(PostgreSQL<br/>tenant-scoped data and audit)]
    DP --> PG
    DP --> TLS[TLS 1.3\nX25519 + ML-KEM-768]
    CP --> KP[Key-provider boundary\noptional, limited integrations]
```

The control plane manages tenant-scoped configuration and review evidence. The gateway and SDK surfaces consume that configuration; they do not replace the application's identity provider or business authorization. See [the architecture](Specs/ARCHITECTURE.md) and [security boundaries](Specs/SECURITY.md) for details.

## Current implementation

Implemented slices include:

- a Go HTTP service with bounded HTTP timeouts, request IDs, security headers, liveness, readiness, and TLS 1.3;
- explicit hybrid TLS preference using Go's X25519 + ML-KEM-768 key exchange profile, with enforcement mode denying other negotiated groups;
- PostgreSQL migrations with tenant-scoped row-level security, append-only audit storage, foreign-key tenant constraints, and migration checksums;
- an OIDC authorization-code flow with server-bound state, nonce, PKCE S256, strict issuer/audience/algorithm/ACR/time checks, restricted egress, opaque revocable sessions, CSRF protection, and append-only sign-in/out events;
- a partial tenant control plane for tenant/member administration, environments, application registration, scoped credential rotation, OAuth client-credentials exchange, paginated audit reads, and immutable policy revisions;
- policy simulation, ETag-guarded activation/scheduling/retirement, rollback by creating a new revision, and a background schedule worker;
- a versioned read-only transport profile registry for the implemented Go TLS profiles;
- mandatory tenant and principal scoped idempotency keys for non-read API calls, with atomic 24-hour response replay;
- a same-origin administrator dashboard for tenant application registration, environment setup, policy drafts/simulation, inventory-only posture, and recent audit review;
- tenant-scoped OIDC identity-adapter inventory with allowlisted HTTPS discovery, strict RS256 token verification, ACR and freshness checks, ETag-guarded updates, and verification audit events;
- a small Go client for readiness checks and scoped, idempotent observation ingestion;
- tenant-isolated, ETag-guarded external key-reference lifecycle records, with version rollover, activation confirmation, disable/revoke actions, and no private-key input;
- an internal key-provider broker with tenant/application/environment scope, capability validation, conditional lifecycle transitions, correlated operation auditing, and an explicitly selected development-only provider;
- role checks from tenant membership rows, transaction-local tenant scope, and audit events for control-plane mutations and denied operations;
- `qg-migrate` and `qg-bootstrap` commands for clean database setup.

The control plane does not yet implement the full specification. Policy simulation remains an informational control-plane evaluator. The inline gateway path uses explicitly configured TLS-terminating routes; it validates the end-user OIDC ID token, evaluates the active policy, audits the decision, and fails closed on evaluation errors. The standalone decision API serves the Go SDK `Protect` method. Both transport profiles remain `simulation-only`, so every non-observe policy fails closed until independent review approves a profile. The gateway and SDK use bearer ID tokens that can be replayed during their 15-minute validity window; neither integration owns the OIDC transaction or consumes a token `jti`. Administrators can rotate scoped application credentials and exchange them for five-minute opaque OAuth bearer tokens. `observations:write` tokens submit bounded, idempotent telemetry for their own application, `posture:read` tokens read that application's inventory, and `decisions:evaluate` tokens authorize fresh SDK decisions. Webhook delivery is implemented with a PostgreSQL outbox and leased worker, but its database integration scenarios remain unvalidated. OIDC identity adapters can be inventoried and verified; the gateway uses an active verified adapter to validate end-user ID tokens. Key-reference APIs remain metadata-only. The internal broker includes an ephemeral development Ed25519 provider and a Vault Transit adapter for non-exportable Ed25519 signing; the Vault adapter is unvalidated against a real Vault service and is not wired to the public key-reference API, TLS key loading, or storage-key use. Broader data-plane APIs remain outstanding. Hybrid TLS is the only configured post-quantum transport profile; it is not a general application-level PQC implementation.

## Requirements

- Go 1.27.1 or later in the Go 1.27 series.
- PostgreSQL 14 or later.
- A configured OIDC provider for control-plane use.

## Local development

Copy `.env.example` to `.env`, replace its development admin, application, and migration passwords, and start PostgreSQL:

```powershell
Copy-Item .env.example .env
docker compose up -d db
```

The Compose file runs only a localhost-bound PostgreSQL development database. On a fresh volume it creates separate non-superuser runtime and migration roles; the application role has `NOBYPASSRLS`, and service startup rejects any role that can bypass row-level security. The Go service does not load `.env` files itself, so set its environment variables in the shell as shown below.

PowerShell example:

```powershell
$env:QG_ENV = 'development'
$env:LISTEN_ADDR = '127.0.0.1:8080'
$env:DATABASE_URL = 'postgres://quantumgate:YOUR_LOCAL_PASSWORD@localhost:5432/quantumgate?sslmode=disable'
$env:MIGRATION_DATABASE_URL = 'postgres://quantumgate_migrator:YOUR_MIGRATION_PASSWORD@localhost:5432/quantumgate?sslmode=disable'
$env:CRYPTO_MODE = 'observe-only'

go run ./cmd/qg-migrate
go test ./...
```

For development control-plane use, configure the OIDC settings below and provision a tenant administrator with `qg-bootstrap` before starting the service. Never use the local `sslmode=disable` example for a remote database.

```powershell
$env:OIDC_ISSUER = 'https://id.example'
$env:OIDC_CLIENT_ID = 'quantumgate-local'
$env:OIDC_REDIRECT_URL = 'http://localhost:8080/auth/callback'
$env:OIDC_ALLOWED_HOSTS = 'id.example,keys.id.example'
$env:OIDC_REQUIRED_ACR = 'urn:example:admin-mfa'
$env:BOOTSTRAP_TENANT_ID = '10000000-0000-4000-8000-000000000001'
$env:BOOTSTRAP_TENANT_NAME = 'Local development'
$env:BOOTSTRAP_ADMIN_ISSUER = $env:OIDC_ISSUER
$env:BOOTSTRAP_ADMIN_SUBJECT = 'the-provider-subject-for-your-admin'

go run ./cmd/qg-bootstrap
```

Start the service with the configured OIDC environment and local listener:

```powershell
go run ./cmd/quantumgate
```

Check its health endpoints:

- `GET /health/live`
- `GET /health/ready`

`qg-bootstrap` is idempotent for the same tenant and administrator. It will not promote an existing non-admin member. Provisioning a tenant requires a valid UUID and an administrator subject from the configured issuer.

## Control-plane API

Open `/auth/login` in a browser to start administrator sign-in. QuantumGate owns the OIDC authorization-code flow, including `state`, nonce, PKCE S256, exact callback, issuer and audience validation, signing-algorithm allow-list, required ACR, and recent `auth_time`. It consumes the browser-bound login transaction once and creates a random server-side session; only its hash is stored. The session cookie is Secure, HttpOnly, and SameSite=Lax, with an eight-hour absolute expiry and a 30-minute idle expiry. `/auth/session` returns the session's CSRF token; browser clients send it as `X-QG-CSRF-Token` with a same-origin `Origin` header on state-changing requests. `/auth/logout` revokes the server-side session and records an append-only authentication event.

Administrator sign-in requests only the OIDC `openid` scope. QuantumGate uses the issuer, subject, ACR, and authentication time for its role and session checks; it does not need profile or email claims.

Control-plane `/v1` routes require `X-QG-Tenant-ID: <tenant UUID>`. This value selects the tenant context but is not trusted as authorization. Tenant roles are looked up from PostgreSQL for every request. Membership must match, and every data query uses that tenant scope under PostgreSQL row-level security. Observation ingestion and application posture reads also accept scoped application OAuth bearer tokens; the service derives tenant and application from the token and rejects access to another application. The production entry point does not enable the internal administrator bearer-token verifier.

Currently implemented routes:

- `GET /v1/tenants/{tenant_id}`
- `PATCH /v1/tenants/{tenant_id}` (tenant display name with `If-Match` ETag)
- `GET /v1/tenants/{tenant_id}/members`
- `POST /v1/tenants/{tenant_id}/members`
- `DELETE /v1/tenants/{tenant_id}/members/{member_id}`
- `GET /v1/tenants/{tenant_id}/audit-events`
- `POST /v1/tenants/{tenant_id}/exports` (redacted audit export; 90-day range, 5,000-event and 7 MiB limits)
- `GET /v1/exports/{export_id}`
- `GET /v1/exports/{export_id}/download`
- `POST /v1/tenants/{tenant_id}/environments`
- `GET /v1/tenants/{tenant_id}/algorithm-profiles`
- `GET /v1/tenants/{tenant_id}/applications`
- `POST /v1/tenants/{tenant_id}/applications`
- `PATCH /v1/applications/{application_id}`
- `GET /v1/applications/{application_id}/policies`
- `POST /v1/applications/{application_id}/policies`
- `GET /v1/applications/{application_id}`
- `POST /v1/applications/{application_id}/disable`
- `POST /v1/applications/{application_id}/credentials/rotate`
- `GET /v1/applications/{application_id}/keys`
- `POST /v1/applications/{application_id}/keys/rotate`
- `GET /v1/applications/{application_id}/webhooks`
- `POST /v1/applications/{application_id}/webhooks`
- `PATCH /v1/webhooks/{webhook_id}`
- `POST /v1/webhooks/{webhook_id}/rotate-key`
- `GET /v1/webhooks/{webhook_id}/deliveries`
- `POST /v1/webhook-deliveries/{delivery_id}/retry`
- `GET /.well-known/qg-webhook-keys/{key_id}`
- `POST /v1/keys/{key_id}/activate`
- `POST /v1/keys/{key_id}/disable`
- `POST /v1/keys/{key_id}/revoke`
- `GET /v1/keys/{key_id}/public-material`
- `GET /v1/applications/{application_id}/identity-adapters`
- `POST /v1/applications/{application_id}/identity-adapters`
- `PATCH /v1/identity-adapters/{adapter_id}`
- `POST /v1/identity-adapters/{adapter_id}/verify`
- `POST /v1/identity-adapters/{adapter_id}/disable`
- `GET /v1/applications/{application_id}/posture`
- `GET /v1/applications/{application_id}/observations`
- `POST /v1/applications/{application_id}/observations` (service token with `observations:write`)
- `GET /v1/policies/{policy_id}`
- `POST /v1/policies/{policy_id}/simulate`
- `POST /v1/policies/{policy_id}/activate`
- `POST /v1/policies/{policy_id}/schedule`
- `POST /v1/policies/{policy_id}/rollback`
- `POST /v1/policies/{policy_id}/retire`
- `POST /oauth/token`
- `POST /oauth/introspect`

The complete resource contract is in [`Specs/API.md`](Specs/API.md). Routes outside the implemented subset must not be assumed to work. Non-read `/v1` requests require an `Idempotency-Key` containing 16–128 ASCII letters, digits, `.`, `_`, `~`, or `-`. Keys are scoped to the tenant and authenticated principal; successful responses and audited control-plane authorization denials are replayed atomically for 24 hours, and reusing a key for a different request returns `409`. Cached response bodies are encrypted at rest. Expired records are removed opportunistically as tenant requests arrive. Tenant and application metadata updates, application disable, policy lifecycle actions, and webhook destination changes require the current ETag in `If-Match`. Policy JSON is immutable after creation. OAuth token issuance, observation ingestion, and audit export operations are rate-limited. Audit-event exports are tenant-scoped, redacted, encrypted at rest, audited, and expire after 24 hours; this does not implement exports for other platform data. Outbound webhooks use a PostgreSQL outbox, a leased at-least-once worker, exact HTTPS host allowlists, and broker-backed Ed25519 signatures. Configure `WEBHOOK_ALLOWED_HOSTS` before creating destinations; private addresses are rejected, redirects are not followed, and real Vault behavior remains unvalidated. `memory-development` signing is ephemeral and only suitable for development. Both transport profiles are unapproved and non-observe enforcement remains fail-closed. Do not expose this version as a production control plane or claim that it provides production-ready application authorization.

Application registration is additive: the registered application keeps its own login and business authorization. A TLS-terminating gateway path is available for explicit, operator-configured host-to-application routes. It derives the transport profile from the live TLS connection, verifies the end-user OIDC ID token against the application's active, verified adapter, evaluates the active policy, and forwards only allowed, observe, or explicitly degraded-allowed traffic to the configured upstream. Production upstreams require HTTPS; development HTTP is limited to explicit loopback IPs. The upstream must be firewalled so requests cannot bypass the gateway. Both registered TLS profiles remain `simulation-only`, so active enforcement fails closed with `PROFILE_NOT_APPROVED` until a profile passes the required independent review. The Go SDK `Protect` calls the standalone decision API and remains additive to existing application authentication and business authorization.

## Configuration

Required in every environment:

- `DATABASE_URL`: PostgreSQL URL with a database name. Production requires `sslmode=verify-full`; unencrypted development connections are allowed only to localhost.
- `MIGRATION_DATABASE_URL`: migration-only PostgreSQL role. Production requires this value and `sslmode=verify-full`. The service uses `DATABASE_URL` and rejects superuser or `BYPASSRLS` privileges.

Production also requires:

- `QG_ENV=production`;
- `LISTEN_ADDR`;
- `CRYPTO_MODE`: `classical-approved` or `hybrid-approved` (or `observe-only` where permitted by the deployment); `pqc-approved` fails closed because no reviewed pure-PQC protocol profile is configured;
- `RATE_LIMIT_HMAC_KEY`: 32 bytes of deployment-generated random key material, encoded as 64 hexadecimal characters. It pseudonymizes client dimensions and derives purpose-separated AES-GCM keys for idempotency response bodies and audit export payloads. Keep it stable for at least 24 hours so retries and unexpired exports remain readable. Development starts with a process-random key when this variable is unset.
- `TLS_CERT_FILE` and `TLS_KEY_FILE`;
- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_ALLOWED_HOSTS`, and `OIDC_REQUIRED_ACR`.
- `OIDC_REDIRECT_URL`, the exact HTTPS callback URL ending in `/auth/callback`.

`IDENTITY_ALLOWED_HOSTS` is a comma-separated list of exact DNS hostnames for customer OIDC adapter discovery and signing keys. It is required when gateway routes are configured. Configure every provider hostname that discovery and JWKS use. Adapter issuers must use HTTPS on port 443 and an exact allowlisted hostname; requests are restricted to public unicast addresses. This list is independent of `OIDC_ALLOWED_HOSTS`, which controls administrator sign-in.

`WEBHOOK_ALLOWED_HOSTS` is an optional comma-separated list of exact DNS hostnames for tenant webhook destinations. Destinations use HTTPS on port 443, and every DNS result must be public; private customer endpoints are unsupported. An empty list disables destination creation and outbound delivery. Delivery requires a configured `KEY_PROVIDER`; production must use an explicitly configured provider and never falls back to `memory-development`. Webhook receivers verify the exact raw JSON body with Ed25519, enforce a five-minute `sent_at` window, and deduplicate by `(tenant_id, event_id)`. Delivery is at least once, so receivers must handle duplicate event IDs.

The optional gateway requires `GATEWAY_ROUTES_FILE`, a separate `GATEWAY_LISTEN_ADDR`, a mounted JSON file based on [`ops/gateway/routes.example.json`](ops/gateway/routes.example.json), and TLS certificate and key files. Development defaults to `127.0.0.1:8444`; production requires an explicit listener on a port different from `LISTEN_ADDR` (for example, `0.0.0.0:9443`). The gateway listener serves only configured application routes and returns not-found for control-plane paths. Each route maps one exact TLS hostname to an existing tenant UUID, an active application UUID registered with `integration_mode: "gateway"`, and one upstream URL. The certificate must cover every route hostname. Production upstreams must use HTTPS on port 443; their exact DNS names must appear in `GATEWAY_UPSTREAM_ALLOWED_HOSTS`. The gateway rejects missing or mismatched SNI, non-TLS 1.3 connections, unsupported negotiated groups, missing bearer ID tokens, disabled applications, stale/unverified identity adapters, stale policies, and database/audit failures. It removes caller-supplied forwarding and `X-QG-*` headers and writes its own values. In development, HTTP upstreams are allowed only for explicit loopback IP addresses. See the [existing-application gateway example](examples/gateway-upstream/README.md) for a local upstream that preserves its own OIDC verification. Configure the gateway as the public TLS terminator and firewall upstreams to accept traffic only from it; a load balancer that terminates TLS ahead of QuantumGate would make the observed profile describe the wrong connection. The API and gateway share a process, so production network policy must also restrict access to `LISTEN_ADDR`.

The internal key-provider boundary is optional and is not connected to key-reference APIs, TLS certificate loading, or storage encryption. `KEY_PROVIDER` accepts `memory-development` in development/test or the limited `vault-transit` adapter. Selecting Vault requires `VAULT_ADDR` and `VAULT_TOKEN_FILE`; production requires HTTPS with normal certificate verification. The token file is expected to be a Vault Agent auto-auth sink populated through workload identity or another reviewed machine identity. Optional settings are `VAULT_NAMESPACE`, `VAULT_TRANSIT_MOUNT`, `VAULT_KEY_PREFIX`, and `VAULT_CA_CERT_FILE`. Do not put the token contents in source, configuration examples, logs, or database metadata. `KEY_PROVIDER_REQUIRED=true` makes startup require a configured provider and readiness require an authenticated Vault Transit read. Fake-server tests are not real-provider validation. Do not treat this adapter as production-ready: it supports Ed25519 signing only, does not implement PQC or destruction, and does not custody TLS or storage-encryption keys.

Provision the runtime and migration roles from [`ops/postgres/roles.sql`](ops/postgres/roles.sql) using a separate database administrator and the two password variables. The migration role owns the schema objects; default privileges grant the runtime role data access while the migration-history table stays private. Do not run the web service with the bootstrap administrator or migration role. A pre-existing development volume created with the earlier superuser application role needs a one-time DBA role/ownership conversion before starting this Compose version; the script preserves table data. For the previous local Compose setup, start the database and run `docker compose exec db psql -U quantumgate -d quantumgate -f /roles.sql` using the old local admin login. Do not delete the volume to perform this upgrade.

Optional OIDC policy settings:

- `OIDC_SIGNING_ALGS`, a comma-separated allow-list from `RS256`, `ES256`, `PS256`, and `EdDSA` (default: `RS256`);
- `OIDC_MAX_TOKEN_AGE`, from `1m` through `1h` (default: `15m`).
- `OIDC_CLIENT_SECRET` is optional for confidential clients and must come from the deployment's secret source. PKCE remains required.
- `RATE_LIMIT_HMAC_KEY` is required in production as 32 deployment-generated random bytes encoded in 64 hexadecimal characters. Keep it stable for at least 24 hours; changing it makes encrypted cached responses and unexpired exports unreadable. Development starts with a process-random key when this variable is unset.

`OIDC_ALLOWED_HOSTS` requires exact DNS hostnames. Discovery and JWKS requests are limited to HTTPS on port 443, and every resolved address must be public unicast. Configure all provider hosts used by discovery and signing-key rotation.

`CRYPTO_MODE=hybrid-approved` serves TLS 1.3 and rejects requests unless the negotiated key exchange is X25519 + ML-KEM-768. It does not silently fall back to classical TLS. The exact runtime and deployment profile still require independent security review before production use.

## Database setup

Apply embedded migrations with:

```powershell
go run ./cmd/qg-migrate
```

The migration command verifies applied checksums and serializes concurrent migrations with a PostgreSQL advisory lock. For a clean environment, run it before `qg-bootstrap` and the service.

## Validation

```powershell
go test ./...
go test -race ./...
go vet ./...
go mod verify
```

`go test` skips PostgreSQL integration tests unless `TEST_DATABASE_URL` points at a disposable PostgreSQL database for a non-superuser migration-test role with `CREATEDB`, and `TEST_RUNTIME_DATABASE_URL` points at a separate non-owner runtime role named `quantumgate`. Tests create randomly named temporary databases, apply the production migrations in `public`, grant the runtime role the same table access as deployment, and drop the databases afterward. The GitHub Actions workflow is configured with separate ordinary checks, a PostgreSQL 17.11 integration job that runs the full suite under `-race`, and a disposable Vault Transit API integration job. It also runs `staticcheck`, `govulncheck`, `go mod verify`, and redacted Gitleaks scans of history and the working tree. A configured workflow is not evidence of an executed CI run; record PostgreSQL, Vault, and race results only after a successful GitHub Actions run. This workspace has no Docker/PostgreSQL/Vault installation, so those infrastructure checks have not run locally. Full end-to-end tests and independent crypto/security review remain outstanding.

The production Docker image is built with `docker build -t quantumgate:local .`. It contains a non-root static binary and CA bundle; mount production TLS files and inject database/OIDC settings at runtime. The image also contains `/qg-migrate` and `/qg-bootstrap` for controlled setup. The Docker image has not been built in this workspace because Docker is unavailable here.

## Security boundaries and limitations

- A customer application or SDK host can read its own process memory; this integration layer cannot protect a fully compromised customer workload.
- The admin browser flow uses revocable server-side sessions. OAuth client-credentials issuance and introspection are available; posture reads and observation ingestion consume the narrowly scoped `posture:read` and `observations:write` scopes. Inline gateway decisions are available on configured routes. Active non-observe enforcement remains blocked while profiles are `simulation-only`, and the gateway's bearer ID tokens are replayable during their bounded validity window.
- Membership, not OIDC role or tenant claims, determines authorization. Application business roles remain the customer's responsibility.
- PostgreSQL tenant RLS is defense-in-depth; the application validates membership and binds each transaction to a tenant. Database superuser or `BYPASSRLS` access can bypass RLS and must never be used by the service role.
- A Vault Transit adapter now supports non-exportable Ed25519 signing through the internal provider boundary, but it is not production-ready: real Vault and PostgreSQL validation, provider-backed public key-reference routes, TLS-key and storage-key custody, required PQC algorithms, and broader KMS/HSM/PKCS#11 integrations remain incomplete. The key-provider boundary and SDK decision path do not establish production key custody or production authorization readiness. Do not use this version to store customer key material or make production authorization decisions.
- No FIPS validation, compliance certification, or production readiness assessment is claimed.

See [`Specs/SECURITY.md`](Specs/SECURITY.md), [`Specs/THREAT_MODEL.md`](Specs/THREAT_MODEL.md), and [`docs/standards/registry.md`](docs/standards/registry.md) for the authoritative requirements and known limits.
