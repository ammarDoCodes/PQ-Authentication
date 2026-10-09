# QuantumGate Testing and Verification

Version: 0.1-draft
Principle: a security feature is incomplete until its negative behavior and operational failure modes are tested.

## 1. Test pyramid

- **Unit tests**: pure validation, policy precedence, lifecycle state transitions, redaction, parsers, error mapping.
- **Component tests**: service plus database/cache/queue/provider fakes with real schemas and authorization.
- **Contract tests**: API schemas, SDK versions, adapter behavior, error formats, event signatures.
- **Integration tests**: real maintained crypto providers, KMS/HSM test mode, IdP fixtures, gateway-to-application flows.
- **End-to-end tests**: tenant setup, registration, migration, enforcement, rotation, rollback, audit, export, recovery.
- **System tests**: multi-region or deployment-profile behavior, load, outages, upgrades, restore.
- **Security tests**: abuse, fuzzing, dependency, supply chain, penetration, and manual review.

## 2. Required test properties

Every test that touches a security boundary should identify:

- tenant and environment context;
- principal and role;
- trust boundary;
- expected decision;
- audit/telemetry expectation;
- failure/timeout expectation;
- secret-redaction expectation where relevant.

Use synthetic data and canary secrets that cannot authenticate to any real environment.

PostgreSQL integration tests require `TEST_DATABASE_URL` to point to a disposable database for a non-superuser migration-test role with `CREATEDB`, and `TEST_RUNTIME_DATABASE_URL` to point to the separate, non-owner runtime role named `quantumgate`. Each test creates a randomly named temporary database, applies the same migrations used by deployment in its `public` schema, grants only the runtime table/function access used by the service, then drops the temporary database. Running application requests as the table owner would bypass the owner-only RLS policy used by security-definer authentication functions and does not validate the production boundary. Never point these variables at a shared or production database.

### Reproducible local PostgreSQL tests (Windows PowerShell)

The repository's local database service is PostgreSQL `17.11-bookworm` in `compose.yaml`, bound to `127.0.0.1:5432`. Start with Docker Desktop and Compose available and running. Create a local-only `.env` from `.env.example`, replace its three sample passwords with distinct random hexadecimal values, and keep `.env` out of source control. Start only the database:

```powershell
Copy-Item .env.example .env
docker compose up -d db
docker compose ps db
```

Compose's initialization runs `ops/postgres/init/01-app-role.sh` and `ops/postgres/roles.sql`. The runtime login `quantumgate` is `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`; the migration login `quantumgate_migrator` has the same restrictions and owns the application database/schema. The local Compose bootstrap admin is a development-only superuser and must not be used as either test URL.

Create a separate test-runner login. It is deliberately not the application runtime or migration login: the integration tests use its `CREATEDB` privilege to create random, disposable databases and its ownership of each temporary database to apply migrations and grant the existing runtime role only the table/function access under test. It needs no `SUPERUSER`, `CREATEROLE`, or `BYPASSRLS` privilege. This psql block creates or resets only that local test role; it accepts the generated password through the child process environment rather than embedding it in SQL text:

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$testPassword = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
$roleSQL = @'
\set ON_ERROR_STOP on
\getenv qg_test_password QG_TEST_DATABASE_PASSWORD
SELECT format(
  CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qg_test_runner')
    THEN 'ALTER ROLE qg_test_runner WITH LOGIN PASSWORD %L CREATEDB NOSUPERUSER NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
    ELSE 'CREATE ROLE qg_test_runner LOGIN PASSWORD %L CREATEDB NOSUPERUSER NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
  END,
  :'qg_test_password'
) \gexec
'@
$roleSQL | docker compose exec -T -e "QG_TEST_DATABASE_PASSWORD=$testPassword" db psql -U quantumgate_admin -d postgres
```

Set both URLs to the maintenance database `postgres`; each test changes the database name to its own random temporary database. Read the runtime password from the local `.env` file, then run the database scenarios:

```powershell
$appPassword = (Get-Content .env | Where-Object { $_ -match '^QG_APP_PASSWORD=' } | Select-Object -First 1) -replace '^QG_APP_PASSWORD=', ''
$env:TEST_DATABASE_URL = "postgres://qg_test_runner:$testPassword@127.0.0.1:5432/postgres?sslmode=disable"
$env:TEST_RUNTIME_DATABASE_URL = "postgres://quantumgate:$appPassword@127.0.0.1:5432/postgres?sslmode=disable"
go test -count=1 -v ./internal/storage ./internal/httpapi -run 'Test(PostgresMigrationTenantIsolationAndAuditImmutability|ProfileReviewMigrationDisablesLegacyApprovals|ControlPlaneTenantIsolationAndRoleAuthorization)$'
```

The profile-review upgrade test applies migrations through 11, inserts a legacy `approved` row without independent-review evidence, applies migration 12, and asserts that the row is `disabled` with no `reviewed_at`. Each database integration test drops its random test database on completion. There is no down-migration in the repository; rerunning the tests rebuilds clean databases. To validate the deployment migration login on the Compose database, set `MIGRATION_DATABASE_URL` to the `quantumgate_migrator` URL for database `quantumgate` and run `go run ./cmd/qg-migrate` twice; the second run must report migrations current without changing their checksums.

```powershell
$migrationPassword = (Get-Content .env | Where-Object { $_ -match '^QG_MIGRATION_PASSWORD=' } | Select-Object -First 1) -replace '^QG_MIGRATION_PASSWORD=', ''
$env:QG_ENV = 'development'
$env:MIGRATION_DATABASE_URL = "postgres://quantumgate_migrator:$migrationPassword@127.0.0.1:5432/quantumgate?sslmode=disable"
go run ./cmd/qg-migrate
go run ./cmd/qg-migrate
docker compose exec -T db psql -U quantumgate_admin -d quantumgate -c "SELECT version, name FROM qg_schema_migrations ORDER BY version"
docker compose exec -T db psql -U quantumgate_admin -d quantumgate -c "SELECT c.relname, pg_get_userbyid(c.relowner) AS table_owner, t.tgname, t.tgenabled, pg_get_userbyid(p.proowner) AS guard_owner, has_function_privilege('quantumgate', p.oid, 'EXECUTE') AS runtime_can_execute_guard FROM pg_class c JOIN pg_trigger t ON t.tgrelid = c.oid JOIN pg_proc p ON p.oid = t.tgfoid WHERE c.oid = 'public.algorithm_profiles'::regclass AND t.tgname = 'algorithm_profiles_immutable_review'"
docker compose exec -T db psql -U quantumgate_admin -d quantumgate -c "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname IN ('quantumgate', 'quantumgate_migrator', 'qg_test_runner') ORDER BY rolname"
```

Expected: migration rows 1–14 are present; the profile trigger is enabled; both table and trigger function are owned by `quantumgate_migrator`; `runtime_can_execute_guard` is false; `quantumgate` is not a superuser, database creator, role creator, or RLS bypass role; only `qg_test_runner` has `rolcreatedb=true`.

The integration assertions exercise runtime tenant isolation and profile-trigger rejections, including direct runtime attempts to self-approve, edit immutable profile data, execute the guard directly, and disable its trigger. Do not grant the runtime role owner, superuser, `CREATEROLE`, or `BYPASSRLS` privileges to make a test pass.

On Windows, Go's race detector supports `windows/amd64` and requires `CGO_ENABLED=1` plus a C compiler in `PATH`. Go 1.25 and later require a Windows GCC/MinGW-w64 toolchain that emits DWARF 5; Go's current requirements page specifies GCC built with binutils 2.37 or later. Verify with `gcc --version` and `gcc --print-file-name libsynchronization.a`, then run `go test -race ./...`.

### Real Vault Transit integration

`TestVaultRealTransitIntegration` runs only when `QG_REAL_VAULT_ADDR`, `QG_REAL_VAULT_TOKEN_FILE`, and `QG_REAL_VAULT_DENIED_TOKEN_FILE` are all set. It accepts only loopback HTTP, requires owner-only token files, and uses a separately scoped application token plus a health-only token for the authorization-negative case. GitHub Actions configures an ephemeral Vault development server, enables Transit with a bootstrap token used only during setup, then runs the integration test with short-lived restricted tokens. The test covers the real Transit health/configuration, Ed25519 key creation, public-key retrieval, signing and QuantumGate signature verification, lifecycle signing floors, denied access, unknown references, correlated audit, and audit redaction. This validates real Vault API compatibility only; it does not validate production hardening, audit-device configuration, HA, renewal, machine identity, or HSM custody.

The control-plane integration test also exercises the gateway with a real TLS 1.3 X25519+ML-KEM-768 handshake, a database-backed observe-only decision, and a local existing-application upstream. It verifies request identity forwarding, replacement of caller-supplied transport and forwarding headers, response-header sanitization, and a correlated decision audit. The test uses a deterministic verifier in place of a live identity provider; it does not replace provider interoperability or a live customer authorization integration.

## 3. Functional test matrix

| Area | Required cases |
|---|---|
| Tenant isolation | permitted access, missing tenant, wrong tenant, cross-tenant query/export/cache/event |
| Admin auth | valid login, invalid issuer/audience, expired token, nonce/state failure, MFA/step-up |
| Service credentials | one-time secret delivery, encrypted idempotent replay, bounded expiry, rotation/revocation, hash-only storage |
| OAuth client credentials | Basic client authentication, explicit scope subset, short token lifetime, per-IP/client limits, inactive-token introspection after rotation |
| SDK decision API | allowed and denied outcomes, decisions:evaluate scope, tenant/application binding, live TLS profile, current profile approval, existing identity token validation, request/audit correlation, fresh re-evaluation, malformed input, timeout, outage, and mismatched response rejection |
| Posture | missing policy/evidence, policy hash mismatch, current exceptions, blocker counts, no enforcement-ready claim |
| Adapters | OIDC/JWKS rotation, SAML validation, WebAuthn challenge/origin, mTLS/service identity |
| Sessions | issue, validate, expire, rotate, revoke, replay, clock skew, wrong audience/tenant |
| Policies | draft, simulate, precedence, activate, schedule, rollback, exception expiry, stale cache |
| Crypto profiles | allowed profile, disabled profile, wrong parameter set, provider mismatch, downgrade attempt |
| Profile review/approval | complete design record, authorized reviewer, unauthorized role, self-review rejection, cross-tenant access, stale ETag, concurrent approve/reject, immutable post-approval evidence, disable/deprecate/reject behavior, audit correlation and redaction, idempotent replay |
| Keys | create, activate, overlap rotation, public distribution, disable, revoke, expiry, invalid transition |
| Webhooks | exact signed bytes, source-audit event identity, stable event ID across retries, timestamp/destination/key binding, broker failure/revocation, 2xx/retry/permanent outcomes, capped backoff/dead-letter/manual replay, exact HTTPS allowlist, private/reserved DNS rejection, pinned DNS, TLS/redirect behavior, tenant roles/RLS, concurrent leases, immutable evidence, audit redaction/correlation |
| Rate limits | per principal, tenant, IP, operation, burst, retry guidance, bypass attempts |
| Audit | complete event, redaction, correlation, append-only, export scope, delivery gap |
| Dashboard | server-side authorization, pagination, sensitive field redaction, inaccessible resource behavior |
| Operations | health/readiness, dependency outage, restore, migration, rollback, regional degradation |

## 4. Cryptographic verification

- Use official/provider test vectors where available.
- Test exact algorithm/profile and provider versions used in production.
- Test key purpose separation and invalid key use.
- Test signature verification failure, malformed input, wrong context, replay, and expired key.
- Test hybrid negotiation and downgrade detection with positive and negative interoperability cases.
- Test provider self-tests and startup behavior according to provider requirements.
- Record performance and size impact for supported profiles.

No test may endorse a custom primitive or combiner merely because it produces the expected output.

The in-memory development provider tests cover scoped references, environment binding, standard Ed25519 operations, public-key preservation across rotation/destruction, invalid and stale concurrent transitions, capability mismatch, malformed signatures/metadata, provider errors/timeouts, and per-operation audit correlation/redaction/fail-closed behavior. `pqc-development` tests cover those scoped/lifecycle/audit boundaries for Ed25519 and FIPS 204 ML-DSA-44/65/87, exact parameter/key/signature matching, context binding, malformed signatures and public keys, capability downgrade, production rejection, expiry, and public verification history. Its benchmarks report key generation/sign/verify latency and the standard public-key/signature sizes; local microbenchmarks are not capacity claims. The Go standard-library Wycheproof integration test could not run because its pinned `github.com/C2SP/wycheproof` module is not cached and the configured module proxy is unreachable; PQC interoperability remains `NOT VALIDATED` until those independent vectors run. Vault fake-HTTP tests cover non-exportable Ed25519 creation, scoped references, metadata/public-key retrieval, signing and local verification, lifecycle gating, concurrent stale transitions, malformed signatures, denied access, TLS certificate validation, and unsupported capabilities. These fake-server tests do not validate an actual Vault release, Vault ACL policy, token renewal, Transit audit-device behavior, enterprise license features, or HSM custody. A PostgreSQL-gated runtime-role integration case covers Vault metadata RLS, serialized transitions, correlated audit, and redaction; it must be reported `NOT VALIDATED` if its test database is unavailable. TLS key integration, local storage-key custody, and PQC decapsulation also remain outside this provider subset.

## 5. Security testing

Required before pilot:

- SAST and type/lint checks;
- dependency/SCA and license scan;
- secret scan;
- container and IaC scan;
- API schema and authorization tests;
- tenant-isolation and cache-key tests;
- fuzzing of tokens, policy documents, provider metadata, event payloads, and parsers;
- SSRF, injection, XSS, CSRF, deserialization, path traversal, and request-smuggling checks as applicable;
- rate-limit and resource-exhaustion tests;
- red-team review of downgrade, replay, policy exception, support access, and export abuse;
- manual crypto/provider review.

Before production, add an independent security assessment appropriate to the deployment risk and remediate critical/high findings or obtain a documented risk acceptance.

## 6. Reliability and chaos testing

Inject:

- policy database/cache outage;
- key provider timeout, denial, malformed response, and key-state lag;
- IdP metadata/JWKS outage or rotation;
- queue duplication, delay, poison message, and out-of-order event;
- webhook signing-provider outage/revocation, DNS/TLS/status failures, retry exhaustion, process crash and lease reclaim, destination disablement, duplicate delivery and receiver deduplication;
- telemetry/audit store degradation;
- clock skew and time-source loss;
- partial region/network failure;
- database failover and restore;
- deployment rollback during a policy or key transition.

Verify that security decisions follow the documented mode, no silent downgrade occurs, audit gaps are visible, and recovery does not generate unmanaged keys or cross tenant data.

## 7. Performance and capacity

Measure p50/p95/p99 latency, error rate, throughput, memory, CPU, queue lag, provider latency, and cache hit behavior for each integration mode and crypto profile. Test worst-case key sizes, token sizes, policy complexity, export volume, and tenant concurrency.

Capacity tests must include noisy-neighbor behavior, rate-limit fairness, autoscaling, cold start, provider quotas, and database index health. Performance improvements cannot remove validation, audit, tenant checks, or cryptographic verification.

## 8. Upgrade and compatibility tests

- Run old SDK against new compatible server and new SDK against supported server versions.
- Test key overlap across rotation and rollback.
- Test policy schema migration and downgrade safety.
- Test database migration forward/rollback in a copy of production-shaped data.
- Test dependency/provider upgrade with vectors and interoperability partners.
- Verify audit schema readers tolerate additive event fields.

## 9. Evidence and release gates

Each release stores:

- commit/build/artifact identifiers;
- test and scan reports;
- dependency manifest/SBOM;
- standards and provider versions;
- migration/rollback evidence;
- threat-model review;
- unresolved findings and risk owners;
- deployment and restore verification.

Release is blocked by:

- critical vulnerability or unmitigated high security finding;
- failed tenant-isolation test;
- missing key-provider or identity-provider failure behavior;
- unverified crypto profile or provider change;
- missing audit event for a security-sensitive mutation;
- secret leakage;
- undocumented breaking API/security behavior;
- inability to roll back or disable the change safely.
