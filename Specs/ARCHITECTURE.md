# QuantumGate Architecture

Version: 0.1-draft
Status: implementation baseline

## 1. Architecture principles

1. Compose standards and mature libraries; never implement cryptographic primitives or protocols manually.
2. Keep the integration surface thin and the security policy explicit.
3. Separate control plane, data plane, and cryptographic provider responsibilities.
4. Make trust boundaries visible in code, deployment, logs, and diagrams.
5. Prefer immutable revisions and append-only evidence over mutable magic configuration.
6. Fail safely and observably; never perform an undocumented downgrade.
7. Make tenant context mandatory at every storage, cache, job, and event boundary.
8. Use boring, replaceable components with small modules and few abstractions.

## 2. Context

```text
Existing application
  ├─ QuantumGate SDK or gateway adapter
  ├─ existing IdP / OAuth / OIDC / SAML / WebAuthn / service identity
  └─ business authorization and data

                 protected request
                         │
                         v
                QuantumGate data plane
        ┌───────────────┼────────────────┐
        │ request/session│ policy decision │
        │ validation      │ crypto provider │
        └───────────────┼────────────────┘
                         │
                         v
                   existing application

QuantumGate control plane
  tenant/app registry · adapters · policies · key metadata · audit · dashboard
                         │
                         v
          KMS/HSM/Vault · identity providers · telemetry systems
```

## 3. Logical components

### 3.1 Edge and integration layer

- **SDK**: typed client, existing identity and action context, server-authoritative policy result, safe error mapping, and response/audit correlation.
- **Gateway/sidecar**: request interception, identity adapter hook, route policy, forwarding, bounded local cache.
- **Admin API**: versioned resource API for control-plane operations.
- **Event intake**: authenticated, rate-limited telemetry and posture observations from SDKs/gateways.

The SDK MUST not contain private key material by default. It SHOULD call a nearby gateway or data-plane service for cryptographic operations when the deployment permits.

The current executable serves the control plane on `LISTEN_ADDR` and, when routes are configured, serves the gateway on a dedicated `GATEWAY_LISTEN_ADDR` TLS listener with a gateway-only handler and a not-found fallback. The listeners share a process and database connection pool; separate ports do not provide process isolation. Production network policy should expose only the listener intended for each caller class and keep upstream applications unreachable except through the gateway.

### 3.2 Control plane

- **Tenant service**: tenants, environments, members, roles, support sessions.
- **Application registry**: applications, integration mode, allowed origins/routes, identity mappings, status.
- **Adapter service**: provider metadata, issuer/audience configuration, certificate/JWKS references, validation policy.
- **Policy service**: draft/active revisions, simulation, scheduling, evaluation metadata.
- **Algorithm registry**: approved/deprecated algorithms, provider versions, parameter sets, allowed use cases.
- **Key metadata service**: identifiers, purpose, version, provider reference, state, rotation schedule; never private key bytes.
- **Audit service**: append-only events, retention, export, integrity metadata.
- **Dashboard/API composition**: read models only; authorization remains in backend services.

### 3.3 Data plane

- **Context validator**: derives tenant/application from scoped service credentials, validates the existing identity token against the registered adapter, derives SDK transport profile from the live TLS connection, and validates the bounded action context and correlation metadata.
- **Policy evaluator**: resolves the active policy revision and returns a typed decision.
- **Crypto broker**: invokes an approved provider for supported operation profiles; enforces purpose, algorithm, key, and provider constraints.
- **Session service**: validates/rotates/revokes session artifacts using maintained token/session libraries.
- **Decision cache**: caches only bounded, revocable, non-secret policy results; includes tenant/application/policy revision and expiry in the key.
- **Failure controller**: maps dependency errors to explicit safe modes and emits telemetry.

### 3.4 Provider boundary

The provider boundary isolates external cryptography and key custody:

- KMS/HSM/Vault adapter;
- TLS/provider configuration;
- maintained PQC/classical library;
- random source and provider self-tests;
- key import/export policy;
- version and validation metadata.

Application code calls an interface such as `KeyProvider`, `Signer`, `KEMSession`, or `SessionStore`, not algorithm internals. The interface must not pretend different algorithms have identical security properties.

The current internal `keyprovider` boundary takes an opaque reference plus trusted tenant/application/environment scope and exposes capability discovery, generation, metadata, public-key retrieval, signing, lifecycle transition, and health operations. A broker binds every call to its configured environment, validates provider capabilities and public/signature results, and requires a per-operation actor and correlation ID in the request context plus an audit sink. Lifecycle transitions compare the expected state atomically at the provider. Audit records contain a hash of the provider reference, never private material, operation inputs, signatures, or backend error text. A failed audit-intent record prevents the provider call; failure to record completion withholds the operation result.

`memory-development` remains an explicitly selected, ephemeral in-process development/test provider. A `vault-transit` adapter now supports non-exportable Ed25519 signing through Vault Transit and records QuantumGate key lifecycle metadata in the tenant-scoped `key_references` table. Its HTTP API is not exposed to clients and its broker uses the append-only database audit sink. The adapter supports generation, metadata, public key, signing, activation, rotation-due, disable, revoke, and expiry; it does not support key deletion. Vault readiness checks an active, unsealed server and an authenticated read of the Transit mount, while algorithm/operation capability is reported separately and individual key availability is checked on its own reference. No real Vault service has been exercised, so the adapter is not production-ready.

`pqc-development` is a separate, explicitly selected process-memory provider for Ed25519 compatibility and FIPS 204 ML-DSA-44/65/87 signing with Go 1.27.1 `crypto/mldsa`. It is classified development/test only, non-persistent, and without protected custody; it is rejected in production and never advertises KEM operations. It has the same opaque scoped-reference, lifecycle, and audited broker boundary as the memory provider. Go's ML-DSA API exposes no zeroization operation, so destroy drops the private-key reference but does not claim memory erasure. This provider does not make a product-approved identity-signing or pure-PQC profile available; the policy registry continues to reject `pqc-approved`. ML-KEM remains only in the maintained TLS 1.3 hybrid stack, with no application-level KEM or hybrid signature/combiner in this provider.

Transit key paths are constructed only from server-generated opaque references and validated tenant/application/environment scope. QuantumGate database state is authoritative for purpose, version, expiry, and lifecycle. The adapter keeps Vault Transit version 1 per opaque reference and models staged rotations as a new reference plus explicit lifecycle transitions. A database row lock serializes signing with lifecycle transitions; Transit minimum signing versions disable inactive references. If the Vault update succeeds but the SQL transaction or completion audit fails, the caller receives no result; operators must reconcile the remote key against its database row.

This boundary does not replace `TLS_KEY_FILE` loading or the local `RATE_LIMIT_HMAC_KEY` used for encrypted idempotency/export payloads. The public key-reference API remains metadata-only and does not invoke Vault. ML-DSA/hybrid/SLH-DSA Transit operations are Enterprise features in current Vault documentation and are not implemented by this adapter; Transit documents no ML-KEM key type. These operations, real-provider validation, token permissions, audit-device redaction configuration, recovery, and remaining custody uses must be reviewed before enabling production key-dependent functionality.

## 4. Deployment topology

```text
Internet / customer network
          │
     WAF / load balancer
          │
  ┌───────┴────────┐
  │ data plane      │  stateless replicas; local bounded cache
  │ gateway/SDK API │
  └───────┬────────┘
          │ private network
  ┌───────┼────────────────────────────┐
  │ control plane services             │
  │ admin API · policy · tenants       │
  │ applications · adapters · audit    │
  └───────┬────────────────────────────┘
          │
  ┌───────┼──────────────┐
  │ relational database   │ encrypted object/event store
  │ cache/queue           │ KMS/HSM/Vault
  └───────────────────────┘
```

No public service talks directly to a key store without an authenticated, authorized provider adapter. The dashboard never talks directly to databases or KMS/HSM.

## 5. Trust boundaries

1. Browser/client to edge.
2. Customer application to SDK/gateway.
3. Data plane to control plane.
4. QuantumGate services to identity providers.
5. QuantumGate services to KMS/HSM/Vault.
6. Tenant data to shared infrastructure.
7. Production services to operators/support users.
8. Build pipeline to released artifacts.

Each boundary requires authenticated transport, explicit identity, authorization, input validation, timeout, rate limit, and audit/telemetry behavior appropriate to the data.

## 6. Core data model

Resource identifiers are opaque, non-sequential, and scoped.

- `Tenant`: id, status, plan/limits, residency, retention, created_at.
- `Environment`: id, tenant_id, name, lifecycle, region, policy defaults.
- `Application`: id, tenant_id, environment_id, display_name, mode, integration, status.
- `IdentityAdapter`: id, application_id, type, issuer/reference, validation profile, status.
- `AlgorithmProfile`: tenant-scoped immutable registry-version snapshot, canonical profile hash, design evidence, submitter, independent reviewer, lifecycle state, and lifecycle revision.
- `KeyReference`: id, tenant_id, application_id, purpose, provider, version, state, dates, public metadata.
- `PolicyRevision`: id, scope, document hash, state, author, approval, effective_at, retired_at.
- `PolicyDecision`: correlation id, policy revision, mode, outcome, reason codes, cache expiry.
- `AuditEvent`: immutable event envelope described in `SPEC.md`.
- `MigrationObservation`: application, source, protocol, algorithm profile, evidence time, blocker, confidence.

All rows and indexes that can be tenant-scoped use `tenant_id`. Repository methods should require a typed tenant context rather than accepting an optional tenant ID.

An algorithm profile submission is an immutable tenant-scoped snapshot of a canonical registry entry. Enforcement eligibility requires a different tenant security engineer to approve the snapshot and its design evidence; the decision is bound to the registry version and profile hash. A new registry version requires a new review. Approved snapshots may be disabled or deprecated, which immediately removes enforcement eligibility.

## 7. Request data flow

1. The API assigns a request correlation ID and returns it with the decision; each SDK call is evaluated independently.
2. Edge terminates or forwards TLS according to deployment policy.
3. Integration layer authenticates the application and establishes tenant/application context from its scoped credential, never from a caller-supplied tenant/application/profile field.
4. Context validator verifies the existing application identity token using the current registered adapter, checks time/audience/signature, validates the bounded method/path, and derives the TLS profile from the connection.
5. Policy evaluator loads the active revision and current tenant profile approval, then returns a decision plus reason code.
6. A separate supported cryptographic operation, when requested, executes only an allowed operation profile through the provider boundary; decision-only calls do not perform cryptographic key operations.
7. SDK mode returns the decision to the existing application; gateway mode forwards only after evaluation. The application still performs business authorization and must apply the decision to the same action context.
8. Audit/telemetry records the decision and operational metadata with redaction.
9. The application performs business authorization and returns its result.

## 8. Control-plane data flow

1. Admin authenticates with strong identity and tenant-scoped role.
2. API validates input, authorization, optimistic concurrency, and idempotency key where needed.
3. Service persists a new immutable revision or lifecycle transition.
4. Audit event is written transactionally where practical; otherwise the outbox pattern guarantees delivery and flags uncertainty.
5. Workers publish cache invalidation, posture, and notification events.
6. Data plane receives a signed/versioned configuration update or fetches within the bounded freshness window.

Outbound tenant webhooks use the same transaction as the source append-only audit event to insert a compact immutable event and one delivery row per matching enabled destination. The source audit UUID is the stable event ID, and a composite foreign key requires every webhook event to correspond to an existing same-tenant audit row. A PostgreSQL `FOR UPDATE SKIP LOCKED` claim function leases at most five rows for two minutes; delivery state is committed before the worker calls the key-provider broker or endpoint. Each request signs the exact version 1 JSON bytes with a domain prefix and broker-backed Ed25519, then sends HTTPS to an exact allowlisted hostname after validating and pinning all public DNS answers. The worker is at-least-once; receivers deduplicate by tenant and event ID. Event rows carry only bounded IDs, fixed reason codes, and correlation metadata. RLS scopes every data read/write by tenant, while the claim function is the only cross-tenant worker entry point and returns only lease metadata. Provider references used for webhook signing are stored in the dedicated forced-RLS `webhook_signing_keys` table and are not returned by the general key-reference API.

## 9. Hybrid crypto architecture

QuantumGate does not define a new cryptographic protocol. Hybrid operation is an integration profile around a maintained protocol/provider implementation. The design record for each profile MUST state:

- named standard or vendor-supported profile;
- classical and PQC mechanisms;
- provider/library and version;
- key purpose and lifecycle;
- downgrade detection;
- transcript/handshake binding;
- test vectors and interoperability partners;
- deprecation and rollback plan.

For TLS or other protocol-level operation, configuration is delegated to the maintained protocol stack. For application signatures, use a standard detached-signature/profile implementation; do not invent dual-signature encoding. If no vetted hybrid profile exists for a use case, the feature remains unsupported or observe-only.

## 10. Caching and consistency

Cache entries MUST include tenant, environment, application, policy revision, algorithm registry version, and expiry. Secrets and private keys MUST NOT be cached in general-purpose caches. A stale policy cache may:

- deny a protected action;
- remain observe-only;
- use a pre-approved emergency policy;
- allow only explicitly configured low-risk operations.

The behavior is per policy and visible in telemetry. “Use the last value forever” is prohibited.

## 11. Failure modes

- **Policy service unavailable**: use bounded cache only if policy permits; otherwise deny high-risk actions and return a retryable error.
- **KMS/HSM unavailable**: do not generate, unwrap, sign, or establish protected sessions; use an existing verified session only if policy permits.
- **Identity provider unavailable**: do not accept unverifiable new identity; existing sessions follow explicit max-staleness rules.
- **Algorithm provider unavailable**: no silent classical fallback from hybrid/PQC enforcement.
- **Audit store unavailable**: high-risk administrative changes stop or enter a documented quarantine; operational logs flag audit gap.
- **Telemetry unavailable**: security decisions continue only if required local controls remain intact; never block all security solely because a non-critical metrics backend is down.
- **Clock skew**: reject or quarantine time-sensitive credentials outside the configured bounded skew.
- **Configuration mismatch**: fail closed for protected routes and surface a remediation ID.

## 12. Observability

Use structured, versioned events and OpenTelemetry-compatible traces/metrics where supported. Required dimensions are service, version, region, tenant hash or authorized tenant identifier, application, policy revision, mode, decision, dependency, and reason code. Never use raw subject identifiers or credentials as high-cardinality labels.

Required dashboards and alerts:

- authentication failures and unusual spikes;
- policy deny/step-up rate;
- downgrade/unsupported-algorithm attempts;
- key rotation and provider health;
- audit delivery lag;
- cross-tenant authorization errors;
- rate-limit exhaustion;
- latency/error budget by integration mode;
- dependency certificate and metadata expiry.
