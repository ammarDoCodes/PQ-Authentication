# QuantumGate Product Specification

Version: 0.1-draft
Status: implementation baseline
Normative words: MUST, MUST NOT, SHOULD, SHOULD NOT, MAY have their usual requirements meaning.

## 1. Purpose

QuantumGate is a multi-tenant SaaS and deployable integration layer that lets existing applications adopt standardized cryptographic agility and post-quantum migration controls without replacing their identity provider or rewriting their security boundary.

The product optimizes for less integration code and more reliable security functionality:

- one small SDK or gateway adapter;
- a narrow, stable API;
- mature cryptographic dependencies instead of custom primitives;
- policy-driven behavior instead of application-specific branches;
- explicit migration and rollback modes;
- strong defaults with observable failures.

QuantumGate MUST use “PQC-ready,” “PQC-enabled,” or “quantum-resistant” only when the specific algorithm and mode justify the term. It MUST NOT claim “fully secure,” “quantum-proof,” or equivalent absolutes.

## 2. Users and use cases

### 2.1 Personas

- **Application developer**: integrates an SDK or gateway adapter, maps the existing user/session context, and handles documented errors.
- **Security engineer**: defines policy, reviews crypto inventory and migration status, investigates events, and approves enforcement.
- **Platform operator**: deploys services, manages regions, scaling, backups, upgrades, and incident response.
- **Auditor/compliance owner**: reads immutable audit evidence, export reports, access history, and configuration changes.
- **Tenant administrator**: manages applications, team roles, identity-provider connections, and environment settings within one tenant.

### 2.2 Primary use cases

1. Register an existing application with minimal code.
2. Connect an existing OAuth/OIDC provider, SAML broker, passkey/WebAuthn flow, API-key system, or service identity system.
3. Run in observe-only mode to inventory algorithms, protocol paths, and migration blockers.
4. Enforce approved classical, hybrid, or PQC policy at a gateway or SDK boundary.
5. Manage application signing and key-encryption metadata without exposing private keys to the application.
6. Establish secure sessions using a maintained protocol/library and controlled lifetimes.
7. Rotate, revoke, disable, and recover key material through a provider-backed lifecycle.
8. View adoption, policy drift, key health, authentication failures, and security events.
9. Export audit and compliance evidence.
10. Roll back a policy change safely when compatibility or operational signals degrade.

## 3. Goals

- G1: Integrate a supported application with a small, documented surface.
- G2: Preserve existing authentication and authorization systems through adapters.
- G3: Make approved cryptographic modes explicit, observable, and upgradeable.
- G4: Support classical-to-hybrid-to-PQC migration without silent downgrade.
- G5: Isolate tenants, environments, identities, keys, policies, and audit records.
- G6: Make secure operation and incident response practical through auditability and telemetry.
- G7: Provide industrial-oriented reliability, change control, and release evidence.

## 4. Non-goals

QuantumGate MUST NOT:

- implement ML-KEM, ML-DSA, SLH-DSA, X25519, AES-GCM, ChaCha20-Poly1305, HKDF, TLS, WebAuthn, OAuth, or other primitives/protocols from scratch;
- invent a new key combiner, wire protocol, token format, password scheme, or authentication method;
- replace a customer’s identity provider, directory, authorization system, or business-domain roles;
- store customer private keys in plaintext in the control plane;
- provide a universal proxy for arbitrary protocols in the first release;
- promise protection against every future quantum or classical attack;
- make compliance certifications or FIPS claims without the required validated module, scope, evidence, and assessment;
- add speculative blockchain, AI, custom hardware, consumer password-manager, or unrelated endpoint features.

## 5. Product surfaces

### 5.1 SDK and gateway integration

The supported integration modes are:

- **SDK mode**: a thin library validates the request/session context, calls the QuantumGate data-plane API, and exposes typed results.
- **Gateway mode**: a reverse proxy or sidecar applies request policy before forwarding traffic to the existing application.
- **Control-plane API mode**: automation manages applications, policies, keys, identity adapters, and audit exports.

The integration MUST be additive. An application should not need to rewrite its user model or migrate its primary login flow to use QuantumGate.

### 5.2 Authentication adapters

Initial adapter contracts:

- OAuth 2.0/OIDC authorization-code flow with PKCE for browser/user login.
- OIDC JWT validation using issuer, audience, algorithm, key-rotation, time, and nonce checks.
- SAML 2.0 through a maintained library or broker when required by an enterprise customer.
- WebAuthn/passkeys through a maintained library; QuantumGate stores credential identifiers and metadata, not raw private key material.
- Existing session-cookie validation through a documented adapter boundary.
- Service-to-service identity using mTLS, workload identity, signed requests, or short-lived tokens through supported providers.
- API keys only for constrained machine access, with hashing, scoping, rotation, expiration, and a migration path to stronger identity.

Adapters MUST normalize identity into a small internal subject model without discarding provider-specific claims needed for authorization or audit. Adapter-specific validation rules are part of the security contract.

### 5.3 Crypto and hybrid modes

The first supported policy modes are:

- `classical-approved`: approved classical algorithms through maintained libraries and current protocol guidance.
- `hybrid-approved`: a library/protocol-supported combination of approved classical and PQC mechanisms.
- `pqc-approved`: approved PQC use where the protocol and ecosystem support it.
- `observe-only`: record posture and violations without blocking.

The exact algorithms, parameter sets, providers, protocol profiles, and deprecation dates MUST be held in a versioned standards/algorithm registry. Applications select a policy profile, not arbitrary algorithm strings. An unknown, disabled, deprecated, or unavailable algorithm MUST fail closed for enforcement paths.

QuantumGate MUST prefer protocol-level hybrid support such as provider-supported TLS or standardized application profiles. It MUST NOT concatenate secrets or signatures using an undocumented combiner.

### 5.4 Key management

Key management MUST support:

- generation through approved providers;
- key purpose and algorithm metadata;
- tenant/application/environment ownership;
- activation, rotation, expiration, revocation, destruction-request, and disabled states;
- versioned key identifiers and public-key distribution;
- separation of signing, key-encryption, session, and data-encryption purposes;
- HSM/KMS/Vault-compatible provider integration;
- envelope encryption for stored sensitive material;
- audit for every administrative and cryptographic lifecycle action;
- emergency revocation and controlled recovery.

Private keys SHOULD remain in an HSM/KMS or provider boundary. If export is unavoidable, it MUST be encrypted with a provider-controlled wrapping key, access controlled, short-lived, and never logged.

### 5.5 Session layer

QuantumGate MAY issue or validate short-lived session artifacts, but the application remains the source of business authorization. Session requirements include:

- explicit audience, issuer, subject, tenant, application, issued-at, expiration, and unique identifier;
- bounded lifetime and clock-skew policy;
- secure cookie defaults when cookies are used;
- replay protection for one-time or high-value operations;
- rotation after authentication-strength changes or suspicious events;
- revocation or deny-list support for emergency response;
- no sensitive secrets in URLs or logs;
- clear behavior when the key provider or policy service is unavailable.

### 5.6 Policy and risk engine

Policy evaluates tenant, environment, application, route/action, identity strength, algorithm mode, key health, source context, and risk signals. It returns `allow`, `deny`, `step_up`, `observe`, or `degraded_allowed` only when explicitly configured.

Policy features:

- versioned immutable policy revisions;
- draft, test, scheduled, active, and retired states;
- precedence and conflict resolution;
- route/action scoping;
- identity and device/context conditions;
- algorithm and key requirements;
- migration exceptions with owner, reason, expiration, and compensating control;
- dry-run and simulation;
- rollback to a prior known-good revision;
- policy decision explanation safe for operators but free of secret material.

Risk scoring MUST not silently become an authorization oracle. Any automated risk signal affecting access needs documented inputs, thresholds, fallback behavior, and audit evidence.

### 5.7 Dashboard

Dashboard areas:

- tenant and environment overview;
- application integration status;
- crypto inventory and PQC migration coverage;
- policy posture and drift;
- key lifecycle and provider health;
- authentication adapter health;
- audit and security event search;
- rate-limit and availability signals;
- migration blockers and recommended next actions;
- exportable evidence.

Dashboard data MUST be tenant-scoped, permission-checked server-side, paginated, and redacted by default.

### 5.8 Audit and monitoring

Audit events MUST cover authentication, authorization, policy, key lifecycle, adapter configuration, tenant administration, export, incident actions, and security-relevant failures. Each event should include event ID, timestamp, tenant, environment, actor/service, action, target type and identifier, outcome, correlation ID, reason code, source context, and schema version.

Audit records MUST be append-only from the product API, access controlled, time-synchronized, exportable, and retained according to tenant policy and legal requirements. Do not log passwords, private keys, bearer tokens, raw credentials, or full sensitive payloads.

Operational telemetry includes metrics, structured logs, traces, health checks, dependency health, queue lag, policy-cache age, key-provider latency, and authentication failure rates. Telemetry itself is sensitive tenant data and follows the same access and retention controls.

## 6. Tenancy and isolation

Every tenant-scoped record MUST carry an immutable tenant ID. Environment IDs separate development, staging, and production. Application IDs are unique within a tenant; external IDs are namespaced and cannot bypass authorization.

Required controls:

- server-side authorization on every control-plane request;
- deny-by-default tenant scoping in repositories and queries;
- separate encryption context/associated data per tenant and environment;
- no cross-tenant cache keys or shared object-storage paths;
- background jobs carry tenant and authorization context;
- exports are tenant-scoped and time-limited;
- support access is explicit, time-bound, approved, logged, and revocable;
- noisy-neighbor controls for rate, storage, queue, and event volume.

The reference deployment may use logically isolated multi-tenancy. High-assurance customers MAY require dedicated data stores, keys, regions, or deployments; this is a deployment profile, not a shortcut around the baseline controls.

## 7. Functional requirements

### FR-001 Integration

The system MUST provide a documented integration path that requires only configuration plus a small adapter surface for a supported framework.

### FR-002 Identity preservation

The system MUST validate and normalize an existing identity result without becoming the authoritative source of business roles.

### FR-003 Explicit mode

Every protected request MUST have an observable policy mode and decision. Missing or ambiguous mode MUST NOT silently select a weaker mode.

### FR-004 Algorithm registry

The system MUST reject algorithms not present and enabled in the versioned registry for the relevant tenant and environment.

### FR-005 Key lifecycle

The system MUST expose lifecycle operations with authorization, state validation, idempotency, and audit.

### FR-006 Policy lifecycle

The system MUST support draft, simulate, activate, schedule, rollback, and retire operations with revision IDs.

### FR-007 Migration

The system MUST show current posture, blockers, exceptions, last-seen evidence, and next action for each registered application.

### FR-008 Failure behavior

Each dependency failure MUST map to a documented fail-closed, fail-open-with-compensating-control, observe-only, or retry behavior. There MUST be no accidental fallback.

### FR-009 Rate limiting

Control-plane, authentication, token, key, export, and event-ingest operations MUST have tenant-aware and identity-aware limits with `429` responses and retry guidance.

### FR-010 Audit

All security-sensitive state changes and decisions MUST be auditable with correlation and revision identifiers.

### FR-011 Backward compatibility

Public APIs use `/v1` versioning, additive changes by default, documented deprecation windows, and contract tests. Security fixes MAY require behavior changes and MUST include migration notes.

### FR-012 Operations

The product MUST provide health, readiness, dependency, metrics, backup, restore, key-provider, and incident-response runbooks before production release.

## 8. Non-functional requirements

- NFR-001: Secure defaults; opt-out requires an explicit, audited decision.
- NFR-002: No private key, password, token, or secret in logs, traces, error messages, analytics, or support exports.
- NFR-003: All network traffic uses current TLS guidance; plaintext production links are prohibited.
- NFR-004: Services are horizontally scalable and stateless where practical; state belongs in explicit stores.
- NFR-005: Policy and key metadata reads have bounded latency and cache age; stale safety behavior is documented.
- NFR-006: Every release has reproducible build metadata, dependency inventory, tests, migration notes, and rollback instructions.
- NFR-007: Security incidents have detection, containment, key-revocation, communication, and recovery procedures.
- NFR-008: Data residency, retention, deletion, and export controls are configurable per tenant where deployment permits.
- NFR-009: Accessibility, localization, and browser support are documented for the dashboard.
- NFR-010: The system is observable without exposing protected data.

## 9. Deployment and operations

Supported profiles:

- managed SaaS control plane with hosted data plane;
- managed control plane with customer-hosted gateway/sidecar;
- customer-managed deployment for high-assurance environments.

Each profile MUST declare trust assumptions, network paths, key-provider responsibility, upgrade responsibility, telemetry location, backup ownership, and support access model.

Deployment requirements:

- infrastructure as code and reviewed configuration;
- separate production credentials and environments;
- secret injection from a secret manager;
- immutable, signed artifacts where available;
- least-privilege service accounts;
- network segmentation between public edge, data plane, control plane, workers, and stores;
- tested database migration and rollback strategy;
- backup encryption and restore drills;
- region and time-source health checks;
- canary or staged release for policy and crypto-provider changes.

## 10. Compliance readiness

The product SHOULD map controls and evidence to SOC 2, ISO 27001, NIST CSF, NIST SP 800-53 where applicable, and customer-specific requirements. It MUST distinguish “control implemented,” “evidence available,” and “certification/attestation completed.” No certification claim is valid without the appropriate independent assessment.

Evidence includes access reviews, change approvals, vulnerability scans, dependency reports, key lifecycle logs, backup/restore results, incident exercises, policy history, and security-test results.

## 11. Definition of product readiness

The MVP is ready for a controlled pilot only when:

- supported SDK/gateway integrations pass contract and interoperability tests;
- tenant isolation tests include negative cross-tenant cases;
- all listed crypto operations use maintained providers;
- migration, downgrade detection, rotation, revocation, and rollback are tested;
- audit events are complete and exportable;
- threat-model findings are resolved or accepted by an accountable owner;
- operational runbooks and restore evidence exist;
- independent security review has no unmitigated critical or high findings.
