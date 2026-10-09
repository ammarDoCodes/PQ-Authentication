# QuantumGate Roadmap

Version: 0.1-draft
Principle: prove the security boundary and migration value before expanding surface area.

## Current implementation status

As of 2026-09-29, the repository implements a substantial but incomplete control-plane service, an initial TLS-terminating gateway path, the standalone SDK decision API, an internal key-provider boundary, and a narrow outbound webhook subsystem. The gateway and SDK paths bind decisions to tenant/application credentials, live TLS profile, a validated existing OIDC identity, current policy/profile state, and correlated audit evidence. The webhook subsystem uses a PostgreSQL outbox, source-audit UUID event identity, exact HTTPS host allowlists, broker-backed Ed25519 signatures, leased at-least-once delivery, bounded retries, and dead-letter visibility; real PostgreSQL and real Vault execution remain unvalidated. Its signed events are classical and are not post-quantum secure. A loopback-only gateway upstream example and an SDK `protect` reference application are present. Key providers include the ephemeral `memory-development` provider, a development/test-only Go `crypto/mldsa` provider for FIPS 204 ML-DSA-44/65/87 signing, and an unvalidated Vault Transit adapter limited to non-exportable Ed25519 signing. The PQC provider is neither protected custody nor an approved product profile; independent test-vector interoperability remains unvalidated. The public key-reference API does not invoke either provider; Vault operations have fake-HTTP tests only, and PostgreSQL-backed provider/outbox integration tests require test database credentials. Existing TLS file keys and local storage-encryption root material are not provider-protected. Live identity-provider/customer authorization interoperability and performance/capacity validation also remain outstanding. Phase 2 exit criteria remain unmet. The tenant-scoped profile review lifecycle blocks self-approval, but no profile review is approved by default, so non-observe enforcement remains unavailable to a tenant until a current independent review is completed. Phase 3 remains incomplete: provider-backed product workflows, production PQC operations/custody, overlap/revocation recovery, TLS/storage-key custody, and partner validation are not available. Phase 4 remains unimplemented.

## Phase 0 — foundations and decisions

Deliver:

- repository layout, build/test pipeline, coding/security agent rules;
- standards and algorithm registry process;
- threat model, data classification, tenant model, and decision-record template;
- dependency policy, SBOM/provenance plan, secret management, logging/redaction baseline;
- minimal service skeleton and health/readiness endpoints;
- test harness with synthetic tenants and provider fakes.

Exit criteria:

- no unresolved architecture ambiguity around trust boundaries or key custody;
- CI blocks secrets, unsafe dependency changes, and failed quality/security checks;
- tenant context is mandatory in the domain model.

## Phase 1 — secure control-plane MVP

Deliver:

- tenant, environment, application, member, role, and integration registry;
- OIDC admin authentication with strong validation and role scope;
- versioned API with problem details, idempotency, pagination, rate limits, and audit;
- policy drafts, simulation, activation, rollback, and revision history;
- algorithm/profile registry without live cryptographic operations yet;
- dashboard for applications, policies, audit, and integration status.

Exit criteria:

- cross-tenant negative tests pass;
- audit is complete for all control-plane mutations;
- policy behavior and failure modes are documented and tested;
- independent design/security review of the control plane is complete.

## Phase 2 — data plane and classical-compatible integration

Deliver:

- thin SDK and gateway/sidecar mode;
- application credentials with rotation and revocation;
- OIDC/JWT adapter and service identity adapter;
- session validation and policy decision path;
- observe-only posture inventory;
- secure defaults, telemetry, dashboards, and operational runbooks.

Exit criteria:

- a reference existing application integrates with minimal code;
- no-change monitor mode and controlled enforcement mode work;
- outage behavior for policy, IdP, key provider, audit, and telemetry is verified;
- performance and capacity budgets are recorded.

## Phase 3 — provider-backed keys and approved hybrid migration

Deliver:

- KMS/HSM/Vault adapter and key metadata lifecycle;
- provider-backed signing/encryption/session operations;
- approved protocol/library hybrid profile(s), initially narrow and explicit;
- downgrade detection, key overlap rotation, revocation, and emergency response;
- migration dashboard with blockers, exceptions, expiry, and evidence;
- interoperability vectors and partner test fixtures.

Exit criteria:

- no custom primitive, protocol, or combiner exists;
- exact providers/versions and standards are registered;
- positive/negative hybrid tests and failure injection pass;
- pilot tenants complete migration and rollback exercises;
- threat model and security review approve the profiles.

## Phase 4 — enterprise operations and compliance readiness

Deliver:

- SAML and WebAuthn/passkey adapters through maintained libraries;
- advanced support-access workflow, approvals, and break-glass controls;
- dedicated deployment profile, regional controls, retention/deletion, and customer-managed provider options;
- immutable audit export, evidence packs, backup/restore drills, incident exercises;
- formal reliability targets, on-call, vulnerability response, and release governance.

Exit criteria:

- production operational readiness review passes;
- independent assessment appropriate to the deployment is complete;
- no unsupported compliance or security claims;
- documented support and deprecation policy exists.

## Intentionally deferred

- arbitrary customer-defined cryptographic algorithms;
- custom application-level hybrid protocol;
- universal protocol proxy;
- hardware-specific acceleration;
- speculative AI risk decisions;
- consumer identity features;
- broad compliance certification claims before evidence exists.

## Change-control rules

Any roadmap change must state customer value, security impact, dependency/provider impact, tenant impact, operational cost, tests, rollback, and why the change cannot be delivered by a smaller existing module.
