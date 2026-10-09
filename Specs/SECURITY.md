# QuantumGate Security Requirements

Version: 0.1-draft
Security posture: security-critical product; security claims require evidence.

## 1. Security objectives

QuantumGate must protect:

- tenant and application isolation;
- identity authenticity and session integrity;
- cryptographic key confidentiality, integrity, purpose separation, and lifecycle;
- policy integrity and non-downgrade behavior;
- audit integrity and accountability;
- availability of protected paths within documented failure behavior;
- confidentiality of customer configuration, metadata, and telemetry;
- software and dependency supply chain integrity.

The product provides risk reduction and migration capability. It does not guarantee immunity from compromise or future cryptanalytic advances.

## 2. Cryptographic rules

1. Use standardized, maintained, reviewed libraries and protocol implementations.
2. Do not write primitive implementations, custom KEM/signature schemes, custom hash constructions, custom password hashing, custom TLS, custom token signing, or custom hybrid combiners.
3. Track NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, applicable NIST key-management guidance, TLS 1.3, OAuth/OIDC, WebAuthn, and relevant IETF specifications through a versioned standards register.
4. Use provider-supported hybrid modes. If a provider or standard does not define the needed hybrid behavior, do not create an ad hoc combination.
5. Algorithm selection is policy-controlled, allow-listed, versioned, and context-specific.
6. Disable deprecated and vulnerable algorithms by default; provide a controlled migration exception only with owner, expiry, and compensating control.
7. Use a cryptographically secure random source from the provider/runtime. Never seed randomness from time, identifiers, or application input.
8. Use authenticated encryption for protected data through a maintained library. Nonces/IVs follow the library’s requirements and are never reused where prohibited.
9. Use domain separation and associated data only as specified by the selected standard/library profile.
10. Do not claim FIPS validation unless the exact module, version, operating mode, boundary, and deployment are validated and documented.

## 3. Identity and access

- Enforce phishing-resistant or strong MFA for QuantumGate administrators where the deployment supports it.
- Use OIDC/OAuth validation with exact issuer/audience rules, signature algorithm allow-list, JWKS rotation, expiration, not-before, nonce/state, PKCE, and redirect URI validation.
- Validate SAML signatures, issuer, audience, recipient, destination, time conditions, and replay controls through a maintained library.
- Validate WebAuthn origin, RP ID, challenge, user verification, sign count behavior, and attestation policy according to the selected profile.
- Service identities use short-lived credentials, workload identity, mTLS, or signed requests with rotation.
- SDK decision calls require the narrow `decisions:evaluate` application-token scope. The service derives tenant/application from that credential, verifies the existing user's identity token with the current tenant application adapter, and derives transport profile from the TLS connection; request fields cannot authorize a tenant, application, or profile.
- Return all policy outcomes as explicit decisions. The SDK validates response binding and fails on transport/protocol errors; it does not compute or cache policy results. Repeated calls re-evaluate current policy and profile approval.
- Roles are deny-by-default and tenant/environment scoped. Support access is time-bound, approved, and logged.
- Crypto profile enforcement requires a tenant-scoped security engineer to review the versioned design evidence; the reviewer must differ from the submitter, and approval is bound to the reviewed profile snapshot.
- Break-glass access is separate, monitored, tested, and revocable.

## 4. Sessions and tokens

- Keep access tokens short-lived and scoped.
- Validate issuer, audience, subject, time, unique identifier, signature, key state, and tenant/application binding.
- Prefer secure, HttpOnly, SameSite cookies for browser sessions when applicable.
- Protect state-changing requests against CSRF where cookie authentication is used.
- Bind high-risk operations to a recent authentication event, transaction context, or one-time challenge.
- Revoke or invalidate sessions after key compromise, identity disablement, policy change requiring it, or incident response.
- Never accept `alg=none`, algorithm confusion, unsigned claims, or arbitrary key locations.

## 5. Key management

Key states are `provisioning`, `active`, `rotation_due`, `disabled`, `revoked`, `expired`, and `destroyed` (or equivalent explicitly documented states). Invalid transitions are rejected.

- Keys have unique opaque IDs, purpose, tenant, environment, application, provider reference, version, creation, activation, expiry, and revocation metadata.
- Private keys remain inside KMS/HSM/Vault where practical.
- Key-encryption keys are separated from data/signing/session keys.
- Rotation is overlapping and staged: create, publish/use, observe, activate, retire old, revoke if needed.
- Public-key distribution has cache expiry, version, issuer, and emergency invalidation behavior.
- Backups are encrypted, access controlled, tested, and separated from production credentials.
- Destruction requires authorization, retention/legal-hold checks, audit, and recovery-impact review.
- Key provider outages never trigger silent generation of an unmanaged replacement key.

The `memory-development` provider remains development/test only. The `vault-transit` adapter is a production-oriented but unvalidated subset: it creates non-exportable Ed25519 signing keys, reads their public keys, signs, and gates lifecycle state with tenant-scoped database metadata plus Vault minimum-signing-version settings. It does not export private material or advertise destruction. Provider operations are behind an environment-bound broker that requires tenant/application scope and per-operation actor/correlation context plus an append-only audit sink; audit records hash references and omit private data, inputs, signatures, and provider error text. Audit-intent failure blocks the operation; an audit-completion failure withholds its result. SQL row locks serialize an operation against lifecycle transitions, while Vault remains a separate system and cannot participate in a distributed atomic commit. The broker rejects providers that advertise private-material export.

Vault auth is supplied by an externally managed token sink file, intended for a Vault Agent auto-auth configuration using workload identity and short-lived tokens. The adapter rereads the token for each call, requires HTTPS with normal certificate verification in production, and has no TLS-verification bypass. Operators must keep Vault audit `log_raw` disabled and must not configure the Transit `input` request field as a non-HMAC field. Real provider operations and that server-side audit configuration have not been validated here.

The provider boundary is not connected to the public key-reference API, TLS certificate loading, or local AES-GCM storage-key use. TLS private keys are still loaded from `TLS_KEY_FILE`, and `RATE_LIMIT_HMAC_KEY` remains available to the process. Vault Community supports the implemented Ed25519 subset; current Vault Enterprise documentation lists ML-DSA, SLH-DSA, and hybrid signatures as Enterprise operations. The adapter does not implement those and does not support ML-KEM. Do not treat it as production-ready or enable product key workflows until integration, real-provider testing, recovery, authorization, and these remaining custody uses are reviewed.

The separate `pqc-development` provider implements FIPS 204 ML-DSA-44/65/87 with Go 1.27.1 `crypto/mldsa` for local development/interoperability work only. It is opt-in, process-resident, non-persistent, and has no protected custody; configuration and the broker reject it in production. It has no KEM operations and does not change the approved profile registry or enable `pqc-approved`. Its local key destruction drops the ML-DSA key reference only; the library exposes no explicit zeroization guarantee. With the FIPS 140 Go module v1.0.0, the Go package documents that ML-DSA key generation, key parsing, and verification return errors; this implementation makes no FIPS-module validation or product approval claim.

## 6. Tenant isolation

- Require tenant context in all repositories, caches, queues, object paths, audit events, and encryption associated data.
- Enforce authorization server-side at every request and worker boundary.
- Add database constraints, row-level protections, or equivalent defense-in-depth where supported.
- Test cross-tenant reads, writes, exports, search, cache collisions, event subscriptions, support access, and timing/error behavior.
- Do not expose tenant existence or resource metadata to unauthorized callers beyond a safe not-found response.

Webhook destination, event, and delivery rows use forced RLS and composite tenant/application foreign keys. Worker claims are globally leased by one bounded security-definer function; before loading the event, destination, or signing reference, the worker establishes the returned tenant context under RLS. Event rows are immutable, audit-correlated, and contain only a small allowlisted metadata envelope. Public key lookup returns public material by opaque QuantumGate key ID only.

## 7. Input, output, and abuse controls

- Validate schema, size, encoding, content type, route, redirect, URL, certificate, issuer, and identifier inputs.
- Reject ambiguous encodings, duplicate security headers, invalid Unicode/control characters where relevant, and parser differentials.
- Apply tenant, principal, IP/network, route, and operation-specific rate limits.
- Bound decision request and identity-token sizes, validate method/path, reject query/unknown fields, and audit each returned or rejected decision with a server-generated correlation ID and profile/policy revision evidence.
- Limit login, token, challenge, key, export, policy simulation, and event-ingest abuse.
- Use bounded timeouts, retries with jitter only for safe/idempotent operations, circuit breakers, and queue limits.
- Return generic authentication/authorization errors to untrusted callers while retaining safe reason codes for operators.

Webhook destinations require exact-host allowlisting and HTTPS port 443. Reject query strings, userinfo, fragments, local/private/link-local/reserved addresses, redirects, and any non-public DNS answer. Resolve and validate on every attempt, pin the request to those addresses, disable proxy use, and retain TLS certificate verification. These controls reduce SSRF risk but do not replace deployment egress firewall rules.

## 8. Secrets and sensitive data

- Store secrets only in an approved secret manager or KMS-backed store.
- Inject secrets at runtime; do not commit, bake into images, place in command lines, or include in fixtures.
- Rotate credentials and support emergency revocation.
- Redact logs, traces, errors, analytics, crash dumps, support bundles, and audit exports.
- Classify tenant data, key metadata, identity claims, audit events, and telemetry with retention and access rules.
- Scrub test data and use synthetic credentials that cannot authenticate anywhere.

## 9. Application and infrastructure security

- Use secure headers, CSRF protection where applicable, strict CORS, SSRF protections, request size limits, and safe deserialization.
- Separate public edge, data plane, control plane, worker, data stores, and provider networks.
- Use least-privilege service accounts and deny-by-default network policies.
- Protect admin UI against XSS, clickjacking, injection, and unsafe file/export handling.
- Encrypt data in transit and at rest using provider-supported configurations.
- Keep clocks synchronized and monitor drift.
- Harden container/OS images and remove compilers, shells, debug endpoints, and test credentials from production images where possible.

## 10. Supply-chain security

- Pin direct and transitive dependencies with reviewable lockfiles.
- Maintain an SBOM and provenance/attestation for released artifacts.
- Scan dependencies, containers, IaC, secrets, licenses, and known vulnerabilities.
- Review cryptographic dependency maintenance, release signatures, supported versions, CVE response, and build reproducibility.
- Use protected branches, signed/reviewed commits where supported, isolated CI credentials, and least-privilege build tokens.
- Rebuild from known source and record compiler/runtime/toolchain versions.
- No dependency is accepted solely because it is popular; crypto dependencies require explicit review.

## 11. Audit and incident response

Audit events cover login, MFA, adapter changes, policy draft/activation/rollback, key lifecycle, export, support access, role changes, rate-limit abuse, and security failures. Audit integrity includes append-only writes, access control, timestamps, correlation, schema version, and delivery-gap monitoring.

Incident runbooks must cover:

- suspected signing or KMS compromise;
- provider vulnerability or algorithm deprecation;
- tenant-isolation incident;
- credential/token leakage;
- malicious policy change;
- audit-store loss or tampering;
- dependency supply-chain compromise;
- regional/service outage.

Runbooks identify containment, revocation, rotation, customer communication, evidence preservation, recovery, and post-incident review.

## 12. Security verification gates

Before pilot: threat model, dependency review, tenant-isolation tests, authentication tests, crypto provider review, key lifecycle tests, secret scan, SAST/SCA/container/IaC scans, and focused penetration review.

Before production: independent security review, restoration drill, incident exercise, canary/rollback evidence, complete audit coverage, vulnerability disposition, standards register review, and no unmitigated critical/high findings.
