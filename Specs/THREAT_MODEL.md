# QuantumGate Threat Model

Version: 0.1-draft
Method: assets, trust boundaries, actors, abuse cases, STRIDE-oriented mitigations

## 1. Scope and assumptions

This model covers the QuantumGate SaaS control plane, data plane, SDK/gateway, dashboard, integrations, key providers, identity providers, storage, build pipeline, and operator workflows. It assumes customer applications and identity providers may be compromised independently. It does not assume that any single network segment is trusted merely because it is private.

Residual risk must be reviewed whenever a new protocol, provider, deployment profile, identity adapter, data type, or tenant feature is added.

## 2. Assets

| ID | Asset | Impact if compromised |
|---|---|---|
| A1 | Tenant boundary and configuration | Cross-customer disclosure or control |
| A2 | Private keys and provider handles | Forgery, decryption, impersonation |
| A3 | Policy revisions and algorithm registry | Downgrade, unauthorized access, unsafe crypto |
| A4 | Sessions, tokens, challenges, identity claims | Account takeover, replay |
| A5 | Audit evidence | Loss of accountability and compliance evidence |
| A6 | Application integration credentials | Unauthorized data-plane access |
| A7 | Customer metadata and telemetry | Privacy and intelligence disclosure |
| A8 | Build artifacts and dependencies | Supply-chain compromise |
| A9 | Availability and recovery state | Denial of service or unsafe emergency behavior |

## 3. Actors

- Unauthenticated internet attacker.
- Stolen customer credential or session holder.
- Malicious or compromised tenant administrator.
- Compromised customer application or SDK host.
- Malicious support/operator account.
- Compromised identity provider or KMS/HSM/Vault.
- Malicious dependency, build worker, registry, or artifact.
- Insider with database, cache, log, or network access.
- Nation-state or well-funded adversary with harvest-now-decrypt-later interest.
- Accidental operator or developer error.

## 4. Trust boundaries

- TB1 client/browser ↔ edge;
- TB2 customer app ↔ SDK/gateway;
- TB3 data plane ↔ control plane;
- TB4 QuantumGate ↔ IdP;
- TB5 QuantumGate ↔ key provider;
- TB6 services ↔ shared tenant storage/cache/queue;
- TB7 operator/support ↔ production;
- TB8 source/CI ↔ release artifact;
- TB9 primary systems ↔ backup/export/telemetry systems.

Every boundary requires identity, authorization, validation, timeout, rate limiting, and appropriate evidence.

## 5. Threat register

| ID | Threat | Assets | Mitigations | Verification |
|---|---|---|---|---|
| T-01 | Cross-tenant read through missing filter | A1,A7 | Required typed tenant context, repository guards, DB defense-in-depth | Negative integration tests, fuzzed queries |
| T-02 | Cross-tenant cache collision | A1,A3,A4 | Tenant/environment/application/policy revision in cache key | Collision tests and cache namespace review |
| T-03 | Forged policy or registry update | A3 | Strong admin auth, tenant-scoped security-engineer role checks, profile approval by an actor distinct from the submitter, immutable profile snapshots bound to registry version and hash, append-only correlated audit | Authorization, self-approval, stale/concurrent transition, tenant-isolation, and tamper tests |
| T-04 | Algorithm downgrade | A2,A3,A4 | Allow-list, explicit mode, negotiation binding, no silent fallback | Downgrade/interoperability tests |
| T-05 | Custom crypto defect | A2,A4 | Prohibit manual primitives/protocols; provider boundary and review | Code/dependency audit |
| T-06 | KMS/HSM compromise or outage | A2,A9 | Provider isolation, least privilege, rotation/revocation, fail-safe modes | Chaos and incident exercise |
| T-07 | Token replay | A4 | Short token age, exact issuer/audience, TLS, and replay store for one-time flows; SDK decisions are freshly evaluated and not response-cached | Replay and clock-skew tests; gateway and SDK identity bearer tokens remain reusable while valid |
| T-08 | Stolen admin session | A1,A2,A3,A5 | MFA, short session, step-up, device/session review, break-glass control | Auth and incident tests |
| T-09 | Malicious identity-provider metadata | A4 | Exact issuer/audience, signed metadata/process, allow-list, change approval | Adapter negative tests |
| T-10 | SSRF via provider/issuer/webhook URL | A6,A7,A9 | No arbitrary URLs, exact-host allow-list, HTTPS/443, per-attempt DNS/IP validation and pinning, no redirects or proxy, TLS verification, egress policy | SSRF, DNS rebinding, private-IP, redirect, TLS-failure tests |
| T-11 | Secret leakage in logs/errors | A2,A4,A6,A7 | Redaction middleware, structured schemas, secret tests | Log snapshot and canary-secret tests |
| T-12 | Abuse of key/export/simulation endpoints | A2,A7,A9 | Fine-grained auth, operation rate limits, bounded export ranges/output, tenant scope | Abuse and load tests |
| T-13 | Malicious SDK/gateway host | A4,A6 | Operator-owned exact routes, dedicated gateway listener, live TLS profile evidence, scoped DB checks, bounded token age, header replacement, upstream network isolation, and explicit application-side decision handling | Compromise scenario review; the shared process is not isolated, a compromised gateway can alter forwarded traffic, and a compromised SDK host can ignore or forge its own reported decision |
| T-14 | Audit deletion or tampering | A5 | Append-only store, restricted access, integrity metadata, encrypted export | Tamper and restore tests |
| T-15 | Queue/event tenant confusion or replay | A1,A5,A7 | Forced RLS, tenant/application composite FKs, immutable event ID bound to source audit, tenant-scoped worker reads, signed tenant/destination context, timestamp acceptance window, receiver dedup guidance, at-least-once semantics | Poison, cross-tenant, duplicate-worker, event-tamper, timestamp, and receiver-dedup tests |
| T-16 | Supply-chain compromise | A8 | Lockfiles, SBOM, provenance, signed artifacts, dependency review | CI policy and build reproduction |
| T-17 | Policy cache staleness | A3,A9 | Max age, revision binding, explicit stale mode, invalidation | Failure-injection tests |
| T-18 | Timing/error enumeration | A1,A4,A7 | Generic untrusted errors, bounded responses, authorization-first lookup | Black-box response tests |
| T-19 | Backup/export disclosure | A1,A2,A5,A7 | Authenticated encryption, role checks, expiry, tenant scope, audit | Restore/export access tests |
| T-20 | Harvest now, decrypt later | A2,A7 | Inventory, TLS/protocol migration, hybrid profiles, retention minimization | Migration posture tests and review |
| T-21 | Malicious policy exception | A3,A4 | Owner/reason/expiry/compensating control, approval, alerting | Exception lifecycle tests |
| T-22 | Clock manipulation | A4,A9 | Trusted time sources, drift monitoring, bounded skew, fail-safe expiry | Clock-skew tests |

## 6. Abuse cases

### 6.1 Forced downgrade

An attacker alters negotiation or provider availability to make a hybrid request use classical-only protection. The system must bind the required mode to policy, detect mismatch, emit an event, and deny or use the explicitly approved migration mode. It must never infer that “any protection” is sufficient.

### 6.2 Tenant export abuse

An administrator requests a large audit or telemetry export and attempts to include another tenant. The implemented audit-export routes require an authorized tenant role, enforce tenant RLS, cap a request at a 90-day range, 5,000 events, and 7 MiB, redact `source_context`, encrypt the stored payload with tenant and export ID as authenticated context, expire jobs after 24 hours, apply tenant/principal/operation rate limits, and audit creation, metadata reads, and downloads. The runtime role cannot directly update or delete export rows; a tenant-scoped security-definer function removes expired rows in bounded batches. Integration tests cover cross-tenant denial, redaction, encrypted storage, expiry, restricted runtime permissions, and idempotent creation.

The current implementation does not support telemetry or general evidence-pack exports, tenant-configurable retention, legal holds, or separate approval/dual control for export access. These remain requirements for broader or production export workflows.

### 6.3 Key compromise

A signing key or provider credential is suspected compromised. The internal provider boundary accepts only opaque references with server-supplied tenant, application, and environment scope; it never returns private material, rejects unsupported capabilities, and requires correlated audit intent before provider operations. The Vault adapter generates references server-side, constructs Transit paths from trusted scope, and uses the existing key-reference table under row-level security for lifecycle state. Row locks serialize broker signing and lifecycle transitions; Transit minimum signing versions block inactive keys. A failed database commit after a Vault configuration update can leave the external key more restrictive than its database state; subsequent use fails closed and requires reconciliation. The `memory-development` provider remains ephemeral process memory and not production custody. The public key-reference API remains metadata-only, and TLS private keys plus the local storage-encryption root key remain process-visible. Operators still need real Vault testing, least-privilege ACL and token renewal review, audit-device input redaction verification, provider-specific recovery procedures, and tested session/token invalidation before claiming the full response requirements below.

The `pqc-development` provider adds process-resident Ed25519 and FIPS 204 ML-DSA-44/65/87 private keys for development/test only. It rejects production selection, scopes references by tenant/application/environment, serializes signing against lifecycle changes, and does not export key material through its provider interface. The Go ML-DSA API has no explicit zeroization operation; destroyed keys are made unusable and dereferenced, but memory erasure is not claimed. This provider advertises no KEM operations and does not authorize a PQC product profile. It is not protected custody and must not be used for production secrets.

Operators must be able to disable/revoke a compromised key, publish replacement metadata, invalidate affected sessions/tokens, preserve evidence, and communicate impact without deleting the audit trail. A provider operation that succeeds remotely but cannot write its completion audit withholds its result; it cannot guarantee atomic rollback at an external provider, so reconciliation and incident handling must account for that outcome.

### 6.4 Compromised customer application

The customer application sends malformed or abusive events or presents stolen integration credentials. QuantumGate must limit credentials, validate events, apply quotas, isolate tenant impact, and make revocation fast.

### 6.5 Gateway identity-token replay

The gateway accepts a signed, audience-bound OIDC ID token as a bearer token and limits its issue and authentication time to 15 minutes. A nonempty OIDC nonce claim is required, but the gateway does not own the login transaction that issued the token and cannot compare the nonce with a gateway-held challenge. It also does not consume a token `jti`; a stolen token can be reused while it remains valid. TLS, audience binding, short age, no-token logging, and the application's own authorization limit exposure, but they do not provide one-time replay prevention. Do not describe this path as replay-proof. A separate gateway-owned OIDC flow or another reviewed session-binding design is required before making that claim.

### 6.6 Malicious dependency update

A dependency release contains a backdoor. CI must fail or quarantine based on provenance, vulnerability/license policy, review, lockfile diff, and behavior checks before production promotion.

## 7. Security assumptions to make explicit

- Customer applications correctly preserve trusted identity context when using SDK mode.
- SDK applications bind each fresh QuantumGate decision to the same method/path and existing identity context used for the protected action, and do not reuse or cache a prior decision. The application remains responsible for business authorization and enforcing the returned outcome.
- Customer-controlled hosts can read their own process memory; SDK mode alone cannot protect secrets from a fully compromised host.
- Key providers, identity providers, cloud infrastructure, and time sources have their own assurance and outage characteristics.
- A hybrid mode is only as strong as its specified protocol, provider, parameters, implementation, and operational deployment.

## 8. Residual risks

Residual risks include compromised customer workloads, provider-wide compromise, unknown cryptanalytic advances, implementation bugs in third-party libraries, incorrect customer policy, insecure deployment, and availability tradeoffs during dependency failure. Gateway and SDK decision calls accept audience-bound bearer ID tokens that can be replayed during their 15-minute validity; the SDK decision service does not consume a one-time token identifier. The separate gateway/control-plane listeners still share one process. Each release must list accepted residual risks, owner, evidence, and review date.
