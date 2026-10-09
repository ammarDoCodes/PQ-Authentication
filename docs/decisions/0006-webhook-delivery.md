# Decision 0006: tenant webhook delivery

- Status: accepted for the implemented event subset; database/provider validation is incomplete
- Date: 2026-09-28
- Scope: outbound, tenant-configured security events over HTTPS

## Context

The API contract requires signed, replay-resistant events, bounded delivery retries, tenant isolation, endpoint controls, rotation, and dead-letter visibility. QuantumGate already has an append-only audit stream, a tenant-scoped PostgreSQL runtime role, and a key-provider broker. This feature must reuse those boundaries without adding a general-purpose queue or introducing a new cryptographic implementation.

## Decision

Use a PostgreSQL outbox. A supported source audit row, the immutable webhook event, matching delivery rows, and the `webhook.event_queued` audit are committed in the source transaction. The webhook event UUID is the source audit UUID. Event rows contain only the event type, schema version, tenant/application IDs, correlation ID, resource type/UUID, occurrence time, and fixed reason code. The currently emitted types are `policy.activated`, `policy.rollback`, `key.rotation_due`, `key.revoked`, `adapter.failure`, and `posture.blocker_found`. Provider-degraded and general security-alert events have no safe source in the existing service and are not emitted.

The worker claims at most five rows through a two-minute PostgreSQL lease using `FOR UPDATE SKIP LOCKED`, commits the lease before external work, sets tenant context before reading each row, and updates delivery state only if it still owns the lease token. The worker signs and sends sequentially. Multiple processes cannot claim the same live lease. An expired lease is reclaimed after a process crash. Shutdown cancels active calls; an incomplete lease is retried after expiration.

Delivery is at least once. Any `2xx` is success. DNS/network/provider timeouts, `408`, `425`, `429`, and `5xx` are retryable. TLS validation failure, unsafe destination, redirect, other `4xx`, invalid key state, or invalid signature is permanent. Automatic delivery permits eight attempts with exponential delays beginning at five seconds, capped at 15 minutes. Dead deliveries retain safe status/error codes and timestamps; an authorized administrator can manually requeue a dead delivery at most five times without changing its event ID.

Each attempt serializes a fixed field-order version 1 JSON envelope once. The signature input is the exact body bytes preceded by `QuantumGate-Webhook-Event-v1` and a NUL byte. The sender exposes the detached RFC 8032 Ed25519 signature in `X-QG-Signature: ed25519=<standard-base64>`. The body binds event ID/type/time, tenant/application, attempt, correlation, destination ID, key ID/algorithm, resource ID, and fixed reason code. No consumer-side canonicalization is needed: verify the exact raw body. Receivers should enforce a five-minute `sent_at` tolerance and deduplicate `(tenant_id,event_id)`; retries keep the identity but have a new signed attempt and send time.

All webhook signing keys are generated and used through the configured broker. The database stores the opaque provider reference internally and only the public PKIX key material is exposed by stable QuantumGate key ID. Rotation retains the old public key and its timestamps. Ed25519 is the only available algorithm today and is not post-quantum. There is no fallback to `memory-development` in production; real Vault Transit remains unvalidated.

Destinations require HTTPS on port 443 and an exact operator-configured hostname. The sender rejects URL userinfo, query, fragment, unlisted host, single-label/local/private/reserved DNS answers, and redirects. It resolves every attempt, rejects the entire answer set if any address is not public, and pins the connection to those validated IPs. It disables proxy use and preserves system TLS certificate verification with a TLS 1.2 minimum. Private customer destinations are unsupported; network egress rules remain a deployment control.

Forced RLS protects signing-key metadata, destinations, events, and deliveries. Composite tenant/application foreign keys prevent mismatched references; a tenant/event foreign key also requires every outbound event ID to reference an append-only source audit row. Provider references used for webhook signing live in the dedicated `webhook_signing_keys` table, separate from the general key-reference API. Database triggers retain signing-key, destination, event, and delivery history and enforce destination revision, lease/state transition, retry-counter, and safe error-code rules. The worker claim and public-key lookup functions use pinned search paths and expose only the minimal intended fields. `webhook.event_queued` and worker outcome audits carry the original correlation and safe codes, never URLs, signatures, body bytes, provider references, or raw backend errors. A broker audit-store outage is a retryable signing failure; no request is sent unless signing and its required audit both succeed.

## Consequences and limitations

- A crash after the receiver accepts an HTTP request but before QuantumGate commits success can cause a duplicate; receiver deduplication is required.
- Provider operations and PostgreSQL changes are not one distributed transaction. If a generated/activated key succeeds but the database transaction fails, an orphan provider key may remain. If an old key is marked rotation-due but the SQL commit fails, delivery fails closed until reconciled.
- Destinations can be changed or disabled with optimistic concurrency. An HTTP request already in flight when disablement commits may complete; pending/retry rows are canceled.
- URL and signing key updates affect queued deliveries that have not yet started; the worker uses the current destination configuration and signing key.
- No destination bearer/HMAC secret is supported. Authentication is the detached event signature.
- `provider.degraded` and `security.alert` have no event producer here. Webhook delivery failures are audited locally and are not recursively sent through the same webhook channel.
- PostgreSQL migration/integration behavior requires `TEST_DATABASE_URL` and `TEST_RUNTIME_DATABASE_URL`; when absent, the database scenarios are `NOT VALIDATED`. Fake broker tests do not validate a real Vault deployment, ACL, token lifecycle, audit device, or custody.

## Validation

Unit tests cover exact signed bytes, event source allowlisting, provider failure, malformed signatures, DNS/IP filtering, redirect behavior, TLS error classification, HTTP status classification, bounded backoff, and retry exhaustion. PostgreSQL-gated integration cases cover migration application, RLS, immutable evidence, source-audit event identity, audit redaction/correlation, public-key lookup, concurrent claims, and manual retry identity. These database tests must be reported `NOT VALIDATED` unless they execute against PostgreSQL with both runtime and migration credentials.
