# QuantumGate API and SDK Contract

Version: v1 baseline
Transport: HTTPS with current TLS guidance
Format: JSON unless an endpoint explicitly declares another media type

## 1. Compatibility

Public routes use `/v1`. Additive fields are allowed; clients must ignore unknown fields. Breaking behavior requires a new version or documented security exception. Every response includes `request_id`; mutation responses may include `operation_id` and `revision_id`.

All timestamps are RFC 3339 UTC. IDs are opaque strings. Every mutation accepts an idempotency key where retries could duplicate state. Mutable resources use `ETag`/`If-Match` or an equivalent revision precondition.

Implemented non-read `/v1` requests require one `Idempotency-Key` header containing 16–128 ASCII letters, digits, `.`, `_`, `~`, or `-`. Keys are scoped to the tenant and authenticated principal and have a 24-hour replay window. The raw key is not stored. Successful responses and audited authorization denials are committed with their state/audit changes; a retry with the same key and request replays the stored status, body, and safe response headers and sets `Idempotency-Replayed: true`. Response bodies are encrypted with AES-256-GCM under a purpose-separated key derived from `RATE_LIMIT_HMAC_KEY`, with tenant and idempotency hash as authenticated context. Keep this deployment key stable for at least 24 hours. Reusing a live key for a different request returns `409 IDEMPOTENCY_KEY_REUSED`. Requests that fail before a mutation commits do not consume the key. Expired rows are cleaned up opportunistically in bounded batches on subsequent tenant requests.

## 2. Authentication and authorization

Control-plane API:

- interactive admins authenticate through configured OIDC with strong MFA;
- service clients use short-lived OAuth client credentials, workload identity, mTLS, or signed requests;
- scopes are narrow and tenant/environment constrained;
- every request is authorized server-side;
- bearer tokens are never accepted in query strings.

`POST /oauth/token` currently supports the `client_credentials` grant. Authenticate with HTTP Basic using the application UUID as `client_id` and a rotated `qgc_` credential as `client_secret`; send `grant_type=client_credentials` and an explicit, space-separated subset of the credential's scopes as form data. The service returns an opaque `qgt_` bearer token valid for five minutes. It stores only a hash, audits issuance, rate-limits token requests, and rejects new issuance immediately after credential rotation or application disable. `POST /oauth/introspect` accepts the same Basic client authentication and a form-encoded `token`; it returns only the caller's own active token metadata. Observation ingestion consumes `observations:write`; application posture reads also accept `posture:read`; standalone decisions consume `decisions:evaluate`. The TLS-terminating gateway continues to evaluate inline without a service-token scope.

The current administrator sign-in uses the OIDC authorization-code flow with server-generated `state`, nonce, and PKCE S256. The callback is bound to a short-lived browser cookie, consumes its server-side transaction once, and validates issuer, client audience, signing algorithm, required ACR, `auth_time`, token age, and the exact nonce. Successful sign-in creates an opaque server-side session referenced by a `Secure`, `HttpOnly`, `SameSite=Lax` cookie; raw session identifiers are never stored. Sessions expire after eight hours and after 30 minutes idle. Cookie-authenticated changes require a same-origin `Origin` and matching CSRF token. Login and logout outcomes are written to a separate append-only system authentication audit table. Administrators can rotate scoped application credentials, and service clients can exchange them for short-lived tokens. The standalone decision API accepts `decisions:evaluate` service tokens; the SDK requests that scope only when `Protect` is called. Event delivery remains unimplemented.

Admin browser routes are `GET /auth/login`, `GET /auth/callback`, `GET /auth/session`, and `POST /auth/logout`. `/auth/session` returns a CSRF token for the current session; browser clients send it in `X-QG-CSRF-Token` on state-changing requests. Configure one exact `OIDC_REDIRECT_URL` ending in `/auth/callback`. An optional `OIDC_CLIENT_SECRET` is accepted from the runtime secret source; PKCE is still required.

Every implemented control-plane request also requires `X-QG-Tenant-ID`. This value selects the tenant context but is not trusted as authorization. The server verifies a matching `(issuer, subject)` membership inside a transaction, sets transaction-local PostgreSQL tenant context, and uses the role from that row. Tenant-scoped reads and writes remain constrained by row-level security and tenant-qualified queries. Unknown membership receives a generic not-found response. Browser sessions use cookie authentication; state-changing requests require CSRF validation. The internal administrator bearer verifier is not enabled by the production entry point. Observation ingestion and posture reads can also use an application bearer token; the service derives tenant and application from the token and does not trust caller-supplied tenant context.

Data-plane API:

- SDK/gateway uses a scoped application credential, mTLS/workload identity, or a documented signed request;
- the application context is derived from registered credentials and trusted deployment metadata;
- customer-supplied tenant/application IDs are treated as claims to validate, not as authority; the implemented observation route binds the path application to the token.

`POST /v1/applications/{application_id}/decisions` is the standalone SDK decision route. It requires a valid application bearer token with `decisions:evaluate`; the tenant and application are derived from that token and the path application must match it. The JSON body contains only `method`, `path`, and the existing application's `identity_token`. The server validates that identity token with the application's current, recently verified OIDC adapter. It derives `profile_id` from the actual TLS 1.3 connection to the decision API; callers cannot supply tenant, application, or profile authority in the body. The route is available only when the registered application is active and configured for `sdk` integration.

Decision requests are bounded to 64 KiB, with action paths limited to 1 KiB and identity tokens to 16 KiB. Query strings, unknown fields, duplicate JSON values, invalid methods, and malformed identity/action context are rejected. Each call evaluates current application, adapter, policy, and profile-review state and writes one correlated audit event before returning. The API does not replay or cache decision responses and does not require an `Idempotency-Key`: repeating a request performs a fresh evaluation, so a prior `allow` cannot be replayed after a policy or profile changes. The route applies the service endpoint's per-IP and per-application limits and the evaluator's per-tenant, per-application, and per-IP decision limits; limit-store failure returns retryable `503`, and excess traffic returns `429` with `Retry-After`.

## 3. Common error format

Use RFC 9457-style problem details:

```json
{
  "type": "https://api.quantumgate.example/problems/policy-denied",
  "title": "Request denied by policy",
  "status": 403,
  "code": "POLICY_DENIED",
  "detail": "The requested protection mode is not enabled for this application.",
  "instance": "/v1/requests/req_01...",
  "request_id": "req_01...",
  "retryable": false
}
```

Untrusted callers receive generic details. Operator-only reason codes must not expose secrets, key material, provider internals, or identity-validation details useful for enumeration.

## 4. Control-plane resources

### Tenants and members

- `GET /v1/tenants/{tenant_id}`
- `PATCH /v1/tenants/{tenant_id}`
- `GET /v1/tenants/{tenant_id}/members`
- `POST /v1/tenants/{tenant_id}/members`
- `DELETE /v1/tenants/{tenant_id}/members/{member_id}`
- `GET /v1/tenants/{tenant_id}/algorithm-profiles`

Tenant-scoped resource routes verify membership and authorization server-side. The algorithm-profile catalog is readable by tenant admins, security engineers, developers, and auditors; review evidence has the narrower roles documented below. Tenant deletion is a controlled asynchronous operation with retention/legal-hold checks.

### Algorithm profiles

- `POST /v1/tenants/{tenant_id}/algorithm-profiles/{profile_id}/reviews`
- `GET /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/approve`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/reject`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/disable`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/deprecate`

Mutations require the tenant-scoped `security_engineer` role; review reads require `security_engineer` or `auditor`. A submission must reference a built-in, versioned profile and provide its design record: named standard/profile, mechanisms, key purpose and lifecycle, downgrade detection, transcript/handshake binding, test-vector references, interoperability partners, deprecation plan, and rollback plan. The submitting engineer cannot approve or reject that review; a different security engineer must provide an HTTPS review-evidence reference. Review records are immutable snapshots. Approval is bound to the current canonical profile hash and registry version. A changed registry version requires a new review; approved profiles can only be disabled or deprecated, and those states fail closed for enforcement. Rejected and retired snapshots remain available as audit history. All mutations require `Idempotency-Key`; reviewer transitions also require the current review ETag in `If-Match`.

### Applications and environments

- `POST /v1/tenants/{tenant_id}/environments`
- `GET /v1/tenants/{tenant_id}/applications`
- `POST /v1/tenants/{tenant_id}/applications`
- `GET /v1/applications/{application_id}`
- `POST /v1/applications/{application_id}/decisions`
- `PATCH /v1/applications/{application_id}`
- `POST /v1/applications/{application_id}/credentials/rotate`
- `POST /v1/applications/{application_id}/disable`

Application creation returns integration metadata but never returns private keys. The implemented credential-rotation action accepts a label, an expiry from five minutes through one year, and a nonempty subset of the registered service scopes. It revokes earlier credentials for that application, stores only a hash, audits the change, and returns the secret once. Same-key retries replay the encrypted response during the idempotency window. OAuth token issuance and caller-scoped introspection are implemented. The gateway's inline decision path does not consume the `decisions:evaluate` service-token scope; the standalone SDK decision route does.

### Identity adapters

- `GET /v1/applications/{application_id}/identity-adapters`
- `POST /v1/applications/{application_id}/identity-adapters`
- `PATCH /v1/identity-adapters/{adapter_id}`
- `POST /v1/identity-adapters/{adapter_id}/verify`
- `POST /v1/identity-adapters/{adapter_id}/disable`

Provider metadata uses references or validated configuration. Arbitrary callback URLs, issuer URLs, or JWKS locations are prohibited unless allowed by deployment policy.

The implemented adapter subset is OIDC only. Creation accepts `adapter_type: "oidc"`, an HTTPS issuer, an audience, and a required ACR. The issuer hostname must exactly match one of the deployment's `IDENTITY_ALLOWED_HOSTS`; discovery and JWKS egress is HTTPS on port 443 and rejects non-public resolved addresses. Adapter metadata starts in `verification_required`. `PATCH` accepts `issuer`, `audience`, and/or `required_acr`, requires the current ETag, and clears verification. `disable` also requires the current ETag. These APIs only inventory provider settings; they do not log users in or enforce end-user authorization.

`verify` requires the current ETag and a bounded OIDC ID token in `{"id_token":"..."}`. Verification allows RS256 only and checks the exact issuer and audience, signature, a nonempty nonce, required ACR, and `auth_time` / `iat` within 15 minutes. A valid token marks the adapter active and records `last_verified_at`. Invalid provider proofs return `verified: false` with the generic `PROVIDER_VERIFICATION_FAILED` reason and an audit event. The `IDENTITY_ALLOWED_HOSTS` list is independent from the administrator login `OIDC_ALLOWED_HOSTS` list.

### Policies

- `GET /v1/applications/{application_id}/policies`
- `POST /v1/applications/{application_id}/policies`
- `GET /v1/policies/{policy_id}`
- `POST /v1/policies/{policy_id}/simulate`
- `POST /v1/policies/{policy_id}/activate`
- `POST /v1/policies/{policy_id}/schedule`
- `POST /v1/policies/{policy_id}/rollback`
- `POST /v1/policies/{policy_id}/retire`
- `POST /oauth/token`
- `POST /oauth/introspect`

Policy documents are schema-validated, immutable after creation, and include explicit `mode`, `allowed_profiles`, `fallback`, `stale_behavior`, `route_rules`, `identity_requirements`, `exceptions`, and `effective_window`.

The current simulation registry contains only `tls13-classical` and `tls13-x25519-mlkem768`, tied to the Go 1.27.1 TLS implementation. Both entries are marked `simulation-only`; they are not an independent cryptographic approval or an end-user enforcement claim. `pqc-approved` is rejected because no reviewed pure-PQC profile is configured. A policy document has this shape:

```json
{
  "mode": "classical-approved",
  "allowed_profiles": ["tls13-classical"],
  "fallback": "deny",
  "stale_behavior": "deny",
  "route_rules": [
    {"method": "GET", "path_prefix": "/api/", "allowed_profiles": ["tls13-classical"]}
  ],
  "identity_requirements": {"required_acrs": ["urn:example:mfa"]},
  "exceptions": [],
  "effective_window": {"starts_at": null, "ends_at": null}
}
```

Route rules select the longest matching method/path prefix. An identity context outside `required_acrs` yields `step_up`. A live exception returns `degraded_allowed` and must include an owner, reason, expiry, and compensating control. Simulation accepts one HTTP method, path, profile ID, and ACR and returns a decision plus reason codes. Simulation remains informational. The configured TLS-terminating gateway evaluates the active policy for each forwarded request; it derives the transport profile from the live TLS connection and verifies a bearer OIDC ID token using the application's active, recently verified adapter. The route's host-to-tenant/application/upstream mapping comes from an operator-owned route file, not request fields. It preserves the ID token for the application to perform its own business authorization. It audits every evaluated decision and fails closed on identity, policy, audit, or database failure. The gateway forwards `allow`, `observe`, and explicit `degraded_allowed` decisions; `deny` returns 403 and `step_up` returns 401. A built-in profile remains `simulation-only` for a tenant until its current registry-version snapshot has a complete design record and a distinct tenant security engineer approves it. Missing or stale approval returns retryable `503 PROFILE_NOT_APPROVED` for non-observe policies; approval never changes the canonical registry definition. Lifecycle actions require the policy's current `ETag` in `If-Match`. Scheduling is applied by the service's database-backed worker. Rollback creates a new active revision from a prior retired revision; historical document content is never edited.

### Keys and provider metadata

- `GET /v1/applications/{application_id}/keys`
- `POST /v1/applications/{application_id}/keys/rotate`
- `POST /v1/keys/{key_id}/activate`
- `POST /v1/keys/{key_id}/disable`
- `POST /v1/keys/{key_id}/revoke`
- `GET /v1/keys/{key_id}/public-material`

The API exposes key references, public material, status, and lifecycle metadata. It does not expose private key bytes through ordinary API calls.

The implemented key API is reference-only. `POST /v1/applications/{application_id}/keys/rotate` records a next-version reference in `provisioning`; it accepts only the enumerated external-provider labels and never accepts key bytes. Those labels are metadata, not implemented provider integrations. `POST /v1/keys/{key_id}/activate` requires the current ETag and `provider_resource_confirmed: true`, which is an administrator assertion and not a provider check. Activation marks an earlier active version of the same purpose `rotation_due`. Disable and revoke are ETag-guarded and audited lifecycle metadata actions. These routes do not call KMS/HSM APIs or generate keys. `GET .../public-material` returns bytes only when an out-of-band provider process has populated the public-material column; the reference API itself cannot populate it.

The internal provider boundary is not a public API and is not wired to the general key-reference routes. It accepts opaque references with trusted tenant/application/environment scope, performs capability and result validation, and requires per-operation actor/correlation audit context. Webhook signing uses a server-generated reference mapped to a scoped Transit path, with QuantumGate metadata stored in the dedicated, forced-RLS `webhook_signing_keys` table; this avoids exposing provider references through the general key-reference listing API. Runtime provider audit events use the append-only `audit_events` table and store only a reference hash and operation metadata. These integrations are covered by PostgreSQL-gated tests; they remain `NOT VALIDATED` where the configured test database is unavailable. Vault key operations themselves have only fake-HTTP contract coverage until a real Vault service is exercised. No public route can supply a Vault path, call Vault directly, or request private material.

### Posture, audit, and exports

- `GET /v1/applications/{application_id}/posture`
- `GET /v1/applications/{application_id}/observations`
- `POST /v1/applications/{application_id}/observations`
- `GET /v1/tenants/{tenant_id}/audit-events`
- `POST /v1/tenants/{tenant_id}/exports`
- `GET /v1/exports/{export_id}`
- `GET /v1/exports/{export_id}/download`

The implemented export subset covers audit events. `POST /v1/tenants/{tenant_id}/exports` accepts `{"from":"<RFC3339>","to":"<RFC3339>"}` and requires the matching `X-QG-Tenant-ID`, an `Idempotency-Key`, and one of `tenant_admin`, `security_engineer`, or `auditor`. The half-open range `[from, to)` must end no later than the server's current time and span no more than 90 days. A successful request returns `201` with an export ID, `status: "ready"`, request/expiry timestamps, row count, and request ID; `Location` points to the status resource. Export generation is synchronous and snapshots at most 5,000 events (7 MiB JSON). Larger ranges return `422 EXPORT_TOO_LARGE`; narrow the range and retry.

The JSON download contains schema version, tenant ID, creation request ID, the requested range, generation time, and audit events in ascending time order. Events include ID, timestamp, pseudonymous actor, action, target type/ID, outcome, correlation ID, and reason code. It deliberately omits `source_context` and all other fields. The export-creation audit event is inserted after the snapshot and therefore is not in that export; subsequent exports may include it. Payloads are encrypted with AES-256-GCM under a purpose-separated key derived from `RATE_LIMIT_HMAC_KEY`, with tenant and export ID as authenticated context. Keep that key stable until all exports have expired. Exports expire after 24 hours, and a restricted security-definer database function deletes expired payloads in bounded tenant-scoped batches during later export creation; the runtime role cannot directly update or delete export rows. Metadata reads and downloads are also audited. Creation is limited to 5 exports per principal per minute and 20 per tenant per minute; status reads and downloads have separate principal limits. All routes are tenant-scoped under row-level security, return not-found for another tenant's or expired export, and use `Cache-Control: no-store`.

The implemented posture read returns an inventory-only snapshot with active policy integrity, active exceptions, adapter/key/credential counts, observation totals, blocker counts, reason codes, and next actions. `assessment_status` is always `inventory_only`; it does not claim that a policy protects application traffic. Observation listing is paginated and returns source/protocol/profile/blocker/confidence metadata while omitting raw `evidence`.

Observation ingestion requires an OAuth access token whose requested scope includes `observations:write`; the token's application must match the path application. `POST /v1/applications/{application_id}/observations` requires the standard `Idempotency-Key` header and accepts `source`, `protocol`, a registered `algorithm_profile`, `confidence`, an optional bounded `blocker`, an optional `observed_at` timestamp (defaulting to server time), and an optional evidence object limited to `key_exchange`, `signature_scheme`, and `endpoint_role`. Timestamps more than five minutes in the future or 90 days old are rejected. The service stores no arbitrary evidence fields and the read API omits evidence values. Successful retries replay the encrypted response for 24 hours. Ingestion is rate-limited by client IP and application. It records migration telemetry only; it does not evaluate or enforce security policy.

## 5. Data-plane contract

The decision response is provider/profile-specific and includes:

```json
{
  "request_id": "req_01...",
  "tenant_id": "ten_01...",
  "application_id": "app_01...",
  "method": "GET",
  "path": "/api/items",
  "profile_id": "tls13-x25519-mlkem768",
  "profile_registry_version": 1,
  "profile_hash": "<64 lowercase hexadecimal characters>",
  "policy_revision_id": "polrev_01...",
  "mode": "hybrid-approved",
  "decision": "allow",
  "reason_codes": ["PROFILE_MATCH", "KEY_ACTIVE"],
  "expires_at": "2026-09-26T16:00:00Z"
}
```

The standalone route returns HTTP `200` for all valid policy outcomes, including `deny`, `step_up`, and explicit `observe` or `degraded_allowed`; consumers must act on the returned decision and must not treat a transport success as an allow. `request_id` also appears in the `X-Request-ID` response header and correlates the decision audit. `profile_id` is the server-derived TLS profile; `profile_registry_version` and `profile_hash` identify the canonical registry entry checked by the service. `expires_at` is present when the active policy has a future effective-window end. Errors use problem details: malformed input `400`, invalid app token `401`, missing scope `403`, app-path mismatch `404`, request limits `429`, and dependency, identity-adapter, active-policy, or unapproved/stale-profile failures `503`. An unapproved profile returns retryable `503 PROFILE_NOT_APPROVED`; it never falls back to observe-only.

The inline gateway decision is not returned as this JSON object; the gateway proxies the application response after evaluation. The control plane listens on `LISTEN_ADDR`; the optional gateway uses a separate `GATEWAY_LISTEN_ADDR` and cannot serve control-plane routes. Each configured gateway route binds hostname, tenant UUID, application UUID, and upstream URL in an operator-managed file. Every route hostname must be covered by the loaded TLS certificate. The gateway requires exact Host/SNI agreement, TLS 1.3, and a recognized negotiated group. It maps X25519+ML-KEM-768 to `tls13-x25519-mlkem768` and X25519/P-256/P-384/P-521 to `tls13-classical`; every other group is rejected. Upstream production URLs must use HTTPS on port 443 and an exact configured hostname. It overwrites forwarding and `X-QG-*` request headers and removes `X-QG-*` response headers. Deployments must prevent clients from bypassing the gateway to reach the upstream application and must isolate the public gateway and control-plane listener according to their caller classes. The listeners share a process and are not process-isolated.

## 6. SDK contract

The SDK should expose a small typed surface similar to:

```text
QuantumGate.configure({ applicationCredential, endpoint, timeout, mode })
QuantumGate.protect(requestContext) -> Decision
QuantumGate.observe(observation) -> Accepted
QuantumGate.health() -> Health
```

Names are illustrative, not a protocol specification. The implementation must preserve the following behavior:

The current Go package is a partial client in `sdk/go/quantumgate`. It provides `Observe`, `Health`, and `Protect`; bounds request and response sizes; uses TLS 1.3; caches short-lived scope-specific application tokens; avoids credential-bearing redirects; and supports stable caller idempotency keys for telemetry writes.

The current Go client also provides `Protect(ctx, DecisionRequest) (Decision, error)`. Configure `TenantID`, `ApplicationID`, the scoped application credential, and an HTTPS endpoint. `Protect` sends the existing identity token and action method/path, obtains a five-minute `decisions:evaluate` token, and requests a fresh decision without automatic retries or decision caching. It verifies the returned tenant, application, action context, server request ID/header correlation, TLS profile, registry version/hash shape, policy revision, mode, outcome, reason codes, and optional expiry. Any malformed/mismatched response, timeout, TLS profile mismatch, or API failure returns an error; each valid outcome is returned as a `Decision` for the application to enforce. The SDK does not evaluate policy locally. Plain HTTP loopback may still be used for telemetry development, but `Protect` requires HTTPS so the server can bind the profile to an authenticated TLS connection.

- no network call without bounded timeout;
- no secret in exception text;
- retry only safe/idempotent operations;
- explicit decision for `allow`, `deny`, `step_up`, `observe`, and `degraded_allowed`;
- structured reason code and correlation ID;
- configurable fail-safe behavior only from server policy;
- no hidden global credentials or mutable cross-tenant state.

## 7. Webhooks/events

The current outbound implementation emits `policy.activated`, `policy.rollback`, `key.rotation_due`, `key.revoked`, `adapter.failure`, and `posture.blocker_found`. `provider.degraded` and `security.alert` remain available event names for a future source/alert subsystem; they are not emitted by this release.

Webhook requirements:

- `GET|POST /v1/applications/{application_id}/webhooks` lists or creates up to 20 destinations. Creation requires `tenant_admin` or `security_engineer`, an `Idempotency-Key`, HTTPS URL, and one or more supported event types. The endpoint hostname must exactly match `WEBHOOK_ALLOWED_HOSTS`.
- `PATCH /v1/webhooks/{webhook_id}` updates the URL, subscriptions, or enabled state. It requires `tenant_admin` or `security_engineer` and the current ETag in `If-Match`. Disabling cancels pending/retry deliveries; an already in-flight HTTP request may finish.
- `POST /v1/webhooks/{webhook_id}/rotate-key` rotates the destination signing key and requires the current ETag. Previously published public keys remain available for verification.
- `GET /v1/webhooks/{webhook_id}/deliveries` returns delivery state to tenant administrators, security engineers, and auditors. It omits endpoint URLs and provider references.
- `POST /v1/webhook-deliveries/{delivery_id}/retry` manually requeues an enabled dead-lettered delivery for tenant administrators or security engineers. It preserves the event ID and is limited to five manual retry cycles.
- `GET /.well-known/qg-webhook-keys/{key_id}` returns only public Ed25519 verification material, its stable QuantumGate key ID, and lifecycle timestamps. It does not expose provider references.

The version 1 envelope contains schema version, event ID, event type, tenant/application IDs, `occurred_at`, per-attempt `sent_at`, attempt, correlation ID, destination ID, key ID, algorithm, resource type/ID, and a fixed reason code. The event ID is the UUID of the correlated source audit row and is preserved across HTTP retries and manual replay. Payloads never copy audit source context, identity tokens, credentials, endpoint URLs, private keys, or arbitrary request fields.

The sender serializes the fixed envelope once for each attempt and signs the exact raw JSON bytes prefixed with `QuantumGate-Webhook-Event-v1` and a NUL byte. `X-QG-Signature` is `ed25519=` plus standard Base64 of the RFC 8032 Ed25519 signature. The body identifies the algorithm and key ID. Receivers must verify the signature against the raw received body without reserializing it. The only currently available algorithm is classical Ed25519; this is not a post-quantum signature.

Receivers should accept `sent_at` only within a five-minute clock window and deduplicate by `(tenant_id, event_id)`. A legitimate retry keeps the event ID but has a new authenticated `attempt` and `sent_at`; after an event has been accepted, a duplicate event ID should be acknowledged without applying its effect twice. Sender retries alone do not prevent replay.

PostgreSQL stores the immutable event and delivery rows in the source audit transaction. A worker claims up to five rows with `FOR UPDATE SKIP LOCKED` leases, commits the claim, and then performs the provider signing and HTTP request. Delivery is **at least once**, not exactly once: a crash after the receiver accepts a request but before the database records success can produce a duplicate. HTTP `2xx` succeeds; network/DNS/timeouts, `408`, `425`, `429`, and `5xx` retry. TLS verification failures, redirects, other `4xx`, invalid destinations, and unusable signing keys are permanent failures. Automatic attempts are capped at eight with exponential delay starting at five seconds and capped at 15 minutes. Permanent errors and exhausted attempts enter `dead`; operators can inspect safe status/error metadata and manually retry the same event.

Destinations require HTTPS on port 443. The sender rejects userinfo, queries, fragments, redirects, unlisted hosts, local/private/link-local/reserved DNS answers, and any non-public address; it pins each request to the validated DNS answers, disables proxy use, and retains normal TLS certificate verification. Private destinations are unsupported. Key generation and signing use the configured key-provider broker; there is no production fallback to `memory-development`. Current signing is Ed25519 only.

## 8. Pagination, filtering, and limits

List endpoints use opaque cursor pagination. Server-side maximum page sizes, filter allow-lists, query timeouts, export thresholds, and sort fields are mandatory. Search must not permit arbitrary database expressions or tenant-bypassing filters.

## 9. Rate limits

Limits are tenant, principal, IP/network, operation, and provider aware. At minimum protect login/verification, policy simulation, key operations, exports, event ingest, and credential rotation. Return `429` with a safe `Retry-After` where appropriate. Limits and limit changes are observable and auditable.

## 10. Deprecation

Deprecations provide notice, replacement guidance, telemetry, and a migration deadline. Security deprecations may be accelerated when required; affected tenants receive a clear action and safe fallback/deny behavior.

## 11. Implemented control-plane subset

The current executable service implements only:

- `GET /v1/tenants/{tenant_id}`
- `PATCH /v1/tenants/{tenant_id}`
- `GET /v1/tenants/{tenant_id}/members`
- `POST /v1/tenants/{tenant_id}/members`
- `DELETE /v1/tenants/{tenant_id}/members/{member_id}`
- `GET /v1/tenants/{tenant_id}/algorithm-profiles`
- `POST /v1/tenants/{tenant_id}/algorithm-profiles/{profile_id}/reviews`
- `GET /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/approve`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/reject`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/disable`
- `POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/deprecate`
- `GET /v1/tenants/{tenant_id}/audit-events`
- `POST /v1/tenants/{tenant_id}/environments`
- `GET /v1/tenants/{tenant_id}/applications`
- `POST /v1/tenants/{tenant_id}/applications`
- `PATCH /v1/applications/{application_id}`
- `GET /v1/applications/{application_id}/policies`
- `POST /v1/applications/{application_id}/policies`
- `GET /v1/applications/{application_id}`
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
- `GET /v1/applications/{application_id}/posture`
- `GET /v1/applications/{application_id}/observations`
- `POST /v1/applications/{application_id}/observations`
- `POST /v1/applications/{application_id}/disable`
- `GET /v1/policies/{policy_id}`
- `POST /v1/policies/{policy_id}/simulate`
- `POST /v1/policies/{policy_id}/activate`
- `POST /v1/policies/{policy_id}/schedule`
- `POST /v1/policies/{policy_id}/rollback`
- `POST /v1/policies/{policy_id}/retire`

The implemented list routes accept `limit` from 1 through 100 and an opaque `cursor`. JSON writes are limited to 64 KiB, reject unknown fields and duplicate JSON documents, and require `Content-Type: application/json`. Tenant display-name updates, application metadata updates and disable, policy lifecycle actions, key-reference lifecycle actions, and webhook destination changes require an `If-Match` ETag. Application `PATCH` accepts `display_name` and/or `integration_mode`; immutable identifiers and environment ownership cannot be changed through this route. Credential rotation accepts an expiry from five minutes through one year and one or more of `decisions:evaluate`, `observations:write`, `posture:read`, and `events:write`; it revokes the application's existing credentials, returns the new secret once, and audits the rotation. The OAuth client-credentials grant accepts only registered scopes, stores token hashes, limits tokens to five minutes, and makes them unusable after credential revocation. Observation ingestion consumes `observations:write`, posture reads accept `posture:read`, and standalone SDK decisions consume `decisions:evaluate`; the inline gateway path remains an operator-configured route and does not consume that service-token scope. Outbound webhook delivery implements the event subset and delivery contract in section 7. Posture reads return an inventory-only snapshot and explicit incompleteness reason codes; observations return blocker metadata while redacting evidence. Key-reference APIs only record external references and operator-confirmed state; there are no KMS/HSM connectors and no API accepts private key material. Policy document validation is bounded and limited to the two transport profiles listed above; it is not an algorithm registry definition API. Policy simulation is informational; configured gateway routes separately evaluate active policies inline. The gateway requires a live TLS 1.3 connection, exact Host/SNI agreement, a recognized group, an operator-owned route mapping, an active gateway-mode application, and a recently verified OIDC adapter. It removes client-supplied forwarding and `X-QG-*` headers and audits decisions before forwarding. A profile is enforcement-eligible only for a tenant with a current, independently reviewed profile snapshot whose hash matches the canonical registry version. Missing, stale, rejected, disabled, or deprecated profile reviews cause retryable `503 PROFILE_NOT_APPROVED`; the observe-only mode is not enforcement. No tenant profile review is approved by default. Gateway and SDK ID tokens are audience-bound and limited to 15 minutes but use bearer semantics and can be replayed while valid; neither integration consumes a one-time `jti`. Database-backed fixed-window limits return `429` and `Retry-After` for login by socket IP, control-plane traffic by socket IP, principal, and tenant, and service-token reads/writes by socket IP and application. Decision evaluation also uses tenant, application, and IP buckets. Limits use keyed hashes; bounded cleanup removes up to 10,000 windows older than 24 hours every five minutes per server instance. Provider-specific and configurable route policies remain outstanding. The complete endpoint inventory above remains the product target, not evidence that unlisted routes are implemented. Non-read API writes use idempotency keys except decision evaluation, which intentionally re-evaluates each call to avoid stale response replay.
