# Decision 0003: Data-plane profile attestation

- Status: accepted for the configured TLS-terminating gateway; cryptographic profile approval remains an open security gate
- Date: 2026-09-27
- Scope: SDK/gateway decisions for protected application traffic

## Context

The API contract requires the server to determine whether the actual transport profile satisfies policy (`Specs/API.md`, section 5). The agent security rules prohibit accepting an algorithm based only on a client-provided string (`Specs/AGENTS.md`). A service credential authenticates an integration application; it does not prove the user's negotiated TLS profile or that a claimed profile describes the protected connection.

## Decision

The implemented data-plane path is an operator-configured TLS-terminating reverse proxy on a dedicated listener. The gateway listener uses a handler that serves configured routes and never falls through to the control-plane API; it derives the profile from the Go TLS connection state, requires TLS 1.3 and exact Host/SNI agreement, and maps only the recognized X25519+ML-KEM-768 and classical groups. An operator-owned route binds one exact hostname to a tenant, an active `gateway`-mode application, and an allowlisted upstream. The runtime rechecks that mapping against tenant-scoped database state and does not accept tenant, application, profile, or upstream values from request headers. The gateway and control plane still share a process and are not process-isolated.

The gateway validates a bearer OIDC ID token against the active application's verified issuer and audience, preserves the token for the existing application to perform its own business authorization, strips caller-supplied forwarding and `X-QG-*` headers, records a redacted decision audit event, and fails closed when it cannot evaluate safely. The TLS terminator must be the first TLS endpoint for the protected connection; any upstream application must be unreachable directly by untrusted clients.

This gateway boundary is accepted for implementation, but it does not approve either transport profile. Both built-in registry entries remain `simulation-only`; every non-observe policy therefore fails closed with `503 PROFILE_NOT_APPROVED`. The observe-only path deliberately forwards after identity validation while reporting `observe`; it is not enforcement. The Go SDK remains non-enforcing and has no `protect` method or standalone decision endpoint.

The gateway's ID-token contract is bearer-based. It checks a signed, audience-bound token with a nonempty nonce claim and a maximum age of 15 minutes, but it does not initiate an OIDC challenge, compare that nonce with gateway-held transaction state, or consume a token `jti`. A stolen token can therefore be replayed until it expires. This bounded replay exposure is a known limitation; the gateway does not claim one-time token semantics.

## Consequences

- Caller-supplied profile headers never provide transport evidence; only the gateway's live TLS state does.
- `decisions:evaluate` is enforced only inline for configured gateway routes; the standalone SDK/API decision operation remains unavailable.
- The gateway's route file, upstream egress allowlist, certificate, upstream network policy, and identity-provider host allowlist are security-sensitive operator configuration.
- Profile status must not change from `simulation-only` until an independent review approves the exact Go TLS implementation, negotiated groups, deployment behavior, interoperability, and downgrade controls.
- Required follow-up tests include forged-header rejection, Host/SNI mismatch, cross-tenant/application route binding, downgrade attempts, identity-provider and audit outages, and explicit replay behavior.

## Revisit criteria

Revisit the gateway identity contract before claiming replay resistance or production authorization suitability. Revisit profile status only after independent cryptographic and operational review of the precise deployed profile and tests.
