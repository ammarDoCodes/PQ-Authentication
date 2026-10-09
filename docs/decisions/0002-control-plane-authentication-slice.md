# Decision 0002: Administrator OIDC sessions

- Status: implemented authentication slice; production gate remains open
- Date: 2026-09-27
- Scope: the initial `/v1` control-plane API slice

## Context

The API contract requires tenant-scoped administrator authorization through configured OIDC, with server-verified state, nonce, and PKCE and revocable sessions. The implementation must not accept caller-supplied tenant or role claims as authority.

## Implemented behavior

- `GET /auth/login` creates a short-lived transaction with random state, nonce, PKCE S256 verifier, and browser binding. The database stores hashes of state and browser binding; the callback consumes the matching transaction once.
- The maintained `go-oidc` and `oauth2` libraries validate provider metadata and ID tokens. Validation requires the configured issuer, audience, signature algorithm, ACR, recent `auth_time`, token age, and exact transaction nonce. Provider traffic uses restricted HTTPS egress.
- Successful login creates a random opaque server-side session. Only the session and CSRF token hashes are stored. Cookies are Secure, HttpOnly where appropriate, SameSite=Lax, and host-only. Sessions expire after eight hours or 30 minutes idle.
- Cookie-authenticated mutations require a same-origin `Origin` and matching CSRF token. Login and logout are recorded in a separate append-only system authentication audit table.
- The tenant context comes from `X-QG-Tenant-ID`, then is verified against `(issuer, subject)` membership in PostgreSQL. The database role row controls authorization. Each request transaction sets the tenant RLS context and queries tenant-qualified resources.
- The production entry point does not enable ID-token bearer authentication. Caller-provided OIDC tenant or role claims are ignored.

## Limitations and required follow-up

Service-client OAuth credentials are not implemented. The authentication slice has unit coverage for PKCE/CSRF and requires live provider plus PostgreSQL integration for end-to-end validation. The service now has shared database-backed fixed-window login/API limits, but provider-specific limits and independent security review remain release gates.

Before production, add OAuth service-client authentication, end-to-end tests against the configured provider, session-revocation tests, auth-event retention/export, provider-specific rate policies, and independent design/security review. Do not relax the current verification rules while doing so.

## Consequences

The admin API uses a server-owned OIDC authorization-code flow with state, nonce, and PKCE S256, and issues opaque server-side sessions in Secure, HttpOnly, SameSite cookies. Cookie-authenticated mutations require same-origin CSRF validation. Tenant selection is explicit and membership-checked; changing the requested tenant cannot grant access. The production entry point does not accept ID tokens as bearer credentials.
