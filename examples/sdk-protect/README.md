# Existing application with SDK `Protect`

This loopback-only Go example preserves the application's existing OIDC login and resource authorization. It verifies the existing user's bearer ID token, asks QuantumGate for a fresh decision for `GET /api/items`, and serves the sample action only for the returned outcomes configured by server policy (`allow`, `observe`, or `degraded_allowed`). A denial returns `403`, `step_up` returns `401`, and an API error—including an unapproved or stale profile—returns `503` without executing the action.

The application credential must be scoped to `decisions:evaluate`. QuantumGate derives tenant/application from that credential and the TLS profile from the live HTTPS connection. The existing identity token is sent separately in the decision body and validated again by the current, recently verified OIDC adapter registered for the application. The example never logs the token or decision payload.

## Configure and run

Register the application with `integration_mode` set to `sdk`, configure and verify its OIDC identity adapter, create an active policy, and approve the policy's current transport profile through an independent tenant review before using a non-observe mode. Obtain a rotated application credential with the `decisions:evaluate` scope and configure the existing OIDC issuer/audience used by the application.

```powershell
$env:APP_OIDC_ISSUER = 'https://login.customer.example'
$env:APP_OIDC_AUDIENCE = 'customer-app'
$env:APP_OIDC_ALLOWED_HOSTS = 'login.customer.example,keys.customer.example'
$env:QG_API_ENDPOINT = 'https://quantumgate.customer.example'
$env:QG_TENANT_ID = '<registered tenant UUID>'
$env:QG_APPLICATION_ID = '<registered application UUID>'
$env:QG_CLIENT_SECRET = '<rotated application credential>'
go run ./examples/sdk-protect
```

The example listens on `127.0.0.1:8082` by default; `APP_LISTEN_ADDR` may select another loopback IP and port. The QuantumGate endpoint must be HTTPS and trusted by the Go system certificate pool. A caller should obtain its ID token through the application's existing login flow, then call:

```powershell
$env:APP_ID_TOKEN = '<ID token from the existing login>'
curl.exe -H "Authorization: Bearer $env:APP_ID_TOKEN" http://127.0.0.1:8082/api/items
```

Invalid tenant/application configuration fails at startup. Every `Protect` call is a fresh evaluation with a new server request ID and audit record; the SDK does not retry or reuse a prior decision. Transport, identity, audit, policy, or profile-review failures block the sample action.

## Limitations

This is a development integration, not a production deployment recipe. The customer application must continue to perform its own business authorization and bind the returned decision to the same authenticated action; a compromised SDK host can ignore the decision. Existing OIDC ID tokens retain bearer-token replay semantics while valid. The example's sample route allows every identity accepted by the verifier and must be replaced with the application's existing authorization logic.
