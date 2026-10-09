# Existing application behind the QuantumGate gateway

This small Go server is a local reference upstream for an existing application. It keeps application-side OIDC validation in place, listens only on a loopback address, and serves a sample authenticated `GET /api/items` route. It uses the repository's existing maintained OIDC verifier; it does not create or issue identity tokens.

The browser or API client obtains an ID token through the application's existing OIDC login and sends it as `Authorization: Bearer ...` to the gateway. The gateway checks the token and active policy, then forwards the same token to the application. The application verifies it again and remains responsible for its own resource authorization. The sample allows every authenticated user to read the static item list; replace that sample rule with the existing application's authorization logic.

## Run the upstream

Configure the same issuer and audience used by the registered QuantumGate OIDC identity adapter. `APP_OIDC_ALLOWED_HOSTS` is a comma-separated exact hostname allowlist for the provider discovery and JWKS endpoints.

```powershell
$env:APP_OIDC_ISSUER = 'https://login.customer.example'
$env:APP_OIDC_AUDIENCE = 'customer-app'
$env:APP_OIDC_ALLOWED_HOSTS = 'login.customer.example,keys.customer.example'
go run ./examples/gateway-upstream
```

The app listens on `127.0.0.1:8081` by default. `APP_LISTEN_ADDR` can change the loopback IP and port; non-loopback addresses are rejected so this development upstream cannot be reached around the gateway from another host.

## Configure the QuantumGate route

Use [routes.example.json](routes.example.json) as the operator-owned host-to-tenant/application/upstream mapping. Replace the tenant and application UUIDs with the registered tenant and active application UUID. Register the application with `integration_mode` set to `gateway`, configure and verify its OIDC adapter, and activate an `observe-only` policy for its route.

For a local development deployment, configure QuantumGate with:

```powershell
$env:GATEWAY_ROUTES_FILE = 'examples/gateway-upstream/routes.example.json'
$env:GATEWAY_LISTEN_ADDR = '127.0.0.1:8444'
```

The mounted gateway TLS certificate must include `app.customer.example` in its SANs. Configure `IDENTITY_ALLOWED_HOSTS` for the adapter's provider hosts. Local loopback HTTP upstreams are allowed only in development. Production upstreams must use HTTPS on port 443 and an exact `GATEWAY_UPSTREAM_ALLOWED_HOSTS` entry, with network controls that prevent clients from bypassing QuantumGate.

Send an ID token from the application's existing login flow to `https://app.customer.example:8444/api/items`, resolving that hostname to the local gateway and trusting the certificate's issuing CA:

```powershell
$env:APP_ID_TOKEN = '<ID token from the existing login>'
curl.exe --resolve app.customer.example:8444:127.0.0.1 --cacert .\local-ca.pem -H "Authorization: Bearer $env:APP_ID_TOKEN" https://app.customer.example:8444/api/items
```

The gateway derives the transport profile from the live TLS connection, audits the observe decision, and proxies the application response. The profile registry is still `simulation-only`; this example does not demonstrate active enforcement or production authorization readiness.
