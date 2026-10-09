# QuantumGate Go client

The client provides health checks, observation ingestion, and server-authoritative `Protect` decisions. Protect is additive to application authentication: verify the user's existing identity as usual, pass that same identity token to QuantumGate, and perform the protected action only when the returned server decision permits it.

```go
client, err := quantumgate.NewClient(quantumgate.Config{
	Endpoint:      "https://quantumgate.example",
	TenantID:      tenantID,
	ApplicationID: applicationID,
	ClientSecret:  applicationSecret,
})
if err != nil {
	return err
}

decision, err := client.Protect(ctx, quantumgate.DecisionRequest{
	Method:        request.Method,
	Path:          request.URL.Path,
	IdentityToken: existingIDToken,
})
if err != nil {
	// Fail closed: do not perform the protected action.
	return err
}
switch decision.Decision {
case "allow", "observe", "degraded_allowed":
	return performProtectedAction()
case "step_up":
	return handleAdditionalAuthentication()
default: // Includes "deny" and any unexpected outcome.
	return denyProtectedAction()
}
```

`Protect` obtains a short-lived `decisions:evaluate` token and makes a fresh `/v1/applications/{application_id}/decisions` request. The service derives tenant/application from that credential, validates the existing identity token with the configured OIDC adapter, derives the transport profile from the live TLS 1.3 connection, evaluates current policy and profile approval, and audits each decision with the response `RequestID`. The SDK checks the response bindings and returns all valid server outcomes; it does not evaluate policy, cache decisions, or retry a decision request. An unapproved/stale profile, invalid identity, API outage, timeout, or malformed/mismatched response returns an error and must block the action.

`Protect` requires `TenantID` and an HTTPS endpoint. Its configured HTTP transport enforces TLS 1.3 and does not follow redirects. The application remains responsible for its own business authorization and for applying the returned decision to the same action context; SDK mode cannot protect a fully compromised application host.

Observation ingestion continues to request an `observations:write` token, caches that token until 15 seconds before expiry, and creates a random idempotency key per `Observe` call. Set `Observation.IdempotencyKey` to a stable caller-generated key when retrying the same observation after an uncertain network result. HTTP loopback endpoints remain available for telemetry-only development; `Protect` rejects plaintext HTTP.

See [the SDK reference application](../../../examples/sdk-protect/README.md) for a small existing-application integration.
