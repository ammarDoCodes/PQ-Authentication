package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"quantumgate/internal/auth"
	"quantumgate/internal/gateway"
)

const (
	gatewayIdentityFreshness  = 24 * time.Hour
	gatewayIdentityFutureSkew = 30 * time.Second
	gatewayVerifierLifetime   = 10 * time.Minute
	maxGatewayVerifiers       = 1000
)

type identityVerifierEntry struct {
	issuer      string
	audience    string
	requiredACR string
	updatedAt   time.Time
	expiresAt   time.Time
	verifier    auth.TokenVerifier
}

type gatewayIdentityAdapter struct {
	ID             string
	Issuer         string
	Audience       string
	RequiredACR    string
	UpdatedAt      time.Time
	LastVerifiedAt time.Time
}

func (s *Server) Evaluate(ctx context.Context, route gateway.Route, request gateway.Request) (gateway.Decision, error) {
	return s.evaluate(ctx, route, request, "gateway", "tls-terminating-gateway")
}

func (s *Server) EvaluateSDK(ctx context.Context, route gateway.Route, request gateway.Request) (gateway.Decision, error) {
	return s.evaluate(ctx, route, request, "sdk", "sdk")
}

func (s *Server) evaluate(ctx context.Context, route gateway.Route, request gateway.Request, integrationMode, integrationName string) (gateway.Decision, error) {
	if s.Store == nil || len(s.RateLimitKey) != sha256.Size {
		return gateway.Decision{}, gatewayFailure(503, "DATA_PLANE_UNAVAILABLE", 0)
	}
	if !validUUID(route.TenantID) || !validUUID(route.ApplicationID) || !oneOf(request.ProfileID, "tls13-classical", "tls13-x25519-mlkem768") ||
		!validPolicyMethod(request.Method) || !validPolicyPath(request.Path) {
		return gateway.Decision{}, gatewayFailure(403, "DECISION_CONTEXT_REJECTED", 0)
	}
	for _, limit := range []struct {
		scope, dimension string
		maximum          int
	}{
		{scope: "decision:tenant", dimension: route.TenantID, maximum: 600},
		{scope: "decision:application", dimension: route.ApplicationID, maximum: 1200},
		{scope: "decision:ip", dimension: request.ClientIP, maximum: 300},
	} {
		limitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		allowed, retryAfter, err := s.checkRateLimit(limitCtx, limit.scope, limit.dimension, limit.maximum)
		cancel()
		if err != nil {
			return gateway.Decision{}, gatewayFailure(503, "RATE_LIMIT_UNAVAILABLE", 0)
		}
		if !allowed {
			return gateway.Decision{}, gatewayFailure(429, "RATE_LIMITED", retryAfter)
		}
	}

	adapter, err := s.loadGatewayIdentityAdapterFor(ctx, route, integrationMode)
	if err != nil {
		reason := "IDENTITY_ADAPTER_UNAVAILABLE"
		if errors.Is(err, sql.ErrNoRows) {
		} else {
			var failure *gateway.Failure
			if errors.As(err, &failure) {
				reason = failure.Code
			}
		}
		if auditErr := s.recordDecisionFailure(ctx, route, request, integrationName, reason); auditErr != nil {
			return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
		}
		return gateway.Decision{}, gatewayFailure(503, reason, 0)
	}
	verifier, err := s.gatewayIdentityVerifier(ctx, adapter)
	if err != nil {
		if auditErr := s.recordDecisionFailure(ctx, route, request, integrationName, "IDENTITY_PROVIDER_UNAVAILABLE"); auditErr != nil {
			return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
		}
		return gateway.Decision{}, gatewayFailure(503, "IDENTITY_PROVIDER_UNAVAILABLE", 0)
	}
	principal, err := verifier.Verify(ctx, request.IdentityToken)
	if err != nil {
		if auditErr := s.recordDecisionFailure(ctx, route, request, integrationName, "IDENTITY_INVALID"); auditErr != nil {
			return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
		}
		return gateway.Decision{}, gatewayFailure(401, "IDENTITY_INVALID", 0)
	}

	tx, err := s.beginGatewayTenantTx(ctx, route.TenantID)
	if err != nil {
		return gateway.Decision{}, gatewayFailure(503, "DATA_PLANE_UNAVAILABLE", 0)
	}
	defer tx.Rollback()
	currentAdapter, err := scanGatewayIdentityAdapter(tx.QueryRowContext(ctx, `SELECT id::text, issuer, audience, config::text,
		updated_at, last_verified_at FROM public.identity_adapters
		WHERE tenant_id = $1 AND application_id = $2 AND id = $3 AND adapter_type = 'oidc' AND status = 'active'
			AND last_verified_at >= clock_timestamp() - interval '24 hours'
			AND last_verified_at <= clock_timestamp() + interval '30 seconds'
		FOR SHARE`, route.TenantID, route.ApplicationID, adapter.ID))
	if err != nil || currentAdapter.UpdatedAt != adapter.UpdatedAt || currentAdapter.Issuer != adapter.Issuer || currentAdapter.Audience != adapter.Audience ||
		currentAdapter.RequiredACR != adapter.RequiredACR {
		if auditErr := s.recordDecisionFailure(ctx, route, request, integrationName, "IDENTITY_CONFIGURATION_CHANGED"); auditErr != nil {
			return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
		}
		return gateway.Decision{}, gatewayFailure(503, "IDENTITY_CONFIGURATION_CHANGED", 0)
	}
	if !s.lockIntegrationApplication(ctx, tx, route, integrationMode) {
		if err := s.recordDecisionEvent(ctx, tx, route, request, integrationName, "application:"+route.ApplicationID, gateway.Decision{}, "failure", "APPLICATION_UNAVAILABLE"); err != nil {
			return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
		}
		if err := tx.Commit(); err != nil {
			return gateway.Decision{}, gatewayFailure(503, "DATA_PLANE_UNAVAILABLE", 0)
		}
		return gateway.Decision{}, gatewayFailure(503, "APPLICATION_UNAVAILABLE", 0)
	}
	policy, err := scanPolicy(tx.QueryRowContext(ctx, `SELECT `+policySelectColumns+`
		FROM public.policy_revisions WHERE tenant_id = $1 AND application_id = $2 AND state = 'active' FOR SHARE`,
		route.TenantID, route.ApplicationID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			failureDecision := gateway.Decision{Outcome: "deny", ReasonCodes: []string{"ACTIVE_POLICY_UNAVAILABLE"}}
			if auditErr := s.recordDecisionEvent(ctx, tx, route, request, integrationName, "application:"+route.ApplicationID, failureDecision, "failure", "ACTIVE_POLICY_UNAVAILABLE"); auditErr != nil {
				return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return gateway.Decision{}, gatewayFailure(503, "DATA_PLANE_UNAVAILABLE", 0)
			}
		}
		return gateway.Decision{}, gatewayFailure(503, "ACTIVE_POLICY_UNAVAILABLE", 0)
	}
	if policy.Document.Mode != "observe-only" {
		approved, err := profileApproved(ctx, tx, route.TenantID, request.ProfileID)
		if err != nil {
			return gateway.Decision{}, gatewayFailure(503, "PROFILE_STATE_UNAVAILABLE", 0)
		}
		if !approved {
			failureDecision := gateway.Decision{Outcome: "deny", Mode: policy.Document.Mode, PolicyRevisionID: policy.ID, ReasonCodes: []string{"PROFILE_NOT_APPROVED"}}
			if err := s.recordDecisionEvent(ctx, tx, route, request, integrationName, auditActor(tenantPrincipal{Issuer: principal.Issuer, Subject: principal.Subject}), failureDecision, "failure", "PROFILE_NOT_APPROVED"); err != nil {
				return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
			}
			if err := tx.Commit(); err != nil {
				return gateway.Decision{}, gatewayFailure(503, "DATA_PLANE_UNAVAILABLE", 0)
			}
			return gateway.Decision{}, gatewayFailure(503, "PROFILE_NOT_APPROVED", 0)
		}
	}
	now := time.Now().UTC()
	decision, reasons := evaluatePolicy(policy.Document, request.Method, request.Path, request.ProfileID, principal.ACR, now)
	if policy.Document.Mode != "observe-only" && len(policy.Document.IdentityRequirements.RequiredACRs) == 0 && principal.ACR != adapter.RequiredACR {
		decision, reasons = "step_up", []string{"IDENTITY_STEP_UP_REQUIRED"}
	}
	expiresAt := policy.Document.EffectiveWindow.EndsAt
	if expiresAt != nil {
		if value := expiresAt.UTC(); value.After(now) {
			expiresAt = &value
		} else {
			expiresAt = nil
		}
	}
	result := gateway.Decision{
		Outcome: decision, Mode: policy.Document.Mode, PolicyRevisionID: policy.ID,
		ReasonCodes: reasons, ExpiresAt: expiresAt,
	}
	auditOutcome := "success"
	if decision == "deny" || decision == "step_up" {
		auditOutcome = "denied"
	}
	if err := s.recordDecisionEvent(ctx, tx, route, request, integrationName, auditActor(tenantPrincipal{Issuer: principal.Issuer, Subject: principal.Subject}), result, auditOutcome, firstReason(reasons)); err != nil {
		return gateway.Decision{}, gatewayFailure(503, "AUDIT_UNAVAILABLE", 0)
	}
	if err := tx.Commit(); err != nil {
		return gateway.Decision{}, gatewayFailure(503, "DATA_PLANE_UNAVAILABLE", 0)
	}
	return result, nil
}

func (s *Server) loadGatewayIdentityAdapter(ctx context.Context, route gateway.Route) (gatewayIdentityAdapter, error) {
	return s.loadGatewayIdentityAdapterFor(ctx, route, "gateway")
}

func (s *Server) loadGatewayIdentityAdapterFor(ctx context.Context, route gateway.Route, integrationMode string) (gatewayIdentityAdapter, error) {
	tx, err := s.beginGatewayTenantTx(ctx, route.TenantID)
	if err != nil {
		return gatewayIdentityAdapter{}, err
	}
	defer tx.Rollback()
	if !s.lockIntegrationApplication(ctx, tx, route, integrationMode) {
		return gatewayIdentityAdapter{}, sql.ErrNoRows
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text, issuer, audience, config::text, updated_at, last_verified_at
		FROM public.identity_adapters WHERE tenant_id = $1 AND application_id = $2 AND adapter_type = 'oidc'
		AND status = 'active' ORDER BY id LIMIT 2`, route.TenantID, route.ApplicationID)
	if err != nil {
		return gatewayIdentityAdapter{}, err
	}
	defer rows.Close()
	var adapter gatewayIdentityAdapter
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			return gatewayIdentityAdapter{}, gatewayFailure(503, "IDENTITY_CONFIGURATION_AMBIGUOUS", 0)
		}
		adapter, err = scanGatewayIdentityAdapter(rows)
		if err != nil {
			return gatewayIdentityAdapter{}, err
		}
	}
	if err := rows.Err(); err != nil {
		return gatewayIdentityAdapter{}, err
	}
	if err := rows.Close(); err != nil {
		return gatewayIdentityAdapter{}, err
	}
	verifiedAge := time.Since(adapter.LastVerifiedAt)
	if count == 0 || adapter.LastVerifiedAt.IsZero() || verifiedAge > gatewayIdentityFreshness || verifiedAge < -gatewayIdentityFutureSkew {
		return gatewayIdentityAdapter{}, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return gatewayIdentityAdapter{}, err
	}
	return adapter, nil
}

func (s *Server) beginGatewayTenantTx(ctx context.Context, tenantID string) (*sql.Tx, error) {
	tx, err := s.Store.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *Server) lockIntegrationApplication(ctx context.Context, tx *sql.Tx, route gateway.Route, expectedMode string) bool {
	var integrationMode string
	err := tx.QueryRowContext(ctx, `SELECT application.integration_mode FROM public.applications AS application
		JOIN public.tenants AS tenant ON tenant.id = application.tenant_id
		WHERE application.tenant_id = $1 AND application.id = $2 AND application.status = 'active'
		AND tenant.status = 'active' AND application.integration_mode = $3
		FOR SHARE OF application, tenant`, route.TenantID, route.ApplicationID, expectedMode).Scan(&integrationMode)
	return err == nil && integrationMode == expectedMode
}

func scanGatewayIdentityAdapter(row interface{ Scan(...any) error }) (gatewayIdentityAdapter, error) {
	var adapter gatewayIdentityAdapter
	var configJSON string
	var lastVerified sql.NullTime
	if err := row.Scan(&adapter.ID, &adapter.Issuer, &adapter.Audience, &configJSON, &adapter.UpdatedAt, &lastVerified); err != nil {
		return gatewayIdentityAdapter{}, err
	}
	var config identityAdapterConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil || !validBoundedToken(config.RequiredACR, 256) {
		return gatewayIdentityAdapter{}, errors.New("stored gateway identity adapter is invalid")
	}
	if !lastVerified.Valid {
		return gatewayIdentityAdapter{}, errors.New("gateway identity adapter has not been verified")
	}
	adapter.RequiredACR = config.RequiredACR
	adapter.UpdatedAt = adapter.UpdatedAt.UTC()
	adapter.LastVerifiedAt = lastVerified.Time.UTC()
	return adapter, nil
}

func (s *Server) gatewayIdentityVerifier(ctx context.Context, adapter gatewayIdentityAdapter) (auth.TokenVerifier, error) {
	now := time.Now()
	s.identityVerifierMu.Lock()
	for id, entry := range s.identityVerifiers {
		if !now.Before(entry.expiresAt) {
			delete(s.identityVerifiers, id)
		}
	}
	if entry, ok := s.identityVerifiers[adapter.ID]; ok && entry.issuer == adapter.Issuer && entry.audience == adapter.Audience &&
		entry.requiredACR == adapter.RequiredACR && entry.updatedAt.Equal(adapter.UpdatedAt) && now.Before(entry.expiresAt) {
		s.identityVerifierMu.Unlock()
		return entry.verifier, nil
	}
	s.identityVerifierMu.Unlock()

	if len(s.IdentityAllowedHosts) == 0 {
		return nil, errors.New("identity provider host policy is not configured")
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	verifier, err := auth.NewOIDCIdentityVerifier(verifyCtx, auth.OIDCSettings{
		Issuer: adapter.Issuer, ClientID: adapter.Audience, AllowedHosts: s.IdentityAllowedHosts,
		SigningAlgs: []string{"RS256"}, MaxTokenAge: 15 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	s.identityVerifierMu.Lock()
	defer s.identityVerifierMu.Unlock()
	if s.identityVerifiers == nil {
		s.identityVerifiers = make(map[string]identityVerifierEntry)
	}
	for id, entry := range s.identityVerifiers {
		if !time.Now().Before(entry.expiresAt) {
			delete(s.identityVerifiers, id)
		}
	}
	if entry, ok := s.identityVerifiers[adapter.ID]; ok && entry.issuer == adapter.Issuer && entry.audience == adapter.Audience &&
		entry.requiredACR == adapter.RequiredACR && entry.updatedAt.Equal(adapter.UpdatedAt) && time.Now().Before(entry.expiresAt) {
		return entry.verifier, nil
	}
	if len(s.identityVerifiers) >= maxGatewayVerifiers {
		return nil, errors.New("gateway identity verifier cache is full")
	}
	s.identityVerifiers[adapter.ID] = identityVerifierEntry{
		issuer: adapter.Issuer, audience: adapter.Audience, requiredACR: adapter.RequiredACR,
		updatedAt: adapter.UpdatedAt, expiresAt: time.Now().Add(gatewayVerifierLifetime), verifier: verifier,
	}
	return verifier, nil
}

func (s *Server) recordDecisionFailure(ctx context.Context, route gateway.Route, request gateway.Request, integrationName, reason string) error {
	tx, err := s.beginGatewayTenantTx(ctx, route.TenantID)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	decision := gateway.Decision{Outcome: "deny", ReasonCodes: []string{reason}}
	if err := s.recordDecisionEvent(ctx, tx, route, request, integrationName, "application:"+route.ApplicationID, decision, "failure", reason); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) recordDecisionEvent(ctx context.Context, tx *sql.Tx, route gateway.Route, request gateway.Request, integrationName, actor string, decision gateway.Decision, outcome, reason string) error {
	if len(reason) == 0 || len(reason) > 128 {
		reason = "DATA_PLANE_DECISION"
	}
	profileHash := ""
	if _, known := policyProfiles[request.ProfileID]; known {
		hash := profileDefinitionHash(request.ProfileID)
		profileHash = hex.EncodeToString(hash[:])
	}
	source, err := json.Marshal(map[string]any{
		"integration": integrationName, "application_id": route.ApplicationID,
		"transport_profile": request.ProfileID, "profile_registry_version": policyRegistryVersion,
		"profile_hash": profileHash, "policy_revision_id": decision.PolicyRevisionID,
		"decision": decision.Outcome,
	})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.audit_events
		(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code, source_context)
		VALUES ($1, 1, $2, 'authorization.decision', 'application', $3, $4, $5, $6, $7::jsonb)`,
		route.TenantID, actor, route.ApplicationID, outcome, request.RequestID, reason, source)
	return err
}

func gatewayFailure(status int, code string, retryAfter int) *gateway.Failure {
	return &gateway.Failure{StatusCode: status, Code: code, RetryAfter: retryAfter}
}

func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return "POLICY_DECISION"
	}
	return reasons[0]
}

var _ gateway.Runtime = (*Server)(nil)
