package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"
)

type serviceApplicationContextKey struct{}

type observationEvidence struct {
	KeyExchange     string `json:"key_exchange,omitempty"`
	SignatureScheme string `json:"signature_scheme,omitempty"`
	EndpointRole    string `json:"endpoint_role,omitempty"`
}

func (s *Server) withServiceTokenAuth(next http.Handler) http.Handler {
	return s.withServiceTokenScope("observations:write", next)
}

func (s *Server) withDecisionServiceTokenAuth(next http.Handler) http.Handler {
	return s.withServiceTokenScopePolicy("decisions:evaluate", false, next)
}

func (s *Server) withServiceTokenScope(requiredScope string, next http.Handler) http.Handler {
	return s.withServiceTokenScopePolicy(requiredScope, true, next)
}

func (s *Server) withServiceTokenScopePolicy(requiredScope string, requireIdempotency bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if s.Store == nil || len(s.RateLimitKey) != sha256.Size {
			writeProblem(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Service unavailable", "The data plane is not configured.", true)
			return
		}
		if r.URL.RawQuery != "" {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "Query parameters are not accepted for this service endpoint.", false)
			return
		}
		limitContext, cancelLimit := context.WithTimeout(r.Context(), 2*time.Second)
		allowed, retryAfter, err := s.checkRateLimit(limitContext, "service:"+requiredScope+":ip", clientIPDimension(r.RemoteAddr), 600)
		cancelLimit()
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		if !allowed {
			writeRateLimitProblem(w, r, retryAfter)
			return
		}
		rawToken, ok := bearerToken(r)
		if !ok || !validOpaqueAccessToken(rawToken) {
			writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "A valid application access token is required.", false)
			return
		}
		tokenHash := sha256.Sum256([]byte(rawToken))
		authContext, cancelAuth := context.WithTimeout(r.Context(), 3*time.Second)
		var tenantID, applicationID, credentialID, tokenID string
		var scopes []string
		var expiresAt time.Time
		err = s.Store.QueryRowContext(authContext, `SELECT tenant_id::text, application_id::text, credential_id::text, token_id::text, scopes, expires_at
			FROM public.qg_validate_service_access_token($1::bytea)`, tokenHash[:]).
			Scan(&tenantID, &applicationID, &credentialID, &tokenID, &scopes, &expiresAt)
		cancelAuth()
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "A valid application access token is required.", false)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "AUTHENTICATION_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		pathApplicationID := r.PathValue("application_id")
		if !validUUID(pathApplicationID) || pathApplicationID != applicationID {
			s.notFound(w, r)
			return
		}
		if !containsScope(scopes, requiredScope) {
			writeProblem(w, r, http.StatusForbidden, "INSUFFICIENT_SCOPE", "Access denied", "The access token does not include the required permission.", false)
			return
		}
		limitContext, cancelLimit = context.WithTimeout(r.Context(), 2*time.Second)
		allowed, retryAfter, err = s.checkRateLimit(limitContext, "service:"+requiredScope+":application", applicationID, 300)
		cancelLimit()
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		if !allowed {
			writeRateLimitProblem(w, r, retryAfter)
			return
		}

		requestTimeout := 5 * time.Second
		if requiredScope == "decisions:evaluate" {
			requestTimeout = 25 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		tx, err := s.Store.BeginTx(ctx, nil)
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "DATA_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		defer tx.Rollback()
		// Revalidate within the transaction, then lock the token and its owners so
		// credential rotation cannot race a telemetry write.
		var currentTenantID, currentApplicationID, currentCredentialID, currentTokenID string
		var currentScopes []string
		var currentExpiry time.Time
		err = tx.QueryRowContext(ctx, `SELECT tenant_id::text, application_id::text, credential_id::text, token_id::text, scopes, expires_at
			FROM public.qg_validate_service_access_token($1::bytea)`, tokenHash[:]).
			Scan(&currentTenantID, &currentApplicationID, &currentCredentialID, &currentTokenID, &currentScopes, &currentExpiry)
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "A valid application access token is required.", false)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "AUTHENTICATION_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		if currentTenantID != tenantID || currentApplicationID != applicationID || currentCredentialID != credentialID || currentTokenID != tokenID ||
			!containsScope(currentScopes, requiredScope) {
			writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "A valid application access token is required.", false)
			return
		}
		if _, err := tx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantID); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "DATA_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		var lockedTokenID string
		err = tx.QueryRowContext(ctx, `SELECT token.id::text
			FROM service_access_tokens AS token
			JOIN application_credentials AS credential
			  ON credential.tenant_id = token.tenant_id AND credential.id = token.credential_id
			JOIN applications AS application
			  ON application.tenant_id = token.tenant_id AND application.id = token.application_id
			JOIN tenants AS tenant_row ON tenant_row.id = token.tenant_id
			WHERE token.tenant_id = $1 AND token.id = $2 AND token.token_hash = $3
			  AND token.revoked_at IS NULL AND token.expires_at > clock_timestamp()
			  AND credential.revoked_at IS NULL AND credential.expires_at > clock_timestamp()
			  AND application.status = 'active' AND tenant_row.status = 'active'
			FOR SHARE OF token, credential, application, tenant_row`, tenantID, tokenID, tokenHash[:]).Scan(&lockedTokenID)
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "A valid application access token is required.", false)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "DATA_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		if lockedTokenID != tokenID {
			writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "A valid application access token is required.", false)
			return
		}

		var keyHash []byte
		if unsafeMethod(r.Method) && requireIdempotency {
			key, valid := validateIdempotencyKey(r.Header.Values(idempotencyKeyHeader))
			if !valid {
				writeProblem(w, r, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Invalid request", "A single 16 to 128 character Idempotency-Key is required.", false)
				return
			}
			body, err := readMutationBody(w, r)
			if err != nil {
				status := http.StatusBadRequest
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				writeProblem(w, r, status, "INVALID_REQUEST", "Invalid request", "The request body could not be read safely.", false)
				return
			}
			principal := tenantPrincipal{TenantID: tenantID, Issuer: "quantumgate-service-client", Subject: applicationID}
			var replay *idempotentResponse
			keyHash, replay, err = s.reserveIdempotency(ctx, tx, r, principal, key, body)
			if errors.Is(err, errIdempotencyKeyReused) {
				writeProblem(w, r, http.StatusConflict, "IDEMPOTENCY_KEY_REUSED", "Conflict", "The idempotency key was already used for a different request.", false)
				return
			}
			if err != nil {
				writeProblem(w, r, http.StatusServiceUnavailable, "IDEMPOTENCY_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
				return
			}
			if replay != nil {
				replayIdempotentResponse(w, replay)
				return
			}
		} else {
			r.Body = http.MaxBytesReader(w, r.Body, maxControlBodyBytes)
		}
		requestContext := context.WithValue(r.Context(), tenantContextKey, tenantID)
		requestContext = context.WithValue(requestContext, transactionContextKey, tx)
		requestContext = context.WithValue(requestContext, serviceApplicationContextKey{}, applicationID)
		r = r.WithContext(requestContext)
		recorder := httptest.NewRecorder()
		next.ServeHTTP(recorder, r)
		status := recorder.Code
		if status == 0 {
			status = http.StatusOK
		}
		commitResponse := status < http.StatusBadRequest || requiredScope == "decisions:evaluate"
		if commitResponse {
			if len(keyHash) != 0 {
				if err := s.saveIdempotentResponse(ctx, tx, tenantID, keyHash, status, recorder.Header(), recorder.Body.Bytes()); err != nil {
					writeProblem(w, r, http.StatusServiceUnavailable, "IDEMPOTENCY_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
					return
				}
			}
			if err := tx.Commit(); err != nil {
				writeProblem(w, r, http.StatusServiceUnavailable, "DATA_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
				return
			}
		}
		writeRecorded(w, recorder)
	})
}

func (s *Server) ingestObservation(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	authenticatedApplicationID, _ := r.Context().Value(serviceApplicationContextKey{}).(string)
	if !validUUID(applicationID) || applicationID != authenticatedApplicationID {
		s.notFound(w, r)
		return
	}
	var input struct {
		Source           string              `json:"source"`
		Protocol         string              `json:"protocol"`
		AlgorithmProfile string              `json:"algorithm_profile"`
		Blocker          *string             `json:"blocker"`
		Confidence       string              `json:"confidence"`
		ObservedAt       *time.Time          `json:"observed_at"`
		Evidence         observationEvidence `json:"evidence"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validLabel(input.Source, 128) || !validLabel(input.Protocol, 128) ||
		!knownPolicyProfile(input.AlgorithmProfile) || !oneOf(input.Confidence, "low", "medium", "high") ||
		input.Blocker != nil && !validBoundedToken(*input.Blocker, 128) ||
		!validOptionalEvidenceValue(input.Evidence.KeyExchange, 128) || !validOptionalEvidenceValue(input.Evidence.SignatureScheme, 128) ||
		!validOptionalEvidenceValue(input.Evidence.EndpointRole, 64) ||
		input.ObservedAt != nil && (input.ObservedAt.After(time.Now().Add(5*time.Minute)) || input.ObservedAt.Before(time.Now().Add(-90*24*time.Hour))) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_OBSERVATION", "Invalid request", "The observation fields or timestamp are invalid.", false)
		return
	}
	evidence, err := json.Marshal(input.Evidence)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_OBSERVATION", "Invalid request", "The observation fields are invalid.", false)
		return
	}
	var blocker any
	if input.Blocker != nil {
		blocker = *input.Blocker
	}
	var observedAt any
	if input.ObservedAt != nil {
		observedAt = input.ObservedAt.UTC()
	}
	var observationID string
	var acceptedAt time.Time
	err = contextTransaction(r).QueryRowContext(r.Context(), `INSERT INTO migration_observations
		(tenant_id, application_id, source, protocol, algorithm_profile, blocker, confidence, evidence, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, COALESCE($9::timestamptz, clock_timestamp()))
		RETURNING id::text, observed_at`, contextTenant(r), applicationID, input.Source, input.Protocol, input.AlgorithmProfile,
		blocker, input.Confidence, evidence, observedAt).Scan(&observationID, &acceptedAt)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "OBSERVATION_UNAVAILABLE", "Service unavailable", "The observation could not be stored safely.", true)
		return
	}
	if input.Blocker != nil {
		principal := tenantPrincipal{Issuer: "quantumgate-service-client", Subject: applicationID, Role: "service", TenantID: contextTenant(r)}
		if err := insertAudit(r.Context(), contextTransaction(r), principal, requestID(r.Context()),
			"posture.blocker_found", "migration_observation", observationID, "success", "POSTURE_BLOCKER_FOUND"); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "OBSERVATION_UNAVAILABLE", "Service unavailable", "The observation could not be stored safely.", true)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"observation_id": observationID,
		"application_id": applicationID,
		"observed_at":    acceptedAt.UTC(),
		"request_id":     requestID(r.Context()),
	})
}

func validOptionalEvidenceValue(value string, max int) bool {
	return value == "" || validBoundedToken(value, max)
}

func containsScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func writeRateLimitProblem(w http.ResponseWriter, r *http.Request, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeProblem(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests", "The request rate exceeds the current limit.", true)
}
