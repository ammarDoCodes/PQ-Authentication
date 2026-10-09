package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const serviceAccessTokenLifetime = 5 * time.Minute
const maxOAuthFormBytes = 4 << 10

func (s *Server) issueServiceAccessToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if s.Store == nil || len(s.RateLimitKey) != 32 {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	limitCtx, cancelLimit := context.WithTimeout(r.Context(), 2*time.Second)
	allowed, retryAfter, err := s.checkRateLimit(limitCtx, "oauth:token:ip", clientIPDimension(r.RemoteAddr), 60)
	cancelLimit()
	if err != nil {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	if !allowed {
		writeOAuthError(w, r, http.StatusTooManyRequests, "rate_limited", false, retryAfter)
		return
	}
	if r.URL.RawQuery != "" {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	contentTypes := r.Header.Values("Content-Type")
	mediaType := ""
	if len(contentTypes) == 1 {
		mediaType, _, err = mime.ParseMediaType(contentTypes[0])
	}
	if len(contentTypes) != 1 || err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOAuthFormBytes))
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeOAuthError(w, r, status, "invalid_request", false, 0)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || !onlyOAuthFormFields(form) || len(form["grant_type"]) != 1 || form.Get("grant_type") != "client_credentials" || len(form["scope"]) != 1 {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	requestedScopes, ok := parseOAuthScope(form.Get("scope"))
	if !ok {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_scope", false, 0)
		return
	}
	clientIDs := r.Header.Values("Authorization")
	clientID, clientSecret, basicAuth := r.BasicAuth()
	if len(clientIDs) != 1 || !basicAuth || !validUUID(clientID) || !validOpaqueCredential(clientSecret) {
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", true, 0)
		return
	}
	clientID = strings.ToLower(clientID)
	secretHash := sha256.Sum256([]byte(clientSecret))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var tenantID, applicationID, credentialID string
	var grantedScopes []string
	err = s.Store.QueryRowContext(ctx, `SELECT tenant_id::text, application_id::text, credential_id::text, scopes
		FROM public.qg_authenticate_application_credential($1::uuid, $2::bytea)`, clientID, secretHash[:]).
		Scan(&tenantID, &applicationID, &credentialID, &grantedScopes)
	if errors.Is(err, sql.ErrNoRows) {
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", true, 0)
		return
	}
	if err != nil {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	if applicationID != clientID || !scopesSubset(requestedScopes, grantedScopes) {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_scope", false, 0)
		return
	}
	clientCtx, cancelClient := context.WithTimeout(ctx, 2*time.Second)
	allowed, retryAfter, err = s.checkRateLimit(clientCtx, "oauth:token:client", applicationID, 30)
	cancelClient()
	if err != nil {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	if !allowed {
		writeOAuthError(w, r, http.StatusTooManyRequests, "rate_limited", false, retryAfter)
		return
	}
	token, expiresAt, err := s.mintServiceAccessToken(ctx, tenantID, applicationID, credentialID, clientSecret, requestedScopes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", true, 0)
			return
		}
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(serviceAccessTokenLifetime.Seconds()),
		"scope":        strings.Join(requestedScopes, " "),
		"expires_at":   expiresAt.UTC(),
		"request_id":   requestID(r.Context()),
	})
}

func (s *Server) introspectServiceAccessToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if s.Store == nil || len(s.RateLimitKey) != 32 {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	limitCtx, cancelLimit := context.WithTimeout(r.Context(), 2*time.Second)
	allowed, retryAfter, err := s.checkRateLimit(limitCtx, "oauth:introspect:ip", clientIPDimension(r.RemoteAddr), 60)
	cancelLimit()
	if err != nil {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	if !allowed {
		writeOAuthError(w, r, http.StatusTooManyRequests, "rate_limited", false, retryAfter)
		return
	}
	if r.URL.RawQuery != "" || len(r.Header.Values("Content-Type")) != 1 {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOAuthFormBytes))
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeOAuthError(w, r, status, "invalid_request", false, 0)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form) != 1 || len(form["token"]) != 1 {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	clientID, clientSecret, basicAuth := r.BasicAuth()
	if len(r.Header.Values("Authorization")) != 1 || !basicAuth || !validUUID(clientID) || !validOpaqueCredential(clientSecret) {
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", true, 0)
		return
	}
	clientID = strings.ToLower(clientID)
	clientSecretHash := sha256.Sum256([]byte(clientSecret))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var tenantID, applicationID, credentialID string
	var grantedScopes []string
	err = s.Store.QueryRowContext(ctx, `SELECT tenant_id::text, application_id::text, credential_id::text, scopes
		FROM public.qg_authenticate_application_credential($1::uuid, $2::bytea)`, clientID, clientSecretHash[:]).
		Scan(&tenantID, &applicationID, &credentialID, &grantedScopes)
	if errors.Is(err, sql.ErrNoRows) {
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", true, 0)
		return
	}
	if err != nil {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	if applicationID != clientID {
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", true, 0)
		return
	}
	clientCtx, cancelClient := context.WithTimeout(ctx, 2*time.Second)
	allowed, retryAfter, err = s.checkRateLimit(clientCtx, "oauth:introspect:client", applicationID, 60)
	cancelClient()
	if err != nil {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
		return
	}
	if !allowed {
		writeOAuthError(w, r, http.StatusTooManyRequests, "rate_limited", false, retryAfter)
		return
	}
	introspection := map[string]any{"active": false, "request_id": requestID(r.Context())}
	if validOpaqueAccessToken(form.Get("token")) {
		tokenHash := sha256.Sum256([]byte(form.Get("token")))
		var tokenTenantID, tokenApplicationID string
		var tokenCredentialID string
		var tokenScopes []string
		var expiresAt time.Time
		err = s.Store.QueryRowContext(ctx, `SELECT tenant_id::text, application_id::text, credential_id::text, scopes, expires_at
			FROM public.qg_validate_service_access_token($1::bytea)`, tokenHash[:]).
			Scan(&tokenTenantID, &tokenApplicationID, &tokenCredentialID, &tokenScopes, &expiresAt)
		if err == nil && tokenTenantID == tenantID && tokenApplicationID == applicationID && tokenCredentialID == credentialID && scopesSubset(tokenScopes, grantedScopes) {
			introspection = map[string]any{
				"active": true, "client_id": applicationID, "sub": applicationID, "tenant_id": tenantID,
				"scope": strings.Join(tokenScopes, " "), "iat": expiresAt.Add(-serviceAccessTokenLifetime).Unix(),
				"exp": expiresAt.Unix(), "request_id": requestID(r.Context()),
			}
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", false, 0)
			return
		}
	}
	writeJSON(w, http.StatusOK, introspection)
}

func (s *Server) mintServiceAccessToken(ctx context.Context, tenantID, applicationID, credentialID, clientSecret string, scopes []string) (string, time.Time, error) {
	secretHash := sha256.Sum256([]byte(clientSecret))
	tx, err := s.Store.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantID); err != nil {
		return "", time.Time{}, err
	}
	var applicationStatus, tenantStatus string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM public.applications
		WHERE tenant_id = $1 AND id = $2 FOR SHARE`, tenantID, applicationID).Scan(&applicationStatus); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT status FROM public.tenants WHERE id = $1 FOR SHARE`, tenantID).Scan(&tenantStatus); err != nil {
		return "", time.Time{}, err
	}
	if applicationStatus != "active" || tenantStatus != "active" {
		return "", time.Time{}, sql.ErrNoRows
	}
	var currentScopes []string
	err = tx.QueryRowContext(ctx, `SELECT scopes FROM public.application_credentials
		WHERE tenant_id = $1 AND application_id = $2 AND id = $3 AND credential_hash = $4
		  AND revoked_at IS NULL AND expires_at > clock_timestamp() FOR SHARE`,
		tenantID, applicationID, credentialID, secretHash[:]).Scan(&currentScopes)
	if err != nil {
		return "", time.Time{}, err
	}
	if !scopesSubset(scopes, currentScopes) {
		return "", time.Time{}, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `WITH stale AS (
		SELECT id FROM public.service_access_tokens
		WHERE tenant_id = $1 AND expires_at < clock_timestamp() - interval '1 hour'
		ORDER BY expires_at LIMIT 1000
	) DELETE FROM public.service_access_tokens AS tokens USING stale WHERE tokens.tenant_id = $1 AND tokens.id = stale.id`, tenantID); err != nil {
		return "", time.Time{}, err
	}
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return "", time.Time{}, err
	}
	token := "qgt_" + base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256([]byte(token))
	var tokenID string
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `WITH issuance_time AS (SELECT clock_timestamp() AS created_at)
		INSERT INTO public.service_access_tokens
			(tenant_id, application_id, credential_id, token_hash, scopes, created_at, expires_at)
		SELECT $1, $2, $3, $4, $5, issuance_time.created_at, issuance_time.created_at + interval '5 minutes'
		FROM issuance_time
		RETURNING id::text, expires_at`, tenantID, applicationID, credentialID, tokenHash[:], scopes).
		Scan(&tokenID, &expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := insertServiceTokenAudit(ctx, tx, tenantID, credentialID, tokenID, scopes); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func insertServiceTokenAudit(ctx context.Context, tx *sql.Tx, tenantID, credentialID, tokenID string, scopes []string) error {
	source, err := json.Marshal(map[string]any{"kind": "oauth_client_credentials", "scopes": scopes})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.audit_events
		(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code, source_context)
		VALUES ($1, 1, $2, 'service_token.issued', 'service_access_token', $3, 'success', $4, 'CLIENT_CREDENTIALS', $5::jsonb)`,
		tenantID, "service-credential:"+credentialID, tokenID, requestID(ctx), source)
	return err
}

func onlyOAuthFormFields(form url.Values) bool {
	if len(form) != 2 {
		return false
	}
	for key := range form {
		if key != "grant_type" && key != "scope" {
			return false
		}
	}
	return true
}

func validOpaqueCredential(value string) bool {
	if !strings.HasPrefix(value, "qgc_") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "qgc_"))
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == strings.TrimPrefix(value, "qgc_")
}

func validOpaqueAccessToken(value string) bool {
	if !strings.HasPrefix(value, "qgt_") {
		return false
	}
	encoded := strings.TrimPrefix(value, "qgt_")
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func scopesSubset(requested, granted []string) bool {
	allowed := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		allowed[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowed[scope]; !ok {
			return false
		}
	}
	return len(requested) > 0
}

func writeOAuthError(w http.ResponseWriter, r *http.Request, status int, code string, authenticate bool, retryAfter int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if authenticate {
		w.Header().Set("WWW-Authenticate", `Basic realm="QuantumGate"`)
	}
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	writeJSON(w, status, map[string]string{"error": code, "request_id": requestID(r.Context())})
}
