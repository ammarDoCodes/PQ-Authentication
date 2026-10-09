package httpapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"quantumgate/internal/auth"
)

type identityAdapterConfig struct {
	RequiredACR string `json:"required_acr"`
}

type identityAdapterView struct {
	ID             string     `json:"id"`
	ApplicationID  string     `json:"application_id"`
	AdapterType    string     `json:"adapter_type"`
	Issuer         string     `json:"issuer"`
	Audience       string     `json:"audience"`
	RequiredACR    string     `json:"required_acr"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
	ETag           string     `json:"etag"`
	RequestID      string     `json:"request_id"`
}

const identityAdapterSelect = `id::text, application_id::text, adapter_type, issuer, audience, config::text,
	status, created_at, updated_at, last_verified_at`

type identityAdapterScanner interface {
	Scan(...any) error
}

func (s *Server) listIdentityAdapters(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer", "auditor") {
		return
	}
	var exists bool
	if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT EXISTS(
		SELECT 1 FROM applications WHERE tenant_id = $1 AND id = $2)`, contextTenant(r), applicationID).Scan(&exists); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !exists {
		s.notFound(w, r)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_LIMIT", "Invalid request", "The page size is invalid.", false)
			return
		}
		limit = parsed
	}
	var after any
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || !validUUID(string(decoded)) {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_CURSOR", "Invalid request", "The pagination cursor is invalid.", false)
			return
		}
		after = string(decoded)
	}
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT `+identityAdapterSelect+`
		FROM identity_adapters WHERE tenant_id = $1 AND application_id = $2 AND ($3::uuid IS NULL OR id > $3::uuid)
		ORDER BY id LIMIT $4`, contextTenant(r), applicationID, after, limit+1)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	defer rows.Close()
	items := make([]identityAdapterView, 0, limit)
	for rows.Next() {
		item, err := scanIdentityAdapter(rows)
		if err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	response := map[string]any{"items": items, "next_cursor": "", "request_id": requestID(r.Context())}
	if len(items) > limit {
		items = items[:limit]
		response["items"] = items
		response["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ID))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) createIdentityAdapter(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	var input struct {
		AdapterType string `json:"adapter_type"`
		Issuer      string `json:"issuer"`
		Audience    string `json:"audience"`
		RequiredACR string `json:"required_acr"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || input.AdapterType != "oidc" ||
		!validOIDCIssuer(input.Issuer, s.IdentityAllowedHosts) || !validBoundedToken(input.Audience, 512) || !validBoundedToken(input.RequiredACR, 256) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_IDENTITY_ADAPTER", "Invalid request", "An OIDC adapter requires an HTTPS issuer on the configured host allowlist, an audience, and a required ACR.", false)
		return
	}
	configJSON, err := json.Marshal(identityAdapterConfig{RequiredACR: input.RequiredACR})
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item, err := scanIdentityAdapter(contextTransaction(r).QueryRowContext(r.Context(), `INSERT INTO identity_adapters
		(tenant_id, application_id, adapter_type, issuer, audience, config, status)
		SELECT $1, application.id, 'oidc', $3, $4, $5::jsonb, 'verification_required'
		FROM applications AS application
		WHERE application.tenant_id = $1 AND application.id = $2 AND application.status = 'active'
		RETURNING id::text, application_id::text, adapter_type, issuer, audience, config::text, status,
			created_at, updated_at, last_verified_at`, contextTenant(r), applicationID, input.Issuer, input.Audience, configJSON))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		writeDatabaseProblem(w, r, err, "IDENTITY_ADAPTER_CONFLICT")
		return
	}
	item.RequestID = requestID(r.Context())
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "identity_adapter.created", "identity_adapter", item.ID, "success", "OIDC_VERIFICATION_REQUIRED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) updateIdentityAdapter(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	adapterID := r.PathValue("adapter_id")
	if !validUUID(adapterID) {
		s.notFound(w, r)
		return
	}
	expected, ok := identityAdapterIfMatch(w, r)
	if !ok {
		return
	}
	var input struct {
		Issuer      *string `json:"issuer"`
		Audience    *string `json:"audience"`
		RequiredACR *string `json:"required_acr"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || input.Issuer == nil && input.Audience == nil && input.RequiredACR == nil {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_IDENTITY_ADAPTER", "Invalid request", "Provide at least one supported adapter setting.", false)
		return
	}
	item, err := scanIdentityAdapter(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+identityAdapterSelect+`
		FROM identity_adapters WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, contextTenant(r), adapterID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !item.UpdatedAt.Equal(expected) {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Adapter changed", "Fetch the identity adapter again before retrying the update.", false)
		return
	}
	adapterConfig := identityAdapterConfig{RequiredACR: item.RequiredACR}
	if input.Issuer != nil {
		item.Issuer = *input.Issuer
	}
	if input.Audience != nil {
		item.Audience = *input.Audience
	}
	if input.RequiredACR != nil {
		adapterConfig.RequiredACR = *input.RequiredACR
	}
	if item.AdapterType != "oidc" || !validOIDCIssuer(item.Issuer, s.IdentityAllowedHosts) || !validBoundedToken(item.Audience, 512) || !validBoundedToken(adapterConfig.RequiredACR, 256) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_IDENTITY_ADAPTER", "Invalid request", "The OIDC issuer, audience, or required ACR is invalid.", false)
		return
	}
	encodedConfig, err := json.Marshal(adapterConfig)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item, err = scanIdentityAdapter(contextTransaction(r).QueryRowContext(r.Context(), `UPDATE identity_adapters
		SET issuer = $3, audience = $4, config = $5::jsonb, status = 'verification_required',
			last_verified_at = NULL, updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 AND updated_at = $6
		RETURNING id::text, application_id::text, adapter_type, issuer, audience, config::text, status,
			created_at, updated_at, last_verified_at`, contextTenant(r), adapterID, item.Issuer, item.Audience, encodedConfig, expected))
	if errors.Is(err, sql.ErrNoRows) {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Adapter changed", "Fetch the identity adapter again before retrying the update.", false)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item.RequestID = requestID(r.Context())
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "identity_adapter.updated", "identity_adapter", adapterID, "success", "VERIFICATION_REQUIRED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) verifyIdentityAdapter(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	adapterID := r.PathValue("adapter_id")
	if !validUUID(adapterID) {
		s.notFound(w, r)
		return
	}
	expected, ok := identityAdapterIfMatch(w, r)
	if !ok {
		return
	}
	if !s.enforceRateLimit(w, r, "identity-adapter:verify", adapterID, 10) {
		return
	}
	var input struct {
		IDToken string `json:"id_token"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || input.IDToken == "" || len(input.IDToken) > maxBearerTokenBytes || strings.ContainsAny(input.IDToken, " \t\r\n") {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_ADAPTER_PROOF", "Invalid request", "A bounded OIDC ID token is required to verify this adapter.", false)
		return
	}
	item, err := scanIdentityAdapter(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+identityAdapterSelect+`
		FROM identity_adapters WHERE tenant_id = $1 AND id = $2`, contextTenant(r), adapterID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !item.UpdatedAt.Equal(expected) {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Adapter changed", "Fetch the identity adapter again before retrying verification.", false)
		return
	}
	if item.Status == "disabled" || item.AdapterType != "oidc" || len(s.IdentityAllowedHosts) == 0 {
		writeProblem(w, r, http.StatusConflict, "ADAPTER_NOT_VERIFIABLE", "Conflict", "The identity adapter cannot currently be verified.", false)
		return
	}
	adapterConfig := identityAdapterConfig{RequiredACR: item.RequiredACR}
	verificationContext, cancelVerification := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancelVerification()
	verifier, verifyErr := auth.NewOIDCVerifier(verificationContext, auth.OIDCSettings{
		Issuer: item.Issuer, ClientID: item.Audience, AllowedHosts: s.IdentityAllowedHosts,
		RequiredACR: adapterConfig.RequiredACR, SigningAlgs: []string{"RS256"}, MaxTokenAge: 15 * time.Minute,
	})
	if verifyErr == nil {
		_, verifyErr = verifier.Verify(verificationContext, input.IDToken)
	}
	if verifyErr != nil {
		if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "identity_adapter.verification_failed", "identity_adapter", adapterID, "failure", "PROVIDER_VERIFICATION_FAILED"); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"adapter_id": adapterID, "verified": false, "reason_code": "PROVIDER_VERIFICATION_FAILED", "request_id": requestID(r.Context())})
		return
	}
	item, err = scanIdentityAdapter(contextTransaction(r).QueryRowContext(r.Context(), `UPDATE identity_adapters
		SET status = 'active', last_verified_at = clock_timestamp(),
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 AND updated_at = $3 AND status <> 'disabled'
		RETURNING id::text, application_id::text, adapter_type, issuer, audience, config::text, status,
			created_at, updated_at, last_verified_at`, contextTenant(r), adapterID, expected))
	if errors.Is(err, sql.ErrNoRows) {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Adapter changed", "Fetch the identity adapter again before retrying verification.", false)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item.RequestID = requestID(r.Context())
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "identity_adapter.verified", "identity_adapter", adapterID, "success", "OIDC_TOKEN_VERIFIED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableIdentityAdapter(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	adapterID := r.PathValue("adapter_id")
	if !validUUID(adapterID) {
		s.notFound(w, r)
		return
	}
	expected, ok := identityAdapterIfMatch(w, r)
	if !ok {
		return
	}
	item, err := scanIdentityAdapter(contextTransaction(r).QueryRowContext(r.Context(), `UPDATE identity_adapters
		SET status = 'disabled', updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 AND status <> 'disabled' AND updated_at = $3
		RETURNING id::text, application_id::text, adapter_type, issuer, audience, config::text, status,
			created_at, updated_at, last_verified_at`, contextTenant(r), adapterID, expected))
	noop := false
	if errors.Is(err, sql.ErrNoRows) {
		item, err = scanIdentityAdapter(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+identityAdapterSelect+
			` FROM identity_adapters WHERE tenant_id = $1 AND id = $2`, contextTenant(r), adapterID))
		if errors.Is(err, sql.ErrNoRows) {
			s.notFound(w, r)
			return
		}
		if err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		current, valid := parseTenantETag(tenantETag(item.UpdatedAt))
		if !valid || !current.Equal(expected) {
			writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Adapter changed", "Fetch the identity adapter again before retrying the update.", false)
			return
		}
		if item.Status != "disabled" {
			controlPlaneUnavailable(w, r)
			return
		}
		noop = true
	} else if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	action, reason := "identity_adapter.disabled", "DISABLED"
	if noop {
		action, reason = "identity_adapter.disable_noop", "ALREADY_DISABLED"
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), action, "identity_adapter", adapterID, "success", reason); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item.ETag = tenantETag(item.UpdatedAt)
	item.RequestID = requestID(r.Context())
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func scanIdentityAdapter(row identityAdapterScanner) (identityAdapterView, error) {
	var item identityAdapterView
	var configJSON string
	var lastVerified sql.NullTime
	err := row.Scan(&item.ID, &item.ApplicationID, &item.AdapterType, &item.Issuer, &item.Audience,
		&configJSON, &item.Status, &item.CreatedAt, &item.UpdatedAt, &lastVerified)
	if err != nil {
		return identityAdapterView{}, err
	}
	var adapterConfig identityAdapterConfig
	if err := json.Unmarshal([]byte(configJSON), &adapterConfig); err != nil || !validBoundedToken(adapterConfig.RequiredACR, 256) {
		return identityAdapterView{}, errors.New("stored identity adapter configuration is invalid")
	}
	item.RequiredACR = adapterConfig.RequiredACR
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	if lastVerified.Valid {
		verified := lastVerified.Time.UTC()
		item.LastVerifiedAt = &verified
	}
	item.ETag = tenantETag(item.UpdatedAt)
	return item, nil
}

func identityAdapterIfMatch(w http.ResponseWriter, r *http.Request) (time.Time, bool) {
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the identity adapter and send its ETag in If-Match.", false)
		return time.Time{}, false
	}
	expected, ok := parseTenantETag(r.Header.Get("If-Match"))
	if !ok {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the identity adapter and send its ETag in If-Match.", false)
		return time.Time{}, false
	}
	return expected, true
}

func validOIDCIssuer(issuer string, allowedHosts []string) bool {
	parsed, err := url.Parse(issuer)
	if len(issuer) > 2048 || strings.ContainsAny(issuer, "?# \t\r\n") || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.Port() != "" && parsed.Port() != "443" || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	for _, allowed := range allowedHosts {
		if host == strings.ToLower(strings.TrimSuffix(allowed, ".")) {
			return true
		}
	}
	return false
}
