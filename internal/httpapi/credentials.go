package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

var applicationCredentialScopes = map[string]struct{}{
	"decisions:evaluate": {},
	"observations:write": {},
	"posture:read":       {},
	"events:write":       {},
}

func (s *Server) rotateApplicationCredential(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r, "credential-rotation:application", applicationID, 10) {
		return
	}
	var input struct {
		Label            string   `json:"label"`
		Scopes           []string `json:"scopes"`
		ExpiresInSeconds int      `json:"expires_in_seconds"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validLabel(input.Label, 80) || !validApplicationCredentialScopes(input.Scopes) ||
		input.ExpiresInSeconds < 300 || input.ExpiresInSeconds > 31_536_000 {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_CREDENTIAL", "Invalid request", "A label, one or more allowed scopes, and an expiry from five minutes to one year are required.", false)
		return
	}

	randomSecret := make([]byte, 32)
	if _, err := rand.Read(randomSecret); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CREDENTIAL_UNAVAILABLE", "Service unavailable", "A credential could not be generated safely.", true)
		return
	}
	secret := "qgc_" + base64.RawURLEncoding.EncodeToString(randomSecret)
	secretHash := sha256.Sum256([]byte(secret))
	tx := contextTransaction(r)
	var lockedApplication string
	err := tx.QueryRowContext(r.Context(), `SELECT id::text FROM applications
		WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR UPDATE`, contextTenant(r), applicationID).Scan(&lockedApplication)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE application_credentials
		SET revoked_at = COALESCE(revoked_at, clock_timestamp())
		WHERE tenant_id = $1 AND application_id = $2 AND revoked_at IS NULL`, contextTenant(r), applicationID); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var credential struct {
		ID        string    `json:"credential_id"`
		Label     string    `json:"label"`
		Scopes    []string  `json:"scopes"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := tx.QueryRowContext(r.Context(), `INSERT INTO application_credentials
		(tenant_id, application_id, credential_hash, label, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, clock_timestamp() + ($6 * interval '1 second'))
		RETURNING id::text, label, scopes, created_at, expires_at`,
		contextTenant(r), applicationID, secretHash[:], input.Label, input.Scopes, input.ExpiresInSeconds).
		Scan(&credential.ID, &credential.Label, &credential.Scopes, &credential.CreatedAt, &credential.ExpiresAt); err != nil {
		writeDatabaseProblem(w, r, err, "CREDENTIAL_CONFLICT")
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()), "application.credential_rotated", "application_credential", credential.ID, "success", "CREDENTIAL_ROTATED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"credential_id": credential.ID,
		"label":         credential.Label,
		"scopes":        credential.Scopes,
		"created_at":    credential.CreatedAt,
		"expires_at":    credential.ExpiresAt,
		"client_secret": secret,
		"request_id":    requestID(r.Context()),
	})
}

func validApplicationCredentialScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > len(applicationCredentialScopes) {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if _, allowed := applicationCredentialScopes[scope]; !allowed {
			return false
		}
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}

func parseOAuthScope(value string) ([]string, bool) {
	if len(value) == 0 || len(value) > 512 || strings.TrimSpace(value) != value {
		return nil, false
	}
	scopes := strings.Split(value, " ")
	if !validApplicationCredentialScopes(scopes) {
		return nil, false
	}
	return scopes, true
}
