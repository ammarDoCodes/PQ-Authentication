package httpapi

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type keyReferenceView struct {
	ID                string     `json:"id"`
	ApplicationID     string     `json:"application_id"`
	Purpose           string     `json:"purpose"`
	Provider          string     `json:"provider"`
	ProviderReference string     `json:"provider_reference"`
	AlgorithmProfile  *string    `json:"algorithm_profile_id,omitempty"`
	Version           int64      `json:"version"`
	State             string     `json:"state"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	ETag              string     `json:"etag"`
	RequestID         string     `json:"request_id"`
}

const keyReferenceSelect = `id::text, application_id::text, purpose, provider, provider_reference,
	algorithm_profile_id::text, version, state, created_at, updated_at, expires_at, revoked_at`

type keyReferenceScanner interface {
	Scan(...any) error
}

func (s *Server) listApplicationKeys(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
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
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT `+keyReferenceSelect+`
		FROM key_references WHERE tenant_id = $1 AND application_id = $2 AND ($3::uuid IS NULL OR id > $3::uuid)
		ORDER BY id LIMIT $4`, contextTenant(r), applicationID, after, limit+1)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	defer rows.Close()
	items := make([]keyReferenceView, 0, limit)
	for rows.Next() {
		item, err := scanKeyReference(rows)
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

func (s *Server) createKeyReference(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r, "key-reference:rotate", applicationID, 10) {
		return
	}
	var input struct {
		Purpose           string     `json:"purpose"`
		Provider          string     `json:"provider"`
		ProviderReference string     `json:"provider_reference"`
		AlgorithmProfile  *string    `json:"algorithm_profile_id"`
		ExpiresAt         *time.Time `json:"expires_at"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil ||
		!oneOf(input.Purpose, "signing", "key-encryption", "session", "data-encryption") ||
		!oneOf(input.Provider, "aws-kms-reference", "azure-key-vault-reference", "gcp-kms-reference", "pkcs11-reference", "external-hsm-reference") ||
		!validLabel(input.ProviderReference, 1024) || input.ExpiresAt == nil ||
		input.ExpiresAt.Before(time.Now().Add(5*time.Minute)) || input.ExpiresAt.After(time.Now().AddDate(5, 0, 0)) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_KEY_REFERENCE", "Invalid request", "A supported purpose, provider reference, and expiry between five minutes and five years are required.", false)
		return
	}
	if input.AlgorithmProfile != nil {
		if !validUUID(*input.AlgorithmProfile) {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_KEY_REFERENCE", "Invalid request", "The algorithm profile reference is invalid.", false)
			return
		}
		var profileExists bool
		if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT EXISTS(
			SELECT 1 FROM algorithm_profiles WHERE tenant_id = $1 AND id = $2)`, contextTenant(r), *input.AlgorithmProfile).Scan(&profileExists); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		if !profileExists {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_KEY_REFERENCE", "Invalid request", "The algorithm profile reference is invalid.", false)
			return
		}
	}
	var lockedApplication string
	err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text FROM applications
		WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR UPDATE`, contextTenant(r), applicationID).Scan(&lockedApplication)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var version int64
	if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT COALESCE(max(version), 0) + 1 FROM key_references
		WHERE tenant_id = $1 AND application_id = $2 AND purpose = $3`, contextTenant(r), applicationID, input.Purpose).Scan(&version); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item, err := scanKeyReference(contextTransaction(r).QueryRowContext(r.Context(), `INSERT INTO key_references
		(tenant_id, application_id, purpose, provider, provider_reference, algorithm_profile_id, version, state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'provisioning', $8)
		RETURNING `+keyReferenceSelect,
		contextTenant(r), applicationID, input.Purpose, input.Provider, input.ProviderReference, input.AlgorithmProfile, version, input.ExpiresAt.UTC()))
	if err != nil {
		writeDatabaseProblem(w, r, err, "KEY_REFERENCE_CONFLICT")
		return
	}
	item.RequestID = requestID(r.Context())
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()),
		"key_reference.created", "key_reference", item.ID, "success", "EXTERNAL_PROVIDER_REFERENCE_RECORDED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) activateKeyReference(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	var input struct {
		ProviderResourceConfirmed bool `json:"provider_resource_confirmed"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !input.ProviderResourceConfirmed {
		writeProblem(w, r, http.StatusBadRequest, "PROVIDER_CONFIRMATION_REQUIRED", "Invalid request", "Confirm that the external provider resource is ready before activation.", false)
		return
	}
	s.transitionKeyReference(w, r, "activate")
}

func (s *Server) disableKeyReference(w http.ResponseWriter, r *http.Request) {
	s.transitionKeyReference(w, r, "disable")
}

func (s *Server) revokeKeyReference(w http.ResponseWriter, r *http.Request) {
	s.transitionKeyReference(w, r, "revoke")
}

func (s *Server) transitionKeyReference(w http.ResponseWriter, r *http.Request, action string) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	keyID := r.PathValue("key_id")
	if !validUUID(keyID) {
		s.notFound(w, r)
		return
	}
	expected, ok := keyReferenceIfMatch(w, r)
	if !ok {
		return
	}
	if action == "activate" {
		var applicationID string
		err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT application_id::text FROM key_references
			WHERE tenant_id = $1 AND id = $2`, contextTenant(r), keyID).Scan(&applicationID)
		if errors.Is(err, sql.ErrNoRows) {
			s.notFound(w, r)
			return
		}
		if err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		var activeApplication string
		err = contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text FROM applications
			WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR UPDATE`, contextTenant(r), applicationID).Scan(&activeApplication)
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, r, http.StatusConflict, "KEY_STATE_CONFLICT", "Conflict", "The application must be active before its key reference can be activated.", false)
			return
		}
		if err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
	}
	item, err := scanKeyReference(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+keyReferenceSelect+`
		FROM key_references WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, contextTenant(r), keyID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !item.UpdatedAt.Equal(expected) {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Key reference changed", "Fetch the key reference again before retrying the lifecycle action.", false)
		return
	}
	targetState, auditAction, reason := "", "", ""
	switch action {
	case "activate":
		targetState, auditAction, reason = "active", "key_reference.activated", "EXTERNAL_PROVIDER_RESOURCE_CONFIRMED"
	case "disable":
		targetState, auditAction, reason = "disabled", "key_reference.disabled", "DISABLED"
	case "revoke":
		targetState, auditAction, reason = "revoked", "key_reference.revoked", "REVOKED"
	default:
		controlPlaneUnavailable(w, r)
		return
	}
	noop := item.State == targetState
	if !noop {
		switch action {
		case "activate":
			if item.State != "provisioning" {
				writeProblem(w, r, http.StatusConflict, "KEY_STATE_CONFLICT", "Conflict", "Only a provisioning key reference can be activated.", false)
				return
			}
			rows, err := contextTransaction(r).QueryContext(r.Context(), `UPDATE key_references
				SET state = 'rotation_due', updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
				WHERE tenant_id = $1 AND application_id = $2 AND purpose = $3 AND state = 'active' AND id <> $4
				RETURNING id::text`, contextTenant(r), item.ApplicationID, item.Purpose, keyID)
			if err != nil {
				controlPlaneUnavailable(w, r)
				return
			}
			var previousIDs []string
			for rows.Next() {
				var previousID string
				if err := rows.Scan(&previousID); err != nil {
					rows.Close()
					controlPlaneUnavailable(w, r)
					return
				}
				previousIDs = append(previousIDs, previousID)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				controlPlaneUnavailable(w, r)
				return
			}
			rows.Close()
			for _, previousID := range previousIDs {
				if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()),
					"key_reference.rotation_due", "key_reference", previousID, "success", "REPLACED_BY_NEW_VERSION"); err != nil {
					controlPlaneUnavailable(w, r)
					return
				}
			}
		case "disable":
			if !oneOf(item.State, "active", "rotation_due", "provisioning") {
				writeProblem(w, r, http.StatusConflict, "KEY_STATE_CONFLICT", "Conflict", "The key reference cannot be disabled from its current state.", false)
				return
			}
		case "revoke":
			if item.State == "destroyed" {
				writeProblem(w, r, http.StatusConflict, "KEY_STATE_CONFLICT", "Conflict", "A destroyed key reference cannot be revoked.", false)
				return
			}
		}
		query := `UPDATE key_references SET state = $3,
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')`
		if action == "revoke" {
			query += `, revoked_at = COALESCE(revoked_at, clock_timestamp())`
		}
		query += ` WHERE tenant_id = $1 AND id = $2 AND updated_at = $4 RETURNING ` + keyReferenceSelect
		item, err = scanKeyReference(contextTransaction(r).QueryRowContext(r.Context(), query, contextTenant(r), keyID, targetState, expected))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Key reference changed", "Fetch the key reference again before retrying the lifecycle action.", false)
				return
			}
			controlPlaneUnavailable(w, r)
			return
		}
	} else {
		reason = "ALREADY_" + strings.ToUpper(action)
		auditAction += "_noop"
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()),
		auditAction, "key_reference", keyID, "success", reason); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item.RequestID = requestID(r.Context())
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) getKeyPublicMaterial(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("key_id")
	if !validUUID(keyID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
		return
	}
	var material []byte
	err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT public_material FROM key_references
		WHERE tenant_id = $1 AND id = $2`, contextTenant(r), keyID).Scan(&material)
	if errors.Is(err, sql.ErrNoRows) || err == nil && len(material) == 0 {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(material)
}

func scanKeyReference(row keyReferenceScanner) (keyReferenceView, error) {
	var item keyReferenceView
	var algorithmProfile sql.NullString
	var expiresAt, revokedAt sql.NullTime
	err := row.Scan(&item.ID, &item.ApplicationID, &item.Purpose, &item.Provider, &item.ProviderReference,
		&algorithmProfile, &item.Version, &item.State, &item.CreatedAt, &item.UpdatedAt, &expiresAt, &revokedAt)
	if err != nil {
		return keyReferenceView{}, err
	}
	if algorithmProfile.Valid {
		value := algorithmProfile.String
		item.AlgorithmProfile = &value
	}
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	if expiresAt.Valid {
		value := expiresAt.Time.UTC()
		item.ExpiresAt = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time.UTC()
		item.RevokedAt = &value
	}
	item.ETag = tenantETag(item.UpdatedAt)
	return item, nil
}

func keyReferenceIfMatch(w http.ResponseWriter, r *http.Request) (time.Time, bool) {
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the key reference and send its ETag in If-Match.", false)
		return time.Time{}, false
	}
	expected, ok := parseTenantETag(r.Header.Get("If-Match"))
	if !ok {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the key reference and send its ETag in If-Match.", false)
		return time.Time{}, false
	}
	return expected, true
}
