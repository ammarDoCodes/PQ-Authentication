package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type posturePolicy struct {
	ID               string `json:"id"`
	Revision         int64  `json:"revision"`
	Mode             string `json:"mode,omitempty"`
	Integrity        string `json:"integrity"`
	ActiveExceptions int    `json:"active_exceptions"`
}

type applicationPosture struct {
	ApplicationID     string         `json:"application_id"`
	ApplicationStatus string         `json:"application_status"`
	AssessmentStatus  string         `json:"assessment_status"`
	AsOf              time.Time      `json:"as_of"`
	ActivePolicy      *posturePolicy `json:"active_policy"`
	ScheduledPolicies int            `json:"scheduled_policy_count"`
	IdentityAdapters  struct {
		Active             int `json:"active"`
		VerificationNeeded int `json:"verification_required"`
	} `json:"identity_adapters"`
	Keys struct {
		Active      int `json:"active"`
		RotationDue int `json:"rotation_due"`
		Expired     int `json:"expired"`
	} `json:"keys"`
	ActiveCredentials int `json:"active_credentials"`
	Observations      struct {
		Count          int        `json:"count"`
		OpenBlockers   int        `json:"open_blockers"`
		LastObservedAt *time.Time `json:"last_observed_at"`
	} `json:"observations"`
	ReasonCodes []string `json:"reason_codes"`
	NextActions []string `json:"next_actions"`
	RequestID   string   `json:"request_id"`
}

func (s *Server) getApplicationPosture(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	serviceApplicationID, _ := r.Context().Value(serviceApplicationContextKey{}).(string)
	if serviceApplicationID != "" {
		if serviceApplicationID != applicationID {
			s.notFound(w, r)
			return
		}
	} else if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer", "auditor") {
		return
	}
	tx := contextTransaction(r)
	var result applicationPosture
	result.ApplicationID = applicationID
	result.AssessmentStatus = "inventory_only"
	err := tx.QueryRowContext(r.Context(), `SELECT id::text, status FROM applications
		WHERE tenant_id = $1 AND id = $2`, contextTenant(r), applicationID).
		Scan(&result.ApplicationID, &result.ApplicationStatus)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := tx.QueryRowContext(r.Context(), `SELECT clock_timestamp()`).Scan(&result.AsOf); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var activePolicyID sql.NullString
	var activePolicyRevision sql.NullInt64
	var policyDocumentJSON string
	var policyHash []byte
	err = tx.QueryRowContext(r.Context(), `SELECT id::text, revision, document::text, content_hash
		FROM policy_revisions WHERE tenant_id = $1 AND application_id = $2 AND state = 'active'`, contextTenant(r), applicationID).
		Scan(&activePolicyID, &activePolicyRevision, &policyDocumentJSON, &policyHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		controlPlaneUnavailable(w, r)
		return
	}
	if err == nil {
		item := &posturePolicy{ID: activePolicyID.String, Revision: activePolicyRevision.Int64, Integrity: "valid"}
		var document policyDocument
		if json.Unmarshal([]byte(policyDocumentJSON), &document) != nil {
			item.Integrity = "invalid"
		} else {
			canonical, marshalErr := json.Marshal(document)
			computedHash := sha256.Sum256(canonical)
			if marshalErr != nil || len(policyHash) != sha256.Size || !hmac.Equal(policyHash, computedHash[:]) {
				item.Integrity = "invalid"
			} else {
				item.Mode = document.Mode
				for _, exception := range document.Exceptions {
					if exception.ExpiresAt.After(result.AsOf) {
						item.ActiveExceptions++
					}
				}
			}
		}
		result.ActivePolicy = item
	}
	err = tx.QueryRowContext(r.Context(), `SELECT
		(SELECT count(*) FROM policy_revisions WHERE tenant_id = $1 AND application_id = $2 AND state = 'scheduled'),
		(SELECT count(*) FROM identity_adapters WHERE tenant_id = $1 AND application_id = $2 AND status = 'active'),
		(SELECT count(*) FROM identity_adapters WHERE tenant_id = $1 AND application_id = $2 AND status = 'verification_required'),
		(SELECT count(*) FROM key_references WHERE tenant_id = $1 AND application_id = $2 AND state = 'active' AND (expires_at IS NULL OR expires_at > clock_timestamp())),
		(SELECT count(*) FROM key_references WHERE tenant_id = $1 AND application_id = $2 AND state = 'rotation_due' AND (expires_at IS NULL OR expires_at > clock_timestamp())),
		(SELECT count(*) FROM key_references WHERE tenant_id = $1 AND application_id = $2 AND state NOT IN ('disabled', 'revoked', 'destroyed', 'expired') AND expires_at <= clock_timestamp()),
		(SELECT count(*) FROM application_credentials WHERE tenant_id = $1 AND application_id = $2 AND revoked_at IS NULL AND expires_at > clock_timestamp()),
		(SELECT count(*) FROM migration_observations WHERE tenant_id = $1 AND application_id = $2),
		(SELECT count(*) FROM migration_observations WHERE tenant_id = $1 AND application_id = $2 AND NULLIF(btrim(blocker), '') IS NOT NULL),
		(SELECT max(observed_at) FROM migration_observations WHERE tenant_id = $1 AND application_id = $2)`, contextTenant(r), applicationID).Scan(
		&result.ScheduledPolicies, &result.IdentityAdapters.Active, &result.IdentityAdapters.VerificationNeeded,
		&result.Keys.Active, &result.Keys.RotationDue, &result.Keys.Expired, &result.ActiveCredentials,
		&result.Observations.Count, &result.Observations.OpenBlockers, &result.Observations.LastObservedAt)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	result.AsOf = result.AsOf.UTC()
	if result.ActivePolicy == nil {
		result.ReasonCodes = append(result.ReasonCodes, "ACTIVE_POLICY_MISSING")
	} else if result.ActivePolicy.Integrity != "valid" {
		result.ReasonCodes = append(result.ReasonCodes, "ACTIVE_POLICY_INTEGRITY_FAILURE")
	} else {
		result.ReasonCodes = append(result.ReasonCodes, "POLICY_SIMULATION_ONLY")
		if result.ActivePolicy.ActiveExceptions > 0 {
			result.ReasonCodes = append(result.ReasonCodes, "MIGRATION_EXCEPTION_ACTIVE")
		}
	}
	if result.ApplicationStatus == "disabled" {
		result.ReasonCodes = append(result.ReasonCodes, "APPLICATION_DISABLED")
	}
	if result.Observations.Count == 0 {
		result.ReasonCodes = append(result.ReasonCodes, "POSTURE_NOT_OBSERVED")
	}
	if result.Observations.OpenBlockers > 0 {
		result.ReasonCodes = append(result.ReasonCodes, "MIGRATION_BLOCKERS_PRESENT")
	}
	if result.IdentityAdapters.VerificationNeeded > 0 {
		result.ReasonCodes = append(result.ReasonCodes, "IDENTITY_ADAPTER_VERIFICATION_REQUIRED")
	}
	if result.Keys.RotationDue > 0 || result.Keys.Expired > 0 {
		result.ReasonCodes = append(result.ReasonCodes, "KEY_REFERENCES_REQUIRE_ATTENTION")
	}
	result.ReasonCodes = append(result.ReasonCodes, "DATA_PLANE_NOT_IMPLEMENTED")
	if result.ActivePolicy == nil {
		result.NextActions = append(result.NextActions, "Create and activate a policy revision.")
	}
	if result.ApplicationStatus == "disabled" {
		result.NextActions = append(result.NextActions, "Re-enable the application before integrating it.")
	}
	result.NextActions = append(result.NextActions, "Connect a reviewed SDK or gateway before relying on policy decisions for application traffic.")
	result.RequestID = requestID(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listApplicationObservations(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer", "auditor") {
		return
	}
	var applicationExists bool
	if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT EXISTS(
		SELECT 1 FROM applications WHERE tenant_id = $1 AND id = $2)`, contextTenant(r), applicationID).Scan(&applicationExists); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !applicationExists {
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
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT id::text, source, protocol, algorithm_profile, blocker, confidence, observed_at
		FROM migration_observations WHERE tenant_id = $1 AND application_id = $2 AND ($3::uuid IS NULL OR id > $3::uuid)
		ORDER BY id LIMIT $4`, contextTenant(r), applicationID, after, limit+1)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	defer rows.Close()
	type observationView struct {
		ID               string    `json:"id"`
		Source           string    `json:"source"`
		Protocol         string    `json:"protocol"`
		AlgorithmProfile string    `json:"algorithm_profile"`
		Blocker          *string   `json:"blocker"`
		Confidence       string    `json:"confidence"`
		ObservedAt       time.Time `json:"observed_at"`
	}
	items := make([]observationView, 0, limit)
	for rows.Next() {
		var item observationView
		var blocker sql.NullString
		if err := rows.Scan(&item.ID, &item.Source, &item.Protocol, &item.AlgorithmProfile, &blocker, &item.Confidence, &item.ObservedAt); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		if blocker.Valid {
			value := strings.TrimSpace(blocker.String)
			item.Blocker = &value
		}
		item.ObservedAt = item.ObservedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	response := map[string]any{"items": items, "next_cursor": "", "request_id": requestID(r.Context()), "evidence_redacted": true}
	if len(items) > limit {
		items = items[:limit]
		response["items"] = items
		response["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ID))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}
