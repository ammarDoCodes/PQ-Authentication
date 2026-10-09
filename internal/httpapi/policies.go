package httpapi

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxPolicyDocumentBytes = 48 << 10

const policyRegistryVersion int64 = 1

type policyWindow struct {
	StartsAt *time.Time `json:"starts_at"`
	EndsAt   *time.Time `json:"ends_at"`
}

type policyRouteRule struct {
	Method          string   `json:"method"`
	PathPrefix      string   `json:"path_prefix"`
	AllowedProfiles []string `json:"allowed_profiles"`
}

type policyIdentityRequirements struct {
	RequiredACRs []string `json:"required_acrs"`
}

type policyException struct {
	Method              string    `json:"method"`
	PathPrefix          string    `json:"path_prefix"`
	AllowedProfiles     []string  `json:"allowed_profiles"`
	Owner               string    `json:"owner"`
	Reason              string    `json:"reason"`
	ExpiresAt           time.Time `json:"expires_at"`
	CompensatingControl string    `json:"compensating_control"`
}

type policyDocument struct {
	Mode                 string                     `json:"mode"`
	AllowedProfiles      []string                   `json:"allowed_profiles"`
	Fallback             string                     `json:"fallback"`
	StaleBehavior        string                     `json:"stale_behavior"`
	RouteRules           []policyRouteRule          `json:"route_rules"`
	IdentityRequirements policyIdentityRequirements `json:"identity_requirements"`
	Exceptions           []policyException          `json:"exceptions"`
	EffectiveWindow      *policyWindow              `json:"effective_window"`
}

type policyView struct {
	ID                 string         `json:"id"`
	TenantID           string         `json:"tenant_id"`
	ApplicationID      string         `json:"application_id"`
	Revision           int64          `json:"revision"`
	State              string         `json:"state"`
	Document           policyDocument `json:"document"`
	ContentHash        string         `json:"content_hash"`
	CreatedBy          string         `json:"created_by"`
	CreatedAt          time.Time      `json:"created_at"`
	EffectiveAt        *time.Time     `json:"effective_at,omitempty"`
	RetiredAt          *time.Time     `json:"retired_at,omitempty"`
	LifecycleUpdatedAt time.Time      `json:"lifecycle_updated_at"`
	LifecycleVersion   int64          `json:"lifecycle_version"`
	ETag               string         `json:"etag"`
	RequestID          string         `json:"request_id"`
}

type policyScanner interface {
	Scan(...any) error
}

const policySelectColumns = `id::text, tenant_id::text, application_id::text, revision, state,
	document::text, content_hash, created_by, created_at, effective_at, retired_at, lifecycle_updated_at, lifecycle_version`

type policyProfile struct {
	Mode            string `json:"mode"`
	Provider        string `json:"provider"`
	ProviderVersion string `json:"provider_version"`
	UseCase         string `json:"use_case"`
	SourceReference string `json:"source_reference"`
}

var policyProfiles = map[string]policyProfile{
	"tls13-classical": {
		Mode: "classical-approved", Provider: "Go crypto/tls", ProviderVersion: "Go 1.27.1",
		UseCase: "transport", SourceReference: "https://go.dev/doc/go1.27",
	},
	"tls13-x25519-mlkem768": {
		Mode: "hybrid-approved", Provider: "Go crypto/tls", ProviderVersion: "Go 1.27.1",
		UseCase: "transport", SourceReference: "https://go.dev/src/crypto/tls/common.go",
	},
}

func (s *Server) listApplicationPolicies(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer", "auditor") {
		return
	}
	var exists bool
	if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT EXISTS (
		SELECT 1 FROM applications WHERE tenant_id = $1 AND id = $2)`, contextTenant(r), applicationID).Scan(&exists); err != nil {
		policyUnavailable(w, r)
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
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		parsed, parseErr := strconv.ParseInt(string(decoded), 10, 64)
		if err != nil || parseErr != nil || parsed < 1 {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_CURSOR", "Invalid request", "The pagination cursor is invalid.", false)
			return
		}
		after = parsed
	}
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT `+policySelectColumns+`
		FROM policy_revisions WHERE tenant_id = $1 AND application_id = $2
		AND ($3::bigint IS NULL OR revision < $3) ORDER BY revision DESC LIMIT $4`, contextTenant(r), applicationID, after, limit+1)
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	defer rows.Close()
	items := make([]policyView, 0, limit)
	for rows.Next() {
		item, err := scanPolicy(rows)
		if err != nil {
			policyUnavailable(w, r)
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		policyUnavailable(w, r)
		return
	}
	response := map[string]any{"items": items, "next_cursor": "", "request_id": requestID(r.Context())}
	if len(items) > limit {
		items = items[:limit]
		response["items"] = items
		response["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(items[len(items)-1].Revision, 10)))
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	var document policyDocument
	if err := decodeControlJSON(w, r, &document); err != nil || validatePolicyDocument(document, time.Now().UTC()) != nil {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_POLICY", "Invalid request", "The policy document is invalid or references an unsupported profile.", false)
		return
	}
	canonical, err := json.Marshal(document)
	if err != nil || len(canonical) > maxPolicyDocumentBytes {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_POLICY", "Invalid request", "The policy document exceeds the allowed size.", false)
		return
	}
	contentHash := sha256.Sum256(canonical)
	tx := contextTransaction(r)
	var lockedApplication string
	err = tx.QueryRowContext(r.Context(), `SELECT id::text FROM applications
		WHERE tenant_id = $1 AND id = $2 AND status = 'active' FOR UPDATE`, contextTenant(r), applicationID).Scan(&lockedApplication)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	var revision int64
	if err := tx.QueryRowContext(r.Context(), `SELECT COALESCE(MAX(revision), 0) + 1 FROM policy_revisions
		WHERE tenant_id = $1 AND application_id = $2`, contextTenant(r), applicationID).Scan(&revision); err != nil {
		policyUnavailable(w, r)
		return
	}
	createdBy := policyActor(contextPrincipal(r))
	item, err := insertPolicy(r, applicationID, revision, "draft", document, canonical, contentHash[:], createdBy, nil)
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()), "policy.draft.created", "policy_revision", item.ID, "success", "DRAFT_CREATED"); err != nil {
		policyUnavailable(w, r)
		return
	}
	item.RequestID = requestID(r.Context())
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := r.PathValue("policy_id")
	if !validUUID(policyID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer", "auditor") {
		return
	}
	item, err := scanPolicy(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+policySelectColumns+`
		FROM policy_revisions WHERE tenant_id = $1 AND id = $2`, contextTenant(r), policyID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	item.RequestID = requestID(r.Context())
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) simulatePolicy(w http.ResponseWriter, r *http.Request) {
	policyID := r.PathValue("policy_id")
	if !validUUID(policyID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer") {
		return
	}
	var input struct {
		Method      string `json:"method"`
		Path        string `json:"path"`
		ProfileID   string `json:"profile_id"`
		IdentityACR string `json:"identity_acr"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validPolicyMethod(input.Method) || !validPolicyPath(input.Path) ||
		!knownPolicyProfile(input.ProfileID) || input.IdentityACR != "" && !validBoundedToken(input.IdentityACR, 512) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_SIMULATION", "Invalid request", "The simulation context is invalid.", false)
		return
	}
	item, err := scanPolicy(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+policySelectColumns+`
		FROM policy_revisions WHERE tenant_id = $1 AND id = $2`, contextTenant(r), policyID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	decision, reasons := evaluatePolicy(item.Document, input.Method, input.Path, input.ProfileID, input.IdentityACR, time.Now().UTC())
	var expiresAt any
	if item.Document.EffectiveWindow.EndsAt != nil {
		expiresAt = item.Document.EffectiveWindow.EndsAt.UTC()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_revision_id": item.ID, "mode": item.Document.Mode, "decision": decision,
		"reason_codes": reasons, "expires_at": expiresAt, "request_id": requestID(r.Context()),
	})
}

func (s *Server) activatePolicy(w http.ResponseWriter, r *http.Request) {
	item, ok := s.lockPolicyForTransition(w, r, "tenant_admin", "security_engineer")
	if !ok {
		return
	}
	if item.State != "draft" && item.State != "scheduled" {
		policyStateConflict(w, r)
		return
	}
	if !s.matchPolicyETag(w, r, item.ID, item.LifecycleVersion) {
		return
	}
	if item.State == "scheduled" {
		if err := cancelPolicySchedule(r, item.TenantID, item.ID); err != nil {
			policyUnavailable(w, r)
			return
		}
	}
	if _, err := contextTransaction(r).ExecContext(r.Context(), `UPDATE policy_revisions SET state = 'retired', retired_at = now(), lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND application_id = $2 AND state = 'active' AND id <> $3`, contextTenant(r), item.ApplicationID, item.ID); err != nil {
		policyUnavailable(w, r)
		return
	}
	if _, err := contextTransaction(r).ExecContext(r.Context(), `UPDATE policy_revisions
		SET state = 'active', effective_at = now(), retired_at = NULL, lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND id = $2`, contextTenant(r), item.ID); err != nil {
		policyUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "policy.activated", "policy_revision", item.ID, "success", "ACTIVATED"); err != nil {
		policyUnavailable(w, r)
		return
	}
	s.writeUpdatedPolicy(w, r, item.ID, http.StatusOK)
}

func (s *Server) schedulePolicy(w http.ResponseWriter, r *http.Request) {
	item, ok := s.lockPolicyForTransition(w, r, "tenant_admin", "security_engineer")
	if !ok {
		return
	}
	if item.State != "draft" {
		policyStateConflict(w, r)
		return
	}
	if !s.matchPolicyETag(w, r, item.ID, item.LifecycleVersion) {
		return
	}
	var input struct {
		EffectiveAt *time.Time `json:"effective_at"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || input.EffectiveAt == nil {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_SCHEDULE", "Invalid request", "A future effective_at timestamp is required.", false)
		return
	}
	now := time.Now().UTC()
	if !input.EffectiveAt.After(now.Add(30*time.Second)) || input.EffectiveAt.After(now.Add(90*24*time.Hour)) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_SCHEDULE", "Invalid request", "The activation time must be at least 30 seconds and no more than 90 days ahead.", false)
		return
	}
	if item.Document.EffectiveWindow.StartsAt != nil && input.EffectiveAt.Before(*item.Document.EffectiveWindow.StartsAt) ||
		item.Document.EffectiveWindow.EndsAt != nil && !input.EffectiveAt.Before(*item.Document.EffectiveWindow.EndsAt) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_SCHEDULE", "Invalid request", "The activation time falls outside the policy effective window.", false)
		return
	}
	if _, err := contextTransaction(r).ExecContext(r.Context(), `UPDATE policy_revisions
		SET state = 'scheduled', effective_at = $3, retired_at = NULL, lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND id = $2`, contextTenant(r), item.ID, input.EffectiveAt.UTC()); err != nil {
		policyUnavailable(w, r)
		return
	}
	if err := schedulePolicy(r, item.TenantID, item.ID, input.EffectiveAt.UTC()); err != nil {
		policyUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "policy.scheduled", "policy_revision", item.ID, "success", "SCHEDULED"); err != nil {
		policyUnavailable(w, r)
		return
	}
	s.writeUpdatedPolicy(w, r, item.ID, http.StatusOK)
}

func (s *Server) retirePolicy(w http.ResponseWriter, r *http.Request) {
	item, ok := s.lockPolicyForTransition(w, r, "tenant_admin", "security_engineer")
	if !ok {
		return
	}
	if item.State == "retired" {
		policyStateConflict(w, r)
		return
	}
	if !s.matchPolicyETag(w, r, item.ID, item.LifecycleVersion) {
		return
	}
	if item.State == "scheduled" {
		if err := cancelPolicySchedule(r, item.TenantID, item.ID); err != nil {
			policyUnavailable(w, r)
			return
		}
	}
	if _, err := contextTransaction(r).ExecContext(r.Context(), `UPDATE policy_revisions
		SET state = 'retired', retired_at = now(), lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND id = $2`, contextTenant(r), item.ID); err != nil {
		policyUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "policy.retired", "policy_revision", item.ID, "success", "RETIRED"); err != nil {
		policyUnavailable(w, r)
		return
	}
	s.writeUpdatedPolicy(w, r, item.ID, http.StatusOK)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	item, ok := s.lockPolicyForTransition(w, r, "tenant_admin", "security_engineer")
	if !ok {
		return
	}
	if item.State != "active" {
		policyStateConflict(w, r)
		return
	}
	if !s.matchPolicyETag(w, r, item.ID, item.LifecycleVersion) {
		return
	}
	var input struct {
		TargetRevisionID string `json:"target_revision_id"`
		ReasonCode       string `json:"reason_code"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validUUID(input.TargetRevisionID) ||
		!oneOf(input.ReasonCode, "ROLLBACK_COMPATIBILITY", "ROLLBACK_SECURITY", "ROLLBACK_INCIDENT", "ROLLBACK_OTHER") {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_ROLLBACK", "Invalid request", "A prior revision and approved reason code are required.", false)
		return
	}
	tx := contextTransaction(r)
	target, err := scanPolicy(tx.QueryRowContext(r.Context(), `SELECT `+policySelectColumns+`
		FROM policy_revisions WHERE tenant_id = $1 AND application_id = $2 AND id = $3 AND state = 'retired' AND revision < $4 FOR UPDATE`,
		contextTenant(r), item.ApplicationID, input.TargetRevisionID, item.Revision))
	if errors.Is(err, sql.ErrNoRows) {
		writeProblem(w, r, http.StatusConflict, "ROLLBACK_TARGET_UNAVAILABLE", "Conflict", "The requested prior policy revision is unavailable.", false)
		return
	}
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	var revision int64
	if err := tx.QueryRowContext(r.Context(), `SELECT COALESCE(MAX(revision), 0) + 1 FROM policy_revisions
		WHERE tenant_id = $1 AND application_id = $2`, contextTenant(r), item.ApplicationID).Scan(&revision); err != nil {
		policyUnavailable(w, r)
		return
	}
	canonical, err := json.Marshal(target.Document)
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	contentHash := sha256.Sum256(canonical)
	if _, err := tx.ExecContext(r.Context(), `UPDATE policy_revisions
		SET state = 'retired', retired_at = now(), lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND id = $2`, contextTenant(r), item.ID); err != nil {
		policyUnavailable(w, r)
		return
	}
	created, err := insertPolicy(r, item.ApplicationID, revision, "active", target.Document, canonical, contentHash[:], policyActor(contextPrincipal(r)), time.Now().UTC())
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()), "policy.rolled_back", "policy_revision", created.ID, "success", input.ReasonCode); err != nil {
		policyUnavailable(w, r)
		return
	}
	created.RequestID = requestID(r.Context())
	w.Header().Set("ETag", created.ETag)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) lockPolicyForTransition(w http.ResponseWriter, r *http.Request, roles ...string) (policyView, bool) {
	policyID := r.PathValue("policy_id")
	if !validUUID(policyID) {
		s.notFound(w, r)
		return policyView{}, false
	}
	if !s.requireRole(w, r, roles...) {
		return policyView{}, false
	}
	item, err := scanPolicy(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+policySelectColumns+`
		FROM policy_revisions WHERE tenant_id = $1 AND id = $2`, contextTenant(r), policyID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return policyView{}, false
	}
	if err != nil {
		policyUnavailable(w, r)
		return policyView{}, false
	}
	var lockedApplication string
	if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text FROM applications
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, contextTenant(r), item.ApplicationID).Scan(&lockedApplication); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.notFound(w, r)
			return policyView{}, false
		}
		policyUnavailable(w, r)
		return policyView{}, false
	}
	item, err = scanPolicy(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+policySelectColumns+`
		FROM policy_revisions WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, contextTenant(r), policyID))
	if err != nil {
		policyUnavailable(w, r)
		return policyView{}, false
	}
	return item, true
}

func (s *Server) matchPolicyETag(w http.ResponseWriter, r *http.Request, policyID string, lifecycleVersion int64) bool {
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the policy and send its ETag in If-Match.", false)
		return false
	}
	if r.Header.Get("If-Match") != policyETag(policyID, lifecycleVersion) {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Policy changed", "Fetch the policy again before retrying the transition.", false)
		return false
	}
	return true
}

func (s *Server) writeUpdatedPolicy(w http.ResponseWriter, r *http.Request, policyID string, status int) {
	item, err := scanPolicy(contextTransaction(r).QueryRowContext(r.Context(), `SELECT `+policySelectColumns+`
		FROM policy_revisions WHERE tenant_id = $1 AND id = $2`, contextTenant(r), policyID))
	if err != nil {
		policyUnavailable(w, r)
		return
	}
	item.RequestID = requestID(r.Context())
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, status, item)
}

func insertPolicy(r *http.Request, applicationID string, revision int64, state string, document policyDocument, canonical, contentHash []byte, createdBy string, effectiveAt any) (policyView, error) {
	query := `INSERT INTO policy_revisions
		(tenant_id, application_id, revision, state, document, content_hash, created_by, effective_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8) RETURNING ` + policySelectColumns
	return scanPolicy(contextTransaction(r).QueryRowContext(r.Context(), query,
		contextTenant(r), applicationID, revision, state, canonical, contentHash, createdBy, effectiveAt))
}

func scanPolicy(row policyScanner) (policyView, error) {
	var item policyView
	var documentJSON string
	var contentHash []byte
	var effectiveAt, retiredAt sql.NullTime
	err := row.Scan(&item.ID, &item.TenantID, &item.ApplicationID, &item.Revision, &item.State, &documentJSON,
		&contentHash, &item.CreatedBy, &item.CreatedAt, &effectiveAt, &retiredAt, &item.LifecycleUpdatedAt, &item.LifecycleVersion)
	if err != nil {
		return policyView{}, err
	}
	if err := json.Unmarshal([]byte(documentJSON), &item.Document); err != nil || len(contentHash) != sha256.Size {
		return policyView{}, errors.New("stored policy is invalid")
	}
	item.ContentHash = hex.EncodeToString(contentHash)
	if effectiveAt.Valid {
		value := effectiveAt.Time.UTC()
		item.EffectiveAt = &value
	}
	if retiredAt.Valid {
		value := retiredAt.Time.UTC()
		item.RetiredAt = &value
	}
	item.CreatedAt = item.CreatedAt.UTC()
	item.LifecycleUpdatedAt = item.LifecycleUpdatedAt.UTC()
	item.ETag = policyETag(item.ID, item.LifecycleVersion)
	return item, nil
}

func policyETag(policyID string, version int64) string {
	return `"` + policyID + ":" + strconv.FormatInt(version, 10) + `"`
}

func validatePolicyDocument(document policyDocument, now time.Time) error {
	if document.AllowedProfiles == nil || document.RouteRules == nil || document.IdentityRequirements.RequiredACRs == nil ||
		document.Exceptions == nil || document.EffectiveWindow == nil {
		return errors.New("required policy fields are missing")
	}
	if !oneOf(document.Mode, "classical-approved", "hybrid-approved", "observe-only") ||
		!oneOf(document.Fallback, "deny", "observe", "degraded_allowed") ||
		!oneOf(document.StaleBehavior, "deny", "observe", "degraded_allowed") {
		return errors.New("unsupported policy mode or behavior")
	}
	if len(document.AllowedProfiles) == 0 || len(document.AllowedProfiles) > 16 || len(document.RouteRules) > 100 ||
		len(document.Exceptions) > 100 || len(document.IdentityRequirements.RequiredACRs) > 16 {
		return errors.New("policy collection is outside its allowed size")
	}
	allowed := make(map[string]struct{}, len(document.AllowedProfiles))
	for _, profileID := range document.AllowedProfiles {
		if !knownPolicyProfile(profileID) {
			return errors.New("unknown policy profile")
		}
		if _, exists := allowed[profileID]; exists {
			return errors.New("duplicate allowed profile")
		}
		allowed[profileID] = struct{}{}
		if document.Mode != "observe-only" && policyProfiles[profileID].Mode != document.Mode {
			return errors.New("profile does not match the selected policy mode")
		}
	}
	acrs := make(map[string]struct{}, len(document.IdentityRequirements.RequiredACRs))
	for _, acr := range document.IdentityRequirements.RequiredACRs {
		if !validBoundedToken(acr, 512) {
			return errors.New("invalid required authentication context")
		}
		if _, exists := acrs[acr]; exists {
			return errors.New("duplicate authentication context")
		}
		acrs[acr] = struct{}{}
	}
	if document.EffectiveWindow.StartsAt != nil && document.EffectiveWindow.EndsAt != nil && !document.EffectiveWindow.EndsAt.After(*document.EffectiveWindow.StartsAt) {
		return errors.New("policy effective window is empty")
	}
	if document.EffectiveWindow.EndsAt != nil && !document.EffectiveWindow.EndsAt.After(now) {
		return errors.New("policy effective window has expired")
	}
	rules := make(map[string]struct{}, len(document.RouteRules))
	for _, rule := range document.RouteRules {
		if !validPolicyMethod(rule.Method) || !validPolicyPath(rule.PathPrefix) || len(rule.AllowedProfiles) == 0 || len(rule.AllowedProfiles) > 16 {
			return errors.New("invalid route rule")
		}
		key := rule.Method + "\x00" + rule.PathPrefix
		if _, exists := rules[key]; exists {
			return errors.New("duplicate route rule")
		}
		rules[key] = struct{}{}
		if err := validateProfileSubset(rule.AllowedProfiles, allowed); err != nil {
			return err
		}
	}
	for _, exception := range document.Exceptions {
		if !validPolicyMethod(exception.Method) || !validPolicyPath(exception.PathPrefix) || len(exception.AllowedProfiles) == 0 ||
			len(exception.AllowedProfiles) > 16 || !validLabel(exception.Owner, 120) || !validLabel(exception.Reason, 512) ||
			!validLabel(exception.CompensatingControl, 512) || !exception.ExpiresAt.After(now) || exception.ExpiresAt.After(now.Add(90*24*time.Hour)) {
			return errors.New("invalid migration exception")
		}
		for _, profileID := range exception.AllowedProfiles {
			if !knownPolicyProfile(profileID) {
				return errors.New("exception references an unsupported profile")
			}
		}
	}
	return nil
}

func validateProfileSubset(profiles []string, allowed map[string]struct{}) error {
	seen := make(map[string]struct{}, len(profiles))
	for _, profileID := range profiles {
		if !knownPolicyProfile(profileID) {
			return errors.New("unknown route profile")
		}
		if _, ok := allowed[profileID]; !ok {
			return errors.New("route profile is not enabled by the policy")
		}
		if _, duplicate := seen[profileID]; duplicate {
			return errors.New("duplicate route profile")
		}
		seen[profileID] = struct{}{}
	}
	return nil
}

func knownPolicyProfile(id string) bool {
	_, ok := policyProfiles[id]
	return ok
}

func validPolicyMethod(method string) bool {
	return oneOf(method, "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
}

func validPolicyPath(path string) bool {
	if len(path) == 0 || len(path) > 1024 || path[0] != '/' || strings.ContainsAny(path, "?#%\\") || strings.Contains(path, "..") || strings.TrimSpace(path) != path {
		return false
	}
	for _, r := range path {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && parsed.Path == path && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validBoundedToken(value string, max int) bool {
	if len(value) == 0 || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func evaluatePolicy(document policyDocument, method, path, profileID, identityACR string, now time.Time) (string, []string) {
	decision := "allow"
	reasons := []string{"POLICY_MATCH"}
	fallback := func(value, reason string) (string, []string) { return value, []string{reason} }
	if document.Mode == "observe-only" {
		return "observe", []string{"OBSERVE_ONLY"}
	}
	if document.EffectiveWindow.StartsAt != nil && now.Before(*document.EffectiveWindow.StartsAt) ||
		document.EffectiveWindow.EndsAt != nil && !now.Before(*document.EffectiveWindow.EndsAt) {
		return fallback(document.StaleBehavior, "POLICY_OUTSIDE_EFFECTIVE_WINDOW")
	}
	if len(document.IdentityRequirements.RequiredACRs) > 0 && !containsString(document.IdentityRequirements.RequiredACRs, identityACR) {
		return "step_up", []string{"IDENTITY_STEP_UP_REQUIRED"}
	}
	for _, exception := range document.Exceptions {
		if exception.Method == method && strings.HasPrefix(path, exception.PathPrefix) && exception.ExpiresAt.After(now) && containsString(exception.AllowedProfiles, profileID) {
			return "degraded_allowed", []string{"MIGRATION_EXCEPTION_ACTIVE"}
		}
	}
	var selected *policyRouteRule
	for index := range document.RouteRules {
		rule := &document.RouteRules[index]
		if rule.Method == method && strings.HasPrefix(path, rule.PathPrefix) && (selected == nil || len(rule.PathPrefix) > len(selected.PathPrefix)) {
			selected = rule
		}
	}
	if len(document.RouteRules) > 0 && selected == nil {
		return fallback(document.Fallback, "NO_ROUTE_RULE")
	}
	allowed := document.AllowedProfiles
	if selected != nil {
		allowed = selected.AllowedProfiles
	}
	if containsString(allowed, profileID) {
		return decision, reasons
	}
	return fallback(document.Fallback, "PROFILE_NOT_ALLOWED")
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func policyActor(principal tenantPrincipal) string {
	hash := sha256.Sum256([]byte(principal.Issuer + "\x00" + principal.Subject))
	return "oidc:" + base64.RawURLEncoding.EncodeToString(hash[:])
}

func schedulePolicy(r *http.Request, tenantID, policyID string, effectiveAt time.Time) error {
	_, err := contextTransaction(r).ExecContext(r.Context(), "SELECT qg_schedule_policy($1, $2, $3)", tenantID, policyID, effectiveAt)
	return err
}

func cancelPolicySchedule(r *http.Request, tenantID, policyID string) error {
	_, err := contextTransaction(r).ExecContext(r.Context(), "SELECT qg_cancel_policy_schedule($1, $2)", tenantID, policyID)
	return err
}

func policyUnavailable(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusServiceUnavailable, "POLICY_UNAVAILABLE", "Service unavailable", "The policy request could not be processed safely.", true)
}

func policyStateConflict(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusConflict, "POLICY_STATE_CONFLICT", "Conflict", "The policy revision is not in a state that permits this transition.", false)
}
