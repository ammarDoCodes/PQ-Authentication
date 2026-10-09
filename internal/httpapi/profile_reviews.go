package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type profileDesignRecord struct {
	StandardProfile        string   `json:"standard_profile"`
	ClassicalMechanisms    []string `json:"classical_mechanisms"`
	PQCMechanisms          []string `json:"pqc_mechanisms"`
	KeyPurposeAndLifecycle string   `json:"key_purpose_and_lifecycle"`
	DowngradeDetection     string   `json:"downgrade_detection"`
	TranscriptBinding      string   `json:"transcript_binding"`
	TestVectors            []string `json:"test_vectors"`
	InteropPartners        []string `json:"interop_partners"`
	DeprecationPlan        string   `json:"deprecation_plan"`
	RollbackPlan           string   `json:"rollback_plan"`
}

type algorithmProfileView struct {
	ID              string               `json:"id"`
	Mode            string               `json:"mode"`
	Provider        string               `json:"provider"`
	ProviderVersion string               `json:"provider_version"`
	UseCase         string               `json:"use_case"`
	Status          string               `json:"status"`
	SourceReference string               `json:"source_reference"`
	RegistryVersion int64                `json:"registry_version"`
	ReviewState     string               `json:"review_state"`
	ReviewID        string               `json:"review_id,omitempty"`
	ReviewRevision  int64                `json:"review_revision,omitempty"`
	ReviewETag      string               `json:"review_etag,omitempty"`
	ReviewedAt      *time.Time           `json:"reviewed_at,omitempty"`
	ProfileHash     string               `json:"profile_hash,omitempty"`
	DesignRecord    *profileDesignRecord `json:"design_record,omitempty"`
}

type profileReviewRecord struct {
	ID               string
	TenantID         string
	ProfileID        string
	Provider         string
	ProviderVersion  string
	UseCase          string
	SourceReference  string
	RegistryVersion  int64
	Revision         int64
	Lifecycle        string
	LifecycleVersion int64
	SubmittedBy      string
	CreatedAt        time.Time
	ReviewedBy       sql.NullString
	ReviewedAt       sql.NullTime
	ReviewReference  sql.NullString
	ProfileHash      []byte
	EvidenceJSON     []byte
}

func profileApproved(ctx context.Context, tx *sql.Tx, tenantID, profileID string) (bool, error) {
	definition, known := policyProfiles[profileID]
	if !known {
		return false, nil
	}
	fingerprint := profileDefinitionHash(profileID)
	var approvedID string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM algorithm_profiles
		WHERE tenant_id = $1 AND registry_version = $2 AND profile_id = $3 AND lifecycle = 'approved'
		AND provider = $4 AND provider_version = $5 AND use_case = $6 AND source_reference = $7
		AND profile_hash = $8 AND submitted_by <> reviewed_by AND reviewed_at IS NOT NULL
		FOR SHARE`, tenantID, policyRegistryVersion, profileID, definition.Provider, definition.ProviderVersion,
		definition.UseCase, definition.SourceReference, fingerprint[:]).Scan(&approvedID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && approvedID != "", err
}

func (s *Server) listAlgorithmProfiles(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer", "auditor") {
		return
	}
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT id::text, profile_id, provider,
		provider_version, use_case, source_reference, revision, lifecycle, lifecycle_version, reviewed_at,
		profile_hash, review_evidence::text
		FROM algorithm_profiles WHERE tenant_id = $1 AND registry_version = $2
		ORDER BY profile_id, revision DESC`, contextTenant(r), policyRegistryVersion)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	defer rows.Close()
	type currentReview struct {
		id              string
		provider        string
		providerVersion string
		useCase         string
		sourceReference string
		revision        int64
		state           string
		version         int64
		reviewedAt      sql.NullTime
		hash            []byte
		evidence        []byte
	}
	latest := make(map[string]currentReview, len(policyProfiles))
	for rows.Next() {
		var profileID string
		var item currentReview
		var evidence sql.NullString
		if err := rows.Scan(&item.id, &profileID, &item.provider, &item.providerVersion, &item.useCase,
			&item.sourceReference, &item.revision, &item.state, &item.version, &item.reviewedAt, &item.hash, &evidence); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		if _, exists := latest[profileID]; !exists {
			item.evidence = []byte(evidence.String)
			latest[profileID] = item
		}
	}
	if err := rows.Err(); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	profileIDs := make([]string, 0, len(policyProfiles))
	for id := range policyProfiles {
		profileIDs = append(profileIDs, id)
	}
	sort.Strings(profileIDs)
	profiles := make([]algorithmProfileView, 0, len(profileIDs))
	for _, id := range profileIDs {
		definition := policyProfiles[id]
		item := algorithmProfileView{
			ID: id, Mode: definition.Mode, Provider: definition.Provider, ProviderVersion: definition.ProviderVersion,
			UseCase: definition.UseCase, Status: "simulation-only", SourceReference: definition.SourceReference,
			RegistryVersion: policyRegistryVersion, ReviewState: "not_submitted",
		}
		if review, ok := latest[id]; ok {
			item.ReviewID = review.id
			item.ReviewRevision = review.revision
			item.ReviewETag = profileReviewETag(review.id, review.version)
			item.ReviewState = review.state
			if review.reviewedAt.Valid {
				reviewedAt := review.reviewedAt.Time.UTC()
				item.ReviewedAt = &reviewedAt
			}
			fingerprint := profileDefinitionHash(id)
			var evidence profileDesignRecord
			evidenceValid := json.Unmarshal(review.evidence, &evidence) == nil && validProfileDesignRecord(definition.Mode, evidence)
			if len(review.hash) != sha256.Size || !bytes.Equal(review.hash, fingerprint[:]) ||
				!matchesProfileDefinition(id, review.provider, review.providerVersion, review.useCase, review.sourceReference) || !evidenceValid {
				item.ReviewState = "stale"
			} else if review.state == "approved" {
				item.Status = "approved"
			} else if oneOf(review.state, "rejected", "disabled", "deprecated") {
				item.Status = review.state
			}
			item.ProfileHash = hex.EncodeToString(review.hash)
			if contextRole(r) == "security_engineer" && evidenceValid {
				item.DesignRecord = &evidence
			}
		}
		profiles = append(profiles, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"registry_version": policyRegistryVersion, "profiles": profiles, "request_id": requestID(r.Context())})
}

func (s *Server) submitProfileReview(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "security_engineer") {
		return
	}
	profileID := r.PathValue("profile_id")
	definition, known := policyProfiles[profileID]
	var input struct {
		DesignRecord profileDesignRecord `json:"design_record"`
	}
	if !known || decodeControlJSON(w, r, &input) != nil || !validProfileDesignRecord(definition.Mode, input.DesignRecord) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_PROFILE_REVIEW", "Invalid request", "A registered profile and complete design record are required.", false)
		return
	}
	evidenceJSON, err := json.Marshal(input.DesignRecord)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	fingerprint := profileDefinitionHash(profileID)
	tx := contextTransaction(r)
	var lockedTenant string
	if err := tx.QueryRowContext(r.Context(), `SELECT id::text FROM tenants WHERE id = $1 FOR UPDATE`, contextTenant(r)).Scan(&lockedTenant); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var existing bool
	if err := tx.QueryRowContext(r.Context(), `SELECT EXISTS (
		SELECT 1 FROM algorithm_profiles WHERE tenant_id = $1 AND profile_id = $2 AND lifecycle = 'pending_review'
	) OR EXISTS (
		SELECT 1 FROM algorithm_profiles WHERE tenant_id = $1 AND registry_version = $3 AND profile_id = $2 AND lifecycle = 'approved'
		AND provider = $4 AND provider_version = $5 AND use_case = $6 AND source_reference = $7 AND profile_hash = $8
	)`, contextTenant(r), profileID, policyRegistryVersion, definition.Provider, definition.ProviderVersion,
		definition.UseCase, definition.SourceReference, fingerprint[:]).Scan(&existing); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if existing {
		writeProblem(w, r, http.StatusConflict, "PROFILE_REVIEW_EXISTS", "Conflict", "This profile version already has a pending or approved review.", false)
		return
	}
	staleRows, err := tx.QueryContext(r.Context(), `UPDATE algorithm_profiles SET lifecycle = 'disabled', lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND profile_id = $2 AND lifecycle = 'approved'
		AND (registry_version <> $3 OR provider IS DISTINCT FROM $4 OR provider_version IS DISTINCT FROM $5 OR
			use_case IS DISTINCT FROM $6 OR source_reference IS DISTINCT FROM $7 OR profile_hash IS DISTINCT FROM $8)
		RETURNING id::text`, contextTenant(r), profileID, policyRegistryVersion, definition.Provider,
		definition.ProviderVersion, definition.UseCase, definition.SourceReference, fingerprint[:])
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var invalidatedIDs []string
	for staleRows.Next() {
		var invalidatedID string
		if err := staleRows.Scan(&invalidatedID); err != nil {
			_ = staleRows.Close()
			controlPlaneUnavailable(w, r)
			return
		}
		invalidatedIDs = append(invalidatedIDs, invalidatedID)
	}
	if err := staleRows.Err(); err != nil {
		_ = staleRows.Close()
		controlPlaneUnavailable(w, r)
		return
	}
	if err := staleRows.Close(); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	for _, invalidatedID := range invalidatedIDs {
		if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()), "algorithm_profile.invalidated",
			"algorithm_profile_review", invalidatedID, "success", "PROFILE_DEFINITION_CHANGED"); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
	}
	var revision int64
	if err := tx.QueryRowContext(r.Context(), `SELECT COALESCE(MAX(revision), 0) + 1 FROM algorithm_profiles
		WHERE tenant_id = $1 AND registry_version = $2 AND profile_id = $3`,
		contextTenant(r), policyRegistryVersion, profileID).Scan(&revision); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var record profileReviewRecord
	err = tx.QueryRowContext(r.Context(), `INSERT INTO algorithm_profiles
		(tenant_id, registry_version, profile_id, provider, provider_version, use_case, lifecycle,
		 source_reference, reviewed_at, revision, submitted_by, review_evidence, profile_hash)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending_review', $7, NULL, $8, $9, $10::jsonb, $11)
		RETURNING id::text, tenant_id::text, profile_id, registry_version, revision, lifecycle, lifecycle_version,
			submitted_by, created_at, reviewed_by, reviewed_at, review_reference, profile_hash, review_evidence::text`,
		contextTenant(r), policyRegistryVersion, profileID, definition.Provider, definition.ProviderVersion, definition.UseCase,
		definition.SourceReference, revision, auditActor(contextPrincipal(r)), evidenceJSON, fingerprint[:]).Scan(
		&record.ID, &record.TenantID, &record.ProfileID, &record.RegistryVersion, &record.Revision, &record.Lifecycle,
		&record.LifecycleVersion, &record.SubmittedBy, &record.CreatedAt, &record.ReviewedBy, &record.ReviewedAt, &record.ReviewReference,
		&record.ProfileHash, &record.EvidenceJSON)
	if err != nil {
		writeDatabaseProblem(w, r, err, "PROFILE_REVIEW_CONFLICT")
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()), "algorithm_profile.review_submitted",
		"algorithm_profile_review", record.ID, "success", "REVIEW_SUBMITTED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("ETag", profileReviewETag(record.ID, record.LifecycleVersion))
	w.Header().Set("Location", "/v1/tenants/"+contextTenant(r)+"/algorithm-profile-reviews/"+record.ID)
	writeJSON(w, http.StatusCreated, profileReviewResponse(record, requestID(r.Context())))
}

func (s *Server) approveProfileReview(w http.ResponseWriter, r *http.Request) {
	s.reviewProfile(w, r, "approved")
}

func (s *Server) getProfileReview(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "security_engineer", "auditor") {
		return
	}
	reviewID := r.PathValue("review_id")
	if !validUUID(reviewID) {
		s.notFound(w, r)
		return
	}
	record, err := scanProfileReview(contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text, tenant_id::text,
		profile_id, provider, provider_version, use_case, source_reference, registry_version, revision, lifecycle, lifecycle_version, submitted_by, created_at,
		reviewed_by, reviewed_at, review_reference, profile_hash, review_evidence::text
		FROM algorithm_profiles WHERE tenant_id = $1 AND id = $2`, contextTenant(r), reviewID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if len(record.EvidenceJSON) != 0 {
		definition, known := policyProfiles[record.ProfileID]
		var evidence profileDesignRecord
		if !known || json.Unmarshal(record.EvidenceJSON, &evidence) != nil || !validProfileDesignRecord(definition.Mode, evidence) {
			controlPlaneUnavailable(w, r)
			return
		}
	} else if oneOf(record.Lifecycle, "pending_review", "approved", "rejected") {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("ETag", profileReviewETag(record.ID, record.LifecycleVersion))
	writeJSON(w, http.StatusOK, profileReviewResponse(record, requestID(r.Context())))
}

func (s *Server) rejectProfileReview(w http.ResponseWriter, r *http.Request) {
	s.reviewProfile(w, r, "rejected")
}

func (s *Server) reviewProfile(w http.ResponseWriter, r *http.Request, outcome string) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "security_engineer") {
		return
	}
	reviewID := r.PathValue("review_id")
	if !validUUID(reviewID) {
		s.notFound(w, r)
		return
	}
	if !requireProfileReviewETag(w, r, reviewID) {
		return
	}
	var input struct {
		ReviewReference string `json:"review_reference"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validHTTPSReference(input.ReviewReference) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_PROFILE_REVIEW", "Invalid request", "A review evidence HTTPS reference is required.", false)
		return
	}
	record, err := lockProfileReview(r, reviewID)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !matchProfileReviewETag(w, r, record) {
		return
	}
	if record.Lifecycle != "pending_review" {
		writeProblem(w, r, http.StatusConflict, "PROFILE_REVIEW_STATE_CONFLICT", "Conflict", "Only a pending profile review can be approved or rejected.", false)
		return
	}
	principal := contextPrincipal(r)
	if auditActor(principal) == record.SubmittedBy {
		if err := insertAudit(r.Context(), contextTransaction(r), principal, requestID(r.Context()), "algorithm_profile.review_denied",
			"algorithm_profile_review", record.ID, "denied", "SELF_REVIEW_REJECTED"); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		writeProblem(w, r, http.StatusForbidden, "INDEPENDENT_REVIEW_REQUIRED", "Access denied", "A different security engineer must review this profile.", false)
		return
	}
	if outcome == "approved" {
		fingerprint := profileDefinitionHash(record.ProfileID)
		definition, known := policyProfiles[record.ProfileID]
		var evidence profileDesignRecord
		if !known || record.RegistryVersion != policyRegistryVersion || len(record.ProfileHash) != sha256.Size ||
			!bytes.Equal(record.ProfileHash, fingerprint[:]) ||
			!matchesProfileDefinition(record.ProfileID, record.Provider, record.ProviderVersion, record.UseCase, record.SourceReference) ||
			json.Unmarshal(record.EvidenceJSON, &evidence) != nil || !validProfileDesignRecord(definition.Mode, evidence) {
			writeProblem(w, r, http.StatusConflict, "PROFILE_VERSION_STALE", "Conflict", "The profile changed after this review was submitted; submit the current registry version.", false)
			return
		}
	}
	var reviewedAt time.Time
	err = contextTransaction(r).QueryRowContext(r.Context(), `UPDATE algorithm_profiles
		SET lifecycle = $3, reviewed_by = $4, reviewed_at = clock_timestamp(), review_reference = $5,
			lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND id = $2 AND lifecycle = 'pending_review' AND lifecycle_version = $6
		RETURNING reviewed_at`, contextTenant(r), reviewID, outcome, auditActor(principal), input.ReviewReference,
		record.LifecycleVersion).Scan(&reviewedAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeProblem(w, r, http.StatusPreconditionFailed, "STALE_PROFILE_REVIEW", "Precondition failed", "The profile review changed; fetch its current version and retry.", false)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	action, reason := "algorithm_profile.approved", "PROFILE_APPROVED"
	if outcome == "rejected" {
		action, reason = "algorithm_profile.rejected", "PROFILE_REJECTED"
	}
	if err := insertAudit(r.Context(), contextTransaction(r), principal, requestID(r.Context()), action,
		"algorithm_profile_review", reviewID, "success", reason); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	record.Lifecycle = outcome
	record.LifecycleVersion++
	record.ReviewedBy = sql.NullString{String: auditActor(principal), Valid: true}
	record.ReviewedAt = sql.NullTime{Time: reviewedAt.UTC(), Valid: true}
	record.ReviewReference = sql.NullString{String: input.ReviewReference, Valid: true}
	w.Header().Set("ETag", profileReviewETag(record.ID, record.LifecycleVersion))
	writeJSON(w, http.StatusOK, profileReviewResponse(record, requestID(r.Context())))
}

func (s *Server) disableProfileReview(w http.ResponseWriter, r *http.Request) {
	s.transitionApprovedProfile(w, r, "disabled")
}

func (s *Server) deprecateProfileReview(w http.ResponseWriter, r *http.Request) {
	s.transitionApprovedProfile(w, r, "deprecated")
}

func (s *Server) transitionApprovedProfile(w http.ResponseWriter, r *http.Request, state string) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "security_engineer") {
		return
	}
	reviewID := r.PathValue("review_id")
	if !validUUID(reviewID) {
		s.notFound(w, r)
		return
	}
	if !requireProfileReviewETag(w, r, reviewID) {
		return
	}
	record, err := lockProfileReview(r, reviewID)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !matchProfileReviewETag(w, r, record) {
		return
	}
	if record.Lifecycle != "approved" {
		writeProblem(w, r, http.StatusConflict, "PROFILE_REVIEW_STATE_CONFLICT", "Conflict", "Only an approved profile can be disabled or deprecated.", false)
		return
	}
	_, err = contextTransaction(r).ExecContext(r.Context(), `UPDATE algorithm_profiles
		SET lifecycle = $3, lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND id = $2 AND lifecycle = 'approved' AND lifecycle_version = $4`,
		contextTenant(r), reviewID, state, record.LifecycleVersion)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()),
		"algorithm_profile."+state, "algorithm_profile_review", reviewID, "success", strings.ToUpper(state)); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	record.Lifecycle = state
	record.LifecycleVersion++
	w.Header().Set("ETag", profileReviewETag(record.ID, record.LifecycleVersion))
	writeJSON(w, http.StatusOK, profileReviewResponse(record, requestID(r.Context())))
}

func lockProfileReview(r *http.Request, reviewID string) (profileReviewRecord, error) {
	var record profileReviewRecord
	err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text, tenant_id::text, profile_id, provider,
		provider_version, use_case, source_reference, registry_version, revision, lifecycle, lifecycle_version, submitted_by, created_at, reviewed_by, reviewed_at,
		review_reference, profile_hash, review_evidence::text
		FROM algorithm_profiles WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, contextTenant(r), reviewID).Scan(
		&record.ID, &record.TenantID, &record.ProfileID, &record.Provider, &record.ProviderVersion, &record.UseCase,
		&record.SourceReference, &record.RegistryVersion, &record.Revision, &record.Lifecycle,
		&record.LifecycleVersion, &record.SubmittedBy, &record.CreatedAt, &record.ReviewedBy, &record.ReviewedAt,
		&record.ReviewReference, &record.ProfileHash, &record.EvidenceJSON)
	return record, err
}

type profileReviewScanner interface {
	Scan(...any) error
}

func scanProfileReview(row profileReviewScanner) (profileReviewRecord, error) {
	var record profileReviewRecord
	err := row.Scan(&record.ID, &record.TenantID, &record.ProfileID, &record.Provider, &record.ProviderVersion,
		&record.UseCase, &record.SourceReference, &record.RegistryVersion, &record.Revision,
		&record.Lifecycle, &record.LifecycleVersion, &record.SubmittedBy, &record.CreatedAt, &record.ReviewedBy,
		&record.ReviewedAt, &record.ReviewReference, &record.ProfileHash, &record.EvidenceJSON)
	return record, err
}

func requireProfileReviewETag(w http.ResponseWriter, r *http.Request, reviewID string) bool {
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the profile review and send its ETag in If-Match.", false)
		return false
	}
	value := r.Header.Get("If-Match")
	if len(value) < 4 || value[0] != '"' || value[len(value)-1] != '"' {
		writeProblem(w, r, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "Precondition failed", "The profile review version does not match.", false)
		return false
	}
	parts := strings.Split(strings.Trim(value, `"`), "-v")
	if len(parts) != 2 || !validUUID(parts[0]) || !strings.EqualFold(parts[0], reviewID) {
		writeProblem(w, r, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "Precondition failed", "The profile review version does not match.", false)
		return false
	}
	versionText := parts[1]
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version < 1 {
		writeProblem(w, r, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "Precondition failed", "The profile review version does not match.", false)
		return false
	}
	return true
}

func matchProfileReviewETag(w http.ResponseWriter, r *http.Request, record profileReviewRecord) bool {
	if r.Header.Get("If-Match") != profileReviewETag(record.ID, record.LifecycleVersion) {
		writeProblem(w, r, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "Precondition failed", "The profile review changed; fetch its current version and retry.", false)
		return false
	}
	return true
}

func profileReviewETag(id string, version int64) string {
	return `"` + id + "-v" + strconv.FormatInt(version, 10) + `"`
}

func profileReviewResponse(record profileReviewRecord, requestID string) map[string]any {
	response := map[string]any{
		"id": record.ID, "profile_id": record.ProfileID, "registry_version": record.RegistryVersion,
		"revision": record.Revision, "state": record.Lifecycle, "etag": profileReviewETag(record.ID, record.LifecycleVersion),
		"profile_hash": hex.EncodeToString(record.ProfileHash), "submitted_by": record.SubmittedBy,
		"submitted_at": record.CreatedAt.UTC(), "request_id": requestID,
	}
	if record.ReviewedBy.Valid {
		response["reviewed_by"] = record.ReviewedBy.String
	}
	if record.ReviewedAt.Valid {
		response["reviewed_at"] = record.ReviewedAt.Time.UTC()
	}
	if record.ReviewReference.Valid {
		response["review_reference"] = record.ReviewReference.String
	}
	var evidence profileDesignRecord
	if len(record.EvidenceJSON) != 0 && json.Unmarshal(record.EvidenceJSON, &evidence) == nil {
		response["design_record"] = evidence
	}
	return response
}

func profileDefinitionHash(profileID string) [sha256.Size]byte {
	definition := policyProfiles[profileID]
	canonical := struct {
		ID              string `json:"id"`
		RegistryVersion int64  `json:"registry_version"`
		Mode            string `json:"mode"`
		Provider        string `json:"provider"`
		ProviderVersion string `json:"provider_version"`
		UseCase         string `json:"use_case"`
		SourceReference string `json:"source_reference"`
	}{profileID, policyRegistryVersion, definition.Mode, definition.Provider, definition.ProviderVersion, definition.UseCase, definition.SourceReference}
	encoded, _ := json.Marshal(canonical)
	return sha256.Sum256(encoded)
}

func matchesProfileDefinition(profileID, provider, providerVersion, useCase, sourceReference string) bool {
	definition, known := policyProfiles[profileID]
	return known && definition.Provider == provider && definition.ProviderVersion == providerVersion &&
		definition.UseCase == useCase && definition.SourceReference == sourceReference
}

func validProfileDesignRecord(mode string, record profileDesignRecord) bool {
	if !validReviewText(record.StandardProfile, 256) ||
		!validReviewText(record.KeyPurposeAndLifecycle, 2048) || !validReviewText(record.DowngradeDetection, 2048) ||
		!validReviewText(record.TranscriptBinding, 2048) || !validReviewText(record.DeprecationPlan, 2048) ||
		!validReviewText(record.RollbackPlan, 2048) || !validTokenList(record.ClassicalMechanisms, 1, 16, 128) ||
		!validReviewTextList(record.InteropPartners, 1, 16, 256) || !validReferenceList(record.TestVectors, 1, 16) {
		return false
	}
	if oneOf(mode, "hybrid-approved", "pqc-approved") && !validTokenList(record.PQCMechanisms, 1, 16, 128) {
		return false
	}
	if mode == "classical-approved" && len(record.PQCMechanisms) > 0 && !validTokenList(record.PQCMechanisms, 1, 16, 128) {
		return false
	}
	return true
}

func validTokenList(values []string, min, max, itemMax int) bool {
	if len(values) < min || len(values) > max {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validBoundedToken(value, itemMax) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validReviewText(value string, max int) bool {
	if len(value) == 0 || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func validReviewTextList(values []string, min, max, itemMax int) bool {
	if len(values) < min || len(values) > max {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validReviewText(value, itemMax) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validReferenceList(values []string, min, max int) bool {
	if len(values) < min || len(values) > max {
		return false
	}
	for _, value := range values {
		if !validHTTPSReference(value) {
			return false
		}
	}
	return true
}

func validHTTPSReference(value string) bool {
	if len(value) == 0 || len(value) > 2048 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil
}
