package httpapi

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"
	"unicode"
)

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if tenantID != contextTenant(r) || !s.requireRole(w, r, "tenant_admin") {
		if tenantID != contextTenant(r) {
			s.notFound(w, r)
		}
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
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT id::text, issuer, subject, role, created_at
		FROM tenant_members WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2::uuid)
		ORDER BY id LIMIT $3`, tenantID, after, limit+1)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	defer rows.Close()
	type memberView struct {
		ID        string    `json:"id"`
		Issuer    string    `json:"issuer"`
		Subject   string    `json:"subject"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"created_at"`
	}
	items := make([]memberView, 0, limit)
	for rows.Next() {
		var item memberView
		if err := rows.Scan(&item.ID, &item.Issuer, &item.Subject, &item.Role, &item.CreatedAt); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	response := map[string]any{"items": items, "next_cursor": "", "request_id": requestID(r.Context())}
	if len(items) > limit {
		items = items[:limit]
		response["items"] = items
		response["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ID))
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) createMember(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if tenantID != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin") {
		return
	}
	var input struct {
		Subject string `json:"subject"`
		Role    string `json:"role"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validIdentityIdentifier(input.Subject) || !oneOf(input.Role, "tenant_admin", "security_engineer", "developer", "auditor") {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "The request body is invalid.", false)
		return
	}
	if s.OIDCIssuer == "" {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The configured identity provider is unavailable.", true)
		return
	}
	var item struct {
		ID        string    `json:"id"`
		Issuer    string    `json:"issuer"`
		Subject   string    `json:"subject"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"created_at"`
		RequestID string    `json:"request_id"`
	}
	err := contextTransaction(r).QueryRowContext(r.Context(), `INSERT INTO tenant_members(tenant_id, issuer, subject, role)
		VALUES ($1, $2, $3, $4) RETURNING id::text, issuer, subject, role, created_at`,
		tenantID, s.OIDCIssuer, input.Subject, input.Role).Scan(&item.ID, &item.Issuer, &item.Subject, &item.Role, &item.CreatedAt)
	if err != nil {
		writeDatabaseProblem(w, r, err, "MEMBER_CONFLICT")
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "tenant.member_added", "tenant_member", item.ID, "success", "MEMBER_ADDED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	item.RequestID = requestID(r.Context())
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	memberID := r.PathValue("member_id")
	if tenantID != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin") {
		return
	}
	if !validUUID(memberID) {
		s.notFound(w, r)
		return
	}
	tx := contextTransaction(r)
	var lockedTenant string
	err := tx.QueryRowContext(r.Context(), `SELECT id::text FROM tenants WHERE id = $1 FOR UPDATE`, tenantID).Scan(&lockedTenant)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	var target struct{ Issuer, Subject, Role string }
	err = tx.QueryRowContext(r.Context(), `SELECT issuer, subject, role FROM tenant_members
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, memberID).Scan(&target.Issuer, &target.Subject, &target.Role)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	if target.Role == "tenant_admin" {
		var count int
		if err := tx.QueryRowContext(r.Context(), `SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'tenant_admin'`, tenantID).Scan(&count); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		if count <= 1 {
			writeProblem(w, r, http.StatusConflict, "LAST_TENANT_ADMIN", "Member cannot be removed", "A tenant must retain at least one administrator.", false)
			return
		}
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM tenant_members WHERE tenant_id = $1 AND id = $2`, tenantID, memberID); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE admin_sessions SET revoked_at = now()
		WHERE issuer = $1 AND subject = $2 AND revoked_at IS NULL`, target.Issuer, target.Subject); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()), "tenant.member_removed", "tenant_member", memberID, "success", "MEMBER_REMOVED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validIdentityIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
