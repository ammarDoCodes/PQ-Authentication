package httpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	maxAuditExportRows  = 5000
	maxAuditExportBytes = 7 << 20
)

var auditExportBodyPrefix = []byte{'Q', 'G', 'E', 'X', 1}

type auditExportEvent struct {
	ID            string    `json:"id"`
	OccurredAt    time.Time `json:"occurred_at"`
	Actor         string    `json:"actor"`
	Action        string    `json:"action"`
	TargetType    string    `json:"target_type"`
	TargetID      string    `json:"target_id,omitempty"`
	Outcome       string    `json:"outcome"`
	CorrelationID string    `json:"correlation_id"`
	ReasonCode    string    `json:"reason_code"`
}

type auditExportDocument struct {
	SchemaVersion int                `json:"schema_version"`
	TenantID      string             `json:"tenant_id"`
	RequestID     string             `json:"request_id"`
	From          time.Time          `json:"from"`
	To            time.Time          `json:"to"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Events        []auditExportEvent `json:"events"`
}

type auditExportView struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RowCount    int       `json:"row_count"`
	RequestID   string    `json:"request_id"`
}

func (s *Server) createAuditExport(w http.ResponseWriter, r *http.Request) {
	tenantID := contextTenant(r)
	if r.PathValue("tenant_id") != tenantID {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
		return
	}
	principal := contextPrincipal(r)
	if !s.enforceRateLimit(w, r, "audit-export:tenant", tenantID, 20) ||
		!s.enforceRateLimit(w, r, "audit-export:principal", principal.Issuer+"\x00"+principal.Subject+"\x00"+tenantID, 5) {
		return
	}
	if len(s.RateLimitKey) != sha256.Size {
		controlPlaneUnavailable(w, r)
		return
	}
	var input struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "The export range is invalid.", false)
		return
	}
	from, fromErr := time.Parse(time.RFC3339Nano, input.From)
	to, toErr := time.Parse(time.RFC3339Nano, input.To)
	now := time.Now().UTC()
	if fromErr != nil || toErr != nil || !from.Before(to) || to.After(now) || to.Sub(from) > 90*24*time.Hour {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_EXPORT_RANGE", "Invalid request", "Provide an RFC 3339 time range no longer than 90 days that ends no later than now.", false)
		return
	}

	ctx := r.Context()
	// The security-definer cleanup function can delete only expired jobs for this tenant.
	var purgedExports int
	if err := contextTransaction(r).QueryRowContext(ctx, `SELECT public.qg_purge_expired_exports($1, 100)`, tenantID).Scan(&purgedExports); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	rows, err := contextTransaction(r).QueryContext(ctx, `SELECT id::text, occurred_at, actor, action, target_type,
		target_id, outcome, correlation_id, reason_code FROM audit_events
		WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
		ORDER BY occurred_at, id LIMIT $4`, tenantID, from.UTC(), to.UTC(), maxAuditExportRows+1)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	events := make([]auditExportEvent, 0, 64)
	for rows.Next() {
		var event auditExportEvent
		var targetID sql.NullString
		if err := rows.Scan(&event.ID, &event.OccurredAt, &event.Actor, &event.Action, &event.TargetType,
			&targetID, &event.Outcome, &event.CorrelationID, &event.ReasonCode); err != nil {
			_ = rows.Close()
			controlPlaneUnavailable(w, r)
			return
		}
		if targetID.Valid {
			event.TargetID = targetID.String
		}
		events = append(events, event)
	}
	rowsErr := rows.Err()
	if err := rows.Close(); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if rowsErr != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if len(events) > maxAuditExportRows {
		writeProblem(w, r, http.StatusUnprocessableEntity, "EXPORT_TOO_LARGE", "Export exceeds limit", "The selected range contains more than 5,000 audit events. Narrow the time range and retry.", false)
		return
	}
	generatedAt := time.Now().UTC()
	document, err := json.Marshal(auditExportDocument{
		SchemaVersion: 1, TenantID: tenantID, RequestID: requestID(ctx), From: from.UTC(), To: to.UTC(), GeneratedAt: generatedAt, Events: events,
	})
	if err != nil || len(document) > maxAuditExportBytes {
		writeProblem(w, r, http.StatusUnprocessableEntity, "EXPORT_TOO_LARGE", "Export exceeds limit", "The selected range produces an export larger than the allowed size.", false)
		return
	}
	exportID, err := generateUUID()
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	ciphertext, err := s.sealAuditExport(document, tenantID, exportID)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var requestedAt, expiresAt time.Time
	if err := contextTransaction(r).QueryRowContext(ctx, `INSERT INTO export_jobs
		(id, tenant_id, expires_at, row_count, payload_ciphertext)
		VALUES ($1, $2, now() + interval '24 hours', $3, $4)
		RETURNING requested_at, expires_at`,
		exportID, tenantID, len(events), ciphertext).Scan(&requestedAt, &expiresAt); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := insertAudit(ctx, contextTransaction(r), principal, requestID(ctx), "export.created", "export", exportID, "success", "AUDIT_RANGE_EXPORTED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	view := auditExportView{ID: exportID, Status: "ready", RequestedAt: requestedAt, ExpiresAt: expiresAt, RowCount: len(events), RequestID: requestID(ctx)}
	w.Header().Set("Location", "/v1/exports/"+exportID)
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) getAuditExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
		return
	}
	exportID := r.PathValue("export_id")
	if !validUUID(exportID) {
		s.notFound(w, r)
		return
	}
	principal := contextPrincipal(r)
	if !s.enforceRateLimit(w, r, "audit-export:read", principal.Issuer+"\x00"+principal.Subject+"\x00"+contextTenant(r), 60) {
		return
	}
	var view auditExportView
	err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text, requested_at, expires_at, row_count
		FROM export_jobs WHERE tenant_id = $1 AND id = $2 AND expires_at > now()`, contextTenant(r), exportID).
		Scan(&view.ID, &view.RequestedAt, &view.ExpiresAt, &view.RowCount)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "export.viewed", "export", exportID, "success", "EXPORT_STATUS_READ"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	view.Status = "ready"
	view.RequestID = requestID(r.Context())
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) downloadAuditExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
		return
	}
	exportID := r.PathValue("export_id")
	if !validUUID(exportID) {
		s.notFound(w, r)
		return
	}
	principal := contextPrincipal(r)
	if !s.enforceRateLimit(w, r, "audit-export:download", principal.Issuer+"\x00"+principal.Subject+"\x00"+contextTenant(r), 10) {
		return
	}
	var ciphertext []byte
	err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT payload_ciphertext FROM export_jobs
		WHERE tenant_id = $1 AND id = $2 AND expires_at > now()`, contextTenant(r), exportID).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	plaintext, err := s.openAuditExport(ciphertext, contextTenant(r), exportID)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "export.downloaded", "export", exportID, "success", "AUDIT_EXPORT_DOWNLOADED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="quantumgate-audit-`+exportID+`.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plaintext)
}

func (s *Server) sealAuditExport(plaintext []byte, tenantID, exportID string) ([]byte, error) {
	aead, err := s.auditExportAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("audit export encryption failed")
	}
	sealed := aead.Seal(nil, nonce, plaintext, auditExportAAD(tenantID, exportID))
	stored := make([]byte, 0, len(auditExportBodyPrefix)+len(nonce)+len(sealed))
	stored = append(stored, auditExportBodyPrefix...)
	stored = append(stored, nonce...)
	stored = append(stored, sealed...)
	return stored, nil
}

func (s *Server) openAuditExport(stored []byte, tenantID, exportID string) ([]byte, error) {
	if !bytes.HasPrefix(stored, auditExportBodyPrefix) {
		return nil, errors.New("audit export ciphertext version is invalid")
	}
	aead, err := s.auditExportAEAD()
	if err != nil {
		return nil, err
	}
	encoded := stored[len(auditExportBodyPrefix):]
	if len(encoded) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("audit export ciphertext is invalid")
	}
	plaintext, err := aead.Open(nil, encoded[:aead.NonceSize()], encoded[aead.NonceSize():], auditExportAAD(tenantID, exportID))
	if err != nil {
		return nil, errors.New("audit export could not be decrypted")
	}
	return plaintext, nil
}

func (s *Server) auditExportAEAD() (cipher.AEAD, error) {
	if len(s.RateLimitKey) != sha256.Size {
		return nil, errors.New("audit export encryption key is unavailable")
	}
	mac := hmac.New(sha256.New, s.RateLimitKey)
	_, _ = mac.Write([]byte("quantumgate/audit-export/aes-256-gcm/v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, errors.New("audit export encryption is unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("audit export encryption is unavailable")
	}
	return aead, nil
}

func auditExportAAD(tenantID, exportID string) []byte {
	return encodeHashFields([]byte("quantumgate/audit-export/v1"), []byte(tenantID), []byte(exportID))
}

func auditActor(principal tenantPrincipal) string {
	identity := sha256.Sum256([]byte(principal.Issuer + "\x00" + principal.Subject))
	return "oidc:" + base64.RawURLEncoding.EncodeToString(identity[:])
}

func generateUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("identifier generation failed")
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmtUUID(value), nil
}

func fmtUUID(value [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
