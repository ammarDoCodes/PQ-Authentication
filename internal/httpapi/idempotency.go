package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const idempotencyKeyHeader = "Idempotency-Key"

var idempotencyBodyPrefix = []byte{'Q', 'G', 'I', 'D', 1}

var errIdempotencyKeyReused = errors.New("idempotency key was already used for a different request")

type idempotentResponse struct {
	status  int
	headers map[string][]string
	body    []byte
}

func validateIdempotencyKey(values []string) (string, bool) {
	if len(values) != 1 || len(values[0]) < 16 || len(values[0]) > 128 {
		return "", false
	}
	for _, r := range values[0] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~-", r)) {
			return "", false
		}
	}
	return values[0], true
}

func (s *Server) reserveIdempotency(ctx context.Context, tx *sql.Tx, r *http.Request, principal tenantPrincipal, key string, body []byte) ([]byte, *idempotentResponse, error) {
	keyHash := idempotencyKeyDigest(principal, key)
	requestHash := sha256.Sum256(encodeHashFields(
		[]byte(r.Method), []byte(r.URL.RequestURI()), []byte(strings.Join(r.Header.Values("If-Match"), "\x00")),
		[]byte(strings.Join(r.Header.Values("Content-Type"), "\x00")), body,
	))
	var inserted []byte
	err := tx.QueryRowContext(ctx, `INSERT INTO idempotency_records
		(tenant_id, key_hash, request_hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, key_hash) DO UPDATE SET
			request_hash = EXCLUDED.request_hash,
			response_status = NULL,
			response_headers = NULL,
			response_body = NULL,
			created_at = now(),
			expires_at = now() + interval '24 hours'
		WHERE idempotency_records.expires_at <= now()
		RETURNING key_hash`, principal.TenantID, keyHash, requestHash[:]).Scan(&inserted)
	if err == nil {
		// Keep cleanup tenant scoped and bounded; expired keys are also reclaimed on reuse.
		_, cleanupErr := tx.ExecContext(ctx, `DELETE FROM idempotency_records
			WHERE tenant_id = $1 AND key_hash IN (
				SELECT key_hash FROM idempotency_records
				WHERE tenant_id = $1 AND expires_at <= now() AND key_hash <> $2
				ORDER BY expires_at LIMIT 1000
			)`, principal.TenantID, keyHash)
		if cleanupErr != nil {
			return nil, nil, cleanupErr
		}
		return keyHash, nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}
	var existingHash []byte
	var status sql.NullInt64
	var headersJSON []byte
	var responseBody []byte
	err = tx.QueryRowContext(ctx, `SELECT request_hash, response_status, response_headers, response_body
		FROM idempotency_records WHERE tenant_id = $1 AND key_hash = $2 FOR UPDATE`, principal.TenantID, keyHash).
		Scan(&existingHash, &status, &headersJSON, &responseBody)
	if err != nil {
		return nil, nil, err
	}
	if !hmac.Equal(existingHash, requestHash[:]) {
		return nil, nil, errIdempotencyKeyReused
	}
	if !status.Valid {
		return nil, nil, errors.New("idempotency response is incomplete")
	}
	var headers map[string][]string
	if err := json.Unmarshal(headersJSON, &headers); err != nil || headers == nil {
		return nil, nil, errors.New("idempotency response headers are invalid")
	}
	plainBody, err := s.openIdempotentBody(responseBody, principal.TenantID, keyHash)
	if err != nil {
		return nil, nil, err
	}
	return nil, &idempotentResponse{status: int(status.Int64), headers: headers, body: plainBody}, nil
}

func (s *Server) saveIdempotentResponse(ctx context.Context, tx *sql.Tx, tenantID string, keyHash []byte, status int, headers http.Header, body []byte) error {
	storedHeaders := make(map[string][]string, 3)
	for _, name := range []string{"Content-Type", "ETag", "Location"} {
		if values := headers.Values(name); len(values) != 0 {
			storedHeaders[name] = append([]string(nil), values...)
		}
	}
	headerJSON, err := json.Marshal(storedHeaders)
	if err != nil {
		return err
	}
	storedBody, err := s.sealIdempotentBody(body, tenantID, keyHash)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE idempotency_records
		SET response_status = $3, response_headers = $4::jsonb, response_body = $5,
			expires_at = now() + interval '24 hours'
		WHERE tenant_id = $1 AND key_hash = $2 AND response_status IS NULL`,
		tenantID, keyHash, status, headerJSON, storedBody)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return errors.New("idempotency response could not be committed")
	}
	return nil
}

func (s *Server) sealIdempotentBody(body []byte, tenantID string, keyHash []byte) ([]byte, error) {
	aead, err := s.idempotencyAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("idempotency response encryption failed")
	}
	sealed := aead.Seal(nil, nonce, body, idempotencyBodyAAD(tenantID, keyHash))
	stored := make([]byte, 0, len(idempotencyBodyPrefix)+len(nonce)+len(sealed))
	stored = append(stored, idempotencyBodyPrefix...)
	stored = append(stored, nonce...)
	stored = append(stored, sealed...)
	return stored, nil
}

func (s *Server) openIdempotentBody(stored []byte, tenantID string, keyHash []byte) ([]byte, error) {
	if !bytes.HasPrefix(stored, idempotencyBodyPrefix) {
		// Compatibility for response bodies written by releases before at-rest encryption.
		return stored, nil
	}
	aead, err := s.idempotencyAEAD()
	if err != nil {
		return nil, err
	}
	encoded := stored[len(idempotencyBodyPrefix):]
	if len(encoded) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("idempotency response ciphertext is invalid")
	}
	nonce, ciphertext := encoded[:aead.NonceSize()], encoded[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, idempotencyBodyAAD(tenantID, keyHash))
	if err != nil {
		return nil, errors.New("idempotency response could not be decrypted")
	}
	return plain, nil
}

func (s *Server) idempotencyAEAD() (cipher.AEAD, error) {
	if len(s.RateLimitKey) != sha256.Size {
		return nil, errors.New("idempotency encryption key is unavailable")
	}
	mac := hmac.New(sha256.New, s.RateLimitKey)
	_, _ = mac.Write([]byte("quantumgate/idempotency-response/aes-256-gcm/v1"))
	key := mac.Sum(nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("idempotency response encryption is unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("idempotency response encryption is unavailable")
	}
	return aead, nil
}

func idempotencyBodyAAD(tenantID string, keyHash []byte) []byte {
	return encodeHashFields([]byte("quantumgate/idempotency-response/v1"), []byte(tenantID), keyHash)
}

func replayIdempotentResponse(w http.ResponseWriter, response *idempotentResponse) {
	for name, values := range response.headers {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.Header().Set("Idempotency-Replayed", "true")
	w.WriteHeader(response.status)
	_, _ = w.Write(response.body)
}

func idempotencyKeyDigest(principal tenantPrincipal, key string) []byte {
	digest := sha256.Sum256(encodeHashFields([]byte(principal.TenantID), []byte(principal.Issuer), []byte(principal.Subject), []byte(key)))
	return digest[:]
}

func encodeHashFields(fields ...[]byte) []byte {
	var encoded []byte
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		encoded = append(encoded, length[:]...)
		encoded = append(encoded, field...)
	}
	return encoded
}

func readMutationBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxControlBodyBytes))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}
