package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"quantumgate/internal/keyprovider"
)

// KeyProviderMetadataStore reuses the existing tenant-scoped key reference
// table as the durable state authority for provider-backed keys.
type KeyProviderMetadataStore struct {
	db *sql.DB
}

func NewKeyProviderMetadataStore(db *sql.DB) *KeyProviderMetadataStore {
	return &KeyProviderMetadataStore{db: db}
}

func (s *KeyProviderMetadataStore) Create(ctx context.Context, scope keyprovider.Scope, item keyprovider.Metadata) (keyprovider.Metadata, error) {
	if s == nil || s.db == nil || !validProviderScope(scope) || item.Provider != keyprovider.VaultTransit ||
		item.Purpose != keyprovider.PurposeSigning || item.Algorithm != keyprovider.AlgorithmEd25519 || item.Reference == "" {
		return keyprovider.Metadata{}, keyprovider.ErrInvalidScope
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	defer tx.Rollback()
	if err := setProviderTenant(ctx, tx, scope.TenantID); err != nil {
		return keyprovider.Metadata{}, err
	}
	lockKey := strings.Join([]string{scope.TenantID, scope.ApplicationID, string(item.Purpose)}, ":")
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	var version int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) + 1
		FROM key_references WHERE tenant_id = $1 AND application_id = $2 AND purpose = $3`,
		scope.TenantID, scope.ApplicationID, item.Purpose).Scan(&version); err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	if version < 1 {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	var createdAt, updatedAt time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO key_references
		(tenant_id, application_id, purpose, provider, provider_reference, version, state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at`, scope.TenantID, scope.ApplicationID, item.Purpose,
		item.Provider, item.Reference, version, item.State, item.ExpiresAt.UTC()).Scan(&createdAt, &updatedAt)
	if err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	if err := tx.Commit(); err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	item.Version, item.CreatedAt, item.UpdatedAt = uint64(version), createdAt.UTC(), updatedAt.UTC()
	return item, nil
}

func (s *KeyProviderMetadataStore) Read(ctx context.Context, scope keyprovider.Scope, reference string) (keyprovider.Metadata, error) {
	if s == nil || s.db == nil || !validProviderScope(scope) || reference == "" {
		return keyprovider.Metadata{}, keyprovider.ErrKeyNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	defer tx.Rollback()
	if err := setProviderTenant(ctx, tx, scope.TenantID); err != nil {
		return keyprovider.Metadata{}, err
	}
	item, err := readProviderMetadata(ctx, tx, scope, reference, false)
	if err != nil {
		return keyprovider.Metadata{}, err
	}
	if err := tx.Commit(); err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	return item, nil
}

// Lock serializes provider lifecycle changes and signing calls across service
// replicas by holding the key-reference row lock until the callback finishes.
func (s *KeyProviderMetadataStore) Lock(ctx context.Context, scope keyprovider.Scope, reference string, action func(*keyprovider.Metadata) error) error {
	if s == nil || s.db == nil || !validProviderScope(scope) || reference == "" || action == nil {
		return keyprovider.ErrKeyNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return keyprovider.ErrProviderUnavailable
	}
	defer tx.Rollback()
	if err := setProviderTenant(ctx, tx, scope.TenantID); err != nil {
		return err
	}
	item, err := readProviderMetadata(ctx, tx, scope, reference, true)
	if err != nil {
		return err
	}
	previousState, previousUpdatedAt := item.State, item.UpdatedAt
	if err := action(&item); err != nil {
		return err
	}
	if item.State != previousState {
		if item.UpdatedAt.IsZero() || item.UpdatedAt.Before(previousUpdatedAt) {
			return keyprovider.ErrMalformedResponse
		}
		var activatedAt any
		if item.State == keyprovider.StateActive {
			activatedAt = item.UpdatedAt.UTC()
		}
		var revokedAt any
		if item.State == keyprovider.StateRevoked {
			revokedAt = item.UpdatedAt.UTC()
		}
		result, err := tx.ExecContext(ctx, `UPDATE key_references
			SET state = $1, updated_at = $2,
				activates_at = COALESCE($3, activates_at),
				revoked_at = COALESCE($4, revoked_at)
			WHERE tenant_id = $5 AND application_id = $6 AND provider = $7
				AND provider_reference = $8 AND state = $9`, item.State, item.UpdatedAt.UTC(),
			activatedAt, revokedAt, scope.TenantID, scope.ApplicationID, keyprovider.VaultTransit, reference, previousState)
		if err != nil {
			return keyprovider.ErrProviderUnavailable
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return keyprovider.ErrStaleTransition
		}
	}
	if err := tx.Commit(); err != nil {
		return keyprovider.ErrProviderUnavailable
	}
	return nil
}

func readProviderMetadata(ctx context.Context, tx *sql.Tx, scope keyprovider.Scope, reference string, lock bool) (keyprovider.Metadata, error) {
	query := `SELECT purpose, version, state, created_at, updated_at, expires_at
		FROM key_references WHERE tenant_id = $1 AND application_id = $2 AND provider = $3 AND provider_reference = $4`
	if lock {
		query += ` FOR UPDATE`
	}
	var purpose, state string
	var version int64
	var createdAt, updatedAt, expiresAt time.Time
	err := tx.QueryRowContext(ctx, query, scope.TenantID, scope.ApplicationID, keyprovider.VaultTransit, reference).
		Scan(&purpose, &version, &state, &createdAt, &updatedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return keyprovider.Metadata{}, keyprovider.ErrKeyNotFound
	}
	if err != nil || version < 1 {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	return keyprovider.Metadata{
		Provider: keyprovider.VaultTransit, Reference: reference, Purpose: keyprovider.Purpose(purpose),
		Algorithm: keyprovider.AlgorithmEd25519, Version: uint64(version), State: keyprovider.State(state),
		CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC(), ExpiresAt: expiresAt.UTC(),
	}, nil
}

func setProviderTenant(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('qg.tenant_id', $1, true)`, tenantID); err != nil {
		return keyprovider.ErrProviderUnavailable
	}
	return nil
}

func validProviderScope(scope keyprovider.Scope) bool {
	return validProviderUUID(scope.TenantID) && validProviderUUID(scope.ApplicationID) &&
		(scope.Environment == "development" || scope.Environment == "test" || scope.Environment == "production")
}

func validProviderUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, char := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F') {
			return false
		}
	}
	return true
}

// KeyProviderAuditSink stores only the already-redacted provider audit event
// fields. The database trigger makes records append-only and RLS scopes each
// insertion to the event tenant.
type KeyProviderAuditSink struct {
	db *sql.DB
}

func NewKeyProviderAuditSink(db *sql.DB) *KeyProviderAuditSink {
	return &KeyProviderAuditSink{db: db}
}

func (s *KeyProviderAuditSink) RecordKeyOperation(ctx context.Context, event keyprovider.AuditEvent) error {
	if s == nil || s.db == nil || !validProviderUUID(event.TenantID) || !validProviderUUID(event.ApplicationID) ||
		len(event.Actor) == 0 || len(event.Actor) > 512 || len(event.CorrelationID) == 0 || len(event.CorrelationID) > 128 ||
		(event.KeyReferenceHash != "" && (len(event.KeyReferenceHash) != 64 || !isLowerHex(event.KeyReferenceHash))) {
		return keyprovider.ErrAuditUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return keyprovider.ErrAuditUnavailable
	}
	defer tx.Rollback()
	if err := setProviderTenant(ctx, tx, event.TenantID); err != nil {
		return keyprovider.ErrAuditUnavailable
	}
	action := fmt.Sprintf("key_provider.%s.%s", event.Operation, event.Phase)
	if len(action) > 128 || event.ReasonCode == "" || len(event.ReasonCode) > 128 {
		return keyprovider.ErrAuditUnavailable
	}
	outcome := "failure"
	switch event.Outcome {
	case "requested", "success":
		outcome = "success"
	case "denied":
		outcome = "denied"
	case "failure":
		outcome = "failure"
	default:
		return keyprovider.ErrAuditUnavailable
	}
	source, err := json.Marshal(map[string]string{
		"application_id": event.ApplicationID, "environment": event.Environment,
		"provider": event.Provider, "purpose": string(event.Purpose), "algorithm": string(event.Algorithm),
		"phase": event.Phase,
	})
	if err != nil {
		return keyprovider.ErrAuditUnavailable
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events
		(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code, source_context)
		VALUES ($1, 1, $2, $3, 'key_provider_reference', NULLIF($4, ''), $5, $6, $7, $8::jsonb)`, event.TenantID,
		event.Actor, action, event.KeyReferenceHash, outcome, event.CorrelationID, event.ReasonCode, source)
	if err != nil {
		return keyprovider.ErrAuditUnavailable
	}
	if err := tx.Commit(); err != nil {
		return keyprovider.ErrAuditUnavailable
	}
	return nil
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

var _ keyprovider.KeyMetadataStore = (*KeyProviderMetadataStore)(nil)
var _ keyprovider.AuditSink = (*KeyProviderAuditSink)(nil)
