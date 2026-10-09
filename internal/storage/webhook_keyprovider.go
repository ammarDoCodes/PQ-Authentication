package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"quantumgate/internal/keyprovider"
)

// WebhookKeyProviderMetadataStore keeps Vault's opaque provider references in
// the webhook-only RLS table instead of the general key-reference API.
type WebhookKeyProviderMetadataStore struct{ db *sql.DB }

func NewWebhookKeyProviderMetadataStore(db *sql.DB) *WebhookKeyProviderMetadataStore {
	return &WebhookKeyProviderMetadataStore{db: db}
}

func (s *WebhookKeyProviderMetadataStore) Create(ctx context.Context, scope keyprovider.Scope,
	item keyprovider.Metadata) (keyprovider.Metadata, error) {
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
	lockKey := strings.Join([]string{scope.TenantID, scope.ApplicationID, "webhook-signing"}, ":")
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	var version int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM webhook_signing_keys
		WHERE tenant_id = $1 AND application_id = $2`, scope.TenantID, scope.ApplicationID).Scan(&version); err != nil || version < 1 {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	var createdAt, updatedAt time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO webhook_signing_keys
		(tenant_id, application_id, provider, provider_reference, algorithm, version, state, created_at, updated_at, expires_at)
		VALUES ($1, $2, $3, $4, 'Ed25519', $5, $6, $7, $8, $9)
		RETURNING created_at, updated_at`, scope.TenantID, scope.ApplicationID, item.Provider, item.Reference,
		version, item.State, item.CreatedAt.UTC(), item.UpdatedAt.UTC(), item.ExpiresAt.UTC()).Scan(&createdAt, &updatedAt)
	if err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	if err := tx.Commit(); err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	item.Version, item.CreatedAt, item.UpdatedAt = uint64(version), createdAt.UTC(), updatedAt.UTC()
	return item, nil
}

func (s *WebhookKeyProviderMetadataStore) Read(ctx context.Context, scope keyprovider.Scope,
	reference string) (keyprovider.Metadata, error) {
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
	item, err := readWebhookProviderMetadata(ctx, tx, scope, reference, false)
	if err != nil {
		return keyprovider.Metadata{}, err
	}
	if err := tx.Commit(); err != nil {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	return item, nil
}

func (s *WebhookKeyProviderMetadataStore) Lock(ctx context.Context, scope keyprovider.Scope,
	reference string, action func(*keyprovider.Metadata) error) error {
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
	item, err := readWebhookProviderMetadata(ctx, tx, scope, reference, true)
	if err != nil {
		return err
	}
	previous := item
	if err := action(&item); err != nil {
		return err
	}
	if item.Provider != previous.Provider || item.Reference != previous.Reference || item.Purpose != previous.Purpose ||
		item.Algorithm != previous.Algorithm || item.Version != previous.Version ||
		!item.CreatedAt.Equal(previous.CreatedAt) || !item.ExpiresAt.Equal(previous.ExpiresAt) {
		return keyprovider.ErrMalformedResponse
	}
	if item.State != previous.State {
		if item.UpdatedAt.IsZero() || !item.UpdatedAt.After(previous.UpdatedAt) {
			return keyprovider.ErrMalformedResponse
		}
		result, err := tx.ExecContext(ctx, `UPDATE webhook_signing_keys SET state = $1, updated_at = $2
			WHERE tenant_id = $3 AND application_id = $4 AND provider = $5 AND provider_reference = $6 AND state = $7`,
			item.State, item.UpdatedAt.UTC(), scope.TenantID, scope.ApplicationID, keyprovider.VaultTransit, reference, previous.State)
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

func readWebhookProviderMetadata(ctx context.Context, tx *sql.Tx, scope keyprovider.Scope,
	reference string, lock bool) (keyprovider.Metadata, error) {
	query := `SELECT version, state, created_at, updated_at, expires_at FROM webhook_signing_keys
		WHERE tenant_id = $1 AND application_id = $2 AND provider = $3 AND provider_reference = $4`
	if lock {
		query += ` FOR UPDATE`
	}
	var version int64
	var state string
	var createdAt, updatedAt, expiresAt time.Time
	err := tx.QueryRowContext(ctx, query, scope.TenantID, scope.ApplicationID, keyprovider.VaultTransit, reference).
		Scan(&version, &state, &createdAt, &updatedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return keyprovider.Metadata{}, keyprovider.ErrKeyNotFound
	}
	if err != nil || version < 1 {
		return keyprovider.Metadata{}, keyprovider.ErrProviderUnavailable
	}
	return keyprovider.Metadata{Provider: keyprovider.VaultTransit, Reference: reference,
		Purpose: keyprovider.PurposeSigning, Algorithm: keyprovider.AlgorithmEd25519, Version: uint64(version),
		State: keyprovider.State(state), CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC(), ExpiresAt: expiresAt.UTC()}, nil
}

var _ keyprovider.KeyMetadataStore = (*WebhookKeyProviderMetadataStore)(nil)
