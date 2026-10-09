package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	Version  int64
	Name     string
	SQL      string
	Checksum []byte
}

const advisoryLockID int64 = 1365721684

func LoadMigrations() ([]migration, error) {
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return nil, errors.New("migration files could not be listed")
	}
	migrations := make([]migration, 0, len(names))
	for _, name := range names {
		base := path.Base(name)
		prefix, suffix, ok := strings.Cut(base, "_")
		if !ok || suffix == "" || !strings.HasSuffix(base, ".sql") {
			return nil, fmt.Errorf("invalid migration filename %q", base)
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid migration version in %q", base)
		}
		content, err := migrationFS.ReadFile(name)
		if err != nil {
			return nil, errors.New("migration file could not be read")
		}
		hash := sha256.Sum256(content)
		migrations = append(migrations, migration{
			Version: version, Name: base, SQL: string(content),
			Checksum: hash[:],
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].Version == migrations[i].Version {
			return nil, errors.New("duplicate migration version")
		}
	}
	return migrations, nil
}

func ApplyMigrations(ctx context.Context, conn *pgx.Conn) error {
	if conn == nil {
		return errors.New("database connection is required")
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockID); err != nil {
		return errors.New("migration lock could not be acquired")
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", advisoryLockID)
	}()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS qg_schema_migrations (
		version BIGINT PRIMARY KEY,
		name TEXT NOT NULL,
		checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return errors.New("migration history table could not be initialized")
	}
	if _, err := conn.Exec(ctx, `DO $block$
	BEGIN
		IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'quantumgate') THEN
			EXECUTE 'REVOKE ALL ON TABLE qg_schema_migrations FROM quantumgate';
		END IF;
	END
	$block$`); err != nil {
		return errors.New("migration history permissions could not be restricted")
	}
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		var name string
		var checksum []byte
		err := conn.QueryRow(ctx, "SELECT name, checksum FROM qg_schema_migrations WHERE version = $1", m.Version).Scan(&name, &checksum)
		switch {
		case err == nil:
			if name != m.Name || !bytes.Equal(checksum, m.Checksum) {
				return fmt.Errorf("applied migration %d differs from the embedded migration", m.Version)
			}
			continue
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return errors.New("migration history could not be read")
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return errors.New("migration transaction could not be started")
		}
		if _, err = tx.Exec(ctx, m.SQL, pgx.QueryExecModeSimpleProtocol); err == nil {
			_, err = tx.Exec(ctx,
				"INSERT INTO qg_schema_migrations(version, name, checksum) VALUES ($1, $2, $3)",
				m.Version, m.Name, m.Checksum)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				return fmt.Errorf("migration %d failed (SQLSTATE %s)", m.Version, pgErr.Code)
			}
			return fmt.Errorf("migration %d failed", m.Version)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("migration %d could not be committed", m.Version)
		}
	}
	return nil
}
