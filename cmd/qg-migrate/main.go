package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"quantumgate/internal/config"
	"quantumgate/internal/storage"
)

func main() {
	if err := run(); err != nil {
		slog.Error("migration command failed", "code", "MIGRATION_FAILURE")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadMigrationDatabase()
	if err != nil {
		slog.Error("migration configuration rejected", "code", "INVALID_CONFIGURATION", "reason", err.Error())
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return errors.New("database connection failed")
	}
	defer conn.Close(context.Background())
	if err := storage.VerifyTenantSafePGXRole(ctx, conn); err != nil {
		return errors.New("migration database role is not permitted")
	}
	if err := storage.ApplyMigrations(ctx, conn); err != nil {
		return err
	}
	slog.Info("database migrations are current")
	return nil
}
