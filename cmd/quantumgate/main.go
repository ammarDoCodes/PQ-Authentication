package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"quantumgate/internal/auth"
	"quantumgate/internal/config"
	"quantumgate/internal/gateway"
	"quantumgate/internal/httpapi"
	"quantumgate/internal/keyprovider"
	"quantumgate/internal/storage"
	"quantumgate/internal/webhook"
)

func main() {
	if err := run(); err != nil {
		slog.Error("QuantumGate stopped", "code", "STARTUP_OR_RUNTIME_FAILURE")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration rejected", "code", "INVALID_CONFIGURATION", "reason", err.Error())
		return err
	}
	var selectedProvider keyprovider.Provider
	if cfg.KeyProvider != "vault-transit" {
		providerCtx, cancelProvider := context.WithTimeout(context.Background(), 2*time.Second)
		selectedProvider, err = keyprovider.SelectProvider(providerCtx, cfg.Environment, cfg.KeyProvider)
		cancelProvider()
		if err != nil {
			slog.Error("key provider configuration rejected", "code", "KEY_PROVIDER_UNAVAILABLE")
			return errors.New("configured key provider is unavailable")
		}
	}
	if cfg.KeyProviderRequired && cfg.KeyProvider == "" {
		slog.Error("required key provider is not configured", "code", "KEY_PROVIDER_REQUIRED")
		return errors.New("a key provider is required")
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		slog.Error("database initialization failed", "code", "DATABASE_UNAVAILABLE")
		return errors.New("database initialization failed")
	}
	defer db.Close()
	db.SetMaxOpenConns(30)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing()
	if err := db.PingContext(pingCtx); err != nil {
		slog.Error("database unavailable during startup", "code", "DATABASE_UNAVAILABLE")
		return errors.New("database unavailable")
	}
	roleCtx, cancelRole := context.WithTimeout(context.Background(), 3*time.Second)
	if err := storage.VerifyTenantSafeRole(roleCtx, db); err != nil {
		cancelRole()
		slog.Error("database role rejected", "code", "UNSAFE_DATABASE_ROLE")
		return errors.New("database role is not permitted for the service")
	}
	cancelRole()
	if cfg.KeyProvider == "vault-transit" {
		providerCtx, cancelProvider := context.WithTimeout(context.Background(), 2*time.Second)
		selectedProvider, err = keyprovider.SelectProviderWithConfig(providerCtx, cfg.Environment, cfg.KeyProvider, &keyprovider.VaultConfig{
			Environment: cfg.Environment, Address: cfg.VaultAddress, Namespace: cfg.VaultNamespace,
			TransitMount: cfg.VaultTransitMount, KeyPrefix: cfg.VaultKeyPrefix,
			TokenFile: cfg.VaultTokenFile, CACertFile: cfg.VaultCACertFile,
			Metadata: storage.NewWebhookKeyProviderMetadataStore(db),
		})
		cancelProvider()
		if err != nil {
			slog.Error("Vault provider configuration rejected", "code", "KEY_PROVIDER_UNAVAILABLE")
			return errors.New("configured key provider is unavailable")
		}
	}
	var keyProvider *keyprovider.Broker
	if selectedProvider != nil {
		providerCtx, cancelProvider := context.WithTimeout(context.Background(), 2*time.Second)
		keyProvider, err = keyprovider.NewBroker(providerCtx, cfg.Environment, selectedProvider, storage.NewKeyProviderAuditSink(db))
		cancelProvider()
		if err != nil {
			slog.Error("key provider initialization failed", "code", "KEY_PROVIDER_UNAVAILABLE")
			return errors.New("configured key provider is unavailable")
		}
	}
	rateLimitKey := cfg.RateLimitKey
	if len(rateLimitKey) == 0 {
		rateLimitKey = make([]byte, 32)
		if _, err := cryptorand.Read(rateLimitKey); err != nil {
			return errors.New("rate-limit privacy key could not be initialized")
		}
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var webhookSender *webhook.SenderClient
	if len(cfg.WebhookAllowedHosts) > 0 {
		webhookSender, err = webhook.NewSender(cfg.WebhookAllowedHosts)
		if err != nil {
			slog.Error("webhook allow-list rejected", "code", "INVALID_WEBHOOK_CONFIGURATION")
			return errors.New("webhook host allow-list is invalid")
		}
	}
	var oidcFlow *auth.OIDCFlow
	if cfg.HasOIDC() {
		verifyCtx, cancelVerify := context.WithTimeout(context.Background(), 10*time.Second)
		oidcFlow, err = auth.NewOIDCFlow(verifyCtx, auth.OIDCSettings{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, AllowedHosts: cfg.OIDCAllowedHosts,
			ClientSecret: cfg.OIDCClientSecret, RedirectURL: cfg.OIDCRedirectURL,
			RequiredACR: cfg.OIDCRequiredACR, SigningAlgs: cfg.OIDCSigningAlgs, MaxTokenAge: cfg.OIDCMaxTokenAge,
		})
		cancelVerify()
		if err != nil {
			slog.Error("OIDC provider validation failed", "code", "OIDC_PROVIDER_UNAVAILABLE")
			return errors.New("OIDC provider validation failed")
		}
	}
	api := &httpapi.Server{DB: db, Store: db, OIDC: oidcFlow, OIDCIssuer: cfg.OIDCIssuer, IdentityAllowedHosts: cfg.IdentityAllowedHosts, PublicOrigin: cfg.OIDCOrigin, RateLimitKey: rateLimitKey, CryptoMode: cfg.CryptoMode, Logger: logger, KeyProvider: keyProvider, KeyProviderRequired: cfg.KeyProviderRequired,
		WebhookSigner: keyProvider, WebhookSender: webhookSender, WebhookEnvironment: cfg.Environment}
	var gatewayRoutes []gateway.Route
	if cfg.GatewayRoutesFile != "" {
		gatewayRoutes, err = gateway.LoadRoutesFile(cfg.GatewayRoutesFile, cfg.GatewayUpstreamHosts, cfg.Environment)
		if err != nil {
			slog.Error("gateway route configuration rejected", "code", "INVALID_GATEWAY_CONFIGURATION")
			return errors.New("gateway route configuration is invalid")
		}
		api.Gateway, err = gateway.New(gatewayRoutes, api, logger, cfg.GatewayUpstreamHosts, cfg.Environment)
		if err != nil {
			slog.Error("gateway initialization failed", "code", "GATEWAY_INITIALIZATION_FAILED")
			return errors.New("gateway initialization failed")
		}
	}
	if api.Gateway != nil {
		defer api.Gateway.CloseIdleConnections()
	}
	server := httpapi.NewHTTPServer(cfg.ListenAddr, api.Handler())
	servers := []*http.Server{server}
	if api.Gateway != nil {
		gatewayServer := httpapi.NewHTTPServer(cfg.GatewayListenAddr, api.GatewayHandler())
		servers = append(servers, gatewayServer)
	}
	var certificate tls.Certificate
	if cfg.TLSCertFile != "" {
		certificate, err = tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return errors.New("configured TLS certificate could not be loaded")
		}
		if api.Gateway != nil && gateway.ValidateServerCertificate(certificate, gatewayRoutes) != nil {
			return errors.New("configured TLS certificate does not cover every gateway route hostname")
		}
		for _, configuredServer := range servers {
			tlsConfig := cfg.ServerTLSConfig()
			tlsConfig.Certificates = []tls.Certificate{certificate}
			configuredServer.TLSConfig = tlsConfig
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go httpapi.RunPolicyScheduleWorker(ctx, db, logger)
	if webhookSender != nil && keyProvider != nil {
		go httpapi.RunWebhookDeliveryWorker(ctx, db, keyProvider, webhookSender, cfg.Environment, logger)
	}
	errCh := make(chan error, len(servers))
	for _, configuredServer := range servers {
		go func(configuredServer *http.Server) {
			var err error
			if configuredServer.TLSConfig != nil {
				err = configuredServer.ListenAndServeTLS("", "")
			} else {
				err = configuredServer.ListenAndServe()
			}
			errCh <- err
		}(configuredServer)
	}
	slog.Info("QuantumGate started", "environment", cfg.Environment, "crypto_mode", cfg.CryptoMode, "listeners", len(servers))
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := shutdownServers(shutdownCtx, servers); err != nil {
			return errors.New("graceful shutdown failed")
		}
		return nil
	case err := <-errCh:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr := shutdownServers(shutdownCtx, servers)
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server failed", "code", "HTTP_SERVER_FAILURE")
			return errors.New("HTTP server failed")
		}
		if shutdownErr != nil {
			return errors.New("graceful shutdown failed")
		}
		return nil
	}
}

func shutdownServers(ctx context.Context, servers []*http.Server) error {
	var shutdownFailed bool
	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil {
			shutdownFailed = true
		}
	}
	if shutdownFailed {
		return errors.New("one or more HTTP servers did not shut down cleanly")
	}
	return nil
}
