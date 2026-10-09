package config

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

func lookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}

func TestLoadFromAppliesDevelopmentDefaults(t *testing.T) {
	cfg, err := LoadFrom(lookup(map[string]string{"DATABASE_URL": "postgres://qg:secret@localhost:5432/qg?sslmode=disable"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:8080" || cfg.CryptoMode != CryptoObserve {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.KeyProvider != "" || cfg.KeyProviderRequired {
		t.Fatalf("key-provider operations must remain unconfigured by default: %+v", cfg)
	}
}

func TestKeyProviderConfigurationIsExplicitAndDevelopmentOnly(t *testing.T) {
	dev, err := LoadFrom(lookup(map[string]string{
		"QG_ENV": "development", "DATABASE_URL": "postgres://qg:secret@localhost:5432/qg?sslmode=disable",
		"KEY_PROVIDER": "memory-development", "KEY_PROVIDER_REQUIRED": "true",
	}))
	if err != nil || dev.KeyProvider != "memory-development" || !dev.KeyProviderRequired {
		t.Fatalf("explicit development provider should load only in development: %+v %v", dev, err)
	}

	for name, mutate := range map[string]func(map[string]string){
		"development provider in production": func(values map[string]string) { values["KEY_PROVIDER"] = "memory-development" },
		"required provider missing":          func(values map[string]string) { values["KEY_PROVIDER_REQUIRED"] = "true" },
		"unknown production provider":        func(values map[string]string) { values["KEY_PROVIDER"] = "aws-kms" },
		"malformed required flag":            func(values map[string]string) { values["KEY_PROVIDER_REQUIRED"] = "yes" },
	} {
		t.Run(name, func(t *testing.T) {
			values := productionConfig()
			mutate(values)
			if _, err := LoadFrom(lookup(values)); err == nil {
				t.Fatal("unsafe or unsupported key-provider configuration should fail closed")
			}
		})
	}
}

func TestPQCDevelopmentProviderConfigurationIsDevelopmentOnly(t *testing.T) {
	values := map[string]string{
		"QG_ENV": "development", "DATABASE_URL": "postgres://qg@localhost:5432/qg?sslmode=disable",
		"KEY_PROVIDER": "pqc-development",
	}
	if cfg, err := LoadFrom(lookup(values)); err != nil || cfg.KeyProvider != "pqc-development" {
		t.Fatalf("explicit PQC development provider should load in development: %+v %v", cfg, err)
	}
	values["QG_ENV"] = "production"
	if _, err := LoadFrom(lookup(values)); err == nil {
		t.Fatal("PQC development provider must be rejected in production")
	}
}

func TestVaultProviderConfigurationRequiresScopedAuthenticationAndTLS(t *testing.T) {
	development := map[string]string{
		"QG_ENV": "development", "DATABASE_URL": "postgres://qg@localhost:5432/qg?sslmode=disable",
		"KEY_PROVIDER": "vault-transit", "VAULT_ADDR": "http://127.0.0.1:8200",
		"VAULT_TOKEN_FILE": "/run/secrets/vault-agent-token",
	}
	if cfg, err := LoadFrom(lookup(development)); err != nil || cfg.KeyProvider != "vault-transit" {
		t.Fatalf("development Vault configuration = %+v, %v", cfg, err)
	}
	production := productionConfig()
	production["KEY_PROVIDER"] = "vault-transit"
	production["VAULT_ADDR"] = "https://vault.example:8200"
	production["VAULT_TOKEN_FILE"] = "/run/secrets/vault-agent-token"
	if cfg, err := LoadFrom(lookup(production)); err != nil || cfg.VaultAddress != production["VAULT_ADDR"] {
		t.Fatalf("production Vault configuration = %+v, %v", cfg, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing token sink":       func(values map[string]string) { delete(values, "VAULT_TOKEN_FILE") },
		"remote plaintext address": func(values map[string]string) { values["VAULT_ADDR"] = "http://vault.example:8200" },
		"path traversal mount":     func(values map[string]string) { values["VAULT_TRANSIT_MOUNT"] = "transit/../sys" },
	} {
		t.Run(name, func(t *testing.T) {
			values := make(map[string]string, len(production))
			for key, value := range production {
				values[key] = value
			}
			mutate(values)
			if _, err := LoadFrom(lookup(values)); err == nil {
				t.Fatal("unsafe Vault configuration must fail closed")
			}
		})
	}
	withoutProvider := map[string]string{
		"DATABASE_URL": "postgres://qg@localhost:5432/qg?sslmode=disable", "VAULT_TOKEN_FILE": "/run/secrets/token",
	}
	if _, err := LoadFrom(lookup(withoutProvider)); err == nil {
		t.Fatal("Vault credentials must not be accepted when no Vault provider is selected")
	}
}

func TestWebhookAllowedHostsRequireExactDNSNames(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":          "postgres://qg@localhost:5432/qg?sslmode=disable",
		"WEBHOOK_ALLOWED_HOSTS": "hooks.customer.example,events.partner.example",
	}
	cfg, err := LoadFrom(lookup(values))
	if err != nil || strings.Join(cfg.WebhookAllowedHosts, ",") != "hooks.customer.example,events.partner.example" {
		t.Fatalf("webhook allow-list = %+v, %v", cfg.WebhookAllowedHosts, err)
	}
	for _, raw := range []string{"*.example.com", "127.0.0.1", "hooks.example.com,HOOKS.example.com", "hooks.example.com:443"} {
		values["WEBHOOK_ALLOWED_HOSTS"] = raw
		if _, err := LoadFrom(lookup(values)); err == nil {
			t.Errorf("unsafe webhook host allow-list accepted: %q", raw)
		}
	}
}

func TestLoadFromRejectsProductionWithoutExplicitSecurityConfig(t *testing.T) {
	_, err := LoadFrom(lookup(map[string]string{"QG_ENV": "production", "DATABASE_URL": "postgres://qg:secret@db.example:5432/qg?sslmode=verify-full"}))
	if err == nil || !strings.Contains(err.Error(), "LISTEN_ADDR") {
		t.Fatalf("expected fail-closed config, got %v", err)
	}
}

func TestLoadFromRejectsPlaintextRemoteDatabase(t *testing.T) {
	_, err := LoadFrom(lookup(map[string]string{"DATABASE_URL": "postgres://qg:secret@db.example:5432/qg?sslmode=disable"}))
	if err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("expected plaintext remote DB rejection, got %v", err)
	}
}

func TestLoadFromRejectsUnreviewedPQCOnlyMode(t *testing.T) {
	_, err := LoadFrom(lookup(map[string]string{"DATABASE_URL": "postgres://qg@localhost/qg?sslmode=disable", "CRYPTO_MODE": "pqc-approved"}))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported pure-PQC mode rejection, got %v", err)
	}
}

func productionConfig() map[string]string {
	return map[string]string{
		"QG_ENV": "production", "LISTEN_ADDR": "0.0.0.0:8443",
		"DATABASE_URL":  "postgres://qg:secret@db.example:5432/qg?sslmode=verify-full",
		"TLS_CERT_FILE": "/run/secrets/server.crt", "TLS_KEY_FILE": "/run/secrets/server.key",
		"CRYPTO_MODE": "hybrid-approved", "OIDC_ISSUER": "https://id.example",
		"OIDC_CLIENT_ID":         "quantumgate",
		"OIDC_REDIRECT_URL":      "https://console.example/auth/callback",
		"OIDC_ALLOWED_HOSTS":     "id.example, keys.id.example",
		"IDENTITY_ALLOWED_HOSTS": "customer-id.example, keys.customer-id.example",
		"OIDC_REQUIRED_ACR":      "urn:example:admin-mfa",
		"RATE_LIMIT_HMAC_KEY":    strings.Repeat("a", 64),
	}
}

func TestProductionConfigurationAcceptsExplicitBoundaries(t *testing.T) {
	cfg, err := LoadFrom(lookup(productionConfig()))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasOIDC() || len(cfg.OIDCAllowedHosts) != 2 || cfg.OIDCRequiredACR != "urn:example:admin-mfa" {
		t.Fatalf("OIDC boundary configuration not loaded: %+v", cfg)
	}
	if cfg.OIDCOrigin != "https://console.example" {
		t.Fatalf("unexpected browser origin: %q", cfg.OIDCOrigin)
	}
	if len(cfg.IdentityAllowedHosts) != 2 || cfg.IdentityAllowedHosts[0] != "customer-id.example" {
		t.Fatalf("identity adapter egress allowlist was not loaded: %v", cfg.IdentityAllowedHosts)
	}
	if len(cfg.OIDCSigningAlgs) != 1 || cfg.OIDCSigningAlgs[0] != "RS256" || cfg.OIDCMaxTokenAge != 15*time.Minute {
		t.Fatalf("OIDC verification defaults are unexpected: %+v", cfg)
	}
}

func TestIdentityHostAllowlistRejectsIPsAndDuplicates(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "customer-id.example,customer-id.example"} {
		if _, err := parseExactHostList(raw, "IDENTITY_ALLOWED_HOSTS"); err == nil {
			t.Errorf("unsafe identity host list was accepted: %q", raw)
		}
	}
}

func TestProductionRequiresRandomizedRateLimitKey(t *testing.T) {
	values := productionConfig()
	delete(values, "RATE_LIMIT_HMAC_KEY")
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "RATE_LIMIT_HMAC_KEY") {
		t.Fatalf("production must require a rate-limit HMAC key, got %v", err)
	}
	values = productionConfig()
	values["RATE_LIMIT_HMAC_KEY"] = "not-hex"
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "64 hexadecimal") {
		t.Fatalf("malformed rate-limit HMAC key should be rejected, got %v", err)
	}
}

func TestOIDCSigningAlgorithmsAreAnExplicitAllowlist(t *testing.T) {
	values := productionConfig()
	values["OIDC_SIGNING_ALGS"] = "ES256,RS256"
	cfg, err := LoadFrom(lookup(values))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.OIDCSigningAlgs, ",") != "ES256,RS256" {
		t.Fatalf("unexpected signing algorithm list: %v", cfg.OIDCSigningAlgs)
	}
	values["OIDC_SIGNING_ALGS"] = "none,RS256"
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "unsupported signing algorithm") {
		t.Fatalf("expected unsupported signing algorithm rejection, got %v", err)
	}
}

func TestProductionRequiresVerifiedDatabaseTLS(t *testing.T) {
	values := productionConfig()
	values["DATABASE_URL"] = "postgres://qg:secret@db.example:5432/qg?sslmode=require"
	_, err := LoadFrom(lookup(values))
	if err == nil || !strings.Contains(err.Error(), "verify-full") {
		t.Fatalf("expected strict DB TLS, got %v", err)
	}
}

func TestGatewayConfigurationRequiresTLSAndAllowlistedProductionUpstreams(t *testing.T) {
	values := productionConfig()
	values["GATEWAY_ROUTES_FILE"] = "/run/config/gateway-routes.json"
	values["GATEWAY_LISTEN_ADDR"] = "0.0.0.0:9443"
	values["GATEWAY_UPSTREAM_ALLOWED_HOSTS"] = "orders.internal.example, catalog.internal.example"
	values["IDENTITY_ALLOWED_HOSTS"] = "customer-id.example"
	cfg, err := LoadFrom(lookup(values))
	if err != nil {
		t.Fatal("valid gateway configuration rejected:", err)
	}
	if cfg.GatewayRoutesFile != values["GATEWAY_ROUTES_FILE"] || cfg.GatewayListenAddr != values["GATEWAY_LISTEN_ADDR"] || strings.Join(cfg.GatewayUpstreamHosts, ",") != "orders.internal.example,catalog.internal.example" {
		t.Fatalf("gateway configuration not loaded: %+v", cfg)
	}

	values = productionConfig()
	values["GATEWAY_ROUTES_FILE"] = "/run/config/gateway-routes.json"
	values["GATEWAY_UPSTREAM_ALLOWED_HOSTS"] = "orders.internal.example"
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "GATEWAY_LISTEN_ADDR") {
		t.Fatalf("production gateway must require its dedicated listener address, got %v", err)
	}
	values = productionConfig()
	values["GATEWAY_ROUTES_FILE"] = "/run/config/gateway-routes.json"
	values["GATEWAY_LISTEN_ADDR"] = "0.0.0.0:9443"
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "GATEWAY_UPSTREAM_ALLOWED_HOSTS") {
		t.Fatalf("production gateway must require its backend host allowlist, got %v", err)
	}
	values = productionConfig()
	values["GATEWAY_ROUTES_FILE"] = "/run/config/gateway-routes.json"
	values["GATEWAY_LISTEN_ADDR"] = "0.0.0.0:9443"
	values["GATEWAY_UPSTREAM_ALLOWED_HOSTS"] = "orders.internal.example"
	delete(values, "IDENTITY_ALLOWED_HOSTS")
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "IDENTITY_ALLOWED_HOSTS") {
		t.Fatalf("gateway must require its customer identity provider allowlist, got %v", err)
	}

	values = map[string]string{"DATABASE_URL": "postgres://qg@localhost/qg?sslmode=disable", "GATEWAY_ROUTES_FILE": "routes.json", "IDENTITY_ALLOWED_HOSTS": "customer-id.example"}
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "TLS_CERT_FILE") {
		t.Fatalf("gateway must require TLS termination even in development, got %v", err)
	}
}

func TestGatewayListenerIsSeparateAndBounded(t *testing.T) {
	base := map[string]string{
		"DATABASE_URL": "postgres://qg@localhost/qg?sslmode=disable", "GATEWAY_ROUTES_FILE": "routes.json",
		"TLS_CERT_FILE": "server.crt", "TLS_KEY_FILE": "server.key", "IDENTITY_ALLOWED_HOSTS": "customer-id.example",
	}
	if cfg, err := LoadFrom(lookup(base)); err != nil || cfg.GatewayListenAddr != "127.0.0.1:8444" {
		t.Fatalf("development gateway should receive a loopback listener default: %+v %v", cfg, err)
	}
	base["GATEWAY_LISTEN_ADDR"] = "127.0.0.1:8080"
	if _, err := LoadFrom(lookup(base)); err == nil || !strings.Contains(err.Error(), "different port") {
		t.Fatalf("gateway must not share the control-plane listener port, got %v", err)
	}
	base["GATEWAY_LISTEN_ADDR"] = "127.0.0.1:99999"
	if _, err := LoadFrom(lookup(base)); err == nil || !strings.Contains(err.Error(), "valid TCP host and port") {
		t.Fatalf("out-of-range gateway listener port must be rejected, got %v", err)
	}
	delete(base, "GATEWAY_ROUTES_FILE")
	if _, err := LoadFrom(lookup(base)); err == nil || !strings.Contains(err.Error(), "GATEWAY_ROUTES_FILE") {
		t.Fatalf("gateway listener without route configuration must be rejected, got %v", err)
	}
}

func TestGatewayUpstreamAllowlistCannotBeSetWithoutRouteFile(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":                   "postgres://qg@localhost/qg?sslmode=disable",
		"GATEWAY_UPSTREAM_ALLOWED_HOSTS": "orders.internal.example",
	}
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "GATEWAY_ROUTES_FILE") {
		t.Fatalf("gateway backend allowlist must be tied to a route configuration, got %v", err)
	}
}

func TestDatabaseCommandsLoadOnlyDatabaseSecuritySettings(t *testing.T) {
	values := map[string]string{
		"QG_ENV": "production", "DATABASE_URL": "postgres://qg:secret@db.example:5432/qg?sslmode=verify-full",
		"MIGRATION_DATABASE_URL": "postgres://qg_migrator:secret@db.example:5432/qg?sslmode=verify-full",
	}
	cfg, err := LoadDatabaseFrom(lookup(values))
	if err != nil || cfg.Environment != "production" {
		t.Fatalf("database-only command config should not require HTTP settings: %+v %v", cfg, err)
	}
	if _, err := LoadBootstrapFrom(lookup(map[string]string{
		"QG_ENV": "production", "DATABASE_URL": values["DATABASE_URL"], "OIDC_ISSUER": "https://id.example",
	})); err != nil {
		t.Fatalf("bootstrap config should require only a verified issuer and runtime database: %v", err)
	}
	migrationConfig, err := LoadMigrationDatabaseFrom(lookup(map[string]string{
		"QG_ENV": "production", "MIGRATION_DATABASE_URL": values["MIGRATION_DATABASE_URL"],
	}))
	if err != nil || migrationConfig.DatabaseURL != values["MIGRATION_DATABASE_URL"] {
		t.Fatalf("migration config should require only its secured migration database: %+v %v", migrationConfig, err)
	}
	if _, err := LoadMigrationDatabaseFrom(lookup(map[string]string{
		"QG_ENV": "production", "DATABASE_URL": values["DATABASE_URL"],
	})); err == nil || !strings.Contains(err.Error(), "MIGRATION_DATABASE_URL") {
		t.Fatalf("production migration config must require its separate credential, got %v", err)
	}
}

func TestOIDCIssuerMustBeInExactHostAllowlist(t *testing.T) {
	values := productionConfig()
	values["OIDC_ALLOWED_HOSTS"] = "*.example"
	_, err := LoadFrom(lookup(values))
	if err == nil || !strings.Contains(err.Error(), "exact DNS") {
		t.Fatalf("expected wildcard host to be rejected, got %v", err)
	}
}

func TestDevelopmentRejectsPartialOIDCConfiguration(t *testing.T) {
	_, err := LoadFrom(lookup(map[string]string{
		"DATABASE_URL": "postgres://qg@localhost/qg?sslmode=disable",
		"OIDC_ISSUER":  "https://id.example",
	}))
	if err == nil || !strings.Contains(err.Error(), "OIDC_CLIENT_ID") {
		t.Fatalf("expected partial OIDC configuration rejection, got %v", err)
	}
}

func TestOIDCRedirectMustUseExpectedCallbackAndSecureOrigin(t *testing.T) {
	values := productionConfig()
	values["OIDC_REDIRECT_URL"] = "http://console.example/auth/callback"
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "callback URL") {
		t.Fatalf("expected production HTTP callback rejection, got %v", err)
	}
	values["OIDC_REDIRECT_URL"] = "https://console.example/other"
	if _, err := LoadFrom(lookup(values)); err == nil || !strings.Contains(err.Error(), "callback URL") {
		t.Fatalf("expected callback path rejection, got %v", err)
	}
}

func TestServerTLSConfigUsesExplicitHybridPreference(t *testing.T) {
	tlsConfig := (Config{CryptoMode: CryptoHybrid}).ServerTLSConfig()
	if tlsConfig.MinVersion != tls.VersionTLS13 || len(tlsConfig.CurvePreferences) == 0 || tlsConfig.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("hybrid TLS profile is not configured: %+v", tlsConfig)
	}
}
