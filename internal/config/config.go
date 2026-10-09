package config

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type CryptoMode string

const (
	CryptoClassical CryptoMode = "classical-approved"
	CryptoHybrid    CryptoMode = "hybrid-approved"
	CryptoObserve   CryptoMode = "observe-only"
	CryptoPQC       CryptoMode = "pqc-approved"
)

type Config struct {
	Environment          string
	ListenAddr           string
	DatabaseURL          string
	TLSCertFile          string
	TLSKeyFile           string
	GatewayListenAddr    string
	CryptoMode           CryptoMode
	OIDCIssuer           string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCRedirectURL      string
	OIDCOrigin           string
	OIDCAllowedHosts     []string
	IdentityAllowedHosts []string
	GatewayRoutesFile    string
	GatewayUpstreamHosts []string
	WebhookAllowedHosts  []string
	KeyProvider          string
	KeyProviderRequired  bool
	VaultAddress         string
	VaultNamespace       string
	VaultTransitMount    string
	VaultKeyPrefix       string
	VaultTokenFile       string
	VaultCACertFile      string
	OIDCRequiredACR      string
	OIDCSigningAlgs      []string
	OIDCMaxTokenAge      time.Duration
	RateLimitKey         []byte
}

type DatabaseConfig struct {
	Environment string
	DatabaseURL string
}

type BootstrapConfig struct {
	DatabaseConfig
	OIDCIssuer string
}

func Load() (Config, error) { return LoadFrom(os.LookupEnv) }

func LoadDatabase() (DatabaseConfig, error) { return LoadDatabaseFrom(os.LookupEnv) }

func LoadDatabaseFrom(lookup func(string) (string, bool)) (DatabaseConfig, error) {
	environment, databaseURL, err := loadDatabaseBoundary(lookup, "DATABASE_URL")
	if err != nil {
		return DatabaseConfig{}, err
	}
	return DatabaseConfig{Environment: environment, DatabaseURL: databaseURL}, nil
}

func LoadMigrationDatabase() (DatabaseConfig, error) { return LoadMigrationDatabaseFrom(os.LookupEnv) }

func LoadMigrationDatabaseFrom(lookup func(string) (string, bool)) (DatabaseConfig, error) {
	if lookup == nil {
		return DatabaseConfig{}, errors.New("configuration lookup is required")
	}
	environment, migrationURL, err := loadDatabaseBoundary(lookup, "MIGRATION_DATABASE_URL")
	if err == nil || !errors.Is(err, errDatabaseURLMissing) {
		if err != nil {
			return DatabaseConfig{}, err
		}
		return DatabaseConfig{Environment: environment, DatabaseURL: migrationURL}, nil
	}
	get := func(key string) string { value, _ := lookup(key); return strings.TrimSpace(value) }
	environment = get("QG_ENV")
	if environment == "" {
		environment = "development"
	}
	if environment != "development" && environment != "production" {
		return DatabaseConfig{}, errors.New("QG_ENV must be development or production")
	}
	if environment == "production" {
		return DatabaseConfig{}, errors.New("MIGRATION_DATABASE_URL is required in production")
	}
	serviceURL := get("DATABASE_URL")
	if serviceURL == "" {
		return DatabaseConfig{}, errors.New("DATABASE_URL is required")
	}
	if err := validateDatabaseURL(serviceURL, environment); err != nil {
		return DatabaseConfig{}, err
	}
	return DatabaseConfig{Environment: environment, DatabaseURL: serviceURL}, nil
}

var errDatabaseURLMissing = errors.New("database URL is missing")

func loadDatabaseBoundary(lookup func(string) (string, bool), key string) (string, string, error) {
	if lookup == nil {
		return "", "", errors.New("configuration lookup is required")
	}
	get := func(name string) string { value, _ := lookup(name); return strings.TrimSpace(value) }
	environment := get("QG_ENV")
	if environment == "" {
		environment = "development"
	}
	if environment != "development" && environment != "production" {
		return "", "", errors.New("QG_ENV must be development or production")
	}
	databaseURL := get(key)
	if databaseURL == "" {
		return environment, "", errDatabaseURLMissing
	}
	if err := validateDatabaseURL(databaseURL, environment); err != nil {
		return "", "", err
	}
	return environment, databaseURL, nil
}

func LoadBootstrap() (BootstrapConfig, error) { return LoadBootstrapFrom(os.LookupEnv) }

func LoadBootstrapFrom(lookup func(string) (string, bool)) (BootstrapConfig, error) {
	database, err := LoadDatabaseFrom(lookup)
	if err != nil {
		return BootstrapConfig{}, err
	}
	issuer, _ := lookup("OIDC_ISSUER")
	issuer = strings.TrimSpace(issuer)
	if err := validateHTTPSURL(issuer); err != nil {
		return BootstrapConfig{}, errors.New("OIDC_ISSUER must be an HTTPS URL without query or fragment")
	}
	return BootstrapConfig{DatabaseConfig: database, OIDCIssuer: issuer}, nil
}

func LoadFrom(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		return Config{}, errors.New("configuration lookup is required")
	}
	get := func(key string) string { value, _ := lookup(key); return strings.TrimSpace(value) }
	cfg := Config{
		Environment: get("QG_ENV"), ListenAddr: get("LISTEN_ADDR"), DatabaseURL: get("DATABASE_URL"),
		TLSCertFile: get("TLS_CERT_FILE"), TLSKeyFile: get("TLS_KEY_FILE"),
		CryptoMode: CryptoMode(get("CRYPTO_MODE")), OIDCIssuer: get("OIDC_ISSUER"),
		KeyProvider:  get("KEY_PROVIDER"),
		VaultAddress: get("VAULT_ADDR"), VaultNamespace: get("VAULT_NAMESPACE"),
		VaultTransitMount: get("VAULT_TRANSIT_MOUNT"), VaultKeyPrefix: get("VAULT_KEY_PREFIX"),
		VaultTokenFile: get("VAULT_TOKEN_FILE"), VaultCACertFile: get("VAULT_CA_CERT_FILE"),
		OIDCClientID: get("OIDC_CLIENT_ID"), OIDCClientSecret: get("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL: get("OIDC_REDIRECT_URL"), OIDCRequiredACR: get("OIDC_REQUIRED_ACR"),
		GatewayRoutesFile: get("GATEWAY_ROUTES_FILE"), GatewayListenAddr: get("GATEWAY_LISTEN_ADDR"), OIDCMaxTokenAge: 15 * time.Minute,
		OIDCSigningAlgs: []string{"RS256"},
	}
	if cfg.Environment == "" {
		cfg.Environment = "development"
	}
	if cfg.Environment != "development" && cfg.Environment != "production" {
		return Config{}, errors.New("QG_ENV must be development or production")
	}
	if rawRequired := get("KEY_PROVIDER_REQUIRED"); rawRequired != "" {
		var err error
		cfg.KeyProviderRequired, err = strconv.ParseBool(rawRequired)
		if err != nil {
			return Config{}, errors.New("KEY_PROVIDER_REQUIRED must be true or false")
		}
	}
	if cfg.KeyProvider != "" && cfg.KeyProvider != "memory-development" &&
		cfg.KeyProvider != "pqc-development" && cfg.KeyProvider != "vault-transit" {
		return Config{}, errors.New("KEY_PROVIDER names an unsupported provider")
	}
	if (cfg.KeyProvider == "memory-development" || cfg.KeyProvider == "pqc-development") && cfg.Environment != "development" {
		return Config{}, errors.New("development-only key provider cannot be selected in production")
	}
	if cfg.KeyProvider == "vault-transit" {
		if err := validateVaultAddress(cfg.VaultAddress, cfg.Environment); err != nil {
			return Config{}, errors.New("VAULT_ADDR must be a valid HTTPS address in production or a loopback address in development")
		}
		if cfg.VaultTokenFile == "" {
			return Config{}, errors.New("VAULT_TOKEN_FILE is required for vault-transit")
		}
		if cfg.VaultTransitMount != "" && !validVaultPath(cfg.VaultTransitMount) {
			return Config{}, errors.New("VAULT_TRANSIT_MOUNT contains an invalid path")
		}
		if cfg.VaultKeyPrefix != "" && !validVaultPath(cfg.VaultKeyPrefix) {
			return Config{}, errors.New("VAULT_KEY_PREFIX contains an invalid path")
		}
		if strings.ContainsAny(cfg.VaultNamespace, "\r\n\x00") || len(cfg.VaultNamespace) > 512 {
			return Config{}, errors.New("VAULT_NAMESPACE is invalid")
		}
	} else if cfg.VaultAddress != "" || cfg.VaultNamespace != "" || cfg.VaultTransitMount != "" ||
		cfg.VaultKeyPrefix != "" || cfg.VaultTokenFile != "" || cfg.VaultCACertFile != "" {
		return Config{}, errors.New("vault settings require KEY_PROVIDER=vault-transit")
	}
	if cfg.KeyProviderRequired && cfg.KeyProvider == "" {
		return Config{}, errors.New("KEY_PROVIDER is required when key-provider protection is required")
	}
	if cfg.ListenAddr == "" {
		if cfg.Environment == "production" {
			return Config{}, errors.New("LISTEN_ADDR is required in production")
		}
		cfg.ListenAddr = "127.0.0.1:8080"
	}
	if _, err := validateListenAddress(cfg.ListenAddr); err != nil {
		return Config{}, errors.New("LISTEN_ADDR must be a valid TCP host and port")
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.CryptoMode == "" {
		if cfg.Environment == "production" {
			return Config{}, errors.New("CRYPTO_MODE must be explicitly configured in production")
		}
		cfg.CryptoMode = CryptoObserve
	}
	switch cfg.CryptoMode {
	case CryptoClassical, CryptoHybrid, CryptoObserve:
	case CryptoPQC:
		return Config{}, errors.New("pqc-approved is unsupported until a reviewed pure-PQC protocol profile is available")
	default:
		return Config{}, errors.New("CRYPTO_MODE is not a supported policy value")
	}
	if err := validateDatabaseURL(cfg.DatabaseURL, cfg.Environment); err != nil {
		return Config{}, err
	}
	if rawKey := get("RATE_LIMIT_HMAC_KEY"); rawKey != "" {
		if len(rawKey) != 64 {
			return Config{}, errors.New("RATE_LIMIT_HMAC_KEY must be 64 hexadecimal characters")
		}
		key, err := hex.DecodeString(rawKey)
		if err != nil || len(key) != 32 {
			return Config{}, errors.New("RATE_LIMIT_HMAC_KEY must be 64 hexadecimal characters")
		}
		cfg.RateLimitKey = key
	} else if cfg.Environment == "production" {
		return Config{}, errors.New("RATE_LIMIT_HMAC_KEY is required in production")
	}
	if rawHosts := get("IDENTITY_ALLOWED_HOSTS"); rawHosts != "" {
		hosts, err := parseExactHostList(rawHosts, "IDENTITY_ALLOWED_HOSTS")
		if err != nil {
			return Config{}, err
		}
		cfg.IdentityAllowedHosts = hosts
	}
	if rawHosts := get("WEBHOOK_ALLOWED_HOSTS"); rawHosts != "" {
		hosts, err := parseExactHostList(rawHosts, "WEBHOOK_ALLOWED_HOSTS")
		if err != nil {
			return Config{}, err
		}
		cfg.WebhookAllowedHosts = hosts
	}
	if cfg.GatewayRoutesFile == "" && cfg.GatewayListenAddr != "" {
		return Config{}, errors.New("GATEWAY_LISTEN_ADDR requires GATEWAY_ROUTES_FILE")
	}
	if cfg.GatewayRoutesFile != "" {
		if cfg.GatewayListenAddr == "" {
			if cfg.Environment == "production" {
				return Config{}, errors.New("GATEWAY_LISTEN_ADDR is required with GATEWAY_ROUTES_FILE in production")
			}
			cfg.GatewayListenAddr = "127.0.0.1:8444"
		}
		gatewayPort, err := validateListenAddress(cfg.GatewayListenAddr)
		if err != nil {
			return Config{}, errors.New("GATEWAY_LISTEN_ADDR must be a valid TCP host and port")
		}
		apiPort, err := validateListenAddress(cfg.ListenAddr)
		if err == nil && gatewayPort == apiPort {
			return Config{}, errors.New("GATEWAY_LISTEN_ADDR must use a different port from LISTEN_ADDR")
		}
	}
	rawGatewayHosts := get("GATEWAY_UPSTREAM_ALLOWED_HOSTS")
	if cfg.GatewayRoutesFile == "" && rawGatewayHosts != "" {
		return Config{}, errors.New("GATEWAY_UPSTREAM_ALLOWED_HOSTS requires GATEWAY_ROUTES_FILE")
	}
	if cfg.GatewayRoutesFile != "" && rawGatewayHosts != "" {
		hosts, err := parseExactHostList(rawGatewayHosts, "GATEWAY_UPSTREAM_ALLOWED_HOSTS")
		if err != nil {
			return Config{}, err
		}
		cfg.GatewayUpstreamHosts = hosts
	}
	if cfg.GatewayRoutesFile != "" && cfg.Environment == "production" && len(cfg.GatewayUpstreamHosts) == 0 {
		return Config{}, errors.New("GATEWAY_UPSTREAM_ALLOWED_HOSTS is required with GATEWAY_ROUTES_FILE in production")
	}
	if cfg.GatewayRoutesFile != "" && len(cfg.IdentityAllowedHosts) == 0 {
		return Config{}, errors.New("IDENTITY_ALLOWED_HOSTS is required with GATEWAY_ROUTES_FILE")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
	}
	if cfg.GatewayRoutesFile != "" && cfg.TLSCertFile == "" {
		return Config{}, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required when the gateway is enabled")
	}
	if cfg.Environment == "production" {
		if cfg.TLSCertFile == "" {
			return Config{}, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required in production")
		}
	}
	oidcValues := []struct{ name, value string }{
		{"OIDC_ISSUER", cfg.OIDCIssuer},
		{"OIDC_CLIENT_ID", cfg.OIDCClientID},
		{"OIDC_REDIRECT_URL", cfg.OIDCRedirectURL},
		{"OIDC_ALLOWED_HOSTS", get("OIDC_ALLOWED_HOSTS")},
		{"OIDC_REQUIRED_ACR", cfg.OIDCRequiredACR},
	}
	oidcCount := 0
	for _, item := range oidcValues {
		if item.value != "" {
			oidcCount++
		}
	}
	if cfg.OIDCClientSecret != "" {
		oidcCount++
	}
	if cfg.Environment == "production" || oidcCount != 0 {
		for _, item := range oidcValues {
			if item.value == "" {
				return Config{}, fmt.Errorf("%s is required when admin OIDC is enabled", item.name)
			}
		}
		allowedHosts, err := parseAllowedHosts(get("OIDC_ALLOWED_HOSTS"))
		if err != nil {
			return Config{}, err
		}
		cfg.OIDCAllowedHosts = allowedHosts
		cfg.OIDCSigningAlgs, err = parseOIDCSigningAlgs(get("OIDC_SIGNING_ALGS"))
		if err != nil {
			return Config{}, err
		}
		if rawAge := get("OIDC_MAX_TOKEN_AGE"); rawAge != "" {
			cfg.OIDCMaxTokenAge, err = time.ParseDuration(rawAge)
			if err != nil || cfg.OIDCMaxTokenAge < time.Minute || cfg.OIDCMaxTokenAge > time.Hour {
				return Config{}, errors.New("OIDC_MAX_TOKEN_AGE must be between 1m and 1h")
			}
		}
		if err := validateHTTPSURL(cfg.OIDCIssuer); err != nil {
			return Config{}, errors.New("OIDC_ISSUER must be an HTTPS URL without query or fragment")
		}
		if err := validateRedirectURL(cfg.OIDCRedirectURL, cfg.Environment); err != nil {
			return Config{}, errors.New("OIDC_REDIRECT_URL must be a valid callback URL for the configured environment")
		}
		redirectURL, _ := url.Parse(cfg.OIDCRedirectURL)
		cfg.OIDCOrigin = canonicalOrigin(redirectURL)
		issuerURL, _ := url.Parse(cfg.OIDCIssuer)
		if !containsHost(cfg.OIDCAllowedHosts, issuerURL.Hostname()) {
			return Config{}, errors.New("OIDC_ALLOWED_HOSTS must include the OIDC issuer host")
		}
		if len(cfg.OIDCClientID) > 512 || len(cfg.OIDCClientSecret) > 1024 || len(cfg.OIDCRequiredACR) > 512 || strings.ContainsAny(cfg.OIDCRequiredACR, " \t\r\n") {
			return Config{}, errors.New("OIDC client or authentication-context configuration exceeds allowed limits")
		}
	}
	return cfg, nil
}

func validateListenAddress(value string) (string, error) {
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("invalid TCP listen address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", errors.New("invalid TCP listen port")
	}
	return strconv.Itoa(number), nil
}

func parseOIDCSigningAlgs(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{"RS256"}, nil
	}
	allowed := map[string]struct{}{"RS256": {}, "ES256": {}, "PS256": {}, "EdDSA": {}}
	seen := make(map[string]struct{})
	algs := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		alg := strings.TrimSpace(part)
		if _, ok := allowed[alg]; !ok {
			return nil, errors.New("OIDC_SIGNING_ALGS contains an unsupported signing algorithm")
		}
		if _, ok := seen[alg]; ok {
			return nil, errors.New("OIDC_SIGNING_ALGS contains a duplicate signing algorithm")
		}
		seen[alg] = struct{}{}
		algs = append(algs, alg)
	}
	if len(algs) == 0 || len(algs) > len(allowed) {
		return nil, errors.New("OIDC_SIGNING_ALGS must contain at least one supported algorithm")
	}
	return algs, nil
}

func (c Config) HasOIDC() bool { return c.OIDCIssuer != "" }

func parseAllowedHosts(raw string) ([]string, error) {
	return parseExactHostList(raw, "OIDC_ALLOWED_HOSTS")
}

func parseExactHostList(raw, settingName string) ([]string, error) {
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(part), "."))
		if !validHostname(host) || net.ParseIP(host) != nil {
			return nil, fmt.Errorf("%s must be a comma-separated list of exact DNS hostnames", settingName)
		}
		if _, exists := seen[host]; exists {
			return nil, fmt.Errorf("%s contains a duplicate hostname", settingName)
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("%s must contain at least one hostname", settingName)
	}
	return hosts, nil
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

func containsHost(hosts []string, target string) bool {
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	for _, host := range hosts {
		if host == target {
			return true
		}
	}
	return false
}

func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !validHostname(strings.ToLower(u.Hostname())) ||
		u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("invalid HTTPS URL")
	}
	return nil
}

func validateVaultAddress(raw, environment string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" ||
		u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return errors.New("invalid Vault address")
	}
	if port := u.Port(); port != "" {
		number, parseErr := strconv.Atoi(port)
		if parseErr != nil || number < 1 || number > 65535 {
			return errors.New("invalid Vault port")
		}
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" || environment == "production" {
		return errors.New("vault requires HTTPS")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("unencrypted Vault connections are limited to loopback development")
	}
	return nil
}

func validVaultPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, char := range segment {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
				return false
			}
		}
	}
	return true
}

func validateRedirectURL(raw, environment string) error {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "/auth/callback" || u.Opaque != "" {
		return errors.New("invalid OIDC callback URL")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return errors.New("invalid OIDC callback host")
	}
	if environment == "production" {
		if u.Scheme != "https" || !validHostname(host) || net.ParseIP(host) != nil {
			return errors.New("production OIDC callback must use HTTPS and a DNS host")
		}
		return nil
	}
	if u.Scheme == "https" && validHostname(host) && net.ParseIP(host) == nil {
		return nil
	}
	if u.Scheme != "http" || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
		return errors.New("development OIDC callback must use HTTPS or loopback HTTP")
	}
	return nil
}

func canonicalOrigin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host
}

func validateDatabaseURL(raw, environment string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.Path == "" || u.Path == "/" {
		return errors.New("DATABASE_URL must be a PostgreSQL URL with a database name")
	}
	sslmode := u.Query().Get("sslmode")
	if environment == "production" && sslmode != "verify-full" {
		return errors.New("DATABASE_URL must use sslmode=verify-full in production")
	}
	if environment == "development" && sslmode == "disable" {
		host := strings.ToLower(u.Hostname())
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return errors.New("unencrypted database connections are allowed only to localhost in development")
		}
	}
	if sslmode != "" && sslmode != "verify-full" && sslmode != "verify-ca" && sslmode != "require" && sslmode != "disable" {
		return errors.New("DATABASE_URL contains an unsupported sslmode")
	}
	return nil
}

func (c Config) ServerTLSConfig() *tls.Config {
	curves := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	if c.CryptoMode == CryptoClassical {
		curves = []tls.CurveID{tls.X25519, tls.CurveP256}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: curves}
}
