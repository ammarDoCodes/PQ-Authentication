package keyprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const VaultTransit = "vault-transit"

const (
	vaultTokenLimit    = 4096
	vaultResponseLimit = 2 << 20
	vaultRequestLimit  = (maxSigningInput * 4 / 3) + 4096
)

// KeyMetadataStore is the durable QuantumGate state authority for provider
// references. Lock serializes lifecycle changes and signing against the
// tenant-scoped database row; callbacks must not retain the supplied pointer.
type KeyMetadataStore interface {
	Create(context.Context, Scope, Metadata) (Metadata, error)
	Read(context.Context, Scope, string) (Metadata, error)
	Lock(context.Context, Scope, string, func(*Metadata) error) error
}

type VaultConfig struct {
	Environment  string
	Address      string
	Namespace    string
	TransitMount string
	KeyPrefix    string
	TokenFile    string
	CACertFile   string
	Metadata     KeyMetadataStore
}

// VaultProvider is deliberately limited to non-exportable Ed25519 signing.
// It has no API for arbitrary Transit paths, imports, deletion, or private-key
// export. QuantumGate references are generated here and resolved only from
// trusted tenant/application/environment scope.
type VaultProvider struct {
	environment  string
	baseURL      *url.URL
	namespace    string
	transitMount string
	keyPrefix    string
	tokenFile    string
	client       *http.Client
	metadata     KeyMetadataStore
	now          func() time.Time
}

func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	if cfg.Environment != "development" && cfg.Environment != "test" && cfg.Environment != "production" {
		return nil, ErrInvalidScope
	}
	baseURL, err := validateVaultAddress(cfg.Address, cfg.Environment)
	if err != nil || strings.TrimSpace(cfg.TokenFile) == "" || cfg.Metadata == nil {
		return nil, ErrUnsupportedProvider
	}
	if cfg.TransitMount == "" {
		cfg.TransitMount = "transit"
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "quantumgate"
	}
	if !validVaultPath(cfg.TransitMount) || !validVaultPath(cfg.KeyPrefix) || strings.ContainsAny(cfg.Namespace, "\r\n\x00") || len(cfg.Namespace) > 512 {
		return nil, ErrUnsupportedProvider
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertFile != "" {
		pem, readErr := os.ReadFile(cfg.CACertFile)
		if readErr != nil {
			return nil, ErrUnsupportedProvider
		}
		roots, poolErr := x509.SystemCertPool()
		if poolErr != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, ErrUnsupportedProvider
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &VaultProvider{
		environment: cfg.Environment, baseURL: baseURL, namespace: cfg.Namespace,
		transitMount: strings.Trim(cfg.TransitMount, "/"), keyPrefix: strings.Trim(cfg.KeyPrefix, "/"),
		tokenFile: cfg.TokenFile, client: client, metadata: cfg.Metadata, now: time.Now,
	}, nil
}

func (p *VaultProvider) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	return Capabilities{
		Provider: VaultTransit, DevelopmentOnly: false, Persistent: true,
		PrivateMaterialExport: false, ProtectedKeyCustody: true,
		Algorithms: []Algorithm{AlgorithmEd25519},
		Operations: []Operation{OperationGenerate, OperationMetadata, OperationPublicKey, OperationSign,
			OperationActivate, OperationRotate, OperationDisable, OperationRevoke, OperationExpire, OperationHealth},
	}, nil
}

// Health confirms an initialized, unsealed active Vault and an authenticated
// read against the configured Transit mount. It does not assert that a key
// exists or that an arbitrary caller has authorization for every operation.
func (p *VaultProvider) Health(ctx context.Context) error {
	if p == nil {
		return ErrProviderUnavailable
	}
	var health struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
		Standby     bool `json:"standby"`
	}
	if err := p.requestJSON(ctx, http.MethodGet, "sys/health", nil, &health); err != nil {
		return sanitizeProviderError(err)
	}
	if !health.Initialized || health.Sealed || health.Standby {
		return ErrProviderUnavailable
	}
	var config struct {
		Data struct {
			DisableUpsert bool `json:"disable_upsert"`
		} `json:"data"`
	}
	if err := p.requestJSON(ctx, http.MethodGet, p.transitMount+"/config/keys", nil, &config); err != nil {
		return sanitizeProviderError(err)
	}
	return nil
}

func (p *VaultProvider) Generate(ctx context.Context, scope Scope, spec KeySpec) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if p == nil || !p.validScope(scope) {
		return Metadata{}, ErrInvalidScope
	}
	if !validKeySpec(spec) {
		return Metadata{}, ErrInvalidKeySpec
	}
	if spec.Purpose != PurposeSigning || spec.Algorithm != AlgorithmEd25519 {
		return Metadata{}, ErrUnsupported
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Metadata{}, ErrProviderUnavailable
	}
	reference := "vault_" + base64.RawURLEncoding.EncodeToString(random[:])
	name, err := p.keyName(scope, reference)
	if err != nil {
		return Metadata{}, err
	}
	create := map[string]any{
		"type": "ed25519", "derived": false, "exportable": false,
		"allow_plaintext_backup": false,
	}
	if err := p.requestJSON(ctx, http.MethodPost, p.keyEndpoint(name), create, nil); err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	// Transit-created keys start signable. Immediately raise the minimum
	// signing version so an unpublished provisioning key is unusable.
	if err := p.setSigningFloor(ctx, name, 2); err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	if _, err := p.readVaultKey(ctx, name); err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	item := Metadata{
		Provider: VaultTransit, Reference: reference, Purpose: spec.Purpose, Algorithm: spec.Algorithm,
		State: StateProvisioning, CreatedAt: p.now().UTC(), UpdatedAt: p.now().UTC(), ExpiresAt: spec.ExpiresAt.UTC(),
	}
	item, err = p.metadata.Create(ctx, scope, item)
	if err != nil {
		// The Transit key remains non-signable. Its opaque name is not returned,
		// and no fallback provider is attempted.
		return Metadata{}, sanitizeProviderError(err)
	}
	return cloneMetadata(item), nil
}

func (p *VaultProvider) Metadata(ctx context.Context, scope Scope, reference string) (Metadata, error) {
	item, err := p.readMetadata(ctx, scope, reference)
	if err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	if item.State == StateActive && !p.now().Before(item.ExpiresAt) {
		_, transitionErr := p.Transition(ctx, scope, reference, StateActive, StateExpired)
		if transitionErr != nil && !errors.Is(transitionErr, ErrStaleTransition) {
			return Metadata{}, sanitizeProviderError(transitionErr)
		}
		item, err = p.metadata.Read(ctx, scope, reference)
		if err != nil {
			return Metadata{}, sanitizeProviderError(err)
		}
	}
	keyName, err := p.keyName(scope, reference)
	if err != nil {
		return Metadata{}, err
	}
	vaultKey, err := p.readVaultKey(ctx, keyName)
	if err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	if !vaultStateMatches(item.State, vaultKey.MinEncryptionVersion) {
		return Metadata{}, ErrKeyUnavailable
	}
	return cloneMetadata(item), nil
}

func (p *VaultProvider) PublicKey(ctx context.Context, scope Scope, reference string) ([]byte, error) {
	item, err := p.readMetadata(ctx, scope, reference)
	if err != nil {
		return nil, sanitizeProviderError(err)
	}
	if item.Algorithm != AlgorithmEd25519 {
		return nil, ErrUnsupported
	}
	name, err := p.keyName(scope, reference)
	if err != nil {
		return nil, err
	}
	vaultKey, err := p.readVaultKey(ctx, name)
	if err != nil {
		return nil, sanitizeProviderError(err)
	}
	public, err := parseVaultEd25519PublicKey(vaultKey.Keys["1"].PublicKey)
	if err != nil {
		return nil, ErrMalformedResponse
	}
	material, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, ErrMalformedResponse
	}
	return material, nil
}

func (p *VaultProvider) Sign(ctx context.Context, scope Scope, reference string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if p == nil || !p.validScope(scope) || !validVaultReference(reference) {
		return nil, ErrKeyNotFound
	}
	if len(digest) == 0 || len(digest) > maxSigningInput || opts == nil || opts.HashFunc() != 0 {
		return nil, ErrInvalidKeySpec
	}
	var signature []byte
	var operationErr error
	err := p.metadata.Lock(ctx, scope, reference, func(item *Metadata) error {
		if !validVaultMetadata(*item) || item.Purpose != PurposeSigning || item.Algorithm != AlgorithmEd25519 {
			operationErr = ErrKeyUnavailable
			return nil
		}
		name, err := p.keyName(scope, reference)
		if err != nil {
			return err
		}
		key, err := p.readVaultKey(ctx, name)
		if err != nil {
			return err
		}
		if item.State != StateActive {
			operationErr = ErrKeyUnavailable
			return nil
		}
		if !p.now().Before(item.ExpiresAt) {
			if err := p.setSigningFloor(ctx, name, 2); err != nil {
				return err
			}
			item.State = StateExpired
			item.UpdatedAt = p.now().UTC()
			operationErr = ErrKeyUnavailable
			return nil
		}
		if !vaultStateMatches(item.State, key.MinEncryptionVersion) {
			operationErr = ErrKeyUnavailable
			return nil
		}
		var response struct {
			Data struct {
				Signature string `json:"signature"`
			} `json:"data"`
		}
		payload := map[string]any{
			"input":       base64.StdEncoding.EncodeToString(digest),
			"key_version": 1,
		}
		if err := p.requestJSON(ctx, http.MethodPost, p.keyEndpoint(name)+"/sign", payload, &response); err != nil {
			return err
		}
		signature, err = parseVaultSignature(response.Data.Signature)
		if err != nil {
			return ErrMalformedResponse
		}
		return nil
	})
	if err != nil {
		return nil, sanitizeProviderError(err)
	}
	if operationErr != nil {
		return nil, operationErr
	}
	return append([]byte(nil), signature...), nil
}

func (p *VaultProvider) Transition(ctx context.Context, scope Scope, reference string, expected, target State) (Metadata, error) {
	if p == nil || !p.validScope(scope) || !validVaultReference(reference) {
		return Metadata{}, ErrKeyNotFound
	}
	if target == StateDestroyed {
		return Metadata{}, ErrUnsupported
	}
	var operationErr error
	err := p.metadata.Lock(ctx, scope, reference, func(item *Metadata) error {
		if !validVaultMetadata(*item) {
			operationErr = ErrMalformedResponse
			return nil
		}
		if item.State != expected {
			operationErr = ErrStaleTransition
			return nil
		}
		if item.State == target {
			return nil
		}
		if !allowedTransition(item.State, target) {
			operationErr = ErrInvalidTransition
			return nil
		}
		if target == StateActive && !p.now().Before(item.ExpiresAt) {
			operationErr = ErrKeyUnavailable
			return nil
		}
		name, err := p.keyName(scope, reference)
		if err != nil {
			return err
		}
		if _, err := p.readVaultKey(ctx, name); err != nil {
			return err
		}
		floor := 2
		if target == StateActive {
			floor = 1
		}
		if err := p.setSigningFloor(ctx, name, floor); err != nil {
			return err
		}
		item.State = target
		item.UpdatedAt = p.now().UTC()
		return nil
	})
	if err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	if operationErr != nil {
		return Metadata{}, operationErr
	}
	item, err := p.metadata.Read(ctx, scope, reference)
	if err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	return cloneMetadata(item), nil
}

type vaultTransitKey struct {
	Type                 string                            `json:"type"`
	LatestVersion        int                               `json:"latest_version"`
	MinEncryptionVersion int                               `json:"min_encryption_version"`
	Exportable           bool                              `json:"exportable"`
	PlaintextBackup      bool                              `json:"allow_plaintext_backup"`
	DeletionAllowed      bool                              `json:"deletion_allowed"`
	SupportsSigning      bool                              `json:"supports_signing"`
	Keys                 map[string]vaultTransitKeyVersion `json:"keys"`
}

type vaultTransitKeyVersion struct {
	PublicKey string `json:"public_key"`
}

func (p *VaultProvider) readVaultKey(ctx context.Context, name string) (vaultTransitKey, error) {
	var response struct {
		Data vaultTransitKey `json:"data"`
	}
	if err := p.requestJSON(ctx, http.MethodGet, p.keyEndpoint(name), nil, &response); err != nil {
		return vaultTransitKey{}, err
	}
	key := response.Data
	if key.Type != "ed25519" || key.LatestVersion != 1 || key.Exportable || key.PlaintextBackup ||
		key.DeletionAllowed || !key.SupportsSigning || len(key.Keys) != 1 || key.Keys["1"].PublicKey == "" {
		return vaultTransitKey{}, ErrMalformedResponse
	}
	if _, err := parseVaultEd25519PublicKey(key.Keys["1"].PublicKey); err != nil {
		return vaultTransitKey{}, ErrMalformedResponse
	}
	return key, nil
}

func (p *VaultProvider) setSigningFloor(ctx context.Context, name string, floor int) error {
	return p.requestJSON(ctx, http.MethodPost, p.keyEndpoint(name)+"/config", map[string]any{
		"min_encryption_version": floor,
	}, nil)
}

func (p *VaultProvider) readMetadata(ctx context.Context, scope Scope, reference string) (Metadata, error) {
	if p == nil || !p.validScope(scope) || !validVaultReference(reference) {
		return Metadata{}, ErrKeyNotFound
	}
	item, err := p.metadata.Read(ctx, scope, reference)
	if err != nil {
		return Metadata{}, err
	}
	if !validVaultMetadata(item) || item.Provider != VaultTransit || item.Reference != reference {
		return Metadata{}, ErrMalformedResponse
	}
	return item, nil
}

func (p *VaultProvider) validScope(scope Scope) bool {
	return validScope(scope) && scope.Environment == p.environment
}

func (p *VaultProvider) keyName(scope Scope, reference string) (string, error) {
	if !p.validScope(scope) || !validVaultReference(reference) {
		return "", ErrKeyNotFound
	}
	return path.Join(p.keyPrefix, scope.Environment, strings.ToLower(scope.TenantID),
		strings.ToLower(scope.ApplicationID), "signing", reference), nil
}

func (p *VaultProvider) keyEndpoint(name string) string {
	return p.transitMount + "/keys/" + name
}

func (p *VaultProvider) requestJSON(ctx context.Context, method, endpoint string, input, output any) error {
	if p == nil {
		return ErrProviderUnavailable
	}
	tokenBytes, err := os.ReadFile(p.tokenFile)
	if err != nil {
		return ErrProviderUnavailable
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) == 0 || len(token) > vaultTokenLimit || strings.ContainsAny(token, " \t\r\n\x00") {
		return ErrProviderUnavailable
	}
	var body io.Reader
	if input != nil {
		encoded, marshalErr := json.Marshal(input)
		if marshalErr != nil || len(encoded) > vaultRequestLimit {
			return ErrInvalidKeySpec
		}
		body = bytes.NewReader(encoded)
	}
	u := *p.baseURL
	u.Path = path.Join("/v1", endpoint)
	u.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return ErrProviderUnavailable
	}
	request.Header.Set("X-Vault-Token", token)
	if p.namespace != "" {
		request.Header.Set("X-Vault-Namespace", p.namespace)
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.client.Do(request)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ErrProviderTimeout
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return context.Canceled
		}
		return ErrProviderUnavailable
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, vaultResponseLimit+1))
	if err != nil || len(data) > vaultResponseLimit {
		return ErrMalformedResponse
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return ErrProviderDenied
		case http.StatusNotFound:
			return ErrKeyNotFound
		case http.StatusTooManyRequests:
			return ErrProviderUnavailable
		default:
			if response.StatusCode >= 500 || response.StatusCode == http.StatusMovedPermanently ||
				response.StatusCode == http.StatusFound || response.StatusCode == http.StatusTemporaryRedirect ||
				response.StatusCode == http.StatusPermanentRedirect {
				return ErrProviderUnavailable
			}
			return ErrMalformedResponse
		}
	}
	if output != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return ErrMalformedResponse
		}
	}
	return nil
}

func parseVaultSignature(value string) ([]byte, error) {
	prefix, encoded, ok := strings.Cut(value, ":")
	if !ok || prefix != "vault" {
		return nil, ErrMalformedResponse
	}
	version, encoded, ok := strings.Cut(encoded, ":")
	if !ok || version != "v1" {
		return nil, ErrMalformedResponse
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrMalformedResponse
	}
	return signature, nil
}

func parseVaultEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	public, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		public, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, ErrMalformedResponse
	}
	return ed25519.PublicKey(public), nil
}

func validVaultMetadata(item Metadata) bool {
	return validMetadata(item) && item.Provider == VaultTransit && item.Purpose == PurposeSigning &&
		item.Algorithm == AlgorithmEd25519 && validVaultReference(item.Reference)
}

func vaultStateMatches(state State, minEncryptionVersion int) bool {
	if minEncryptionVersion < 0 {
		return false
	}
	if state == StateActive {
		return minEncryptionVersion == 0 || minEncryptionVersion == 1
	}
	return minEncryptionVersion >= 2
}

func validVaultReference(value string) bool {
	if !strings.HasPrefix(value, "vault_") {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "vault_"))
	return err == nil && len(raw) == 32
}

func validateVaultAddress(raw, environment string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" ||
		u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrUnsupportedProvider
	}
	port := u.Port()
	if port != "" {
		number, parseErr := strconv.Atoi(port)
		if parseErr != nil || number < 1 || number > 65535 {
			return nil, ErrUnsupportedProvider
		}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if environment == "production" || !isLoopbackHost(u.Hostname()) {
			return nil, ErrUnsupportedProvider
		}
	default:
		return nil, ErrUnsupportedProvider
	}
	u.Path = ""
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

var _ Provider = (*VaultProvider)(nil)
