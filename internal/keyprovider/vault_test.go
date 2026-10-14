package keyprovider

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type vaultTestKey struct {
	private map[int]ed25519.PrivateKey
	public  map[int]ed25519.PublicKey
	latest  int
	floor   int
}

type vaultTestServer struct {
	server        *httptest.Server
	mu            sync.Mutex
	keys          map[string]*vaultTestKey
	deny          bool
	denyStatus    int
	failureStatus int
	badHealth     bool
	badSig        bool
	seen          []string
}

func newVaultTestServer(t *testing.T) *vaultTestServer {
	t.Helper()
	value := &vaultTestServer{keys: make(map[string]*vaultTestKey)}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		if value.authorize(w, r) {
			return
		}
		if value.badHealth {
			_, _ = w.Write([]byte("{"))
			return
		}
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
	})
	mux.HandleFunc("/v1/transit/config/keys", func(w http.ResponseWriter, r *http.Request) {
		if value.authorize(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"data":{"disable_upsert":true}}`))
	})
	mux.HandleFunc("/v1/transit/sign/", func(w http.ResponseWriter, r *http.Request) {
		if value.authorize(w, r) {
			return
		}
		keyName := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
		value.mu.Lock()
		value.seen = append(value.seen, r.Method+" "+r.URL.Path)
		key := value.keys[keyName]
		if key == nil || keyName == "" || strings.Contains(keyName, "/") {
			value.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		var payload struct {
			Input      string `json:"input"`
			KeyVersion int    `json:"key_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.KeyVersion < key.floor || payload.KeyVersion > key.latest {
			value.mu.Unlock()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		private, exists := key.private[payload.KeyVersion]
		if !exists {
			value.mu.Unlock()
			http.Error(w, "unknown key version", http.StatusBadRequest)
			return
		}
		input, err := base64.StdEncoding.DecodeString(payload.Input)
		if err != nil {
			value.mu.Unlock()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		signature := ed25519.Sign(private, input)
		encoded := base64.StdEncoding.EncodeToString(signature)
		if value.badSig {
			encoded = "%%%"
		}
		value.mu.Unlock()
		writeVaultJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"signature": "vault:v1:" + encoded}})
	})
	mux.HandleFunc("/v1/transit/keys/", func(w http.ResponseWriter, r *http.Request) {
		if value.authorize(w, r) {
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
		value.mu.Lock()
		value.seen = append(value.seen, r.Method+" "+r.URL.Path)
		if strings.HasSuffix(path, "/rotate") && r.Method == http.MethodPost {
			keyName := strings.TrimSuffix(path, "/rotate")
			key := value.keys[keyName]
			if key == nil {
				value.mu.Unlock()
				http.NotFound(w, r)
				return
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				value.mu.Unlock()
				http.Error(w, "rotation failed", http.StatusInternalServerError)
				return
			}
			key.latest++
			key.private[key.latest] = private
			key.public[key.latest] = public
			value.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(path, "/config") && r.Method == http.MethodPost {
			keyName := strings.TrimSuffix(path, "/config")
			key := value.keys[keyName]
			if key == nil {
				value.mu.Unlock()
				http.NotFound(w, r)
				return
			}
			var payload struct {
				MinEncryptionVersion int `json:"min_encryption_version"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.MinEncryptionVersion < 0 || payload.MinEncryptionVersion > key.latest {
				value.mu.Unlock()
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			key.floor = payload.MinEncryptionVersion
			value.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost {
			if _, exists := value.keys[path]; exists {
				value.mu.Unlock()
				http.Error(w, "already exists", http.StatusBadRequest)
				return
			}
			var payload struct {
				Type                 string `json:"type"`
				Derived              bool   `json:"derived"`
				Exportable           bool   `json:"exportable"`
				AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Type != "ed25519" || payload.Derived || payload.Exportable || payload.AllowPlaintextBackup {
				value.mu.Unlock()
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				value.mu.Unlock()
				http.Error(w, "generation failed", http.StatusInternalServerError)
				return
			}
			value.keys[path] = &vaultTestKey{private: map[int]ed25519.PrivateKey{1: private}, public: map[int]ed25519.PublicKey{1: public}, latest: 1}
			value.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet {
			key := value.keys[path]
			if key == nil {
				value.mu.Unlock()
				http.NotFound(w, r)
				return
			}
			versions := make(map[string]any, len(key.public))
			for version, public := range key.public {
				versions[strconv.Itoa(version)] = map[string]string{
					"creation_time": time.Now().UTC().Format(time.RFC3339Nano),
					"public_key":    base64.StdEncoding.EncodeToString(public),
				}
			}
			response := map[string]any{"data": map[string]any{
				"type": "ed25519", "latest_version": key.latest, "min_encryption_version": key.floor,
				"min_decryption_version": 1,
				"exportable":             false, "allow_plaintext_backup": false, "deletion_allowed": false,
				"supports_signing": true,
				"keys":             versions,
			}}
			value.mu.Unlock()
			writeVaultJSON(w, http.StatusOK, response)
			return
		}
		value.mu.Unlock()
		http.NotFound(w, r)
	})
	value.server = httptest.NewServer(mux)
	t.Cleanup(value.server.Close)
	return value
}

func (s *vaultTestServer) authorize(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deny || r.Header.Get("X-Vault-Token") != "test-only-token" {
		status := s.denyStatus
		if status == 0 {
			status = http.StatusForbidden
		}
		http.Error(w, `{"errors":["credential-canary"]}`, status)
		return true
	}
	if s.failureStatus != 0 {
		http.Error(w, "backend unavailable", s.failureStatus)
		return true
	}
	return false
}

func writeVaultJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type vaultTestStore struct {
	mu   sync.Mutex
	rows map[string]Metadata
}

func newVaultTestStore() *vaultTestStore { return &vaultTestStore{rows: make(map[string]Metadata)} }

func (s *vaultTestStore) Create(_ context.Context, scope Scope, item Metadata) (Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := vaultStoreKey(scope, item.Reference)
	if _, exists := s.rows[key]; exists {
		return Metadata{}, ErrProviderUnavailable
	}
	item.Version = 1
	item.CreatedAt = time.Now().UTC()
	item.UpdatedAt = item.CreatedAt
	s.rows[key] = item
	return item, nil
}

func (s *vaultTestStore) Read(_ context.Context, scope Scope, reference string) (Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, exists := s.rows[vaultStoreKey(scope, reference)]
	if !exists {
		return Metadata{}, ErrKeyNotFound
	}
	return item, nil
}

func (s *vaultTestStore) Lock(_ context.Context, scope Scope, reference string, action func(*Metadata) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := vaultStoreKey(scope, reference)
	item, exists := s.rows[key]
	if !exists {
		return ErrKeyNotFound
	}
	previous := item
	if err := action(&item); err != nil {
		return err
	}
	if item.State != previous.State {
		s.rows[key] = item
	}
	return nil
}

func vaultStoreKey(scope Scope, reference string) string {
	return fmt.Sprintf("%s/%s/%s/%s", scope.TenantID, scope.ApplicationID, scope.Environment, reference)
}

func newVaultTestProvider(t *testing.T, address string, store KeyMetadataStore) *VaultProvider {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "vault-agent-token")
	if err := os.WriteFile(tokenFile, []byte("test-only-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewVaultProvider(VaultConfig{
		Environment: "development", Address: address, TokenFile: tokenFile,
		Metadata: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

var vaultScopeA = Scope{
	TenantID:      "9c0d0c44-1e99-4d15-8c4f-a303d6389890",
	ApplicationID: "bd3e5672-e07d-4f72-a82d-62a2c4d3e4cc",
	Environment:   "development",
}

func TestVaultGenerateActivateSignDisableAndScopeBinding(t *testing.T) {
	server := newVaultTestServer(t)
	store := newVaultTestStore()
	provider := newVaultTestProvider(t, server.server.URL, store)
	ctx := context.Background()
	if err := provider.Health(ctx); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	item, err := provider.Generate(ctx, vaultScopeA, KeySpec{
		Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if item.State != StateProvisioning || item.Version != 1 || !validVaultReference(item.Reference) {
		t.Fatalf("Generate() metadata = %#v", item)
	}
	publicDER, err := provider.PublicKey(ctx, vaultScopeA, item.Reference)
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	public := parsed.(ed25519.PublicKey)
	if _, err := provider.Sign(ctx, vaultScopeA, item.Reference, []byte("provisioning must not sign"), crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("provisioning Sign() error = %v", err)
	}
	item, err = provider.Transition(ctx, vaultScopeA, item.Reference, StateProvisioning, StateActive)
	if err != nil || item.State != StateActive {
		t.Fatalf("activate = %#v, %v", item, err)
	}
	message := []byte("payload stays out of audit records")
	signature, err := provider.Sign(ctx, vaultScopeA, item.Reference, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("Vault signature failed Ed25519 verification")
	}
	item, err = provider.Transition(ctx, vaultScopeA, item.Reference, StateActive, StateDisabled)
	if err != nil || item.State != StateDisabled {
		t.Fatalf("disable = %#v, %v", item, err)
	}
	if _, err := provider.Sign(ctx, vaultScopeA, item.Reference, message, crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("disabled Sign() error = %v", err)
	}
	name, err := provider.keyName(vaultScopeA, item.Reference)
	if err != nil {
		t.Fatal("construct scoped Transit key name:", err)
	}
	server.mu.Lock()
	key := server.keys[name]
	if key == nil || key.latest < 2 || key.floor != 2 {
		server.mu.Unlock()
		t.Fatalf("disabled key must have a valid Transit signing floor: %#v", key)
	}
	server.mu.Unlock()
	otherTenant := vaultScopeA
	otherTenant.TenantID = "ac1d0c44-1e99-4d15-8c4f-a303d6389890"
	if _, err := provider.Metadata(ctx, otherTenant, item.Reference); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("cross-tenant Metadata() error = %v", err)
	}
	if _, err := provider.PublicKey(ctx, otherTenant, item.Reference); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("cross-tenant PublicKey() error = %v", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, request := range server.seen {
		methodAndName := strings.SplitN(request, " ", 2)
		if len(methodAndName) != 2 || strings.Contains(request, "../") {
			t.Fatalf("Vault request path is not server-scoped: %q", request)
		}
		name := methodAndName[1]
		if strings.HasPrefix(name, "/v1/transit/sign/") {
			name = strings.TrimPrefix(name, "/v1/transit/sign/")
		} else {
			name = strings.TrimPrefix(name, "/v1/transit/keys/")
			name = strings.TrimSuffix(strings.TrimSuffix(name, "/config"), "/rotate")
		}
		prefix := "qg_" + base64.RawURLEncoding.EncodeToString([]byte("quantumgate")) + "_" + vaultScopeA.Environment + "_"
		if !strings.HasPrefix(name, prefix) || strings.Contains(name, "/") {
			t.Fatalf("Vault key name is not one scoped path segment: %q", request)
		}
		encodedScope, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(name, prefix))
		if err != nil || string(encodedScope) != strings.Join([]string{vaultScopeA.TenantID, vaultScopeA.ApplicationID, item.Reference}, "\x00") {
			t.Fatalf("Vault key name did not preserve its trusted scope: %q", request)
		}
	}
}

func TestVaultErrorPreservesSafeOperationStage(t *testing.T) {
	server := newVaultTestServer(t)
	provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
	audit := newRecordingAudit()
	broker, err := NewBroker(context.Background(), "development", provider, audit)
	if err != nil {
		t.Fatal("construct broker:", err)
	}
	server.deny = true
	server.denyStatus = http.StatusNotFound
	_, err = broker.Generate(WithAuditContext(context.Background(), testAuditContext), vaultScopeA, KeySpec{
		Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if !errors.Is(err, ErrKeyNotFound) || !strings.Contains(err.Error(), "Vault Transit key creation") {
		t.Fatalf("safe operation stage was not preserved through broker sanitization: %v", err)
	}
	if strings.Contains(err.Error(), "credential-canary") {
		t.Fatal("provider response detail leaked through operation context")
	}
}

func TestVaultRejectsUnauthorizedMalformedAndUnsupportedRequests(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		server := newVaultTestServer(t)
		server.deny = true
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		if err := provider.Health(context.Background()); !errors.Is(err, ErrProviderDenied) {
			t.Fatalf("Health() error = %v", err)
		}
		if strings.Contains(fmt.Sprint(provider.Health(context.Background())), "credential-canary") {
			t.Fatal("provider error exposed Vault response text")
		}
	})
	t.Run("authentication failure", func(t *testing.T) {
		server := newVaultTestServer(t)
		server.deny = true
		server.denyStatus = http.StatusUnauthorized
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		if err := provider.Health(context.Background()); !errors.Is(err, ErrProviderDenied) {
			t.Fatalf("Health() error = %v", err)
		}
	})
	t.Run("provider unavailable", func(t *testing.T) {
		server := newVaultTestServer(t)
		server.failureStatus = http.StatusServiceUnavailable
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		if err := provider.Health(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("Health() error = %v", err)
		}
	})
	t.Run("malformed health response", func(t *testing.T) {
		server := newVaultTestServer(t)
		server.badHealth = true
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		if err := provider.Health(context.Background()); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("Health() error = %v", err)
		}
	})
	t.Run("bad signature format", func(t *testing.T) {
		server := newVaultTestServer(t)
		store := newVaultTestStore()
		provider := newVaultTestProvider(t, server.server.URL, store)
		item, err := provider.Generate(context.Background(), vaultScopeA, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.Transition(context.Background(), vaultScopeA, item.Reference, StateProvisioning, StateActive); err != nil {
			t.Fatal(err)
		}
		server.mu.Lock()
		server.badSig = true
		server.mu.Unlock()
		if _, err := provider.Sign(context.Background(), vaultScopeA, item.Reference, []byte("message"), crypto.Hash(0)); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("Sign() error = %v", err)
		}
	})
	t.Run("unsupported purpose", func(t *testing.T) {
		server := newVaultTestServer(t)
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		_, err := provider.Generate(context.Background(), vaultScopeA, KeySpec{Purpose: PurposeSession, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().Add(time.Hour)})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Generate() error = %v", err)
		}
	})
	t.Run("unsupported algorithm", func(t *testing.T) {
		server := newVaultTestServer(t)
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		_, err := provider.Generate(context.Background(), vaultScopeA, KeySpec{
			Purpose: PurposeSigning, Algorithm: Algorithm("ML-DSA-65"), ExpiresAt: time.Now().Add(time.Hour),
		})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Generate(ML-DSA-65) error = %v", err)
		}
	})
	t.Run("arbitrary reference rejected", func(t *testing.T) {
		server := newVaultTestServer(t)
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		if _, err := provider.PublicKey(context.Background(), vaultScopeA, "../../other/tenant"); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("PublicKey() error = %v", err)
		}
	})
	t.Run("unknown provider key", func(t *testing.T) {
		server := newVaultTestServer(t)
		provider := newVaultTestProvider(t, server.server.URL, newVaultTestStore())
		item, err := provider.Generate(context.Background(), vaultScopeA, KeySpec{
			Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		server.mu.Lock()
		clear(server.keys)
		server.mu.Unlock()
		if _, err := provider.PublicKey(context.Background(), vaultScopeA, item.Reference); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("PublicKey() for missing Vault key error = %v", err)
		}
	})
}

func TestVaultTimeoutFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "vault-agent-token")
	if err := os.WriteFile(tokenFile, []byte("test-only-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewVaultProvider(VaultConfig{
		Environment: "test", Address: server.URL, TokenFile: tokenFile, Metadata: newVaultTestStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := provider.Health(ctx); !errors.Is(err, ErrProviderTimeout) {
		t.Fatalf("Health() error = %v", err)
	}
}

func TestVaultConcurrentTransitionsCompareStateAtomically(t *testing.T) {
	server := newVaultTestServer(t)
	store := newVaultTestStore()
	provider := newVaultTestProvider(t, server.server.URL, store)
	item, err := provider.Generate(context.Background(), vaultScopeA, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Transition(context.Background(), vaultScopeA, item.Reference, StateProvisioning, StateActive); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, target := range []State{StateDisabled, StateRevoked} {
		target := target
		go func() {
			<-start
			_, transitionErr := provider.Transition(context.Background(), vaultScopeA, item.Reference, StateActive, target)
			results <- transitionErr
		}()
	}
	close(start)
	first, second := <-results, <-results
	if !((first == nil && errors.Is(second, ErrStaleTransition)) || (second == nil && errors.Is(first, ErrStaleTransition))) {
		t.Fatalf("concurrent transition errors = %v, %v", first, second)
	}
}

func TestVaultRequiresVerifiedTLSAndRejectsRemotePlainHTTP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
			return
		}
		if r.URL.Path == "/v1/transit/config/keys" {
			_, _ = w.Write([]byte(`{"data":{"disable_upsert":true}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-only-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewVaultProvider(VaultConfig{Environment: "production", Address: "http://vault.example:8200", TokenFile: tokenFile, Metadata: newVaultTestStore()}); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("NewVaultProvider(remote HTTP) error = %v", err)
	}
	provider := newVaultTestProvider(t, server.URL, newVaultTestStore())
	if err := provider.Health(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Health(untrusted TLS) error = %v", err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(caFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	trusted, err := NewVaultProvider(VaultConfig{Environment: "development", Address: server.URL, TokenFile: tokenFile, CACertFile: caFile, Metadata: newVaultTestStore()})
	if err != nil {
		t.Fatal(err)
	}
	if err := trusted.Health(context.Background()); err != nil {
		t.Fatalf("Health(trusted TLS) error = %v", err)
	}
}

func TestVaultCapabilitiesDoNotClaimPQCOrDestruction(t *testing.T) {
	provider := newVaultTestProvider(t, "http://127.0.0.1:8200", newVaultTestStore())
	capabilities, err := provider.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities.Algorithms) != 1 || capabilities.Algorithms[0] != AlgorithmEd25519 {
		t.Fatalf("unexpected Vault algorithms: %#v", capabilities.Algorithms)
	}
	if containsOperation(capabilities.Operations, OperationDestroy) {
		t.Fatal("Vault adapter must not advertise key destruction")
	}
	if capabilities.PrivateMaterialExport || !capabilities.ProtectedKeyCustody || !capabilities.Persistent {
		t.Fatalf("unexpected Vault custody capabilities: %#v", capabilities)
	}
}
