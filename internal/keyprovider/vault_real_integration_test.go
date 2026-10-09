package keyprovider

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestVaultRealTransitIntegration is enabled only by an explicitly configured,
// loopback development Vault. It validates real Transit API compatibility; it
// does not validate a production Vault deployment.
func TestVaultRealTransitIntegration(t *testing.T) {
	address := os.Getenv("QG_REAL_VAULT_ADDR")
	runtimeTokenFile := os.Getenv("QG_REAL_VAULT_TOKEN_FILE")
	deniedTokenFile := os.Getenv("QG_REAL_VAULT_DENIED_TOKEN_FILE")
	if address == "" && runtimeTokenFile == "" && deniedTokenFile == "" {
		t.Skip("real Vault integration is not configured")
	}
	if address == "" || runtimeTokenFile == "" || deniedTokenFile == "" {
		t.Fatal("real Vault integration requires an address and both restricted token files")
	}
	parsedAddress, err := url.Parse(address)
	if err != nil || parsedAddress.Scheme != "http" || !isLoopbackHost(parsedAddress.Hostname()) {
		t.Fatal("real Vault integration accepts only a loopback HTTP development server")
	}
	for _, tokenPath := range []string{runtimeTokenFile, deniedTokenFile} {
		info, statErr := os.Stat(tokenPath)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Mode().Perm()&0o077 != 0 {
			t.Fatal("real Vault integration token files must exist, be non-empty, and be owner-only")
		}
	}

	ctx := context.Background()
	scope := vaultScopeA
	scope.Environment = "test"
	provider, err := NewVaultProvider(VaultConfig{
		Environment: "test", Address: address, TransitMount: "transit", KeyPrefix: "quantumgate",
		TokenFile: runtimeTokenFile, Metadata: newVaultTestStore(),
	})
	if err != nil {
		t.Fatalf("construct real Vault provider: %v", err)
	}
	audit := newRecordingAudit()
	broker, err := NewBroker(ctx, "test", provider, audit)
	if err != nil {
		t.Fatalf("construct audited real Vault broker: %v", err)
	}
	if err := broker.Health(ctx); err != nil {
		t.Fatalf("real Vault health and Transit configuration read: %v", err)
	}

	operationContext := func(operation string) context.Context {
		return WithAuditContext(ctx, AuditContext{
			Actor: "ci:real-vault-integration", CorrelationID: "vault-real-" + operation,
		})
	}
	var signatures []string
	newSigningKey := func(name string) Metadata {
		t.Helper()
		item, generateErr := broker.Generate(operationContext(name+"-generate"), scope, KeySpec{
			Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		})
		if generateErr != nil {
			t.Fatalf("real Transit Ed25519 key creation: %v", generateErr)
		}
		activated, transitionErr := broker.Transition(operationContext(name+"-activate"), scope, item.Reference, StateActive)
		if transitionErr != nil || activated.State != StateActive {
			t.Fatalf("activate real Transit key: metadata=%#v error=%v", activated, transitionErr)
		}
		return activated
	}
	verifySigningKey := func(name string, item Metadata) {
		t.Helper()
		publicDER, publicErr := broker.PublicKey(operationContext(name+"-public"), scope, item.Reference)
		if publicErr != nil {
			t.Fatalf("read real Transit public key: %v", publicErr)
		}
		parsedPublic, parseErr := x509.ParsePKIXPublicKey(publicDER)
		public, ok := parsedPublic.(ed25519.PublicKey)
		if parseErr != nil || !ok {
			t.Fatalf("real Transit public key is not Ed25519: %v", parseErr)
		}
		message := []byte("vault-real-integration-payload-canary")
		signature, signErr := broker.Sign(operationContext(name+"-sign"), scope, item.Reference, message, crypto.Hash(0))
		if signErr != nil {
			t.Fatalf("sign through real Transit: %v", signErr)
		}
		if !ed25519.Verify(public, message, signature) {
			t.Fatal("real Transit signature did not pass QuantumGate Ed25519 verification")
		}
		signatures = append(signatures, base64.StdEncoding.EncodeToString(signature))
	}

	firstKey := newSigningKey("first")
	verifySigningKey("first", firstKey)
	rotated, err := broker.Transition(operationContext("first-rotation-due"), scope, firstKey.Reference, StateRotationDue)
	if err != nil || rotated.State != StateRotationDue {
		t.Fatalf("mark old Transit reference rotation-due: metadata=%#v error=%v", rotated, err)
	}
	loaded, err := broker.Metadata(operationContext("first-inactive-metadata"), scope, firstKey.Reference)
	if err != nil || loaded.State != StateRotationDue {
		t.Fatalf("read real Transit reference after signing floor update: metadata=%#v error=%v", loaded, err)
	}
	if _, err := broker.Sign(operationContext("first-inactive-sign"), scope, firstKey.Reference,
		[]byte("must-not-sign-after-rotation"), crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("rotation-due Transit reference remained usable: %v", err)
	}

	secondKey := newSigningKey("second")
	verifySigningKey("second", secondKey)
	disabled, err := broker.Transition(operationContext("second-disable"), scope, secondKey.Reference, StateDisabled)
	if err != nil || disabled.State != StateDisabled {
		t.Fatalf("disable real Transit reference: metadata=%#v error=%v", disabled, err)
	}
	if _, err := broker.Sign(operationContext("second-disabled-sign"), scope, secondKey.Reference,
		[]byte("must-not-sign-after-disable"), crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("disabled Transit reference remained usable: %v", err)
	}
	if _, err := broker.Transition(operationContext("unsupported-destroy"), scope, secondKey.Reference, StateDestroyed); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("adapter unexpectedly allowed Transit key destruction: %v", err)
	}
	unknownReference := "vault_" + strings.Repeat("A", 43)
	if _, err := broker.Metadata(operationContext("unknown-key"), scope, unknownReference); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown Vault reference did not fail closed: %v", err)
	}

	deniedProvider, err := NewVaultProvider(VaultConfig{
		Environment: "test", Address: address, TransitMount: "transit", KeyPrefix: "quantumgate",
		TokenFile: deniedTokenFile, Metadata: newVaultTestStore(),
	})
	if err != nil {
		t.Fatalf("construct authorization-negative Vault provider: %v", err)
	}
	if err := deniedProvider.Health(ctx); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("health-only Vault policy must be denied from Transit configuration: %v", err)
	}

	audit.mu.Lock()
	auditEvents := append([]AuditEvent(nil), audit.events...)
	audit.mu.Unlock()
	if len(auditEvents) == 0 {
		t.Fatal("real Vault operations produced no QuantumGate audit evidence")
	}
	auditJSON, err := json.Marshal(auditEvents)
	if err != nil {
		t.Fatalf("serialize real Vault audit evidence: %v", err)
	}
	for _, sensitive := range []string{
		firstKey.Reference, secondKey.Reference,
		"vault-real-integration-payload-canary",
	} {
		if strings.Contains(string(auditJSON), sensitive) {
			t.Fatal("real Vault audit evidence contained an unredacted reference or signing payload")
		}
	}
	for _, signature := range signatures {
		if strings.Contains(string(auditJSON), signature) {
			t.Fatal("real Vault audit evidence contained a signature")
		}
	}
	for _, event := range auditEvents {
		if event.TenantID != scope.TenantID || event.ApplicationID != scope.ApplicationID ||
			event.Actor != "ci:real-vault-integration" || !strings.HasPrefix(event.CorrelationID, "vault-real-") {
			t.Fatalf("real Vault audit event lost its tenant, actor, or correlation context: %#v", event)
		}
		if event.KeyReferenceHash != "" && (len(event.KeyReferenceHash) != 64 ||
			event.KeyReferenceHash == firstKey.Reference || event.KeyReferenceHash == secondKey.Reference) {
			t.Fatal("real Vault audit reference was not reduced to a one-way hash")
		}
	}
}
