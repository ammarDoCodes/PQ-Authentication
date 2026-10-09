package keyprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPQCDevelopmentProviderSignsFIPS204ParameterSets(t *testing.T) {
	ctx := context.Background()
	provider := NewPQCDevelopmentProvider()
	broker, audit := newTestBroker(t, provider)
	caps := broker.Capabilities()
	if caps.Provider != PQCDevelopment || !caps.DevelopmentOnly || caps.Persistent || caps.ProtectedKeyCustody || caps.PrivateMaterialExport {
		t.Fatalf("PQC development provider has an unsafe custody classification: %+v", caps)
	}
	for _, algorithm := range []Algorithm{AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87} {
		if !containsAlgorithm(caps.Algorithms, algorithm) {
			t.Fatalf("provider does not advertise required standardized variant %q: %+v", algorithm, caps.Algorithms)
		}
	}
	for _, operation := range []Operation{"encapsulate", "decapsulate"} {
		if containsOperation(caps.Operations, operation) {
			t.Fatalf("signing provider must not advertise unsupported KEM operation %q", operation)
		}
	}

	message := []byte("qg-pqc-message-canary")
	issuedReferences := make(map[string]struct{})
	var signatures [][]byte
	for _, algorithm := range []Algorithm{AlgorithmEd25519, AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) {
			spec := KeySpec{Purpose: PurposeSigning, Algorithm: algorithm, ExpiresAt: time.Now().Add(time.Hour)}
			key, err := broker.Generate(ctx, testScope, spec)
			if err != nil || key.State != StateProvisioning || key.Algorithm != algorithm || key.Reference == "" {
				t.Fatalf("generate %s key: metadata=%+v err=%v", algorithm, key, err)
			}
			if key.Provider != PQCDevelopment || key.Version == 0 {
				t.Fatalf("unexpected provider metadata: %+v", key)
			}
			issuedReferences[key.Reference] = struct{}{}
			if _, err := broker.Sign(ctx, testScope, key.Reference, message, pqcTestSignerOptions(algorithm)); !errors.Is(err, ErrKeyUnavailable) {
				t.Fatalf("provisioning key must not sign: %v", err)
			}
			if _, err := broker.Transition(ctx, testScope, key.Reference, StateActive); err != nil {
				t.Fatalf("activate %s key: %v", algorithm, err)
			}
			opts := pqcTestSignerOptions(algorithm)
			signature, err := broker.Sign(ctx, testScope, key.Reference, message, opts)
			if err != nil {
				t.Fatalf("sign with %s: %v", algorithm, err)
			}
			signatures = append(signatures, append([]byte(nil), signature...))
			publicDER, err := broker.PublicKey(ctx, testScope, key.Reference)
			if err != nil {
				t.Fatalf("retrieve %s public key: %v", algorithm, err)
			}
			public, err := x509.ParsePKIXPublicKey(publicDER)
			if err != nil || !validPublicKey(algorithm, public) {
				t.Fatalf("public key does not match %s: type=%T err=%v", algorithm, public, err)
			}
			if algorithm == AlgorithmEd25519 {
				if !ed25519.Verify(public.(ed25519.PublicKey), message, signature) {
					t.Fatal("Ed25519 regression signature did not verify")
				}
				return
			}
			mldsaPublic := public.(*mldsa.PublicKey)
			parameters, err := mldsaParameters(algorithm)
			if err != nil {
				t.Fatal("resolve ML-DSA parameter set:", err)
			}
			if mldsaPublic.Parameters().String() != string(algorithm) ||
				len(mldsaPublic.Bytes()) != parameters.PublicKeySize() || len(signature) != parameters.SignatureSize() {
				t.Fatalf("wrong ML-DSA key/signature sizes: parameters=%s public=%d signature=%d", mldsaPublic.Parameters(), len(mldsaPublic.Bytes()), len(signature))
			}
			if err := mldsa.Verify(mldsaPublic, message, signature, opts.(*mldsa.Options)); err != nil {
				t.Fatalf("ML-DSA signature did not verify: %v", err)
			}
			if err := mldsa.Verify(mldsaPublic, message, signature, &mldsa.Options{Context: "wrong context"}); err == nil {
				t.Fatal("ML-DSA signature verified under a different context")
			}
			corrupted := append([]byte(nil), signature...)
			corrupted[len(corrupted)-1] ^= 1
			if err := mldsa.Verify(mldsaPublic, message, corrupted, opts.(*mldsa.Options)); err == nil {
				t.Fatal("modified ML-DSA signature unexpectedly verified")
			}
		})
	}

	audit.mu.Lock()
	defer audit.mu.Unlock()
	foundPQCSign := false
	encodedAudit, err := json.Marshal(audit.events)
	if err != nil {
		t.Fatal("marshal audit evidence:", err)
	}
	if bytes.Contains(encodedAudit, message) {
		t.Fatal("operation audit exposed the signing message")
	}
	for _, event := range audit.events {
		if event.Provider != PQCDevelopment {
			t.Fatalf("unexpected provider in operation audit: %+v", event)
		}
		if event.Operation == OperationSign && event.Phase == "completed" && event.Outcome == "success" {
			foundPQCSign = true
			if event.KeyReferenceHash == "" || strings.Contains(event.KeyReferenceHash, "devpqc_") ||
				containsReference(issuedReferences, event.KeyReferenceHash) ||
				event.Actor != testAuditContext.Actor || event.CorrelationID != testAuditContext.CorrelationID {
				t.Fatalf("audit evidence must be correlated and hide opaque references: %+v", event)
			}
		}
		if strings.Contains(event.ReasonCode, string(message)) || strings.Contains(event.KeyReferenceHash, string(message)) {
			t.Fatal("operation audit exposed signing input")
		}
	}
	for _, signature := range signatures {
		if bytes.Contains(encodedAudit, signature) {
			t.Fatal("operation audit exposed signature bytes")
		}
	}
	if !foundPQCSign {
		t.Fatal("successful PQC signing must produce correlated audit evidence")
	}
}

func TestPQCDevelopmentProviderRejectsUnsafeInputsAndProductionSelection(t *testing.T) {
	ctx := context.Background()
	if _, err := SelectProvider(ctx, "production", PQCDevelopment); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("PQC development provider must not be selectable in production: %v", err)
	}
	provider, err := SelectProvider(ctx, "development", PQCDevelopment)
	if err != nil {
		t.Fatal("explicit PQC development provider selection:", err)
	}
	if _, err := NewBroker(ctx, "production", provider, newRecordingAudit()); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("production broker must reject development-only provider: %v", err)
	}
	broker, _ := newTestBroker(t, provider)
	for _, algorithm := range []Algorithm{"MLDSA65", "ML-KEM-768", "unknown"} {
		_, err := broker.Generate(ctx, testScope, KeySpec{Purpose: PurposeSigning, Algorithm: algorithm, ExpiresAt: time.Now().Add(time.Hour)})
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("unsupported or malformed algorithm %q must fail closed, got %v", algorithm, err)
		}
	}
	if _, err := broker.Generate(ctx, testScope, KeySpec{Purpose: PurposeKeyEncryption, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("signing provider must reject key-encryption purpose: %v", err)
	}
	key, err := broker.Generate(ctx, testScope, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal("generate test key:", err)
	}
	if _, err := broker.Transition(ctx, testScope, key.Reference, StateActive); err != nil {
		t.Fatal("activate test key:", err)
	}
	if _, err := broker.Sign(ctx, testScope, key.Reference, nil, &mldsa.Options{}); !errors.Is(err, ErrInvalidKeySpec) {
		t.Fatalf("empty signing input must be rejected: %v", err)
	}
	if _, err := broker.Sign(ctx, testScope, key.Reference, []byte("message"), crypto.Hash(crypto.SHA256)); !errors.Is(err, ErrInvalidKeySpec) {
		t.Fatalf("pre-hashed/classical signer options must be rejected: %v", err)
	}
	if _, err := broker.Sign(ctx, testScope, key.Reference, []byte("message"), &mldsa.Options{Context: strings.Repeat("x", 256)}); !errors.Is(err, ErrInvalidKeySpec) {
		t.Fatalf("overlong ML-DSA context must be rejected: %v", err)
	}
	if _, err := broker.Generate(ctx, Scope{TenantID: "bad", ApplicationID: testScope.ApplicationID, Environment: "development"},
		KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("malformed tenant scope must be rejected: %v", err)
	}
}

func TestPQCDevelopmentProviderEnforcesScopeAndKeyAlgorithmBinding(t *testing.T) {
	ctx := context.Background()
	provider := NewPQCDevelopmentProvider()
	broker, _ := newTestBroker(t, provider)
	key, err := broker.Generate(ctx, testScope, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA44, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal("generate ML-DSA-44 key:", err)
	}
	otherTenant := testScope
	otherTenant.TenantID = "30000000-0000-4000-8000-000000000003"
	otherApplication := testScope
	otherApplication.ApplicationID = "40000000-0000-4000-8000-000000000004"
	for name, scope := range map[string]Scope{"other tenant": otherTenant, "other application": otherApplication} {
		t.Run(name, func(t *testing.T) {
			if _, err := broker.Metadata(ctx, scope, key.Reference); !errors.Is(err, ErrKeyNotFound) {
				t.Errorf("cross-scope metadata access must look not-found: %v", err)
			}
			if _, err := broker.PublicKey(ctx, scope, key.Reference); !errors.Is(err, ErrKeyNotFound) {
				t.Errorf("cross-scope public-key access must look not-found: %v", err)
			}
			if _, err := broker.Sign(ctx, scope, key.Reference, []byte("message"), &mldsa.Options{}); !errors.Is(err, ErrKeyNotFound) {
				t.Errorf("cross-scope signing must look not-found: %v", err)
			}
			if _, err := broker.Transition(ctx, scope, key.Reference, StateRevoked); !errors.Is(err, ErrKeyNotFound) {
				t.Errorf("cross-scope lifecycle change must look not-found: %v", err)
			}
		})
	}

	key65, err := broker.Generate(ctx, testScope, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal("generate mismatch key:", err)
	}
	otherPublicDER, err := broker.PublicKey(ctx, testScope, key65.Reference)
	if err != nil {
		t.Fatal("get other variant public key:", err)
	}
	otherPublic, err := x509.ParsePKIXPublicKey(otherPublicDER)
	if err != nil || validPublicKey(AlgorithmMLDSA44, otherPublic) {
		t.Fatalf("ML-DSA-65 material must not be accepted as ML-DSA-44: %T %v", otherPublic, err)
	}
	wrapped, err := NewBroker(ctx, "development", &pqcPublicKeyOverride{Provider: provider, publicKey: otherPublicDER}, newRecordingAudit())
	if err != nil {
		t.Fatal("create mismatch broker:", err)
	}
	if _, err := wrapped.PublicKey(WithAuditContext(ctx, testAuditContext), testScope, key.Reference); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("provider response with the wrong ML-DSA parameter set must be rejected: %v", err)
	}
	malformed, err := NewBroker(ctx, "development", &pqcPublicKeyOverride{Provider: provider, publicKey: []byte("not a DER public key")}, newRecordingAudit())
	if err != nil {
		t.Fatal("create malformed-response broker:", err)
	}
	if _, err := malformed.PublicKey(WithAuditContext(ctx, testAuditContext), testScope, key.Reference); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("malformed PQC public material must be rejected: %v", err)
	}
	if _, err := broker.Transition(ctx, testScope, key.Reference, StateActive); err != nil {
		t.Fatal("activate key before malformed-signature test:", err)
	}
	badSigner, err := NewBroker(ctx, "development", &pqcSignatureOverride{Provider: provider}, newRecordingAudit())
	if err != nil {
		t.Fatal("create malformed-signature broker:", err)
	}
	if _, err := badSigner.Sign(WithAuditContext(ctx, testAuditContext), testScope, key.Reference, []byte("message"), &mldsa.Options{}); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("malformed ML-DSA signature must be rejected: %v", err)
	}
}

func TestPQCDevelopmentProviderRejectsStaleConcurrentTransitionsAndPreservesPublicHistory(t *testing.T) {
	ctx := context.Background()
	provider := NewPQCDevelopmentProvider()
	first, err := provider.Generate(ctx, testScope, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal("generate key:", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := provider.Transition(ctx, testScope, first.Reference, StateProvisioning, StateActive)
			results <- err
		}()
	}
	close(start)
	var committed, stale int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			committed++
		case errors.Is(err, ErrStaleTransition):
			stale++
		default:
			t.Fatalf("unexpected concurrent transition result: %v", err)
		}
	}
	if committed != 1 || stale != 1 {
		t.Fatalf("expected one committed transition and one stale result; committed=%d stale=%d", committed, stale)
	}
	if _, err := provider.Transition(ctx, testScope, first.Reference, StateProvisioning, StateRevoked); !errors.Is(err, ErrStaleTransition) {
		t.Fatalf("stale provisioning state must be rejected: %v", err)
	}
	if _, err := provider.Transition(ctx, testScope, first.Reference, StateActive, StateDestroyed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("active key must not skip lifecycle states: %v", err)
	}

	message := []byte("historical verification")
	signature, err := provider.Sign(ctx, testScope, first.Reference, message, &mldsa.Options{})
	if err != nil {
		t.Fatal("sign before rotation:", err)
	}
	publicDER, err := provider.PublicKey(ctx, testScope, first.Reference)
	if err != nil {
		t.Fatal("read historical public key:", err)
	}
	second, err := provider.Generate(ctx, testScope, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal("generate replacement:", err)
	}
	if _, err := provider.Transition(ctx, testScope, second.Reference, StateProvisioning, StateActive); err != nil {
		t.Fatal("activate replacement:", err)
	}
	if item, err := provider.Metadata(ctx, testScope, first.Reference); err != nil || item.State != StateRotationDue {
		t.Fatalf("replacement must retire former active key from signing: %+v %v", item, err)
	}
	if _, err := provider.Sign(ctx, testScope, first.Reference, message, &mldsa.Options{}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("rotation-due key must not sign: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil || mldsa.Verify(parsed.(*mldsa.PublicKey), message, signature, &mldsa.Options{}) != nil {
		t.Fatalf("prior public key must remain available to verify its signature: %v", err)
	}
	if _, err := provider.Transition(ctx, testScope, first.Reference, StateRotationDue, StateRevoked); err != nil {
		t.Fatal("revoke historical key:", err)
	}
	if _, err := provider.Sign(ctx, testScope, first.Reference, message, &mldsa.Options{}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("revoked key must not sign: %v", err)
	}
	if _, err := provider.Transition(ctx, testScope, first.Reference, StateRevoked, StateDestroyed); err != nil {
		t.Fatal("destroy historical key:", err)
	}
	if _, err := provider.Sign(ctx, testScope, first.Reference, message, &mldsa.Options{}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("destroyed key must not sign: %v", err)
	}
	if retained, err := provider.PublicKey(ctx, testScope, first.Reference); err != nil || string(retained) != string(publicDER) {
		t.Fatalf("destroy must preserve public verification history: err=%v", err)
	}
}

func TestPQCDevelopmentProviderExpiresKeysAndRejectsCanceledOperations(t *testing.T) {
	clock := time.Now().UTC()
	provider := NewPQCDevelopmentProvider()
	provider.now = func() time.Time { return clock }
	ctx := context.Background()
	key, err := provider.Generate(ctx, testScope, KeySpec{
		Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA44, ExpiresAt: clock.Add(time.Hour),
	})
	if err != nil {
		t.Fatal("generate expiring key:", err)
	}
	if _, err := provider.Transition(ctx, testScope, key.Reference, StateProvisioning, StateActive); err != nil {
		t.Fatal("activate expiring key:", err)
	}
	clock = clock.Add(time.Hour + time.Second)
	if _, err := provider.Sign(ctx, testScope, key.Reference, []byte("expired"), &mldsa.Options{}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("expired key must not sign: %v", err)
	}
	if item, err := provider.Metadata(ctx, testScope, key.Reference); err != nil || item.State != StateExpired {
		t.Fatalf("expired key should transition to expired: %+v %v", item, err)
	}
	if _, err := provider.PublicKey(ctx, testScope, key.Reference); err != nil {
		t.Fatalf("expiry must preserve public verification material: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := provider.Generate(canceled, testScope, KeySpec{
		Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA44, ExpiresAt: clock.Add(time.Hour),
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled generation must fail closed: %v", err)
	}
}

func TestPQCDevelopmentProviderDoesNotFallBackWhenCapabilityIsMissing(t *testing.T) {
	ctx := context.Background()
	inner := NewPQCDevelopmentProvider()
	limited := &pqcCapabilitiesOverride{Provider: inner, algorithms: []Algorithm{AlgorithmEd25519}}
	broker, err := NewBroker(ctx, "development", limited, newRecordingAudit())
	if err != nil {
		t.Fatal("create classical-only capability broker:", err)
	}
	_, err = broker.Generate(WithAuditContext(ctx, testAuditContext), testScope,
		KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, ErrUnsupported) || len(inner.keys) != 0 {
		t.Fatalf("missing PQC capability must reject without classical fallback: err=%v generated=%d", err, len(inner.keys))
	}
}

func TestPQCDevelopmentProviderRequiresAuditBeforeGeneration(t *testing.T) {
	provider := NewPQCDevelopmentProvider()
	audit := &recordingAudit{err: errors.New("audit database credential canary")}
	broker, err := NewBroker(context.Background(), "development", provider, audit)
	if err != nil {
		t.Fatal("create broker with unavailable audit sink:", err)
	}
	_, err = broker.Generate(WithAuditContext(context.Background(), testAuditContext), testScope,
		KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmMLDSA65, ExpiresAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, ErrAuditUnavailable) || strings.Contains(err.Error(), "credential canary") {
		t.Fatalf("missing audit must fail closed and hide backend details: %v", err)
	}
	if len(provider.keys) != 0 {
		t.Fatal("provider generated PQC material without successful intent audit")
	}
}

func pqcTestSignerOptions(algorithm Algorithm) crypto.SignerOpts {
	if algorithm == AlgorithmEd25519 {
		return crypto.Hash(0)
	}
	return &mldsa.Options{Context: "QuantumGate development signing"}
}

type pqcPublicKeyOverride struct {
	Provider
	publicKey []byte
}

type pqcSignatureOverride struct{ Provider }

func (p *pqcSignatureOverride) Sign(ctx context.Context, _ Scope, _ string, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []byte("malformed-signature"), nil
}

func (p *pqcPublicKeyOverride) PublicKey(ctx context.Context, _ Scope, _ string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]byte(nil), p.publicKey...), nil
}

type pqcCapabilitiesOverride struct {
	Provider
	algorithms []Algorithm
}

func containsReference(references map[string]struct{}, candidate string) bool {
	_, exists := references[candidate]
	return exists
}

func (p *pqcCapabilitiesOverride) Capabilities(ctx context.Context) (Capabilities, error) {
	caps, err := p.Provider.Capabilities(ctx)
	if err != nil {
		return Capabilities{}, err
	}
	caps.Algorithms = append([]Algorithm(nil), p.algorithms...)
	return caps, nil
}

func BenchmarkPQCDevelopmentOperations(b *testing.B) {
	for _, algorithm := range []Algorithm{AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87} {
		params, err := mldsaParameters(algorithm)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(string(algorithm)+"/keygen", func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(params.PublicKeySize()), "public-B/op")
			b.ReportMetric(float64(params.SignatureSize()), "signature-B/op")
			for range b.N {
				private, err := mldsa.GenerateKey(params)
				if err != nil {
					b.Fatal(err)
				}
				_ = private
			}
		})
		private, err := mldsa.GenerateKey(params)
		if err != nil {
			b.Fatal(err)
		}
		public := private.PublicKey()
		message := []byte("qg benchmark message")
		opts := &mldsa.Options{}
		signature, err := private.Sign(rand.Reader, message, opts)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(string(algorithm)+"/sign", func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(params.PublicKeySize()), "public-B/op")
			b.ReportMetric(float64(params.SignatureSize()), "signature-B/op")
			for range b.N {
				if _, err := private.Sign(rand.Reader, message, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(string(algorithm)+"/verify", func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(params.PublicKeySize()), "public-B/op")
			b.ReportMetric(float64(params.SignatureSize()), "signature-B/op")
			for range b.N {
				if err := mldsa.Verify(public, message, signature, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
