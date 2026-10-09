package keyprovider

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var testScope = Scope{
	TenantID: "10000000-0000-4000-8000-000000000001", ApplicationID: "20000000-0000-4000-8000-000000000002",
	Environment: "development",
}

func TestMemoryProviderSignsByScopedReferenceAndRotatesWithoutLosingPublicKeys(t *testing.T) {
	ctx := context.Background()
	provider, err := SelectProvider(ctx, "development", MemoryDevelopment)
	if err != nil {
		t.Fatal("select explicitly configured development provider:", err)
	}
	broker, audit := newTestBroker(t, provider)
	caps := broker.Capabilities()
	if !caps.DevelopmentOnly || caps.Persistent || caps.ProtectedKeyCustody || caps.PrivateMaterialExport ||
		!containsAlgorithm(caps.Algorithms, AlgorithmEd25519) || containsOperation(caps.Operations, "decapsulate") {
		t.Fatalf("development provider advertises the wrong custody/capabilities: %+v", caps)
	}

	first, err := broker.Generate(ctx, testScope, testSpec(t, time.Now().Add(time.Hour)))
	if err != nil || first.Version != 1 || first.State != StateProvisioning || first.Reference == "" {
		t.Fatalf("new key must return scoped provisioning metadata only: %+v, %v", first, err)
	}
	if _, err := broker.Sign(ctx, testScope, first.Reference, []byte("protected action"), crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("provisioning key must not sign: %v", err)
	}
	if _, err := broker.Transition(ctx, testScope, first.Reference, StateActive); err != nil {
		t.Fatal("activate first key:", err)
	}
	message := []byte("protected action")
	signature, err := broker.Sign(ctx, testScope, first.Reference, message, crypto.Hash(0))
	if err != nil {
		t.Fatal("sign through opaque provider reference:", err)
	}
	publicDER, err := broker.PublicKey(ctx, testScope, first.Reference)
	if err != nil {
		t.Fatal("retrieve public verification material:", err)
	}
	parsedPublic, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil || !ed25519.Verify(parsedPublic.(ed25519.PublicKey), message, signature) {
		t.Fatalf("provider public key did not verify the result: %v", err)
	}
	firstSignature := append([]byte(nil), signature...)

	second, err := broker.Generate(ctx, testScope, testSpec(t, time.Now().Add(2*time.Hour)))
	if err != nil || second.Version != 2 {
		t.Fatalf("rotation candidate should receive the next purpose version: %+v, %v", second, err)
	}
	if _, err := broker.Transition(ctx, testScope, second.Reference, StateActive); err != nil {
		t.Fatal("activate replacement:", err)
	}
	old, err := broker.Metadata(ctx, testScope, first.Reference)
	if err != nil || old.State != StateRotationDue {
		t.Fatalf("replacement should move the former active key to rotation_due: %+v, %v", old, err)
	}
	if _, err := broker.Sign(ctx, testScope, first.Reference, message, crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("rotation_due key must stop signing: %v", err)
	}
	oldPublicDER, err := broker.PublicKey(ctx, testScope, first.Reference)
	if err != nil {
		t.Fatal("old public key must remain available for verification:", err)
	}
	oldPublic, err := x509.ParsePKIXPublicKey(oldPublicDER)
	if err != nil || !ed25519.Verify(oldPublic.(ed25519.PublicKey), message, firstSignature) {
		t.Fatalf("old public material did not verify its prior signature: %v", err)
	}

	if _, err := broker.Transition(ctx, testScope, second.Reference, StateDisabled); err != nil {
		t.Fatal("disable active replacement:", err)
	}
	if _, err := broker.Sign(ctx, testScope, second.Reference, message, crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("disabled key must not sign: %v", err)
	}
	if _, err := broker.Transition(ctx, testScope, second.Reference, StateActive); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("disabled key must not be reactivated: %v", err)
	}
	if _, err := broker.Transition(ctx, testScope, second.Reference, StateRevoked); err != nil {
		t.Fatal("revoke disabled key:", err)
	}
	if _, err := broker.Sign(ctx, testScope, second.Reference, message, crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("revoked key must not sign: %v", err)
	}
	if _, err := broker.Transition(ctx, testScope, second.Reference, StateDestroyed); err != nil {
		t.Fatal("destroy revoked key:", err)
	}
	if _, err := broker.Sign(ctx, testScope, second.Reference, message, crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("destroyed key must not sign: %v", err)
	}
	if _, err := broker.PublicKey(ctx, testScope, second.Reference); err != nil {
		t.Fatalf("public verification material should survive private key destruction: %v", err)
	}
	if _, err := broker.Transition(ctx, testScope, second.Reference, StateActive); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("destroyed key must be terminal: %v", err)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	foundSign := false
	for _, event := range audit.events {
		if event.Operation == OperationSign && event.Outcome == "success" && event.Phase == "completed" {
			foundSign = true
			if event.TenantID != testScope.TenantID || event.ApplicationID != testScope.ApplicationID ||
				event.Actor != testAuditContext.Actor || event.CorrelationID != testAuditContext.CorrelationID ||
				event.KeyReferenceHash == "" || event.KeyReferenceHash == first.Reference || event.ReasonCode != "SIGNATURE_CREATED" {
				t.Fatalf("signature audit must be bound and use a hashed reference: %+v", event)
			}
		}
	}
	if !foundSign {
		t.Fatal("successful signing operation must emit correlated audit evidence")
	}
}

func TestProviderSelectionHasNoProductionFallback(t *testing.T) {
	if provider, err := SelectProvider(context.Background(), "development", ""); err != nil || provider != nil {
		t.Fatalf("empty selection must leave key operations unconfigured: provider=%v err=%v", provider, err)
	}
	if _, err := SelectProvider(context.Background(), "production", MemoryDevelopment); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("development provider must be rejected in production: %v", err)
	}
	if _, err := SelectProvider(context.Background(), "production", "aws-kms"); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("unimplemented production provider must not be selected: %v", err)
	}
	if _, err := SelectProvider(context.Background(), "development", "unknown-provider"); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("unknown provider must be rejected: %v", err)
	}
	if _, err := SelectProvider(context.Background(), "development", MemoryDevelopment); err != nil {
		t.Fatalf("explicit development selection should work: %v", err)
	}
	if _, err := SelectProvider(context.Background(), "test", MemoryDevelopment); err != nil {
		t.Fatalf("explicit test selection should work: %v", err)
	}
	provider, _ := SelectProvider(context.Background(), "development", MemoryDevelopment)
	if _, err := NewBroker(context.Background(), "production", provider, newRecordingAudit()); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("broker must reject a development-only provider in production: %v", err)
	}
}

func TestProviderRejectsCrossTenantAndUnknownReferences(t *testing.T) {
	provider, _ := SelectProvider(context.Background(), "development", MemoryDevelopment)
	broker, _ := newTestBroker(t, provider)
	key, err := broker.Generate(context.Background(), testScope, testSpec(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	otherTenant := testScope
	otherTenant.TenantID = "30000000-0000-4000-8000-000000000003"
	otherApplication := testScope
	otherApplication.ApplicationID = "40000000-0000-4000-8000-000000000004"
	otherEnvironment := testScope
	otherEnvironment.Environment = "test"
	for name, scope := range map[string]Scope{"other tenant": otherTenant, "other application": otherApplication} {
		t.Run(name, func(t *testing.T) {
			if _, err := broker.Metadata(context.Background(), scope, key.Reference); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("cross-scope metadata access must look not-found: %v", err)
			}
			if _, err := broker.PublicKey(context.Background(), scope, key.Reference); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("cross-scope public key access must look not-found: %v", err)
			}
			if _, err := broker.Transition(context.Background(), scope, key.Reference, StateRevoked); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("cross-scope lifecycle access must look not-found: %v", err)
			}
		})
	}
	if _, err := broker.Metadata(context.Background(), otherEnvironment, key.Reference); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("broker must reject cross-environment key access: %v", err)
	}
	if _, err := broker.Metadata(context.Background(), testScope, "devmem_unknown_reference_000"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown key must not reveal provider data: %v", err)
	}
}

func TestProviderRejectsUnsupportedAlgorithmsAndInvalidLifecycle(t *testing.T) {
	provider, _ := SelectProvider(context.Background(), "development", MemoryDevelopment)
	broker, _ := newTestBroker(t, provider)
	if _, err := broker.Generate(context.Background(), testScope, KeySpec{
		Purpose: PurposeSigning, Algorithm: "Ed448", ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unregistered algorithm must fail closed: %v", err)
	}
	if _, err := broker.Generate(context.Background(), testScope, KeySpec{
		Purpose: PurposeDataEncryption, Algorithm: AlgorithmEd25519, ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("signing algorithm must not be used for data encryption: %v", err)
	}
	for _, expiry := range []time.Time{{}, time.Now().Add(-time.Second), time.Now().AddDate(6, 0, 0)} {
		if _, err := broker.Generate(context.Background(), testScope, KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: expiry}); !errors.Is(err, ErrInvalidKeySpec) {
			t.Errorf("invalid expiry %v should be rejected: %v", expiry, err)
		}
	}
	key, err := broker.Generate(context.Background(), testScope, testSpec(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Transition(context.Background(), testScope, key.Reference, StateDestroyed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("provisioning key must not skip directly to destruction: %v", err)
	}
	if _, err := broker.Transition(context.Background(), testScope, "devmem_unknown_reference_000", StateActive); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown key transition must fail closed: %v", err)
	}
}

func TestProviderExpiryTimeoutUnavailableAndRedactedErrors(t *testing.T) {
	ctx := context.Background()
	provider := NewMemoryDevelopmentProvider()
	key, err := provider.Generate(ctx, testScope, testSpec(t, time.Now().Add(5*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Transition(ctx, testScope, key.Reference, StateProvisioning, StateActive); err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return time.Now().Add(10 * time.Second) }
	broker, _ := newTestBroker(t, provider)
	if err := broker.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Sign(ctx, testScope, key.Reference, []byte("expired"), crypto.Hash(0)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("expired keys must not sign: %v", err)
	}
	if expired, err := broker.Metadata(ctx, testScope, key.Reference); err != nil || expired.State != StateExpired {
		t.Fatalf("expiration should be reflected in lifecycle metadata: %+v %v", expired, err)
	}

	secret := "provider-password-canary"
	denied := &providerOverride{Provider: provider, healthError: errors.New(secret)}
	if _, err := NewBroker(ctx, "development", denied, newRecordingAudit()); !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), secret) {
		t.Fatalf("provider details must be redacted from errors: %v", err)
	}
	timedOut := &providerOverride{Provider: provider, healthError: context.DeadlineExceeded}
	if _, err := NewBroker(ctx, "development", timedOut, newRecordingAudit()); !errors.Is(err, ErrProviderTimeout) {
		t.Fatalf("provider timeout must have a safe typed result: %v", err)
	}
	accessDenied := &providerOverride{Provider: provider, healthError: ErrProviderDenied}
	if _, err := NewBroker(ctx, "development", accessDenied, newRecordingAudit()); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("provider authorization failure must be surfaced: %v", err)
	}

	signingProvider := NewMemoryDevelopmentProvider()
	signingBroker, _ := newTestBroker(t, signingProvider)
	signingKey, err := signingBroker.Generate(ctx, testScope, testSpec(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signingBroker.Transition(ctx, testScope, signingKey.Reference, StateActive); err != nil {
		t.Fatal(err)
	}
	secretSignError := &providerOverride{Provider: signingProvider, signError: errors.New(secret)}
	secretBroker, err := NewBroker(ctx, "development", secretSignError, newRecordingAudit())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAuditedBroker(secretBroker).Sign(ctx, testScope, signingKey.Reference, []byte("message"), crypto.Hash(0)); !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), secret) {
		t.Fatalf("provider operation error must be sanitized: %v", err)
	}
}

func TestBrokerRejectsAlgorithmMismatchAndMalformedSignatures(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryDevelopmentProvider()
	broker, _ := newTestBroker(t, base)
	if err := broker.Health(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := broker.Generate(ctx, testScope, testSpec(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Transition(ctx, testScope, key.Reference, StateActive); err != nil {
		t.Fatal(err)
	}
	mismatched := &providerOverride{Provider: base, generateMutation: func(value Metadata) Metadata {
		value.Algorithm = "unregistered"
		return value
	}}
	mismatchBroker, err := NewBroker(ctx, "development", mismatched, newRecordingAudit())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAuditedBroker(mismatchBroker).Generate(ctx, testScope, testSpec(t, time.Now().Add(time.Hour))); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("provider algorithm mismatch must fail closed: %v", err)
	}
	malformed := &providerOverride{Provider: base, signResult: []byte("not-a-valid-signature")}
	malformedBroker, err := NewBroker(ctx, "development", malformed, newRecordingAudit())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAuditedBroker(malformedBroker).Sign(ctx, testScope, key.Reference, []byte("message"), crypto.Hash(0)); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("malformed provider signature must be rejected: %v", err)
	}
	withoutSign := &providerOverride{Provider: base, removeSignCapability: true}
	capabilityBroker, err := NewBroker(ctx, "development", withoutSign, newRecordingAudit())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAuditedBroker(capabilityBroker).Sign(ctx, testScope, key.Reference, []byte("message"), crypto.Hash(0)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing sign capability must not trigger fallback: %v", err)
	}
	exportsPrivate := &providerOverride{Provider: base, capabilitiesMutation: func(value Capabilities) Capabilities {
		value.PrivateMaterialExport = true
		return value
	}}
	if _, err := NewBroker(ctx, "development", exportsPrivate, newRecordingAudit()); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("broker must reject providers advertising private-material export: %v", err)
	}
	futureTimestamp := &providerOverride{Provider: base, generateMutation: func(value Metadata) Metadata {
		value.CreatedAt = time.Now().Add(time.Hour)
		value.UpdatedAt = value.CreatedAt
		return value
	}}
	futureBroker, err := NewBroker(ctx, "development", futureTimestamp, newRecordingAudit())
	if err != nil {
		t.Fatal("create future-metadata provider broker:", err)
	}
	if _, err := newAuditedBroker(futureBroker).Generate(ctx, testScope, testSpec(t, time.Now().Add(time.Hour))); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("provider metadata with future timestamps must be rejected: %v", err)
	}
}

func TestBrokerRequiresAuditAndDoesNotOperateWhenAuditIsUnavailable(t *testing.T) {
	provider := NewMemoryDevelopmentProvider()
	if _, err := NewBroker(context.Background(), "development", provider, nil); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("provider broker must require an audit sink: %v", err)
	}
	audit := &recordingAudit{err: errors.New("audit database password canary")}
	broker, err := NewBroker(context.Background(), "development", provider, audit)
	if err != nil {
		t.Fatal("construct broker with required audit sink:", err)
	}
	_, operationErr := broker.Generate(WithAuditContext(context.Background(), testAuditContext), testScope, testSpec(t, time.Now().Add(time.Hour)))
	if !errors.Is(operationErr, ErrAuditUnavailable) {
		t.Fatalf("provider operation must fail closed when audit cannot be recorded: %v", operationErr)
	}
	if strings.Contains(operationErr.Error(), "password canary") || len(provider.keys) != 0 {
		t.Fatal("audit failure details leaked or provider operation ran without audit")
	}
}

func TestBrokerWithholdsResultWhenCompletionAuditFails(t *testing.T) {
	provider := NewMemoryDevelopmentProvider()
	audit := &recordingAudit{err: errors.New("audit backend credential canary"), failOnCall: 2}
	broker, err := NewBroker(context.Background(), "development", provider, audit)
	if err != nil {
		t.Fatal("construct broker:", err)
	}
	result, err := broker.Generate(WithAuditContext(context.Background(), testAuditContext), testScope, testSpec(t, time.Now().Add(time.Hour)))
	if !errors.Is(err, ErrAuditUnavailable) || result.Reference != "" {
		t.Fatalf("completion-audit failure must withhold generated reference: result=%+v err=%v", result, err)
	}
	if len(provider.keys) != 1 {
		t.Fatal("test must show that the provider-side operation can complete before audit storage fails")
	}
	if strings.Contains(err.Error(), "credential canary") {
		t.Fatal("audit backend details were exposed to the caller")
	}
}

func TestAuditContextIsRequiredAndBoundPerOperation(t *testing.T) {
	ctx := context.Background()
	provider := NewMemoryDevelopmentProvider()
	audit := newRecordingAudit()
	broker, err := NewBroker(ctx, "development", provider, audit)
	if err != nil {
		t.Fatal("construct broker:", err)
	}
	if _, err := broker.Generate(ctx, testScope, testSpec(t, time.Now().Add(time.Hour))); !errors.Is(err, ErrInvalidAuditContext) {
		t.Fatalf("missing actor/correlation must reject before provider use: %v", err)
	}
	if len(provider.keys) != 0 {
		t.Fatal("provider generated a key without operation-bound audit context")
	}
	firstContext := AuditContext{Actor: "operator:alice", CorrelationID: "request-key-generation-0001"}
	key, err := broker.Generate(WithAuditContext(ctx, firstContext), testScope, testSpec(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal("generate with request audit context:", err)
	}
	secondContext := AuditContext{Actor: "operator:bob", CorrelationID: "request-key-metadata-0002"}
	if _, err := broker.Metadata(WithAuditContext(ctx, secondContext), testScope, key.Reference); err != nil {
		t.Fatal("read metadata with a separate request audit context:", err)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.events) != 4 {
		t.Fatalf("expected start/completion evidence for both operations, got %d events", len(audit.events))
	}
	if audit.events[0].Actor != firstContext.Actor || audit.events[0].CorrelationID != firstContext.CorrelationID ||
		audit.events[2].Actor != secondContext.Actor || audit.events[2].CorrelationID != secondContext.CorrelationID {
		t.Fatalf("audit actor/correlation must come from each operation context: %+v", audit.events)
	}
}

func TestConcurrentLifecycleUpdatesRejectStaleState(t *testing.T) {
	provider := NewMemoryDevelopmentProvider()
	key, err := provider.Generate(context.Background(), testScope, testSpec(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal("generate key:", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := provider.Transition(context.Background(), testScope, key.Reference, StateProvisioning, StateActive)
			results <- err
		}()
	}
	close(start)
	var successCount, staleCount int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, ErrStaleTransition):
			staleCount++
		default:
			t.Fatalf("concurrent transition returned unexpected error: %v", err)
		}
	}
	if successCount != 1 || staleCount != 1 {
		t.Fatalf("expected one committed and one stale transition, success=%d stale=%d", successCount, staleCount)
	}
}

var testAuditContext = AuditContext{Actor: "service:test-key-boundary", CorrelationID: "test-request-key-op-0001"}

func newTestBroker(t *testing.T, provider Provider) (*testBroker, *recordingAudit) {
	t.Helper()
	audit := newRecordingAudit()
	broker, err := NewBroker(context.Background(), "development", provider, audit)
	if err != nil {
		t.Fatal("create audited provider broker:", err)
	}
	return newAuditedBroker(broker), audit
}

type testBroker struct{ *Broker }

func newAuditedBroker(broker *Broker) *testBroker { return &testBroker{Broker: broker} }

func (b *testBroker) Generate(ctx context.Context, scope Scope, spec KeySpec) (Metadata, error) {
	return b.Broker.Generate(WithAuditContext(ctx, testAuditContext), scope, spec)
}

func (b *testBroker) Metadata(ctx context.Context, scope Scope, reference string) (Metadata, error) {
	return b.Broker.Metadata(WithAuditContext(ctx, testAuditContext), scope, reference)
}

func (b *testBroker) PublicKey(ctx context.Context, scope Scope, reference string) ([]byte, error) {
	return b.Broker.PublicKey(WithAuditContext(ctx, testAuditContext), scope, reference)
}

func (b *testBroker) Sign(ctx context.Context, scope Scope, reference string, input []byte, opts crypto.SignerOpts) ([]byte, error) {
	return b.Broker.Sign(WithAuditContext(ctx, testAuditContext), scope, reference, input, opts)
}

func (b *testBroker) Transition(ctx context.Context, scope Scope, reference string, target State) (Metadata, error) {
	return b.Broker.Transition(WithAuditContext(ctx, testAuditContext), scope, reference, target)
}

type recordingAudit struct {
	mu         sync.Mutex
	events     []AuditEvent
	err        error
	calls      int
	failOnCall int
}

func newRecordingAudit() *recordingAudit { return &recordingAudit{} }

func (a *recordingAudit) RecordKeyOperation(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil && (a.failOnCall == 0 || a.calls >= a.failOnCall) {
		return a.err
	}
	a.events = append(a.events, event)
	return nil
}

func testSpec(t *testing.T, expires time.Time) KeySpec {
	t.Helper()
	return KeySpec{Purpose: PurposeSigning, Algorithm: AlgorithmEd25519, ExpiresAt: expires.UTC()}
}

type providerOverride struct {
	Provider
	healthError          error
	signError            error
	signResult           []byte
	generateMutation     func(Metadata) Metadata
	capabilitiesMutation func(Capabilities) Capabilities
	removeSignCapability bool
}

func (p *providerOverride) Capabilities(ctx context.Context) (Capabilities, error) {
	capabilities, err := p.Provider.Capabilities(ctx)
	if err == nil && p.removeSignCapability {
		filtered := capabilities.Operations[:0]
		for _, operation := range capabilities.Operations {
			if operation != OperationSign {
				filtered = append(filtered, operation)
			}
		}
		capabilities.Operations = filtered
	}
	if err == nil && p.capabilitiesMutation != nil {
		capabilities = p.capabilitiesMutation(capabilities)
	}
	return capabilities, err
}

func (p *providerOverride) Health(context.Context) error {
	if p.healthError != nil {
		return p.healthError
	}
	return nil
}

func (p *providerOverride) Generate(ctx context.Context, scope Scope, spec KeySpec) (Metadata, error) {
	item, err := p.Provider.Generate(ctx, scope, spec)
	if err == nil && p.generateMutation != nil {
		item = p.generateMutation(item)
	}
	return item, err
}

func (p *providerOverride) Sign(ctx context.Context, scope Scope, reference string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if p.signError != nil {
		return nil, p.signError
	}
	if p.signResult != nil {
		return append([]byte(nil), p.signResult...), nil
	}
	return p.Provider.Sign(ctx, scope, reference, digest, opts)
}

var _ ed25519.PublicKey
