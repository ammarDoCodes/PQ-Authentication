// Package keyprovider defines the narrow boundary between QuantumGate and
// managed cryptographic keys. It includes an explicitly development-only
// in-memory providers and a Vault Transit adapter with a limited Ed25519 scope.
package keyprovider

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	MemoryDevelopment           = "memory-development"
	PQCDevelopment              = "pqc-development"
	AlgorithmEd25519  Algorithm = "Ed25519"
	AlgorithmMLDSA44  Algorithm = "ML-DSA-44"
	AlgorithmMLDSA65  Algorithm = "ML-DSA-65"
	AlgorithmMLDSA87  Algorithm = "ML-DSA-87"
	maxSigningInput             = 1 << 20
)

type Algorithm string
type Purpose string
type State string
type Operation string

const (
	PurposeSigning        Purpose = "signing"
	PurposeKeyEncryption  Purpose = "key-encryption"
	PurposeSession        Purpose = "session"
	PurposeDataEncryption Purpose = "data-encryption"
)

const (
	StateProvisioning State = "provisioning"
	StateActive       State = "active"
	StateRotationDue  State = "rotation_due"
	StateDisabled     State = "disabled"
	StateRevoked      State = "revoked"
	StateExpired      State = "expired"
	StateDestroyed    State = "destroyed"
)

const (
	OperationGenerate  Operation = "generate"
	OperationMetadata  Operation = "metadata"
	OperationPublicKey Operation = "public-key"
	OperationSign      Operation = "sign"
	OperationActivate  Operation = "activate"
	OperationRotate    Operation = "rotate"
	OperationDisable   Operation = "disable"
	OperationRevoke    Operation = "revoke"
	OperationExpire    Operation = "expire"
	OperationDestroy   Operation = "destroy"
	OperationHealth    Operation = "health"
)

var (
	ErrUnsupportedProvider = errors.New("key provider is unsupported")
	ErrProviderUnavailable = errors.New("key provider is unavailable")
	ErrProviderTimeout     = errors.New("key provider timed out")
	ErrProviderDenied      = errors.New("key provider access was denied")
	ErrInvalidScope        = errors.New("key operation scope is invalid")
	ErrInvalidKeySpec      = errors.New("key specification is invalid")
	ErrUnsupported         = errors.New("key provider capability is unsupported")
	ErrKeyNotFound         = errors.New("key reference was not found")
	ErrKeyUnavailable      = errors.New("key is not available for this operation")
	ErrInvalidTransition   = errors.New("key lifecycle transition is invalid")
	ErrStaleTransition     = errors.New("key lifecycle state changed concurrently")
	ErrMalformedResponse   = errors.New("key provider returned malformed data")
	ErrAuditUnavailable    = errors.New("key operation audit is unavailable")
	ErrInvalidAuditContext = errors.New("key operation audit context is invalid")
)

type Scope struct {
	TenantID      string
	ApplicationID string
	Environment   string
}

type KeySpec struct {
	Purpose   Purpose
	Algorithm Algorithm
	ExpiresAt time.Time
}

// Metadata deliberately contains no private or symmetric key bytes.
type Metadata struct {
	Provider  string
	Reference string
	Purpose   Purpose
	Algorithm Algorithm
	Version   uint64
	State     State
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}

type Capabilities struct {
	Provider              string
	DevelopmentOnly       bool
	Persistent            bool
	PrivateMaterialExport bool
	ProtectedKeyCustody   bool
	Algorithms            []Algorithm
	Operations            []Operation
}

type AuditContext struct {
	Actor         string
	CorrelationID string
}

type auditContextKey struct{}

// WithAuditContext binds the authenticated actor and server-generated request
// correlation ID to one provider operation. Callers must source these values
// from authenticated server context, never directly from untrusted input.
func WithAuditContext(ctx context.Context, value AuditContext) context.Context {
	return context.WithValue(ctx, auditContextKey{}, value)
}

// AuditEvent deliberately carries only a hash of the provider reference and
// never contains operation input, signatures, private bytes, or backend errors.
type AuditEvent struct {
	TenantID         string
	ApplicationID    string
	Environment      string
	Actor            string
	CorrelationID    string
	Provider         string
	KeyReferenceHash string
	Purpose          Purpose
	Algorithm        Algorithm
	Operation        Operation
	Phase            string
	Outcome          string
	ReasonCode       string
}

type AuditSink interface {
	RecordKeyOperation(context.Context, AuditEvent) error
}

// safeProviderOperationError adds only a fixed operation label to a sanitized
// provider error, preserving useful failure stage without retaining backend
// response text that could contain credentials or sensitive paths.
type safeProviderOperationError struct {
	operation string
	cause     error
}

func (e *safeProviderOperationError) Error() string {
	return e.operation + ": " + e.cause.Error()
}

func (e *safeProviderOperationError) Unwrap() error { return e.cause }

// Provider methods address keys by opaque reference and trusted tenant,
// application, and environment scope. Implementations must never return
// private material. Transition must atomically compare expectedState and
// reject stale state before applying targetState. Sign follows crypto.Signer's
// digest/options contract.
type Provider interface {
	Capabilities(context.Context) (Capabilities, error)
	Generate(context.Context, Scope, KeySpec) (Metadata, error)
	Metadata(context.Context, Scope, string) (Metadata, error)
	PublicKey(context.Context, Scope, string) ([]byte, error)
	Sign(context.Context, Scope, string, []byte, crypto.SignerOpts) ([]byte, error)
	Transition(context.Context, Scope, string, State, State) (Metadata, error)
	Health(context.Context) error
}

// Broker validates provider capabilities and every result before returning it
// to application code. Callers still own authorization and audit transactions.
type Broker struct {
	environment  string
	provider     Provider
	capabilities Capabilities
	audit        AuditSink
}

func NewBroker(ctx context.Context, environment string, provider Provider, audit AuditSink) (*Broker, error) {
	if provider == nil {
		return nil, ErrUnsupportedProvider
	}
	if environment != "development" && environment != "test" && environment != "production" {
		return nil, ErrInvalidScope
	}
	if audit == nil {
		return nil, ErrAuditUnavailable
	}
	capabilities, err := provider.Capabilities(ctx)
	if err != nil {
		return nil, sanitizeProviderError(err)
	}
	if !validCapabilities(capabilities) {
		return nil, ErrMalformedResponse
	}
	if capabilities.DevelopmentOnly && environment == "production" {
		return nil, ErrUnsupportedProvider
	}
	if err := provider.Health(ctx); err != nil {
		return nil, sanitizeProviderError(err)
	}
	return &Broker{environment: environment, provider: provider, capabilities: cloneCapabilities(capabilities), audit: audit}, nil
}

// SelectProvider has no production fallback. An empty selection means no key
// provider is configured; the memory provider is available only in development.
func SelectProvider(ctx context.Context, environment, name string) (Provider, error) {
	return SelectProviderWithConfig(ctx, environment, name, nil)
}

// SelectProviderWithConfig selects only explicitly configured backends. Vault
// requires its durable tenant-scoped metadata store and never falls back to
// development providers when construction or health checks fail.
func SelectProviderWithConfig(ctx context.Context, environment, name string, vaultConfig *VaultConfig) (Provider, error) {
	if name == "" {
		return nil, nil
	}
	if name == VaultTransit {
		if vaultConfig == nil || vaultConfig.Environment != environment {
			return nil, ErrUnsupportedProvider
		}
		provider, err := NewVaultProvider(*vaultConfig)
		if err != nil {
			return nil, sanitizeProviderError(err)
		}
		if err := provider.Health(ctx); err != nil {
			return nil, sanitizeProviderError(err)
		}
		return provider, nil
	}
	if (environment != "development" && environment != "test") ||
		(name != MemoryDevelopment && name != PQCDevelopment) {
		return nil, ErrUnsupportedProvider
	}
	var provider Provider
	if name == PQCDevelopment {
		provider = NewPQCDevelopmentProvider()
	} else {
		provider = NewMemoryDevelopmentProvider()
	}
	if err := provider.Health(ctx); err != nil {
		return nil, sanitizeProviderError(err)
	}
	return provider, nil
}

func (b *Broker) Name() string {
	if b == nil {
		return ""
	}
	return b.capabilities.Provider
}

func (b *Broker) Capabilities() Capabilities {
	if b == nil {
		return Capabilities{}
	}
	return cloneCapabilities(b.capabilities)
}

func (b *Broker) Health(ctx context.Context) error {
	if b == nil || b.provider == nil {
		return ErrProviderUnavailable
	}
	if err := b.provider.Health(ctx); err != nil {
		return sanitizeProviderError(err)
	}
	return nil
}

func (b *Broker) Generate(ctx context.Context, scope Scope, spec KeySpec) (Metadata, error) {
	if b == nil || b.provider == nil {
		return Metadata{}, ErrProviderUnavailable
	}
	if !b.validScope(scope) {
		return Metadata{}, ErrInvalidScope
	}
	if !validKeySpec(spec) {
		return Metadata{}, ErrInvalidKeySpec
	}
	if !b.supports(OperationGenerate, spec.Algorithm) {
		return Metadata{}, ErrUnsupported
	}
	if err := b.auditEvent(ctx, scope, OperationGenerate, "", nil, "started", "requested", "KEY_GENERATION_REQUESTED"); err != nil {
		return Metadata{}, err
	}
	item, err := b.provider.Generate(ctx, scope, spec)
	if err != nil {
		return Metadata{}, b.finishFailure(ctx, scope, OperationGenerate, "", nil, err)
	}
	if !validMetadata(item) || item.Provider != b.Name() || item.Purpose != spec.Purpose ||
		item.Algorithm != spec.Algorithm || item.State != StateProvisioning || !item.ExpiresAt.Equal(spec.ExpiresAt.UTC()) {
		return Metadata{}, b.finishFailure(ctx, scope, OperationGenerate, item.Reference, &item, ErrMalformedResponse)
	}
	if err := b.auditEvent(ctx, scope, OperationGenerate, item.Reference, &item, "completed", "success", "KEY_GENERATED"); err != nil {
		return Metadata{}, err
	}
	return cloneMetadata(item), nil
}

func (b *Broker) Metadata(ctx context.Context, scope Scope, reference string) (Metadata, error) {
	if b == nil || b.provider == nil {
		return Metadata{}, ErrProviderUnavailable
	}
	if !b.validScope(scope) || !validReference(reference) {
		return Metadata{}, ErrInvalidScope
	}
	if !b.supports(OperationMetadata, "") {
		return Metadata{}, ErrUnsupported
	}
	if err := b.auditEvent(ctx, scope, OperationMetadata, reference, nil, "started", "requested", "KEY_METADATA_REQUESTED"); err != nil {
		return Metadata{}, err
	}
	item, err := b.metadata(ctx, scope, reference)
	if err != nil {
		return Metadata{}, b.finishFailure(ctx, scope, OperationMetadata, reference, nil, err)
	}
	if err := b.auditEvent(ctx, scope, OperationMetadata, reference, &item, "completed", "success", "KEY_METADATA_READ"); err != nil {
		return Metadata{}, err
	}
	return cloneMetadata(item), nil
}

func (b *Broker) PublicKey(ctx context.Context, scope Scope, reference string) ([]byte, error) {
	if b == nil || b.provider == nil {
		return nil, ErrProviderUnavailable
	}
	if !b.validScope(scope) || !validReference(reference) {
		return nil, ErrInvalidScope
	}
	if !b.supports(OperationPublicKey, "") {
		return nil, ErrUnsupported
	}
	if err := b.auditEvent(ctx, scope, OperationPublicKey, reference, nil, "started", "requested", "PUBLIC_KEY_REQUESTED"); err != nil {
		return nil, err
	}
	item, err := b.metadata(ctx, scope, reference)
	if err != nil {
		return nil, b.finishFailure(ctx, scope, OperationPublicKey, reference, nil, err)
	}
	if !b.supports(OperationPublicKey, item.Algorithm) {
		return nil, b.finishFailure(ctx, scope, OperationPublicKey, reference, &item, ErrUnsupported)
	}
	material, err := b.publicKey(ctx, scope, reference, item)
	if err != nil {
		return nil, b.finishFailure(ctx, scope, OperationPublicKey, reference, &item, err)
	}
	if err := b.auditEvent(ctx, scope, OperationPublicKey, reference, &item, "completed", "success", "PUBLIC_KEY_READ"); err != nil {
		return nil, err
	}
	return append([]byte(nil), material...), nil
}

func (b *Broker) Sign(ctx context.Context, scope Scope, reference string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if b == nil || b.provider == nil {
		return nil, ErrProviderUnavailable
	}
	if !b.validScope(scope) || !validReference(reference) {
		return nil, ErrInvalidScope
	}
	if !b.supports(OperationSign, "") {
		return nil, ErrUnsupported
	}
	if err := b.auditEvent(ctx, scope, OperationSign, reference, nil, "started", "requested", "SIGNATURE_REQUESTED"); err != nil {
		return nil, err
	}
	item, err := b.metadata(ctx, scope, reference)
	if err != nil {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, nil, err)
	}
	if item.Purpose != PurposeSigning || item.State != StateActive {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, &item, ErrKeyUnavailable)
	}
	if !time.Now().Before(item.ExpiresAt) {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, &item, ErrKeyUnavailable)
	}
	if !b.supports(OperationSign, item.Algorithm) {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, &item, ErrUnsupported)
	}
	if len(digest) == 0 || len(digest) > maxSigningInput || !validSigningOptions(item.Algorithm, opts) {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, &item, ErrInvalidKeySpec)
	}
	signature, err := b.provider.Sign(ctx, scope, reference, append([]byte(nil), digest...), opts)
	if err != nil {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, &item, err)
	}
	publicBytes, err := b.publicKey(ctx, scope, reference, item)
	if err != nil {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, &item, err)
	}
	public, err := x509.ParsePKIXPublicKey(publicBytes)
	if err != nil || !verifySignature(item.Algorithm, public, digest, signature, opts) {
		return nil, b.finishFailure(ctx, scope, OperationSign, reference, &item, ErrMalformedResponse)
	}
	if err := b.auditEvent(ctx, scope, OperationSign, reference, &item, "completed", "success", "SIGNATURE_CREATED"); err != nil {
		return nil, err
	}
	return append([]byte(nil), signature...), nil
}

func (b *Broker) Transition(ctx context.Context, scope Scope, reference string, target State) (Metadata, error) {
	if b == nil || b.provider == nil {
		return Metadata{}, ErrProviderUnavailable
	}
	if !b.validScope(scope) || !validReference(reference) {
		return Metadata{}, ErrInvalidScope
	}
	operation := transitionOperation(target)
	if operation == "" || !b.supports(operation, "") {
		return Metadata{}, ErrUnsupported
	}
	if err := b.auditEvent(ctx, scope, operation, reference, nil, "started", "requested", "KEY_LIFECYCLE_CHANGE_REQUESTED"); err != nil {
		return Metadata{}, err
	}
	current, err := b.metadata(ctx, scope, reference)
	if err != nil {
		return Metadata{}, b.finishFailure(ctx, scope, operation, reference, nil, err)
	}
	if !b.supports(operation, current.Algorithm) {
		return Metadata{}, b.finishFailure(ctx, scope, operation, reference, &current, ErrUnsupported)
	}
	if current.State == target {
		if err := b.auditEvent(ctx, scope, operation, reference, &current, "completed", "success", "KEY_LIFECYCLE_UNCHANGED"); err != nil {
			return Metadata{}, err
		}
		return current, nil
	}
	if !allowedTransition(current.State, target) {
		return Metadata{}, b.finishFailure(ctx, scope, operation, reference, &current, ErrInvalidTransition)
	}
	item, err := b.provider.Transition(ctx, scope, reference, current.State, target)
	if err != nil {
		return Metadata{}, b.finishFailure(ctx, scope, operation, reference, &current, err)
	}
	if !validMetadata(item) || item.Provider != current.Provider || item.Reference != current.Reference ||
		item.Purpose != current.Purpose || item.Algorithm != current.Algorithm || item.Version != current.Version ||
		item.State != target || item.UpdatedAt.Before(current.UpdatedAt) {
		return Metadata{}, b.finishFailure(ctx, scope, operation, reference, &current, ErrMalformedResponse)
	}
	if err := b.auditEvent(ctx, scope, operation, reference, &item, "completed", "success", "KEY_LIFECYCLE_CHANGED"); err != nil {
		return Metadata{}, err
	}
	return cloneMetadata(item), nil
}

func (b *Broker) supports(operation Operation, algorithm Algorithm) bool {
	if operation != "" && !containsOperation(b.capabilities.Operations, operation) {
		return false
	}
	return algorithm == "" || containsAlgorithm(b.capabilities.Algorithms, algorithm)
}

func (b *Broker) validScope(scope Scope) bool {
	return b != nil && validScope(scope) && scope.Environment == b.environment
}

func (b *Broker) metadata(ctx context.Context, scope Scope, reference string) (Metadata, error) {
	item, err := b.provider.Metadata(ctx, scope, reference)
	if err != nil {
		return Metadata{}, sanitizeProviderError(err)
	}
	if !validMetadata(item) || item.Provider != b.Name() || item.Reference != reference || !b.supports("", item.Algorithm) {
		return Metadata{}, ErrMalformedResponse
	}
	return cloneMetadata(item), nil
}

func (b *Broker) publicKey(ctx context.Context, scope Scope, reference string, item Metadata) ([]byte, error) {
	material, err := b.provider.PublicKey(ctx, scope, reference)
	if err != nil {
		return nil, sanitizeProviderError(err)
	}
	if len(material) == 0 || len(material) > 4096 {
		return nil, ErrMalformedResponse
	}
	public, err := x509.ParsePKIXPublicKey(material)
	if err != nil || !validPublicKey(item.Algorithm, public) {
		return nil, ErrMalformedResponse
	}
	return append([]byte(nil), material...), nil
}

func (b *Broker) finishFailure(ctx context.Context, scope Scope, operation Operation, reference string, item *Metadata, failure error) error {
	safeFailure := sanitizeProviderError(failure)
	if err := b.auditEvent(ctx, scope, operation, reference, item, "completed", "failure", reasonCode(safeFailure)); err != nil {
		return ErrAuditUnavailable
	}
	return safeFailure
}

func (b *Broker) auditEvent(ctx context.Context, scope Scope, operation Operation, reference string, item *Metadata, phase, outcome, reason string) error {
	if b == nil || b.audit == nil || !b.validScope(scope) {
		return ErrAuditUnavailable
	}
	auditContext, ok := ctx.Value(auditContextKey{}).(AuditContext)
	if !ok || !validAuditContext(auditContext) {
		return ErrInvalidAuditContext
	}
	event := AuditEvent{
		TenantID: scope.TenantID, ApplicationID: scope.ApplicationID, Environment: scope.Environment,
		Actor: auditContext.Actor, CorrelationID: auditContext.CorrelationID,
		Provider: b.Name(), Operation: operation, Phase: phase, Outcome: outcome, ReasonCode: reason,
	}
	if item != nil {
		event.Purpose = item.Purpose
		event.Algorithm = item.Algorithm
	}
	if validReference(reference) {
		referenceHash := sha256.Sum256([]byte(reference))
		event.KeyReferenceHash = hex.EncodeToString(referenceHash[:])
	}
	if err := b.audit.RecordKeyOperation(ctx, event); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func reasonCode(err error) string {
	switch {
	case errors.Is(err, ErrProviderTimeout):
		return "PROVIDER_TIMEOUT"
	case errors.Is(err, ErrProviderDenied):
		return "PROVIDER_ACCESS_DENIED"
	case errors.Is(err, ErrProviderUnavailable):
		return "PROVIDER_UNAVAILABLE"
	case errors.Is(err, ErrKeyNotFound):
		return "KEY_NOT_FOUND"
	case errors.Is(err, ErrKeyUnavailable):
		return "KEY_UNAVAILABLE"
	case errors.Is(err, ErrInvalidTransition):
		return "INVALID_KEY_TRANSITION"
	case errors.Is(err, ErrStaleTransition):
		return "STALE_KEY_TRANSITION"
	case errors.Is(err, ErrMalformedResponse):
		return "MALFORMED_PROVIDER_RESPONSE"
	case errors.Is(err, ErrUnsupported):
		return "UNSUPPORTED_PROVIDER_CAPABILITY"
	case errors.Is(err, ErrInvalidKeySpec):
		return "INVALID_KEY_SPEC"
	default:
		return "KEY_OPERATION_FAILED"
	}
}

func validAuditContext(value AuditContext) bool {
	return validAuditText(value.Actor, 256) && validAuditText(value.CorrelationID, 128)
}

func validAuditText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}

type MemoryDevelopmentProvider struct {
	mu       sync.RWMutex
	now      func() time.Time
	keys     map[scopedReference]*memoryKey
	versions map[versionScope]uint64
}

type memoryKey struct {
	metadata  Metadata
	publicKey []byte
	private   ed25519.PrivateKey
}

type scopedReference struct {
	Scope     Scope
	Reference string
}

type versionScope struct {
	Scope   Scope
	Purpose Purpose
}

func NewMemoryDevelopmentProvider() *MemoryDevelopmentProvider {
	return &MemoryDevelopmentProvider{
		now: time.Now, keys: make(map[scopedReference]*memoryKey), versions: make(map[versionScope]uint64),
	}
}

func (p *MemoryDevelopmentProvider) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	return Capabilities{
		Provider: MemoryDevelopment, DevelopmentOnly: true, Persistent: false,
		PrivateMaterialExport: false, ProtectedKeyCustody: false,
		Algorithms: []Algorithm{AlgorithmEd25519},
		Operations: []Operation{OperationGenerate, OperationMetadata, OperationPublicKey, OperationSign,
			OperationActivate, OperationRotate, OperationDisable, OperationRevoke, OperationExpire, OperationDestroy, OperationHealth},
	}, nil
}

func (p *MemoryDevelopmentProvider) Health(ctx context.Context) error {
	return ctx.Err()
}

func (p *MemoryDevelopmentProvider) Generate(ctx context.Context, scope Scope, spec KeySpec) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if !validScope(scope) || (scope.Environment != "development" && scope.Environment != "test") {
		return Metadata{}, ErrInvalidScope
	}
	if !validKeySpec(spec) || spec.Purpose != PurposeSigning || spec.Algorithm != AlgorithmEd25519 {
		return Metadata{}, ErrUnsupported
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Metadata{}, ErrProviderUnavailable
	}
	defer clear(private)
	publicBytes, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return Metadata{}, ErrProviderUnavailable
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Metadata{}, ErrProviderUnavailable
	}
	reference := "devmem_" + base64.RawURLEncoding.EncodeToString(random[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	keyID := scopedReference{Scope: scope, Reference: reference}
	if _, exists := p.keys[keyID]; exists {
		return Metadata{}, ErrProviderUnavailable
	}
	versionID := versionScope{Scope: scope, Purpose: spec.Purpose}
	p.versions[versionID]++
	now := p.now().UTC()
	item := Metadata{
		Provider: MemoryDevelopment, Reference: reference, Purpose: spec.Purpose,
		Algorithm: spec.Algorithm, Version: p.versions[versionID], State: StateProvisioning,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: spec.ExpiresAt.UTC(),
	}
	p.keys[keyID] = &memoryKey{
		metadata: item, publicKey: append([]byte(nil), publicBytes...), private: append(ed25519.PrivateKey(nil), private...),
	}
	return cloneMetadata(item), nil
}

func (p *MemoryDevelopmentProvider) Metadata(ctx context.Context, scope Scope, reference string) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if !validScope(scope) || (scope.Environment != "development" && scope.Environment != "test") || !validReference(reference) {
		return Metadata{}, ErrKeyNotFound
	}
	p.mu.RLock()
	item := p.keys[scopedReference{Scope: scope, Reference: reference}]
	if item == nil {
		p.mu.RUnlock()
		return Metadata{}, ErrKeyNotFound
	}
	value := item.metadata
	p.mu.RUnlock()
	if value.State == StateActive && !p.now().Before(value.ExpiresAt) {
		return p.Transition(ctx, scope, reference, StateActive, StateExpired)
	}
	return cloneMetadata(value), nil
}

func (p *MemoryDevelopmentProvider) PublicKey(ctx context.Context, scope Scope, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validScope(scope) || (scope.Environment != "development" && scope.Environment != "test") || !validReference(reference) {
		return nil, ErrKeyNotFound
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	item := p.keys[scopedReference{Scope: scope, Reference: reference}]
	if item == nil {
		return nil, ErrKeyNotFound
	}
	return append([]byte(nil), item.publicKey...), nil
}

func (p *MemoryDevelopmentProvider) Sign(ctx context.Context, scope Scope, reference string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(digest) == 0 || len(digest) > maxSigningInput || opts == nil || opts.HashFunc() != 0 {
		return nil, ErrInvalidKeySpec
	}
	if !validScope(scope) || (scope.Environment != "development" && scope.Environment != "test") || !validReference(reference) {
		return nil, ErrKeyNotFound
	}
	p.mu.Lock()
	item := p.keys[scopedReference{Scope: scope, Reference: reference}]
	if item == nil {
		p.mu.Unlock()
		return nil, ErrKeyNotFound
	}
	if item.metadata.State == StateActive && !p.now().Before(item.metadata.ExpiresAt) {
		item.metadata.State = StateExpired
		item.metadata.UpdatedAt = p.now().UTC()
	}
	if item.metadata.Purpose != PurposeSigning || item.metadata.Algorithm != AlgorithmEd25519 ||
		item.metadata.State != StateActive || len(item.private) != ed25519.PrivateKeySize {
		p.mu.Unlock()
		return nil, ErrKeyUnavailable
	}
	// Keep the lock while signing so a concurrent revoke, disable, expiry, or
	// destroy cannot return an old active key after its transition has won.
	signature := ed25519.Sign(item.private, digest)
	p.mu.Unlock()
	return signature, nil
}

func (p *MemoryDevelopmentProvider) Transition(ctx context.Context, scope Scope, reference string, expected, target State) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if !validScope(scope) || (scope.Environment != "development" && scope.Environment != "test") || !validReference(reference) {
		return Metadata{}, ErrKeyNotFound
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	item := p.keys[scopedReference{Scope: scope, Reference: reference}]
	if item == nil {
		return Metadata{}, ErrKeyNotFound
	}
	if item.metadata.State != expected {
		return Metadata{}, ErrStaleTransition
	}
	if item.metadata.State == target {
		return cloneMetadata(item.metadata), nil
	}
	if !allowedTransition(item.metadata.State, target) {
		return Metadata{}, ErrInvalidTransition
	}
	if target == StateActive && !p.now().Before(item.metadata.ExpiresAt) {
		return Metadata{}, ErrKeyUnavailable
	}
	if target == StateActive {
		for keyID, other := range p.keys {
			if keyID.Scope == scope && keyID.Reference != reference && other.metadata.Purpose == item.metadata.Purpose && other.metadata.State == StateActive {
				other.metadata.State = StateRotationDue
				other.metadata.UpdatedAt = p.now().UTC()
			}
		}
	}
	if target == StateExpired && item.metadata.State == StateActive {
		item.metadata.State = StateExpired
	}
	item.metadata.State = target
	item.metadata.UpdatedAt = p.now().UTC()
	if target == StateDestroyed {
		clear(item.private)
		item.private = nil
	}
	return cloneMetadata(item.metadata), nil
}

func validScope(scope Scope) bool {
	return validUUID(scope.TenantID) && validUUID(scope.ApplicationID) &&
		(scope.Environment == "development" || scope.Environment == "test" || scope.Environment == "production")
}

func validKeySpec(spec KeySpec) bool {
	return oneOfPurpose(spec.Purpose) && spec.ExpiresAt.After(time.Now()) && spec.ExpiresAt.Before(time.Now().AddDate(5, 0, 0))
}

func validMetadata(item Metadata) bool {
	now := time.Now()
	return validProviderName(item.Provider) && validReference(item.Reference) && oneOfPurpose(item.Purpose) &&
		oneOfAlgorithm(item.Algorithm) && item.Version > 0 && oneOfState(item.State) &&
		!item.CreatedAt.IsZero() && !item.UpdatedAt.IsZero() && !item.ExpiresAt.IsZero() &&
		item.CreatedAt.Before(item.ExpiresAt) && !item.UpdatedAt.Before(item.CreatedAt) &&
		!item.CreatedAt.After(now.Add(30*time.Second)) && !item.UpdatedAt.After(now.Add(30*time.Second))
}

func validCapabilities(value Capabilities) bool {
	if !validProviderName(value.Provider) || value.PrivateMaterialExport || len(value.Algorithms) == 0 || len(value.Algorithms) > 16 || len(value.Operations) == 0 || len(value.Operations) > 32 {
		return false
	}
	seenAlgorithms := make(map[Algorithm]struct{}, len(value.Algorithms))
	for _, algorithm := range value.Algorithms {
		if !oneOfAlgorithm(algorithm) {
			return false
		}
		if _, exists := seenAlgorithms[algorithm]; exists {
			return false
		}
		seenAlgorithms[algorithm] = struct{}{}
	}
	seenOperations := make(map[Operation]struct{}, len(value.Operations))
	for _, operation := range value.Operations {
		if !oneOfOperation(operation) {
			return false
		}
		if _, exists := seenOperations[operation]; exists {
			return false
		}
		seenOperations[operation] = struct{}{}
	}
	return true
}

func oneOfOperation(operation Operation) bool {
	switch operation {
	case OperationGenerate, OperationMetadata, OperationPublicKey, OperationSign, OperationActivate,
		OperationRotate, OperationDisable, OperationRevoke, OperationExpire, OperationDestroy, OperationHealth:
		return true
	default:
		return false
	}
}

func validPublicKey(algorithm Algorithm, public any) bool {
	switch algorithm {
	case AlgorithmEd25519:
		key, ok := public.(ed25519.PublicKey)
		return ok && len(key) == ed25519.PublicKeySize
	case AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87:
		key, ok := public.(*mldsa.PublicKey)
		return ok && key != nil && key.Parameters().String() == string(algorithm)
	default:
		return false
	}
}

func verifySignature(algorithm Algorithm, public any, message, signature []byte, opts crypto.SignerOpts) bool {
	switch algorithm {
	case AlgorithmEd25519:
		key, ok := public.(ed25519.PublicKey)
		return ok && ed25519.Verify(key, message, signature)
	case AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87:
		key, keyOK := public.(*mldsa.PublicKey)
		options, optionsOK := opts.(*mldsa.Options)
		return keyOK && key != nil && optionsOK && options != nil && key.Parameters().String() == string(algorithm) &&
			mldsa.Verify(key, message, signature, options) == nil
	default:
		return false
	}
}

func validSigningOptions(algorithm Algorithm, opts crypto.SignerOpts) bool {
	if opts == nil || opts.HashFunc() != 0 {
		return false
	}
	switch algorithm {
	case AlgorithmEd25519:
		return true
	case AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87:
		options, ok := opts.(*mldsa.Options)
		return ok && options != nil && len(options.Context) <= 255
	default:
		return false
	}
}

func oneOfAlgorithm(algorithm Algorithm) bool {
	switch algorithm {
	case AlgorithmEd25519, AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87:
		return true
	default:
		return false
	}
}

func allowedTransition(current, target State) bool {
	switch current {
	case StateProvisioning:
		return target == StateActive || target == StateDisabled || target == StateRevoked || target == StateExpired
	case StateActive:
		return target == StateRotationDue || target == StateDisabled || target == StateRevoked || target == StateExpired
	case StateRotationDue:
		return target == StateDisabled || target == StateRevoked || target == StateExpired
	case StateDisabled:
		return target == StateRevoked || target == StateExpired
	case StateRevoked, StateExpired:
		return target == StateDestroyed
	default:
		return false
	}
}

func transitionOperation(target State) Operation {
	switch target {
	case StateActive:
		return OperationActivate
	case StateRotationDue:
		return OperationRotate
	case StateDisabled:
		return OperationDisable
	case StateRevoked:
		return OperationRevoke
	case StateExpired:
		return OperationExpire
	case StateDestroyed:
		return OperationDestroy
	default:
		return ""
	}
}

func sanitizeProviderError(err error) error {
	switch {
	case err == nil:
		return nil
	case hasSafeProviderOperationError(err):
		var operationErr *safeProviderOperationError
		_ = errors.As(err, &operationErr)
		return &safeProviderOperationError{operation: operationErr.operation, cause: sanitizeProviderError(operationErr.cause)}
	case errors.Is(err, context.DeadlineExceeded):
		return ErrProviderTimeout
	case errors.Is(err, ErrProviderTimeout):
		return ErrProviderTimeout
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, ErrProviderDenied):
		return ErrProviderDenied
	case errors.Is(err, ErrKeyNotFound):
		return ErrKeyNotFound
	case errors.Is(err, ErrKeyUnavailable):
		return ErrKeyUnavailable
	case errors.Is(err, ErrInvalidTransition):
		return ErrInvalidTransition
	case errors.Is(err, ErrStaleTransition):
		return ErrStaleTransition
	case errors.Is(err, ErrUnsupported):
		return ErrUnsupported
	case errors.Is(err, ErrMalformedResponse):
		return ErrMalformedResponse
	case errors.Is(err, ErrInvalidScope):
		return ErrInvalidScope
	case errors.Is(err, ErrInvalidKeySpec):
		return ErrInvalidKeySpec
	default:
		return ErrProviderUnavailable
	}
}

func hasSafeProviderOperationError(err error) bool {
	var operationErr *safeProviderOperationError
	return errors.As(err, &operationErr)
}

func cloneCapabilities(value Capabilities) Capabilities {
	value.Algorithms = append([]Algorithm(nil), value.Algorithms...)
	value.Operations = append([]Operation(nil), value.Operations...)
	return value
}

func cloneMetadata(value Metadata) Metadata { return value }

func validReference(value string) bool {
	if len(value) < 16 || len(value) > 1024 || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}

func validProviderName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' ||
			index > 0 && (char == '.' || char == '_' || char == '-')) {
			return false
		}
	}
	return true
}

func oneOfPurpose(value Purpose) bool {
	return value == PurposeSigning || value == PurposeKeyEncryption || value == PurposeSession || value == PurposeDataEncryption
}

func oneOfState(value State) bool {
	return value == StateProvisioning || value == StateActive || value == StateRotationDue || value == StateDisabled ||
		value == StateRevoked || value == StateExpired || value == StateDestroyed
}

func containsAlgorithm(values []Algorithm, candidate Algorithm) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func containsOperation(values []Operation, candidate Operation) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F') {
			return false
		}
	}
	return true
}
