package keyprovider

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"sync"
	"time"
)

// PQCDevelopmentProvider provides ephemeral, process-resident signing keys for
// development and interoperability checks. It does not provide protected key
// custody, persistence, KEM operations, or production signing profiles.
type PQCDevelopmentProvider struct {
	mu       sync.Mutex
	now      func() time.Time
	keys     map[scopedReference]*pqcDevelopmentKey
	versions map[versionScope]uint64
}

type pqcDevelopmentKey struct {
	metadata  Metadata
	publicKey []byte
	private   crypto.Signer
}

func NewPQCDevelopmentProvider() *PQCDevelopmentProvider {
	return &PQCDevelopmentProvider{
		now: time.Now, keys: make(map[scopedReference]*pqcDevelopmentKey),
		versions: make(map[versionScope]uint64),
	}
}

func (p *PQCDevelopmentProvider) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	return Capabilities{
		Provider: PQCDevelopment, DevelopmentOnly: true, Persistent: false,
		PrivateMaterialExport: false, ProtectedKeyCustody: false,
		Algorithms: []Algorithm{AlgorithmEd25519, AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87},
		Operations: []Operation{OperationGenerate, OperationMetadata, OperationPublicKey, OperationSign,
			OperationActivate, OperationRotate, OperationDisable, OperationRevoke, OperationExpire,
			OperationDestroy, OperationHealth},
	}, nil
}

func (p *PQCDevelopmentProvider) Health(ctx context.Context) error { return ctx.Err() }

func (p *PQCDevelopmentProvider) Generate(ctx context.Context, scope Scope, spec KeySpec) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if !validScope(scope) || (scope.Environment != "development" && scope.Environment != "test") {
		return Metadata{}, ErrInvalidScope
	}
	if !validKeySpec(spec) || spec.Purpose != PurposeSigning {
		return Metadata{}, ErrUnsupported
	}

	private, err := developmentSigner(spec.Algorithm)
	if err != nil {
		return Metadata{}, err
	}
	if err := ctx.Err(); err != nil {
		discardDevelopmentSigner(private)
		return Metadata{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		discardDevelopmentSigner(private)
		return Metadata{}, ErrProviderUnavailable
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		discardDevelopmentSigner(private)
		return Metadata{}, ErrProviderUnavailable
	}
	reference := "devpqc_" + base64.RawURLEncoding.EncodeToString(random[:])

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		discardDevelopmentSigner(private)
		return Metadata{}, err
	}
	keyID := scopedReference{Scope: scope, Reference: reference}
	if _, exists := p.keys[keyID]; exists {
		discardDevelopmentSigner(private)
		return Metadata{}, ErrProviderUnavailable
	}
	versionID := versionScope{Scope: scope, Purpose: spec.Purpose}
	p.versions[versionID]++
	now := p.now().UTC()
	item := Metadata{
		Provider: PQCDevelopment, Reference: reference, Purpose: spec.Purpose,
		Algorithm: spec.Algorithm, Version: p.versions[versionID], State: StateProvisioning,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: spec.ExpiresAt.UTC(),
	}
	p.keys[keyID] = &pqcDevelopmentKey{
		metadata: item, publicKey: append([]byte(nil), publicBytes...), private: private,
	}
	return cloneMetadata(item), nil
}

func developmentSigner(algorithm Algorithm) (crypto.Signer, error) {
	switch algorithm {
	case AlgorithmEd25519:
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, ErrProviderUnavailable
		}
		stored := ed25519.PrivateKey(append([]byte(nil), private...))
		clear(private)
		return stored, nil
	case AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87:
		parameters, err := mldsaParameters(algorithm)
		if err != nil {
			return nil, err
		}
		private, err := mldsa.GenerateKey(parameters)
		if err != nil {
			return nil, ErrProviderUnavailable
		}
		return private, nil
	default:
		return nil, ErrUnsupported
	}
}

func mldsaParameters(algorithm Algorithm) (mldsa.Parameters, error) {
	switch algorithm {
	case AlgorithmMLDSA44:
		return mldsa.MLDSA44(), nil
	case AlgorithmMLDSA65:
		return mldsa.MLDSA65(), nil
	case AlgorithmMLDSA87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, ErrUnsupported
	}
}

func (p *PQCDevelopmentProvider) Metadata(ctx context.Context, scope Scope, reference string) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if !validDevelopmentScope(scope) || !validReference(reference) {
		return Metadata{}, ErrKeyNotFound
	}
	p.mu.Lock()
	item := p.keys[scopedReference{Scope: scope, Reference: reference}]
	if item == nil {
		p.mu.Unlock()
		return Metadata{}, ErrKeyNotFound
	}
	value := cloneMetadata(item.metadata)
	p.mu.Unlock()
	if value.State == StateActive && !p.now().Before(value.ExpiresAt) {
		return p.Transition(ctx, scope, reference, StateActive, StateExpired)
	}
	return value, nil
}

func (p *PQCDevelopmentProvider) PublicKey(ctx context.Context, scope Scope, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validDevelopmentScope(scope) || !validReference(reference) {
		return nil, ErrKeyNotFound
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	item := p.keys[scopedReference{Scope: scope, Reference: reference}]
	if item == nil {
		return nil, ErrKeyNotFound
	}
	return append([]byte(nil), item.publicKey...), nil
}

func (p *PQCDevelopmentProvider) Sign(ctx context.Context, scope Scope, reference string, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(message) == 0 || len(message) > maxSigningInput {
		return nil, ErrInvalidKeySpec
	}
	if !validDevelopmentScope(scope) || !validReference(reference) {
		return nil, ErrKeyNotFound
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	item := p.keys[scopedReference{Scope: scope, Reference: reference}]
	if item == nil {
		return nil, ErrKeyNotFound
	}
	if !validSigningOptions(item.metadata.Algorithm, opts) {
		return nil, ErrInvalidKeySpec
	}
	if item.metadata.State == StateActive && !p.now().Before(item.metadata.ExpiresAt) {
		item.metadata.State = StateExpired
		item.metadata.UpdatedAt = p.now().UTC()
	}
	if item.metadata.Purpose != PurposeSigning || item.private == nil || item.metadata.State != StateActive {
		return nil, ErrKeyUnavailable
	}
	// The lock serializes signing against disable, revoke, expiry, and destroy.
	signature, err := item.private.Sign(rand.Reader, message, opts)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	return signature, nil
}

func (p *PQCDevelopmentProvider) Transition(ctx context.Context, scope Scope, reference string, expected, target State) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if !validDevelopmentScope(scope) || !validReference(reference) {
		return Metadata{}, ErrKeyNotFound
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
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
			if keyID.Scope == scope && keyID.Reference != reference &&
				other.metadata.Purpose == item.metadata.Purpose && other.metadata.State == StateActive {
				other.metadata.State = StateRotationDue
				other.metadata.UpdatedAt = p.now().UTC()
			}
		}
	}
	item.metadata.State = target
	item.metadata.UpdatedAt = p.now().UTC()
	if target == StateDestroyed {
		discardDevelopmentSigner(item.private)
		item.private = nil
	}
	return cloneMetadata(item.metadata), nil
}

func validDevelopmentScope(scope Scope) bool {
	return validScope(scope) && (scope.Environment == "development" || scope.Environment == "test")
}

func discardDevelopmentSigner(private crypto.Signer) {
	if key, ok := private.(ed25519.PrivateKey); ok {
		clear(key)
	}
	// crypto/mldsa intentionally exposes no key-zeroization operation. Dropping
	// the reference prevents further use but does not claim memory erasure.
}
