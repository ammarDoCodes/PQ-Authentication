# Decision 0007: Development-only ML-DSA provider

- Status: implemented for development/interoperability; independent cryptographic review pending
- Date: 2026-09-29
- Scope: internal provider broker; ML-DSA signing only

## Context

FIPS 204 standardizes ML-DSA-44, ML-DSA-65, and ML-DSA-87. Go 1.27.1 provides the maintained standard-library `crypto/mldsa` API. The configured Vault Transit adapter supports Ed25519 only; QuantumGate must not represent Vault as supporting algorithms it does not implement. The existing TLS 1.3 X25519+ML-KEM-768 path is already implemented in `crypto/tls` and is separate from application signing. The current profile registry deliberately has no product-approved pure-PQC identity-signing profile.

The specifications permit software-backed PQC operations for development/interoperability only when that provider is accurately classified and does not become a production default. No external production PQC signer or provider is configured in this environment. Go's standard library test harness refers to an external C2SP Wycheproof module for ML-DSA vectors, but that module is not cached and the configured network proxy is unreachable here.

## Decision

Add `pqc-development`, an explicitly selected ephemeral in-process provider available only in development/test. It supports the existing Ed25519 development use plus FIPS 204 ML-DSA-44/65/87 generation, PKIX public-key retrieval, direct-message signing with the standard ML-DSA context option, verification through the broker, and the existing key lifecycle. Algorithm identifiers are typed and exactly allow-listed. The provider advertises no KEM capability and has no fallback to another algorithm. It shares the broker's tenant/application/environment-scoped opaque references, environment binding, capability checks, per-operation correlated audit, and fail-closed audit behavior.

Configuration and `NewBroker` reject this provider in production. It is marked development-only, non-persistent, and without protected custody or private-material export through the provider interface. Ed25519 transient generation bytes are cleared and stored bytes are cleared at destruction. Go's ML-DSA API exposes no explicit key-zeroization operation; destroying an ML-DSA key makes it unusable and drops the provider reference without claiming memory erasure.

No public API, application-level hybrid construction, signature envelope, or product-approved profile is added. `pqc-approved` continues to fail closed. ML-KEM remains in the existing TLS 1.3 implementation and is not moved into the key-provider broker. Vault Transit remains Ed25519-only.

## Validation and limitations

Repository tests cover all three ML-DSA parameter sets, key/signature size and algorithm binding, context mismatch, signature corruption, malformed/mismatched public material, lifecycle/expiry/concurrency, scope isolation, production rejection, capability downgrade, audit redaction/correlation, and no-classical-fallback behavior. Benchmarks use Go 1.27.1 on Windows/amd64 and report allocation and size data; they are local microbenchmarks, not production capacity evidence.

One-second benchmark samples on Go 1.27.1 `windows/amd64`, Intel Core i5-8265U @ 1.60 GHz:

| Parameter set | Key generation | Sign | Verify | Raw public key | Signature |
|---|---:|---:|---:|---:|---:|
| ML-DSA-44 | 223,614 ns/op; 196,609 B/op; 2 allocs/op | 469,331 ns/op; 2,688 B/op; 1 alloc/op | 133,447 ns/op; 0 B/op; 0 allocs/op | 1,312 B | 2,420 B |
| ML-DSA-65 | 340,907 ns/op; 196,608 B/op; 2 allocs/op | 757,931 ns/op; 3,456 B/op; 1 alloc/op | 208,203 ns/op; 0 B/op; 0 allocs/op | 1,952 B | 3,309 B |
| ML-DSA-87 | 467,690 ns/op; 196,608 B/op; 2 allocs/op | 837,132 ns/op; 4,864 B/op; 1 alloc/op | 335,317 ns/op; 0 B/op; 0 allocs/op | 2,592 B | 4,627 B |

These are local benchmark samples, not service-level latency or capacity guarantees.

`go test crypto/mldsa` was attempted for the Go standard-library Wycheproof suite. It failed because the suite attempted to fetch pinned `github.com/C2SP/wycheproof@v0.0.0-20260625212325-ee7b4f7e6119` from `proxy.golang.org`, and network access was unavailable. Independent-vector interoperability therefore remains **NOT VALIDATED**. No vectors were skipped or weakened, and no crypto dependency was added. No FIPS 140 module validation or product cryptographic approval is claimed.

## Sources

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [Go 1.27 release notes](https://go.dev/doc/go1.27)
- [Go `crypto/mldsa` package](https://pkg.go.dev/crypto/mldsa)
- [C2SP Wycheproof project](https://github.com/C2SP/wycheproof)
