# Decision 0005: Vault Transit provider subset

- Status: accepted for an internal classical signing adapter; not production-ready
- Date: 2026-09-28
- Scope: QuantumGate internal key-provider boundary, Ed25519 signing only

## Context

The internal provider boundary needs an externally controlled key custody implementation without coupling QuantumGate to one cloud. Current Vault Transit documentation establishes a documented non-exportable Ed25519 path in Community Edition. It also documents ML-DSA, SLH-DSA, and hybrid signing key types as Enterprise features. The adapter is intentionally limited to the existing QuantumGate `Ed25519` capability and does not attempt those additional types.

## Verified capability matrix

| Capability | Current Vault Transit documentation | QuantumGate adapter |
|---|---|---|
| Ed25519 key generation | Documented Transit key type | Implemented as a non-derived key with export and plaintext backup disabled |
| Private-key custody | Transit signing works without returning private bytes; private-key export is a separate operation | `exportable=false`, `allow_plaintext_backup=false`; response flags are checked; no private export method exists |
| Signing | `transit/sign/:name` accepts base64 input and returns a `vault:v<version>:<base64>` signature | Sends exact Ed25519 message bytes as base64; pins Vault version 1; checks the documented Vault signature envelope and returns the raw Ed25519 signature bytes expected by the existing broker |
| Public key | Reading an asymmetric key returns standard public-key material with key version data | Reads the key, checks non-exportability, decodes the Ed25519 public value, and returns PKIX DER to the broker |
| Versions and rotation | Transit has key versions and a rotate endpoint | Each QuantumGate version receives its own generated Transit key name and opaque reference. QuantumGate's lifecycle marks old keys rotation-due; the adapter does not call Transit rotate |
| Disable, revoke, expire | Transit `min_encryption_version` controls whether a key version can sign; key state is not otherwise a native Transit lifecycle enum | A floor of 2 blocks version 1 signing; QuantumGate's database records the distinct lifecycle state and the broker checks it on each use |
| Destruction | Transit key deletion requires `deletion_allowed=true` | Not supported or advertised. The adapter leaves deletion disabled and has no destroy operation |
| Community PQC | Current key-type list documents Ed25519, ECDSA, RSA, and other classical/symmetric types | Not implemented beyond Ed25519 |
| Enterprise PQC | Current docs list ML-DSA, SLH-DSA, and hybrid signatures as Enterprise key types | Not implemented or advertised |
| ML-KEM | No Transit ML-KEM key type appears in the current documented key-type list | Unsupported; no KEM or decapsulation API is exposed |
| Machine authentication | Vault Agent auto-auth supports workload and platform authentication methods, renews tokens, and writes tokens to configured sinks | The adapter rereads a token from an operator-configured file. Production must provision this sink from Vault Agent auto-auth with workload identity or another reviewed short-lived machine identity. The adapter implements no login protocol |
| Namespaces and tenancy | Vault namespaces are an optional deployment boundary; Transit key paths are supplied by the caller | Namespace is operator configuration. Key paths are assembled from validated server scope, fixed purpose, and a server-generated random reference; clients cannot send Vault paths |
| Health | `/sys/health` reports initialization, seal, and active/standby state; authenticated API calls require a Vault token | Readiness requires an initialized, unsealed active server plus authenticated read access to the configured Transit key config. It does not prove individual operation ACLs or key existence |
| Audit | Vault audit devices HMAC sensitive request data by default; raw logging and mount-level non-HMAC settings can change this | QuantumGate audit writes correlated intent/completion records without payloads. Deployment must leave audit raw logging disabled and keep Transit `input` HMAC-protected. This external Vault configuration is not checked by the adapter |

## Decision

Implement `vault-transit` as a production-oriented adapter for non-exportable Ed25519 signing only. Keep the generic provider interface, and keep PQC algorithms unavailable until a specific provider/library profile is implemented, reviewed, and validated. Use the standard Vault HTTP API without a new dependency. Require HTTPS and certificate verification in production; permit plaintext Vault HTTP only to loopback in development/test. Use a token file populated outside QuantumGate, never a static token configuration value.

Persist QuantumGate metadata in the existing tenant-scoped `key_references` table. The SQL runtime role remains the existing restricted, non-owner role and uses transaction-local tenant context under RLS. The database row lock spans the provider operation to serialize sign against lifecycle transitions across service replicas. Transit's minimum signing version makes disabled references fail closed at the provider. The Vault API call and SQL transaction cannot commit atomically; if the provider update succeeds and SQL or completion-audit commit fails, withhold results and reconcile the reference before reuse.

Provider audit events are written through the existing append-only `audit_events` table. Intent audit failure blocks provider calls. Completion audit failure withholds the caller's signature or metadata. Events contain actor, correlation ID, operation, outcome, reason, and a hash of the provider reference only.

## Provider-side policy expectations

The QuantumGate token should be restricted to the configured Transit mount and the adapter's key prefix. It needs key creation, key reads, key config updates, Ed25519 signing, and Transit key-config read for health. `/sys/health` is a system health endpoint and does not require a token policy grant. The token must not receive Transit import, export, delete, mount management, policy management, audit management, or root capabilities. Exact ACL policy behavior must be validated against the deployed Vault version before production use.

The token file should be written by a Vault Agent file sink configured with an appropriate machine authentication method, preferably a platform/workload identity where available. Do not use Vault Agent's `token_file` auto-auth method in production; that method is intended for development. Restrict token file permissions and storage, and rotate/revoke the identity through the platform's normal process.

## Validation and limitations

Fake HTTP tests validate request shape, path scoping, lifecycle gates, public-key extraction, Ed25519 signing, malformed/denied responses, TLS verification, and concurrent stale transitions. They do not validate real Vault behavior, ACL policy, audit-device redaction, token renewal, Enterprise capabilities, HSM custody, or operational recovery. PostgreSQL tests validate RLS metadata and audit behavior only when `TEST_DATABASE_URL` and `TEST_RUNTIME_DATABASE_URL` are configured.

This adapter is not production-ready. It is not wired to public key-reference routes, `TLS_KEY_FILE`, or local storage-encryption key use. It does not provide ML-KEM, ML-DSA, SLH-DSA, hybrid signing, import, or destruction. It does not validate the server's audit-device HMAC configuration. Those requirements remain open.

## Authoritative documentation reviewed

- [Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- [Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Vault audit best practices](https://developer.hashicorp.com/vault/docs/audit/best-practices)
- [Vault audit log schema](https://developer.hashicorp.com/vault/docs/audit/schema)
- [Vault Agent auto-auth](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth)
- [Vault Agent file sink](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth/sinks/file)
- [Kubernetes auth](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
- [AppRole authentication best practices](https://developer.hashicorp.com/vault/docs/auth/approle/approle-pattern)
