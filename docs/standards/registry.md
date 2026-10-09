# Standards and implementation registry

Review date: 2026-09-29
Status: implementation inventory; crypto/provider review and certification are not complete

| Area | Standard/profile | Implementation | Status / limitation |
|---|---|---|---|
| Runtime | Go 1.27.1 | Go toolchain | Required toolchain; update only after compatibility and security review. |
| Transport | TLS 1.3, RFC 8446 | Go crypto/tls | Production listener enforces TLS 1.3. |
| Hybrid key exchange | X25519MLKEM768 | Go crypto/tls | Supported by the Go TLS stack; the service rejects requests whose negotiated group is not X25519MLKEM768 when hybrid mode is required. No application-level combiner is implemented. |
| Policy profile registry v1 | `tls13-classical`, `tls13-x25519-mlkem768` | Read-only registry, simulator, and inline gateway policy evaluator in `internal/httpapi/policies.go` | Both profiles remain `simulation-only`; non-observe gateway enforcement fails closed pending independent review. The pure-PQC profile is deliberately absent. |
| OIDC admin authentication | OpenID Connect Core; OAuth 2.0 Security BCP | github.com/coreos/go-oidc/v3 v3.20.0; golang.org/x/oauth2 v0.37.0 | Authorization-code flow with server-bound state, nonce, PKCE S256, issuer/audience/signature/ACR/auth-time validation, restricted egress, hashed opaque sessions, CSRF, and append-only auth audit. Service-client credentials and independent security review remain outstanding. |
| Development-only reference signing | Ed25519, RFC 8032 | Go `crypto/ed25519` via `internal/keyprovider` | Unit/development provider only. Private keys are ephemeral and process-resident; this is not a production profile, approved provider, or custody claim. |
| Vault-backed reference signing | Ed25519, RFC 8032 | HashiCorp Vault Transit HTTP API via `internal/keyprovider` | Non-exportable classical subset only. Fake HTTP tests pass; no real Vault version, ACL, audit-device, or custody operation has been validated. Not production-ready. |
| Outbound webhook signatures | Ed25519, RFC 8032 | `internal/webhook` signs exact versioned JSON bytes through the internal key-provider broker | Classical signatures only, not post-quantum. Vault Transit is the production-oriented provider when explicitly configured; the real provider and database outbox have not been exercised in this environment. |
| PostgreSQL driver | PostgreSQL 14+ | github.com/jackc/pgx/v5 v5.11.0 | Pinned direct dependency; dependency tree and advisories must be reviewed before release. |
| PQC signatures | FIPS 204 ML-DSA-44 | Go 1.27.1 `crypto/mldsa` via `pqc-development` | Development/test only; ephemeral software key, no protected custody, production selection rejected, no product profile approval, no FIPS-module validation claim. Raw public key 1,312 bytes; signature 2,420 bytes. Independent-vector interoperability is `NOT VALIDATED`. |
| PQC signatures | FIPS 204 ML-DSA-65 | Go 1.27.1 `crypto/mldsa` via `pqc-development` | Development/test only; ephemeral software key, no protected custody, production selection rejected, no product profile approval, no FIPS-module validation claim. Raw public key 1,952 bytes; signature 3,309 bytes. Independent-vector interoperability is `NOT VALIDATED`. |
| PQC signatures | FIPS 204 ML-DSA-87 | Go 1.27.1 `crypto/mldsa` via `pqc-development` | Development/test only; ephemeral software key, no protected custody, production selection rejected, no product profile approval, no FIPS-module validation claim. Raw public key 2,592 bytes; signature 4,627 bytes. Independent-vector interoperability is `NOT VALIDATED`. |
| PQC-only protocol | No selected profile | None | Unsupported; `pqc-approved` configuration fails closed. |
| Other profiles | FIPS 205 SLH-DSA; application-level hybrid signatures | None | Unsupported until an approved provider/profile is selected and reviewed. |

## Source references

- [Go 1.27 release notes](https://go.dev/doc/go1.27)
- [Go `crypto/mldsa` package](https://pkg.go.dev/crypto/mldsa)
- [Go TLS source](https://go.dev/src/crypto/tls/common.go)
- [Go release history](https://go.dev/doc/devel/release)
- [pgx release history](https://github.com/jackc/pgx/blob/master/CHANGELOG.md)
- [go-oidc releases](https://github.com/coreos/go-oidc/releases)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [C2SP Wycheproof test vectors](https://github.com/C2SP/wycheproof/tree/main/testvectors_v1) (the Go standard-library ML-DSA vector suite could not be executed locally because its pinned module download was blocked)
- [HashiCorp Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- [HashiCorp Vault Transit documentation](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [HashiCorp Vault audit best practices](https://developer.hashicorp.com/vault/docs/audit/best-practices)
- [HashiCorp Vault Agent auto-auth](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth)
- [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [Edwards-Curve Digital Signature Algorithm (EdDSA), RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)
