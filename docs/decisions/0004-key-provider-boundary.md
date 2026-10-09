# Decision 0004: Key-provider boundary and initial implementation

- Status: accepted for the internal provider boundary; provider selection is superseded by Decision 0005
- Date: 2026-09-28
- Scope: key generation, signing, key metadata, and lifecycle operations

## Context

The architecture and security specifications require external provider-backed key custody, opaque references, capability checks, health behavior, tenant/environment binding, and audited lifecycle operations. They name KMS/HSM/Vault patterns but do not select a first production product, standard, or maintained adapter library. Existing key-reference API routes only store provider metadata and do not invoke a provider. TLS certificate private keys and the local storage-encryption root key are still loaded into or generated in the service process.

The task requests the smallest safe boundary and a development/test provider when the production choice is unspecified. It prohibits invented cryptography and fake production integrations.

## Decision

Add an internal provider interface addressed by opaque reference and trusted tenant, application, and environment scope. It supports capability and health discovery, generation, metadata, public-key retrieval, signing, and compare-and-set lifecycle transitions. The broker verifies advertised capabilities, validates metadata/public-key/signature results, rejects private-material-export capability, binds operations to one environment, and requires per-operation actor/correlation context and an audit sink. An intent audit must succeed before provider use; completion audit failure withholds the result. Provider implementations must enforce key state and expected lifecycle state atomically.

At the time of this decision, the only implementation was `memory-development`, an ephemeral in-process Ed25519 signing provider for development/test use. It has no persistence, makes no protected-custody claim, and has no private-key export API. Configuration and the broker reject it for production; an empty provider selection never falls back to it. No new cryptographic dependency or algorithm was added. Decision 0005 later selects a narrowly scoped Vault Transit adapter; Decision 0007 later adds a separate development-only ML-DSA provider without changing the product profile registry.

## Consequences

- This record does not validate Vault operations; see Decision 0005 for the documented adapter scope and remaining real-provider validation gate.
- The provider boundary is not connected to the key-reference API, TLS key loading, or local AES-GCM storage-key use.
- Provider-operation audit storage now has both an interface and a tenant-scoped append-only SQL adapter. The Vault adapter wires both intent and completion audit records into runtime operations; real PostgreSQL validation remains pending.
- An external provider operation may have succeeded even if completion-audit persistence fails. The caller receives no result, and the operation needs provider-side reconciliation; the external side effect cannot be atomically rolled back by this interface.
- `memory-development` remains a development-only Ed25519 provider. Decision 0005 selects a Vault Transit Ed25519 adapter, but that adapter is not production-ready and does not satisfy PQC signing or decapsulation requirements. Decision 0007 adds ML-DSA signing only for local development/interoperability; it is not production custody, product approval, or KEM support.
- Before production key operations can be enabled, validate the real provider, its credential identity and least-privilege policy, and the required algorithm profile; integrate it with TLS/storage use cases; and complete database-backed validation.

## Revisit criteria

Review and validate the selected Vault adapter against real provider infrastructure; document and test its identity and least-privilege permissions, algorithms, key custody/export properties, error/timeout semantics, audit and lifecycle guarantees, and disaster recovery. Complete required PQC and TLS/storage integrations before enabling production key-dependent functionality.
