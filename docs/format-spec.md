# Format specification

Status: Release Candidate
Type: Normative
Audience: implementers, auditors, interoperability tool authors, test-vector maintainers
Scope: current-state normative baseline for Quantum Vault artifact formats and verifier behavior
Out of scope: whitepaper rationale, detailed threat analysis, archive-class policy, long-term renewal design
Primary implementation sources: `src/core/crypto/qenc/format.js`, `src/core/crypto/qcont/lifecycle-shard.js`, `src/core/crypto/qcont/restore.js`, `src/core/crypto/lifecycle/artifacts.js`

## Role

This document is the normative home for artifact structure, canonicalization, binding semantics, detached-signature targets, shard layout, and restore behavior.
It is intentionally paired with [`trust-and-policy.md`](trust-and-policy.md):

- `format-spec.md` defines bytes, fields, schemas, attachment points, and restore/verifier flow
- `trust-and-policy.md` defines what signatures, pinning, and policy outcomes mean

## Scope

This document covers the current Quantum Vault artifact family and verifier behavior for:

- `.qenc` encrypted containers
- `QVqcont-7` `.qcont` shards
- archive-state descriptors
- cohort bindings
- `QV-Lifecycle-Bundle` v1
- transition records and source-evidence objects
- detached `.qsig`, `.sig`, `.pqpk`, and `.ots` artifacts accepted by the shipped implementation

This document does not define whitepaper rationale, the full threat model, archive-class policy, or long-term evidence-renewal design.

## Normative status

This document is normative for the currently implemented Quantum Vault format family and verifier behavior.
Use it for compatibility-required statements about bytes, schema fields, canonicalization, binding rules, and fail-closed parser or restore behavior.

Conformance:

- this document is normative for all conforming implementations of the current Quantum Vault format family
- an implementation is conformant to this version if and only if it satisfies all MUST-level requirements defined in the current normative sections of this document
- if an implementation deviates from this specification, it MUST explicitly document the deviation and MUST declare itself non-conformant to this version
- statements explicitly labeled as future or recommended direction are non-normative unless they are promoted into the current sections of this file
- in case of ambiguity, this document MUST be interpreted conservatively and fail-closed

## Sources and references

Internal current-state grounding:

- `src/core/crypto/qenc/format.js`, `src/core/crypto/index.js`, and `src/core/crypto/aead.js` for `.qenc` header layout, authenticated-data boundaries, and decrypt-path behavior
- `src/core/crypto/qcont/lifecycle-shard.js` for `QVqcont-7` shard build, parse, same-state resharing, and lifecycle-bundle rewriting
- `src/core/crypto/qcont/restore.js` for successor restore grouping, explicit disambiguation, and policy-gated restore
- `src/core/crypto/lifecycle/artifacts.js` for archive-state, cohort-binding, lifecycle-bundle, transition-record, source-evidence, and detached-signature target semantics
- `src/core/crypto/auth/qsig.js`, `src/core/crypto/auth/stellar-sig.js`, and `src/core/crypto/auth/opentimestamps.js` for detached authenticity artifact handling
- successor schemas under `docs/schema/` for the grammar layer

External references already used elsewhere in the repository:

- RFC 4648 for Base64 encoding conventions
- RFC 8785 for canonical JSON behavior under `QV-JSON-RFC8785-v1`
- RFC 5116 for AEAD interface discipline: unambiguous AAD construction, prohibition on interpreting ciphertext using unauthenticated fields, and injective encoding requirements for variable-length AAD inputs
- FIPS 202 for `SHA3-256` and `SHA3-512`
- SP 800-185 for KMAC256-based derivation inputs, domain-separation customization strings, and unambiguous composite input encoding
- SP 800-38D for AES-256-GCM AEAD assumptions and IV uniqueness requirements
- FIPS 203 for ML-KEM-1024 naming and profile context

## Current implementation surface

Implemented now:

- one supported shard wire family: `QVqcont-7`
- one supported archive-approval signable object: `quantum-vault-archive-state-descriptor/v1`
- one supported mutable authenticity bundle: `QV-Lifecycle-Bundle` v1
- detached authenticity artifacts accepted by the shipped implementation: `.qsig`, `.sig`, `.pqpk`, and `.ots`
- successor lifecycle artifacts: archive-state descriptor, cohort binding, transition record, source-evidence object, and lifecycle bundle
- strict successor restore grouping by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes
- fail-closed restore when ambiguity remains in `archiveId`, `stateId`, `cohortId`, or embedded lifecycle-bundle digest; explicit operator selection is a warned override, not an automatic winner selection
- explicit detached-signature target families for archive approval, maintenance, source evidence, and OTS evidence

Deferred roadmap:

- state-changing continuity records across future rewrap or reencryption
- renewable evidence records
- broader governance or trust-root layers

## Future work and non-normative notes

Statements explicitly labeled as future or recommended direction are non-normative.
Likely future promotion targets include:

- state-changing continuity records for future rewrap or reencryption
- frozen standalone conformance corpora outside the repository tree
- archive-wide evidence objects and renewal-chain formats

## 1. Status and conformance

The currently supported Quantum Vault artifact family is:

- `.qenc` container magic `QVv1`
- `.qenc` metadata format identifier `QVv1-5-0`
- `.qcont` shard magic `QVC1`
- `.qcont` shard metadata format identifier `QVqcont-7`
- shard metadata `artifactFamily = "successor-lifecycle-v1"`
- archive-state descriptor schema `quantum-vault-archive-state-descriptor/v1`
- cohort binding schema `quantum-vault-cohort-binding/v1`
- transition record schema `quantum-vault-transition-record/v1`
- source-evidence schema `quantum-vault-source-evidence/v1`
- lifecycle bundle type/version `QV-Lifecycle-Bundle` v1

Current conformance rules:

- parsers MUST reject unknown major versions, unknown magic values, unknown schema values, and unsupported canonicalization labels
- parsers MUST reject non-canonical JSON where canonical bytes are required
- parsers MUST reject mismatched archive-state, cohort-binding, lifecycle-bundle, or shard digests
- parsers MUST reject malformed or unresolved attachment references that would make verification unsafe
- parsers MUST NOT infer algorithms, families, or target bytes heuristically from filenames, key lengths, or wrapper type alone

## 2. Notation and conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

Quantum Vault-specific conventions:

- binary Quantum Vault formats use big-endian length and index fields
- text fields are UTF-8
- hex digests are lowercase
- Base64 fields use standard RFC 4648 Base64 with no line breaks
- `SHA3-512(x)` means SHA3-512 over the exact byte sequence `x`
- `stateId` means `SHA3-512(canonical archive-state descriptor bytes)`
- `cohortBindingDigest` means `SHA3-512(canonical cohort-binding bytes)`

Canonicalization conventions:

- `QV-JSON-RFC8785-v1` governs canonical JSON for archive-state descriptors, cohort bindings, transition records, source-evidence objects, and canonicalized `authPolicy` input used by `authPolicyCommitment`
- `QV-BUNDLE-JSON-v1` governs canonical JSON for lifecycle bundles
- JSON Schema files under `docs/schema/` are the grammar layer only; they do not define canonical bytes, derived identifiers, or policy semantics

Specification layers:

| Layer | Governs | Current anchor |
| --- | --- | --- |
| Serialization / canonicalization | Exact bytes, key ordering, primitive encoding, whitespace rules, UTF-8 encoding | `QV-JSON-RFC8785-v1`, `QV-BUNDLE-JSON-v1` |
| Structural grammar | Required fields, value domains, object shapes, closed-object behavior | JSON Schema draft 2020-12 files under `docs/schema/` |
| Semantic rules | What fields mean, what signatures cover, what restore behavior is required | This document, [`trust-and-policy.md`](trust-and-policy.md), [`security-model.md`](security-model.md) |

Conforming parsers MUST enforce all three layers.

## 3. Artifact model

| Artifact | Role in the format family | Relationship to other artifacts |
| --- | --- | --- |
| `.qenc` | Encrypted container | The primary ciphertext object |
| `.qcont` | Threshold shard | Carries one shard's recovery state plus embedded successor lifecycle artifacts |
| Archive-state descriptor JSON | Canonical signable archive-state object | Detached archive-approval target; carried in shards and in the lifecycle bundle |
| Cohort-binding JSON | State-bound shard-cohort description | Carries shard commitments and the digest input used to derive `cohortId` |
| Transition-record JSON | Same-state resharing continuity record | Maintenance target; carried in the lifecycle bundle when present |
| Source-evidence JSON | Digest-first provenance object | Source-evidence-signature target; carried in the lifecycle bundle when present |
| `QV-Lifecycle-Bundle` v1 | Mutable authenticity bundle | Carries archive-state, cohort binding, policy, transitions, source evidence, and attachments; not the archive-approval signable payload |
| `.qsig` | Detached PQ signature | Used for archive approval or other declared lifecycle targets |
| `.sig` | Detached Stellar/Ed25519 signature proof | Used for archive approval or other declared lifecycle targets |
| `.pqpk` | Detached PQ public key | Used for bundled or user-supplied PQ pinning |
| `.ots` | OpenTimestamps evidence | Targets detached signature bytes, not lifecycle-bundle bytes |
| `.qvpack` | Multi-file payload bundle | Pre-encryption binary bundle for multiple files |

Artifact lifecycle summary:

- Encrypt creates a `.qenc` container from a plaintext payload
- Split creates `QVqcont-7` shards and successor lifecycle objects
- Attach updates lifecycle-bundle attachments without mutating canonical archive-state or cohort-binding bytes
- Restore reconstructs one explicitly selected successor archive/state/cohort/bundle context and gates recovery by archive policy
- Decrypt recovers the plaintext payload from `.qenc`

## 4. Archive identity and binding model

Current identity and binding objects are layered:

- `qenc.qencHash` is the primary current-state fixity anchor and is `SHA3-512` over the full `.qenc` bytes
- `qenc.containerId` is a secondary identifier and is currently `SHA3-512(qenc-header-bytes)`
- `archiveId` is the stable archive identifier within one successor archive family
- `stateId` is `SHA3-512` over canonical archive-state descriptor bytes
- `cohortId` is derived from `archiveId`, `stateId`, and `cohortBindingDigest`
- `authPolicyCommitment` binds the canonical archive-state bytes to the concrete `authPolicy` carried by the lifecycle bundle

Current binding invariants:

- detached archive-approval signatures sign canonical archive-state descriptor bytes only
- lifecycle-bundle mutation MUST NOT mutate canonical archive-state or cohort-binding bytes
- maintenance and source-evidence signatures target their declared lifecycle objects only
- the lifecycle-bundle digest is not part of archive-state or cohort identity

### 4.1 Archive-state descriptor

The archive-state descriptor is the current long-lived archive-approval object.

- schema: `quantum-vault-archive-state-descriptor/v1`
- canonicalization: `QV-JSON-RFC8785-v1`
- digest algorithm: `SHA3-512`
- `stateId = archiveStateDigest.value`

The exact top-level member set is:

- `schema`
- `version`
- `stateType`
- `canonicalization`
- `archiveId`
- `parentStateId`
- `cryptoProfileId`
- `kdfTreeId`
- `noncePolicyId`
- `nonceMode`
- `counterBits`
- `maxChunkCount`
- `aadPolicyId`
- `qenc`
- `authPolicyCommitment`

The exact `qenc` member set is:

- `chunkSize`
- `chunkCount`
- `payloadLength`
- `hashAlg`
- `primaryAnchor`
- `qencHash`
- `containerId`
- `containerIdRole`
- `containerIdAlg`

Current archive-state rules:

- `stateId` is derived metadata and MUST NOT appear inside the canonical archive-state bytes used to derive it
- schema validation and semantic validation MUST both reject additional top-level or `qenc` members
- `authPolicyCommitment` binds the canonical archive-state bytes to the concrete `authPolicy` object carried in the lifecycle bundle

### 4.2 Cohort binding

The cohort binding is the state-bound shard-cohort description.

- schema: `quantum-vault-cohort-binding/v1`
- canonicalization: `QV-JSON-RFC8785-v1`
- digest algorithm: `SHA3-512`
- `cohortId = SHA3-256(canonical cohort-id preimage)`

The exact top-level member set is:

- `schema`
- `version`
- `cohortType`
- `canonicalization`
- `archiveId`
- `stateId`
- `sharding`
- `bodyDefinitionId`
- `bodyDefinition`
- `shardBodyHashAlg`
- `shardBodyHashes`
- `shareCommitment`
- `shareCommitments`

Current cohort-binding rules:

- `cohortId` is derived metadata and MUST NOT appear inside the canonical cohort-binding bytes used to derive `cohortBindingDigest`
- `cohortId` is derived from `archiveId`, `stateId`, and `cohortBindingDigest`, not from lifecycle-bundle bytes
- schema validation and semantic validation MUST reject additional top-level members

### 4.3 Lifecycle bundle

`QV-Lifecycle-Bundle` v1 is the mutable authenticity bundle for the current format family.

The exact top-level member set is:

- `type`
- `version`
- `bundleCanonicalization`
- `archiveStateCanonicalization`
- `archiveState`
- `archiveStateDigest`
- `currentCohortBinding`
- `currentCohortBindingDigest`
- `authPolicy`
- `sourceEvidence`
- `transitions`
- `attachments`

The exact `attachments` member set is:

- `publicKeys`
- `archiveApprovalSignatures`
- `maintenanceSignatures`
- `sourceEvidenceSignatures`
- `timestamps`

Current lifecycle-bundle rules:

- all five attachment arrays MUST be present even when empty
- `sourceEvidence` and `transitions` MUST be present even when empty
- `archiveStateDigest` MUST equal `SHA3-512` over the canonical embedded archive-state bytes
- `currentCohortBindingDigest` MUST equal `SHA3-512` over the canonical embedded cohort-binding bytes
- lifecycle-bundle mutation MUST NOT mutate canonical archive-state or cohort-binding bytes

### 4.4 Detached-signature target mappings

Current detached-signature target mappings are:

| Signature family | Target object | Required `targetType` | Counting role |
| --- | --- | --- | --- |
| archive approval | archive-state descriptor | `archive-state` | counts toward archive policy |
| maintenance | transition record | `transition-record` | reported separately; does not count toward archive policy |
| source evidence | source-evidence object | `source-evidence` | reported separately; does not count toward archive policy |

Current target rules:

- detached archive-approval signatures MUST target canonical archive-state descriptor bytes
- maintenance signatures MUST target canonical transition-record bytes
- source-evidence signatures MUST target canonical source-evidence bytes
- timestamps MUST target detached signature bytes by `SHA-256(detachedSignatureBytes)`; SHA-256 is used here as an interoperability requirement of the OpenTimestamps proof format (which defines its stamp operation over SHA-256 digests), not as an independent QV hash-function choice; SHA-3 variants are not currently defined in the OpenTimestamps proof header format
- mutable lifecycle-bundle bytes are never the archive-approval signable payload

This separation is one of the current format family's core invariants. Archive-approval signatures remain stable when lifecycle bundles are rewritten, while timestamp evidence attaches to one detached proof artifact rather than to a bundle that may legitimately change over time.

## 5. `.qenc` container format

### 5.1 Binary layout

| Data | Length | Description |
| --- | --- | --- |
| MAGIC | 4 bytes | ASCII `QVv1` |
| keyLen | 4 bytes (Uint32 BE) | length of `encapsulatedKey` |
| encapsulatedKey | keyLen bytes | ML-KEM ciphertext |
| containerNonce | 12 bytes | container nonce / IV root |
| kdfSalt | 16 bytes | random salt for KMAC |
| metaLen | 2 bytes (Uint16 BE) | length of `metaJSON` |
| metaJSON | metaLen bytes UTF-8 | metadata |
| keyCommitment | 32 bytes | required `SHA3-256(Kenc)` |
| ciphertext | remaining bytes | AES-GCM ciphertext stream |

### 5.2 Current metadata contract

| Field | Current emitted value or shape | Current acceptance note |
| --- | --- | --- |
| `KEM` | `ML-KEM-1024` | descriptive algorithm label |
| `KDF` | `KMAC256` | descriptive algorithm label |
| `AEAD` | `AES-256-GCM` | descriptive algorithm label |
| `fmt` | `QVv1-5-0` | MUST match the supported container metadata format |
| `cryptoProfileId` | `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2` | required by current validation |
| `kdfTreeId` | `QV-KDF-TREE-v2` | required by current validation |
| `aead_mode` | `single-container-aead` or `per-chunk-aead` | MUST be one of the supported current AEAD modes |
| `iv_strategy` | `random96` or `kmac-prefix64-ctr32-v3` | MUST match `aead_mode` |
| `noncePolicyId` | `QV-GCM-RAND96-v1` or `QV-GCM-KMACPFX64-CTR32-v3` | MUST match `aead_mode` |
| `nonceMode` | `random96` or `kmac-prefix64-ctr32` | MUST match `aead_mode` |
| `counterBits` | `0` or `32` | MUST match `aead_mode` |
| `maxChunkCount` | `1` or `4294967295` | MUST match `aead_mode` |
| `aadPolicyId` | `QV-AAD-HEADER-CHUNK-v1` | required by current validation |
| `hasKeyCommitment` | `true` | current containers require a key commitment |
| `payloadFormat` | `wrapped-v1` | current payload wrapper |
| `payloadLength` | positive integer | cleartext payload length |
| `chunkSize` | positive integer | runtime chunk size |
| `chunkCount` | positive integer | validated against the nonce policy |
| `domainStrings.kdf` | `quantum-vault:kdf:v2` | required by current validation |
| `domainStrings.iv` | `quantum-vault:chunk-iv:v2` | required by current validation |
| `domainStrings.kenc` | `quantum-vault:kenc:v2` | required by current validation |
| `domainStrings.kiv` | `quantum-vault:kiv:v2` | required by current validation |

### 5.3 Payload and private metadata

Current private payload metadata for `wrapped-v1` contains:

- `originalFilename`
- `timestamp`
- `fileHash`
- `originalLength`

Current `wrapped-v1` payload format is:

```text
[uint32be privateMetaLen][privateMetaJSON][fileBytes]
```

When multiple files are archived, the payload bytes are a `.qvpack` bundle detected by magic `QVB1`, not by filename.

### 5.4 AEAD, KDF, and key commitment rules

Current AEAD and KDF rules:

- single-container AAD is the entire header from magic through `keyCommitment`
- per-chunk AAD is `header || uint32_be(chunkIndex) || uint32_be(plainLen_i)`
- AES-GCM nonce size is 96 bits
- key commitment is mandatory and is verified before decryption
- `Kraw`, `Kenc`, and `Kiv` are derived via KMAC256 with explicit domain strings
- per-chunk IV derivation uses `prefix64 || uint32_be(chunkIndex)` where `prefix64` is derived from `Kiv` and `containerNonce`

Current implementation note:

- the `Kraw` input is exactly the byte string `kdfSalt || metaJSON`
- this is unambiguous in the current format because `kdfSalt` is fixed at 16 bytes and `metaJSON` is already length-delimited in the `.qenc` header
- the current format does not define a separately serialized SP 800-185 tuple encoding inside the KMAC message

### 5.5 Current decrypt/verify order

Current decrypt/verify order is:

1. parse header
2. validate metadata, profile, and nonce-policy fields
3. decapsulate with the ML-KEM private key
4. derive `Kenc` and `Kiv`
5. verify `keyCommitment`
6. decrypt with AES-GCM using the required AAD
7. unpack `wrapped-v1`
8. optionally compare `privateMeta.fileHash` with a fresh `SHA3-512` over recovered file bytes

## 6. `.qcont` shard format

Quantum Vault supports one `.qcont` layout distinguished by `metaJSON.alg.fmt = "QVqcont-7"` and `metaJSON.artifactFamily = "successor-lifecycle-v1"`.

Parsers MUST use the format identifier and embedded lengths to interpret the byte stream and MUST reject any shard that does not match this layout.

### 6.1 Successor lifecycle shard layout (`QVqcont-7`)

Successor shards use `QVC1` magic and a UTF-8 `metaJSON` prefix.
After `metaJSON`, the byte stream embeds three canonical JSON artifacts with fixed-length digest anchors:

| Data | Length | Description |
| --- | --- | --- |
| `archiveStateLen` | 4 bytes (Uint32 BE) | length of embedded archive-state JSON bytes |
| `archiveStateBytes` | `archiveStateLen` bytes | canonical `quantum-vault-archive-state-descriptor/v1` bytes |
| `archiveStateDigest` | 64 bytes | `SHA3-512(archiveStateBytes)` |
| `cohortBindingLen` | 4 bytes (Uint32 BE) | length of embedded cohort-binding JSON bytes |
| `cohortBindingBytes` | `cohortBindingLen` bytes | canonical `quantum-vault-cohort-binding/v1` bytes |
| `cohortBindingDigest` | 64 bytes | `SHA3-512(cohortBindingBytes)` |
| `lifecycleBundleLen` | 4 bytes (Uint32 BE) | length of embedded lifecycle-bundle JSON bytes |
| `lifecycleBundleBytes` | `lifecycleBundleLen` bytes | canonical `QV-Lifecycle-Bundle` v1 bytes |
| `lifecycleBundleDigest` | 64 bytes | `SHA3-512(lifecycleBundleBytes)` |
| `encapBlobLen` | 4 bytes (Uint32 BE) | length of encapsulated key blob |
| `encapBlob` | `encapBlobLen` bytes | ML-KEM ciphertext |
| `containerNonce` | 12 bytes | copied from `.qenc` |
| `kdfSalt` | 16 bytes | copied from `.qenc` |
| `qencMetaLen` | 2 bytes (Uint16 BE) | length of duplicated `.qenc` metadata |
| `qencMetaBytes` | `qencMetaLen` bytes UTF-8 | duplicated `.qenc` metadata |
| `keyCommitLen` | 1 byte | key commitment length |
| `keyCommitBytes` | `keyCommitLen` bytes | required `SHA3-256(Kenc)` |
| `shardIndex` | 2 bytes (Uint16 BE) | 0-based shard index |
| `shareLen` | 2 bytes (Uint16 BE) | length of Shamir share |
| `shareBytes` | `shareLen` bytes | one Shamir share |
| `fragments stream` | variable | RS fragment stream encoded as repeated `[len32 | fragmentBytes]` |

### 6.2 Successor shard metadata contract

Current shard metadata fields are:

| Field | Current meaning |
| --- | --- |
| `artifactFamily` | MUST be `successor-lifecycle-v1` |
| `archiveId` | summary copy of the embedded archive-state identifier |
| `stateId` | summary copy of `SHA3-512(archiveStateBytes)` |
| `cohortId` | summary copy of the derived cohort identifier |
| `alg.KEM` | `ML-KEM-1024` |
| `alg.KDF` | `KMAC256` |
| `alg.AEAD` | `AES-256-GCM` |
| `alg.RS` | `ErasureCodes` |
| `alg.fmt` | `QVqcont-7` |
| `cryptoProfileId` | current crypto profile identifier |
| `noncePolicyId` / `nonceMode` / `counterBits` / `maxChunkCount` | summary copy of the selected nonce contract |
| `aadPolicyId` | summary copy of the current AAD policy |
| `n` / `k` / `m` / `t` | shard-count, RS, and Shamir parameters |
| `rsEncodeBase` | current Reed-Solomon encode-base constant |
| `chunkSize` / `chunkCount` | summary copy of the `.qenc` chunk geometry |
| `containerId` / `containerHash` | summary copy of the `.qenc` binding anchors |
| `encapBlobHash` | digest of the encapsulated ML-KEM ciphertext |
| `privateKeyHash` | digest of the ML-KEM private key bytes |
| `payloadLength` / `originalLength` / `ciphertextLength` | payload summary values |
| `domainStrings` | summary copy of the `.qenc` KMAC domain strings |
| `fragmentFormat` | current fragment-stream encoding |
| `perFragmentSize` | per-shard fragment size |
| `hasKeyCommitment` | MUST be `true` |
| `keyCommitmentHex` | summary copy of the required key commitment |
| `shardIndex` | current shard index |

Current shard metadata rules:

- `archiveId`, `stateId`, and `cohortId` MUST match the embedded archive-state and cohort-binding objects
- `keyCommitmentHex` MUST match the embedded key-commitment bytes
- `stateId` and `cohortId` are summary copies; the canonical sources of truth are the embedded archive-state and cohort-binding bytes and their derived digests

### 6.3 Embedded artifact invariants

Successor shard invariants:

- every supported `.qcont` shard embeds canonical archive-state bytes, canonical cohort-binding bytes, and canonical lifecycle-bundle bytes
- `archiveStateDigest` MUST equal `SHA3-512(archiveStateBytes)`
- `cohortBindingDigest` MUST equal `SHA3-512(cohortBindingBytes)`
- `lifecycleBundleDigest` MUST equal `SHA3-512(lifecycleBundleBytes)`
- the embedded lifecycle bundle's `archiveStateDigest` MUST match the embedded archive-state bytes
- the embedded lifecycle bundle's `currentCohortBindingDigest` MUST match the embedded cohort-binding bytes
- exact archive-state and cohort-binding byte equality is part of cohort consistency during restore

Important current distinction:

- multiple embedded lifecycle-bundle digests MAY appear across one otherwise consistent archive/state/cohort set
- that condition does not create a new `cohortId`
- restore MUST treat it as lifecycle-bundle ambiguity and require explicit operator selection

### 6.4 Split and same-state resharing semantics

Current split behavior:

- parse the `.qenc` header
- split the ML-KEM private key with Shamir secret sharing
- split ciphertext with Reed-Solomon erasure coding
- compute threshold `t = k + (n-k)/2`
- derive archive-state, cohort-binding, and lifecycle-bundle objects
- embed the three canonical lifecycle objects into each shard

Current same-state resharing behavior:

- reconstruct one predecessor archive/state/cohort set
- preserve exact archive-state descriptor bytes
- emit a new cohort binding and derived `cohortId`
- emit a required transition record
- update the lifecycle bundle without mutating preserved archive-state bytes

Same-state resharing is maintenance, not archive re-approval.

## 7. External authenticity artifacts accepted by Quantum Vault

Current accepted external authenticity artifacts are:

| Artifact | Current acceptance rule |
| --- | --- |
| `.qsig` | Quantum Signer detached signature, major version 2, context `quantum-signer/v2` |
| `.sig` | Stellar detached signature JSON with schema `stellar-signature/v2` |
| `.pqpk` | Detached PQ public key used for bundled or user-supplied pinning |
| `.ots` | OpenTimestamps proof linked to detached signature bytes |

Current acceptance boundaries:

- `.qsig` and `.sig` are integration contracts; this specification does not restate their full upstream format definitions
- external signatures used at restore are archive-approval signatures over canonical archive-state bytes
- bundled lifecycle signatures may target archive-state, transition-record, or source-evidence bytes according to their declared family
- `.pqpk` material may be used for bundled or user-supplied PQ pinning
- `.ots` timestamps target detached signature bytes, not lifecycle-bundle bytes
- OTS acceptance and linkage do not require `apparentlyComplete` / `completeProof` to be true; those fields are reporting outputs, not acceptance preconditions

Detailed linkage, pinning, and ambiguity rules are defined in [appendices/external-artifacts.md](appendices/external-artifacts.md).

## 8. Verification and restore algorithm

The implementation follows one restore path: successor lifecycle restore for `QVqcont-7`.

Verifier and restore order:

1. parse artifacts and classify shard, archive-state, lifecycle-bundle, signature, key, and timestamp inputs
2. parse every shard using the strict `QVqcont-7` layout
3. reject any non-successor parsed shard input
4. group successor shard candidates by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes
5. apply any explicit selection filters from uploaded archive-state bytes, uploaded lifecycle-bundle bytes, selected `archiveId`, selected `stateId`, selected `cohortId`, or explicit embedded lifecycle-bundle digest
6. fail closed if same-state forks or multi-cohort ambiguity remain after explicit filtering
7. fail closed if the selected cohort still carries multiple embedded lifecycle-bundle digests and no explicit lifecycle bundle or selected digest was supplied
8. reconstruct `.qenc` and the ML-KEM private key from one internally consistent successor cohort
9. verify that the selected lifecycle bundle matches the selected archive-state and cohort-binding objects
10. verify detached signatures against the exact canonical target bytes for their declared family
11. ignore self-verified PQ signatures for trust and policy counting when they verified only via the key embedded inside the `.qsig` itself and no bundled or user-supplied pin verified; the embedded signer public key inside a `.qsig` is a convenience field, not by itself an externally anchored identity, so a proof that verifies only against its own embedded key must not count toward policy; full counting semantics and rationale are defined in [`trust-and-policy.md#64-counting-rules`](trust-and-policy.md#64-counting-rules)
12. evaluate archive policy using `archiveApprovalSignatures` only
13. link timestamps to detached signature bytes and emit separate transition and source-evidence reports
14. emit distinct status fields including `archiveApprovalSignatureVerified`, `maintenanceSignatureVerified`, `sourceEvidenceSignatureVerified`, `otsEvidenceLinked`, `signerPinned`, `bundlePinned`, and `userPinned`

Restore selection rules:

- if an uploaded lifecycle bundle is supplied, it MUST match exactly one candidate archive/state/cohort set
- if an uploaded archive-state descriptor is supplied, it narrows candidate states by exact canonical bytes; it does not authorize heuristic cohort selection
- if multiple candidate cohorts remain after explicit archive/state filtering, restore MUST require explicit cohort selection or a matching lifecycle bundle
- if exactly one archive/state/cohort candidate remains and it carries multiple embedded lifecycle-bundle digests, restore MUST require uploaded lifecycle-bundle bytes or an explicit embedded-bundle digest
- if the operator explicitly selects one cohort or one lifecycle-bundle variant in an otherwise ambiguous case, restore MAY proceed, but it MUST warn rather than pretend the ambiguity was resolved automatically
- restore MUST block if archive policy is not satisfied

## 9. Error handling and fail-closed behavior

Quantum Vault MUST fail closed on:

- unknown major versions
- unknown magic or schema values
- unsupported canonicalization labels
- non-canonical archive-state, cohort-binding, transition-record, source-evidence, or lifecycle-bundle bytes
- derived-field violations such as `stateId` inside archive-state bytes or `cohortId` inside cohort-binding bytes
- mismatched archive-state, cohort-binding, or lifecycle-bundle digests
- archive-state/cohort-binding identifier mismatches inside a shard
- detached-signature target mismatch
- malformed signature or key references that prevent safe verification
- unsupported algorithm IDs
- inconsistent shard cohorts
- exact archive-state or cohort-binding byte mismatch inside a selected cohort
- ambiguous same-state forks when no explicit cohort or lifecycle-bundle selection is supplied
- multiple embedded lifecycle-bundle digests inside a selected cohort when no explicit bundle bytes or digest are supplied
- multiple matching user-supplied PQ pin files for one detached PQ signature
- unrelated or ambiguously linked OTS evidence

Current non-rejection note for explicit successor disambiguation:

- when the operator explicitly selects a successor cohort or lifecycle bundle for an otherwise ambiguous same-state fork or multi-bundle cohort, restore may proceed, but Quantum Vault MUST warn rather than pretend that the ambiguity was resolved automatically

## 10. Compatibility and version policy

Changes to the Quantum Vault format family fall into three categories depending on which specification layer they affect:

| Kind of change | Requires | Examples |
| --- | --- | --- |
| Change to canonical byte output for the same logical input | new canonicalization label | changing key-ordering rules, number serialization, whitespace behavior |
| Change to required fields, value domains, or object shapes | new schema/version identifier | adding a required archive-state field, changing a `const` identifier, widening or narrowing a type constraint |
| Change to what fields mean, what operations are permitted, or what verification outcomes are required | semantic documentation update; may also require a new schema/version if structure changes too | changing the meaning of `authPolicyCommitment`, redefining restore-gating behavior |

Current version-boundary rules:

- changing canonical JSON byte rules for archive-state, cohort-binding, transition-record, source-evidence, or `authPolicyCommitment` input requires a new canonicalization label and a new schema/version for the affected artifact type
- changing lifecycle-bundle canonical byte rules requires a new bundle canonicalization label and a new lifecycle-bundle version
- adding new top-level fields to archive-state, cohort-binding, transition-record, or source-evidence requires a new schema/version
- adding new lifecycle-bundle attachment families or new lifecycle-bundle top-level members requires a new lifecycle-bundle version
- adding a new shard wire layout requires a new shard-format identifier
- unknown fields in the current artifact grammars are forbidden at every object level
- future extensibility, if needed, MUST use an explicit versioned mechanism rather than silently opening current objects

## 11. Future coverage retained for this document

This document carries the current normative baseline, but it still needs future expansion in the following areas:

- state-changing continuity records that preserve archive identity semantics across future rewrap or reencryption
- archive-wide renewable evidence objects and renewal-chain formats
- a frozen standalone conformance corpus with stable case identifiers outside the repository tree
- future wire representation of broader governance or trust-root material, if those become first-class format artifacts
