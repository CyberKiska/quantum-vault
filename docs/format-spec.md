# Format specification

Status: Release Candidate
Type: Normative
Audience: implementers, auditors, interoperability tool authors, test-vector maintainers
Scope: current-state normative baseline for Quantum Vault artifact formats and verifier behavior
Out of scope: whitepaper rationale, detailed threat analysis, archive-class policy, long-term renewal design
Primary implementation sources: implementation code, `docs/series/SERIES-STANDARTS.md`
Historical consolidation source: `process/IMPLEMENTATION-NOTES.md`

## Role

This document is the normative home for artifact structure, canonicalization, binding semantics, and verifier behavior.
It consolidates the currently implemented format rules that were previously split across `README.md` and the former spec-oriented version of `process/IMPLEMENTATION-NOTES.md`.

It is intentionally paired with `trust-and-policy.md`:

- `format-spec.md` defines bytes, fields, schemas, attachment points, and restore/verifier flow for **both** legacy and successor artifacts
- `trust-and-policy.md` defines what signatures, pinning, and policy outcomes mean for **both** tracks

## Scope

This document covers the current Quantum Vault artifact family and verifier behavior for `.qenc`, `.qcont`, and the detached authenticity artifacts the implementation currently accepts.

Quantum Vault now uses the **successor lifecycle track** as its primary format baseline:

- **Successor lifecycle track:** archive-state descriptor (`quantum-vault-archive-state-descriptor/v1`), cohort binding (`quantum-vault-cohort-binding/v1`), `QV-Lifecycle-Bundle` v1, transition and source-evidence artifacts as applicable, and **QVqcont-7** shards that embed lifecycle objects (see Section 8).
- **Deprecated v1 track:** canonical manifest (`quantum-vault-archive-manifest/v3`), mutable `QV-Manifest-Bundle` v2, and **QVqcont-6** shards that embed manifest and bundle bytes.

The shipped Lite and Pro build/export surface now emits successor artifacts by default. Beginning with release **v1.5.3**, v1 manifest/bundle creation is no longer part of the normal regular-user creation path. The v1 track remains implemented only to interpret previously created material during the documented phase-out window.

JSON Schema files under `docs/schema/` are the **grammar layer** for each artifact shape; they do not define canonical bytes, derived identifiers, or policy semantics (see Section 2).

It does not define whitepaper rationale, full threat-model analysis, archive-class policy, or long-term evidence-renewal design.

## Normative status

This document is normative for the currently implemented Quantum Vault artifact family and verifier behavior.
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
- `src/core/crypto/qcont/build.js`, `src/core/crypto/qcont/attach.js`, `src/core/crypto/qcont/lifecycle-attach.js`, `src/core/crypto/qcont/lifecycle-shard.js`, and `src/core/crypto/qcont/restore.js` for shard layout, bundle attachment, lifecycle attach, and restore candidate selection (legacy and successor)
- `src/core/crypto/manifest/archive-manifest.js`, `src/core/crypto/manifest/manifest-bundle.js`, and `src/core/crypto/manifest/jcs.js` for manifest, bundle, and canonicalization behavior
- `src/core/crypto/lifecycle/artifacts.js` for successor lifecycle canonicalization, digests, and bundle semantics
- `docs/schema/qv-common-types.schema.json`, `docs/schema/qv-manifest-v3.schema.json`, `docs/schema/qv-manifest-bundle-v2.schema.json`, and successor schemas (`qv-archive-state-descriptor-v1`, `qv-cohort-binding-v1`, `qv-lifecycle-bundle-v1`, `qv-transition-record-v1`, `qv-source-evidence-v1`) for machine-readable grammar layers
- `src/core/crypto/auth/verify-signatures.js`, `src/core/crypto/auth/qsig.js`, `src/core/crypto/auth/stellar-sig.js`, and `src/core/crypto/auth/opentimestamps.js` for detached attachment handling relevant to format acceptance
- `docs/glossary.md`, `docs/trust-and-policy.md`, and `docs/security-model.md` for shared terminology and cross-document semantic constraints

External references already used elsewhere in the repository:

- RFC 4648 for Base64 encoding conventions
- RFC 8785 for canonical signable-manifest byte rules under `QV-JSON-RFC8785-v1`
- FIPS 202 for `SHA3-256` and `SHA3-512`
- SP 800-185 for KMAC256-based derivation inputs and commitment-related terminology
- SP 800-38D for AES-GCM AEAD assumptions
- FIPS 203 for ML-KEM-1024 naming and profile context

## Current implementation status

Implemented now:

- the supported versions, schema IDs, and artifact boundaries listed in Section 1
- regular-user build/export defaults to **QVqcont-7** successor shards plus successor archive-state, cohort-binding, and lifecycle-bundle artifacts; new legacy manifest/bundle creation is retired from the normal product path
- successor lifecycle artifacts: `quantum-vault-archive-state-descriptor/v1`, `quantum-vault-cohort-binding/v1`, `quantum-vault-transition-record/v1`, `quantum-vault-source-evidence/v1`, and `QV-Lifecycle-Bundle` v1 with closed attachment arrays
- **QVqcont-7** successor `.qcont` shards embedding archive-state, cohort-binding, and lifecycle-bundle bytes plus digests (`src/core/crypto/qcont/lifecycle-shard.js`)
- successor restore grouping by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes, with explicit disambiguation required for same-state forks or multi-bundle cohorts (`src/core/crypto/qcont/restore.js`)
- detached signatures split by family in successor lifecycle bundles; archive policy is evaluated over `attachments.archiveApprovalSignatures` only, while maintenance and source-evidence signatures are verified and reported separately
- JSON Schema draft 2020-12 files under `docs/schema/` for structural grammar plus a checked-in fixture corpus validated in JavaScript CI by a checked-in validator that covers the active repository keyword subset, not the full draft 2020-12 vocabulary
- active compatibility appendices for canonicalization, external-artifact handling, and current vector coverage under `docs/appendices/`

Deferred roadmap:

- state-changing continuity records that preserve successor `archiveId` semantics across future rewrap or reencryption
- a frozen standalone interoperability corpus versioned separately from the repository examples and selftests

Deprecated v1 context:

- v1 canonical manifest export and embedding under `QV-JSON-RFC8785-v1`
- v1 canonical bundle export under `QV-BUNDLE-JSON-v1` for the manifest-bundle family
- detached signatures over canonical v1 manifest bytes, plus the deprecated v1 restore-specific richer-bundle heuristic documented only for `QVqcont-6`

## Future work and non-normative notes

Statements explicitly labeled as future or recommended direction are non-normative.
Current likely promotion targets, but not current compatibility rules, include:

- expanding the active appendices with additional vectors, malformed cases, and machine-consumable corpus material
- introducing state-changing continuity records that preserve successor `archiveId` semantics across future rewrap or reencryption
- the current three-layer specification stack (serialization, structural grammar, semantic rules) is described in Section 2; future work may extend the stack with additional representation-information layers for OAIS-oriented archival packaging

## 1. Status and conformance

This file describes the currently supported Quantum Vault format family as documented in the repository today.

### 1.1 Shared boundaries

These apply to all tracks:

- `.qenc` binary container with magic `QVv1`
- `.qenc` metadata format identifier `QVv1-5-0`
- `.qcont` binary shard with magic `QVC1`
- manifest canonicalization label `QV-JSON-RFC8785-v1` for canonical manifest bytes and for successor signable artifacts that declare this label
- bundle canonicalization label `QV-BUNDLE-JSON-v1` for manifest bundles and lifecycle bundles
- detached PQ signature acceptance: Quantum Signer major version 2 with context `quantum-signer/v2`
- detached Stellar signature acceptance: `stellar-signature/v2`

### 1.2 Deprecated v1 manifest / shard track

- `.qcont` shard metadata format identifier **`QVqcont-6`**
- canonical manifest schema/version `quantum-vault-archive-manifest/v3`
- manifest bundle type/version `QV-Manifest-Bundle` v2
- shards embed canonical manifest bytes and `QV-Manifest-Bundle` v2 bytes (Section 8.1–8.3)

### 1.3 Successor lifecycle track

- archive-state descriptor schema `quantum-vault-archive-state-descriptor/v1`
- cohort binding schema `quantum-vault-cohort-binding/v1`
- transition record schema `quantum-vault-transition-record/v1` (when used)
- source-evidence schema `quantum-vault-source-evidence/v1` (when used)
- lifecycle bundle type/version `QV-Lifecycle-Bundle` v1
- `.qcont` shard metadata format identifier **`QVqcont-7`**; `metaJSON.artifactFamily` **`successor-lifecycle-v1`**
- shards embed canonical archive-state bytes, cohort-binding bytes, and lifecycle-bundle bytes with `SHA3-512` digests (Section 8.5)

Current conformance rules:

- Parsers MUST reject unknown major versions, unknown magic values, unknown schema values, and unsupported canonicalization labels.
- Parsers MUST reject mismatched manifest, bundle, or shard digests.
- Parsers MUST reject malformed or unresolved attachment references that would make verification unsafe.
- Parsers MUST NOT infer algorithms heuristically from filenames, key lengths, or wrapper type.

## 2. Notation and conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

Quantum Vault-specific conventions:

- Binary Quantum Vault formats use big-endian length and index fields.
- Text fields are UTF-8.
- Hex digests are lowercase.
- Base64 fields use standard RFC 4648 Base64 with no line breaks.
- `SHA3-512(x)` means SHA3-512 over the exact byte sequence `x`.
- `manifestBytes` means the canonical byte serialization of the manifest under `QV-JSON-RFC8785-v1`.

Canonicalization convention:

- `QV-JSON-RFC8785-v1` is the canonical JSON label used for canonical manifest bytes (legacy), successor signable artifacts (archive-state descriptor, cohort binding, transition record, source evidence), and for canonicalized `authPolicy` input when computing `authPolicyCommitment`.
- `QV-BUNDLE-JSON-v1` is the canonical JSON label used for manifest bundle bytes and for `QV-Lifecycle-Bundle` v1 bytes.
- current code uses one strict UTF-8 JSON canonicalizer for these labels; they remain separately labeled because **legacy** archive-approval detached signatures target **manifest** bytes, while **successor** archive-approval detached signatures target **archive-state descriptor** bytes (`trust-and-policy.md` §11)

Formal grammar convention:

- the current manifest-family grammar layer is published as JSON Schema draft 2020-12 files under `docs/schema/`
- `docs/schema/qv-manifest-v3.schema.json` governs the canonical manifest grammar
- `docs/schema/qv-manifest-bundle-v2.schema.json` governs the manifest-bundle grammar
- `docs/schema/qv-common-types.schema.json` provides shared constrained types and enums reused by both artifact families
- schema-valid does not imply canonical bytes, digest equality, `authPolicyCommitment` equality, signature safety, or restore safety
- conforming parsers MUST enforce all three layers: canonicalization, schema/grammar, and semantic binding rules

Key terminology rule used by this file:

- `privateKey` means asymmetric secret key material, such as the ML-KEM decryption key currently exported in the file named `privateKey.qkey`
- `publicKey` means asymmetric public key material
- `secretKey` means symmetric secret material, such as `Kenc` or `Kiv`

### Specification stack

Quantum Vault artifacts (legacy manifest family and successor lifecycle family) are governed by three distinct specification layers:

| Layer | Governs | Current anchor |
| --- | --- | --- |
| Serialization / canonicalization | Exact bytes: canonical byte output, key ordering, primitive encoding, whitespace rules, UTF-8 encoding | RFC 8785 via `QV-JSON-RFC8785-v1` for canonical manifest bytes, successor signable artifacts, and `authPolicyCommitment` input; `QV-BUNDLE-JSON-v1` for manifest bundle and lifecycle bundle bytes |
| Structural grammar | Required and optional fields, value domains, object shapes, closed-object and extension rules | JSON Schema draft 2020-12 files under `docs/schema/` |
| Semantic rules | What fields mean, what signatures cover, what changes are permitted, what policy commitment requires, what restore behavior is required | This document (`format-spec.md`), `trust-and-policy.md`, `security-model.md` |

These layers are related but distinct:

- A value can be structurally valid (schema-valid) but not canonical (not serialized under the declared canonicalization profile).
- A value can be canonical and schema-valid but semantically invalid (for example, `reedSolomon.parity` does not equal `n - k`).
- A value can be semantically meaningful but structurally incomplete (missing a required field that the grammar requires).

Conforming parsers MUST enforce all three layers. The JSON Schema grammar layer does not replace canonicalization rules or semantic validation. The current structural grammar layer uses JSON Schema draft 2020-12; the repository's checked-in JavaScript CI helper validates only the keyword subset exercised by the current checked-in schemas and fixtures. Any future use of CDDL (RFC 8610) would be a separate long-term representation-information concern, not a replacement for the current validation layer.

## 3. Artifact model

| Artifact | Role in the format family | Relationship to other artifacts |
| --- | --- | --- |
| `.qenc` | Encrypted container | The primary ciphertext object |
| `.qcont` | Threshold shard | Carries one shard's recovery state plus embedded authenticity material (legacy: manifest + manifest bundle; successor: archive-state + cohort binding + lifecycle bundle) |
| Archive-state descriptor JSON | Canonical signable archive state (successor) | Detached-signature payload for archive approval; carried in `QV-Lifecycle-Bundle` and successor shards |
| Cohort-binding JSON | State-bound shard cohort description (successor) | Carries current sharding commitments and the digest input used to derive `cohortId` |
| `QV-Lifecycle-Bundle` v1 | Mutable lifecycle bundle (successor) | Carries archive state, cohort binding, policy, attachments, source evidence, and transitions; not the archive-approval signable byte sequence |
| `*.qvmanifest.json` | Canonical signable manifest (legacy) | Detached-signature payload for legacy archives |
| `*.extended.qvmanifest.json` | Mutable manifest bundle (legacy) | Carries manifest + policy + attachments |
| `.qsig` | Detached PQ signature | Signs canonical manifest bytes (legacy) or canonical archive-state bytes (successor archive-approval), depending on bundle shape |
| `.sig` | Detached Stellar/Ed25519 signature proof | Same path-dependent rule as `.qsig` |
| `.pqpk` | Detached PQ public key | Used for bundle pinning or restore-time user pinning |
| `.ots` | OpenTimestamps evidence | Targets detached signature bytes, not the bundle |
| `.qvpack` | Multi-file payload bundle | Pre-encryption binary bundle of multiple files; becomes the plaintext payload inside `.qenc` |

Artifact lifecycle summary:

- When multiple files are archived, Encrypt first bundles them into a `.qvpack` payload.
- Encrypt creates a `.qenc` container from the plaintext payload (single file or `.qvpack`).
- Split creates `.qcont` shards and successor lifecycle objects (`QVqcont-7`) on the normal shipped path; legacy manifest artifacts remain compatibility-only.
- Attach creates or updates a manifest bundle (legacy) or updates lifecycle bundle attachments on successor shards without mutating canonical archive-state bytes or canonical cohort-binding bytes.
- Restore may use embedded or externally supplied manifests, bundles, lifecycle bundles, signatures, keys, and timestamps depending on shard format.
- Decrypt recovers the plaintext payload; if it is a `.qvpack`, the individual files are extracted.
- **Legacy:** detached archive-approval signatures target canonical manifest bytes only. **Successor:** detached archive-approval signatures target canonical archive-state descriptor bytes only; other attachment families target their declared objects (`trust-and-policy.md` §11).

## 4. Current archive identity and binding model

Current identity and binding objects are layered rather than unified under one cross-state continuity object:

- `qenc.qencHash` is the primary current-state fixity/authenticity anchor and is `SHA3-512` over the full `.qenc` bytes.
- `qenc.containerId` is a secondary identifier and is currently `SHA3-512(qenc-header-bytes)`.
- **Legacy track:** `manifestDigest` is `SHA3-512` over canonical manifest bytes, and `authPolicyCommitment` binds restore-relevant authenticity policy semantics from canonical-manifest bytes to the mutable manifest-bundle policy object.
- **Successor track:** `archiveId` is the stable archive identifier within one successor archive family; `stateId` is `SHA3-512` over canonical archive-state bytes; `cohortId` is derived from `archiveId`, `stateId`, and `cohortBindingDigest` and does not include the lifecycle-bundle digest.

Current binding invariants:

- **Legacy:** detached archive-approval signatures sign canonical manifest bytes only.
- **Successor:** detached archive-approval signatures sign canonical archive-state descriptor bytes only.
- Bundle mutation MUST NOT mutate the canonical signable bytes for the selected track.
- **Legacy:** `manifestDigest` MUST match the canonical manifest bytes embedded in the bundle, and `authPolicyCommitment` in the manifest MUST match the concrete `authPolicy` carried by the manifest bundle.
- **Successor:** lifecycle-bundle mutation MUST NOT mutate canonical archive-state or cohort-binding bytes, and the lifecycle bundle's digests MUST match the selected archive-state and cohort-binding objects.

### 4.1 Successor archive-state descriptor (implemented now)

The successor archive-state descriptor is the current long-lived archive-approval object.

- schema: `quantum-vault-archive-state-descriptor/v1`
- canonicalization: `QV-JSON-RFC8785-v1`
- `stateId = SHA3-512(canonical archive-state descriptor bytes)`
- `stateId` is derived metadata and MUST NOT appear inside the canonical archive-state bytes used to derive it
- the descriptor carries `archiveId`, `parentStateId`, crypto/profile/nonce/AAD identifiers, the current `qenc` binding object, and `authPolicyCommitment`

### 4.2 Successor cohort binding (implemented now)

The successor cohort binding carries the state-bound shard-cohort commitments that are allowed to change during same-state resharing.

- schema: `quantum-vault-cohort-binding/v1`
- canonicalization: `QV-JSON-RFC8785-v1`
- `cohortBindingDigest = SHA3-512(canonical cohort-binding bytes)`
- `cohortId = SHA3-256(canonical cohort-id preimage rooted in archiveId, stateId, and cohortBindingDigest)`
- `cohortId` is derived metadata and MUST NOT appear inside the canonical cohort-binding bytes used to derive `cohortBindingDigest`
- lifecycle-bundle digest is not part of state or cohort identity

### 4.3 Successor lifecycle bundle (implemented now)

The lifecycle bundle is the mutable carrier for successor policy and detached evidence.

- type/version: `QV-Lifecycle-Bundle` v1
- canonicalization: `QV-BUNDLE-JSON-v1`
- top-level members include `archiveState`, `archiveStateDigest`, `currentCohortBinding`, `currentCohortBindingDigest`, `authPolicy`, `sourceEvidence`, `transitions`, and `attachments`
- `attachments` contains exactly `publicKeys`, `archiveApprovalSignatures`, `maintenanceSignatures`, `sourceEvidenceSignatures`, and `timestamps`
- archive policy counts only `attachments.archiveApprovalSignatures`
- `maintenanceSignatures` and `sourceEvidenceSignatures` are verified and reported separately from archive policy
- `.ots` evidence targets detached signature bytes, not lifecycle-bundle bytes

### 4.4 Deprecated v1 anchors

Historical v1 identity and binding rules remain implemented only to interpret older archives:

- `manifestDigest` is `SHA3-512` over canonical manifest bytes
- detached archive-approval signatures sign canonical manifest bytes
- `authPolicyCommitment` binds canonical manifest bytes to the mutable manifest-bundle policy object

Not yet present as a first-class artifact:

- state-changing continuity records that preserve successor `archiveId` semantics across future rewrap or reencryption

## 5. Deprecated v1 canonicalization and canonical manifest

### 5.1 Canonicalization

The legacy canonical manifest uses canonical JSON `QV-JSON-RFC8785-v1`.
Current behavior is:

- for deprecated v1 material, the same canonical bytes are exported as `*.qvmanifest.json`
- the same canonical bytes are embedded into every `.qcont` shard
- the same canonical bytes are embedded inside every manifest bundle
- detached signatures are always computed over those canonical bytes

Because detached signatures depend on exact bytes:

- Quantum Vault MUST sign only bytes produced by the supported canonicalizer
- Quantum Vault MUST NOT claim RFC 8785 compatibility for any label that does not actually use RFC 8785-compatible byte rules
- The current repository demonstrates byte-level parity only for the checked-in regression vectors and current manifest-family shapes; it does not make a broader external conformance claim beyond that covered scope

The manifest canonicalizer rejects duplicate-key JSON on the parse path, rejects invalid UTF-8, rejects lone surrogates, rejects unsupported runtime values, and emits UTF-8 canonical bytes with recursively sorted object keys.

Detailed current edge cases, examples, and unsupported cases for the current canonicalization labels are defined in [appendices/canonicalization-profile.md](appendices/canonicalization-profile.md).

### 5.2 Canonical manifest contract

The current canonical manifest is generated at split stage with schema/version `quantum-vault-archive-manifest/v3`.
Its current machine-readable grammar is published in `docs/schema/qv-manifest-v3.schema.json`.

Current required contract points include:

- explicit schema/version and canonicalization label
- `qenc.qencHash` with `qenc.hashAlg = "SHA3-512"`
- `qenc.containerId` with role `secondary-header-id`
- `qenc.containerIdAlg = "SHA3-512(qenc-header-bytes)"`
- explicit nonce policy fields: `noncePolicyId`, `nonceMode`, `counterBits`, `maxChunkCount`
- explicit sharding and shard-binding metadata
- `authPolicyCommitment`

Current shard-binding semantics:

- `bodyDefinitionId = "QV-QCONT-SHARDBODY-v1"`
- shard body hash input includes fragment stream payload only
- the body definition excludes the shard header, embedded manifest/digest, embedded bundle/digest, and detached external signatures
- optional Shamir share commitments commit to raw share bytes

Current nonce-bound contract:

- `chunkIndex` is a `uint32`
- `0 <= chunkIndex < chunkCount <= maxChunkCount <= 4294967295`

Display order in the following tables is explanatory only.
Canonical key order is determined by `QV-JSON-RFC8785-v1`, not by the order shown here.

### 5.2.1 Current top-level manifest fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `schema` | string | MUST be `quantum-vault-archive-manifest/v3` |
| `version` | integer | MUST be `3` |
| `manifestType` | string | MUST be `archive` |
| `canonicalization` | string | MUST be `QV-JSON-RFC8785-v1` |
| `cryptoProfileId` | string | MUST be a supported crypto profile; current builder emits `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2` |
| `kdfTreeId` | string | MUST match the selected crypto profile; current builder emits `QV-KDF-TREE-v2` |
| `noncePolicyId` | string | MUST match the selected AEAD mode's nonce contract |
| `nonceMode` | string | MUST match the selected AEAD mode's nonce contract |
| `counterBits` | integer | MUST match the selected AEAD mode's nonce contract |
| `maxChunkCount` | integer | MUST match the selected AEAD mode's nonce contract |
| `aadPolicyId` | string | MUST match the selected crypto profile; current builder emits `QV-AAD-HEADER-CHUNK-v1` |
| `qenc` | object | REQUIRED encrypted-container binding object; fields in Section 5.2.2 |
| `sharding` | object | REQUIRED threshold and erasure-coding parameters; fields in Section 5.2.3 |
| `authPolicyCommitment` | object | REQUIRED commitment to the concrete mutable `authPolicy`; fields in Section 5.2.3 |
| `shardBinding` | object | conditionally present when shard-body hashes or share commitments are emitted; fields in Section 5.2.3 |

### 5.2.2 Current `manifest.qenc` fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `format` | string | MUST be `QVv1-5-0` |
| `aeadMode` | string | MUST be `single-container-aead` or `per-chunk-aead` |
| `ivStrategy` | string | MUST match the selected `aeadMode`; current supported values are `single-iv` and `kmac-prefix64-ctr32-v3` |
| `chunkSize` | integer | positive safe integer chunk size used for current encryption layout |
| `chunkCount` | integer | positive count; MUST remain within the nonce-policy bound |
| `payloadLength` | integer | positive safe integer plaintext payload length carried by `.qenc` |
| `hashAlg` | string | MUST be `SHA3-512` |
| `qencHash` | string | lowercase hex `SHA3-512` over the full `.qenc` bytes |
| `primaryAnchor` | string | MUST be `qencHash` |
| `containerId` | string | lowercase hex secondary identifier for the current `.qenc` header |
| `containerIdRole` | string | MUST be `secondary-header-id` |
| `containerIdAlg` | string | MUST be `SHA3-512(qenc-header-bytes)` |

### 5.2.3 Current `sharding`, `authPolicyCommitment`, and `shardBinding` fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `sharding.shamir.threshold` | integer | positive safe integer threshold for share recovery |
| `sharding.shamir.shareCount` | integer | positive safe integer Shamir share count |
| `sharding.reedSolomon.n` | integer | positive safe integer total shard count |
| `sharding.reedSolomon.k` | integer | positive safe integer minimum fragment count for erasure recovery |
| `sharding.reedSolomon.parity` | integer | current parity count as a uint32 integer |
| `sharding.reedSolomon.codecId` | string | MUST be `QV-RS-ErasureCodes-v1` |
| `authPolicyCommitment.alg` | string | MUST be `SHA3-512` |
| `authPolicyCommitment.canonicalization` | string | MUST be `QV-JSON-RFC8785-v1` |
| `authPolicyCommitment.value` | string | lowercase hex digest over the canonicalized concrete `authPolicy` object |
| `shardBinding.bodyDefinitionId` | string | MUST be `QV-QCONT-SHARDBODY-v1` |
| `shardBinding.bodyDefinition.includes` | string array | current builder includes `fragment-len32-stream` |
| `shardBinding.bodyDefinition.excludes` | string array | current builder excludes shard header, embedded manifest/bundle material, and external signatures |
| `shardBinding.shardBodyHashAlg` | string | MUST be `SHA3-512` |
| `shardBinding.shardBodyHashes[]` | string array | optional per-shard body hash list |
| `shardBinding.shareCommitment.hashAlg` | string | when present, MUST be `SHA3-512` |
| `shardBinding.shareCommitment.input` | string | when present, MUST be `raw-shamir-share-bytes` |
| `shardBinding.shareCommitments[]` | string array | optional per-share commitment list |

### 5.2.4 Illustrative current manifest fragment

The following fragment is illustrative only.
Array contents are elided for readability; exact bytes remain governed by the canonical manifest and its canonicalization rules.

```json
{
  "aadPolicyId": "QV-AAD-HEADER-CHUNK-v1",
  "authPolicyCommitment": {
    "alg": "SHA3-512",
    "canonicalization": "QV-JSON-RFC8785-v1",
    "value": "...128 hex chars..."
  },
  "canonicalization": "QV-JSON-RFC8785-v1",
  "counterBits": 32,
  "cryptoProfileId": "QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2",
  "kdfTreeId": "QV-KDF-TREE-v2",
  "manifestType": "archive",
  "maxChunkCount": 4294967295,
  "nonceMode": "kmac-prefix64-ctr32",
  "noncePolicyId": "QV-GCM-KMACPFX64-CTR32-v3",
  "qenc": {
    "aeadMode": "per-chunk-aead",
    "chunkCount": 2,
    "chunkSize": 8388608,
    "containerId": "...128 hex chars...",
    "containerIdAlg": "SHA3-512(qenc-header-bytes)",
    "containerIdRole": "secondary-header-id",
    "format": "QVv1-5-0",
    "hashAlg": "SHA3-512",
    "ivStrategy": "kmac-prefix64-ctr32-v3",
    "payloadLength": 10442341,
    "primaryAnchor": "qencHash",
    "qencHash": "...128 hex chars..."
  },
  "schema": "quantum-vault-archive-manifest/v3",
  "shardBinding": {
    "bodyDefinition": {
      "excludes": ["qcont-header", "embedded-manifest", "embedded-manifest-digest", "embedded-bundle", "embedded-bundle-digest", "external-signatures"],
      "includes": ["fragment-len32-stream"]
    },
    "bodyDefinitionId": "QV-QCONT-SHARDBODY-v1",
    "shardBodyHashAlg": "SHA3-512",
    "shardBodyHashes": ["..."],
    "shareCommitment": {
      "hashAlg": "SHA3-512",
      "input": "raw-shamir-share-bytes"
    },
    "shareCommitments": ["..."]
  },
  "sharding": {
    "reedSolomon": {
      "codecId": "QV-RS-ErasureCodes-v1",
      "k": 2,
      "n": 6,
      "parity": 4
    },
    "shamir": {
      "shareCount": 6,
      "threshold": 4
    }
  },
  "version": 3
}
```

### 5.3 Current manifest parsing behavior

Current canonical-manifest parsing behavior is:

- manifest input bytes MUST already be canonical `QV-JSON-RFC8785-v1` JSON
- parsers reject invalid UTF-8, duplicate object keys, lone surrogates, and unsupported schema/version or canonicalization labels
- JSON member names are always treated as inert data keys on the parse path; names such as `__proto__`, `constructor`, and `prototype` do not trigger prototype or accessor behavior
- parsers validate the required current fields and the current binding and algorithm identifiers
- unknown additional manifest fields are rejected at every object level
- compatibility fails closed on unsupported schema, version, canonicalization, and required-binding mismatches

## 6. Deprecated v1 manifest bundle

### 6.1 Purpose and top-level structure

The manifest bundle is a self-contained mutable JSON object.
It is not the detached-signature payload.
Its current machine-readable grammar is published in `docs/schema/qv-manifest-bundle-v2.schema.json`.

The current top-level structure is:

- `type = "QV-Manifest-Bundle"`
- `version = 2`
- `bundleCanonicalization = "QV-BUNDLE-JSON-v1"`
- `manifestCanonicalization = "QV-JSON-RFC8785-v1"`
- `manifest`
- `manifestDigest = { alg: "SHA3-512", value: SHA3-512(canonical manifest bytes) }`
- `authPolicy`
- `attachments.publicKeys[]`
- `attachments.signatures[]`
- `attachments.timestamps[]`

Naming behavior:

- deprecated v1 split exports canonical signable manifest as `*.qvmanifest.json`
- deprecated v1 attach exports the self-contained bundle as `*.extended.qvmanifest.json`
- extracting a signable manifest from an existing bundle may use `*.signable.qvmanifest.json`

### 6.1.1 Current top-level bundle fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `type` | string | MUST be `QV-Manifest-Bundle` |
| `version` | integer | MUST be `2` |
| `bundleCanonicalization` | string | MUST be `QV-BUNDLE-JSON-v1` |
| `manifestCanonicalization` | string | MUST be `QV-JSON-RFC8785-v1` |
| `manifest` | object | REQUIRED canonical-manifest object; canonicalized independently from the mutable bundle |
| `manifestDigest.alg` | string | MUST be `SHA3-512` |
| `manifestDigest.value` | string | lowercase hex `SHA3-512` over canonical manifest bytes |
| `authPolicy.level` | string | MUST be `integrity-only`, `any-signature`, or `strong-pq-signature` |
| `authPolicy.minValidSignatures` | integer | positive safe integer; current runtime rejects values above `9007199254740991` |
| `attachments.publicKeys` | array | current canonical bundle input MUST carry the array even when empty |
| `attachments.signatures` | array | current canonical bundle input MUST carry the array even when empty |
| `attachments.timestamps` | array | current canonical bundle input MUST carry the array even when empty |

### 6.2 Bundle invariants

Current bundle invariants:

- `manifest` is the exact structured object whose canonical bytes are signed
- `manifestDigest` is computed over canonical manifest bytes only
- `attachments` are not part of the detached-signature payload
- changing `attachments` MUST NOT invalidate detached signatures

### 6.3 Attachment objects

Current attachment families accepted by the bundle are:

| Attachment family | Required current role |
| --- | --- |
| `publicKeys[]` | Bundled signer identity material or verification key material |
| `signatures[]` | Detached signatures that target the canonical manifest |
| `timestamps[]` | OTS evidence objects that target detached signatures |

Current `publicKeys[]` contract:

- includes an `id`
- includes `kty`, `suite`, `encoding`, and `value`
- may use a Stellar address as `value` for Stellar/Ed25519 identity cases

Current `signatures[]` contract:

- includes an `id`
- includes `format`, `suite`, and target descriptor
- `target.type` MUST be `canonical-manifest`
- `target.digestValue` MUST match `bundle.manifestDigest.value`
- verification is over canonical manifest bytes, not bundle bytes
- optional `publicKeyRef` may link to compatible bundled signer material
- if `publicKeyRef` is present, it MUST resolve to a known compatible bundled key entry and MUST be treated as authoritative for safe verification of that bundled signature
- a verifier MUST reject unresolved, incompatible, or non-verifying `publicKeyRef` bindings rather than silently ignoring the bundled reference and falling back to some other signer source

Current `timestamps[]` contract:

- includes an `id`
- `type` is currently `opentimestamps`
- `targetRef` references a known signature object
- carries proof bytes plus completeness/reporting metadata

### 6.3.1 Current `attachments.publicKeys[]` fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `id` | string | REQUIRED unique attachment identifier |
| `kty` | string | MUST match the declared `suite`; current values include PQ public-key types and `ed25519-public-key` |
| `suite` | string | MUST be a canonical supported signature-suite identifier |
| `encoding` | string | MUST be `base64` or `stellar-address` |
| `value` | string | encoded key material or Stellar signer address |
| `legacy` | boolean | optional compatibility marker; omitted or `false` for current-format material |

Current compatibility rules:

- `encoding = "base64"` is used for PQ public keys
- `encoding = "stellar-address"` is used only for `ed25519`
- `ed25519` public keys must not be bundled with `base64` encoding

### 6.3.2 Current `attachments.signatures[]` fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `id` | string | REQUIRED unique attachment identifier |
| `format` | string | MUST be `qsig` or `stellar-sig` |
| `suite` | string | MUST be a canonical supported signature-suite identifier for the detached artifact |
| `target.type` | string | MUST be `canonical-manifest` |
| `target.digestAlg` | string | MUST be `SHA3-512` |
| `target.digestValue` | string | MUST equal `manifestDigest.value` |
| `signatureEncoding` | string | current bundle format uses Base64-encoded detached signature bytes |
| `signature` | string | Base64 payload bytes of the detached signature artifact |
| `publicKeyRef` | string or `null` | optional authoritative reference to a compatible bundled signer key |
| `legacy` | boolean | optional compatibility marker |

### 6.3.3 Current `attachments.timestamps[]` fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `id` | string | REQUIRED unique attachment identifier |
| `type` | string | MUST be `opentimestamps` |
| `targetRef` | string | MUST reference a known bundle signature id |
| `proofEncoding` | string | current bundle format uses Base64-encoded proof bytes |
| `proof` | string | Base64 payload bytes of the `.ots` proof |
| `apparentlyComplete` | boolean | heuristic completeness report |
| `completeProof` | boolean | current implementation normalizes this to the same heuristic completeness value |

### 6.3.4 Illustrative current bundle fragment

The following fragment is illustrative only.
Long Base64 payloads are elided for readability.

```json
{
  "attachments": {
    "publicKeys": [
      {
        "encoding": "base64",
        "id": "key-a55bb3ab4cbe019a",
        "kty": "ml-dsa-public-key",
        "legacy": false,
        "suite": "mldsa-87",
        "value": "...base64..."
      }
    ],
    "signatures": [
      {
        "format": "qsig",
        "id": "sig-7291922586144f4f",
        "legacy": false,
        "publicKeyRef": "key-a55bb3ab4cbe019a",
        "signature": "...base64...",
        "signatureEncoding": "base64",
        "suite": "mldsa-87",
        "target": {
          "digestAlg": "SHA3-512",
          "digestValue": "...128 hex chars...",
          "type": "canonical-manifest"
        }
      }
    ],
    "timestamps": [
      {
        "apparentlyComplete": true,
        "completeProof": true,
        "id": "ots-58c15732c3ec5480",
        "proof": "...base64...",
        "proofEncoding": "base64",
        "targetRef": "sig-7291922586144f4f",
        "type": "opentimestamps"
      }
    ]
  },
  "authPolicy": {
    "level": "strong-pq-signature",
    "minValidSignatures": 1
  },
  "bundleCanonicalization": "QV-BUNDLE-JSON-v1",
  "manifest": { "...": "canonical manifest object" },
  "manifestCanonicalization": "QV-JSON-RFC8785-v1",
  "manifestDigest": {
    "alg": "SHA3-512",
    "value": "...128 hex chars..."
  },
  "type": "QV-Manifest-Bundle",
  "version": 2
}
```

### 6.4 Current bundle parsing behavior

Current canonical-bundle parsing behavior is:

- bundle input bytes MUST already be canonical `QV-BUNDLE-JSON-v1` JSON under the current normalized bundle schema
- bundle input bytes MUST already include the normalized top-level shape, including `manifestDigest.alg`, `manifestDigest.value`, and explicit `attachments.publicKeys`, `attachments.signatures`, and `attachments.timestamps` arrays
- parsers reject invalid UTF-8, duplicate object keys, lone surrogates, unsupported bundle or embedded-manifest labels/versions, and structurally unknown current bundle fields
- parsers normalize bundle content to the current known field set and then require byte-for-byte equality with the canonical bytes of that normalized output
- the only supported non-canonical bundle parse boundary is the preview-only API used for UI shard inspection; normal bundle parse APIs remain fail-closed on non-canonical bytes
- unresolved or incompatible `publicKeyRef` bindings fail closed

## 7. `.qenc` container format

### 7.1 Binary layout

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

### 7.2 Current metadata contract

Current `.qenc` emitter metadata and compatibility notes are:

| Field | Current emitted value or shape | Current acceptance note |
| --- | --- | --- |
| `KEM` | `ML-KEM-1024` | descriptive algorithm label |
| `KDF` | `KMAC256` | descriptive algorithm label |
| `AEAD` | `AES-256-GCM` | descriptive algorithm label |
| `fmt` | `QVv1-5-0` | MUST match the supported container metadata format |
| `cryptoProfileId` | `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2` | required by current direct `.qenc` policy validation |
| `kdfTreeId` | `QV-KDF-TREE-v2` | emitted now; direct `.qenc` validation tolerates legacy omission, but shard restore cross-checks the duplicated `.qenc` metadata against the manifest |
| `aead_mode` | `single-container-aead` or `per-chunk-aead` | MUST be one of the supported current AEAD modes |
| `iv_strategy` | `random96` for single-container, `kmac-prefix64-ctr32-v3` for per-chunk | MUST match `aead_mode` |
| `noncePolicyId` | `QV-GCM-RAND96-v1` for single-container, `QV-GCM-KMACPFX64-CTR32-v3` for per-chunk | MUST match `aead_mode` |
| `nonceMode` | `random96` for single-container, `kmac-prefix64-ctr32` for per-chunk | MUST match `aead_mode` |
| `counterBits` | `0` for single-container, `32` for per-chunk | MUST match `aead_mode` |
| `maxChunkCount` | `1` for single-container, `4294967295` for per-chunk | MUST match `aead_mode` |
| `aadPolicyId` | `QV-AAD-HEADER-CHUNK-v1` | emitted now; direct `.qenc` validation tolerates legacy omission, but shard restore cross-checks it against the manifest |
| `hasKeyCommitment` | `true` | current containers require a key commitment |
| `payloadFormat` | `wrapped-v1` | current payload wrapper |
| `payloadLength` | positive integer | cleartext payload length |
| `chunkSize` | positive integer | current emitter uses the runtime chunk size constant |
| `chunkCount` | positive integer | current emitter includes it in both AEAD modes; per-chunk mode requires it for validation |
| `domainStrings.kdf` | `quantum-vault:kdf:v2` | required for current policy validation |
| `domainStrings.iv` | `quantum-vault:chunk-iv:v2` | required for current policy validation |
| `domainStrings.kenc` | `quantum-vault:kenc:v2` | required for current policy validation |
| `domainStrings.kiv` | `quantum-vault:kiv:v2` | required for current policy validation |

Illustrative current `.qenc` metadata fragment:

```json
{
  "AEAD": "AES-256-GCM",
  "KDF": "KMAC256",
  "KEM": "ML-KEM-1024",
  "aadPolicyId": "QV-AAD-HEADER-CHUNK-v1",
  "aead_mode": "per-chunk-aead",
  "chunkCount": 2,
  "chunkSize": 8388608,
  "counterBits": 32,
  "cryptoProfileId": "QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2",
  "domainStrings": {
    "iv": "quantum-vault:chunk-iv:v2",
    "kdf": "quantum-vault:kdf:v2",
    "kenc": "quantum-vault:kenc:v2",
    "kiv": "quantum-vault:kiv:v2"
  },
  "fmt": "QVv1-5-0",
  "hasKeyCommitment": true,
  "iv_strategy": "kmac-prefix64-ctr32-v3",
  "kdfTreeId": "QV-KDF-TREE-v2",
  "maxChunkCount": 4294967295,
  "nonceMode": "kmac-prefix64-ctr32",
  "noncePolicyId": "QV-GCM-KMACPFX64-CTR32-v3",
  "payloadFormat": "wrapped-v1",
  "payloadLength": 10442341
}
```

### 7.3 Payload and private metadata

Current private payload metadata for `wrapped-v1` contains:

- `originalFilename`
- `timestamp`
- `fileHash`
- `originalLength`

Current `wrapped-v1` payload format is:

```text
[uint32be privateMetaLen][privateMetaJSON][fileBytes]
```

When `aead_mode = per-chunk-aead`, ciphertext is the concatenation of per-chunk AES-GCM outputs, each including its own authentication tag.

#### Multi-file payload bundle (`.qvpack`)

When multiple files are archived in a single `.qenc` container, the files are first packed into a binary payload bundle before encryption.
The bundle becomes the `fileBytes` content within the `wrapped-v1` payload envelope.

The `.qvpack` format uses magic `QVB1`, version `1`, big-endian integer fields, and length-prefixed entries.
Detection is by magic bytes, not by filename.

Binary layout:

| Data | Length | Description |
| --- | --- | --- |
| MAGIC | 4 bytes | ASCII `QVB1` |
| version | 1 byte | MUST be `1` |
| count | 2 bytes (Uint16 BE) | number of bundled file entries; MUST be > 0 |
| entries | variable | repeated entry records (see below) |

Per-entry layout:

| Data | Length | Description |
| --- | --- | --- |
| nameLen | 2 bytes (Uint16 BE) | length of filename in bytes; MUST be > 0 |
| nameBytes | nameLen bytes | UTF-8 encoded original filename |
| size | 4 bytes (Uint32 BE) | length of file content in bytes |
| bytes | size bytes | raw file content |

Current constraints:

- filename length MUST be > 0 and ≤ 65535 bytes
- file content length MUST be ≤ 4294967295 bytes (uint32 max)
- the minimum valid `.qvpack` size is 7 bytes (magic + version + count with zero entries is rejected; the smallest accepted bundle has one entry)
- parsers MUST reject trailing bytes after the last entry
- parsers MUST reject unknown versions

Current implementation source: `src/core/features/bundle-payload.js`.

### 7.4 AEAD, KDF, and key commitment rules

Current AEAD and KDF rules:

- single-container AAD is the entire header from MAGIC through `keyCommitment`
- per-chunk AAD is `header || uint32_be(chunkIndex) || uint32_be(plainLen_i)`, where `header` is the same full header including `keyCommitment`
- AES-GCM nonce size is 96 bits
- key commitment is mandatory and is verified before decryption
- `Kraw`, `Kenc`, and `Kiv` are derived via KMAC256 with explicit domain strings
- per-chunk IV derivation uses `prefix64 || uint32_be(chunkIndex)` where `prefix64` is derived from `Kiv` and `containerNonce`

Current derivation chain:

1. `{encapsulatedKey, sharedSecret} = ml_kem1024.encapsulate(publicKey)`
2. derive `Kraw = KMAC256(sharedSecret, kdfSalt || metaBytes, customization = domainStrings.kdf)`
3. derive `Kenc` and `Kiv` from `Kraw` using distinct customization strings
4. compute `keyCommitment = SHA3-256(Kenc)`

### 7.5 Current decrypt/verify order

Current decrypt/verify order is:

1. parse header
2. validate metadata/profile/nonce fields
3. decapsulate with the ML-KEM private key
4. derive `Kenc` and `Kiv`
5. verify `keyCommitment`
6. decrypt with AES-GCM using the required AAD
7. unpack `wrapped-v1`
8. optionally compare `privateMeta.fileHash` with a fresh `SHA3-512` over recovered file bytes

## 8. `.qcont` shard format

The implementation supports **two** `.qcont` layouts distinguished by `metaJSON.alg.fmt`:

- **QVqcont-6** — embeds a canonical manifest and a `QV-Manifest-Bundle` v2 (Sections 8.1–8.4).
- **QVqcont-7** — embeds successor lifecycle objects: archive-state descriptor, cohort binding, and `QV-Lifecycle-Bundle` v1 (Section 8.5).

Parsers MUST use the format identifier and embedded lengths to interpret the byte stream; they MUST NOT infer layout from filename alone.

### 8.1 Legacy binary layout (QVqcont-6)

| Data | Length | Description |
| --- | --- | --- |
| MAGIC_SHARD | 4 bytes | ASCII `QVC1` |
| metaLen | 2 bytes (Uint16 BE) | length of `metaJSON` |
| metaJSON | metaLen bytes UTF-8 | shard metadata |
| manifestLen | 4 bytes (Uint32 BE) | length of embedded canonical manifest |
| manifestBytes | manifestLen bytes | canonical `*.qvmanifest.json` bytes |
| manifestDigest | 64 bytes | `SHA3-512(manifestBytes)` |
| bundleLen | 4 bytes (Uint32 BE) | length of embedded bundle |
| bundleBytes | bundleLen bytes | embedded `QV-Manifest-Bundle` JSON bytes |
| bundleDigest | 64 bytes | `SHA3-512(bundleBytes)` |
| encapBlobLen | 4 bytes (Uint32 BE) | length of encapsulation blob |
| encapBlob | encapBlobLen bytes | ML-KEM ciphertext |
| containerNonce | 12 bytes | copied from `.qenc` |
| kdfSalt | 16 bytes | copied from `.qenc` |
| qencMetaLen | 2 bytes (Uint16 BE) | length of duplicated `.qenc` metadata |
| qencMetaBytes | qencMetaLen bytes UTF-8 | duplicated `.qenc` metadata |
| keyCommitLen | 1 byte | key commitment length |
| keyCommitBytes | keyCommitLen bytes | required `SHA3-256(Kenc)` |
| shardIndex | 2 bytes (Uint16 BE) | 0-based shard index |
| shareLen | 2 bytes (Uint16 BE) | length of Shamir share |
| shareBytes | shareLen bytes | one Shamir share |
| fragments stream | variable | RS fragment stream encoded as repeated `[len32 | fragmentBytes]` |

### 8.2 Legacy shard metadata contract (QVqcont-6)

Legacy `.qcont` emitter metadata and compatibility notes are:

| Field | Current emitted value or shape | Purpose or current note |
| --- | --- | --- |
| `containerId` | lowercase hex string | summary copy of the manifest/header-derived container identifier |
| `alg.KEM` | `ML-KEM-1024` | descriptive algorithm label |
| `alg.KDF` | `KMAC256` | descriptive algorithm label |
| `alg.AEAD` | `AES-256-GCM` | descriptive algorithm label |
| `alg.RS` | `ErasureCodes` | descriptive erasure-coding label |
| `alg.fmt` | `QVqcont-6` | MUST match the legacy shard metadata format for this layout |
| `aead_mode` | `per-chunk` or `single-container` | shard-summary AEAD label; this is distinct from the duplicated embedded `.qenc` metadata values `per-chunk-aead` / `single-container-aead` |
| `iv_strategy` | string | summary copy of the `.qenc` IV strategy |
| `cryptoProfileId` | `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2` | current emitted profile id |
| `noncePolicyId` | string | summary copy of the selected nonce policy |
| `nonceMode` | string | summary copy of the selected nonce mode |
| `counterBits` | integer | summary copy of the selected nonce contract |
| `maxChunkCount` | integer | summary copy of the selected nonce contract |
| `aadPolicyId` | `QV-AAD-HEADER-CHUNK-v1` | summary copy of the current AAD policy |
| `n` | integer | total shard count |
| `k` | integer | erasure-recovery threshold |
| `m` | integer | current parity count |
| `t` | integer | Shamir recovery threshold |
| `rsEncodeBase` | `255` | current Reed-Solomon encode-base constant |
| `chunkSize` | integer | summary copy of the `.qenc` chunk size |
| `chunkCount` | integer | summary copy of the `.qenc` chunk count |
| `containerHash` | lowercase hex string | summary copy of the current `qencHash` value |
| `encapBlobHash` | lowercase hex string | hash of the encapsulated ML-KEM ciphertext blob |
| `privateKeyHash` | lowercase hex string | current field name for the hash of the ML-KEM private key bytes |
| `payloadLength` | positive integer or `null` | copied payload length when available |
| `originalLength` | positive integer | original recovered file length |
| `ciphertextLength` | positive integer | ciphertext payload length |
| `domainStrings` | object | current emitter copies the `.qenc` domain strings |
| `fragmentFormat` | `len32-prefixed` | current fragment-stream encoding |
| `perFragmentSize` | positive integer | current RS fragment size |
| `hasKeyCommitment` | `true` | indicates embedded key-commitment material is present |
| `keyCommitmentHex` | lowercase hex string | summary copy of the required key commitment |
| `hasEmbeddedManifest` | `true` | current shards always embed a canonical manifest |
| `manifestDigest` | lowercase hex string | digest of the embedded canonical manifest bytes |
| `hasEmbeddedBundle` | `true` | current shards always embed a manifest bundle |
| `bundleDigest` | lowercase hex string | digest of the embedded canonical bundle bytes |
| `authPolicyLevel` | string | summary copy of the initial bundle policy level; the authoritative policy object still lives in the bundle |
| `shareCommitments[]` | string array | per-share commitments when emitted |
| `fragmentBodyHashes[]` | string array | per-shard body hashes when emitted |
| `timestamp` | string | build-time ISO-8601 timestamp for the shard metadata record |

`privateKeyHash` is the current field name for the hash of the ML-KEM private key bytes.

Illustrative current `.qcont` metadata fragment:

```json
{
  "aadPolicyId": "QV-AAD-HEADER-CHUNK-v1",
  "aead_mode": "per-chunk",
  "alg": {
    "AEAD": "AES-256-GCM",
    "KDF": "KMAC256",
    "KEM": "ML-KEM-1024",
    "RS": "ErasureCodes",
    "fmt": "QVqcont-6"
  },
  "authPolicyLevel": "strong-pq-signature",
  "bundleDigest": "...128 hex chars...",
  "chunkCount": 2,
  "chunkSize": 8388608,
  "containerHash": "...128 hex chars...",
  "containerId": "...128 hex chars...",
  "counterBits": 32,
  "cryptoProfileId": "QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2",
  "domainStrings": {
    "iv": "quantum-vault:chunk-iv:v2",
    "kdf": "quantum-vault:kdf:v2",
    "kenc": "quantum-vault:kenc:v2",
    "kiv": "quantum-vault:kiv:v2"
  },
  "fragmentFormat": "len32-prefixed",
  "hasEmbeddedBundle": true,
  "hasEmbeddedManifest": true,
  "hasKeyCommitment": true,
  "iv_strategy": "kmac-prefix64-ctr32-v3",
  "keyCommitmentHex": "...64 hex chars...",
  "manifestDigest": "...128 hex chars...",
  "maxChunkCount": 4294967295,
  "n": 6,
  "nonceMode": "kmac-prefix64-ctr32",
  "noncePolicyId": "QV-GCM-KMACPFX64-CTR32-v3",
  "originalLength": 10442341,
  "payloadLength": 10442341,
  "perFragmentSize": 123456,
  "privateKeyHash": "...128 hex chars...",
  "rsEncodeBase": 255,
  "t": 4,
  "timestamp": "2026-03-09T23:43:16.000Z"
}
```

### 8.3 Embedded manifest and bundle invariants (QVqcont-6)

QVqcont-6 shard invariants:

- every legacy `.qcont` shard embeds the canonical manifest
- every currently emitted legacy `.qcont` shard embeds the current manifest bundle
- `manifestDigest` MUST equal `SHA3-512(manifestBytes)`
- if `bundleBytes` exist, `bundle.manifest` canonical bytes MUST equal `manifestBytes`
- if `bundleBytes` exist, `bundle.manifestDigest.value` MUST equal the embedded `manifestDigest`

### 8.4 Legacy split/combine semantics

Legacy split behavior:

- parse the `.qenc` header
- split the ML-KEM private key with Shamir secret sharing
- split ciphertext with Reed-Solomon erasure coding
- compute threshold `t = k + (n-k)/2`
- embed both canonical manifest and initial bundle into each shard

Legacy combine/restore behavior:

- classify provided artifacts
- resolve archive context deterministically from embedded or uploaded manifest/bundle material
- never use a "largest cohort wins" rule
- verify shard commitments and digests before reconstruction
- reconstruct the ML-KEM private key and `.qenc` only from a consistent cohort
- verify `qencHash` from the canonical manifest before allowing decrypt flow

### 8.5 Successor lifecycle shard layout (QVqcont-7)

Successor shards use the same `QVC1` magic and a UTF-8 `metaJSON` prefix. Parsers MUST require `metaJSON.alg.fmt = QVqcont-7` and `metaJSON.artifactFamily = successor-lifecycle-v1` before interpreting the successor layout.

After `metaJSON`, the byte stream embeds three canonical JSON artifacts with fixed-length digest anchors:

| Data | Length | Description |
| --- | --- | --- |
| `archiveStateLen` | 4 bytes (Uint32 BE) | length of embedded archive-state descriptor JSON bytes |
| `archiveStateBytes` | `archiveStateLen` bytes | UTF-8 JSON; canonical `quantum-vault-archive-state-descriptor/v1` under `QV-JSON-RFC8785-v1` |
| `archiveStateDigest` | 64 bytes | `SHA3-512(archiveStateBytes)` |
| `cohortBindingLen` | 4 bytes (Uint32 BE) | length of embedded cohort-binding JSON bytes |
| `cohortBindingBytes` | `cohortBindingLen` bytes | UTF-8 JSON; canonical `quantum-vault-cohort-binding/v1` |
| `cohortBindingDigest` | 64 bytes | `SHA3-512(cohortBindingBytes)` |
| `lifecycleBundleLen` | 4 bytes (Uint32 BE) | length of embedded lifecycle bundle JSON bytes |
| `lifecycleBundleBytes` | `lifecycleBundleLen` bytes | UTF-8 JSON; canonical `QV-Lifecycle-Bundle` v1 under `QV-BUNDLE-JSON-v1` |
| `lifecycleBundleDigest` | 64 bytes | `SHA3-512(lifecycleBundleBytes)` |

The stream then continues with encapsulation blob, container nonce, KDF salt, duplicated `.qenc` metadata, key commitment, shard index, Shamir share, and RS fragment stream using the same cryptographic conventions as legacy shards (implementation source: `src/core/crypto/qcont/lifecycle-shard.js`).

Shard metadata MUST carry `archiveId`, `stateId`, and `cohortId` consistent with the embedded archive-state and cohort-binding objects. **`cohortId`** is derived metadata (SHA3-256 over a fixed cohort-id preimage); it MUST NOT be confused with `SHA3-512(lifecycleBundleBytes)` — the lifecycle-bundle digest is **not** part of cohort identity.

### 8.6 `QV-Lifecycle-Bundle` v1 and successor restore selection

Normative summary (grammar: `docs/schema/qv-lifecycle-bundle-v1.schema.json`; semantics: `src/core/crypto/lifecycle/artifacts.js` and `trust-and-policy.md` §11):

- Top-level members are closed to the v1 set; `attachments` contains exactly `publicKeys`, `archiveApprovalSignatures`, `maintenanceSignatures`, `sourceEvidenceSignatures`, and `timestamps` (all arrays, present even if empty).
- **Archive-approval** detached signatures authenticate canonical **archive-state descriptor** bytes (`targetType` archive-state). Mutable lifecycle-bundle bytes are **not** the archive-approval signable payload.
- **Archive policy** counts only verified `archiveApprovalSignatures`; maintenance and source-evidence signatures remain separate reporting channels and do not satisfy archive policy.
- Restore groups successor shards by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes. Mixed-state or mixed-cohort sets MUST be rejected.
- If a cohort embeds **more than one** distinct lifecycle-bundle digest across its shards and the operator does not supply matching lifecycle-bundle bytes or an explicit selected digest, restore MUST **fail closed** (no lexical, timestamp, or “richest bundle” heuristic).
- If an explicit lifecycle bundle or embedded lifecycle-bundle digest is supplied for a mixed-bundle cohort, restore MAY proceed, but it MUST report that authenticity and policy were evaluated against the explicitly selected bundle rather than auto-selected embedded bytes.
- If multiple valid **cohorts** exist for the same `archiveId` and `stateId` (same-state fork), restore MUST reject ambiguous inputs without auto-selecting a winner by timestamp, attachment count, or lexical order.
- If the operator explicitly selects one cohort or supplies a matching lifecycle bundle for a same-state fork, restore MAY proceed but MUST emit a warning that multiple valid cohorts remain known and that Quantum Vault did not auto-select a winner.
- Successor restore reporting uses distinct status channels including `archiveApprovalSignatureVerified`, `maintenanceSignatureVerified`, `sourceEvidenceSignatureVerified`, `otsEvidenceLinked`, `signerPinned`, `bundlePinned`, and `userPinned`.

Informative design rationale: `docs/process/roadmap/lifecycle/resharing-design.md`.

## 9. External authenticity artifacts accepted by Quantum Vault

Current accepted external authenticity artifacts are:

| Artifact | Current acceptance rule |
| --- | --- |
| `.qsig` | Quantum Signer detached signature, major version 2, context `quantum-signer/v2` |
| `.sig` | Stellar detached signature JSON with schema `stellar-signature/v2` |
| `.pqpk` | Detached PQ public key used for bundled or user-supplied pinning |
| `.ots` | OpenTimestamps proof linked to detached signature bytes |

Current acceptance boundaries:

- `.qsig` and `.sig` are integration contracts; Quantum Vault does not restate their full upstream specs
- **Legacy:** bundle `attachments.signatures` target the canonical manifest only
- **Successor:** lifecycle bundle detached signatures are split by family; archive-approval targets canonical archive-state bytes (Section 8.6)
- bundled or external `.pqpk` material may be used for signer pinning
- `.ots` timestamps target detached signature bytes, not the bundle or lifecycle bundle as a whole

Detailed current acceptance, linkage, deduplication, and ambiguity rules for these detached artifacts are defined in [appendices/external-artifacts.md](appendices/external-artifacts.md).

## 10. Verification and restore algorithm

The implementation follows **two** restore paths. The shipped default path is the **successor** lifecycle path for `QVqcont-7`. The deprecated v1 manifest-bundle path remains implemented only for previously created archives during the phase-out window.

Successor verifier/restore order is:

1. parse artifacts and classify shard, archive-state, lifecycle-bundle, signature, key, and timestamp inputs
2. reject mixed legacy/successor artifact families
3. group successor shard candidates by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes
4. apply any explicit selection filters from uploaded archive-state bytes, uploaded lifecycle-bundle bytes, selected `archiveId`, selected `stateId`, selected `cohortId`, or explicit embedded lifecycle-bundle digest
5. fail closed if same-state forks or multi-bundle cohorts remain ambiguous after explicit filtering
6. reconstruct `.qenc` and the ML-KEM private key from one internally consistent successor cohort
7. verify that the selected lifecycle bundle matches the selected archive-state and cohort-binding objects
8. verify detached signatures by family against the exact canonical target bytes for that family
9. evaluate archive policy using `archiveApprovalSignatures` only
10. link timestamps/evidence to detached signature bytes and emit separate transition and source-evidence reports
11. emit status fields including `archiveApprovalSignatureVerified`, `maintenanceSignatureVerified`, `sourceEvidenceSignatureVerified`, `otsEvidenceLinked`, `signerPinned`, `bundlePinned`, and `userPinned`

Successor restore selection rules:

- if an uploaded lifecycle bundle is supplied, it MUST match exactly one candidate archive/state/cohort set
- if an uploaded archive-state descriptor is supplied, it narrows candidate states by exact canonical bytes; it does not authorize heuristic cohort selection
- if multiple successor candidate sets remain after explicit archive/state filtering, restore MUST require explicit cohort selection or lifecycle-bundle input
- if exactly one archive/state/cohort candidate remains and it carries multiple embedded lifecycle-bundle digests, restore MUST require uploaded lifecycle-bundle bytes or an explicit embedded bundle digest
- if the operator explicitly selects a cohort in a known same-state fork, restore MAY proceed but MUST emit a warning naming the known competing cohort IDs
- if payload reconstruction uses shards carrying multiple embedded lifecycle-bundle digests, restore MUST report that authenticity and policy were evaluated against the explicitly selected lifecycle bundle

Deprecated v1 verifier/restore order is:

1. parse artifacts and classify optional external manifest, bundle, signature, public-key, and timestamp inputs
2. validate versions, schema values, canonicalization labels, and declared format/profile identifiers
3. determine candidate shard cohorts by `manifestDigest`, `bundleDigest`, and format/profile identifiers
4. verify structural integrity:
   shard format, commitments, fragment hashes, manifest digest, bundle digest, and bundle/manifest consistency
5. reconstruct `.qenc` and the ML-KEM private key if threshold requirements are met
6. validate canonical manifest bindings and verify reconstructed `qencHash`
7. validate detached signatures over canonical manifest bytes
8. resolve bundle pin and user pin states
9. evaluate archive policy as defined in `trust-and-policy.md`
10. link timestamps/evidence to detached signature bytes
11. decide restore authorization and emit status fields

Legacy restore context selection rules:

- if an uploaded bundle is supplied, it is selected before embedded-bundle preference logic, MUST match candidate manifest bytes, and MUST itself satisfy archive policy for restore to continue
- if an uploaded canonical manifest is supplied, it can disambiguate only if it matches exactly one candidate bundle cohort; that selected candidate MUST still satisfy archive policy
- without an uploaded bundle or disambiguating manifest, restore evaluates each embedded candidate and selects the only policy-satisfying candidate if exactly one exists
- if multiple policy-satisfying embedded candidates share identical canonical manifest bytes, restore may deterministically prefer the richer satisfying bundle by descending score: valid signatures, valid strong-PQ signatures, `attachments.signatures[]` count, `attachments.publicKeys[]` count, then `attachments.timestamps[]` count
- if multiple policy-satisfying candidates remain tied after that comparison, restore fails closed and requires explicit disambiguation
- payload reconstruction may use shards carrying multiple embedded bundle digests only when those shards share the same canonical manifest bytes; authenticity and policy are then evaluated against the explicitly selected bundle context and reported as such
- no "largest cohort wins" rule

## 11. Error handling and fail-closed behavior

Quantum Vault MUST fail closed on:

- unknown major versions
- unknown magic or schema values
- unsupported canonicalization labels
- mismatched `manifestDigest`
- mismatched `bundleDigest`
- bundle/manifest inconsistency
- detached signature target digest mismatch
- malformed signature or key references that prevent safe verification
- unsupported algorithm IDs
- inconsistent shard cohorts
- mixed legacy/successor artifact families in one restore attempt
- exact archive-state or cohort-binding byte mismatch inside a selected successor cohort
- ambiguous same-state successor forks when no explicit cohort or lifecycle-bundle selection is supplied
- multiple embedded lifecycle-bundle digests inside a selected successor cohort when no explicit bundle bytes or digest are supplied
- OTS evidence that fails the supported target-linkage checks for its declared target

Current mandatory rejection examples:

1. canonical-manifest bytes do not match supported canonicalization behavior
2. `manifestDigest` mismatch
3. embedded bundle round-trips to a different canonical manifest
4. detached signature target digest does not match the manifest digest
5. bundle references missing key material required for safe verification
6. shard cohort mixes conflicting manifest digests or bundle digests
7. mixed legacy and successor shard families are supplied to one restore attempt
8. successor shards disagree on exact archive-state bytes or exact cohort-binding bytes inside one selected cohort
9. multiple valid successor cohorts exist for one `archiveId` and `stateId`, but the operator did not explicitly select one cohort or lifecycle bundle
10. one successor cohort carries multiple embedded lifecycle-bundle digests, but the operator did not explicitly select one bundle variant

Current non-rejection note for explicit successor disambiguation:

- when the operator explicitly selects a successor cohort or lifecycle bundle for an otherwise ambiguous same-state fork or multi-bundle cohort, restore may proceed, but Quantum Vault MUST warn rather than pretend that the ambiguity was resolved automatically.

Related policy consequences are defined in `trust-and-policy.md`.
Current selftest-backed vector classes, regression coverage, malformed or fail-closed cases, and any local-development example artifacts are mapped in [appendices/interoperability-and-test-vectors.md](appendices/interoperability-and-test-vectors.md).

## 12. Compatibility and version policy

Changes to the Quantum Vault format family fall into three categories depending on which specification layer they affect:

| Kind of change | Requires | Examples |
| --- | --- | --- |
| Change to canonical byte output for the same logical input | New canonicalization label | Changing key-ordering rules, number serialization, whitespace behavior |
| Change to required/optional fields, value domains, or object shapes | New schema/version identifier | Adding a required manifest field, changing a `const` identifier, widening or narrowing a type constraint |
| Change to what fields mean, what operations are permitted, or what verification outcomes are required | Semantic documentation update; may also require a new schema/version if the change also affects structure | Changing the meaning of `authPolicyCommitment`, redefining restore-gating behavior at a given policy level |

Current version-boundary rules:

- Changing canonical JSON byte rules for the manifest or `authPolicyCommitment` requires a new `canonicalization` label and a new manifest schema/version.
- Changing canonical bundle byte rules requires a new `bundleCanonicalization` label and a new bundle version.
- Adding new top-level fields to the canonical manifest requires a new manifest schema/version.
- Adding new attachment fields or new attachment families to the bundle requires a new bundle schema/version.
- Unknown fields in the canonical manifest are forbidden at every object level.
- Unknown fields in the current bundle grammar are forbidden at every object level.
- Future extensibility, if needed, MUST use an explicit versioned extension mechanism rather than silently opening current objects.

## 13. Future coverage retained for this document

This document now carries the current normative baseline, but it still needs future expansion in the following areas:

- state-changing continuity records that preserve successor `archiveId` semantics across future rewrap or reencryption
- a frozen standalone conformance corpus with stable case identifiers outside the repository tree
- future wire representation of archive-wide evidence objects, if those become first-class format artifacts
- future wire representation of `cryptoPolicy`, if it becomes a first-class format artifact
