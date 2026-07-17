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

For a consolidated descriptive index of the current shipped identifiers and version strings, see [appendices/registry.md](appendices/registry.md).

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
- [appendices/registry.md](appendices/registry.md) for a descriptive, source-backed index of current shipped identifiers and registry-style constants
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
| `.pqpk` | Detached PQ public key | May be carried as mutable bundle verification material or supplied independently as a PQ signer pin |
| `.ots` | OpenTimestamps evidence | Targets detached signature bytes, not lifecycle-bundle bytes |
| `.qvpack` | Multi-file payload bundle | Pre-encryption binary bundle for multiple files |

Artifact lifecycle summary:

- Encrypt creates a `.qenc` container from a plaintext payload
- Split creates `QVqcont-7` shards and successor lifecycle objects
- Attach updates lifecycle-bundle attachments without mutating canonical archive-state or cohort-binding bytes
- Restore reconstructs one explicitly selected successor archive/state/cohort/bundle context and gates recovery by archive policy
- Decrypt recovers the plaintext payload from `.qenc`

### 3.1 Current cryptographic role separation

Conforming implementations MUST preserve the following role boundaries when parsing artifacts, surfacing status, or building automation around the format family:

| Mechanism or field | Current role | Must not be misread as |
| --- | --- | --- |
| `.qenc` confidentiality path (`cryptoProfileId`, ML-KEM, KMAC derivation, AES-GCM, `keyCommitment`) | Confidentiality, authenticated metadata, and wrong-key rejection within one container | Signer identity, archive approval, or time evidence |
| `qencHash`, `stateId`, `cohortBindingDigest`, `authPolicyCommitment` | Fixity and binding over canonical bytes | Detached-signature approval, restore authorization by themselves, or timestamp evidence |
| Detached `.qsig` / `.sig` proofs | Cryptographic evidence that a signer key signed one declared canonical target | Automatic trust, institutional authorization, or timestamp evidence |
| `authPolicy` plus restore-time external signer pins, counting, and suite evaluation | Restore authorization rule over externally pinned, verified archive-approval signatures | A property carried by mutable bundle keys, AEAD tags, key commitments, or hashes alone |
| `.ots` proofs | Supplementary time-evidence linkage to detached signature bytes | Archive-approval signature validity or archive-policy satisfaction |

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
- the shipped browser Attach workflow imports archive-approval, maintenance, and source-evidence detached signatures through an explicit channel selector; imported `.pqpk` bytes become bundle verification material, while the operator must supply a pin independently again at verify/restore time

### 4.4 Detached-signature target mappings

Current detached-signature target mappings are:

| Signature family | Target object | Required `targetType` | Counting role |
| --- | --- | --- | --- |
| archive approval | archive-state descriptor | `archive-state` | counts toward archive policy only after its signer matches an independent restore-time pin |
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
| keyLen | 4 bytes (Uint32 BE) | MUST be `1568` for the current ML-KEM-1024 profile |
| encapsulatedKey | exactly 1568 bytes | ML-KEM-1024 ciphertext |
| containerNonce | 12 bytes | container nonce / IV root |
| kdfSalt | 16 bytes | random salt for KMAC |
| metaLen | 2 bytes (Uint16 BE) | length of `metaJSON`; MUST be in `1..4096` for current writers and readers |
| metaJSON | metaLen bytes UTF-8 | metadata |
| keyCommitment | 32 bytes | required `SHA3-256(Kenc)` |
| ciphertext | remaining bytes | AES-GCM ciphertext stream |

### 5.2 Current metadata contract

For `fmt = "QVv1-5-0"`, `metaJSON` is a closed object with exactly these 19
members: `KEM`, `KDF`, `AEAD`, `aead_mode`, `iv_strategy`, `fmt`,
`hasKeyCommitment`, `payloadFormat`, `payloadLength`, `chunkSize`, `chunkCount`,
`cryptoProfileId`, `kdfTreeId`, `noncePolicyId`, `nonceMode`, `counterBits`,
`maxChunkCount`, `aadPolicyId`, and `domainStrings`. `domainStrings` is itself a
closed object with exactly `kdf`, `iv`, `kenc`, and `kiv`. Missing or unknown
members at either level MUST be rejected. Algorithm and profile labels are
normative dispatch constraints, not descriptive annotations.

| Field | Current emitted value or shape | Current acceptance note |
| --- | --- | --- |
| `KEM` | `ML-KEM-1024` | MUST equal this exact value |
| `KDF` | `KMAC256` | MUST equal this exact value |
| `AEAD` | `AES-256-GCM` | MUST equal this exact value |
| `fmt` | `QVv1-5-0` | MUST match the supported container metadata format |
| `cryptoProfileId` | `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2` | required by current validation |
| `kdfTreeId` | `QV-KDF-TREE-v2` | required by current validation |
| `aead_mode` | `single-container-aead` or `per-chunk-aead` | MUST be one of the supported current AEAD modes |
| `iv_strategy` | `single-iv` or `kmac-prefix64-ctr32-v3` | MUST match `aead_mode` |
| `noncePolicyId` | `QV-GCM-RAND96-v1` or `QV-GCM-KMACPFX64-CTR32-v3` | MUST match `aead_mode` |
| `nonceMode` | `random96` or `kmac-prefix64-ctr32` | MUST match `aead_mode` |
| `counterBits` | `0` or `32` | MUST match `aead_mode` |
| `maxChunkCount` | `1` or `4294967295` | MUST match `aead_mode` |
| `aadPolicyId` | `QV-AAD-HEADER-CHUNK-v1` | required by current validation |
| `hasKeyCommitment` | `true` | current containers require a key commitment |
| `payloadFormat` | `wrapped-v1` | MUST equal this exact value |
| `payloadLength` | positive safe integer | wrapped cleartext payload length |
| `chunkSize` | `8388608` | fixed runtime chunk size for the current format |
| `chunkCount` | positive safe integer | MUST equal `ceil(payloadLength / chunkSize)` for per-chunk mode and `1` for single-container mode |
| `domainStrings.kdf` | `quantum-vault:kdf:v2` | required by current validation |
| `domainStrings.iv` | `quantum-vault:chunk-iv:v2` | required by current validation |
| `domainStrings.kenc` | `quantum-vault:kenc:v2` | required by current validation |
| `domainStrings.kiv` | `quantum-vault:kiv:v2` | required by current validation |

### 5.3 Payload and private metadata

Current private payload metadata for `wrapped-v1` is a closed object with exactly
four members. Missing, duplicate, or unknown members MUST be rejected after AEAD
authentication and before plaintext is returned or published.

| Field | Current required value or shape | Validation rule |
| --- | --- | --- |
| `originalFilename` | `null` or a well-formed Unicode string | The complete encoded private object, including this value, MUST remain within the shared byte limit below |
| `timestamp` | canonical UTC ISO-8601 with exactly millisecond precision, for example `2026-07-17T12:34:56.789Z` | MUST be exactly 24 ASCII bytes and round-trip through calendar validation without normalization |
| `fileHash` | 128 lowercase hexadecimal characters | MUST equal `SHA3-512(fileBytes)` |
| `originalLength` | positive safe integer no greater than the current 1 GiB plaintext limit | MUST equal the recovered `fileBytes` length exactly |

Current `wrapped-v1` payload format is:

```text
[uint32be privateMetaLen][privateMetaJSON][fileBytes]
```

`privateMetaLen` MUST be in `1..4096`; writers and readers MUST enforce the same
non-bypassable upper bound. Both public and private metadata are decoded with
fatal UTF-8 and duplicate-key rejection. After authentication, readers MUST
validate the closed private schema, compare `originalLength`, recompute
`SHA3-512(fileBytes)`, and reject on either mismatch before returning plaintext.
The ciphertext length MUST equal `payloadLength + 16 * chunkCount`, including one
AES-GCM tag per chunk. Implementations MUST reject unsafe-integer overflow before
this calculation and MUST reject both truncated ciphertext and trailing bytes.

Strict-current migration note: canonical output from the shipped JavaScript and
Rust writers remains valid. Artifacts using false algorithm/profile labels,
missing or unknown public members, a non-1568-byte encapsulated key, or public
metadata larger than 4096 bytes are now invalid for normal decrypt, split, and
restore processing. Authenticated private objects with missing or extra members,
noncanonical timestamps, non-lowercase or incorrect hashes, mismatched lengths,
or more than 4096 encoded bytes are likewise invalid. This includes Rust artifacts
created with a noncanonical custom timestamp override; default canonical Rust
writer timestamps remain compatible. These artifacts MUST NOT be reinterpreted or
accepted through a larger caller-supplied limit. Any future inspection-only legacy
path must be explicitly named, byte-preserving, non-decrypting, and separate from
current-format acceptance. Canonical current JavaScript writer bytes are unchanged.

When multiple files are archived, the payload bytes are a `.qvpack` bundle detected
by magic `QVB1`, not by filename.

#### 5.3.1 QVPACK v1 binary profile

All integers are unsigned and big-endian:

```text
magic        4 bytes   ASCII "QVB1"
version      1 byte    0x01
entryCount   2 bytes
entries      entryCount repetitions of:
  nameLen    2 bytes
  name       nameLen bytes of strict UTF-8
  dataLen    4 bytes
  data       dataLen bytes
```

The current reader and writer MUST enforce one non-raiseable resource profile:

- `entryCount` is in `1..4096`;
- each name is in `1..255` encoded UTF-8 bytes;
- each entry payload is at most 1,073,741,824 bytes;
- the sum of entry payload bytes is at most 1,073,741,824 bytes; and
- the complete encoded QVPACK, including framing and names, is at most
  1,073,741,824 bytes.

Names MUST decode as fatal UTF-8, MUST be non-empty, and MUST NOT contain `/`,
`\\`, or NUL. Writers MUST reject unpaired UTF-16 surrogates before encoding.
Because each name is already length-delimited, an initial UTF-8 BOM is filename
data and MUST decode to U+FEFF rather than being stripped as a transport marker.
Exact duplicate decoded names are forbidden. Filesystem case folding and Unicode
normalization are not part of QVPACK name equality; extraction code must address
those platform alias risks separately. Empty entry payloads are permitted.

Readers MUST check lengths with safe arithmetic before slicing or allocating,
consume exactly `entryCount` entries, and reject truncation and trailing bytes.
Resource-limit rejection is distinct at the core API from malformed-format
rejection. Callers MUST NOT widen this current profile.

Strict-current migration note: canonical QVPACK v1 output within this profile is
byte-for-byte unchanged. Previously accepted bundles with invalid UTF-8 names,
exact duplicate names, more than 4096 entries, names longer than 255 UTF-8 bytes,
or any 1 GiB limit violation are now invalid rather than reinterpreted. Writer
input containing an unpaired surrogate is rejected instead of being silently
serialized with a Unicode replacement character. No wire-version migration is
required for conforming existing bundles; an inspection-only legacy path, if ever
added, must remain separate from normal decrypt/extract acceptance.

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
8. require the exact `wrapped-v1` private schema, compare `originalLength`, and
   compare `privateMeta.fileHash` with a fresh `SHA3-512` over recovered file
   bytes before returning plaintext

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
| `encapBlobLen` | 4 bytes (Uint32 BE) | MUST be `1568` for the current profile during reconstruction |
| `encapBlob` | exactly 1568 bytes | copied ML-KEM-1024 ciphertext |
| `containerNonce` | 12 bytes | copied from `.qenc` |
| `kdfSalt` | 16 bytes | copied from `.qenc` |
| `qencMetaLen` | 2 bytes (Uint16 BE) | length of duplicated `.qenc` metadata; MUST be in `1..4096` |
| `qencMetaBytes` | `qencMetaLen` bytes UTF-8 | duplicated `.qenc` metadata |
| `keyCommitLen` | 1 byte | key commitment length |
| `keyCommitBytes` | `keyCommitLen` bytes | required `SHA3-256(Kenc)` |
| `shardIndex` | 2 bytes (Uint16 BE) | 0-based shard index |
| `shareLen` | 2 bytes (Uint16 BE) | MUST be `3169` for a current ML-KEM-1024 private-key share |
| `shareBytes` | exactly 3169 bytes | one dependency-compatible Shamir share: one coordinate byte plus 3168 secret bytes |
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

### 6.4 Authenticated reconstruction geometry

Outer shard `metaJSON` geometry fields are redundant presentation copies and MUST
NOT drive allocation, ciphertext length, or Reed-Solomon decoding. Reconstruction
uses these sources in order:

1. the selected canonical archive-state and cohort-binding bytes define the
   `containerId`, `qencHash`, `n`, `k`, parity, threshold, share commitments, and
   fragment-body hashes;
2. at least one copied QENC header MUST rebuild to exact bytes whose
   `SHA3-512(header)` equals the archive-state `containerId`;
3. that header's metadata MUST pass the same closed `QVv1-5-0` validator as a
   standalone `.qenc` parser and MUST match the archive-state profile and
   geometry;
4. the reconstructed full container MUST strict-parse and match both
   `containerId` and `qencHash` before it is returned.

A copied header that fails these checks is ignored as a separate invalid facet;
it does not invalidate an independently committed share or fragment body. At
least one valid header copy is required. Two different exact header byte strings
claiming the same `containerId` are an ambiguity and MUST fail closed.

For current Reed-Solomon framing, let:

```text
encodeSize = floor(255 / n) * n
inputSize  = encodeSize * k / n
symbolSize = inputSize / k
fragLen_i  = ceil(cipherLen_i / inputSize) * symbolSize
```

`cipherLen_i` is `payloadLength + 16` in single-container mode. In per-chunk
mode it is `min(chunkSize, remainingPayload) + 16`. Each shard fragment stream
MUST contain exactly `chunkCount` records, each `[uint32be fragLen_i][fragment]`,
and MUST end exactly after the final record. Short records are not padded and
long records are not truncated. The exact total stream length is derived before
body hashing so an oversized extra can be quarantined without attacker-directed
allocation.

An invalid share length or share commitment is skipped for Shamir purposes. An
invalid fragment-stream length, fragment record, or body commitment is an RS
erasure. Recovery MAY continue only while at least `t` valid shares exist and
the number of missing/invalid fragment bodies is at most `parity / 2`. Duplicate
or out-of-range shard indices are cohort ambiguity errors and fail closed.

Current JavaScript reconstruction enforces a non-raiseable ciphertext ceiling of
`1074790400` bytes (1 GiB + 1 MiB); an internal caller may only lower it. Checked
safe-integer arithmetic precedes every derived length and allocation. Canonical
current shard and QENC bytes are unchanged by these reader rules.

### 6.5 Split and same-state resharing semantics

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
| `.qsig` | Quantum Signer detached signature, major version 2, context `quantum-signer/v2`; accepted for archive-approval, maintenance, or source-evidence channels when the selected target bytes match |
| `.sig` | Stellar detached signature JSON with schema `stellar-signature/v2`; same channel and target-family rules as `.qsig` |
| `.pqpk` | Detached PQ public key; bundle-carried use is non-trust verification material, independently supplied use is a signer pin |
| `.ots` | OpenTimestamps proof linked to detached signature bytes |

Current acceptance boundaries:

- `.qsig` and `.sig` are integration contracts; this specification does not restate their full upstream format definitions
- the shipped browser Attach workflow imports `.qsig` / `.sig` through the selected evidence channel: archive approval, maintenance, or source evidence
- external signatures used at restore are archive-approval signatures over canonical archive-state bytes
- bundled lifecycle signatures may target archive-state, transition-record, or source-evidence bytes according to their declared family
- bundle-carried `.pqpk` material can constrain cryptographic verification but is not a trust anchor; only independently supplied `.pqpk` input can authorize policy
- `.ots` timestamps target detached signature bytes, not lifecycle-bundle bytes
- `.ots` timestamps are timestamp evidence only and do not satisfy archive policy
- archive-approval attach binds signatures to `targetType = archive-state`, `targetRef = state:{stateId}`, and the SHA3-512 digest of the canonical archive-state descriptor
- maintenance attach requires a canonical transition-record target already present in the selected lifecycle bundle and binds signatures to `targetType = transition-record`, `targetRef = transition:sha3-512:{transitionRecordDigest}`, and that transition-record digest
- source-evidence attach requires canonical source-evidence JSON, stores that object in `sourceEvidence[]` if needed, and binds signatures to `targetType = source-evidence`, `targetRef = source-evidence:sha3-512:{sourceEvidenceDigest}`, and that source-evidence digest
- only archive-approval signatures whose signers match independent restore-time pins count toward archive policy; maintenance and source-evidence signatures are reported separately
- OTS acceptance and linkage do not require `apparentlyComplete` / `completeProof` to be true; those fields are reporting outputs, not acceptance preconditions
- `apparentlyComplete` / `completeProof` are derived by the current implementation from proof-name keywords first (`initial`, `pending`, `incomplete` => incomplete; `complete`, `completed`, `confirmed`, `upgraded` => complete), with proof size `>= 1024` bytes used only as a fallback when no keyword matches
- the current implementation does not treat `apparentlyComplete` / `completeProof` as validation of a Bitcoin attestation chain
- user-facing restore summaries should label complete-looking proofs as `OTS proof appears complete (heuristic)` and should state that timestamp evidence does not satisfy archive policy

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
11. report embedded-key-only and bundle-key-only cryptographic verification separately; neither source is an external trust anchor and neither can make a signature policy-eligible
12. evaluate archive policy using unique externally pinned `archiveApprovalSignatures` only; current external inputs are restore-time `.pqpk` files and the restore-time expected Stellar signer
13. link timestamps to detached signature bytes, report linkage failures as timestamp-evidence warnings, and emit separate transition and source-evidence reports
14. emit distinct status fields including `archiveApprovalCryptographicallyVerified`, `archiveApprovalSignatureVerified` (externally authorized legacy-safe meaning), `maintenanceSignatureVerified`, `sourceEvidenceSignatureVerified`, `otsEvidenceLinked`, `bundledKeyVerified`, `externallyPinned`, and `authorizedForPolicy`; deprecated `bundlePinned` MUST remain false

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

Current attach-time OTS failure rule:

- the shipped Attach workflow resolves each imported `.ots` proof against the currently known detached signature bytes and MUST fail closed if the proof matches zero or multiple signatures

Current non-rejection note for explicit successor disambiguation:

- when the operator explicitly selects a successor cohort or lifecycle bundle for an otherwise ambiguous same-state fork or multi-bundle cohort, restore may proceed, but Quantum Vault MUST warn rather than pretend that the ambiguity was resolved automatically

### 9.1 CLI fail-closed checklist

The Node.js CLI is a non-browser adapter over the same successor lifecycle parsers and restore verifier. A CLI workflow is conforming only when it preserves these fail-closed checks:

- `qv inspect` may structurally summarize supported detached artifacts, but restore and verify policy decisions MUST still use target-specific verification paths.
- `qv canonicalize` MUST only canonicalize recognized lifecycle JSON artifacts and MUST reject binary artifacts or unsupported JSON.
- `qv verify` MUST evaluate archive approval over canonical archive-state descriptor bytes; lifecycle-bundle bytes are mutable evidence carriers and are not the archive-approval signing target.
- `qv restore --dry-run` and write-mode `qv restore` MUST apply the same archiveId, stateId, cohortId, exact archive-state bytes, exact cohort-binding bytes, lifecycle-bundle selection, signature target, and authenticity-policy checks.
- `qv restore` write mode MUST write no output when archive policy is not satisfied.
- `qv reshare` MUST preserve exact archive-state bytes and stateId; same-state resharing is not archive re-approval.
- Direct symlink input paths MUST be rejected unless the operator explicitly supplies `--allow-symlink`.
- CLI JSON errors MUST preserve a stable `qvCode` so automation can distinguish usage errors, quorum failures, ambiguity, policy failure, and restored-integrity failure without parsing prose.

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
