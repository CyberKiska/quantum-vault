# Format specification

Status: Release Candidate
Type: Normative
Audience: implementers, auditors, interoperability tool authors, test-vector maintainers
Scope: current-state normative baseline for Quantum Vault artifact formats and verifier behavior
Out of scope: whitepaper rationale, detailed threat analysis, archive-class policy, long-term renewal design
Primary implementation sources: `README.md`, `series/SERIES-STANDARTS.md`, implementation code
Historical consolidation source: `process/IMPLEMENTATION-NOTES.md`

## Role

This document is the normative home for artifact structure, canonicalization, binding semantics, and verifier behavior.
It consolidates the currently implemented format rules that were previously split across `README.md` and the former spec-oriented version of `process/IMPLEMENTATION-NOTES.md`.

It is intentionally paired with `trust-and-policy.md`:

- `format-spec.md` defines bytes, fields, schemas, attachment points, and restore/verifier flow
- `trust-and-policy.md` defines what signatures, pinning, and policy outcomes mean

## Scope

This document covers the current Quantum Vault artifact family and verifier behavior for `.qenc`, `.qcont`, canonical manifests, manifest bundles, and the detached authenticity artifacts they currently accept.
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
- `src/core/crypto/qcont/build.js`, `src/core/crypto/qcont/attach.js`, and `src/core/crypto/qcont/restore.js` for shard layout, bundle attachment, and restore candidate selection
- `src/core/crypto/manifest/archive-manifest.js`, `src/core/crypto/manifest/manifest-bundle.js`, and `src/core/crypto/manifest/jcs.js` for manifest, bundle, and canonicalization behavior
- `src/core/crypto/auth/verify-signatures.js`, `src/core/crypto/auth/qsig.js`, `src/core/crypto/auth/stellar-sig.js`, and `src/core/crypto/auth/opentimestamps.js` for detached attachment handling relevant to format acceptance
- `docs/glossary.md`, `docs/trust-and-policy.md`, and `docs/security-model.md` for shared terminology and cross-document semantic constraints

External references already used elsewhere in the repository:

- RFC 4648 for Base64 encoding conventions
- RFC 8785 as a comparison point only; `QV-C14N-v1` is not claimed as full JCS
- FIPS 202 for `SHA3-256` and `SHA3-512`
- SP 800-185 for KMAC256-based derivation inputs and commitment-related terminology
- SP 800-38D for AES-GCM AEAD assumptions
- FIPS 203 for ML-KEM-1024 naming and profile context

## Current implementation status

Implemented now:

- the supported versions, schema IDs, and artifact boundaries listed in Section 1
- canonical manifest export and embedding under `QV-C14N-v1`
- detached signatures over canonical manifest bytes only
- embedded or external bundle, signature, key, and timestamp inputs during restore
- current unknown-field handling and deterministic restore candidate selection as documented in the current sections of this file
- active compatibility appendices for canonicalization, external-artifact handling, and current vector coverage under `docs/appendices/`

Not yet first-class in the current implementation:

- a stable archive-wide `archiveId` that survives future rewrap or reencryption
- a frozen standalone interoperability corpus versioned separately from the repository examples and selftests

## Future work and non-normative notes

Statements explicitly labeled as future or recommended direction are non-normative.
Current likely promotion targets, but not current compatibility rules, include:

- expanding the active appendices with additional vectors, malformed cases, and machine-consumable corpus material
- introducing archive-wide identity material that survives future rewrap or reencryption
- converging the long-term format stack toward RFC 8785 for canonical signable manifest bytes, RFC 8610 / CDDL for formal artifact schema description, and an OAIS-oriented package model for archival packaging and renewal semantics; until that work is completed, the current compatibility baseline remains the project-defined `QV-C14N-v1` profile and the code-defined current schemas

## 1. Status and conformance

This file describes the currently supported Quantum Vault format family as documented in the repository today.
The supported current boundary is:

- `.qenc` binary container with magic `QVv1`
- `.qenc` metadata format identifier `QVv1-5-0`
- `.qcont` binary shard with magic `QVC1`
- `.qcont` shard metadata format identifier `QVqcont-6`
- canonical manifest schema/version `quantum-vault-archive-manifest/v2`
- manifest canonicalization label `QV-C14N-v1`
- manifest bundle type/version `QV-Manifest-Bundle` v1
- detached PQ signature acceptance: Quantum Signer major version 2 with context `quantum-signer/v2`
- detached Stellar signature acceptance: `stellar-signature/v2`

Current conformance rules:

- Parsers MUST reject unknown major versions, unknown magic values, unknown schema values, and unsupported canonicalization labels.
- Parsers MUST reject mismatched manifest, bundle, or shard digests.
- Parsers MUST reject malformed or unresolved attachment references that would make verification unsafe.
- Parsers MUST NOT infer algorithms heuristically from filenames, key lengths, or wrapper type.

## 2. Notation and conventions

Quantum Vault-specific conventions:

- Binary Quantum Vault formats use big-endian length and index fields.
- Text fields are UTF-8.
- Hex digests are lowercase.
- Base64 fields use standard RFC 4648 Base64 with no line breaks.
- `SHA3-512(x)` means SHA3-512 over the exact byte sequence `x`.
- `manifestBytes` means the canonical byte serialization of the manifest under `QV-C14N-v1`.

Canonicalization convention:

- `QV-C14N-v1` is the project-defined canonical JSON label used for the canonical manifest and for the bundle's embedded canonical-manifest binding.
- `QV-C14N-v1` is not claimed to be full RFC 8785 JCS.

Key terminology rule used by this file:

- `privateKey` means asymmetric secret key material, such as the ML-KEM decryption key currently exported in the file named `secretKey.qkey`
- `publicKey` means asymmetric public key material
- `secretKey` means symmetric secret material, such as `Kenc` or `Kiv`

The current file name `secretKey.qkey` is treated as a legacy operational name, not as the canonical terminology for the asymmetric object it contains.

## 3. Artifact model

| Artifact | Role in the format family | Relationship to other artifacts |
| --- | --- | --- |
| `.qenc` | Encrypted container | The primary ciphertext object |
| `.qcont` | Threshold shard | Carries one shard's recovery state plus embedded manifest/bundle |
| `*.qvmanifest.json` | Canonical signable manifest | Detached-signature payload |
| `*.extended.qvmanifest.json` | Mutable manifest bundle | Carries manifest + policy + attachments |
| `.qsig` | Detached PQ signature | Signs canonical manifest bytes |
| `.sig` | Detached Stellar/Ed25519 signature proof | Signs canonical manifest bytes |
| `.pqpk` | Detached PQ public key | Used for bundle pinning or restore-time user pinning |
| `.ots` | OpenTimestamps evidence | Targets detached signature bytes, not the bundle |
| `.qvpack` | Multi-file payload bundle | Pre-encryption binary bundle of multiple files; becomes the plaintext payload inside `.qenc` |

Artifact lifecycle summary:

- When multiple files are archived, Encrypt first bundles them into a `.qvpack` payload.
- Encrypt creates a `.qenc` container from the plaintext payload (single file or `.qvpack`).
- Split creates `.qcont` shards and a canonical manifest.
- Attach creates or updates a manifest bundle.
- Restore may use embedded or externally supplied manifests, bundles, signatures, keys, and timestamps.
- Decrypt recovers the plaintext payload; if it is a `.qvpack`, the individual files are extracted.
- Detached signatures always target canonical manifest bytes only.

## 4. Current archive identity and binding model

Current identity and binding objects are layered rather than unified under a single archive-wide identifier:

- `qenc.qencHash` is the primary current-state fixity/authenticity anchor and is `SHA3-512` over the full `.qenc` bytes.
- `qenc.containerId` is a secondary identifier and is currently `SHA3-512(qenc-header-bytes)`.
- `manifestDigest` is `SHA3-512` over canonical manifest bytes.
- `authPolicyCommitment` binds restore-relevant authenticity policy semantics from canonical-manifest bytes to the mutable bundle policy object.

Current binding invariants:

- Detached signatures sign canonical manifest bytes only.
- Bundle mutation MUST NOT mutate the canonical manifest bytes.
- `manifestDigest` MUST match the canonical manifest bytes embedded in the bundle.
- `authPolicyCommitment` in the manifest MUST match the concrete `authPolicy` carried by the bundle.

Not yet present as a first-class artifact:

- a stable `archiveId` that survives future rewrap or reencryption

## 5. Canonicalization and canonical manifest

### 5.1 Canonicalization

The canonical manifest uses project-defined canonical JSON `QV-C14N-v1`.
Current behavior is:

- the same canonical bytes are exported as `*.qvmanifest.json`
- the same canonical bytes are embedded into every `.qcont` shard
- the same canonical bytes are embedded inside every manifest bundle
- detached signatures are always computed over those canonical bytes

Because detached signatures depend on exact bytes:

- Quantum Vault MUST sign only bytes produced by the supported canonicalizer
- Quantum Vault MUST NOT claim full RFC 8785 compliance unless it implements and labels full RFC 8785

Detailed current edge cases, examples, and unsupported cases for `QV-C14N-v1` are defined in [appendices/canonicalization-profile.md](appendices/canonicalization-profile.md).

### 5.2 Canonical manifest contract

The current canonical manifest is generated at split stage with schema/version `quantum-vault-archive-manifest/v2`.

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
Canonical key order is determined by `QV-C14N-v1`, not by the order shown here.

### 5.2.1 Current top-level manifest fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `schema` | string | MUST be `quantum-vault-archive-manifest/v2` |
| `version` | integer | MUST be `2` |
| `manifestType` | string | MUST be `archive` |
| `canonicalization` | string | MUST be `QV-C14N-v1` |
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
| `format` | string | MUST identify the supported `.qenc` metadata format; current emitter uses `QVv1-5-0` |
| `aeadMode` | string | MUST be `single-container-aead` or `per-chunk-aead` |
| `ivStrategy` | string | MUST match the selected `aeadMode`; current supported values are `random96` and `kmac-prefix64-ctr32-v3` |
| `chunkSize` | integer | positive chunk size used for current encryption layout |
| `chunkCount` | integer | positive count; MUST remain within the nonce-policy bound |
| `payloadLength` | integer | positive plaintext payload length carried by `.qenc` |
| `hashAlg` | string | MUST be `SHA3-512` |
| `qencHash` | string | lowercase hex `SHA3-512` over the full `.qenc` bytes |
| `primaryAnchor` | string | MUST be `qencHash` |
| `containerId` | string | lowercase hex secondary identifier for the current `.qenc` header |
| `containerIdRole` | string | MUST be `secondary-header-id` |
| `containerIdAlg` | string | MUST be `SHA3-512(qenc-header-bytes)` |

### 5.2.3 Current `sharding`, `authPolicyCommitment`, and `shardBinding` fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `sharding.shamir.threshold` | integer | positive threshold for share recovery |
| `sharding.shamir.shareCount` | integer | positive Shamir share count |
| `sharding.reedSolomon.n` | integer | positive total shard count |
| `sharding.reedSolomon.k` | integer | positive minimum fragment count for erasure recovery |
| `sharding.reedSolomon.parity` | integer | current parity count |
| `sharding.reedSolomon.codecId` | string | current builder emits `QV-RS-ErasureCodes-v1` |
| `authPolicyCommitment.alg` | string | MUST be `SHA3-512` |
| `authPolicyCommitment.canonicalization` | string | MUST be `QV-C14N-v1` |
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
    "canonicalization": "QV-C14N-v1",
    "value": "...128 hex chars..."
  },
  "canonicalization": "QV-C14N-v1",
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
  "schema": "quantum-vault-archive-manifest/v2",
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
  "version": 2
}
```

### 5.3 Current manifest parsing behavior

Current canonical-manifest parsing behavior is:

- manifest input bytes MUST already be canonical `QV-C14N-v1` JSON
- parsers validate the required current fields and the current binding and algorithm identifiers
- unknown additional manifest fields are not currently rejected solely for being additional fields
- if additional manifest fields are present, they remain part of the canonical manifest bytes and therefore part of the detached-signature payload
- compatibility still fails closed on unsupported schema, version, canonicalization, and required-binding mismatches

## 6. Manifest bundle

### 6.1 Purpose and top-level structure

The manifest bundle is a self-contained mutable JSON object.
It is not the detached-signature payload.

The current top-level structure is:

- `type = "QV-Manifest-Bundle"`
- `version = 1`
- `bundleCanonicalization = "QV-C14N-v1"`
- `manifestCanonicalization = "QV-C14N-v1"`
- `manifest`
- `manifestDigest = { alg: "SHA3-512", value: SHA3-512(canonical manifest bytes) }`
- `authPolicy`
- `attachments.publicKeys[]`
- `attachments.signatures[]`
- `attachments.timestamps[]`

Naming behavior:

- split exports canonical signable manifest as `*.qvmanifest.json`
- attach exports the self-contained bundle as `*.extended.qvmanifest.json`
- extracting a signable manifest from an existing bundle may use `*.signable.qvmanifest.json`

### 6.1.1 Current top-level bundle fields

| Field | Type | Current constraint or meaning |
| --- | --- | --- |
| `type` | string | MUST be `QV-Manifest-Bundle` |
| `version` | integer | MUST be `1` |
| `bundleCanonicalization` | string | MUST be `QV-C14N-v1` |
| `manifestCanonicalization` | string | MUST be `QV-C14N-v1` |
| `manifest` | object | REQUIRED canonical-manifest object; canonicalized independently from the mutable bundle |
| `manifestDigest.alg` | string | MUST be `SHA3-512` |
| `manifestDigest.value` | string | lowercase hex `SHA3-512` over canonical manifest bytes |
| `authPolicy.level` | string | MUST be `integrity-only`, `any-signature`, or `strong-pq-signature` |
| `authPolicy.minValidSignatures` | integer | positive integer, currently normalized with minimum `1` |
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
| `suite` | string | normalized supported signature suite |
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
| `suite` | string | normalized signature suite for the detached artifact |
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
  "bundleCanonicalization": "QV-C14N-v1",
  "manifest": { "...": "canonical manifest object" },
  "manifestCanonicalization": "QV-C14N-v1",
  "manifestDigest": {
    "alg": "SHA3-512",
    "value": "...128 hex chars..."
  },
  "type": "QV-Manifest-Bundle",
  "version": 1
}
```

### 6.4 Current bundle parsing behavior

Current canonical-bundle parsing behavior is:

- bundle input bytes MUST already be canonical `QV-C14N-v1` JSON under the current normalized bundle schema
- bundle input bytes MUST already include the normalized top-level shape, including `manifestDigest.alg`, `manifestDigest.value`, and explicit `attachments.publicKeys`, `attachments.signatures`, and `attachments.timestamps` arrays
- parsers normalize bundle content to the current known field set and then require byte-for-byte equality with the canonical bytes of that normalized output
- unknown additional bundle fields are therefore rejected in current canonical bundle inputs
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

### 8.1 Binary layout

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

### 8.2 Current shard metadata contract

Current `.qcont` emitter metadata and compatibility notes are:

| Field | Current emitted value or shape | Purpose or current note |
| --- | --- | --- |
| `containerId` | lowercase hex string | summary copy of the manifest/header-derived container identifier |
| `alg.KEM` | `ML-KEM-1024` | descriptive algorithm label |
| `alg.KDF` | `KMAC256` | descriptive algorithm label |
| `alg.AEAD` | `AES-256-GCM` | descriptive algorithm label |
| `alg.RS` | `ErasureCodes` | descriptive erasure-coding label |
| `alg.fmt` | `QVqcont-6` | MUST match the supported shard metadata format |
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

### 8.3 Embedded manifest and bundle invariants

Current shard invariants:

- every `.qcont` shard embeds the canonical manifest
- every currently emitted `.qcont` shard embeds the current manifest bundle
- `manifestDigest` MUST equal `SHA3-512(manifestBytes)`
- if `bundleBytes` exist, `bundle.manifest` canonical bytes MUST equal `manifestBytes`
- if `bundleBytes` exist, `bundle.manifestDigest.value` MUST equal the embedded `manifestDigest`

### 8.4 Current split/combine semantics

Current split behavior:

- parse the `.qenc` header
- split the ML-KEM private key with Shamir secret sharing
- split ciphertext with Reed-Solomon erasure coding
- compute threshold `t = k + (n-k)/2`
- embed both canonical manifest and initial bundle into each shard

Current combine/restore behavior:

- classify provided artifacts
- resolve archive context deterministically from embedded or uploaded manifest/bundle material
- never use a "largest cohort wins" rule
- verify shard commitments and digests before reconstruction
- reconstruct the ML-KEM private key and `.qenc` only from a consistent cohort
- verify `qencHash` from the canonical manifest before allowing decrypt flow

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
- bundle signatures target the canonical manifest only
- bundled or external `.pqpk` material may be used for signer pinning
- `.ots` timestamps target detached signature bytes, not the bundle as a whole

Detailed current acceptance, linkage, deduplication, and ambiguity rules for these detached artifacts are defined in [appendices/external-artifacts.md](appendices/external-artifacts.md).

## 10. Verification and restore algorithm

Current verifier/restore order is:

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

Current restore context selection rules:

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
- OTS evidence that fails the supported target-linkage checks for its declared target

Current mandatory rejection examples:

1. canonical-manifest bytes do not match supported canonicalization behavior
2. `manifestDigest` mismatch
3. embedded bundle round-trips to a different canonical manifest
4. detached signature target digest does not match the manifest digest
5. bundle references missing key material required for safe verification
6. shard cohort mixes conflicting manifest digests or bundle digests

Related policy consequences are defined in `trust-and-policy.md`.
Current selftest-backed vector classes, regression coverage, malformed or fail-closed cases, and any local-development example artifacts are mapped in [appendices/interoperability-and-test-vectors.md](appendices/interoperability-and-test-vectors.md).

## 12. Future coverage retained for this document

This document now carries the current normative baseline, but it still needs future expansion in the following areas:

- a final archive-wide identity primitive if `archiveId` is introduced
- a frozen standalone conformance corpus with stable case identifiers outside the repository tree
- future wire representation of archive-wide evidence objects, if those become first-class format artifacts
- future wire representation of `cryptoPolicy`, if it becomes a first-class format artifact
