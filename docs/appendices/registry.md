# Current Identifier Registry

Status: Release Candidate
Type: Descriptive compatibility appendix
Audience: implementers, auditors, interoperability tool authors, maintainers
Scope: consolidated current identifier and registry-style values for the shipped successor-family surface
Out of scope: defining new semantics, changing policy meaning, or reserving future version strings

## Role

This appendix is a descriptive index of the current shipped identifiers already defined by the implementation and owner docs.
It does not create a new semantics layer.
[`format-spec.md`](../format-spec.md), [`trust-and-policy.md`](../trust-and-policy.md), and the referenced implementation modules remain the owners of meaning and acceptance behavior.

## Sources

Current values in this appendix are traced to:

- `src/core/crypto/constants.js`
- `src/core/crypto/aead.js`
- `src/core/crypto/policy.js`
- `src/core/crypto/kdf.js`
- `src/core/crypto/lifecycle/artifacts.js`
- `src/core/crypto/qcont/lifecycle-shard.js`
- `src/core/crypto/auth/qsig.js`
- `src/core/crypto/auth/signature-suites.js`
- `src/core/crypto/auth/opentimestamps.js`
- `src/core/crypto/manifest/jcs.js`
- `src/core/crypto/manifest/auth-policy.js`

## 1. Wire, schema, and artifact identifiers

| Identifier class | Current value | Source |
| --- | --- | --- |
| `.qenc` container magic | `QVv1` | `src/core/crypto/constants.js` |
| `.qenc` metadata format identifier | `QVv1-5-0` | `src/core/crypto/constants.js` |
| `.qcont` shard magic | `QVC1` | `src/core/crypto/qcont/lifecycle-shard.js` |
| `.qcont` shard format identifier | `QVqcont-7` | `src/core/crypto/qcont/lifecycle-shard.js` |
| `.qcont` artifact family | `successor-lifecycle-v1` | `src/core/crypto/qcont/lifecycle-shard.js` |
| Archive-state schema | `quantum-vault-archive-state-descriptor/v1` | `src/core/crypto/lifecycle/artifacts.js` |
| Cohort-binding schema | `quantum-vault-cohort-binding/v1` | `src/core/crypto/lifecycle/artifacts.js` |
| Transition-record schema | `quantum-vault-transition-record/v1` | `src/core/crypto/lifecycle/artifacts.js` |
| Source-evidence schema | `quantum-vault-source-evidence/v1` | `src/core/crypto/lifecycle/artifacts.js` |
| Lifecycle-bundle type | `QV-Lifecycle-Bundle` | `src/core/crypto/lifecycle/artifacts.js` |
| Archive-state version | `1` | `src/core/crypto/lifecycle/artifacts.js` |
| Cohort-binding version | `1` | `src/core/crypto/lifecycle/artifacts.js` |
| Transition-record version | `1` | `src/core/crypto/lifecycle/artifacts.js` |
| Source-evidence version | `1` | `src/core/crypto/lifecycle/artifacts.js` |
| Lifecycle-bundle version | `1` | `src/core/crypto/lifecycle/artifacts.js` |

Related current binding labels:

| Label | Current value | Source |
| --- | --- | --- |
| Archive-state type default | `archive-state` | `src/core/crypto/lifecycle/artifacts.js` |
| Cohort type default | `shard-cohort` | `src/core/crypto/lifecycle/artifacts.js` |
| Transition type default | `same-state-resharing` | `src/core/crypto/lifecycle/artifacts.js` |
| Source-evidence type default | `source-evidence` | `src/core/crypto/lifecycle/artifacts.js` |
| Primary fixity anchor | `qencHash` | `src/core/crypto/lifecycle/artifacts.js` |
| `containerIdRole` | `secondary-header-id` | `src/core/crypto/lifecycle/artifacts.js` |
| `containerIdAlg` | `SHA3-512(qenc-header-bytes)` | `src/core/crypto/lifecycle/artifacts.js` |
| Reed-Solomon codec identifier | `QV-RS-ErasureCodes-v1` | `src/core/crypto/lifecycle/artifacts.js` |
| Shard body definition identifier | `QV-QCONT-SHARDBODY-v1` | `src/core/crypto/lifecycle/artifacts.js` |
| Share-commitment input label | `raw-shamir-share-bytes` | `src/core/crypto/lifecycle/artifacts.js` |

## 2. Canonicalization labels

| Use | Current label | Source |
| --- | --- | --- |
| Archive-state descriptor canonicalization | `QV-JSON-RFC8785-v1` | `src/core/crypto/lifecycle/artifacts.js`, `src/core/crypto/manifest/jcs.js` |
| Cohort-binding canonicalization | `QV-JSON-RFC8785-v1` | `src/core/crypto/lifecycle/artifacts.js`, `src/core/crypto/manifest/jcs.js` |
| Transition-record canonicalization | `QV-JSON-RFC8785-v1` | `src/core/crypto/lifecycle/artifacts.js`, `src/core/crypto/manifest/jcs.js` |
| Source-evidence canonicalization | `QV-JSON-RFC8785-v1` | `src/core/crypto/lifecycle/artifacts.js`, `src/core/crypto/manifest/jcs.js` |
| Lifecycle-bundle canonicalization | `QV-BUNDLE-JSON-v1` | `src/core/crypto/lifecycle/artifacts.js`, `src/core/crypto/manifest/jcs.js` |
| `authPolicyCommitment.canonicalization` | `QV-JSON-RFC8785-v1` | `src/core/crypto/manifest/auth-policy.js` |

## 3. Detached-signature and key-wrapper identifiers

### 3.1 Current wrapper magics and version fields

| Artifact | Current identifier | Current value | Source |
| --- | --- | --- | --- |
| `.qsig` | magic | `PQSG` | `src/core/crypto/auth/qsig.js` |
| `.qsig` | supported context | `quantum-signer/v2` | `src/core/crypto/auth/qsig.js` |
| `.qsig` | format major version | `0x02` | `src/core/crypto/auth/qsig.js` |
| `.qsig` TBS | magic | `QSTB` | `src/core/crypto/auth/qsig.js` |
| `.qsig` TBS | format major version | `0x02` | `src/core/crypto/auth/qsig.js` |
| `.pqpk` | magic | `PQPK` | `src/core/crypto/auth/qsig.js` |
| `.pqpk` | format major version | `0x01` | `src/core/crypto/auth/qsig.js` |
| signer fingerprint record | algorithm id | `0x01` (`SHA3-256`) | `src/core/crypto/auth/qsig.js` |

### 3.2 Current `.qsig` registry values

| Registry field | Current value | Source |
| --- | --- | --- |
| `signatureProfileId` | `0x01` (`PQ_DETACHED_PURE_CONTEXT_V2`) | `src/core/crypto/auth/qsig.js` |
| `hashAlgId` | `0x01` (`SHA3-512`) | `src/core/crypto/auth/qsig.js` |
| `authDigestAlgId` | `0x01` (`SHA3-256`) | `src/core/crypto/auth/qsig.js` |

Current detached PQ suite ids:

| Suite id | Display name | Normalized suite key | Source |
| --- | --- | --- | --- |
| `0x01` | `ML-DSA-44` | `mldsa-44` | `src/core/crypto/auth/qsig.js` |
| `0x02` | `ML-DSA-65` | `mldsa-65` | `src/core/crypto/auth/qsig.js` |
| `0x03` | `ML-DSA-87` | `mldsa-87` | `src/core/crypto/auth/qsig.js` |
| `0x11` | `SLH-DSA-SHAKE-128s` | `slhdsa-shake-128s` | `src/core/crypto/auth/qsig.js` |
| `0x12` | `SLH-DSA-SHAKE-192s` | `slhdsa-shake-192s` | `src/core/crypto/auth/qsig.js` |
| `0x13` | `SLH-DSA-SHAKE-256s` | `slhdsa-shake-256s` | `src/core/crypto/auth/qsig.js` |
| `0x14` | `SLH-DSA-SHAKE-256f` | `slhdsa-shake-256f` | `src/core/crypto/auth/qsig.js` |

### 3.3 Lifecycle attachment field registry

The current lifecycle-bundle attachment fields for detached signatures are:

| Signature family | Attachment field | Required `targetType` | Source |
| --- | --- | --- | --- |
| archive approval | `archiveApprovalSignatures` | `archive-state` | `src/core/crypto/lifecycle/artifacts.js` |
| maintenance | `maintenanceSignatures` | `transition-record` | `src/core/crypto/lifecycle/artifacts.js` |
| source evidence | `sourceEvidenceSignatures` | `source-evidence` | `src/core/crypto/lifecycle/artifacts.js` |

## 4. Crypto profile, KDF, IV, nonce, and AAD identifiers

| Identifier class | Current value | Source |
| --- | --- | --- |
| `cryptoProfileId` | `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2` | `src/core/crypto/policy.js` |
| `kdfTreeId` | `QV-KDF-TREE-v2` | `src/core/crypto/policy.js` |
| `aadPolicyId` | `QV-AAD-HEADER-CHUNK-v1` | `src/core/crypto/policy.js` |
| KDF domain string | `quantum-vault:kdf:v2` | `src/core/crypto/constants.js` |
| IV domain string | `quantum-vault:chunk-iv:v2` | `src/core/crypto/constants.js` |
| `Kenc` domain string | `quantum-vault:kenc:v2` | `src/core/crypto/constants.js` |
| `Kiv` domain string | `quantum-vault:kiv:v2` | `src/core/crypto/constants.js` |

Current AEAD-mode registry:

| `aead_mode` | `iv_strategy` | `noncePolicyId` | `nonceMode` | `counterBits` | `maxChunkCount` | Source |
| --- | --- | --- | --- | --- | --- | --- |
| `single-container-aead` | `single-iv` | `QV-GCM-RAND96-v1` | `random96` | `0` | `1` | `src/core/crypto/aead.js`, `src/core/crypto/policy.js`, `src/core/crypto/qenc/format.js` |
| `per-chunk-aead` | `kmac-prefix64-ctr32-v3` | `QV-GCM-KMACPFX64-CTR32-v3` | `kmac-prefix64-ctr32` | `32` | `4294967295` | `src/core/crypto/aead.js`, `src/core/crypto/policy.js`, `src/core/crypto/qenc/format.js` |

## 5. Signature suite registry and `strongPq`

Current normalized suite mapping:

| Normalized suite key | Display name | Family | `strongPq` | `legacy` | Public key type | Source |
| --- | --- | --- | --- | --- | --- | --- |
| `mldsa-44` | `ML-DSA-44` | `mldsa` | `false` | `false` | `ml-dsa-public-key` | `src/core/crypto/auth/signature-suites.js` |
| `mldsa-65` | `ML-DSA-65` | `mldsa` | `false` | `false` | `ml-dsa-public-key` | `src/core/crypto/auth/signature-suites.js` |
| `mldsa-87` | `ML-DSA-87` | `mldsa` | `true` | `false` | `ml-dsa-public-key` | `src/core/crypto/auth/signature-suites.js` |
| `slhdsa-shake-128s` | `SLH-DSA-SHAKE-128s` | `slhdsa-shake` | `false` | `false` | `slh-dsa-public-key` | `src/core/crypto/auth/signature-suites.js` |
| `slhdsa-shake-192s` | `SLH-DSA-SHAKE-192s` | `slhdsa-shake` | `false` | `false` | `slh-dsa-public-key` | `src/core/crypto/auth/signature-suites.js` |
| `slhdsa-shake-256s` | `SLH-DSA-SHAKE-256s` | `slhdsa-shake` | `true` | `false` | `slh-dsa-public-key` | `src/core/crypto/auth/signature-suites.js` |
| `slhdsa-shake-256f` | `SLH-DSA-SHAKE-256f` | `slhdsa-shake` | `true` | `false` | `slh-dsa-public-key` | `src/core/crypto/auth/signature-suites.js` |
| `ed25519` | `Ed25519` | `ed25519` | `false` | `true` | `ed25519-public-key` | `src/core/crypto/auth/signature-suites.js` |

## 6. Digest and commitment identifiers

| Mechanism | Current value | Source |
| --- | --- | --- |
| Archive-state, cohort-binding, transition-record, and source-evidence digest label | `SHA3-512` | `src/core/crypto/lifecycle/artifacts.js` |
| OTS stamped digest label | `SHA-256` | `src/core/crypto/lifecycle/artifacts.js`, `src/core/crypto/auth/opentimestamps.js` |
| Key-commitment rule | `SHA3-256(Kenc)` | `src/core/crypto/constants.js`, `src/core/crypto/kdf.js` |
| `authPolicyCommitment.alg` | `SHA3-512` | `src/core/crypto/manifest/auth-policy.js` |
| `authPolicyCommitment.canonicalization` | `QV-JSON-RFC8785-v1` | `src/core/crypto/manifest/auth-policy.js` |

## 7. OpenTimestamps heuristic note

Current parser and reporting identifiers:

| Field or rule | Current value | Source |
| --- | --- | --- |
| OpenTimestamps proof header digest op | `0x08` (`SHA-256`) | `src/core/crypto/auth/opentimestamps.js` |
| Incomplete-proof filename keywords | `initial`, `pending`, `incomplete` | `src/core/crypto/auth/opentimestamps.js` |
| Complete-proof filename keywords | `complete`, `completed`, `confirmed`, `upgraded` | `src/core/crypto/auth/opentimestamps.js` |
| Size fallback | `bytes.length >= 1024` | `src/core/crypto/auth/opentimestamps.js` |
| Reporting fields | `appearsComplete` and `completeProof` carry the same heuristic result | `src/core/crypto/auth/opentimestamps.js` |

Current scope note:

- the heuristic above is a reporting aid, not a validated Bitcoin confirmation chain
- OTS target resolution currently matches `SHA-256(detachedSignatureBytes)` against exactly one detached signature
- attach and restore semantics for OTS acceptance, fail-closed linkage, and non-policy-satisfaction remain owned by [`format-spec.md`](../format-spec.md), [`trust-and-policy.md`](../trust-and-policy.md), and [`external-artifacts.md`](external-artifacts.md)
