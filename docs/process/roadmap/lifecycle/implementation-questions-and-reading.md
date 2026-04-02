# Quantum Vault — Implementation Questions & Reading Guide

Status: Historical transition reading guide plus remaining open questions
Type: Informative architecture / standards / frozen-decision guide
Audience: contributors, implementers, reviewers, cryptographic auditors
Scope: preserved lifecycle design questions and frozen decisions from the successor transition, plus the still-open deferred questions
Relationship: the current normative baseline remains `docs/format-spec.md`, `docs/trust-and-policy.md`, and `docs/security-model.md`; this document now supports historical interpretation of the successor design in `resharing-design.md` and the execution record in `implementation-plan-lifecycle.md`

## Purpose

This document is intentionally **not** the implementation checklist.

Its job is to:

- restate the fixed baseline inherited from Stage A, Stage B, and Stage C
- separate current fact from frozen decision
- preserve implementation-relevant nuance that matters at signer, attach, restore, and shard-carriage seams
- identify the few questions that truly remain open
- tie the main lifecycle decisions to the standards frame without pretending standards dictate the exact QV object model

## How To Read This Document

The document uses four labels deliberately:

- **Current fact:** already true in the current Quantum Vault baseline
- **Frozen decision:** design choice this revision freezes as a completed Phase 0 contract
- **True open question:** still undecided after this revision because implementation can proceed without freezing it yet
- **Future research:** not part of the near-term successor family

Normative language in this document:

- uppercase `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals
- explanatory prose outside frozen-decision, wire-contract, and verifier-predicate sections is informative and does not create independent conformance requirements
- sections labeled **Frozen decision**, **Frozen derivation**, or **Frozen identifier** record completed Phase 0 contracts; later phases may only codify or implement them

## Current reading posture

Most of the architecture questions in this document are now resolved in the shipped implementation and in the current owner docs.

- Sections 1 through 10 should be read primarily as historical rationale and frozen-decision context for the successor migration that is now implemented.
- Section 12 remains the main place where this file records genuinely open deferred questions.
- Current behavior should be taken from `docs/format-spec.md`, `docs/trust-and-policy.md`, `docs/security-model.md`, and the shipped successor implementation.

## 1. Fixed Baseline Inherited From Stage A-C

Status: Current fact

The following are already settled and must be treated as hard inputs for lifecycle design:

1. Detached signatures currently authenticate canonical signable JSON bytes only.
2. Bundle mutation MUST NOT change the detached-signature payload.
3. Signable canonical JSON uses the RFC 8785-aligned `QV-JSON-RFC8785-v1` profile.
4. Bundle serialization is separately versioned under `QV-BUNDLE-JSON-v1`.
5. Stage A, Stage B, and Stage C are completed constraints:
   - Stage A: RFC 8785-aligned canonicalization for the signable manifest surface
   - Stage B: JSON Schema structural validation and closed grammar discipline
   - Stage C: strict separation of serialization, schema, and semantics
6. Closed grammar remains in force:
   - new top-level fields require a new schema/version
   - new attachment families require a new schema/version
   - grammar openness is not an extension mechanism
7. JSON Schema draft 2020-12 is the grammar layer only.
8. `qencHash` is the current ciphertext binding anchor.
9. Detached signatures are external authenticity artifacts linked to the signable object.
10. OpenTimestamps is evidence-only and targets detached signature bytes, not bundle bytes.
11. Current trust semantics keep integrity, signature validity, pinning, and policy satisfaction distinct.

Lifecycle work therefore MUST NOT:

- reopen the Stage A canonicalization question
- treat schema validity as if it settled lifecycle meaning
- silently add lifecycle semantics to the current manifest/bundle family
- weaken the current integrity/signature/pinning/policy separation

### 1.1 JSON discipline inherited into lifecycle v1

Status: Frozen decision

Lifecycle parsing and normalization MUST stay explicit:

- lifecycle JSON text MUST parse as RFC 8259 JSON before any schema, canonicalization, digest, or signature step
- parsers MUST reject duplicate object names
- lifecycle v1 artifacts MUST stay within an I-JSON-safe subset compatible with RFC 7493:
  - strings are encoded as UTF-8 JSON text at the byte level
  - numeric fields, where used, MUST be finite integers in the exact interoperable range `0..2^53-1`
  - non-finite numbers are forbidden
- JSON Schema draft 2020-12 remains grammar only; it does not define canonical bytes, derived identifiers, target semantics, or policy semantics

## 2. Lifecycle Pressure Points Exposed By The Current Baseline

Status: Current fact

The current split-time manifest model is internally coherent for the implemented artifact family, but lifecycle requirements expose several real tensions.

### 2.1 Split-time signature target vs same-state resharing

Current fact:

- the current canonical manifest includes shard-distribution material
- that material includes concrete `n/k/t/codecId`, shard-body hashes, and share-commitment-related content
- detached signatures therefore target a **cohort-bound** object

Implementation consequence:

- same-state resharing changes current signable bytes
- `manifestDigest` changes
- detached signatures and OTS linkage tied to those bytes do not carry forward as stable archive-state approval

This is not a cosmetic documentation problem.
It is the architectural reason lifecycle work needs a successor-family split.

### 2.2 Archive-state approval vs source-review claims

Current fact:

- a detached signature currently means only that a signer key signed the canonical signable bytes
- it does not prove, by itself, that the signer reviewed plaintext
- it does not prove that the signer approved a later resharing or migration event

Implementation consequence:

- source-review provenance and archive-state approval must not be overloaded onto one signature surface

### 2.3 Availability maintenance vs compromise response

Current fact:

- custodian churn, quorum erosion, and compromised old quorum material are different event classes
- the current docs already contain operational churn language, but the lifecycle successor family must make the distinction explicit

Implementation consequence:

- same-state resharing is an availability-maintenance mechanism
- if old quorum material may already have leaked, same-state resharing is not sufficient response

### 2.4 Stable archive identity vs current state anchors

Current fact:

- the current artifact family has strong current-state anchors such as `qencHash`, `containerId`, `manifestDigest`, and `authPolicyCommitment`
- it does not have a first-class archive-wide `archiveId`

Implementation consequence:

- reencryption or future `rewrap` continuity is under-specified until the successor family introduces a stable logical-archive identifier

### 2.5 Closed grammar vs lifecycle expansion

Current fact:

- archive-state descriptors, cohort bindings, transition records, and source-evidence objects are new artifact classes
- the current manifest and bundle cannot absorb them informally because grammar openness is not allowed

Implementation consequence:

- lifecycle work must be a versioned successor family, not a quiet semantic reinterpretation of the current family

## 3. Architecture Decisions Frozen In This Revision

Status: Frozen decision

This revision freezes the following architecture strongly enough for implementation planning.

### 3.1 Successor-family model

- Lifecycle support is a successor artifact family.
- The current `quantum-vault-archive-manifest/v3` and `QV-Manifest-Bundle` v2 family stays unchanged.
- Signable successor artifacts reuse `QV-JSON-RFC8785-v1` unless byte rules truly change.
- The lifecycle bundle uses `QV-BUNDLE-JSON-v1` unless bundle byte rules truly change.

### 3.2 Long-lived signable object

- The long-lived detached-signature target is the **archive-state descriptor**.
- Archive-approval signatures sign canonical archive-state descriptor bytes.
- `qenc` authenticity is normally indirect:

```text
archive-approval signature
  -> archive-state descriptor canonical bytes
  -> qencHash / containerId
  -> exact .qenc bytes
```

- Direct `.qenc` signatures remain optional external-workflow artifacts, not the default QV authenticity mechanism.

### 3.3 State/cohort boundary

- The archive-state descriptor carries stable archive-state, ciphertext, and policy identity.
- Concrete `n/k/t/codecId` are cohort-level.
- Same-state resharing MAY change concrete cohort parameters without changing `stateId`.
- A new `stateId` always requires a new cohort-binding object and therefore a new `cohortId`, because cohort bindings are state-bound in the successor family.

### 3.4 Shard carriage strategy

- QV-produced successor shards embed archive-state descriptor bytes and digest, cohort-binding bytes and digest, and lifecycle-bundle bytes and digest.
- Shards remain self-contained by default.
- External archive-state, bundle, signature, key, and timestamp artifacts are still allowed as attach/restore inputs.
- Differing embedded lifecycle-bundle digests inside one otherwise identical state-plus-cohort are bundle variants, not different cohorts.

### 3.5 Lifecycle-bundle v1 contents

Lifecycle-bundle v1 is frozen as carrying:

- `type`
- `version`
- `bundleCanonicalization`
- `archiveStateCanonicalization`
- `archiveState`
- `archiveStateDigest`
- `currentCohortBinding`
- `currentCohortBindingDigest`
- `authPolicy`
- `sourceEvidence[]`
- `transitions[]`
- `attachments.publicKeys[]`
- `attachments.archiveApprovalSignatures[]`
- `attachments.maintenanceSignatures[]`
- `attachments.sourceEvidenceSignatures[]`
- `attachments.timestamps[]`

All arrays above are present even when empty.
The lifecycle-bundle v1 top-level member set is exactly `type`, `version`, `bundleCanonicalization`, `archiveStateCanonicalization`, `archiveState`, `archiveStateDigest`, `currentCohortBinding`, `currentCohortBindingDigest`, `authPolicy`, `sourceEvidence`, `transitions`, and `attachments`.
The `attachments` member set is exactly `publicKeys`, `archiveApprovalSignatures`, `maintenanceSignatures`, `sourceEvidenceSignatures`, and `timestamps`.
No additional top-level lifecycle-bundle v1 members and no additional `attachments` members are permitted.

### 3.6 `publicKeyRef` semantics

- A bundled signature entry that declares `publicKeyRef` MUST resolve using the frozen compatibility predicate below.
- Failure to resolve or verify that declared reference is a signature verification failure for that signature.
- This is true for archive-approval, maintenance, and source-evidence signatures.
- Pinning remains a separate status layer.

Frozen compatibility predicate:

- exactly one bundled key entry MUST satisfy `id == publicKeyRef`
- that entry MUST also satisfy `suite == <signature-entry.suite>`
- the declared key `encoding` MUST decode successfully into exactly one key value
- the decoded key MUST be structurally valid for the declared `kty` and usable with the declared `suite`
- detached-signature verification against that decoded key and the declared target bytes MUST succeed
- zero matches, multiple matches, decode failure, structural key invalidity, suite mismatch, or verification failure MUST reject the signature entry

### 3.7 Transition records

- Every QV-produced same-state resharing event MUST create a transition record.
- Transition records are maintenance/provenance records.
- Maintenance signatures over transition records are not archive-approval signatures.
- Maintenance-signature support belongs in the successor family from the start even if governance later decides when such signatures are mandatory.
- `actorHints` remain free-form advisory metadata in v1.

### 3.8 Migration continuity requirement

- State-changing operations are deferred, but the requirement is already frozen:
- policy change, reencryption, and future `rewrap` MUST preserve predecessor archive-state descriptors, predecessor archive-approval signatures, predecessor timestamps/evidence, and explicit continuity links sufficient to verify lineage

## 4. Archive Identity, Archive State, Cohort Identity, And Source Evidence

Status: Frozen decision

The lifecycle successor family uses three identity layers plus a separate provenance layer.

### 4.1 Archive identity

Current fact:

- the current artifact family has no first-class stable archive-wide identifier

Frozen decision:

- introduce `archiveId` as a random, opaque, non-content-derived logical-archive identifier
- assign it once at archive creation
- preserve it across same-state resharing, reencryption, and future `rewrap`

Why not content-derived:

- content-derived identity leaks equivalence
- ciphertext-derived identity is too state-specific
- OAIS-style continuity benefits from a durable logical identifier separate from any one ciphertext state

### 4.2 Archive state

Frozen decision:

- `archiveStateDigest` has shape `{ "alg": "SHA3-512", "value": "<lowercase hex>" }`
- `archiveStateDigest.value = SHA3-512(canonical archive-state descriptor bytes)`
- `stateId = archiveStateDigest.value`
- `stateId` is derived-only metadata
- the archive-state descriptor MUST NOT contain `stateId` inside the canonical bytes used to derive it
- one `stateId` corresponds to one canonical archive-state descriptor
- bundle mutation does not change `stateId`
- same-state resharing does not change `stateId`

#### 4.2.1 Exact archive-state descriptor v1 field set

The archive-state descriptor v1 field set is frozen exactly as:

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
- `qenc.chunkSize`
- `qenc.chunkCount`
- `qenc.payloadLength`
- `qenc.hashAlg`
- `qenc.primaryAnchor`
- `qenc.qencHash`
- `qenc.containerId`
- `qenc.containerIdRole`
- `qenc.containerIdAlg`
- `authPolicyCommitment`

Why each class of fields matters:

- `cryptoProfileId`, `kdfTreeId`, `noncePolicyId`, `nonceMode`, `counterBits`, `maxChunkCount`, and `aadPolicyId` are algorithm-interpretation and ciphertext-interpretation fields, not distribution metadata
- `qenc` fields bind the descriptor to one exact ciphertext state
- `authPolicyCommitment` preserves the current “mutable policy carrier, immutable signable commitment” model

Frozen exclusion boundary:

- no concrete `n/k/t/codecId`
- no `shareCommitments[]`
- no `shardBodyHashes[]`
- no cohort-specific body-definition material
- no custodian identities or cohort logistics

Exact closure rule:

- top-level members are exactly `schema`, `version`, `stateType`, `canonicalization`, `archiveId`, `parentStateId`, `cryptoProfileId`, `kdfTreeId`, `noncePolicyId`, `nonceMode`, `counterBits`, `maxChunkCount`, `aadPolicyId`, `qenc`, and `authPolicyCommitment`
- `qenc` members are exactly `chunkSize`, `chunkCount`, `payloadLength`, `hashAlg`, `primaryAnchor`, `qencHash`, `containerId`, `containerIdRole`, and `containerIdAlg`
- archive-state descriptor v1 MUST reject any additional top-level members or additional `qenc` members

### 4.3 Cohort identity

Frozen decision:

- `cohortId` identifies one shard-distribution cohort for one archive state
- `cohortBindingDigest` has shape `{ "alg": "SHA3-512", "value": "<lowercase hex>" }`
- `cohortBindingDigest.value = SHA3-512(canonical cohort-binding bytes)`
- `cohortId` is derived-only metadata
- the cohort-binding bytes used to derive `cohortBindingDigest` MUST NOT contain `cohortId`
- `cohortId` is derived from the exact RFC 8785-canonicalized JSON preimage:

```json
{
  "type": "quantum-vault-cohort-id-preimage/v1",
  "archiveId": "<archiveId>",
  "stateId": "<stateId>",
  "cohortBindingDigest": {
    "alg": "SHA3-512",
    "value": "<cohortBindingDigest.value>"
  }
}
```

- `cohortId = SHA3-256(canonical cohort-id preimage bytes)` encoded as lowercase hex

Important distinction:

- `cohortId` identifies the semantic shard-distribution cohort
- `cohortBindingDigest` identifies exact canonical cohort-binding bytes

In Phase 1 v1, the cohort-binding object is intentionally narrow enough that these values should move together under normal processing.

### 4.4 Source authenticity evidence

Current fact:

- the current artifact family does not contain a first-class source-evidence object

Frozen decision:

- the successor family defines a separate source-evidence object family
- source evidence is provenance about reviewed or precursor objects
- it is not archive-state approval

Minimum useful source-evidence content:

- `schema`
- `version`
- `sourceEvidenceType`
- `canonicalization`
- `relationType`
- `sourceObjectType`
- one or more `sourceDigests`
- optional external-source-signature references
- optional descriptive fields only under a privacy-preserving default profile

#### 4.4.1 Privacy-preserving default profile

Frozen decision:

- the default v1 source-evidence profile SHOULD emit only:
  - `relationType`
  - `sourceObjectType`
  - `sourceDigests`
  - external-source-signature references, if any
- human-readable descriptive fields are opt-in, not default
- local paths, usernames, email addresses, and operator notes MUST NOT be emitted by default
- `mediaType` MAY be emitted when operationally necessary
- descriptive metadata never upgrades provenance into archive approval

## 5. Authenticity Surfaces And Signature Targets

Status: Frozen decision

Lifecycle work is strongest when it keeps the authenticity surfaces explicit.

| Surface | Primary object | Typical proof | Role in archive policy |
| --- | --- | --- | --- |
| Source authenticity | source artifact or source-evidence object | source signature or source-evidence signature | Not counted toward archive policy |
| Ciphertext authenticity | exact `.qenc` bytes | indirect archive-approval binding via `qencHash` / `containerId`; optional direct `.qenc` signature | Indirect by default |
| Archive-state authenticity | archive-state descriptor | archive-approval detached signatures | Counted toward archive policy |
| Cohort integrity | cohort binding plus shards | commitments, hashes, shard checks | Integrity only, not archive approval |
| Maintenance history | transition records | maintenance signatures and timestamps | Not counted toward archive policy |

Frozen target split:

- archive-approval signatures target archive-state descriptor bytes
- maintenance signatures target transition-record bytes
- source-evidence signatures target source-evidence object bytes
- OTS targets detached signature bytes

### 5.1 Minimal successor attachment wire contracts

Frozen decision:

Successor detached-signature entries share one minimum contract:

- `id`: required unique attachment identifier
- `signatureFamily`: required; one of `archive-approval`, `maintenance`, `source-evidence`
- `format`: required detached-signature wrapper family
- `suite`: required signature-suite identifier
- `targetType`: required; one of `archive-state`, `transition-record`, `source-evidence`
- `targetRef`: required typed reference string
- `targetDigest`: required digest object `{ "alg": "...", "value": "<lowercase hex>" }`
- `signatureEncoding`: required detached-signature payload encoding
- `signature`: required detached-signature payload bytes encoded as declared
- `publicKeyRef`: optional bundled-key reference string

Frozen family mappings:

- `archiveApprovalSignatures[]` entries MUST carry `signatureFamily = "archive-approval"` and `targetType = "archive-state"`
- `maintenanceSignatures[]` entries MUST carry `signatureFamily = "maintenance"` and `targetType = "transition-record"`
- `sourceEvidenceSignatures[]` entries MUST carry `signatureFamily = "source-evidence"` and `targetType = "source-evidence"`

Frozen `targetRef` and `targetDigest` rules:

- archive-state signatures:
  - `targetRef = "state:" + stateId`
  - `targetDigest = archiveStateDigest`
- maintenance signatures:
  - `targetRef = "transition:sha3-512:" + SHA3-512(canonical transition-record bytes)`
  - `targetDigest = { "alg": "SHA3-512", "value": SHA3-512(canonical transition-record bytes) }`
- source-evidence signatures:
  - `targetRef = "source-evidence:sha3-512:" + SHA3-512(canonical source-evidence bytes)`
  - `targetDigest = { "alg": "SHA3-512", "value": SHA3-512(canonical source-evidence bytes) }`

Frozen bundled-key contract:

- `attachments.publicKeys[]` entries MUST carry `id`, `kty`, `suite`, `encoding`, and `value`
- if `publicKeyRef` is present, it MUST equal one bundled key `id`
- attach and restore MUST use the same `publicKeyRef` resolution and compatibility rules
- exact compatibility predicate:
  - exactly one bundled key entry MUST satisfy `id == publicKeyRef`
  - that entry MUST also satisfy `suite == <signature-entry.suite>`
  - the declared key `encoding` MUST decode successfully into exactly one key value
  - the decoded key MUST be structurally valid for the declared `kty` and usable with the declared `suite`
  - detached-signature verification against that decoded key and the declared target bytes MUST succeed
  - zero matches, multiple matches, decode failure, structural key invalidity, suite mismatch, or verification failure MUST reject the signature entry

Frozen timestamp contract:

- `attachments.timestamps[]` entries MUST carry:
  - `id`
  - `type = "opentimestamps"`
  - `targetRef`
  - `targetDigest = { "alg": "SHA-256", "value": "<lowercase hex>" }`
  - `proofEncoding`
  - `proof`
- `targetRef` MUST reference one known detached-signature attachment entry by `id`
- `targetDigest.value` MUST equal `SHA-256` over the exact detached-signature bytes targeted by that `targetRef`
- “exact detached-signature bytes” means the decoded payload bytes from the targeted signature entry’s `signature` field, not bundle bytes and not canonical JSON bytes

Attach and restore consequence:

- attach and restore MUST interpret `signatureFamily`, `targetType`, `targetRef`, `targetDigest`, and `publicKeyRef` identically
- no lifecycle code path may reinterpret a signature target by family-local heuristic

## 6. Successor Verification Invariants

Status: Frozen decision

The successor family MUST preserve the current trust-model separation.

Minimum required successor verification states:

1. `integrity verified`
   - archive-state, cohort-binding, shard, digest, and reconstruction checks hold
2. `archive-approval signature verified`
   - at least one detached archive-approval signature verifies over the canonical archive-state descriptor bytes
3. `signer pinned`
   - a verified signature matches bundled or user-supplied signer identity material
4. `archive policy satisfied`
   - the declared archive policy is satisfied by archive-approval signatures only

Additional successor verification states MAY be reported, but they do not replace the four above:

- `maintenance signature verified`
- `source-evidence signature verified`
- `OTS evidence linked`

Required non-collapse rules:

- integrity does not imply signature validity
- signature validity does not imply pinning
- pinning does not imply policy satisfaction
- OTS evidence does not satisfy archive policy
- maintenance signatures do not satisfy archive policy
- source-evidence signatures do not satisfy archive policy

### 6.1 Required verifier predicates

Frozen decision:

At minimum, successor verification MUST evaluate the following predicates explicitly:

1. archive-state digest equality
   - recompute `SHA3-512(canonical archive-state descriptor bytes)` and require equality with `archiveStateDigest.value`
2. archive identity equality
   - require one `archiveId` across the selected candidate set
3. `stateId` derivation equality
   - require `stateId == archiveStateDigest.value`
4. cohort-binding digest equality
   - recompute `SHA3-512(canonical cohort-binding bytes)` and require equality with `cohortBindingDigest.value`
5. `cohortId` derivation equality
   - recompute the exact canonical cohort-id preimage and require `cohortId == SHA3-256(preimage-bytes)` encoded as lowercase hex
6. shard-set consistency
   - require one `archiveId`, one `stateId`, one `cohortId`, one exact archive-state byte sequence, and one exact cohort-binding byte sequence inside the selected candidate set
7. signature target equality
   - require each detached signature entry’s `signatureFamily`, `targetType`, `targetRef`, and `targetDigest` to match its actual target object and target bytes
8. fail-closed `publicKeyRef` resolution
   - if `publicKeyRef` is present, require the frozen exact-one-match compatibility predicate and successful verification against that key or reject that signature
9. OTS linkage equality
   - if an OTS entry is present, require `targetRef` resolution to one detached signature entry and require `targetDigest.value == SHA-256(exact detached-signature bytes)`
10. archive-policy counting
   - count only verified archive-approval signatures toward archive policy

Required rejection conditions:

- mixed `archiveId` values in one restore candidate set MUST be rejected
- mixed `stateId` values in one restore candidate set MUST be rejected
- mixed `cohortId` values in one restore candidate set MUST be rejected
- exact archive-state byte mismatch inside one claimed state MUST be rejected
- exact cohort-binding byte mismatch inside one claimed cohort MUST be rejected
- any explicit lifecycle bundle whose `archiveStateDigest` or `currentCohortBindingDigest` does not match the selected state-plus-cohort MUST be rejected
- mismatched `targetType` / `targetRef` / `targetDigest` metadata MUST reject the affected signature entry
- unresolved or incompatible `publicKeyRef` MUST reject the affected signature entry
- unresolved or mismatched OTS linkage MUST reject the affected timestamp entry as invalid evidence and MUST NOT be reassigned heuristically to another signature

## 7. Signer, Attach, Restore, And Shard-Carriage Implications

Status: Frozen decision

This section keeps the implementation-relevant seams explicit so the architecture does not become cleaner but weaker.

### 7.1 External signer tooling implications

Current fact:

- Quantum Vault currently uses external signer tooling to sign canonical signable bytes

Frozen decision:

- successor external signing targets canonical archive-state descriptor bytes
- detached signature wrappers remain external artifacts
- target descriptors and verification metadata must change from `canonical-manifest` semantics to `archive-state` semantics

Practical implication:

- export/import, signer documentation, and verification tooling must be updated explicitly
- this is not just a schema change inside QV core

### 7.2 Attach-flow implications

Frozen decision:

- attach mutates the lifecycle bundle only
- attach MUST NOT mutate archive-state descriptor bytes
- attach MUST NOT mutate cohort-binding bytes
- attach validates:
  - signature target types and digests
  - declared `publicKeyRef`
  - timestamp linkage to detached signature bytes

Practical implication:

- partial shard rewriting remains possible
- when some shards carry older embedded lifecycle bundles and some carry newer ones, restore must treat this as a bundle-variant condition inside one cohort, not as mixed-cohort acceptance

### 7.3 Restore cohort-selection implications

Frozen decision:

- restore groups candidates by explicit state/cohort identity
- the grouping boundary is:
  - `archiveId`
  - `stateId`
  - `cohortId`
  - exact archive-state bytes
  - exact cohort-binding bytes

Practical implication:

- the current `manifestDigestHex:bundleDigestHex` composite key is replaced
- uploaded archive-state descriptors and lifecycle bundles remain valid explicit disambiguation tools
- an uploaded lifecycle bundle is acceptable only if its `archiveStateDigest` and `currentCohortBindingDigest` match the already selected state-plus-cohort
- if exactly one embedded lifecycle-bundle digest is present inside the already selected state-plus-cohort, restore MAY use it automatically
- if more than one embedded lifecycle-bundle digest is present inside the selected state-plus-cohort and no explicit bundle input is supplied, restore MUST NOT auto-select; it MUST require explicit lifecycle-bundle bytes or explicit operator selection of one embedded bundle digest
- attachment count, timestamp count, “richness,” lexical order, and similar heuristics MUST NOT choose a bundle variant

### 7.4 Shard carriage and embedding implications

Frozen decision:

- successor shards remain self-contained
- every QV-produced shard embeds:
  - archive-state descriptor bytes and digest
  - current cohort-binding bytes and digest
  - current lifecycle-bundle bytes and digest

Practical implication:

- current “attach and optionally rewrite embedded bundles” behavior carries forward naturally
- restore can still proceed from shards alone
- external files remain optional overrides or augmentations rather than mandatory dependencies

## 8. Same-State Resharing: What It Is And What It Is Not

Status: Frozen decision

### 8.1 What same-state resharing is

Same-state resharing is:

- availability maintenance for one unchanged archive state
- rotation of shard-distribution material
- creation of a new cohort binding and new `cohortId`
- preservation of the existing archive-state descriptor and its archive-approval signatures

### 8.2 Exact meaning of reconstructed secret material

Do not blur this point.

Frozen decision:

- same-state resharing reconstructs the threshold-recovered ML-KEM private key material needed to re-split access to the current encrypted state
- it does not require decrypting plaintext
- it does not change the `.qenc` bytes

### 8.3 What same-state resharing does not prove or repair

Same-state resharing does **not**:

- re-approve archive content
- revoke previously leaked old quorum material
- create new source-authenticity evidence
- change the ciphertext state
- by itself respond to algorithm weakness, HNDL pressure, or policy change

Therefore:

- ordinary maintenance stays same-state
- compromise response requiring new cryptographic state is not same-state resharing

## 9. Event Classes That Must Stay Distinct

Status: Frozen decision

| Event class | Primary problem | Correct artifact effect | Same state? |
| --- | --- | --- | --- |
| Availability maintenance | quorum erosion, custodian rotation, benign shard loss | new cohort binding, new `cohortId`, required transition record | Yes |
| Suspected old-quorum leakage | old cohort may already reveal the secret | new archive state at minimum | No |
| Policy change | archive approval semantics change | new archive-state descriptor and new archive-approval signatures | No |
| Reencryption / crypto migration | ciphertext or crypto profile changes | new archive-state descriptor, new cohort, continuity preservation required | No |
| Future `rewrap` | outer confidentiality envelope rotates under future DEK design | future branch only | No |

### 9.1 Operational trigger guidance

Current fact preserved as useful cohort-level guidance:

```text
safety_margin = ceil((n - t) / 2)
reshare_trigger: available_honest_custodians < t + safety_margin
```

Frozen interpretation:

- this is maintenance guidance for the current cohort
- it is not part of archive-state authenticity
- it is not proof that compromise has or has not occurred

### 9.2 Cross-cohort mixing

Current fact:

- independent cohorts use independent Shamir polynomials
- shares from different cohorts are not combinable into one valid reconstruction set

Important caveat:

- this is weaker than saying resharing “revokes” old shares
- an old cohort remains its own confidentiality surface until enough old material is destroyed or otherwise known unavailable

## 10. Evidence And Time

Status: Current fact plus recommended decision

### 10.1 Current OTS posture

Current fact:

- OTS currently witnesses detached signature bytes
- it does not witness the whole bundle in its later mutable form
- it does not satisfy archive policy by itself

### 10.2 Frozen successor posture

Frozen decision:

- archive-approval signatures remain the main long-lived OTS target
- maintenance signatures may also carry timestamps for maintenance provenance
- source-evidence signatures may also carry timestamps for provenance, but those timestamps do not become archive approval

### 10.3 What current OTS does and does not prove

Current OTS use does prove:

- detached signature bytes existed before some witness-observed time
- those signature bytes can be linked to the relevant signed object if the detached signature verifies

Current OTS use does **not** prove:

- that archive policy was satisfied
- that a signer was pinned
- that the plaintext source was reviewed
- that a renewable evidence chain already exists

### 10.4 Standards claim boundary

Frozen decision:

- RFC 4998 is future-direction context for renewable evidence
- the current lifecycle successor family does not adopt any additional timestamp standard beyond the fixed QV OTS evidence posture inherited from the baseline
- RFC 4998 does not describe current implementation capability and MUST remain future-only context

## 11. Standards Reading Map

Status: Reading map for design reasoning

| Standard / authority | Architectural question it informs | Why it matters here |
| --- | --- | --- |
| RFC 8785 | What exact bytes should signable or deterministically hashed lifecycle JSON objects use? | Archive-state, transition, cohort-binding, and source-evidence bytes need deterministic canonicalization compatible with the Stage A baseline |
| RFC 7493 | What JSON subset should lifecycle artifacts stay within? | Reinforces I-JSON-safe expectations such as no duplicate names, portable number handling, and interoperable JSON discipline |
| RFC 8259 | What JSON parser constraints still matter before canonicalization? | Lifecycle parsing still must reject malformed JSON before any canonicalization or semantic steps |
| JSON Schema draft 2020-12 | How should lifecycle grammar stay closed and versioned? | New artifact families and attachment families need explicit schemas rather than prose-only extension paths |
| RFC 2119 / RFC 8174 | Where should lifecycle docs use MUST/SHOULD language? | Distinguishes frozen implementation requirements from recommendations and future work |
| RFC 5116 / NIST SP 800-38D | Which AEAD and AAD semantics belong in archive-state identity? | Nonce and AAD interpretation are state semantics, not cohort logistics |
| FIPS 202 | Which digest-family assumptions back state IDs, cohort IDs, and binding digests? | Keeps identifier and commitment choices aligned with current QV primitive families |
| FIPS 203 | What current KEM state is the archive-state descriptor describing? | The successor state descriptor still represents an ML-KEM-based confidentiality state in the current baseline |
| NIST SP 800-185 | Why do KMAC/KDF interpretation fields remain state-level? | KDF-tree and derivation semantics are part of cryptographic state identity |
| ISO 14721 (OAIS) | Why separate logical archive identity, fixity, provenance, and preservation events? | Supports the archive/state/cohort/provenance split without pretending OAIS dictates QV JSON shape |
| ISO 16363 | Why preserve auditable distinction among integrity, authenticity, provenance, and evidence? | Supports explicit, separately reportable verification outcomes rather than one opaque trust bit |
| RFC 4998 | How should future renewable evidence be framed honestly? | Only as future-direction context for evidence renewal, not current implementation |

## 12. True Open Questions After This Revision

Status: True open question

The following remain open because implementation can proceed without freezing them today:

1. Whether future governance profiles should require maintenance signatures for every resharing event or only for some archive classes.
2. Whether direct `.qenc` signatures should ever be bundled in a future extension family for non-QV repository workflows.
3. Whether later lifecycle versions need a signed “active cohort” governance rule for resolving known same-state forks without operator intervention.

These are deliberately smaller than the state/cohort boundary question and do not justify reopening the frozen architecture.

## 13. Future Research / Not In Near-Term Scope

Status: Future research

### 13.1 Distributed resharing

PSS, VSS, and DPSS remain future research only.

Why:

- they require interactive online custodians
- they require secure channels or broadcast semantics
- they would move QV away from the current browser-first, client-only model

### 13.2 Merkleized cohort commitments

Flat commitments remain sufficient at current scale.
Merkleization is an optimization, not a Phase 1 gate.

### 13.3 Envelope-DEK and future `rewrap`

Future `rewrap` remains architecture-blocked until QV adopts a wrapped-DEK design.

### 13.4 Renewable evidence chains

Renewable evidence is important for long-term archives but is not already implemented.
It remains future work rather than current lifecycle capability.

## 14. Key Insight

Status: Consolidated conclusion

The lifecycle contradiction was never just “resharing needs a nicer description.”

It was:

- shard-distribution material lived inside the signable object
- same-state resharing changed that material
- canonical signable bytes changed
- detached signatures and OTS linkage no longer carried forward cleanly as archive-state approval

The successor-family fix is therefore structural:

- archive-state approval moves to a stable archive-state descriptor
- distribution-specific material moves to a cohort binding
- maintenance history moves to transition records
- source-review provenance moves to source evidence

That split preserves the post-Stage A-C baseline, keeps the model fail closed, and turns same-state resharing into a coherent implementation target rather than a semantic contradiction.
