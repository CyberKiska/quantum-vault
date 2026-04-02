# Quantum Vault — Lifecycle Implementation Plan

Status: Draft execution plan
Type: Informative implementation plan
Audience: implementers, reviewers, maintainers
Scope: phased execution plan for the successor lifecycle artifact family
Relationship: architecture is defined in `resharing-design.md`; decision framing and standards map live in `implementation-questions-and-reading.md`; milestone ordering lives in `roadmap-archive-lifecycle.md`

## 1. Role Of This Document

This is the **execution document** for lifecycle work.

It exists to answer:

- what must be implemented
- in what order
- with what prerequisites
- in which code paths
- with which fail-closed checks
- with which test vectors and review gates

It is intentionally **not** the full theory or design rationale document.
Those responsibilities stay in:

- `implementation-questions-and-reading.md`
- `resharing-design.md`
- `roadmap-archive-lifecycle.md`

## 1.1 Document Conventions

This plan is informative except where it restates:

- Phase 0 frozen inputs
- mandatory security-review dispositions
- mandatory exit criteria
- mandatory later-phase implementation gates derived from frozen Phase 0 inputs

Uppercase `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.
Later phases may codify, schema-encode, test, or implement Phase 0 contracts, but they MUST NOT reopen or weaken them.

## 2. Fixed Inputs From The Current Quantum Vault Baseline

The implementation plan inherits the current baseline and must not reopen it:

1. Detached signatures authenticate canonical signable JSON bytes only.
2. Bundle mutation MUST NOT change the detached-signature payload.
3. Signable canonical JSON uses the RFC 8785-aligned `QV-JSON-RFC8785-v1` baseline.
4. Bundle serialization remains separately versioned under `QV-BUNDLE-JSON-v1`.
5. Stage A, Stage B, and Stage C are fixed:
   - Stage A: RFC 8785-aligned canonicalization for the signable manifest surface
   - Stage B: JSON Schema structural validation and closed grammar discipline
   - Stage C: strict separation of serialization, schema, and semantics
6. New top-level objects or new attachment families require a new schema/version.
7. JSON Schema draft 2020-12 is the grammar layer only; it does not replace canonicalization or semantic verification.
8. `qencHash` remains the ciphertext binding anchor.
9. OpenTimestamps remains evidence-only over detached signature bytes.
10. Integrity, signature validity, pinning, and policy satisfaction remain separate states and MUST stay separate in the successor family.

Lifecycle JSON discipline is also fixed input for implementation:

- parse as RFC 8259 JSON before any schema, canonicalization, digest, or signature step
- reject duplicate object names
- keep lifecycle v1 artifacts inside an I-JSON-safe subset compatible with RFC 7493
- treat JSON Schema draft 2020-12 as grammar only, not canonicalization or policy semantics

## 3. Cross-Document Architecture Decisions Frozen For Implementation

The following decisions are treated as frozen inputs for engineering work in this plan.

### 3.1 Successor-family boundary

- Lifecycle support is a **successor artifact family**, not a mutation of `quantum-vault-archive-manifest/v3` or `QV-Manifest-Bundle` v2.
- The current family remains authoritative until the successor family ships.

### 3.2 Long-lived signable object

- The long-lived detached-signature target is the **archive-state descriptor**.
- Archive-approval signatures sign canonical archive-state descriptor bytes under `QV-JSON-RFC8785-v1`.
- Direct `.qenc` signatures are optional external-workflow artifacts, not the default archive authenticity path.

### 3.3 State/cohort boundary

- The archive-state descriptor carries stable archive-state, ciphertext, and policy identity.
- Concrete sharding parameters are **cohort-level**, not state-level.
- In the frozen v1 implementation surface, same-state resharing MAY change `n` and `k`, with `t` derived from the RS parity relation under `QV-RS-ErasureCodes-v1`; `codecId` and shard body-definition details remain schema-frozen in v1.
- This does not freeze one universal numeric `n/k/m/t` tuple: Lite, Pro, or operator-selected workflows may choose different valid tuples, so long as they remain compatible with the current builder and restore semantics.
- Any state change creates a new `stateId`.
- Because cohort bindings are state-bound, any new `stateId` also requires a new cohort-binding object and a new `cohortId`.

### 3.4 Exact archive-state descriptor v1 field set

The successor archive-state descriptor v1 field set is frozen exactly as:

- top-level members:
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
- `qenc` members:
  - `chunkSize`
  - `chunkCount`
  - `payloadLength`
  - `hashAlg`
  - `primaryAnchor`
  - `qencHash`
  - `containerId`
  - `containerIdRole`
  - `containerIdAlg`
- no additional top-level members and no additional `qenc` members are permitted in archive-state descriptor v1
- schema validation and semantic validation MUST both reject any archive-state descriptor v1 object that carries out-of-set members

This field set is frozen strongly enough for schema work, external signer target updates, restore checks, and future migration continuity.

Identifier representation rule:

- `archiveStateDigest = { alg: "SHA3-512", value: "<lowercase hex>" }`
- `stateId = archiveStateDigest.value`
- `stateId` is derived-only metadata and MUST NOT appear inside the canonical archive-state descriptor bytes used to derive it

### 3.5 Shard carriage strategy

Successor `.qcont` shards produced by Quantum Vault will embed:

- canonical archive-state descriptor bytes plus digest
- canonical current cohort-binding bytes plus digest
- current lifecycle-bundle bytes plus digest
- shard metadata including `archiveId`, `stateId`, `cohortId`, and shard index

This is a deliberate carry-forward of the current self-contained shard model.
External archive-state, bundle, signature, key, and timestamp artifacts may still be supplied at attach or restore time, but QV-produced shards remain self-describing.

Identifier and digest rule for cohort material:

- `cohortBindingDigest = { alg: "SHA3-512", value: "<lowercase hex>" }`
- `cohortId` is derived-only metadata and MUST NOT appear inside the canonical cohort-binding bytes used to derive `cohortBindingDigest`
- `cohortId` is derived from the exact RFC 8785-canonicalized preimage:

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

### 3.6 Lifecycle-bundle v1 contents

`QV-Lifecycle-Bundle` v1 is frozen as containing exactly:

- top-level members:
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
- `attachments` members:
  - `publicKeys`
  - `archiveApprovalSignatures`
  - `maintenanceSignatures`
  - `sourceEvidenceSignatures`
  - `timestamps`
- no additional top-level members and no additional `attachments` members are permitted in lifecycle-bundle v1
- `sourceEvidence`, `transitions`, and all five attachment arrays MUST be present even when empty

This avoids a second top-level schema change merely to introduce a semantically central lifecycle object class.

### 3.7 `publicKeyRef` and pinning semantics

- A bundled signature entry that declares `publicKeyRef` MUST resolve using the frozen compatibility predicate below.
- Failure to resolve or verify a declared `publicKeyRef` is a **signature verification failure** for that signature, not merely absence of pinning.
- Pinning remains separate from signature validity and separate from archive policy satisfaction.

Frozen compatibility predicate:

- exactly one bundled key entry MUST satisfy `id == publicKeyRef`
- that entry MUST also satisfy `suite == <signature-entry.suite>`
- the declared bundled-key `encoding` MUST decode successfully into exactly one key value
- the decoded key value MUST be structurally valid for the declared `kty` and usable with the declared `suite`
- detached-signature verification against that decoded key and the declared target bytes MUST succeed
- zero matches, multiple matches, decode failure, structural key invalidity, suite mismatch, or verification failure MUST reject the signature entry

### 3.8 Transition-record semantics

- Every QV-produced same-state resharing event MUST create a transition record.
- Transition records are maintenance/provenance records, not archive-approval substitutes.
- Maintenance signatures over transition records MUST be supported by the artifact family.
- Presence of a maintenance signature is not a Phase 1 precondition for resharing unless a later governance profile requires it.

### 3.9 Migration continuity requirement

State-changing lifecycle operations are deferred, but the architectural requirement is already frozen:

- any later policy change, reencryption, or future `rewrap` MUST preserve predecessor archive-state descriptors, predecessor archive-approval signatures, predecessor timestamp/evidence sets, and continuity links sufficient to verify lineage
- no state-changing feature may ship until that preservation path is defined and implemented

## 4. Success Criteria For The First Shipping Wave

Phase 1 shipping is complete only if Quantum Vault can:

1. produce successor archive-state descriptors, cohort bindings, and lifecycle bundles deterministically
2. export archive-state descriptor bytes as the external signer target
3. attach archive-approval signatures, public keys, and OTS evidence without mutating archive-state bytes
4. restore from successor shards using explicit state/cohort selection rather than manifest/bundle digest pairing
5. perform same-state resharing without changing archive-state descriptor bytes
6. emit a required transition record for every QV-produced same-state resharing event
7. keep integrity, signature validity, pinning, and policy satisfaction distinct in verification output

## 5. Phase 0 — Freeze Specs, Artifact IDs, And Wire Decisions

Objective:

- remove remaining architecture ambiguity before code changes start

Required decisions and outputs:

- freeze schema/type/version identifiers for:
  - archive-state descriptor
  - cohort binding
  - transition record
  - source-evidence object
  - lifecycle bundle
- freeze the exact archive-state descriptor v1 allowed field set with no additional v1 fields
- freeze derived-only `stateId` semantics
- freeze derived-only `cohortId` semantics and the exact cohort-id preimage
- freeze shard carriage and embedding strategy
- freeze lifecycle-bundle v1 contents and the exact top-level / `attachments` member boundary
- freeze transition-record requirement for same-state resharing
- freeze successor `publicKeyRef` compatibility and fail-closed semantics
- freeze detached-signature and timestamp attachment contracts:
  - `signatureFamily`
  - `targetType`
  - `targetRef`
  - `targetDigest`
  - `publicKeyRef`
- freeze restore bundle-selection semantics with no heuristic auto-selection across multiple embedded bundle digests
- freeze verifier predicates and rejection conditions

Spec/document tasks:

- align `implementation-questions-and-reading.md`, `resharing-design.md`, and `roadmap-archive-lifecycle.md` with the frozen decisions above
- document explicit successor-family cutover from the current manifest/bundle family
- document migration continuity as an architectural requirement even though migration features remain deferred
- document normative/informative boundaries and RFC 2119 / RFC 8174 usage

Code tasks:

- none beyond issue breakdown and file-scope planning

Test-vector tasks:

- none; Phase 0 should only freeze the contracts later vectors must encode

Security review points:

- confirm the frozen field set fully preserves current ciphertext/policy interpretation requirements
- confirm bundle v1 contents do not weaken closed-schema discipline
- confirm shard carriage keeps the Phase 1 system browser-first and client-only
- confirm there is no self-referential identifier hashing ambiguity

Exit criteria:

- no remaining ambiguity on archive-state fields, shard carriage, lifecycle-bundle v1 contents, or transition-record requirement

### 5.1 Phase 0 Freeze Addendum

This addendum is the authoritative Phase 0 freeze record for the lifecycle successor family.
Later phases may only encode, test, or implement the contracts below.
They MUST NOT reinterpret or reopen them.

| Contract | Frozen now in Phase 0 | Later codification work |
| --- | --- | --- |
| Successor-family boundary | Successor artifact family only; current manifest/bundle family remains unchanged; archive-state descriptor is the long-lived archive-approval target | Encode in schemas, tooling selectors, and migration guards without reopening the boundary |
| Artifact identifiers | `quantum-vault-archive-state-descriptor/v1`, `quantum-vault-cohort-binding/v1`, `quantum-vault-transition-record/v1`, `quantum-vault-source-evidence/v1`, and `QV-Lifecycle-Bundle` v1 are fixed | Materialize these exact identifiers in schemas, fixtures, parsers, and reporting |
| Archive-state descriptor v1 field closure | Exact allowed top-level and `qenc` members are frozen; no additional v1 fields are permitted | Encode the closed schema and semantic rejection paths |
| `stateId` | `stateId = archiveStateDigest.value`; derived-only; excluded from canonical archive-state bytes | Implement digest/identifier helpers and rejection vectors |
| `cohortId` | `cohortId = SHA3-256(RFC 8785-canonicalized cohort-id preimage)`; derived-only; excluded from canonical cohort-binding bytes | Encode the exact preimage and rejection vectors |
| Shard carriage | QV-produced shards embed archive-state bytes/digest, cohort-binding bytes/digest, lifecycle-bundle bytes/digest, plus shard metadata carrying `archiveId`, `stateId`, `cohortId`, and shard index | Encode shard-carrier fields and restore readers without changing semantics |
| Lifecycle-bundle v1 member boundary | Exact top-level members and exact `attachments` members are frozen; arrays are always present; no extra v1 members are permitted | Encode bundle schema, serializers, and honest mixed-bundle reporting |
| Transition requirement | Every QV-produced same-state resharing event MUST emit one transition record | Implement emission and verification paths; governance policy may later require extra signatures but not remove the record |
| Detached-signature and timestamp wire contracts | Attachment field set, family mappings, target mappings, exact detached-signature-byte timestamp linkage, and no heuristic reinterpretation are frozen | Encode schemas, signer exports, attach handling, and restore validation |
| `publicKeyRef` | Compatibility predicate and fail-closed behavior are frozen, including exact-one-match, suite equality, successful decode, structural key validity, and successful verification | Encode shared attach/restore resolution logic and negative vectors |
| Restore bundle selection | Restore groups by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes; no heuristic bundle auto-selection across multiple embedded bundle digests | Implement UI/input flows and bundle-selection validation without adding heuristics |
| Verifier predicates and rejections | Digest equality, derived-ID equality, shard-set consistency, target equality, exact OTS linkage, fail-closed `publicKeyRef`, and explicit rejection conditions are frozen | Implement verifier/reporting code and test vectors; no predicate may be silently dropped or collapsed |
| Normative/informative boundary | RFC 2119 / RFC 8174 keywords apply only where documents explicitly use all-caps requirements; explanatory prose remains informative | Keep later edits consistent with the same boundary and avoid prose-only contract changes |

### 5.2 Phase 0 Security Review Dispositions

Disposition 1: frozen field set preserves current ciphertext/policy interpretation requirements.

- accepted
- the archive-state descriptor retains the current ciphertext-binding and policy-interpretation classes:
  - `qencHash` / container identity anchors
  - AEAD/AAD interpretation fields carried by `noncePolicyId`, `nonceMode`, `counterBits`, `maxChunkCount`, and `aadPolicyId`
  - KDF interpretation fields carried by `kdfTreeId`
  - crypto-profile identity carried by `cryptoProfileId`
  - policy commitment carried by `authPolicyCommitment`
- cohort-level sharding details, shard hashes, and custodian logistics remain outside archive-state identity and therefore do not weaken ciphertext/policy interpretation

Disposition 2: lifecycle-bundle v1 contents do not weaken closed-schema discipline.

- accepted
- lifecycle-bundle v1 now has an exact top-level member set and exact `attachments` member set
- all attachment families and top-level arrays are mandatory even when empty, so later semantics do not depend on missing-member heuristics
- later work must encode explicit schemas under JSON Schema draft 2020-12 rather than introduce prose-only extension paths

Disposition 3: shard carriage keeps the Phase 1 system browser-first and client-only.

- accepted
- QV-produced shards remain self-contained and carry all lifecycle objects needed for restore
- attach and restore may accept optional external files, but no server coordinator, interactive MPC protocol, or always-online dependency is introduced by shard carriage

Disposition 4: there is no self-referential identifier hashing ambiguity.

- accepted
- `stateId` is excluded from the canonical archive-state descriptor bytes used to derive it
- `cohortId` is excluded from the canonical cohort-binding bytes used to derive `cohortBindingDigest`
- `cohortId` is derived from a separate frozen preimage rooted in `archiveId`, `stateId`, and `cohortBindingDigest`
- lifecycle-bundle digest is explicitly outside state/cohort identity
- timestamp linkage is over exact detached-signature bytes rather than over mutable bundle bytes

## 6. Phase 1 — Encode Frozen Successor Artifacts, Canonical Bytes, And Shard Layout

Objective:

- implement the successor artifact family and the carrier layout used by shards

Depends on:

- Phase 0

Spec/schema tasks:

- encode `quantum-vault-archive-state-descriptor/v1`
- encode `quantum-vault-cohort-binding/v1`
- encode `quantum-vault-transition-record/v1`
- encode `quantum-vault-source-evidence/v1`
- encode `QV-Lifecycle-Bundle` v1
- encode that archive-state, cohort-binding, transition-record, and source-evidence canonical bytes use `QV-JSON-RFC8785-v1`
- encode that lifecycle-bundle bytes use `QV-BUNDLE-JSON-v1`
- encode `archiveStateDigest = SHA3-512(canonical archive-state bytes)`
- encode `stateId = archiveStateDigest.value`
- enforce that `stateId` MUST NOT appear inside the canonical archive-state descriptor bytes
- encode `cohortBindingDigest = SHA3-512(canonical cohort-binding bytes)`
- enforce that `cohortId` MUST NOT appear inside the canonical cohort-binding bytes
- encode the exact preimage used for `cohortId`
- encode lowercase-hex output for all successor digest and identifier values
- encode duplicate-name rejection and I-JSON-safe numeric expectations for lifecycle parsing

Shard-format tasks:

- encode successor `.qcont` embedding fields for archive-state bytes/digest, cohort-binding bytes/digest, and lifecycle-bundle bytes/digest
- encode shard metadata fields carrying `archiveId`, `stateId`, `cohortId`, and shard index
- enforce that lifecycle-bundle digest is **not** part of cohort identity
- encode that mixed bundle digests inside one otherwise consistent cohort are bundle-variation cases, not mixed-cohort cases

Implementation tasks:

- add canonicalization helpers for archive-state, cohort-binding, transition-record, and source-evidence objects
- add digest helpers for `archiveStateDigest` and `cohortBindingDigest`
- implement `archiveId` generation
- implement `stateId` derivation from archive-state canonical bytes
- implement `cohortId` derivation from the frozen preimage
- reject archive-state objects that attempt to carry `stateId`
- reject cohort-binding objects that attempt to carry `cohortId`
- add serializers/parsers for all successor artifacts
- update shard builder to embed the three successor objects plus their digests

Test-vector tasks:

- valid/invalid archive-state descriptor fixtures
- valid/invalid cohort-binding fixtures
- valid/invalid lifecycle-bundle fixtures
- identifier derivation vectors for `archiveId`, `stateId`, and `cohortId`
- cross-runtime canonicalization vectors for archive-state, cohort-binding, transition-record, and source-evidence bytes
- malformed JSON vectors with duplicate object names
- out-of-profile numeric vectors that violate the I-JSON-safe subset

Security review points:

- verify archive-state fields include all algorithm-interpretation-critical fields from the current baseline
- verify `cohortId` cannot be reused across distinct cohort-binding objects
- verify lifecycle-bundle digests are not accidentally promoted into state/cohort identity

Exit criteria:

- successor artifact schemas exist
- shards can carry the successor artifacts
- canonicalization/digest vectors pass

## 7. Phase 2 — External Signer Targets, Attach Flow, And Frozen Signature Attachment Semantics

Objective:

- update signer-facing and attach-facing workflows to the new archive-state target and successor bundle

Depends on:

- Phase 1

Spec/schema tasks:

- encode archive-approval signature attachment shape targeting archive-state descriptor bytes
- encode maintenance-signature attachment shape targeting transition-record bytes
- encode source-evidence-signature attachment shape targeting source-evidence object bytes
- require all detached-signature entries to carry:
  - `id`
  - `signatureFamily`
  - `format`
  - `suite`
  - `targetType`
  - `targetRef`
  - `targetDigest`
  - `signatureEncoding`
  - `signature`
  - optional `publicKeyRef`
- encode family mappings:
  - archive-approval -> `targetType = "archive-state"`
  - maintenance -> `targetType = "transition-record"`
  - source-evidence -> `targetType = "source-evidence"`
- encode `targetRef` rules:
  - `state:<stateId>`
  - `transition:sha3-512:<digest>`
  - `source-evidence:sha3-512:<digest>`
- encode `targetDigest` rules:
  - `SHA3-512` over canonical target bytes for archive-state, transition-record, and source-evidence targets
- encode timestamp attachment shape targeting detached signature bytes by `targetRef` plus exact `targetDigest = SHA-256(detached-signature-bytes)`
- encode bundled `publicKeys[]` shape and the frozen `publicKeyRef` compatibility predicate across attachment families

External signer tooling tasks:

- update export flows so the canonical archive-state descriptor is the signable external artifact
- update signature verification descriptors so archive-approval signatures declare `targetType = "archive-state"`
- preserve the current detached-wrapper discipline for `.qsig` and `.sig`
- keep direct `.qenc` signatures out of the default archive-approval flow

Attach-flow tasks:

- update attach to import archive-approval signatures, bundled key material, and OTS evidence into `QV-Lifecycle-Bundle` v1
- validate that archive-approval signatures target the selected `archiveStateDigest`
- validate all signature-family / `targetType` / `targetRef` / `targetDigest` combinations against the actual target bytes
- validate `publicKeyRef` fail closed for bundled signatures
- validate OTS linkage only against detached signature bytes
- write updated lifecycle bundles without mutating archive-state or cohort-binding bytes
- support rewriting embedded lifecycle bundles across all shards of the selected cohort
- support partial shard rewrites safely: mixed embedded lifecycle-bundle digests inside one cohort remain allowed but must be reported honestly at restore time

Implementation tasks:

- update attachment parsing/normalization to understand:
  - `archiveApprovalSignatures[]`
  - `maintenanceSignatures[]`
  - `sourceEvidenceSignatures[]`
  - `publicKeys[]`
  - `timestamps[]`
- implement fail-closed `publicKeyRef` resolution for all bundled signature families
- keep pinning state separate from signature validity and separate from archive policy evaluation

Test-vector tasks:

- valid archive-approval signature vectors over archive-state descriptor bytes
- invalid target-type and target-digest vectors
- invalid `signatureFamily` / `targetType` combinations
- invalid `targetRef` prefix or digest-reference vectors
- `publicKeyRef` mismatch vectors that fail signature verification
- OTS linkage vectors over detached signature bytes
- attach/regression vectors proving archive-state bytes remain unchanged through attach

Security review points:

- verify archive-approval signatures cannot be misread as signatures over mutable bundle bytes
- verify `publicKeyRef` failure cannot degrade into mere “unpinned” reporting
- verify OTS remains evidence-only and cannot satisfy archive policy by itself

Exit criteria:

- external signer target is archive-state descriptor bytes
- attach can update lifecycle bundles without mutating archive-state or cohort-binding bytes
- bundled-key and OTS linkage checks are fail-closed

## 8. Phase 3 — Restore Flow, Cohort Selection, And Successor Verification States

Objective:

- replace current restore cohort-selection assumptions with explicit archive/state/cohort handling

Depends on:

- Phase 1
- Phase 2

Restore-selection tasks:

- group restore candidates by:
  - `archiveId`
  - `stateId`
  - `cohortId`
- verify exact archive-state descriptor byte equality inside a candidate cohort
- verify exact cohort-binding byte equality inside a candidate cohort
- reject mixed-state or mixed-cohort candidate sets fail closed

Bundle-selection tasks:

- treat differing embedded lifecycle-bundle digests within one otherwise identical cohort as bundle variants, not new cohorts
- accept an uploaded lifecycle bundle only if it matches the selected archive-state and current cohort-binding digests
- if no uploaded bundle is supplied and exactly one embedded lifecycle-bundle digest is present, use it
- if no uploaded bundle is supplied and more than one embedded lifecycle-bundle digest is present, fail closed and require explicit lifecycle-bundle bytes or explicit operator selection of one embedded bundle digest
- preserve honest reporting when payload reconstruction uses shards carrying different embedded lifecycle-bundle digests

Verification-state tasks:

- preserve distinct successor verification outputs for:
  - integrity verified
  - archive-approval signature verified
  - signer pinned
  - archive policy satisfied
  - maintenance signature verified
  - source-evidence signature verified
  - OTS evidence linked
- ensure archive policy is satisfied only by archive-approval signatures
- ensure maintenance or source-evidence signatures never satisfy archive policy
- implement and report the frozen explicit verifier predicates for:
  - archive-state digest equality
  - archive identity equality
  - `stateId` derivation equality
  - cohort-binding digest equality
  - `cohortId` derivation equality
  - shard-set consistency
  - fail-closed `publicKeyRef` resolution
  - OTS linkage equality
  - archive-policy counting

Implementation tasks:

- replace current manifest/bundle digest-pair candidate grouping with explicit state/cohort grouping
- update restore UI/reporting to surface mixed bundle variants within one cohort honestly
- preserve explicit uploaded bundle / uploaded archive-state disambiguation paths
- remove bundle-richness heuristics from automatic restore selection

Test-vector tasks:

- mixed state rejection
- mixed cohort rejection
- same cohort with multiple embedded lifecycle-bundle digests
- restore rejection when multiple embedded bundle digests exist and no explicit bundle is supplied
- uploaded lifecycle bundle disambiguation
- uploaded archive-state descriptor disambiguation
- vectors showing policy is driven by archive-approval signatures only
- vectors showing maintenance/source-evidence signatures do not satisfy archive policy

Security review points:

- verify restore never falls back to a “largest cohort wins” rule
- verify bundle-variant selection cannot cross state or cohort boundaries
- verify multi-bundle states fail closed without explicit operator selection
- verify pinning and archive policy remain distinct result channels

Exit criteria:

- restore selection uses archive/state/cohort identity explicitly
- successor verification states are separated and reported correctly

## 9. Phase 4 — Same-State Resharing

Objective:

- implement same-state resharing as availability maintenance over a stable archive state

Depends on:

- Phase 3

Implementation semantics to preserve:

- same-state resharing reconstructs the ML-KEM private key material required to re-split the current encrypted state
- it does **not** decrypt plaintext unless a separate decrypt flow is invoked
- the `.qenc` bytes remain unchanged
- archive-state descriptor bytes remain unchanged
- a new cohort binding and new `cohortId` are produced

Allowed changes in same-state resharing:

- `n`
- `k`
- derived `t` under the frozen `QV-RS-ErasureCodes-v1` parity rule
- `shareCommitments[]`
- `shardBodyHashes[]`
- custodian assignment
- embedded lifecycle-bundle bytes

Current v1 limitation:

- the shipped successor implementation keeps `codecId`, `bodyDefinitionId`, and `bodyDefinition` frozen to the closed v1 schema and artifact contracts
- broader cohort-level flexibility remains design direction, not current v1 behavior

Forbidden changes in same-state resharing:

- `archiveId`
- `stateId`
- archive-state descriptor bytes
- `qencHash`
- `containerId`
- `cryptoProfileId`
- `kdfTreeId`
- nonce/AAD semantics
- `authPolicyCommitment`

Implementation tasks:

- implement `reshareSameState(...)`
- require a threshold of shards from one internally consistent predecessor cohort
- verify predecessor share commitments and shard-body hashes
- reconstruct the ML-KEM private key material in memory
- generate fresh Shamir shares and a new cohort binding
- derive the successor `cohortId`
- emit successor shards embedding:
  - unchanged archive-state descriptor
  - new cohort binding
  - updated lifecycle bundle
- generate the required transition record
- attempt best-effort zeroization immediately after resharing

Operational tasks:

- instruct custodians to destroy predecessor shards
- report clearly that resharing does not prove destruction and does not revoke previously leaked old quorum material

Test-vector tasks:

- same-state resharing with unchanged archive state and changed cohort
- resharing with changed `n/k`, with successor `t` derived under the frozen v1 codec/body-definition surface
- rejection of accidental archive-state mutation
- rejection of mixed predecessor cohorts
- rejection of ambiguous predecessor lifecycle-bundle selection without explicit disambiguation
- rejection when predecessor share commitments or shard-body hashes fail beyond tolerance
- regression vectors proving archive-approval signatures survive resharing

Security review points:

- verify resharing is availability maintenance, not implicit archive re-approval
- verify resharing does not claim to repair predecessor-cohort compromise
- verify secret-in-memory handling stays within the acknowledged browser/runtime risk model

Exit criteria:

- same-state resharing works end to end
- archive-state signatures survive unchanged
- required transition record is emitted

## 10. Phase 5 — Transition Verification, Maintenance Signatures, And Fork Handling

Objective:

- make resharing auditable and detect parallel cohorts for the same archive state

Depends on:

- Phase 4

Transition-record tasks:

- implement canonical transition-record serialization and digesting
- implement maintenance-signature verification over transition-record bytes
- surface maintenance signature purpose labels such as:
  - `maintenance-authorization`
  - `operator-attestation`
  - `witness`

Implementation note:

- Phase 5 verification intentionally accepts only `same-state-resharing` transitions with `fromStateId === toStateId`; future state-changing transition types require explicit verifier extension.
- Maintenance purpose labels are advisory allow-list metadata in the lifecycle verifier; unknown `actorHints` purpose strings are ignored and do not affect archive policy or maintenance-signature verification.

Fork-handling tasks:

- detect multiple valid `cohortId` values for one `archiveId` plus `stateId`
- distinguish:
  - different cohorts for one state
  - different lifecycle-bundle digests for one cohort
- warn when multiple valid cohorts exist for one state
- reject mixed cohorts in one restore attempt even if both cohorts are individually valid
- do not auto-select an active cohort by timestamp, attachment count, or lexical identifier order

Implementation tasks:

- verify transition references to predecessor/successor cohort-binding digests
- verify transition-record family and target semantics for maintenance signatures
- add tooling output for same-state fork conditions

Test-vector tasks:

- valid resharing transition chain
- unsigned transition record present
- signed transition record present
- invalid maintenance-signature target
- same-state fork with two valid cohorts
- mixed bundle variants within one cohort, proving this is not treated as a fork

Security review points:

- verify maintenance signatures cannot be miscounted as archive-approval signatures
- verify no heuristic winner selection overrides explicit governance

Exit criteria:

- transition records verify
- maintenance signatures verify
- fork warnings are correct and scoped to state/cohort conflicts

## 11. Phase 6 — Source-Evidence Object Support

Objective:

- implement first-class provenance support without conflating it with archive-state approval

Depends on:

- Phase 2 for bundle/signature attachment support
- Phase 3 for successor verification reporting

Important scope note:

- lifecycle-bundle v1 already includes `sourceEvidence[]` and `sourceEvidenceSignatures[]`
- this phase is about producing, parsing, validating, and semantically verifying non-empty source-evidence content
- it is **not** a prerequisite for same-state resharing

Implementation tasks:

- implement source-evidence schema validation
- implement canonical source-evidence serialization and digesting
- implement source-evidence signature verification
- implement the privacy-preserving default profile:
  - emit digests and relation metadata by default
  - require explicit opt-in for descriptive fields
  - suppress local paths, usernames, email addresses, and operator notes by default
- display source-evidence verification distinctly from archive approval and maintenance signatures
- preserve external-source-signature references when present

Test-vector tasks:

- source-evidence fixtures with different `relationType` values
- source-evidence signature vectors
- negative vectors proving source-evidence signatures do not satisfy archive policy
- privacy/regression vectors for optional descriptive fields

Security review points:

- verify source-review claims cannot be promoted automatically to archive approval
- verify optional descriptive fields do not create accidental privacy leaks by default

Exit criteria:

- source-evidence provenance is supported as a separate semantic layer

## 12. Phase 7 — Full UI/UX Migration, Documentation Closure, And Legacy Retirement

Objective:

- make the successor lifecycle available on the normal regular-user surface
- move both Lite and Pro workflows to the successor artifact family and successor shard containers
- finish documentation of the current implementation state
- retire the legacy manifest/bundle system as an active product path rather than leaving it as the default user experience

Depends on:

- Phase 6
- publication-readiness correction of the current documentation set
- release-hardening verification for successor build, attach, restore, and same-state resharing flows

Important scope note:

- this phase is about product cutover, documentation closure, and legacy retirement
- it MUST preserve the frozen successor contracts and fail-closed restore semantics already established in Phases 0 through 6
- it MUST NOT reopen Phase 0 wire decisions or substitute a new architecture

Lite-mode migration tasks:

- make Lite create new archives as successor archives by default, including successor shard output rather than legacy manifest/bundle-first output
- export the correct successor signable artifact for external archive approval in Lite workflows
- update Lite labels, help text, and guided steps so they describe:
  - archive-state descriptor signing
  - lifecycle-bundle attachment
  - successor restore verification states
  - same-state resharing as maintenance rather than re-approval
- keep any temporary legacy import or restore affordance explicitly labeled as compatibility-only until final removal
- ensure Lite never hides required explicit selection when multiple lifecycle bundles or same-state cohorts are present

Pro-mode migration tasks:

- move Pro build/export flows to the successor archive-state / cohort-binding / lifecycle-bundle model and successor shard container outputs
- expose successor-specific operator controls where the implementation already requires explicit operator choice, including:
  - archive/state/cohort selection
  - lifecycle-bundle selection when one cohort carries multiple embedded bundle digests
  - same-state resharing controls and resulting transition records
- update Pro restore and inspection output so archive approval, maintenance signatures, source evidence, pinning, and OTS remain visibly separate
- keep any temporary legacy tooling behind an explicit compatibility boundary until final retirement

Container and artifact cutover tasks:

- make successor containers and successor artifact exports the default downloadable outputs in the regular-user UI
- ensure the signable archive-state descriptor, lifecycle bundle, and successor shard set can be exported and re-imported without falling back to legacy manifest assumptions
- remove generation of new legacy manifest/bundle artifacts from the default build path once successor UI cutover is complete
- preserve explicit compatibility parsing only as long as the documented phase-out window remains open

Documentation-closure tasks:

- update the current public and maintainer-facing documentation so it fully describes the current shipped state rather than the previously frozen implementation intent
- explicitly document, separately for Lite and Pro:
  - which successor workflows are available to regular users
  - which successor workflows remain advanced or operator-facing
  - which legacy affordances, if any, still exist during the phase-out window
- verify that the following are fully current and mutually consistent:
  - `README.md`
  - `docs/README.md`
  - `docs/format-spec.md`
  - `docs/WHITEPAPER.md`
  - `docs/security-model.md`
  - `docs/trust-and-policy.md`
  - `docs/long-term-archive.md`
  - in-product Lite and Pro help text
  - interoperability/vector appendices
- remove or relocate any remaining outdated text that still describes:
  - legacy manifest signing as the default path for new archives
  - successor `archiveId` or successor artifact support as future work if it is already implemented
  - deferred features as current capability
- document any still-deferred areas explicitly as deferred, including:
  - state-changing lifecycle continuity
  - future `rewrap` / wrapped-DEK work
  - RFC 4998-style renewable evidence
  - governance or trust-root objects beyond the current implementation

Legacy phase-out tasks:

- define and publish the point at which legacy becomes compatibility-only rather than a normal creation path
- stop offering legacy archive creation in Lite and Pro once successor build/export is available on the regular-user surface
- migrate any remaining legacy-first UI wording, screenshots, examples, and walkthroughs to successor-first wording before release
- after the compatibility window closes, remove user-facing legacy build, attach, and restore flows from the product surface
- move any remaining legacy-only material to historical or archival documentation if it is retained for reference
- remove legacy code paths only after successor replacements are shipped, documented, and covered by release-gate tests

Test and release-gate tasks:

- add release-gate coverage for regular-user successor build/export paths in Lite and Pro
- add UI/regression coverage proving the product surface no longer defaults to legacy manifest/bundle semantics for new archives
- keep explicit fail-closed regression coverage for:
  - mixed legacy/successor inputs
  - mixed same-state cohorts
  - ambiguous lifecycle-bundle selection
  - separation of archive approval, maintenance, source evidence, and OTS
- keep legacy regression coverage only for as long as legacy compatibility support remains in the shipped product

Security review points:

- verify the UI cutover does not reintroduce heuristic restore or bundle-selection behavior
- verify Lite simplification does not collapse archive approval, maintenance, source evidence, pinning, and policy into one generic “trusted” state
- verify legacy retirement does not leave undocumented fallback paths or misleading help text
- verify publication and product wording do not imply normal regular-user availability until the successor UI cutover is actually shipped

Exit criteria:

- regular users can create and work with successor archives in both Lite and Pro
- successor containers and successor artifact exports are the default product path
- the current documentation set is complete, current, and honest about implemented vs deferred capability
- legacy creation and other legacy-first product flows are retired from the normal user surface
- any remaining legacy compatibility support is explicitly documented as temporary or historical, or is removed entirely

## 13. Later Phases — Deferred But Architecturally Constrained

### 13.1 Later Phase A — State-changing migration continuity

Not part of the first shipping wave.

Must not start until there is an implemented continuity-preservation path for:

- predecessor archive-state descriptors
- predecessor archive-approval signatures
- predecessor timestamps/evidence
- transition links across states

Planned work:

- policy-change transitions
- reencryption transitions
- continuity-preserving historical packaging
- renewed archive-approval signatures and timestamps for new states

### 13.2 Later Phase B — Envelope-DEK and future `rewrap`

Architecture-blocked until QV adopts a wrapped-DEK design.

Planned work:

- inner/outer ciphertext design
- new state semantics for `rewrap`
- continuity rules for rewrap-capable states

### 13.3 Later Phase C — Renewable evidence records

Future work only.

Planned work:

- renewable evidence-record objects
- explicit renewal timing and witness strategy
- RFC 4998-inspired lifecycle, without misrepresenting it as current capability

### 13.4 Later Phase D — Distributed resharing

Future research only.

Planned work:

- PSS / VSS / DPSS feasibility
- online-custodian trust model
- protocol transcripts and witnessability

This branch must not leak server-coordinated or MPC assumptions into the Phase 1 browser-first model.

## 14. Explicit Non-Goals For The First Shipping Wave

- no mutation of current manifest/bundle schemas
- no implicit grammar extension path
- no server-coordinated or online-custodian resharing
- no claim that same-state resharing revokes leaked predecessor quorum material
- no direct `.qenc` signature requirement in the default archive-authenticity path
- no collapsing of archive approval, maintenance signatures, and source-evidence signatures into one generic attachment class
- no auto-winner selection for same-state cohort forks
- no state-changing migration feature before predecessor-state preservation is designed and implemented

## 15. Implementation Summary

The strict execution order is:

1. freeze the artifact family, field set, shard carriage, bundle contents, and transition semantics
2. implement successor artifacts and successor shard layout
3. move external signer and attach flows to archive-state descriptor bytes
4. replace restore candidate selection with explicit archive/state/cohort logic
5. ship same-state resharing with required transition records
6. add transition verification, maintenance signatures, and fork warnings
7. optionally ship source-evidence authoring and verification
8. complete regular-user UI/UX cutover, documentation closure, and legacy retirement
9. defer migration continuity, `rewrap`, renewable evidence, and distributed resharing

That order keeps the implementation aligned with the current Quantum Vault baseline while solving the actual lifecycle contradiction instead of only renaming it.
