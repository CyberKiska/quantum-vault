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
- Concrete `n/k/t/codecId` are **cohort-level**, not state-level.
- Same-state resharing MAY change concrete cohort parameters without changing `stateId`.
- Any state change creates a new `stateId`.
- Because cohort bindings are state-bound, any new `stateId` also requires a new cohort-binding object and a new `cohortId`.

### 3.4 Minimum archive-state descriptor field set

The successor archive-state descriptor MUST carry at least:

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

This field set is frozen strongly enough for schema work, external signer target updates, restore checks, and future migration continuity.

### 3.5 Shard carriage strategy

Successor `.qcont` shards produced by Quantum Vault will embed:

- canonical archive-state descriptor bytes plus digest
- canonical current cohort-binding bytes plus digest
- current lifecycle-bundle bytes plus digest
- shard metadata including `archiveId`, `stateId`, `cohortId`, and shard index

This is a deliberate carry-forward of the current self-contained shard model.
External archive-state, bundle, signature, key, and timestamp artifacts may still be supplied at attach or restore time, but QV-produced shards remain self-describing.

### 3.6 Lifecycle-bundle v1 contents

`QV-Lifecycle-Bundle` v1 is frozen as containing:

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

All array-valued attachment families and top-level arrays above MUST be present even when empty.
This avoids a second top-level schema change merely to introduce a semantically central lifecycle object class.

### 3.7 `publicKeyRef` and pinning semantics

- A bundled signature entry that declares `publicKeyRef` MUST resolve to compatible bundled key material for that signature.
- Failure to resolve or verify a declared `publicKeyRef` is a **signature verification failure** for that signature, not merely absence of pinning.
- Pinning remains separate from signature validity and separate from archive policy satisfaction.

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
- freeze the minimum archive-state descriptor field set
- freeze the cohort-binding preimage for `cohortId`
- freeze shard carriage and embedding strategy
- freeze lifecycle-bundle v1 contents
- freeze transition-record requirement for same-state resharing
- freeze successor `publicKeyRef` failure semantics

Spec/document tasks:

- align `implementation-questions-and-reading.md`, `resharing-design.md`, and `roadmap-archive-lifecycle.md` with the frozen decisions above
- document explicit successor-family cutover from the current manifest/bundle family
- document migration continuity as an architectural requirement even though migration features remain deferred

Code tasks:

- none beyond issue breakdown and file-scope planning

Test-vector tasks:

- none; Phase 0 should only freeze the contracts later vectors must encode

Security review points:

- confirm the frozen field set fully preserves current ciphertext/policy interpretation requirements
- confirm bundle v1 contents do not weaken closed-schema discipline
- confirm shard carriage keeps the Phase 1 system browser-first and client-only

Exit criteria:

- no remaining ambiguity on archive-state fields, shard carriage, lifecycle-bundle v1 contents, or transition-record requirement

## 6. Phase 1 — Define Successor Artifacts, Canonical Bytes, And Shard Layout

Objective:

- implement the successor artifact family and the carrier layout used by shards

Depends on:

- Phase 0

Spec/schema tasks:

- define `quantum-vault-archive-state-descriptor/v1`
- define `quantum-vault-cohort-binding/v1`
- define `quantum-vault-transition-record/v1`
- define `quantum-vault-source-evidence/v1`
- define `QV-Lifecycle-Bundle` v1
- state that archive-state, cohort-binding, transition-record, and source-evidence canonical bytes use `QV-JSON-RFC8785-v1`
- state that lifecycle-bundle bytes use `QV-BUNDLE-JSON-v1`
- define `archiveStateDigest = SHA3-512(canonical archive-state bytes)`
- define `stateId = archiveStateDigest.value`
- define `cohortBindingDigest = SHA3-512(canonical cohort-binding bytes)`
- define the exact preimage used for `cohortId`

Shard-format tasks:

- define successor `.qcont` embedding fields for archive-state bytes/digest, cohort-binding bytes/digest, and lifecycle-bundle bytes/digest
- define shard metadata fields carrying `archiveId`, `stateId`, `cohortId`, and shard index
- freeze that lifecycle-bundle digest is **not** part of cohort identity
- define that mixed bundle digests inside one otherwise consistent cohort are bundle-variation cases, not mixed-cohort cases

Implementation tasks:

- add canonicalization helpers for archive-state, cohort-binding, transition-record, and source-evidence objects
- add digest helpers for `archiveStateDigest` and `cohortBindingDigest`
- implement `archiveId` generation
- implement `stateId` derivation from archive-state canonical bytes
- implement `cohortId` derivation from the frozen preimage
- add serializers/parsers for all successor artifacts
- update shard builder to embed the three successor objects plus their digests

Test-vector tasks:

- valid/invalid archive-state descriptor fixtures
- valid/invalid cohort-binding fixtures
- valid/invalid lifecycle-bundle fixtures
- identifier derivation vectors for `archiveId`, `stateId`, and `cohortId`
- cross-runtime canonicalization vectors for archive-state, cohort-binding, transition-record, and source-evidence bytes

Security review points:

- verify archive-state fields include all algorithm-interpretation-critical fields from the current baseline
- verify `cohortId` cannot be reused across distinct cohort-binding objects
- verify lifecycle-bundle digests are not accidentally promoted into state/cohort identity

Exit criteria:

- successor artifact schemas exist
- shards can carry the successor artifacts
- canonicalization/digest vectors pass

## 7. Phase 2 — External Signer Targets, Attach Flow, And Signature Attachment Semantics

Objective:

- update signer-facing and attach-facing workflows to the new archive-state target and successor bundle

Depends on:

- Phase 1

Spec/schema tasks:

- define archive-approval signature attachment shape targeting archive-state descriptor bytes
- define maintenance-signature attachment shape targeting transition-record bytes
- define source-evidence-signature attachment shape targeting source-evidence object bytes
- define timestamp attachment shape targeting detached signature bytes by signature-family plus `targetRef`
- define bundled `publicKeys[]` shape and compatible `publicKeyRef` use across attachment families

External signer tooling tasks:

- update export flows so the canonical archive-state descriptor is the signable external artifact
- update signature verification descriptors so archive-approval signatures declare `target.type = archive-state`
- preserve the current detached-wrapper discipline for `.qsig` and `.sig`
- keep direct `.qenc` signatures out of the default archive-approval flow

Attach-flow tasks:

- update attach to import archive-approval signatures, bundled key material, and OTS evidence into `QV-Lifecycle-Bundle` v1
- validate that archive-approval signatures target the selected `archiveStateDigest`
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
- if no uploaded bundle is supplied, select an embedded lifecycle bundle deterministically only within the already selected state/cohort
- preserve honest warnings when payload reconstruction uses shards carrying different embedded lifecycle-bundle digests

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

Implementation tasks:

- replace current manifest/bundle digest-pair candidate grouping with explicit state/cohort grouping
- update restore UI/reporting to surface mixed bundle variants within one cohort honestly
- preserve explicit uploaded bundle / uploaded archive-state disambiguation paths
- keep bundle richness heuristics scoped only to lifecycle-bundle selection within one already selected cohort

Test-vector tasks:

- mixed state rejection
- mixed cohort rejection
- same cohort with multiple embedded lifecycle-bundle digests
- uploaded lifecycle bundle disambiguation
- uploaded archive-state descriptor disambiguation
- vectors showing policy is driven by archive-approval signatures only
- vectors showing maintenance/source-evidence signatures do not satisfy archive policy

Security review points:

- verify restore never falls back to a “largest cohort wins” rule
- verify bundle-variant selection cannot cross state or cohort boundaries
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
- `t`
- `codecId`
- `bodyDefinitionId`
- `bodyDefinition`
- `shareCommitments[]`
- `shardBodyHashes[]`
- custodian assignment
- embedded lifecycle-bundle bytes

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
- resharing with changed `n/k/t/codecId`
- rejection of accidental archive-state mutation
- rejection of mixed predecessor cohorts
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

## 12. Later Phases — Deferred But Architecturally Constrained

### 12.1 Later Phase A — State-changing migration continuity

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

### 12.2 Later Phase B — Envelope-DEK and future `rewrap`

Architecture-blocked until QV adopts a wrapped-DEK design.

Planned work:

- inner/outer ciphertext design
- new state semantics for `rewrap`
- continuity rules for rewrap-capable states

### 12.3 Later Phase C — Renewable evidence records

Future work only.

Planned work:

- renewable evidence-record objects
- explicit renewal timing and witness strategy
- RFC 4998-inspired lifecycle, without misrepresenting it as current capability

### 12.4 Later Phase D — Distributed resharing

Future research only.

Planned work:

- PSS / VSS / DPSS feasibility
- online-custodian trust model
- protocol transcripts and witnessability

This branch must not leak server-coordinated or MPC assumptions into the Phase 1 browser-first model.

## 13. Explicit Non-Goals For The First Shipping Wave

- no mutation of current manifest/bundle schemas
- no implicit grammar extension path
- no server-coordinated or online-custodian resharing
- no claim that same-state resharing revokes leaked predecessor quorum material
- no direct `.qenc` signature requirement in the default archive-authenticity path
- no collapsing of archive approval, maintenance signatures, and source-evidence signatures into one generic attachment class
- no auto-winner selection for same-state cohort forks
- no state-changing migration feature before predecessor-state preservation is designed and implemented

## 14. Implementation Summary

The strict execution order is:

1. freeze the artifact family, field set, shard carriage, bundle contents, and transition semantics
2. implement successor artifacts and successor shard layout
3. move external signer and attach flows to archive-state descriptor bytes
4. replace restore candidate selection with explicit archive/state/cohort logic
5. ship same-state resharing with required transition records
6. add transition verification, maintenance signatures, and fork warnings
7. optionally ship source-evidence authoring and verification
8. defer migration continuity, `rewrap`, renewable evidence, and distributed resharing

That order keeps the implementation aligned with the current Quantum Vault baseline while solving the actual lifecycle contradiction instead of only renaming it.
