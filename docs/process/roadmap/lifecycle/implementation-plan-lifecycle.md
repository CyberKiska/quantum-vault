# Quantum Vault — Lifecycle Implementation Plan

Status: Draft execution plan
Type: Informative implementation plan
Audience: implementers, reviewers, maintainers
Scope: staged implementation of the lifecycle successor family
Relationship: architecture is defined in `resharing-design.md`; unresolved questions and standards map live in `implementation-questions-and-reading.md`

## 1. Goal And Implementation Scope

Goal:

- introduce a successor lifecycle artifact family that separates archive-state approval, source provenance, and cohort maintenance
- enable same-state resharing without invalidating archive-approval signatures
- create a clean path for later migration and provenance features without weakening Stage A-C fail-closed guarantees

Implementation scope for the first lifecycle wave:

- archive-state descriptor
- cohort binding
- lifecycle bundle
- `archiveId`, `stateId`, and `cohortId`
- same-state resharing
- transition records
- transition verification and fork warnings

Not required in the first lifecycle wave:

- source-evidence UI/productization
- migration / reencryption continuity flows
- envelope-DEK `rewrap`
- distributed resharing

## 2. Assumptions And Fixed Prerequisites

- Stage A, Stage B, and Stage C outcomes are fixed.
- Detached signatures still authenticate canonical signable JSON bytes only.
- Current manifest and bundle schemas remain closed and unchanged.
- Lifecycle work is a successor family, not a mutation of current `v3` / `v2` artifacts.
- `QV-JSON-RFC8785-v1` remains the signable canonicalization profile unless byte rules truly change.
- `QV-BUNDLE-JSON-v1` remains the bundle canonicalization profile unless bundle byte rules truly change.
- Browser-first, client-only operation remains the delivery model for Phase 1.
- Reconstruct-and-resplit is the approved same-state resharing mechanism for Phase 1.

## 3. Phase 0: Document Decisions To Freeze

Objective:

- freeze the minimum architecture needed to avoid coding against contradictory assumptions

Required inputs / decisions:

- choose the archive-state vs cohort boundary
- freeze the rule that concrete `n/k/t/codecId` are cohort-level
- freeze archive approval vs source evidence vs maintenance signature semantics
- choose provisional successor artifact identifiers
- choose whether `parentStateId` is inside the archive-state descriptor
- choose whether transition records are required or merely strongly recommended
- freeze the current evidence/time claim boundary for Phase 1

Format / spec work:

- update lifecycle design docs to one coherent recommended direction
- define provisional schema/version names for:
  - archive-state descriptor
  - cohort binding
  - transition record
  - lifecycle bundle
  - later source-evidence object
- record compatibility boundaries against the current manifest/bundle baseline
- record Phase 1 threat-model alignment against `docs/security-model.md`
- record successor-bundle follow-up items for pinning and policy semantics (see `docs/trust-and-policy.md` Section 11.1, non-normative placeholder)

Code work:

- none beyond scaffolding or issue breakdown

Test vectors / interoperability checks:

- none yet; this phase should produce the artifact list and invariant checklist needed for later vectors

Security review points:

- confirm that same-state resharing does not change the archive-approval target
- confirm that lifecycle plans do not weaken Stage B closed-schema discipline
- confirm that current OTS claims remain detached-signature-scoped and evidence-only
- confirm that threat-model language about old-cohort leakage matches `docs/security-model.md`

Blockers / dependencies:

- none; this phase is the blocker remover for all later work

## 4. Phase 1: Artifact Model And IDs

Objective:

- introduce the successor lifecycle artifact model and identity primitives

Required inputs / decisions:

- frozen successor artifact names
- frozen field boundaries for archive state vs cohort
- frozen `archiveId`, `stateId`, and `cohortId` derivation rules

Format / spec work:

- draft JSON Schema files for lifecycle artifacts
- define archive-state descriptor field set
- define cohort-binding field set
- define lifecycle-bundle top-level shape
- define identifier derivation rules and invariants
- freeze the canonical byte definition for the `cohortId` preimage and any cohort-binding digest
- decide `.qcont` embedding/version impact if lifecycle JSON artifacts are embedded in shards

Code work:

- add lifecycle canonicalization and digest helpers if needed
- implement `archiveId` generation
- implement `stateId` derivation from archive-state descriptor bytes
- implement `cohortId` derivation from cohort-binding preimage
- add parse/validate/serialize paths for the new artifacts
- add restore-time consistency checks for `archiveId`, `stateId`, and `cohortId`

Test vectors / interoperability checks:

- valid and invalid archive-state descriptor fixtures
- valid and invalid cohort-binding fixtures
- identifier derivation vectors
- cross-runtime canonicalization parity for archive-state descriptor bytes
- cross-runtime canonicalization parity for cohort-binding and transition-record bytes

Security review points:

- verify that the archive-state descriptor contains all required ciphertext-binding and policy-binding fields
- verify that cohort-level fields are fully excluded from the archive-approval signature target
- verify fail-closed rejection for mixed or malformed IDs

Blockers / dependencies:

- Phase 0 decisions frozen

## 5. Phase 2: Signature / Evidence Split

Objective:

- implement the distinct authenticity surfaces for archive approval, maintenance, and future source evidence

Required inputs / decisions:

- frozen archive-approval target
- frozen transition-record signature semantics
- decision on lifecycle-bundle attachment taxonomy

Format / spec work:

- define archive-approval signature attachment shape for the successor family
- define maintenance-signature attachment shape targeting transition records
- reserve lifecycle-bundle space for future source-evidence objects and signatures
- define target-reference rules and signature-purpose labels
- define successor-bundle notes for signer pinning and policy evolution, to be reflected later in `trust-and-policy.md` (see Section 11.1 placeholder)

Code work:

- update attachment parsing and verification for lifecycle-bundle target types
- implement transition-record digest/reference handling
- ensure archive-approval verification uses archive-state descriptor bytes only
- ensure maintenance verification uses transition-record bytes only

Test vectors / interoperability checks:

- archive-approval signature vectors that survive same-state resharing
- maintenance-signature vectors over transition records
- negative vectors for mismatched target references
- OTS linkage vectors over archive-approval signature bytes
- pinning/reference compatibility vectors for successor bundles, if pinning material is carried there

Security review points:

- verify that maintenance signatures cannot be misread as archive approval
- verify that OTS remains evidence-only and does not satisfy signature policy by itself
- verify that bundle mutation still cannot mutate archive-approval targets
- verify that successor-bundle pinning or policy metadata cannot silently weaken archive policy semantics

Phase 2 note — Evidence and time architecture:

- keep Phase 1 evidence semantics narrow: OTS over detached signature bytes only
- treat RFC 3161 and RFC 4998 as standards context and deferred design input
- do not imply renewable evidence chains already exist

Blockers / dependencies:

- Phase 1 artifact model implemented

## 6. Phase 3: Same-State Resharing

Objective:

- implement reconstruct-and-resplit for the successor lifecycle family without changing archive state

Required inputs / decisions:

- working archive-state descriptor and cohort-binding handling
- frozen same-state resharing invariants
- decision on whether transition records are emitted unconditionally

Format / spec work:

- finalize same-state resharing preconditions and allowed changes
- define resharing output packaging rules
- define predecessor/successor cohort-binding references
- define how resharing interacts with shard embedding if lifecycle artifacts are stored inside `.qcont`

Code work:

- implement `reshareSameState(...)`
- verify predecessor cohort consistency before reconstruction
- generate successor cohort binding and `cohortId`
- emit new shards with unchanged archive-state descriptor
- emit lifecycle-bundle updates and transition record
- add best-effort zeroization and ceremony cleanup

Test vectors / interoperability checks:

- reshare with unchanged state and changed cohort
- reshare with changed `n/k/t/codecId`
- reject mixed predecessor cohorts
- reject accidental archive-state mutation during same-state resharing
- regression vector proving archive-approval signatures remain valid across resharing

Security review points:

- verify no archive-state descriptor bytes change during same-state resharing
- verify memory-handling and zeroization behavior is as narrow as current runtime permits
- verify docs do not claim resharing revokes already leaked old quorum material
- verify resharing threat language stays aligned with `docs/security-model.md`

Blockers / dependencies:

- Phase 2 signature-target split implemented

## 7. Phase 4: Transition Verification And Fork Handling

Objective:

- make same-state resharing auditable and detect competing cohorts for the same state

Required inputs / decisions:

- frozen fork semantics
- frozen maintenance-signature verification behavior
- decision on warning vs hard-fail behavior for known multiple cohorts

Format / spec work:

- finalize transition-record schema and reason codes
- define fork-detection rules
- define lifecycle-bundle history semantics

Code work:

- implement transition-record verification
- implement maintenance-signature verification
- detect multiple successor cohorts for the same `archiveId` and `stateId`
- surface fork warnings without auto-selecting a winner
- ensure restore rejects mixed cohorts even when multiple valid cohorts are known

Test vectors / interoperability checks:

- valid transition chain
- same-state fork with two valid cohorts
- mismatched transition references
- unsigned transition record behavior
- signed transition record behavior

Security review points:

- verify no heuristic winner-selection rule can silently override explicit governance
- verify transition history cannot be confused with archive approval

Blockers / dependencies:

- Phase 3 resharing implemented

## 8. Phase 5: Optional Provenance / Source-Evidence Support

Objective:

- add first-class support for source-review and precursor-artifact provenance without conflating it with archive approval

Required inputs / decisions:

- frozen minimum source-evidence object
- frozen relation-type vocabulary
- frozen signature semantics for source evidence

Format / spec work:

- define source-evidence schema
- define source-evidence signature attachment shape
- define references to external source signatures when present

Code work:

- implement source-evidence parsing, validation, and bundle carriage
- implement signature verification over source-evidence objects
- expose source evidence distinctly in verification output

Test vectors / interoperability checks:

- source-evidence fixtures with different relation types
- source-evidence signature vectors
- negative vectors showing source-evidence signatures do not satisfy archive-approval requirements

Security review points:

- verify source-review claims are never promoted automatically to archive approval
- verify optional descriptive fields do not create accidental privacy leaks by default

Blockers / dependencies:

- Phases 1 and 2 complete
- product decision that source evidence is worth shipping in the near term

## 9. Deferred Phases

### Deferred Phase A — Reencryption continuity

- new-state creation for migration
- continuity records across states
- renewed archive-approval signatures and evidence
- informative migration-trigger framing using NIST IR 8547, without treating that as a current compliance claim

### Deferred Phase B — Envelope-DEK / `rewrap`

- redesign confidentiality envelope
- implement future `rewrap` semantics

### Deferred Phase C — Renewable evidence records

- RFC 4998-inspired evidence renewal chain
- future timestamp renewal policy

### Deferred Phase D — Distributed resharing research

- PSS / VSS / DPSS feasibility
- interactive custodian trust model

## 10. Explicit Non-Goals

- no mutation of current `quantum-vault-archive-manifest/v3`
- no mutation of current `QV-Manifest-Bundle` v2
- no Phase 1 MPC protocol
- no claim that same-state resharing repairs prior secret leakage
- no near-term `rewrap` without envelope-DEK redesign
- no automatic branch resolution by timestamp heuristics
- no collapsing of archive approval, source evidence, and maintenance signatures into one attachment class

## 11. Implementation Summary

The strict order is:

1. freeze the design
2. build the successor artifacts and IDs
3. split signature and evidence semantics
4. ship same-state resharing
5. add transition verification and fork handling
6. optionally add source-evidence support
7. defer migration, `rewrap`, renewable evidence, and distributed resharing

That sequence solves the current lifecycle contradiction without overcommitting the first implementation wave.
