# Quantum Vault — Archive Lifecycle Roadmap

Status: Draft roadmap
Type: Informative capability and dependency roadmap
Audience: contributors, implementers, reviewers
Scope: staged evolution from the current Stage A-C baseline to a successor lifecycle artifact family
Relationship: architectural depth lives in `resharing-design.md`; decision-prep and research framing lives in `implementation-questions-and-reading.md`; execution sequencing lives in `implementation-plan-lifecycle.md`

## 1. Post-Stage A-C Baseline

Status: Fixed baseline

The lifecycle roadmap starts from the completed manifest-canonisation baseline:

- signable JSON bytes use the RFC 8785-aligned `QV-JSON-RFC8785-v1` profile
- `authPolicyCommitment` uses the same signable canonicalization profile
- bundle serialization is versioned separately under `QV-BUNDLE-JSON-v1`
- current manifest and bundle grammar are closed and fail-closed
- JSON Schema draft 2020-12 is the grammar layer, not a substitute for canonicalization or semantics
- detached signatures authenticate canonical signable bytes only
- bundle mutation must not change that detached-signature payload
- `qencHash` remains the current ciphertext binding anchor
- OTS remains evidence-only over detached signature bytes

This roadmap therefore assumes that lifecycle work will be a **successor artifact-family design**, not a patch onto the current `quantum-vault-archive-manifest/v3` and `QV-Manifest-Bundle` v2 schemas.

## 2. Roadmap Objective

Status: Recommended direction

The objective is to introduce lifecycle support that cleanly separates:

- archive identity and archive-state approval
- source authenticity or provenance evidence
- cohort or shard-distribution integrity
- maintenance history for resharing and later migration events

The preferred architecture is:

- archive-state descriptor as the long-lived archive-approval signature target
- cohort binding as replaceable distribution-specific material
- transition records for maintenance history
- optional first-class source-evidence objects for source-review claims

Concrete `n/k/t/codecId` are recommended to live at the cohort level, not the archive-state level. That is the key enabling decision for signature-preserving same-state resharing.

## 3. Format Cutover Strategy

Status: Required delivery strategy

Because current schemas are closed, lifecycle support should be introduced as a new format family and cut over deliberately.

Recommended cutover strategy:

1. Freeze the current Stage A-C artifacts as the stable pre-lifecycle baseline.
2. Define the lifecycle successor family in parallel:
   - archive-state descriptor
   - cohort binding
   - transition record
   - lifecycle bundle
   - later, source-evidence object
3. Reuse existing canonicalization labels where byte rules are unchanged:
   - `QV-JSON-RFC8785-v1` for signable lifecycle objects
   - `QV-BUNDLE-JSON-v1` for bundle-style lifecycle carriers unless bundle byte rules actually change
4. Introduce new schema/version identifiers for every new lifecycle artifact family.
5. Implement the successor family behind explicit tooling/version selection.
6. After validation and test-vector coverage are complete, make the lifecycle family the preferred path.

There are no active deployed users, so the cutover can prioritize coherence over backward-compatibility complexity. Even so, the cutover should remain explicit and versioned rather than implicit.

## 4. Dependency-Ordered Milestones

Status: Primary roadmap

### Milestone 1 — Choose the archive-state vs cohort-state boundary

Dependency reason:

- every later decision depends on what the long-lived approval surface is

Preferred outcome:

- archive-state descriptor signs archive state only
- cohort binding carries distribution-specific material
- concrete `n/k/t/codecId` are cohort-level

### Milestone 2 — Define authenticity surfaces and signature targets

Dependency reason:

- the lifecycle family must know what each signature means before new attachment families or verification flows are designed

Required outputs:

- archive-approval signature semantics
- source-authenticity semantics
- maintenance / transition-signature semantics
- clear statement that same-state resharing does not re-approve content

### Milestone 2A — Source authenticity / provenance object design

Dependency reason:

- source evidence should not be improvised inside archive-approval or maintenance objects

Required outputs:

- minimum field set for a `source-evidence` object
- signature model for source-review claims
- relationship model such as `encrypted-from`, `derived-from`, or `reviewed-as`

This milestone can define the object before implementation without forcing it into the first resharing release.

### Milestone 2B — Operator authority / governance semantics

Dependency reason:

- same-state resharing, migration, and branch handling all need a clear maintenance-authority model

Required outputs:

- who may authorize same-state resharing
- who may witness or attest a transition
- what a maintenance signature means
- which governance semantics are Phase 1 vs later

### Milestone 2C — Evidence / time architecture claim boundary

Dependency reason:

- lifecycle signatures and transitions need a clear evidence story before future renewal is discussed

Required outputs:

- restate current OTS scope: detached-signature evidence only
- document that RFC 3161 and RFC 4998 are standards context, not current implementation claims
- define how archive-approval signatures, maintenance signatures, and later evidence records relate
- record that renewal-capable evidence chains remain deferred work

### Milestone 2D — Threat-model, pinning, and policy-evolution alignment

Dependency reason:

- successor bundles will affect how the project explains trust semantics, but must stay aligned with `security-model.md` and `trust-and-policy.md`

Required outputs:

- threat-model alignment note for same-state resharing and old-cohort leakage
- successor-bundle pinning and signer-identity compatibility notes
- policy-evolution notes for future updates to `trust-and-policy.md`
- explicit statement that evidence, pinning, and archive policy remain distinct

### Milestone 3 — Define the successor artifact family and schema/version taxonomy

Dependency reason:

- closed grammar discipline means new objects need explicit schemas before implementation starts

Required outputs:

- archive-state descriptor schema/version
- cohort binding schema/version
- transition-record schema/version
- lifecycle-bundle schema/version
- extension policy for future lifecycle artifacts
- canonical byte definition for the `cohortId` preimage and any cohort-binding digest
- `.qcont` embedding/version impact if lifecycle JSON artifacts are embedded in shards

### Milestone 4 — Implement `archiveId`, `stateId`, and `cohortId`

Dependency reason:

- resharing, transitions, and continuity verification all depend on stable identifiers

Required outputs:

- `archiveId` generation and persistence rules
- `stateId` derivation from the archive-state descriptor
- `cohortId` derivation from the cohort binding
- restore-time consistency checks over those identifiers
- cross-runtime canonicalization vectors for archive-state, cohort-binding, and transition-record bytes

### Milestone 5 — Implement same-state resharing

Dependency reason:

- this is the first concrete lifecycle capability unlocked by the new artifact boundaries

Required outputs:

- reconstruct-and-resplit workflow
- new cohort-binding generation
- archive-state preservation across resharing
- updated shard production embedding unchanged archive state plus new cohort

### Milestone 6 — Implement transition-record verification and fork handling

Dependency reason:

- once resharing exists, maintenance history and parallel-cohort detection become necessary

Required outputs:

- transition-record generation and verification
- maintenance-signature support
- fork detection for multiple cohorts on the same state
- warning semantics for branch conditions

### Milestone 7 — Later: migration / reencryption continuity

Dependency reason:

- migration should build on the already-defined archive/state/cohort separation and transition-record model

Required outputs:

- new-state continuity rules
- reencryption transition handling
- archive-approval signature renewal for new states
- historical evidence preservation across state changes
- informative migration-trigger framing using NIST IR 8547, without presenting it as a current compliance claim

### Milestone 8 — Much later: envelope-DEK / `rewrap`

Dependency reason:

- `rewrap` is architecture-blocked until QV stops encrypting payload content directly under state-derived symmetric material

Required outputs:

- envelope-DEK design
- inner/outer binding model
- continuity semantics for rewrap

This is not a near-term feature.

### Milestone 9 — Future research: distributed resharing

Dependency reason:

- it depends on a broader architectural shift to online or interactive custodians

Required outputs:

- threat and trust model for interactive custodians
- VSS/PSS feasibility analysis
- PQ-secure protocol evaluation

This remains research, not Phase 1 engineering.

## 5. Capability Tracks

Status: Cross-cutting roadmap view

### Archive approval track

Primary objects:

- archive-state descriptor
- archive-approval signatures
- OTS evidence over archive-approval signature bytes

Dependency order:

- Milestones 1 -> 2 -> 2C -> 2D -> 3 -> 4 -> 5 -> 7

Milestones 2C and 2D document claim boundaries and trust alignment before schema and code work harden assumptions.

### Source authenticity track

Primary objects:

- source-evidence object
- source-evidence signatures
- references to external source signatures or reviewed source digests

Dependency order:

- Milestones 2 -> 2A -> 2C -> 3 -> later implementation

Milestone 2C fixes the evidence and standards claim boundary before normative source-evidence schema work.

### Maintenance / transition track

Primary objects:

- cohort binding
- transition records
- maintenance signatures

Dependency order:

- Milestones 1 -> 2 -> 2B -> 2C -> 2D -> 3 -> 4 -> 5 -> 6

These tracks are intentionally separate. Archive approval, source provenance, and maintenance history must not be collapsed into one signature class.

## 6. Compatibility Matrix

Status: Required planning tool

The matrix below is for the **successor lifecycle family** once it exists.

| Change type | New canonicalization label? | New schema/version? | New `stateId`? | New `cohortId`? | New signatures? | New timestamp evidence? |
| --- | --- | --- | --- | --- | --- | --- |
| Change signable byte rules for archive-state descriptor | Yes | Usually yes | Yes | Maybe | Yes, archive approval | Recommended |
| Add a new field to the archive-state descriptor in a closed schema | No, unless byte rules change | Yes | Yes | Maybe | Yes, archive approval | Recommended |
| Add a new field to cohort binding in a closed schema | No, unless byte rules change | Yes | No | Yes | Maintenance signatures may be needed | No |
| Same-state resharing with new cohort only | No | No | No | Yes | Archive approval: no; maintenance: recommended | No |
| New transition record only | No | No | No | Maybe | Maintenance: recommended | Optional |
| Add new source-evidence object family | No, unless byte rules change | Yes | No | No | Source-evidence signatures as needed | Optional |
| Policy change affecting `authPolicyCommitment` | No, unless byte rules change | Maybe | Yes | Usually yes | Yes, archive approval | Recommended |
| Reencryption / crypto-profile migration | No, unless byte rules change | Maybe | Yes | Usually yes | Yes, archive approval | Recommended |
| Future `rewrap` under envelope-DEK design | No, unless byte rules change | Yes | Yes | Usually yes | Yes, archive approval | Recommended |
| Add maintenance signature attachment only | No | No, if already in schema | No | No | Yes, maintenance only | Optional |

### 6.1 Resolving "Maybe" cells

Use this key when a cell says **Maybe**:

- **New `stateId?` (archive-state descriptor rows):** Treat as **Yes** whenever the canonical archive-state descriptor bytes that define `stateId` change. Treat as **No** only if nothing in that signable object changes (rare for a schema bump). When unsure, assume **Yes** (fail closed).
- **New `cohortId?` (archive-state rows):** **Yes** if cohort binding or shard-distribution material changes. **No** if only the archive-state descriptor changes and the cohort binding bytes are unchanged. Same-state resharing with a new cohort is always **Yes** for `cohortId`.
- **New `cohortId?` (first row — signable byte rules for archive-state descriptor):** **Maybe** covers cases where byte-rule changes are scoped only to serialization of objects that are not part of the cohort preimage. If in doubt, recompute both `stateId` and cohort-binding digests from frozen definitions.
- **New schema/version? = Maybe** (policy change, reencryption rows): In a closed-schema family, assume **Yes** when any versioned artifact gains a new field or new schema id. Do not rely on implicit extension.

The matrix is intentionally fail-closed:

- new fields in closed current objects require a new schema/version
- signature survival is driven by signature-target stability, not by bundle mutability
- evidence renewal is distinct from signature generation

## 7. Near-Term Priorities

Status: First implementation wave

The near-term lifecycle roadmap should prioritize:

1. freeze the state/cohort boundary
2. freeze the signature/evidence split (Milestone 2 outputs)
3. close Milestone 2C: evidence/time claim boundary for successor signatures and OTS scope
4. close Milestone 2D: threat-model alignment, pinning, and policy-evolution notes for successor bundles
5. define the successor artifact taxonomy and canonical byte rules (Milestone 3)
6. implement identifiers and verification rules
7. ship same-state resharing
8. ship transition verification and fork warnings

This is enough to solve the current contradiction around resharing and signature survivability without prematurely designing all later archival features.

## 8. Deferred Branches

Status: Deliberately deferred

### 8.1 Reencryption continuity

Important, but depends on the earlier lifecycle scaffolding.

### 8.2 Envelope-DEK and `rewrap`

Explicitly demoted from near-term work.
It stays blocked until a DEK-envelope redesign exists.

### 8.3 Distributed resharing

Future research only.

### 8.4 Merkleized cohort commitments

Optional optimization, not a roadmap gate.

### 8.5 RFC 4998-style renewable evidence

Useful long-term direction, but not current capability.

## 9. Out Of Scope For The First Implementation Wave

Status: Explicit non-scope

The first lifecycle wave should not attempt to deliver all of the following at once:

- MPC or online-custodian resharing
- fully fledged institutional governance
- a complete source-provenance product surface
- envelope-DEK `rewrap`
- full evidence-renewal chains
- automatic branch resolution across competing same-state cohorts

## 10. Roadmap Conclusion

Status: Recommended roadmap conclusion

The least risky order for Quantum Vault is:

- first separate archive state from cohort material
- then separate archive approval from source provenance and maintenance signatures
- then define the successor family explicitly
- then implement identifiers and same-state resharing
- then add transition verification and only later tackle migration continuity

That order preserves the Stage A-C baseline, respects closed-schema discipline, and makes same-state resharing a tractable operational feature instead of a semantic contradiction.
