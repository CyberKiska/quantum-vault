# Quantum Vault — Archive Lifecycle Roadmap

Status: Draft roadmap
Type: Informative capability and dependency roadmap
Audience: contributors, implementers, reviewers
Scope: staged evolution from the current Stage A-C baseline to the successor lifecycle artifact family
Relationship: architectural depth lives in `resharing-design.md`; decision framing and standards reasoning live in `implementation-questions-and-reading.md`; execution sequencing lives in `implementation-plan-lifecycle.md`

## 1. Post-Stage A-C Baseline

Status: Fixed baseline

The lifecycle roadmap starts from the completed manifest-canonisation baseline:

- signable JSON bytes use `QV-JSON-RFC8785-v1`
- `authPolicyCommitment` uses the same signable canonicalization profile
- bundle serialization uses `QV-BUNDLE-JSON-v1`
- current manifest and bundle grammar are closed and fail closed
- JSON Schema draft 2020-12 is the grammar layer, not a substitute for canonicalization or semantics
- detached signatures authenticate canonical signable bytes only
- bundle mutation must not change the detached-signature payload
- `qencHash` remains the ciphertext binding anchor
- OTS remains evidence-only over detached signature bytes
- integrity, signature validity, pinning, and policy satisfaction remain distinct states

This roadmap therefore assumes a **successor artifact family**, not a patch onto the current `quantum-vault-archive-manifest/v3` and `QV-Manifest-Bundle` v2 schemas.

## 2. Roadmap Objective

Status: Frozen direction

The roadmap objective is to introduce lifecycle support that cleanly separates:

- archive identity and archive-state approval
- source-review provenance
- cohort or shard-distribution integrity
- maintenance history for resharing and later migration events

The preferred architecture is:

- archive-state descriptor as the long-lived archive-approval signature target
- cohort binding as replaceable distribution-specific material
- transition records as required maintenance records for QV-produced same-state resharing
- optional but first-class source-evidence objects for source-review claims

Concrete `n/k/t/codecId` are frozen as **cohort-level**, not archive-state-level.

## 3. Successor-Family Cutover Strategy

Status: Required delivery strategy

Because current schemas are closed, lifecycle support should be introduced as a new format family and cut over deliberately.

Required cutover posture:

1. Keep the current Stage A-C family stable and unchanged.
2. Define the lifecycle successor family explicitly:
   - archive-state descriptor
   - cohort binding
   - transition record
   - source-evidence object
   - lifecycle bundle
3. Reuse current canonicalization labels where byte rules are unchanged:
   - `QV-JSON-RFC8785-v1` for signable and deterministically hashed lifecycle JSON objects
   - `QV-BUNDLE-JSON-v1` for lifecycle-bundle bytes
4. Introduce new schema/type/version identifiers for every new lifecycle artifact family.
5. Implement the successor family behind explicit tooling/version selection.
6. Make the successor family the preferred path only after artifact, attach, restore, and resharing flows are complete.

There are no active deployed users forcing legacy compatibility.
The cutover can therefore optimize for coherence and correctness rather than compatibility layering.

## 4. Frozen Architecture Consequences

Status: Cross-document decisions the roadmap assumes

The roadmap assumes the following are already frozen:

- archive-state descriptor is the long-lived archive-approval target
- concrete `n/k/t/codecId` are cohort-level
- successor shards remain self-contained and embed archive-state, cohort-binding, and lifecycle-bundle bytes plus digests
- lifecycle-bundle v1 contents are fixed rather than “reserved for later”
- `publicKeyRef` failure is fail closed
- every QV-produced same-state resharing event MUST create a transition record
- any future state-changing migration must preserve predecessor descriptor/signature/evidence sets before the feature ships

## 5. Dependency-Ordered Milestones

Status: Primary roadmap

### Milestone 1 — Freeze the state/cohort boundary and artifact family

Dependency reason:

- every later design and implementation task depends on what the long-lived approval surface is

Required outputs:

- archive-state descriptor selected as long-lived signable object
- cohort binding selected as the distribution-specific object
- concrete `n/k/t/codecId` frozen as cohort-level
- successor-family artifact list frozen

### Milestone 2 — Freeze successor verification semantics

Dependency reason:

- attachment taxonomy and restore logic depend on what each verification result means

Required outputs:

- archive-approval signatures count toward archive policy
- source-evidence signatures do not count toward archive policy
- maintenance signatures do not count toward archive policy
- integrity, signature validity, pinning, and policy satisfaction remain distinct
- OTS remains evidence-only over detached signature bytes

### Milestone 2A — Source-authenticity / provenance object design

Dependency reason:

- source-review provenance should not be improvised inside archive-approval or maintenance objects

Required outputs:

- source-evidence object family
- minimum field set
- relation-type vocabulary
- source-evidence signature target semantics

This milestone defines the object class without forcing full productization in the first resharing release.

### Milestone 2B — Operator authority / governance semantics

Dependency reason:

- resharing history and fork handling need clear maintenance-role semantics

Required outputs:

- archive maintainer semantics
- witness semantics
- optional governance-authority semantics
- explicit statement that maintenance signatures are not archive approval

### Milestone 2C — Evidence and time claim boundary

Dependency reason:

- future roadmap work should not overclaim current timestamp capability

Required outputs:

- current OTS scope restated precisely
- RFC 3161 framed as timestamping context only
- RFC 4998 framed as future-direction context only
- clear relationship among archive-approval signatures, maintenance signatures, source-evidence signatures, and OTS evidence

### Milestone 2D — Pinning and fail-closed bundled-key semantics

Dependency reason:

- successor bundle contents are frozen, so `publicKeyRef` and pinning consequences must be frozen as well

Required outputs:

- bundled `publicKeys[]` carried in lifecycle-bundle v1
- fail-closed `publicKeyRef` semantics for bundled signatures
- explicit separation between pinning and policy satisfaction

### Milestone 3 — Freeze shard carriage and successor bundle contents

Dependency reason:

- implementation cannot proceed while one document assumes embedded artifacts and another leaves them open

Required outputs:

- self-contained shard strategy frozen
- lifecycle-bundle v1 contents frozen
- distinction between mixed lifecycle-bundle digests and mixed cohorts frozen

### Milestone 4 — Implement successor artifact schemas and canonical bytes

Dependency reason:

- all later code depends on explicit object models and canonical byte rules

Required outputs:

- archive-state descriptor schema/version
- cohort binding schema/version
- transition-record schema/version
- source-evidence schema/version
- lifecycle-bundle schema/version
- `stateId`, `cohortId`, and digest derivation rules

### Milestone 5 — Update signer, attach, and restore seams

Dependency reason:

- lifecycle success is not just schema work; it lives at signer, attach, and restore boundaries

Required outputs:

- archive-state descriptor exported as signer target
- attach flow updated for successor bundle and bundled-key semantics
- restore selection updated to explicit archive/state/cohort logic
- bundle-variant handling within one cohort specified and implemented

### Milestone 6 — Implement same-state resharing

Dependency reason:

- this is the first concrete lifecycle capability unlocked by the new artifact boundaries

Required outputs:

- reconstruct-and-resplit workflow
- unchanged archive-state descriptor across resharing
- new cohort binding and new `cohortId`
- required transition record on every QV-produced resharing event

### Milestone 7 — Implement transition verification and fork handling

Dependency reason:

- once resharing exists, maintenance history and same-state fork detection become necessary

Required outputs:

- transition-record verification
- maintenance-signature verification
- same-state cohort-fork detection
- warning semantics without automatic winner selection

### Milestone 8 — Later: state-changing migration continuity

Dependency reason:

- migration must not ship until predecessor-state continuity preservation exists

Required outputs:

- policy-change continuity rules
- reencryption continuity rules
- preserved predecessor descriptor/signature/evidence sets
- renewed archive-approval signatures for new states

### Milestone 9 — Much later: envelope-DEK and future `rewrap`

Dependency reason:

- `rewrap` is architecture-blocked until QV stops encrypting payload content directly under state-derived symmetric material

Required outputs:

- envelope-DEK design
- inner/outer binding model
- continuity semantics for rewrap-capable states

### Milestone 10 — Future research: distributed resharing

Dependency reason:

- it depends on an architectural shift to interactive online custodians

Required outputs:

- threat and trust model for interactive custodians
- VSS/PSS/DPSS feasibility
- PQ-secure protocol evaluation

## 6. Capability Tracks

Status: Cross-cutting roadmap view

### 6.1 Archive-approval track

Primary objects:

- archive-state descriptor
- archive-approval signatures
- OTS evidence over detached archive-approval signature bytes

Roadmap dependency order:

- 1 -> 2 -> 2C -> 2D -> 3 -> 4 -> 5 -> 6 -> 8

### 6.2 Source-authenticity track

Primary objects:

- source-evidence object
- source-evidence signatures
- references to external source signatures or reviewed source digests

Roadmap dependency order:

- 1 -> 2 -> 2A -> 2C -> 3 -> 4 -> later implementation

### 6.3 Maintenance / transition track

Primary objects:

- cohort binding
- transition records
- maintenance signatures

Roadmap dependency order:

- 1 -> 2 -> 2B -> 2C -> 2D -> 3 -> 4 -> 5 -> 6 -> 7

These tracks remain intentionally separate.
Archive approval, source provenance, and maintenance history must not collapse into one signature class.

## 7. Consequence Matrix

Status: Strict compatibility and consequence matrix for the successor family

| Change type | Same `archiveId`? | Same `stateId`? | Same `cohortId`? | New archive-approval signatures required? | Existing OTS over archive-approval signatures still relevant? | Transition record required? |
| --- | --- | --- | --- | --- | --- | --- |
| Add archive-approval signatures, bundled keys, or OTS only | Yes | Yes | Yes | No; new signatures optional | Yes | No |
| Add source-evidence objects or source-evidence signatures only | Yes | Yes | Yes | No | Yes | No |
| Add maintenance signatures to existing transition records only | Yes | Yes | Yes | No | Yes | No |
| Same-state resharing with new cohort only | Yes | Yes | No | No | Yes | Yes |
| Change concrete `n/k/t/codecId` during same-state resharing | Yes | Yes | No | No | Yes | Yes |
| Change `authPolicyCommitment` | Yes | No | No | Yes | Old OTS remains historical only for the predecessor state | Yes once state-changing transitions exist |
| Reencryption / crypto-profile migration | Yes | No | No | Yes | Old OTS remains historical only for the predecessor state | Yes once migration exists |
| Future `rewrap` under envelope-DEK | Yes | No | No | Yes | Old OTS remains historical only for the predecessor state | Yes once migration exists |
| New logical archive | No | No | No | Yes | No carry-forward | No continuity transition |

Interpretation notes:

- “Same `cohortId`?” is strict. A new `stateId` requires a new cohort binding and therefore a new `cohortId`.
- “Existing OTS still relevant?” distinguishes surviving current-state approval from preserved historical evidence.
- Archive policy is evaluated from archive-approval signatures only, regardless of what other signature families are present.

## 8. Near-Term Priorities

Status: First implementation wave

The near-term lifecycle roadmap should prioritize:

1. freeze the artifact family, state/cohort boundary, and successor verification semantics
2. freeze shard carriage and lifecycle-bundle v1 contents
3. implement successor artifact schemas and canonical bytes
4. update external signer, attach, and restore seams
5. ship same-state resharing
6. ship transition verification and fork warnings
7. optionally ship source-evidence authoring and semantic verification

This is enough to solve the current resharing/signature contradiction without prematurely broadening the feature set into migration or MPC work.

## 9. First-Wave Out Of Scope

Status: Explicit non-scope

The first lifecycle wave should not attempt to deliver:

- state-changing migration features before predecessor-state continuity preservation is designed
- envelope-DEK `rewrap`
- distributed resharing or online-custodian coordination
- institutional trust-root programs
- automatic winner selection across competing same-state cohorts
- direct `.qenc` signatures as part of the default archive-approval path

## 10. Deferred Branches

Status: Deliberately deferred

### 10.1 State-changing migration continuity

Important, but blocked on continuity-preservation design and later implementation capacity.

### 10.2 Envelope-DEK and `rewrap`

Explicitly blocked until confidentiality-envelope redesign exists.

### 10.3 Distributed resharing

Future research only.

### 10.4 Merkleized cohort commitments

Optional optimization, not a roadmap gate.

### 10.5 Renewable evidence

Useful long-term direction, but not current lifecycle capability.

## 11. Roadmap Conclusion

Status: Recommended roadmap conclusion

The least risky lifecycle order for Quantum Vault is:

- first freeze the successor-family boundary and verification semantics
- then freeze shard carriage and lifecycle-bundle v1 contents
- then implement successor artifacts and the signer/attach/restore seams
- then ship same-state resharing with required transition records
- then add transition verification and fork handling
- only later ship state-changing migration continuity

That ordering keeps the roadmap aligned with the current baseline, preserves fail-closed discipline, and avoids the failure mode where the prose becomes cleaner while the architecture gets softer.
