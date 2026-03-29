# Quantum Vault — Archive Lifecycle Roadmap

Status: Historical transition roadmap with implemented phases 0-7 and deferred later branches
Type: Informative historical capability and dependency roadmap
Audience: contributors, implementers, reviewers
Scope: preserved record of the staged evolution from the current Stage A-C baseline to the shipped successor lifecycle artifact family, plus the remaining deferred branches
Relationship: architectural depth lives in `resharing-design.md`; decision framing and standards reasoning live in `implementation-questions-and-reading.md`; historical execution sequencing lives in `implementation-plan-lifecycle.md`; current normative behavior lives in `docs/format-spec.md`, `docs/trust-and-policy.md`, and `docs/security-model.md`

Uppercase `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.
This roadmap is otherwise informative except where it restates frozen Phase 0 decisions or mandatory dependency ordering.

## Current status

This file is now a historical transition record rather than an active delivery roadmap.

Implemented in the `2a2b957..HEAD` transition window:

- Milestones 1-3 / Phase 0 frozen contracts for the successor artifact family
- Milestone 4 / Phase 1 successor schemas, canonical bytes, and shard layout
- Milestone 5 / Phases 2-3 signer, attach, restore, and explicit successor selection seams
- Milestone 6 / Phase 4 same-state resharing
- Milestone 7 / Phases 5-7 transition verification, maintenance signatures, source-evidence support, and shipped UI/UX migration

Deferred roadmap:

- Milestone 8 state-changing migration continuity
- Milestone 9 envelope-DEK and future `rewrap`
- Milestone 10 distributed resharing and related research branches

Interpretation rule:

- Sections below preserve the dependency order and design rationale that shaped the shipped migration.
- Completed milestones should not be read as open backlog items; only the explicitly deferred branches remain future work.

## 1. Post-Stage A-C Baseline

Status: Fixed baseline

The lifecycle roadmap starts from the completed manifest-canonisation baseline:

- signable JSON bytes use `QV-JSON-RFC8785-v1`
- `authPolicyCommitment` uses the same signable canonicalization profile
- bundle serialization uses `QV-BUNDLE-JSON-v1`
- current manifest and bundle grammar are closed and fail closed
- JSON Schema draft 2020-12 is the grammar layer, not a substitute for canonicalization or semantics
- lifecycle JSON parsing must follow RFC 8259, reject duplicate object names, and stay within an I-JSON-safe subset compatible with RFC 7493
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

Concrete sharding parameters are frozen as **cohort-level**, not archive-state-level.
The shipped v1 surface keeps `codecId` and body-definition details fixed, and derives `t` from the RS parity relation.

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
- archive-state descriptor v1 has an exact closed field set with no additional v1 members
- concrete sharding parameters are cohort-level
- `stateId` is derived-only from canonical archive-state descriptor bytes and MUST NOT appear inside those bytes
- `cohortId` is derived-only from a frozen preimage rooted in `archiveId`, `stateId`, and `cohortBindingDigest`
- successor shards remain self-contained and embed archive-state, cohort-binding, and lifecycle-bundle bytes plus digests
- lifecycle-bundle v1 contents and exact top-level / `attachments` member boundary are fixed rather than “reserved for later”
- detached-signature and timestamp attachment fields are frozen strongly enough for attach and restore to share one target contract
- `publicKeyRef` compatibility and failure behavior are fail closed
- every QV-produced same-state resharing event MUST create a transition record
- any future state-changing migration must preserve predecessor descriptor/signature/evidence sets before the feature ships

## 5. Dependency-Ordered Milestones

Status: Primary roadmap

Milestones 1 through 3 are decision-complete under the Phase 0 freeze addendum.
Milestone 4 and later may encode and implement those decisions, but must not reopen them.

### Milestone 1 — Freeze the state/cohort boundary and artifact family

Dependency reason:

- every later design and implementation task depends on what the long-lived approval surface is

Required outputs:

- archive-state descriptor selected as long-lived signable object
- cohort binding selected as the distribution-specific object
- concrete sharding parameters frozen as cohort-level
- successor-family artifact list frozen
- derived-only `stateId` semantics frozen
- exact `cohortId` preimage frozen

### Milestone 2 — Freeze successor verification semantics

Dependency reason:

- attachment taxonomy and restore logic depend on what each verification result means

Required outputs:

- archive-approval signatures count toward archive policy
- source-evidence signatures do not count toward archive policy
- maintenance signatures do not count toward archive policy
- integrity, signature validity, pinning, and policy satisfaction remain distinct
- OTS remains evidence-only over detached signature bytes
- archive policy counts archive-approval signatures only

### Milestone 2A — Source-authenticity / provenance object design

Dependency reason:

- source-review provenance should not be improvised inside archive-approval or maintenance objects

Required outputs:

- source-evidence object family
- minimum field set
- relation-type vocabulary
- source-evidence signature target semantics
- privacy-preserving default descriptive profile

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
- no additional timestamp standard adopted into the current lifecycle claim set
- RFC 4998 framed as future-direction context only
- clear relationship among archive-approval signatures, maintenance signatures, source-evidence signatures, and OTS evidence

### Milestone 2D — Pinning and fail-closed bundled-key semantics

Dependency reason:

- successor bundle contents are frozen, so `publicKeyRef` and pinning consequences must be frozen as well

Required outputs:

- bundled `publicKeys[]` carried in lifecycle-bundle v1
- frozen `publicKeyRef` compatibility predicate and fail-closed semantics for bundled signatures
- explicit separation between pinning and policy satisfaction
- one shared detached-signature / timestamp target contract for attach and restore

### Milestone 3 — Freeze shard carriage and successor bundle contents

Dependency reason:

- implementation cannot proceed while one document assumes embedded artifacts and another leaves them open

Required outputs:

- self-contained shard strategy frozen
- lifecycle-bundle v1 contents and exact member boundary frozen
- distinction between mixed lifecycle-bundle digests and mixed cohorts frozen
- restore bundle-selection rule frozen:
  - auto-select only when exactly one embedded lifecycle-bundle digest exists inside the selected state-plus-cohort
  - otherwise require explicit bundle input or explicit operator selection

### Milestone 4 — Encode successor artifact schemas and canonical bytes

Dependency reason:

- all later code depends on explicit object models and canonical byte rules

Required outputs:

- archive-state descriptor schema/version encoded using the frozen Phase 0 identifier and field closure
- cohort binding schema/version encoded using the frozen Phase 0 identifier
- transition-record schema/version encoded using the frozen Phase 0 identifier
- source-evidence schema/version encoded using the frozen Phase 0 identifier
- lifecycle-bundle schema/version encoded using the frozen Phase 0 identifier and member closure
- frozen `stateId`, `cohortId`, and digest derivation rules encoded without semantic change
- frozen detached-signature field contracts encoded without semantic change:
  - `signatureFamily`
  - `targetType`
  - `targetRef`
  - `targetDigest`
  - `publicKeyRef`
- frozen OTS linkage contract to exact detached-signature bytes encoded without semantic change

### Milestone 5 — Update signer, attach, and restore seams

Dependency reason:

- lifecycle success is not just schema work; it lives at signer, attach, and restore boundaries

Required outputs:

- archive-state descriptor exported as signer target
- attach flow updated for successor bundle and bundled-key semantics
- restore selection updated to explicit archive/state/cohort logic
- bundle-variant handling within one cohort specified and implemented
- no heuristic bundle auto-selection across multiple embedded bundle digests

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
- explicit rejection conditions for mixed state / mixed cohort inputs

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
| Change supported cohort-level sharding parameters during same-state resharing | Yes | Yes | No | No | Yes | Yes |
| Change `authPolicyCommitment` | Yes | No | No | Yes | Old OTS remains historical only for the predecessor state | Yes once state-changing transitions exist |
| Reencryption / crypto-profile migration | Yes | No | No | Yes | Old OTS remains historical only for the predecessor state | Yes once migration exists |
| Future `rewrap` under envelope-DEK | Yes | No | No | Yes | Old OTS remains historical only for the predecessor state | Yes once migration exists |
| New logical archive | No | No | No | Yes | No carry-forward | No continuity transition |

Interpretation notes:

- “Same `cohortId`?” is strict. A new `stateId` requires a new cohort binding and therefore a new `cohortId`.
- “Existing OTS still relevant?” distinguishes surviving current-state approval from preserved historical evidence.
- Archive policy is evaluated from archive-approval signatures only, regardless of what other signature families are present.
- Mixed embedded lifecycle-bundle digests inside one selected cohort do not authorize heuristic winner selection.

## 8. Historical First Shipping Wave

Status: Implemented transition wave

The historical first shipping wave prioritized:

1. freeze the artifact family, state/cohort boundary, and successor verification semantics
2. freeze shard carriage, lifecycle-bundle v1 contents, and the no-heuristic bundle-selection rule
3. implement successor artifact schemas, canonical bytes, and exact derived-identifier rules
4. update external signer, attach, and restore seams around one shared target contract
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

## 11. Historical Transition Conclusion

Status: Preserved transition conclusion

The least risky lifecycle order for Quantum Vault is:

- first freeze the successor-family boundary and verification semantics
- then freeze shard carriage and lifecycle-bundle v1 contents
- then implement successor artifacts and the signer/attach/restore seams
- then ship same-state resharing with required transition records
- then add transition verification and fork handling
- only later ship state-changing migration continuity

That ordering keeps the roadmap aligned with the current baseline, preserves fail-closed discipline, and avoids the failure mode where the prose becomes cleaner while the architecture gets softer.
