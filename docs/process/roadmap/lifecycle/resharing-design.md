# Quantum Vault — Resharing And Lifecycle Artifact Design

Status: Draft successor-design document
Type: Informative technical design with recommended Phase 1 direction
Audience: contributors, implementers, reviewers, cryptographic auditors
Scope: same-state resharing, lifecycle artifact boundaries, signature/evidence split, transition semantics, and operator roles
Out of scope: byte-for-byte normative spec text for the successor family, MPC protocols, and a full governance program
Relationship: builds on the fixed Stage A-C baseline; feeds `implementation-plan-lifecycle.md`, future normative lifecycle specs, and any future successor format implementation

## 1. Design Posture

Status: Fixed framing

This document describes a **successor artifact family**, not a mutation of the current `quantum-vault-archive-manifest/v3` plus `QV-Manifest-Bundle` v2 baseline.

That choice follows directly from the completed Stage A-C work:

- signable bytes are already pinned to the RFC 8785-aligned `QV-JSON-RFC8785-v1` profile
- current manifest and bundle grammar are closed and fail-closed
- serialization, schema, and semantics are already deliberately separated

Therefore, if lifecycle support introduces:

- an archive-state descriptor
- a cohort binding
- transition records
- source-evidence objects
- new attachment families for maintenance or provenance signatures

then it must do so as a new artifact family with new schema/version identifiers.

This document recommends reusing the existing signable canonicalization profile for signable successor objects unless the byte rules themselves change. No new canonicalization label is justified merely because the signed object changes shape.

## Motivation

Status: Current failure mode that motivates the successor design

The current `quantum-vault-archive-manifest/v3` baseline is correct for the already-implemented split-time model, but it has a lifecycle failure mode:

- shard-distribution fields live inside the signable object
- same-state resharing necessarily changes those shard-distribution fields
- canonical manifest bytes therefore change
- `manifestDigest` therefore changes
- detached signatures and OTS proofs linked to those bytes no longer carry forward as stable archive-state approval

In current-format terms, the problem is not "resharing is impossible." The problem is narrower and more important:

- the current signable object is cohort-bound
- same-state resharing needs a state-bound approval object and a separate cohort-bound distribution object

That is why this document adopts a successor artifact family rather than trying to reinterpret the current manifest semantics.

For a single consolidated summary of this failure mode and the fix, see `implementation-questions-and-reading.md` Section 12 (Key insight).

## 2. Goals And Non-Goals

Status: Recommended design direction

### 2.1 Goals

1. Separate archive-state authenticity from shard-distribution integrity.
2. Make same-state resharing an operational preservation event rather than a disguised re-approval of archive content.
3. Preserve long-lived archive-approval signatures and timestamp evidence across same-state resharing.
4. Distinguish source-review claims from archive-state approval claims.
5. Keep the design implementable in a client-only, browser-first system.
6. Preserve fail-closed behavior and closed grammar discipline.

### 2.2 Non-goals for the first lifecycle wave

- no MPC or interactive custodian protocol
- no attempt to retrofit lifecycle fields into the current manifest/bundle schema
- no implication that same-state resharing repairs full confidentiality compromise
- no assumption that `rewrap` is near-term unless an envelope-DEK redesign is adopted
- no requirement that source-evidence support block same-state resharing

## 3. Identity Model

Status: Recommended Phase 1 direction

Quantum Vault lifecycle work should use three primary identity layers plus a separate provenance layer:

```text
┌────────────────────────────────────────────────────────────┐
│ Archive Identity (archiveId)                              │
│ "This is the same logical archive."                       │
│ Stable across: same-state resharing, reencryption,        │
│ future rewrap                                             │
├────────────────────────────────────────────────────────────┤
│ Archive State (stateId)                                   │
│ "This specific archive-state descriptor."                 │
│ Stable across: attach, re-sign, evidence add,             │
│ same-state resharing                                      │
│ Changes on: policy/state change, reencryption,            │
│ future rewrap                                             │
├────────────────────────────────────────────────────────────┤
│ Shard Cohort (cohortId)                                   │
│ "This specific shard-distribution cohort for one state."  │
│ Stable across: nothing; unique per split or reshare       │
└────────────────────────────────────────────────────────────┘
```

Source evidence is orthogonal to this three-layer identity model. It is provenance about reviewed or precursor artifacts, not a replacement for archive identity, state, or cohort identity.

### 3.1 `archiveId`

Recommended derivation:

```text
archiveId = random 256-bit identifier encoded as lowercase hex
```

Recommended invariants:

- assigned once at archive creation
- never content-derived
- stable across same-state resharing, reencryption, and future rewrap
- visible to lifecycle tooling as the continuity anchor for the logical archive

Recommended design invariants:

```text
INV-AID-1 (recommended): archiveId is assigned once at archive creation.
INV-AID-2 (recommended): archiveId does not change across same-state
                         resharing, reencryption, or future rewrap.
INV-AID-3 (recommended): archiveId is not derived from plaintext,
                         ciphertext, or key material.
INV-AID-4 (recommended): a new archiveId means a new logical archive.
```

Where it appears as a design requirement:

- archive-state descriptor
- lifecycle bundle
- transition records
- shard metadata or an equivalent shard-selection surface

### 3.2 `stateId`

Recommended derivation:

```text
stateId = hex(SHA3-512(canonical archive-state descriptor bytes))
```

Recommended meaning:

- one `stateId` corresponds to one archive-state descriptor
- the archive-state descriptor is the long-lived archive-approval signature target
- same-state resharing preserves `stateId`
- changing the archive-state descriptor creates a new `stateId`

The archive-state descriptor should bind at least:

- `archiveId`
- its own schema/version/canonicalization identity
- `qencHash`
- `containerId`
- the relevant `qenc` interpretation details
- `cryptoProfileId`
- nonce/AAD semantics
- `authPolicyCommitment`

Recommended design invariants:

```text
INV-SID-1 (recommended): stateId identifies one archive-state descriptor.
INV-SID-2 (recommended): stateId changes when the archive-state descriptor
                         changes.
INV-SID-3 (recommended): same-state resharing does not change stateId.
INV-SID-4 (recommended): bundle mutation alone does not change stateId.
```

Where it appears as a design requirement:

- cohort binding, as the state anchor for the cohort
- lifecycle bundle
- transition records
- shard metadata directly, or indirectly through an embedded archive-state descriptor digest

### 3.3 `parentStateId`

`parentStateId` expresses archive-state lineage, not shard-cohort lineage.

Recommended meaning:

- null or absent for the initial state
- predecessor reference for later states
- forms a DAG for state-changing events such as reencryption or future rewrap

Phase-0 freeze note:

- the exact placement of `parentStateId` must still be frozen
- the preferred direction is to carry it in the archive-state descriptor and mirror it in transition records where useful

Recommended design invariants:

```text
INV-PSID-1 (Phase-0 freeze): every non-initial archive state references a
                             predecessor stateId.
INV-PSID-2 (recommended): parentStateId describes state lineage only.
INV-PSID-3 (recommended): same-state cohort forks do not create new state
                          nodes in the parentStateId DAG.
```

Where it appears as a design requirement:

- archive-state descriptor, if Phase 0 freezes that choice
- transition records

Important distinction:

- `parentStateId` DAG semantics are about state-changing preservation events
- cohort-fork semantics are about multiple valid cohorts under one unchanged state

These are related operationally, but they are not the same graph.

### 3.4 `cohortId`

The formula below is **illustrative**. Exact field order, optional fields, nested shape (for example how Reed–Solomon parameters sit under `sharding`), and the canonicalization label for the cohort-binding preimage must be **frozen with the successor JSON Schema and test vectors** in Phase 1. Do not treat the brace object as a normative byte contract until then.

Recommended derivation:

```text
cohortId = hex(SHA3-256(canonicalize({
  archiveId,
  stateId,
  sharding,
  bodyDefinitionId,
  bodyDefinition,
  shareCommitments,
  shardBodyHashes
})))
```

The `cohortId` is derived from the cohort-binding preimage, then stored in the final cohort-binding object.

Recommended meaning:

- unique to one split or reshare event
- replaceable without changing archive state
- carried in every shard and in lifecycle records
- MUST be consistent across all shards in a restore candidate set

Recommended design invariants:

```text
INV-COH-1 (recommended): cohortId identifies one shard-distribution cohort
                         for one archive state.
INV-COH-2 (recommended): every shard in one candidate set carries the same
                         cohortId.
INV-COH-3 (recommended): same-state resharing creates a new cohortId
                         without changing stateId.
INV-COH-4 (recommended): mixed-cohort restore attempts fail closed.
```

Where it appears as a design requirement:

- cohort binding
- lifecycle bundle
- transition records
- shard metadata

### 3.5 Source evidence

Source evidence is not an identity layer for the encrypted archive state. It is provenance.

Recommended meaning:

- references the original source artifact or a reviewed precursor object
- may preserve source digests, source signatures, or auditor claims
- survives same-state resharing as provenance if the referenced source relationship is unchanged

## 4. Preferred State/Cohort Boundary

Status: Preferred architecture

This document chooses **Option 2**:

- concrete `n/k/t/codecId` are cohort-level
- same-state resharing MAY change them
- therefore they are not part of the archive-state approval signature target

### 4.1 Why Option 2 is preferred now

It is the least dangerous option for Quantum Vault because it aligns all of the following at once:

- the signed archive-state descriptor stays stable across same-state resharing
- detached archive-approval signatures survive without reinterpretation
- OTS evidence over those detached signatures also survives
- resharing remains an operational maintenance event rather than a state-reapproval event

### 4.2 What this means operationally

Concrete cohort parameters such as `n`, `k`, `t`, and `codecId` may change during same-state resharing.

That does **not** mean such changes are semantically trivial. They still change:

- recoverability posture
- threshold margin
- shard-count logistics
- cohort-management risk

The important distinction is narrower:

- they do not change the archive-state authenticity surface
- they do change the operational shard-distribution surface

That change belongs in maintenance history and, later, governance semantics.

### 4.3 Future refinement path

If QV later needs signed operational bounds on resharing, it can introduce an archive-level distribution-policy object in a future successor branch.

That would be a move toward Option 3, not a reason to keep concrete `n/k/t/codecId` in the Phase 1 archive-state descriptor.

## 5. Successor Artifact Family

Status: Recommended structure

The lifecycle successor family should introduce four main JSON artifact types.

The exact schema names below are recommended placeholders for Phase 0 freeze.

### 5.1 Archive-state descriptor

Recommended identifier:

```text
schema = "quantum-vault-archive-state-descriptor/v1"
```

Recommended role:

- long-lived archive-approval signature target
- canonicalized under `QV-JSON-RFC8785-v1`
- immutable for the lifetime of that archive state

Recommended fields:

| Field | Purpose |
| --- | --- |
| `schema`, `version`, `canonicalization` | artifact identity and canonicalization contract |
| `archiveId` | logical archive continuity anchor |
| `parentStateId` | predecessor state reference; null for initial state |
| `stateType` | explicit object role such as `archive-state` |
| `cryptoProfileId`, `kdfTreeId` | current crypto/KDF interpretation |
| nonce/AAD fields | ciphertext interpretation contract |
| `qenc` object | `qencHash`, `containerId`, format and digest labels, and other stable ciphertext anchors |
| `authPolicyCommitment` | binds the mutable policy carrier to the state approval object |

Explicitly excluded from the archive-state descriptor:

- `cohortId`
- `n/k/t/codecId`
- `shareCommitments[]`
- `shardBodyHashes[]`
- body-definition details for shard payload layout
- custodian identities or cohort-distribution metadata

### 5.2 Cohort binding

Recommended identifier:

```text
schema = "quantum-vault-cohort-binding/v1"
```

Recommended role:

- binds one shard-distribution cohort to one archive state
- commitment-bearing object for restore and cohort integrity
- not the long-lived archive-approval signature target

Recommended fields:

| Field | Purpose |
| --- | --- |
| `schema`, `version` | artifact identity |
| `archiveId`, `stateId` | ties the cohort to one archive and one archive state |
| `cohortId` | cohort identity |
| `sharding` | concrete `n`, `k`, `t`, parity, `codecId`, and related concrete layout parameters |
| `bodyDefinitionId`, `bodyDefinition` | exact shard-body definition |
| `shareCommitmentAlg`, `shareCommitments[]` | per-share integrity |
| `shardBodyHashAlg`, `shardBodyHashes[]` | per-shard integrity |
| optional operational metadata | future-only, if a later version needs it |

Recommended invariants:

- same `stateId`, new `cohortId` on same-state resharing
- restore MUST reject mixed `cohortId` sets
- one cohort binding commits to exactly one concrete shard layout

### 5.3 Transition record

Recommended identifier:

```text
schema = "quantum-vault-transition-record/v1"
```

Recommended role:

- records maintenance or migration events
- signable under the same strict JSON canonicalization profile
- separate from archive-state approval

Recommended fields:

| Field | Purpose |
| --- | --- |
| `schema`, `version`, `canonicalization` | artifact identity |
| `transitionType` | `reshareSameState`, `reencryption`, `policyChange`, future `rewrap` |
| `archiveId` | archive continuity anchor |
| `fromStateId`, `toStateId` | state transition endpoints |
| `fromCohortId`, `toCohortId` | cohort transition endpoints when applicable |
| `fromCohortBindingDigest`, `toCohortBindingDigest` | stable references to exact cohort-binding objects |
| `reasonCode` | operational reason |
| `performedAt` | event time |
| `operatorRole` or `actorHints` | maintenance-role metadata |
| optional notes | informational only |

For same-state resharing:

- `fromStateId == toStateId`
- `fromCohortId != toCohortId`

### 5.4 Lifecycle bundle

Recommended identifier:

```text
type = "QV-Lifecycle-Bundle"
version = 1
```

Recommended role:

- mutable carrier for lifecycle artifacts and detached authenticity material
- not itself the long-lived approval surface

Recommended contents:

- current archive-state descriptor
- current cohort binding
- `transitions[]`
- optional `sourceEvidence[]`
- attachments grouped by semantic role:
  - `archiveApprovalSignatures[]`
  - `maintenanceSignatures[]`
  - `sourceEvidenceSignatures[]`
  - `publicKeys[]`
  - `timestamps[]`

This grouping is intentionally more explicit than the current bundle because lifecycle semantics need to distinguish archive approval from provenance and maintenance attestations.

## 6. Recommended Signature And Evidence Model

Status: Core lifecycle design

### 6.1 Archive-approval signatures

Archive-approval signatures are the successor to today's detached signatures over the split-time manifest.

Recommended semantics:

- target: canonical archive-state descriptor bytes
- meaning: "I approve this archive state"
- expected signers: auditor, archive approver, or another external authority defined by workflow
- resharing effect: unchanged archive-state descriptor means the signatures survive

These are the signatures OTS evidence should continue to timestamp for long-lived archive-state approval claims.

### 6.2 Source-evidence signatures

Source-evidence signatures should target either:

- the original source object in an external workflow, or
- a first-class QV source-evidence object that references the reviewed source

Recommended semantics:

- meaning: "I reviewed or attest to this source artifact or relation"
- not interchangeable with archive-state approval
- survivability: they remain provenance records across same-state resharing because their semantic target is different

### 6.3 Maintenance signatures

Maintenance signatures should target transition-record bytes.

Recommended semantics:

- meaning: "I authorized, performed, or witnessed this maintenance event"
- not archive approval
- not source review
- useful for operational audit trails and future governance

Expected signer categories:

- archive maintainer or repository operator
- authorized governance actor, if such a role exists
- optional quorum participants or witnesses

### 6.4 Direct `qenc` signatures

Direct `.qenc` signatures are optional and not part of the preferred QV path.

Reason:

- the archive-state descriptor already binds `qencHash` and `containerId`
- archive-approval signatures therefore already bind exact `.qenc` bytes indirectly

Direct `.qenc` signatures remain reasonable only for external interoperability or transport-specific workflows.

## 7. What Signatures Survive Same-State Resharing, And Why

Status: Required clarification

| Signature / evidence type | Target | Survives same-state resharing? | Why |
| --- | --- | --- | --- |
| Archive-approval signature | archive-state descriptor | Yes | The target bytes do not change |
| OTS evidence over archive-approval signature bytes | detached archive-approval signature bytes | Yes | The detached signature bytes do not change |
| Source-evidence signature | source object or source-evidence object | Yes, if object unchanged | It is a different semantic surface from cohort maintenance |
| Maintenance signature over prior transition record | transition record | Yes, as historical provenance | It remains a record of what was signed at that time |
| Direct `.qenc` signature | exact `.qenc` bytes | Yes, if `.qenc` unchanged | Same ciphertext bytes |
| Cohort-specific signature, if ever used | cohort binding or maintenance record | No automatic carry-forward | The new cohort is a new operational object |

This is the main reason the signature split matters.

If the long-lived signature target remains archive-state only, same-state resharing can change cohort material without forcing new archive-approval signatures.

## 8. Same-State Resharing Design

Status: Recommended Phase 1 mechanism

### 8.1 Preconditions

Same-state resharing requires:

- a threshold of shards from one internally consistent predecessor cohort
- a single consistent `archiveId`
- a single consistent `stateId`
- unchanged archive-state descriptor bytes

If the intended operation would change:

- `qencHash`
- `containerId`
- `cryptoProfileId`
- nonce/AAD semantics
- `authPolicyCommitment`

then it is not same-state resharing.

### 8.2 Ceremony

1. Gather at least `t` shards from the predecessor cohort.
2. Verify `archiveId`, `stateId`, and `cohortId` consistency; reject mixed cohorts.
3. Verify share commitments and shard-body hashes for the predecessor cohort.
4. Reconstruct the underlying secret material in memory.
5. Choose the new cohort parameters:
   - `n'`
   - `k'`
   - `t'`
   - `codecId'`
   - any updated shard-body layout that remains cohort-specific
6. Generate a fresh cohort with fresh share randomness.
7. Build the new cohort-binding object and derive `cohortId'`.
8. Build new shards embedding:
   - the unchanged archive-state descriptor
   - the new cohort binding
   - an updated lifecycle bundle
9. Create a transition record from predecessor cohort to successor cohort.
10. Optionally sign the transition record with maintenance keys.
11. Zeroize reconstructed secret material as quickly as possible.
12. Instruct custodians to destroy predecessor-cohort shards, while recognizing that the system cannot prove destruction.

### 8.3 Allowed and forbidden changes

Allowed in same-state resharing:

- `cohortId`
- `n/k/t/codecId`
- shard-body hashes
- share commitments
- custodian assignment or distribution logistics

Forbidden in same-state resharing:

- `archiveId`
- `stateId`
- archive-state descriptor bytes
- `qencHash`
- `containerId`
- nonce/AAD semantics
- `authPolicyCommitment`

### 8.4 Secret-in-memory risk

Reconstruct-and-resplit exposes the underlying secret in memory.

This is not a new class of exposure compared with restore. It is the same browser/runtime risk surface already acknowledged by the current security model.

Recommended mitigations:

- perform resharing on a trusted or offline machine where feasible
- minimize ceremony duration
- zeroize buffers on best-effort completion

Distributed resharing remains out of scope for Phase 1.

## 9. What Same-State Resharing Does Not Prove Or Repair

Status: Required claim boundary

Same-state resharing does **not** prove or repair the following:

### 9.1 It does not re-approve archive content

A new cohort is not a new archive-state approval.
If a new archive-state approval is desired, produce new archive-approval signatures explicitly.

### 9.2 It does not revoke leaked old quorum material

If the predecessor cohort may already have leaked enough material to reconstruct the underlying secret, same-state resharing does not retroactively repair that exposure.

Important wording:

- new and old cohorts are operationally distinct
- cross-cohort share mixing does not create a valid single cohort
- but the predecessor cohort remains its own confidentiality surface until enough old material is destroyed or known unavailable

### 9.3 It does not create new source-authenticity evidence

A resharing ceremony says nothing new about the original source artifact.
If new source-review claims are needed, they must be modeled explicitly as provenance or source evidence.

### 9.4 It does not address algorithm weakness or HNDL by itself

Resharing leaves the ciphertext state unchanged.

If the response requirement is:

- algorithm migration
- compromise response for the underlying secret
- protection against future captures under a new profile

then the correct path is a new archive state, at minimum via reencryption.

Future `rewrap` is a separate branch that depends on an envelope-DEK redesign.

## 10. Transition Record Semantics

Status: Recommended semantics

### 10.1 What exactly is signed?

If a transition record is signed, the signature target is the canonical transition-record bytes.

It is **not**:

- the mutable lifecycle bundle bytes
- the archive-state descriptor bytes
- the cohort binding bytes directly, unless a future profile explicitly adds that as a separate signature type

### 10.2 Who is expected to sign?

Recommended role mapping:

- archive maintainer or repository operator: maintenance authorization or operator attestation
- governance actor, if present: formal maintenance authorization
- quorum participant: optional witness signature

Auditors are not required to sign transition records unless they are also acting in one of the maintenance roles above.

### 10.3 What kind of signature is it?

Recommended purpose labels:

- `maintenance-authorization`
- `operator-attestation`
- `witness`

These signatures are maintenance/provenance records, not replacements for archive approval.

### 10.4 Required or optional?

Recommended Phase 1 rule:

- a transition record itself SHOULD be created for every QV-produced same-state resharing event
- support for detached maintenance signatures over transition records SHOULD exist in the successor family
- presence of at least one maintenance signature is RECOMMENDED but not a hard precondition for same-state resharing in the first implementation wave

Why not make them strictly mandatory immediately:

- same-state resharing should remain usable in a client-only environment
- the first lifecycle wave should not depend on a full governance rollout

This leaves room for later governance profiles to tighten the requirement.

### 10.5 Should the cohort binding be independently signed?

Recommended Phase 1 answer: no.

Reason:

- cohort integrity is already enforced by commitments and shard-level consistency checks
- a signed transition record that references predecessor and successor cohort-binding digests is usually enough to create maintenance provenance

Independent cohort-binding signatures remain a future option if custodial attestation becomes a first-class requirement.

## 11. Branch Detection And Forked Resharing

Status: Required operational semantics

Two different valid cohorts can exist for the same `archiveId` and `stateId`.

This is a cohort fork, not a `parentStateId` state-DAG branch. The archive state is unchanged; only the distribution layer has diverged.

This can happen if:

- two operators independently reshare the same predecessor cohort
- two partially overlapping custodian groups both perform same-state resharing

### 11.1 Detection

Fork condition:

- same `archiveId`
- same `stateId`
- different `cohortId`
- distinct transition records or distinct active cohort bindings

### 11.2 Verification behavior

Recommended verification behavior:

- restore MUST reject mixed shard sets across different `cohortId` values
- restore MAY proceed from any single internally consistent cohort for the same state
- tooling SHOULD warn when multiple valid cohorts are known for one state

### 11.3 No automatic winner selection in Phase 1

The first lifecycle implementation wave should not guess a winner by:

- latest timestamp alone
- attachment count
- lexical order of identifiers

If a future governance layer defines a preferred active cohort rule, that should be explicit and separately signed.

## 12. Operator Roles

Status: Recommended semantic separation

### 12.1 Auditor / source verifier

These are **different claims** and must not be collapsed:

- **Source review:** "I reviewed (or attest to) a specific source artifact or precursor object." Expected signature surface: **source-evidence object** (or an external source signature workflow).
- **Archive-state approval:** "I approve this encrypted archive state (descriptor)." Expected signature surface: **archive-state descriptor** (detached archive-approval signatures).

The same party may perform both in one workflow, but the semantics and signature targets stay distinct.

### 12.2 Archive maintainer

Primary claim:

- authorized or performed lifecycle maintenance

Expected signature surface:

- transition records

### 12.3 Quorum participants / custodians

Primary claim:

- supplied shards or witnessed an operational ceremony

Expected signature surface:

- usually none in Phase 1
- optional witness signatures on transition records if desired

### 12.4 Restore operator / verifier

Primary role:

- evaluates integrity, authenticity, maintenance history, and policy outcomes

Restore operators may also act as maintainers in smaller workflows, but the semantic roles should still remain distinct.

## 13. Availability Maintenance, Compromise Response, Policy Change, And Migration

Status: Recommended decision table

| Event class | Typical trigger | Correct artifact effect | Signature consequence |
| --- | --- | --- | --- |
| Availability maintenance | custodian loss, rotation, margin erosion | new cohort binding, same archive state | archive-approval signatures survive |
| Suspected old-quorum leakage | predecessor cohort may already expose the secret | new archive state required | new archive-approval signatures required |
| Policy change | archive approval semantics change | new archive-state descriptor | new archive-approval signatures required |
| Reencryption / crypto migration | new ciphertext or new crypto profile | new archive-state descriptor and likely new cohort | new archive-approval signatures required |
| Future rewrap | future outer-envelope refresh only | future branch, architecture-blocked | new archive-state descriptor and new archive-approval signatures expected |

### 13.1 Operational resharing trigger

The current safety-margin guidance remains useful as cohort-level operational guidance:

```text
safety_margin = ceil((n - t) / 2)
reshare_trigger: available_honest_custodians < t + safety_margin
```

This is maintenance guidance, not part of archive-state authenticity.

### 13.2 HNDL implications

Harvest-now-decrypt-later pressure is addressed by:

- current PQ encryption choices for the existing state
- future reencryption when crypto migration is needed

Same-state resharing does not change captured ciphertext and therefore is not a direct HNDL response.

## 14. Alternatives Considered

Status: Preserved alternatives

### 14.1 Option 1 — keep concrete `n/k/t/codecId` in the archive-state descriptor

Rejected for now because it makes signature survival incompatible with resharing flexibility.

### 14.2 Option 3 — sign a sharding-policy class, keep concrete values in the cohort

Deferred, not rejected outright.

This remains the most plausible future refinement if QV later needs signed limits such as:

- minimum threshold
- allowed codec families
- permitted `n` bounds

### 14.3 Direct cohort-binding signatures

Deferred because transition-record signatures already provide a cleaner maintenance surface.

### 14.4 Direct `.qenc` signatures as a primary path

Not recommended because they duplicate the normal archive-state binding chain.

## 15. Future Work And Out Of Scope

Status: Future work

### 15.1 Source-evidence object design and richer provenance

Recommended for a later phase, but not a blocker for same-state resharing.

### 15.2 Envelope-DEK and future `rewrap`

Still architecture-blocked.
Current QV encrypts payload content directly under state-derived symmetric material.

### 15.3 Distributed resharing

PSS, VSS, and DPSS remain future research only.
They require interactive online custodians and do not fit the current client-only model.

### 15.4 Merkleized cohort commitments

Useful only if the flat cohort-commitment model becomes too large or if independent membership proofs become important.

### 15.5 Evidence renewal

RFC 4998-style renewal remains future-direction context.
Current OTS usage remains evidence-only over detached signature bytes.

## 16. Design Summary

Status: Recommended conclusion

The preferred Quantum Vault lifecycle architecture is:

- a successor archive-state descriptor as the long-lived archive-approval signature target
- a separate cohort binding for distribution-specific material, including concrete `n/k/t/codecId`
- optional source-evidence objects for original-source authenticity claims
- transition records and maintenance signatures for resharing and migration history

This is the least dangerous path because it:

- preserves the completed Stage A-C baseline
- keeps same-state resharing truly same-state
- avoids conflating source review, archive approval, and maintenance authorization
- maintains a fail-closed, versioned extension story
- leaves room for later governance and provenance refinement without weakening current security boundaries
