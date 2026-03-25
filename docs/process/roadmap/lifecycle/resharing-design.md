# Quantum Vault — Resharing And Lifecycle Artifact Design

Status: Draft successor-design document with Phase 0-frozen contracts
Type: Informative technical design recording the Phase 0-frozen successor design
Audience: contributors, implementers, reviewers, cryptographic auditors
Scope: same-state resharing, lifecycle artifact boundaries, signature/evidence split, transition semantics, shard carriage, and operator roles
Out of scope: full external-format publication, institutional governance policy, and interactive MPC protocols
Relationship: builds on the completed Stage A-C baseline; feeds `implementation-plan-lifecycle.md`, future normative lifecycle specs, and any future successor-format implementation

## 1. Design Posture

Status: Fixed framing

This document describes a **successor artifact family**, not a mutation of the current `quantum-vault-archive-manifest/v3` plus `QV-Manifest-Bundle` v2 family.

That follows directly from the fixed baseline:

- signable bytes are already pinned to `QV-JSON-RFC8785-v1`
- current manifest and bundle grammar are closed and fail closed
- serialization, schema, and semantics are already deliberately separated
- detached signatures currently target canonical signable bytes only
- mutable bundle bytes are not a detached-signature payload

Therefore, if lifecycle support introduces:

- an archive-state descriptor
- a cohort binding
- transition records
- source-evidence objects
- new attachment families for maintenance and provenance signatures

then it must do so as a new artifact family with explicit schemas and versions.

### 1.1 Normative language and JSON discipline

Uppercase `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.
Explanatory prose outside frozen-decision, wire-contract, and verifier-predicate sections is informative.
Sections labeled **Frozen decision**, **Frozen derivation**, **Frozen identifier**, **Frozen role**, **Frozen fields**, or **Frozen meaning** record completed Phase 0 contracts; later work may only codify or implement them.

Lifecycle JSON discipline is part of the design, not a later editorial cleanup:

- lifecycle JSON text MUST parse as RFC 8259 JSON before any schema, canonicalization, digest, or signature step
- parsers MUST reject duplicate object names
- lifecycle v1 artifacts MUST stay within an I-JSON-safe subset compatible with RFC 7493:
  - strings are encoded as UTF-8 JSON text at the byte level
  - numeric fields, where used, MUST be finite integers in the exact interoperable range `0..2^53-1`
  - non-finite numbers are forbidden
- JSON Schema draft 2020-12 remains grammar only; it does not define canonical bytes, derived identifiers, target semantics, or policy semantics

## 2. Motivation: The Current Failure Mode

Status: Current fact motivating the successor design

The current split-time manifest family is correct for the implemented baseline, but it has a lifecycle failure mode:

- shard-distribution fields sit inside the current signable object
- same-state resharing changes those fields
- canonical signable bytes change
- `manifestDigest` changes
- detached signatures and OTS linkage tied to those bytes no longer carry forward as stable archive-state approval

The problem is not that resharing is impossible.
The problem is narrower and more important:

- the current signable object is **cohort-bound**
- same-state resharing needs a **state-bound** approval object and a separate **cohort-bound** distribution object

That is why this document adopts a successor artifact family rather than trying to reinterpret the current manifest semantics.

## 3. Goals And Non-Goals

Status: Frozen design direction

### 3.1 Goals

1. Separate archive-state authenticity from shard-distribution integrity.
2. Make same-state resharing an availability-maintenance event rather than disguised archive re-approval.
3. Preserve archive-approval signatures and their OTS evidence across same-state resharing.
4. Separate source-review provenance from archive-state approval.
5. Keep the design browser-first and client-only for Phase 1.
6. Preserve closed-schema and fail-closed discipline.
7. Preserve current trust semantics: integrity, signature validity, pinning, and policy satisfaction stay distinct.

### 3.2 Non-goals For The First Lifecycle Wave

- no mutation of the current manifest/bundle family
- no online-custodian or MPC resharing protocol
- no claim that same-state resharing repairs leaked predecessor quorum material
- no direct `.qenc` signature requirement in the default archive-authenticity path
- no state-changing migration feature until predecessor-state preservation is designed

## 4. Identity Model

Status: Frozen identity model

Quantum Vault lifecycle work uses three identity layers plus a separate provenance layer:

```text
┌────────────────────────────────────────────────────────────┐
│ Archive Identity (archiveId)                              │
│ "This is the same logical archive."                       │
│ Stable across: same-state resharing, reencryption,        │
│ future rewrap                                             │
├────────────────────────────────────────────────────────────┤
│ Archive State (stateId)                                   │
│ "This specific ciphertext/policy/crypto state."           │
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

Source evidence is orthogonal to these three identity layers.
It is provenance, not archive-state identity.

### 4.1 `archiveId`

Frozen derivation:

```text
archiveId = random 256-bit identifier encoded as lowercase hex
```

Frozen invariants:

- assigned once at archive creation
- never content-derived
- stable across same-state resharing, reencryption, and future `rewrap`
- visible to lifecycle tooling as the continuity anchor for the logical archive

### 4.2 `stateId`

Frozen derivation:

```text
archiveStateDigest = {
  alg: "SHA3-512",
  value: hex(SHA3-512(canonical archive-state descriptor bytes))
}
stateId = archiveStateDigest.value
```

Frozen meaning:

- `stateId` is derived-only metadata
- the archive-state descriptor MUST NOT contain `stateId` inside the canonical bytes used to derive it
- one `stateId` corresponds to one archive-state descriptor
- the archive-state descriptor is the long-lived archive-approval signature target
- same-state resharing preserves `stateId`
- bundle mutation alone does not change `stateId`
- changing the archive-state descriptor creates a new `stateId`

### 4.3 Exact archive-state descriptor v1 field set

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

Rationale:

- these are state-interpretation and ciphertext-binding fields, not cohort logistics
- omitting `kdfTreeId`, nonce/AAD fields, or key `qenc` interpretation fields would silently weaken state identity compared with the current baseline
- top-level members are exactly `schema`, `version`, `stateType`, `canonicalization`, `archiveId`, `parentStateId`, `cryptoProfileId`, `kdfTreeId`, `noncePolicyId`, `nonceMode`, `counterBits`, `maxChunkCount`, `aadPolicyId`, `qenc`, and `authPolicyCommitment`
- `qenc` members are exactly `chunkSize`, `chunkCount`, `payloadLength`, `hashAlg`, `primaryAnchor`, `qencHash`, `containerId`, `containerIdRole`, and `containerIdAlg`
- archive-state descriptor v1 MUST reject any additional top-level members or additional `qenc` members

### 4.4 `parentStateId`

Frozen decision:

- `parentStateId` belongs in the archive-state descriptor
- the initial state uses `null`
- non-initial states reference the predecessor `stateId`

Important distinction:

- `parentStateId` is state lineage
- it is not cohort-fork lineage

### 4.5 `cohortId`

Frozen derivation:

```text
cohortBindingDigest = {
  alg: "SHA3-512",
  value: hex(SHA3-512(canonical cohort-binding bytes))
}

cohortIdPreimage = canonicalize({
  type: "quantum-vault-cohort-id-preimage/v1",
  archiveId,
  stateId,
  cohortBindingDigest
})

cohortId = hex(SHA3-256(cohortIdPreimage))
```

Frozen meaning:

- `cohortId` is derived-only metadata
- the canonical cohort-binding bytes used for `cohortBindingDigest` MUST NOT contain `cohortId`
- unique to one split or reshare event
- replaceable without changing archive state
- carried in every shard and lifecycle record
- MUST be consistent across all shards in a restore candidate set

### 4.6 Source evidence

Source evidence is not an identity layer for the encrypted archive state.
It is provenance about reviewed or precursor artifacts.

Frozen meaning:

- references the original source object or reviewed precursor object
- may preserve source digests, source signatures, or source-review claims
- survives same-state resharing as provenance if the referenced relation is unchanged

Frozen privacy-preserving default profile:

- source-evidence v1 SHOULD emit digests and relation metadata by default
- human-readable descriptive fields are opt-in, not default
- local paths, usernames, email addresses, and operator notes MUST NOT be emitted by default
- `mediaType` MAY be emitted when operationally necessary

## 5. Frozen State/Cohort Boundary

Status: Frozen architecture

This document chooses **Option 2** and freezes it:

- concrete `n/k/t/codecId` are cohort-level
- same-state resharing MAY change them
- therefore they are not part of the archive-state approval signature target

### 5.1 Why this is the preferred QV boundary

It is the least dangerous option for Quantum Vault because it keeps all of the following true at once:

- archive-state descriptor bytes stay stable across same-state resharing
- archive-approval signatures survive without reinterpretation
- OTS evidence over those detached signatures survives as well
- same-state resharing remains maintenance, not state re-approval
- the browser-first, client-only Phase 1 model does not need a second policy layer before resharing exists

### 5.2 Consequences of the boundary

Changes that preserve `stateId`:

- attach/update bundled archive-approval signatures
- attach/update bundled public keys
- attach/update OTS evidence
- add or update source evidence
- add or update maintenance signatures
- same-state resharing that changes only cohort-level material

Changes that require a new `cohortId` but preserve `stateId`:

- fresh resharing with new share commitments
- changing concrete `n/k/t/codecId`
- changing body-definition details
- changing shard-body hashes

Changes that require a new `stateId`:

- changing `qencHash`
- changing `containerId`
- changing `cryptoProfileId`
- changing `kdfTreeId`
- changing nonce/AAD semantics
- changing `authPolicyCommitment`

Changes that require new archive-approval signatures:

- any new `stateId`

Changes that recommend new timestamp evidence:

- any new archive-approval signature set for a new state

## 6. Successor Artifact Family

Status: Frozen successor artifact structure

The successor family introduces five main artifact classes.

### 6.1 Archive-state descriptor

Frozen identifier:

```text
schema = "quantum-vault-archive-state-descriptor/v1"
```

Frozen role:

- long-lived archive-approval signature target
- canonicalized under `QV-JSON-RFC8785-v1`
- immutable for the lifetime of that archive state

### 6.2 Cohort binding

Frozen identifier:

```text
schema = "quantum-vault-cohort-binding/v1"
```

Frozen role:

- binds one shard-distribution cohort to one archive state
- commitment-bearing object for restore and cohort integrity
- not the long-lived archive-approval signature target

Frozen fields:

- `schema`
- `version`
- `cohortType`
- `canonicalization`
- `archiveId`
- `stateId`
- `sharding`
- `bodyDefinitionId`
- `bodyDefinition`
- `shardBodyHashAlg`
- `shardBodyHashes[]`
- `shareCommitment`
- `shareCommitments[]`

Important representation rule:

- `cohortId` is derived from the canonical cohort-binding bytes but is not carried inside those bytes
- `cohortId` may be carried in shard metadata, transition records, and verification reports

### 6.3 Transition record

Frozen identifier:

```text
schema = "quantum-vault-transition-record/v1"
```

Frozen role:

- records maintenance or state-changing lifecycle events
- signable under `QV-JSON-RFC8785-v1`
- separate from archive-state approval

Frozen fields:

- `schema`
- `version`
- `canonicalization`
- `transitionType`
- `archiveId`
- `fromStateId`
- `toStateId`
- `fromCohortId`
- `toCohortId`
- `fromCohortBindingDigest`
- `toCohortBindingDigest`
- `reasonCode`
- `performedAt`
- `operatorRole`
- `actorHints`
- `notes`

`actorHints` stays free-form in v1.
It is advisory operator metadata, not a controlled authority vocabulary.

For same-state resharing:

- `fromStateId == toStateId`
- `fromCohortId != toCohortId`

### 6.4 Source-evidence object

Frozen identifier:

```text
schema = "quantum-vault-source-evidence/v1"
```

Frozen role:

- carries source-review or precursor-artifact provenance
- never substitutes for archive-state approval

### 6.5 Lifecycle bundle v1

Frozen identifier:

```text
type = "QV-Lifecycle-Bundle"
version = 1
```

Frozen role:

- mutable carrier for lifecycle artifacts and detached authenticity material
- not itself the long-lived archive-approval surface

Frozen lifecycle-bundle v1 contents:

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

## 7. Exact Binding Chain

Status: Required architectural clarification

```text
Source artifact bytes
  └── optional external source signature
         └── optional source-evidence object
                └── optional source-evidence signature
                       └── optional OTS over detached source-evidence signature bytes

Canonical archive-state descriptor bytes
  └── archive-approval detached signatures
         └── optional OTS over detached archive-approval signature bytes
                └── archive policy may count only archive-approval signatures

Archive-state descriptor
  ├── archiveId
  ├── archiveStateDigest = SHA3-512(canonical archive-state descriptor bytes)
  ├── stateId = archiveStateDigest.value
  ├── qencHash / containerId
  ├── cryptoProfileId / kdfTreeId / nonce/AAD semantics
  └── authPolicyCommitment
         └── concrete authPolicy object in lifecycle bundle

Archive-state descriptor
  └── binds exact .qenc bytes indirectly through qencHash / containerId

Cohort binding
  ├── archiveId
  ├── stateId
  ├── concrete n/k/t/codecId
  ├── bodyDefinition
  ├── shareCommitments[]
  └── shardBodyHashes[]
         └── cohortBindingDigest = SHA3-512(canonical cohort-binding bytes)
                └── cohortId = SHA3-256(canonical cohort-id preimage)
                       └── binds one shard-distribution cohort for one archive state

Transition record
  ├── archiveId
  ├── fromStateId / toStateId
  ├── fromCohortId / toCohortId
  └── cohort-binding digests
         └── optional maintenance signatures
                └── optional OTS over detached maintenance-signature bytes

Lifecycle bundle
  └── carries the current archive-state descriptor, current cohort binding,
      authPolicy, source evidence, transition records, detached signatures,
      bundled key material, and timestamps
```

Key interpretation points:

- archive approval binds `.qenc` indirectly through `qencHash` and `containerId`
- cohort integrity is commitment-driven, not archive-approval-signature-driven
- source evidence is provenance, not archive approval
- transition records are maintenance history, not archive approval
- OTS is evidence over detached signature bytes only

## 8. Signature And Evidence Model

Status: Core lifecycle design

### 8.1 Archive-approval signatures

Archive-approval signatures are the successor to today’s detached signatures over canonical manifest bytes.

Semantics:

- target: canonical archive-state descriptor bytes
- meaning: "I approve this archive state"
- counted by archive policy: yes
- same-state resharing effect: unchanged archive-state descriptor means the signatures survive

### 8.2 Source-evidence signatures

Source-evidence signatures target:

- the original source object in an external workflow, or
- a first-class QV source-evidence object

Semantics:

- meaning: "I reviewed or attest to this source artifact or relation"
- counted by archive policy: no
- same-state resharing effect: survive as provenance if the source-evidence object is unchanged

### 8.3 Maintenance signatures

Maintenance signatures target transition-record bytes.

Semantics:

- meaning: "I authorized, performed, or witnessed this lifecycle event"
- counted by archive policy: no
- same-state resharing effect: remain as maintenance provenance

### 8.4 Direct `.qenc` signatures

Direct `.qenc` signatures are optional and not part of the preferred QV path.

Reason:

- archive-state descriptor already binds `qencHash` and `containerId`
- archive-approval signatures therefore already bind exact `.qenc` bytes indirectly

## 9. What Signatures Survive Same-State Resharing, And Why

Status: Required clarification

| Signature / evidence type | Target | Survives same-state resharing? | Why |
| --- | --- | --- | --- |
| Archive-approval signature | archive-state descriptor | Yes | Archive-state descriptor bytes do not change |
| OTS over archive-approval signature bytes | detached archive-approval signature bytes | Yes | The detached signature bytes do not change |
| Source-evidence signature | source object or source-evidence object | Yes, if unchanged | Different semantic surface from cohort maintenance |
| Maintenance signature over prior transition record | transition-record bytes | Yes, as historical provenance | It remains a record of what was signed at that time |
| Direct `.qenc` signature | exact `.qenc` bytes | Yes, if `.qenc` is unchanged | Same ciphertext bytes |
| Cohort-binding signature, if ever introduced later | cohort binding | No automatic carry-forward | A new cohort binding is a new object |

This is the main reason the signature split matters.
If the long-lived signature target remains archive-state only, same-state resharing can change cohort material without forcing new archive-approval signatures.

## 10. Phase 1 Decision On Independent Cohort-Binding Signatures

Status: Frozen Phase 0 decision

Phase 1 answer: **no independent cohort-binding signature requirement**.

Reason:

- cohort integrity is already enforced by commitments and shard-level consistency checks
- a required transition record plus optional maintenance signatures provide a cleaner maintenance/provenance surface
- adding a second detached-signature path for cohort bindings would complicate verification without improving the main archive-approval surface

Independent cohort-binding signatures remain a future option if custodial attestation becomes a first-class requirement.

## 11. Lifecycle Bundle, `publicKeyRef`, And Pinning Semantics

Status: Required successor-family clarification

### 11.1 Bundled key material

Lifecycle-bundle v1 includes `attachments.publicKeys[]` from the start.

These entries exist for:

- bundled verification material
- bundled signer identity material
- bundled `publicKeyRef` resolution
- optional pinning

### 11.2 Fail-closed `publicKeyRef`

Required rule:

- if a bundled signature entry declares `publicKeyRef`, the verifier MUST resolve it using the frozen compatibility predicate below and verify against that key
- failure is a verification failure for that signature
- it is **not** merely an unpinned-but-still-valid case

Frozen compatibility predicate:

- exactly one bundled key entry MUST satisfy `id == publicKeyRef`
- that entry MUST also satisfy `suite == <signature-entry.suite>`
- the declared key `encoding` MUST decode successfully into exactly one key value
- the decoded key MUST be structurally valid for the declared `kty` and usable with the declared `suite`
- detached-signature verification against that decoded key and the declared target bytes MUST succeed
- zero matches, multiple matches, decode failure, structural key invalidity, suite mismatch, or verification failure MUST reject the signature entry

This preserves the current fail-closed safety boundary from the existing bundle model.

### 11.3 Pinning stays separate

Pinning remains separate from:

- signature validity
- archive policy satisfaction
- maintenance-signature verification
- source-evidence verification

Archive policy counts archive-approval signatures only.

### 11.4 Minimal successor attachment contracts

Required minimum detached-signature fields:

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

Required family mappings:

- archive-approval signature entries MUST carry `signatureFamily = "archive-approval"` and `targetType = "archive-state"`
- maintenance signature entries MUST carry `signatureFamily = "maintenance"` and `targetType = "transition-record"`
- source-evidence signature entries MUST carry `signatureFamily = "source-evidence"` and `targetType = "source-evidence"`

Required target mappings:

- archive-state signatures:
  - `targetRef = "state:" + stateId`
  - `targetDigest = archiveStateDigest`
- maintenance signatures:
  - `targetRef = "transition:sha3-512:" + SHA3-512(canonical transition-record bytes)`
  - `targetDigest = { alg: "SHA3-512", value: SHA3-512(canonical transition-record bytes) }`
- source-evidence signatures:
  - `targetRef = "source-evidence:sha3-512:" + SHA3-512(canonical source-evidence bytes)`
  - `targetDigest = { alg: "SHA3-512", value: SHA3-512(canonical source-evidence bytes) }`

Attach and restore MUST interpret these fields identically.
No family-local heuristic reinterpretation is allowed.

### 11.5 Bundled-key and OTS linkage contract

Bundled key entries MUST carry:

- `id`
- `kty`
- `suite`
- `encoding`
- `value`

`publicKeyRef` rule:

- if present, `publicKeyRef` MUST equal one bundled key `id`
- unresolved, incompatible, or non-verifying `publicKeyRef` is a verification failure for that signature
- exact compatibility predicate:
  - exactly one bundled key entry MUST satisfy `id == publicKeyRef`
  - that entry MUST also satisfy `suite == <signature-entry.suite>`
  - the declared key `encoding` MUST decode successfully into exactly one key value
  - the decoded key MUST be structurally valid for the declared `kty` and usable with the declared `suite`
  - detached-signature verification against that decoded key and the declared target bytes MUST succeed
  - zero matches, multiple matches, decode failure, structural key invalidity, suite mismatch, or verification failure MUST reject the signature entry

Timestamp entries MUST carry:

- `id`
- `type = "opentimestamps"`
- `targetRef`
- `targetDigest = { alg: "SHA-256", value: "<lowercase hex>" }`
- `proofEncoding`
- `proof`

Exact OTS linkage rule:

- `targetRef` MUST resolve to one detached-signature entry by `id`
- the verifier MUST decode that signature entry’s `signature` field to the exact detached-signature bytes
- `targetDigest.value` MUST equal `SHA-256` over those exact detached-signature bytes
- an unresolved or mismatched OTS entry is invalid evidence for that signature and MUST NOT be heuristically reassigned

## 12. Shard Carriage, Attach Flow, And Restore Flow

Status: Required implementation-relevant design detail

### 12.1 Shard carriage strategy

Successor `.qcont` shards produced by QV carry:

- canonical archive-state descriptor bytes plus digest
- canonical current cohort-binding bytes plus digest
- current lifecycle-bundle bytes plus digest
- shard metadata including `archiveId`, `stateId`, `cohortId`, and shard index

This preserves the self-contained shard model.

### 12.2 Attach-flow implications

Attach updates lifecycle-bundle bytes only.

Attach MUST:

- validate detached archive-approval signatures against archive-state descriptor bytes
- validate declared `publicKeyRef`
- validate OTS linkage to detached signature bytes
- preserve archive-state bytes unchanged
- preserve cohort-binding bytes unchanged

Attach MAY rewrite embedded lifecycle bundles across the selected cohort.
If some shards are not rewritten, mixed embedded lifecycle-bundle digests are allowed **within that same cohort** and must be reported honestly later.

### 12.3 Restore-flow implications

Restore selection occurs in two steps.

Step 1: select archive state plus cohort

- group by `archiveId`, `stateId`, and `cohortId`
- require exact archive-state byte equality inside the candidate set
- require exact cohort-binding byte equality inside the candidate set
- fail closed on mixed states or mixed cohorts

Step 2: select lifecycle-bundle context

- accept uploaded lifecycle bundle only if it matches the selected archive-state and current cohort-binding digests
- if no explicit lifecycle bundle is supplied and the selected shard set carries exactly one embedded lifecycle-bundle digest, use that digest
- if the selected shard set carries more than one embedded lifecycle-bundle digest, restore MUST NOT auto-select by timestamp count, signature count, “richness,” lexical order, or similar heuristics
- in that multi-bundle case, restore MUST require explicit lifecycle-bundle bytes or explicit operator selection of one embedded bundle digest

Important distinction:

- multiple bundle digests inside one selected cohort are **not** a cohort fork
- different `cohortId` values for one `archiveId` plus `stateId` **are** a cohort fork

### 12.4 Verifier predicates and rejection conditions

Required predicates:

1. archive-state digest equality
   - require `archiveStateDigest.value == SHA3-512(canonical archive-state descriptor bytes)`
2. archive identity equality
   - require one `archiveId` across the selected candidate set
3. `stateId` derivation equality
   - require `stateId == archiveStateDigest.value`
4. cohort-binding digest equality
   - require `cohortBindingDigest.value == SHA3-512(canonical cohort-binding bytes)`
5. `cohortId` derivation equality
   - require `cohortId == SHA3-256(canonical cohort-id preimage bytes)` encoded as lowercase hex
6. shard-set consistency
   - require one `archiveId`, one `stateId`, one `cohortId`, one exact archive-state byte sequence, and one exact cohort-binding byte sequence inside the selected candidate set
7. signature target equality
   - require each detached signature entry’s `signatureFamily`, `targetType`, `targetRef`, and `targetDigest` to match its actual target object and target bytes
8. fail-closed `publicKeyRef`
   - if `publicKeyRef` is present, require the frozen exact-one-match compatibility predicate and successful verification against that key
9. exact OTS linkage
   - if an OTS entry is present, require `targetRef` resolution and `targetDigest.value == SHA-256(exact detached-signature bytes)`
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
- unresolved or mismatched OTS linkage MUST reject the affected timestamp entry as invalid evidence

## 13. Same-State Resharing Design

Status: Recommended Phase 1 mechanism

### 13.1 Preconditions

Same-state resharing requires:

- a threshold of shards from one internally consistent predecessor cohort
- one consistent `archiveId`
- one consistent `stateId`
- one consistent predecessor `cohortId`
- unchanged archive-state descriptor bytes

If the intended operation changes:

- `qencHash`
- `containerId`
- `cryptoProfileId`
- `kdfTreeId`
- nonce/AAD semantics
- `authPolicyCommitment`

then it is not same-state resharing.

### 13.2 Exact meaning of reconstructed secret material

Do not replace this with vague wording.

Same-state resharing reconstructs:

- the threshold-recovered ML-KEM private key material needed to recover the current protected encryption state for re-splitting

It does not require:

- decrypting plaintext
- changing the `.qenc` bytes

### 13.3 Ceremony

1. Gather at least `t` shards from the predecessor cohort.
2. Verify `archiveId`, `stateId`, and `cohortId` consistency.
3. Recompute `archiveStateDigest`, `stateId`, `cohortBindingDigest`, and `cohortId`; reject any mismatch with carried metadata.
4. Verify predecessor archive-state bytes and predecessor cohort-binding bytes are internally consistent.
5. Verify share commitments and shard-body hashes for the predecessor cohort.
6. Reconstruct the ML-KEM private key material in memory.
7. Choose new cohort parameters:
   - `n'`
   - `k'`
   - `t'`
   - `codecId'`
   - body-definition changes that remain cohort-level
8. Generate a fresh cohort with fresh share randomness.
9. Build the successor cohort-binding object, compute `cohortBindingDigest`, and derive the new `cohortId`.
10. Build successor shards embedding:
   - unchanged archive-state descriptor
   - new cohort binding
   - updated lifecycle bundle
11. Create the required transition record.
12. Optionally sign that transition record with maintenance keys.
13. Zeroize reconstructed secret material as quickly as possible.
14. Instruct custodians to destroy predecessor shards, recognizing that the system cannot prove destruction.

### 13.4 Allowed and forbidden changes

Allowed in same-state resharing:

- `cohortId`
- concrete `n/k/t/codecId`
- body-definition details
- `shareCommitments[]`
- `shardBodyHashes[]`
- custodian assignment
- embedded lifecycle-bundle digest

Forbidden in same-state resharing:

- `archiveId`
- `stateId`
- archive-state descriptor bytes
- `qencHash`
- `containerId`
- `cryptoProfileId`
- `kdfTreeId`
- nonce/AAD semantics
- `authPolicyCommitment`

### 13.5 Secret-in-memory risk

Reconstruct-and-resplit exposes the reconstructed ML-KEM private key material in memory.

This is not a new class of risk compared with restore.
It is the same browser/runtime exposure class already acknowledged by the current security model.

Recommended mitigations:

- perform resharing on a trusted or offline machine where feasible
- minimize ceremony duration
- zeroize buffers on best-effort completion

Distributed resharing remains out of scope for Phase 1.

## 14. What Same-State Resharing Does NOT Prove Or Repair

Status: Required claim boundary

### 14.1 It does not re-approve archive content

A new cohort is not a new archive-state approval.
If new archive-state approval is desired, produce new archive-approval signatures explicitly.

### 14.2 It does not revoke leaked old quorum material

If the predecessor cohort may already have leaked enough material to reconstruct the old secret, same-state resharing does not retroactively repair that exposure.

Important wording:

- old and new cohorts are operationally distinct
- cross-cohort share mixing does not create a valid single cohort
- the predecessor cohort remains its own confidentiality surface until enough old material is destroyed or otherwise known unavailable

### 14.3 It does not create fresh source-authenticity evidence

A resharing ceremony says nothing new about the original source artifact.
If source-review claims are needed, they must be modeled explicitly as source evidence.

### 14.4 It does not address algorithm weakness or HNDL by itself

Same-state resharing leaves the ciphertext state unchanged.

If the response requirement is:

- algorithm migration
- compromise response for the underlying secret
- protection against future captures under a new profile

then the correct path is a new archive state, at minimum via reencryption.

## 15. Transition Record Semantics

Status: Frozen semantics

### 15.1 What exactly is signed?

If a transition record is signed, the signature target is the canonical transition-record bytes.

It is **not**:

- mutable lifecycle-bundle bytes
- archive-state descriptor bytes
- cohort-binding bytes directly

### 15.2 What does a maintenance signature mean?

Frozen meanings:

- `maintenance-authorization`
- `operator-attestation`
- `witness`

These signatures mean that a lifecycle event was authorized, performed, or witnessed.
They do not mean archive-state approval.

### 15.3 Who signs it?

Expected signer categories:

- archive maintainer or repository operator
- governance actor, if present
- optional witness or quorum participant

Auditors are not required to sign transition records unless they are also acting in one of the maintenance roles above.

### 15.4 Is a transition record required?

Yes, for QV-produced same-state resharing.

Required Phase 1 rule:

- a transition record MUST be created for every QV-produced same-state resharing event
- the successor artifact family MUST support detached maintenance signatures over transition records
- maintenance signatures MAY be absent in the first implementation wave unless a governance profile requires them

This is intentionally stronger than “recommended but optional.”
Without a required transition record, same-state resharing changes too much operationally while leaving too little durable maintenance history behind.

## 16. Branch Detection And Forked Resharing

Status: Required operational semantics

Two different valid cohorts can exist for the same `archiveId` and `stateId`.

This is a cohort fork, not a `parentStateId` state-DAG branch.
The archive state is unchanged; only the distribution layer has diverged.

### 16.1 Detection

Fork condition:

- same `archiveId`
- same `stateId`
- different `cohortId`
- distinct active cohort bindings or distinct transition histories

### 16.2 Verification behavior

Required behavior:

- restore MUST reject mixed shard sets across different `cohortId` values
- restore MAY proceed from any single internally consistent cohort for the same state
- tooling SHOULD warn when multiple valid cohorts are known for one state

### 16.3 No automatic winner selection

Phase 1 must not guess a winner by:

- latest timestamp alone
- attachment count
- lexical order of identifiers

If future governance defines a preferred active cohort rule, that rule must be explicit and separately carried as signed maintenance/governance data.

## 17. Operator Roles

Status: Recommended semantic separation

### 17.1 Auditor / source verifier

These are different claims and must not be collapsed:

- **Source review:** "I reviewed or attest to a specific source artifact or precursor object." Expected surface: source-evidence object or external source-signature workflow.
- **Archive-state approval:** "I approve this encrypted archive state." Expected surface: archive-state descriptor.

The same person may perform both roles in one workflow, but the signature targets and semantics remain distinct.

### 17.2 Archive maintainer

Primary claim:

- authorized, performed, or witnessed lifecycle maintenance

Expected surface:

- transition records

### 17.3 Quorum participants / custodians

Primary claim:

- supplied shards or participated operationally in maintenance

Expected surface:

- usually none in Phase 1
- optional witness signatures on transition records if desired

### 17.4 Restore operator / verifier

Primary role:

- evaluates integrity, archive approval, pinning, policy outcome, source provenance, maintenance history, and evidence linkage

## 18. Availability Maintenance, Compromise Response, Policy Change, And Migration

Status: Frozen decision table

| Event class | Typical trigger | Correct artifact effect | Archive-approval consequence |
| --- | --- | --- | --- |
| Availability maintenance | custodian loss, rotation, margin erosion | new cohort binding, same archive state, required transition record | archive-approval signatures survive |
| Suspected old-quorum leakage | predecessor cohort may already expose the secret | new archive state required | new archive-approval signatures required |
| Policy change | approval semantics change | new archive-state descriptor, new cohort binding, continuity preservation required | new archive-approval signatures required |
| Reencryption / crypto migration | new ciphertext or crypto profile | new archive-state descriptor, new cohort binding, continuity preservation required | new archive-approval signatures required |
| Future `rewrap` | future outer-envelope refresh only | future branch, architecture-blocked | new archive-approval signatures expected |

### 18.1 Operational resharing trigger

The current safety-margin guidance remains useful as cohort-level maintenance guidance:

```text
safety_margin = ceil((n - t) / 2)
reshare_trigger: available_honest_custodians < t + safety_margin
```

This is operational maintenance guidance, not archive-state authenticity.

### 18.2 HNDL implications

HNDL pressure is addressed by:

- current PQ choices for the existing state
- future reencryption when migration is needed

Same-state resharing does not change captured ciphertext and therefore is not a direct HNDL response.

## 19. Migration Continuity Requirement

Status: Architectural requirement preserved even though implementation is deferred

The successor family must not ship state-changing lifecycle features until it can preserve predecessor-state continuity explicitly.

Required continuity-preservation requirement:

- preserve predecessor archive-state descriptor bytes
- preserve predecessor archive-approval signatures
- preserve predecessor timestamps/evidence
- preserve transition links sufficient to verify lineage from predecessor to successor

This requirement is frozen now even though exact state-history packaging may arrive in a later versioned implementation phase.

## 20. Alternatives Considered

Status: Preserved alternatives

### 20.1 Option 1 — keep concrete `n/k/t/codecId` in the archive-state descriptor

Rejected because it makes signature survival incompatible with same-state resharing flexibility.

### 20.2 Option 3 — sign a sharding-policy class, keep concrete values in the cohort

Deferred, not rejected outright.

This remains the most plausible future refinement if QV later needs signed operational bounds such as:

- minimum threshold
- permitted `n` ranges
- allowed codec families

### 20.3 Direct cohort-binding signatures as a Phase 1 requirement

Rejected for Phase 1 because transition records plus commitment checks already provide the cleaner maintenance surface.

### 20.4 Direct `.qenc` signatures as the primary path

Rejected because they duplicate the normal archive-state binding chain and weaken the clarity of the preferred archive-approval model.

## 21. Future Work And Out Of Scope

Status: Future work

### 21.1 Source-evidence richness beyond the minimum v1 model

Possible later additions:

- reviewer role metadata
- richer external-source-signature references
- richer opt-in descriptive vocabularies beyond the privacy-preserving default profile

### 21.2 Envelope-DEK and future `rewrap`

Still architecture-blocked.
Current QV encrypts payload content directly under state-derived symmetric material.

### 21.3 Distributed resharing

PSS, VSS, and DPSS remain future research only.
They require interactive online custodians and do not fit the current client-only model.

### 21.4 Merkleized cohort commitments

Useful only if flat cohort commitments become too large or per-shard membership proofs become operationally important.

### 21.5 Renewable evidence

RFC 4998-style renewal remains future-direction context.
Current OTS usage remains evidence-only over detached signature bytes.

## 22. Design Summary

Status: Frozen conclusion

The preferred Quantum Vault lifecycle architecture is:

- a successor archive-state descriptor as the long-lived archive-approval signature target
- a separate cohort binding for distribution-specific material, including concrete `n/k/t/codecId`
- a self-contained shard model carrying archive-state, cohort-binding, and lifecycle-bundle bytes
- lifecycle-bundle v1 carrying auth policy, source evidence, transition records, bundled key material, detached signatures, and timestamps
- required transition records for QV-produced same-state resharing
- source-evidence objects for provenance rather than archive approval

This is the least dangerous path because it:

- preserves the completed Stage A-C baseline
- keeps same-state resharing truly same-state
- preserves fail-closed schema and `publicKeyRef` discipline
- avoids conflating source review, archive approval, and maintenance authorization
- keeps the design browser-first and client-only for Phase 1
- preserves the migration-continuity requirement instead of dropping it from the architecture
