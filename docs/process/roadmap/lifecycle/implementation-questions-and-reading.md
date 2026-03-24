# Quantum Vault — Implementation Questions & Reading Guide

Status: Decision-prep document
Type: Informative planning / research guide
Audience: contributors, implementers, reviewers, cryptographic auditors
Scope: lifecycle design questions that remain after the completed Stage A–C baseline
Relationship: the current normative baseline remains `docs/format-spec.md`, `docs/trust-and-policy.md`, and `docs/security-model.md`; this document prepares the successor lifecycle design captured in `resharing-design.md` and the staged work in `implementation-plan-lifecycle.md`

## Purpose

This document is intentionally not the strict implementation plan.

Its role is to:

- restate the fixed baseline inherited from the completed manifest-canonisation work
- identify the tensions introduced by lifecycle requirements
- separate resolved questions from still-open design choices
- preserve meaningful alternatives and trade-off analysis
- tie the major design questions to the standards that inform them

The goal is to make implementation planning safer, not to compress every issue into a single final answer.

## 1. Fixed Baseline Inherited From Stage A-C

Status: Fixed baseline

The following points are already settled and must be treated as constraints for lifecycle work:

1. Detached signatures currently authenticate canonical signable JSON bytes only. They do not authenticate mutable bundle bytes.
2. Bundle mutation MUST NOT change the detached-signature payload.
3. Canonicalization is now role-specific:
   - signable manifest-family bytes use the RFC 8785-aligned `QV-JSON-RFC8785-v1` profile
   - `authPolicyCommitment` uses the same signable canonicalization profile
   - bundle serialization is versioned separately under `QV-BUNDLE-JSON-v1`
4. Current grammar discipline is closed and fail-closed:
   - unknown current top-level fields are not an implicit extension path
   - adding new top-level objects or new attachment families requires a new schema/version
5. JSON Schema draft 2020-12 is the grammar layer. It does not replace canonicalization rules or semantic verification.
6. Current restore and verification already treat `qencHash` as the primary ciphertext binding anchor and detached signatures as external authenticity artifacts linked to the signable object.
7. OpenTimestamps evidence is evidence-only. It targets detached signature bytes, not the bundle and not the whole archive package.

Lifecycle work therefore MUST NOT:

- reopen the Stage A canonicalization question
- reintroduce grammar openness through roadmap prose
- treat schema validity as if it settled semantic lifecycle meaning
- silently retrofit new lifecycle fields into `quantum-vault-archive-manifest/v3` or `QV-Manifest-Bundle` v2

The lifecycle branch is a successor artifact-family design problem, not a quiet patch to the current manifest/bundle baseline.

## 2. Current Tensions Introduced By Lifecycle Requirements

Status: Active design pressure

The completed baseline is internally coherent for the current split-time manifest model, but lifecycle requirements expose several tensions:

### 2.1 Split-time signature target vs same-state resharing

Today the signable object is produced at split time and includes shard-specific material. That makes detached signatures cohort-bound.

If `shareCommitments[]`, `shardBodyHashes[]`, or concrete shard-layout parameters remain inside the long-lived signature target, same-state resharing cannot preserve signatures.

### 2.2 Archive authenticity vs source authenticity

Current detached signatures prove only that a signer key signed the signable JSON bytes.

They do not, by themselves, prove:

- that the signer reviewed the plaintext source
- that the signer approved a later resharing ceremony
- that the signer approved a migration event

Lifecycle planning must stop treating these as one claim.

### 2.3 Availability maintenance vs compromise response

Ordinary custodian churn and suspected quorum leakage are different classes of event.

- Availability maintenance is about keeping a state recoverable.
- Compromise response is about whether the underlying secret may already be exposed.

Same-state resharing can help the first problem. It does not, by itself, repair the second.

### 2.4 Stable identity vs current current-state anchors

The current baseline has strong current-state fixity anchors (`qencHash`, `containerId`, `manifestDigest`, `authPolicyCommitment`) but no first-class `archiveId` that survives reencryption or future rewrap.

Long-term continuity therefore remains under-specified until lifecycle artifacts introduce it explicitly.

### 2.5 Closed schemas vs lifecycle expansion

Archive descriptors, cohort bindings, transition records, maintenance signatures, and source evidence are all new artifact concepts.

Because Stage B adopted closed grammar discipline, these concepts cannot be added informally to the current manifest or bundle. They require a successor artifact family with its own schema/version taxonomy.

## 3. Archive Identity, Archive State, Cohort Identity, And Source Evidence

Status: Recommended conceptual separation

The lifecycle design should use four distinct objects or identity layers:

### 3.1 Archive identity

`archiveId` identifies the logical archive across lifecycle events.

Recommended properties:

- random, opaque, non-content-derived identifier
- assigned once at archive creation
- stable across same-state resharing, reencryption, and future rewrap

Why this matters:

- content-derived identifiers leak equivalence
- `qencHash` is too state-specific to serve as long-term archive identity
- OAIS-style continuity needs a durable identifier distinct from any one ciphertext state

### 3.2 Archive state

`stateId` identifies one specific archive-state descriptor: one cryptographic/policy state of an archive.

Recommended meaning:

- a state is defined by the signed archive-state descriptor
- changing the ciphertext binding, crypto profile, nonce/AAD semantics, or `authPolicyCommitment` creates a new state
- bundle mutation alone does not create a new state
- same-state resharing does not create a new state

### 3.3 Cohort identity

`cohortId` identifies one shard-distribution cohort for one archive state.

Recommended meaning:

- new cohort on every split or reshare
- tied to one archive state, but replaceable within that state
- carries distribution-specific integrity material such as concrete `n/k/t/codecId`, `shareCommitments[]`, `shardBodyHashes[]`, and shard-body definition

Recommended preimage intent:

- archive/state binding, so the cohort cannot be silently reinterpreted as belonging to another archive state
- threshold semantics, including at least the concrete reconstruction threshold and share count for that cohort
- Reed-Solomon or equivalent coding parameters, including codec/profile identifiers and parity/data-count semantics
- shard-body-definition identity, so body-hash meaning is stable
- per-share commitments and per-shard body hashes

The exact nested JSON shape should be frozen in the successor schema, not improvised in prose. The important point here is the semantic content of the preimage, not the placeholder object syntax.

### 3.4 Source authenticity evidence

Source evidence is a separate provenance object, not a substitute for archive-state authenticity.

It exists to express claims like:

- "this plaintext source object had digest X"
- "this package was encrypted from that reviewed source"
- "this archived state derives from an externally signed source artifact"

Source evidence may survive same-state resharing as provenance, but its semantic claim is different from archive approval.

## 4. Authenticity Surfaces And Signature Targets

Status: Core design question

Lifecycle work is safest when it explicitly separates four authenticity/integrity surfaces:

| Surface | Primary object | Typical proof | Survives same-state resharing? | Notes |
| --- | --- | --- | --- | --- |
| Source authenticity | source artifact or source-evidence object | source signature or auditor signature | Yes, as provenance | Distinct from approval of encrypted archive state |
| Ciphertext/container authenticity | exact `.qenc` bytes | indirect archive-state signature via `qencHash`/`containerId`, or optional direct `qenc` signature | Yes, if `.qenc` bytes unchanged | Usually indirect in QV |
| Archive-state authenticity | archive-state descriptor | detached archive-approval signatures | Yes | This is the long-lived approval surface |
| Cohort/shard-distribution integrity | cohort binding + shards | commitments, hashes, optional maintenance signatures | No; new cohort replaces old one | Operational and replaceable |

Recommended target split:

- Archive-approval signatures sign canonical archive-state descriptor bytes.
- Source-authenticity signatures sign either the original source artifact or a dedicated source-evidence object.
- Maintenance signatures sign transition records and, if ever needed, other maintenance-specific artifacts.
- Cohort integrity is primarily commitment-based, not approval-signature-based.

### 4.1 Should QV support a first-class source-evidence object?

Recommended answer: yes, but not as a Phase 1 blocker for same-state resharing.

Minimal useful fields:

- `schema` / `version`
- `relationType` such as `encrypted-from`, `derived-from`, or `reviewed-as`
- `sourceObjectType`
- one or more `sourceDigests`
- optional non-sensitive source descriptors such as `sourceFilename` or `mediaType`
- references to external source signatures or reviewer evidence, if present

Why first-class support is useful:

- it prevents source-review claims from being silently overloaded onto archive-state signatures
- it creates a place to preserve external provenance without changing the archive-state signature target

### 4.2 Should source evidence be signed separately from archive-state signatures?

Recommended answer: yes.

If Quantum Vault carries a source-evidence object, signatures over that object SHOULD remain semantically separate from archive-approval signatures.

Reason:

- "I reviewed this source object" is a different claim from "I approve this encrypted archive state"
- keeping them separate allows either claim to exist without misrepresenting the other

### 4.3 Should `qenc` itself be directly signed?

Recommended answer: usually no, optionally yes for external workflows.

If archive-approval signatures cover an archive-state descriptor that binds `qencHash` and `containerId`, then a direct `.qenc` signature is normally redundant inside Quantum Vault:

`archive-state signature -> qencHash/containerId -> exact qenc bytes`

A direct `.qenc` signature may still be useful when:

- a non-QV workflow consumes `.qenc` without the lifecycle artifacts
- a repository wants an independent transport-layer authenticity claim over the ciphertext object itself

## 5. Hard Unresolved Decisions Before Code

Status: Open questions that still affect implementation shape

The following issues should be frozen before the lifecycle successor family is coded:

1. Exact successor artifact names and schema/version identifiers.
2. Whether `parentStateId` belongs inside the archive-state descriptor, only inside transition records, or in both.
3. Whether transition records are required for every same-state resharing event or only strongly recommended.
4. Whether maintenance signatures on transition records are mandatory for produced records or optional but supported.
5. The minimum Phase 1 field set for source-evidence objects if that work is started before resharing ships.
6. Whether `archiveId` remains cleartext in shard metadata or is hidden behind a commitment/reference strategy.
7. Whether fork handling is warning-only in Phase 1 or whether some governance rule is needed to mark a preferred active cohort.

These are real design choices. They are smaller than the state/cohort boundary question, but they still affect format and verification behavior.

## 6. Recommended Decisions

Status: Recommended direction for implementation planning

### 6.1 Use a successor lifecycle artifact family

Do not mutate the current `quantum-vault-archive-manifest/v3` and `QV-Manifest-Bundle` v2 objects.

Recommended path:

- keep the current Stage A-C baseline intact as the implemented current family
- define a successor lifecycle family with separate archive-state, cohort, transition, and evidence artifacts
- reuse the same signable canonicalization profile (`QV-JSON-RFC8785-v1`) for signable successor objects unless byte rules actually change

### 6.2 Prefer Option 2 for concrete sharding parameters

Recommended choice:

- concrete `n/k/t/codecId` belong to the cohort binding, not the archive-state descriptor
- same-state resharing MAY change these values without changing `stateId`

Why this is the least dangerous option now:

- it matches the requirement that same-state resharing preserve archive-approval signatures
- it keeps distribution-specific material out of the long-lived approval target
- it avoids inventing a fake "same state" while still changing signed bytes

Important caveat:

- changing `n/k/t` may change operational security and recoverability posture
- that change should be represented as maintenance history and, later, governance semantics
- it is not itself proof that the archive content changed

### 6.3 Define archive-state authenticity narrowly but explicitly

The archive-state descriptor should bind at least:

- `archiveId`
- its own schema/version/canonicalization identity
- the ciphertext anchor (`qencHash`, `containerId`, and related stable binding details)
- `cryptoProfileId`
- nonce/AAD semantics
- `authPolicyCommitment`
- optional lineage material such as `parentStateId`, if Phase 0 freezes that choice

It should not bind:

- `shareCommitments[]`
- `shardBodyHashes[]`
- `cohortId`
- concrete custodial layout or distribution metadata

### 6.4 Represent source authenticity as provenance, not as archive approval

Quantum Vault should plan for a first-class source-evidence object, but it should be framed as provenance support rather than as a prerequisite for same-state resharing.

Phase 1 implication:

- the lifecycle model should reserve a place for source evidence
- same-state resharing should not depend on having source evidence implemented

### 6.5 Make transition records maintenance records

Transition records should document events such as same-state resharing, reencryption, or future rewrap.

Recommended semantics:

- they record what maintenance event occurred
- they do not replace archive-approval signatures
- their signatures, when present, are maintenance/authorization/witness signatures
- verifiers MUST NOT treat them as proof that an auditor approved the archive content

### 6.6 Prefer indirect `qenc` authenticity inside QV

The default QV path should be:

`archive-state signature -> archive-state descriptor -> qencHash/containerId -> qenc bytes`

Direct `.qenc` signatures are optional future support, not the main architectural path.

### 6.7 Bridge from the current implementation to explicit cohort identity

The current implementation already has an implicit notion of "these shards belong together" during restore, but it is not expressed as a first-class lifecycle object.

Today, restore groups candidates using the manifest/bundle digest pairing as an implicit cohort key. In practice this behaves like a composite archive-state-plus-distribution selector.

Recommended successor strengthening:

- carry an explicit `cohortId` in shard metadata
- bind it to an explicit cohort-binding object
- keep `stateId` separate from `cohortId`

This is not just a rename. It makes same-state resharing auditable and explicit:

- `stateId` says "same archive state"
- `cohortId` says "this specific shard-distribution cohort for that state"

That is a cleaner and more fail-closed model than continuing to overload manifest/bundle digest pairing as an implicit cohort selector.

## 7. Availability Maintenance, Compromise Response, Policy Change, And Migration

Status: Recommended operational separation

These event classes should not be merged in the docs:

| Event class | Primary problem | Preferred response | Same state? |
| --- | --- | --- | --- |
| Availability maintenance | custodians lost, rotated, or threshold margin eroded | same-state resharing | Yes |
| Compromise response | old quorum material may have leaked | new cryptographic state, at minimum reencryption | No |
| Policy change | archive approval semantics changed | new archive state and new archive-approval signatures | No |
| Migration / reencryption | ciphertext or crypto profile changes | new archive state plus continuity records | No |
| Future rewrap | outer confidentiality envelope rotates while inner content stays stable | future branch only, depends on envelope-DEK redesign | No |

### 7.1 Resharing does not strongly revoke old shares

This point needs especially careful wording.

Same-state resharing:

- creates a fresh cohort with fresh share randomness
- prevents old and new shares from being mixed into one valid cohort
- improves forward availability and future custodial posture

But same-state resharing does **not** guarantee that old shares are cryptographically useless in the strong confidentiality sense.

If an adversary already obtained enough shares from the old cohort to reconstruct the old underlying secret, resharing does not undo that exposure. Old shares may also remain dangerous if custodians fail to destroy them and an adversary later accumulates enough of that old cohort.

### 7.2 Suggested availability trigger

The current churn guidance remains useful if interpreted as cohort-level operational guidance:

```text
safety_margin = ceil((n - t) / 2)
reshare_trigger: available_honest_custodians < t + safety_margin
```

This is an operational trigger for the current cohort, not part of archive-state authenticity.

Worked examples:

- `(6, 4)` gives `safety_margin = ceil((6 - 4) / 2) = 1`, so the trigger is `available < 5`. In practice, losing two custodians means the cohort is down to the threshold plus a one-loss margin and should be reshared.
- `(8, 5)` gives `safety_margin = ceil((8 - 5) / 2) = 2`, so the trigger is `available < 7`. Losing two custodians already consumes the whole extra margin.
- `(10, 6)` gives `safety_margin = ceil((10 - 6) / 2) = 2`, so the trigger is `available < 8`.

What the margin is protecting:

- it is not a proof of security
- it is operational headroom so the resharing ceremony is not started only when the cohort is already one additional loss away from irrecoverability
- in other words, it is intended to tolerate one more loss during the ceremony window, not merely losses before the ceremony starts

### 7.3 Cross-cohort mixing

Cross-cohort share mixing does not help an attacker reconstruct a valid cohort because each cohort is generated independently.

That property is useful, but it is weaker than saying resharing "invalidates" old shares outright. The old cohort remains its own confidentiality surface until enough of it is destroyed or otherwise known unavailable.

### 7.4 Threat model / adversary operations

The lifecycle design should stay aligned with `docs/security-model.md`, especially its current adversary assumptions around passive capture, active tampering, long-horizon storage, and residual browser/runtime risk.

Byzantine-fault and distributed-systems literature is useful vocabulary for **custodian misbehavior and churn modeling**; Quantum Vault does not implement a Byzantine agreement protocol, but the distinction between benign loss, rotation, and hostile behavior remains operationally important.

Collecting shares over time:

- fewer than `t` shares from one cohort reveal no information about the secret under Shamir's model
- collecting shares across different cohorts does not let the adversary mix them into one valid reconstruction set, because the cohorts are independently generated
- however, if the adversary accumulates `t` or more shares from a single cohort before resharing or destruction, the secret for that cohort is compromised

Tampering path:

- shard tampering is detected first by cohort consistency checks
- then by shard-body hashes for the encoded shard body
- then by share commitments for the raw threshold-share material before reconstruction

This is important operationally. A bad shard should fail closed and reduce the usable cohort, not produce a silent wrong reconstruction.

Residual risk:

- if `>= t` shares from a predecessor cohort leak before resharing completes, same-state resharing does not repair that exposure
- if the host environment is compromised during restore or resharing, the browser implementation cannot fully defeat that adversary

### 7.5 Migration and crypto-agility context

NIST IR 8547 is useful here as migration-trigger framing, not as a claim that Quantum Vault already implements an IR-8547-complete migration program.

Useful planning posture:

- migrate before confidence in the active profile erodes, not only after public failure
- treat algorithm diversity as a future option, not a present commitment
- record migration continuity explicitly once lifecycle transition records exist

Optional future directions, not commitments:

- alternative or diversified KEM families such as HQC
- hybrid KEM constructions during transition periods
- signature diversity such as SLH-DSA alongside existing PQ approval paths

Why `rewrap` is still blocked today:

```text
Current:
  ML-KEM -> shared secret -> KMAC -> Kenc -> AES-GCM(payload)

Future rewrap-capable direction:
  DEK (random) -> AES-GCM(payload)                 [inner stable layer]
  ML-KEM -> shared secret -> KMAC -> Kwrap -> wrap(DEK)  [outer replaceable layer]
```

Until such a two-layer envelope exists, migration that changes confidentiality state means reencryption, not `rewrap`.

## 8. Evidence & Time

Status: Current scope vs future direction

### 8.1 Current OTS posture and Q-Day framing

For long-lived archives it is useful to think in three times:

- archive creation time
- `Q-Day`, when large-scale practical attacks against classical public-key signatures become realistic
- later verification time, potentially years or decades after both

Current QV posture:

- detached signatures are the authenticity object
- `.ots` evidence is linked to detached signature bytes
- OTS therefore currently says, at most, "these detached signature bytes existed before some witness-observed time"

Implication for signature families:

- if the detached signature is PQ and the OTS proof predates `Q-Day`, the verifier has both a still-meaningful signature family and evidence that the signature existed before that time
- if the detached signature is classical-only, the OTS proof can still preserve historical timing value, but it does not make the classical signature cryptographically future-proof after `Q-Day`

### 8.2 What current OTS does and does not prove

Current OTS use does prove:

- detached signature bytes existed before a witness-observed time
- those signature bytes can be linked to the archive state if the detached signature verifies against the archive-state descriptor

Current OTS use does **not** prove:

- that the whole bundle existed in exactly its later form
- that the source plaintext was reviewed
- that signer pinning or archive policy was satisfied
- that a renewal-capable archival evidence chain already exists

This is consistent with the current `trust-and-policy.md` posture: evidence is supplementary and must not be misread as a substitute for signature policy.

### 8.3 Standards context, not current implementation

RFC 3161 is relevant as timestamping context.
RFC 4998 is relevant as evidence-renewal context.

Neither should be presented as a current QV implementation claim here.

Honest current statement:

- Quantum Vault currently interoperates with OTS as a detached-signature witness layer
- Quantum Vault does not currently implement RFC 4998-style renewable evidence chains
- any future renewal design would need first-class evidence-record objects, successor-witness strategy, and explicit renewal timing rules

## 9. Alternatives Considered

Status: Alternatives retained for architectural memory

### 9.1 Option 1 — `n/k/t/codecId` are state-level

Model:

- concrete sharding parameters remain inside the archive-state descriptor
- same-state resharing MUST NOT change them
- changing them creates a new state

Strengths:

- simple approval semantics
- threshold policy stays inside the signed state object

Weaknesses:

- too restrictive for operational resharing
- still leaves pressure to explain why some shard changes are same-state and others are not
- does not match the existing desire to let same-state resharing change concrete distribution parameters

### 9.2 Option 2 — `n/k/t/codecId` are cohort-level

Model:

- concrete sharding parameters move into the cohort binding
- same-state resharing MAY change them
- archive-state signatures survive because the archive-state descriptor is unchanged

Strengths:

- cleanest signature-survival story
- best match for the operational-maintenance framing

Weaknesses:

- operational security posture can change without changing the archive-state descriptor
- later governance semantics may need an additional signed operational-policy layer

### 9.3 Option 3 — split policy class from concrete cohort parameters

Model:

- archive state carries a signed sharding-policy class or allowed bounds
- each cohort carries concrete `n/k/t/codecId`
- same-state resharing may vary concrete values only inside the signed bounds

Why it remains interesting:

- preserves signature survival
- gives a place to sign operational limits

Why it is not the current recommendation:

- it adds another policy object before the simpler archive-state/cohort split is implemented
- it risks overdesign for a project that currently has no deployed users and no existing governance layer

This remains the most credible future refinement if QV later needs signed operational limits on resharing.

## 10. Future Research / Not In Current Scope

Status: Future work

The following branches are worth preserving, but they should not block the first lifecycle implementation wave:

### 10.1 Distributed resharing, PSS, and DPSS

Proactive Secret Sharing and Dynamic PSS remain future research only.

Useful reference points:

- Herzberg et al. (1995) for proactive share refresh
- Feldman (1987) and Pedersen (1991) for VSS building blocks
- later DPSS literature for committee-change assumptions and transcript complexity

Reasons:

- they require interactive custodian participation rather than inert shard files
- they assume online participants during protocol rounds
- they assume secure pairwise channels or a broadcast channel
- they introduce honest-participant and committee-overlap assumptions that do not match the current offline client-only model
- DPSS adds further committee-change assumptions, often requiring sufficient honest overlap in the predecessor committee
- PQ-secure verifiable distributed resharing remains a research-heavy area

Related note:

- Feldman/Pedersen-style verifiability may still be worth studying as a separate integrity enhancement for initial split, but not as a Phase 1 lifecycle dependency

### 10.2 Merkle cohort commitments

Flat `shareCommitments[]` and `shardBodyHashes[]` are sufficient at current scale.
Merkleized cohort proofs remain an optional later optimization.

### 10.3 RFC 4998-style evidence renewal

Evidence renewal is important for long-term archives, but it is not already implemented.

Current baseline:

- OTS evidence is supplementary and signature-byte-targeted

Future direction:

- first-class renewable evidence records that can chain across decades

### 10.4 Envelope-DEK and future rewrap

`rewrap` is architecture-blocked until QV adopts a wrapped-DEK design.
Until then, cryptographic compromise response means reencryption, not rewrap.

### 10.5 Richer source-evidence claims

Possible later additions:

- reviewer role metadata
- chain-of-custody annotations
- normalized references to external signature containers
- privacy-preserving or partially redacted source descriptors

## 11. Standards Reading Map

Status: Reading map for specific design questions

| Standard / source | Architectural question it informs | Why it matters here |
| --- | --- | --- |
| RFC 8785 | What exact bytes should archive-state descriptors, transition records, and other signable JSON artifacts use? | Signable lifecycle objects should reuse the Stage A signable canonicalization discipline unless byte rules truly change |
| RFC 7493 and RFC 8259 | What JSON edge cases must lifecycle JSON reject before canonicalization? | Successor lifecycle artifacts should inherit the same fail-closed JSON discipline as the current signable manifest family |
| JSON Schema draft 2020-12 | How should lifecycle artifacts express closed grammar and versioned evolution? | Archive-state, cohort, transition, and source-evidence objects need their own closed schemas rather than ad hoc extensions |
| RFC 2119 and RFC 8174 | Where should lifecycle docs use normative terms? | Useful for freezing fail-closed verification behavior and distinguishing recommendations from binding Phase 1 rules |
| RFC 5116 and NIST SP 800-38D | Which ciphertext semantics belong in the archive-state descriptor? | AEAD interpretation depends on nonce/AAD semantics; those semantics belong with the long-lived ciphertext-binding state, not with cohort metadata |
| FIPS 202 | Which digest-family assumptions back `archiveId`-adjacent identifiers, `stateId`, `cohortId`, and commitment hashes? | Keeps identifier and commitment choices aligned with current QV primitive families |
| FIPS 203 and NIST SP 800-185 | Which primitive choices matter for current QV state interpretation? | The current KEM/KDF stack shapes what a state means and what a migration would change |
| RFC 3161 | What timestamping model is relevant as standards context? | Useful as timestamp-token context, but not a claim that QV currently implements RFC 3161 flows |
| ISO 14721 (OAIS) and ISO 16363 | Why separate archive identity, state history, provenance, and fixity surfaces? | Long-term archival framing needs durable identifiers, preservation events, provenance records, and fixity evidence with clear scope |
| RFC 4998 | How might later evidence renewal work without changing the present implementation story? | Useful only as future-direction context for evidence renewal; not evidence that QV already implements renewable evidence records |
| NIST IR 8547 | How should QV think about when migration planning becomes urgent? | Useful as migration-trigger framing for PQ timelines and long-horizon risk, not as a compliance claim |

## 12. Key Insight

The old split-time unified manifest created a specific failure mechanism:

- shard-distribution fields sat inside the signable object
- resharing changed those fields
- canonical manifest bytes changed
- `manifestDigest` changed
- detached signatures and OTS linkage tied to those bytes no longer carried forward cleanly

The successor split fixes that by separating:

- archive-state approval, which should survive same-state resharing
- cohort/distribution material, which is operationally replaceable

That separation is the key lifecycle design move. It is what turns resharing from a signature-breaking manifest mutation into a maintenance event on a stable archive state.

See also `resharing-design.md` (Motivation) for the same failure mode in design-doc form.

## 13. Sources And Cross-links

Status: Consolidated bibliography appendix

Archival identity and continuity:

- ISO 14721 (OAIS)
- ISO 16363
- `docs/long-term-archive.md`

Threshold, churn, and threat framing:

- Shamir (1979)
- Byzantine fault-tolerance / distributed fault-model literature as general churn-model context
- `docs/security-model.md`

Distributed resharing and verifiability:

- Herzberg et al. (1995) on proactive secret sharing
- Feldman (1987)
- Pedersen (1991)
- later DPSS / MPC literature as future research context

Evidence and time:

- RFC 3161
- RFC 4998
- OpenTimestamps project documentation
- `docs/trust-and-policy.md`
- `docs/long-term-archive.md`

Migration and crypto agility:

- NIST IR 8547 as migration-trigger framing
- FIPS 202
- FIPS 203
- NIST SP 800-185
- `docs/long-term-archive.md`

Current-format and successor-design cross-links:

- `docs/format-spec.md`
- `docs/security-model.md`
- `docs/trust-and-policy.md`
- `docs/process/roadmap/lifecycle/resharing-design.md`
