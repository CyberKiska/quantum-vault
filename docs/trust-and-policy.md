# Trust and policy

Status: Release Candidate
Type: Normative
Audience: archive creators, signers, custodians, restore operators, implementers of policy evaluation, auditors
Scope: current-state normative semantics for signatures, archive authenticity policy, proof counting, pinning, and restore authorization
Out of scope: byte-level encoding, complete threat model, long-term archive classes, full governance framework
Primary implementation sources: `src/core/crypto/qcont/restore.js`, `src/core/crypto/lifecycle/artifacts.js`, `src/core/crypto/auth/qsig.js`, `src/core/crypto/auth/stellar-sig.js`

## Role

This document defines what signatures, pinning, and policy outcomes mean in Quantum Vault today.
It is the semantic counterpart to [`format-spec.md`](format-spec.md).

Division of labor:

- `format-spec.md` defines how signatures, pins, timestamps, lifecycle objects, and shards are represented and processed
- `trust-and-policy.md` defines what those processed results mean for policy evaluation and restore authorization

## Scope

This document defines the current semantics of:

- detached signatures and signer identity material
- archive authenticity policy
- proof counting and strong-PQ evaluation
- bundled pinning and user-supplied pinning
- restore authorization and result reporting
- the separation among archive approval, maintenance signatures, source evidence, and OTS evidence

This document does not define byte-level encoding, the full threat model, long-term archive classes, or a complete governance framework.

## Normative status

This document is normative for the current semantics of detached signatures, pinning, archive authenticity policy, proof counting, and restore authorization.
Use it for compatibility-required meaning, not just explanatory prose.

Conformance:

- this document is normative for all conforming implementations of the current Quantum Vault policy and restore-authorization semantics
- an implementation is conformant to this version if and only if it satisfies all MUST-level requirements defined in the current normative sections of this document
- if an implementation deviates from this specification, it MUST explicitly document the deviation and MUST declare itself non-conformant to this version
- statements explicitly labeled as future or recommended direction are non-normative until they are promoted into the current sections of this file
- in case of ambiguity, this document MUST be interpreted conservatively and fail-closed

## Sources and references

Internal current-state grounding:

- `src/core/crypto/qcont/restore.js` for restore-time policy gating, proof counting, pinning, and reporting behavior
- `src/core/crypto/lifecycle/artifacts.js` for lifecycle bundle semantics, detached-signature target registry, and `publicKeyRef` compatibility rules
- `src/core/crypto/auth/qsig.js` and `src/core/crypto/auth/stellar-sig.js` for detached-signature verification behavior
- `src/core/crypto/auth/signature-identity.js` and `src/core/crypto/auth/signature-suites.js` for proof normalization, deduplication, and suite handling
- `src/core/crypto/auth/opentimestamps.js` for current evidence linkage and heuristic completeness reporting
- `src/core/features/lite-mode.js` and `src/core/features/qcont/build-ui.js` for current built-in policy defaults and user-facing guidance
- [`format-spec.md`](format-spec.md), [`security-model.md`](security-model.md), and [`glossary.md`](glossary.md) for format constraints, security invariants, and shared terminology

External references already used elsewhere in the repository:

- FIPS 204 for ML-DSA suite family context (parameter sets, security categories, normative algorithm identifiers)
- FIPS 205 for SLH-DSA suite family context (parameter sets, security categories, hash-based security basis)
- RFC 8032 for Ed25519 verification context
- SEP-0023 for Stellar address encoding context
- Trail of Bits, "The treachery of post-quantum signatures" (2023): engineering perspective on PQ signature operational constraints (large signature sizes, verification cost, protocol integration issues); relevant to understanding why PQ signature size and verification overhead are non-trivial considerations when designing the attach and verify workflows

## Current implementation surface

Implemented now:

- one supported shard wire family: `QVqcont-7`
- one archive-approval payload: canonical `quantum-vault-archive-state-descriptor/v1` bytes
- one mutable authenticity bundle: `QV-Lifecycle-Bundle` v1
- detached authenticity artifacts accepted by the shipped implementation: `.qsig`, `.sig`, `.pqpk`, and `.ots`
- archive authenticity policy levels `integrity-only`, `any-signature`, and `strong-pq-signature`
- archive-state-centric archive approval
- `QV-Lifecycle-Bundle` v1 attachment families and their distinct policy roles
- proof counting by unique detached proof identity
- separate status channels for archive approval, maintenance signatures, source-evidence signatures, OTS evidence, bundle pinning, and user pinning
- fail-closed restore when ambiguity remains in `archiveId`, `stateId`, `cohortId`, or embedded lifecycle-bundle digest; explicit operator selection is a warned override, not an automatic winner selection

Deferred roadmap:

- first-class policy-profile identifiers
- institution-level governance and change-control objects
- trust-root programs
- state-changing continuity or renewal authority semantics

## Future work and non-normative notes

Statements explicitly labeled as future or recommended direction are non-normative.
Likely future expansion areas include:

- first-class profile identifiers for distinct operating contexts
- institution-level governance and change-control mechanisms
- renewal and migration authority semantics
- tighter integration of long-term evidence lifecycle requirements with restore policy

## 1. Status and scope

This document currently defines:

- the distinction among integrity, signature validity, pinning, and policy satisfaction
- the current archive authenticity policy object and policy levels
- the meaning of archive-approval, maintenance, and source-evidence signatures
- proof-counting and strong-PQ evaluation rules
- pinning semantics and status vocabulary
- restore authorization consequences

This document does not currently define:

- archive classes for long-term preservation
- a full crypto-policy object
- institutional trust-root programs
- migration or renewal authority semantics beyond current attachment and restore behavior

## 2. Core distinctions and current model

Quantum Vault distinguishes the following states:

1. `integrity verified`
   Structural, digest, commitment, and reconstruction checks are internally consistent.

2. `archive approval signature verified`
   At least one detached archive-approval signature cryptographically verifies over the exact canonical archive-state descriptor bytes.

3. `signer identity pinned`
   A verified signature is linked to expected signer identity material supplied either by the lifecycle bundle or by the restore operator.

4. `archive policy satisfied`
   The archive's declared authenticity policy is satisfied by the available verified archive-approval signatures that count toward policy.

5. `maintenance signature verified`
   At least one detached maintenance signature verifies over a declared transition record.

6. `source-evidence signature verified`
   At least one detached source-evidence signature verifies over a declared source-evidence object.

7. `OTS evidence linked`
   At least one OpenTimestamps proof linked correctly to detached signature bytes.

These states MUST remain distinct in code, logs, UI, and documentation.

Current mandatory separation:

- integrity does not imply provenance
- archive-approval signature validity does not imply signer pinning
- signer pinning does not replace policy evaluation
- maintenance signatures do not satisfy archive policy
- source-evidence signatures do not satisfy archive policy
- OTS evidence does not satisfy archive policy

Current restore reporting uses distinct status fields including:

- `archiveApprovalSignatureVerified`
- `strongPqSignatureVerified`
- `maintenanceSignatureVerified`
- `sourceEvidenceSignatureVerified`
- `otsEvidenceLinked`
- `signerPinned`
- `bundlePinned`
- `userPinned`
- `policySatisfied`

## 3. Current role model and authority boundary

Quantum Vault encodes artifact verification and restore-policy behavior, not a complete institutional workflow.
The current role model therefore distinguishes:

- roles that are directly reflected in archive creation, attachment, restore, or verification behavior
- operational roles that matter for provenance or stewardship but are not yet first-class trust objects

| Role | Current meaning | What the implementation knows directly |
| --- | --- | --- |
| Archive creator | Party that creates the archive, chooses split parameters, and selects `authPolicy` at split time | The chosen policy and split parameters are represented in the archive-state descriptor, cohort binding, and lifecycle bundle |
| Signer | Party producing detached signatures over archive-state, transition-record, or source-evidence bytes | The verifier can determine that a signer key signed a specific canonical target |
| Custodian | Holder of one or more `.qcont` shards or related detached artifacts | Shard custody is operational; custodian identity is not a first-class policy object |
| Restore operator | Party coordinating restore and supplying optional lifecycle bundles, signatures, pins, or timestamps | Restore input selection and user pinning are directly reflected in restore behavior |
| Verifier / relying party | Party evaluating integrity, signature validity, pinning, OTS linkage, and policy outcome | This role is directly reflected in current verify and restore behavior |
| Policy maintainer | Party defining shipped defaults and the current strong-PQ suite registry | Product defaults and the strong-PQ registry are reflected in the current codebase and docs |

Current boundary to preserve:

- Quantum Vault can enforce that artifacts are structurally valid, signatures verify, pins match or fail, and archive policy is or is not satisfied
- Quantum Vault cannot, by itself, prove that a signer was organizationally authorized to approve plaintext, migration, custody transfer, or governance actions

Current authority boundary for lifecycle state-change events:

| Event | Current Quantum Vault enforcement | What remains external |
| --- | --- | --- |
| Create and split archive | Policy and split parameters are committed in the archive-state descriptor and lifecycle bundle | Who authorized the creation or the policy choice |
| Sign archive-state descriptor | Verification proves a signer key signed the canonical archive-state bytes under a supported suite | Whether the signer was organizationally authorized to approve the archive content |
| Attach signatures, signer material, or timestamps | Attach validates linkage and MUST NOT mutate canonical archive-state or cohort-binding bytes | Who authorized the attach operation |
| Store or distribute shards | Shard integrity and threshold reconstruction rules are enforced | Custodian identity and custody authorization |
| Restore archive | Integrity, signature verification, pinning semantics, and archive-policy gating are enforced | Who authorized the restore or what purpose it serves |
| Re-sign, renew evidence, rewrap, reencryption, custody transfer, or policy deprecation | No first-class authority object for any of these actions exists in the current format family; enforcement is external to Quantum Vault | Organizational authorization, migration rationale, and continuity records for all of these events |

The last row is intentional. Until the format family defines first-class continuity records or authority claim objects for state-changing lifecycle events, Quantum Vault cannot and does not enforce authorization for those events at the artifact level.

## 4. Meaning of signatures in the current implementation

Current Quantum Vault signature semantics are intentionally narrow:

- an `archive-approval` signature means a signer key signed the canonical archive-state descriptor bytes
- a `maintenance` signature means a signer key signed the canonical bytes of one declared transition record
- a `source-evidence` signature means a signer key signed the canonical bytes of one declared source-evidence object
- a signature does not, by itself, encode that the signer audited plaintext, approved archive class, authorized reencryption, or confirmed custody transfer

Current supported detached signature wrappers:

- Quantum Signer `.qsig`
- Stellar WebSigner `.sig`

### 4.1 Source-evidence v1 privacy design

`quantum-vault-source-evidence/v1` objects are intentionally digest-first.
The schema limits optional fields to `mediaType` and `externalSourceSignatureRefs`.
There are no first-class path, username, host, or free-form operator note fields in v1.
Privacy defaults are structural: sensitive fields are absent from the schema by design, not suppressed at runtime from a richer optional set.

This means:

- a source-evidence object records what was witnessed (a digest and optional media type) without embedding the originating path, operator identity, or workflow notes into the bundled artifact
- adding path, username, or operator note fields to a future source-evidence schema requires a new schema version, not a runtime configuration flag
- attach implementations MUST NOT extend source-evidence with fields outside the current `quantum-vault-source-evidence/v1` schema; additional context should travel in provenance records outside the artifact family until a successor schema version is defined

Current verification semantics:

- bundled detached signatures are verified against the exact canonical bytes for their declared `targetType`, `targetRef`, and `targetDigest`
- external signatures supplied at restore are interpreted as archive-approval signatures over the selected archive-state bytes
- wrapper-specific parsing, context handling, and normalized suite evaluation are part of signature validity
- if a bundled signature carries `publicKeyRef`, the referenced bundled signer material constrains safe verification for that bundled signature
- a bundled signature with a bad, incompatible, ambiguous, or non-verifying `publicKeyRef` binding is rejected rather than treated as merely unpinned

## 5. Archive authenticity policy object

Archive authenticity policy is committed by `authPolicyCommitment` in the archive-state descriptor and carried concretely in the lifecycle bundle as `authPolicy`.

Current object shape:

```json
{
  "authPolicy": {
    "level": "integrity-only | any-signature | strong-pq-signature",
    "minValidSignatures": 1
  }
}
```

### 5.1 Current policy levels

| Policy level | Current minimum requirement | Unsigned restore allowed | Ed25519-only signatures sufficient |
| --- | --- | --- | --- |
| `integrity-only` | No detached archive-approval signature required | Yes | Yes, but not required |
| `any-signature` | `minValidSignatures` valid archive-approval signatures | No | Yes |
| `strong-pq-signature` | `minValidSignatures` valid archive-approval signatures and at least one valid strong-PQ archive-approval signature | No | No |

### 5.2 Current defaults

Current shipped defaults:

- Lite mode default: `integrity-only`
- Pro mode default: `strong-pq-signature`
- builder fallback MUST NOT silently weaken the Pro default

### 5.3 What policy does and does not prove

Current policy semantics:

- `integrity-only` allows recovery but does not provide signer-authenticated archive approval
- `any-signature` requires at least one valid archive-approval signature but does not require a PQ suite specifically
- `strong-pq-signature` requires at least one valid strong-PQ archive-approval signature

Current policy non-claims:

- policy satisfaction does not imply signer pinning
- policy satisfaction does not imply timestamp evidence
- policy satisfaction does not imply maintenance approval
- policy satisfaction does not imply source-review approval
- policy satisfaction does not imply a broader organizational workflow

### 5.4 Recommended policy profiles

The profiles in this section are recommended operational profiles built from the implemented policy object.
They are descriptive guidance, not first-class on-wire `policyId` values.

| Recommended profile | Current policy object | Typical use | Current consequence |
| --- | --- | --- | --- |
| Personal recovery profile | `level = integrity-only`, `minValidSignatures = 1` | Personal or family archival storage where recoverability is primary and signer-authenticated provenance is optional | Restore is allowed if reconstruction integrity holds |
| Signature-required recovery profile | `level = any-signature`, `minValidSignatures = 1` | Distributed storage where unsigned restore must fail, but Ed25519 interoperability is acceptable | Restore blocks unless at least one valid archive-approval signature verifies over canonical archive-state bytes |
| Auditor-led archival profile | `level = strong-pq-signature`, `minValidSignatures = 1` | Verified data where long-lived archive approval matters | Restore blocks unless at least one valid strong-PQ archive-approval signature exists |
| Multi-approver archival profile | `level = strong-pq-signature`, `minValidSignatures > 1` | Dual-control or committee-style archival approval | Restore blocks unless the signature threshold is met and at least one valid strong-PQ archive-approval signature exists |

### 5.5 Current hard boundary between lifecycle-bundle updates and state changes

The following MUST remain distinct:

- adding or replacing bundled signatures, bundled signer material, timestamps, transition records, or source-evidence objects is a lifecycle-bundle update and MUST NOT mutate canonical archive-state or cohort-binding bytes
- changing `authPolicy.level` or `authPolicy.minValidSignatures` changes restore-relevant semantics and therefore changes `authPolicyCommitment`
- a change to `authPolicyCommitment` requires a new archive-state descriptor and new archive-approval signatures over the new canonical archive-state bytes

## 6. Signature evaluation and counting semantics

### 6.1 Policy satisfaction rule

An archive satisfies authenticity policy if:

- at least `minValidSignatures` archive-approval detached signatures are cryptographically valid over the exact canonical archive-state descriptor bytes
- at least one of those valid archive-approval signatures satisfies the policy level's suite requirement when `strong-pq-signature` is selected
- maintenance signatures and source-evidence signatures are not counted toward `minValidSignatures`

Current policy satisfaction is existential, not exclusive:

- `strong-pq-signature` requires at least one strong-PQ archive-approval signature
- extra Ed25519 or other supported signatures may coexist
- policy does not mean "only PQ signatures may be present"

### 6.2 Strong PQ suite registry

Current strong-PQ suites are:

- `mldsa-87`
- `slhdsa-shake-256s`
- `slhdsa-shake-256f`

All three target NIST security category 5 (roughly equivalent to a 256-bit symmetric reference level). `mldsa-87` is the largest ML-DSA parameter set, as defined in FIPS 204 §4. `slhdsa-shake-256s` and `slhdsa-shake-256f` are the SHAKE-256-instantiated SLH-DSA parameter sets at the highest security level, as defined in FIPS 205 §10. The `s` variant (`256s`) produces smaller signatures at the cost of slower signing; the `f` variant (`256f`) produces larger signatures with faster signing. Both SLH-DSA variants are deliberately included to provide algorithmic-foundation diversity: SLH-DSA's security rests on hash-function assumptions rather than on the module learning-with-errors problem underlying ML-DSA, so the two families are not simultaneously broken by the same cryptanalytic advance.

Lower ML-DSA or SLH-DSA parameter sets (e.g., `mldsa-44`, `mldsa-65`, `slhdsa-shake-128s`) are not included in the strong-PQ registry because they target lower NIST security categories. Their exclusion is an explicit registry decision, not a claim that those suites are broken.

Current evaluation rule:

- policy is evaluated against canonical suite identifiers after parsing and normalization
- broad family names such as `ML-DSA` or `SLH-DSA` are not sufficient by themselves; the exact parameter-set identifier must be present and recognized

### 6.3 Wrapper versus suite

Current wrapper distinction:

- `.qsig` and `.sig` are transport or encoding wrappers
- policy strength is determined by the normalized suite and verifier result, not by wrapper alone

### 6.4 Counting rules

Current counting rules are:

- `minValidSignatures` counts unique detached proof identities, not repeated verification results for the same proof
- semantically equivalent Stellar proofs are deduplicated even if JSON serialization differs
- invalid extra signatures are reported but ignored for archive-policy counting
- self-verified PQ signatures that verified only with the key embedded in the `.qsig` itself and matched neither bundled nor user-supplied signer material are ignored for trust and policy counting; "self-verified" means the signature was verified exclusively against the public key carried inside the `.qsig` binary wrapper, without corroboration from an externally-anchored identity source; this condition is excluded from policy satisfaction because it provides no binding to an identity established outside the artifact being evaluated
- `strong-pq-signature` requires at least one valid strong-PQ archive-approval signature in addition to `minValidSignatures`

## 7. Signer identity and pinning semantics

Pinned signer identity is an additional trust signal.
It is not the same thing as policy satisfaction.

### 7.1 Current pin sources

Current signer pin sources are:

- `bundlePinned`: a verified signature matched bundled signer material explicitly linked from the lifecycle bundle
- `userPinned`: signer identity material came from restore-time user input
- `signerPinned = bundlePinned || userPinned`

Current bundle pin sources include:

- lifecycle-bundle `attachments.publicKeys[]` entries referenced by `publicKeyRef`

Current user pin sources include:

- restore-time `.pqpk`
- restore-time expected Stellar signer input

### 7.2 Current pinning rules

Current pinning rules are:

- signer pinning is optional unless a specific verification path declares an authoritative `publicKeyRef`
- a matching pin strengthens provenance reporting
- lack of pinning does not by itself block restore if archive policy is satisfied
- valid signature and pinned signature are separate states and MUST stay separate
- if a bundled signature references bundled signer material via `publicKeyRef`, failure of that reference is a verification failure for that bundled signature, not merely an absence of pinning
- ambiguous user-supplied PQ pin matches fail closed
- mismatched expected Stellar signer input fails closed for that verification path

Current required distinct status fields:

- `archiveApprovalSignatureVerified`
- `policySatisfied`
- `signerPinned`
- `bundlePinned`
- `userPinned`

It is forbidden to collapse these into one generic state such as `trusted`.

### 7.3 Current status vocabulary

Allowed current status terms include:

- `integrity verified`
- `archive approval signature verified`
- `strong PQ signature verified`
- `archive policy satisfied`
- `bundle signer pinned`
- `user signer pinned`
- `OTS evidence linked to signature`
- `OTS proof appears complete`
- `OTS proof appears incomplete`

Terms that should not be used loosely:

- `trusted archive`
- `authenticated cohort`

## 8. Timestamp and evidence interaction with policy

Current `.ots` semantics are deliberately limited:

- `.ots` is an evidence object
- it targets detached signature bytes, not lifecycle-bundle bytes
- linkage is performed by stamped `SHA-256(detachedSignatureBytes)`
- a bundled timestamp entry references a detached signature by `targetRef`

Current policy rule:

- timestamps NEVER satisfy archive signature policy by themselves

Current handling rules:

- OTS may be bundled or supplied externally
- if multiple OTS proofs target the same detached signature, reporting may prefer one apparently complete proof
- current `appears complete` / `completeProof` labels are heuristic reporting fields derived from filename hints or proof size; they are not a cryptographic guarantee that a full external attestation chain was validated
- unrelated or ambiguous `.ots` inputs fail closed

## 9. Attach and restore policy lifecycle

### 9.1 Split stage

At split stage, the archive creator chooses:

- split parameters
- archive authenticity policy

Current outputs include:

- `QVqcont-7` shards
- an archive-state descriptor
- a lifecycle bundle
- a cohort binding for operator-facing workflows

The initial lifecycle bundle contains:

- the archive-state descriptor and its digest
- the current cohort binding and its digest
- the concrete `authPolicy`
- empty or initial attachment arrays

### 9.2 Attach stage

Current attach behavior:

- validates detached signatures against the correct canonical target bytes
- validates OTS target linkage
- imports public keys and signer identifiers
- writes an updated lifecycle bundle
- may rewrite embedded lifecycle bundles across a full shard cohort
- MUST NOT mutate canonical archive-state or cohort-binding bytes

### 9.3 Restore evaluation

Current restore policy evaluation occurs after structural and reconstruction checks.

Restore decision logic:

- `integrity-only`: allow restore if structural and reconstruction integrity holds
- `any-signature`: allow restore only if at least `minValidSignatures` archive-approval signatures verify over canonical archive-state bytes
- `strong-pq-signature`: allow restore only if the count threshold is met and at least one valid strong-PQ archive-approval signature is present

Current ambiguity rule:

- restore fails closed by default when ambiguity remains in `archiveId`, `stateId`, `cohortId`, or embedded lifecycle-bundle digest after explicit filtering
- if an operator explicitly selects a cohort or lifecycle-bundle variant in an otherwise ambiguous case, restore may proceed, but the result MUST be reported as an explicit operator choice with warning rather than as an automatic winner selection

Current pinning consequence:

- pinning affects provenance reporting
- pinning does not block restore by default once archive policy is satisfied

## 10. Conflict and ambiguity handling

Current handling is:

- valid but unpinned archive-approval signatures may still satisfy policy
- invalid extra signatures do not count if another signature satisfies policy
- self-verified PQ signatures do not count toward trust or policy
- no satisfying archive-approval signature blocks restore for `any-signature` and `strong-pq-signature`
- bundle pinning and user pinning are tracked separately and may both be true
- timestamp evidence does not upgrade an otherwise unsatisfied signature policy
- malformed or ambiguously linked evidence is rejected rather than silently tolerated
- Quantum Vault does not auto-select among ambiguous cohorts or lifecycle-bundle variants

Current restore MUST NOT fail solely because:

- no signer is pinned
- OTS evidence is absent
- a non-satisfying signature is present alongside a satisfying one

## 11. Same-state resharing semantics

Same-state resharing reconstructs one predecessor successor cohort, preserves exact archive-state descriptor bytes, and emits a new cohort plus a required transition record.
It is a maintenance path, not an archive re-approval path.

Current same-state resharing rules:

- resharing does not produce a restore authorization decision
- resharing does not rerun archive policy as the user-facing Restore flow does
- preserved archive-approval signatures remain archive-approval evidence over the unchanged archive state
- new maintenance signatures over the transition record remain separate maintenance evidence and do not satisfy archive policy

## 12. Future coverage retained for this document

This document still needs future expansion in the following areas:

- richer signature semantic claim types
- a fuller crypto-policy object definition
- explicit trust-root models
- first-class migration, renewal, or external approval claim objects that span archive states
- institution-level deployment patterns and governance mechanisms beyond the current documentation-level expectations
