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
It is also the owner document for repeated trust semantics around self-verified `.qsig` handling and deployment-local authority boundaries.

Division of labor:

- `format-spec.md` defines how signatures, pins, timestamps, lifecycle objects, and shards are represented and processed
- `trust-and-policy.md` defines what those processed results mean for policy evaluation and restore authorization

## Scope

This document defines the current semantics of:

- detached signatures and signer identity material
- archive authenticity policy
- proof counting and strong-PQ evaluation
- bundled-key cryptographic verification and independently supplied signer pinning
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
- archive-policy counting by unique verified signer identity, with detached proof identity used to detect duplicate encodings/proofs
- separate status channels for cryptographic archive-approval verification, policy authorization, maintenance signatures, source-evidence signatures, OTS evidence, bundled-key verification, and external signer pinning
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
   A verified signature is linked to expected signer identity material supplied independently by the restore operator. Signer material inside the mutable lifecycle bundle is not a pin or trust anchor.

4. `archive policy satisfied`
   The archive's declared authenticity policy is satisfied by the available verified archive-approval signatures that count toward policy.

5. `maintenance signature verified`
   At least one detached maintenance signature verifies over a declared transition record.

6. `source-evidence signature verified`
   At least one detached source-evidence signature verifies over a declared source-evidence object.

7. `OTS evidence linked`
   At least one OpenTimestamps proof linked correctly to detached signature bytes.

These states MUST remain distinct in code, logs, UI, and documentation.
FIPS 204 and FIPS 205 describe digital signatures as evidence about signed bytes, but signer identity, organizational authority, and long-term time evidence require additional context beyond bare cryptographic validity. The current Quantum Vault status model makes those boundaries explicit instead of flattening them into one generic "trusted" result.

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
- `archiveApprovalCryptographicallyVerified`
- `strongPqArchiveApprovalCryptographicallyVerified`
- `maintenanceSignatureVerified`
- `sourceEvidenceSignatureVerified`
- `otsEvidenceLinked`
- `signerPinned`
- `bundledKeyVerified`
- `externallyPinned`
- `authorizedForPolicy`
- `policySatisfied`

`bundlePinned` remains a deprecated compatibility field and MUST be `false`. `userPinned` and `signerPinned` remain compatibility aliases for `externallyPinned`; unlike their former combined semantics, they never become true from lifecycle-bundle material.

## 3. Current role model and authority boundary

Quantum Vault encodes artifact verification and restore-policy behavior, not a complete institutional workflow.
The current role model therefore distinguishes:

- roles that are directly reflected in archive creation, attachment, restore, or verification behavior
- operational roles that matter for provenance or stewardship but are not yet first-class trust objects

Deployment roles are intentionally deployment-local. This specification does not create a global Quantum Vault signer registry, a project-issued trust root, or an "official operator" whose statements become authoritative for every archive. Institutions using Quantum Vault must define their own approval, custody, and renewal roles; the current implementation evaluates the artifacts those local roles produce, but it does not elevate the project itself into an enduring authority.

| Role | Current meaning | What the implementation knows directly |
| --- | --- | --- |
| Archive creator | Party that creates the archive, chooses split parameters, and selects `authPolicy` at split time | The chosen policy and split parameters are represented in the archive-state descriptor, cohort binding, and lifecycle bundle |
| Signer | Party producing detached signatures over archive-state, transition-record, or source-evidence bytes | The verifier can determine that a signer key signed a specific canonical target |
| Custodian | Holder of one or more `.qcont` shards or related detached artifacts | Shard custody is operational; custodian identity is not a first-class policy object |
| Restore operator | Party coordinating restore and supplying optional lifecycle bundles, signatures, pins, or timestamps | Restore input selection and user pinning are directly reflected in restore behavior |
| Verifier / relying party | Party evaluating integrity, signature validity, pinning, OTS linkage, and policy outcome | This role is directly reflected in current verify and restore behavior |
| Policy maintainer | Party defining shipped defaults and the current strong-PQ suite registry | Product defaults and the strong-PQ registry are reflected in the current codebase and docs, but this role is not a deployment-wide cryptographic trust root |

Current boundary to preserve:

- Quantum Vault can enforce that artifacts are structurally valid, signatures verify, pins match or fail, and archive policy is or is not satisfied
- Quantum Vault cannot, by itself, prove that a signer was organizationally authorized to approve plaintext, migration, custody transfer, or governance actions
- Quantum Vault does not require a QV-run server, corporation, or project operator to define archive-policy meaning; deployments choose their own signer material, approval roles, and external trust process

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
| `any-signature` | `minValidSignatures` cryptographically valid archive-approval signatures whose signers match independent external pins | No | Yes |
| `strong-pq-signature` | The same externally pinned threshold, including at least one strong-PQ archive-approval signature | No | No |

### 5.2 Current defaults

Current shipped defaults:

- Lite mode default: `integrity-only`
- Pro mode default: `strong-pq-signature`
- builder fallback MUST NOT silently weaken the Pro default

### 5.3 What policy does and does not prove

Current policy semantics:

- `integrity-only` allows recovery but does not provide signer-authenticated archive approval
- `any-signature` requires at least one cryptographically valid archive-approval signature matched by an independently supplied signer pin, but does not require a PQ suite specifically
- `strong-pq-signature` requires at least one externally pinned, cryptographically valid strong-PQ archive-approval signature

These meanings are intentionally narrow. Restore authorization is derived from explicit archive-policy rules over archive-approval signatures; auxiliary provenance material may improve reporting, but it does not silently change what the policy itself requires.

Current policy non-claims:

- policy satisfaction implies that each counted signer matched an independently supplied pin; it does not imply organizational authority beyond that operator-supplied expectation
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
| Signature-required recovery profile | `level = any-signature`, `minValidSignatures = 1` | Distributed storage where unsigned restore must fail, but Ed25519 interoperability is acceptable | Restore blocks unless at least one valid archive-approval signature verifies and matches an external signer pin |
| Auditor-led archival profile | `level = strong-pq-signature`, `minValidSignatures = 1` | Verified data where long-lived archive approval matters | Restore blocks unless at least one valid strong-PQ archive-approval signature matches an external signer pin |
| Multi-approver archival profile | `level = strong-pq-signature`, `minValidSignatures > 1` | Dual-control or committee-style archival approval | Restore blocks unless the externally pinned signer threshold is met and at least one counted signature is strong PQ |

### 5.5 Current hard boundary between lifecycle-bundle updates and state changes

The following MUST remain distinct:

- adding or replacing bundled signatures, bundled signer material, timestamps, transition records, or source-evidence objects is a lifecycle-bundle update and MUST NOT mutate canonical archive-state or cohort-binding bytes
- changing `authPolicy.level` or `authPolicy.minValidSignatures` changes restore-relevant semantics and therefore changes `authPolicyCommitment`
- a change to `authPolicyCommitment` requires a new archive-state descriptor and new archive-approval signatures over the new canonical archive-state bytes

## 6. Signature evaluation and counting semantics

### 6.1 Policy satisfaction rule

An archive satisfies authenticity policy if:

- at least `minValidSignatures` unique archive-approval signers have cryptographically valid signatures over the exact canonical archive-state descriptor bytes and match independently supplied signer pins
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

All three target NIST security category 5 (roughly equivalent to a 256-bit symmetric reference level). `mldsa-87` is the largest ML-DSA parameter set, as defined in FIPS 204 §4. `slhdsa-shake-256s` and `slhdsa-shake-256f` are the SHAKE-256-instantiated SLH-DSA parameter sets at the highest security level, as defined in FIPS 205 §10. The `s` variant (`256s`) produces smaller signatures at the cost of slower signing; the `f` variant (`256f`) produces larger signatures with faster signing. Both SLH-DSA variants are deliberately included to provide algorithmic-foundation diversity: SLH-DSA's security rests on hash-function assumptions rather than on the module-lattice assumptions underlying ML-DSA, so the two families are not simultaneously broken by the same cryptanalytic advance.

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

- `minValidSignatures` counts unique, externally pinned signer identities within the archive-approval family; multiple proofs from one signer count once
- QSIG proof identity is derived from signed TBS fields, signing context, and signature bytes, excluding unauthenticated display metadata
- semantically equivalent Stellar proofs are deduplicated using decoded signature/XDR bytes even if JSON serialization or base64 spelling differs
- invalid extra signatures are reported but ignored for archive-policy counting
- self-verified PQ signatures that verified only with the key embedded in the `.qsig` itself are ignored for policy counting
- signatures verified by signer material found only in the mutable lifecycle bundle remain cryptographically visible but are ignored for policy counting
- only restore-time `.pqpk` input or a restore-time expected Stellar signer can make a signature policy-eligible in the current implementation
- `strong-pq-signature` requires at least one externally pinned, policy-eligible strong-PQ archive-approval signature in addition to `minValidSignatures`

This is a trust-boundary rule, not a weaker verifier. Embedded and bundled keys can establish cryptographic consistency, but an attacker who can rewrite the mutable lifecycle bundle can replace both a signature and its bundled key. A bundle therefore cannot bootstrap its own authority.

## 7. Signer identity and pinning semantics

An independently pinned signer identity is the current authorization input for signature-required policy.
A matching pin does not by itself prove organizational authority, and policy evaluation remains a separate threshold-and-suite decision.

### 7.1 Current verification and pin sources

Current non-trust verification source:

- `bundledKeyVerified`: a signature verified against signer material referenced from the same mutable lifecycle bundle. This proves only internal cryptographic consistency.

Current external pin sources are:

- restore-time `.pqpk`
- restore-time expected Stellar signer input
- `externallyPinned`, `authorizedForPolicy`, `userPinned`, and `signerPinned` become true only from one of those independent inputs

Lifecycle-bundle `attachments.publicKeys[]` entries referenced by `publicKeyRef` remain mandatory verification constraints when declared, but they are not pins and never authorize policy by themselves.

### 7.2 Current pinning rules

Current pinning rules are:

- a declared `publicKeyRef` is authoritative only for checking that bundle entry's internal signature/key linkage; it is not authoritative for trust
- a matching external pin is required before a signature can count for `any-signature` or `strong-pq-signature`
- lack of external pinning blocks signature-required policy even when bundled material verifies cryptographically
- valid signature and pinned signature are separate states and MUST stay separate
- if a bundled signature references bundled signer material via `publicKeyRef`, failure of that reference is a verification failure for that bundled signature, not merely an absence of pinning
- ambiguous user-supplied PQ pin matches fail closed
- mismatched expected Stellar signer input fails closed for that verification path

Current required distinct status fields:

- `archiveApprovalSignatureVerified`
- `archiveApprovalCryptographicallyVerified`
- `policySatisfied`
- `signerPinned`
- `bundledKeyVerified`
- `externallyPinned`
- `authorizedForPolicy`

It is forbidden to collapse these into one generic state such as `trusted`.

### 7.3 Current status vocabulary

Allowed current status terms include:

- `integrity verified`
- `archive approval signature verified cryptographically`
- `strong PQ signature verified cryptographically`
- `signature verified with bundled key; not a trust anchor`
- `self-verified signature ignored for archive policy`
- `archive policy satisfied`
- `external signer pin matched`
- `OTS evidence linked to signature`
- `OTS proof appears complete (heuristic)`
- `OTS proof incomplete or pending`
- `Timestamp evidence does not satisfy archive policy`

Terms that should not be used loosely:

- `trusted archive`
- `authenticated cohort`
- `bundle signer pinned`

### 7.4 Report and workflow migration

This change does not alter `QVqcont-7`, archive-state, cohort-binding, lifecycle-bundle, `.qsig`, `.sig`, or `.pqpk` bytes. It intentionally changes acceptance and report semantics:

- existing bundle-only signatures continue to report cryptographic validity through `ok`, `bundledKeyVerified`, `archiveApprovalCryptographicallyVerified`, and the `cryptographicallyValidArchiveApproval*` counters
- they no longer set policy-adjacent legacy fields or counters; `bundlePinned` and `bundlePinnedValidTotal` remain `false`/`0`, while `validArchiveApproval*`, `archiveApprovalSignatureVerified`, and `strongPqSignatureVerified` include only externally pinned approvals
- `externallyPinned`, `authorizedForPolicy`, and `policyEligibleArchiveApproval*` expose the current authorization decision explicitly
- operators migrating an existing signed archive must independently retain and supply the expected `.pqpk` file or Stellar signer address at verify/restore time
- there is no normal-mode option to accept a bundle-carried key as trusted

Automation that previously relied on `bundlePinned`, `validArchiveApproval`, or `archiveApprovalSignatureVerified` for bundle-only evidence must migrate to the explicit cryptographic fields for inspection and must supply an external pin for policy authorization.

## 8. Timestamp and evidence interaction with policy

Current `.ots` semantics are deliberately limited:

- `.ots` is an evidence object
- it targets detached signature bytes, not lifecycle-bundle bytes
- linkage is performed by stamped `SHA-256(detachedSignatureBytes)`
- a bundled timestamp entry references a detached signature by `targetRef`

Current policy rule:

- timestamp evidence does not satisfy archive policy

Current handling rules:

- OTS may be bundled or supplied externally
- if multiple OTS proofs target the same detached signature, reporting may prefer one apparently complete proof
- current `appears complete` / `completeProof` labels are heuristic reporting fields derived from proof-name keywords first and proof size only as a fallback, not a cryptographic guarantee that a full external attestation chain was validated; exact acceptance, linkage, deduplication, and ambiguity rules are owned by [`appendices/external-artifacts.md#5-opentimestamps-linkage-and-completion-reporting`](appendices/external-artifacts.md#5-opentimestamps-linkage-and-completion-reporting)
- attach fails closed on unrelated or ambiguous `.ots` inputs
- restore reports bad or unresolved OTS linkage on the timestamp-evidence channel and does not let OTS alone satisfy archive policy

This preserves the current policy boundary: OTS can strengthen evidence reporting and future archival interpretation, but it does not upgrade an otherwise unsatisfied archive-approval signature policy.

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
- exposes archive-approval, maintenance, and source-evidence attach channels
- imports detached signatures (`.qsig`, `.sig`), `.pqpk` bundle verification keys, and `.ots` proofs for the selected channel; imported keys are not trust pins
- validates OTS target linkage fail closed during import
- imports public keys and signer identifiers
- writes an updated lifecycle bundle
- may rewrite embedded lifecycle bundles across a full shard cohort
- MUST NOT mutate canonical archive-state or cohort-binding bytes

Current attach channel targets:

| Attach channel | Required target material | Bundle destination | Restore-policy role |
| --- | --- | --- | --- |
| `archive-approval` | Selected canonical archive-state descriptor, either embedded in shards/bundle or provided as `*.archive-state.json` | `attachments.archiveApprovalSignatures[]` | Counts toward `any-signature` and `strong-pq-signature` only when valid, policy-compatible, and matched by an independent restore-time signer pin |
| `maintenance` | Selected lifecycle bundle plus the matching canonical `transition-record.json` already represented in that bundle | `attachments.maintenanceSignatures[]` | Reported separately; never counted toward archive policy |
| `source-evidence` | Canonical `source-evidence.json`; Attach adds the source-evidence object to the lifecycle bundle if needed | `sourceEvidence[]` and `attachments.sourceEvidenceSignatures[]` | Reported separately; never counted toward archive policy |

Target-binding expectations:

- archive-approval signatures bind `targetType = archive-state`, `targetRef = state:{stateId}`, and the SHA3-512 digest of the canonical archive-state descriptor
- maintenance signatures bind `targetType = transition-record`, `targetRef = transition:sha3-512:{transitionRecordDigest}`, and the SHA3-512 digest of the canonical transition record
- source-evidence signatures bind `targetType = source-evidence`, `targetRef = source-evidence:sha3-512:{sourceEvidenceDigest}`, and the SHA3-512 digest of the canonical source-evidence object
- `.pqpk` bytes may be carried in a bundle for cryptographic linkage or supplied independently at restore; only the independently supplied form is a signer pin and policy authorization input
- `.ots` files target detached signature bytes by `SHA-256(signatureBytes)`, not archive-state, transition-record, source-evidence, or lifecycle-bundle bytes; attach fails closed when a proof matches zero or multiple known detached signatures

### 9.3 Restore evaluation

Current restore policy evaluation occurs after structural and reconstruction checks.

Restore decision logic:

- `integrity-only`: allow restore if structural and reconstruction integrity holds
- `any-signature`: allow restore only if at least `minValidSignatures` archive-approval signatures verify over canonical archive-state bytes and their unique signers match external pins
- `strong-pq-signature`: allow restore only if that externally pinned threshold is met and at least one counted signature is strong PQ

Current ambiguity rule:

- restore fails closed by default when ambiguity remains in `archiveId`, `stateId`, `cohortId`, or embedded lifecycle-bundle digest after explicit filtering
- if an operator explicitly selects a cohort or lifecycle-bundle variant in an otherwise ambiguous case, restore may proceed, but the result MUST be reported as an explicit operator choice with warning rather than as an automatic winner selection

Current pinning consequence:

- external pinning is required for signature-required archive-policy counting
- bundled-key verification remains a separate cryptographic inspection result

Current restore-time OTS consequence:

- malformed, unresolved, or badly linked OTS evidence is reported as timestamp-evidence warning material and ignored for policy counting
- restore MUST NOT fail solely because OTS evidence did not link cleanly when archive policy is otherwise satisfied

## 10. Conflict and ambiguity handling

Current handling is:

- cryptographically valid but externally unpinned archive-approval signatures do not satisfy signature-required policy
- invalid extra signatures do not count if another signature satisfies policy
- self-verified PQ signatures do not count toward trust or policy
- self-verified PQ signatures should be reported as cryptographically valid but ignored for archive policy, never as trusted or approved
- no satisfying archive-approval signature blocks restore for `any-signature` and `strong-pq-signature`
- bundled-key verification and external pinning are tracked separately; only the latter authorizes policy
- timestamp evidence does not upgrade an otherwise unsatisfied signature policy
- malformed or ambiguously linked evidence is rejected rather than silently tolerated
- Quantum Vault does not auto-select among ambiguous cohorts or lifecycle-bundle variants

For `integrity-only`, absence of an external signer pin is non-blocking. For `any-signature` and `strong-pq-signature`, it is a policy failure by design.

Current restore MUST NOT fail solely because:

- OTS evidence is absent
- a non-satisfying signature is present alongside a satisfying one

## 11. CLI policy gating

The CLI exposes policy decisions through exit codes and stable JSON fields so automation can fail closed without scraping human text.

CLI policy rules:

- `qv verify` exits `0` only when the effective archive policy is satisfied.
- `qv verify --required-policy-level <level>` compares the selected policy against a caller-required minimum and exits non-zero when the requested level is stricter than the archive's satisfied policy.
- `qv restore --required-policy-level <level>` applies the same caller-required minimum to dry-run and write mode; a weaker archive returns `wouldSucceed = false` in dry-run and write mode creates no outputs.
- `qv restore --dry-run --json` writes nothing and reports `wouldSucceed`; successful dry-runs include `outputs: null`.
- `qv restore` write mode exits non-zero and writes no recovered artifacts when `policy.satisfied !== true`.
- `--accept-policy-warnings` does not override `policy.satisfied === false`; it is only an operator acknowledgement channel for warnings when policy is otherwise satisfied.
- Policy failure is reported as `qvCode: "POLICY_NOT_SATISFIED"` with exit code `1`; ambiguity remains `AMBIGUOUS_INPUTS` with exit code `9`; lifecycle-bundle variant acknowledgement failures are reported as `RESTORE_LIFECYCLE_VARIANT_ACK_REQUIRED` with exit code `12`; quorum failure remains `QUORUM_UNREACHABLE` with exit code `7`; restored material integrity failure remains `RESTORED_INTEGRITY_FAILED` with exit code `11`.

The CLI therefore treats policy as a gate, not as advisory metadata.

## 12. Same-state resharing semantics

Same-state resharing reconstructs one predecessor successor cohort, preserves exact archive-state descriptor bytes, and emits a new cohort plus a required transition record.
It is a maintenance path, not an archive re-approval path.

Current same-state resharing rules:

- resharing does not produce a restore authorization decision
- resharing does not rerun archive policy as the user-facing Restore flow does
- preserved archive-approval signatures remain archive-approval evidence over the unchanged archive state
- new maintenance signatures over the transition record remain separate maintenance evidence and do not satisfy archive policy

## 13. Future coverage retained for this document

This document still needs future expansion in the following areas:

- richer signature semantic claim types
- a fuller crypto-policy object definition
- explicit trust-root models
- first-class migration, renewal, or external approval claim objects that span archive states
- institution-level deployment patterns and governance mechanisms beyond the current documentation-level expectations
