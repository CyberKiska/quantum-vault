# Trust and policy

Status: Release Candidate
Type: Normative
Audience: archive creators, signers, custodians, restore operators, implementers of policy evaluation, auditors
Scope: current-state normative semantics for signatures, archive authenticity policy, proof counting, pinning, and restore authorization
Out of scope: byte-level encoding, complete threat model, long-term archive classes, full governance framework
Primary implementation sources: implementation code, `docs/format-spec.md`
Historical consolidation source: `process/IMPLEMENTATION-NOTES.md`

## Role

This document defines what signatures, pinning, and policy outcomes mean in Quantum Vault today.
It is the semantic counterpart to `format-spec.md`.

Quantum Vault currently supports **two coexisting format tracks** (see `format-spec.md` Scope):

- **Legacy track:** canonical manifest (`quantum-vault-archive-manifest/v3`), mutable `QV-Manifest-Bundle` v2, and `QVqcont-6` shards.
- **Successor lifecycle track:** archive-state descriptor, `QV-Lifecycle-Bundle` v1, and `QVqcont-7` shards.

Sections below apply to **both** tracks unless explicitly scoped to **legacy** or **successor** semantics.

Division of labor:

- `format-spec.md` defines how signatures, pins, timestamps, manifests, bundles, lifecycle objects, and shards are represented and processed
- `trust-and-policy.md` defines what those processed results mean for policy evaluation and restore authorization

## Scope

This document covers the current semantics of detached signatures, archive authenticity policy, proof counting, signer pinning, and restore authorization for **both** the legacy manifest-bundle model and the **successor lifecycle** model.

It does not define byte-level encoding, the full threat model, long-term archive classes, or a complete governance framework.

## Normative status

This document is normative for the current semantics of detached signatures, pinning, archive authenticity policy, proof counting, and restore authorization.
Use it for compatibility-required meaning, not just for explanatory prose.

Conformance:

- this document is normative for all conforming implementations of the current Quantum Vault policy and restore-authorization semantics
- an implementation is conformant to this version if and only if it satisfies all MUST-level requirements defined in the current normative sections of this document
- if an implementation deviates from this specification, it MUST explicitly document the deviation and MUST declare itself non-conformant to this version
- statements explicitly labeled as future or recommended direction are non-normative until they are promoted into the current sections of this file
- in case of ambiguity, this document MUST be interpreted conservatively and fail-closed

## Sources and references

Internal current-state grounding:

- `src/core/crypto/constants.js`, `src/core/crypto/qcont/build.js`, `src/core/features/lite-mode.js`, and `src/core/features/qcont/build-ui.js` for current built-in policy defaults and archive-policy object construction
- `src/core/crypto/auth/verify-signatures.js`, `src/core/crypto/auth/signature-identity.js`, and `src/core/crypto/auth/signature-suites.js` for proof normalization, deduplication, suite handling, and policy counting inputs
- `src/core/crypto/auth/qsig.js` and `src/core/crypto/auth/stellar-sig.js` for current detached-signature wrapper acceptance and verification behavior
- `src/core/crypto/auth/opentimestamps.js` for current evidence linkage and heuristic completeness reporting
- `src/core/crypto/qcont/restore.js` for restore-time policy gating and reporting behavior (legacy manifest-bundle path and **successor lifecycle** path)
- `src/core/crypto/lifecycle/artifacts.js` for successor lifecycle bundle semantics, detached-signature target registry, and `publicKeyRef` compatibility rules
- `docs/format-spec.md`, `docs/security-model.md`, and `docs/glossary.md` for format constraints, security invariants, and shared terminology

External references already used elsewhere in the repository:

- FIPS 204 for ML-DSA suite family context
- FIPS 205 for SLH-DSA suite family context
- RFC 8032 for Ed25519 verification context
- SEP-0023 for Stellar address encoding context
- OpenTimestamps project documentation for the current evidence ecosystem Quantum Vault interoperates with

## Current implementation status

Implemented now:

- current policy levels `integrity-only`, `any-signature`, and `strong-pq-signature` (for **both** legacy and successor bundles)
- **Successor lifecycle** artifacts: `QV-Lifecycle-Bundle` v1, archive-state descriptor signing, `QVqcont-7` shards, and restore-time evaluation described in **§11**
- current proof-counting and strong-PQ suite evaluation rules
- current bundle pinning and user pinning semantics (legacy `attachments.signatures`; successor `attachments.archiveApprovalSignatures` and related families per §11)
- current restore authorization behavior and status vocabulary
- current OTS evidence linkage and heuristic completeness reporting (detached signature bytes as targets; see §8 and §11)

Not yet first-class in the current implementation:

- first-class policy-profile identifiers or enforcement beyond the current built-in levels
- institution-level governance objects and change-control mechanisms for policy meaning
- institutional trust-root programs or repository-level authority models
- first-class migration, renewal, or external approval claim types

## Future work and non-normative notes

Statements explicitly labeled as future or recommended direction are non-normative.
Likely future expansion areas, but not current policy semantics, include:

- first-class profile identifiers for distinct archive classes or operating contexts
- institution-level governance and change-control mechanisms for policy evolution
- renewal and migration authority semantics
- tighter integration of long-term evidence lifecycle requirements with restore policy

## 1. Status and scope

This document currently defines:

- the distinction among integrity, signature validity, pinning, and policy satisfaction
- the current archive authenticity policy object (including how it applies to **legacy** manifests and **successor** archive-state descriptors)
- the meaning of `integrity-only`, `any-signature`, and `strong-pq-signature`
- current proof-counting and strong-PQ evaluation rules
- current bundle pinning and user pinning semantics
- **Successor lifecycle** policy semantics and attachment taxonomy (**§11**)
- current restore authorization consequences

This document does not currently define:

- archive classes for long-term preservation
- a full crypto-policy object
- institutional trust-root programs
- migration authority semantics beyond current attachment and restore behavior

Those remain future coverage and are preserved in the appendix.

## 2. Core distinctions and current model

Quantum Vault currently distinguishes four separate states:

1. `integrity verified`
   The reconstructed `.qenc`, shard body, and related commitments are internally consistent. For the **legacy** path, manifest digest, bundle digest, and embedded bundle agreement are part of integrity checks. For the **successor** path, archive-state, cohort-binding, and lifecycle-bundle digest checks apply as defined in `format-spec.md`.

2. `signature verified`
   At least one detached signature cryptographically verifies over the exact **signable** canonical bytes for that path: **legacy** path — canonical **manifest** bytes; **successor** path — for archive-approval signatures, canonical **archive-state descriptor** bytes (see §11).

3. `signer identity pinned`
   A verified signature is linked to expected signer identity material supplied either by the bundle or by the user.

4. `archive policy satisfied`
   The archive's declared authenticity policy is satisfied by the available verified signatures that **count toward policy** (legacy: `attachments.signatures`; successor: `attachments.archiveApprovalSignatures` only — see §11.1).

These states MUST remain distinct in code, logs, UI, and documentation.

Current mandatory separation:

- integrity does not imply provenance
- signature validity does not imply signer pinning
- signer pinning does not replace policy evaluation
- timestamps do not satisfy archive signature policy
- **successor:** maintenance and source-evidence detached signatures do not satisfy archive policy (§11)

## 3. Current role model and lifecycle authority

Quantum Vault's current implementation encodes artifact verification and restore-policy behavior, not a complete institutional workflow.
The role model below therefore distinguishes:

- roles that are directly reflected in current archive creation, attachment, restore, or verification behavior
- operational roles that matter for provenance or stewardship but are not yet first-class signed claim types or trust-root objects

### 3.1 Current role definitions

| Role | Current meaning | What the implementation knows directly |
| --- | --- | --- |
| Archive creator | Entity that creates the archive, chooses split parameters, and selects the archive authenticity policy during split | The chosen split parameters and committed `authPolicy` are represented in the current track's signable object and mutable bundle; creator identity is not first-class unless preserved through detached signatures or external records |
| Auditor / source verifier | Entity that verifies the source data before archiving and bears provenance responsibility for confirming "this is the data" | This role is operational today; Quantum Vault does not automatically distinguish "audited this data" from the narrower claim "signed the current signable archive description" |
| Signer | Entity that cryptographically signs the current signable archive description using supported detached signer tooling | The verifier can determine that a signer key signed the current signable archive description; broader semantic meaning remains external unless the workflow documents it |
| Custodian | Entity that stores one or more `.qcont` shards or related detached artifacts | Shard custody is operational; custodian identity is not encoded as a first-class trust object in the current format family |
| Restoration quorum | Operational set of custodians or participants able to supply enough consistent shards to meet the threshold required for restore | Threshold and shard consistency are enforced by the current format and restore logic, but quorum membership is not a first-class policy object |
| Restore operator | Entity coordinating restore, supplying shard cohorts and optional external signatures, pins, or timestamps | Restore input selection, pinning input, and policy evaluation are reflected in current restore behavior |
| Verifier / relying party | Entity evaluating integrity, signature validity, pinning, timestamp linkage, and policy outcome | This role is directly reflected in current verify/restore behavior and status reporting |
| Policy maintainer | Entity that defines shipped defaults and the current "strong PQ" suite registry used by policy evaluation | Product defaults and the strong-PQ suite registry are reflected in the current codebase and documentation |

Important current distinction:

- `Auditor / source verifier` is not the same role as the later `Verifier / relying party`
- the first role concerns pre-archive source-data responsibility
- the second role concerns later artifact verification and restore authorization

### 3.2 Current operational role patterns

The main operational pattern motivating this document is an auditor-led archival workflow:

1. an auditor or source verifier verifies the source data before archiving
2. the archive creator encrypts and shards the verified data with Quantum Vault
3. the signer signs the current signable archive description
4. custodians hold the resulting `.qcont` shards
5. a restoration quorum later supplies enough consistent shards for recovery
6. the restore operator reconstructs the archive and restore policy decides whether decryption may proceed

In the common case, the auditor and signer may be the same entity.
That is a valid and expected workflow, but the current implementation still distinguishes:

- cryptographic proof that a signer key signed the current signable archive description
- operational or provenance responsibility for having verified the source data before archiving

Current meaning in that workflow:

- integrity is established by the current structural checks, digest checks, commitments, and reconstruction checks
- authenticity or provenance is strengthened by detached signatures and optional pinning, not by hashes alone
- source-data verification performed before encrypt or split is operationally important, but it is not yet a first-class signed claim type in the Quantum Vault artifact family

Another current operational pattern is personal distributed archival storage:

- the archive creator, signer, and restore operator may all be the same person
- independent custodians still hold shards for recoverability
- `integrity-only` may be acceptable when recoverability matters more than signer-authenticated provenance
- when signer-authenticated provenance matters, `any-signature` or `strong-pq-signature` remain the relevant current policy levels

### 3.3 Current lifecycle authority boundaries

Current lifecycle authority is partly enforced by format and policy semantics, and partly external to the implementation.

| Action | Current authority model | What Quantum Vault enforces today |
| --- | --- | --- |
| Create and split archive | Archive creator chooses split parameters and `authPolicy` | The chosen policy is committed via `authPolicyCommitment` and carried in the current track's mutable bundle |
| Sign archive description | Signer signs the current signable archive description with supported detached tooling | Verification proves signature validity over the correct canonical bytes for the selected track |
| Attach signatures, signer material, or timestamps | Attach operator may bundle valid detached artifacts after archive creation | Attach validates linkage and MUST NOT mutate the current track's signable bytes |
| Store or distribute shards | Custodians hold shards under an external custody arrangement | Current format enforces shard integrity and threshold reconstruction rules, not custodian identity rules |
| Restore archive | Restore operator gathers a consistent shard cohort and any optional external artifacts | Restore enforces integrity, signature verification, pinning semantics, and archive-policy gating |
| Satisfy restoration quorum | Enough custodians or participants supply enough consistent shards to meet threshold | Threshold and cohort consistency are enforced; quorum membership itself is not a first-class signed or policy object |
| Re-sign, renew evidence, rewrap, reencryption, custody transfer, or deprecate policy | Any such authority is external unless and until the format family defines first-class approval or lifecycle claim objects | Current implementation has no first-class authority object for these actions |

Current boundary to preserve:

- Quantum Vault can enforce that artifacts are structurally valid, signatures verify, pins match, and archive policy is or is not satisfied
- Quantum Vault cannot, by itself, prove that a particular person was organizationally authorized to audit data, approve a migration, or authorize a custody transfer unless an external workflow records that meaning

## 4. Meaning of signatures in the current implementation

Current Quantum Vault semantics are intentionally narrow:

- **Legacy path:** a detached signature in the manifest-bundle model means a signer key signed the **canonical manifest bytes**
- **Successor path:** archive-approval detached signatures mean a signer key signed the **canonical archive-state descriptor** bytes (see §11)
- it does not, by itself, encode that the signer audited the plaintext, approved preservation class, authorized a migration, or confirmed custody transfer
- broader semantic claims may exist in an external workflow, but they are not currently first-class signed claim types in the Quantum Vault format family

Current supported detached signature wrappers:

- Quantum Signer `.qsig`
- Stellar WebSigner `.sig`

Current signing targets (path-dependent):

- **Legacy:** canonical **manifest** bytes only; never mutable bundle bytes; never detached timestamp artifacts
- **Successor:** canonical **archive-state descriptor** bytes for `archiveApprovalSignatures`; canonical **transition-record** bytes for `maintenanceSignatures`; canonical **source-evidence** object bytes for `sourceEvidenceSignatures`; mutable **lifecycle-bundle** bytes are never the archive-approval signable payload

Current verification semantics:

- **Legacy:** bundled and external detached signatures are verified against the exact canonical manifest bytes
- **Successor:** bundled detached signatures are verified against the exact canonical bytes for their declared `targetType` / `targetDigest` (see `format-spec.md` and §11)
- wrapper-specific parsing, context handling, and normalized suite evaluation are part of signature validity, not optional reporting details
- if a bundled signature carries `publicKeyRef`, the referenced bundled signer material constrains safe verification for that bundled signature
- a bundled signature with a bad, incompatible, or non-verifying `publicKeyRef` binding is rejected rather than treated as merely "unpinned"

## 5. Archive authenticity policy object

**Legacy path:** Archive authenticity policy is fixed at archive creation time, committed into the canonical manifest via `authPolicyCommitment`, and carried concretely in the manifest bundle as `authPolicy`.

**Successor path:** The same logical `authPolicy` object shape is carried inside `QV-Lifecycle-Bundle` v1. Policy is committed via `authPolicyCommitment` in the **archive-state descriptor** (not the manifest). Restore evaluates policy against **archive-approval** detached signatures only (§11).

The following object shape applies to **both** paths for the mutable `authPolicy` field:

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
| `integrity-only` | No detached signature required | Yes | Yes, but not required |
| `any-signature` | `minValidSignatures` valid detached signatures | No | Yes |
| `strong-pq-signature` | `minValidSignatures` valid detached signatures and at least one valid strong PQ detached signature | No | No |

### 5.2 Current defaults

Current shipped defaults:

- Lite mode default: `integrity-only`
- Pro mode default: `strong-pq-signature`
- builder fallback must not silently weaken the Pro default

### 5.3 What policy does and does not prove

Current policy semantics:

- `integrity-only` allows recovery but does not provide signer-authenticated provenance
- `any-signature` requires at least one valid detached signature but does not require a PQ signature
- `strong-pq-signature` requires at least one valid detached signature from the current strong-PQ registry

Current policy non-claims:

- policy satisfaction does not imply signer pinning
- policy satisfaction does not imply timestamp evidence
- policy satisfaction does not imply a broader organizational approval workflow

### 5.4 Recommended policy profiles

The profiles in this section are recommended operational profiles built from the current implemented policy object.
They are descriptive guidance for operators and documentation, not first-class `policyId` values or archive-class fields in the current format family.

| Recommended profile | Current policy object | Typical use | Current consequence |
| --- | --- | --- | --- |
| Personal recovery profile | `level = integrity-only`, `minValidSignatures = 1` | Personal or family archival storage where recoverability is primary and signer-authenticated provenance is optional | Restore is allowed if reconstruction integrity holds; detached signatures may still be attached later but are not required |
| Signature-required recovery profile | `level = any-signature`, `minValidSignatures = 1` | Distributed storage where restore must block unless at least one detached signature exists, but interoperability with Ed25519 or mixed signature sets is acceptable | Restore blocks unless at least one valid detached signature verifies over the canonical manifest |
| Auditor-led archival profile | `level = strong-pq-signature`, `minValidSignatures = 1` | Verified data where provenance responsibility matters and the auditor and signer may be the same entity | Restore blocks unless at least one valid strong-PQ detached signature exists; signer identity material should be preserved with the archive |
| Multi-approver archival profile | `level = strong-pq-signature`, `minValidSignatures > 1` | Dual-control or committee-style archival approval where more than one valid signature is required | Restore blocks unless the signature count threshold is met and at least one valid strong-PQ detached signature is present |

Current profile guidance:

- use `integrity-only` only when recoverability is intentionally allowed without signer-authenticated provenance
- use `any-signature` when "unsigned restore must fail" is more important than requiring a PQ signature specifically
- use `strong-pq-signature` when long-lived provenance matters or when the archive is intended for auditor-led or archival-grade workflows
- increase `minValidSignatures` only when operators are prepared to preserve enough independent valid signatures over time
- preserve signer identity material and any linked timestamp evidence with the bundle even though pinning and timestamps do not satisfy policy by themselves

Current non-claim for these profiles:

- these are recommended operating patterns over the existing policy object
- they do not create new on-wire profile identifiers
- they do not, by themselves, define archive classes or institutional governance programs

### 5.5 Governance and change-control expectations

Quantum Vault does not yet implement a first-class governance object or trust-root program.
This section therefore records the current documentation-level change-control expectations needed to keep policy meaning stable and auditable.

#### 5.5.1 Current hard boundary between bundle updates and policy changes

The following MUST remain distinct:

- adding or replacing bundled signatures, bundled signer material, or bundled timestamps is a bundle-level update and MUST NOT mutate the canonical manifest bytes
- changing `authPolicy.level` or `authPolicy.minValidSignatures` changes restore-relevant semantics and therefore changes `authPolicyCommitment`
- a change to `authPolicyCommitment` requires a new canonical manifest and new detached signatures over the new canonical manifest bytes

#### 5.5.2 Current governance expectations for policy meaning

Current maintainers and operators should treat the following as change-controlled policy meaning:

- the interpretation of `integrity-only`, `any-signature`, and `strong-pq-signature`
- the normalized suite registry that determines which suites count as strong PQ
- the meaning of shipped defaults in Lite and Pro modes
- any future recommended policy profile names published in this document

Current expectation for maintainers:

- publish any change to the meaning of `strong-pq-signature` as a documented project policy change
- preserve a clear change record when adding or removing suites from the strong-PQ registry
- avoid silently weakening shipped defaults or changing profile descriptions without corresponding documentation updates

Current expectation for archive operators:

- preserve the policy object, signer material, detached signatures, and relevant software/documentation context with the archive package
- do not treat later documentation guidance as retroactively changing the committed policy of an already-created archive
- if organizational policy meaning changes materially, create a new archive state or external governance record rather than pretending the original committed policy meant something different all along

#### 5.5.3 Current limitations of governance enforcement

The current implementation does not yet provide:

- a first-class `policyId` or `policyVersion`
- a first-class trust-root list or external authority program
- a first-class lifecycle approval object for migration, renewal, custody transfer, or policy deprecation
- automatic publication or validation of governance advisories

Therefore:

- governance expectations here are normative documentation guidance for maintainers and operators
- they are not yet fully represented as machine-validated policy objects in the current format family

## 6. Signature evaluation and counting semantics

### 6.1 Policy satisfaction rule

**Legacy path:** An archive satisfies authenticity policy if:

- at least `minValidSignatures` detached signatures are cryptographically valid over the exact canonical manifest bytes
- at least one of those valid signatures satisfies the policy level's suite requirement

**Successor path:** An archive satisfies authenticity policy if:

- at least `minValidSignatures` **archive-approval** detached signatures (in `attachments.archiveApprovalSignatures`) are cryptographically valid over the exact canonical **archive-state descriptor** bytes and satisfy suite rules
- **`maintenanceSignatures` and `sourceEvidenceSignatures` do not count** toward `minValidSignatures` or policy satisfaction
- at least one of those valid archive-approval signatures satisfies the policy level's suite requirement when `strong-pq-signature` is selected

See §11 for attachment taxonomy and failure modes.

Current policy satisfaction is existential, not exclusive:

- `strong-pq-signature` requires at least one strong PQ detached signature
- extra Ed25519 or other supported signatures may coexist
- policy does not mean "only PQ signatures may be present"

### 6.2 Strong PQ suite registry

Current policy evaluation is based on signature suite identifiers, not on wrapper type or file extension. Bundle parsing requires canonical suite identifiers on input; broader verifier flows may normalize other detached-artifact inputs before policy evaluation.

Current initial strong-PQ suites are:

- `mldsa-87`
- `slhdsa-shake-256s`
- `slhdsa-shake-256f`

Current evaluation rule:

- policy is evaluated against canonical suite identifiers after parsing/normalization and against verifier results
- broad family names such as `ML-DSA` or `SLH-DSA` are not sufficient by themselves

### 6.3 Wrapper versus suite

Current wrapper distinction:

- `.qsig` and `.sig` are transport/encoding wrappers
- policy strength is determined by the normalized suite and verifier result, not by wrapper alone

### 6.4 Counting rules

Current counting rules are:

- `minValidSignatures` counts unique detached proof identities, not repeated verification results for the same proof
- semantically equivalent Stellar v2 proofs are deduplicated even if JSON serialization differs
- invalid extra signatures are reported but ignored for policy counting
- `strong-pq-signature` requires at least one valid strong-PQ detached signature in addition to `minValidSignatures`

## 7. Signer identity and pinning semantics

Pinned signer identity is an additional trust signal.
It is not a default hard blocker in the current implementation.

### 7.1 Current pin sources

Current signer pin sources are:

- `bundlePinned`: a verified signature matched bundled signer material explicitly linked from the manifest bundle
- `userPinned`: signer identity material came from restore-time user input
- `signerPinned = bundlePinned || userPinned`

Current bundle pin sources include:

- **Legacy:** bundled PQ public key attachment referenced by `attachments.signatures[].publicKeyRef`
- **Legacy:** bundled Stellar signer identifier referenced by `attachments.signatures[].publicKeyRef`
- **Successor:** bundled `attachments.publicKeys[]` referenced by `publicKeyRef` on entries in `archiveApprovalSignatures`, `maintenanceSignatures`, or `sourceEvidenceSignatures` (see §11)

Current user pin sources include:

- restore-time `.pqpk`
- restore-time expected Stellar signer input

### 7.2 Current pinning rules

Current pinning rules are:

- signer pinning is optional
- a matching pin strengthens provenance reporting
- lack of pinning does not by itself block restore if archive policy is satisfied
- valid signature and pinned signature are separate states and must stay separate
- if a bundled signature references bundled signer material via `publicKeyRef`, failure of that bundled reference is a verification failure for that bundled signature, not merely an absence of pinning

Current required distinct status fields:

- `signatureVerified`
- `policySatisfied`
- `signerPinned`
- `bundlePinned`
- `userPinned`

It is forbidden to collapse these into a single generic state such as `trusted`.

### 7.3 Current status vocabulary

Allowed current status terms include:

- `integrity verified`
- `signature verified`
- `strong PQ signature verified`
- `archive policy satisfied`
- `bundle signer pinned`
- `user signer pinned`
- `OTS evidence linked to signature`
- `OTS proof appears complete`
- `OTS proof appears incomplete`

Terms that should not be used loosely:

- `trusted archive`
- `authenticated shard cohort`

## 8. Timestamp and evidence interaction with policy

Current `.ots` semantics are deliberately limited:

- `.ots` is an evidence object
- it targets detached signature bytes, not the bundle itself
- linkage is performed by stamped `SHA-256(detachedSignatureBytes)`
- a bundle timestamp entry references a detached signature by `targetRef`

Current policy rule:

- timestamps NEVER satisfy archive signature policy by themselves

Current handling rules:

- OTS may be bundled or supplied externally
- if multiple OTS proofs target the same detached signature, restore may prefer one apparently complete proof for reporting
- current `appears complete` / `completeProof` labels are heuristic reporting fields derived from proof naming hints or proof size; they are not a cryptographic guarantee that a full external OpenTimestamps attestation chain was validated
- unrelated or ambiguous `.ots` inputs fail closed
- current handling is linkage-focused and report-focused; it does not claim full external timestamp attestation validation

## 9. Attach and restore policy lifecycle

### 9.1 Split stage

At split stage, the archive creator chooses:

- split parameters
- archive authenticity policy

**Legacy outputs** include:

- `.qcont` shards (`QVqcont-6`)
- canonical signable manifest
- initial manifest bundle

The initial manifest bundle contains:

- embedded canonical manifest
- concrete `authPolicy`
- empty or initial attachments

**Successor outputs** include `QVqcont-7` shards carrying an archive-state descriptor, cohort binding, and initial `QV-Lifecycle-Bundle` v1 (see `format-spec.md` Section 8).

### 9.2 Attach stage

**Legacy** `attach` behavior:

- validates detached signatures against canonical manifest bytes
- validates `.ots` target linkage
- imports public keys and signer identifiers
- writes updated bundle
- may rewrite embedded bundles across a full shard cohort
- MUST NOT mutate canonical manifest bytes

**Successor** attach updates `QV-Lifecycle-Bundle` v1 attachments and may rewrite embedded lifecycle bundles across shards; it MUST NOT mutate canonical **archive-state** or **cohort-binding** bytes (`format-spec.md`, implementation in `lifecycle-attach.js`).

### 9.3 Restore evaluation

Current restore policy evaluation occurs after structural and reconstruction checks.

**Legacy manifest-bundle restore** uses the following decision logic:

- `integrity-only`: allow restore if structural/reconstruction integrity holds; report weak provenance status
- `any-signature`: allow restore only if at least one valid detached signature exists over canonical **manifest** bytes
- `strong-pq-signature`: allow restore only if at least one valid strong-PQ detached signature exists over canonical **manifest** bytes

**Successor lifecycle restore** (see `format-spec.md` and **§11**) uses the same three policy **levels** but evaluates **only** `attachments.archiveApprovalSignatures` over canonical **archive-state descriptor** bytes. Restore must also resolve cohort and lifecycle-bundle selection without heuristic auto-selection across multiple embedded bundle digests or mixed cohorts when the implementation requires explicit disambiguation.

Current pinning consequence:

- pinning affects status/provenance reporting
- pinning does not block restore by default

## 10. Conflict and ambiguity handling

Current or current-intended handling is:

- valid but unpinned signatures may still satisfy policy
- invalid extra signatures do not count if another signature satisfies policy
- no satisfying signature blocks restore for `any-signature` and `strong-pq-signature`
- bundle pinning and user pinning are tracked separately and may both be true
- timestamp evidence does not upgrade an otherwise unsatisfied signature policy
- malformed or ambiguously linked evidence is rejected rather than silently tolerated

Current restore must not fail solely because:

- no signer is pinned
- OTS proof is absent
- a non-satisfying signature is present alongside a satisfying one

## 11. Successor lifecycle bundles (normative)

Quantum Vault implements a **successor lifecycle** artifact family **alongside** the legacy manifest bundle family. Byte layout, canonicalization labels, and shard format identifiers are normative in `format-spec.md`. Informative design rationale and Phase 0 frozen contracts are in `docs/process/roadmap/lifecycle/` (for example `resharing-design.md`, `implementation-plan-lifecycle.md`).

### 11.1 Format tracks and transition

Quantum Vault is **phasing out** the **legacy** model in favor of the **successor lifecycle** model: archive-state-centric approval, `QV-Lifecycle-Bundle` v1, and `QVqcont-7` shards.

The **legacy** model (`quantum-vault-archive-manifest/v3`, `QV-Manifest-Bundle` v2, `QVqcont-6`) remains **supported** for **compatibility** with existing archives and tooling, but it is no longer the normal creation path on the shipped Lite or Pro UI surface. Beginning with release **v1.5.3**, legacy creation became compatibility-only on the regular-user surface. Legacy is **not** removed from the implementation while the documented compatibility window remains open.

| Track | Signable approval object | Mutable bundle | Typical shard metadata `alg.fmt` |
| --- | --- | --- | --- |
| Legacy | Canonical **manifest** bytes | `QV-Manifest-Bundle` v2 | `QVqcont-6` |
| Successor | Canonical **archive-state descriptor** bytes | `QV-Lifecycle-Bundle` v1 | `QVqcont-7` |

### 11.2 Attachment families (`QV-Lifecycle-Bundle` v1)

The lifecycle bundle carries `authPolicy` and five attachment arrays (all mandatory; may be empty except as required by policy semantics):

- `attachments.publicKeys[]` — bundled signer identity material for verification and optional pinning
- `attachments.archiveApprovalSignatures[]` — **archive policy**; `signatureFamily` **archive-approval**; `targetType` **archive-state**; signs canonical **archive-state descriptor** bytes
- `attachments.maintenanceSignatures[]` — **maintenance / provenance** over transition records; `targetType` **transition-record**; **MUST NOT** be counted toward archive policy satisfaction
- `attachments.sourceEvidenceSignatures[]` — **source-evidence** provenance; `targetType` **source-evidence**; **MUST NOT** be counted toward archive policy satisfaction
- `attachments.timestamps[]` — OpenTimestamps evidence; `targetDigest` is **SHA-256** over the **detached signature bytes** referenced by `targetRef`; **MUST NOT** satisfy archive policy by itself

### 11.3 Policy satisfaction, pinning, and OTS (successor)

- **Archive policy** (`integrity-only`, `any-signature`, `strong-pq-signature`) is evaluated using **only** verified signatures in `archiveApprovalSignatures` that meet `minValidSignatures` and suite rules. **Maintenance** and **source-evidence** signatures are reported separately and **do not** satisfy archive policy.
- **OTS** linkage does not satisfy archive policy; semantics match §8 (detached signature bytes as targets).
- **Pinning:** If a bundled signature declares `publicKeyRef`, resolution uses bundled `publicKeys[]` and MUST fail closed on unknown, ambiguous, incompatible, or non-verifying bindings (not merely “unpinned”).
- **Integrity, signature validity, pinning, policy satisfaction, and OTS evidence** remain **distinct** reporting channels (§§2–8).

### 11.4 Restore semantics (successor)

Successor restore groups candidate shards by `archiveId`, `stateId`, and `cohortId`, and requires exact byte equality for embedded **archive-state** and **cohort-binding** objects within a cohort. If more than one embedded **lifecycle-bundle** digest appears for an otherwise consistent cohort and the operator does not supply an explicit lifecycle bundle or selected digest, restore **fails closed** (no heuristic “richest bundle” or lexical winner). If multiple valid **cohorts** exist for the same archive state (same-state fork), restore **rejects** mixed cohorts without auto-selecting by timestamp, attachment count, or lexical order.

### 11.5 Same-state resharing semantics (successor)

Same-state resharing reconstructs one predecessor successor cohort, preserves exact archive-state descriptor bytes, and emits a new cohort plus a required transition record. It is a **threshold-shard reconstruction and maintenance path**, not a substitute for full restore-policy evaluation.

- resharing does **not** produce a restore authorization decision
- resharing does **not** rerun archive policy as the user-facing Restore flow does
- preserved archive-approval signatures remain archive-approval evidence over the unchanged archive state; new maintenance signatures over the transition record remain separate maintenance evidence and **do not** satisfy archive policy

### 11.6 Source-evidence v1 (privacy posture)

`quantum-vault-source-evidence/v1` objects carried in `lifecycleBundle.sourceEvidence[]` are intentionally **digest-first**; optional fields are limited (for example optional `mediaType` and `externalSourceSignatureRefs` per schema). There are **no** first-class path, username, or free-form operator note fields in v1; privacy defaults are **structural** (omit sensitive fields), not runtime redaction of rich optional fields.

---

## 12. Future coverage retained for this document

This document still needs future expansion in the following areas:

- richer signature semantic claim types beyond the two format tracks
- full crypto-policy object definition
- archive classes and their consequences
- explicit trust-root models
- first-class migration, renewal, or external approval claim objects that may span archive states (successor migration continuity remains architecture-blocked per `implementation-plan-lifecycle.md`)
- institution-level deployment patterns and governance mechanisms beyond the current documentation-level expectations
- audit/compliance framing that does not overclaim certification
