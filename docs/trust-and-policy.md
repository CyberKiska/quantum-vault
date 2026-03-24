# Trust and policy

Status: Release Candidate
Type: Normative
Audience: archive creators, signers, custodians, restore operators, implementers of policy evaluation, auditors
Scope: current-state normative semantics for signatures, archive authenticity policy, proof counting, pinning, and restore authorization
Out of scope: byte-level encoding, complete threat model, long-term archive classes, full governance framework
Primary implementation sources: `README.md`, implementation code
Historical consolidation source: `process/IMPLEMENTATION-NOTES.md`

## Role

This document defines what signatures, pinning, and policy outcomes mean in Quantum Vault today.
It is the semantic counterpart to `format-spec.md`.

Division of labor:

- `format-spec.md` defines how signatures, pins, timestamps, manifests, and bundles are represented and processed
- `trust-and-policy.md` defines what those processed results mean for policy evaluation and restore authorization

## Scope

This document covers the current semantics of detached signatures, archive authenticity policy, proof counting, signer pinning, and restore authorization.
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
- `src/core/crypto/qcont/restore.js` for restore-time policy gating and reporting behavior
- `docs/format-spec.md`, `docs/security-model.md`, and `docs/glossary.md` for format constraints, security invariants, and shared terminology

External references already used elsewhere in the repository:

- FIPS 204 for ML-DSA suite family context
- FIPS 205 for SLH-DSA suite family context
- RFC 8032 for Ed25519 verification context
- SEP-0023 for Stellar address encoding context
- OpenTimestamps project documentation for the current evidence ecosystem Quantum Vault interoperates with

## Current implementation status

Implemented now:

- current policy levels `integrity-only`, `any-signature`, and `strong-pq-signature`
- current proof-counting and strong-PQ suite evaluation rules
- current bundle pinning and user pinning semantics
- current restore authorization behavior and status vocabulary
- current OTS evidence linkage and heuristic completeness reporting

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
- the current archive authenticity policy object
- the meaning of `integrity-only`, `any-signature`, and `strong-pq-signature`
- current proof-counting and strong-PQ evaluation rules
- current bundle pinning and user pinning semantics
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
   The reconstructed `.qenc`, shard body, manifest digest, bundle digest, and related commitments are internally consistent.

2. `signature verified`
   At least one detached signature cryptographically verifies over the exact canonical manifest bytes.

3. `signer identity pinned`
   A verified signature is linked to expected signer identity material supplied either by the bundle or by the user.

4. `archive policy satisfied`
   The archive's declared authenticity policy is satisfied by the available verified signatures.

These states MUST remain distinct in code, logs, UI, and documentation.

Current mandatory separation:

- integrity does not imply provenance
- signature validity does not imply signer pinning
- signer pinning does not replace policy evaluation
- timestamps do not satisfy archive signature policy

## 3. Current role model and lifecycle authority

Quantum Vault's current implementation encodes artifact verification and restore-policy behavior, not a complete institutional workflow.
The role model below therefore distinguishes:

- roles that are directly reflected in current archive creation, attachment, restore, or verification behavior
- operational roles that matter for provenance or stewardship but are not yet first-class signed claim types or trust-root objects

### 3.1 Current role definitions

| Role | Current meaning | What the implementation knows directly |
| --- | --- | --- |
| Archive creator | Entity that creates the archive, chooses split parameters, and selects the archive authenticity policy during split | The chosen split parameters and committed `authPolicy` are represented in the manifest and bundle; creator identity is not first-class unless preserved through detached signatures or external records |
| Auditor / source verifier | Entity that verifies the source data before archiving and bears provenance responsibility for confirming "this is the data" | This role is operational today; Quantum Vault does not automatically distinguish "audited this data" from the narrower claim "signed these canonical manifest bytes" |
| Signer | Entity that cryptographically signs the canonical manifest bytes using supported detached signer tooling | The verifier can determine that a signer key signed the canonical manifest bytes; broader semantic meaning remains external unless the workflow documents it |
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
3. the signer signs the canonical manifest bytes
4. custodians hold the resulting `.qcont` shards
5. a restoration quorum later supplies enough consistent shards for recovery
6. the restore operator reconstructs the archive and restore policy decides whether decryption may proceed

In the common case, the auditor and signer may be the same entity.
That is a valid and expected workflow, but the current implementation still distinguishes:

- cryptographic proof that a signer key signed the canonical manifest bytes
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
| Create and split archive | Archive creator chooses split parameters and `authPolicy` | The chosen policy is committed via `authPolicyCommitment` and carried in the bundle |
| Sign canonical manifest | Signer signs canonical manifest bytes with supported detached tooling | Verification proves signature validity over canonical manifest bytes only |
| Attach signatures, signer material, or timestamps | Attach operator may bundle valid detached artifacts after archive creation | Attach validates linkage and MUST NOT mutate canonical manifest bytes |
| Store or distribute shards | Custodians hold shards under an external custody arrangement | Current format enforces shard integrity and threshold reconstruction rules, not custodian identity rules |
| Restore archive | Restore operator gathers a consistent shard cohort and any optional external artifacts | Restore enforces integrity, signature verification, pinning semantics, and archive-policy gating |
| Satisfy restoration quorum | Enough custodians or participants supply enough consistent shards to meet threshold | Threshold and cohort consistency are enforced; quorum membership itself is not a first-class signed or policy object |
| Re-sign, renew evidence, rewrap, reencryption, custody transfer, or deprecate policy | Any such authority is external unless and until the format family defines first-class approval or lifecycle claim objects | Current implementation has no first-class authority object for these actions |

Current boundary to preserve:

- Quantum Vault can enforce that artifacts are structurally valid, signatures verify, pins match, and archive policy is or is not satisfied
- Quantum Vault cannot, by itself, prove that a particular person was organizationally authorized to audit data, approve a migration, or authorize a custody transfer unless an external workflow records that meaning

## 4. Meaning of signatures in the current implementation

Current Quantum Vault semantics are intentionally narrow:

- a detached signature means a signer key signed the canonical manifest bytes
- it does not, by itself, encode that the signer audited the plaintext, approved preservation class, authorized a migration, or confirmed custody transfer
- broader semantic claims may exist in an external workflow, but they are not currently first-class signed claim types in the Quantum Vault format family

Current supported detached signature wrappers:

- Quantum Signer `.qsig`
- Stellar WebSigner `.sig`

Current signing target:

- canonical manifest bytes only
- never mutable bundle bytes
- never detached timestamp artifacts

Current verification semantics:

- bundled and external detached signatures are verified against the exact canonical manifest bytes
- wrapper-specific parsing, context handling, and normalized suite evaluation are part of signature validity, not optional reporting details
- if a bundled signature carries `publicKeyRef`, the referenced bundled signer material constrains safe verification for that bundled signature
- a bundled signature with a bad, incompatible, or non-verifying `publicKeyRef` binding is rejected rather than treated as merely "unpinned"

## 5. Archive authenticity policy object

Archive authenticity policy is fixed at archive creation time, committed into the canonical manifest via `authPolicyCommitment`, and carried concretely in the manifest bundle as `authPolicy`.

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

An archive satisfies authenticity policy if:

- at least `minValidSignatures` detached signatures are cryptographically valid over the exact canonical manifest bytes
- at least one of those valid signatures satisfies the policy level's suite requirement

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

- bundled PQ public key attachment referenced by `attachments.signatures[].publicKeyRef`
- bundled Stellar signer identifier referenced by `attachments.signatures[].publicKeyRef`

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

Current outputs include:

- `.qcont` shards
- canonical signable manifest
- initial manifest bundle

The initial bundle contains:

- embedded canonical manifest
- concrete `authPolicy`
- empty or initial attachments

### 9.2 Attach stage

Current `attach` behavior:

- validates detached signatures against canonical manifest bytes
- validates `.ots` target linkage
- imports public keys and signer identifiers
- writes updated bundle
- may rewrite embedded bundles across a full shard cohort
- MUST NOT mutate canonical manifest bytes

### 9.3 Restore evaluation

Current restore policy evaluation occurs after structural and reconstruction checks.
The current decision logic is:

- `integrity-only`: allow restore if structural/reconstruction integrity holds; report weak provenance status
- `any-signature`: allow restore only if at least one valid detached signature exists
- `strong-pq-signature`: allow restore only if at least one valid strong-PQ detached signature exists

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

## 11. Future coverage retained for this document

This document now carries the current normative baseline, but it still needs future expansion in the following areas:

- richer signature semantic claim types
- full crypto-policy object definition
- archive classes and their consequences
- explicit trust-root models
- first-class lifecycle approval objects for migration, renewal, custody transfer, and policy deprecation
- institution-level deployment patterns and governance mechanisms beyond the current documentation-level expectations
- audit/compliance framing that does not overclaim certification

### 11.1 Successor lifecycle bundles (non-normative placeholder)

The successor lifecycle artifact family described in `docs/process/roadmap/lifecycle/resharing-design.md` is **not** part of the current normative policy model in this file. Planning and design live under `docs/process/roadmap/lifecycle/`.

When lifecycle bundles are implemented, this document will need normative updates for at least:

- how archive-approval signatures, maintenance signatures, source-evidence signatures, and OTS evidence relate to integrity, signature validity, pinning, and policy satisfaction for the successor bundle shape
- pinning and `authPolicy` / policy satisfaction when attachment taxonomy differs from the current manifest bundle
- explicit OTS scope: evidence remains over detached signature bytes and does not satisfy archive policy by itself

Until those updates land, `docs/format-spec.md`, `docs/trust-and-policy.md` (current sections), and `docs/security-model.md` remain authoritative for the **current** `quantum-vault-archive-manifest/v3` and `QV-Manifest-Bundle` v2 family only.
