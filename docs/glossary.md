# Glossary

Status: Release Candidate
Type: Informative
Audience: maintainers, contributors, reviewers, implementers, auditors
Scope: shared vocabulary and status terms used across the current Quantum Vault documentation set
Out of scope: replacing the full normative semantics owned by the core docs

## Role

This file is the shared vocabulary home for the Quantum Vault documentation set.
It defines the baseline meaning of core terms so that `README.md`, the owner docs, process docs, and UX guidance use the same words consistently.

This file does not replace the owner docs:

- [`format-spec.md`](format-spec.md) owns byte-level and artifact-structure semantics
- [`trust-and-policy.md`](trust-and-policy.md) owns signature, pinning, and policy semantics
- [`security-model.md`](security-model.md) owns assumptions, invariants, and claim boundaries
- [`long-term-archive.md`](long-term-archive.md) owns archival and lifecycle terminology

If a term meaning changes, update this file and the owning document in the same change.

## Scope

This document covers the shared vocabulary and status terms used across the current Quantum Vault documentation set.
It does not replace the full technical semantics owned by the current owner docs.

## Normative status

This document is informative, but it is the shared vocabulary owner for the current Quantum Vault documentation set.
Use it to stabilize baseline term meaning across the landing page, owner docs, process docs, and UX guidance.

Interpretation rule:

- this file does not override the detailed technical semantics owned by the owner docs
- if a glossary term and an owning document diverge, repair both together rather than treating the glossary as an independent semantic source
- future-only terms should not be introduced here as if they were current behavior

## Sources and references

Current grounding for this glossary comes from the active owner docs and the implementation they summarize:

- [`format-spec.md`](format-spec.md)
- [`trust-and-policy.md`](trust-and-policy.md)
- [`security-model.md`](security-model.md)
- [`long-term-archive.md`](long-term-archive.md)
- [`README.md`](../README.md)

## Usage rules

- one term, one baseline meaning
- other docs may summarize a term, but should not redefine it incompatibly
- if a term is future-only, mark that explicitly rather than presenting it as current behavior
- product-specific archive and cryptographic terms should be defined here first, then referenced elsewhere

## Artifact and format terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| archive | The logical protected object and its authenticity and evidence context, not just a single file. | [`long-term-archive.md`](long-term-archive.md) |
| payload | The original user content before `.qenc` containerization. | [`format-spec.md`](format-spec.md) |
| container | The `.qenc` encrypted object. | [`format-spec.md`](format-spec.md) |
| shard | One `QVqcont-7` threshold fragment carrying part of the recovery state plus embedded archive-state, cohort-binding, and lifecycle-bundle bytes. | [`format-spec.md`](format-spec.md) |
| archive-state descriptor | The immutable signable archive-state object (`quantum-vault-archive-state-descriptor/v1`); canonical bytes are the archive-approval payload. | [`format-spec.md`](format-spec.md), [`trust-and-policy.md`](trust-and-policy.md) |
| cohort binding | The state-bound shard-cohort description that carries sharding commitments and the digest input used to derive `cohortId`. | [`format-spec.md`](format-spec.md) |
| lifecycle bundle | The mutable `QV-Lifecycle-Bundle` v1 object carrying `authPolicy`, archive-state and cohort-binding digests, transitions, source evidence, and attachments. | [`format-spec.md`](format-spec.md), [`trust-and-policy.md`](trust-and-policy.md) |
| transition record | A same-state resharing maintenance record carried in the lifecycle bundle and targeted by maintenance signatures. | [`format-spec.md`](format-spec.md), [`trust-and-policy.md`](trust-and-policy.md) |
| source evidence | A digest-first provenance object carried in the lifecycle bundle and targeted by source-evidence signatures. | [`format-spec.md`](format-spec.md), [`trust-and-policy.md`](trust-and-policy.md) |
| detached signature | A signature artifact stored separately from the current target object and verified over declared canonical target bytes. | [`trust-and-policy.md`](trust-and-policy.md) |

## General cryptographic and operational terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| keypair | A matched asymmetric `publicKey` and `privateKey`. | [`glossary.md`](glossary.md) |
| digest | A cryptographic hash value over specified input bytes; the algorithm and target depend on the surrounding format or verification rule. | [`format-spec.md`](format-spec.md) |
| fingerprint | A short identifier derived from key material or related identity data for display and operator comparison; it is not the key itself. | [`trust-and-policy.md`](trust-and-policy.md) |
| session | In-memory application-held state that persists only until explicit wipe, page close, or equivalent runtime loss. | [`security-model.md`](security-model.md) |

## Status, trust, and evidence terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| integrity verified | Structural, digest, commitment, and reconstruction checks are internally consistent. | [`trust-and-policy.md`](trust-and-policy.md) |
| archive approval signature verified | At least one detached archive-approval signature cryptographically verifies over canonical archive-state descriptor bytes. | [`trust-and-policy.md`](trust-and-policy.md) |
| archive authenticity policy | The restore and verify rule committed in the archive-state descriptor and carried concretely in the lifecycle bundle as `authPolicy`. | [`trust-and-policy.md`](trust-and-policy.md) |
| archive policy satisfied | The available verified archive-approval signatures satisfy the archive authenticity policy. | [`trust-and-policy.md`](trust-and-policy.md) |
| signer pinning | Binding a valid signature to expected signer material from the lifecycle bundle or from restore-time user input; distinct from policy satisfaction. | [`trust-and-policy.md`](trust-and-policy.md) |
| `bundlePinned` | At least one verified signature matched bundled signer material explicitly linked from the lifecycle bundle. | [`trust-and-policy.md`](trust-and-policy.md) |
| `userPinned` | At least one verified signature matched restore-time user-supplied signer material. | [`trust-and-policy.md`](trust-and-policy.md) |
| `signerPinned` | The combined status `bundlePinned || userPinned`. | [`trust-and-policy.md`](trust-and-policy.md) |
| archive approval | The signature family that signs canonical archive-state descriptor bytes and is the only family counted toward archive policy. | [`trust-and-policy.md`](trust-and-policy.md) |
| maintenance signature | A detached signature over a transition record; reported separately from archive policy. | [`trust-and-policy.md`](trust-and-policy.md) |
| source-evidence signature | A detached signature over a source-evidence object; reported separately from archive policy. | [`trust-and-policy.md`](trust-and-policy.md) |
| evidence | Supplementary material linked to detached signatures that may improve reporting or future time and provenance interpretation, but does not satisfy archive signature policy by itself. | [`trust-and-policy.md`](trust-and-policy.md) |
| OTS evidence | OpenTimestamps proof linked by `SHA-256(detachedSignatureBytes)` to detached signature bytes; current completeness labels are heuristic reporting only. | [`trust-and-policy.md`](trust-and-policy.md) |
| fixity | Evidence that stored bytes have not changed. | [`long-term-archive.md`](long-term-archive.md) |
| provenance | Evidence about origin and archive history; in current Quantum Vault, archive approval, maintenance evidence, source evidence, pinning, and OTS remain separate signals. | [`long-term-archive.md`](long-term-archive.md) |

## Archival and lifecycle terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| representation information | The documentation, identifiers, and future tools or material needed to interpret the archive over time. | [`long-term-archive.md`](long-term-archive.md) |
| archive class | The current documentation and policy taxonomy for archival burden: `backup`, `audited-archive`, and `long-term-archive`. | [`long-term-archive.md`](long-term-archive.md) |
| renewal | Replacement or chaining of signatures or evidence before their trust basis degrades. | [`long-term-archive.md`](long-term-archive.md) |
| migration | A stewardship change over time that may alter packaging, confidentiality, or representation while preserving or recording continuity. | [`long-term-archive.md`](long-term-archive.md) |
| same-state resharing | Availability maintenance that preserves archive-state bytes while producing a new cohort and required transition record. | [`format-spec.md`](format-spec.md), [`trust-and-policy.md`](trust-and-policy.md) |
| rewrap | A future state-changing operation that would change key-wrapping or confidentiality envelope without changing higher-level intent. | [`long-term-archive.md`](long-term-archive.md) |
| reencryption | A future state-changing operation that generates new ciphertext under new confidentiality material. | [`long-term-archive.md`](long-term-archive.md) |

## Role terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| archive creator | Party that creates the archive, chooses split parameters, and selects the archive authenticity policy during split. | [`trust-and-policy.md`](trust-and-policy.md) |
| signer | Party producing detached signatures over archive-state, transition-record, or source-evidence bytes. | [`trust-and-policy.md`](trust-and-policy.md) |
| custodian | Holder of one or more `.qcont` shards or related detached artifacts. | [`trust-and-policy.md`](trust-and-policy.md) |
| restoration quorum | Operational set of custodians or participants able to supply enough consistent shards to satisfy threshold recovery; not a first-class policy or trust-root object. | [`trust-and-policy.md`](trust-and-policy.md) |
| restore operator | Party supplying artifacts at restore time and possibly providing user pinning input. | [`trust-and-policy.md`](trust-and-policy.md) |
| verifier / relying party | Party evaluating integrity, signature validity, pinning, and policy outcome during later verification or restore. | [`trust-and-policy.md`](trust-and-policy.md) |
| policy maintainer | Party defining product defaults and the current strong-PQ suite registry used by policy evaluation. | [`trust-and-policy.md`](trust-and-policy.md) |

## Identifier and commitment terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| `qencHash` | `SHA3-512` over the full `.qenc` bytes; the primary fixity anchor for one archive state. | [`format-spec.md`](format-spec.md) |
| `containerId` | `SHA3-512(qenc-header-bytes)`; the current secondary identifier derived from `.qenc` header bytes. | [`format-spec.md`](format-spec.md) |
| `archiveId` | Stable archive identifier within one successor archive family. | [`format-spec.md`](format-spec.md) |
| `stateId` | `SHA3-512` over canonical archive-state descriptor bytes. | [`format-spec.md`](format-spec.md) |
| `cohortBindingDigest` | `SHA3-512` over canonical cohort-binding bytes. | [`format-spec.md`](format-spec.md) |
| `cohortId` | `SHA3-256` over the canonical cohort-id preimage rooted in `archiveId`, `stateId`, and `cohortBindingDigest`. | [`format-spec.md`](format-spec.md) |
| `authPolicyCommitment` | Commitment binding restore-relevant authenticity-policy semantics from canonical archive-state bytes to the concrete lifecycle-bundle `authPolicy`. | [`format-spec.md`](format-spec.md) |

## Key terminology rule

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| `privateKey` | Asymmetric secret key material. | [`format-spec.md`](format-spec.md) |
| `publicKey` | Asymmetric public key material. | [`format-spec.md`](format-spec.md) |
| `secretKey` | Symmetric secret material such as derived `Kenc` or `Kiv`. | [`format-spec.md`](format-spec.md) |

Current file naming note:

- the exported filename `privateKey.qkey` contains the ML-KEM private key

## Related maintenance tasks

- add or change a core term in this file first
- update the detailed owner document in the same change if the term meaning or current behavior changes
- in `README.md`, process docs, and UX docs, prefer summary wording plus a reference to the owner doc instead of repeating full definitions
