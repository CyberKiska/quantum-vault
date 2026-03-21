# Glossary

Status: Release Candidate
Type: Informative
Audience: Maintainers, contributors, reviewers, implementers, auditors
Scope: Shared vocabulary and status terms used across the current Quantum Vault documentation set
Out of scope: Replacing the full normative semantics owned by the core docs

## Role

This file is the shared vocabulary home for the Quantum Vault documentation set.
It defines the baseline meaning of core terms so that `README.md`, the owner docs, process docs, and UX guidance use the same words consistently.

This file does not replace the owner docs:

- `format-spec.md` owns byte-level and artifact-structure semantics
- `trust-and-policy.md` owns signature, pinning, and policy semantics
- `security-model.md` owns assumptions, invariants, and claim boundaries
- `long-term-archive.md` owns archival and lifecycle terminology

If a term meaning changes, update this file and the owning document in the same change.

## Scope

This document covers the shared vocabulary and status terms used across the current Quantum Vault documentation set.
It does not replace the full technical semantics owned by the current owner docs.

## Normative status

This document is informative, but it is the shared vocabulary owner for the current Quantum Vault documentation set.
Use it to stabilize baseline term meaning across the landing page, owner docs, process docs, and UX guidance.

Interpretation rule:

- this file does not override the detailed technical semantics owned by `format-spec.md`, `trust-and-policy.md`, `security-model.md`, or `long-term-archive.md`
- if a glossary term and an owning document diverge, repair both together rather than treating the glossary as an independent semantic source
- future-only terms should not be introduced here as if they were current behavior

## Sources and references

Current grounding for this glossary comes from the active owner docs and the current implementation they summarize:

- `docs/format-spec.md` for artifact, identifier, canonicalization, and key terminology
- `docs/trust-and-policy.md` for signature, pinning, policy, and evidence terminology
- `docs/security-model.md` for session, assumption, and claim-boundary terminology
- `docs/long-term-archive.md` for archival, fixity, provenance, and lifecycle terminology
- `README.md`, `docs/README.md`, and `docs/series/UX-STYLE-SERIES.md` for cross-document usage and label consistency

## Current implementation status

This glossary reflects the terminology of the current repository state.
It intentionally tracks implemented behavior and currently adopted documentation taxonomy, including terms that are documentation-level classifications rather than first-class wire-level fields.

Current examples:

- `archive class` is currently a documentation and policy taxonomy, not a manifest field
- `OTS evidence` reflects current linkage behavior and heuristic completeness labels
- `secretKey.qkey` remains a legacy filename even though the canonical term for the contained asymmetric object is `privateKey`

## Future work and non-normative notes

Future vocabulary should be added here only after the owning document gives it a stable meaning.
Do not preload speculative roadmap terminology into the shared glossary before the corresponding owner doc has been grounded and reviewed.

## Usage rules

- One term, one baseline meaning.
- Other docs may summarize a term, but should not redefine it incompatibly.
- If a term is future-only or target-only, mark that explicitly rather than presenting it as current behavior.
- Product-specific archive and cryptographic terms should be defined here first, then referenced elsewhere.

## Artifact and format terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| archive | The logical protected object and its authenticity and evidence context, not just a single file. | `docs/long-term-archive.md` |
| payload | The original user content before `.qenc` containerization. | `docs/format-spec.md` |
| container | The `.qenc` encrypted object. | `docs/format-spec.md` |
| shard | One `.qcont` threshold fragment carrying part of the recovery state plus embedded manifest and bundle material. | `docs/format-spec.md` |
| canonical manifest | The immutable signable archive description whose canonical bytes are the only detached-signature payload. | `docs/format-spec.md` |
| manifest bundle | The mutable JSON package carrying the canonical manifest, `authPolicy`, and authenticity attachments. | `docs/format-spec.md` |
| detached signature | A signature artifact stored separately from the canonical manifest bytes and verified over those bytes. | `docs/trust-and-policy.md` |

## General cryptographic and operational terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| keypair | A matched asymmetric `publicKey` and `privateKey`. | `docs/glossary.md` |
| digest | A cryptographic hash value over specified input bytes; the algorithm and target depend on the surrounding format or verification rule. | `docs/glossary.md` |
| fingerprint | A short identifier derived from key material or related identity data for display and operator comparison; it is not the key itself. | `docs/glossary.md` |
| session | In-memory application-held state that persists only until explicit wipe, page close, or equivalent runtime loss. | `docs/security-model.md` |

## Status, trust, and evidence terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| integrity verified | Structural, digest, commitment, and reconstruction checks are internally consistent. | `docs/trust-and-policy.md` |
| signature verified | At least one detached signature cryptographically verifies over the exact canonical manifest bytes. | `docs/trust-and-policy.md` |
| archive authenticity policy | The restore and verify rule committed in the canonical manifest and carried concretely in the bundle as `authPolicy`. | `docs/trust-and-policy.md` |
| archive policy satisfied | The available verified signatures satisfy the archive authenticity policy. | `docs/trust-and-policy.md` |
| signer pinning | Binding a valid signature to expected signer material from the bundle or from restore-time user input; distinct from policy satisfaction. | `docs/trust-and-policy.md` |
| `bundlePinned` | At least one verified signature matched bundled signer material explicitly linked from the manifest bundle. | `docs/trust-and-policy.md` |
| `userPinned` | At least one verified signature matched restore-time user-supplied signer material. | `docs/trust-and-policy.md` |
| `signerPinned` | The combined status `bundlePinned || userPinned`. | `docs/trust-and-policy.md` |
| evidence | Supplementary material linked to detached signatures that may improve reporting or future time and provenance interpretation, but does not satisfy archive signature policy by itself. | `docs/trust-and-policy.md` |
| OTS evidence | OpenTimestamps proof linked by `SHA-256(detachedSignatureBytes)` to detached signature bytes; current completeness labels are heuristic reporting only. | `docs/trust-and-policy.md` |
| fixity | Evidence that stored bytes have not changed. | `docs/long-term-archive.md` |
| provenance | Evidence about origin and archive history; in current Quantum Vault, signature validity, pinning, policy satisfaction, and optional evidence remain separate signals. | `docs/long-term-archive.md` |

## Archival and lifecycle terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| representation information | The documentation, identifiers, and future tools or material needed to interpret the archive over time. | `docs/long-term-archive.md` |
| archive class | The current documentation and policy taxonomy for archival burden: `backup`, `audited-archive`, and `long-term-archive`. | `docs/long-term-archive.md` |
| renewal | Replacement or chaining of signatures or evidence before their trust basis degrades. | `docs/long-term-archive.md` |
| migration | A stewardship change over time that may alter packaging, confidentiality, or representation while preserving or recording continuity. | `docs/long-term-archive.md` |
| rewrap | Changing key-wrapping or confidentiality envelope without re-encrypting content. | `docs/long-term-archive.md` |
| reencryption | Generating new ciphertext under new confidentiality material. | `docs/long-term-archive.md` |

## Role terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| archive creator | Party that creates the archive, chooses split parameters, and selects the archive authenticity policy during split. | `docs/trust-and-policy.md` |
| auditor / source verifier | Party that verifies source data before archiving and bears provenance responsibility for confirming that "this is the data"; this role is operational today and is not automatically encoded by detached signatures alone. | `docs/trust-and-policy.md` |
| signer | Party producing detached signatures over canonical manifest bytes. | `docs/trust-and-policy.md` |
| custodian | Holder of one or more `.qcont` shards or related detached artifacts. | `docs/trust-and-policy.md` |
| restoration quorum | Operational set of custodians or participants able to supply enough consistent shards to satisfy the threshold required for restore; not a first-class policy or trust-root object in the current format family. | `docs/trust-and-policy.md` |
| restore operator | Party supplying artifacts at restore time and possibly providing user pinning input. | `docs/trust-and-policy.md` |
| verifier / relying party | Party evaluating integrity, signature validity, pinning, and policy outcome during later verification or restore. | `docs/trust-and-policy.md` |
| policy maintainer | Party defining product defaults and the current strong-PQ suite registry used by policy evaluation. | `docs/trust-and-policy.md` |

## Identifier and commitment terms

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| `qencHash` | `SHA3-512` over the full `.qenc` bytes; the current primary fixity and authenticity anchor for the archive state. | `docs/format-spec.md` |
| `containerId` | `SHA3-512(qenc-header-bytes)`; the current secondary identifier derived from the `.qenc` header bytes. | `docs/format-spec.md` |
| `manifestDigest` | `SHA3-512` over canonical manifest bytes. | `docs/format-spec.md` |
| `authPolicyCommitment` | Commitment binding restore-relevant authenticity-policy semantics from canonical manifest bytes to the concrete bundle `authPolicy`. | `docs/format-spec.md` |

## Key terminology rule

| Term | Current definition | Detailed owner |
| --- | --- | --- |
| `privateKey` | Asymmetric secret key material. | `docs/format-spec.md` |
| `publicKey` | Asymmetric public key material. | `docs/format-spec.md` |
| `secretKey` | Symmetric secret material such as derived `Kenc` or `Kiv`. | `docs/format-spec.md` |

Compatibility note:

- the exported filename `secretKey.qkey` currently contains the ML-KEM private key
- the filename is a legacy operational name and not the canonical term for the asymmetric object it contains

## Related maintenance tasks

- Add or change a core term in this file first.
- Update the detailed owner document in the same change if the term meaning or current behavior changes.
- In `README.md`, process docs, and UX docs, prefer summary wording plus a reference to the owner doc instead of repeating full definitions.
- If a repeated term still appears only in support docs, either move it here or state explicitly that the support doc is standardizing a UI label rather than defining product semantics.
- If a UI label intentionally differs for usability reasons, keep the underlying product term here and record the UI exception explicitly in the relevant UX guidance.
