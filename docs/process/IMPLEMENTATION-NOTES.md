# Implementation Notes

Status: Draft
Type: Informative
Audience: Contributors, maintainers, reviewers
Scope: Current successor-family contributor notes and codebase orientation
Out of scope: Normative format rules, normative policy semantics, threat-model claims, archival taxonomy

## Role

This file is not a specification.

It preserves the implementation-facing model behind the shipped successor-family runtime:

- archive-state descriptors as the archive-approval signable object
- cohort bindings as the state-bound shard-cohort description
- `QV-Lifecycle-Bundle` v1 as the mutable evidence carrier
- detached signatures, `.pqpk` pins, and `.ots` evidence as external or bundled authenticity artifacts
- restore-time separation of integrity, signature validity, pinning, and policy satisfaction

Use this file when you need contributor context, current implementation intent, or a codebase map.
Use the core docs when you need normative rules.
Use `docs/glossary.md` when you need the canonical meaning of shared terms.

## Current normative homes

| Topic | Current owner |
| --- | --- |
| Artifact structure, canonicalization, embedded lifecycle objects, and restore/verifier flow | `docs/format-spec.md` |
| Signature meaning, proof counting, pinning, policy levels, and restore authorization semantics | `docs/trust-and-policy.md` |
| Security boundaries, assumptions, invariants, and failure semantics | `docs/security-model.md` |
| Archive classes, OAIS mapping, renewal, migration, and long-horizon archival direction | `docs/long-term-archive.md` |
| Shared vocabulary and status terms | `docs/glossary.md` |
| Documentation roles and source-of-truth map | `docs/README.md` |

## Current mental model for contributors

### 1. Archive-state bytes are the archive-approval target

The shipped implementation keeps one immutable archive-approval object and one mutable evidence object.

Archive-state descriptors exist so that:

- detached archive-approval signatures always target stable canonical bytes
- signers can use external tools without understanding shard or bundle layout
- attach and same-state reshare can add evidence later without changing what was approved

When working on signing, attach, or restore code, treat canonical archive-state bytes as the only current archive-approval payload unless the core spec changes explicitly.

### 2. The lifecycle bundle is an evidence carrier, not an approval target

`QV-Lifecycle-Bundle` v1 exists so that:

- authenticity material can travel with the archive
- shards can remain self-contained enough for recovery workflows
- archive approval can stay detached from later bundle growth

Contributors should preserve the split between immutable archive-state bytes and mutable lifecycle-bundle evidence.
Attach and same-state reshare may update bundle content; they must not rewrite canonical archive-state bytes.

### 3. Cohort binding is part of recovery safety

Restore is intentionally cohort-consistency-first, not volume-first.

Contributors touching shard restore logic should preserve the idea that restore selects one coherent archive/state/cohort set based on exact bytes and derived identifiers, rather than preferring the numerically largest pile of shards.

That rule exists because:

- mixed or conflicting cohorts are a safety problem, not just a UX problem
- reconstructing from the "largest" set can silently select the wrong state

### 4. `.ots` is supplementary evidence only

OpenTimestamps is integrated as evidence, not as a replacement for detached signatures or policy satisfaction.

In practice, contributors should think about `.ots` handling as:

- target linkage to detached signature bytes
- reporting of heuristic completion labels
- export and import portability

Do not let `.ots` handling drift into archive-policy satisfaction or signer-identity semantics unless the normative docs change explicitly.

### 5. Restore outcomes must stay separated

The implementation is deliberately shaped around distinct outcomes:

1. integrity verified
2. archive-approval signature verified
3. signer identity pinned
4. archive policy satisfied

Maintenance signatures, source-evidence signatures, and timestamp evidence are separate channels on top of that.
If a change touches restore status, logging, or UI labels, preserve this separation unless the trust model is intentionally changed in the normative docs.

### 6. Terminology note for `privateKey.qkey`

The canonical terminology home is `docs/glossary.md`.

The implementation uses the filename `privateKey.qkey`.
Historically that name was convenient operationally, but it is not the right cryptographic term for the object inside.

Contributor rule:

- treat the object in `privateKey.qkey` as an asymmetric `privateKey`
- reserve `secretKey` for symmetric secret material such as derived AES/KMAC keys

If you touch docs, logs, UI, or code comments, keep that distinction explicit.

## Contributor guidance for future changes

### If you change archive-state, cohort-binding, transition-record, source-evidence, or lifecycle-bundle structure

- update `docs/format-spec.md`
- keep canonical archive-state bytes stable across attach operations unless the format contract is intentionally changed
- verify that embedded archive-state, cohort-binding, and lifecycle-bundle bindings still round-trip cleanly

### If you change signature, pinning, or restore-policy semantics

- update `docs/trust-and-policy.md`
- preserve the distinction among signature validity, pinning, and policy satisfaction
- verify status vocabulary in UI and logs

### If you change failure behavior, invariants, or security claims

- update `docs/security-model.md`
- check whether the change weakens fail-closed behavior or broadens claims beyond what the project can honestly support

### If you change long-horizon archival behavior

- update `docs/long-term-archive.md`
- distinguish current implementation from future archival direction

## Current module map

| Area | Responsibility | Key outputs or decisions |
| --- | --- | --- |
| `src/core/crypto/index.js` | Encrypt/decrypt orchestration | `.qenc` construction and parsing |
| `src/core/crypto/qenc/` | Archive header format | Container header and metadata framing |
| `src/core/crypto/lifecycle/artifacts.js` | Successor artifact schemas, canonicalization, and semantic validation | Archive-state, cohort-binding, transition-record, source-evidence, and lifecycle-bundle parsing/building |
| `src/core/crypto/qcont/lifecycle-shard.js` | Successor split and same-state reshare | `QVqcont-7` shard creation, lifecycle embedding, and same-state cohort rotation |
| `src/core/crypto/qcont/lifecycle-attach.js` | Successor attach workflow | Lifecycle-bundle updates, shard rewrite decisions, detached-artifact import |
| `src/core/crypto/qcont/restore.js` | Cohort selection and reconstruction | Policy-gated restore, ambiguity handling, lifecycle verification reports |
| `src/core/crypto/auth/` | Detached signature, pinning, and OTS verification | `.qsig`, `.sig`, `.pqpk`, timestamp linkage, proof-identity dedupe |
| `src/app/restore-inputs.js` | Restore-time file classification | Detects successor shards, archive-state descriptors, lifecycle bundles, detached signatures, `.pqpk`, and `.ots` |
| `src/core/features/qcont/` | Pro-mode successor workflows | Split, attach, restore, and reshare UI integration |
| `src/core/features/lite-mode.js` | Lite-mode workflow | Simplified successor archive creation and restore |

## Current examples and fixtures

The development repository contains local fixtures and self-tests for contributor inspection, including:

- encrypted containers and shard sets
- detached signature examples
- timestamp evidence examples
- successor lifecycle object fixtures exercised by `src/core/crypto/selftest.js`

Use those fixtures for manual inspection and regression work.
Do not treat them as a frozen interoperability corpus unless the repository later promotes them to that role.
