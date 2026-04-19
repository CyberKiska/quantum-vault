# Documentation

Status: Release Candidate
Type: Mixed
Audience: Maintainers, contributors, reviewers
Scope: Active control point for the Quantum Vault documentation set
Out of scope: Replacing the normative content of the core docs themselves

## Purpose

This file is the active documentation control point for the repository.
It defines:

- which documents are authoritative for which topics
- which files are published docs, support docs, or internal working material
- the terminology and ownership rules that future doc edits should follow
- the publication status of the current documentation set

When documents disagree about role or ownership, `docs/README.md` wins.

## Publication boundary

The documentation set is intentionally split into three surfaces:

- top-level `docs/` files are the current primary Quantum Vault docs surface
- `docs/process/` is published support/reference material, not the primary product doc surface
- `docs/series/` and `docs/internal/` are contributor/internal working material and are not treated as published product documentation

Publication note:

- `docs/internal/`, `docs/series/`, and `examples/` are excluded from published releases via `.gitignore`
- internal planning material has been absorbed into the published owner docs and is not referenced as required reading in the release surface
- `docs/process/roadmap/lifecycle/` remains published as historical transition/design material, not as the active normative or execution surface for current behavior

## Published-doc source policy

Published owner docs and active appendices may rely on:

- primary standards and specifications
- primary research directly supporting a current implementation, security, archival, or whitepaper-rationale claim
- current implementation modules when the claim is specifically about shipped repository behavior

Current release status:

Implemented now:

- the documentation set is successor-family-only for the shipped product surface
- the regular-user product surface creates successor lifecycle archives in both Lite and Pro
- current published docs MUST distinguish implemented now, historical background, and deferred roadmap material explicitly

Historical and rejected runtime context:

- pre-successor planning material is retained only as historical reference
- legacy manifest-era inputs are rejected by the current runtime and MUST NOT be presented as a live migration path in owner docs

Deferred roadmap:

- RFC 4998-style renewal
- state-changing continuity records
- governance objects and trust-root programs

Current product surfaces:

- Lite: regular-user successor archive creation/export of `.qcont`, `*.archive-state.json`, and `*.lifecycle-bundle.json`, successor restore, and explicit ambiguity resolution when successor archive/state/cohort or lifecycle-bundle selection is required
- Pro: all Lite successor workflows plus standalone `*.cohort-binding.json` export, explicit successor artifact export/attach/inspection, and same-state resharing controls
- Historical material: roadmap and archival reference files may describe earlier artifact families or earlier planning baselines, but they are not part of the current shipped product surface

Current release-gate note:

- automated release-gate coverage for successor-default build/export, mixed legacy/successor rejection, same-state cohort ambiguity, and lifecycle-bundle ambiguity currently lives in `src/core/crypto/selftest.js`
- a dedicated headless browser harness is not yet part of the repo; until one lands, maintainers MUST manually verify before release that Lite and Pro restore/reshare actions remain disabled until required successor selections are made, mixed legacy/successor input shows the blocking compatibility message, and successor-first labels remain on the create/build/attach surface

## Control rules

1. One topic, one home.
   A topic may be summarized elsewhere, but only one document owns its normative definition.

2. The core destination docs are:
   `README.md`, `glossary.md`, `WHITEPAPER.md`, `format-spec.md`, `trust-and-policy.md`, `security-model.md`, `long-term-archive.md`.

   Format-compatibility appendices that are actively referenced by `format-spec.md` live under `docs/appendices/`.
   They are support docs by default, but an appendix may own a bounded compatibility topic when a core owner doc explicitly delegates that topic to it.

3. Distinguish published docs from contributor/internal material.
   Files in `docs/internal/` and `docs/series/` are not authoritative product docs for the published Quantum Vault documentation set.

4. Distinguish current behavior from historical and future direction.
   Every core doc should label statements as implemented now, historical background, or recommended future direction.

5. Owner docs MUST keep the status split explicit.
   Core owner docs should mark current successor-family behavior, deferred roadmap material, and historical reference material separately rather than mixing them into one narrative.

6. Shared vocabulary lives in `docs/glossary.md`.
   If a core term meaning changes, update the glossary and the owning document in the same change.

## Current source-of-truth map

| Topic | Working source now | Destination owner |
| --- | --- | --- |
| Product overview and workflow | `README.md` | `README.md` + `WHITEPAPER.md` |
| Artifact formats, canonicalization, verifier flow, and successor lifecycle attachments | `format-spec.md`, `src/core/crypto/qcont/restore.js`, `src/core/crypto/qcont/lifecycle-shard.js`, `src/core/crypto/lifecycle/artifacts.js`, `docs/schema/` | `format-spec.md` |
| Successor lifecycle design history and Phase 0 frozen contracts (informative) | `docs/process/roadmap/lifecycle/` plus the shipped successor implementation and schemas | Historical transition record only; normative bytes/policy remain in `format-spec.md` and `trust-and-policy.md` |
| Archive policy, proof counting, pinning, role semantics | `trust-and-policy.md` | `trust-and-policy.md` |
| Threat model, assumptions, invariants, claim boundaries | `security-model.md` | `security-model.md` |
| Archive classes, OAIS mapping, renewal, migration | `long-term-archive.md` | `long-term-archive.md` |
| Shared vocabulary, key terminology, and status terms | `glossary.md` | `glossary.md` |
| Format-compatibility appendices for canonicalization, detached artifact handling, and vectors | `docs/appendices/` | `format-spec.md` remains the primary owner for format semantics; active appendices carry compatibility detail and may own bounded delegated semantics when a core owner doc says so |
| Contributor process and doc hygiene | `docs/README.md`, `docs/process/DOCS-WRITING.md` | `docs/README.md` |
| Contributor-only cross-app engineering reference material | `docs/series/SERIES-STANDARTS.md` | Contributor reference only; published Quantum Vault docs cite standards and implementation directly |
| Contributor-only cross-app UX and interface terminology guidance | `docs/series/UX-STYLE-SERIES.md` | Contributor reference only; Quantum Vault-specific product terms remain owned by `glossary.md` and the product docs |

## Current document map

| File | Role now | Current state |
| --- | --- | --- |
| `README.md` | Product landing page | Active |
| `docs/README.md` | Documentation control point | Release Candidate |
| `docs/glossary.md` | Shared vocabulary and status-term baseline | Release Candidate |
| `docs/WHITEPAPER.md` | Informative system-level design and rationale doc | Release Candidate |
| `docs/format-spec.md` | Normative format/verifier doc | Release Candidate |
| `docs/schema/` | Machine-readable JSON Schema grammar layer and fixture corpus for the shipped successor-family artifacts (`qv-archive-state-descriptor-v1`, `qv-cohort-binding-v1`, `qv-lifecycle-bundle-v1`, `qv-transition-record-v1`, `qv-source-evidence-v1`) plus retained historical schema files | Release Candidate |
| `docs/process/roadmap/lifecycle/` | Historical successor transition roadmap, resharing rationale, and frozen design record | Historical; phases 0-7 implemented, later phases deferred; not normative for bytes |
| `docs/process/roadmap/manifest-canonisation/` | Historical pre-successor planning baseline | Historical — completed baseline; superseded by the shipped successor-family design |
| `docs/appendices/canonicalization-profile.md` | Compatibility appendix for current canonicalization labels | Release Candidate |
| `docs/appendices/external-artifacts.md` | Compatibility appendix for detached artifact acceptance/linkage; owner appendix for bounded OTS completeness/linkage-vs-completeness semantics | Release Candidate |
| `docs/appendices/interoperability-and-test-vectors.md` | Compatibility appendix for examples, vectors, and malformed coverage | Release Candidate |
| `docs/trust-and-policy.md` | Normative policy/pinning doc | Release Candidate |
| `docs/security-model.md` | Normative threat/invariants doc | Release Candidate |
| `docs/long-term-archive.md` | Mixed archival/roadmap doc | Release Candidate |
| `docs/process/DOCS-WRITING.md` | Contributor guidance | Secondary process guide |
| `docs/process/IMPLEMENTATION-NOTES.md` | Contributor successor-family design and codebase guide | Secondary contributor reference |
| `docs/series/SERIES-STANDARTS.md` | Cross-app engineering/security reference | Unpublished contributor reference |
| `docs/series/UX-STYLE-SERIES.md` | Cross-app UX/terminology reference | Unpublished contributor reference; Quantum Vault-specific terms defer to `docs/glossary.md` and the owner docs |
| `docs/internal/` | Internal research, consolidation records, and preserved backup docs | Unpublished working material |

## Current structure

```text
README.md

docs/
  README.md
  glossary.md
  WHITEPAPER.md
  format-spec.md
  schema/
    qv-common-types.schema.json
    qv-archive-state-descriptor-v1.schema.json
    qv-cohort-binding-v1.schema.json
    qv-lifecycle-bundle-v1.schema.json
    qv-transition-record-v1.schema.json
    qv-source-evidence-v1.schema.json
    archive/
      README.md                    # historical schema material retained for reference
      qv-manifest-v3.schema.json
      qv-manifest-bundle-v2.schema.json
    fixtures/
      index.json
  process/roadmap/lifecycle/
    roadmap-archive-lifecycle.md
    implementation-questions-and-reading.md
    resharing-design.md
    implementation-plan-lifecycle.md
  process/roadmap/manifest-canonisation/
    RFC8785-stageA.md
    json-schema-stageB.md
    spec-layer-separation-stageC.md
  appendices/
    canonicalization-profile.md
    external-artifacts.md
    interoperability-and-test-vectors.md
  trust-and-policy.md
  security-model.md
  long-term-archive.md
  process/
    DOCS-WRITING.md
    IMPLEMENTATION-NOTES.md
  series/
    SERIES-STANDARTS.md
    UX-STYLE-SERIES.md
```
