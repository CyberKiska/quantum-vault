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
- `docs/process/` and `docs/series/` are support/reference material, not the primary product doc surface
- `docs/internal/` is internal-only working material and planning history; it is not treated as published product documentation

Publication note:

- `docs/internal/` and `examples/` are excluded from published releases via `.gitignore`
- internal planning material has been absorbed into the published owner docs and is not referenced as required reading in the release surface

Current release status:

- the documentation set covers two coexisting artifact tracks: the legacy manifest/bundle family and the successor lifecycle family
- the regular-user product surface now creates successor lifecycle archives by default in both Lite and Pro
- beginning with v1.5.3, legacy manifest/bundle creation became compatibility-only rather than a normal product path on the shipped UI surface
- legacy manifest/bundle creation is no longer a normal product path; legacy attach/restore material remains compatibility-only during the documented phase-out window
- current published docs MUST distinguish implemented now, shipped-but-legacy, and future-only material explicitly; deferred work such as RFC 4998-style renewal, state-changing continuity records, and governance objects MUST remain clearly non-current

Current product surfaces:

- Lite: regular-user successor archive creation/export of `.qcont`, `*.archive-state.json`, and `*.lifecycle-bundle.json`, successor restore, and explicit ambiguity resolution when successor archive/state/cohort or lifecycle-bundle selection is required
- Pro: all Lite successor workflows plus standalone `*.cohort-binding.json` export, explicit successor artifact export/attach/inspection, and same-state resharing controls
- Legacy: compatibility-only attach/restore/documentation for previously created legacy archives; no normal legacy creation path remains on the shipped UI surface

Current release-gate note:

- automated release-gate coverage for successor-default build/export, mixed legacy/successor rejection, same-state cohort ambiguity, and lifecycle-bundle ambiguity currently lives in `src/core/crypto/selftest.js`
- a dedicated headless browser harness is not yet part of the repo; until one lands, maintainers MUST manually verify before release that Lite and Pro restore/reshare actions remain disabled until required successor selections are made, mixed legacy/successor input shows the blocking compatibility message, and successor-first labels remain on the create/build/attach surface

## Control rules

1. One topic, one home.
   A topic may be summarized elsewhere, but only one document owns its normative definition.

2. The core destination docs are:
   `README.md`, `glossary.md`, `WHITEPAPER.md`, `format-spec.md`, `trust-and-policy.md`, `security-model.md`, `long-term-archive.md`.

   Format-compatibility appendices that are actively referenced by `format-spec.md` live under `docs/appendices/`.
   They are support docs, not separate semantic owner docs.

3. Distinguish published docs from internal material.
   Files in `docs/internal/` are internal references and planning artifacts, not authoritative product docs.

4. Distinguish current behavior from future direction.
   Every core doc should label statements as implemented now, required for compatibility now, or recommended future direction.

5. Shared vocabulary lives in `docs/glossary.md`.
   If a core term meaning changes, update the glossary and the owning document in the same change.

## Current source-of-truth map

| Topic | Working source now | Destination owner |
| --- | --- | --- |
| Product overview and workflow | `README.md` | `README.md` + `WHITEPAPER.md` |
| Artifact formats, canonicalization, verifier flow (legacy manifest bundle and successor lifecycle) | `format-spec.md` | `format-spec.md` |
| Successor lifecycle design history and Phase 0 frozen contracts (informative) | `docs/process/roadmap/lifecycle/` | Informative only; normative bytes/policy remain in `format-spec.md` and `trust-and-policy.md` |
| Archive policy, proof counting, pinning, role semantics | `trust-and-policy.md` | `trust-and-policy.md` |
| Threat model, assumptions, invariants, claim boundaries | `security-model.md` | `security-model.md` |
| Archive classes, OAIS mapping, renewal, migration | `long-term-archive.md` | `long-term-archive.md` |
| Shared vocabulary, key terminology, and status terms | `glossary.md` | `glossary.md` |
| Format-compatibility appendices for canonicalization, detached artifact handling, and vectors | `docs/appendices/` | `format-spec.md` owns the semantics; `docs/appendices/` carries active compatibility detail |
| Contributor process and doc hygiene | `docs/README.md`, `docs/process/DOCS-WRITING.md` | `docs/README.md` |
| Cross-app engineering standards | `docs/series/SERIES-STANDARTS.md` | `docs/series/` reference set |
| Cross-app UX and interface terminology guidance | `docs/series/UX-STYLE-SERIES.md` | `docs/series/` reference set; Quantum Vault-specific product terms remain owned by `glossary.md` and the product docs |

## Current document map

| File | Role now | Current state |
| --- | --- | --- |
| `README.md` | Product landing page | Active |
| `docs/README.md` | Documentation control point | Release Candidate |
| `docs/glossary.md` | Shared vocabulary and status-term baseline | Release Candidate |
| `docs/WHITEPAPER.md` | Informative system-level design and rationale doc | Release Candidate |
| `docs/format-spec.md` | Normative format/verifier doc | Release Candidate |
| `docs/schema/` | Machine-readable JSON Schema grammar layer and fixture corpus for manifest-family and **successor lifecycle** artifacts (`qv-archive-state-descriptor-v1`, `qv-cohort-binding-v1`, `qv-lifecycle-bundle-v1`, `qv-transition-record-v1`, `qv-source-evidence-v1`, plus manifest schemas) | Release Candidate |
| `docs/process/roadmap/lifecycle/` | Informative lifecycle roadmap, resharing design, implementation plan | Active; not normative for bytes |
| `docs/appendices/canonicalization-profile.md` | Compatibility appendix for current manifest and bundle canonicalization labels | Release Candidate |
| `docs/appendices/external-artifacts.md` | Compatibility appendix for detached artifact acceptance/linkage | Release Candidate |
| `docs/appendices/interoperability-and-test-vectors.md` | Compatibility appendix for examples, vectors, and malformed coverage | Release Candidate |
| `docs/trust-and-policy.md` | Normative policy/pinning doc | Release Candidate |
| `docs/security-model.md` | Normative threat/invariants doc | Release Candidate |
| `docs/long-term-archive.md` | Mixed archival/roadmap doc | Release Candidate |
| `docs/process/DOCS-WRITING.md` | Contributor guidance | Secondary process guide |
| `docs/process/IMPLEMENTATION-NOTES.md` | Contributor design-history and codebase guide | Secondary contributor reference |
| `docs/series/SERIES-STANDARTS.md` | Cross-app engineering/security reference | Draft reference |
| `docs/series/UX-STYLE-SERIES.md` | Cross-app UX/terminology reference | Draft reference; Quantum Vault-specific terms defer to `docs/glossary.md` and the owner docs |
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
    qv-manifest-v3.schema.json
    qv-manifest-bundle-v2.schema.json
    qv-archive-state-descriptor-v1.schema.json
    qv-cohort-binding-v1.schema.json
    qv-lifecycle-bundle-v1.schema.json
    qv-transition-record-v1.schema.json
    qv-source-evidence-v1.schema.json
    fixtures/
      index.json
  process/roadmap/lifecycle/
    resharing-design.md
    implementation-plan-lifecycle.md
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
