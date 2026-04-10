# Documentation writing guide

Status: Draft
Type: Informative
Audience: Contributors, maintainers, reviewers
Scope: Contributor guidance for writing and updating the current Quantum Vault document set
Out of scope: Normative format, policy, or security definitions

`docs/README.md` is the active documentation control point.
This file is contributor guidance and drafting support, not the top-level source of truth for document ownership.

Use this file to keep drafting discipline consistent with the current repository structure.

## 1. Document status taxonomy

Every document should begin with:

* **Status**: Draft / Proposed / Stable / Deprecated
* **Type**:

  * **Normative**: binding rules for implementation or verification
  * **Informative**: rationale, background, design explanation
* **Audience**:

  * users,
  * implementers,
  * auditors,
  * external cryptographers,
  * archivists
* **Scope boundaries**
* **Out of scope**
* **Relationship to other docs**

### Why

Without this, the same statement will drift between “must implement”, “design intent”, and “future idea”.

### Touches

Entire documentation stack.

### References

* RFC 2119 / RFC 8174 terminology for MUST/SHOULD language
* `docs/README.md` control rules and the current owner-doc conventions

---

## 2. Controlled vocabulary

`docs/glossary.md` is now the shared vocabulary home for the Quantum Vault docs set.
When a core term meaning changes, update `docs/glossary.md` first and update the owning document in the same change.

The glossary currently covers the term families that were previously repeated across multiple drafts:

* artifact and format terms
* status, trust, and evidence terms
* archival and lifecycle terms
* role terms
* identifier and commitment terms
* key terminology (`privateKey`, `publicKey`, `secretKey`)

### Why

Quantum Vault already mixes product language, crypto language, and archival language. A glossary prevents ambiguity.

### Touches

All docs, especially `format-spec.md`, `long-term-archive.md`, `trust-and-policy.md`.

### References

* `docs/glossary.md`
* Current README artifact model and policy vocabulary
* OAIS/PDI language from `docs/long-term-archive.md` and the primary archival standards

---

## 3. Cross-document division of labor

The current repository already has a documentation control point in `docs/README.md`.
Contributor writing should follow these active boundaries:

* **`README.md`** is the product-facing landing page.
* **`docs/glossary.md`** defines shared vocabulary and status terms used across the Quantum Vault docs set.
* **`docs/WHITEPAPER.md`** explains and justifies the design.
* **`docs/security-model.md`** defines adversaries, assumptions, invariants, failure semantics, and claim boundaries.
* **`docs/format-spec.md`** defines bytes, fields, schemas, bindings, and verifier behavior.
* **`docs/trust-and-policy.md`** defines signature semantics, pinning, policy levels, proof counting, and restore authorization meaning.
* **`docs/long-term-archive.md`** defines archival classes, OAIS mapping, renewal, migration, and long-horizon direction.
* **`docs/process/`** is contributor/process guidance, not a normative product-doc surface.
* **`docs/series/`** and **`docs/internal/`** are contributor/internal working material. They may help drafting, but published Quantum Vault docs should cite standards, primary research, and implementation code directly rather than treating those folders as authority.

### Why

This prevents duplication and contradictions.

## 3.1 Published-doc source policy

When writing or revising the published Quantum Vault docs:

* cite primary standards and specifications directly
* cite primary research only when it supports a current implementation claim, a current security/archival claim, or a bounded whitepaper rationale point
* cite implementation modules directly when describing shipped behavior

## 4. Doc invariants to preserve

When updating the current owner docs, preserve the following implementation-boundary text and distinctions unless the code, schema, and owner docs are intentionally changing together:

* successor-only scope for the current shipped artifact family
* archive-state descriptor versus lifecycle bundle
* archive approval versus maintenance signatures versus source-evidence signatures versus OTS evidence
* fail-closed ambiguity handling during restore
* explicit operator selection as a warning-bearing override, not an automatic winner selection
* source-evidence privacy posture as defined by the current schema
* no overclaiming around evidence renewal or long-term time-proof capabilities

Reference-discipline rule:

* prefer explicit artifact names such as `QVqcont-7`, `quantum-vault-archive-state-descriptor/v1`, and `QV-Lifecycle-Bundle` v1 over abstractions like "current track", "current signable object", or "current artifact family" unless the wording is clearly marked as historical comparison

# Recommended reference discipline for each document

To keep the set clean, we would use the following rule:

## `docs/WHITEPAPER.md`

Use:

* standards + papers
* `README.md` as the user-facing product description
* the core owner docs as stabilized explanation inputs
* implementation code where rationale needs to stay honest about current behavior

## `docs/security-model.md`

Use:

* implementation code and current `README.md` behavior
* standards directly
* selected primary research only for bounded threat or implementation-risk discussion

## `docs/format-spec.md`

Use:

* `README.md` and implementation code behavior as the source of truth for current formats
* standards only for primitive constraints, not for container semantics

## `docs/long-term-archive.md`

Use:

* OAIS / ISO 16363
* RFC 3161 / RFC 4998
* Haber–Stornetta lineage
* current `README.md` and the core docs only to distinguish current state from target state
* implementation code where the current evidence or restore behavior needs to be described precisely

## `docs/trust-and-policy.md`

Use:

* current `README.md` policy behavior
* implementation behavior and status vocabulary
* `docs/security-model.md` for trust assumptions and residual-risk boundaries
* `docs/long-term-archive.md` only when policy intersects with long-horizon archival questions

---

# Current writing order guidance

The original bootstrap recommendation for this repository was:

1. `security-model.md`
2. `format-spec.md`
3. `trust-and-policy.md`
4. `long-term-archive.md`
5. `WHITEPAPER.md`

That order was useful because:

* the **security model** defines what the system is trying to guarantee,
* the **format spec** defines how those guarantees are instantiated,
* the **trust/policy** doc defines what signatures and policy decisions mean,
* the **long-term archive** doc defines preservation and renewal over time,
* the **whitepaper** should be written last, because it explains the already-stabilized design rather than inventing it mid-stream.

For the current repository state, the first four already have draft baselines.
The main remaining authored target is `docs/WHITEPAPER.md`, and most future work should update the existing owner docs rather than restart the bootstrap order.

### Normative vs Informative Sections

- Normative: MUST/SHALL, protocol invariants, format constraints
- Informative: rationale, examples, threat discussion

That guidance still fits the project well: `README.md` describes the implemented workflow and artifact set, the owner docs define the published semantics, and published claims should be grounded in standards, primary research, and implementation code. Contributor-only material in `docs/series/` and `docs/internal/` may still help drafting, but it should not be cited as normative authority in the published Quantum Vault docs.
