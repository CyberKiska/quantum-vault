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
* Current `docs/series/SERIES-STANDARTS.md` style and assumptions

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
* OAIS/PDI language from the research basis 

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
* **`docs/series/`** holds cross-app standards and UX guidance; it may standardize labels, but it should not redefine Quantum Vault product terms incompatibly with `docs/glossary.md` and the owner docs.
* **`docs/internal/`** holds internal research and planning history.

### Why

This prevents duplication and contradictions.

# Recommended reference discipline for each document

To keep the set clean, we would use the following rule:

## `docs/WHITEPAPER.md`

Use:

* standards + papers
* `README.md` as the user-facing product description
* the four core docs as the stabilized explanation inputs
* Internal research reports as synthesis/background input

## `docs/security-model.md`

Use:

* `docs/series/SERIES-STANDARTS.md`
* current `README.md` behavior
* standards directly
* Internal research reports where it frames threat objectives or long-horizon risks

## `docs/format-spec.md`

Use:

* `README.md` and implementation code behavior as the source of truth for current formats
* `docs/series/SERIES-STANDARTS.md` for global encoding, fail-closed, and primitive-usage rules
* standards only for primitive constraints, not for container semantics

## `docs/long-term-archive.md`

Use:

* OAIS / ISO 16363
* RFC 3161 / RFC 4998
* Haber–Stornetta lineage
* Internal research reports as the main synthesis layer
* current `README.md` and the core docs only to distinguish current state from target state

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

That guidance still fits the project well: `README.md` describes the implemented workflow and artifact set, `docs/series/SERIES-STANDARTS.md` remains one of the early architectural documents that establishes client-only and fail-closed engineering rules, `docs/series/UX-STYLE-SERIES.md` remains an early UX/terminology document, and internal research reports captures the long-horizon security and archival direction.
