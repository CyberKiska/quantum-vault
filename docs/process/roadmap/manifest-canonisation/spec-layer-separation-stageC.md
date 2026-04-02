# Quantum Vault Roadmap C — Separate Serialization, Schema, and Semantics

Status: Draft roadmap  
Type: Informative planning document  
Audience: spec authors, implementers, reviewers, auditors

## 1. Purpose

This roadmap covers a documentation and specification refactor: clearly separating three distinct layers in Quantum Vault manifest-family design:

1. **Serialization rules** — exact bytes
2. **Schema / grammar rules** — structural validity
3. **Semantic rules** — what fields mean and what changes are or are not allowed

This separation is already latent in the project, but not yet fully formalized as an explicit standards-oriented design discipline.

## 2. Why this matters

Many interoperability and archival-spec errors come from mixing these three layers together.

Examples of common confusion:
- valid JSON vs canonical JSON
- schema-valid manifest vs semantically acceptable manifest
- mutable bundle change vs signature-payload change
- display order in docs vs canonical key order in bytes
- parser acceptance vs verifier semantics

Quantum Vault already has a strong foundation for separating these concerns:
- detached signatures target canonical manifest bytes only
- the canonical manifest is immutable once created
- the bundle is mutable and carries policy/evidence context
- `authPolicyCommitment` binds semantic policy expectations from canonical manifest to concrete bundle policy

This roadmap makes that discipline explicit.

## 3. Current Quantum Vault baseline to preserve

Current documented invariants include:

- detached signatures sign canonical manifest bytes only
- bundle mutation must not mutate canonical manifest bytes
- `manifestDigest` must match canonical manifest bytes embedded in the bundle
- `authPolicyCommitment` in the manifest must match the concrete `authPolicy` in the bundle
- verifiers must reject unknown unsupported canonicalization labels
- current display order in documentation is explanatory only; canonical key order is determined by the canonicalization profile

Internal QV grounding to review before implementation:

- `docs/format-spec.md`
- `docs/trust-and-policy.md`
- `docs/WHITEPAPER.md`
- `README.md`

## 4. Recommended specification stack

### Layer 1 — Serialization rules
This layer should answer:

- what exact bytes are signed?
- how are canonical bytes produced?
- what is the canonicalization label?
- what are the UTF-8 / ordering / whitespace / primitive serialization rules?
- what malformed values must be rejected?

Recommended standards anchor:
- RFC 8785 for canonical JSON bytes (after migration away from `QV-C14N-v1`)

### Layer 2 — Schema / grammar rules
This layer should answer:

- which fields are required?
- which are optional?
- what value domains are allowed?
- what shapes do nested objects and attachment entries have?
- what extension points exist?
- is the canonical manifest closed (no unknown fields) or open?

Recommended standards anchor:
- JSON Schema (draft 2020-12): https://json-schema.org/draft/2020-12

### Layer 3 — Semantic rules
This layer should answer:

- what each field means
- what object is the detached-signature payload
- what changes preserve archive description and what changes do not
- what bundle mutation means
- what policy commitment means
- what restore or verifier behavior is required

Recommended source of truth:
- `format-spec.md`
- `trust-and-policy.md`
- `security-model.md`
- future lifecycle / archive-identity docs

## 5. C-lite design baseline

The following decisions are adopted as the short first-step baseline for subsequent Roadmap A and B work.
They are intentionally conservative and fail closed.

### 5.1 Closed canonical-manifest policy

- the canonical manifest is **closed**
- unknown fields are forbidden at every object level
- future manifest fields require a new manifest schema/version
- verifier acceptance must not treat unknown signed fields as harmless, because a signature over ignored fields is not safely interpretable

Decision:

- the next standards-aligned canonical manifest baseline should be emitted under a new manifest schema/version rather than reusing the current open acceptance model

### 5.2 Bundle extension policy

- bundle mutability is about **content evolution**, not grammar openness
- current bundle top-level structure is **closed**
- current attachment entry shapes are **closed**
- attachment arrays may grow in length over time with more entries of the currently defined shapes
- new bundle top-level fields, new attachment object fields, or new attachment families require a new bundle schema/version

Decision:

- do not use broad `additionalProperties` or implicit extension points in the current bundle generation
- if a future extensibility channel is needed, introduce it explicitly under a dedicated `extensions` namespace in a future bundle version rather than silently opening current objects

### 5.3 Canonicalization scope

- RFC 8785 migration is driven by the signable byte surface first
- detached signatures cover canonical manifest bytes only
- `authPolicyCommitment` is also byte-sensitive and should use the same standards-aligned JSON canonicalization profile as the manifest
- bundle serialization is important for deterministic export and validation, but it is not itself the detached-signature payload

Decision:

- the first standards-aligned canonicalization migration applies to:
  - canonical manifest bytes
  - `authPolicyCommitment` input canonicalization
  - bundle `manifestCanonicalization` metadata that identifies the embedded manifest byte profile
- the mutable bundle's own serialization profile remains a separate concern and must not drive or delay the signable-manifest migration

### 5.4 Version and label taxonomy

Adopt a role-specific taxonomy rather than one shared label across all JSON contexts.

Decision:

- canonical manifest schema/version target: `quantum-vault-archive-manifest/v3`
- canonical manifest `canonicalization` label target: `QV-JSON-RFC8785-v1`
- `authPolicyCommitment.canonicalization` target: `QV-JSON-RFC8785-v1`
- manifest bundle type remains `QV-Manifest-Bundle`, but the next baseline target is `version = 2`
- bundle `manifestCanonicalization` target: `QV-JSON-RFC8785-v1`
- bundle `bundleCanonicalization` target: `QV-BUNDLE-JSON-v1`

Compatibility rule:

- changing canonical JSON byte rules requires a new canonicalization label
- changing artifact grammar requires a new schema/version
- for the planned next baseline, both occur together: the manifest moves to `v3`, the bundle moves to `v2`, and `QV-C14N-v1` is retired rather than kept as a long-lived accepted legacy profile

## 6. Recommended implementation/documentation direction

### Phase C1 — Record the C-lite decisions in the owner docs

Before a large documentation rewrite:

- record the closed-manifest policy
- record the closed current-bundle policy
- record the canonicalization scope split between manifest/policy-commitment bytes and bundle serialization
- record the version/label taxonomy above

This keeps later A/B implementation work from inheriting conflicting assumptions.

### Phase C2 — Rewrite the format-spec sections by layer
Recommended structure inside `format-spec.md`:

1. Artifact model
2. Serialization rules
3. Canonical manifest grammar
4. Bundle grammar
5. Semantic binding invariants
6. Verification and restore semantics
7. Compatibility and extension policy

This avoids embedding semantic claims inside field tables and avoids embedding byte-level rules inside rationale prose.

### Phase C3 — Make the “canonical manifest vs bundle” split more explicit
Add a dedicated section explaining:

- canonical manifest:
  - immutable
  - signable
  - signature payload
  - carries archive description at creation time

- manifest bundle:
  - mutable
  - carries concrete `authPolicy`
  - carries public keys, signatures, timestamps
  - does not redefine detached-signature payload
  - may evolve without invalidating signatures over the canonical manifest

This is already the QV design center and should remain the central documentation pattern.

### Phase C4 — State explicit compatibility rules
Recommended explicit statements:

- changing serialization rules requires a new canonicalization label
- changing artifact grammar may require a new schema/version
- changing field meaning may require a semantic version boundary even when JSON shape stays similar
- unknown fields must be handled according to layer-specific rules:
  - serialization layer
  - schema layer
  - semantic layer

### Phase C5 — Introduce normative language carefully
Use RFC 2119 / RFC 8174 language only where implementation behavior is truly intended to be binding.

Suggested references:
- RFC 2119: https://www.rfc-editor.org/rfc/rfc2119.txt
- RFC 8174: https://www.rfc-editor.org/rfc/rfc8174.txt

This is useful for:
- fail-closed parsing
- canonicalization label dispatch
- bundle-manifest consistency checks
- policy-commitment matching
- restore gating behavior

## 7. Questions this roadmap should answer

- What exact object is signed?
- What exact bytes are signed?
- Which spec layer defines that?
- Which fields are signature-relevant?
- Which fields are mutable over time?
- Which changes require new signatures?
- Which changes require a new schema/version?
- Which changes require only bundle updates?
- Which unknown fields are tolerated, and where?
- Which rules belong in docs vs code vs schema files?

## 8. Risks and pitfalls

- mixing semantic meaning into canonicalization rules
- letting documentation field order imply canonical key order
- allowing extension rules to weaken detached-signature invariants
- writing ambiguous language about what signatures do or do not prove
- using “schema-valid” as if it meant “safe to verify” or “safe to restore”
- creating duplicate sources of truth between prose spec, code, and schema files
- treating bundle mutability as justification for grammar openness
- reusing one canonicalization label across signed and unsigned JSON contexts with different compatibility needs

## 9. Concrete deliverables

Recommended deliverables for this track:

1. A short C-lite decision record embedded in this roadmap and reflected into `docs/format-spec.md`
2. A revised `docs/format-spec.md` structure with clearly separated layers
3. A short “specification stack” subsection in `README.md` or `glossary.md`
4. Cross-references:
   - serialization -> RFC 8785 profile
   - schema -> JSON Schema files (`docs/schema/*.schema.json`)
   - semantics -> format / trust / security docs
5. A compatibility matrix stating what kind of change requires:
   - new canonicalization label
   - new schema/version
   - new semantic version / policy documentation update
6. Explicit invariant list for:
   - canonical manifest immutability
   - bundle mutability boundaries
   - signature payload boundaries

## 10. Suggested document wording to preserve

Recommended preserved principle:

> Canonical bytes, structural validity, and semantic meaning are related but distinct layers and MUST NOT be conflated.

And specifically for QV:

> Detached signatures cover canonical manifest bytes only; bundle mutation is permitted only insofar as it does not alter those bytes or silently weaken committed policy semantics.

## 11. Definition of done

This roadmap is complete when Quantum Vault has:

- documentation that clearly separates bytes / schema / semantics
- fewer ambiguous statements about what signatures cover
- explicit compatibility rules for serialization vs grammar vs meaning
- cross-links from docs to canonicalization profile and JSON Schema files
- a spec structure that an external implementer (including the Rust parser) can follow without reading the JavaScript source code first

## 12. Reference links

- RFC 8785: https://www.rfc-editor.org/rfc/rfc8785.txt
- JSON Schema draft 2020-12: https://json-schema.org/draft/2020-12
- RFC 2119: https://www.rfc-editor.org/rfc/rfc2119.txt
- RFC 8174: https://www.rfc-editor.org/rfc/rfc8174.txt
