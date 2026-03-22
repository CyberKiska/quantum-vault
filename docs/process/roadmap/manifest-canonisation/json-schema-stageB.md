# Quantum Vault Roadmap B — JSON Schema Structural Validation

Status: Draft roadmap  
Type: Informative planning document  
Audience: implementers, spec authors, tooling maintainers, auditors

## 1. Purpose

This roadmap covers the introduction of a formal schema / grammar layer for Quantum Vault manifest-family artifacts using JSON Schema (draft 2020-12).

It is intended to standardize the structure of current JSON artifacts without changing the fact that canonical detached-signature payloads are defined separately by canonicalization rules (Roadmap A / RFC 8785).

## 2. Why JSON Schema instead of CDDL

An earlier draft of this roadmap proposed RFC 8610 (CDDL) as the schema language. JSON Schema was chosen instead for the following reasons:

- **Cross-implementation tooling.** Quantum Vault has both a JavaScript implementation and a Rust parser. JSON Schema has mature, well-maintained validators in both languages — `ajv` for JavaScript and the `jsonschema` crate for Rust. CDDL has no mature validator in either language; the primary tool is a Ruby gem, which would be a foreign dependency for both implementations.
- **Developer familiarity.** JSON Schema is widely known. Contributors to either the JS or Rust codebase will recognize `.schema.json` files without explanation. CDDL requires a separate specification to read and a learning curve for most developers.
- **Ecosystem fit.** JSON Schema files are themselves JSON. They integrate with IDE auto-completion, inline validation, and existing CI tooling without additional infrastructure.
- **QV artifacts are pure JSON.** CDDL was designed primarily for CBOR, with JSON as a secondary target. Its CBOR-native features (tags, major types, byte string qualifiers) are irrelevant to QV.

JSON Schema is not an IETF RFC. It was previously published as IETF Internet-Drafts but has moved to independent publication. This is a minor standards-credibility gap, but JSON Schema is a de facto industry standard with massive adoption and specification stability.

## 3. Current Quantum Vault baseline

The current QV docs already describe:

- a canonical manifest with schema/version `quantum-vault-archive-manifest/v2`
- a mutable manifest bundle `QV-Manifest-Bundle` v1
- procedural validation in code (`archive-manifest.js`, `manifest-bundle.js`)
- no current machine-readable formal schema language for manifest or bundle validation

Internal QV grounding to review before implementation:

- `docs/format-spec.md`
- `docs/WHITEPAPER.md`
- `README.md`
- `docs/trust-and-policy.md`
- `src/core/crypto/manifest/archive-manifest.js`
- `src/core/crypto/manifest/manifest-bundle.js`

## 4. Why a formal schema layer matters

With multiple implementations (JavaScript and Rust) parsing the same wire format, a machine-readable schema serves as an interoperability contract. Its value is:

- a shared structural definition that both implementations validate against
- explicit required vs optional fields
- explicit value domains (enums, patterns, integer ranges)
- machine-checkable artifact constraints
- clearer extension policy (closed canonical manifest vs selectively open bundle)
- documentation quality for auditors and external implementers

## 5. Relevant external sources

Primary:
- JSON Schema draft 2020-12 (latest stable): https://json-schema.org/draft/2020-12
  - Core specification: schema identification, composition, `$ref`, `$defs`, vocabulary system
  - Validation specification: `type`, `properties`, `required`, `enum`, `pattern`, `additionalProperties`, `minimum`/`maximum`, `format`
- RFC 8259 — JSON syntax baseline: https://www.rfc-editor.org/rfc/rfc8259.txt
- RFC 7493 — I-JSON constraints relevant to JSON compatibility: https://www.rfc-editor.org/rfc/rfc7493.txt

Key JSON Schema capabilities relevant to QV:
- `additionalProperties: false` — enforces closed objects (no unknown fields)
- `pattern` — constrains string formats (hex-encoded digests, identifiers)
- `enum` — constrains string values to known sets (policy levels, formats, encodings)
- `minimum` / `maximum` / `type: "integer"` — constrains numeric fields
- `$ref` / `$defs` — shared type definitions across schema files
- `required` — explicit required field lists

## 6. Recommended scope

### In scope for this roadmap
- canonical manifest grammar
- manifest bundle grammar
- attachment entry grammar for signatures, public keys, timestamps
- explicit required vs optional fields
- extension-point policy (closed manifest, controlled bundle)
- validation tooling direction (JS + Rust)
- documentation integration

### Out of scope for this roadmap
- binary `.qenc` and `.qcont` byte layout description
- archive continuity semantics
- timestamp renewal semantics
- governance object design
- OAIS package envelope design

## 7. Recommended implementation direction

### Phase B1 — Inventory current artifact shapes

Before writing schemas:

- inventory current manifest fields from `format-spec.md` and `archive-manifest.js`
- inventory current bundle fields and attachment arrays from `manifest-bundle.js`
- inventory current policy object shape
- inventory current known enums, string identifiers, and digest encodings
- mark which fields are normative today vs provisional or future

### Phase B2 — Write JSON Schema for canonical manifest

Per the C-lite baseline, this schema targets the next closed manifest baseline rather than the current open acceptance model.

Create `docs/schema/qv-manifest-v3.schema.json` covering:

- `schema`, `version`, `manifestType`
- `canonicalization`
- `cryptoProfileId`, `kdfTreeId`
- `noncePolicyId`, `nonceMode`, `counterBits`, `maxChunkCount`
- `aadPolicyId`
- `qenc` object (format, aeadMode, ivStrategy, chunkSize, chunkCount, payloadLength, hash fields, containerId, primaryAnchor)
- `sharding` object (shamir, reedSolomon)
- `shardBinding` object (optional; bodyDefinitionId, shardBodyHashes, shareCommitments)
- `authPolicyCommitment` object

The canonical manifest schema must use `additionalProperties: false` at every object level. Unknown fields in the signed object are a signature-safety hazard.

Recommended discipline:
- represent digest strings with `pattern: "^[0-9a-f]+$"` and appropriate length constraints
- constrain integers with `minimum` / `maximum` where the code enforces bounds
- use `enum` for known string identifiers
- keep the first pass conservative and close to current code behavior

### Phase B3 — Write JSON Schema for manifest bundle

Per the C-lite baseline, the current mutable bundle remains structurally closed even though its content evolves over time.

Create `docs/schema/qv-manifest-bundle-v2.schema.json` covering:

- `type`, `version`
- `bundleCanonicalization`, `manifestCanonicalization`
- embedded `manifest` (referencing the manifest schema via `$ref`)
- `manifestDigest` object
- `authPolicy` object
- `attachments` object:
  - `publicKeys[]` — id, kty, suite, encoding, value, legacy
  - `signatures[]` — id, format, suite, target, signatureEncoding, signature, publicKeyRef, legacy
  - `timestamps[]` — id, type, targetRef, proofEncoding, proof, apparentlyComplete, completeProof

The bundle schema should be closed at the top level and within current attachment entry objects.
Bundle mutability is expressed by changing values and by adding more entries to the existing arrays, not by leaving current objects open to unknown fields.

### Phase B4 — Write shared type definitions

Create `docs/schema/qv-common-types.schema.json` with `$defs` for:

- digest strings (hex-encoded, specific lengths for SHA3-512 / SHA3-256)
- algorithm identifiers
- policy level enum
- signature format enum
- signature suite identifiers
- public key encoding enum
- constrained integer ranges (minimum share counts, chunk counts)

Both the manifest and bundle schemas reference these shared definitions via `$ref`.

### Phase B5 — Define extension policy using schema constraints

- **Canonical manifest**: strictly closed (`additionalProperties: false` at all levels). Unknown fields are forbidden. This is the signature-safety rule expressed as a machine-checkable constraint.
- **Bundle core fields**: closed. `type`, `version`, `bundleCanonicalization`, `manifestCanonicalization`, `manifest`, `manifestDigest`, `authPolicy` have fixed shapes.
- **Bundle attachment arrays**: item shapes are closed, but the arrays themselves can grow in length over time with more entries of the defined item schemas.
- **Future extension**: adding new top-level fields to the canonical manifest requires a new `schema`/`version`. Adding new attachment object fields or new attachment families to the bundle requires a new bundle schema/version unless a future explicit `extensions` namespace is introduced.

### Phase B6 — Connect schemas to validation tooling

Validation must run in both implementation languages:

- **JavaScript**: validate test fixtures and example instances against schemas using `ajv` (or a lighter JSON Schema 2020-12 validator) in CI
- **Rust**: future independent implementations should validate against the same schema files using the `jsonschema` crate or equivalent validator
- A fixture that passes one implementation must pass the other

A strong intermediate milestone is:
- schema files live in `docs/schema/`
- example manifest and bundle fixtures validate against them in JS CI immediately; non-JS consumers reuse the same files and vectors later
- docs reference the schemas as the formal grammar layer

## 8. Important caveats

JSON Schema is not a substitute for canonicalization or semantic validation.

The docs should explicitly state:

- RFC 8785 governs exact signable bytes (Layer 1 — serialization)
- JSON Schema governs structure / grammar / validation shape (Layer 2 — schema)
- semantic meaning (what fields mean, what changes require new signatures, what policy commitment means) still lives in the format and policy specification (Layer 3 — semantics)

JSON Schema should be treated as one layer in a stack, not as a complete spec by itself. "Schema-valid" does not mean "canonical" and does not mean "safe to verify" or "safe to restore."

## 9. Key design decisions to settle

- Should the canonical manifest permit any unknown extension fields at all? **Recommended: no.** `additionalProperties: false` everywhere in the manifest schema.
- Should current bundle objects be open under implicit extension points? **Recommended: no.** Current bundle objects remain closed; future extensibility should use a new schema/version or a future explicit `extensions` namespace.
- Should QV maintain one monolithic schema file or separate files per artifact family? **Recommended: separate files** — `qv-manifest-v3.schema.json`, `qv-manifest-bundle-v2.schema.json`, `qv-common-types.schema.json`.
- Should detached-signature wrapper metadata be fully described in JSON Schema, or only bundle-carried references to them? **Recommended: bundle-carried references only** — detached signatures are binary containers, not JSON.
- Should JSON number fields be restricted to I-JSON-safe ranges in the schema? **Recommended: constrain integers with `minimum` / `maximum` where implementation limits exist** (e.g., chunk counts, share counts).

## 10. Risks and pitfalls

- writing schemas that are looser than the actual code validation
- writing schemas that are so strict they block legitimate future evolution
- assuming schema validity implies canonical bytes
- allowing extension rules to weaken detached-signature invariants via unknown manifest fields
- forgetting JSON-specific number limitations (all numbers are IEEE 754 doubles)
- defining fields in docs and code but not keeping schemas in sync
- treating advisory examples as normative grammar
- schema drift between JavaScript and Rust — both must validate against the same schema files

## 11. Concrete deliverables

Recommended deliverables for this track:

1. `docs/schema/qv-manifest-v3.schema.json`
2. `docs/schema/qv-manifest-bundle-v2.schema.json`
3. `docs/schema/qv-common-types.schema.json` (shared `$defs` for digests, identifiers, enums, constrained integers)
4. Documentation section in `format-spec.md`:
   - "formal grammar layer"
   - "how JSON Schema relates to canonicalization"
5. CI validation step: fixtures validated against schemas in JavaScript immediately, with the same schema and fixture corpus reused by future non-JS implementations
6. Example valid and invalid instances

## 12. Suggested implementation order

A practical order:

1. canonical manifest schema (closed, strict)
2. shared type definitions
3. bundle schema (closed current structure, closed current attachment item shapes)
4. attachment entry schemas (publicKeys, signatures, timestamps)
5. CI validation from JavaScript
6. future non-JS consumer validation against the same schema and fixture corpus
7. docs alignment pass

## 13. Definition of done

This roadmap is complete when Quantum Vault has:

- machine-readable JSON Schema files for current manifest-family artifacts
- documentation that points to them as the formal grammar layer
- CI validation of fixtures in JavaScript, with the same schema and fixture corpus ready for reuse by future non-JS implementations
- a clear extension policy: canonical manifest closed, current bundle grammar closed
- a maintained mapping between spec text, code behavior, and schema files

## 14. Reference links

- JSON Schema draft 2020-12: https://json-schema.org/draft/2020-12
- JSON Schema Core: https://json-schema.org/draft/2020-12/json-schema-core.html
- JSON Schema Validation: https://json-schema.org/draft/2020-12/json-schema-validation.html
- RFC 8259: https://www.rfc-editor.org/rfc/rfc8259.txt
- RFC 7493: https://www.rfc-editor.org/rfc/rfc7493.txt
- ajv (JavaScript validator): https://ajv.js.org/
- jsonschema (Rust crate): https://docs.rs/jsonschema
