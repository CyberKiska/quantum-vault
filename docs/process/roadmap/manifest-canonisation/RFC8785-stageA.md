# Quantum Vault Roadmap A — RFC 8785 Canonical Manifest Standardization

Status: Historical — completed baseline; superseded by current successor-family design  
Type: Informative historical record  
Audience: implementers, reviewers, cryptography/documentation maintainers

Historical note:
This file records a completed pre-successor planning baseline. It is retained for background only and is not active execution guidance for the current runtime.

## 1. Purpose

This roadmap covers the migration of Quantum Vault canonical manifest serialization from the current project-defined `QV-C14N-v1` profile to a stricter RFC 8785-aligned canonical JSON model for signable manifest bytes.

It is intentionally a roadmap, not a final implementation commitment. The goal is to narrow the design space, identify implementation constraints, and define a safe migration path.

## 2. Current Quantum Vault baseline

The current documented baseline is:

- canonical manifest schema/version: `quantum-vault-archive-manifest/v2`
- canonicalization label: `QV-C14N-v1`
- the same canonical bytes are:
  - exported as `*.qvmanifest.json`
  - embedded into every `.qcont` shard
  - embedded into every manifest bundle
  - used as the detached-signature payload
- Quantum Vault explicitly does not claim that `QV-C14N-v1` is full RFC 8785
- repository docs already identify RFC 8785 as the likely future convergence target for canonical signable manifest bytes
- `authPolicyCommitment` also uses `QV-C14N-v1` internally — `computeAuthPolicyCommitment()` calls `canonicalizeJsonToBytes()` over the policy object and hashes the result; the commitment object carries its own `canonicalization: QV-C14N-v1` field
- the manifest bundle carries both `bundleCanonicalization` and `manifestCanonicalization` labels, both currently `QV-C14N-v1`

Internal QV grounding to review before implementation:

- `docs/format-spec.md`
- `docs/WHITEPAPER.md`
- `README.md`
- `src/core/crypto/manifest/archive-manifest.js`
- `src/core/crypto/manifest/manifest-bundle.js`
- `src/core/crypto/manifest/jcs.js`

## 3. Why RFC 8785 matters here

RFC 8785 (JSON Canonicalization Scheme, JCS) exists to make hashing and signing over JSON stable and repeatable across implementations. Its core value for Quantum Vault is that the canonical manifest is already the single detached-signature payload, so standardizing that byte representation improves:

- implementation (identical canonical bytes in one program) and cross-implementation interoperability (JavaScript and Rust parsers must produce identical canonical bytes)
- future verifier portability
- cross-language reproducibility
- archival representation clarity
- test-vector stability

For Quantum Vault, RFC 8785 is relevant specifically to the **canonical manifest bytes**, not to all JSON artifacts indiscriminately.

## 4. Relevant external sources

Primary:
- RFC 8785 — JSON Canonicalization Scheme (JCS): https://www.rfc-editor.org/rfc/rfc8785.txt
- RFC 7493 — The I-JSON Message Format: https://www.rfc-editor.org/rfc/rfc7493.txt
- RFC 8259 — The JSON Data Interchange Format: https://www.rfc-editor.org/rfc/rfc8259.txt
- ECMA-262 JSON serialization behavior (referenced by RFC 8785): https://tc39.es/ecma262/

Key RFC 8785 points to implement or explicitly account for:
- JCS builds on ECMAScript serialization of JSON primitives
- data must be adapted to the I-JSON subset
- object properties must be sorted recursively
- array order must not change
- whitespace must not be emitted
- output must be UTF-8
- duplicate property names are not allowed
- lone surrogates must raise an error
- NaN / Infinity must raise an error
- numbers follow ECMAScript-compatible serialization rules

## 5. Gap analysis: QV-C14N-v1 vs RFC 8785

Code inspection of `src/core/crypto/manifest/jcs.js` indicates the behavioral gap between `QV-C14N-v1` and RFC 8785 is narrow:

**Key sorting**: `Object.keys(obj).sort()` sorts by UTF-16 code-unit comparison. RFC 8785 Section 3.2.3 specifies "ascending order based on the UTF-16 encoding of the property name strings." These are identical for all strings, including those with supplementary-plane characters (surrogate pairs sort by high surrogate first in both cases). No behavioral change expected.

**Number serialization**: `JSON.stringify(value)` for finite numbers follows the ECMAScript `Number::toString` algorithm, which is exactly what RFC 8785 requires. No behavioral change expected for the numeric types QV actually uses (integers and small floats).

**String serialization**: `JSON.stringify(string)` follows ECMAScript `QuoteJSONString`, which is what RFC 8785 requires.

**Known gaps**:

1. **No lone-surrogate rejection.** RFC 8785 (via I-JSON / RFC 7493) requires rejection of strings containing lone surrogates. The current code passes strings through `JSON.stringify` without checking.
2. **No explicit duplicate-key detection on the parse path.** `JSON.parse` silently uses last-one-wins. RFC 8785 forbids duplicate keys. The builder path is safe (objects are constructed in code), but `parseArchiveManifestBytes` accepting external JSON does not reject duplicates.
3. **The whitepaper states divergence in number-serialization rules.** Based on code inspection, this may be a conservative documentation hedge rather than an actual behavioral divergence — `JSON.stringify` number output matches JCS requirements. This must be verified with an explicit test-vector pass, not assumed.

**authPolicyCommitment dependency**: `authPolicyCommitment` is computed using `canonicalizeJsonToBytes()`. If the canonicalization function changes even one byte of output for any input the policy object can produce, then the commitment value changes. For the current `{ level, minValidSignatures }` policy shape, the inputs contain only ASCII strings and small integers — the JCS-vs-QV-C14N-v1 output is byte-identical for these inputs. **This must be verified by test, not assumed.** If byte-identity holds, then migrating the manifest canonicalization label does not force re-commitment.

## 6. Recommended scope

### In scope for this roadmap
- canonical manifest serialization only
- exact byte stability for detached-signature payloads
- canonicalization label/version strategy
- test vectors and malformed-case vectors
- verifier behavior based on declared canonicalization label
- `authPolicyCommitment` canonicalization consistency
- bundle `manifestCanonicalization` metadata consistency with the embedded manifest byte profile
- cross-implementation byte-identity verification (JavaScript and Rust)

### Out of scope for this roadmap (belongs to another branch)
- `archiveId`
- migration continuity
- reshard / reencrypt semantics
- OAIS packaging envelope
- evidence-record renewal chain
- non-manifest binary container redesign

## 7. Recommended implementation direction

### Phase A1 — Verify byte-identity between QV-C14N-v1 and RFC 8785

Before changing behavior, determine the actual behavioral delta:

- produce canonical bytes for all current manifest-family inputs under QV-C14N-v1
- produce RFC 8785-compliant bytes for the same inputs
- compare byte-for-byte
- include `authPolicyCommitment` policy objects (`{ level, minValidSignatures }` for all supported policy levels and reasonable `minValidSignatures` values)
- bundle-level canonicalization outputs may be measured for information, but they are not a gate for the first signable-manifest migration
- document any divergences found

If byte-identity holds for all current inputs, the migration is a label change with tightened edge-case handling. If byte-identity does not hold, the exact divergences must be documented and addressed before the label changes.

### Phase A2 — Introduce a new canonicalization label

Do not silently mutate `QV-C14N-v1`.

Instead, introduce a new label for the RFC 8785-aligned form, e.g.:

- `QV-JSON-RFC8785-v1`

Recommended principle:
- new manifests are emitted under the new label
- verifiers dispatch canonicalization strictly by declared label
- unsupported labels fail closed
- `authPolicyCommitment.canonicalization` and bundle `manifestCanonicalization` migrate to the new label at the same time
- bundle serialization uses its own explicit label (`QV-BUNDLE-JSON-v1`) rather than being forced into the signable-manifest migration scope

Since there are no active deployed archives requiring backward compatibility, legacy dispatch machinery for `QV-C14N-v1` is not required. The old label is superseded, not preserved.

### Phase A3 — Implement a strict internal JCS canonicalizer

Implementation target:
- canonicalize **internal manifest objects** into exact RFC 8785-compatible bytes
- reject unsupported or ambiguous values instead of coercing them
- zero external runtime dependencies (the current `jcs.js` is 53 lines with no dependencies; keep it that way)

Minimum acceptance rules:
- only JSON-compatible types are accepted
- no `undefined`, functions, symbols, bigint, custom class instances, cycles
- numbers must be finite
- strings and property names must reject lone surrogates
- object keys must be sorted using raw property-name strings according to RFC 8785 expectations
- arrays preserve order
- final bytes are UTF-8

The Rust implementation must produce identical bytes for identical manifest objects. Cross-implementation byte-identity is a hard requirement, not a goal.

### Phase A4 — Define input-boundary discipline

Quantum Vault should distinguish between:

1. **builder path**
   - manifests created internally by QV code
   - safest first target for JCS support

2. **import / parse path**
   - externally supplied JSON text
   - must not claim full safety unless duplicate-key and Unicode edge cases are handled correctly before canonicalization
   - duplicate-key detection requires inspection at the raw JSON text level, not after `JSON.parse` (which silently deduplicates using last-one-wins)

A conservative design is:
- canonicalization is authoritative for internally constructed manifest objects
- external JSON must pass strict validation before being accepted as a source of canonical bytes
- duplicate-key rejection should be applied on the manifest parse path; it does not need to apply to all JSON parsing in the codebase

### Phase A5 — Add conformance tests

Add test categories:

- same manifest object -> same canonical bytes
- different insertion order -> same canonical bytes
- nested object recursive ordering
- array order unchanged
- UTF-8 output checks
- malformed Unicode cases (lone surrogate rejection)
- NaN / Infinity rejection
- unsupported type rejection
- cross-runtime consistency (browser vs Node)
- cross-implementation consistency (JavaScript vs Rust)
- compatibility vectors based on RFC 8785 examples
- `authPolicyCommitment` byte-identity verification across policy inputs
- negative zero, very large integers, very small fractions (edge-case number serialization)

## 8. Key design decisions to settle

- **authPolicyCommitment scope**: The new RFC 8785-aligned profile applies to canonical manifest bytes and `authPolicyCommitment` computation. Bundle serialization is versioned separately and does not have to migrate in the same step.
- **External JSON acceptance**: Will Quantum Vault accept externally supplied already-canonicalized signable JSON, or only internally constructed manifest objects? On the import path, duplicate-key detection is required before accepting external JSON as a source of canonical bytes.
- **Module structure**: Canonicalization should remain a dedicated small module with zero external runtime dependencies. The current `jcs.js` approach is correct.
- **Detached-signature metadata**: Will current detached-signature tools need an explicit profile identifier in output metadata?
- **Bundle-carried canonical bytes**: Will bundle-carried canonical manifest remain a structured object, or also carry exact canonical bytes for easier audit/debug workflows?

## 9. Risks and pitfalls

- claiming RFC 8785 compliance before exact behavior matches the RFC
- incorrect property sorting (unlikely — JS `.sort()` matches RFC 8785 UTF-16 code-unit ordering)
- relying on locale-sensitive string comparison
- failing to reject lone surrogates
- silent differences between browser and Node number/string behavior
- silent differences between JavaScript and Rust JSON serialization for edge-case numeric values
- forgetting that duplicate JSON keys are a parse-path problem, not merely a serialization problem
- changing `authPolicyCommitment` byte output without detecting it (breaks commitment verification even if signatures are unaffected)
- conflating bundle serialization compatibility with manifest-signature compatibility and over-scoping the migration

## 10. Concrete deliverables

Recommended deliverables for this track:

1. Byte-identity test suite: QV-C14N-v1 vs RFC 8785 for all manifest and policy shapes
2. Lone-surrogate rejection in the canonicalization module
3. Duplicate-key detection on the manifest parse path
4. Updated canonicalization label constant and verifier dispatch
5. Cross-implementation test vectors (JavaScript and Rust must produce identical bytes)
6. RFC 8785 reference test vectors (from the RFC's own examples)
7. Updated `docs/format-spec.md` section for canonicalization labels and compatibility boundary
8. Updated `docs/WHITEPAPER.md` section describing the JCS transition
9. `authPolicyCommitment` and bundle `manifestCanonicalization` label migration aligned with the manifest label change

## 11. Suggested documentation wording to preserve

Recommended principle to preserve in docs:

> Quantum Vault does not claim full RFC 8785 compliance unless it actually implements and labels a full RFC 8785-compatible canonicalization profile.

That preserves clarity and fail-closed semantics during the transition.

## 12. Definition of done

This roadmap is complete when Quantum Vault has:

- a new explicit canonicalization label
- a strict implementation for that label
- label-based verifier dispatch
- reproducible test vectors verified across JavaScript and Rust implementations
- `authPolicyCommitment` and bundle canonicalization labels migrated consistently
- documentation that clearly describes the RFC 8785-aligned profile

## 13. Reference links

- RFC 8785: https://www.rfc-editor.org/rfc/rfc8785.txt
- RFC 7493: https://www.rfc-editor.org/rfc/rfc7493.txt
- RFC 8259: https://www.rfc-editor.org/rfc/rfc8259.txt
- ECMA-262: https://tc39.es/ecma262/
