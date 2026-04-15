# Current JSON canonicalization profiles

Status: Release Candidate
Type: Normative compatibility appendix
Audience: implementers, auditors, interoperability tool authors, test-vector maintainers
Scope: exact current serialization rules for `QV-JSON-RFC8785-v1` and `QV-BUNDLE-JSON-v1` as used by successor artifacts and canonicalized policy commitments
Out of scope: signature semantics, archive-policy meaning, parser acceptance policy for unknown fields

## Role

This appendix is the compatibility reference for the current Quantum Vault canonical JSON labels.
It supports [`format-spec.md`](../format-spec.md), which owns where canonical bytes are required and how parsers use them.

## Scope

This file defines the exact current serialization behavior of the active canonicalization labels.
It does not decide whether unknown fields are accepted or rejected in a given artifact type; that remains the responsibility of [`format-spec.md`](../format-spec.md).

## Normative status

This appendix is normative for the current successor signable-artifact and lifecycle-bundle byte profiles.
An implementation is conformant to this version if and only if it satisfies all MUST-level requirements defined in the current normative sections of this appendix and the owner document [`format-spec.md`](../format-spec.md).
If an implementation deviates from this appendix, it MUST explicitly document the deviation and MUST declare itself non-conformant to this version.
Statements explicitly labeled as future or recommended direction are non-normative until promoted into the current sections of this appendix.
In case of ambiguity, this appendix MUST be interpreted conservatively and fail-closed.

## Sources and references

Internal current-state grounding:

- the repository's shared strict JSON canonicalization helpers used by successor artifacts
- `src/core/crypto/lifecycle/artifacts.js`
- [`format-spec.md`](../format-spec.md)

External references already used elsewhere in the repository:

- RFC 8785 for the current strict canonicalization behavior
- RFC 8259 for the JSON data model baseline

This appendix intentionally cites the serializer implementation and the RFCs directly. Current canonicalization compatibility is an implementation-and-standards question, not a research-synthesis question.

## Current implementation status

Implemented now:

- strict UTF-8 canonical byte output for archive-state descriptors, cohort bindings, transition records, source-evidence objects, lifecycle bundles, and canonicalized policy commitments
- RFC 8785-aligned canonicalization for signable lifecycle artifacts and `authPolicyCommitment` input, with byte-level regression coverage for the current repository vectors and active artifact shapes
- lifecycle-bundle canonicalization using the same strict serializer but a separate bundle-specific label
- duplicate-key rejection on lifecycle parse paths
- lone-surrogate rejection on parse and canonicalization paths
- JSON member names are parsed as inert data keys even when named `__proto__`, `constructor`, or `prototype`
- rejection of non-finite numbers, `bigint`, unsupported runtime value types, non-plain objects, and cyclic structures

Not yet first-class in the current implementation:

- a frozen standalone canonicalization vector corpus outside the repository examples and selftests
- a separately published external conformance release for the current canonicalization labels

## Future work and non-normative notes

- future vector publications may mirror this appendix in a machine-consumable corpus, but that does not change the current profile labels
- if a materially different profile is introduced later, it should receive a new canonicalization label rather than silently changing `QV-JSON-RFC8785-v1` or `QV-BUNDLE-JSON-v1`
- intended longer-term direction, not current behavior: Quantum Vault may in the future add CDDL (RFC 8610) as a representation-information layer for OAIS-oriented archival package description and long-term format portability

## 1. Current profile summary

Current labels:

- `QV-JSON-RFC8785-v1` governs archive-state descriptor bytes, cohort-binding bytes, transition-record bytes, source-evidence bytes, and canonicalized `authPolicy` input for `authPolicyCommitment`
- `QV-BUNDLE-JSON-v1` governs lifecycle-bundle bytes

Current implementation note:

- both labels are currently emitted by the same strict UTF-8 JSON canonicalizer
- the labels remain distinct because detached signatures target signable lifecycle objects rather than mutable lifecycle-bundle bytes

Current uses include:

- canonical archive-state descriptor bytes
- canonical cohort-binding bytes
- canonical transition-record bytes
- canonical source-evidence bytes
- canonicalized `authPolicy` input when computing `authPolicyCommitment`
- canonical lifecycle-bundle bytes

## 2. Serialization rules

| JSON value category | Current behavior |
| --- | --- |
| `null` | serialized as `null` |
| boolean | serialized as `true` or `false` |
| finite number | serialized with the runtime `JSON.stringify` number rendering |
| non-finite number (`NaN`, `Infinity`, `-Infinity`) | rejected |
| string | serialized with the runtime `JSON.stringify` string escaping rules after lone-surrogate rejection |
| array | preserves element order; each element is serialized recursively |
| array element equal to `undefined`, `function`, or `symbol` | rejected |
| object | serialized with keys sorted by `Object.keys(obj).sort()` |
| object property equal to `undefined`, `function`, or `symbol` | rejected |
| `bigint` | rejected |
| non-plain objects or cyclic structures | rejected |
| other unsupported runtime value types | rejected |

Additional current profile rules:

- no whitespace is emitted outside JSON strings
- object members use `:` with no extra spacing
- array and object separators use `,` with no extra spacing
- canonical bytes are the UTF-8 bytes of the resulting string
- parse paths reject invalid UTF-8, duplicate object keys, and lone surrogates

## 3. Object-key ordering and parse discipline

Current object handling:

- key order is determined only by `Object.keys(obj).sort()`
- unsupported properties are rejected rather than omitted

Current array handling:

- array positions are preserved
- unsupported array element values are rejected rather than coerced

## 4. Comparison boundary against RFC 8785

`QV-JSON-RFC8785-v1` should be described honestly:

- it is the current signable-object canonical JSON profile for successor lifecycle artifacts
- the current repository demonstrates byte-level parity for the covered vectors and active lifecycle JSON objects it emits and accepts
- compatibility with an external RFC 8785 tool exists only when that tool emits the same bytes for the same JSON value

`QV-BUNDLE-JSON-v1` should also be described honestly:

- it is the current mutable lifecycle-bundle byte profile label
- it currently uses the same strict canonicalizer as `QV-JSON-RFC8785-v1`
- it remains separately labeled so lifecycle-bundle compatibility can evolve independently from detached-signature payload compatibility

This appendix does not attempt to restate every RFC 8785 edge case.
Its purpose is to document the exact current serializer behavior used by Quantum Vault.

## 5. Current canonical examples

### 5.1 Object key sorting

Input object:

```json
{"b":2,"a":1}
```

Current canonical output:

```json
{"a":1,"b":2}
```

### 5.2 Object-key sorting with successor labels

Input object:

```json
{"canonicalization":"QV-JSON-RFC8785-v1","schema":"quantum-vault-archive-state-descriptor/v1"}
```

Current canonical output:

```json
{"canonicalization":"QV-JSON-RFC8785-v1","schema":"quantum-vault-archive-state-descriptor/v1"}
```

### 5.3 Bundle-label example

Input object:

```json
{"bundleCanonicalization":"QV-BUNDLE-JSON-v1","type":"QV-Lifecycle-Bundle","version":1}
```

Current canonical output:

```json
{"bundleCanonicalization":"QV-BUNDLE-JSON-v1","type":"QV-Lifecycle-Bundle","version":1}
```

### 5.4 Current malformed or unsupported cases

The current serializer rejects:

- `NaN`
- `Infinity`
- `-Infinity`
- `bigint`
- `undefined`, `function`, and `symbol`
- lone surrogates
- duplicate object keys on parse paths
- invalid UTF-8 on parse paths
- unsupported runtime value types that cannot be represented by the serializer
- non-plain objects and cyclic structures

Higher-layer parsers add additional requirements on top of this profile.
For example, [`format-spec.md`](../format-spec.md) requires successor signable lifecycle artifacts to already be serialized exactly in `QV-JSON-RFC8785-v1` form, and lifecycle bundles to already be serialized exactly in `QV-BUNDLE-JSON-v1` form.
