# QV-C14N-v1 canonicalization profile

Status: Release Candidate
Type: Normative compatibility appendix
Audience: implementers, auditors, interoperability tool authors, test-vector maintainers
Scope: exact current serialization rules for `QV-C14N-v1` as used by canonical manifests, manifest bundles, and canonicalized policy commitments
Out of scope: signature semantics, archive-policy meaning, parser acceptance policy for unknown fields

## Role

This appendix is the compatibility reference for the current `QV-C14N-v1` canonical JSON profile.
It supports [format-spec.md](../format-spec.md), which owns where canonical bytes are required and how parsers use them.

## Scope

This file defines the exact current serialization behavior of `QV-C14N-v1`.
It does not decide whether unknown fields are accepted or rejected in a given artifact type; that remains the responsibility of [format-spec.md](../format-spec.md).

## Normative status

This appendix is normative for the current `QV-C14N-v1` byte profile.
An implementation is conformant to this version if and only if it satisfies all MUST-level requirements defined in the current normative sections of this appendix and the owner document `format-spec.md`.
If an implementation deviates from this appendix, it MUST explicitly document the deviation and MUST declare itself non-conformant to this version.
Statements explicitly labeled as future or recommended direction are non-normative until promoted into the current sections of this appendix.
In case of ambiguity, this appendix MUST be interpreted conservatively and fail-closed.

## Sources and references

Internal current-state grounding:

- `src/core/crypto/manifest/jcs.js`
- `src/core/crypto/manifest/archive-manifest.js`
- `src/core/crypto/manifest/manifest-bundle.js`
- `docs/format-spec.md`

External references already used elsewhere in the repository:

- RFC 8785 as a comparison point only; `QV-C14N-v1` is not claimed as full JCS
- RFC 8259 for the JSON data model baseline

## Current implementation status

Implemented now:

- UTF-8 canonical byte output for manifests, bundles, and canonicalized policy commitments
- lexicographic object-key ordering
- omission of object properties whose value is `undefined`, `function`, or `symbol`
- coercion of array elements whose value is `undefined`, `function`, or `symbol` to `null`
- rejection of `bigint` and non-finite numbers

Not yet first-class in the current implementation:

- a frozen standalone canonicalization vector corpus outside the repository examples and selftests
- any claim that `QV-C14N-v1` is byte-for-byte identical to full RFC 8785 JCS for all JSON edge cases

## Future work and non-normative notes

- Future vector publications may mirror this appendix in a machine-consumable corpus, but that does not change the current profile label.
- If a materially different profile is introduced later, it should receive a new canonicalization label rather than silently changing `QV-C14N-v1`.
- Intended standards direction, not current behavior: Quantum Vault's long-term target is to move toward a three-layer standards stack consisting of RFC 8785 for canonical signable manifest bytes, RFC 8610 / CDDL for formal artifact descriptions, and an OAIS-oriented archival package model handled in [long-term-archive.md](../long-term-archive.md).
- In that future direction, CDDL is valuable not as decorative schema text but as a machine-readable conformance and representation-information layer: it reduces parser ambiguity, supports controlled extensibility, strengthens independent implementation work, and improves long-horizon maintainability.

## 1. Current profile summary

`QV-C14N-v1` is the project-defined canonical JSON serializer used by Quantum Vault today.
Its canonical bytes are the UTF-8 encoding of the serializer output.

Current uses include:

- canonical manifest export bytes
- the manifest bytes embedded inside a manifest bundle
- canonicalized `authPolicy` input when computing `authPolicyCommitment`

## 2. Serialization rules

| JSON value category | Current `QV-C14N-v1` behavior |
| --- | --- |
| `null` | serialized as `null` |
| boolean | serialized as `true` or `false` |
| finite number | serialized with the runtime `JSON.stringify` number rendering |
| non-finite number (`NaN`, `Infinity`, `-Infinity`) | rejected |
| string | serialized with the runtime `JSON.stringify` string escaping rules |
| array | preserves element order; each element is serialized recursively |
| array element equal to `undefined`, `function`, or `symbol` | serialized as `null` |
| object | serialized with keys sorted by `Object.keys(obj).sort()` |
| object property equal to `undefined`, `function`, or `symbol` | omitted |
| `bigint` | rejected |
| other unsupported runtime value types | rejected |

Additional current profile rules:

- no whitespace is emitted outside JSON strings
- object members use `:` with no extra spacing
- array and object separators use `,` with no extra spacing
- canonical bytes are the UTF-8 bytes of the resulting string

## 3. Object-key ordering and omission rules

Current object handling is intentionally simple:

- key order is determined only by `Object.keys(obj).sort()`
- omitted object properties do not appear in the canonical byte sequence at all
- omission is value-based, not schema-based

Current array handling differs from object handling:

- array positions are preserved
- unsupported array element values become literal `null`

## 4. Comparison boundary against RFC 8785

`QV-C14N-v1` should be described honestly:

- it is a project-defined canonical JSON profile
- it is not claimed to be a full RFC 8785 implementation
- compatibility with an external tool claiming RFC 8785 exists only when that tool emits the same bytes as `QV-C14N-v1` for the concrete object being serialized

This appendix does not attempt to restate every RFC 8785 edge case.
Its purpose is to document the exact current serializer behavior used by Quantum Vault.

Future design note:

- if Quantum Vault later adopts RFC 8785 canonical bytes for the signable manifest, that should be introduced as an explicit standards-aligned migration target rather than being retroactively implied for `QV-C14N-v1`
- if Quantum Vault later adds CDDL artifact definitions, those definitions should describe the manifest, manifest bundle, and the logical structure of the `.qcont` header as a formal schema layer above the current code-defined structures

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

### 5.2 Object omission of unsupported property values

Conceptual input object:

```js
{
  keep: 1,
  omitUndefined: undefined,
  omitFunction: () => 1,
  omitSymbol: Symbol('x')
}
```

Current canonical output:

```json
{"keep":1}
```

### 5.3 Array coercion of unsupported element values

Conceptual input array:

```js
[1, undefined, () => 1, Symbol('x'), "ok"]
```

Current canonical output:

```json
[1,null,null,null,"ok"]
```

## 6. Current malformed or unsupported cases

The current serializer rejects:

- `NaN`
- `Infinity`
- `-Infinity`
- `bigint`
- unsupported runtime value types that cannot be represented by the serializer

Higher-layer parsers add additional requirements on top of this profile.
For example, [format-spec.md](../format-spec.md) requires canonical manifest and canonical bundle inputs to already be serialized exactly in `QV-C14N-v1` form.
