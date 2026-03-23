# Interoperability and test vectors

Status: Release Candidate
Type: Mixed compatibility appendix
Audience: implementers, auditors, interoperability tool authors, test-vector maintainers
Scope: current selftest-backed conformance classes, regression vectors, malformed or fail-closed coverage, and local-development example artifacts
Out of scope: a frozen external vector release process, archive-policy governance, whitepaper rationale

## Role

This appendix is the active compatibility map for the selftests and local-development examples that currently anchor interoperability work.
It supports [format-spec.md](../format-spec.md) by making the current vector surface explicit without treating unpublished development examples as part of the required release surface.

## Scope

This file describes the current selftest-backed vector classes and any local-development example sources already present in the repository.
It does not claim that the repository already ships a frozen standalone published corpus with stable vector identifiers.

## Normative status

This appendix is normative for the minimum current conformance expectations it describes in Sections 1, 3, 4, and 5.
Local-development example artifacts are informative only and are not part of the published release surface.
The repository selftests remain implementation-coupled material, so future changes must keep this appendix accurate.

## Sources and references

Current implementation grounding:

- `src/core/crypto/selftest.js`
- `docs/format-spec.md`
- `docs/appendices/canonicalization-profile.md`
- `docs/appendices/external-artifacts.md`

## Current implementation status

Implemented now:

- selftests covering signature-policy counting, `publicKeyRef`, OTS linkage, restore selection, malformed parsing, and nonce/AEAD invariants
- regression vectors for KMAC customization semantics and per-chunk IV derivation
- local-development example artifact sets for single-archive, signature-focused, and bundle-focused flows

Not yet first-class in the current implementation:

- a frozen standalone vector package with immutable case identifiers
- machine-readable manifest of all malformed cases outside the source tree
- a cross-language conformance harness distributed separately from the repository

## Future work and non-normative notes

- A future release may promote the current repository examples and selftests into a versioned external vector corpus.
- Any such publication should preserve the current fail-closed expectations rather than simplifying them away.

## 1. Minimum current conformance expectations

An interoperable implementation should currently be able to:

- parse and validate canonical manifests under `QV-JSON-RFC8785-v1` and canonical bundles under `QV-BUNDLE-JSON-v1`
- verify detached signatures only against canonical manifest bytes
- reject malformed or ambiguous `publicKeyRef` bindings
- link `.ots` evidence only to detached signature bytes
- reject malformed `.qenc`, `.qcont`, `.qsig`, `.pqpk`, and detached-signature inputs in the fail-closed cases covered by the repository selftests

## 2. Current local-development example-artifact sources

The development repository may contain example artifact sets for contributor inspection and manual testing.
These examples are not included in published releases and are not the normative source of release-time conformance bytes.

| Source | Current coverage |
| --- | --- |
| `examples/single/` | baseline `.qcont` shard set, canonical manifest, detached PQ signature, detached Stellar signature, and `.ots` timestamp |
| `examples/sig/` | multiple detached-signature families over one canonical manifest, including PQ and Stellar examples |
| `examples/bundle/` | canonical manifest, mutable manifest bundle, multiple PQ public keys, multiple detached PQ signatures, multiple `.ots` proofs, and embedded-bundle shard sets |

Current usage note:

- these example directories are local-development examples, not a published conformance release
- the `examples/` directory is excluded from published releases via `.gitignore`

## 3. Current vector classes already covered by selftests

| Vector class | Current repository coverage |
| --- | --- |
| canonicalization behavior | canonical manifest and bundle normalization through parser/canonicalizer paths |
| detached-signature policy counting | duplicate proof deduplication, unique-signature counting, and bundle-plus-external interactions |
| `publicKeyRef` fail-closed behavior | authoritative bundled-key verification, incompatible reference rejection, and suite-mismatch rejection |
| OTS linkage | external and embedded `.ots` linkage, unrelated proof rejection, and per-signature evidence deduplication |
| restore selection | richer-bundle preference when canonical manifest bytes are identical, uploaded-bundle override rules, and mixed embedded-bundle reporting |
| `.qenc` correctness | chunked roundtrip, nonce-policy bounds, KMAC regression vectors, IV-derivation regression vector, tamper failure, and key-commitment enforcement |
| malformed input handling | invalid magic, oversize framing, unsupported major versions, duplicate shard indices, and other fail-closed parser cases |

## 4. Current malformed and fail-closed coverage highlights

The selftests currently exercise at least the following compatibility-relevant negative cases:

- unsupported `.qsig` major version
- unsupported `.pqpk` major version
- unknown critical `.qsig` TLV tags
- oversized `.qsig` authenticated metadata
- oversized `.pqpk` key length
- duplicate detached signature payloads in one bundle
- invalid `.qenc` magic
- missing `.qenc` key commitment
- duplicate shard indices
- unrelated `.ots` evidence

These are current compatibility expectations, not merely advisory checks.

## 5. Current deterministic regression vectors

The repository currently contains deterministic regression coverage for:

- KMAC customization-string and `dkLen` behavior
- per-chunk IV derivation under the current nonce contract
- chunk-count bound enforcement near the `uint32` counter boundary

Those vectors are currently anchored in `src/core/crypto/selftest.js`.

## 6. Current limitation of this appendix

This appendix promotes the interoperability surface into active documentation, but it does not yet replace a standalone published vector release.
For published releases, the source of truth is the current normative docs plus the selftest-backed behavioral classes summarized here, not the omitted local-development example directories.
