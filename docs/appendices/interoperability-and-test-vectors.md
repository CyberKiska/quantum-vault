# Interoperability and test vectors

Status: Release Candidate
Type: Mixed compatibility appendix
Audience: implementers, auditors, interoperability tool authors, test-vector maintainers
Scope: current selftest-backed conformance classes, regression vectors, malformed or fail-closed coverage, and repository-local vector sources
Out of scope: a frozen external vector release process, archive-policy governance, whitepaper rationale

## Role

This appendix is the active compatibility map for the selftests and checked-in fixtures that currently anchor interoperability work.
It supports [`format-spec.md`](../format-spec.md) by making the current vector surface explicit without treating repository-local development material as a published conformance release.

## Scope

This file describes the current selftest-backed vector classes and the checked-in schema-fixture sources already present in the repository.
It does not claim that the repository already ships a frozen standalone published corpus with stable vector identifiers.

## Normative status

This appendix is normative for the minimum current conformance expectations it describes in Sections 1, 3, 4, and 5.
Repository-local examples and fixture organization are informative only and are not themselves the published release surface.
The repository selftests remain implementation-coupled material, so future changes must keep this appendix accurate.

## Sources and references

Current implementation grounding:

- `src/core/crypto/selftest.js`
- `docs/schema/`
- [`format-spec.md`](../format-spec.md)
- [`appendices/canonicalization-profile.md`](canonicalization-profile.md)
- [`appendices/external-artifacts.md`](external-artifacts.md)

## Current implementation status

Implemented now:

- selftests covering signature-policy counting, `publicKeyRef`, OTS linkage, restore selection, malformed parsing, nonce and AEAD invariants, and successor lifecycle bundle and shard parsing
- checked-in JSON Schema fixtures under `docs/schema/fixtures/`, including schema-valid but runtime-invalid cases that exercise the bytes/schema/semantics boundary explicitly
- regression vectors for KMAC customization semantics and per-chunk IV derivation

Not yet first-class in the current implementation:

- a frozen standalone vector package with immutable case identifiers
- a machine-readable manifest of all malformed cases outside the source tree
- a cross-language conformance harness distributed separately from the repository

## Future work and non-normative notes

- a future release may promote the current repository fixtures and selftests into a versioned external vector corpus
- any such publication should preserve the current fail-closed expectations rather than simplifying them away

## 1. Minimum current conformance expectations

An interoperable implementation should currently be able to:

- parse and validate archive-state descriptors, cohort bindings, transition records, and source-evidence objects under `QV-JSON-RFC8785-v1`, and lifecycle bundles under `QV-BUNDLE-JSON-v1`
- parse and validate `QVqcont-7` shards only
- verify archive-approval signatures against canonical archive-state bytes, maintenance signatures against canonical transition-record bytes, and source-evidence signatures against canonical source-evidence bytes
- reject malformed or ambiguous `publicKeyRef` bindings and lifecycle `targetType` / `targetRef` / `targetDigest` mismatches
- link `.ots` evidence only to detached signature bytes
- reject malformed `.qenc`, `.qcont`, `.qsig`, `.pqpk`, and detached-signature inputs in the fail-closed cases covered by the repository selftests
- reject ambiguous archive, state, cohort, or lifecycle-bundle candidate sets without explicit disambiguation

## 2. Current repository vector sources

The active repository vector surface currently comes from:

| Source | Current coverage |
| --- | --- |
| `docs/schema/fixtures/` | structural valid and invalid successor artifacts plus schema-valid but semantic-invalid boundary cases |
| `src/core/crypto/selftest.js` | restore, attach, detached-signature, OTS, `.qenc`, and lifecycle regression behavior |
| owner docs and appendices | current canonicalization rules, detached-artifact rules, and fail-closed behavior descriptions |

Current usage note:

- these sources anchor current implementation conformance work
- they are not yet a separately versioned external vector release

## 3. Current vector classes already covered by selftests

| Vector class | Current repository coverage |
| --- | --- |
| canonicalization behavior | archive-state, cohort-binding, transition-record, source-evidence, and lifecycle-bundle normalization through parser and canonicalizer paths |
| schema grammar behavior | JSON Schema validation of valid and invalid successor fixtures, plus schema-valid but runtime-invalid boundary cases |
| detached-signature policy counting | duplicate proof deduplication, unique-signature counting, archive-approval counting, and bundle-plus-external interactions |
| `publicKeyRef` and target-contract fail-closed behavior | authoritative bundled-key verification, incompatible reference rejection, suite-mismatch rejection, and lifecycle target-family mismatch rejection |
| OTS linkage | external and embedded `.ots` linkage, unrelated proof rejection, and per-signature evidence deduplication |
| restore selection | archive/state/cohort grouping, explicit lifecycle-bundle override rules, same-state fork disambiguation, and mixed embedded-bundle reporting |
| `.qenc` correctness | chunked roundtrip, nonce-policy bounds, KMAC regression vectors, IV-derivation regression vector, tamper failure, and key-commitment enforcement |
| malformed input handling | invalid magic, oversize framing, unsupported major versions, duplicate shard indices, unsupported shard formats, and other fail-closed parser cases |

## 4. Current malformed and fail-closed coverage highlights

The selftests currently exercise at least the following compatibility-relevant negative cases:

- unsupported `.qsig` major version
- unsupported `.pqpk` major version
- unknown critical `.qsig` TLV tags
- oversized `.qsig` authenticated metadata
- oversized `.pqpk` key length
- invalid `.qenc` magic
- missing `.qenc` key commitment
- duplicate shard indices
- unsupported non-successor shard format
- duplicate bundle signature identifiers in one lifecycle bundle
- unrelated `.ots` evidence
- ambiguous successor lifecycle-bundle selection within one cohort
- same-state fork ambiguity without explicit operator selection

These are current compatibility expectations, not merely advisory checks.

## 5. Current deterministic regression vectors

The repository currently contains deterministic regression coverage for:

- KMAC customization-string and `dkLen` behavior
- per-chunk IV derivation under the current nonce contract
- chunk-count bound enforcement near the `uint32` counter boundary
- successor artifact canonicalization and parsing invariants anchored by checked-in fixtures

Those vectors are currently anchored in `src/core/crypto/selftest.js` and `docs/schema/fixtures/`.

## 6. Current limitation of this appendix

This appendix promotes the interoperability surface into active documentation, but it does not yet replace a standalone published vector release.
For published releases, the source of truth is the current normative docs plus the selftest-backed behavioral classes summarized here, not repository-local fixture organization.
