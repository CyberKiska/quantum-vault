# Quantum Vault Binary Corpus

Status: successor-family conformance corpus for the current baseline

This directory freezes binary artifact cases for the shipped successor family.
Each case is a standalone JSON file with committed bytes encoded as base64 and a committed `SHA3-512` digest over those exact bytes.

Required case fields:

- `id`: stable case identifier
- `description`: human-readable summary
- `artifactType`: one of `QVqcont-7`, `.qsig`, `.pqpk`, `.ots`
- `artifactVersion`: artifact-specific frozen version label
- `encoding`: always `base64`
- `bytes`: exact artifact bytes encoded as base64
- `expectedDigestAlg`: always `SHA3-512`
- `expectedDigest`: lowercase hex digest of decoded `bytes`
- `valid`: `true` or `false`
- `rejectionReason`: required for `valid: false`; must be a stable substring, not a full brittle error string

Optional `runtime` fields are allowed when the runtime check needs more than a parser call:

- `runtime.messageBytes`: base64-encoded target bytes for `.qsig` verification cases
- `runtime.pinnedPqPublicKeyBytes`: base64-encoded `.pqpk` bytes for `.qsig` verification cases
- `runtime.bundlePqPublicKeyBytes`: base64-encoded `.pqpk` bytes for authoritative bundled-key verification cases
- `runtime.authoritativeBundlePqPublicKey`: boolean for `.qsig` authoritative bundled-key verification
- `runtime.expectedSuite`: normalized suite name expected from a valid `.qsig` verification result
- `runtime.expectedSuiteId`: expected numeric suite id for valid `.pqpk` cases
- `runtime.expectedMetaJSON`: subset of `metaJSON` fields to assert for valid `QVqcont-7` shard cases
- `runtime.signatures`: detached-signature byte fixtures for `.ots` target-linkage cases

`npm run corpus:verify` verifies both layers of the Phase 1 conformance baseline:

1. `docs/schema/fixtures/` through `scripts/schema-fixtures.mjs` for canonical JSON lifecycle artifacts
2. `docs/schema/corpus/` through `scripts/corpus-verify.mjs` for frozen binary artifact cases

Expected digests in this directory must be derived from the committed `bytes` payloads.
They are not authoritative by themselves; the committed bytes are.
