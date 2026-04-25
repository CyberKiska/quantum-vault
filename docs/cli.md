# Quantum Vault CLI

Nowadays QV ships a read-only Node.js CLI:

- `qv inspect`
- `qv canonicalize`
- `qv verify`
- `qv restore --dry-run`

Write-mode `restore` and `attach` are out of scope in Phase 1.

## Install / Run

Use the repo-local entrypoint:

```bash
npm run cli -- --help
```

The package also exposes `qv` via the `bin` field when installed as a package.

## Commands

### `qv inspect <artifact-file> [--json]`

Classifies an artifact, reports its version, and prints canonical JSON plus a SHA3-512 digest.

Supported Phase 1 artifact families:

- `archive-state.json`
- `cohort-binding.json`
- `lifecycle-bundle.json`
- `transition-record.json`
- `source-evidence.json`
- `*.qcont`
- `*.qsig`
- `*.pqpk`
- `*.ots`

`--json` output shape:

```json
{
  "command": "inspect",
  "file": "string",
  "artifactType": "string",
  "artifactVersion": "string",
  "encoding": "json|binary",
  "digestAlg": "SHA3-512",
  "digestHex": "hex",
  "inputDigestHex": "hex",
  "canonicalInput": true,
  "canonicalJson": {},
  "canonicalJsonText": "string",
  "parsedSummary": {}
}
```

Notes:

- JSON artifacts include `inputDigestHex`, `canonicalInput`, `canonicalJson`, and `canonicalJsonText`.
- Binary artifacts include `parsedSummary`. `*.qcont` also includes `canonicalJson` and `canonicalJsonText` for embedded shard metadata.

### `qv canonicalize <artifact-file> [--json]`

Outputs canonical JSON bytes to stdout for canonicalizable JSON lifecycle artifacts. Non-canonicalizable inputs fail closed.

Without `--json`, stdout is the canonical byte stream.

`--json` output shape:

```json
{
  "command": "canonicalize",
  "file": "string",
  "artifactType": "string",
  "artifactVersion": "string",
  "digestAlg": "SHA3-512",
  "digestHex": "hex",
  "canonicalJson": {},
  "canonicalJsonText": "string"
}
```

### `qv verify <archive-state.json> [options] [--json]`

Verifies archive authenticity using the same `src/core/crypto/qcont/restore.js` authenticity path used by browser restore.

Options:

- `--bundle <file>`
- `--sig <file>` repeatable
- `--pqpk <file>` repeatable
- `--ots <file>` repeatable
- `--ed25519-signer <address>`

Exit status:

- `0` when archive policy is satisfied
- `1` otherwise

When `--bundle` is present, `--json` emits the same authenticity object shape produced by browser restore for the same inputs.

Stable top-level fields:

```json
{
  "verification": {
    "provided": true,
    "results": [],
    "warnings": [],
    "counts": {},
    "signatureArtifacts": [],
    "status": {}
  },
  "policy": {
    "level": "string",
    "minValidSignatures": 1,
    "satisfied": true,
    "reason": "string"
  },
  "timestampEvidence": [],
  "transitionReport": {},
  "sourceEvidenceReport": {},
  "warnings": [],
  "status": {
    "integrityVerified": true,
    "archiveApprovalSignatureVerified": true,
    "strongPqSignatureVerified": false,
    "signerPinned": false,
    "bundlePinned": false,
    "userPinned": false,
    "userPinProvided": false,
    "transitionRecordPresent": false,
    "transitionChainValid": false,
    "sourceEvidencePresent": false,
    "cohortForkDetected": false,
    "bundleCohortMixed": false,
    "mixedLifecycleBundleVariantsWithinCohort": false,
    "maintenanceSignatureVerified": false,
    "sourceEvidenceSignatureVerified": false,
    "otsEvidenceLinked": false,
    "policySatisfied": true,
    "archivePolicySatisfied": true
  }
}
```

Bundleless verification behavior:

- `qv verify` still verifies external detached signatures, `.pqpk` pins, and `.ots` linkage against the provided archive-state bytes.
- Policy remains unresolved without a lifecycle bundle.
- `policy.level` is `"unresolved"`.
- exit status is `1`.

### `qv restore --shards <glob-or-file> [options] --dry-run [--json]`

Evaluates whether restore would succeed without writing plaintext, `.qkey`, or any output file.

Verification options match `qv verify` and add explicit selection flags:

- `--archive-state <file>`
- `--bundle <file>`
- `--sig <file>` repeatable
- `--pqpk <file>` repeatable
- `--ots <file>` repeatable
- `--ed25519-signer <address>`
- `--archive-id <hex>`
- `--state-id <hex>`
- `--cohort-id <hex>`
- `--bundle-digest <hex>`

Exit status:

- `0` when the selected restore would succeed
- `1` otherwise

`--json` output shape:

```json
{
  "command": "restore",
  "dryRun": true,
  "wouldSucceed": true,
  "archiveId": "hex",
  "stateId": "hex",
  "cohortId": "hex",
  "archiveStateDigestHex": "hex",
  "cohortBindingDigestHex": "hex",
  "lifecycleBundleDigestHex": "hex",
  "selectionSource": "string",
  "lifecycleBundleSource": "string",
  "embeddedLifecycleBundleDigestsUsed": [],
  "qencOk": true,
  "qkeyOk": true,
  "privateKeyHashMatchesMetadata": true,
  "rejectedShardIndices": [],
  "lifecycleVerification": {},
  "authenticity": {}
}
```

Dry-run guarantees:

- no plaintext file is written
- no recovered key file is written
- no write-mode restore path exists in Phase 1
- temporary recovered `qencBytes` and `privKey` buffers are zeroized before the CLI returns

## JSON Error Shape

All commands emit this shape on failure when `--json` is passed:

```json
{
  "command": "inspect|canonicalize|verify|restore",
  "ok": false,
  "error": "message"
}
```

## Examples

```bash
npm run cli -- inspect docs/schema/fixtures/qv-archive-state-descriptor-v1.valid.json --json
npm run cli -- canonicalize docs/schema/fixtures/qv-archive-state-descriptor-v1.valid.json
npm run cli -- verify /path/to/archive-state.json --bundle /path/to/lifecycle-bundle.json --sig /path/to/archive.qsig --pqpk /path/to/archive.pqpk --ots /path/to/archive.ots --json
npm run cli -- restore --shards '/path/to/shards/**/*.qcont' --bundle /path/to/lifecycle-bundle.json --dry-run --json
```
