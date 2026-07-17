# Quantum Vault CLI

Quantum Vault ships a Node.js CLI with key generation, encryption, successor shard creation, lifecycle attachment, same-state resharing, write-mode restore, and lifecycle inspection and verification:

- `qv keygen`
- `qv encrypt`
- `qv decrypt`
- `qv split`
- `qv attach`
- `qv reshare`
- `qv inspect`
- `qv canonicalize`
- `qv verify`
- `qv restore`
- `qv restore --dry-run`
- `qv selftest`
- `qv version`

## Install / Run

Use the repo-local entrypoint:

```bash
npm run cli -- --help
```

The package also exposes `qv` via the `bin` field when installed as a package.

Global flags:

- `--help` / `-h` prints top-level help, and `qv help <command>` prints the same text as `qv <command> --help`
- `--no-color` is accepted and is the default; current CLI output is plain text
- `--color` is accepted as an explicit opt-in only when stderr is a TTY; current CLI output remains plain
- `--quiet` is accepted for forward compatibility with future stderr progress output
- `--allow-symlink` permits explicit symlink input paths and symlinked path components; without it, symlink reads fail closed

Filesystem notes:

- File modes are requested modes. The operating system umask may make resulting files more restrictive.
- Small detached and lifecycle artifacts (`.qsig`, `.pqpk`, `.ots`, lifecycle JSON, source-evidence, and key inputs) are capped at 32 MiB before parsing. `.qenc` and `.qcont` are not subject to that small-artifact cap.

`cliSchemaVersion` (currently `1`) labels the stdout JSON contract for automation:

- Schema **v1** may add new object fields. It must not remove or rename fields, and must not change a field's type incompatibly (for example `string` → `number`, widening or narrowing arrays in ways that break parsers). Any incompatible change requires incrementing the schema version.
- Error JSON from failed commands includes `command`, `ok: false`, `cliSchemaVersion`, `error`, and `qvCode` only (no success-only payload fields).

## Commands

### `qv keygen --out <dir> [--name <prefix>] [--force] [--print-public] [--json]`

Generates an ML-KEM-1024 keypair and writes raw `.qkey` files:

- `<out>/publicKey.qkey` or `<out>/<prefix>publicKey.qkey`
- `<out>/privateKey.qkey` or `<out>/<prefix>privateKey.qkey`

Options:

- `--out <dir>` required; creates that directory if it does not exist and its parent exists
- `--name <prefix>` optional filename prefix; path separators are rejected
- `--force` allows overwriting existing key files
- `--print-public` emits the public key as base64; the private key is never printed
- `--json` emits one JSON document on stdout

Exit status:

- `0` when keys were written
- `2` for usage errors, including missing `--out` or refused overwrite
- `3` for entropy/RNG health-check failure
- `1` for other failures

`--json` output shape:

```json
{
  "command": "keygen",
  "ok": true,
  "cliSchemaVersion": 1,
  "alg": { "KEM": "ML-KEM-1024" },
  "publicKeyPath": "string",
  "privateKeyPath": "string",
  "publicKeyDigestHex": "hex",
  "privateKeyDigestHex": "hex",
  "publicKeyLength": 1568,
  "privateKeyLength": 3168,
  "seed": { "source": "secure-random" }
}
```

When `--json --print-public` are used together, `publicKeyBase64` is included in the same JSON document. The private key is never included in stdout.

Security notes:

- `privateKey.qkey` is written with mode `0600` best-effort.
- `publicKey.qkey` is written with mode `0644` best-effort.
- The CLI zeroizes private-key buffers in a `finally` block, but Node.js memory zeroization is best-effort and does not protect against swap, tracing, crash dumps, or hostile local administrators.

### `qv encrypt <input-file> --public-key <publicKey.qkey> --out <output.qenc> [--filename <name>] [--force] [--json]`

Encrypts one plaintext file under an ML-KEM-1024 public key and writes a `.qenc` container using the same `src/core/crypto/index.js#encryptFile` implementation as the browser.

Options:

- `<input-file>` required for single-file encryption
- `--public-key <publicKey.qkey>` required raw ML-KEM-1024 public key
- `--out <output.qenc>` required output path; the parent directory must already exist
- `--filename <name>` optional private metadata filename override; path separators and NUL are rejected
- `--force` allows overwriting an existing output file
- `--json` emits one JSON document on stdout

Multi-file payloads:

```bash
qv encrypt --pack <file-a> <file-b> [...] --public-key publicKey.qkey --out bundle.qenc --filename bundle.qvpack
```

`--pack` builds a pre-encryption `.qvpack` payload with magic `QVB1`, then encrypts that payload into a normal `.qenc` container. Pack entry names are `basename()` values only, duplicate basenames are rejected, and `--filename` must end with `.qvpack`. An existing `.qvpack` file can also be passed as the single input; the CLI recognizes it by `QVB1` magic for reporting. Restore tooling must detect a decrypted pack by `QVB1` magic, not by filename alone.

Exit status:

- `0` when the container was written
- `2` for usage errors, including missing flags, duplicate pack entry names, or refused overwrite
- `4` for format/policy rejection, including payloads above `MAX_FILE_SIZE`
- `5` for invalid public key material
- `1` for other failures

`--json` output shape:

```json
{
  "command": "encrypt",
  "ok": true,
  "cliSchemaVersion": 1,
  "alg": { "KEM": "ML-KEM-1024", "KDF": "KMAC256", "AEAD": "AES-256-GCM" },
  "inputPath": "string|null",
  "inputPaths": ["string"],
  "outputPath": "string",
  "publicKeyPath": "string",
  "fmt": "QVv1-5-0",
  "aeadMode": "single-container-aead",
  "chunkSize": 8388608,
  "chunkCount": 1,
  "payloadLength": 12345,
  "plaintextLength": 123,
  "inputLength": 123,
  "containerHashAlg": "SHA3-512",
  "containerHashHex": "hex",
  "containerId": "hex",
  "fileHashHex": "hex",
  "originalFilename": "input.bin",
  "payloadKind": "file|qvpack",
  "fileCount": 1
}
```

Security notes:

- The CLI reads plaintext into memory and calls `encryptFile`; true streaming I/O is not added in this phase.
- Plaintext buffers are zeroized in `finally` after encryption or failure, but Node.js memory zeroization is best-effort and does not protect against swap, tracing, crash dumps, or hostile local administrators.
- Container hashes and plaintext hashes use SHA3-512 and are computed over exact bytes.

### `qv decrypt <input.qenc> --private-key <privateKey.qkey> [--out <file>] [--out-dir <dir>] [--use-original-filename] [--force] [--json]`

Decrypts a `.qenc` container with an ML-KEM-1024 private key and writes plaintext with mode `0600` best-effort. Decryption uses the same `src/core/crypto/index.js#decryptFile` implementation as the browser.

Private key sources, exactly one required:

- `--private-key <privateKey.qkey>`
- `--private-key-stdin`
- `--private-key-env <ENV_NAME>`, where the environment variable contains a file path, not raw key bytes

Output path selection:

- `--out <file>` writes exactly that file
- `--out-dir <dir>` writes `<dir>/<originalFilename>` after strict filename sanitization
- `--use-original-filename` writes the sanitized recovered filename next to the input when `--out-dir` is not supplied
- no output option writes `<input.qenc>.decrypted`

`.qvpack` payloads:

- By default, a decrypted `.qvpack` payload is written as exact `QVB1` bundle bytes.
- `--extract-qvpack --out-dir <dir>` requires an authenticated `QVB1` payload and writes each pack entry as a separate `0600` file.
- Extracted entry names are sanitized again: no path separators, no leading dot, no NUL/control bytes, and no overlong UTF-8 filename.

Exit status:

- `0` when plaintext was written
- `2` for usage errors, including conflicting output flags, unsafe recovered names, or refused overwrite
- `4` for format/policy rejection, including malformed containers or malformed `.qvpack` payloads
- `5` for invalid private key length
- `6` for AEAD/key-commitment/authentication failure
- `11` for restored plaintext hash mismatch against authenticated private metadata
- `1` for other failures

`--json` output shape:

```json
{
  "command": "decrypt",
  "ok": true,
  "cliSchemaVersion": 1,
  "inputPath": "string",
  "outputPath": "string|null",
  "outputPaths": ["string"],
  "alg": { "KEM": "ML-KEM-1024", "KDF": "KMAC256", "AEAD": "AES-256-GCM" },
  "fmt": "QVv1-5-0",
  "aeadMode": "single-container-aead",
  "chunkSize": 8388608,
  "chunkCount": 1,
  "payloadLength": 12345,
  "plaintextLength": 123,
  "originalFilename": "input.bin",
  "fileHashHex": "hex",
  "containerHashAlg": "SHA3-512",
  "containerHashHex": "hex",
  "containerId": "hex",
  "payloadKind": "file|qvpack",
  "fileCount": 1,
  "qvpackExtracted": false,
  "qvpackEntries": []
}
```

Security notes:

- The private key is read through the shared CLI secret reader and zeroized with best-effort `Uint8Array.fill(0)` after use.
- The plaintext `Blob` is converted to one `Uint8Array`, written, and zeroized before return.
- Authentication failures use a fixed message and `qvCode: "AEAD_FAILED"` so diagnostics do not reveal key material or decrypted bytes.

### `qv split <input.qenc> --private-key <privateKey.qkey> --n <int> --k <int> [--out <dir>] [--auth-policy-level <level>] [--min-valid-signatures <int>] [--force] [--json]`

Builds a successor lifecycle cohort of QVqcont-7 shards from a `.qenc` container and the matching ML-KEM-1024 private key. Split uses `src/core/crypto/qcont/lifecycle-shard.js#buildLifecycleQcontShards` and the vendored Reed-Solomon runtime loaded by the CLI; no new dependency or network path is introduced.

Private key sources, exactly one required:

- `--private-key <privateKey.qkey>`
- `--private-key-stdin`

Required geometry:

- `--n <int>` shard count
- `--k <int>` Reed-Solomon data threshold

The runtime-supported tuple is validated by core lifecycle code. For the current codec, parity must be even and `t = k + ((n - k) / 2)`.

Output:

- `--out <dir>` output directory; defaults to `./shards` and is created if its parent exists
- shard names mirror the browser convention: `<input-basename>.partN-of-M.qcont`
- sidecar JSON names are `<input-basename>.archive-state.json`, `<input-basename>.cohort-binding.json`, and `<input-basename>.lifecycle-bundle.json`
- `.qcont` shards are written with mode `0600` best-effort
- sidecar JSON artifacts are canonical bytes from core and are written with mode `0644` best-effort

Archive policy options:

- `--auth-policy-level <integrity-only|any-signature|strong-pq-signature>`
- `--min-valid-signatures <int>`, default `1`

Internal deterministic fixture options are accepted only when `QV_ALLOW_DETERMINISTIC=1` is set and are intentionally hidden from the short help:

- `--archive-id <64 lowercase hex>`
- `--archive-id-random <64 hex chars>`
- `--parent-state-id <128 lowercase hex>`
- `--state-type <string>`

Exit status:

- `0` when all artifacts were written
- `2` for usage errors or refused overwrite
- `4` for malformed `.qenc` format/policy rejection
- `5` for invalid private key length or private key/container mismatch
- `7` for unsupported RS/Shamir geometry
- `1` for other failures

`--json` output shape:

```json
{
  "command": "split",
  "ok": true,
  "cliSchemaVersion": 1,
  "inputPath": "string",
  "outDir": "string",
  "archiveId": "hex",
  "stateId": "hex",
  "cohortId": "hex",
  "n": 5,
  "k": 3,
  "m": 2,
  "t": 4,
  "rsCodecId": "QV-RS-ErasureCodes-v1",
  "shamir": { "n": 5, "t": 4 },
  "authPolicy": { "level": "integrity-only", "minValidSignatures": 1 },
  "archiveStateBytesPath": "string",
  "archiveStateDigestHex": "hex",
  "cohortBindingBytesPath": "string",
  "cohortBindingDigestHex": "hex",
  "lifecycleBundleBytesPath": "string",
  "lifecycleBundleDigestHex": "hex",
  "shards": [
    { "index": 0, "path": "string", "shardDigestHex": "hex", "shardSize": 12345 }
  ],
  "fmt": "QVqcont-7",
  "containerHashAlg": "SHA3-512",
  "containerHashHex": "hex",
  "containerId": "hex",
  "privateKeyHashHex": "hex"
}
```

Security notes:

- The CLI validates the private key size before split and core verifies the `.qenc` key commitment before shard generation.
- Output paths are preflighted before any artifact write unless `--force` is supplied.
- The loaded private key, input container buffer, and emitted shard byte buffers are zeroized best-effort after write/report construction. Node.js memory zeroization remains best-effort and does not protect against swap, tracing, crash dumps, or hostile local administrators.

### `qv attach [--shards <glob-or-file> ...] [--bundle <file>] [options]`

Attaches detached lifecycle artifacts to a QV-Lifecycle-Bundle v1 and optionally rewrites QVqcont-7 shards with the updated lifecycle bundle embedded. Attach uses `src/core/crypto/qcont/lifecycle-attach.js#attachLifecycleBundleToShards`; it does not implement separate CLI-only signature, timestamp, or lifecycle-binding logic.

Inputs:

- `--shards <glob-or-file>` repeatable; selects successor QVqcont-7 shards from one archive/state/cohort set
- `--archive-state <file>` optional explicit archive-state descriptor; must byte-match selected shards or bundle
- `--bundle <file>` optional lifecycle bundle; required to disambiguate shard sets with mixed embedded lifecycle-bundle digests
- `--sig <file>` repeatable archive-approval detached signature import
- `--sig-import <json>` repeatable typed signature import descriptor with explicit `signatureFamily`, optional `targetType`, `targetRef`, and `targetDigest`
- `--pqpk <file>` repeatable pinned PQ public key material for `.qsig` verification
- `--ots <file>` repeatable OpenTimestamps proof import linked to imported lifecycle signatures
- `--source-evidence <json-file>` or `--source-evidence-bytes <file>` source-evidence material for `signatureFamily:"source-evidence"` imports. With `--source-evidence`, strictly invalid JSON fails closed (it is not silently treated as builder JSON). Valid JSON that is not already RFC 8785-canonical for source-evidence is still accepted as builder JSON and canonicalized by core.
- `--ed25519-signer <address>` optional signer pin for supported Stellar `.sig` imports

Typed `--sig-import` descriptor example:

```json
{
  "file": "source-review.qsig",
  "signatureFamily": "source-evidence",
  "targetType": "source-evidence",
  "targetRef": "source-evidence:sha3-512:<digest>",
  "targetDigest": "<digest>"
}
```

Output:

- `--out-bundle <file>` defaults to `./lifecycle-bundle.json`; written with mode `0644` best-effort
- `--out-shards <dir>` defaults to `./attached-shards`; used when shards are selected and embedding is enabled
- `--no-embed-into-shards` writes only the updated lifecycle bundle
- `--force` allows overwriting output files
- `--json` emits one JSON document on stdout

Exit status:

- `0` when the updated lifecycle bundle was written
- `2` for usage errors or refused overwrite
- `8` for signature, timestamp, typed import, or pinned-key verification failure
- `9` for ambiguous shard/bundle lifecycle inputs
- `1` for other failures

`--json` output shape:

```json
{
  "command": "attach",
  "ok": true,
  "cliSchemaVersion": 1,
  "archiveId": "hex",
  "stateId": "hex",
  "cohortId": "hex",
  "lifecycleBundlePath": "string",
  "lifecycleBundleDigestHex": "hex",
  "lifecycleBundleDigestAlg": "SHA3-512",
  "embeddedIntoShards": true,
  "embeddedIntoShardsReason": "embedded",
  "shardsRewritten": [
    { "index": 0, "path": "string" }
  ],
  "addedAttachments": {
    "publicKeys": [],
    "archiveApprovalSignatures": [],
    "maintenanceSignatures": [],
    "sourceEvidenceSignatures": [],
    "timestamps": [],
    "sourceEvidence": []
  },
  "embeddedLifecycleBundleDigests": [],
  "mixedEmbeddedLifecycleBundleDigests": false,
  "archiveStateDigestHex": "hex",
  "cohortBindingDigestHex": "hex"
}
```

Security notes:

- Attach remains fail-closed on archiveId, stateId, cohortId derivation, canonical archive-state bytes, cohort-binding bytes, and lifecycle-bundle ambiguity.
- Archive approval signatures are bound to canonical archive-state descriptor bytes; lifecycle bundles remain mutable containers for detached signatures, public keys, timestamp evidence, transition records, and source-evidence objects.
- `--sig-import` does not infer target semantics from filenames or lengths. Maintenance imports require an explicit transition `targetRef`; source-evidence imports bind to canonical source-evidence bytes or validated builder JSON.
- Detached artifacts and shard shares are handled in memory. The CLI zeroizes rewritten shard buffers and parsed shard shares best-effort after use, but Node.js memory zeroization does not protect against swap, tracing, crash dumps, or hostile local administrators.

### `qv reshare --shards <glob-or-file> ... --n <int> --k <int> [options]`

Produces a same-state successor cohort from a predecessor QVqcont-7 cohort. Reshare preserves exact canonical archive-state bytes, `archiveId`, and `stateId`; rotates the cohort binding and `cohortId`; appends a transition record to the lifecycle bundle; and embeds the updated bundle into every successor shard. The CLI wraps `src/core/crypto/qcont/lifecycle-shard.js#reshareSameState`.

Options:

- `--shards <glob-or-file>` repeatable; selects predecessor successor-lifecycle shards
- `--n <int>` and `--k <int>` required successor Reed-Solomon geometry
- `--bundle <file>` optional explicit predecessor lifecycle bundle; required when embedded predecessor bundle digests are ambiguous
- `--archive-id <hex>`, `--state-id <hex>`, `--cohort-id <hex>`, `--bundle-digest <hex>` explicit predecessor selection pins
- `--reason-code <string>`, `--operator-role <string>`, `--notes <string>`, `--performed-at <iso8601>` transition-record fields
- `--maintenance-sig <file>`, `--maintenance-pqpk <file>`, `--maintenance-ots <file>` optional same-run maintenance evidence import for the newly emitted transition record
- `--out <dir>` defaults to `./reshared-shards`
- `--force` allows overwriting output files
- `--json` emits one JSON document on stdout

Output:

- successor `.qcont` shards with mode `0600` best-effort
- `archive-state.json` and `cohort-binding.json` sidecars
- `lifecycle-bundle.json` with mode `0644` best-effort
- `transition-record.json`, the maintenance signing target

Exit status:

- `0` when the successor cohort and sidecars were written
- `2` for usage errors or refused overwrite
- `7` for unsupported RS/Shamir geometry or unreachable predecessor quorum
- `8` for same-run maintenance signature, signer-key, or timestamp import failure
- `9` for ambiguous predecessor cohort or lifecycle-bundle selection
- `10` for same-state contract violations or forbidden archive-state override attempts
- `1` for other failures

`--json` output shape:

```json
{
  "command": "reshare",
  "ok": true,
  "cliSchemaVersion": 1,
  "archiveId": "hex",
  "stateId": "hex",
  "predecessorCohortId": "hex",
  "cohortId": "hex",
  "predecessorLifecycleBundleDigestHex": "hex",
  "predecessorLifecycleBundleSource": "embedded-lifecycle-bundle",
  "archiveStateBytesPath": "string",
  "archiveStateDigestHex": "hex",
  "cohortBindingBytesPath": "string",
  "cohortBindingDigestHex": "hex",
  "transitionRecordPath": "string",
  "transitionRecordDigestHex": "hex",
  "lifecycleBundlePath": "string",
  "lifecycleBundleDigestHex": "hex",
  "shards": [
    { "index": 0, "path": "string", "shardDigestHex": "hex", "shardSize": 12345 }
  ],
  "verificationReport": {
    "invalidShareIndices": [],
    "corruptedShardIndices": [],
    "missingShardIndices": [],
    "privateKeyHashMatchesMetadata": true
  },
  "maintenanceSignatureCountAdded": 0,
  "operationalWarnings": [],
  "semantics": {
    "sameStateAvailabilityMaintenance": true,
    "archiveReapprovalPerformed": false,
    "plaintextDecrypted": false,
    "sourceEvidenceCreated": false,
    "compromiseRepairClaimed": false
  },
  "zeroization": {
    "attempted": true,
    "privateKeyBytesCleared": true,
    "shareCopiesCleared": true
  }
}
```

Security notes:

- Reshare reconstructs predecessor `.qenc` and private-key material in memory through core lifecycle code. The CLI surfaces core's `zeroization` report verbatim and zeroizes parsed predecessor share buffers best-effort after use.
- Same-state resharing is availability maintenance only. It does not reapprove the archive state, does not decrypt plaintext, does not create source evidence, and does not repair a leaked predecessor quorum.
- The CLI rejects flags that would override archive-state semantics (`--archive-state`, `--qenc-hash`, auth-policy overrides, nonce/KDF overrides, and related fields) with `RESHARE_CONTRACT_VIOLATION`.
- `--performed-at` is only used when explicitly provided. Otherwise the CLI lets core create the transition timestamp and writes the exact canonical transition record emitted by core.
- Because successor cohort generation is randomized, operators normally sign the emitted `transition-record.json` after reshare and import that detached maintenance signature later with `qv attach`.

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
  "ok": true,
  "cliSchemaVersion": 1,
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
  "ok": true,
  "cliSchemaVersion": 1,
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
- `--pqpk <file>` repeatable; each file is an independently supplied PQ signer pin for this verification
- `--ots <file>` repeatable
- `--ed25519-signer <address>` supplies the independently expected Stellar signer
- `--include-detached-summary` adds a byte-free detached-signature summary for automation
- `--required-policy-level <integrity-only|any-signature|strong-pq-signature>` fails closed unless the bundle-declared policy is at least that strong and satisfied

Exit status:

- `0` when archive policy is satisfied and any requested `--required-policy-level` is satisfied
- `1` otherwise

When `--bundle` is present and no extension flags are supplied, `--json` emits the same authenticity object shape produced by browser restore for the same inputs. The extension flags only add fields; they do not remove or weaken existing authenticity data.

Signer material inside `--bundle` can make `bundledKeyVerified` true but cannot satisfy `any-signature` or `strong-pq-signature` by itself. Supply `--pqpk` or `--ed25519-signer` independently. Deprecated `bundlePinned` and bundle-pinned counters remain false/zero so stale automation fails closed.

Stable top-level fields:

```json
{
  "command": "verify",
  "ok": true,
  "cliSchemaVersion": 1,
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
    "archiveApprovalCryptographicallyVerified": true,
    "strongPqArchiveApprovalCryptographicallyVerified": false,
    "archiveApprovalSignatureVerified": true,
    "strongPqSignatureVerified": false,
    "bundledKeyVerified": false,
    "externallyPinned": true,
    "authorizedForPolicy": true,
    "signerPinned": true,
    "bundlePinned": false,
    "userPinned": true,
    "userPinProvided": true,
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

When `--required-policy-level` is supplied, `--json` also includes:

```json
{
  "requiredPolicy": {
    "level": "strong-pq-signature",
    "declaredPolicyLevel": "integrity-only",
    "declaredPolicySatisfiesRequired": false,
    "archivePolicySatisfied": true,
    "satisfied": false,
    "reason": "Archive policy level integrity-only is weaker than required policy level strong-pq-signature."
  }
}
```

When `--include-detached-summary` is supplied, `--json` also includes a byte-free `detachedSummary` array:

```json
{
  "detachedSummary": [
    {
      "id": "sig-...",
      "name": "archive.qsig",
      "source": "bundle",
      "family": "archive-approval",
      "format": "qsig",
      "ok": true,
      "targetType": "archive-state",
      "targetRef": "state:<stateId>",
      "signatureContentDigestHex": "hex",
      "proofIdentityDigestHex": "hex|null",
      "otsStampedDigestHex": "hex|null",
      "transitionIndex": null,
      "maintenancePurposeLabels": []
    }
  ]
}
```

Security notes:

- `--required-policy-level` only tightens verification. It cannot downgrade the bundle-declared policy and cannot turn an unsatisfied archive policy into success.
- `--include-detached-summary` intentionally omits detached signature bytes; use the original artifacts for byte-level archival.

Bundleless verification behavior:

- `qv verify` still verifies external detached signatures, `.pqpk` pins, and `.ots` linkage against the provided archive-state bytes.
- Policy remains unresolved without a lifecycle bundle.
- `policy.level` is `"unresolved"`.
- exit status is `1`.

Fail-closed operator checklist:

- Use `--archive-id`, `--state-id`, `--cohort-id`, and `--bundle-digest` when shard custody may contain multiple cohorts or lifecycle-bundle variants; the CLI does not choose a winner by timestamp, file name, or count.
- Preserve the exact archive-state descriptor bytes that were approved. Archive-approval signatures verify canonical archive-state bytes, not mutable lifecycle-bundle bytes.
- Treat lifecycle bundles as mutable evidence carriers. A restore may require explicit bundle selection or `--accept-policy-warnings` when a selected cohort carries multiple embedded bundle digests.
- Keep `.sig`, `.qsig`, `.pqpk`, and `.ots` target relationships intact. Detached signatures and timestamp proofs are only counted when their explicit target references match the archive-state, transition record, source-evidence object, or signature bytes expected by core verification.
- Cross-check implementation invariants against [`format-spec.md#91-cli-fail-closed-checklist`](format-spec.md#91-cli-fail-closed-checklist) when scripting ceremonies.

### `qv restore --shards <glob-or-file> [options] [--dry-run] [--json]`

Restores from a selected QVqcont-7 quorum. Without `--dry-run`, restore writes recovered `.qenc`, private-key, archive-state, and lifecycle-bundle artifacts. With `--dry-run`, it only evaluates whether restore would succeed and writes nothing.

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
- `--required-policy-level <integrity-only|any-signature|strong-pq-signature>`
  applies an operator minimum in addition to the archive-declared policy; it can
  only tighten restore and never changes archive bytes

Write options:

- `--out <dir>` defaults to `./restored`
- `--out-qenc <file>` overrides `<out>/recovered.qenc`
- `--out-key <file>` overrides `<out>/recovered.privateKey.qkey`
- `--decrypt` also decrypts the recovered `.qenc` in memory
- `--out-plaintext <file>` overrides `<out>/recovered.plaintext` and requires `--decrypt`
- `--accept-policy-warnings` is accepted for automation, but does not override `policy.satisfied === false`
- `--force` allows overwriting output files

Exit status:

- `0` when selected restore succeeds and, for write mode, artifacts were written
- `1` when authenticity policy prevents write-mode restore or restore would not succeed
- `2` for usage errors or refused overwrite
- `7` for quorum/RS/Shamir failure
- `9` for ambiguous archive/state/cohort or lifecycle-bundle selection
- `11` for restored `.qenc`, private-key, or plaintext integrity failure
- `12` when restore is otherwise policy-satisfied but the selected cohort embeds multiple lifecycle-bundle digests and `--accept-policy-warnings` was not supplied

When `--required-policy-level` is stronger than the selected archive's declared
and satisfied policy, dry-run returns `wouldSucceed: false` and write mode fails
with `POLICY_NOT_SATISFIED` before creating the output directory or files.

`--dry-run --json` output shape remains:

```json
{
  "command": "restore",
  "ok": true,
  "cliSchemaVersion": 1,
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
  "authenticity": {},
  "outputs": null
}
```

When `--required-policy-level` is present, both dry-run and successful write-mode
reports add a `requiredPolicy` object with the requested level, declared level,
comparison result, archive-policy result, final `satisfied` decision, and reason.
The field is absent when no operator floor was requested.

Write-mode `--json` output includes the same fields with `dryRun: false` and an `outputs` block:

```json
{
  "command": "restore",
  "ok": true,
  "cliSchemaVersion": 1,
  "dryRun": false,
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
  "authenticity": {},
  "outputs": {
    "qencPath": "string",
    "keyPath": "string",
    "archiveStatePath": "string",
    "lifecycleBundlePath": "string",
    "plaintextPath": "string|null"
  },
  "plaintext": {
    "outputPath": "string",
    "plaintextLength": 123,
    "fileHashHex": "hex",
    "originalFilename": "string|null"
  }
}
```

Dry-run guarantees:

- no plaintext file is written
- no recovered key file is written
- temporary recovered `qencBytes` and `privKey` buffers are zeroized before the CLI returns

Write-mode security notes:

- Core `restoreFromShards` enforces restore authenticity policy before reconstructing material. Policy failure writes no artifacts.
- The CLI enforces `--required-policy-level` after core authenticity evaluation
  and before any output preflight or directory creation. It cannot downgrade the
  archive-declared policy and `--accept-policy-warnings` cannot override it.
- The CLI writes recovered `.qenc` first with mode `0644` best-effort, then recovered private key with mode `0600` best-effort, then public sidecars with mode `0644`, then optional plaintext with mode `0600`.
- Recovered `qencBytes`, `privKey`, optional plaintext bytes, and parsed shard share buffers are zeroized best-effort in `finally` blocks. Node.js memory zeroization does not protect against swap, tracing, crash dumps, or hostile local administrators.
- `--decrypt` decrypts with the recovered key still in memory and verifies the authenticated private metadata plaintext hash before writing plaintext.

### `qv selftest [--filter <substring>] [--json]`

Runs the core cryptographic self-test suite exposed by `src/core/crypto/selftest.js#runSelfTest`.

Options:

- `--filter <substring>` runs only self-test cases whose prefixed name contains the substring
- `--json` emits one JSON document on stdout

Exit status:

- `0` when all selected self-tests pass
- `1` when any selected self-test fails
- `2` for usage errors, including a filter that matches no cases

`--json` output shape:

```json
{
  "command": "selftest",
  "ok": true,
  "cliSchemaVersion": 1,
  "total": 1,
  "passed": 1,
  "failed": 0,
  "results": [
    { "name": "CORE: RFC 8785 number serialization reference vectors", "ok": true }
  ],
  "filter": "RFC 8785 number serialization reference vectors"
}
```

Security notes:

- Self-test initializes the same Node WebCrypto and vendored Reed-Solomon runtime used by CLI split/restore/reshare.
- `--filter` is a test-selection aid only; release validation should run the full unfiltered suite.

### `qv version [--json]`

Prints package version, registered container/lifecycle format identifiers, and the active cryptographic profile without performing cryptographic operations.

`--json` output shape:

```json
{
  "command": "version",
  "ok": true,
  "cliSchemaVersion": 1,
  "version": "2.1.3",
  "format": {
    "qenc": "QVv1-5-0",
    "qcont": "QVqcont-7",
    "lifecycleBundle": "QV-Lifecycle-Bundle/v1",
    "archiveState": "quantum-vault-archive-state-descriptor/v1",
    "cohortBinding": "quantum-vault-cohort-binding/v1",
    "transitionRecord": "quantum-vault-transition-record/v1",
    "sourceEvidence": "quantum-vault-source-evidence/v1"
  },
  "alg": {
    "KEM": "ML-KEM-1024",
    "KDF": "KMAC256",
    "AEAD": "AES-256-GCM",
    "digest": ["SHA3-512", "SHA3-256"]
  },
  "cryptoProfileId": "QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2"
}
```

## JSON Error Shape

All commands emit this shape on failure when `--json` is passed:

```json
{
  "command": "keygen|encrypt|decrypt|split|attach|reshare|inspect|canonicalize|verify|restore|selftest|version",
  "ok": false,
  "cliSchemaVersion": 1,
  "error": "message",
  "qvCode": "USAGE|POLICY_NOT_SATISFIED|UNEXPECTED|..."
}
```

## Browser-To-CLI Migration

| Browser workflow | CLI command | Notes |
| --- | --- | --- |
| Generate keys | `qv keygen --out <dir>` | Writes the same raw ML-KEM-1024 `.qkey` key material. The optional `--name` value is a literal filename prefix. |
| Encrypt one file | `qv encrypt <file> --public-key <publicKey.qkey> --out <file.qenc>` | Uses the same `.qenc` core encryption path as the browser. |
| Encrypt a file bundle | `qv encrypt --pack <file> <file> ... --public-key <publicKey.qkey> --out <bundle.qenc> --filename <name.qvpack>` | Creates an authenticated `.qvpack` payload before `.qenc` encryption. |
| Decrypt | `qv decrypt <file.qenc> --private-key <privateKey.qkey> --out <file>` | `--extract-qvpack --out-dir <dir>` mirrors browser multi-file extraction when the decrypted payload is a `QVB1` pack. |
| Split / create successor shards | `qv split <file.qenc> --private-key <privateKey.qkey> --n <n> --k <k> --out <dir>` | Emits QVqcont-7 shards plus archive-state, cohort-binding, and lifecycle-bundle sidecars. |
| Attach archive approval | `qv attach --shards '<dir>/*.qcont' --sig <archive.qsig> --pqpk <signer.pqpk> --out-bundle <bundle.json> --out-shards <dir>` | Archive approval signatures target canonical archive-state bytes. |
| Attach maintenance evidence | `qv attach --bundle <bundle.json> --sig-import <descriptor.json> --out-bundle <bundle.json>` | Maintenance signatures must target an explicit transition-record already represented in the selected lifecycle bundle. |
| Attach source evidence | `qv attach --bundle <bundle.json> --source-evidence <source-evidence.json> --sig-import <descriptor.json> --out-bundle <bundle.json>` | Source-evidence signatures remain separate from archive policy satisfaction. |
| Verify archive policy | `qv verify <archive-state.json> --bundle <bundle.json> [--sig <sig>] [--pqpk <pin>] [--required-policy-level <level>]` | Non-zero means policy is not satisfied or inputs are invalid. `--required-policy-level` only tightens. |
| Restore dry-run | `qv restore --shards '<dir>/*.qcont' --dry-run --json` | Writes nothing and reports `outputs: null`. |
| Restore write mode | `qv restore --shards '<dir>/*.qcont' --bundle <bundle.json> --out <dir>` | Writes recovered `.qenc`, recovered private key, and sidecars only when policy is satisfied. |
| Same-state reshare | `qv reshare --shards '<dir>/*.qcont' --n <n> --k <k> --out <dir>` | Preserves exact archive-state bytes and emits a successor cohort plus transition record. |
| Inspect artifacts | `qv inspect <artifact> --json` | Supports lifecycle JSON, QVqcont-7 shards, `.qsig`, `.sig`, `.pqpk`, and `.ots`. |
| Canonicalize lifecycle JSON | `qv canonicalize <artifact.json>` | Emits canonical bytes for supported lifecycle JSON artifacts. |

## Examples

```bash
npm run cli -- inspect docs/schema/fixtures/qv-archive-state-descriptor-v1.valid.json --json
npm run cli -- keygen --out ./keys --json
npm run cli -- canonicalize docs/schema/fixtures/qv-archive-state-descriptor-v1.valid.json
npm run cli -- attach --shards '/path/to/shards/**/*.qcont' --sig /path/to/archive.qsig --pqpk /path/to/archive.pqpk --ots /path/to/archive.ots --out-bundle /path/to/attached.lifecycle-bundle.json --out-shards /path/to/attached-shards --json
npm run cli -- reshare --shards '/path/to/shards/**/*.qcont' --n 5 --k 3 --out /path/to/reshared-shards --performed-at 2026-03-25T12:34:56.000Z --json
npm run cli -- verify /path/to/archive-state.json --bundle /path/to/lifecycle-bundle.json --sig /path/to/archive.qsig --pqpk /path/to/archive.pqpk --ots /path/to/archive.ots --json
npm run cli -- verify /path/to/archive-state.json --bundle /path/to/lifecycle-bundle.json --required-policy-level strong-pq-signature --include-detached-summary --json
npm run cli -- restore --shards '/path/to/shards/**/*.qcont' --bundle /path/to/lifecycle-bundle.json --out /path/to/recovered --json
npm run cli -- restore --shards '/path/to/shards/**/*.qcont' --bundle /path/to/lifecycle-bundle.json --out /path/to/recovered --decrypt --out-plaintext /path/to/plaintext.bin --json
npm run cli -- restore --shards '/path/to/shards/**/*.qcont' --bundle /path/to/lifecycle-bundle.json --dry-run --json
npm run cli -- selftest --json
npm run cli -- version --json
```
