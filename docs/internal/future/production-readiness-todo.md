# Production-hardening TODO

Status date: 2026-07-17

JavaScript baseline: `improvementV3` at `70c6eca7238a70deb2e4bd6ba1c3202697b33422`

Rust comparison baseline: external `CyberKiska/qv-rs` at `f29f0905d88118858b44a6c71a355291544f3e97`

This file turns `analysis.md` into an evidence-ranked implementation queue. It is
not a production-readiness claim. A task is complete only when its stated gate is
covered by implementation, negative tests, current specifications, and migration
notes. Passing regression tests do not substitute for cryptographic review,
independent implementation review, or an operational security assessment.

Status values:

- **open** — the required property is absent;
- **partial** — some required behavior exists, but the acceptance gate is not met;
- **blocked-external** — evidence or changes are required outside this checkout;
- **complete** — the recorded acceptance gate passed on the named baseline.

## Stage 0 — evidence baseline and compatibility boundary

- [x] **BASE-001 (complete): clean branch baseline.** `npm run check` passed:
  40 core tests, 79 CLI tests, 5 same-implementation parity tests, 190 self-test
  checks, 27 schema fixtures, 59 corpus entries, CLI self-test, and production
  build. Browser and Rust release checks are separate gates below.
- [ ] **FMT-000 (open): machine-readable active-format and domain registry.**
  Record every magic value, suite identifier, exact size, byte order, domain
  string, critical field, resource limit, and lifecycle state. CI must compare
  implementation constants with the registry.
- [ ] **CLAIM-001 (partial): claims ledger.** Reconcile security, format, trust,
  preservation, CLI, and UI claims with executable behavior. Current confirmed
  corrections to `analysis.md` are:
  - standalone JavaScript `.qenc` parsing now derives and checks exact ciphertext
    geometry;
  - restore already exposes exact state and cohort selectors, although it still
    lacks a restore-time policy floor;
  - `tests/parity` compares the Node CLI with the shared JavaScript core, not Rust.
- [ ] **RUST-001 (blocked-external): co-equal Rust conformance changes.** The Rust
  repository is not part of this branch. Audit it at the pinned commit, keep shared
  corpus changes portable, and require a coordinated Rust change before declaring
  a cross-language gate complete.

## Stage 1 — release-blocking trust and archive-key isolation

- [x] **SEC-101-JS (complete, critical): remove mutable-bundle
  self-authorization in JavaScript.**
  Bundled signer material may establish only cryptographic self-consistency. It
  must not be described as pinned/trusted or count toward archive policy without
  an independently supplied signer pin or trust policy. Apply the rule to PQ and
  classical signature paths. Preserve inspection of cryptographically valid but
  unauthorized evidence.
  - Gate: an attacker-created key, signature, and rewritten lifecycle bundle can
    verify but contributes zero authorized approvals and cannot satisfy
    `any-signature` or `strong-pq-signature`.
  - Gate: the same signature counts when its identity is supplied independently.
  - Migration: current bytes remain readable; acceptance becomes deliberately
    stricter. No compatibility switch may restore bundle-self-trust.
- [ ] **SEC-101-RUST (blocked-external, critical): apply the same trust boundary
  to the co-equal Rust implementation.** Rust baseline `f29f090` still treats a
  key carried by the lifecycle bundle as archive-policy authority. Until its
  implementation, negative tests, and migration notes change, SEC-101 is not an
  ecosystem-wide property and the trust milestone remains open.
- [ ] **SEC-102 (open, high): fresh Lite ML-KEM keypair per archive.** Remove the
  session-global archive key reuse domain and wipe per-operation private material
  on success, failure, and cancellation.
  - Gate: two consecutive Lite creations have distinct keys and key commitments;
    recovery material from either archive cannot decrypt the other.
  - Migration: previously reused-key archives require fresh-key re-encryption;
    resharing does not isolate them.
- [ ] **SEC-103 (partial, high): explicit threshold-bypass accounting.** Raw
  private-key export is a 1-of-1 recovery root. Separate it from threshold-only
  creation, require an explicit acknowledgement, and record the choice without
  recording secret material.
- [ ] **SEC-104 (partial): secret-boundary regression suite.** Add canaries proving
  private keys, shared secrets, derived keys, plaintext, private filenames, and
  stable private-key fingerprints never enter JSON reports, errors, logs, DOM,
  storage, output filenames, or telemetry.
- [ ] **SEC-105 (partial): restore-time external constraints.** Add a minimum policy
  floor and explicit expectation terminology for the existing archive/state/cohort
  selectors. Define a versioned, independently supplied trust-policy artifact
  before supporting signer roles or allowlists.
  - [x] **SEC-105-POLICY-FLOOR (complete):** CLI verify and restore accept the
    same fail-closed `--required-policy-level`; dry-run reports the comparison and
    write mode rejects a weaker archive before any output creation.
  - [ ] **SEC-105-TRUST-POLICY (open):** define the versioned external artifact,
    roles/fingerprints, freshness expectations, and browser workflow. Existing
    exact archive/state/cohort selectors remain the current expectation inputs.

## Stage 2 — fail-closed current formats and recoverability

- [ ] **FMT-201 (partial, high): strict `.qenc` metadata profile.** Exact KEM, KDF,
  AEAD, payload, crypto-profile, nonce, AAD, domain, and geometry values must be
  mandatory. Reject unknown fields and nested unknown fields. Align the writer's
  metadata bound with every reader and validate required private metadata after
  authentication.
  - Gate: JavaScript and Rust make the same accept/reject decision for every
    canonical and malformed corpus item.
  - Migration: canonical current output is unchanged; noncanonical artifacts are
    inspection/quarantine-only and are never silently reinterpreted.
  - [x] **FMT-201-JS-PUBLIC (complete):** JavaScript now requires the exact closed
    19-member public metadata schema and four-member domain map, fixed current
    algorithms/profile/nonce contracts, exact 1568-byte ML-KEM ciphertext, one
    non-bypassable 4096-byte metadata cap, safe ciphertext arithmetic, and exact
    ciphertext exhaustion. Golden and malformed vectors cover the boundary.
  - [x] **FMT-201-JS-PRIVATE (complete):** authenticated `wrapped-v1` private
    metadata is an exact four-field schema under one 4096-byte writer/reader cap.
    The timestamp has one canonical UTC millisecond form; original length and
    lowercase SHA3-512 fixity are mandatory and recomputed before plaintext is
    returned. Negative vectors cover missing, extra, duplicate, mistyped,
    oversized, noncanonical, and inconsistent authenticated values without
    reflecting private values in errors. Canonical writer bytes remain unchanged;
    noncanonical custom-timestamp artifacts are quarantine-only.
  - [ ] **FMT-201-RUST (blocked-external):** Rust baseline `f29f090` already
    denies unknown public fields but still permits omitted algorithm/profile
    labels, lets its low-level writer exceed its 4096-byte reader cap, and defers
    the 1568-byte KEM-ciphertext check until decapsulation. Parser parity remains
    unproved until mirrored changes and live differential tests land externally.
- [ ] **REL-201 (partial, high): authenticated shard reconstruction geometry.** Select
  and quarantine shards individually using the archive-state `containerId` and
  authenticated `.qenc` header. Derive ciphertext and RS fragment geometry from
  that header, require exact fragment lengths, checked safe arithmetic, input caps,
  and exact stream exhaustion.
  - Gate: a malformed or poisoned non-quorum extra shard cannot deny recovery of a
    valid quorum.
  - Gate: short, long, duplicate-index, out-of-range, oversized, and trailing-byte
    shards fail closed without large attacker-driven allocations.
  - [x] **REL-201-JS (complete):** JavaScript selects only a strict QENC header
    whose exact bytes match the archive-state `containerId`; treats outer geometry
    as non-authoritative; derives exact ciphertext and fragment-stream lengths;
    enforces exact 3169-byte shares, commitments, checked arithmetic, a
    non-raiseable 1 GiB + 1 MiB ciphertext ceiling, and exact stream exhaustion;
    reuses one bounded erasure buffer; and strict-parses and hashes the completed
    QENC. Header, share, and body faults are independently quarantined within the
    committed budget. Adversarial and injected-runtime tests cover poisoned first
    headers, short/long/overflow/trailing/oversized bodies, bad share size,
    duplicate/out-of-range indices, resource ceilings, and wrong RS output size.
  - [ ] **REL-201-RUST (blocked-external):** Rust baseline `f29f090` already uses
    committed header geometry and exact fragment lengths, but an exact-length
    mismatch in a parse-valid extra aborts the selected cohort rather than being
    quarantined within the erasure budget, and it lacks the same explicit
    reconstruction ceiling. Ecosystem recovery parity remains unproved.
- [ ] **FMT-202 (open, high): normative Shamir and erasure-code specification.**
  Freeze field polynomials, coordinate encodings, generator matrices, shortening,
  padding, fragment geometry, corruption semantics, and known-answer vectors.
- [ ] **INT-201 (blocked-external): live JS↔Rust interoperability and differential
  malformed-input testing.** Each implementation must generate artifacts consumed
  by the other in CI; copied fixtures and JS-core parity are insufficient.

## Stage 3 — bounded processing and late commit

- [ ] **REL-301 (partial, high): no output before complete validation.** Pro browser
  restore/decrypt must verify authenticated private fixity and validate every
  output name before triggering any download. CLI multi-file extraction must
  commit as one artifact set or roll back completely under injected write,
  `fsync`, and rename failures.
  - [x] **REL-301-DESTINATION-GATE (complete):** atomic file helpers reject
    directories, live or broken symlinks, and other non-file destinations even
    under `--force`; multi-artifact plans reject duplicate and lexical
    ancestor/descendant paths before staging. Regression tests preserve existing
    directory contents and symlink targets and leave no temp/backup artifacts on
    these preflight failures. This does not establish crash-atomic multi-file
    publication or close input/output alias races.
  - [x] **REL-301-QVPACK-PREFLIGHT (complete):** CLI extraction plans and
    sanitizes every direct-child destination, rejects duplicate names and an exact
    lexical input-QENC alias, builds all hashes and report data, and stages one
    `0600` artifact set before publication. A bad later destination cannot modify
    an earlier output. Crash consistency, rollback/cleanup fault tolerance,
    filesystem-normalized aliases, inode aliases, and parent-directory TOCTOU
    remain open under REL-301.
- [ ] **REL-302 (open, high): aggregate resource policy.** Bound file count,
  individual bytes, aggregate bytes, metadata, shard count, reconstructed bytes,
  and allocation arithmetic before reads/allocations. Report local resource-limit
  failures distinctly from invalid-format failures.
  - [x] **REL-302-QVPACK-CORE (complete):** QVPACK v1 reader and writer share
    non-raiseable limits of 4096 entries, 255 UTF-8 name bytes, and 1 GiB for each
    entry, aggregate payload, and encoded bundle. Fatal UTF-8, duplicate names,
    truncation, trailing bytes, and checked pre-allocation arithmetic have negative
    and deterministic property coverage; canonical in-profile bytes are unchanged.
    Adapter pre-read bounds, streaming, distinct CLI resource `qvCode`,
    filesystem-normalized aliases, and physical boundary tests remain open.
- [ ] **REL-303 (open, large): streaming encryption, decryption, RS, hashing, and
  private temporary output.** Peak memory must be a documented bounded function of
  chunk size and shard profile. Publication occurs only after AEAD, length, private
  metadata, and final digest checks pass.
- [ ] **REL-304 (open): localized fixity and scrub/repair tooling.** Detached,
  versioned per-chunk fixity may augment current whole-shard hashes without changing
  existing shard meaning.

## Stage 4 — operational custody and digital preservation

- [ ] **SEC-401 (open): signed active-cohort checkpoints.** Independently trusted,
  monotonic, PQ-authorized checkpoints bind archive, state, active cohort, epoch,
  predecessor, and policy. Offline freshness limits remain explicit.
- [ ] **ARC-401 (open): deterministic preservation pack.** Package public artifacts,
  schemas, KATs, malformed corpus, trust material, SBOM, source/build provenance,
  and PREMIS-compatible events without secret keys. Packaging is not OAIS or ISO
  16363 certification.
- [ ] **ARC-402 (open): renewable evidence and operations.** Define scrub, repair,
  media-refresh, hash/signature/timestamp renewal, dependency escrow, migration,
  rollback, and representation-information schedules.
- [ ] **SUP-401 (open): release/supply-chain evidence.** Reproducible build recipe,
  pinned toolchain, SBOM, signed release artifacts, browser security headers, and
  an independent cryptographic/security review.

## Stage 5 — successor-format research and migration

- [ ] **NEXT-501 (deferred): reserve, specify, and prototype successor formats.** A
  successor may split a per-archive recovery secret wrapping a random payload DEK,
  separate immutable payload from replaceable access state, localize shard damage,
  and offer explicit privacy profiles. It must use new magic/version identifiers.
- [ ] **MIG-501 (deferred): dual-read, full-reencrypt migration.** Never convert in
  place. Verify old and new anchors, issue a signed continuity record, preserve
  rollback material, and never delete legacy artifacts automatically.
- [ ] **RESEARCH-501 (deferred): PQ VSS/DKG/threshold KEM, PoR, and ZK.** These remain
  optional research until exact security statements, PQ assumptions, corruption
  bounds, formal analysis, and independent implementations exist. Classical
  ECC/pairings must not become a confidentiality or authorization root.

## Milestone release gates

1. **Trust gate:** Stage 1 attacker/regression tests pass; no mutable evidence can
   bootstrap its own authorization; Lite archive keys are isolated.
2. **Format gate:** Stage 2 strict corpus and live bidirectional JS↔Rust tests pass;
   malformed extras cannot poison a valid quorum.
3. **Reliability gate:** Stage 3 resource and fault-injection tests pass; corrupt or
   partial plaintext is never published.
4. **Preservation gate:** Stage 4 artifacts and recurring procedures are executable,
   independently anchored, and tested through a migration/repair exercise.
5. **Production claim gate:** all earlier gates plus independent security review,
   deployment review, cryptographic dependency review, reproducible release
   evidence, and an explicit residual-risk acceptance are complete. Until then,
   Quantum Vault remains experimental.
