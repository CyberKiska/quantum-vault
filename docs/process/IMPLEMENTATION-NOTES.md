# Implementation Notes

Status: Draft
Type: Informative
Audience: Contributors, maintainers, reviewers
Scope: Historical design rationale for the manifest/bundle/signature workflow, plus contributor-oriented codebase notes
Out of scope: Normative format rules, normative policy semantics, threat-model claims, archival taxonomy

## Role

This file is no longer a specification.

It preserves the implementation-facing theory that shaped the current mechanics around:

- canonical manifests versus mutable manifest bundles
- detached signatures and bundle attachments
- `.ots` evidence handling
- restore-time separation of integrity, signature validity, pinning, and policy satisfaction

Use this file when you need contributor context, historical design intent, or a codebase map.
Use the core docs when you need the current normative rules.
Use `docs/glossary.md` when you need the canonical meaning of shared terms.

## Current normative homes

| Topic | Current owner |
| --- | --- |
| Artifact structure, canonicalization, embedded manifest/bundle layout, restore/verifier flow | `docs/format-spec.md` |
| Signature meaning, proof counting, pinning, policy levels, restore authorization semantics | `docs/trust-and-policy.md` |
| Security boundaries, assumptions, invariants, failure semantics, claim limits | `docs/security-model.md` |
| Archive classes, OAIS mapping, renewal, migration, long-horizon archival direction | `docs/long-term-archive.md` |
| Shared vocabulary and status terms | `docs/glossary.md` |
| Documentation roles and source-of-truth map | `docs/README.md` |

## Historical context

This document was written while the repository was deciding how to model:

- the canonical manifest as the stable signable object
- the embedded or external bundle as the mutable authenticity carrier
- detached signatures and detached `.ots` proofs as add-on artifacts rather than inline rewrites of signed bytes

That strategy work led directly to the current implementation, but the project now has better homes for detailed format and policy descriptions.

## Design rationale retained for contributors

### 1. Why the canonical manifest is separate from the bundle

The main design choice was to keep one immutable signable object and one mutable attachment object.

The canonical manifest exists so that:

- detached signatures always target stable bytes
- signers can use external tooling without understanding the bundle format
- the implementation can add signatures, bundled keys, or `.ots` evidence later without changing what was signed

The bundle exists so that:

- authenticity material can travel with the archive
- `.qcont` shards can stay self-contained enough for recovery workflows
- the system can preserve detached-signature interoperability while still offering a portable archive package

That split remains one of the most important mental models for contributors.

### 2. Why signatures target the canonical manifest only

The implementation intentionally avoids signing mutable bundle bytes.

The reason is simple:

- signatures should remain valid when attachments are added later
- bundle growth should not force re-signing
- verifiers should be able to answer "what exact archive description was signed?" without ambiguity

When working on signing, attach, or restore code, treat the canonical manifest as the only detached-signature payload unless the core spec changes explicitly.

### 3. Why `.ots` is supplementary evidence

OpenTimestamps was integrated as evidence, not as a substitute for a detached signature.

That choice came from the strategy phase because:

- timestamp linkage is useful even when it is incomplete or externally verified later
- `.ots` artifacts are easier to treat honestly as supporting evidence than as a standalone authenticity primitive
- keeping `.ots` tied to detached signature artifacts avoids changing manifest signing semantics

In practice, this means contributors should think about `.ots` handling as:

- target linkage
- completeness reporting
- export/import portability

and not as a replacement for signature verification or policy satisfaction.

#### Timestamp-target options considered during design

During the strategy phase, three timestamping approaches were considered:

1. Timestamp only the detached signature artifact.
2. Timestamp both the canonical manifest and the detached signature separately.
3. Timestamp a small seal object containing the manifest hash plus signature hashes.

The current implementation direction favored timestamping the detached signature artifact because it added the least workflow complexity while still preserving useful existence evidence for a signed object.
The core docs now define only the current supported behavior, but this tradeoff remains useful context for contributors evaluating future timestamp changes.

### 4. Why restore separates four states

The implementation was deliberately shaped around four separate outcomes:

1. integrity verified
2. signature verified
3. signer identity pinned
4. archive policy satisfied

This separation exists to prevent UI and code from collapsing distinct facts into vague claims like "trusted."
If a change touches restore status, logging, or UI labels, preserve this separation unless the core trust model is intentionally changed.

### 5. Why restore uses consistent cohorts, not "largest cohort wins"

The strategy phase surfaced an important recovery rule: consistency matters more than volume.

Contributors touching shard restore logic should preserve the idea that restore selects a coherent shard cohort based on matching bindings and format identity, rather than simply preferring the numerically largest pile of shards.

The exact normative rule now lives in the core docs, but the reason is implementation-facing:

- mixed or conflicting cohorts are a safety problem, not just a UX problem
- recovering from the "largest" set can silently select the wrong archive state

### 6. Terminology note for `secretKey.qkey`

The canonical terminology home is `docs/glossary.md`.

The implementation still uses the filename `secretKey.qkey`.
Historically that name was convenient operationally, but it is not the right cryptographic term for the object inside.

Contributor rule:

- treat the object in `secretKey.qkey` as an asymmetric `privateKey`
- reserve `secretKey` for symmetric secret material such as derived AES/KMAC keys

If you touch docs, logs, UI, or code comments, keep that distinction explicit.

## Contributor guidance for future changes

### If you change manifest or bundle structure

- update `docs/format-spec.md`
- keep canonical manifest bytes stable across attach operations unless the format contract is intentionally changed
- verify that embedded manifest and embedded bundle bindings still round-trip cleanly

### If you change signature, pinning, or restore-policy semantics

- update `docs/trust-and-policy.md`
- preserve the distinction among signature validity, pinning, and policy satisfaction
- verify status vocabulary in UI and logs

### If you change failure behavior, invariants, or security claims

- update `docs/security-model.md`
- check whether the change weakens fail-closed behavior or broadens claims beyond what the project can honestly support

### If you change long-horizon archival behavior

- update `docs/long-term-archive.md`
- distinguish current implementation from future archival direction

## Current examples and fixtures

The development repository contains an `examples/` folder with example data for contributor inspection, including:

- small and multi-file encrypted containers
- encryption and signature key material
- canonical manifest examples
- detached signature examples
- timestamp evidence examples

Use those fixtures for manual inspection and documentation work.
Do not treat them as a stable interoperability test-vector suite unless the repository later promotes them to that role.

Note: the `examples/` directory is excluded from published releases via `.gitignore` and is available only in local development copies of the full repository.

## Current repository layout

This appendix preserves the contributor-facing codebase map that previously lived in `README.md`.

```text
LICENSE                              # License text (AGPL-3.0)
README.md                            # Product landing page
index.html                           # Main HTML file
style.css                            # Main CSS styles file
package.json                         # Dependencies and npm scripts
package-lock.json                    # Locked dependency graph
scripts/
├── dev.mjs                          # Local static dev server
├── build.mjs                        # Deterministic build + integrity checks
└── selftest.mjs                     # Headless self-test runner entrypoint
public/
└── third-party/
    └── erasure.js                   # Reed-Solomon runtime library
src/
├── main.js                          # Application entry point
├── utils.js                         # Shared browser utilities
├── app/                             # Browser/runtime adapters
│   ├── crypto-service.js            # UI-facing facade for core crypto operations
│   ├── session-wipe.js              # beforeunload/pagehide secret wipe registry
│   ├── browser-entropy-collector.js # Browser entropy collection (DOM events)
│   ├── restore-inputs.js            # Restore input classification from File objects
│   └── shard-preview.js             # Lightweight .qcont preview for UI status
└── core/
    ├── crypto/                      # Core crypto + format logic (UI-agnostic)
    │   ├── index.js                 # Main encryption/decryption orchestration
    │   ├── aead.js                  # AES-GCM nonce/IV policy helpers
    │   ├── kdf.js                   # KMAC derivation and key commitment helpers
    │   ├── kmac.js                  # Local SP 800-185 KMAC adapter over noble
    │   ├── mlkem.js                 # ML-KEM-1024 implementation
    │   ├── entropy.js               # CSPRNG + entropy mixing primitives
    │   ├── erasure-runtime.js       # RS runtime resolver (globalThis/injected)
    │   ├── constants.js             # Format/profile constants
    │   ├── policy.js                # Crypto policy validation
    │   ├── bytes.js                 # Byte/hex/constant-time helpers
    │   ├── qenc/
    │   │   └── format.js            # .qenc header build/parse
    │   ├── qcont/
    │   │   ├── build.js             # Shard construction + initial manifest bundle
    │   │   ├── attach.js            # Manifest bundle attach/merge workflow
    │   │   └── restore.js           # Shard restore/reconstruction + authenticity gating
    │   ├── manifest/
    │   │   ├── archive-manifest.js  # Canonical archive manifest schema/validation
    │   │   ├── manifest-bundle.js   # Self-contained manifest bundle schema/validation
    │   │   └── jcs.js               # Project-defined canonicalization helpers (QV-C14N-v1)
    │   ├── auth/
    │   │   ├── qsig.js              # Quantum Signer v2 detached signature parsing/verify
    │   │   ├── stellar-sig.js       # Stellar WebSigner v2 detached signature verify
    │   │   ├── opentimestamps.js    # OpenTimestamps parsing/linking
    │   │   ├── signature-identity.js # Detached proof identity normalization/dedupe
    │   │   ├── signature-suites.js  # Normalized signature suite registry
    │   │   └── verify-signatures.js # Unified verification policy orchestration
    │   ├── splitting/
    │   │   └── sss.js               # Shamir Secret Sharing
    │   └── selftest.js              # Headless/browser self-test suite
    └── features/                    # UI workflows and rendering
        ├── lite-mode.js             # Simplified interface
        ├── bundle-payload.js        # Multi-file bundle payload helpers
        ├── qcont/
        │   ├── build-ui.js          # Pro split UI handlers
        │   ├── attach-ui.js         # Pro attach UI handlers
        │   └── restore-ui.js        # Pro restore UI handlers
        └── ui/
            ├── ui.js                # Pro UI orchestration
            ├── shards-status.js     # Shard threshold/readiness status UI
            ├── logging.js           # Unified structured logs for Lite/Pro
            └── toast.js             # Toast notification UI helpers
docs/                                # Documentation set and working notes
```

## Current module map

| Area | Responsibility | Key outputs or decisions |
| --- | --- | --- |
| `src/core/crypto/index.js` | Encrypt/decrypt orchestration | `.qenc` construction and parsing |
| `src/core/crypto/qenc/` | Archive header format | Container header and metadata framing |
| `src/core/crypto/qcont/build.js` | Split/shard builder | `.qcont`, canonical manifest, initial bundle |
| `src/core/crypto/qcont/attach.js` | Bundle attachment workflow | Extended bundle, optional shard rewrites |
| `src/core/crypto/qcont/restore.js` | Cohort selection and reconstruction | Policy-gated restore, mixed-bundle handling |
| `src/core/crypto/manifest/` | Manifest and bundle schemas | Canonical archive description and mutable authenticity bundle |
| `src/core/crypto/auth/` | Detached signature and OTS verification | PQ signatures, Stellar proofs, proof-identity dedupe, timestamp linkage |
| `src/app/restore-inputs.js` | Restore-time file classification | Detects `.qcont`, manifest, bundle, signatures, `.pqpk`, `.ots` |
| `src/core/features/qcont/` | Pro mode shard workflows | Build, attach, and restore UI integration |
| `src/core/features/lite-mode.js` | Lite mode workflow | Simpler end-to-end protect/restore experience |

## Retained historical note

During the original strategy phase, this document temporarily carried detailed format and policy text because those mechanics were still being invented.
That material has now been absorbed into the proper destination docs.

At that time, the project also assumed there were no active users to preserve for compatibility.
Any future compatibility decisions should now be made explicitly in the core docs rather than inferred from this historical note.

If future work needs another large strategy memo, prefer placing it under `docs/internal/` rather than turning this file back into a shadow specification.
