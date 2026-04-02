# Security model

Status: Release Candidate
Type: Normative
Audience: implementers, security auditors, reviewers, maintainers
Scope: current-state normative baseline for security boundaries, adversary assumptions, hard invariants, security claims, and failure semantics
Out of scope: byte-level field definitions, archive-class policy, evidence-renewal architecture, whitepaper rationale
Primary implementation sources: implementation code, `docs/format-spec.md`, `docs/trust-and-policy.md`

## Role

This document is the normative home for security boundaries, assumptions, hard invariants, and claim limits.
It turns the repository's current behavior into explicit security statements for implementers and auditors.

Division of labor:

- `format-spec.md` defines byte-level format, canonicalization, and verifier flow
- `trust-and-policy.md` defines the meaning of signatures, pinning, and archive policy outcomes
- `security-model.md` defines what the system is trying to protect, what it assumes, what it does not claim, and which invariants must not be violated

## Scope

This document covers the current security boundaries, assets, adversary assumptions, hard invariants, security claims, and failure semantics for the Quantum Vault artifact family and restore flow.
It does not define byte-level field layouts, archive-class policy, evidence-renewal architecture, or whitepaper rationale.

## Normative status

This document is normative for current security boundaries, assumptions, hard invariants, claim limits, and failure semantics.
Use it to understand which guarantees the repository is actually claiming today and which claims remain intentionally out of scope.

Conformance:

- this document defines the security model and claim boundary for conforming implementations of the current Quantum Vault artifact family
- an implementation is conformant to this version if and only if it satisfies all MUST-level requirements defined in the current normative sections of this document
- if an implementation deviates from this security model, it MUST explicitly document the deviation and MUST declare itself non-conformant to this version
- statements explicitly labeled as future or recommended direction are non-normative until they are promoted into the current sections of this file
- in case of ambiguity, this document MUST be interpreted conservatively and in favor of narrower claims and fail-closed behavior

## Sources and references

Internal current-state grounding:

- `src/app/session-wipe.js` and `src/app/browser-entropy-collector.js` for browser-session secret handling and entropy collection posture
- `src/core/crypto/index.js`, `src/core/crypto/aead.js`, and `src/core/crypto/qenc/format.js` for encryption, AAD boundaries, and key-commitment behavior
- `src/core/crypto/qcont/restore.js`, `src/core/crypto/qcont/lifecycle-shard.js`, `src/core/crypto/manifest/archive-manifest.js`, and `src/core/crypto/manifest/manifest-bundle.js` for reconstruction, manifest, bundle, and successor lifecycle integrity behavior
- `src/core/crypto/lifecycle/artifacts.js` for successor lifecycle bundle and detached-signature target semantics
- `src/core/crypto/auth/verify-signatures.js`, `src/core/crypto/auth/qsig.js`, `src/core/crypto/auth/stellar-sig.js`, and `src/core/crypto/auth/opentimestamps.js` for authenticity and evidence handling
- `index.html`, `README.md`, `docs/series/SERIES-STANDARTS.md`, `docs/format-spec.md`, `docs/trust-and-policy.md`, `docs/long-term-archive.md`, and `docs/glossary.md` for delivery, client-only assumptions, threat framing, and cross-document constraints

External references already used elsewhere in the repository:

- FIPS 203 for ML-KEM-1024 context
- FIPS 202 for SHA-3 hashing context
- SP 800-185 for KMAC256 derivation context
- SP 800-38D for AES-GCM AEAD assumptions
- FIPS 204 and FIPS 205 for detached PQ signature context
- RFC 8032 for Ed25519 signature context

## Current implementation status

Implemented now:

- client-only browser execution with no runtime cryptographic network service
- detached-signature and policy-gated authenticity evaluation layered on top of archive integrity checks
- fail-closed parsing and deterministic restore behavior for the current artifact family
- best-effort in-memory secret wiping and no intended persistent secret storage
- explicit separation among integrity, signature validity, pinning, and policy satisfaction
- **Successor lifecycle** artifacts (QVqcont-7 shards, `QV-Lifecycle-Bundle` v1) with archive-state–centric approval and fail-closed restore selection rules described in `format-spec.md` Section 8
- successor-default regular-user creation in Lite and Pro, with legacy manifest/bundle handling retained only as a compatibility surface for existing archives

Not yet provided by the current implementation:

- resistance to a fully compromised host or browser environment
- hardware-backed key isolation or strong side-channel resistance
- a complete renewable evidence-record architecture
- institutional governance, repository certification, or mandatory signer pinning by default

## Future work and non-normative notes

Statements explicitly labeled as future or recommended direction are non-normative.
Likely future security-document expansion areas, but not current claims, include:

- more explicit time-shifted adversary phases and long-horizon claim language
- deeper treatment of verifier-oracle exposure and chosen-ciphertext surfaces
- security requirements for migration, rewrap, reencryption, and renewal events

## 1. Status, scope, and claim boundaries

This document applies to the current Quantum Vault artifact family and restore flow:

- `.qenc` encrypted containers
- `.qcont` threshold shards
- canonical `*.qvmanifest.json` and mutable `*.extended.qvmanifest.json` bundles for the legacy track
- archive-state descriptors, cohort bindings, lifecycle bundles, transition records, and source-evidence objects for the successor lifecycle track
- detached `.qsig`, `.sig`, `.pqpk`, and `.ots` inputs as currently supported

It also assumes the current supporting tool ecosystem:

- Quantum Vault for encrypt, split, attach, restore, and decrypt
- Quantum Signer for detached PQ signatures and `.pqpk`
- Stellar WebSigner for detached Ed25519/Stellar proofs
- OpenTimestamps tooling for optional evidence files

Current claim boundaries:

- This document defines current security properties only for the presently documented implementation model.
- This document distinguishes current guarantees, current assumptions, and future recommendations.
- This document does not claim that the current repository already provides a full long-term evidence-record architecture or a final 50-year archival design.

Terminology used here follows `docs/glossary.md` and `format-spec.md`:

- `privateKey` means asymmetric secret material
- `secretKey` means symmetric secret material
- the exported filename `secretKey.qkey` is a legacy operational name for the ML-KEM private key file

## 2. Assets and trust boundaries

### 2.1 Assets

| Asset | Primary security concern | Current notes |
| --- | --- | --- |
| Plaintext payload | Confidentiality, integrity | Exists before encrypt and after decrypt in browser memory |
| ML-KEM private key file (`secretKey.qkey`) | Confidentiality, recoverability | This is asymmetric `privateKey` material, despite the legacy filename |
| ML-KEM public key file (`publicKey.qkey`) | Integrity, correct binding | Used to encapsulate the shared secret for `.qenc` creation |
| Shared secret and derived symmetric secrets (`Kraw`, `Kenc`, `Kiv`) | Confidentiality | Ephemeral runtime-only symmetric `secretKey` material |
| `.qenc` container | Confidentiality, fixity, parse safety | Public metadata plus authenticated ciphertext |
| `.qcont` shards | Threshold secrecy, recoverability, integrity | Carry one share, RS fragments, and embedded authenticity material; legacy shards embed manifest and bundle, successor shards embed archive-state, cohort binding, and lifecycle bundle |
| Canonical manifest / archive-state descriptor | Fixity, signature target integrity | Immutable detached-signature payload for the selected track |
| Manifest bundle / lifecycle bundle | Policy transport, authenticity metadata integrity | Mutable object carrying policy and attachments for the selected track |
| Cohort binding and transition records | Cohort integrity, lineage integrity | Successor-only lifecycle objects used for cohort identity and same-state resharing provenance |
| Detached signatures and public-key attachments | Provenance, signer binding | Current external authenticity material |
| OTS evidence | Evidence linkage | Supplementary only; not a policy-satisfying signature substitute |

### 2.2 Trust boundaries

Current major trust boundaries are:

- the browser/runtime boundary, where secret material exists only as best-effort ephemeral memory
- the delivery/build boundary, where users must trust or verify the static application they loaded
- the storage/custodian boundary, where shards and detached artifacts may be stored by untrusted third parties
- the external signer/evidence boundary, where Quantum Vault consumes signatures and timestamps produced by separate tools

## 3. Adversary model

Quantum Vault's current security model assumes an adversary may:

- capture and store ciphertexts, shards, manifests, signatures, and bundles indefinitely, including for harvest-now-decrypt-later scenarios
- tamper with stored artifacts, substitute artifacts, replay stale artifacts, or mix conflicting shard cohorts
- inject malformed inputs to exploit parser differences or unsafe error handling
- compromise one or more shard custodians or storage providers
- observe verifier success/failure behavior
- compromise the host environment, browser runtime, or browser extensions
- compromise dependencies or the application delivery path
- gain stronger future cryptanalytic capability, including post-quantum capability against classical public-key systems

Current model distinctions:

- passive capture is in scope
- active tampering is in scope
- post-quantum adversaries are in scope for long-lived archives
- a fully compromised local runtime is acknowledged as a serious residual risk, not a threat the current browser implementation can defeat

### 3.1 Harvest-now-decrypt-later timeline model

For long-lived archives, the adversary model uses an explicit time-horizon framework:

- **t₀** = time of archive creation
- **t_Q** = "Q-Day": the time when a cryptographically relevant quantum computer exists for practical attacks against classical public-key cryptography (factoring, discrete log)
- **t_V** = time of verification or restore, which may be decades after both t₀ and t_Q

The HNDL risk is the primary time-horizon driver: an adversary captures encrypted artifacts at t₀ and waits until t_Q or later to attempt decryption using quantum capability.
NIST IR 8547 explicitly recognizes this as a pressing motivation for PQC transition.

Under this timeline, three long-term objectives must be treated as distinct:

1. **Long-term confidentiality**
   Prevent retrospective decryption of captured ciphertexts across the full t₀ → t_Q → t_V horizon.
   Quantum Vault addresses this by using ML-KEM-1024 (FIPS 203) for key encapsulation and AES-256-GCM (SP 800-38D) for symmetric encryption, where Grover-style speedup is mitigated by the 256-bit key size.

2. **Long-term authenticity and verifiability**
   Permit a verifier at t_V to validate integrity and signer identity even if some algorithms used at t₀ are obsolete at t_V.
   After a broad classical-signature collapse at t_Q, classical detached signatures (Ed25519) cannot independently establish provenance; PQ detached signatures (ML-DSA, SLH-DSA) remain the viable path.

3. **Long-term time verifiability**
   Provide evidence that an artifact existed by time T (often "before t_Q"), in a way that survives algorithm transitions.
   This requires evidence-record renewal chains — not yet fully implemented in the current system, which carries `.ots` evidence as supplementary material only.

The third objective is acknowledged as incomplete in the current implementation.
See `long-term-archive.md` for the current evidence posture and future renewal direction.

### 3.2 Chosen-ciphertext feedback surface

An adversary who can observe verifier success/failure responses (e.g., "valid/invalid" outcomes during restore or decrypt) may gain information relevant to AEAD misuse and key-commitment attacks.
This is a realistic assumption for systems where containers are processed non-interactively.

Current mitigations:

- mandatory key commitment (`SHA3-256(Kenc)` verified before decryption) prevents key-commitment attacks against AES-GCM
- fail-closed parsing rejects malformed inputs before reaching the AEAD layer
- AAD binding ensures ciphertext is not silently reinterpreted under a different header context

This surface is not fully eliminated by the current design and remains a residual consideration for any system that exposes verification outcomes.

## 4. Security goals

The current system aims to keep the following goals separate:

1. Confidentiality
   Plaintext should remain unavailable to an adversary who only captures archive artifacts without the required decryption material.

2. Integrity and fixity
   Modified `.qenc`, `.qcont`, and the current track's signable and mutable authenticity objects should be detected rather than silently accepted.

3. Authenticity and provenance
   Detached signatures should allow the verifier to determine whether a signer key signed the current signable archive description: canonical manifest bytes for legacy archives or canonical archive-state bytes for successor archive approval.

4. Threshold secrecy
   Fewer than the required number of shards should not reconstruct the ML-KEM private key.

5. Threshold recoverability
   A sufficient and internally consistent shard cohort should permit reconstruction of the archive state.

6. Policy-gated restoration
   Restore should be explicitly allowed or blocked according to archive authenticity policy, not by ad hoc UI interpretation.

7. Evidence linkage
   Timestamp evidence should be attachable and linkable to detached signatures without being mistaken for signature policy satisfaction.

8. Long-term interpretability
   Artifacts should remain self-describing enough that future tools can determine what algorithms, formats, and identities were used.

## 5. Non-goals and non-claims

The current implementation does not claim:

- resistance to a fully compromised host, browser, or malicious browser extension
- protection against side-channel extraction in JavaScript runtimes
- sender authentication from ML-KEM encryption alone
- mandatory signer pinning by default
- third-party-verifiable proof that an archive existed before a claimed time
- a complete evidence-renewal or long-term witness architecture
- institutional repository certification or external governance approval
- perfect future-proofing of current PQ or symmetric primitives
- recoverability if too many custodians lose shards or if threshold assumptions fail operationally

## 6. Trust assumptions

Current security claims depend on the following assumptions:

- cryptographic operations are performed locally in the client and are not routed through runtime network services
- the user trusts or verifies the delivered application build
- the browser/OS cryptographic RNG exposed via `crypto.getRandomValues()`, together with any best-effort user-event mixing the implementation performs, is sufficient for key generation and random values used by the format
- enough independent custodians remain uncompromised and available to satisfy threshold recovery
- the supported canonicalization implementation is applied consistently
- detached signatures are verified using the correct wrapper semantics, context, and normalized suite identifiers
- archive authenticity policy is evaluated exactly as defined in `trust-and-policy.md` and is not silently weakened
- users preserve enough required artifacts for the selected recovery path

## 7. Hard invariants

This is the most important section of the document.
Violating these invariants risks silent catastrophic failure.

### 7.1 Runtime and secret-handling invariants

Current runtime invariants:

- secret material MUST remain in runtime memory only and MUST NOT be stored in `localStorage`, `sessionStorage`, `IndexedDB`, or cookies
- zeroization is best-effort but MUST still be attempted for secret buffers as soon as practical
- session-level wiping on unload/pagehide remains part of the current security posture
- cryptographic operations MUST stay in the core/service layer rather than the UI layer

### 7.2 Encryption invariants for `.qenc`

Current confidentiality and AEAD invariants:

- parsers and decryptors MUST use explicit algorithm/profile identifiers, not heuristic inference
- AES-GCM nonce size MUST remain 96 bits in the current format family
- a `(key, nonce)` pair MUST NOT be reused
- security-relevant header fields MUST remain inside the authenticated boundary
- single-container AAD is the full header through `keyCommitment`
- per-chunk AAD is `header || uint32_be(chunkIndex) || uint32_be(plainLen_i)`, where `header` includes `keyCommitment`
- key commitment is mandatory and MUST be verified before decryption
- KMAC domain strings for KDF and IV derivation MUST remain explicit, non-colliding, and stable for the artifact instance

### 7.3 Legacy manifest, bundle, and authenticity invariants

Current authenticity invariants:

- canonical manifest bytes are the only detached-signature payload
- bundle mutation MUST NOT mutate canonical manifest bytes
- detached signatures MUST NOT be treated as signatures over mutable bundle bytes
- `manifestDigest` and `authPolicyCommitment` bindings MUST remain consistent with the embedded manifest and bundle policy object
- integrity verified, signature verified, signer pinned, and archive policy satisfied MUST remain separate states
- timestamp evidence MUST NOT satisfy archive signature policy by itself

### 7.4 Shard and reconstruction invariants

Current threshold and shard invariants:

- shard cohort selection MUST be deterministic and MUST NOT use a "largest cohort wins" rule
- threshold semantics MUST remain deterministic, with current threshold derived as `t = k + (n-k)/2`
- Shamir share commitments MUST bind raw share bytes
- fragment integrity validation MUST remain mandatory
- conflicting manifest digests, bundle digests, or incompatible cohorts MUST fail closed
- fewer than threshold shards MUST NOT reconstruct the ML-KEM private key

### 7.5 Parsing and verifier invariants

Current parser and verifier invariants:

- unknown major versions, unknown magic values, and unsupported schema identifiers MUST be rejected
- lengths, counters, and allocation-driving integer fields MUST be validated before use
- parsers MUST NOT infer cryptographic meaning from filenames, file extensions, or key lengths
- cryptographic meaning MUST NOT depend on mutable filesystem metadata
- malformed or ambiguously linked evidence MUST be rejected rather than silently downgraded

### 7.6 Successor lifecycle and same-state resharing (claim boundaries)

The **successor** track separates archive-state approval from cohort-level sharding (`format-spec.md`, `trust-and-policy.md` §11). Invariants include:

- archive-approval signatures MUST verify over canonical **archive-state descriptor** bytes, not mutable lifecycle-bundle bytes
- maintenance and source-evidence detached signatures MUST NOT satisfy archive policy
- restore MUST NOT auto-select a lifecycle bundle digest, cohort, or fork winner by heuristic when disambiguation is required

**Same-state resharing** (availability maintenance) produces a new cohort and `cohortId` but preserves archive-state bytes and existing archive-approval signatures. The implementation does **not** claim to:

- revoke or repair compromise of previously leaked predecessor quorum material
- perform implicit archive re-approval or plaintext decryption as part of resharing
- solve host-compromise, HNDL, or algorithm migration beyond the stated cryptographic profile

Operational warnings emitted by resharing flows are advisory; they are not a substitute for external custody policy.

## 8. Security claims and their conditions

| Claim | Holds if | Does not imply |
| --- | --- | --- |
| `.qenc` confidentiality against passive capture | ML-KEM, KMAC256, and AES-256-GCM remain secure enough for the threat horizon; nonce and key-commitment invariants hold; private key material is not exposed | Sender authentication, protection against host compromise, or future-proofing against all algorithm breaks |
| `.qenc` / `.qcont` integrity and fixity | AEAD checks, hashes, commitments, manifest digests, and shard checks all verify | Provenance or signer identity |
| Threshold secrecy | Fewer than the required shards are available and Shamir/recovery invariants hold | Availability or recoverability |
| Threshold recoverability | A sufficient consistent shard cohort is available and policy permits restore | That every shard source was honest or that provenance is strong |
| A verified detached signature | The signature cryptographically verifies over the exact canonical **signable** bytes for the path (legacy: manifest bytes; successor archive-approval: archive-state descriptor bytes) under a supported suite/wrapper | That the signer audited plaintext, approved archive class, or authorized migration |
| Archive policy satisfied | The required valid signature set exists under the current policy semantics | Signer pinning, timestamp evidence, or broader organizational approval |
| OTS evidence linked | The evidence object targets a detached signature under the supported linkage checks | A full independent third-party time proof or policy satisfaction by itself |

Current long-horizon qualification:

- confidentiality against harvest-now-decrypt-later risk depends on the continued strength of the current PQ and symmetric profile
- authenticity after broad classical-signature collapse depends on PQ detached signatures or on future evidence-renewal architecture not yet fully implemented here
- the current implementation carries timestamp evidence, but it does not yet provide a full renewable time-proof model

## 9. Failure semantics

| Failure category | Current effect | What may still remain knowable |
| --- | --- | --- |
| Structural parse failure, unknown version, bad magic, bad length, or mismatched digest | Reject the artifact or cohort; do not continue as if compatible | Some unrelated external artifacts may still be inspectable, but the failed object is not trusted |
| Inconsistent shard cohort or insufficient threshold | Do not reconstruct `.qenc` or the private key | Detached signatures or manifests may still be separately inspectable if available |
| Invalid detached signature | Do not count it toward policy; do not upgrade provenance status | Structural integrity may still be known |
| Unsatisfied `any-signature` or `strong-pq-signature` policy | Block restore after integrity/reconstruction evaluation | Integrity may still be knowable even though restore is not authorized |
| Missing signer pin | Report weaker provenance status; do not block restore by default | Signature validity and policy satisfaction may still hold |
| Absent OTS evidence | Do not fail solely for absence | Integrity and signature validity may still be known |
| Malformed or ambiguously linked OTS evidence | Reject the evidence path rather than silently trusting it | Other valid signatures or structural checks may still remain knowable |

## 10. Residual risks

Current residual risks include:

- host compromise, malicious extensions, and browser-side memory inspection
- side-channel leakage inherent to JavaScript runtimes
- user error in shard custody, backup discipline, or artifact preservation
- dependency or delivery-path compromise before the app is loaded
- future cryptographic weakening of current PQ or symmetric primitives
- incomplete long-term time-proof and evidence-renewal architecture
- future ambiguity in trust roots, governance, or migration authority
- per-chunk AEAD key reuse within a single container: the current `per-chunk-aead` mode derives all chunk encryption keys from the same `Kenc`; while per-chunk IVs are unique by construction (KMAC-derived prefix + counter), the shared `Kenc` means that a single key-recovery event compromises all chunks in the container; for 50+ year archive horizons, envelope-DEK or per-chunk key derivation may be warranted as a future hardening measure
- chosen-ciphertext feedback from verifier success/failure responses (see §3.2)

## 11. Future coverage retained for this document

This document now carries the current security baseline, but it still needs future expansion in the following areas:

- time-shifted adversary phases and explicit pre-Q / transitional / post-Q treatment
- stronger formal claim language for long-term provenance and evidence renewal
- deeper treatment of verifier-oracle and chosen-ciphertext exposure
- institution-level trust-root and governance models
- security requirements for archive migration, rewrap, reencryption, and renewal operations
- audit/compliance framing that avoids overclaiming certification
