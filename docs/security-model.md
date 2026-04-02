# Security model

Status: Release Candidate
Type: Normative
Audience: implementers, security auditors, reviewers, maintainers
Scope: current-state normative baseline for security boundaries, adversary assumptions, hard invariants, security claims, and failure semantics
Out of scope: byte-level field definitions, archive-class policy, evidence-renewal architecture, whitepaper rationale
Primary implementation sources: `src/core/crypto/index.js`, `src/core/crypto/qcont/restore.js`, `src/core/crypto/qcont/lifecycle-shard.js`, `src/core/crypto/lifecycle/artifacts.js`

## Role

This document is the normative home for security boundaries, assumptions, hard invariants, and claim limits.
It turns the repository's current behavior into explicit security statements for implementers and auditors.

Division of labor:

- [`format-spec.md`](format-spec.md) defines byte-level format, canonicalization, and verifier flow
- [`trust-and-policy.md`](trust-and-policy.md) defines the meaning of signatures, pinning, and archive policy outcomes
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
- `src/core/crypto/index.js`, `src/core/crypto/aead.js`, `src/core/crypto/qenc/format.js`, and `src/core/crypto/policy.js` for encryption, AAD boundaries, nonce-policy enforcement, and key-commitment behavior
- `src/core/crypto/qcont/lifecycle-shard.js` and `src/core/crypto/qcont/restore.js` for reconstruction, shard parsing, same-state resharing, and restore selection behavior
- `src/core/crypto/lifecycle/artifacts.js` for archive-state, cohort-binding, lifecycle-bundle, transition-record, source-evidence, and detached-signature target semantics
- `src/core/crypto/auth/qsig.js`, `src/core/crypto/auth/stellar-sig.js`, and `src/core/crypto/auth/opentimestamps.js` for authenticity and evidence handling
- [`format-spec.md`](format-spec.md), [`trust-and-policy.md`](trust-and-policy.md), [`long-term-archive.md`](long-term-archive.md), and [`glossary.md`](glossary.md) for cross-document constraints

External references already used elsewhere in the repository:

- FIPS 203 for ML-KEM-1024 context
- FIPS 202 for SHA-3 hashing context
- SP 800-185 for KMAC256 derivation context
- SP 800-38D for AES-256-GCM AEAD assumptions
- FIPS 204 for ML-DSA detached-signature context
- FIPS 205 for SLH-DSA detached-signature context
- RFC 8032 for Ed25519 signature context

## Current implementation surface

Implemented now:

- one supported shard wire family: `QVqcont-7`
- one archive-approval payload: canonical `quantum-vault-archive-state-descriptor/v1` bytes
- one mutable authenticity bundle: `QV-Lifecycle-Bundle` v1
- detached authenticity artifacts accepted by the shipped implementation: `.qsig`, `.sig`, `.pqpk`, and `.ots`
- client-only browser execution with no runtime cryptographic network service
- detached-signature and policy-gated authenticity evaluation layered on top of archive integrity checks
- fail-closed parsing and deterministic restore behavior, with explicit operator selection only as a warned override when successor ambiguity is intentionally resolved
- best-effort in-memory secret wiping and no intended persistent secret storage
- explicit separation among integrity, signature validity, pinning, maintenance evidence, source-evidence provenance, OTS evidence, and policy satisfaction
- `QVqcont-7` shards with archive-state-centric approval and fail-closed restore selection rules

Deferred roadmap:

- resistance to a fully compromised host or browser environment
- hardware-backed key isolation or strong side-channel resistance
- a complete renewable evidence-record architecture
- institutional governance, repository certification, or mandatory signer pinning by default
- state-changing continuity records for future rewrap or reencryption

## Future work and non-normative notes

Statements explicitly labeled as future or recommended direction are non-normative.
Likely future security-document expansion areas include:

- more explicit time-shifted adversary phases and long-horizon claim language
- deeper treatment of verifier-oracle exposure and chosen-ciphertext surfaces
- security requirements for migration, rewrap, reencryption, and renewal events

## 1. Status, scope, and claim boundaries

This document applies to the current Quantum Vault artifact family and restore flow:

- `.qenc` encrypted containers
- `QVqcont-7` threshold shards
- archive-state descriptors, cohort bindings, lifecycle bundles, transition records, and source-evidence objects
- detached `.qsig`, `.sig`, `.pqpk`, and `.ots` inputs as currently supported

It also assumes the current supporting tool ecosystem:

- Quantum Vault for encrypt, split, attach, restore, decrypt, and same-state resharing
- Quantum Signer for detached PQ signatures and `.pqpk`
- Stellar WebSigner for detached Ed25519/Stellar proofs
- OpenTimestamps tooling for optional evidence files

Current claim boundaries:

- this document defines current security properties only for the presently documented implementation model
- this document distinguishes current guarantees, current assumptions, and future recommendations
- this document does not claim that the current repository already provides a full long-term evidence-record architecture or a final multi-decade archival system

Terminology used here follows [`glossary.md`](glossary.md) and [`format-spec.md`](format-spec.md):

- `privateKey` means asymmetric secret material
- `secretKey` means symmetric secret material

## 2. Assets and trust boundaries

### 2.1 Assets

| Asset | Primary security concern | Current notes |
| --- | --- | --- |
| Plaintext payload | Confidentiality, integrity | Exists before encrypt and after decrypt in browser memory |
| ML-KEM private key file (`privateKey.qkey`) | Confidentiality, recoverability | Asymmetric private-key material |
| ML-KEM public key file (`publicKey.qkey`) | Integrity, correct binding | Used to encapsulate the shared secret for `.qenc` creation |
| Shared secret and derived symmetric secrets (`Kraw`, `Kenc`, `Kiv`) | Confidentiality | Ephemeral runtime-only symmetric `secretKey` material |
| `.qenc` container | Confidentiality, fixity, parse safety | Public metadata plus authenticated ciphertext |
| `.qcont` shards | Threshold secrecy, recoverability, integrity | Carry one Shamir share, Reed-Solomon fragments, and embedded archive-state descriptor, cohort-binding, and lifecycle-bundle bytes |
| Archive-state descriptor | Fixity, signature-target integrity | Immutable archive-approval payload |
| Cohort binding | Cohort integrity, shard-commitment integrity | State-bound shard cohort description |
| Lifecycle bundle | Policy transport, authenticity metadata integrity | Mutable object carrying policy and attachments |
| Transition records and source-evidence objects | Lineage integrity, provenance integrity | Detached-signature targets for maintenance and source-evidence families |
| Detached signatures and public-key attachments | Provenance, signer binding | Current external authenticity material |
| OTS evidence | Evidence linkage | Supplementary only; not a policy-satisfying signature substitute |

### 2.2 Trust boundaries

Current major trust boundaries are:

- the browser/runtime boundary, where secret material exists only as best-effort ephemeral memory
- the delivery/build boundary, where users must trust or verify the static application they loaded
- the storage/custodian boundary, where shards and detached artifacts may be stored by untrusted third parties
- the external signer and evidence boundary, where Quantum Vault consumes signatures and timestamps produced by separate tools

## 3. Adversary model

Quantum Vault's current security model assumes an adversary may:

- capture and store ciphertexts, shards, signatures, lifecycle bundles, and related artifacts indefinitely, including for harvest-now-decrypt-later scenarios
- tamper with stored artifacts, substitute artifacts, replay stale artifacts, or mix conflicting shard cohorts
- inject malformed inputs to exploit parser differences or unsafe error handling
- compromise one or more shard custodians or storage providers
- observe verifier success or failure behavior
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

- `t0` = time of archive creation
- `tQ` = "Q-Day": the time when a cryptographically relevant quantum computer exists for practical attacks against classical public-key cryptography (integer factoring, elliptic-curve discrete logarithm)
- `tV` = time of verification or restore, which may be decades after both `t0` and `tQ`

The HNDL risk is the primary time-horizon driver: an adversary captures encrypted artifacts at `t0` and waits until `tQ` or later to attempt decryption using quantum computational capability. NIST IR 8547 explicitly identifies HNDL as a pressing driver for post-quantum migration.

Under this timeline, three long-term objectives must remain distinct:

1. Long-term confidentiality
   Prevent retrospective decryption of captured ciphertexts across the full `t0` → `tQ` → `tV` horizon. Quantum Vault addresses this by using ML-KEM-1024 (FIPS 203) for key encapsulation and AES-256-GCM (SP 800-38D) for symmetric encryption, where the 256-bit key size mitigates Grover-style quadratic speedup. The explicit `cryptoProfileId` in every artifact ensures algorithm agility without parser ambiguity.

2. Long-term authenticity and verifiability
   Permit a verifier at `tV` to validate integrity and signer identity even if some algorithms used at `t0` are obsolete at `tV`. After a broad classical-signature collapse at `tQ`, Ed25519 and other classical detached signatures cannot independently establish provenance; PQ detached signatures (ML-DSA / FIPS 204, SLH-DSA / FIPS 205) remain the viable path. Quantum Vault's `strong-pq-signature` policy level enforces at least one PQ archive-approval signature at restore time.

3. Long-term time verifiability
   Provide evidence that an artifact existed before a given time boundary in a way that survives algorithm transitions. This requires evidence-record renewal chains. The current implementation carries `.ots` evidence as supplementary material linked to detached signature bytes; it does not yet provide a first-class renewable time-proof architecture. See [`long-term-archive.md`](long-term-archive.md) for the current evidence posture and renewal direction.

The third objective is explicitly acknowledged as incomplete in the current implementation. The current OTS linkage is evidence-in-progress, not a full long-horizon time-proof.

### 3.2 Chosen-ciphertext feedback surface

An adversary who can observe verifier success or failure responses may gain information relevant to AEAD misuse and key-commitment attacks.

Current mitigations:

- mandatory key commitment verified before decryption
- fail-closed parsing before the AEAD layer
- AAD binding that prevents silent reinterpretation of security-relevant metadata

This surface is not fully eliminated and remains a residual consideration for any system that exposes verification outcomes.

## 4. Security goals

The current system keeps the following goals separate:

1. Confidentiality
   Plaintext should remain unavailable to an adversary who only captures archive artifacts without the required decryption material.

2. Integrity and fixity
   Modified `.qenc`, `QVqcont-7` shards, archive-state descriptors, cohort bindings, lifecycle bundles, transition records, and source-evidence objects should be detected rather than silently accepted.

3. Authenticity and provenance
   Detached signatures should allow the verifier to determine whether a signer key signed the canonical archive-state descriptor bytes for archive approval, or the canonical bytes of another declared lifecycle target (transition record or source-evidence object) for maintenance and source-evidence families respectively.

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

Archive approval provenance in the current implementation means:

- a verifier can determine whether a signer key signed the canonical archive-state descriptor bytes
- maintenance and source-evidence signatures are tracked separately from archive approval

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
- the browser or OS RNG exposed via `crypto.getRandomValues()`, together with any best-effort user-event mixing the implementation performs, is sufficient for key generation and random values
- enough independent custodians remain uncompromised and available to satisfy threshold recovery
- the supported canonicalization implementation is applied consistently
- detached signatures are verified using the correct wrapper semantics, context, and normalized suite identifiers
- archive authenticity policy is evaluated exactly as defined in [`trust-and-policy.md`](trust-and-policy.md) and is not silently weakened
- users preserve enough required artifacts for the selected recovery path

## 7. Hard invariants

This is the most important section of the document.
Violating these invariants risks silent catastrophic failure.

### 7.1 Runtime and secret-handling invariants

Current runtime invariants:

- secret material MUST remain in runtime memory only and MUST NOT be stored in `localStorage`, `sessionStorage`, `IndexedDB`, or cookies
- zeroization is best-effort but MUST still be attempted for secret buffers as soon as practical
- session-level wiping on unload or `pagehide` remains part of the current security posture
- cryptographic operations MUST stay in the core or service layer rather than the UI layer

### 7.2 Encryption invariants for `.qenc`

Current confidentiality and AEAD invariants:

- parsers and decryptors MUST use explicit algorithm and profile identifiers, not heuristic inference
- AES-GCM nonce size MUST remain 96 bits in the current format family
- a `(key, nonce)` pair MUST NOT be reused
- security-relevant header fields MUST remain inside the authenticated boundary
- single-container AAD is the full header through `keyCommitment`
- per-chunk AAD is `header || uint32_be(chunkIndex) || uint32_be(plainLen_i)`, where `header` includes `keyCommitment`
- key commitment is mandatory and MUST be verified before decryption
- KMAC domain strings for KDF and IV derivation MUST remain explicit, non-colliding, and stable for the artifact instance

### 7.3 Successor lifecycle authenticity and restore invariants

Current successor invariants:

- archive-approval signatures MUST verify over canonical archive-state descriptor bytes, not mutable lifecycle-bundle bytes
- lifecycle-bundle mutation MUST NOT mutate canonical archive-state or canonical cohort-binding bytes
- archive policy MUST count only `archiveApprovalSignatures`
- maintenance and source-evidence signatures MUST remain separate from archive policy satisfaction
- OTS evidence MUST target detached signature bytes and MUST NOT satisfy archive policy by itself
- restore MUST group successor candidates by `archiveId`, `stateId`, `cohortId`, and exact archive-state/cohort-binding bytes
- restore MUST fail closed when archive, state, cohort, or lifecycle-bundle selection remains ambiguous
- restore MUST NOT auto-select a same-state fork winner or lifecycle-bundle variant by timestamp, attachment count, lexical order, or similar heuristic
- if an operator explicitly selects a cohort or lifecycle-bundle variant in an otherwise ambiguous case, the result MUST be reported as an explicit operator choice with warning rather than as an automatic winner
- self-verified PQ signatures that verified only with the key embedded in the `.qsig` itself MUST NOT count toward trust or archive policy unless bundled or user-supplied signer material also verified
- same-state resharing is maintenance, not archive re-approval

### 7.4 Shard and reconstruction invariants

Current threshold and shard invariants:

- shard cohort selection MUST be deterministic and MUST NOT use a "largest cohort wins" rule
- threshold semantics MUST remain deterministic, with current threshold derived as `t = k + (n-k)/2`
- Shamir share commitments MUST bind raw share bytes
- fragment integrity validation MUST remain mandatory
- conflicting archive-state bytes, cohort-binding bytes, lifecycle-bundle digests, or incompatible cohorts MUST fail closed
- fewer than threshold shards MUST NOT reconstruct the ML-KEM private key

### 7.5 Parsing and verifier invariants

Current parser and verifier invariants:

- unknown major versions, unknown magic values, and unsupported schema identifiers MUST be rejected
- lengths, counters, and allocation-driving integer fields MUST be validated before use
- parsers MUST reject duplicate JSON object keys and other strict-JSON violations where canonical artifact parsing requires them
- parsers MUST NOT infer cryptographic meaning from filenames, file extensions, or key lengths
- cryptographic meaning MUST NOT depend on mutable filesystem metadata
- unresolved or incompatible `publicKeyRef` bindings MUST be rejected rather than silently downgraded
- malformed or ambiguously linked OTS evidence MUST be rejected rather than silently trusted

### 7.6 Same-state resharing and future state-change claim boundaries

Current same-state resharing preserves archive-state bytes and archive-approval signatures while producing a new cohort plus a required transition record.
The implementation does not claim to:

- revoke or repair compromise of previously leaked predecessor quorum material
- perform implicit archive re-approval or plaintext decryption as part of resharing
- provide first-class continuity across future rewrap or reencryption events

Operational warnings emitted by resharing flows are advisory; they are not a substitute for external custody policy or future continuity records.

## 8. Security claims and their conditions

| Claim | Holds if | Does not imply |
| --- | --- | --- |
| `.qenc` confidentiality against passive capture | ML-KEM, KMAC256, and AES-256-GCM remain secure enough for the threat horizon; nonce and key-commitment invariants hold; private key material is not exposed | Sender authentication, protection against host compromise, or future-proofing against all algorithm breaks |
| `.qenc` / `.qcont` integrity and fixity | AEAD checks, hashes, commitments, archive-state and cohort-binding checks, and shard checks all verify | Provenance or signer identity |
| Threshold secrecy | Fewer than the required shards are available and Shamir invariants hold | Availability or recoverability |
| Threshold recoverability | A sufficient consistent shard cohort is available and policy permits restore | That every shard source was honest or that provenance is strong |
| A verified archive-approval signature | The signature cryptographically verifies over canonical archive-state bytes under a supported suite or wrapper | That the signer audited plaintext, approved archive class, or authorized migration |
| Archive policy satisfied | The required valid archive-approval signature set exists under the current policy semantics | Signer pinning, timestamp evidence, maintenance approval, source-review approval, or broader organizational approval |
| OTS evidence linked | The evidence object targets detached signature bytes under the supported linkage checks | A full independent third-party time proof or policy satisfaction by itself |

Current long-horizon qualification:

- confidentiality against harvest-now-decrypt-later risk depends on the continued strength of the current PQ and symmetric profile
- authenticity after broad classical-signature collapse depends on PQ detached signatures or on future evidence-renewal architecture not yet fully implemented here
- the current implementation carries timestamp evidence, but it does not yet provide a full renewable time-proof model

## 9. Failure semantics

| Failure category | Current effect | What may still remain knowable |
| --- | --- | --- |
| Structural parse failure, unknown version, bad magic, bad length, or mismatched digest | Reject the artifact or cohort; do not continue as if compatible | Some unrelated external artifacts may still be inspectable, but the failed object is not trusted |
| Inconsistent shard cohort or insufficient threshold | Do not reconstruct `.qenc` or the private key | Detached signatures or bundles may still be separately inspectable if available |
| Invalid detached signature | Do not count it toward policy; do not upgrade provenance status | Structural integrity may still be known |
| Self-verified PQ signature with no bundled or user pin | Do not count it toward trust or policy | The `.qsig` may still be a cryptographically valid self-signature artifact |
| Unsatisfied `any-signature` or `strong-pq-signature` policy | Block restore after integrity and reconstruction evaluation | Integrity may still be knowable even though restore is not authorized |
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
- per-chunk AEAD key reuse within one container: the current `per-chunk-aead` mode derives distinct IVs but uses a single `Kenc` across chunks, which is acceptable for the current size regime but may warrant future hardening for much larger payloads
- chosen-ciphertext feedback from verifier success or failure responses

## 11. Future coverage retained for this document

This document carries the current security baseline, but it still needs future expansion in the following areas:

- time-shifted adversary phases and explicit pre-Q / transitional / post-Q treatment
- stronger formal claim language for long-term provenance and evidence renewal
- deeper treatment of verifier-oracle and chosen-ciphertext exposure
- institution-level trust-root and governance models
- security requirements for archive migration, rewrap, reencryption, and renewal operations
