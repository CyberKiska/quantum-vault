# Quantum Vault: Post-Quantum Archival Encryption with Threshold Recovery and Detached Provenance

**Status:** Release Candidate  
**Version:** 0.1  
**Date:** 2026-03-21

---

## Abstract

Quantum Vault is a client-only archival containerization system that combines post-quantum confidentiality, threshold recoverability, and detached provenance into a long-lived artifact family. The current baseline uses the successor lifecycle model: a canonical archive-state descriptor, cohort binding, and `QV-Lifecycle-Bundle` v1, with archive-approval signatures bound to canonical archive-state bytes. Previously, v1 used a canonical signable manifest plus mutable manifest bundle. The current repository still implements both tracks during the phase-out window, but the shipped Lite and Pro surface now creates successor shard sets by default; beginning with v1.5.3, v1 manifest/bundle creation left the normal product path. Across both tracks, mutable evidence — signatures, signer identity material, and timestamp proofs — can evolve without invalidating previously computed approval signatures. Restoration is gated by an explicit archive authenticity policy committed at creation time. The current implementation executes entirely within the browser with no runtime network cryptographic service. This paper describes the system's design rationale, cryptographic construction, canonicality and binding model, security invariants, and long-term archival direction, and identifies the limitations and open risks that remain.

---

## 1. Introduction and Problem Statement

### 1.1 The Insufficiency of Encrypted Files

An encrypted file, taken alone, addresses a single concern: confidentiality at the time of encryption. For data that must remain protected across years or decades, this is insufficient. Several distinct problems arise that a simple "encrypted file plus signature" model does not solve.

**Long-lived confidentiality under harvest-now-decrypt-later (HNDL) risk.** An adversary who captures ciphertexts today may store them indefinitely and attempt decryption once cryptographically relevant quantum computers become available. Classical public-key key-establishment mechanisms such as RSA and ECDH are vulnerable to Shor's algorithm [1]; ciphertexts protected solely by these mechanisms face retrospective decryption after a quantum transition. NIST IR 8547 identifies HNDL as a pressing driver for post-quantum migration [2]. The cost of passive data collection is negligible, making HNDL a rational adversary strategy today — not merely a future contingency [26]. This creates an asymmetry: confidentiality migration cannot be deferred because captured ciphertexts are retroactively vulnerable, whereas authentication forgery requires a quantum computer to be available at the time of attack. IR 8547 reflects this by treating key-establishment migration as more urgent than digital-signature migration [2]. Quantum Vault's architecture responds to this asymmetry: post-quantum encryption is mandatory from archive creation, while the authentication layer accepts both PQ and classical-interoperability signatures during the transition period.

**Long-lived provenance.** Integrity verification (detecting whether bytes have changed) is distinct from provenance. In Quantum Vault's current model, detached signatures provide cryptographic evidence that a specific signer key signed the current signable archive description: canonical manifest bytes in the legacy track or canonical archive-state descriptor bytes for successor archive approval. Binding that key to a real-world identity, an approval workflow, or a custody role is external to the artifact family. AEAD authentication tags protect ciphertext integrity against tampering but do not establish signer identity. For archives that must remain attributable over decades, detached digital signatures are required — and those signatures must themselves survive the quantum transition. Concrete quantum resource estimates for elliptic-curve discrete logarithms [27] confirm that EdDSA on curves of order ~2^256 is a feasible quantum target once fault-tolerant quantum computers of sufficient scale exist, reinforcing the need for post-quantum signature alternatives alongside classical-interoperability paths.

**Long-lived time evidence.** Demonstrating that an artifact existed before a given time boundary requires external evidence beyond self-asserted timestamps. After a cryptographic transition, classical signatures on timestamp tokens may become forgeable; time evidence must therefore be renewable or rooted in mechanisms that do not depend solely on the continued security of a single signature algorithm [3][4].

**Distributed custody and threshold recovery.** Storing a single encrypted file and a single decryption key creates a single point of failure. Loss, compromise, or unavailability of the key renders the archive unrecoverable. Splitting key material and ciphertext across multiple independent custodians, with reconstruction requiring only a threshold subset, mitigates both loss and collusion risks.

**Mutable evidence without invalidating signed descriptions.** An archive's provenance material — signatures, signer identity, timestamp evidence — may need to be added, updated, or extended after the archive is created. If signatures cover a mutable object, every attachment invalidates all prior signatures. Separating an immutable signable description from a mutable evidence carrier allows provenance to accumulate without re-signing.

### 1.2 Design Response

Quantum Vault addresses these problems through a layered artifact family in which confidentiality, recoverability, canonical description, detached provenance, and mutable evidence are distinct concerns with distinct artifacts and invariants. The following sections describe the system's goals and boundaries, its cryptographic construction, the canonicality and binding model that supports long-lived provenance, the security rationale, and the intended archival direction.

---

## 2. Goals and Non-Goals

### 2.1 Goals

The system is designed to achieve the following properties:

1. **Post-quantum confidentiality.** Plaintext must remain unavailable to an adversary who captures archive artifacts, including under HNDL scenarios where the adversary later gains quantum computational capability.

2. **Threshold recoverability.** Archive reconstruction must require a configurable threshold of custodian-held shards, tolerating both loss and limited compromise among custodians.

3. **Signer-verifiable provenance.** A verifier must be able to determine whether a specific signer key signed the canonical archive description, using both post-quantum and classical-interoperability signature families.

4. **Policy-gated restoration.** Restoration must be explicitly allowed or blocked by an archive authenticity policy committed at creation time, rather than by ad hoc interpretation.

5. **Client-only operation.** All cryptographic operations — key generation, encryption, splitting, signing verification, and decryption — are intended to execute in the user's browser with no runtime cryptographic network service.

6. **Format longevity and auditability.** Artifacts must carry explicit algorithm identifiers, version tags, and self-describing metadata sufficient for future tools to determine what was used and how to validate.

### 2.2 Non-Goals

The system does not claim to provide:

- **Resistance to a fully compromised host or browser environment.** A malicious browser, extension, or operating system can observe all in-memory secrets. Client-side JavaScript operates within a lossy trust boundary, not a hardware enclave.

- **Strong side-channel resistance.** JavaScript runtimes do not offer the constant-time guarantees available in native cryptographic implementations. Side-channel extraction in the browser environment is an acknowledged residual risk.

- **Sender authentication from encryption alone.** ML-KEM provides confidentiality, not origin authentication. Provenance requires detached signatures at the archive layer.

- **Coercion resistance of custodians.** The threshold model protects against loss and limited collusion. It does not protect against coercion or against all custodians simultaneously being compromised.

- **Guaranteed permanence of specific post-quantum algorithms.** The current cryptographic profile reflects NIST-standardized primitives as of 2024–2025. Algorithm agility is a design principle; specific algorithms may require migration over multi-decade horizons.

- **Institutional archival certification.** The system is not claimed to satisfy ISO 16363 audit criteria [5] or any institutional governance program. Archive-class terminology is used as a planning taxonomy, not a compliance assertion.

---

## 3. Design Overview

### 3.1 Artifact Family

Quantum Vault produces and consumes the following artifacts:

| Artifact | Role |
|---|---|
| `.qenc` | Encrypted container carrying public metadata, key commitment, and AEAD ciphertext |
| `.qcont` | Threshold shard carrying one Shamir share, Reed–Solomon fragments, and embedded authenticity material (legacy: manifest and bundle; successor: archive-state, cohort binding, lifecycle bundle) |
| `*.qvmanifest.json` | Canonical signable manifest — the immutable detached-signature payload for the legacy track |
| `*.extended.qvmanifest.json` | Manifest bundle — mutable carrier of policy, signatures, signer keys, and timestamps for the legacy track |
| Archive-state descriptor / `QV-Lifecycle-Bundle` v1 | Successor signable approval object plus mutable lifecycle bundle |
| `.qsig` | Detached post-quantum signature over the current signable archive description or declared successor lifecycle target |
| `.sig` | Detached Ed25519/Stellar signature proof following the same path-dependent target rule as `.qsig` |
| `.pqpk` | Detached post-quantum public key for signer pinning |
| `.ots` | OpenTimestamps evidence linked to detached signature bytes |

### 3.2 Lifecycle

The archive lifecycle proceeds through the following stages:

1. **Key generation.** An ML-KEM-1024 keypair is generated client-side using the browser/OS cryptographic RNG exposed via `crypto.getRandomValues()`, with optional best-effort mixing of user interaction events.

2. **Encryption.** The payload is encrypted into a `.qenc` container. ML-KEM encapsulates a shared secret; KMAC256 derives encryption and IV-derivation keys; AES-256-GCM provides authenticated encryption. A key commitment (SHA3-256 over the encryption key) is embedded in the header.

3. **Split.** The `.qenc` container is split into `.qcont` shards. The ML-KEM private key is split using Shamir secret sharing; the ciphertext is split using Reed–Solomon erasure coding. The shipped regular-user flow emits successor `QVqcont-7` shards plus an archive-state descriptor, cohort binding, and lifecycle bundle. Legacy `QVqcont-6` creation remains compatibility-only for previously created archives.

4. **Sign (external).** An external signer tool produces detached signatures (`.qsig` or `.sig`) over the current signable archive description: canonical manifest bytes in the legacy track or canonical archive-state bytes for successor archive approval.

5. **Attach.** Detached signatures, signer public keys, and timestamp evidence are attached to the mutable bundle layer. In the legacy track, attachment updates the manifest bundle without altering the canonical manifest bytes. In the successor track, attachment updates the lifecycle bundle without altering canonical archive-state or cohort-binding bytes. Updated bundles may optionally be re-embedded into shards.

6. **Restore.** A threshold of consistent shards is supplied, along with any optional external manifest, bundle, signature, key, or timestamp material. The system verifies structural integrity, reconstructs the `.qenc` container and private key, verifies detached signatures, evaluates archive policy, and gates restoration accordingly.

7. **Decrypt.** The restored `.qenc` container is decrypted using the reconstructed private key.

**Successor lifecycle track (current implementation):** For **`QVqcont-7`** shards, embedded objects replace the manifest/bundle pair with an **archive-state descriptor**, **cohort binding**, and **`QV-Lifecycle-Bundle` v1**. Detached **archive-approval** signatures target canonical **archive-state** bytes, separating cohort-level sharding from the stable approval object. The shipped regular-user surface now uses this successor flow by default. The **legacy** manifest-based flow remains **supported** only as a compatibility path for existing archives while the project phases legacy behavior out. Normative details: `docs/format-spec.md`, `docs/trust-and-policy.md`; design history: `docs/process/roadmap/lifecycle/resharing-design.md`.

### 3.3 Current implementation boundary

**Implemented now**

- successor-default build/export in Lite and Pro
- canonical archive-state approval separated from mutable lifecycle-bundle evidence
- state-bound cohort bindings plus derived `archiveId`, `stateId`, and `cohortId`
- detached archive-approval, maintenance, and source-evidence signature families
- restore-time policy evaluation over archive-approval signatures only
- same-state resharing with required transition records

**Deferred roadmap**

- state-changing continuity records across rewrap or reencryption
- RFC 4998-style renewable evidence records
- governance and trust-root objects
- distributed resharing

**Historical v1 context**

- canonical manifest, mutable manifest bundle, and `QVqcont-6` remain implemented only for previously created archives and historical transition analysis

---

## 4. Cryptographic Construction

### 4.1 Key Encapsulation: ML-KEM-1024

Quantum Vault uses ML-KEM-1024 (FIPS 203 [6]) for key establishment. ML-KEM is a module-lattice-based key-encapsulation mechanism standardized by NIST as the primary post-quantum replacement for classical key-establishment schemes. The ML-KEM-1024 parameter set targets NIST security category 5 (equivalent to AES-256 against classical attack; at least 128-bit security against quantum adversaries under the module-LWE assumption).

The encapsulation produces a shared secret and a ciphertext (the encapsulated key). The shared secret is not used directly as an encryption key; it enters the key-derivation tree described in Section 4.2.

The chosen parameter set (`ML-KEM-1024`) is recorded as an explicit algorithm identifier in every `.qenc` container header and in the current signable archive description's `cryptoProfileId` field: the legacy canonical manifest or the successor archive-state descriptor. This follows SP 800-227's guidance that a KEM parameter set must be selected before key generation and must be bound to the resulting key pair [23].

ML-KEM provides IND-CCA2-secure key encapsulation under the module-LWE hardness assumption. It protects against passive capture, including HNDL scenarios. It does not provide sender authentication; origin claims require the detached signature layer described in Section 4.6. SP 800-227 explicitly states that a KEM is not a key-agreement mechanism: the encapsulator and decapsulator roles are asymmetric, and the shared secret is established unilaterally by the encapsulation operation [23].

### 4.2 Key Derivation: KMAC256

Key material is derived from the ML-KEM shared secret using KMAC256 (SP 800-185 [7]), a keyed hash construction based on SHA-3's Keccak permutation. KMAC256 supports explicit domain separation through customization strings, which Quantum Vault uses to ensure that distinct derived keys cannot collide even when produced from the same root material.

The derivation tree is:

1. `Kraw = KMAC256(sharedSecret, salt ‖ metaBytes, customization = "quantum-vault:kdf:v2", dkLen = 32)`
2. `Kenc = KMAC256(Kraw, 0x01, customization = "quantum-vault:kenc:v2", dkLen = 32)`
3. `Kiv  = KMAC256(Kraw, 0x02, customization = "quantum-vault:kiv:v2", dkLen = 32)`

where `salt` is a 16-byte random value and `metaBytes` is the UTF-8 encoding of the container's public metadata JSON. The derivation uses fixed one-byte labels (0x01, 0x02) to separate encryption and IV-derivation key paths. The salt is always exactly 16 bytes (128 bits); fixed-length encoding eliminates the need for length-prefixed input construction and ensures that `salt ‖ metaBytes` is an unambiguous concatenation — no two distinct (salt, metaBytes) pairs can produce the same byte string, because the salt length is constant and known to the verifier.

Domain separation strings are recorded in the container metadata and are included in the authenticated data boundary. A verifier that encounters unknown or missing domain strings must reject the container. SP 800-185 specifies that KMAC accepts a customization string `S` that "is intended for the user to select a variant of the function" and provides domain separation between distinct uses of the same keyed function [7]. Quantum Vault follows this guidance by assigning a unique customization string to each derivation step, ensuring that the outputs of distinct derivation steps are cryptographically independent even when sourced from the same root key material. SP 800-185 further requires that composite inputs to Keccak-based functions use the `encode_string` encoding or equivalent unambiguous framing to prevent canonicalization attacks on variable-length inputs [7]; Quantum Vault achieves this separation via the fixed-length salt and the KMAC interface's native encoding of `X` and `S` parameters.

### 4.3 Authenticated Encryption: AES-256-GCM

Payload encryption uses AES-256-GCM (SP 800-38D [8]) with 96-bit initialization vectors and 128-bit authentication tags. Two AEAD modes are supported:

**Single-container mode.** Used for payloads at or below the chunk size (8 MiB). The 12-byte `containerNonce` generated at encryption time serves directly as the GCM IV. The authenticated additional data (AAD) is the complete `.qenc` header from the magic bytes through the key commitment.

**Per-chunk mode.** Used for payloads exceeding the chunk size. The payload is divided into fixed-size chunks (8 MiB), each encrypted independently under AES-256-GCM with a distinct per-chunk IV:

`IV_i = KMAC256(Kiv, containerNonce, customization = "quantum-vault:chunk-iv:v2", dkLen = 8) ‖ uint32_be(i)`

where `i` is the zero-based chunk index. This construction ensures IV uniqueness across chunks by combining a secret-derived 8-byte prefix with a 4-byte counter, yielding the required 12-byte GCM nonce. Per-chunk AAD is `header ‖ uint32_be(i) ‖ uint32_be(plainLen_i)`, binding each chunk's position and plaintext length into its authentication scope.

The per-chunk nonce policy enforces a maximum chunk count of 2^32 − 1, recorded in the manifest as `maxChunkCount`. This bound is conservative for the current maximum file size (1 GiB at 8 MiB chunks yields at most 128 chunks), but the format records it explicitly to support future validation.

SP 800-38D warns that GCM IV reuse under the same key can "compromise the security assurance almost entirely" [8]. The deterministic per-chunk IV derivation eliminates IV reuse risk within a single container instance by construction: each chunk receives a unique counter suffix, and the prefix is derived from key material unique to the container.

**AEAD interface discipline.** Quantum Vault's AEAD usage conforms to the abstract AEAD interface defined in RFC 5116 [28]: a single authenticated-decryption operation that accepts ciphertext, associated data, nonce, and key, and returns either plaintext or an explicit error indication. The decryption implementation follows the RFC 5116 requirement that "if the integrity check fails then [the implementation] MUST NOT provide any portion of the plaintext or additional authenticated data" [28]. Authentication failure is treated as a hard error — no partial output is emitted. The AAD construction is injective: because header fields use fixed-length binary encodings (magic bytes, format version, algorithm identifiers, nonce, key commitment), and per-chunk AAD appends a fixed-width chunk index and plaintext length, distinct inputs always produce distinct AAD byte strings. This injectivity prevents an adversary from rearranging header fields to produce a valid authentication tag under a different interpretation, a property recommended by RFC 5116 Section 3 [28].

### 4.4 Key Commitment

The `.qenc` header carries a mandatory key commitment computed as `SHA3-256(Kenc)` (32 bytes). The commitment is verified before decryption begins. Its purpose is to prevent key-commitment attacks in which an adversary constructs a ciphertext that decrypts validly under multiple keys — a class of attack to which AES-GCM is susceptible without an external commitment mechanism [9].

The key commitment is included within the AAD boundary, ensuring it is itself authenticated. Containers without a valid key commitment are rejected.

### 4.5 Hashing and Fixity: SHA3-512 and SHA3-256

Quantum Vault uses SHA3-512 (FIPS 202 [10]) as its primary hash function for:

- `qencHash`: SHA3-512 over the full `.qenc` container bytes (primary fixity anchor)
- `containerId`: SHA3-512 over the `.qenc` header bytes (secondary identifier)
- `manifestDigest`: SHA3-512 over canonical manifest bytes (historical v1 anchor)
- `stateId`: SHA3-512 over canonical archive-state descriptor bytes (successor)
- `cohortBindingDigest`: SHA3-512 over canonical cohort-binding bytes (successor)
- `authPolicyCommitment`: SHA3-512 over canonicalized authenticity policy
- Shard body hashes and Shamir share commitments

SHA3-256 is used for key commitment (`SHA3-256(Kenc)`) and for signer fingerprints in detached signature tooling.

SHA-3 (Keccak) is chosen over SHA-2 for its distinct algebraic structure, which provides diversity against potential future weakening of the Merkle–Damgård construction family. Under Grover's algorithm, SHA3-512 retains a theoretical 256-bit preimage security bound against quantum adversaries — NIST security category 5. Recent quantum resource estimates suggest that a full Grover search over a 256-bit keyspace would require on the order of 2^128 sequential oracle queries on a fault-tolerant quantum computer, with circuit-depth and qubit costs that may render the attack impractical within foreseeable hardware parameters [29]. NIST states that "existing algorithm standards for symmetric cryptography are less vulnerable to attacks by quantum computers" and does not anticipate needing to transition away from SHA-3 as part of the PQC migration [2].

### 4.6 Threshold Recovery: Shamir Secret Sharing and Reed–Solomon Erasure Coding

Quantum Vault splits archive material across `n` shards using two complementary mechanisms:

**Shamir secret sharing** [11] splits the ML-KEM private key into `n` shares such that any `t` shares suffice to reconstruct the key, but fewer than `t` shares reveal no information about it (information-theoretic secrecy). The threshold is computed as `t = k + (n − k) / 2`, where `k` is the Reed–Solomon data-shard count and `n` is the total shard count, with the constraint that `n − k` is even. Shamir's original construction provides secrecy and reconstruction but does not inherently provide integrity: a corrupted or maliciously substituted share will cause reconstruction to yield a wrong secret without detection [11]. Quantum Vault mitigates this by computing a SHA3-512 commitment over each raw share at creation time and recording these commitments in the current track's distribution object: the legacy canonical manifest or the successor cohort binding. During restoration, each submitted share is checked against its committed digest before entering reconstruction; a share that does not match its commitment is rejected. This design provides share-level integrity verification but does not provide verifiable secret sharing in the formal cryptographic sense (e.g., Feldman VSS or Pedersen VSS), which would require additional round-trip interaction or computational assumptions beyond the information-theoretic model.

**Reed–Solomon erasure coding** [12] splits the `.qenc` ciphertext into `k` data fragments and `n − k` parity fragments, such that any `k` of `n` fragments suffice to reconstruct the ciphertext. The implementation operates over GF(2^8) with a maximum codeword length of 255 symbols. Per-shard fragment body hashes (SHA3-512) are recorded in the current track's shard-distribution object and verified during restoration: the legacy canonical manifest or the successor cohort binding.

The combination provides both confidentiality protection (Shamir threshold for key material) and availability protection (Reed–Solomon erasure tolerance for ciphertext fragments). Each `.qcont` shard carries one Shamir share, one set of Reed–Solomon fragments, and the track-specific embedded authenticity material for its format family. Legacy `QVqcont-6` shards embed the canonical manifest and manifest bundle. The current shipped successor `QVqcont-7` shards embed the archive-state descriptor, cohort binding, and lifecycle bundle.

### 4.7 Detached Signatures

Quantum Vault supports detached signatures over the current signable archive description from two external signer tools:

**Post-quantum signatures (`.qsig`).** Produced by Quantum Signer, a client-only tool that supports ML-DSA parameter sets (FIPS 204 [13]) and SLH-DSA parameter sets (FIPS 205 [14]). The `.qsig` format is a versioned binary container (context `quantum-signer/v2`) that carries the signature suite identifier, a SHA3-512 prehash of the signed payload, signer fingerprint, and signature bytes.

ML-DSA is a module-lattice-based signature scheme whose security relies on the hardness of Module-LWE and Module-SIS problems [13]. FIPS 204 provides three security levels; Quantum Vault currently recognizes `ML-DSA-87` (security category 5) as a "strong PQ" suite. ML-DSA provides the standard properties of existential unforgeability under chosen-message attack (EUF-CMA) [13].

SLH-DSA is a stateless hash-based signature scheme whose security rests solely on the properties of the underlying hash function (collision resistance, second-preimage resistance, and PRF security) [14]. Quantum Vault recognizes `SLH-DSA-SHAKE-256s` and `SLH-DSA-SHAKE-256f` as "strong PQ" suites. SLH-DSA's value for long-term archival provenance lies in its conservative hardness assumption: its security does not depend on the hardness of structured lattice problems, providing a hedge against potential future advances in lattice cryptanalysis. Quantum resource estimates for breaking lattice-based schemes remain an active research area [27], and maintaining algorithm diversity across distinct mathematical families is a prudent long-term strategy.

**Classical-interoperability signatures (`.sig`).** Produced by Stellar WebSigner using Ed25519 (RFC 8032 [15]). These signatures provide interoperability with existing identity ecosystems but are not quantum-resistant. Ed25519 relies on the hardness of the elliptic-curve discrete-logarithm problem on Curve25519, which Shor's algorithm solves in polynomial time [1]. Roetteler et al. estimate that breaking 256-bit elliptic-curve keys requires on the order of 2330 logical qubits and 10^11 Toffoli gates [27] — feasible for a fault-tolerant quantum computer but well beyond current hardware. After a quantum transition, Ed25519 signatures lose cryptographic force unless time evidence proves they were produced before the transition. Accordingly, the archive policy system treats Ed25519 signatures as valid for `any-signature` policy but insufficient for `strong-pq-signature` policy (Section 6.2). IR 8547 frames this as a transitional posture: classical signatures remain useful while quantum computers are unavailable, but long-term provenance requires PQ alternatives [2].

In the legacy track, detached archive-approval signatures target canonical manifest bytes. In the successor track, detached archive-approval signatures target canonical archive-state descriptor bytes, while maintenance and source-evidence signatures target canonical transition-record or source-evidence bytes and are reported separately from archive policy.

Current archive authenticity policy recognizes three signature-strength suites as "strong PQ": `mldsa-87` (ML-DSA-87), `slhdsa-shake-256s` (SLH-DSA-SHAKE-256s), and `slhdsa-shake-256f` (SLH-DSA-SHAKE-256f). Policy evaluation is based on normalized suite identifiers, not on wrapper type or file extension.

---

## 5. Canonicality, Mutability, and Binding Model

This section describes one of the most important architectural patterns in Quantum Vault: the separation between an immutable signable object and a mutable evidence carrier.
The shipped regular-user surface now uses the successor variant of this pattern: an immutable archive-state descriptor plus a mutable `QV-Lifecycle-Bundle` v1. The legacy manifest/bundle pattern remains relevant for compatibility analysis, but it is no longer the default archive model.

### 5.1 Successor archive-state descriptor (current primary track)

The successor archive-state descriptor is the long-lived archive-approval object for one archive state. It is canonicalized under `QV-JSON-RFC8785-v1` and carries:

- `archiveId` as the stable archive identifier within the successor family
- `parentStateId` for state lineage
- cryptographic profile and KDF identifiers
- nonce/AAD interpretation fields
- a `qenc` binding object containing `qencHash`, `containerId`, and related current-state fixity anchors
- `authPolicyCommitment` binding the canonical archive-state bytes to the mutable `authPolicy` object carried in the lifecycle bundle

The canonical archive-state bytes are the payload of successor archive-approval signatures. The derived `stateId` is `SHA3-512(canonical archive-state descriptor bytes)`. `stateId` does not appear inside the canonical archive-state bytes used to derive it.

### 5.2 Successor lifecycle bundle (current primary track)

`QV-Lifecycle-Bundle` v1 is the mutable evidence carrier for the successor track. It embeds:

- the current archive-state descriptor and its digest
- the current cohort binding and its digest
- the concrete `authPolicy`
- `sourceEvidence[]`
- `transitions[]`
- `attachments.publicKeys[]`
- `attachments.archiveApprovalSignatures[]`
- `attachments.maintenanceSignatures[]`
- `attachments.sourceEvidenceSignatures[]`
- `attachments.timestamps[]`

The lifecycle bundle is mutable by design. Detached archive-approval signatures do not sign lifecycle-bundle bytes; they sign canonical archive-state bytes. This lets new signatures, keys, timestamps, transition records, and source-evidence objects accumulate over time without invalidating existing archive-approval signatures.

Archive policy is evaluated using `archiveApprovalSignatures` only. Maintenance and source-evidence signatures remain separate semantic channels and do not satisfy archive policy.

### 5.3 Successor cohort binding and binding chain

The cohort binding is the state-bound distribution object that carries sharding commitments and shard-body binding data for one shard cohort. It is canonicalized separately from the archive-state descriptor. `cohortId` is derived from `archiveId`, `stateId`, and `cohortBindingDigest`; the lifecycle-bundle digest is not part of cohort identity.

The successor binding model creates the following chain:

1. Detached signatures sign canonical archive-state bytes for archive approval, or other declared successor lifecycle targets for maintenance and source evidence.
2. The archive-state descriptor binds the current `.qenc` container through `qencHash`, `containerId`, and related interpretation fields.
3. The cohort binding binds that archive state to one concrete shard cohort and its commitments.
4. `authPolicyCommitment` binds the canonical archive-state descriptor to the concrete `authPolicy` carried in the lifecycle bundle.
5. `.ots` evidence targets the bytes of a detached signature artifact, linking timestamp evidence to a signed lifecycle object rather than to mutable lifecycle-bundle bytes.

This layered binding ensures that:

- Signature validity is evaluated over a stable, immutable object.
- Evidence can be added without re-signing.
- The mutable lifecycle bundle can carry evolving provenance without compromising the signed archive-state description.
- Changing restore-relevant policy semantics requires a new archive-state descriptor and new archive-approval signatures, preventing silent policy weakening.

### 5.4 Historical v1 manifest/bundle comparison

Previously, v1 used the same general architectural pattern with different object boundaries:

- canonical manifest bytes were the detached archive-approval payload
- the mutable manifest bundle carried policy, public keys, signatures, and timestamps
- sharding parameters, shard body hashes, and share commitments lived inside the manifest rather than in a separate cohort-binding object

That older model remains technically relevant only for historical analysis and for previously created archives, but the successor track is the current primary architecture because it cleanly separates archive-state approval from replaceable shard-cohort distribution.

### 5.5 Current Timestamp Evidence Semantics

OpenTimestamps (`.ots`) evidence is linked to detached signature bytes via `SHA-256(detachedSignatureBytes)`. A bundle timestamp entry references a detached signature by identifier (`targetRef`).

The OpenTimestamps protocol follows the public-witness timestamping model introduced by Haber and Stornetta [4] and refined by Bayer, Haber, and Stornetta [18]: instead of relying on a trusted timestamp authority (as in RFC 3161's TSA model [20]), evidence is anchored into a widely witnessed, append-only public ledger — in this case, the Bitcoin blockchain. This approach eliminates single-point-of-trust dependency on a TSA's signing key, which would itself require quantum-transition planning. The Bitcoin blockchain provides a hash-linked chain of proof-of-work commitments that any verifier can independently validate against the public ledger, without requiring trust in a specific institutional authority. This is conceptually closer to the "widely witnessed event" model of Haber–Stornetta than to the X.509-certificate-chain model of RFC 3161 [20].

Current `.ots` semantics are deliberately limited:

- Timestamp evidence is supplementary. It does not satisfy archive signature policy by itself.
- Completeness labels (`apparentlyComplete`, `completeProof`) are heuristic reporting fields, not cryptographic guarantees that a full external attestation chain has been validated against the Bitcoin blockchain.
- The current implementation performs linkage and reporting; it does not claim full external OpenTimestamps attestation-chain verification.
- A single `.ots` proof provides a one-off existence assertion. It does not, by itself, constitute a renewable evidence chain as envisioned by RFC 4998 [3]. If the hash function used for `.ots` anchoring (currently SHA-256) is weakened in the future, the timestamp evidence would need to be renewed — re-timestamped under a stronger function while the original proof is still verifiable — to maintain long-term probative value.

This design treats OpenTimestamps as a useful current evidence layer — "a detached signature existed before some witness-observed time" — while leaving room for richer evidence architectures (Section 8.3) in future work.

---

## 6. Archive Authenticity Policy

### 6.1 Policy Object

In the legacy track, archive authenticity policy is fixed at creation time and committed into the canonical manifest via `authPolicyCommitment`. In the successor lifecycle track, the same logical `authPolicy` object is committed in the archive-state descriptor and carried in `QV-Lifecycle-Bundle` v1. The concrete policy shape is:

```json
{
  "authPolicy": {
    "level": "integrity-only | any-signature | strong-pq-signature",
    "minValidSignatures": 1
  }
}
```

### 6.2 Policy Levels

| Level | Requirement | Unsigned restore | Ed25519-only sufficient |
|---|---|---|---|
| `integrity-only` | No detached signature required | Yes | Yes, but not required |
| `any-signature` | At least `minValidSignatures` valid detached signatures | No | Yes |
| `strong-pq-signature` | At least `minValidSignatures` valid detached signatures, including at least one strong PQ signature | No | No |

### 6.3 Separation of States

The system maintains four distinct states that must not be conflated:

1. **Integrity verified.** Structural checks, digests, commitments, and reconstruction consistency hold.
2. **Signature verified.** At least one detached signature cryptographically verifies over the current signable archive description: canonical manifest bytes in the legacy track or canonical archive-state bytes for successor archive approval.
3. **Signer identity pinned.** A verified signature matches expected signer material from the bundle or from restore-time user input.
4. **Archive policy satisfied.** The verified signature set satisfies the declared policy level.

Integrity does not imply provenance. Signature validity does not imply signer pinning. Signer pinning does not replace policy evaluation. Timestamp evidence does not satisfy archive signature policy. In the successor lifecycle track, maintenance and source-evidence signatures are also kept separate from archive policy.

This four-state separation is designed to support auditability and traceable verification outcomes, aligning with the audit and certification principles used by ISO 16363 for trustworthy digital repositories [5]. Each verification step produces an independent, auditable assertion, and the overall archive status is the conjunction of these assertions rather than a single opaque "valid/invalid" judgment. A verifier can report, for example, that integrity holds and a signature verifies, but the signer is not pinned and policy is not satisfied — a partial-confidence state that an archivist can act on without loss of information.

---

## 7. Security Rationale

This section describes the major security invariants and the reasoning behind them. It is not a formal security proof; it is a design rationale intended for engineering and review audiences.

### 7.1 Explicit Algorithm Identifiers

Every `.qenc` container, `.qcont` shard, canonical manifest, and detached signature artifact carries explicit algorithm and format identifiers (`cryptoProfileId`, `kdfTreeId`, `noncePolicyId`, `aadPolicyId`, suite identifiers in signatures). Parsers must not infer algorithms from file extensions, key lengths, or other heuristic signals. This invariant ensures that future tools can unambiguously determine what algorithms were used, and that algorithm substitution attacks require overwriting authenticated metadata rather than exploiting parser ambiguity.

### 7.2 Fail-Closed Parsing

Quantum Vault rejects:

- Unknown major versions, magic values, or schema identifiers
- Unsupported canonicalization labels
- Mismatched `manifestDigest`, `bundleDigest`, or `authPolicyCommitment`
- Inconsistent shard cohorts (conflicting manifest or bundle digests)
- Malformed or unresolved signature references
- Unresolved, incompatible, or non-verifying `publicKeyRef` bindings in bundled signatures

The fail-closed posture ensures that ambiguous or partially valid inputs are rejected rather than silently downgraded. A shard cohort that mixes different manifest digests is rejected; there is no "largest cohort wins" rule.

### 7.3 AAD Binding

Security-relevant header fields reside within the AES-GCM AAD boundary. In single-container mode, the AAD is the entire header from magic bytes through the key commitment. In per-chunk mode, chunk index and plaintext length are additionally bound into each chunk's AAD. This prevents an adversary from modifying metadata fields (algorithm identifiers, nonce policy, chunk counts) without detection.

The AAD construction is injective: because header fields use fixed-length binary encodings, no two distinct header states produce the same AAD byte string (see Section 4.3). This property follows RFC 5116's recommendation that AAD must be unambiguously encoded to prevent cross-message authentication confusion [28].

### 7.4 IV Uniqueness

The per-chunk IV construction — an 8-byte KMAC-derived prefix concatenated with a 4-byte big-endian chunk counter — ensures IV uniqueness within a container by construction. The prefix is derived from `Kiv` and the `containerNonce`, both of which are unique to the container instance. The counter suffix is unique across chunks. No two chunks within a container share an IV under the same key.

For single-container mode, the `containerNonce` is generated via `crypto.getRandomValues()` (12 bytes). IV collision probability across independent containers is bounded by the birthday paradox over 96-bit random IVs — negligible for practical container counts — and each container uses independently derived keys.

### 7.5 Key Commitment

Key commitment (`SHA3-256(Kenc)`) is mandatory and is verified before decryption. The commitment is embedded in the AAD-authenticated header. This prevents scenarios in which an adversary constructs a ciphertext that decrypts validly under multiple keys, which is possible with bare AES-GCM [9]. The commitment is checked before any decryption operation proceeds.

### 7.6 Domain Separation

KMAC256 derivation steps use distinct, non-colliding customization strings (`quantum-vault:kdf:v2`, `quantum-vault:kenc:v2`, `quantum-vault:kiv:v2`, `quantum-vault:chunk-iv:v2`). These strings are recorded in the container metadata and included in the AAD boundary. Domain separation prevents cross-purpose key reuse: a key derived for encryption cannot be confused with a key derived for IV generation, even if the same root material is used, following SP 800-185 guidance [7].

### 7.7 Signer Pinning

A detached signature may optionally reference bundled signer identity material via `publicKeyRef`. When this reference is present, the verifier must resolve it to a compatible bundled key entry and verify the signature against that key. Failure to resolve or verify a declared `publicKeyRef` is treated as a verification failure for that signature — not merely as an absence of pinning. This prevents an attacker from stripping a bundled key reference and substituting a different key.

### 7.8 Timestamp Evidence Is Not Policy Satisfaction

Timestamp evidence is tracked and reported separately from signature verification and policy evaluation. An `.ots` proof linked to a detached signature provides evidence that the signature existed before some witness-observed time, but it does not substitute for the signature itself. An archive with valid timestamp evidence but no valid detached signature still fails `any-signature` and `strong-pq-signature` policies. This separation prevents a class of confusion attacks in which evidence presence is mistaken for cryptographic verification.

---

## 8. Long-Term Archival Direction

Quantum Vault is designed with multi-decade archival horizons in mind, but the current implementation does not yet provide a complete long-term archival system. This section describes the intended direction and identifies the gap between current capability and archival target state.

### 8.1 Long-Term Objectives

Long-term archival evaluation requires keeping the following objectives distinct [17][5]:

1. **Confidentiality.** Captured ciphertext must not become retrospectively readable solely because time passes or classical public-key cryptography fails.
2. **Authenticity and provenance.** A verifier must be able to determine whether preserved signer-origin evidence remains credible at a later verification time.
3. **Time verifiability.** A verifier must be able to determine whether archive evidence existed before a claimed time boundary.
4. **Interpretability.** Stored artifacts must remain understandable to future verifiers, including algorithm identifiers, canonicalization rules, and validation procedures.
5. **Recoverability.** The archive must remain reconstructable from preserved material and custody practices over the chosen horizon.

### 8.2 Archive Classes

Quantum Vault defines three archive classes as a documentation and planning taxonomy. These are not yet first-class wire-level fields in the manifest or bundle.

| Class | Minimum expectation | Current feasibility |
|---|---|---|
| `backup` | Confidentiality and recoverability; signatures optional | Fully supported |
| `audited-archive` | At least one detached signature; signer identity preserved; evidence recommended | Partially supported |
| `long-term-archive` | Strong PQ provenance, external evidence, renewal plan, representation package | Not fully implemented |

### 8.3 Evidence Renewal

The current `.ots` integration provides evidence linkage but not a renewable evidence-record chain. A one-off timestamp — whether from RFC 3161 [20] or OpenTimestamps — proves existence at a single point in time, but provides no mechanism to extend its validity when the underlying hash function or signature algorithm weakens. RFC 4998 (Evidence Record Syntax [3]) addresses this gap by defining a structure for maintaining chains of timestamp evidence over time. An ERS evidence record contains an initial Archive Timestamp over a hash tree of protected data objects, and defines a renewal procedure whereby new Archive Timestamps are generated over the existing evidence before the current algorithms are compromised [3]. This renewal procedure — "hash-tree renewal" when only the hash algorithm is weakened, or "timestamp renewal" when the timestamp authority's signature algorithm is threatened — is designed to preserve the evidentiary value of the original timestamp chain indefinitely, provided renewal occurs while the existing algorithms are still trustworthy [3].

The archival direction for Quantum Vault, informed by RFC 4998 and the Haber–Stornetta / Bayer–Haber–Stornetta timestamping literature [4][18], envisions:

- An initial evidence object `E₀` committing to archive anchors, detached signature digests, signer key identifiers, and witness outputs
- Successor evidence records `E₁, E₂, …` that commit to prior evidence and bind new witness material, creating a continuity chain analogous to ERS Archive Timestamp Chains
- Support for multiple independent witness regimes (Bitcoin anchoring, future PQ-signed evidence tokens, institutional witnesses) rather than dependence on a single timestamp authority
- Renewal before trust anchors or algorithms become untrustworthy, retaining old evidence as historical context — following RFC 4998's principle that renewal must precede algorithm compromise

This architecture is a recommended future direction, not a current implementation claim. The current `.ots` model provides the foundational linkage (signature → timestamp → witness) upon which a renewable evidence chain can be built.

### 8.4 Migration and Archive Identity

The current system uses layered identity anchors with the successor lifecycle track as the primary baseline. Historically, v1 relied on `qencHash`, `containerId`, `manifestDigest`, and `authPolicyCommitment`. The successor lifecycle track adds stable `archiveId`, `stateId`, and `cohortId` semantics within one archive family. This means:

- If ciphertext changes (rewrap or reencryption), `qencHash` changes.
- If the signable archive description changes to reflect new ciphertext or policy, the legacy `manifestDigest` changes or the successor `stateId` changes.
- Archival continuity across reencryption or policy-changing rebuilds is not yet format-native.

Stable `archiveId` now exists within the successor lifecycle family. The remaining gap is first-class continuity across future rewrap, reencryption, or other state-changing migration events. Until those continuity records exist, long-term continuity depends on documented migration records and explicit predecessor/successor archive provenance.

The following migration taxonomy guides future design:

| Event | Effect on current anchors |
|---|---|
| Attach signatures/evidence | current track signable object unchanged; mutable bundle content changes |
| Reshard | successor `archiveId` and `stateId` stay stable; `cohortId` and shard packaging change |
| Rewrap | Higher-level continuity may be intended; current fixity anchors may change |
| Reencryption | `qencHash`, `containerId`, and the current track's signable-state anchor change; explicit continuity records required |

### 8.5 OAIS Alignment

Quantum Vault is not an OAIS (ISO 14721 [17]) implementation and does not claim OAIS compliance. The following mapping is provided as an orientation layer for archivists evaluating the system:

| OAIS concept | Current Quantum Vault mapping |
|---|---|
| Fixity Information | `qencHash`, digests, commitments, detached signatures |
| Provenance Information | Detached signatures, signer identity material (partial) |
| Reference Information | successor `archiveId`, `stateId`, `cohortId`, `qencHash`, `containerId`, and legacy `manifestDigest` where applicable |
| Context Information | Policy object, evidence linkage, signer material |
| Representation Information | Format specification, algorithm identifiers, canonicalization rules, documentation |

OAIS also distinguishes Packaging Information — the metadata that binds Content Information and Preservation Description Information into a coherent, deliverable package [17]. Quantum Vault's current packaging relies on file-naming conventions and manifest/bundle cross-references rather than a formally specified packaging envelope. Package identity does not depend solely on filenames (the binding chain uses cryptographic digests), but the absence of a single self-describing package container means that a Dissemination or Archival Information Package, in OAIS terms, must be reconstructed from co-located artifacts. A future packaging envelope that aggregates all components into a single archivable unit is a recognized gap.

Representation Information — the information that maps a data object's bit sequences into "more meaningful concepts" [17] — is currently carried by the format specification document, algorithm identifiers, canonicalization labels, and version tags in artifact headers. OAIS emphasizes that Representation Information is itself a preservation object and must be maintained alongside the content it describes [17]. For Quantum Vault, this means that the format specification, canonicalization profile documentation, and algorithm-identifier registries must be preserved as part of the archival package, not merely referenced by external URL.

A minimally sufficient long-term archival package would include the `.qenc` or restorable `.qcont` cohort, the current track's signable archive description (successor archive-state descriptor on the normal shipped path; legacy manifest for compatibility packages), the current track's mutable bundle, detached signature set, timestamp/evidence set, representation information (format specification, canonicalization profile, algorithm identifiers), and packaging metadata sufficient for future verification. The current product generates most but not all of these components automatically.

---

## 9. Limitations and Open Risks

### 9.1 JavaScript Runtime Limitations

All cryptographic operations execute in JavaScript within the browser. This environment does not provide:

- Constant-time arithmetic guarantees. JavaScript engines may optimize away timing-safe patterns.
- Hardware-backed key isolation. Key material exists in process memory accessible to the browser and its extensions.
- Protection against memory remanence. Secret zeroization is best-effort; JavaScript does not guarantee that overwritten memory is not retained in heap copies, JIT artifacts, or garbage-collected generations.

These limitations are inherent to the client-only browser execution model. They are mitigated but not eliminated by session-wipe handlers (`beforeunload`, `pagehide`) and by avoiding persistent secret storage (no `localStorage`, `sessionStorage`, `IndexedDB`, or cookies for secret material).

### 9.2 Supply-Chain and Delivery Assumptions

The user must trust or verify the delivered application build. A compromised build or dependency could exfiltrate secrets or weaken cryptographic operations. This risk is common to all client-side web applications and is not specific to Quantum Vault, but it represents a real trust boundary that users must evaluate.

### 9.3 Incomplete Long-Term Evidence Architecture

The current `.ots` integration provides evidence linkage and heuristic completeness reporting. It does not provide:

- Full external OpenTimestamps attestation-chain validation
- Renewable evidence-record chains
- Multi-witness diversity
- Evidence continuity across migration events

These are future work items. The current system carries timestamp evidence as supplementary material but does not yet satisfy the full evidence requirements of a multi-decade archival system.

### 9.4 Current Migration and Renewal Incompleteness

The format does not yet support:

- First-class continuity records preserving successor `archiveId` semantics across rewrap or reencryption
- First-class migration-event or renewal-event logs
- Envelope DEK designs that would allow key-wrapping material to be replaced without re-encrypting the payload
- Hybrid KEM wrapping as a hedge against single-algorithm compromise
- KEM diversification beyond ML-KEM. NIST has selected HQC (a code-based KEM) as an additional standard to provide algorithm diversity against potential future weakening of module-lattice assumptions [2]. When HQC is finalized, incorporating it as an alternative or hybrid KEM would strengthen the system's long-term confidentiality posture by ensuring that no single mathematical hardness assumption is a single point of cryptographic failure.

These features are identified as recommended future directions in the deep research basis for the project.

### 9.5 Lightweight Trust and Governance Model

The current implementation does not include:

- First-class governance objects or trust-root programs
- Institutional authority models for migration, renewal, or custody transfer
- Machine-validated policy versioning or algorithm deprecation records

Governance expectations are currently documentation-level guidance for maintainers and operators, not machine-enforced policy objects.

### 9.6 Single-Key AEAD for Large Payloads

The current per-chunk mode derives distinct IVs per chunk but uses a single encryption key `Kenc` across all chunks. SP 800-38D notes that GCM security guarantees degrade as more data is processed under a single key [8]. For the current maximum file size (1 GiB), this is well within conservative GCM data limits. For future support of very large payloads, per-chunk key derivation would provide a stronger bound.

### 9.7 Entropy Source

Key generation depends primarily on the browser/OS cryptographic RNG exposed via `crypto.getRandomValues()`. User interaction events MAY be mixed in as a best-effort augmentation, but they are not treated as a standards-validated entropy source in their own right. The quality of the underlying RNG is determined by the browser and operating system implementation and is outside Quantum Vault's control. SP 800-90B [19] provides entropy-source requirements, but browser implementations are not individually certified against this standard.

---

## 10. References

[1] P. W. Shor, "Algorithms for Quantum Computation: Discrete Logarithms and Factoring," in *Proceedings 35th Annual Symposium on Foundations of Computer Science*, IEEE, 1994, pp. 124–134.

[2] National Institute of Standards and Technology, "Transition to Post-Quantum Cryptography Standards," NIST IR 8547, 2024. https://csrc.nist.gov/pubs/ir/8547/ipd

[3] T. Gondrom, R. Brandner, and U. Pordesch, "Evidence Record Syntax (ERS)," RFC 4998, IETF, August 2007. https://www.rfc-editor.org/rfc/rfc4998

[4] S. Haber and W. S. Stornetta, "How to Time-Stamp a Digital Document," *Journal of Cryptology*, vol. 3, no. 2, pp. 99–111, 1991.

[5] ISO 16363:2025, "Space data and information transfer systems — Audit and certification of trustworthy digital repositories." See also CCSDS 652.0-M-2.

[6] National Institute of Standards and Technology, "Module-Lattice-Based Key-Encapsulation Mechanism Standard," FIPS 203, August 2024. https://doi.org/10.6028/NIST.FIPS.203

[7] National Institute of Standards and Technology, "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash," SP 800-185, December 2016. https://doi.org/10.6028/NIST.SP.800-185

[8] National Institute of Standards and Technology, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC," SP 800-38D, November 2007. https://doi.org/10.6028/NIST.SP.800-38D

[9] J. Len, P. Grubbs, and T. Ristenpart, "Partitioning Oracle Attacks," in *USENIX Security Symposium*, 2021. See also: S. Gueron and Y. Lindell, "Better Bounds for Block Cipher Modes of Operation via Nonce-Based Key Derivation," in *ACM CCS*, 2017.

[10] National Institute of Standards and Technology, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions," FIPS 202, August 2015. https://doi.org/10.6028/NIST.FIPS.202

[11] A. Shamir, "How to Share a Secret," *Communications of the ACM*, vol. 22, no. 11, pp. 612–613, November 1979.

[12] I. S. Reed and G. Solomon, "Polynomial Codes over Certain Finite Fields," *Journal of the Society for Industrial and Applied Mathematics*, vol. 8, no. 2, pp. 300–304, June 1960.

[13] National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard," FIPS 204, August 2024. https://doi.org/10.6028/NIST.FIPS.204

[14] National Institute of Standards and Technology, "Stateless Hash-Based Digital Signature Standard," FIPS 205, August 2024. https://doi.org/10.6028/NIST.FIPS.205

[15] S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, IETF, January 2017. https://www.rfc-editor.org/rfc/rfc8032

[16] A. Rundgren, B. Jordan, and S. Erdtman, "JSON Canonicalization Scheme (JCS)," RFC 8785, IETF, June 2020. https://www.rfc-editor.org/rfc/rfc8785

[17] ISO 14721:2025, "Space Data System Practices — Reference model for an open archival information system (OAIS)." See also CCSDS 650.0-M-3.

[18] D. Bayer, S. Haber, and W. S. Stornetta, "Improving the Efficiency and Reliability of Digital Time-Stamping," in *Sequences II: Methods in Communication, Security and Computer Science*, Springer, 1993, pp. 329–334.

[19] National Institute of Standards and Technology, "Recommendation for the Entropy Sources Used for Random Bit Generation," SP 800-90B, January 2018. https://doi.org/10.6028/NIST.SP.800-90B

[20] C. Adams, P. Cain, D. Pinkas, and R. Zuccherato, "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)," RFC 3161, IETF, August 2001. https://www.rfc-editor.org/rfc/rfc3161

[21] A. Dent and C. Mitchell, "AEAD and Nonce Reuse," in *Authenticated Encryption*, Springer, 2014. See also: NIST guidance in SP 800-38D Section 8.

[22] J. Kelsey, S. Chang, and R. Perlner, "SHA-3 Derived Functions," NIST, 2016. (Context for KMAC domain-separation properties.)

[23] National Institute of Standards and Technology, "Recommendations for Key-Encapsulation Mechanisms," SP 800-227, 2025. https://csrc.nist.gov/pubs/sp/800/227/final

[24] K. Moriarty, B. Kaliski, J. Jonsson, and A. Rusch, "PKCS #1: RSA Cryptography Specifications Version 2.2," RFC 8017, IETF, November 2016. (Context for classical key establishment vulnerability.)

[25] P. Rogaway, "Authenticated-Encryption with Associated-Data," in *ACM CCS*, 2002.

[26] M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?" *IEEE Security & Privacy*, vol. 16, no. 5, pp. 38–41, 2018. (Context for HNDL as a rational present-day adversary strategy.)

[27] M. Roetteler, M. Naehrig, K. M. Svore, and K. Lauter, "Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms," in *Advances in Cryptology — ASIACRYPT 2017*, Springer LNCS 10625, pp. 241–270. https://doi.org/10.1007/978-3-319-70697-9_9

[28] D. McGrew, "An Interface and Algorithms for Authenticated Encryption," RFC 5116, IETF, January 2008. https://www.rfc-editor.org/rfc/rfc5116

[29] M. Amy, O. Di Matteo, V. Gheorghiu, M. Mosca, A. Parent, and J. Schanck, "Estimating the Cost of Generic Quantum Pre-image Attacks on SHA-2 and SHA-3," in *Selected Areas in Cryptography — SAC 2016*, Springer LNCS 10532, pp. 317–337, 2017. https://doi.org/10.1007/978-3-319-69453-5_18

[30] H. Birkholz, C. Vigano, and C. Bormann, "Concise Data Definition Language (CDDL): A Notational Convention to Express Concise Binary Object Representation (CBOR) and JSON Data Structures," RFC 8610, IETF, June 2019. https://www.rfc-editor.org/rfc/rfc8610
