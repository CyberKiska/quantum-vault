# Quantum Vault: Post-Quantum Archival Encryption with Threshold Recovery and Detached Provenance

**Status:** Release Candidate  
**Version:** 2.0.0  
**Date:** 2026-04-02

---

## Abstract

Quantum Vault is a client-only archival containerization system that combines post-quantum confidentiality, threshold recoverability, and detached provenance into one successor artifact family. The current baseline uses a canonical archive-state descriptor, cohort binding, and `QV-Lifecycle-Bundle` v1, with archive-approval signatures bound to canonical archive-state bytes. Mutable evidence such as signatures, signer identity material, transition records, source-evidence objects, and timestamp proofs can evolve without invalidating previously computed archive-approval signatures. Restoration is gated by an explicit archive authenticity policy committed at creation time and evaluated fail-closed. Same-state resharing is supported as maintenance over a stable archive state: archive-state bytes stay unchanged while a new cohort and required transition record are emitted. The current implementation executes entirely within the browser with no runtime network cryptographic service. This paper describes the system's design rationale, cryptographic construction, canonicality and binding model, security invariants, and long-term archival direction, and identifies the limitations and open risks that remain.

---

## 1. Introduction and Problem Statement

### 1.1 The Insufficiency of Encrypted Files

An encrypted file, taken alone, addresses only one concern: confidentiality at the time of encryption. For data that must remain protected across years or decades, this is insufficient.

**Long-lived confidentiality under harvest-now-decrypt-later (HNDL) risk.** An adversary who captures ciphertexts today may store them indefinitely and attempt decryption once cryptographically relevant quantum computers become available. Classical public-key key-establishment mechanisms such as RSA and finite-field or elliptic-curve Diffie-Hellman are vulnerable to Shor's algorithm [1]. NIST's transition report states (quoted):

> Even though the transition to post-quantum cryptography is starting before a cryptographically relevant quantum computer has been built, there is a pressing threat. Encrypted data remains at risk because of the "harvest now, decrypt later" threat in which adversaries collect encrypted data now with the goal of decrypting it once quantum technology matures. Since sensitive data often retains its value for many years, starting the transition to post-quantum cryptography now is critical to preventing these future breaches. This threat model is one of the main reasons why the transition to post-quantum cryptography is urgent.

The same document recounts Mosca's timeline argument (secret lifetime *X*, migration time *Y*, time *Z* to a cryptographically relevant quantum computer) and continues (quoted): *"This threat, often referred to as 'harvest now, decrypt later,' underscores the necessity of acting immediately, especially for data with long-term sensitivity, such as government secrets or medical records."* [2]; see Mosca [26]. **Implication for archival encryption:** continuing to wrap new or long-stored payloads with *quantum-vulnerable* key establishment does not “wait for Q-Day”—it invites HNDL against every captured archive. NIST explicitly separates **confidentiality** from **authentication** on this axis (quoted):

> Unlike with encryption, where there is a threat of "harvest now, decrypt later," an authentication system remains secure as long as the cryptographic algorithms and keys used to perform the authentication are secure when the authentication is performed.

For real protocols, the same report ties confidentiality timelines to **how** the symmetric keys were produced (quoted):

> As symmetric keys that are established through the key-establishment process are used to provide confidentiality, the "harvest now, decrypt later" threat needs to be considered when determining a migration timeline for the key-establishment scheme. The cryptographic algorithm used for authentication may be transitioned at a different time, and for that the considerations in Sec. 3.1.2 apply.

File- and message-level confidentiality is placed in the same bucket as email encryption: *"As with other applications providing data confidentiality, email encryption is subject to 'harvest now, decrypt later'"* [2]. For **transition policy**, NIST notes that *"in order to mitigate the risk of 'harvest now, decrypt later' attacks on network communications, application-specific guidance, as described in Sec. 4.2, may require or recommend migration to quantum-resistant key establishment schemes before the classical schemes are generally disallowed"* [2]—archives with multi-decade sensitivity are an obvious case where “later” migration of the **KEM** does not redeem ciphertext already encrypted under classical establishment. SP 800-227 lists ECDH-based and RSA-based KEM constructions as *"quantum-insecure"* examples and requires a parameter set with *"application-appropriate security strength"* [23]; Quantum Vault therefore fixes **ML-KEM-1024** at capture time for the public-key layer while using AES-256-GCM for bulk data, consistent with NIST's observation that approved symmetric primitives at ≥128-bit classical security are *"significantly less vulnerable to known quantum attacks"* than public-key schemes in SP 800-56A, SP 800-56B, and FIPS 186 [2].

Analysis of distributed ledger networks illustrates the same **retrospective** failure mode at ecosystem scale: historically captured replicas remain vulnerable even after a network later migrates its live protocols [31]. Quantum Vault's architecture matches the NIST distinction above: **post-quantum confidentiality from creation**, while the archive-authenticity layer may still accept classical-interoperability signatures during migration because their security is evaluated **when verified**, not when ciphertext was stored [2].

**Concrete quantum resource narratives for ECDLP (secp256k1) and a minority physical hypothesis.** Babbush *et al.* [34] analyze the 256-bit ECDLP over **secp256k1** and state in their abstract (quoted):

> We demonstrate that Shor's algorithm for this problem can execute with either ≤1200 logical qubits and ≤90 million Toffoli gates or ≤1450 logical qubits and ≤70 million Toffoli gates. In the interest of responsible disclosure, we use a zero-knowledge proof to validate these results without disclosing attack vectors. On superconducting architectures with 10⁻³ physical error rates and planar connectivity, those circuits can execute in minutes using fewer than half a million physical qubits.

These estimates concern a specific curve and hardware model; they do **not** specify when such machines exist, but they reinforce why classical ECC-based authenticity should be treated as transitional for long horizons.

**Public salience, disclosure model, and how this intersects Quantum Vault’s threat model.** The manuscript has attracted wide attention because it attaches **named orders of magnitude** (logical qubits, Toffoli counts, physical-qubit projections, wall-clock sketches) to a curve that underpins large parts of the digital-asset economy, and because it packages those claims behind a **zero-knowledge verification** artifact rather than publishing full attack circuits. The authors write (quoted from the introduction):

> Second, we rigorously substantiate our resource estimates by sharing a cryptographic zero-knowledge (ZK) proof … that enables trustless third parties to cryptographically verify the estimates without access to the underlying attack details. Specifically, we publish a ZK proof that we have compiled two quantum circuits for solving the 256-bit ECDLP: one with 1200 logical qubits and 90 million Toffoli gates and one with 1450 logical qubits and 70 million Toffoli gates.

(The ellipsis replaces in-paper citation markers in the original PDF.)

They further state that, on their superconducting surface-code model, the computations *"could be realized with fewer than half a million physical qubits (nearly a 20 fold reduction over prior estimates)"* and argue this is part of the same broad pattern of **algorithmic tightening** seen for factoring estimates. None of this supplies a calendar “deadline year” for industry—**press and policy timelines are not theorems**—but it does sharpen the conversation from hand-waving about “distant Q-Day” to **auditable resource statements** subject to revision as compilation and error-correction models improve.

For **live transaction layers**, the paper stresses a distinction that matters operationally. They define **on-spend** attacks as those requiring ECDLP to be solved within a chain’s settlement window, **at-rest** attacks where exposed keys sit available for much longer, and **on-setup** attacks that break fixed protocol parameters to mint a reusable classical backdoor [34]. They motivate PQC migration and mitigations such as private mempools partly because, under their fast-clock hardware assumptions, *"superconducting qubits could launch attacks within the average block time of Bitcoin and Bitcoin Cash, thus enabling ‘on-spend’ attacks"* (quoted). **Quantum Vault is not a mempool or a blockchain client:** its core archival risk remains **HNDL against captured `.qenc` ciphertext** protected by **ML-KEM-derived keys**, orthogonal to mempool racing. Conversely, the same work is a reminder that **classical ECC signatures** used for interoperability on lifecycle objects remain on the **wrong side** of Shor’s asymptotics for long-horizon provenance unless policy explicitly treats them as transitional—precisely the split QV encodes between PQ confidentiality and mixed-signature authenticity during migration.

**Independent reduction in logical qubits for generic 256-bit prime-field ECDLP (NIST P-256 class curves).** Separate from [34], Chevignard, Fouque, and Schrottenloher give a **space–time tradeoff** that roughly halves logical qubits versus earlier ECDLP compilations at the cost of a much larger Toffoli count and multiple independent runs [37]. Their abstract states (quoted):

> This strategy allows us to obtain the most space-efficient polynomial-time algorithm for the ECDLP to date, with only 3.12n + o(n) qubits, at the expense of an increase in gate count, from O(n³) to Õ(n⁴). For n = 256 we estimate that 1098 qubits would be necessary, with 22 independent runs, using 2^38.10 Toffoli gates each.

**Technical hygiene:** popular commentary sometimes conflates **logical** and **physical** qubit counts or cites round calendar years without a primary equation; when writing or reviewing risk material, anchor claims to **stated models** (curve family, error rate, distance, reaction-limited control assumptions) as in [34][37][27].

**Hybrid key exchange and “delay.”** Standards already recognize **PQ/traditional hybrid** constructions as a *defined interoperability pattern* during migration. RFC 9794 [36] records, for example, that *“Data encrypted today (in 2025) with an algorithm vulnerable to a quantum computer can be stored for decryption by a future attacker with a CRQC”*—the same HNDL logic that motivates QV’s ML-KEM layer [2][6]. Hybrids can add a CRQC-resistant component alongside traditional algorithms during protocol evolution [36], but they **do not retroactively re-encrypt ciphertexts already harvested** under classical key establishment—so they are not a substitute for **PQ confidentiality at capture time**, which is QV’s baseline. Urgent adoption of **ML-DSA** and related signatures [13] addresses **long-lived authenticity** under the same broad transition; operational costs of large PQ signatures remain a real deployment constraint [32].

A minority speculative literature also argues for much harsher physical limits on scalable quantum computation; Palmer [35], for example, proposes Rational Quantum Mechanics (RaQM) and argues that Shor-style practical breaking may saturate far below the scales usually assumed. **Quantum Vault’s engineering posture does not depend on such hypotheses.** Archive confidentiality and migration urgency remain grounded in the conventional cryptographically relevant quantum computer (CRQC) threat model and HNDL framing used by NIST and related transition guidance [2][31].

**Long-lived provenance.** Integrity verification is distinct from provenance. In Quantum Vault's current model, detached signatures provide cryptographic evidence that a specific signer key signed a canonical archive-state descriptor or another declared lifecycle object. Binding that key to a real-world identity, an approval workflow, or a custody role is external to the artifact family. AEAD authentication tags protect ciphertext integrity against tampering but do not establish signer identity. For archives that must remain attributable over decades, detached digital signatures are required, and those signatures must themselves survive the quantum transition.

**Long-lived time evidence.** Demonstrating that an artifact existed before a given time boundary requires external evidence beyond self-asserted timestamps. After a cryptographic transition, classical timestamp attestations may themselves become suspect; time evidence must therefore be renewable or rooted in mechanisms that do not depend solely on the continued security of one signature system [3][4].

**Distributed custody and threshold recovery.** Storing a single encrypted file and a single decryption key creates a single point of failure. Loss, compromise, or unavailability of the key renders the archive unrecoverable. Splitting key material and ciphertext across multiple independent custodians, with reconstruction requiring only a threshold subset, mitigates both loss and collusion risks.

**Mutable evidence without invalidating signed descriptions.** An archive's provenance material may need to be added, updated, or extended after the archive is created. If signatures cover a mutable object, every attachment invalidates all prior signatures. Separating an immutable signable description from a mutable evidence carrier allows provenance to accumulate without re-signing.

### 1.2 Design Response

Quantum Vault addresses these problems through a layered artifact family in which confidentiality, recoverability, canonical description, detached provenance, and mutable evidence are distinct concerns with distinct artifacts and invariants. The sections that follow describe the system's goals and boundaries, its cryptographic construction, the canonicality and binding model that supports long-lived provenance, the security rationale, and the intended archival direction.

---

## 2. Goals and Non-Goals

### 2.1 Goals

The system is designed to achieve the following properties:

1. **Post-quantum confidentiality.** Plaintext must remain unavailable to an adversary who captures archive artifacts, including under HNDL scenarios where the adversary later gains quantum computational capability.
2. **Threshold recoverability.** Archive reconstruction must require a configurable threshold of custodian-held shards, tolerating both loss and limited compromise among custodians.
3. **Signer-verifiable provenance.** A verifier must be able to determine whether a specific signer key signed the canonical archive-state description or another declared lifecycle object, using both post-quantum and classical-interoperability signature families.
4. **Policy-gated restoration.** Restoration must be explicitly allowed or blocked by an archive authenticity policy committed at creation time, rather than by ad hoc interpretation.
5. **Client-only operation.** All cryptographic operations are intended to execute in the user's browser with no runtime cryptographic network service.
6. **Format longevity and auditability.** Artifacts must carry explicit algorithm identifiers, version tags, and self-describing metadata sufficient for future tools to determine what was used and how to validate.

### 2.2 Non-Goals

The system does not claim to provide:

- resistance to a fully compromised host or browser environment
- strong side-channel resistance in JavaScript runtimes
- sender authentication from encryption alone
- coercion resistance of custodians
- guaranteed permanence of specific post-quantum algorithms
- institutional archival certification

---

## 3. Design Overview

### 3.1 Artifact Family

Quantum Vault produces and consumes the following artifacts:

| Artifact | Role |
| --- | --- |
| `.qenc` | Encrypted container carrying public metadata, key commitment, and AEAD ciphertext |
| `.qcont` | Threshold shard carrying one Shamir share, Reed-Solomon fragments, and embedded lifecycle artifacts |
| Archive-state descriptor | Canonical signable archive-state object |
| Cohort binding | State-bound shard-cohort description |
| `QV-Lifecycle-Bundle` v1 | Mutable carrier of policy, signatures, signer keys, timestamps, transitions, and source evidence |
| `.qsig` | Detached post-quantum signature over canonical archive-state bytes or another declared lifecycle target |
| `.sig` | Detached Ed25519/Stellar signature proof following the same declared-target rule |
| `.pqpk` | Detached post-quantum public key for signer pinning |
| `.ots` | OpenTimestamps evidence linked to detached signature bytes |

### 3.2 Lifecycle

The archive lifecycle proceeds through the following stages:

1. **Key generation.** An ML-KEM-1024 keypair is generated client-side using the browser or OS cryptographic RNG exposed via `crypto.getRandomValues()`, with optional best-effort mixing of user interaction events.
2. **Encryption.** The payload is encrypted into a `.qenc` container. ML-KEM encapsulates a shared secret; KMAC256 derives encryption and IV-derivation keys; AES-256-GCM provides authenticated encryption. A key commitment (`SHA3-256(Kenc)`) is embedded in the header.
3. **Split.** The `.qenc` container is split into `QVqcont-7` shards. The ML-KEM private key is split using Shamir secret sharing; the ciphertext is split using Reed-Solomon erasure coding. Split also emits an archive-state descriptor, cohort binding, and lifecycle bundle.
4. **Sign (external).** An external signer tool produces detached signatures (`.qsig` or `.sig`) over canonical archive-state bytes for archive approval, or over other declared lifecycle targets when maintenance or source-evidence signatures are created.
5. **Attach.** The shipped attach workflow merges detached signatures, signer public keys, and timestamp evidence into the lifecycle bundle without altering canonical archive-state or cohort-binding bytes. The lifecycle format can also carry transition records and source-evidence objects; same-state resharing emits required transition records. Updated bundles may optionally be re-embedded into shards.
6. **Restore.** A threshold of consistent shards is supplied, along with any optional external archive-state, lifecycle-bundle, signature, key, or timestamp material. The system verifies structural integrity, reconstructs the `.qenc` container and private key, verifies detached signatures, evaluates archive policy, and gates restoration accordingly.
7. **Decrypt.** The restored `.qenc` container is decrypted using the reconstructed private key.

### 3.3 Current implementation boundary

**Implemented now**

- one shard family: `QVqcont-7`
- canonical archive-state approval separated from mutable lifecycle-bundle evidence
- state-bound cohort bindings plus derived `archiveId`, `stateId`, and `cohortId`
- detached archive-approval, maintenance, and source-evidence signature families
- restore-time policy evaluation over archive-approval signatures only
- fail-closed archive, state, cohort, and lifecycle-bundle selection
- same-state resharing with required transition records

**Deferred roadmap**

- state-changing continuity records across rewrap or reencryption
- RFC 4998-style renewable evidence records
- governance and trust-root objects
- distributed resharing

---

## 4. Cryptographic Construction

### 4.1 Key Encapsulation: ML-KEM-1024

Quantum Vault uses ML-KEM-1024 (FIPS 203 [6]) for key establishment. ML-KEM is a module-lattice-based key-encapsulation mechanism standardized by NIST as a primary post-quantum replacement for classical key-establishment schemes. The ML-KEM-1024 parameter set targets NIST security category 5.

The encapsulation produces a shared secret and a ciphertext. The shared secret is not used directly as an encryption key; it enters the key-derivation tree described in Section 4.2.

The chosen parameter set is recorded as an explicit algorithm identifier in every `.qenc` container header and in the archive-state descriptor's `cryptoProfileId` field. This follows SP 800-227's guidance that a KEM parameter set must be selected before key generation and must be bound to the resulting key pair [23].

ML-KEM provides IND-CCA2-secure key encapsulation under the module-LWE hardness assumption. It protects against passive capture, including HNDL scenarios. It does not provide sender authentication; origin claims require the detached signature layer described in Section 4.7.

**Implementation timing hazards (KyberSlash).** KyberSlash names **secret-dependent division by a public modulus** in some Kyber/ML-KEM software paths, which can leak key material through **timing** on certain CPUs, compilers, and build options—not a claimed polynomial-time break of the module-LWE problem or of the ML-KEM specification itself [38]. The KyberSlash site summarizes the issue as follows (quoted):

> Various Kyber software libraries in various environments leak secret information into timing, specifically because these libraries include a line of code that divides a secret numerator by a public denominator, the number of CPU cycles for division in various environments varies depending on the inputs to the division, and this variation appears within the range of numerators used in these libraries.

Bernstein *et al.* document two patterns (KyberSlash1 and KyberSlash2), demonstrate key recovery in embedded-class environments for vulnerable builds, and report coordinated patching across affected libraries [38]. That work is **orthogonal to HNDL**: a remote adversary who only stores `.qenc` ciphertext for later algebraic attack does not observe local encapsulation or decapsulation timings. Conversely, a **co-resident** attacker who can measure those timings targets the same implementation layer that must be kept under review for **any** high-assurance KEM deployment. The shipped browser build delegates ML-KEM to the `@noble/post-quantum` dependency (see `src/core/crypto/mlkem.js`); maintainers should track upstream releases and the KyberSlash [library tracker](https://kyberslash.cr.yp.to/libraries.html) alongside the already-stated absence of constant-time guarantees in JavaScript (Section 9.1). **Algorithm diversification** (for example NIST’s selection of HQC as a second KEM standard [33]) remains the format-level hedge against a future **mathematical** break of module-lattice KEMs, distinct from patching **concrete** implementations against side channels.

### 4.2 Key Derivation: KMAC256

Key material is derived from the ML-KEM shared secret using KMAC256 (SP 800-185 [7]).
The derivation tree is:

1. `Kraw = KMAC256(sharedSecret, salt || metaBytes, customization = "quantum-vault:kdf:v2", dkLen = 32)`
2. `Kenc = KMAC256(Kraw, 0x01, customization = "quantum-vault:kenc:v2", dkLen = 32)`
3. `Kiv  = KMAC256(Kraw, 0x02, customization = "quantum-vault:kiv:v2", dkLen = 32)`

where `salt` is a 16-byte random value and `metaBytes` is the UTF-8 encoding of the container's public metadata JSON.

The pseudocode above is a simplified representation. In the current implementation, `Kraw` is derived from the byte string `salt || metaBytes`. This remains unambiguous because `salt` is fixed at 16 bytes and `metaBytes` occupies the remainder of the KMAC message; the current format therefore relies on a fixed-width prefix plus explicit domain-separation strings, not on a separately serialized SP 800-185 tuple encoding inside the KMAC message [7].

Domain-separation strings are recorded in container metadata and included in the authenticated-data boundary. A verifier that encounters unknown or missing domain strings must reject the container.

### 4.3 Authenticated Encryption: AES-256-GCM

Payload encryption uses AES-256-GCM (SP 800-38D [8]) with 96-bit initialization vectors and 128-bit authentication tags.
Two AEAD modes are supported:

**Single-container mode.** Used for payloads at or below the chunk size. The 12-byte `containerNonce` generated at encryption time serves directly as the GCM IV. The authenticated additional data (AAD) is the complete `.qenc` header from the magic bytes through the key commitment.

**Per-chunk mode.** Used for payloads exceeding the chunk size. The payload is divided into fixed-size chunks, each encrypted independently under AES-256-GCM with a distinct per-chunk IV:

`IV_i = KMAC256(Kiv, containerNonce, customization = "quantum-vault:chunk-iv:v2", dkLen = 8) || uint32_be(i)`

This produces an 8-byte (64-bit) KMAC-derived prefix concatenated with a 4-byte big-endian chunk counter, for a total 96-bit IV per SP 800-38D requirements [8].

Per-chunk AAD is `header || uint32_be(i) || uint32_be(plainLen_i)`, binding each chunk's position and plaintext length into its authentication scope. The fixed widths of `uint32_be` fields ensure the AAD concatenation is injective, satisfying the unambiguous additional-data construction requirement of the AEAD interface [28].

SP 800-38D warns that GCM IV reuse under the same key can compromise security almost entirely [8]. The deterministic per-chunk IV derivation eliminates IV reuse risk within one container by construction.

### 4.4 Key Commitment

The `.qenc` header carries a mandatory key commitment computed as `SHA3-256(Kenc)`.
The commitment is verified before decryption begins. Its purpose is to prevent key-commitment attacks in which an adversary constructs a ciphertext that decrypts validly under multiple keys [9].

The key commitment is included within the AAD boundary, ensuring that it is itself authenticated.

### 4.5 Hashing and Fixity: SHA3-512 and SHA3-256

SHA3-512 is chosen as the primary digest function partly for its conservative quantum headroom. Generic quantum preimage attacks on SHA-2 and SHA-3 are not simply "Grover halves the bits": the actual fault-tolerant quantum resource cost of finding a preimage is substantially higher than a naïve quadratic speedup suggests [29]. SHA3-512 therefore provides significant conservative margin even under optimistic assumptions about future quantum adversaries. The Keccak sponge construction also provides clean domain-separation properties that complement the KMAC-based key derivation layer.

Quantum Vault uses SHA3-512 (FIPS 202 [10]) as its primary hash function for:

- `qencHash`: SHA3-512 over the full `.qenc` bytes
- `containerId`: SHA3-512 over the `.qenc` header bytes
- `stateId`: SHA3-512 over canonical archive-state descriptor bytes
- `cohortBindingDigest`: SHA3-512 over canonical cohort-binding bytes
- `authPolicyCommitment`: SHA3-512 over canonicalized authenticity policy
- transition-record and source-evidence digests
- shard body hashes and Shamir share commitments

SHA3-256 is used for key commitment (`SHA3-256(Kenc)`) and for deriving `cohortId` from the canonical cohort-id preimage.

### 4.6 Threshold Recovery: Shamir Secret Sharing and Reed-Solomon Erasure Coding

Quantum Vault splits archive material across `n` shards using two complementary mechanisms:

**Shamir secret sharing** [11] splits the ML-KEM private key into `n` shares such that any `t` shares suffice to reconstruct the key, but fewer than `t` shares reveal no information about it. The threshold is computed as `t = k + (n - k) / 2`, where `k` is the Reed-Solomon data-shard count and `n` is the total shard count.

Share commitments are recorded in the cohort binding. During restoration, each submitted share is checked against its committed digest before entering reconstruction.

**Reed-Solomon erasure coding** [12] splits the `.qenc` ciphertext into `k` data fragments and `n - k` parity fragments, such that any `k` of `n` fragments suffice to reconstruct the ciphertext. Per-shard fragment body hashes are also recorded in the cohort binding and verified during restoration.

Each `QVqcont-7` shard carries one Shamir share, one set of Reed-Solomon fragments, and the embedded archive-state, cohort-binding, and lifecycle-bundle bytes for the selected cohort.

### 4.7 Detached Signatures

Quantum Vault supports detached signatures from two external signer tools:

**Post-quantum signatures (`.qsig`).** Produced by Quantum Signer, supporting ML-DSA parameter sets (FIPS 204 [13]) and SLH-DSA parameter sets (FIPS 205 [14]). The `.qsig` format is a versioned binary container carrying suite identifiers, prehash information, signer fingerprint material, and signature bytes.

ML-DSA is a module-lattice-based post-quantum signature family standardized in FIPS 204 [13]. SLH-DSA derives its post-quantum security from hash-function assumptions alone, with no dependence on structured algebraic hardness. This orthogonal security basis means that an unforeseen break in module-lattice assumptions would not compromise a SLH-DSA signature, and vice versa. The practical trade-off is that SLH-DSA produces substantially larger signatures and verifies more slowly than ML-DSA at equivalent security levels [32].

**Classical-interoperability signatures (`.sig`).** Produced by Stellar WebSigner using Ed25519 (RFC 8032 [15]). These signatures provide interoperability with existing identity ecosystems but are not quantum-resistant.

Current archive authenticity policy recognizes three suites as "strong PQ":

- `mldsa-87`
- `slhdsa-shake-256s`
- `slhdsa-shake-256f`

All three are NIST security category 5 instantiations. `mldsa-87` is the largest ML-DSA parameter set (FIPS 204 §4). `slhdsa-shake-256s` and `slhdsa-shake-256f` are the SHAKE-256-instantiated SLH-DSA variants at the highest security level (FIPS 205 §10); the `s` variant optimizes for smaller signatures while the `f` variant optimizes for faster signing. Including both SLH-DSA variants provides hash-based algorithmic diversification relative to ML-DSA's lattice foundation.

Current signature-target model:

- archive-approval signatures target canonical archive-state descriptor bytes
- maintenance signatures target canonical transition-record bytes
- source-evidence signatures target canonical source-evidence bytes
- lifecycle-bundle bytes are never the archive-approval target

---

## 5. Canonicality, Mutability, and Binding Model

This section describes one of the most important architectural patterns in Quantum Vault: the separation between an immutable signable object and a mutable evidence carrier.

### 5.1 Archive-state descriptor

The archive-state descriptor is the long-lived archive-approval object for one archive state. It is canonicalized under `QV-JSON-RFC8785-v1` (a strict UTF-8 JSON canonicalization profile aligned with RFC 8785 [16]; byte-level parity is demonstrated for current artifact shapes in the repository's canonicalization appendix) and carries:

- `archiveId` as the stable archive identifier within the successor family
- `parentStateId` for state lineage
- cryptographic profile and KDF identifiers
- nonce and AAD interpretation fields
- a `qenc` binding object containing `qencHash`, `containerId`, and related fixity anchors
- `authPolicyCommitment` binding the canonical archive-state bytes to the mutable `authPolicy` object carried in the lifecycle bundle

The canonical archive-state bytes are the payload of archive-approval signatures.
The derived `stateId` is `SHA3-512(canonical archive-state descriptor bytes)`.
`stateId` does not appear inside the canonical archive-state bytes used to derive it.

### 5.2 Lifecycle bundle

`QV-Lifecycle-Bundle` v1 is the mutable evidence carrier. It embeds:

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

This separation is a direct answer to the archival mutability problem. Archive approval must remain anchored to one byte-stable object so that detached signatures, proof counting, and restore policy all refer to the same payload over time. Evidence that naturally grows after creation therefore travels in the lifecycle bundle, while the archive-state descriptor remains the immutable approval target.

### 5.3 Cohort binding and binding chain

The cohort binding is the state-bound distribution object that carries sharding commitments and shard-body binding data for one shard cohort. It is canonicalized separately from the archive-state descriptor. `cohortId` is derived from `archiveId`, `stateId`, and `cohortBindingDigest`; the lifecycle-bundle digest is not part of cohort identity.

The current binding model creates the following chain:

1. Detached signatures sign canonical archive-state bytes for archive approval, or other declared lifecycle targets for maintenance and source evidence.
2. The archive-state descriptor binds the current `.qenc` container through `qencHash`, `containerId`, and related interpretation fields.
3. The cohort binding binds that archive state to one concrete shard cohort and its commitments.
4. `authPolicyCommitment` binds the canonical archive-state descriptor to the concrete `authPolicy` carried in the lifecycle bundle.
5. `.ots` evidence targets detached-signature bytes, linking timestamp evidence to a signed lifecycle object rather than to mutable lifecycle-bundle bytes.

### 5.4 Historical comparison

Earlier iterations of the system used the same high-level architectural pattern, but with a signable manifest and mutable bundle boundary that coupled shard-distribution details more closely to archive approval. The current successor model separates stable archive-state approval from replaceable cohort-level sharding more cleanly. This historical comparison remains useful only as design context; the active implementation described in this paper is the successor model above.

### 5.5 Current timestamp evidence semantics

OpenTimestamps (`.ots`) evidence is linked to detached signature bytes via `SHA-256(detachedSignatureBytes)`. SHA-256 is used here as an interoperability requirement of the OpenTimestamps proof format, which defines its stamp operation over SHA-256 digests; this is not an independent QV design choice but a constraint of the OTS ecosystem. It does not affect the SHA-3 dominance of the artifact family's fixity and binding layer, where all other digests use SHA3-512 or SHA3-256.

Current `.ots` semantics are deliberately limited:

- timestamp evidence is supplementary
- it does not satisfy archive signature policy by itself
- completeness labels (`apparentlyComplete`, `completeProof`) are heuristic reporting fields, not cryptographic guarantees that a full external attestation chain was validated
- the current implementation performs linkage and reporting; it does not claim full external OpenTimestamps attestation-chain verification

In the shipped implementation, linkage depends on the OTS proof header and stamped digest matching detached signature bytes. `apparentlyComplete` / `completeProof` are reporting labels inferred from filename hints and proof size, not from a separately validated Bitcoin confirmation chain.

This design treats OpenTimestamps as a useful current evidence layer while leaving room for richer evidence architectures in future work.

---

## 6. Archive Authenticity Policy

### 6.1 Policy Object

Archive authenticity policy is committed in the archive-state descriptor via `authPolicyCommitment` and carried concretely in `QV-Lifecycle-Bundle` v1 as:

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
| --- | --- | --- | --- |
| `integrity-only` | No detached archive-approval signature required | Yes | Yes, but not required |
| `any-signature` | At least `minValidSignatures` valid archive-approval signatures | No | Yes |
| `strong-pq-signature` | At least `minValidSignatures` valid archive-approval signatures, including at least one strong-PQ archive-approval signature | No | No |

### 6.3 Separation of states

The system maintains the following distinct states that must not be conflated:

1. integrity verified
2. archive-approval signature verified
3. signer identity pinned
4. archive policy satisfied
5. maintenance signature verified
6. source-evidence signature verified
7. OTS evidence linked

Integrity does not imply provenance. Signature validity does not imply signer pinning. Signer pinning does not replace policy evaluation. Timestamp evidence does not satisfy archive policy. Maintenance and source-evidence signatures remain separate from archive policy by design.

---

## 7. Security Rationale

### 7.1 Explicit algorithm identifiers

Every `.qenc` container, `QVqcont-7` shard, archive-state descriptor, and detached signature artifact carries explicit algorithm and format identifiers. Parsers must not infer algorithms from file extensions, key lengths, or other heuristic signals. This ensures that future tools can unambiguously determine what algorithms were used and that substitution attacks require overwriting authenticated metadata rather than exploiting parser ambiguity.

### 7.2 Fail-closed parsing

Quantum Vault rejects:

- unknown major versions, magic values, or schema identifiers
- unsupported canonicalization labels
- mismatched digests or derived identifiers
- inconsistent shard cohorts
- malformed or unresolved signature references
- unresolved, incompatible, or non-verifying `publicKeyRef` bindings in bundled signatures
- ambiguous archive, state, cohort, or lifecycle-bundle selection during restore

The fail-closed posture ensures that ambiguous or partially valid inputs are rejected rather than silently downgraded.

### 7.3 AAD binding

Security-relevant header fields reside within the AES-GCM AAD boundary. In single-container mode, the AAD is the entire header from magic bytes through the key commitment. In per-chunk mode, chunk index and plaintext length are additionally bound into each chunk's AAD. This prevents an adversary from modifying metadata fields without detection.

### 7.4 IV uniqueness

The per-chunk IV construction, an 8-byte KMAC-derived prefix concatenated with a 4-byte big-endian chunk counter, ensures IV uniqueness within a container by construction. For single-container mode, the `containerNonce` is generated via `crypto.getRandomValues()` and collision probability across independent containers remains negligible in the current operating regime.

### 7.5 Key commitment

Key commitment (`SHA3-256(Kenc)`) is mandatory and is verified before decryption. The commitment is embedded in the authenticated header. This prevents scenarios in which an adversary constructs a ciphertext that decrypts validly under multiple keys [9].

### 7.6 Domain separation

KMAC256 derivation steps use distinct, non-colliding customization strings. These strings are recorded in container metadata and included in the authenticated boundary. Domain separation prevents cross-purpose key reuse: a key derived for encryption cannot be confused with a key derived for IV generation, even when the same root material is used.

### 7.7 Signer pinning

A detached signature may optionally reference bundled signer identity material via `publicKeyRef`. When this reference is present, the verifier must resolve it to a compatible bundled key entry and verify the signature against that key. Failure to resolve or verify a declared `publicKeyRef` is treated as a verification failure for that signature, not merely as an absence of pinning.

### 7.8 Timestamp evidence is not policy satisfaction

Timestamp evidence is tracked and reported separately from signature verification and policy evaluation. An `.ots` proof linked to a detached signature provides evidence that the signature existed before some witness-observed time, but it does not substitute for the signature itself.

---

## 8. Long-Term Archival Direction

### 8.1 Long-term objectives

Long-term archival evaluation requires keeping the following objectives distinct:

1. confidentiality
2. authenticity and provenance
3. time verifiability
4. interpretability
5. recoverability

### 8.2 Archive classes

Quantum Vault defines three archive classes as a documentation and planning taxonomy:

| Class | Minimum expectation | Current feasibility |
| --- | --- | --- |
| `backup` | Confidentiality and recoverability; signatures optional | Fully supported |
| `audited-archive` | At least one detached archive-approval signature; signer identity preserved; evidence recommended | Partially supported |
| `long-term-archive` | Strong PQ provenance, external evidence, renewal plan, representation package | Not fully implemented |

### 8.3 Evidence renewal

The current `.ots` integration provides evidence linkage but not a renewable evidence-record chain. A one-off timestamp proves existence at one point in time, but provides no mechanism to extend its validity when the underlying hash function or signature algorithm weakens. RFC 4998 (Evidence Record Syntax [3]) addresses this gap by defining structures for maintaining timestamp evidence over time.

The archival direction for Quantum Vault envisions:

- an initial evidence object `E0` committing to archive anchors, detached signature digests, signer key identifiers, and witness outputs
- successor evidence records `E1`, `E2`, and so on that commit to prior evidence and bind new witness material
- support for multiple independent witness regimes rather than dependence on one timestamp authority
- renewal before trust anchors or algorithms become untrustworthy

This architecture is a recommended future direction, not a current implementation claim.

### 8.4 Migration and archive identity

The current system uses layered identity anchors:

- `archiveId`
- `stateId`
- `cohortId`
- `qencHash`
- `containerId`
- `authPolicyCommitment`

This means:

- if ciphertext changes, `qencHash` changes
- if the signable archive-state descriptor changes to reflect new ciphertext or policy, `stateId` changes
- same-state resharing preserves archive-state bytes and therefore preserves archive-approval signatures and their OTS linkage
- archival continuity across rewrap or reencryption is not yet format-native

Until state-changing continuity records exist, long-term continuity depends on documented migration records and explicit predecessor or successor provenance.

### 8.5 OAIS alignment

Quantum Vault is not an OAIS (ISO 14721 [17]) implementation and does not claim OAIS compliance.
The following mapping is provided as an orientation layer:

| OAIS concept | Current Quantum Vault mapping |
| --- | --- |
| Fixity Information | `qencHash`, digests, commitments, detached signatures |
| Provenance Information | Detached signatures, signer identity material, transition records, source-evidence objects |
| Reference Information | `archiveId`, `stateId`, `cohortId`, `qencHash`, `containerId` |
| Context Information | Policy object, evidence linkage, signer material |
| Representation Information | Format specification, algorithm identifiers, canonicalization rules, documentation |

A minimally sufficient long-term archival package would include the `.qenc` or a restorable `.qcont` cohort, the archive-state descriptor, the cohort binding, the lifecycle bundle, the detached-signature set, the timestamp or evidence set, representation information, and packaging metadata sufficient for future verification.

---

## 9. Limitations and Open Risks

### 9.1 JavaScript runtime limitations

All cryptographic operations execute in JavaScript within the browser. This environment does not provide:

- constant-time arithmetic guarantees
- hardware-backed key isolation
- protection against memory remanence

These limitations are inherent to the client-only browser execution model. They interact with **implementation-level** KEM risks such as KyberSlash-class timing leakage in vulnerable libraries [38]: even a sound ML-KEM **specification** still requires a **sound implementation** and supply-chain discipline (Section 4.1).

### 9.2 Supply-chain and delivery assumptions

The user must trust or verify the delivered application build. A compromised build or dependency could exfiltrate secrets or weaken cryptographic operations. This is a real trust boundary that users must evaluate.

### 9.3 Incomplete long-term evidence architecture

The current `.ots` integration provides evidence linkage and heuristic completeness reporting. It does not provide:

- full external OpenTimestamps attestation-chain validation
- renewable evidence-record chains
- multi-witness diversity
- evidence continuity across migration events

### 9.4 Current migration and renewal incompleteness

The format does not yet support:

- first-class continuity records preserving `archiveId` semantics across rewrap or reencryption
- first-class migration-event or renewal-event logs
- envelope-DEK designs that would allow key-wrapping material to be replaced without re-encrypting the payload
- hybrid KEM wrapping as a hedge against single-algorithm compromise (see RFC 9794 for IETF terminology on hybrid PQ/traditional schemes [36])
- KEM diversification beyond ML-KEM

The importance of KEM diversification is directly evidenced by NIST's March 2025 selection of HQC as a second KEM standard, explicitly to provide a backup based on code-based cryptography in case ML-KEM proves vulnerable to future cryptanalysis [33]. The current format's `cryptoProfileId` field is extensible by design, and this extensibility will be required when a second KEM is incorporated.

### 9.5 Lightweight trust and governance model

The current implementation does not include:

- first-class governance objects or trust-root programs
- institutional authority models for migration, renewal, or custody transfer
- machine-validated policy versioning or algorithm deprecation records

### 9.6 Single-key AEAD for large payloads

The current per-chunk mode derives distinct IVs per chunk but uses a single encryption key `Kenc` across all chunks. For the current maximum file-size regime this remains within conservative GCM data limits. For much larger future payloads, per-chunk key derivation would provide a stronger bound.

### 9.7 Entropy source

Key generation depends primarily on the browser or OS cryptographic RNG exposed via `crypto.getRandomValues()`. User interaction events may be mixed in as a best-effort augmentation, but they are not treated as a standards-validated entropy source in their own right.

---

## 10. References

[1] P. W. Shor, "Algorithms for Quantum Computation: Discrete Logarithms and Factoring," in *Proceedings 35th Annual Symposium on Foundations of Computer Science*, IEEE, 1994, pp. 124–134.

[2] National Institute of Standards and Technology, "Transition to Post-Quantum Cryptography Standards," NIST IR 8547 (Initial Public Draft), November 2024. https://csrc.nist.gov/pubs/ir/8547/ipd (as of the date of this document, no final version has been published; the IPD is the current available reference)

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

[21] A. Dent and C. Mitchell, "AEAD and Nonce Reuse," in *Authenticated Encryption*, Springer, 2014.

[22] J. Kelsey, S. Chang, and R. Perlner, "SHA-3 Derived Functions," NIST, 2016.

[23] National Institute of Standards and Technology, "Recommendations for Key-Encapsulation Mechanisms," SP 800-227, 2025. https://csrc.nist.gov/pubs/sp/800/227/final

[24] K. Moriarty, B. Kaliski, J. Jonsson, and A. Rusch, "PKCS #1: RSA Cryptography Specifications Version 2.2," RFC 8017, IETF, November 2016.

[25] P. Rogaway, "Authenticated-Encryption with Associated-Data," in *ACM CCS*, 2002.

[26] M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?" *IEEE Security & Privacy*, vol. 16, no. 5, pp. 38–41, 2018.

[27] M. Roetteler, M. Naehrig, K. M. Svore, and K. Lauter, "Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms," in *Advances in Cryptology — ASIACRYPT 2017*, Springer LNCS 10625, pp. 241–270. https://doi.org/10.1007/978-3-319-70697-9_9

[28] D. McGrew, "An Interface and Algorithms for Authenticated Encryption," RFC 5116, IETF, January 2008. https://www.rfc-editor.org/rfc/rfc5116

[29] M. Amy, O. Di Matteo, V. Gheorghiu, M. Mosca, A. Parent, and J. Schanck, "Estimating the Cost of Generic Quantum Pre-image Attacks on SHA-2 and SHA-3," in *Selected Areas in Cryptography — SAC 2016*, Springer LNCS 10532, pp. 317–337, 2017. https://doi.org/10.1007/978-3-319-69453-5_18

[30] H. Birkholz, C. Vigano, and C. Bormann, "Concise Data Definition Language (CDDL): A Notational Convention to Express Concise Binary Object Representation (CBOR) and JSON Data Structures," RFC 8610, IETF, June 2019. https://www.rfc-editor.org/rfc/rfc8610

[31] K. Mascelli and A. Rodden, "Harvest Now, Decrypt Later: Examining Post-Quantum Cryptography and the Data Privacy Risks for Distributed Ledger Networks," *FEDS Notes*, Federal Reserve Board, 2025. https://www.federalreserve.gov/econres/feds/harvest-now-decrypt-later-examining-post-quantum-cryptography-and-the-data-privacy-risks-for-distributed-ledger-networks.htm

[32] D. J. Bernstein, A. Hülsing, S. Kölbl, R. Niederhagen, J. Rijneveld, and P. Schwabe, "The SPHINCS+ Signature Framework," in *ACM CCS*, 2019. https://sphincs.org/data/sphincs+-paper.pdf (academic precursor to SLH-DSA / FIPS 205; see also Trail of Bits, "The treachery of post-quantum signatures," 2023, https://blog.trailofbits.com/2023/03/01/the-treachery-of-post-quantum-signatures/ for an engineering perspective on operational constraints of large-signature PQ schemes)

[33] National Institute of Standards and Technology, "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption," NIST News, March 2025. https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption (HQC selected as a second KEM to provide code-based-cryptography diversification complementary to ML-KEM's module-lattice basis; see also NIST IR 8545 for the fourth-round evaluation rationale)

[34] R. Babbush, A. Zalcman, C. Gidney, M. Broughton, T. Khattar, H. Neven, T. Bergamaschi, J. Drake, and D. Boneh, "Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations," arXiv:2603.28846 [quant-ph], 2026. https://arxiv.org/abs/2603.28846 (quotations follow the PDF text of the submitted manuscript; some in-paper citation markers are elided in quoted passages to avoid confusion with this document’s own reference numbers)

[35] T. Palmer, "Rational Quantum Mechanics: Testing Quantum Theory with Quantum Computers," arXiv:2510.02877v3 [quant-ph], revised 15 Feb. 2026. https://arxiv.org/abs/2510.02877v3 (quotations in this whitepaper follow the PDF text of v3; RaQM is a minority speculative hypothesis and is **not** an assumption behind Quantum Vault’s design)

[36] F. Driscoll, M. Parsons, and B. Hale, "Terminology for Post-Quantum Traditional Hybrid Schemes," RFC 9794, IETF, June 2025. https://www.rfc-editor.org/rfc/rfc9794.html

[37] C. Chevignard, P.-A. Fouque, and A. Schrottenloher, "Reducing the Number of Qubits in Quantum Discrete Logarithms on Elliptic Curves," in *EUROCRYPT 2026* (also Cryptology ePrint Archive Report 2026/280). https://eprint.iacr.org/2026/280 (quotations follow the ePrint abstract; applies to 256-bit prime-field curves including NIST P-256; **not** the same curve model as secp256k1 in [34])

[38] D. J. Bernstein, K. Bhargavan, S. Bhasin, A. Chattopadhyay, T. K. Chia, M. J. Kannwischer, F. Kiefer, T. B. Paiva, P. Ravi, and G. Tamvada, "KyberSlash: Exploiting secret-dependent division timings in Kyber implementations," *IACR Transactions on Cryptographic Hardware and Embedded Systems*, vol. 2025, no. 2, pp. 209–234, 2025. https://doi.org/10.46586/tches.v2025.i2.209-234. Project summary and library tracker: https://kyberslash.cr.yp.to/
