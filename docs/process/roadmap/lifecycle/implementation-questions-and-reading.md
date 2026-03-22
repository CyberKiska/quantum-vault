# Quantum Vault — Implementation Questions & Reading Guide

## Purpose

This document defines:
- critical design questions
- required research areas
- primary standards and sources
- proposed resolutions and their rationale

---

# 1. Archive Identity

## Questions

- What defines "same archive"?
- Should identity depend on:
  - plaintext hash?
  - encrypted payload?
- Can identity survive reencryption?

## Proposed Resolution

**What defines "same archive":** A stable random identifier (`archiveId`), assigned at creation, independent of content, ciphertext, or shard configuration. Two archives with the same `archiveId` are the same logical archive across all lifecycle events.

**Why not content-derived identity:**
- A plaintext-derived `archiveId` leaks equivalence — an observer who sees two manifests can determine whether they protect the same file without accessing the plaintext.
- Content-derived identity also fails for semantically equivalent but bitwise-different content (re-encoded, reformatted, appended metadata).
- A random identifier avoids both problems.

**Survival across reencryption:** Yes. `archiveId` is assigned once and carried forward through all state transitions including reencryption. A state-transition record links the old `stateId` to the new one, preserving the historical chain under the same `archiveId`.

**Key design decision:** The current system conflates two levels of identity — archive/payload identity and shard distribution identity — into a single canonical manifest. These must be separated into an archive descriptor (signature target, carries `archiveId`) and a cohort binding (shard-specific, carries `cohortId`). See `resharing-design.md` Section 2.

## Sources

- ISO 14721 (OAIS) — Archival Information Package identity
- Quantum Vault long-term archive doc — Section 7.3 (archive identity and continuity)
- `resharing-design.md` — Section 1 (identity model)

---

# 2. State Model

## Questions

- What constitutes a state change?
- Should resharing create a new state?
- How to model parent-child relationships?

## Proposed Resolution

**What constitutes a state change:** A change to the archive descriptor. Specifically, any change to `qencHash`, `containerId`, `authPolicyCommitment`, or `cryptoProfileId` produces a new `stateId`. Bundle mutations (attaching signatures, evidence) do NOT change the state. Resharing does NOT change the state under the two-layer architecture — it changes only the cohort binding, which is outside the archive descriptor.

**Should resharing create a new state:** No. This was a critical design insight. With the two-layer manifest separation (archive descriptor + cohort binding), resharing changes only the cohort binding. The archive descriptor and its `stateId` remain stable. Signatures and evidence survive resharing intact.

Under the old (current) unified manifest, resharing would change `manifestDigest` because `shareCommitments[]` and `shardBodyHashes[]` are embedded in the manifest. This contradiction was the primary motivation for the two-layer separation.

**Parent-child relationships:** Modeled as a DAG via `parentStateId`. The initial state has `parentStateId = null`. Each state transition records the predecessor. Multiple successors are possible (branching migration scenarios), but this should be operationally discouraged.

**Event types and their state impact:**

| Event | Changes stateId? | Changes cohortId? |
| --- | --- | --- |
| Create / initial split | N/A (first state) | N/A (first cohort) |
| Sign / attach / timestamp | No | No |
| Reshard (same state) | No | Yes |
| Rewrap | Yes | Yes |
| Reencryption | Yes | Yes |
| Policy change | Yes | Yes |

## Sources

- Content-addressable systems (Git, IPFS) — hash-linked DAG model
- Merkle DAG structures — state chaining
- `resharing-design.md` — Sections 1.3, 3.1

---

# 3. Resharing (Same-State)

## Questions

- When to trigger resharing?
- How to distinguish:
  - shard loss vs attack?
- Should resharing be signed?

## Proposed Resolution

**When to trigger resharing:** When the number of available honest custodians drops below `t + safety_margin`, where `safety_margin = ceil((n - t) / 2)`. For a `(6, 4)` scheme, reshare after losing 2 custodians. For a `(10, 6)` scheme, reshare after losing 3.

The urgency depends on the churn type:
- Benign loss: reshare at convenience, before the margin erodes further.
- Planned rotation: schedule proactively.
- Hostile custodian: reshare immediately. New shares are generated from a fresh random polynomial; old compromised shares cannot reconstruct new shares.

**Distinguishing shard loss vs attack:** The system cannot distinguish these cryptographically — Shamir shares carry no authentication of custodian behavior. The distinction is operational:
- Benign loss: custodian reports loss, no evidence of compromise.
- Suspected attack: custodian is unreachable, detected compromise, or operational security incident.
The response (resharing) is the same in both cases; only the urgency differs.

**Should resharing be signed:** The resharing operation itself should produce a signed state-transition record documenting the event, the old and new `cohortId`, the reason, and the operator. The new cohort binding is committed (hashed) in each new shard and tied to the archive descriptor, but independent signing of the cohort binding is optional — the archive descriptor's existing signatures remain valid.

**Implementation approach:** Reconstruct-and-resplit. The ML-KEM private key is reconstructed from threshold shards, then immediately resplit with fresh Shamir randomness. The exposure window is identical to normal restore; best-effort zeroization applies.

## Sources

- Shamir (1979) — information-theoretic secrecy guarantees
- Practical threshold systems — operational churn patterns
- `resharing-design.md` — Sections 4, 5

---

# 4. Distributed Resharing

## Questions

- Can we avoid full secret reconstruction?
- What trust model is required?
- How to verify correctness?

## Key Concepts

- Proactive Secret Sharing
- Verifiable Secret Sharing (VSS)
- Distributed PSS (DPSS)

## Proposed Resolution

**Can we avoid full secret reconstruction:** Yes, in theory. Proactive Secret Sharing (Herzberg et al., 1995) allows share refresh by adding shares of a zero-polynomial. Each shareholder updates their share locally; the combined effect is a new sharing of the same secret without reconstruction.

**However, PSS is incompatible with Quantum Vault's architecture:**
- PSS requires all (or at least `t`) shareholders to be simultaneously online and participate in an interactive protocol round.
- Quantum Vault is client-only, offline, with no runtime network service. Custodians hold inert shard files, not active protocol participants.
- PQ-secure VSS constructions (needed for share verification in PSS) are not yet NIST-standardized; lattice-based VSS remains a research topic.

**What trust model is required:** PSS requires either a broadcast channel or pairwise secure channels between custodians, plus honest behavior from at least `t` participants during the protocol. DPSS (dynamic committee change) additionally requires `2t+1` honest participants in the old committee.

**How to verify correctness:** Feldman VSS or Pedersen VSS allow shareholders to verify their shares against public commitments. This is a useful enhancement for the initial split even without PSS — it provides stronger share integrity than the current hash-based commitments (which require trusting the dealer).

**Verdict:** Classify distributed resharing as future research (Phase 3 at earliest). The reconstruct-and-resplit approach is operationally sound and compatible with the client-only model. If the system ever adds custodian-to-custodian communication, PSS becomes viable, but that is an architectural paradigm shift.

**Near-term enhancement:** Consider Feldman-style commitments for the initial split as an independently useful improvement to share integrity verification.

## Sources

- Herzberg et al. (1995) — Proactive Secret Sharing
- Feldman (1987) — A practical scheme for non-interactive verifiable secret sharing
- Pedersen (1991) — Non-interactive and information-theoretic secure verifiable secret sharing
- Recent DPSS papers (IACR ePrint)
- MPC literature
- `resharing-design.md` — Section 6

---

# 5. Custodian Churn

## Questions

- How to model participant failure?
- What is acceptable threshold margin?
- How to detect malicious custodian?

## Proposed Resolution

**Participant failure model:** Three types — benign loss, planned rotation, and hostile custodian. Each has different detection characteristics and urgency levels, but the response is always the same: reshare when the safety margin is breached.

**Acceptable threshold margin:**

```
safety_margin = ceil((n - t) / 2)
reshare_trigger: available_honest_custodians < t + safety_margin
```

For `(6, 4)`: margin = 1, trigger at 5 available.
For `(8, 5)`: margin = 2, trigger at 7 available.
For `(10, 6)`: margin = 2, trigger at 8 available.

The formula ensures resharing is triggered before losing reconstruction capability, with enough headroom to tolerate one additional loss during the resharing ceremony itself.

**Detecting malicious custodians:** The system cannot detect malice cryptographically from shard content alone — Shamir shares carry no authentication of custodian behavior. Detection is operational:
- External security monitoring and incident response.
- The system provides no first-class custodian identity objects; custodian tracking is currently external to the format.

**Important safety property:** Shamir secret sharing provides information-theoretic secrecy: fewer than `t` shares from any single cohort reveal zero information about the secret. Cross-cohort share mixing is also safe — each cohort uses an independent random polynomial.

## Sources

- Distributed systems fault models — Byzantine fault tolerance
- `resharing-design.md` — Section 5

---

# 6. Migration & Crypto Agility

## Questions

- When must migration occur?
- How to prove continuity after reencryption?
- What algorithms are acceptable long-term?

## Proposed Resolution

**When to migrate:**
- When a KEM, signature, or hash algorithm is weakened or deprecated by NIST or the cryptographic community.
- When the `cryptoProfileId` is no longer considered adequate for the archive's class and horizon.
- Proactively, before trust anchors weaken — not reactively after compromise.

NIST IR 8547 provides the migration trigger framework for the PQ transition. The current ML-KEM-1024 profile targets security category 5, which provides substantial margin. Future triggers may include HQC standardization (code-based KEM diversity) or advancement in lattice cryptanalysis.

**Proving continuity after reencryption:** The `archiveId` provides the continuity thread. A state-transition record links the old `stateId` (with its historical signatures, evidence, and provenance) to the new `stateId`. The old archive descriptor, its signatures, and its `.ots` evidence are preserved in the transition record as historical provenance. The transition record itself should be signed.

**Continuity without `archiveId`:** Not safely achievable. Without `archiveId`, continuity depends on out-of-band documentation and operator assertion, which is insufficient for machine-verifiable multi-decade provenance.

**Algorithms acceptable long-term:** The system should support algorithm diversity:
- ML-KEM-1024 (current, lattice-based)
- HQC (future, code-based — provides hedging against lattice weakness)
- Hybrid KEM constructions (as a transitional measure)
- SLH-DSA for signature diversity (hash-based, conservative assumption)

**`rewrap` vs reencryption:** `rewrap` requires an envelope-DEK architecture not present in the current format. The current `.qenc` encrypts the payload directly under `Kenc` derived from the ML-KEM shared secret. To support `rewrap`, a two-layer key design is needed:
- Inner layer: DEK → AES-GCM(payload) (stable across rewrap)
- Outer layer: ML-KEM → Kwrap → wrap(DEK) (replaceable)

Until envelope-DEK is implemented, the only cryptographic refresh path is full reencryption.

## Sources

- NIST IR 8547 (PQC transition) — migration triggers and timeline
- FIPS 203 / 204 / 205 — current standardized primitives
- `resharing-design.md` — Sections 8, 9

---

# 7. Cohort Integrity

## Questions

- How to bind shards to a cohort?
- How to detect mixed cohorts?
- Is Merkle structure needed?

## Proposed Resolution

**Binding shards to a cohort:** Each shard carries a `cohortId` in its metadata. The `cohortId` is derived from the cohort binding material:

```
cohortId = hex(SHA3-256(canonicalize({
  shareCommitments, shardBodyHashes, threshold, shareCount,
  reedSolomon: { k, n, parity, codecId }
})))
```

The cohort binding object (separate from the archive descriptor) contains the full shard-specific material. Each shard embeds a digest of this object.

**Detecting mixed cohorts:** Restore validates that all submitted shards share the same `cohortId`. Inconsistent `cohortId` values produce a hard failure — no "largest cohort wins" rule. This is a strengthening of the current behavior (which uses `manifestDigestHex:bundleDigestHex` as an implicit cohort key).

**Is Merkle structure needed:** Not for Phase 1–2. The flat commitment model (`shardBodyHashes[]` and `shareCommitments[]` as arrays) is sufficient at current scale (`n` ≤ 255). Merkle commitments become useful if:
- `n` grows large enough that compact proofs matter
- Custodians need to independently verify shard membership without seeing the full cohort binding
- Third-party audit requires per-shard inclusion proofs

Recommended as Phase 3 optional enhancement.

## Sources

- Reed-Solomon coding — erasure recovery within cohort
- Merkle trees — compact commitment and membership proofs
- `resharing-design.md` — Sections 2.2, 7

---

# 8. Evidence & Time

## Questions

- How to prove existence before Q-Day?
- How to renew trust after crypto break?

## Proposed Resolution

**Proving existence before Q-Day:** Current `.ots` evidence linked to detached signature bytes provides a one-off existence assertion: "this signature existed before witness-observed time T." If the detached signature is a strong PQ signature (ML-DSA or SLH-DSA), and the `.ots` evidence is anchored before Q-Day, the combined provenance chain survives the quantum transition:
- The PQ signature remains cryptographically valid after Q-Day.
- The `.ots` evidence proves the signature existed before Q-Day.
- Classical (Ed25519) signatures lose cryptographic force after Q-Day but retain historical value if timestamped before the transition.

**Renewing trust after crypto break:** RFC 4998 (Evidence Record Syntax) provides the model. The direction is:
- Create evidence record `E0` at initial archival time.
- Before the current hash or signature algorithm weakens, create `E1` committing to `E0` and new witness material under a stronger algorithm.
- Continue chaining: `E2`, `E3`, etc.
- Each renewal must occur while the current algorithms are still trustworthy.

This is not yet implemented. The current `.ots` model provides the foundation (signature → timestamp → witness), but the renewal chain requires:
- A first-class evidence-record schema
- A renewal trigger mechanism
- Support for multiple witness regimes (Bitcoin anchoring, PQ-signed evidence tokens, institutional witnesses)

**Resharing preserves evidence:** Under the two-layer architecture, resharing does not touch the archive descriptor or its detached signatures. Therefore, all evidence (`.ots` proofs targeting those signatures) survives resharing intact. This is a direct benefit of the identity separation.

## Sources

- RFC 3161 (timestamping) — TSA model
- RFC 4998 (evidence records) — renewal chain architecture
- OpenTimestamps — current witness ecosystem
- `resharing-design.md` — Section 10

---

# 9. Threat Model

## Questions

- What if attacker:
  - collects shards over time?
  - tampers subset of shards?
  - compromises custodian?

## Proposed Resolution

**Collecting shards over time:** Shamir secret sharing provides information-theoretic secrecy: fewer than `t` shares from any single cohort reveal zero information about the secret. An adversary collecting shares from different cohorts (pre- and post-resharing) gains no advantage — each cohort uses an independent random polynomial. Cross-cohort shares are not combinable.

However, an adversary who accumulates `t` or more shares from a single cohort can reconstruct the secret. This is mitigated by:
- Timely resharing when custodian compromise is suspected (invalidates old shares)
- Custodian independence (shares stored in genuinely separate environments)
- The safety margin formula (`reshare_trigger: available < t + safety_margin`)

**Tampering with subset of shards:** Detected by share commitments (`SHA3-512` over raw share bytes, verified before reconstruction) and shard body hashes (`SHA3-512` over RS fragment bytes, verified before reassembly). A tampered shard is rejected, reducing the available cohort. If too many shards are tampered, reconstruction fails cleanly rather than producing a wrong result.

With the cohort binding model, `cohortId` consistency provides an additional layer: a shard with a mismatched `cohortId` is rejected before any commitment check.

**Compromising a custodian:** The response is immediate resharing (Section 5.3 of `resharing-design.md`). After resharing, the compromised shares belong to the old cohort and cannot reconstruct the new shares. The adversary's window of opportunity is bounded by the resharing ceremony time.

Residual risk: if the adversary compromises `t` or more custodians before resharing occurs, the secret is compromised regardless. The safety margin and churn monitoring exist to prevent this.

## Sources

- Quantum Vault security model — Section 3 (adversary model)
- HNDL literature
- `resharing-design.md` — Sections 4, 5

---

# Key Insight

Separate clearly:

- archive identity (`archiveId` — permanent, content-independent)
- archive state (`stateId` — changes on rewrap, reencryption, policy change)
- shard cohort (`cohortId` — changes on every resplit)
- lifecycle events (state-transition records linking states)

Without this separation:
- resharing invalidates signatures (currently true — this is the critical bug)
- migration history is unrecoverable
- provenance chains break at every operational event

The two-layer manifest architecture (archive descriptor + cohort binding) resolves this by putting only archive-level identity in the signature target and keeping shard-specific bindings in a separate committed object.
