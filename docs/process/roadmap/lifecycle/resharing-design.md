# Quantum Vault — Resharing & Archive Identity Design

Status: Draft
Type: Informative
Audience: Contributors, implementers, reviewers, cryptographic auditors
Scope: Architectural design for archive identity separation, resharing operations, custodian churn, cohort integrity, and distributed resharing evaluation
Out of scope: Byte-level format definitions, normative policy semantics, UI workflow
Relationship: Feeds into future updates of `format-spec.md`, `long-term-archive.md`, `security-model.md`, `trust-and-policy.md`

---

## Motivation

The current system conflates two distinct levels of identity:

1. **Archive/payload identity** — what the auditor actually approved: a specific encrypted container, its contents, its hash, policy commitment, and provenance.
2. **Shard distribution identity** — the specific `n`, `k`, `t`, cohort, shard indices, share commitments, body hashes, carrier-format details, and embedded bundle state.

These are currently merged into a single canonical manifest. The `shareCommitments[]` and `shardBodyHashes[]` fields sit alongside `qencHash`, `containerId`, and `authPolicyCommitment` in the same signed object. Any resharing operation therefore invalidates all existing detached signatures, because new Shamir shares produce new commitments, which change the canonical manifest bytes, which change `manifestDigest`.

This document proposes separating these two identity levels so that resharing (the most common operational need) does not break archive-level provenance.

Since the project has no active users and no backward-compatibility obligations, this separation can be designed as a clean architectural change rather than a migration path from the current format.

---

## 1. Identity Model

### 1.1 Three-Layer Identity

```
┌─────────────────────────────────────────────────────────┐
│  Archive Identity (archiveId)                           │
│  "This is the same archive."                            │
│  Stable across: resharing, rewrap, reencryption         │
│  Changes: never (for the lifetime of the logical        │
│  archive; a new archiveId means a new archive)          │
├─────────────────────────────────────────────────────────┤
│  Archive State (stateId)                                │
│  "This specific cryptographic + policy state."          │
│  Stable across: attach, re-sign, evidence renewal       │
│  Changes on: resharing, rewrap, reencryption            │
├─────────────────────────────────────────────────────────┤
│  Shard Cohort (cohortId)                                │
│  "This specific set of shards."                         │
│  Stable across: nothing — unique per split/resplit      │
│  Changes on: any resharing or resplitting               │
└─────────────────────────────────────────────────────────┘
```

### 1.2 `archiveId`

**Derivation:**

```
archiveId = hex(SHA3-256(random(32)))
```

A 256-bit random identifier, generated once at initial archive creation. Independent of content, ciphertext, keys, or shard configuration.

**Why not content-derived?** A plaintext-derived identifier leaks equivalence: two archives of the same file would share an `archiveId`, which reveals information about the plaintext to any observer who sees both manifests. A random identifier avoids this.

**Where it appears:**
- Archive descriptor (the new signature target — see Section 2)
- Every `.qcont` shard metadata
- Every state-transition record
- Every manifest bundle

**Invariant:**

```
INV-AID-1: archiveId MUST be assigned at archive creation.
INV-AID-2: archiveId MUST NOT change across resharing, rewrap, reencryption,
           or format migration events.
INV-AID-3: archiveId MUST NOT be derived from plaintext content, ciphertext,
           or key material.
INV-AID-4: A new archiveId means a new archive. Two archives with different
           archiveIds are never the same logical archive.
```

### 1.3 `stateId`

**Derivation:**

```
stateId = archiveDescriptorDigest
        = SHA3-512(canonical bytes of archive descriptor)
```

The `stateId` is the digest of the archive descriptor (Section 2.1). It changes whenever anything in the archive descriptor changes — which by design excludes shard-level bindings.

**What changes `stateId`:**
- `qencHash` changes (rewrap or reencryption)
- `containerId` changes (reencryption)
- `authPolicyCommitment` changes (policy modification)
- `cryptoProfileId` changes (algorithm migration)

**What does NOT change `stateId`:**
- Resharing (new shards, same archive content)
- Attaching signatures to the bundle
- Adding evidence (`.ots`) to the bundle
- Updating embedded bundles in shards

**Invariant:**

```
INV-SID-1: stateId MUST uniquely identify the archive descriptor state.
INV-SID-2: stateId MUST change when qencHash, containerId,
           authPolicyCommitment, or cryptoProfileId changes.
INV-SID-3: stateId MUST NOT change on resharing, bundle attachment,
           or evidence addition alone.
```

### 1.4 `parentStateId`

**Semantics:**

A reference to the predecessor `stateId`. Null (or absent) for the initial state. Forms a DAG (not a chain, since multiple successors are possible in branching migration scenarios).

**Where it appears:**
- Archive descriptor (optional field)
- State-transition records

**Invariant:**

```
INV-PSID-1: Every state after the initial MUST carry a parentStateId
            referencing the predecessor state's stateId.
INV-PSID-2: The (archiveId, stateId) pair MUST be globally unique.
```

### 1.5 `cohortId`

**Derivation:**

```
cohortId = hex(SHA3-256(
  canonicalize({
    shareCommitments: [...],
    shardBodyHashes: [...],
    threshold: t,
    shareCount: n,
    reedSolomon: { k, n, parity, codecId }
  })
))
```

The `cohortId` is derived from the shard binding material. Fresh randomness in Shamir splitting guarantees new share commitments, which guarantees a distinct `cohortId` for every split or resplit operation.

**Where it appears:**
- Cohort binding object (Section 2.2)
- Every `.qcont` shard metadata
- State-transition records for resharing events

**Invariant:**

```
INV-COH-1: cohortId MUST uniquely identify a specific set of shards
           produced by a single split or resharing operation.
INV-COH-2: Every .qcont shard MUST carry its cohortId in shard metadata.
INV-COH-3: Restore MUST reject any shard set where cohortIds are
           inconsistent.
INV-COH-4: A cohortId MUST NOT be reused across resharing events.
```

---

## 2. Two-Layer Manifest Architecture

### 2.1 Archive Descriptor (Signature Target)

The archive descriptor replaces the current canonical manifest as the sole detached-signature payload. It contains only archive-level identity and cryptographic state — no shard-specific bindings.

**Schema:** `quantum-vault-archive-descriptor/v1`

**Fields:**

| Field | Type | Semantics |
| --- | --- | --- |
| `schema` | string | `quantum-vault-archive-descriptor/v1` |
| `version` | integer | Schema version |
| `canonicalization` | string | `QV-C14N-v1` (or future label) |
| `archiveId` | string | Stable archive identity |
| `parentStateId` | string or null | Predecessor stateId; null for initial state |
| `cryptoProfileId` | string | KEM + KDF + AEAD + hash profile |
| `kdfTreeId` | string | KDF derivation tree identifier |
| `noncePolicyId` | string | Nonce contract identifier |
| `nonceMode` | string | Nonce generation mode |
| `counterBits` | integer | Counter width |
| `maxChunkCount` | integer | Maximum chunks under this nonce policy |
| `aadPolicyId` | string | AAD construction identifier |
| `qenc` | object | Encrypted container binding (qencHash, containerId, etc.) |
| `sharding` | object | Threshold/RS parameters (`n`, `k`, `t`, `codecId`) |
| `authPolicyCommitment` | object | Policy commitment hash |
| `manifestType` | string | `archive` |

Detached signatures sign the canonical bytes of this object.

**What is NOT in the archive descriptor:**
- `shareCommitments[]`
- `shardBodyHashes[]`
- `bodyDefinitionId` and `bodyDefinition`
- Any shard-index-specific data

### 2.2 Cohort Binding (Shard-Level Commitment)

The cohort binding is a separate object that binds shard-specific material to the archive descriptor. It is committed (hashed) and carried in each shard, but it is NOT part of the detached-signature target.

**Schema:** `quantum-vault-cohort-binding/v1`

**Fields:**

| Field | Type | Semantics |
| --- | --- | --- |
| `schema` | string | `quantum-vault-cohort-binding/v1` |
| `version` | integer | Schema version |
| `archiveDescriptorDigest` | string | `SHA3-512` over archive descriptor canonical bytes |
| `cohortId` | string | Derived cohort identity |
| `bodyDefinitionId` | string | Shard body definition identifier |
| `bodyDefinition` | object | `includes` / `excludes` specification |
| `shardBodyHashAlg` | string | `SHA3-512` |
| `shardBodyHashes` | string[] | Per-shard body hashes |
| `shareCommitment` | object | Hash algorithm and input specification |
| `shareCommitments` | string[] | Per-share commitment hashes |

**Integrity assurance:** Each shard embeds the cohort binding bytes and a digest. Restore validates that all shards in a set share the same cohort binding digest. The `archiveDescriptorDigest` ties the cohort binding back to the archive descriptor.

**Consequence for resharing:**
- Resharing produces a new cohort binding (new `cohortId`, new commitments)
- The archive descriptor is unchanged
- Existing detached signatures over the archive descriptor remain valid
- Evidence chain (`.ots`) targeting those signatures is preserved
- A state-transition record documents the resharing event

### 2.3 Manifest Bundle (Mutable Evidence Carrier)

The manifest bundle schema is updated to reference the archive descriptor (not the old unified manifest):

| Field | Change |
| --- | --- |
| `manifest` → `archiveDescriptor` | Carries the structured archive descriptor object |
| `manifestDigest` → `archiveDescriptorDigest` | `SHA3-512` over archive descriptor canonical bytes |
| `cohortBinding` | New field: embedded cohort binding object (for the current/initial cohort) |
| `cohortBindingDigest` | `SHA3-512` over cohort binding canonical bytes |
| `transitions[]` | New array: state-transition records |
| Other fields | Unchanged: `authPolicy`, `attachments`, `type`, `version` |

### 2.4 Updated `.qcont` Shard Layout

Each shard carries:
- Archive descriptor bytes + digest (replaces `manifestBytes` + `manifestDigest`)
- Cohort binding bytes + digest (new)
- Bundle bytes + digest (existing)
- Shard metadata including `archiveId`, `cohortId`, `shardIndex`
- Key material, RS fragments, etc. (unchanged)

### 2.5 Binding Chain (Updated)

```
Detached signatures
    └──► sign archive descriptor canonical bytes
              │
              ├──► archiveId (stable identity)
              ├──► qencHash (binds .qenc container)
              ├──► containerId (secondary .qenc identifier)
              ├──► authPolicyCommitment (binds policy)
              └──► sharding parameters (n, k, t, codecId)

Cohort binding
    └──► archiveDescriptorDigest (ties to signed descriptor)
              │
              ├──► cohortId (identifies this shard set)
              ├──► shareCommitments[] (per-share integrity)
              └──► shardBodyHashes[] (per-shard integrity)

OTS evidence
    └──► targets detached signature bytes (unchanged)
              └──► linked via SHA-256(detachedSignatureBytes)

Bundle
    └──► carries archive descriptor + cohort binding + attachments
              └──► mutable; mutations do not affect signatures
```

---

## 3. Preservation Events

### 3.1 Event Taxonomy

Every change to an archive is a preservation event. Each event type has defined behavior regarding which identifiers it changes and which it preserves.

| Event | archiveId | stateId | cohortId | Signatures valid? | Evidence valid? |
| --- | --- | --- | --- | --- | --- |
| Create / initial split | assigned | assigned | assigned | N/A | N/A |
| Sign (detached) | stable | stable | stable | new added | N/A |
| Attach (bundle update) | stable | stable | stable | stable | N/A |
| Timestamp (`.ots`) | stable | stable | stable | stable | new added |
| Renew evidence | stable | stable | stable | stable | new added |
| Re-sign | stable | stable | stable | new added | old still valid |
| **Reshard (same state)** | **stable** | **stable** | **new** | **stable** | **stable** |
| Rewrap | stable | **new** | **new** | **invalidated** | **invalidated** |
| Reencryption | stable | **new** | **new** | **invalidated** | **invalidated** |
| Custody transfer | stable | stable | stable | stable | stable |

The critical row is **Reshard (same state)**: with the two-layer architecture, resharding preserves `stateId` because the archive descriptor is unchanged. Signatures and evidence survive. Only the cohort binding changes.

### 3.2 State-Transition Record Schema

```json
{
  "schema": "quantum-vault-state-transition/v1",
  "type": "reshareSameState | rewrap | reencryption | policyChange",
  "archiveId": "...",
  "parentStateId": "...",
  "newStateId": "... (same as parentStateId for reshareSameState)",
  "parentCohortId": "...",
  "newCohortId": "...",
  "timestamp": "ISO-8601",
  "reason": "custodian-rotation | threshold-margin | crypto-agility | policy-update",
  "operator": "optional operator identifier",
  "signatures": []
}
```

For `reshareSameState`, `parentStateId == newStateId` because the archive descriptor did not change.

For `rewrap` or `reencryption`, `newStateId` is derived from the new archive descriptor.

---

## 4. Resharing Design

### 4.1 Same-State Resharing (Reconstruct + Resplit)

**Precondition:** A threshold of consistent shards from the current cohort is available.

**Ceremony:**

1. **Gather shards.** Collect at least `t` shards from the current cohort (validated by `cohortId`).
2. **Reconstruct.** Rebuild the ML-KEM private key from Shamir shares. Verify against share commitments.
3. **Choose new parameters.** Select new `n'`, `k'`, `t'` (may differ from original).
4. **Resplit.** Generate new Shamir shares with fresh randomness. Compute new RS fragments from the same `.qenc` ciphertext (unchanged).
5. **Build new cohort binding.** New `shareCommitments[]`, `shardBodyHashes[]`, `cohortId`.
6. **Build new shards.** Embed the same archive descriptor, the new cohort binding, and an updated bundle.
7. **Record transition.** Create a state-transition record linking old `cohortId` to new `cohortId`.
8. **Zeroize.** Wipe private key material from memory immediately after resplitting.
9. **Destroy old shards.** Instruct custodians to destroy all shards from the old cohort.

**Implementation path:** New function in `src/core/crypto/qcont/`:

```
reshareSameState(shards[], newN, newK, options) → {
  newShards[],
  archiveDescriptor,     // unchanged
  newCohortBinding,
  newBundle,
  transitionRecord
}
```

### 4.2 Resharing Invariants

```
INV-RSH-1: Same-state resharing MUST NOT alter the archive descriptor.
           archiveId, stateId, qencHash, containerId, authPolicyCommitment
           MUST remain identical.

INV-RSH-2: Same-state resharing MUST produce:
           - new Shamir shares (fresh randomness)
           - new share commitments
           - new shard body hashes (if RS fragments change due to new n/k)
           - a new cohortId
           - a new cohort binding object

INV-RSH-3: Existing detached signatures over the archive descriptor MUST
           remain valid after same-state resharing.

INV-RSH-4: Same-state resharing MUST produce a state-transition record.

INV-RSH-5: After resharing, all shards from the predecessor cohort
           SHOULD be destroyed by custodians. The system MUST NOT rely
           on destruction happening (defense in depth): old shares
           reconstruct the same secret, so compromise of enough old
           shares remains a confidentiality risk.

INV-RSH-6: The ML-KEM private key MUST exist in memory only for the
           minimum duration required for reconstruction + resplitting.
           Zeroization MUST be attempted immediately after resplitting
           completes.
```

### 4.3 Secret-In-Memory Risk Assessment

Resharing requires the ML-KEM private key to be reconstructed in memory. This is the same exposure surface as the existing restore-and-decrypt flow.

| Factor | Assessment |
| --- | --- |
| Exposure surface | Identical to normal restore |
| Duration | Short: reconstruct + resplit, then wipe |
| Mitigation | Best-effort zeroization, session wipe on unload |
| Residual risk | JS runtime memory remanence (already acknowledged in security-model.md §9.1) |
| Alternative (PSS) | Would eliminate reconstruction, but requires interactive MPC (see Section 6) |

The risk is proportional to the ceremony duration. Recommended operational practice: perform resharing on an offline or air-gapped machine when possible, complete the operation quickly, close the session.

---

## 5. Custodian Churn Model

### 5.1 Churn Types

| Type | Description | Detection | Response |
| --- | --- | --- | --- |
| Benign loss | Custodian loses shard, device failure, becomes unreachable | Custodian reports loss or stops responding | Reshare when available honest custodians approach the safety margin |
| Planned rotation | Custodian voluntarily leaves, organizational handoff | Advance notice from custodian | Schedule resharing at a convenient time; batch with other maintenance |
| Hostile custodian | Custodian is compromised, coerced, or acts maliciously | Suspected compromise, security incident | Immediate resharing to invalidate the compromised shares |

### 5.2 Safety Margin

**Definitions:**
- `n` = total shards
- `t` = Shamir threshold (minimum for reconstruction)
- `available` = number of shards held by honest, reachable custodians
- `lost` = shards destroyed, unavailable, or held by unreachable custodians
- `compromised` = shards known or suspected to be in adversary hands

**Formula:**

```
safety_margin = ceil((n - t) / 2)
reshare_trigger: available < t + safety_margin
```

**Examples:**

| Configuration | n | t | safety_margin | Trigger |
| --- | --- | --- | --- | --- |
| (6, 4) | 6 | 4 | 1 | available < 5 → reshare after losing 2 |
| (8, 5) | 8 | 5 | 2 | available < 7 → reshare after losing 2 |
| (10, 6) | 10 | 6 | 2 | available < 8 → reshare after losing 3 |

### 5.3 Hostile Custodian Response

When a custodian is suspected compromised:

1. **Immediate resharing.** Reconstruct from honest shards and resplit to a new cohort. The compromised shares become useless for reconstructing the new shares (new Shamir polynomial, independent of old shares).
2. **Exclusion.** Do not assign new shards to the compromised party.
3. **Record.** Create a state-transition record documenting the reason (`hostile-custodian-compromise`).

**Important:** Shamir secret sharing provides information-theoretic secrecy. Fewer than `t` shares reveal no information about the secret. Therefore, compromise of up to `t-1` shares from any single cohort does not leak the ML-KEM private key. However, an adversary who collects shares across multiple cohorts (old and new) cannot combine them — each cohort uses an independent random polynomial.

### 5.4 Threshold Selection Guidance

| Archive class | Recommended `n` | Recommended `t` | Rationale |
| --- | --- | --- | --- |
| backup | 5–6 | 3–4 | Moderate redundancy, personal custody |
| audited-archive | 6–8 | 4–5 | Higher redundancy, organizational custody |
| long-term-archive | 8–12 | 5–7 | Maximum redundancy, institutional custody, multi-decade horizon |

---

## 6. Distributed Resharing Evaluation

### 6.1 Proactive Secret Sharing (PSS)

Herzberg et al. (1995) define proactive secret sharing: shareholders can refresh their shares without reconstructing the secret. Each shareholder adds a share of a zero-polynomial (random polynomial with zero constant term) to their current share. After refresh, old shares are incompatible with new shares.

**Requirements:**
- All (or at least `t`) shareholders must be simultaneously online
- Pairwise secure channels or a broadcast channel between shareholders
- A commitment scheme for verifying share updates (Feldman or Pedersen VSS)
- Synchronous rounds — partial participation produces inconsistent state

### 6.2 Verifiable Secret Sharing (VSS)

Feldman VSS / Pedersen VSS allow shareholders to verify their shares are consistent with a committed polynomial, without revealing the secret. Relevant for initial split (adds verifiability beyond the current hash-based commitments). Not a resharing mechanism by itself, but a building block for PSS.

### 6.3 Dynamic Proactive Secret Sharing (DPSS)

DPSS combines PSS with committee change: transfer shares from an old committee to a new committee without reconstructing the secret. Requires `2t+1` honest participants in the old committee, simultaneous online presence, secure channels.

### 6.4 Feasibility Assessment

| Criterion | PSS / DPSS | Reconstruct + resplit |
| --- | --- | --- |
| Secret exposure | No reconstruction | Brief in-memory exposure |
| Online requirement | All/most custodians simultaneously | Only threshold set + resharing operator |
| Protocol complexity | Multi-round interactive MPC | Single-party operation |
| PQ-secure construction | Research-stage (no NIST-standardized lattice-based VSS) | Uses existing Shamir over GF(2^8) |
| Client-only compatibility | Incompatible (requires custodian-to-custodian communication) | Compatible |
| Auditability | Complex (distributed protocol transcripts) | Simple (single ceremony) |

### 6.5 Recommendation

Classify distributed resharing as **future research** (Phase 3 at earliest). The current reconstruct-and-resplit approach is operationally sound for the near and medium term.

**If the system ever adds a custodian-coordination protocol** (moving away from pure client-only), PSS becomes viable — but that is an architectural paradigm shift (introduction of interactive multi-party computation), not an incremental feature.

**Near-term alternative for share integrity:** Adopt Feldman-style commitments for the initial split (public verification that shares are consistent with a committed polynomial). This improves initial split integrity without requiring interactive protocols. It can be implemented as an optional enhancement to the current Shamir splitting code.

---

## 7. Cohort-Level Integrity

### 7.1 Flat Commitments (Current Direction)

The current approach embeds per-shard hashes and per-share commitments as flat arrays in the cohort binding object. Restore validates each shard against its entry.

**Sufficient for:** current scale (`n` ≤ 255).

### 7.2 Merkle-Based Commitments (Optional Enhancement)

Replace flat arrays with a Merkle tree:

```
cohortMerkleRoot = MerkleRoot(
  leaf[0] = SHA3-256(shardBodyHash[0] || shareCommitment[0]),
  leaf[1] = SHA3-256(shardBodyHash[1] || shareCommitment[1]),
  ...
  leaf[n-1] = SHA3-256(shardBodyHash[n-1] || shareCommitment[n-1])
)
```

**Benefits:**
- Compact commitment: single root hash instead of `n` hashes
- Membership proofs: a shard proves cohort membership with `O(log n)` sibling hashes
- Independent verification: a custodian can verify their shard belongs to a cohort without seeing all other shards

**Tradeoff:** Adds implementation complexity. At `n` ≤ 255, the space savings are modest. Merkle proofs are most useful if custodians need to independently verify membership without the full cohort binding.

**Recommendation:** Implement as a Phase 3 optional enhancement. The flat commitment model is sufficient for Phase 1–2.

---

## 8. `rewrap` Architecture Prerequisite

The current `.qenc` format encrypts the payload directly with `Kenc` derived from the ML-KEM shared secret. There is no intermediate wrapping key. This means `rewrap` as defined in `long-term-archive.md` ("changing key-wrapping or confidentiality envelope without re-encrypting content") is not implementable under the current key architecture.

**Required change for `rewrap`:**

Introduce an envelope-DEK (Data Encryption Key) design:

```
Current:
  ML-KEM → shared secret → KMAC → Kenc → AES-GCM(payload)

Proposed:
  DEK (random symmetric key) → AES-GCM(payload)     [inner layer, stable]
  ML-KEM → shared secret → KMAC → Kwrap → wrap(DEK)  [outer layer, replaceable]
```

With this design, `rewrap` replaces only the outer layer (new ML-KEM keypair, new shared secret, new `Kwrap`) while the inner ciphertext (encrypted under `DEK`) remains unchanged.

**Impact on identity model:**
- The inner ciphertext would have its own fixity anchor (e.g., `innerCiphertextHash`)
- `qencHash` would change on rewrap (outer envelope changes)
- A new anchor (`payloadCiphertextHash` or similar) would remain stable across rewrap
- `archiveId` survives both rewrap and reencryption by design (INV-AID-2)
- `stateId` changes on rewrap (archive descriptor changes because `qencHash` changes)

**Recommendation:** Implement envelope-DEK as a prerequisite for the `rewrap` milestone. Until then, the only cryptographic refresh path is full reencryption.

---

## 9. HNDL Implications for Resharing and Migration

Harvest-now-decrypt-later creates an asymmetric urgency:

- **Resharing** does not affect HNDL exposure. The ciphertext is unchanged; an adversary who already captured ciphertext gains nothing from a resharing event. Resharing addresses custodian-level risk, not cryptanalytic risk.

- **Reencryption** directly addresses HNDL. If the current KEM or symmetric profile is weakened, reencryption under a stronger profile protects the payload going forward. However, previously captured ciphertexts remain vulnerable — reencryption only protects future captures.

- **Rewrap** (with envelope-DEK) provides a middle path. If only the outer KEM is weakened, rewrapping under a new KEM protects the DEK without touching the inner ciphertext. The inner ciphertext remains encrypted under the original symmetric key (AES-256-GCM), which retains strong post-quantum margins under Grover.

**Decision framework:**

| Threat | Response | Identity impact |
| --- | --- | --- |
| Custodian compromise | Reshard immediately | archiveId stable, stateId stable, cohortId new |
| KEM weakening (future) | Rewrap (if envelope-DEK exists) or reencrypt | archiveId stable, stateId new |
| Symmetric weakening (unlikely) | Full reencryption under new profile | archiveId stable, stateId new |
| Hash weakening (SHA3-512) | Append successor fixity material | archiveId stable, stateId new |

---

## 10. Evidence and Provenance Durability

### 10.1 Resharing Preserves Evidence

With the two-layer architecture:
- Detached signatures target the archive descriptor, not the cohort binding
- `.ots` evidence targets detached signature bytes
- Resharing does not touch the archive descriptor or its signatures
- Therefore, the full evidence chain (signatures + timestamps) survives resharing intact

### 10.2 Migration Requires Evidence Renewal

Rewrap and reencryption produce a new archive descriptor (new `stateId`), which invalidates existing detached signatures. After a migration event:

1. New signatures must be produced over the new archive descriptor
2. New `.ots` evidence should be created for the new signatures
3. The old archive descriptor, its signatures, and their evidence should be preserved in the state-transition record as historical provenance
4. The transition record itself should be signed to create a witnessable chain

### 10.3 Cross-Decade Continuity

For 50+ year archives, the continuity chain is:

```
archiveId (permanent)
  └── stateId_0 (initial)
        ├── signatures_0 + evidence_0
        └── transition → stateId_1 (post-migration)
              ├── signatures_1 + evidence_1
              ├── predecessor: stateId_0 + historical evidence
              └── transition → stateId_2 (second migration)
                    └── ...
```

Each state carries its own provenance. The `archiveId` thread ties all states together. Historical signatures and evidence are preserved as records, even after they lose cryptographic force (e.g., after a quantum transition invalidates classical signatures).

---

## 11. Open Questions

1. **Should `archiveId` be exposed in plaintext metadata?** It is not derived from content, so it does not leak plaintext information. But it does allow linking two shard sets as belonging to the same archive. If unlinkability between cohorts is desired, `archiveId` could be encrypted or committed rather than stored in the clear.

2. **Should cohort binding be independently signed?** The current design commits the cohort binding via a digest in each shard and ties it to the archive descriptor via `archiveDescriptorDigest`. An adversary who substitutes a cohort binding would need to produce valid share commitments for fabricated shares. Independent signing of the cohort binding would add tamper evidence but is not strictly necessary if shard-level integrity checks are sufficient.

3. **Should the threshold parameters (`n`, `k`, `t`) stay in the archive descriptor or move entirely to the cohort binding?** Currently proposed: keep them in the archive descriptor (they describe the sharding policy, not the specific shard set). But different cohorts could have different `n`/`k`/`t` if resharing changes the configuration. If that flexibility is desired, threshold parameters should move to the cohort binding, and the archive descriptor would only carry a `shardingPolicy` reference.

4. **How to handle branching?** If an archive is reshared independently by two different operators (perhaps from different custodian subsets), two valid cohorts exist for the same state. Is this acceptable? Should the system prevent or detect it? The DAG model (via `parentStateId`) allows it, but operational guidance may want to discourage it.
