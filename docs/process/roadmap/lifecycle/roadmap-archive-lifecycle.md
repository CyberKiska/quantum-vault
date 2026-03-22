# Quantum Vault — Archive Lifecycle Roadmap

Status: Draft
Type: Informative
Audience: Contributors, implementers, reviewers
Scope: Phased evolution toward a full long-term archival system with stable identity, lifecycle state transitions, resharing, and migration
Relationship: Design rationale in `resharing-design.md`; resolved questions in `implementation-questions-and-reading.md`

## Scope

This roadmap covers the evolution of Quantum Vault toward a full long-term archival system with:

- stable archive identity separated from shard identity
- two-layer manifest architecture (archive descriptor + cohort binding)
- lifecycle state transitions with signed records
- shard cohort management and resharing
- migration and crypto agility (rewrap, reencryption)
- custodian churn handling
- cohort-level integrity
- distributed resharing evaluation (future)

## Architectural Prerequisite: Identity Separation

The current system merges archive-level identity and shard-level identity into a single canonical manifest. This means `shareCommitments[]` and `shardBodyHashes[]` sit alongside `qencHash` and `authPolicyCommitment` in the same signed object. Any resharing changes `manifestDigest` and invalidates all existing detached signatures.

**Resolution:** Split the canonical manifest into two objects:

1. **Archive descriptor** — the new detached-signature target. Contains only archive-level identity: `archiveId`, `qencHash`, `containerId`, `authPolicyCommitment`, `cryptoProfileId`, sharding parameters (`n`, `k`, `t`), and nonce/AEAD policy. Does NOT contain shard-specific bindings.

2. **Cohort binding** — a separate committed object. Contains `cohortId`, `shareCommitments[]`, `shardBodyHashes[]`, `bodyDefinitionId`. Tied to the archive descriptor via `archiveDescriptorDigest`. Committed (hashed) in each shard.

This separation allows resharing without invalidating signatures or evidence.

Since there are no active users and no backward-compatibility obligations, this can be implemented as a clean format change rather than a migration path.

See `resharing-design.md` for the full architectural design.

---

# 1. Archive Identity Layer

## Goal
Introduce stable archive identity independent of encryption, shards, or format changes.

## Invariants

```
INV-AID-1: archiveId MUST be assigned at archive creation.
INV-AID-2: archiveId MUST NOT change across resharing, rewrap, reencryption,
           or format migration events.
INV-AID-3: archiveId MUST NOT be derived from plaintext content, ciphertext,
           or key material. Use random 256-bit identifier.
INV-AID-4: A new archiveId means a new archive.
```

## Derivation Rules

- `archiveId = hex(SHA3-256(random(32)))` — generated once at initial creation.
- `stateId = archiveDescriptorDigest = SHA3-512(canonical archive descriptor bytes)` — deterministic from archive descriptor content.
- `parentStateId` = predecessor `stateId`, or null for initial state.

## Deliverables

### Phase 1
- Introduce `archiveId` as a required field in the archive descriptor
- Introduce `stateId` as a derived identifier (= archive descriptor digest)
- Define canonical derivation rules (documented above)
- Add `archiveId` to `.qcont` shard metadata
- Implement archive descriptor schema (`quantum-vault-archive-descriptor/v1`)

### Phase 2
- Add `parentStateId` to archive descriptor (optional; null for initial state)
- Define state-transition DAG model
- Implement state-transition record schema (`quantum-vault-state-transition/v1`)

### Phase 3
- Verify `archiveId` persistence across all lifecycle events (resharing, rewrap, reencryption)
- Implement validation rules for state continuity (verify `parentStateId` chain)

---

# 2. Two-Layer Manifest Architecture

## Goal
Separate archive-level identity (signature target) from shard-level identity (cohort binding).

## Design

**Archive descriptor** (`quantum-vault-archive-descriptor/v1`):
- Signature target — detached signatures sign its canonical bytes
- Contains: `archiveId`, `parentStateId`, `cryptoProfileId`, `kdfTreeId`, nonce policy fields, `aadPolicyId`, `qenc` binding (`qencHash`, `containerId`), `sharding` parameters, `authPolicyCommitment`
- Does NOT contain: `shareCommitments[]`, `shardBodyHashes[]`, `bodyDefinitionId`

**Cohort binding** (`quantum-vault-cohort-binding/v1`):
- Committed in each shard via digest
- Contains: `archiveDescriptorDigest`, `cohortId`, `bodyDefinitionId`, `bodyDefinition`, `shardBodyHashes[]`, `shareCommitments[]`
- Tied to archive descriptor via `archiveDescriptorDigest`

**Updated manifest bundle:**
- Carries `archiveDescriptor` (replaces `manifest`)
- Carries `archiveDescriptorDigest` (replaces `manifestDigest`)
- New field: `cohortBinding` and `cohortBindingDigest`
- New field: `transitions[]` for state-transition records

## Deliverables

### Phase 1
- Implement archive descriptor schema and canonicalization
- Implement cohort binding schema and derivation
- Update `.qcont` shard layout: embed archive descriptor + cohort binding (replaces unified manifest)
- Update manifest bundle schema to reference archive descriptor

### Phase 2
- Update detached-signature tooling to sign archive descriptor bytes (not unified manifest)
- Update restore logic to validate archive descriptor + cohort binding separately
- Update attach workflow to operate on the new bundle schema

### Phase 3
- Update all normative docs (`format-spec.md`, `trust-and-policy.md`, `security-model.md`, `long-term-archive.md`)
- Update `WHITEPAPER.md` binding chain description

---

# 3. State Transition Model

## Goal
Formalize all changes as explicit state transitions with signed records.

## Event Taxonomy

| Event | Changes stateId? | Changes cohortId? | Signatures survive? |
| --- | --- | --- | --- |
| Create / initial split | N/A | N/A | N/A |
| Sign / attach / timestamp | No | No | Yes (new added) |
| Reshard (same state) | **No** | **Yes** | **Yes** |
| Rewrap | Yes | Yes | No (re-sign required) |
| Reencryption | Yes | Yes | No (re-sign required) |
| Policy change | Yes | Yes | No (re-sign required) |

## Transition Record Schema

```json
{
  "schema": "quantum-vault-state-transition/v1",
  "type": "reshareSameState | rewrap | reencryption | policyChange",
  "archiveId": "...",
  "parentStateId": "...",
  "newStateId": "...",
  "parentCohortId": "...",
  "newCohortId": "...",
  "timestamp": "ISO-8601",
  "reason": "custodian-rotation | threshold-margin | crypto-agility | policy-update",
  "operator": "optional operator identifier",
  "signatures": []
}
```

For `reshareSameState`: `parentStateId == newStateId` (archive descriptor unchanged).

## Deliverables

### Phase 1
- Define state-transition types (above table)
- Implement transition record schema

### Phase 2
- Add `transitions[]` array to manifest bundle
- Require at least one signature on transition records

### Phase 3
- Implement verification rules for state continuity (validate `parentStateId` chain)
- Detect and warn on branching (two independent reshares from same state)

---

# 4. Resharing (Same-State)

## Goal
Support frequent operational shard redistribution without changing archive state or invalidating signatures.

## Critical Property
With the two-layer architecture, resharing produces a new cohort binding but does NOT change the archive descriptor. Detached signatures and `.ots` evidence survive intact.

## Invariants

```
INV-RSH-1: Same-state resharing MUST NOT alter the archive descriptor.
INV-RSH-2: Same-state resharing MUST produce new Shamir shares (fresh
           randomness), new commitments, new cohortId, new cohort binding.
INV-RSH-3: Existing detached signatures MUST remain valid after resharing.
INV-RSH-4: A signed state-transition record MUST be produced.
INV-RSH-5: Old cohort shards SHOULD be destroyed; the system MUST NOT
           rely on destruction happening.
INV-RSH-6: ML-KEM private key MUST exist in memory only for the minimum
           duration of reconstruct + resplit. Zeroize immediately after.
```

## Resharing Ceremony

1. Gather at least `t` shards from current cohort (validated by `cohortId`)
2. Reconstruct ML-KEM private key from Shamir shares
3. Choose new parameters (`n'`, `k'`, `t'` — may differ from original)
4. Resplit with fresh Shamir randomness; recompute RS fragments if `n`/`k` changed
5. Build new cohort binding (new commitments, new `cohortId`)
6. Build new shards (same archive descriptor, new cohort binding)
7. Create state-transition record
8. Zeroize private key material
9. Instruct custodians to destroy old-cohort shards

## Deliverables

### Phase 1
- Define `cohortId` derivation: `SHA3-256(canonicalize({shareCommitments, shardBodyHashes, threshold, shareCount, reedSolomon}))`
- Add `cohortId` to `.qcont` shard metadata and cohort binding
- Implement `reshareSameState()` in `src/core/crypto/qcont/`

### Phase 2
- Implement cohort consistency validation (reject mixed `cohortId` sets)
- Implement state-transition record generation

### Phase 3
- Add proactive resharing trigger alerts (based on safety margin formula)
- Integrate safety-margin monitoring into restore/status reporting

---

# 5. Custodian Churn Model

## Goal
Handle real-world participant changes safely with defined triggers and response procedures.

## Churn Types and Response

| Type | Detection | Response | Urgency |
| --- | --- | --- | --- |
| Benign loss | Custodian reports loss or becomes unreachable | Reshare before margin erodes further | Medium |
| Planned rotation | Advance notice from custodian | Schedule resharing at convenience | Low |
| Hostile custodian | Suspected compromise or security incident | Immediate resharing; exclude compromised party | Critical |

## Safety Margin

```
safety_margin = ceil((n - t) / 2)
reshare_trigger: available_honest_custodians < t + safety_margin
```

| Configuration | safety_margin | Trigger |
| --- | --- | --- |
| (6, 4) | 1 | available < 5 |
| (8, 5) | 2 | available < 7 |
| (10, 6) | 2 | available < 8 |

## Security Property

Shamir provides information-theoretic secrecy: fewer than `t` shares from any single cohort reveal zero information about the secret. Cross-cohort share mixing is also safe — each cohort uses an independent random polynomial.

## Deliverables

### Phase 1
- Define churn types, detection criteria, and response procedures (above)
- Define safety margin formula and resharing triggers
- Document threshold selection guidance per archive class

### Phase 2
- Add quorum health monitoring to shard restore status reporting
- Add custodian replacement event to state-transition records

### Phase 3
- Introduce governance layer for resharing authorization
- Add accountability tracking (who authorized resharing, who participated)

---

# 6. Migration / Rewrap / Reencryption

## Goal
Enable cryptographic evolution without breaking archive continuity.

## Migration Types and Identity Impact

| Event | archiveId | stateId | cohortId | Requires re-signing |
| --- | --- | --- | --- | --- |
| Rewrap | stable | **new** | **new** | Yes |
| Reencryption | stable | **new** | **new** | Yes |
| Policy change | stable | **new** | **new** | Yes |

## Architectural Prerequisite: Envelope-DEK

`rewrap` requires a two-layer key architecture not present in the current format:

```
Current:  ML-KEM → shared secret → KMAC → Kenc → AES-GCM(payload)
Required: DEK (random) → AES-GCM(payload)     [inner, stable across rewrap]
          ML-KEM → shared secret → KMAC → Kwrap → wrap(DEK)  [outer, replaceable]
```

Until envelope-DEK is implemented, the only cryptographic refresh path is full reencryption.

## Deliverables

### Phase 1
- Define rewrap vs reencryption semantics with identity impact (above table)
- Design envelope-DEK key architecture
- Add migration event to state-transition record schema

### Phase 2
- Implement envelope-DEK key architecture
- Implement rewrap flow (replace outer KEM layer, preserve inner ciphertext)
- Implement reencryption flow (new payload encryption, new archive descriptor, same `archiveId`)

### Phase 3
- Introduce crypto policy profiles (algorithm acceptability for each archive class)
- Implement migration validation rules (verify `parentStateId` chain, verify `archiveId` continuity)

---

# 7. Cohort-Level Integrity

## Goal
Ensure shard sets are internally consistent and tamper-detectable.

## Invariants

```
INV-COH-1: cohortId MUST uniquely identify a specific shard set from one
           split/resplit operation.
INV-COH-2: Every .qcont shard MUST carry its cohortId.
INV-COH-3: Restore MUST reject inconsistent cohortId sets.
INV-COH-4: cohortId MUST NOT be reused across resharing events
           (guaranteed by fresh Shamir randomness → new commitments).
```

## Deliverables

### Phase 1
- Add `cohortId` to shard metadata and cohort binding object
- Add `cohortCommitment` (= `SHA3-256` over canonical cohort binding bytes)

### Phase 2
- Implement cross-shard `cohortId` validation in restore
- Implement deterministic cohort selection based on `cohortId` (replaces current `manifestDigestHex:bundleDigestHex` composite key)

### Phase 3
- Optional: Merkle-based commitments for large-`n` scenarios
  - Compact root hash instead of `n` individual hashes
  - Per-shard membership proofs (`O(log n)`)
  - Useful if custodians need independent membership verification

---

# 8. Distributed Resharing (Future)

## Goal
Evaluate and potentially enable resharing without reconstructing the secret.

## Assessment

| Criterion | PSS / DPSS | Reconstruct + resplit |
| --- | --- | --- |
| Secret exposure | No reconstruction | Brief in-memory exposure |
| Online requirement | All/most custodians simultaneously | Threshold set + operator |
| Protocol complexity | Multi-round interactive MPC | Single-party operation |
| PQ-secure construction | Research-stage | Uses existing Shamir |
| Client-only compatibility | Incompatible | Compatible |

**Verdict:** Classify as future research. The reconstruct-and-resplit approach is sound for the near and medium term. PSS requires interactive custodian communication, which is a paradigm shift from the current offline model.

## Deliverables

### Phase 1 (Research)
- Evaluate Shamir refresh schemes (Herzberg et al., 1995)
- Evaluate VSS / PVSS for initial-split integrity enhancement
- Assess PQ-secure VSS constructions (lattice-based, research-stage)

### Phase 2 (Near-term enhancement)
- Implement Feldman-style commitments for initial split (independently useful, no MPC required)

### Phase 3 (Future prototype)
- Prototype share refresh protocol (requires custodian communication channel)
- Evaluate dynamic committee support (DPSS)

---

# 9. Evidence & Continuity

## Goal
Preserve long-term verifiability across resharing and migration events.

## Key Property

With the two-layer architecture, resharing preserves the full evidence chain:
- Detached signatures target the archive descriptor (unchanged by resharing)
- `.ots` evidence targets detached signature bytes (unchanged by resharing)
- Evidence survives resharing intact

Migration (rewrap, reencryption) requires evidence renewal:
- New signatures over new archive descriptor
- New `.ots` evidence for new signatures
- Old evidence preserved as historical provenance in transition records

## Deliverables

### Phase 1
- Link state-transition records to existing signature set
- Preserve predecessor evidence in transition records

### Phase 2
- Add timestamp chaining for migration events
- Support multi-witness evidence anchoring

### Phase 3
- Introduce renewable evidence chains (RFC 4998 direction)
- Evidence renewal trigger mechanism (renew before trust anchors weaken)

---

# Summary

## Priority order

1. Two-layer manifest architecture (archive descriptor + cohort binding) — architectural prerequisite
2. `archiveId` + `stateId` + `parentStateId` — identity primitives
3. `cohortId` + cohort binding — shard-level identity
4. `reshareSameState` + resharing ceremony — primary operational capability
5. State-transition records + event model — lifecycle tracking
6. Custodian churn model + safety margins — operational safety
7. Migration support (envelope-DEK + rewrap) — crypto agility
8. Distributed resharing (PSS/DPSS) — future research

## Dependency graph

```
[Two-layer manifest] ──► [archiveId + stateId] ──► [resharing]
                     │                          │
                     └──► [cohortId]      ──────┘
                                                │
                                    [transition records]
                                                │
                                    [custodian churn model]
                                                │
                                    [migration / rewrap]
                                                │
                                    [distributed resharing (future)]
```
