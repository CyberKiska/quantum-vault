# Long-term archive

Status: Release Candidate
Type: Mixed
Audience: archivists, long-term custodians, policy designers, implementers of renewal or migration tooling, auditors
Scope: current archival posture, archive classes, evidence and renewal baseline, OAIS mapping, migration semantics, and archive-identity roadmap
Out of scope: byte-level format details, detailed threat model, UI workflow explanation, claims of institutional compliance
Primary sources: [`security-model.md`](security-model.md), [`trust-and-policy.md`](trust-and-policy.md), [`format-spec.md`](format-spec.md), [`README.md`](../README.md), [`WHITEPAPER.md`](WHITEPAPER.md)

## Role

This document is the archival counterpart to the current security, format, and policy docs.
It explains how Quantum Vault should be evaluated when the archive must remain meaningful across years or decades.

Division of labor:

- [`format-spec.md`](format-spec.md) defines current artifact structure and verifier behavior
- [`trust-and-policy.md`](trust-and-policy.md) defines current signature, pinning, and archive-policy semantics
- [`security-model.md`](security-model.md) defines current boundaries, assumptions, and invariants
- `long-term-archive.md` defines archive classes, long-horizon evidence expectations, OAIS mapping, migration semantics, and the current roadmap gaps

This file is mixed by design:

- normative for archive-class terminology and requirement labels used in this documentation set
- informative for OAIS mapping and future evidence-renewal architecture until those designs become first-class format or policy objects

## Scope

This document covers current archival posture, archive classes, evidence and renewal baseline, OAIS mapping, migration semantics, and archive-identity direction for Quantum Vault.
It does not define byte-level format details, detailed threat modeling, UI workflow behavior, or claims of institutional compliance.

## Normative status

This document is mixed by design.
It is normative for the archive-class terminology and requirement labels explicitly defined as current in this file, and informative for OAIS mapping, evidence-renewal direction, and broader archival roadmap material that is not yet first-class in the implementation.

Conformance and interpretation:

- this document is normative only for the archive-class terminology and requirement labels explicitly defined as current in this file
- informative OAIS mapping, evidence-renewal direction, and roadmap material do not become current requirements unless they are promoted into the current sections of this document
- if a current implementation or published owner document diverges from the current normative terminology or requirement labels here, the divergence MUST be documented explicitly and treated as non-conformant to this version
- in case of ambiguity, this document MUST be interpreted conservatively and MUST NOT be read as promoting roadmap text into present-day guarantees

## Sources and references

Internal current-state grounding:

- [`security-model.md`](security-model.md), [`trust-and-policy.md`](trust-and-policy.md), [`format-spec.md`](format-spec.md), [`glossary.md`](glossary.md), and [`README.md`](../README.md) for current implemented boundaries, terms, and artifact semantics
- `src/core/crypto/qcont/restore.js`, `src/core/crypto/qcont/lifecycle-shard.js`, `src/core/crypto/lifecycle/artifacts.js`, and `src/core/crypto/auth/opentimestamps.js` for current evidence, restore, lifecycle, and archive-binding capabilities actually present in the repo

External references already used elsewhere in the repository:

- OAIS / ISO 14721:2025 for archival concepts such as representation information and preservation description information
- ISO 16363 for trustworthy digital repository audit context (note: ISO 16363 defines audit criteria for repositories, not a conformance target for standalone client-side tools; individual QV design choices may be *aligned with* ISO 16363 criteria without the tool as a whole constituting a trustworthy digital repository)
- RFC 3161 for timestamp-token context (TSA-based trusted timestamping; not currently implemented in QV but the relevant model for a classical server-based evidence path)
- RFC 4998 for evidence-record and renewal direction; ERS defines the structure of renewable evidence records: an archive evidence archive (ARA) carries initial timestamp tokens plus successor renewal records (Section 5), each new record committing to prior evidence and new witness material, providing the formal model for multi-decade time-proof renewal
- Haber-Stornetta (1991) and Bayer-Haber-Stornetta (1993) lineage for long-term time-proof direction: Haber-Stornetta establishes the conceptual security target (anti-backdating / anti-forward-dating without trust in mutable metadata); Bayer-Haber-Stornetta introduces Merkle tree aggregation for public witness scalability, which is the direct conceptual ancestor of OpenTimestamps' blockchain anchoring model
- OpenTimestamps project documentation for the current external evidence ecosystem
- ML-KEM-1024 (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) for the current PQ cryptographic baseline carried by Quantum Vault and related tools
- AES-256-GCM (SP 800-38D) for the current confidentiality layer carried by `.qenc`

## Current implementation status

Implemented now:

- confidentiality and threshold recovery for the current successor `QVqcont-7` / archive-state descriptor / lifecycle-bundle family
- archive-state descriptors, cohort bindings, and lifecycle bundles
- same-state resharing over one unchanged archive state, including required transition-record emission for QV-produced resharing
- stable `archiveId` / `stateId` / `cohortId` semantics within the successor lifecycle family
- detached archive approval, maintenance signatures, source-evidence signatures, and optional OTS linkage over detached signature bytes
- archive-class terminology as a documentation and planning taxonomy
- OAIS-oriented interpretation guidance for the current artifacts

Deferred roadmap:

- renewable evidence-record chains
- state-changing migration, reencryption, or rewrap continuity records across successor archive states
- repository or custodian governance objects
- complete representation-information packaging or archival decoder distribution

## Future work and non-normative notes

Statements explicitly labeled as target or recommended direction are non-normative.
Likely future archival promotions include:

- evidence-renewal chains and archive-continuity records
- more formal repository and custodian governance objects and accountability records
- migration, rewrap, and reencryption continuity records
- stronger representation-information packaging and archival interoperability artifacts

## 1. Status, scope, and current archival boundary

This document applies to the current Quantum Vault archival surface:

- `.qenc` containers
- `.qcont` shard cohorts
- archive-state descriptors
- cohort bindings
- lifecycle bundles
- transition records and source-evidence objects
- detached signatures and signer-identity attachments
- optional `.ots` timestamp evidence

Current archival boundary:

- Quantum Vault already supports confidentiality, threshold recovery, detached signatures, bundle-carried authenticity metadata, evidence linkage, and same-state resharing records for one unchanged archive state
- Quantum Vault does not yet implement a first-class renewable evidence-record chain
- Quantum Vault implements stable `archiveId` semantics within the successor lifecycle family, but continuity across future rewrap, reencryption, or other state-changing migration is not yet first-class
- Quantum Vault does not yet implement a first-class renewal-event log or state-changing migration-event log

Current interpretation rule:

- statements labeled as current describe the repository's presently documented behavior
- statements labeled as recommended future direction describe the intended long-term archival model, not a completed implementation

## 2. Long-term objectives

Long-term archival evaluation must keep the following objectives separate:

1. long-term confidentiality
2. long-term authenticity and provenance
3. long-term time verifiability
4. long-term interpretability
5. long-term recoverability

## 3. Current archival posture and major gaps

| Topic | Current posture | Long-term implication |
| --- | --- | --- |
| Confidentiality | Current design uses ML-KEM-1024 (FIPS 203) plus AES-256-GCM (SP 800-38D) and key commitment | Strong current baseline, but future migration still needs crypto-agility and rewrap strategy |
| Authenticity | Current system supports detached signatures over canonical archive-state descriptor bytes, plus separate maintenance and source-evidence signatures for declared lifecycle targets | Good current provenance layer, but long-term authority semantics remain intentionally narrow |
| Time evidence | Current `.ots` handling links evidence to detached signature bytes and reports status | Useful evidence add-on, but not a full renewable time-proof architecture |
| Evidence renewal | No first-class evidence-record chain today | Required for serious multi-decade archival confidence |
| Archive identity continuity | Successor lifecycle artifacts carry stable `archiveId`, `stateId`, and `cohortId` semantics within one archive family | Rewrap and reencryption continuity still need explicit state-changing transition records and renewal logic |
| Representation information | Core docs exist, but test vectors, archival decoder packaging, and designated-community material are still incomplete | Long-term interpretability is improved but not yet archival-grade |
| Migration semantics | Rewrap, reencryption, renewal, and migration authority are not yet first-class archival objects | Cross-decade continuity currently depends on documentation discipline rather than format-native records |

## 4. Archive classes

Archive classes are currently a documentation and policy taxonomy, not yet a first-class wire-level field.
They are meant to make archival burden explicit instead of pretending every archive has the same long-term requirements.

| Class | Current minimum expectation | Current feasibility | Long-horizon meaning |
| --- | --- | --- | --- |
| `backup` | Confidentiality and recoverability are primary; detached signatures are optional; evidence is optional | Fully approximable today | Good for recovery-oriented storage, not strong archival provenance |
| `audited-archive` | At least one detached archive-approval signature is expected; signer identity material should be preserved; external evidence is recommended | Partially approximable today | Intended for archives where provenance matters, but full renewal may still be external or manual |
| `long-term-archive` | Strong PQ provenance, external evidence, renewal plan, representation package, and migration planning are required | Not fully implemented today | Target class for multi-decade preservation |

### 4.1 `backup`

Current focus:

- confidentiality
- threshold recoverability
- structural integrity

Current posture:

- compatible with `integrity-only` restore policy
- detached signatures are optional
- timestamp evidence is optional

### 4.2 `audited-archive`

Current focus:

- recoverability plus signer-backed provenance
- clearer custody and approval expectations

Current posture:

- at least one detached archive-approval signature should be preserved
- `strong-pq-signature` is preferred even if `any-signature` is technically compatible
- signer identity material and optional evidence should travel with the archival package

### 4.3 `long-term-archive`

Target focus:

- multi-decade confidentiality
- durable provenance after cryptographic transitions
- renewable evidence
- self-describing archival package

Target posture:

- `strong-pq-signature` is the minimum current-compatible policy floor, not the whole class
- external evidence is mandatory
- renewal schedule is mandatory
- representation-information package is mandatory
- migration and stewardship planning are mandatory

Current limitation:

- the repository can approximate parts of this class today, but the class is not fully realized until evidence renewal, archive identity continuity, and migration records become first-class archival features

## 5. Evidence and time model

### 5.1 Current evidence layer

Current supported evidence behavior is intentionally narrow:

- `.ots` evidence links to detached signature bytes
- evidence may be bundled or supplied externally
- evidence is supplementary only
- evidence does not satisfy archive signature policy by itself
- current handling is linkage-focused and report-focused, not a full external timestamp-attestation framework

Current detached-signature timestamping rationale:

- the witness target is the detached signature artifact rather than lifecycle-bundle bytes
- detached signature bytes bind canonical archive-state bytes or other declared lifecycle targets
- the signed target then binds the current `.qenc` and shard cohort through the current fixity and shard-binding anchors
- current `.ots` evidence is therefore evidence for a signed archive description and its current binding chain, not a standalone proof about plaintext semantics

### 5.2 Current witness strategy and its limits

Current practical witness strategy:

- Quantum Vault interoperates with OpenTimestamps because it provides a public external witness ecosystem for detached-signature evidence without requiring Quantum Vault itself to operate a single long-lived attester service
- this keeps the witness target stable when signatures are added or transported independently of lifecycle-bundle rewrites
- OpenTimestamps aggregates document digests into Bitcoin transaction outputs using Merkle tree constructions in the tradition of Bayer, Haber, and Stornetta; the distributed public-witness character of Bitcoin mining reduces reliance on any single trusted-authority server as compared with RFC 3161 TSA-based timestamps

Trust model of the current OTS integration:

- the distributed witness character mitigates single-authority failure modes that affect RFC 3161 TSP tokens
- however, the OTS model inherits trust assumptions about the continued security of SHA-256 as the proof's internal hash function and the continued availability of the Bitcoin blockchain as a publicly verifiable record
- OTS evidence therefore carries its own long-horizon trust assumptions: an adversary capable of a SHA-256 second-preimage attack could forge the proof chain, and an archived Bitcoin transaction becomes unverifiable if the blockchain is no longer accessible to the verifier
- these assumptions are different in character from QV's SHA-3 fixity layer but do not nullify the OTS evidence value within the expected operating window; they inform the recommendation to treat OTS as one witness regime rather than the only long-horizon witness

Current limits and interpretation:

- OpenTimestamps is not treated here as the final archival evidence architecture
- RFC 4998 remains the model for renewal-capable evidence chaining and long-horizon verification continuity
- future archival evidence may combine OpenTimestamps with other witness or renewal regimes rather than treating one mechanism as permanently sufficient

### 5.3 Recommended future evidence object

The research basis points toward a future evidence object or evidence-record chain modeled on RFC 4998 Evidence Record Syntax (ERS). In RFC 4998's model, an archive evidence archive (ARA) starts with an initial evidence record that commits to a set of initial timestamp tokens. Each subsequent renewal record commits to the preceding evidence and adds new witness material, forming a chain in which the security of later records does not depend solely on the continued strength of the algorithms used in earlier ones.

A QV evidence object's minimum purpose would be to commit to:

- one or more archive anchors or fixity anchors (at minimum: `archiveId`, `stateId`, canonical archive-state bytes, and `qencHash`)
- detached signature digests linked to the signatures being evidenced
- signer key identifiers or fingerprints associated with those signatures
- witness outputs, witness-regime metadata (including which hash functions and chains the witness relies on), and renewal events
- predecessor evidence references when renewal occurs

Recommended future shape:

- `E0` as the initial archival evidence object; may carry current detached-signature-targeted `.ots` evidence as its first witness material
- `E1`, `E2`, ... as renewal records, each committing to the preceding evidence object's digest and adding new witness anchors under a successor witness regime
- each record in the chain should be designed so that a verifier who has the chain `E0` through `Ek` can establish evidence continuity even if the algorithms used in `E0` are no longer trusted at verification time

Current expected use of `E0`:

- it may begin by carrying current detached-signature-targeted evidence such as `.ots`
- it should be able to bind successor witness material without losing earlier evidence context
- it should preserve enough metadata that a later verifier can understand what was witnessed, by whom or by what witness regime, and what prior evidence record it extends

### 5.4 Witness model and renewal direction

Recommended long-term direction:

- do not rely on a single classical timestamp authority as the only durable witness
- use multiple independent witness channels where possible
- treat OpenTimestamps as one useful witness regime, not necessarily the only long-horizon witness regime
- renew evidence before trust anchors or algorithms become untrustworthy
- retain old evidence as historical context, but carry forward successor evidence in a continuity chain
- when successor evidence is created, bind it both to prior evidence and to the current archive anchor being preserved

## 6. Minimal archival package and OAIS mapping

### 6.1 Minimal archival package

A minimally sufficient long-term Quantum Vault package should contain the following components, even if the current product does not yet generate all of them automatically:

| Component | Current availability | Long-term role |
| --- | --- | --- |
| `.qenc` or a full restorable `.qcont` cohort | Current | Core protected object or recovery carrier |
| Archive-state descriptor | Current | Stable signable archive description |
| Cohort binding | Current | Current shard-cohort definition and commitment set |
| `QV-Lifecycle-Bundle` v1 | Current | Carries policy and attached authenticity material |
| Transition and source-evidence context, when present | Current | Maintenance lineage and provenance context |
| Detached signature set | Current | Provenance and signer-verifiable fixity evidence |
| Timestamp/evidence set | Partial | Time evidence and future renewal anchor |
| Representation information package | Partial | Lets future verifiers understand the format and validation rules |
| Migration and renewal log | Future | Preserves continuity across stewardship events |

### 6.2 OAIS mapping

Quantum Vault is not OAIS itself and this document does not claim OAIS (ISO 14721:2025) or ISO 16363 compliance.
The mapping below is a practical orientation layer.

| OAIS concept | Current Quantum Vault mapping | Current status |
| --- | --- | --- |
| SIP | User input files plus generated archive artifacts during create, split, sign, and attach workflows | Informal but recognizable |
| AIP | Long-term package containing the protected object, archive-state descriptor, cohort binding, lifecycle bundle, detached signatures, evidence, and representation material | Partial; not all components are first-class yet |
| DIP | Restored `.qenc`, decrypted payloads, and supporting verification artifacts for dissemination | Partial and workflow-dependent |
| Fixity Information | `qencHash`, digests, commitments, detached signatures | Strong current baseline |
| Provenance Information | Detached signatures, signer identity material, transition records, source-evidence objects | Partial |
| Reference Information | `archiveId`, `stateId`, `cohortId`, `qencHash`, `containerId`, and related lifecycle anchors | Partial |
| Context Information | Policy object, signer identity material, evidence linkage context, external archival metadata | Partial |
| Access Rights Information | Mostly external to the current format family | Minimal in current docs |
| Representation Information | `format-spec.md`, `trust-and-policy.md`, `security-model.md`, future test vectors and decoders | Improved, not complete |

## 7. Preservation events, migration, and archive identity

### 7.1 Preservation events

Long-term stewardship requires event history, not just static artifacts.
The following event taxonomy is the current recommended baseline:

| Event | Current meaning | Continuity consequence |
| --- | --- | --- |
| Create / split | Initial archive creation and package generation | Starts the archival record |
| Sign / attach | Adds provenance material without changing the archive-state descriptor | Preserves the same archive state |
| Same-state resharing | Repackages shard distribution without changing archive-state bytes | Preserves the same archive state while changing cohort material |
| Renew evidence | Future event type for successor witness material | Should preserve archival continuity |
| Re-sign | Future or external event adding successor signatures to the same archive-state or other lifecycle target | Should preserve archival continuity if it binds to the same archival anchor |
| Rewrap | Future event replacing confidentiality wrapping material without changing higher-level intent | Intended to preserve continuity, but not yet format-native |
| Reencryption | Generates new ciphertext under new confidentiality material | Changes current fixity anchors and needs explicit continuity records |
| Custody transfer / export | Changes stewardship or dissemination context | Should preserve continuity but requires provenance records |

### 7.2 Migration model

The following distinctions should remain explicit:

- refresh: media replacement with no cryptographic or logical change
- replication: additional copies with the same logical archive state
- repackaging: changing package structure without changing the protected object
- rewrap: changing key-wrapping or confidentiality envelope without re-encrypting content
- reencryption: generating new ciphertext under new confidentiality material
- transformational migration: changing representation, semantics, or designated-community interpretation

Current important boundary:

- rewrap and reencryption are not the same
- same-state resharing and reencryption are not the same
- long-term continuity must not be inferred from filenames or operator intent alone

### 7.3 Archive identity and continuity decision framework

Current archive anchors are layered rather than fully unified across all future lifecycle events.

Current anchor set:

- `archiveId`
- `stateId`
- `cohortId`
- `qencHash`
- `containerId`
- `authPolicyCommitment`

Current binding chain for detached-signature-based provenance:

- detached signatures bind canonical archive-state bytes for archive approval, or other declared lifecycle targets for maintenance and source evidence
- the archive-state descriptor binds the current archive description
- the current archive description binds the current `.qenc` and shard cohort through `qencHash`, `containerId`, and shard-binding material
- `.ots` evidence then witnesses the detached signature artifact linked to that signed archive description

Current gap:

- there is not yet a first-class continuity model that preserves `archiveId` semantics across future rewrap or reencryption

Current consequence:

- if ciphertext changes, `qencHash` changes
- if the signable archive-state descriptor changes to reflect new ciphertext or policy semantics, `stateId` changes
- same-state resharing preserves archive-state bytes and therefore preserves archive-approval signatures and their existing OTS linkage
- archival continuity across reencryption or policy-changing rebuilds is therefore not yet format-native
- until state-changing continuity records exist, long-term continuity across those events depends on documented migration records, preserved provenance chains, and explicit predecessor or successor archive records

Current continuity decision framework:

| Event or change | Anchors expected to stay stable | Anchors expected to change | Current continuity judgment |
| --- | --- | --- | --- |
| Update lifecycle-bundle evidence for the same archive state | `archiveId`, `stateId`, `qencHash`, `containerId`, `authPolicyCommitment` | lifecycle-bundle digest, attachment set, transition set, evidence set may change | Same archive state; mutable authenticity layer updated |
| Re-sign the same archive-state descriptor | `archiveId`, `stateId`, `qencHash`, `containerId`, `authPolicyCommitment` | signature set changes | Same archive description with refreshed detached-signature provenance |
| Renew evidence for the same detached signature set | detached-signature target and archive anchors stay the same | evidence set changes | Same archive description with successor evidence context |
| Same-state resharing | `archiveId`, `stateId`, `qencHash`, `containerId`, archive-approval targets | cohort binding, `cohortId`, shard packaging, and custody distribution change | Same archive state when archive-state bytes are unchanged and required transition records are preserved |
| Rewrap without changing higher-level archive meaning | higher-level continuity may be intended | current fixity anchors may change and state-changing continuity records do not yet exist | Continuity cannot be inferred safely without explicit migration records |
| Reencryption under new confidentiality material | higher-level provenance may still matter | `qencHash`, `containerId`, and `stateId` change | Treat as a new archive state unless explicit continuity records bind predecessor and successor |
| Transformational migration | continuity may be partial or contested | representation, semantics, and likely anchors change | Never infer continuity from intent alone; require explicit provenance and migration records |

Current operator rule:

- continuity must not be inferred from filenames, storage location, or operator assertion alone
- continuity claims should be recorded in migration logs or equivalent archival provenance records until state-changing continuity records become first-class

### 7.4 Repository and custodian responsibilities

Quantum Vault can define artifact semantics, verification rules, and archival package expectations.
It does not, by itself, guarantee that a repository, custodian, or restore workflow will meet those expectations over decades.

Current recommended stewardship boundary:

| Actor | Current recommended responsibility | Why it matters |
| --- | --- | --- |
| Repository or archive-maintenance function | Preserve the complete archival package needed for the chosen archive class, including the protected object or shard cohort, archive-state descriptor, cohort binding, lifecycle bundle, detached signatures, evidence, and supporting documentation | Without the full package, long-term interpretability and provenance degrade even if ciphertext survives |
| Repository or archive-maintenance function | Preserve software, specification, and representation information sufficient for later verification and interpretation | Long-term archives fail if future operators cannot interpret algorithms, canonicalization, or validation procedure |
| Repository or archive-maintenance function | Record stewardship events such as re-signing, evidence renewal, same-state resharing, rewrap, reencryption, export, or custody transfer | Continuity across decades depends on event history, not just static bytes |
| Custodian | Preserve assigned `.qcont` shards and related detached artifacts verbatim, without mutating bytes or silently rewriting metadata | Recoverability and fixity depend on byte-preserving custody |
| Custodian | Maintain genuinely independent storage and communicate loss, corruption, or availability failures promptly | Threshold recoverability depends on independent and honest custody |
| Restoration quorum | Supply enough consistent shards to meet threshold and avoid silently mixing incompatible cohorts | Current restore safety depends on coherent cohorts, not "largest pile wins" behavior |
| Restore operator | Record which shard cohort, lifecycle bundle, signatures, pins, and evidence were actually used during restore or audit | Later provenance review depends on knowing what evidence path was relied upon |

## 8. Deprecation policy and horizon-based recommendations

### 8.1 Deprecation and migration triggers

Recommended response rules:

- if a signature family is weakened, add successor signatures and keep prior signatures as historical evidence
- if a KEM or confidentiality wrapper is weakened, prefer rewrap over full reencryption when the architecture permits it
- if SHA3-512 or another fixity primitive is weakened, append successor fixity material and preserve chain continuity
- if a timestamp witness becomes untrustworthy, renew evidence into a successor witness regime before trust collapse
- if an archive-class policy is deprecated, preserve existing evidence but record the migration rationale and successor policy

These are current archival policy recommendations, not yet fully automated product behavior.

### 8.2 Minimal recommendations by horizon

| Horizon | Recommended posture | Current feasibility |
| --- | --- | --- |
| 5-10 years | Preserve the archive-state descriptor, lifecycle bundle, and at least one detached signature when provenance matters; `.ots` evidence is optional but useful; keep the core docs with the archive | Mostly feasible now |
| 20 years | Prefer `strong-pq-signature`; preserve signer identity material; include external evidence; preserve representation information and a migration plan | Partially feasible now |
| 50+ years | Use signature diversity, renewable evidence, witness diversity, representation package, migration log, and continuity records across rewrap or reencryption | Roadmap only; not yet fully implemented |

## 9. Future coverage retained for this document

This document carries the current archival baseline, but it still needs future expansion in the following areas:

- first-class evidence-object schema and renewal-chain processing
- continuity rules across migration events that preserve successor archive identity semantics
- machine-readable stewardship roles and accountability objects for renewal and migration authority
- more precise migration records and custody-transfer provenance
- designated-community guidance and fuller representation-information packaging
- stronger archival packaging guidance tied to test vectors and reference decoders
