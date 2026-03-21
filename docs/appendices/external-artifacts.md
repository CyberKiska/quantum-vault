# External authenticity artifacts

Status: Release Candidate
Type: Normative compatibility appendix
Audience: implementers, auditors, interoperability tool authors, archive operators
Scope: current acceptance and linkage rules for detached signatures, detached PQ public keys, and OpenTimestamps evidence
Out of scope: full upstream signature-format specifications, archive-policy semantics, long-term evidence-renewal design

## Role

This appendix is the compatibility reference for the detached authenticity artifacts accepted by Quantum Vault today.
It supports [format-spec.md](../format-spec.md) for ingestion and linkage rules and [trust-and-policy.md](../trust-and-policy.md) for policy meaning.

## Scope

This file documents how Quantum Vault currently accepts and links:

- detached PQ signatures (`.qsig`)
- Stellar/Ed25519 detached signatures (`.sig`)
- detached PQ public keys (`.pqpk`)
- OpenTimestamps proofs (`.ots`)

It does not restate the complete upstream formats for those artifacts.

## Normative status

This appendix is normative for current external-artifact acceptance and linkage behavior.
An implementation is conformant to this version if and only if it satisfies all MUST-level requirements defined in the current normative sections of this appendix and the owner documents `format-spec.md` and `trust-and-policy.md`.
If an implementation deviates from this appendix, it MUST explicitly document the deviation and MUST declare itself non-conformant to this version.
Statements explicitly labeled as future or recommended direction are non-normative until promoted into the current sections of this appendix.
In case of ambiguity, this appendix MUST be interpreted conservatively and fail-closed.

## Sources and references

Internal current-state grounding:

- `src/core/crypto/auth/verify-signatures.js`
- `src/core/crypto/auth/qsig.js`
- `src/core/crypto/auth/stellar-sig.js`
- `src/core/crypto/auth/opentimestamps.js`
- `src/core/crypto/auth/signature-identity.js`
- `src/core/crypto/manifest/manifest-bundle.js`
- `docs/format-spec.md`
- `docs/trust-and-policy.md`

External references already used elsewhere in the repository:

- OpenTimestamps proof ecosystem as currently linked evidence
- RFC 4648 for Base64 handling

## Current implementation status

Implemented now:

- detached PQ signature verification for the current `.qsig` wrapper and context
- Stellar detached-signature verification for the current `stellar-signature/v2` JSON profiles
- detached PQ public-key wrapper parsing for user pinning and bundled signer references
- OpenTimestamps linkage to detached signature bytes
- proof-identity deduplication for policy counting
- fail-closed rejection of ambiguous or incompatible references

Not yet first-class in the current implementation:

- archive-wide evidence objects separate from detached signatures
- frozen standalone interoperability corpus for every artifact combination
- automatic long-term evidence renewal or RFC 4998 evidence-record chaining

## Future work and non-normative notes

- Additional detached artifact families should receive explicit acceptance rules rather than being inferred by filename alone.
- Broader evidence chaining may be added later, but must remain clearly labeled as future behavior until implemented.

## 1. Accepted artifact families

| Artifact family | Current acceptance boundary | Current linkage target |
| --- | --- | --- |
| `.qsig` | binary wrapper with magic `PQSG`, detached PQ signature major version `2`, and context `quantum-signer/v2` | canonical manifest bytes |
| `.sig` | JSON document accepted only when it matches the supported `stellar-signature/v2` schema/profile combinations | canonical manifest bytes |
| `.pqpk` | binary wrapper with magic `PQPK` and detached PQ public-key major version `1` | signer pinning and `publicKeyRef` resolution |
| `.ots` | OpenTimestamps proof with the supported proof header and SHA-256 stamped digest operation | detached signature bytes |

Current detection rules:

- external `.qsig` detection is byte-based by magic, not by filename alone
- external `.sig` detection requires JSON decoding plus a supported Stellar signature profile
- external `.pqpk` is parsed explicitly as a detached PQ public-key wrapper
- `.ots` linkage is based on the stamped digest matching detached signature bytes, not on a filename convention

## 2. Signature linkage rules

Current detached-signature linkage rules are:

- both bundled and external signatures are verified over canonical manifest bytes only
- bundled signatures MUST declare `target.type = "canonical-manifest"`
- bundled signatures MUST declare `target.digestAlg = "SHA3-512"`
- bundled signatures MUST carry a `target.digestValue` equal to the bundle's `manifestDigest.value`
- external signatures are verified directly against the selected canonical manifest bytes rather than bundle bytes

Current acceptance limits:

- Quantum Vault does not treat the mutable manifest bundle as the signable payload
- Quantum Vault does not infer signer algorithms from wrapper filenames or key lengths
- unsupported detached-signature major versions, contexts, or profile identifiers fail closed

## 3. Public-key attachment and pinning rules

Current signer-identity sources are layered:

- a bundled `attachments.publicKeys[]` entry may act as the authoritative verification key for a bundled detached signature when referenced by `publicKeyRef`
- a user-supplied `.pqpk` file may act as an external PQ pin
- a user-supplied expected Stellar signer string may act as an external Ed25519 identity pin

Current `publicKeyRef` rules:

- `publicKeyRef` is optional
- if `publicKeyRef` is present on a bundled signature, it is authoritative for that bundled signature
- unresolved, incompatible, or non-verifying `publicKeyRef` bindings fail closed
- a bundled `qsig` `publicKeyRef` must reference a bundled PQ public key with `encoding = "base64"` and a matching PQ suite
- a bundled `stellar-sig` `publicKeyRef` must reference a bundled Stellar signer with `encoding = "stellar-address"` and suite `ed25519`

Current pinning consequences:

- bundled-signature verification against a bundled key contributes to `bundlePinned`
- verification against user-supplied pin material contributes to `userPinned`
- a valid signature does not become invalid merely because a supplied user pin does not match; it remains valid but unpinned, with an explicit warning

## 4. Proof identity deduplication and ambiguity handling

Current policy counting deduplicates detached signatures by proof identity, not by filename.

Current proof-identity rules:

- `qsig` proofs are deduplicated by `SHA3-512` of the detached signature bytes
- Stellar proofs are deduplicated by a normalized semantic payload, not raw JSON formatting alone
- semantically duplicate signatures across bundled and external inputs count once for policy purposes

Current ambiguity handling:

- duplicate bundle signature ids are rejected
- duplicate detached signature proofs under different bundle ids are rejected
- multiple provided `.pqpk` pins that all match the same detached PQ signature fail closed as ambiguous
- an `.ots` proof must match exactly one detached signature; zero matches or multiple matches fail closed

## 5. OpenTimestamps linkage and completion reporting

Current `.ots` rules are intentionally narrow:

- the stamped digest is the SHA-256 digest of detached signature bytes
- bundled timestamps link to `attachments.signatures[]` through `targetRef`
- external timestamps resolve by matching the stamped digest against the detached signature bytes seen during verification
- `.ots` evidence does not satisfy archive signature policy by itself

Current completeness reporting is heuristic:

- `apparentlyComplete` / `completeProof` is inferred from filename hints such as `complete`, `completed`, `confirmed`, or `upgraded`, or from proof size
- the current implementation treats proof size `>= 1024` bytes as appearing complete when filename hints are absent
- this is reporting convenience, not full long-horizon evidence validation

Current OTS deduplication:

- evidence is deduplicated per stamped detached-signature digest
- when duplicate evidence exists for one detached signature, the implementation prefers apparently complete proofs over incomplete ones
- when completeness is tied, embedded evidence is preferred over otherwise equivalent external evidence

## 6. Current fail-closed cases

Quantum Vault currently rejects at least the following cases:

- unsupported `.qsig` major version or context
- unsupported `.pqpk` major version or CRC failure
- unsupported Stellar signature schema/profile
- bundled signature target digest mismatch
- incompatible or unresolved `publicKeyRef`
- unrelated `.ots` proof that matches no detached signature
- `.ots` proof that matches multiple detached signatures

These rules are part of the current interoperability contract, not optional hardening advice.
