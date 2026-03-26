import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesEqual, bytesToUtf8, toHex } from '../bytes.js';
import { parseJsonBytesStrict } from '../manifest/strict-json.js';
import { buildQencHeader, parseQencHeader } from '../qenc/format.js';
import { DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL } from '../constants.js';
import { DEFAULT_CRYPTO_PROFILE, getNonceContractForAeadMode } from '../policy.js';
import { decapsulate } from '../mlkem.js';
import { clearKeys, deriveKeyWithKmac, verifyKeyCommitment } from '../kdf.js';
import { resolveErasureRuntime } from '../erasure-runtime.js';
import {
  buildArchiveStateDescriptor,
  buildCohortBinding,
  buildLifecycleBundle,
  buildTransitionRecord,
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeLifecycleBundle,
  canonicalizeTransitionRecord,
  deriveCohortId,
  deriveStateId,
  generateArchiveId,
  parseArchiveStateDescriptorBytes,
  parseCohortBindingBytes,
  parseLifecycleBundleBytes,
  REED_SOLOMON_CODEC_ID,
} from '../lifecycle/artifacts.js';

export const LIFECYCLE_QCONT_MAGIC = 'QVC1';
export const LIFECYCLE_QCONT_FORMAT_VERSION = 'QVqcont-7';
export const LIFECYCLE_ARTIFACT_FAMILY = 'successor-lifecycle-v1';

const DIGEST_LEN = 64;
const KEY_COMMITMENT_LEN = 32;
const MAX_META_LEN = 65535;
const MAX_ARTIFACT_LEN = 16 * 1024 * 1024;
const LOWER_HEX_RE = /^[0-9a-f]+$/;
const RESHARE_OPERATIONAL_WARNINGS = Object.freeze([
  'Predecessor shard destruction cannot be proven by Quantum Vault; operators must handle custodial destruction outside the system.',
  'Same-state resharing does not revoke leaked predecessor quorum material or repair prior compromise; suspected old-quorum leakage requires a new archive state.',
]);
const RESHARE_SEMANTICS = Object.freeze({
  sameStateAvailabilityMaintenance: true,
  archiveReapprovalPerformed: false,
  plaintextDecrypted: false,
  sourceEvidenceCreated: false,
  compromiseRepairClaimed: false,
});
const FORBIDDEN_RESHARE_FIELDS = Object.freeze([
  'archiveId',
  'stateId',
  'archiveState',
  'archiveStateBytes',
  'archiveStateDigest',
  'archiveStateDigestHex',
  'qencHash',
  'containerId',
  'cryptoProfileId',
  'kdfTreeId',
  'noncePolicyId',
  'nonceMode',
  'counterBits',
  'maxChunkCount',
  'aadPolicyId',
  'authPolicy',
  'authPolicyCommitment',
]);

function readJsonStrict(bytes, field) {
  try {
    return parseJsonBytesStrict(bytes);
  } catch (error) {
    throw new Error(`Invalid ${field}: ${error?.message || error}`);
  }
}

function computeDigestHex(bytes) {
  return toHex(sha3_512(bytes));
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

function requireLowercaseHexMetadata(value, field, expectedLength) {
  if (typeof value !== 'string' || value.length !== expectedLength || !LOWER_HEX_RE.test(value)) {
    throw new Error(`Invalid shard metadata ${field}`);
  }
  return value;
}

function ensurePositiveInteger(value, field, min = 1) {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function ensureEqual(actual, expected, field) {
  if (actual !== expected) {
    throw new Error(`${field} mismatch (expected ${expected}, got ${actual})`);
  }
}

function normalizeHexString(value) {
  return String(value || '').trim().toLowerCase();
}

function isLifecycleParsedShard(shard) {
  return (
    shard?.archiveStateBytes instanceof Uint8Array &&
    shard?.cohortBindingBytes instanceof Uint8Array &&
    shard?.lifecycleBundleBytes instanceof Uint8Array
  );
}

function ensureReshareArray(value, field) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function assertNoForbiddenReshareOverrides(params = {}, options = {}) {
  const rejected = [];
  for (const field of FORBIDDEN_RESHARE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(params, field)) {
      rejected.push(`params.${field}`);
    }
    if (Object.prototype.hasOwnProperty.call(options, field)) {
      rejected.push(`options.${field}`);
    }
  }
  if (rejected.length > 0) {
    throw new Error(`Same-state resharing forbids overriding ${rejected.join(', ')}`);
  }
}

function validateReshareTargetParams(params, predecessorCohortBinding) {
  const n = ensurePositiveInteger(Number(params?.n), 'params.n', 2);
  const k = ensurePositiveInteger(Number(params?.k), 'params.k', 2);
  if (k >= n) {
    throw new Error('Invalid RS parameters: require 2 <= k < n');
  }
  const m = n - k;
  if ((m % 2) !== 0) {
    throw new Error('n-k must be even');
  }
  const derivedThreshold = k + (m / 2);
  const requestedThreshold = params?.t == null
    ? derivedThreshold
    : ensurePositiveInteger(Number(params.t), 'params.t', 2);
  if (requestedThreshold !== derivedThreshold) {
    throw new Error('Same-state resharing currently requires t = k + ((n-k)/2) under QV-RS-ErasureCodes-v1');
  }

  const predecessorCodecId = predecessorCohortBinding?.sharding?.reedSolomon?.codecId || REED_SOLOMON_CODEC_ID;
  const requestedCodecId = String(params?.rsCodecId || params?.codecId || predecessorCodecId);
  if (requestedCodecId !== REED_SOLOMON_CODEC_ID) {
    throw new Error(`Same-state resharing currently supports only codecId ${REED_SOLOMON_CODEC_ID} under the frozen v1 schema`);
  }

  if (
    Object.prototype.hasOwnProperty.call(params || {}, 'bodyDefinitionId') &&
    params.bodyDefinitionId !== predecessorCohortBinding.bodyDefinitionId
  ) {
    throw new Error('Same-state resharing currently supports only the frozen bodyDefinitionId carried by the predecessor cohort');
  }

  if (Object.prototype.hasOwnProperty.call(params || {}, 'bodyDefinition')) {
    const requested = params.bodyDefinition || {};
    const expected = predecessorCohortBinding.bodyDefinition || {};
    const requestedIncludes = Array.isArray(requested.includes) ? requested.includes : [];
    const requestedExcludes = Array.isArray(requested.excludes) ? requested.excludes : [];
    const expectedIncludes = Array.isArray(expected.includes) ? expected.includes : [];
    const expectedExcludes = Array.isArray(expected.excludes) ? expected.excludes : [];
    const sameIncludes = requestedIncludes.length === expectedIncludes.length &&
      requestedIncludes.every((value, index) => value === expectedIncludes[index]);
    const sameExcludes = requestedExcludes.length === expectedExcludes.length &&
      requestedExcludes.every((value, index) => value === expectedExcludes[index]);
    if (!sameIncludes || !sameExcludes) {
      throw new Error('Same-state resharing currently supports only the frozen shard body-definition carried by the predecessor cohort');
    }
  }

  return {
    n,
    k,
    t: requestedThreshold,
    rsCodecId: requestedCodecId,
  };
}

function assertArchiveStateMatchesQencMetadata(archiveState, qencMetaJSON) {
  const qenc = archiveState.qenc || {};

  ensureEqual(qenc.hashAlg, 'SHA3-512', 'qenc.hashAlg');
  ensureEqual(qenc.primaryAnchor, 'qencHash', 'qenc.primaryAnchor');
  ensureEqual(qenc.containerIdRole, 'secondary-header-id', 'qenc.containerIdRole');
  ensureEqual(qenc.containerIdAlg, 'SHA3-512(qenc-header-bytes)', 'qenc.containerIdAlg');

  ensureEqual(Number(qencMetaJSON.chunkSize), Number(qenc.chunkSize), 'qenc.chunkSize');
  ensureEqual(Number(qencMetaJSON.chunkCount), Number(qenc.chunkCount), 'qenc.chunkCount');
  ensureEqual(Number(qencMetaJSON.payloadLength), Number(qenc.payloadLength), 'qenc.payloadLength');

  ensureEqual(qencMetaJSON.cryptoProfileId, archiveState.cryptoProfileId, 'cryptoProfileId');
  ensureEqual(qencMetaJSON.kdfTreeId, archiveState.kdfTreeId, 'kdfTreeId');
  ensureEqual(qencMetaJSON.noncePolicyId, archiveState.noncePolicyId, 'noncePolicyId');
  ensureEqual(qencMetaJSON.nonceMode, archiveState.nonceMode, 'nonceMode');
  ensureEqual(Number(qencMetaJSON.counterBits), Number(archiveState.counterBits), 'counterBits');
  ensureEqual(Number(qencMetaJSON.maxChunkCount), Number(archiveState.maxChunkCount), 'maxChunkCount');
  ensureEqual(qencMetaJSON.aadPolicyId, archiveState.aadPolicyId, 'aadPolicyId');
}

function collectSinglePredecessorCohort(preparedShards) {
  const byIdentity = new Map();
  for (const shard of preparedShards) {
    const archiveId = normalizeHexString(shard?.archiveState?.archiveId || shard?.metaJSON?.archiveId);
    const stateId = normalizeHexString(shard?.stateId || shard?.metaJSON?.stateId);
    const cohortId = normalizeHexString(shard?.cohortId || shard?.metaJSON?.cohortId);
    if (!archiveId || !stateId || !cohortId) {
      throw new Error('Predecessor shard is missing archive/state/cohort identity');
    }
    const key = `${archiveId}:${stateId}:${cohortId}`;
    if (!byIdentity.has(key)) {
      byIdentity.set(key, {
        key,
        archiveId,
        stateId,
        cohortId,
        archiveStateBytes: shard.archiveStateBytes,
        archiveStateDigestHex: normalizeHexString(shard.archiveStateDigestHex),
        archiveState: shard.archiveState,
        cohortBindingBytes: shard.cohortBindingBytes,
        cohortBindingDigestHex: normalizeHexString(shard.cohortBindingDigestHex),
        cohortBinding: shard.cohortBinding,
        embeddedLifecycleBundles: new Map(),
        shards: [],
      });
    }
    const entry = byIdentity.get(key);
    if (!bytesEqual(entry.archiveStateBytes, shard.archiveStateBytes)) {
      throw new Error(`Exact archive-state byte mismatch inside predecessor cohort ${key}`);
    }
    if (!bytesEqual(entry.cohortBindingBytes, shard.cohortBindingBytes)) {
      throw new Error(`Exact cohort-binding byte mismatch inside predecessor cohort ${key}`);
    }
    if (entry.archiveStateDigestHex !== normalizeHexString(shard.archiveStateDigestHex)) {
      throw new Error(`archive-state digest mismatch inside predecessor cohort ${key}`);
    }
    if (entry.cohortBindingDigestHex !== normalizeHexString(shard.cohortBindingDigestHex)) {
      throw new Error(`cohort-binding digest mismatch inside predecessor cohort ${key}`);
    }
    if (archiveId !== normalizeHexString(shard?.metaJSON?.archiveId || shard?.archiveState?.archiveId)) {
      throw new Error(`Mixed archiveId values detected inside predecessor cohort ${key}`);
    }
    if (stateId !== normalizeHexString(shard?.metaJSON?.stateId || shard?.stateId)) {
      throw new Error(`Mixed stateId values detected inside predecessor cohort ${key}`);
    }
    if (cohortId !== normalizeHexString(shard?.metaJSON?.cohortId || shard?.cohortId)) {
      throw new Error(`Mixed cohortId values detected inside predecessor cohort ${key}`);
    }

    const lifecycleBundleDigestHex = normalizeHexString(shard.lifecycleBundleDigestHex);
    if (!entry.embeddedLifecycleBundles.has(lifecycleBundleDigestHex)) {
      entry.embeddedLifecycleBundles.set(lifecycleBundleDigestHex, {
        digestHex: lifecycleBundleDigestHex,
        bytes: shard.lifecycleBundleBytes,
        bundle: shard.lifecycleBundle,
      });
    }
    const bundleEntry = entry.embeddedLifecycleBundles.get(lifecycleBundleDigestHex);
    if (!bytesEqual(bundleEntry.bytes, shard.lifecycleBundleBytes)) {
      throw new Error(`Lifecycle-bundle bytes mismatch inside predecessor cohort ${key} for digest ${lifecycleBundleDigestHex}`);
    }
    entry.shards.push(shard);
  }

  if (byIdentity.size !== 1) {
    throw new Error('Same-state resharing requires shards from exactly one predecessor archive/state/cohort set.');
  }

  return [...byIdentity.values()][0];
}

async function selectPredecessorLifecycleBundle(candidate, options = {}) {
  if (options.lifecycleBundleBytes instanceof Uint8Array) {
    const parsedBundle = await parseLifecycleBundleBytes(options.lifecycleBundleBytes);
    const canonicalArchiveState = canonicalizeArchiveStateDescriptor(parsedBundle.lifecycleBundle.archiveState);
    const canonicalCohortBinding = canonicalizeCohortBinding(parsedBundle.lifecycleBundle.currentCohortBinding);
    if (
      parsedBundle.lifecycleBundle.archiveStateDigest.value !== candidate.archiveStateDigestHex ||
      !bytesEqual(canonicalArchiveState.bytes, candidate.archiveStateBytes)
    ) {
      throw new Error('Provided lifecycle bundle does not match the predecessor archive-state bytes');
    }
    if (
      parsedBundle.lifecycleBundle.currentCohortBindingDigest.value !== candidate.cohortBindingDigestHex ||
      !bytesEqual(canonicalCohortBinding.bytes, candidate.cohortBindingBytes)
    ) {
      throw new Error('Provided lifecycle bundle does not match the predecessor cohort-binding bytes');
    }
    return {
      lifecycleBundle: parsedBundle.lifecycleBundle,
      lifecycleBundleBytes: parsedBundle.bytes,
      lifecycleBundleDigestHex: parsedBundle.digest.value,
      lifecycleBundleSource: 'provided-lifecycle-bundle',
    };
  }

  const embeddedDigests = [...candidate.embeddedLifecycleBundles.keys()].sort();
  const explicitDigest = normalizeHexString(options.selectedLifecycleBundleDigestHex);
  if (explicitDigest) {
    const selected = candidate.embeddedLifecycleBundles.get(explicitDigest);
    if (!selected) {
      throw new Error(`Selected lifecycle-bundle digest ${explicitDigest} is not present in the predecessor cohort`);
    }
    return {
      lifecycleBundle: selected.bundle,
      lifecycleBundleBytes: selected.bytes,
      lifecycleBundleDigestHex: selected.digestHex,
      lifecycleBundleSource: 'selected-embedded-lifecycle-bundle-digest',
    };
  }

  if (embeddedDigests.length !== 1) {
    throw new Error(
      'Predecessor cohort carries multiple embedded lifecycle-bundle digests. Provide lifecycleBundleBytes or selectedLifecycleBundleDigestHex to fail closed.'
    );
  }

  const selected = candidate.embeddedLifecycleBundles.get(embeddedDigests[0]);
  return {
    lifecycleBundle: selected.bundle,
    lifecycleBundleBytes: selected.bytes,
    lifecycleBundleDigestHex: selected.digestHex,
    lifecycleBundleSource: 'embedded-lifecycle-bundle',
  };
}

async function reconstructPredecessorMaterial(candidate, { erasureRuntime, onLog, onWarn }) {
  const archiveState = candidate.archiveState;
  const cohortBinding = candidate.cohortBinding;
  const group = candidate.shards.slice();

  const shamir = cohortBinding?.sharding?.shamir || {};
  const reedSolomon = cohortBinding?.sharding?.reedSolomon || {};
  const n = ensurePositiveInteger(Number(reedSolomon.n), 'cohortBinding.sharding.reedSolomon.n', 2);
  const k = ensurePositiveInteger(Number(reedSolomon.k), 'cohortBinding.sharding.reedSolomon.k', 2);
  const m = ensurePositiveInteger(Number(reedSolomon.parity), 'cohortBinding.sharding.reedSolomon.parity', 0);
  const t = ensurePositiveInteger(Number(shamir.threshold), 'cohortBinding.sharding.shamir.threshold', 2);
  const shareCount = ensurePositiveInteger(Number(shamir.shareCount), 'cohortBinding.sharding.shamir.shareCount', 2);
  if (shareCount !== n) {
    throw new Error(`Invalid cohort binding: Shamir shareCount ${shareCount} must equal RS n ${n}`);
  }
  if ((m % 2) !== 0) {
    throw new Error('Invalid cohort binding: RS parity must be even');
  }
  if (k >= n) {
    throw new Error('Invalid cohort binding: expected k < n');
  }

  const allowedFailures = m / 2;
  const expectedThreshold = k + allowedFailures;
  if (t !== expectedThreshold) {
    throw new Error(`Invalid cohort threshold: expected ${expectedThreshold}, got ${t}`);
  }

  const qenc = archiveState.qenc || {};
  const chunkSize = ensurePositiveInteger(Number(qenc.chunkSize), 'archiveState.qenc.chunkSize', 1);
  const chunkCount = ensurePositiveInteger(Number(qenc.chunkCount), 'archiveState.qenc.chunkCount', 1);
  const payloadLength = ensurePositiveInteger(Number(qenc.payloadLength), 'archiveState.qenc.payloadLength', 1);
  const containerId = String(qenc.containerId || '');
  if (containerId.length === 0) {
    throw new Error('Archive-state descriptor is missing qenc.containerId');
  }

  if (group.length < t) {
    throw new Error(`Need at least ${t} predecessor shards from one cohort, got ${group.length}`);
  }

  const base = group[0];
  if (!(base.keyCommit instanceof Uint8Array) || base.keyCommit.length !== KEY_COMMITMENT_LEN) {
    throw new Error('Predecessor shard is missing required key commitment');
  }

  const shardByIndex = new Map();
  for (const shard of group) {
    if (!Number.isInteger(shard.shardIndex) || shard.shardIndex < 0 || shard.shardIndex >= n) {
      throw new Error(`Invalid shardIndex ${shard.shardIndex}`);
    }
    if (shardByIndex.has(shard.shardIndex)) {
      throw new Error(`Duplicate shardIndex ${shard.shardIndex} detected`);
    }
    shardByIndex.set(shard.shardIndex, shard);

    ensureEqual(normalizeHexString(shard.metaJSON?.archiveId), candidate.archiveId, 'archiveId');
    ensureEqual(normalizeHexString(shard.metaJSON?.stateId), candidate.stateId, 'stateId');
    ensureEqual(normalizeHexString(shard.metaJSON?.cohortId), candidate.cohortId, 'cohortId');
    ensureEqual(shard.archiveStateDigestHex, candidate.archiveStateDigestHex, 'archiveStateDigest');
    ensureEqual(shard.cohortBindingDigestHex, candidate.cohortBindingDigestHex, 'cohortBindingDigest');
    ensureEqual(shard.archiveStateDigestHex, candidate.stateId, 'stateId');

    ensureEqual(shard.metaJSON?.containerId, containerId, 'containerId');
    ensureEqual(Number(shard.metaJSON?.n), n, 'n');
    ensureEqual(Number(shard.metaJSON?.k), k, 'k');
    ensureEqual(Number(shard.metaJSON?.m), m, 'm');
    ensureEqual(Number(shard.metaJSON?.t), t, 't');

    if (!bytesEqual(shard.archiveStateBytes, candidate.archiveStateBytes)) {
      throw new Error('Exact archive-state byte mismatch inside predecessor cohort');
    }
    if (!bytesEqual(shard.cohortBindingBytes, candidate.cohortBindingBytes)) {
      throw new Error('Exact cohort-binding byte mismatch inside predecessor cohort');
    }
    if (!bytesEqual(shard.encapsulatedKey, base.encapsulatedKey)) {
      throw new Error(`Shard header mismatch: encapsulatedKey differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.iv, base.iv)) {
      throw new Error(`Shard header mismatch: iv differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.salt, base.salt)) {
      throw new Error(`Shard header mismatch: salt differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.qencMetaBytes, base.qencMetaBytes)) {
      throw new Error(`Shard header mismatch: qenc metadata differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.keyCommit, base.keyCommit)) {
      throw new Error(`Shard header mismatch: key commitment differs for shard ${shard.shardIndex}`);
    }
  }

  const missingIndices = new Set();
  for (let i = 0; i < n; i += 1) {
    if (!shardByIndex.has(i)) missingIndices.add(i);
  }

  const qencMetaJSON = base.qencMetaJSON;
  assertArchiveStateMatchesQencMetadata(archiveState, qencMetaJSON);

  const ciphertextLength = ensurePositiveInteger(Number(base.metaJSON?.ciphertextLength), 'ciphertextLength', 1);
  for (const shard of group) {
    ensureEqual(Number(shard.metaJSON?.ciphertextLength), ciphertextLength, 'ciphertextLength');
    ensureEqual(Number(shard.metaJSON?.chunkCount), chunkCount, 'chunkCount');
    ensureEqual(Number(shard.metaJSON?.chunkSize), chunkSize, 'chunkSize');
  }

  const isPerChunkMode = qencMetaJSON.aead_mode === 'per-chunk-aead';
  if (!isPerChunkMode && qencMetaJSON.aead_mode !== 'single-container-aead') {
    throw new Error(`Unsupported AEAD mode: ${qencMetaJSON.aead_mode ?? 'unknown'}`);
  }

  const expectedCiphertextLength = isPerChunkMode
    ? (payloadLength + (16 * chunkCount))
    : ciphertextLength;
  if (isPerChunkMode && ciphertextLength !== expectedCiphertextLength) {
    throw new Error(`Ciphertext length mismatch for per-chunk mode (expected ${expectedCiphertextLength}, got ${ciphertextLength})`);
  }

  const encapHash = computeDigestHex(base.encapsulatedKey);
  if (normalizeHexString(base.metaJSON?.encapBlobHash) !== normalizeHexString(encapHash)) {
    throw new Error('encapBlobHash mismatch');
  }

  const shareCommitments = cohortBinding?.shareCommitments || null;
  const fragmentBodyHashes = cohortBinding?.shardBodyHashes || null;

  let validShareShards = group;
  const invalidShareIndices = new Set();
  if (Array.isArray(shareCommitments)) {
    if (shareCommitments.length !== n) {
      throw new Error('Invalid shareCommitments length');
    }
    validShareShards = [];
    for (const shard of group) {
      const expected = normalizeHexString(shareCommitments[shard.shardIndex]);
      const actual = normalizeHexString(computeDigestHex(shard.share));
      if (!expected || actual !== expected) {
        onWarn(`Share commitment verification failed for predecessor shard ${shard.shardIndex}. Share will be skipped.`);
        invalidShareIndices.add(shard.shardIndex);
        continue;
      }
      validShareShards.push(shard);
    }
    if (validShareShards.length < t) {
      throw new Error(`Not enough valid predecessor shards for Shamir reconstruction: need ${t}, have ${validShareShards.length}`);
    }
    onLog(invalidShareIndices.size > 0 ? `Predecessor share commitment failures: ${invalidShareIndices.size} shard(s) rejected.` : 'Predecessor share commitments verified.');
  }

  const corruptedShardIndices = new Set();
  if (Array.isArray(fragmentBodyHashes)) {
    if (fragmentBodyHashes.length !== n) {
      throw new Error('Invalid shardBodyHashes length');
    }
    for (const shard of group) {
      const expected = normalizeHexString(fragmentBodyHashes[shard.shardIndex]);
      const actual = normalizeHexString(computeDigestHex(shard.fragments));
      if (expected && actual !== expected) {
        onWarn(`Shard body hash verification failed for predecessor shard ${shard.shardIndex}. Treating as erasure.`);
        corruptedShardIndices.add(shard.shardIndex);
      }
    }
    if (corruptedShardIndices.size === 0) {
      onLog('Predecessor shard body hashes verified.');
    }
  }

  const totalBad = missingIndices.size + corruptedShardIndices.size;
  if (totalBad > allowedFailures) {
    throw new Error(`Too many missing/corrupted predecessor shards for RS reconstruction: allowed ${allowedFailures}, got ${totalBad}`);
  }

  const sortedShares = validShareShards.slice().sort((a, b) => a.shardIndex - b.shardIndex);
  const selectedShareCopies = sortedShares.slice(0, t).map((item) => item.share.slice());
  let shareCopiesCleared = false;
  let privKey = null;
  try {
    const { combineShares } = await import('../splitting/sss.js');
    privKey = await combineShares(selectedShareCopies);
  } finally {
    for (const share of selectedShareCopies) {
      share.fill(0);
    }
    shareCopiesCleared = selectedShareCopies.every((share) => share.every((value) => value === 0));
  }

  const rsEncodeBase = Number.isInteger(base.metaJSON?.rsEncodeBase) ? base.metaJSON.rsEncodeBase : 255;
  const cipherChunks = [];
  const shardOffsets = new Array(n).fill(0);

  for (let i = 0; i < chunkCount; i += 1) {
    const plainLen = Math.min(chunkSize, payloadLength - (i * chunkSize));
    const thisLen = isPerChunkMode ? (plainLen + 16) : ciphertextLength;

    const encodeSize = Math.floor(rsEncodeBase / n) * n;
    if (encodeSize === 0) throw new Error('RS parameters too large');
    const inputSize = (encodeSize * k) / n;
    const symbolSize = inputSize / k;
    const blocks = Math.ceil(thisLen / inputSize);
    const expectedFragLen = blocks * symbolSize;

    const encoded = new Array(n);
    for (let j = 0; j < n; j += 1) {
      const shard = shardByIndex.get(j);
      const fragStream = (shard && !corruptedShardIndices.has(j)) ? shard.fragments : null;
      if (!fragStream) {
        encoded[j] = new Uint8Array(expectedFragLen);
        continue;
      }

      const streamOffset = shardOffsets[j];
      if (streamOffset + 4 > fragStream.length) {
        throw new Error('Fragment stream underflow');
      }

      const dvFrag = new DataView(fragStream.buffer, fragStream.byteOffset + streamOffset);
      const fragLen = dvFrag.getUint32(0, false);
      const fragStart = streamOffset + 4;
      const fragEnd = fragStart + fragLen;
      if (fragEnd > fragStream.length) {
        throw new Error('Fragment length overflow');
      }

      let fragment = fragStream.subarray(fragStart, fragEnd);
      if (fragment.length < expectedFragLen) {
        const padded = new Uint8Array(expectedFragLen);
        padded.set(fragment);
        fragment = padded;
      } else if (fragment.length > expectedFragLen) {
        fragment = fragment.subarray(0, expectedFragLen);
      }

      encoded[j] = fragment;
      shardOffsets[j] = fragEnd;
    }

    let recombined;
    try {
      recombined = erasureRuntime.recombine(encoded, thisLen, k, m / 2, rsEncodeBase);
    } catch (error) {
      throw new Error(`RS recombination failed on chunk ${i}: ${error?.message ?? error}`);
    }

    cipherChunks.push(recombined);
    if (!isPerChunkMode) break;
  }

  for (let j = 0; j < n; j += 1) {
    if (corruptedShardIndices.has(j)) continue;
    const shard = shardByIndex.get(j);
    if (!shard) continue;
    if (shardOffsets[j] !== shard.fragments.length) {
      throw new Error(`Fragment stream has trailing or missing data in predecessor shard ${j}`);
    }
  }

  const ciphertext = isPerChunkMode
    ? (() => {
        const total = cipherChunks.reduce((sum, item) => sum + item.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const chunk of cipherChunks) {
          out.set(chunk, offset);
          offset += chunk.length;
        }
        return out;
      })()
    : cipherChunks[0];

  if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== ciphertextLength) {
    throw new Error('Reconstructed ciphertext length mismatch');
  }

  const header = buildQencHeader({
    encapsulatedKey: base.encapsulatedKey,
    containerNonce: base.iv,
    kdfSalt: base.salt,
    metaBytes: base.qencMetaBytes,
    keyCommitment: base.keyCommit,
  });

  const qencBytes = new Uint8Array(header.length + ciphertext.length);
  qencBytes.set(header, 0);
  qencBytes.set(ciphertext, header.length);

  const recoveredQencHash = normalizeHexString(computeDigestHex(qencBytes));
  const expectedQencHash = normalizeHexString(qenc.qencHash);
  if (recoveredQencHash !== expectedQencHash) {
    throw new Error('Reconstructed .qenc hash does not match predecessor archive-state descriptor');
  }

  const recoveredPrivHash = normalizeHexString(computeDigestHex(privKey));
  const privateKeyHash = normalizeHexString(base.metaJSON?.privateKeyHash || '');
  const privateKeyHashMatchesMetadata = privateKeyHash ? (privateKeyHash === recoveredPrivHash) : true;
  if (!privateKeyHashMatchesMetadata) {
    onWarn('Recovered predecessor secret key hash does not match predecessor shard metadata.');
  }

  return {
    qencBytes,
    privKey,
    invalidShareIndices: [...invalidShareIndices].sort((a, b) => a - b),
    corruptedShardIndices: [...corruptedShardIndices].sort((a, b) => a - b),
    missingShardIndices: [...missingIndices].sort((a, b) => a - b),
    privateKeyHashMatchesMetadata,
    shareCopiesCleared,
  };
}

function assertSameStatePreserved(predecessor, successorSplit) {
  if (!bytesEqual(predecessor.archiveStateBytes, successorSplit.archiveStateBytes)) {
    throw new Error('Same-state resharing must preserve exact archive-state descriptor bytes');
  }
  if (successorSplit.archiveId !== predecessor.archiveId) {
    throw new Error('Same-state resharing changed archiveId');
  }
  if (successorSplit.stateId !== predecessor.stateId) {
    throw new Error('Same-state resharing changed stateId');
  }

  const predecessorState = predecessor.archiveState;
  const successorState = successorSplit.archiveState;
  ensureEqual(successorState.qenc.qencHash, predecessorState.qenc.qencHash, 'qencHash');
  ensureEqual(successorState.qenc.containerId, predecessorState.qenc.containerId, 'containerId');
  ensureEqual(successorState.cryptoProfileId, predecessorState.cryptoProfileId, 'cryptoProfileId');
  ensureEqual(successorState.kdfTreeId, predecessorState.kdfTreeId, 'kdfTreeId');
  ensureEqual(successorState.noncePolicyId, predecessorState.noncePolicyId, 'noncePolicyId');
  ensureEqual(successorState.nonceMode, predecessorState.nonceMode, 'nonceMode');
  ensureEqual(successorState.counterBits, predecessorState.counterBits, 'counterBits');
  ensureEqual(successorState.maxChunkCount, predecessorState.maxChunkCount, 'maxChunkCount');
  ensureEqual(successorState.aadPolicyId, predecessorState.aadPolicyId, 'aadPolicyId');
  ensureEqual(
    normalizeHexString(JSON.stringify(successorState.authPolicyCommitment)),
    normalizeHexString(JSON.stringify(predecessorState.authPolicyCommitment)),
    'authPolicyCommitment'
  );
}

function validateNewMaintenanceArtifacts(newArtifacts, canonicalTransition) {
  const targetRef = `transition:sha3-512:${canonicalTransition.digest.value}`;
  const newSignatureIds = new Set();
  for (const signature of newArtifacts.maintenanceSignatures) {
    if (signature?.signatureFamily !== 'maintenance') {
      throw new Error('Same-state resharing accepts only maintenance detached signatures for new transition artifacts');
    }
    if (signature?.targetType !== 'transition-record') {
      throw new Error('New maintenance signatures must target transition-record bytes');
    }
    if (signature?.targetRef !== targetRef) {
      throw new Error('New maintenance signatures must target the newly emitted transition record');
    }
    if (
      signature?.targetDigest?.alg !== 'SHA3-512' ||
      normalizeHexString(signature?.targetDigest?.value) !== canonicalTransition.digest.value
    ) {
      throw new Error('New maintenance signatures must carry the newly emitted transition-record digest');
    }
    newSignatureIds.add(String(signature.id || ''));
  }

  for (const timestamp of newArtifacts.timestamps) {
    if (!newSignatureIds.has(String(timestamp?.targetRef || ''))) {
      throw new Error('New maintenance timestamps must reference one of the new maintenance signatures for this resharing event');
    }
  }
}

async function collectNewMaintenanceArtifacts(options, canonicalTransition) {
  const combined = {
    publicKeys: [],
    maintenanceSignatures: [],
    timestamps: [],
  };

  const sources = [];
  if (options.maintenanceArtifacts != null) {
    sources.push(options.maintenanceArtifacts);
  }
  if (typeof options.buildMaintenanceArtifacts === 'function') {
    sources.push(await options.buildMaintenanceArtifacts({
      transitionRecord: canonicalTransition.transitionRecord,
      transitionRecordBytes: canonicalTransition.bytes,
      transitionRecordDigest: canonicalTransition.digest,
      targetRef: `transition:sha3-512:${canonicalTransition.digest.value}`,
    }));
  }

  for (const source of sources) {
    if (source == null) continue;
    if (source.archiveApprovalSignatures || source.sourceEvidenceSignatures) {
      throw new Error('Same-state resharing maintenance artifacts must not add archive-approval or source-evidence signatures');
    }
    combined.publicKeys.push(...ensureReshareArray(source.publicKeys, 'maintenanceArtifacts.publicKeys'));
    combined.maintenanceSignatures.push(...ensureReshareArray(source.maintenanceSignatures, 'maintenanceArtifacts.maintenanceSignatures'));
    combined.timestamps.push(...ensureReshareArray(source.timestamps, 'maintenanceArtifacts.timestamps'));
  }

  validateNewMaintenanceArtifacts(combined, canonicalTransition);
  return combined;
}

function preparePredecessorShards(shards) {
  if (!Array.isArray(shards) || shards.length === 0) {
    throw new Error('No predecessor shards provided');
  }

  const prepared = [];
  for (let i = 0; i < shards.length; i += 1) {
    const shard = shards[i];
    if (shard?.diagnostics?.errors?.length) {
      throw new Error(`Predecessor shard parse failed at input index ${i}: ${shard.diagnostics.errors.join('; ')}`);
    }
    if (!isLifecycleParsedShard(shard)) {
      throw new Error('Same-state resharing requires parsed successor lifecycle shards');
    }
    prepared.push({
      ...shard,
      inputOrder: i,
      inputShardIndex: Number.isInteger(shard?.shardIndex) ? shard.shardIndex : i,
    });
  }
  return prepared;
}

function buildSuccessorShardBlob({
  metaJSON,
  archiveStateBytes,
  cohortBindingBytes,
  lifecycleBundleBytes,
  encapsulatedKey,
  containerNonce,
  kdfSalt,
  qencMetaBytes,
  keyCommitment,
  shardIndex,
  share,
  bodyBytes,
}) {
  const metaJSONBytes = new TextEncoder().encode(JSON.stringify(metaJSON));
  const metaLenBytes = new Uint8Array(2);
  new DataView(metaLenBytes.buffer).setUint16(0, metaJSONBytes.length, false);

  const archiveStateDigestBytes = sha3_512(archiveStateBytes);
  const archiveStateLenBytes = new Uint8Array(4);
  new DataView(archiveStateLenBytes.buffer).setUint32(0, archiveStateBytes.length, false);

  const cohortBindingDigestBytes = sha3_512(cohortBindingBytes);
  const cohortBindingLenBytes = new Uint8Array(4);
  new DataView(cohortBindingLenBytes.buffer).setUint32(0, cohortBindingBytes.length, false);

  const lifecycleBundleDigestBytes = sha3_512(lifecycleBundleBytes);
  const lifecycleBundleLenBytes = new Uint8Array(4);
  new DataView(lifecycleBundleLenBytes.buffer).setUint32(0, lifecycleBundleBytes.length, false);

  const encapLenBytes = new Uint8Array(4);
  new DataView(encapLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);

  const qencMetaLenBytes = new Uint8Array(2);
  new DataView(qencMetaLenBytes.buffer).setUint16(0, qencMetaBytes.length, false);

  const keyCommitLenByte = new Uint8Array([keyCommitment.length]);
  const shardIndexBytes = new Uint8Array(2);
  new DataView(shardIndexBytes.buffer).setUint16(0, shardIndex, false);
  const shareLenBytes = new Uint8Array(2);
  new DataView(shareLenBytes.buffer).setUint16(0, share.length, false);

  const magic = new TextEncoder().encode(LIFECYCLE_QCONT_MAGIC);
  const header = new Uint8Array(
    magic.length +
      2 +
      metaJSONBytes.length +
      4 +
      archiveStateBytes.length +
      archiveStateDigestBytes.length +
      4 +
      cohortBindingBytes.length +
      cohortBindingDigestBytes.length +
      4 +
      lifecycleBundleBytes.length +
      lifecycleBundleDigestBytes.length +
      4 +
      encapsulatedKey.length +
      12 +
      16 +
      2 +
      qencMetaBytes.length +
      1 +
      keyCommitment.length +
      2 +
      2 +
      share.length
  );

  let offset = 0;
  header.set(magic, offset); offset += magic.length;
  header.set(metaLenBytes, offset); offset += 2;
  header.set(metaJSONBytes, offset); offset += metaJSONBytes.length;
  header.set(archiveStateLenBytes, offset); offset += 4;
  header.set(archiveStateBytes, offset); offset += archiveStateBytes.length;
  header.set(archiveStateDigestBytes, offset); offset += archiveStateDigestBytes.length;
  header.set(cohortBindingLenBytes, offset); offset += 4;
  header.set(cohortBindingBytes, offset); offset += cohortBindingBytes.length;
  header.set(cohortBindingDigestBytes, offset); offset += cohortBindingDigestBytes.length;
  header.set(lifecycleBundleLenBytes, offset); offset += 4;
  header.set(lifecycleBundleBytes, offset); offset += lifecycleBundleBytes.length;
  header.set(lifecycleBundleDigestBytes, offset); offset += lifecycleBundleDigestBytes.length;
  header.set(encapLenBytes, offset); offset += 4;
  header.set(encapsulatedKey, offset); offset += encapsulatedKey.length;
  header.set(containerNonce, offset); offset += 12;
  header.set(kdfSalt, offset); offset += 16;
  header.set(qencMetaLenBytes, offset); offset += 2;
  header.set(qencMetaBytes, offset); offset += qencMetaBytes.length;
  header.set(keyCommitLenByte, offset); offset += 1;
  header.set(keyCommitment, offset); offset += keyCommitment.length;
  header.set(shardIndexBytes, offset); offset += 2;
  header.set(shareLenBytes, offset); offset += 2;
  header.set(share, offset);

  return new Blob([header, bodyBytes], { type: 'application/octet-stream' });
}

export async function buildLifecycleQcontShards(qencBytes, privKeyBytes, params, options = {}) {
  const authPolicyLevel = options.authPolicyLevel || DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL;
  const erasureRuntime = resolveErasureRuntime(options.erasureRuntime ?? options.erasure);

  const { n, k } = params;
  const m = n - k;
  if (k < 2 || n <= k) {
    throw new Error('Invalid RS parameters: require 2 <= k < n');
  }
  if ((m % 2) !== 0) {
    throw new Error('n-k must be even');
  }

  const {
    header,
    offset,
    encapsulatedKey,
    containerNonce,
    kdfSalt,
    metaBytes,
    metadata,
    storedKeyCommitment,
  } = parseQencHeader(qencBytes);
  const meta = metadata;
  const keyCommitment = storedKeyCommitment;
  const ciphertext = qencBytes.subarray(offset);
  if (!(keyCommitment instanceof Uint8Array) || keyCommitment.length !== KEY_COMMITMENT_LEN) {
    throw new Error('QENC container is missing required 32-byte key commitment.');
  }

  const ds = meta.domainStrings;
  if (
    !ds ||
    typeof ds.kdf !== 'string' ||
    typeof ds.iv !== 'string' ||
    typeof ds.kenc !== 'string' ||
    typeof ds.kiv !== 'string'
  ) {
    throw new Error('QENC metadata is missing valid domainStrings');
  }

  let trialSharedSecret;
  try {
    trialSharedSecret = await decapsulate(encapsulatedKey, privKeyBytes);
    const { Kraw, Kenc, Kiv } = await deriveKeyWithKmac(trialSharedSecret, kdfSalt, metaBytes, ds);
    const keyMatch = verifyKeyCommitment(Kenc, keyCommitment);
    clearKeys(trialSharedSecret, Kraw, Kenc, Kiv);
    if (!keyMatch) {
      throw new Error(
        'Secret key does not match this .qenc container (key commitment mismatch). ' +
        'Ensure you are using the correct secretKey.qkey for this container.'
      );
    }
  } catch (error) {
    if (trialSharedSecret instanceof Uint8Array) trialSharedSecret.fill(0);
    if (String(error?.message || error).includes('does not match')) throw error;
    throw new Error(`Key verification failed: ${error?.message || error}`);
  }

  const effectiveLength = meta.payloadLength || meta.originalLength;
  const containerId = computeDigestHex(header);
  const containerHash = computeDigestHex(qencBytes);

  const t = k + (m / 2);
  if (t > n) {
    throw new Error('Invalid threshold computed');
  }
  const { splitSecret } = await import('../splitting/sss.js');
  const shares = await splitSecret(privKeyBytes, n, t);
  const shareCommitments = shares.map((share) => computeDigestHex(share));

  const shardBuffers = Array.from({ length: n }, () => []);
  const chunkSize = meta.chunkSize;
  const isPerChunk = meta.aead_mode === 'per-chunk-aead';
  const totalChunks = isPerChunk ? (meta.chunkCount || Math.ceil(effectiveLength / chunkSize)) : 1;
  const nonceContract = getNonceContractForAeadMode(meta.aead_mode, DEFAULT_CRYPTO_PROFILE);

  const RS_MAX_CODEWORD = 255;
  let ctOffset = 0;
  let perFragmentSize = 0;
  for (let i = 0; i < totalChunks; i += 1) {
    let cipherChunk;
    if (isPerChunk) {
      const plainLen = Math.min(chunkSize, effectiveLength - (i * chunkSize));
      const encLen = plainLen + 16;
      cipherChunk = ciphertext.subarray(ctOffset, ctOffset + encLen);
      ctOffset += encLen;
    } else {
      cipherChunk = ciphertext;
    }

    const encodeSize = Math.floor(RS_MAX_CODEWORD / n) * n;
    if (encodeSize === 0) {
      throw new Error('RS parameters too large');
    }
    const inputSize = (encodeSize * k) / n;
    const padTarget = Math.ceil(cipherChunk.length / inputSize) * inputSize;
    let chunkForRS = cipherChunk;
    if (padTarget > cipherChunk.length) {
      const padded = new Uint8Array(padTarget);
      padded.set(cipherChunk);
      chunkForRS = padded;
    }

    const fragments = erasureRuntime.split(chunkForRS, k, m / 2, RS_MAX_CODEWORD);
    if (fragments.length !== n) {
      throw new Error('RS split returned unexpected number of fragments');
    }
    if (i === 0) {
      perFragmentSize = fragments[0].length;
    }
    for (let j = 0; j < fragments.length; j += 1) {
      const frag = fragments[j];
      const len32 = new Uint8Array(4);
      new DataView(len32.buffer).setUint32(0, frag.length, false);
      shardBuffers[j].push(len32, frag);
    }
  }

  const shardBodyBytesArr = [];
  const fragmentBodyHashes = [];
  for (let j = 0; j < n; j += 1) {
    const body = new Blob(shardBuffers[j]);
    const bodyBytes = new Uint8Array(await body.arrayBuffer());
    shardBodyBytesArr.push(bodyBytes);
    fragmentBodyHashes.push(computeDigestHex(bodyBytes));
  }

  const archiveId = options.archiveId
    ? String(options.archiveId)
    : generateArchiveId(options.archiveIdRandomBytes);

  const archiveState = buildArchiveStateDescriptor({
    archiveId,
    parentStateId: options.parentStateId ?? null,
    cryptoProfileId: meta.cryptoProfileId || DEFAULT_CRYPTO_PROFILE.cryptoProfileId,
    kdfTreeId: meta.kdfTreeId || DEFAULT_CRYPTO_PROFILE.kdfTreeId,
    noncePolicyId: meta.noncePolicyId || nonceContract.noncePolicyId,
    nonceMode: meta.nonceMode || nonceContract.nonceMode,
    counterBits: meta.counterBits ?? nonceContract.counterBits,
    maxChunkCount: meta.maxChunkCount ?? nonceContract.maxChunkCount,
    aadPolicyId: meta.aadPolicyId || DEFAULT_CRYPTO_PROFILE.aadPolicyId,
    chunkSize,
    chunkCount: totalChunks,
    payloadLength: meta.payloadLength || effectiveLength,
    qencHash: containerHash,
    containerId,
    authPolicy: {
      level: authPolicyLevel,
      minValidSignatures: options.minValidSignatures ?? 1,
    },
  });
  const canonicalArchiveState = canonicalizeArchiveStateDescriptor(archiveState);
  const stateId = canonicalArchiveState.stateId;

  const cohortBinding = buildCohortBinding({
    archiveId,
    stateId,
    shamirThreshold: t,
    shamirShareCount: n,
    rsN: n,
    rsK: k,
    rsParity: m,
    shardBodyHashes: fragmentBodyHashes,
    shareCommitments,
  });
  const canonicalCohortBinding = canonicalizeCohortBinding(cohortBinding);
  const cohortId = deriveCohortId({
    archiveId,
    stateId,
    cohortBindingDigest: canonicalCohortBinding.digest,
  });

  const lifecycleBundle = await buildLifecycleBundle({
    archiveState,
    currentCohortBinding: cohortBinding,
    authPolicy: {
      level: authPolicyLevel,
      minValidSignatures: options.minValidSignatures ?? 1,
    },
    sourceEvidence: [],
    transitions: [],
    attachments: {
      publicKeys: [],
      archiveApprovalSignatures: [],
      maintenanceSignatures: [],
      sourceEvidenceSignatures: [],
      timestamps: [],
    },
  });
  const canonicalLifecycleBundle = await canonicalizeLifecycleBundle(lifecycleBundle);

  const metaJSONBase = {
    artifactFamily: LIFECYCLE_ARTIFACT_FAMILY,
    archiveId,
    stateId,
    cohortId,
    alg: {
      KEM: 'ML-KEM-1024',
      KDF: 'KMAC256',
      AEAD: 'AES-256-GCM',
      RS: 'ErasureCodes',
      fmt: LIFECYCLE_QCONT_FORMAT_VERSION,
    },
    cryptoProfileId: meta.cryptoProfileId || DEFAULT_CRYPTO_PROFILE.cryptoProfileId,
    noncePolicyId: meta.noncePolicyId || nonceContract.noncePolicyId,
    nonceMode: meta.nonceMode || nonceContract.nonceMode,
    counterBits: meta.counterBits ?? nonceContract.counterBits,
    maxChunkCount: meta.maxChunkCount ?? nonceContract.maxChunkCount,
    aadPolicyId: meta.aadPolicyId || DEFAULT_CRYPTO_PROFILE.aadPolicyId,
    n,
    k,
    m,
    t,
    rsEncodeBase: RS_MAX_CODEWORD,
    chunkSize,
    chunkCount: totalChunks,
    containerId,
    containerHash,
    encapBlobHash: computeDigestHex(encapsulatedKey),
    privateKeyHash: computeDigestHex(privKeyBytes),
    payloadLength: meta.payloadLength || null,
    originalLength: effectiveLength,
    ciphertextLength: ciphertext.length,
    domainStrings: { kdf: ds.kdf, iv: ds.iv, kenc: ds.kenc, kiv: ds.kiv },
    fragmentFormat: 'len32-prefixed',
    perFragmentSize,
    hasKeyCommitment: true,
    keyCommitmentHex: toHex(keyCommitment),
  };

  const shards = [];
  for (let j = 0; j < n; j += 1) {
    const blob = buildSuccessorShardBlob({
      metaJSON: {
        ...metaJSONBase,
        shardIndex: j,
      },
      archiveStateBytes: canonicalArchiveState.bytes,
      cohortBindingBytes: canonicalCohortBinding.bytes,
      lifecycleBundleBytes: canonicalLifecycleBundle.bytes,
      encapsulatedKey,
      containerNonce,
      kdfSalt,
      qencMetaBytes: metaBytes,
      keyCommitment,
      shardIndex: j,
      share: shares[j],
      bodyBytes: shardBodyBytesArr[j],
    });
    shards.push({ blob, index: j });
  }

  return {
    shards,
    archiveId,
    stateId,
    cohortId,
    archiveState,
    archiveStateBytes: canonicalArchiveState.bytes,
    archiveStateDigestHex: canonicalArchiveState.digest.value,
    cohortBinding,
    cohortBindingBytes: canonicalCohortBinding.bytes,
    cohortBindingDigestHex: canonicalCohortBinding.digest.value,
    lifecycleBundle,
    lifecycleBundleBytes: canonicalLifecycleBundle.bytes,
    lifecycleBundleDigestHex: canonicalLifecycleBundle.digest.value,
    formatVersion: LIFECYCLE_QCONT_FORMAT_VERSION,
  };
}

export function rewriteLifecycleBundleInShard(shard, lifecycleBundleBytes) {
  if (!(lifecycleBundleBytes instanceof Uint8Array) || lifecycleBundleBytes.length === 0) {
    throw new Error('rewriteLifecycleBundleInShard requires canonical lifecycle-bundle bytes');
  }
  return {
    index: shard.shardIndex,
    shardIndex: shard.shardIndex,
    blob: buildSuccessorShardBlob({
      metaJSON: shard.metaJSON,
      archiveStateBytes: shard.archiveStateBytes,
      cohortBindingBytes: shard.cohortBindingBytes,
      lifecycleBundleBytes,
      encapsulatedKey: shard.encapsulatedKey,
      containerNonce: shard.iv,
      kdfSalt: shard.salt,
      qencMetaBytes: shard.qencMetaBytes,
      keyCommitment: shard.keyCommit,
      shardIndex: shard.shardIndex,
      share: shard.share,
      bodyBytes: shard.fragments,
    }),
  };
}

async function parseLifecycleShardUnsafe(arr) {
  if (!(arr instanceof Uint8Array)) {
    throw new Error('Shard must be a Uint8Array');
  }

  const minHeader = 4 + 2 + 4 + DIGEST_LEN + 4 + DIGEST_LEN + 4 + DIGEST_LEN + 4 + 12 + 16 + 2 + 1 + 2 + 2;
  if (arr.length < minHeader) {
    throw new Error('Shard is too small to contain a valid header');
  }

  const dv = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  let off = 0;

  const ensure = (need, reason) => {
    if (off + need > arr.length) {
      throw new Error(`Shard is truncated: ${reason}`);
    }
  };

  const readU8 = (reason) => {
    ensure(1, reason);
    const value = dv.getUint8(off);
    off += 1;
    return value;
  };

  const readU16 = (reason) => {
    ensure(2, reason);
    const value = dv.getUint16(off, false);
    off += 2;
    return value;
  };

  const readU32 = (reason) => {
    ensure(4, reason);
    const value = dv.getUint32(off, false);
    off += 4;
    return value;
  };

  const readBytes = (len, reason) => {
    ensure(len, reason);
    const out = arr.subarray(off, off + len);
    off += len;
    return out;
  };

  const magic = bytesToUtf8(readBytes(4, 'magic'));
  if (magic !== LIFECYCLE_QCONT_MAGIC) {
    throw new Error('Invalid .qcont magic');
  }

  const metaLen = readU16('metaLen');
  if (metaLen <= 0 || metaLen > MAX_META_LEN) {
    throw new Error('Invalid shard metadata length');
  }
  const metaBytes = readBytes(metaLen, 'metaJSON');
  const metaJSON = readJsonStrict(metaBytes, 'shard metadata JSON');
  if (metaJSON?.alg?.fmt !== LIFECYCLE_QCONT_FORMAT_VERSION) {
    throw new Error(
      `Unsupported shard format: expected ${LIFECYCLE_QCONT_FORMAT_VERSION}, got ${metaJSON?.alg?.fmt ?? 'unknown'}`
    );
  }
  if (metaJSON?.artifactFamily !== LIFECYCLE_ARTIFACT_FAMILY) {
    throw new Error(`Unsupported shard artifactFamily: ${metaJSON?.artifactFamily ?? 'unknown'}`);
  }

  const archiveStateLen = readU32('archive-state length');
  if (archiveStateLen <= 0 || archiveStateLen > MAX_ARTIFACT_LEN) {
    throw new Error('Invalid embedded archive-state length');
  }
  const archiveStateBytes = readBytes(archiveStateLen, 'archive-state bytes');
  const archiveStateDigestBytes = readBytes(DIGEST_LEN, 'archive-state digest');
  const computedArchiveStateDigestBytes = sha3_512(archiveStateBytes);
  if (!bytesEqual(archiveStateDigestBytes, computedArchiveStateDigestBytes)) {
    throw new Error('Embedded archive-state digest mismatch');
  }
  const archiveStateDigestHex = toHex(archiveStateDigestBytes);
  const parsedArchiveState = parseArchiveStateDescriptorBytes(archiveStateBytes);

  const cohortBindingLen = readU32('cohort-binding length');
  if (cohortBindingLen <= 0 || cohortBindingLen > MAX_ARTIFACT_LEN) {
    throw new Error('Invalid embedded cohort-binding length');
  }
  const cohortBindingBytes = readBytes(cohortBindingLen, 'cohort-binding bytes');
  const cohortBindingDigestBytes = readBytes(DIGEST_LEN, 'cohort-binding digest');
  const computedCohortBindingDigestBytes = sha3_512(cohortBindingBytes);
  if (!bytesEqual(cohortBindingDigestBytes, computedCohortBindingDigestBytes)) {
    throw new Error('Embedded cohort-binding digest mismatch');
  }
  const cohortBindingDigestHex = toHex(cohortBindingDigestBytes);
  const parsedCohortBinding = parseCohortBindingBytes(cohortBindingBytes);

  const lifecycleBundleLen = readU32('lifecycle-bundle length');
  if (lifecycleBundleLen <= 0 || lifecycleBundleLen > MAX_ARTIFACT_LEN) {
    throw new Error('Invalid embedded lifecycle-bundle length');
  }
  const lifecycleBundleBytes = readBytes(lifecycleBundleLen, 'lifecycle-bundle bytes');
  const lifecycleBundleDigestBytes = readBytes(DIGEST_LEN, 'lifecycle-bundle digest');
  const computedLifecycleBundleDigestBytes = sha3_512(lifecycleBundleBytes);
  if (!bytesEqual(lifecycleBundleDigestBytes, computedLifecycleBundleDigestBytes)) {
    throw new Error('Embedded lifecycle-bundle digest mismatch');
  }
  const lifecycleBundleDigestHex = toHex(lifecycleBundleDigestBytes);
  const parsedLifecycleBundle = await parseLifecycleBundleBytes(lifecycleBundleBytes);

  const encapLen = readU32('encapsulatedKey length');
  if (encapLen <= 0) {
    throw new Error('Invalid encapsulated key length');
  }
  const encapsulatedKey = readBytes(encapLen, 'encapsulatedKey');

  const iv = readBytes(12, 'container nonce');
  const salt = readBytes(16, 'kdf salt');

  const qencMetaLen = readU16('qenc metadata length');
  if (qencMetaLen <= 0 || qencMetaLen > MAX_META_LEN) {
    throw new Error('Invalid qenc metadata length');
  }
  const qencMetaBytes = readBytes(qencMetaLen, 'qenc metadata');
  const qencMetaJSON = readJsonStrict(qencMetaBytes, 'qenc metadata JSON');

  if (metaJSON?.hasKeyCommitment !== true) {
    throw new Error('Shard metadata must indicate hasKeyCommitment=true');
  }

  const keyCommitmentLen = readU8('key commitment length');
  if (keyCommitmentLen !== KEY_COMMITMENT_LEN) {
    throw new Error(`Invalid key commitment length: expected ${KEY_COMMITMENT_LEN}, got ${keyCommitmentLen}`);
  }
  const keyCommit = readBytes(keyCommitmentLen, 'key commitment');
  if (String(metaJSON?.keyCommitmentHex || '').toLowerCase() !== toHex(keyCommit)) {
    throw new Error('Shard metadata keyCommitmentHex mismatch');
  }

  const shardIndex = readU16('shard index');
  const shareLen = readU16('share length');
  if (shareLen <= 0) {
    throw new Error('Invalid Shamir share length');
  }
  const share = readBytes(shareLen, 'Shamir share');
  const fragments = arr.subarray(off);
  if (fragments.length === 0) {
    throw new Error('Shard fragment payload is empty');
  }

  const stateId = deriveStateId(parsedArchiveState.archiveState);
  if (archiveStateDigestHex !== stateId) {
    throw new Error('archive-state stateId/digest mismatch');
  }
  if (parsedCohortBinding.cohortBinding.archiveId !== parsedArchiveState.archiveState.archiveId) {
    throw new Error('Embedded archive-state/cohort-binding archiveId mismatch');
  }
  if (parsedCohortBinding.cohortBinding.stateId !== stateId) {
    throw new Error('Embedded archive-state/cohort-binding stateId mismatch');
  }
  const cohortId = deriveCohortId({
    archiveId: parsedArchiveState.archiveState.archiveId,
    stateId,
    cohortBindingDigest: parsedCohortBinding.digest,
  });
  const metadataArchiveId = requireLowercaseHexMetadata(metaJSON?.archiveId, 'archiveId', 64);
  const metadataStateId = requireLowercaseHexMetadata(metaJSON?.stateId, 'stateId', 128);
  const metadataCohortId = requireLowercaseHexMetadata(metaJSON?.cohortId, 'cohortId', 64);
  if (metadataArchiveId !== parsedArchiveState.archiveState.archiveId) {
    throw new Error('Shard metadata archiveId mismatch');
  }
  if (metadataStateId !== stateId) {
    throw new Error('Shard metadata stateId mismatch');
  }
  if (metadataCohortId !== cohortId) {
    throw new Error('Shard metadata cohortId mismatch');
  }
  if (Number(metaJSON?.shardIndex) !== shardIndex) {
    throw new Error('Shard metadata shardIndex mismatch');
  }
  if (parsedLifecycleBundle.lifecycleBundle.archiveStateDigest.value !== archiveStateDigestHex) {
    throw new Error('Embedded lifecycle-bundle archiveStateDigest mismatch');
  }
  if (parsedLifecycleBundle.lifecycleBundle.currentCohortBindingDigest.value !== cohortBindingDigestHex) {
    throw new Error('Embedded lifecycle-bundle currentCohortBindingDigest mismatch');
  }
  if (!bytesEqual(parsedLifecycleBundle.lifecycleBundleBytes ?? parsedLifecycleBundle.bytes, lifecycleBundleBytes)) {
    throw new Error('Embedded lifecycle-bundle canonical bytes mismatch');
  }

  return {
    metaJSON,
    metaBytes,
    archiveStateBytes,
    archiveStateDigestHex,
    archiveState: parsedArchiveState.archiveState,
    stateId,
    cohortBindingBytes,
    cohortBindingDigestHex,
    cohortBinding: parsedCohortBinding.cohortBinding,
    cohortId,
    lifecycleBundleBytes,
    lifecycleBundleDigestHex,
    lifecycleBundle: parsedLifecycleBundle.lifecycleBundle,
    encapsulatedKey,
    iv,
    salt,
    qencMetaBytes,
    qencMetaJSON,
    keyCommit,
    shardIndex,
    share,
    fragments,
    diagnostics: { errors: [], warnings: [] },
  };
}

export async function parseLifecycleShard(arr, options = {}) {
  const { strict = true } = options;
  try {
    return await parseLifecycleShardUnsafe(arr);
  } catch (error) {
    // Non-strict mode is diagnostics-only and must not be treated as a security boundary.
    if (strict) throw error;
    return {
      diagnostics: { errors: [error?.message || String(error)], warnings: [] },
    };
  }
}

export async function reshareSameState(predecessorShards, params, options = {}) {
  assertNoForbiddenReshareOverrides(params, options);

  const onLog = options.onLog || (() => {});
  const onWarn = options.onWarn || options.onError || (() => {});
  const erasureRuntime = resolveErasureRuntime(options.erasureRuntime ?? options.erasure);
  const prepared = preparePredecessorShards(predecessorShards);
  const predecessorCandidate = collectSinglePredecessorCohort(prepared);
  const predecessorBundleSelection = await selectPredecessorLifecycleBundle(predecessorCandidate, options);
  const predecessorLifecycleBundle = predecessorBundleSelection.lifecycleBundle;
  const targetParams = validateReshareTargetParams(params, predecessorCandidate.cohortBinding);

  const transitionOptions = options.transition || options.transitionRecord || {};
  let reconstructedPrivKey = null;
  let result = null;
  const zeroization = {
    attempted: false,
    privateKeyBytesCleared: false,
    shareCopiesCleared: false,
  };

  try {
    const reconstructed = await reconstructPredecessorMaterial(predecessorCandidate, {
      erasureRuntime,
      onLog,
      onWarn,
    });
    reconstructedPrivKey = reconstructed.privKey;
    zeroization.shareCopiesCleared = reconstructed.shareCopiesCleared === true;

    const successorSplit = await buildLifecycleQcontShards(
      reconstructed.qencBytes,
      reconstructedPrivKey,
      { n: targetParams.n, k: targetParams.k },
      {
        erasureRuntime,
        archiveId: predecessorCandidate.archiveId,
        parentStateId: predecessorCandidate.archiveState.parentStateId,
        authPolicyLevel: predecessorLifecycleBundle.authPolicy.level,
        minValidSignatures: predecessorLifecycleBundle.authPolicy.minValidSignatures,
      }
    );
    assertSameStatePreserved(predecessorCandidate, successorSplit);

    const transitionRecord = buildTransitionRecord({
      archiveId: predecessorCandidate.archiveId,
      fromStateId: predecessorCandidate.stateId,
      toStateId: successorSplit.stateId,
      fromCohortId: predecessorCandidate.cohortId,
      toCohortId: successorSplit.cohortId,
      fromCohortBindingDigest: { alg: 'SHA3-512', value: predecessorCandidate.cohortBindingDigestHex },
      toCohortBindingDigest: { alg: 'SHA3-512', value: successorSplit.cohortBindingDigestHex },
      reasonCode: transitionOptions.reasonCode || 'cohort-rotation',
      performedAt: transitionOptions.performedAt || new Date().toISOString(),
      operatorRole: transitionOptions.operatorRole || 'operator',
      actorHints: transitionOptions.actorHints || {},
      notes: transitionOptions.notes ?? null,
    });
    const canonicalTransition = canonicalizeTransitionRecord(transitionRecord);
    const newMaintenanceArtifacts = await collectNewMaintenanceArtifacts(options, canonicalTransition);

    const lifecycleBundle = await buildLifecycleBundle({
      archiveState: predecessorCandidate.archiveState,
      currentCohortBinding: successorSplit.cohortBinding,
      authPolicy: predecessorLifecycleBundle.authPolicy,
      sourceEvidence: predecessorLifecycleBundle.sourceEvidence,
      transitions: [...predecessorLifecycleBundle.transitions, transitionRecord],
      attachments: {
        publicKeys: [
          ...predecessorLifecycleBundle.attachments.publicKeys,
          ...newMaintenanceArtifacts.publicKeys,
        ],
        archiveApprovalSignatures: [
          ...predecessorLifecycleBundle.attachments.archiveApprovalSignatures,
        ],
        maintenanceSignatures: [
          ...predecessorLifecycleBundle.attachments.maintenanceSignatures,
          ...newMaintenanceArtifacts.maintenanceSignatures,
        ],
        sourceEvidenceSignatures: [
          ...predecessorLifecycleBundle.attachments.sourceEvidenceSignatures,
        ],
        timestamps: [
          ...predecessorLifecycleBundle.attachments.timestamps,
          ...newMaintenanceArtifacts.timestamps,
        ],
      },
    });
    const canonicalLifecycleBundle = await canonicalizeLifecycleBundle(lifecycleBundle);

    const parsedSuccessorBaseShards = await Promise.all(
      successorSplit.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob)))
    );
    const rewrittenShards = parsedSuccessorBaseShards.map((shard) => rewriteLifecycleBundleInShard(shard, canonicalLifecycleBundle.bytes));

    onLog(`Same-state resharing emitted successor cohort ${successorSplit.cohortId} with required transition record ${canonicalTransition.digest.value}.`);

    result = {
      shards: rewrittenShards,
      archiveId: predecessorCandidate.archiveId,
      stateId: predecessorCandidate.stateId,
      predecessorCohortId: predecessorCandidate.cohortId,
      predecessorCohortBindingDigestHex: predecessorCandidate.cohortBindingDigestHex,
      predecessorLifecycleBundle: predecessorLifecycleBundle,
      predecessorLifecycleBundleBytes: predecessorBundleSelection.lifecycleBundleBytes,
      predecessorLifecycleBundleDigestHex: predecessorBundleSelection.lifecycleBundleDigestHex,
      predecessorLifecycleBundleSource: predecessorBundleSelection.lifecycleBundleSource,
      archiveState: predecessorCandidate.archiveState,
      archiveStateBytes: predecessorCandidate.archiveStateBytes,
      archiveStateDigestHex: predecessorCandidate.archiveStateDigestHex,
      cohortBinding: successorSplit.cohortBinding,
      cohortBindingBytes: successorSplit.cohortBindingBytes,
      cohortBindingDigestHex: successorSplit.cohortBindingDigestHex,
      cohortId: successorSplit.cohortId,
      lifecycleBundle,
      lifecycleBundleBytes: canonicalLifecycleBundle.bytes,
      lifecycleBundleDigestHex: canonicalLifecycleBundle.digest.value,
      transitionRecord,
      transitionRecordBytes: canonicalTransition.bytes,
      transitionRecordDigestHex: canonicalTransition.digest.value,
      verificationReport: {
        invalidShareIndices: reconstructed.invalidShareIndices,
        corruptedShardIndices: reconstructed.corruptedShardIndices,
        missingShardIndices: reconstructed.missingShardIndices,
        privateKeyHashMatchesMetadata: reconstructed.privateKeyHashMatchesMetadata,
      },
      maintenanceSignatureCountAdded: newMaintenanceArtifacts.maintenanceSignatures.length,
      operationalWarnings: [...RESHARE_OPERATIONAL_WARNINGS],
      semantics: { ...RESHARE_SEMANTICS },
    };
  } finally {
    zeroization.attempted = true;
    if (reconstructedPrivKey instanceof Uint8Array) {
      reconstructedPrivKey.fill(0);
      zeroization.privateKeyBytesCleared = reconstructedPrivKey.every((value) => value === 0);
    } else {
      zeroization.privateKeyBytesCleared = true;
    }
  }

  return {
    ...result,
    zeroization,
  };
}
