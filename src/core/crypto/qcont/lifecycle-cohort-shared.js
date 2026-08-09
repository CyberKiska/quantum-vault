import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesEqual, toHex } from '../bytes.js';
import { clearKeys, deriveKeyWithKmac, verifyKeyCommitment } from '../kdf.js';
import {
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  deriveCohortId,
  parseArchiveStateDescriptorBytes,
  parseCohortBindingBytes,
  parseLifecycleBundleBytes,
  REED_SOLOMON_CODEC_ID,
  validateRuntimeSupportedCohortTuple,
} from '../lifecycle/artifacts.js';
import {
  decapsulate,
  ML_KEM_1024_ENCAPSULATED_KEY_SIZE,
  ML_KEM_1024_PRIVATE_KEY_SIZE,
} from '../mlkem.js';
import {
  buildQencHeader,
  MAX_QENC_METADATA_BYTES,
  parseQencHeader,
  parseQencMetadataBytes,
} from '../qenc/format.js';
import { combineSharesFromCopiedSlices } from './shamir-share-combine.js';
import { ensureEqual } from './validation.js';

const AES_GCM_TAG_SIZE = 16;
const RS_MAX_CODEWORD = 255;
const MAX_UINT32 = 0xffffffff;
export const MAX_RECONSTRUCTED_CIPHERTEXT_BYTES = (1024 * 1024 * 1024) + (1024 * 1024);
const CURRENT_SHAMIR_SHARE_BYTES = ML_KEM_1024_PRIVATE_KEY_SIZE + 1;

export function normalizeHexString(value) {
  return String(value || '').trim().toLowerCase();
}

function ensureSafeInteger(value, field, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function checkedAdd(left, right, field) {
  ensureSafeInteger(left, field, 0);
  ensureSafeInteger(right, field, 0);
  if (left > Number.MAX_SAFE_INTEGER - right) {
    throw new Error(`${field} overflow`);
  }
  return left + right;
}

function checkedMultiply(left, right, field) {
  ensureSafeInteger(left, field, 0);
  ensureSafeInteger(right, field, 0);
  if (left !== 0 && right > Math.floor(Number.MAX_SAFE_INTEGER / left)) {
    throw new Error(`${field} overflow`);
  }
  return left * right;
}

function allocateBytes(length, field) {
  ensureSafeInteger(length, field, 0);
  try {
    return new Uint8Array(length);
  } catch {
    throw new Error(`Unable to allocate ${field}`);
  }
}

function encryptedChunkLength(geometry, chunkIndex) {
  if (!geometry.isPerChunk) return geometry.ciphertextLength;
  const chunkStart = checkedMultiply(chunkIndex, geometry.chunkSize, 'QENC per-chunk offset');
  if (chunkStart >= geometry.payloadLength) {
    throw new Error('QENC per-chunk framing exceeds payloadLength');
  }
  const plainLength = Math.min(geometry.chunkSize, geometry.payloadLength - chunkStart);
  return checkedAdd(plainLength, AES_GCM_TAG_SIZE, 'QENC encrypted chunk length');
}

function expectedFragmentLength(cipherLength, n, k) {
  if (n <= 0 || k <= 0 || n > RS_MAX_CODEWORD) {
    throw new Error('RS parameters too large');
  }
  const encodeSize = checkedMultiply(Math.floor(RS_MAX_CODEWORD / n), n, 'RS encode layout');
  const scaledInputSize = checkedMultiply(encodeSize, k, 'RS input layout');
  const inputSize = scaledInputSize / n;
  const symbolSize = inputSize / k;
  if (
    encodeSize === 0 ||
    !Number.isSafeInteger(inputSize) ||
    inputSize <= 0 ||
    !Number.isSafeInteger(symbolSize) ||
    symbolSize <= 0
  ) {
    throw new Error('Invalid RS layout');
  }
  const blocks = Math.ceil(cipherLength / inputSize);
  const fragmentLength = checkedMultiply(blocks, symbolSize, 'RS fragment length');
  if (fragmentLength > MAX_UINT32) {
    throw new Error('RS fragment length exceeds len32 framing');
  }
  return fragmentLength;
}

function parseExactFragmentStream(bytes, geometry, n, k) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('Fragment stream must be Uint8Array');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fragments = [];
  let offset = 0;
  for (let chunkIndex = 0; chunkIndex < geometry.chunkCount; chunkIndex += 1) {
    const lengthEnd = checkedAdd(offset, 4, 'Fragment stream offset');
    if (lengthEnd > bytes.length) {
      throw new Error('Fragment stream underflow');
    }
    const fragmentLength = view.getUint32(offset, false);
    offset = lengthEnd;
    const fragmentEnd = checkedAdd(offset, fragmentLength, 'Fragment stream offset');
    if (fragmentEnd > bytes.length) {
      throw new Error('Fragment length overflow');
    }
    const expectedLength = expectedFragmentLength(encryptedChunkLength(geometry, chunkIndex), n, k);
    if (fragmentLength !== expectedLength) {
      throw new Error('Shard fragment length does not match authenticated RS layout');
    }
    fragments.push(bytes.subarray(offset, fragmentEnd));
    offset = fragmentEnd;
  }
  if (offset !== bytes.length) {
    throw new Error('Fragment stream has trailing data');
  }
  return fragments;
}

function expectedFragmentStreamLength(geometry, n, k) {
  let total = 0;
  for (let chunkIndex = 0; chunkIndex < geometry.chunkCount; chunkIndex += 1) {
    const fragmentLength = expectedFragmentLength(encryptedChunkLength(geometry, chunkIndex), n, k);
    total = checkedAdd(total, 4, 'Fragment stream length');
    total = checkedAdd(total, fragmentLength, 'Fragment stream length');
  }
  return total;
}

export function assertArchiveStateMatchesQencMetadata(archiveState, qencMetaJSON) {
  const qenc = archiveState.qenc || {};

  ensureEqual(qenc.hashAlg, 'SHA3-512', 'qenc.hashAlg');
  ensureEqual(qenc.primaryAnchor, 'qencHash', 'qenc.primaryAnchor');
  ensureEqual(qenc.containerIdRole, 'secondary-header-id', 'qenc.containerIdRole');
  ensureEqual(qenc.containerIdAlg, 'SHA3-512(qenc-header-bytes)', 'qenc.containerIdAlg');

  ensureEqual(qencMetaJSON.chunkSize, qenc.chunkSize, 'qenc.chunkSize');
  ensureEqual(qencMetaJSON.chunkCount, qenc.chunkCount, 'qenc.chunkCount');
  ensureEqual(qencMetaJSON.payloadLength, qenc.payloadLength, 'qenc.payloadLength');

  ensureEqual(qencMetaJSON.cryptoProfileId, archiveState.cryptoProfileId, 'cryptoProfileId');
  ensureEqual(qencMetaJSON.kdfTreeId, archiveState.kdfTreeId, 'kdfTreeId');
  ensureEqual(qencMetaJSON.noncePolicyId, archiveState.noncePolicyId, 'noncePolicyId');
  ensureEqual(qencMetaJSON.nonceMode, archiveState.nonceMode, 'nonceMode');
  ensureEqual(qencMetaJSON.counterBits, archiveState.counterBits, 'counterBits');
  ensureEqual(qencMetaJSON.maxChunkCount, archiveState.maxChunkCount, 'maxChunkCount');
  ensureEqual(qencMetaJSON.aadPolicyId, archiveState.aadPolicyId, 'aadPolicyId');
}

async function validateRecoveredMlKemPrivateKeyAgainstQencCommitment(base, privKey, options = {}) {
  const { messages = {}, keyValidationHooks = null } = options;
  const failureMessage = messages.recoveredPrivateKeyCommitmentFailure
    || 'Recovered ML-KEM secret key does not satisfy the embedded .qenc key commitment.';
  let sharedSecret = null;
  let Kenc = null;
  let Kiv = null;

  try {
    sharedSecret = await decapsulate(base.encapsulatedKey, privKey);
    ({ Kenc, Kiv } = await deriveKeyWithKmac(
      sharedSecret,
      base.salt,
      base.qencMetaBytes,
      base.qencMetaJSON.domainStrings,
      { includeAesKey: false }
    ));
    if (!verifyKeyCommitment(Kenc, base.keyCommit)) {
      throw new Error(failureMessage);
    }
    return true;
  } catch (error) {
    const detail = String(error?.message || error);
    if (detail === failureMessage) {
      throw error;
    }
    throw new Error(`${failureMessage} ${detail}`.trim());
  } finally {
    clearKeys(sharedSecret, Kenc, Kiv);
    if (typeof keyValidationHooks?.onFinally === 'function') {
      keyValidationHooks.onFinally({ sharedSecret, Kenc, Kiv });
    }
  }
}

/**
 * Insert one parsed successor lifecycle shard into a map of cohort groups keyed by
 * `${archiveId}:${stateId}:${cohortId}`. Used by restore (candidate cohorts) and
 * same-state resharing (predecessor cohort) with identical consistency checks.
 *
 * @param {Map<string, object>} byIdentity Cohort accumulator
 * @param {object} shard Parsed lifecycle shard
 * @param {{ groupLabel: string, missingIdentityMessage: string }} options
 */
export function mergeLifecycleShardIntoCohortGroups(byIdentity, shard, options) {
  const { groupLabel, missingIdentityMessage } = options;
  const parsedArchiveState = parseArchiveStateDescriptorBytes(shard?.archiveStateBytes);
  const parsedCohortBinding = parseCohortBindingBytes(shard?.cohortBindingBytes);
  const archiveId = normalizeHexString(parsedArchiveState.archiveState.archiveId);
  const stateId = normalizeHexString(parsedArchiveState.stateId);
  const cohortBindingDigestHex = normalizeHexString(parsedCohortBinding.digest.value);
  const cohortId = normalizeHexString(deriveCohortId({
    archiveId,
    stateId,
    cohortBindingDigest: parsedCohortBinding.digest,
  }));
  if (!archiveId || !stateId || !cohortId) {
    throw new Error(missingIdentityMessage);
  }
  if (normalizeHexString(shard?.archiveStateDigestHex) !== stateId) {
    throw new Error(`archive-state digest mismatch inside ${groupLabel}`);
  }
  if (normalizeHexString(shard?.cohortBindingDigestHex) !== cohortBindingDigestHex) {
    throw new Error(`cohort-binding digest mismatch inside ${groupLabel}`);
  }
  if (normalizeHexString(parsedCohortBinding.cohortBinding.archiveId) !== archiveId) {
    throw new Error(`cohort-binding archiveId mismatch inside ${groupLabel}`);
  }
  if (normalizeHexString(parsedCohortBinding.cohortBinding.stateId) !== stateId) {
    throw new Error(`cohort-binding stateId mismatch inside ${groupLabel}`);
  }
  if (
    normalizeHexString(shard?.metaJSON?.archiveId) !== archiveId ||
    normalizeHexString(shard?.metaJSON?.stateId) !== stateId ||
    normalizeHexString(shard?.metaJSON?.cohortId) !== cohortId
  ) {
    throw new Error(`Shard metadata identity mismatch inside ${groupLabel}`);
  }
  const key = `${archiveId}:${stateId}:${cohortId}`;
  if (!byIdentity.has(key)) {
    byIdentity.set(key, {
      key,
      archiveId,
      stateId,
      cohortId,
      archiveStateBytes: parsedArchiveState.bytes.slice(),
      archiveStateDigestHex: stateId,
      archiveState: parsedArchiveState.archiveState,
      cohortBindingBytes: parsedCohortBinding.bytes.slice(),
      cohortBindingDigestHex,
      cohortBinding: parsedCohortBinding.cohortBinding,
      embeddedLifecycleBundles: new Map(),
      shards: [],
    });
  }
  const entry = byIdentity.get(key);
  if (!bytesEqual(entry.archiveStateBytes, shard.archiveStateBytes)) {
    throw new Error(`Exact archive-state byte mismatch inside ${groupLabel} ${key}`);
  }
  if (!bytesEqual(entry.cohortBindingBytes, shard.cohortBindingBytes)) {
    throw new Error(`Exact cohort-binding byte mismatch inside ${groupLabel} ${key}`);
  }
  if (entry.archiveStateDigestHex !== normalizeHexString(shard.archiveStateDigestHex)) {
    throw new Error(`archive-state digest mismatch inside ${groupLabel} ${key}`);
  }
  if (entry.cohortBindingDigestHex !== normalizeHexString(shard.cohortBindingDigestHex)) {
    throw new Error(`cohort-binding digest mismatch inside ${groupLabel} ${key}`);
  }
  const lifecycleBundleDigestHex = toHex(sha3_512(shard.lifecycleBundleBytes));
  if (lifecycleBundleDigestHex !== normalizeHexString(shard.lifecycleBundleDigestHex)) {
    throw new Error(`Lifecycle-bundle digest mismatch inside ${groupLabel} ${key}`);
  }
  if (!entry.embeddedLifecycleBundles.has(lifecycleBundleDigestHex)) {
    entry.embeddedLifecycleBundles.set(lifecycleBundleDigestHex, {
      digestHex: lifecycleBundleDigestHex,
      bytes: shard.lifecycleBundleBytes.slice(),
    });
  }
  const bundleEntry = entry.embeddedLifecycleBundles.get(lifecycleBundleDigestHex);
  if (!bytesEqual(bundleEntry.bytes, shard.lifecycleBundleBytes)) {
    throw new Error(`Lifecycle-bundle bytes mismatch inside ${groupLabel} ${key} for digest ${lifecycleBundleDigestHex}`);
  }
  entry.shards.push(shard);
}

export async function rehydrateLifecycleBundleForCohort(candidate, bundleEntry, sourceLabel = 'lifecycle bundle') {
  if (!(bundleEntry?.bytes instanceof Uint8Array)) {
    throw new Error(`Missing canonical bytes for ${sourceLabel}`);
  }
  const parsedBundle = await parseLifecycleBundleBytes(bundleEntry.bytes);
  const digestHex = normalizeHexString(parsedBundle.digest.value);
  if (digestHex !== normalizeHexString(bundleEntry.digestHex)) {
    throw new Error(`${sourceLabel} digest does not match its canonical bytes`);
  }

  const canonicalArchiveState = canonicalizeArchiveStateDescriptor(parsedBundle.lifecycleBundle.archiveState);
  const canonicalCohortBinding = canonicalizeCohortBinding(parsedBundle.lifecycleBundle.currentCohortBinding);
  if (
    parsedBundle.lifecycleBundle.archiveStateDigest.value !== candidate.archiveStateDigestHex ||
    !bytesEqual(canonicalArchiveState.bytes, candidate.archiveStateBytes)
  ) {
    throw new Error(`${sourceLabel} does not match the selected archive-state bytes`);
  }
  if (
    parsedBundle.lifecycleBundle.currentCohortBindingDigest.value !== candidate.cohortBindingDigestHex ||
    !bytesEqual(canonicalCohortBinding.bytes, candidate.cohortBindingBytes)
  ) {
    throw new Error(`${sourceLabel} does not match the selected cohort-binding bytes`);
  }

  return {
    lifecycleBundle: parsedBundle.lifecycleBundle,
    lifecycleBundleBytes: parsedBundle.bytes,
    lifecycleBundleDigestHex: digestHex,
  };
}

export async function reconstructLifecycleCohortMaterial(candidate, options = {}) {
  const {
    erasureRuntime,
    onLog = () => {},
    onWarn = () => {},
    keyCommitmentLength = 32,
    digestHex,
    validateQencMeta = () => {},
    messages = {},
    keyValidationHooks = null,
    maxCiphertextBytes = MAX_RECONSTRUCTED_CIPHERTEXT_BYTES,
  } = options;

  if (typeof digestHex !== 'function') {
    throw new Error('reconstructLifecycleCohortMaterial requires digestHex');
  }
  if (!erasureRuntime || typeof erasureRuntime.recombine !== 'function') {
    throw new Error('reconstructLifecycleCohortMaterial requires an erasure runtime');
  }
  const ciphertextResourceLimit = ensureSafeInteger(
    maxCiphertextBytes,
    'maxCiphertextBytes',
    1
  );
  if (ciphertextResourceLimit > MAX_RECONSTRUCTED_CIPHERTEXT_BYTES) {
    throw new Error(
      `maxCiphertextBytes cannot exceed ${MAX_RECONSTRUCTED_CIPHERTEXT_BYTES}`
    );
  }

  const archiveState = candidate.archiveState;
  const cohortBinding = candidate.cohortBinding;
  const candidateShards = candidate.shards;
  if (!Array.isArray(candidateShards)) {
    throw new Error('Lifecycle cohort candidate is missing shards');
  }

  const shamir = cohortBinding?.sharding?.shamir || {};
  const reedSolomon = cohortBinding?.sharding?.reedSolomon || {};
  const n = ensureSafeInteger(reedSolomon.n, 'cohortBinding.sharding.reedSolomon.n', 2);
  const k = ensureSafeInteger(reedSolomon.k, 'cohortBinding.sharding.reedSolomon.k', 2);
  const m = ensureSafeInteger(reedSolomon.parity, 'cohortBinding.sharding.reedSolomon.parity', 0);
  const t = ensureSafeInteger(shamir.threshold, 'cohortBinding.sharding.shamir.threshold', 2);
  const shareCount = ensureSafeInteger(shamir.shareCount, 'cohortBinding.sharding.shamir.shareCount', 2);
  const supportedTuple = validateRuntimeSupportedCohortTuple({
    n,
    k,
    parity: m,
    threshold: t,
    shareCount,
    codecId: String(reedSolomon.codecId || REED_SOLOMON_CODEC_ID),
  });
  const allowedFailures = supportedTuple.allowedFailures;
  if (candidateShards.length > n) {
    throw new Error(`Lifecycle cohort has more shard inputs than its committed n=${n}`);
  }
  const group = candidateShards.slice();

  const qenc = archiveState.qenc || {};
  const containerId = normalizeHexString(qenc.containerId);
  if (!/^[0-9a-f]{128}$/.test(containerId)) {
    throw new Error('Archive-state descriptor is missing qenc.containerId');
  }
  const expectedQencHash = normalizeHexString(qenc.qencHash);
  if (!/^[0-9a-f]{128}$/.test(expectedQencHash)) {
    throw new Error('Archive-state descriptor is missing qenc.qencHash');
  }

  if (group.length < t) {
    throw new Error(messages.needThreshold ? messages.needThreshold(t, group.length) : `Need at least ${t} matching shards, got ${group.length}`);
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

    if (!bytesEqual(shard.archiveStateBytes, candidate.archiveStateBytes)) {
      throw new Error(messages.archiveStateMismatch || 'Exact archive-state byte mismatch inside lifecycle cohort');
    }
    if (!bytesEqual(shard.cohortBindingBytes, candidate.cohortBindingBytes)) {
      throw new Error(messages.cohortBindingMismatch || 'Exact cohort-binding byte mismatch inside lifecycle cohort');
    }
  }

  const missingIndices = new Set();
  for (let i = 0; i < n; i += 1) {
    if (!shardByIndex.has(i)) missingIndices.add(i);
  }

  // Header copies are outside the shard-body commitment. Snapshot and accept
  // only a copy whose exact QENC header bytes satisfy the archive-state anchor.
  let selectedHeader = null;
  let firstHeaderError = null;
  const ignoredQencHeaderIndices = new Set();
  for (const shard of group) {
    try {
      if (!(shard.keyCommit instanceof Uint8Array) || shard.keyCommit.length !== keyCommitmentLength) {
        throw new Error(messages.missingKeyCommitment || 'Lifecycle shard is missing required key commitment');
      }
      if (
        !(shard.encapsulatedKey instanceof Uint8Array) ||
        shard.encapsulatedKey.length !== ML_KEM_1024_ENCAPSULATED_KEY_SIZE
      ) {
        throw new Error('Lifecycle shard has an invalid ML-KEM-1024 encapsulated key length');
      }
      if (!(shard.iv instanceof Uint8Array) || shard.iv.length !== 12) {
        throw new Error('Lifecycle shard has an invalid QENC nonce length');
      }
      if (!(shard.salt instanceof Uint8Array) || shard.salt.length !== 16) {
        throw new Error('Lifecycle shard has an invalid QENC salt length');
      }
      if (
        !(shard.qencMetaBytes instanceof Uint8Array) ||
        shard.qencMetaBytes.length <= 0 ||
        shard.qencMetaBytes.length > MAX_QENC_METADATA_BYTES
      ) {
        throw new Error('Lifecycle shard has an invalid QENC metadata length');
      }
      const material = {
        encapsulatedKey: shard.encapsulatedKey.slice(),
        iv: shard.iv.slice(),
        salt: shard.salt.slice(),
        qencMetaBytes: shard.qencMetaBytes.slice(),
        keyCommit: shard.keyCommit.slice(),
      };
      const header = buildQencHeader({
        encapsulatedKey: material.encapsulatedKey,
        containerNonce: material.iv,
        kdfSalt: material.salt,
        metaBytes: material.qencMetaBytes,
        keyCommitment: material.keyCommit,
      });
      const recoveredContainerId = normalizeHexString(await digestHex(header.slice()));
      if (recoveredContainerId !== containerId) {
        throw new Error('QENC header does not match archive-state containerId');
      }

      const parsedMetadata = parseQencMetadataBytes(material.qencMetaBytes);
      const qencMetaJSON = parsedMetadata.metadata;
      const geometry = parsedMetadata.geometry;
      Object.freeze(qencMetaJSON.domainStrings);
      Object.freeze(qencMetaJSON);
      assertArchiveStateMatchesQencMetadata(archiveState, qencMetaJSON);
      await validateQencMeta(archiveState, qencMetaJSON);

      const validated = {
        shard,
        header,
        qencMetaJSON,
        geometry,
        ...material,
      };
      if (selectedHeader && !bytesEqual(selectedHeader.header, validated.header)) {
        throw new Error('Ambiguous QENC header bytes share the committed containerId');
      }
      if (!selectedHeader) selectedHeader = validated;
    } catch (error) {
      if (String(error?.message || error).startsWith('Ambiguous QENC header bytes')) {
        throw error;
      }
      if (firstHeaderError == null) firstHeaderError = String(error?.message || error);
      ignoredQencHeaderIndices.add(shard.shardIndex);
      onWarn(
        messages.qencHeaderIgnored
          ? messages.qencHeaderIgnored(shard.shardIndex)
          : `Shard ${shard.shardIndex} carries QENC header fields that do not match the committed archive state; those header fields were ignored.`
      );
    }
  }
  if (!selectedHeader) {
    const detail = firstHeaderError ? `: ${firstHeaderError}` : '';
    throw new Error(`No shard carries a supported QENC header matching archive-state containerId${detail}`);
  }

  const base = {
    ...selectedHeader.shard,
    encapsulatedKey: selectedHeader.encapsulatedKey,
    iv: selectedHeader.iv,
    salt: selectedHeader.salt,
    qencMetaBytes: selectedHeader.qencMetaBytes,
    qencMetaJSON: selectedHeader.qencMetaJSON,
    keyCommit: selectedHeader.keyCommit,
  };
  const geometry = selectedHeader.geometry;
  const {
    chunkSize,
    chunkCount,
    payloadLength,
    ciphertextLength,
  } = geometry;
  if (ciphertextLength > ciphertextResourceLimit) {
    throw new Error(
      `Authenticated QENC ciphertext length ${ciphertextLength} exceeds reconstruction limit ${ciphertextResourceLimit}`
    );
  }
  const expectedFragmentStreamBytes = expectedFragmentStreamLength(geometry, n, k);

  const selectedEncapHash = normalizeHexString(await digestHex(base.encapsulatedKey));
  for (const shard of group) {
    const redundantNumbers = [
      ['n', n],
      ['k', k],
      ['m', m],
      ['t', t],
      ['chunkCount', chunkCount],
      ['chunkSize', chunkSize],
      ['payloadLength', payloadLength],
      ['ciphertextLength', ciphertextLength],
      ['rsEncodeBase', RS_MAX_CODEWORD],
    ];
    let mismatch = redundantNumbers.some(([field, expected]) => shard.metaJSON?.[field] !== expected);
    mismatch ||= normalizeHexString(shard.metaJSON?.containerId) !== containerId;
    mismatch ||= normalizeHexString(shard.metaJSON?.containerHash) !== expectedQencHash;
    mismatch ||= normalizeHexString(shard.metaJSON?.encapBlobHash) !== selectedEncapHash;
    if (mismatch) {
      onWarn(
        messages.redundantMetadataMismatch
          ? messages.redundantMetadataMismatch(shard.shardIndex)
          : `Shard ${shard.shardIndex} has inconsistent unauthenticated redundant metadata; committed archive-state/QENC geometry was used instead.`
      );
    }
  }

  const shareCommitments = cohortBinding?.shareCommitments || null;
  const fragmentBodyHashes = cohortBinding?.shardBodyHashes || null;
  if (!Array.isArray(shareCommitments) || shareCommitments.length !== n) {
    throw new Error('Invalid shareCommitments length');
  }
  if (!Array.isArray(fragmentBodyHashes) || fragmentBodyHashes.length !== n) {
    throw new Error('Invalid shardBodyHashes length');
  }

  const validShareShards = [];
  const invalidShareIndices = new Set();
  for (const shard of group) {
    if (!(shard.share instanceof Uint8Array) || shard.share.length !== CURRENT_SHAMIR_SHARE_BYTES) {
      onWarn(messages.shareLayoutFailure ? messages.shareLayoutFailure(shard.shardIndex) : `Share validation failed for shard ${shard.shardIndex}. Share will be skipped.`);
      invalidShareIndices.add(shard.shardIndex);
      continue;
    }
    const expected = normalizeHexString(shareCommitments[shard.shardIndex]);
    const actual = normalizeHexString(await digestHex(shard.share));
    if (!expected || actual !== expected) {
      onWarn(messages.shareCommitmentFailure ? messages.shareCommitmentFailure(shard.shardIndex) : `Share commitment verification failed for shard ${shard.shardIndex}. Share will be skipped.`);
      invalidShareIndices.add(shard.shardIndex);
      continue;
    }
    validShareShards.push(shard);
  }
  if (validShareShards.length < t) {
    throw new Error(messages.notEnoughValidShares ? messages.notEnoughValidShares(t, validShareShards.length) : `Not enough valid shards for Shamir reconstruction: need ${t}, have ${validShareShards.length}`);
  }
  if (invalidShareIndices.size > 0) {
    onLog(messages.shareCommitmentSummary ? messages.shareCommitmentSummary(invalidShareIndices.size) : `Share commitment failures: ${invalidShareIndices.size} shard(s) rejected.`);
  } else if (messages.shareCommitmentVerified) {
    onLog(messages.shareCommitmentVerified);
  }

  const corruptedShardIndices = new Set();
  const validFragmentsByIndex = new Map();
  for (const shard of group) {
    if (!(shard.fragments instanceof Uint8Array) || shard.fragments.length !== expectedFragmentStreamBytes) {
      onWarn(
        messages.fragmentLayoutFailure
          ? messages.fragmentLayoutFailure(shard.shardIndex)
          : `Fragment layout validation failed for shard ${shard.shardIndex}. Treating as erasure.`
      );
      corruptedShardIndices.add(shard.shardIndex);
      continue;
    }
    const expected = normalizeHexString(fragmentBodyHashes[shard.shardIndex]);
    const actual = normalizeHexString(await digestHex(shard.fragments));
    if (!expected || actual !== expected) {
      onWarn(messages.shardBodyFailure ? messages.shardBodyFailure(shard.shardIndex) : `Fragment integrity check failed for shard ${shard.shardIndex}. Treating as erasure.`);
      corruptedShardIndices.add(shard.shardIndex);
      continue;
    }
    try {
      validFragmentsByIndex.set(
        shard.shardIndex,
        parseExactFragmentStream(shard.fragments, geometry, n, k)
      );
    } catch {
      onWarn(
        messages.fragmentLayoutFailure
          ? messages.fragmentLayoutFailure(shard.shardIndex)
          : `Fragment layout validation failed for shard ${shard.shardIndex}. Treating as erasure.`
      );
      corruptedShardIndices.add(shard.shardIndex);
    }
  }
  if (corruptedShardIndices.size === 0 && messages.shardBodyVerified) {
    onLog(messages.shardBodyVerified);
  }

  const totalBad = n - validFragmentsByIndex.size;
  if (totalBad > allowedFailures) {
    throw new Error(messages.tooManyMissingCorrupted ? messages.tooManyMissingCorrupted(allowedFailures, totalBad) : `Too many missing/corrupted shards for RS reconstruction: allowed ${allowedFailures}, got ${totalBad}`);
  }

  const sortedShares = validShareShards.slice().sort((a, b) => a.shardIndex - b.shardIndex);
  const { secret: privKey, shareCopiesCleared } = await combineSharesFromCopiedSlices(sortedShares, t);
  let materialReturned = false;
  let qencBytes = null;
  try {
    const recoveredKeyCommitmentValidated = await validateRecoveredMlKemPrivateKeyAgainstQencCommitment(base, privKey, {
      messages,
      keyValidationHooks,
    });

    const qencLength = checkedAdd(
      selectedHeader.header.length,
      ciphertextLength,
      'Reconstructed QENC length'
    );
    qencBytes = allocateBytes(qencLength, 'reconstructed QENC');
    qencBytes.set(selectedHeader.header, 0);
    let ciphertextOffset = 0;
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
      const thisLength = encryptedChunkLength(geometry, chunkIndex);
      const expectedFragLength = expectedFragmentLength(thisLength, n, k);
      const encoded = new Array(n);
      const zeroErasureFragment = validFragmentsByIndex.size < n
        ? allocateBytes(expectedFragLength, 'RS erasure fragment')
        : null;
      for (let shardIndex = 0; shardIndex < n; shardIndex += 1) {
        const fragments = validFragmentsByIndex.get(shardIndex);
        if (!fragments) {
          // The integrity-pinned vendored runtime reads encoded fragments but
          // does not mutate them. Reusing one zero view keeps scratch memory
          // bounded to one fragment per chunk; final qencHash remains the
          // fail-closed check for injected runtimes.
          encoded[shardIndex] = zeroErasureFragment;
          continue;
        }
        const fragment = fragments[chunkIndex];
        if (!(fragment instanceof Uint8Array) || fragment.length !== expectedFragLength) {
          throw new Error('Shard fragment length changed after validation');
        }
        encoded[shardIndex] = fragment;
      }

      let recombined;
      try {
        recombined = erasureRuntime.recombine(
          encoded,
          thisLength,
          k,
          allowedFailures,
          RS_MAX_CODEWORD
        );
      } catch (error) {
        throw new Error(`RS recombination failed on chunk ${chunkIndex}: ${error?.message ?? error}`);
      }
      if (!(recombined instanceof Uint8Array) || recombined.length !== thisLength) {
        throw new Error(`RS recombination returned an invalid chunk on chunk ${chunkIndex}`);
      }
      const chunkEnd = checkedAdd(ciphertextOffset, recombined.length, 'Reconstructed ciphertext offset');
      if (chunkEnd > ciphertextLength) {
        throw new Error('RS recombination exceeded authenticated ciphertext geometry');
      }
      const outputOffset = checkedAdd(
        selectedHeader.header.length,
        ciphertextOffset,
        'Reconstructed QENC write offset'
      );
      qencBytes.set(recombined, outputOffset);
      ciphertextOffset = chunkEnd;
    }
    if (ciphertextOffset !== ciphertextLength) {
      throw new Error('Reconstructed ciphertext length mismatch');
    }

    const header = buildQencHeader({
      encapsulatedKey: base.encapsulatedKey,
      containerNonce: base.iv,
      kdfSalt: base.salt,
      metaBytes: base.qencMetaBytes,
      keyCommitment: base.keyCommit,
    });
    if (!bytesEqual(header, selectedHeader.header)) {
      throw new Error('Rebuilt QENC header changed after committed-header validation');
    }
    if (!bytesEqual(qencBytes.subarray(0, header.length), header)) {
      throw new Error('Reconstructed QENC header bytes changed before final validation');
    }

    const parsedRecovered = parseQencHeader(qencBytes);
    if (!bytesEqual(parsedRecovered.header, selectedHeader.header)) {
      throw new Error('Strictly parsed reconstructed QENC header does not match selected header');
    }
    const recoveredContainerId = normalizeHexString(await digestHex(parsedRecovered.header));
    if (recoveredContainerId !== containerId) {
      throw new Error('Reconstructed .qenc header hash does not match archive-state containerId');
    }
    const recoveredQencHash = normalizeHexString(await digestHex(qencBytes));
    if (recoveredQencHash !== expectedQencHash) {
      throw new Error(messages.qencHashMismatch || 'Reconstructed .qenc hash does not match archive-state descriptor');
    }

    const recoveredPrivHash = normalizeHexString(await digestHex(privKey));
    const privateKeyHash = normalizeHexString(base.metaJSON?.privateKeyHash || '');
    const privateKeyHashMatchesMetadata = group.every((shard) => {
      const expected = normalizeHexString(shard.metaJSON?.privateKeyHash || '');
      return !expected || expected === recoveredPrivHash;
    });
    if (!privateKeyHashMatchesMetadata && messages.privateKeyHashMismatch) {
      onWarn(messages.privateKeyHashMismatch);
    }

    const result = {
      qencBytes,
      privKey,
      ignoredQencHeaderIndices: [...ignoredQencHeaderIndices].sort((a, b) => a - b),
      invalidShareIndices: [...invalidShareIndices].sort((a, b) => a - b),
      corruptedShardIndices: [...corruptedShardIndices].sort((a, b) => a - b),
      missingShardIndices: [...missingIndices].sort((a, b) => a - b),
      recoveredKeyCommitmentValidated,
      privateKeyHashMatchesMetadata,
      shareCopiesCleared,
    };
    materialReturned = true;
    return result;
  } finally {
    if (!materialReturned) {
      clearKeys(privKey, qencBytes);
    }
  }
}
