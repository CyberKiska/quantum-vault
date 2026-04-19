import { bytesEqual } from '../bytes.js';
import { clearKeys, deriveKeyWithKmac, verifyKeyCommitment } from '../kdf.js';
import { REED_SOLOMON_CODEC_ID, validateRuntimeSupportedCohortTuple } from '../lifecycle/artifacts.js';
import { decapsulate } from '../mlkem.js';
import { buildQencHeader } from '../qenc/format.js';
import { combineSharesFromCopiedSlices } from './shamir-share-combine.js';

export function normalizeHexString(value) {
  return String(value || '').trim().toLowerCase();
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

export function assertArchiveStateMatchesQencMetadata(archiveState, qencMetaJSON) {
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

async function validateRecoveredMlKemPrivateKeyAgainstQencCommitment(base, privKey, options = {}) {
  const { messages = {}, keyValidationHooks = null } = options;
  const failureMessage = messages.recoveredPrivateKeyCommitmentFailure
    || 'Recovered ML-KEM secret key does not satisfy the embedded .qenc key commitment.';
  let sharedSecret = null;
  let Kraw = null;
  let Kenc = null;
  let Kiv = null;

  try {
    sharedSecret = await decapsulate(base.encapsulatedKey, privKey);
    ({ Kraw, Kenc, Kiv } = await deriveKeyWithKmac(
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
    clearKeys(sharedSecret, Kraw, Kenc, Kiv);
    if (typeof keyValidationHooks?.onFinally === 'function') {
      keyValidationHooks.onFinally({ sharedSecret, Kraw, Kenc, Kiv });
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
  const archiveId = normalizeHexString(shard?.archiveState?.archiveId || shard?.metaJSON?.archiveId);
  const stateId = normalizeHexString(shard?.stateId || shard?.metaJSON?.stateId);
  const cohortId = normalizeHexString(shard?.cohortId || shard?.metaJSON?.cohortId);
  if (!archiveId || !stateId || !cohortId) {
    throw new Error(missingIdentityMessage);
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
  if (archiveId !== normalizeHexString(shard?.metaJSON?.archiveId || shard?.archiveState?.archiveId)) {
    throw new Error(`Mixed archiveId values detected inside ${groupLabel} ${key}`);
  }
  if (stateId !== normalizeHexString(shard?.metaJSON?.stateId || shard?.stateId)) {
    throw new Error(`Mixed stateId values detected inside ${groupLabel} ${key}`);
  }
  if (cohortId !== normalizeHexString(shard?.metaJSON?.cohortId || shard?.cohortId)) {
    throw new Error(`Mixed cohortId values detected inside ${groupLabel} ${key}`);
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
    throw new Error(`Lifecycle-bundle bytes mismatch inside ${groupLabel} ${key} for digest ${lifecycleBundleDigestHex}`);
  }
  entry.shards.push(shard);
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
  } = options;

  if (typeof digestHex !== 'function') {
    throw new Error('reconstructLifecycleCohortMaterial requires digestHex');
  }

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
  const supportedTuple = validateRuntimeSupportedCohortTuple({
    n,
    k,
    parity: m,
    threshold: t,
    shareCount,
    codecId: String(reedSolomon.codecId || REED_SOLOMON_CODEC_ID),
  });
  const allowedFailures = supportedTuple.allowedFailures;

  const qenc = archiveState.qenc || {};
  const chunkSize = ensurePositiveInteger(Number(qenc.chunkSize), 'archiveState.qenc.chunkSize', 1);
  const chunkCount = ensurePositiveInteger(Number(qenc.chunkCount), 'archiveState.qenc.chunkCount', 1);
  const payloadLength = ensurePositiveInteger(Number(qenc.payloadLength), 'archiveState.qenc.payloadLength', 1);
  const containerId = String(qenc.containerId || '');
  if (containerId.length === 0) {
    throw new Error('Archive-state descriptor is missing qenc.containerId');
  }

  if (group.length < t) {
    throw new Error(messages.needThreshold ? messages.needThreshold(t, group.length) : `Need at least ${t} matching shards, got ${group.length}`);
  }

  const base = group[0];
  if (!(base.keyCommit instanceof Uint8Array) || base.keyCommit.length !== keyCommitmentLength) {
    throw new Error(messages.missingKeyCommitment || 'Lifecycle shard is missing required key commitment');
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
      throw new Error(messages.archiveStateMismatch || 'Exact archive-state byte mismatch inside lifecycle cohort');
    }
    if (!bytesEqual(shard.cohortBindingBytes, candidate.cohortBindingBytes)) {
      throw new Error(messages.cohortBindingMismatch || 'Exact cohort-binding byte mismatch inside lifecycle cohort');
    }
    if (!bytesEqual(shard.encapsulatedKey, base.encapsulatedKey)) {
      throw new Error(messages.headerMismatch ? messages.headerMismatch('encapsulatedKey', shard.shardIndex) : `Shard header mismatch: encapsulatedKey differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.iv, base.iv)) {
      throw new Error(messages.headerMismatch ? messages.headerMismatch('iv', shard.shardIndex) : `Shard header mismatch: iv differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.salt, base.salt)) {
      throw new Error(messages.headerMismatch ? messages.headerMismatch('salt', shard.shardIndex) : `Shard header mismatch: salt differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.qencMetaBytes, base.qencMetaBytes)) {
      throw new Error(messages.headerMismatch ? messages.headerMismatch('qenc metadata', shard.shardIndex) : `Shard header mismatch: qenc metadata differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.keyCommit, base.keyCommit)) {
      throw new Error(messages.headerMismatch ? messages.headerMismatch('key commitment', shard.shardIndex) : `Shard header mismatch: key commitment differs for shard ${shard.shardIndex}`);
    }
  }

  const missingIndices = new Set();
  for (let i = 0; i < n; i += 1) {
    if (!shardByIndex.has(i)) missingIndices.add(i);
  }

  const qencMetaJSON = base.qencMetaJSON;
  validateQencMeta(archiveState, qencMetaJSON);

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

  const encapHash = normalizeHexString(await digestHex(base.encapsulatedKey));
  if (normalizeHexString(base.metaJSON?.encapBlobHash) !== encapHash) {
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
  }

  const corruptedShardIndices = new Set();
  if (Array.isArray(fragmentBodyHashes)) {
    if (fragmentBodyHashes.length !== n) {
      throw new Error('Invalid shardBodyHashes length');
    }
    for (const shard of group) {
      const expected = normalizeHexString(fragmentBodyHashes[shard.shardIndex]);
      const actual = normalizeHexString(await digestHex(shard.fragments));
      if (expected && actual !== expected) {
        onWarn(messages.shardBodyFailure ? messages.shardBodyFailure(shard.shardIndex) : `Fragment integrity check failed for shard ${shard.shardIndex}. Treating as erasure.`);
        corruptedShardIndices.add(shard.shardIndex);
      }
    }
    if (corruptedShardIndices.size === 0 && messages.shardBodyVerified) {
      onLog(messages.shardBodyVerified);
    }
  }

  const totalBad = missingIndices.size + corruptedShardIndices.size;
  if (totalBad > allowedFailures) {
    throw new Error(messages.tooManyMissingCorrupted ? messages.tooManyMissingCorrupted(allowedFailures, totalBad) : `Too many missing/corrupted shards for RS reconstruction: allowed ${allowedFailures}, got ${totalBad}`);
  }

  const sortedShares = validShareShards.slice().sort((a, b) => a.shardIndex - b.shardIndex);
  const { secret: privKey, shareCopiesCleared } = await combineSharesFromCopiedSlices(sortedShares, t);
  const recoveredKeyCommitmentValidated = await validateRecoveredMlKemPrivateKeyAgainstQencCommitment(base, privKey, {
    messages,
    keyValidationHooks,
  });

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
      throw new Error(messages.fragmentStreamTrailing ? messages.fragmentStreamTrailing(j) : `Fragment stream has trailing or missing data in shard ${j}`);
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

  const recoveredQencHash = normalizeHexString(await digestHex(qencBytes));
  const expectedQencHash = normalizeHexString(qenc.qencHash);
  if (recoveredQencHash !== expectedQencHash) {
    throw new Error(messages.qencHashMismatch || 'Reconstructed .qenc hash does not match archive-state descriptor');
  }

  const recoveredPrivHash = normalizeHexString(await digestHex(privKey));
  const privateKeyHash = normalizeHexString(base.metaJSON?.privateKeyHash || '');
  const privateKeyHashMatchesMetadata = privateKeyHash ? (privateKeyHash === recoveredPrivHash) : true;
  if (!privateKeyHashMatchesMetadata && messages.privateKeyHashMismatch) {
    onWarn(messages.privateKeyHashMismatch);
  }

  return {
    qencBytes,
    privKey,
    invalidShareIndices: [...invalidShareIndices].sort((a, b) => a - b),
    corruptedShardIndices: [...corruptedShardIndices].sort((a, b) => a - b),
    missingShardIndices: [...missingIndices].sort((a, b) => a - b),
    recoveredKeyCommitmentValidated,
    privateKeyHashMatchesMetadata,
    shareCopiesCleared,
  };
}
