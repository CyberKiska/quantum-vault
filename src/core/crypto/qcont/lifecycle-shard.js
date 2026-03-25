import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesEqual, bytesToUtf8, toHex } from '../bytes.js';
import { parseJsonBytesStrict } from '../manifest/strict-json.js';
import { parseQencHeader } from '../qenc/format.js';
import { DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL } from '../constants.js';
import { DEFAULT_CRYPTO_PROFILE, getNonceContractForAeadMode } from '../policy.js';
import { decapsulate } from '../mlkem.js';
import { clearKeys, deriveKeyWithKmac, verifyKeyCommitment } from '../kdf.js';
import { resolveErasureRuntime } from '../erasure-runtime.js';
import {
  buildArchiveStateDescriptor,
  buildCohortBinding,
  buildLifecycleBundle,
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeLifecycleBundle,
  deriveCohortId,
  deriveStateId,
  generateArchiveId,
  parseArchiveStateDescriptorBytes,
  parseCohortBindingBytes,
  parseLifecycleBundleBytes,
} from '../lifecycle/artifacts.js';

export const LIFECYCLE_QCONT_MAGIC = 'QVC1';
export const LIFECYCLE_QCONT_FORMAT_VERSION = 'QVqcont-7';
export const LIFECYCLE_ARTIFACT_FAMILY = 'successor-lifecycle-v1';

const DIGEST_LEN = 64;
const KEY_COMMITMENT_LEN = 32;
const MAX_META_LEN = 65535;
const MAX_ARTIFACT_LEN = 16 * 1024 * 1024;
const LOWER_HEX_RE = /^[0-9a-f]+$/;

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

function requireLowercaseHexMetadata(value, field, expectedLength) {
  if (typeof value !== 'string' || value.length !== expectedLength || !LOWER_HEX_RE.test(value)) {
    throw new Error(`Invalid shard metadata ${field}`);
  }
  return value;
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
