import { sha3_512 } from '@noble/hashes/sha3.js';
import { CHUNK_SIZE, hashBytes } from '../index.js';
import { toHex } from '../bytes.js';
import { parseQencHeader } from '../qenc/format.js';
import { DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL, QCONT_FORMAT_VERSION } from '../constants.js';
import { buildArchiveManifest, canonicalizeArchiveManifest } from '../manifest/archive-manifest.js';
import { buildInitialManifestBundle, canonicalizeManifestBundle } from '../manifest/manifest-bundle.js';
import { DEFAULT_CRYPTO_PROFILE, getNonceContractForAeadMode } from '../policy.js';
import { decapsulate } from '../mlkem.js';
import { deriveKeyWithKmac, verifyKeyCommitment, clearKeys } from '../kdf.js';
import { resolveErasureRuntime } from '../erasure-runtime.js';

export function buildShardBlob({
  metaJSON,
  manifestBytes,
  bundleBytes,
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

  const manifestDigestBytes = sha3_512(manifestBytes);
  const manifestLenBytes = new Uint8Array(4);
  new DataView(manifestLenBytes.buffer).setUint32(0, manifestBytes.length, false);

  const bundleDigestBytes = sha3_512(bundleBytes);
  const bundleLenBytes = new Uint8Array(4);
  new DataView(bundleLenBytes.buffer).setUint32(0, bundleBytes.length, false);

  const encapLenBytes = new Uint8Array(4);
  new DataView(encapLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);

  const qencMetaLenBytes = new Uint8Array(2);
  new DataView(qencMetaLenBytes.buffer).setUint16(0, qencMetaBytes.length, false);

  const keyCommitLenByte = new Uint8Array([keyCommitment.length]);
  const shardIndexBytes = new Uint8Array(2);
  new DataView(shardIndexBytes.buffer).setUint16(0, shardIndex, false);
  const shareLenBytes = new Uint8Array(2);
  new DataView(shareLenBytes.buffer).setUint16(0, share.length, false);

  const qcontMagic = new TextEncoder().encode('QVC1');
  const shardHeader = new Uint8Array(
    qcontMagic.length +
      2 +
      metaJSONBytes.length +
      4 +
      manifestBytes.length +
      manifestDigestBytes.length +
      4 +
      bundleBytes.length +
      bundleDigestBytes.length +
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
  shardHeader.set(qcontMagic, offset); offset += qcontMagic.length;
  shardHeader.set(metaLenBytes, offset); offset += 2;
  shardHeader.set(metaJSONBytes, offset); offset += metaJSONBytes.length;
  shardHeader.set(manifestLenBytes, offset); offset += 4;
  shardHeader.set(manifestBytes, offset); offset += manifestBytes.length;
  shardHeader.set(manifestDigestBytes, offset); offset += manifestDigestBytes.length;
  shardHeader.set(bundleLenBytes, offset); offset += 4;
  shardHeader.set(bundleBytes, offset); offset += bundleBytes.length;
  shardHeader.set(bundleDigestBytes, offset); offset += bundleDigestBytes.length;
  shardHeader.set(encapLenBytes, offset); offset += 4;
  shardHeader.set(encapsulatedKey, offset); offset += encapsulatedKey.length;
  shardHeader.set(containerNonce, offset); offset += 12;
  shardHeader.set(kdfSalt, offset); offset += 16;
  shardHeader.set(qencMetaLenBytes, offset); offset += 2;
  shardHeader.set(qencMetaBytes, offset); offset += qencMetaBytes.length;
  shardHeader.set(keyCommitLenByte, offset); offset += 1;
  shardHeader.set(keyCommitment, offset); offset += keyCommitment.length;
  shardHeader.set(shardIndexBytes, offset); offset += 2;
  shardHeader.set(shareLenBytes, offset); offset += 2;
  shardHeader.set(share, offset);

  return new Blob([shardHeader, bodyBytes], { type: 'application/octet-stream' });
}

export async function buildQcontShards(qencBytes, privKeyBytes, params, options = {}) {
  const authPolicyLevel = options.authPolicyLevel || DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL;
  const erasureRuntime = resolveErasureRuntime(options.erasureRuntime ?? options.erasure);
  const formatVersion = QCONT_FORMAT_VERSION;

  const { n, k } = params;
  const m = n - k;
  if (k < 2 || n <= k) throw new Error('Invalid RS parameters: require 2 <= k < n');
  if ((m % 2) !== 0) throw new Error('n-k must be even');

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
  if (!(keyCommitment instanceof Uint8Array) || keyCommitment.length !== 32) {
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
    const { Kraw, Kenc, Kiv } = await deriveKeyWithKmac(
      trialSharedSecret, kdfSalt, metaBytes, ds
    );
    const keyMatch = verifyKeyCommitment(Kenc, keyCommitment);
    clearKeys(trialSharedSecret, Kraw, Kenc, Kiv);
    if (!keyMatch) {
      throw new Error(
        'Private key does not match this .qenc container (key commitment mismatch). ' +
        'Ensure you are using the correct privateKey.qkey for this container.'
      );
    }
  } catch (error) {
    if (trialSharedSecret instanceof Uint8Array) trialSharedSecret.fill(0);
    if (error.message.includes('does not match')) throw error;
    throw new Error(`Key verification failed: ${error.message}`);
  }

  const effectiveLength = meta.payloadLength || meta.originalLength;
  const containerId = await hashBytes(header);
  const containerHash = await hashBytes(qencBytes);

  const t = k + (m / 2);
  if (t > n) throw new Error('Invalid threshold computed');
  const { splitSecret } = await import('../splitting/sss.js');
  const shares = await splitSecret(privKeyBytes, n, t);
  const shareCommitments = [];
  for (let j = 0; j < n; j += 1) {
    shareCommitments.push(await hashBytes(shares[j]));
  }

  const shardBuffers = Array.from({ length: n }, () => []);
  const chunkSize = meta.chunkSize || CHUNK_SIZE;
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
    if (encodeSize === 0) throw new Error('RS parameters too large');
    const inputSize = (encodeSize * k) / n;
    const padTarget = Math.ceil(cipherChunk.length / inputSize) * inputSize;
    let chunkForRS = cipherChunk;
    if (padTarget > cipherChunk.length) {
      const padded = new Uint8Array(padTarget);
      padded.set(cipherChunk);
      chunkForRS = padded;
    }

    const fragments = erasureRuntime.split(chunkForRS, k, m / 2, RS_MAX_CODEWORD);
    if (fragments.length !== n) throw new Error('RS split returned unexpected number of fragments');
    if (i === 0) perFragmentSize = fragments[0].length;
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
    fragmentBodyHashes.push(await hashBytes(bodyBytes));
  }

  const archiveManifest = buildArchiveManifest({
    cryptoProfileId: meta.cryptoProfileId || DEFAULT_CRYPTO_PROFILE.cryptoProfileId,
    qencFormat: meta.fmt,
    aeadMode: meta.aead_mode,
    ivStrategy: meta.iv_strategy || 'single-iv',
    noncePolicyId: meta.noncePolicyId || nonceContract.noncePolicyId,
    nonceMode: meta.nonceMode || nonceContract.nonceMode,
    counterBits: meta.counterBits ?? nonceContract.counterBits,
    maxChunkCount: meta.maxChunkCount ?? nonceContract.maxChunkCount,
    chunkSize,
    chunkCount: totalChunks,
    payloadLength: meta.payloadLength || effectiveLength,
    qencHash: containerHash,
    containerId,
    shamirThreshold: t,
    shamirShareCount: n,
    rsN: n,
    rsK: k,
    rsParity: m,
    rsCodecId: 'QV-RS-ErasureCodes-v1',
    shardBodyHashes: fragmentBodyHashes,
    shareCommitments,
    authPolicyLevel,
    minValidSignatures: options.minValidSignatures ?? 1,
  });
  const canonicalManifest = canonicalizeArchiveManifest(archiveManifest);

  const initialBundle = buildInitialManifestBundle({
      manifest: archiveManifest,
      authPolicy: {
      level: authPolicyLevel,
      minValidSignatures: options.minValidSignatures ?? 1,
    },
  });
  const canonicalBundle = canonicalizeManifestBundle(initialBundle);

  const timestamp = new Date().toISOString();
  const metaJSON = {
    containerId,
    alg: { KEM: 'ML-KEM-1024', KDF: 'KMAC256', AEAD: 'AES-256-GCM', RS: 'ErasureCodes', fmt: formatVersion },
    aead_mode: isPerChunk ? 'per-chunk' : 'single-container',
    iv_strategy: meta.iv_strategy,
    cryptoProfileId: meta.cryptoProfileId || DEFAULT_CRYPTO_PROFILE.cryptoProfileId,
    noncePolicyId: meta.noncePolicyId || nonceContract.noncePolicyId,
    nonceMode: meta.nonceMode || nonceContract.nonceMode,
    counterBits: meta.counterBits ?? nonceContract.counterBits,
    maxChunkCount: meta.maxChunkCount ?? nonceContract.maxChunkCount,
    aadPolicyId: meta.aadPolicyId || DEFAULT_CRYPTO_PROFILE.aadPolicyId,
    n, k, m, t,
    rsEncodeBase: RS_MAX_CODEWORD,
    chunkSize,
    chunkCount: totalChunks,
    containerHash,
    encapBlobHash: await hashBytes(encapsulatedKey),
    privateKeyHash: await hashBytes(privKeyBytes),
    payloadLength: meta.payloadLength || null,
    originalLength: effectiveLength,
    ciphertextLength: ciphertext.length,
    domainStrings: { kdf: ds.kdf, iv: ds.iv, kenc: ds.kenc, kiv: ds.kiv },
    fragmentFormat: 'len32-prefixed',
    perFragmentSize,
    hasKeyCommitment: true,
    keyCommitmentHex: toHex(keyCommitment),
    hasEmbeddedManifest: true,
    manifestDigest: canonicalManifest.digestHex,
    hasEmbeddedBundle: true,
    bundleDigest: canonicalBundle.digestHex,
    authPolicyLevel: initialBundle.authPolicy.level,
    shareCommitments,
    fragmentBodyHashes,
    timestamp,
  };

  const qconts = [];
  for (let j = 0; j < n; j += 1) {
    const blob = buildShardBlob({
      metaJSON,
      manifestBytes: canonicalManifest.bytes,
      bundleBytes: canonicalBundle.bytes,
      encapsulatedKey,
      containerNonce,
      kdfSalt,
      qencMetaBytes: metaBytes,
      keyCommitment,
      shardIndex: j,
      share: shares[j],
      bodyBytes: shardBodyBytesArr[j],
    });
    qconts.push({ blob, index: j });
  }

  return {
    shards: qconts,
    manifest: archiveManifest,
    bundle: initialBundle,
    manifestBytes: canonicalManifest.bytes,
    manifestDigestHex: canonicalManifest.digestHex,
    bundleBytes: canonicalBundle.bytes,
    bundleDigestHex: canonicalBundle.digestHex,
    formatVersion,
  };
}
