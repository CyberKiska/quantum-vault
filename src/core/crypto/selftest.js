import { CHUNK_SIZE, FORMAT_VERSION, MAX_FILE_SIZE, decryptFile, encryptFile, generateKeyPair, hashBytes } from './index.js';
import { asciiBytes, base64ToBytes, bytesToBase64, concatBytes, digestSha256, fromHex, timingSafeEqual, utf8ToBytes } from './bytes.js';
import { validatePublicKey, validateSecretKey } from './mlkem.js';
import { buildQcontShards } from './qcont/build.js';
import { attachManifestBundleToShards } from './qcont/attach.js';
import { parseShard, restoreFromShards } from './qcont/restore.js';
import { parseQencHeader } from './qenc/format.js';
import { canonicalizeManifestBundle, parseManifestBundleBytes } from './manifest/manifest-bundle.js';
import { createBundlePayloadFromFiles, isBundlePayload, parseBundlePayload } from '../features/bundle-payload.js';
import { buildAttachedArtifactExports } from '../features/qcont/attach-ui.js';
import { classifyRestoreInputFiles } from '../../app/restore-inputs.js';
import { verifyManifestSignatures } from './auth/verify-signatures.js';
import { unpackPqpk, unpackQsig } from './auth/qsig.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { inspectManifestBundleTimestamps, parseOpenTimestampProof } from './auth/opentimestamps.js';
import {
  DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL,
  LITE_DEFAULT_AUTH_POLICY_LEVEL,
  PRO_DEFAULT_AUTH_POLICY_LEVEL,
} from './constants.js';
import {
  assertPerChunkNonceContract,
  deriveChunkIvFromK,
  IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
  NONCE_COUNTER_BITS_U32,
  NONCE_MAX_CHUNK_COUNT_U32,
} from './aead.js';
import { toHex } from './bytes.js';
import {
  DEFAULT_CRYPTO_PROFILE,
  NONCE_MODE_KMAC_CTR32,
  NONCE_MODE_RANDOM96,
  NONCE_POLICY_PER_CHUNK_V3,
  NONCE_POLICY_SINGLE_CONTAINER_V1,
} from './policy.js';
import { kmac256 } from './kmac.js';
import { resolveErasureRuntime } from './erasure-runtime.js';

function textBytes(value) {
  return new TextEncoder().encode(value);
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

function toArrayBufferView(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function fileLike(name, bytes) {
  return {
    name,
    async arrayBuffer() {
      return toArrayBufferView(bytes);
    },
  };
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function expectFailure(fn, message) {
  let failed = false;
  try {
    await fn();
  } catch {
    failed = true;
  }
  if (!failed) {
    throw new Error(message);
  }
}

function mutateTail(bytes, delta = 1) {
  const out = bytes.slice();
  const index = out.length - 1;
  out[index] ^= delta & 0xff;
  return out;
}

function removeQencKeyCommitmentBytes(containerBytes) {
  const parsed = parseQencHeader(containerBytes);
  const keyCommitmentLen = parsed.storedKeyCommitment?.length || 0;
  if (keyCommitmentLen <= 0) {
    throw new Error('No key commitment present in source container');
  }

  const headerWithoutCommitLen = parsed.offset - keyCommitmentLen;
  const out = new Uint8Array(headerWithoutCommitLen + (containerBytes.length - parsed.offset));
  out.set(containerBytes.subarray(0, headerWithoutCommitLen), 0);
  out.set(containerBytes.subarray(parsed.offset), headerWithoutCommitLen);
  return out;
}

function qcontManifestRegion(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  offset += 4; // magic
  const metaLen = dv.getUint16(offset, false);
  offset += 2 + metaLen;
  const manifestLen = dv.getUint32(offset, false);
  offset += 4;
  return {
    manifestStart: offset,
    manifestLen,
    manifestDigestStart: offset + manifestLen,
  };
}

function mutateQcontManifestByte(bytes, delta = 1) {
  const out = bytes.slice();
  const region = qcontManifestRegion(out);
  if (region.manifestLen <= 0) {
    throw new Error('No embedded manifest to mutate');
  }
  out[region.manifestStart] ^= delta & 0xff;
  return out;
}

function createLargeDeterministicPayload(length) {
  const payload = new Uint8Array(length);
  for (let i = 0; i < payload.length; i += 1) {
    payload[i] = (i * 31 + 17) & 0xff;
  }
  return payload;
}

const bytesToHex = toHex;

function u16le(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

function u32le(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function crc16Xmodem(bytes) {
  let crc = 0x0000;
  for (let i = 0; i < bytes.length; i += 1) {
    crc ^= bytes[i] << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      if ((crc & 0x8000) !== 0) crc = ((crc << 1) ^ 0x1021) & 0xffff;
      else crc = (crc << 1) & 0xffff;
    }
  }
  return crc;
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  while ((out.length % 8) !== 0) out += '=';
  return out;
}

function encodeStellarAddress(publicKeyBytes) {
  const version = 6 << 3;
  const payload = concatBytes([Uint8Array.of(version), publicKeyBytes]);
  const crc = crc16Xmodem(payload);
  const checksum = Uint8Array.of(crc & 0xff, (crc >>> 8) & 0xff);
  return base32Encode(concatBytes([payload, checksum])).replace(/=+$/g, '');
}

function buildQsigFixture(messageBytes) {
  const suiteId = 0x03;
  const keys = ml_dsa87.keygen();
  const fileHash = sha3_512(messageBytes);
  const tbs = concatBytes([
    asciiBytes('QSTB'),
    Uint8Array.of(0x01, 0x00, 0x01, 0x00, suiteId, 0x01, 0x00),
    fileHash,
  ]);
  const signature = ml_dsa87.sign(tbs, keys.secretKey);
  const fingerprintRecord = concatBytes([Uint8Array.of(0x01), sha3_256(keys.publicKey)]);
  const metaBytes = concatBytes([
    Uint8Array.of(0x10), u16le(keys.publicKey.length), keys.publicKey,
    Uint8Array.of(0x11), u16le(fingerprintRecord.length), fingerprintRecord,
  ]);
  const qsigBytes = concatBytes([
    asciiBytes('PQSG'),
    Uint8Array.of(0x01, 0x00, suiteId, 0x01),
    u16le(0x000f),
    fileHash,
    Uint8Array.of(0x00, 0x00),
    u16le(metaBytes.length),
    u32le(signature.length),
    metaBytes,
    signature,
  ]);
  const pqpkPrefix = concatBytes([
    asciiBytes('PQPK'),
    Uint8Array.of(0x01, 0x00, suiteId, 0x00),
    u32le(keys.publicKey.length),
    keys.publicKey,
  ]);
  const pqpkBytes = concatBytes([pqpkPrefix, u32le(crc32(pqpkPrefix))]);
  return { qsigBytes, pqpkBytes };
}

function mutateQsigMajorVersion(qsigBytes, versionMajor) {
  const out = qsigBytes.slice();
  out[4] = versionMajor & 0xff;
  return out;
}

function mutatePqpkMajorVersion(pqpkBytes, versionMajor) {
  const out = pqpkBytes.slice();
  out[4] = versionMajor & 0xff;
  const prefix = out.subarray(0, out.length - 4);
  const checksum = u32le(crc32(prefix));
  out.set(checksum, out.length - 4);
  return out;
}

function appendUnknownCriticalQsigMetadata(qsigBytes) {
  const parsed = unpackQsig(qsigBytes);
  const metaBytes = concatBytes([
    Uint8Array.of(0x90),
    u16le(1),
    Uint8Array.of(0x01),
  ]);
  const mutated = concatBytes([
    asciiBytes('PQSG'),
    Uint8Array.of(parsed.versionMajor, parsed.versionMinor, parsed.suiteId, parsed.hashAlgId),
    u16le(parsed.flags || 0),
    parsed.fileHash,
    u16le(parsed.ctxBytes.length),
    u16le(metaBytes.length),
    u32le(parsed.signature.length),
    parsed.ctxBytes,
    metaBytes,
    parsed.signature,
  ]);
  return mutated;
}

async function buildOtsFixture(stampedBytes, { completeProof = false } = {}) {
  const header = concatBytes([
    asciiBytes('\x00OpenTimestamps\x00\x00Proof\x00'),
    Uint8Array.of(0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01, 0x08),
    await digestSha256(stampedBytes),
  ]);
  const tail = completeProof
    ? createLargeDeterministicPayload(1600)
    : createLargeDeterministicPayload(96);
  return concatBytes([header, tail]);
}

async function buildStellarSignatureFixture(messageBytes) {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const signer = encodeStellarAddress(publicKeyBytes);
  const hashes = [
    { alg: 'SHA-256', hex: bytesToHex(await digestSha256(messageBytes)) },
    { alg: 'SHA3-512', hex: bytesToHex(sha3_512(messageBytes)) },
  ];
  const message = [
    'STELLAR-WSIGN/v1',
    'type=file',
    `size=${messageBytes.length}`,
    'hashes=SHA-256,SHA3-512',
    `sha256=${hashes[0].hex}`,
    `sha3_512=${hashes[1].hex}`,
  ].join('\n');
  const payload = await digestSha256(utf8ToBytes(`Stellar Signed Message:\n${message}`));
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', keyPair.privateKey, payload));
  const doc = {
    schema: 'stellar-file-signature/v1',
    mode: 'sep53',
    input: { type: 'file' },
    signer,
    message,
    hashes,
    signatureB64: bytesToBase64(signature),
  };
  return new TextEncoder().encode(JSON.stringify(doc));
}

async function buildStellarSignatureFixtureWithSigner(messageBytes) {
  const bytes = await buildStellarSignatureFixture(messageBytes);
  const doc = JSON.parse(new TextDecoder().decode(bytes));
  return {
    bytes,
    signer: String(doc.signer || ''),
  };
}

async function ensureRuntimeCrypto() {
  if (globalThis.crypto?.subtle) return;
  const isNode = typeof process !== 'undefined' && Boolean(process.versions?.node);
  if (!isNode) {
    throw new Error('Web Crypto API is not available in current runtime');
  }
  // Keep specifier non-literal so browser bundles do not try to resolve node built-ins.
  const nodeCryptoSpecifier = ['node', 'crypto'].join(':');
  const { webcrypto } = await import(nodeCryptoSpecifier);
  globalThis.crypto = webcrypto;
}

async function ensureErasureRuntime() {
  try {
    resolveErasureRuntime();
    return;
  } catch {
    // Continue with runtime bootstrap.
  }

  const isNode = typeof process !== 'undefined' && Boolean(process.versions?.node);
  if (!isNode) {
    throw new Error('Reed-Solomon runtime (globalThis.erasure) is unavailable');
  }

  const fsSpecifier = ['node', 'fs/promises'].join(':');
  const pathSpecifier = ['node', 'path'].join(':');
  const urlSpecifier = ['node', 'url'].join(':');

  const [{ readFile }, { dirname, resolve }, { fileURLToPath }] = await Promise.all([
    import(fsSpecifier),
    import(pathSpecifier),
    import(urlSpecifier),
  ]);

  const thisFile = fileURLToPath(import.meta.url);
  const erasurePath = resolve(dirname(thisFile), '../../../public/third-party/erasure.js');
  const erasureSource = await readFile(erasurePath, 'utf8');

  const cjsShim = { exports: {} };
  const evaluateErasure = new Function('module', 'exports', erasureSource);
  evaluateErasure(cjsShim, cjsShim.exports);
  globalThis.erasure = cjsShim.exports;

  resolveErasureRuntime();
}

async function runCase(name, fn) {
  try {
    await fn();
    return { name, ok: true };
  } catch (error) {
    return { name, ok: false, error: error?.message || String(error) };
  }
}

function classifySelfTestGroup(name) {
  const label = String(name || '');
  if (/^(AUTH|ATTACH|QCONT|CORE): /.test(label)) return null;
  if (/attach|OpenTimestamps|OTS/i.test(label)) return 'ATTACH';
  if (/pinning|signature|auth policy|strong-pq/i.test(label)) return 'AUTH';
  if (/restore|parseShard|buildQcontShards|qcont|shard|split|cohort/i.test(label)) return 'QCONT';
  return 'CORE';
}

function prefixSelfTestName(name) {
  const group = classifySelfTestGroup(name);
  return group ? `${group}: ${name}` : name;
}

function buildCases() {
  return [
    {
      name: 'ML-KEM keygen',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        assert(publicKey.length === 1568, `public key length mismatch: ${publicKey.length}`);
        assert(secretKey.length === 3168, `secret key length mismatch: ${secretKey.length}`);
        validatePublicKey(publicKey);
        validateSecretKey(secretKey);
      },
    },
    {
      name: 'ML-KEM key import (.qkey bytes)',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const importedPublic = new Uint8Array(await fileLike('public.qkey', publicKey).arrayBuffer());
        const importedSecret = new Uint8Array(await fileLike('secret.qkey', secretKey).arrayBuffer());

        validatePublicKey(importedPublic);
        validateSecretKey(importedSecret);

        const originalPubHash = await hashBytes(publicKey);
        const importedPubHash = await hashBytes(importedPublic);
        const originalSecHash = await hashBytes(secretKey);
        const importedSecHash = await hashBytes(importedSecret);
        assert(originalPubHash === importedPubHash, 'imported public key hash mismatch');
        assert(originalSecHash === importedSecHash, 'imported secret key hash mismatch');
      },
    },
    {
      name: 'one file -> .qenc container encrypt',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('single-file-payload');
        const encrypted = await encryptFile(payload, publicKey, 'single.txt');
        const encryptedBytes = await blobToBytes(encrypted);
        const parsedHeader = parseQencHeader(encryptedBytes);

        assert(parsedHeader.metadata.fmt === FORMAT_VERSION, `unexpected format: ${parsedHeader.metadata.fmt}`);
        assert(parsedHeader.metadata.payloadFormat === 'wrapped-v1', 'unexpected payload format');
        assert(parsedHeader.metadata.aead_mode === 'single-container-aead', 'unexpected AEAD mode');
        assert(parsedHeader.metadata.noncePolicyId === NONCE_POLICY_SINGLE_CONTAINER_V1, 'single-container noncePolicyId mismatch');
        assert(parsedHeader.metadata.nonceMode === NONCE_MODE_RANDOM96, 'single-container nonceMode mismatch');
        assert(parsedHeader.metadata.counterBits === 0, 'single-container counterBits mismatch');
        assert(parsedHeader.metadata.maxChunkCount === 1, 'single-container maxChunkCount mismatch');
        assert(parsedHeader.metadata.cryptoProfileId === DEFAULT_CRYPTO_PROFILE.cryptoProfileId, 'cryptoProfileId mismatch');
        assert(parsedHeader.metadata.kdfTreeId === DEFAULT_CRYPTO_PROFILE.kdfTreeId, 'kdfTreeId mismatch');
        assert(parsedHeader.metadata.domainStrings.kdf === DEFAULT_CRYPTO_PROFILE.domainStrings.kdf, 'domainStrings.kdf mismatch');
        assert(parsedHeader.metadata.domainStrings.iv === DEFAULT_CRYPTO_PROFILE.domainStrings.iv, 'domainStrings.iv mismatch');
        assert(parsedHeader.metadata.domainStrings.kenc === DEFAULT_CRYPTO_PROFILE.domainStrings.kenc, 'domainStrings.kenc mismatch');
        assert(parsedHeader.metadata.domainStrings.kiv === DEFAULT_CRYPTO_PROFILE.domainStrings.kiv, 'domainStrings.kiv mismatch');

        const { decryptedBlob, metadata } = await decryptFile(encryptedBytes, secretKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert(metadata.originalFilename === 'single.txt', 'original filename mismatch');
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'single-file roundtrip mismatch');
      },
    },
    {
      name: 'multi files -> .qenc container encrypt',
      fn: async () => {
        const files = [
          fileLike('a.txt', textBytes('alpha payload')),
          fileLike('b.bin', createLargeDeterministicPayload(2048)),
        ];
        const { bundleBytes, bundleName, fileCount } = await createBundlePayloadFromFiles(files);
        assert(fileCount === 2, `expected 2 files in bundle, got ${fileCount}`);

        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const encrypted = await encryptFile(bundleBytes, publicKey, bundleName);
        const encryptedBytes = await blobToBytes(encrypted);
        const { decryptedBlob, metadata } = await decryptFile(encryptedBytes, secretKey);
        const decrypted = await blobToBytes(decryptedBlob);

        assert(metadata.originalFilename === bundleName, 'bundle original filename mismatch');
        assert(isBundlePayload(decrypted), 'decrypted multi-file payload is not a bundle');

        const entries = parseBundlePayload(decrypted);
        assert(entries.length === 2, `expected 2 entries after decrypt, got ${entries.length}`);
        assert(entries[0].name === 'a.txt', `unexpected first entry name: ${entries[0].name}`);
        assert(entries[1].name === 'b.bin', `unexpected second entry name: ${entries[1].name}`);
        assert((await hashBytes(entries[0].bytes)) === (await hashBytes(textBytes('alpha payload'))), 'entry a.txt hash mismatch');
      },
    },
    {
      name: '.qenc + secret.qkey -> split',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('split-check');
        const encrypted = await encryptFile(payload, publicKey, 'split.txt');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 });
        const shards = split.shards;

        assert(shards.length === 5, `expected 5 shards, got ${shards.length}`);
        for (const shard of shards) {
          const parsed = parseShard(await blobToBytes(shard.blob));
          assert(parsed.metaJSON.n === 5, 'shard metadata n mismatch');
          assert(parsed.metaJSON.k === 3, 'shard metadata k mismatch');
          assert(parsed.metaJSON.t === 4, 'shard metadata t mismatch');
          assert(parsed.metaJSON.hasEmbeddedBundle === true, 'shard metadata must indicate embedded bundle');
          assert(typeof parsed.metaJSON.bundleDigest === 'string' && parsed.metaJSON.bundleDigest.length === 128, 'bundle digest metadata missing');
        }
      },
    },
    {
      name: '.qcont reconstruction',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(256 * 1024);
        const encrypted = await encryptFile(payload, publicKey, 'restore.txt');
        const qencBytes = await blobToBytes(encrypted);
        const built = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const builtShards = built.shards;
        const shardBytes = await Promise.all(builtShards.map((shard) => blobToBytes(shard.blob)));
        const oneCorrupted = shardBytes.map((bytes, idx) => (idx === 0 ? mutateTail(bytes) : bytes.slice()));
        const parsedShards = oneCorrupted.map((bytes) => parseShard(bytes));

        const restored = await restoreFromShards(parsedShards, { onLog: () => {}, onError: () => {} });
        assert(restored.qencOk, 'reconstructed qenc hash mismatch');
        assert(restored.qkeyOk, 'reconstructed qkey hash mismatch');

        const { decryptedBlob } = await decryptFile(restored.qencBytes, restored.privKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'reconstructed payload mismatch');
      },
    },
    {
      name: 'restore rejects mixed manifest cohorts without selector',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payloadA = textBytes('cohort-a');
        const payloadB = textBytes('cohort-b');

        const qencA = await blobToBytes(await encryptFile(payloadA, pairA.publicKey, 'a.bin'));
        const qencB = await blobToBytes(await encryptFile(payloadB, pairB.publicKey, 'b.bin'));

        const splitA = await buildQcontShards(qencA, pairA.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const splitB = await buildQcontShards(qencB, pairB.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });

        const mixed = [
          ...(await Promise.all(splitA.shards.slice(0, 3).map((item) => blobToBytes(item.blob)))),
          ...(await Promise.all(splitB.shards.slice(0, 2).map((item) => blobToBytes(item.blob)))),
        ];
        const parsed = mixed.map((bytes) => parseShard(bytes));

        await expectFailure(
          () => restoreFromShards(parsed, { onLog: () => {}, onError: () => {} }),
          'restore unexpectedly accepted mixed manifest cohorts without selector'
        );
      },
    },
    {
      name: 'restore uses uploaded manifest to select correct cohort',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payloadA = textBytes('selector-a');
        const payloadB = textBytes('selector-b');

        const qencA = await blobToBytes(await encryptFile(payloadA, pairA.publicKey, 'sa.bin'));
        const qencB = await blobToBytes(await encryptFile(payloadB, pairB.publicKey, 'sb.bin'));

        const splitA = await buildQcontShards(qencA, pairA.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const splitB = await buildQcontShards(qencB, pairB.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });

        const selectedShardBytes = await Promise.all(splitA.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const distractorShardBytes = await blobToBytes(splitB.shards[0].blob);
        const parsed = [...selectedShardBytes, distractorShardBytes].map((bytes) => parseShard(bytes));

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: { manifestBytes: splitA.manifestBytes },
        });

        assert(restored.qencOk, 'restore with uploaded manifest failed qenc hash check');
        assert(restored.manifestSource === 'uploaded-manifest', `unexpected manifest source: ${restored.manifestSource}`);
      },
    },
    {
      name: 'parseShard rejects tampered embedded manifest digest',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('manifest-tamper');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'tamper.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 });
        const shardBytes = await blobToBytes(split.shards[0].blob);
        const tampered = mutateQcontManifestByte(shardBytes);

        await expectFailure(
          async () => {
            parseShard(tampered);
          },
          'parseShard unexpectedly accepted tampered embedded manifest'
        );
      },
    },
    {
      name: 'pinning: valid PQ signature without pin remains valid and unpinned',
      fn: async () => {
        const manifestBytes = textBytes('pinning-no-pin');
        const { qsigBytes } = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
        });

        assert(verification.status.signatureVerified === true, 'signature should remain verified without a pin');
        assert(verification.status.signerPinned === false, 'signature should remain unpinned without a pin');
        assert(verification.status.bundlePinned === false, 'external signature without bundle key must not set bundlePinned');
        assert(verification.status.userPinned === false, 'external signature without user pin must not set userPinned');
      },
    },
    {
      name: 'pinning: valid PQ signature with wrong pin remains valid and unpinned',
      fn: async () => {
        const manifestBytes = textBytes('pinning-wrong-pin');
        const { qsigBytes } = buildQsigFixture(manifestBytes);
        const { pqpkBytes: wrongPqpkBytes } = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pinnedPqPublicKeyFileBytes: wrongPqpkBytes,
        });

        assert(verification.status.signatureVerified === true, 'wrong pin must not downgrade signature verification');
        assert(verification.status.signerPinned === false, 'wrong pin must not mark signer as pinned');
        assert(verification.status.userPinned === false, 'wrong pin must not set userPinned');
        assert(
          verification.warnings.some((warning) => warning.includes('Pinned PQ signer key did not match')),
          'wrong pin should emit an explicit warning'
        );
      },
    },
    {
      name: 'pinning: valid PQ signature with matching pin remains valid and pinned',
      fn: async () => {
        const manifestBytes = textBytes('pinning-matching-pin');
        const { qsigBytes, pqpkBytes } = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pinnedPqPublicKeyFileBytes: pqpkBytes,
        });

        assert(verification.status.signatureVerified === true, 'matching pin must preserve signature verification');
        assert(verification.status.signerPinned === true, 'matching pin must mark signer as pinned');
        assert(verification.status.bundlePinned === false, 'external signature should not set bundlePinned');
        assert(verification.status.userPinned === true, 'matching external pin must set userPinned');
      },
    },
    {
      name: 'policy counting ignores duplicate detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-policy-count');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'duplicate-policy-count.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes } = buildQsigFixture(split.manifestBytes);

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [
                { name: 'duplicate-a.qsig', bytes: qsigBytes },
                { name: 'duplicate-b.qsig', bytes: qsigBytes },
              ],
            },
          }),
          'duplicate detached signatures unexpectedly satisfied minValidSignatures'
        );
      },
    },
    {
      name: 'policy counting accepts two unique detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('unique-policy-count');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'unique-policy-count.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [
              { name: 'unique-a.qsig', bytes: sigA.qsigBytes },
              { name: 'unique-b.qsig', bytes: sigB.qsigBytes },
            ],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'two unique signatures should satisfy minValidSignatures');
        assert(restored.authenticity.verification.counts.validTotal === 2, 'expected two unique signatures in policy counts');
      },
    },
    {
      name: 'policy counting ignores a duplicate detached signature repeated in bundle and external inputs',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('bundle-external-duplicate-policy-count');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'bundle-external-duplicate-policy-count.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });
        const updatedShards = await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));

        await expectFailure(
          () => restoreFromShards(updatedShards, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
            },
          }),
          'bundle + external duplicate detached signature unexpectedly satisfied minValidSignatures'
        );
      },
    },
    {
      name: 'parser rejects unsupported .qsig major version',
      fn: async () => {
        const manifestBytes = textBytes('bad-qsig-major');
        const { qsigBytes } = buildQsigFixture(manifestBytes);
        const badQsigBytes = mutateQsigMajorVersion(qsigBytes, 0x02);

        await expectFailure(
          () => verifyManifestSignatures({
            manifestBytes,
            externalSignatures: [{ name: 'bad.qsig', bytes: badQsigBytes }],
          }),
          '.qsig parser unexpectedly accepted unsupported major version'
        );
      },
    },
    {
      name: 'parser rejects unsupported .pqpk major version',
      fn: async () => {
        const manifestBytes = textBytes('bad-pqpk-major');
        const { pqpkBytes } = buildQsigFixture(manifestBytes);
        const badPqpkBytes = mutatePqpkMajorVersion(pqpkBytes, 0x02);

        await expectFailure(
          () => Promise.resolve(unpackPqpk(badPqpkBytes)),
          '.pqpk parser unexpectedly accepted unsupported major version'
        );
      },
    },
    {
      name: 'parser rejects unknown critical .qsig metadata TLV tag',
      fn: async () => {
        const manifestBytes = textBytes('bad-qsig-critical-tag');
        const { qsigBytes } = buildQsigFixture(manifestBytes);
        const badQsigBytes = appendUnknownCriticalQsigMetadata(qsigBytes);

        await expectFailure(
          () => verifyManifestSignatures({
            manifestBytes,
            externalSignatures: [{ name: 'critical.qsig', bytes: badQsigBytes }],
          }),
          '.qsig parser unexpectedly accepted an unknown critical metadata tag'
        );
      },
    },
    {
      name: 'manifest bundle rejects duplicate detached signature payload bytes under different ids',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-bundle-signatures');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'duplicate-bundle-signatures.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);
        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });
        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        const duplicateSignature = {
          ...parsedBundle.bundle.attachments.signatures[0],
          id: 'sig-duplicate',
        };
        const mutatedBundle = {
          ...parsedBundle.bundle,
          attachments: {
            ...parsedBundle.bundle.attachments,
            signatures: [
              ...parsedBundle.bundle.attachments.signatures,
              duplicateSignature,
            ],
          },
        };

        await expectFailure(
          () => Promise.resolve(canonicalizeManifestBundle(mutatedBundle)),
          'manifest bundle unexpectedly accepted duplicate detached signature payload bytes'
        );
      },
    },
    {
      name: 'auth policy defaults: Lite integrity-only, Pro strong-pq, builder fallback matches Pro',
      fn: async () => {
        assert(LITE_DEFAULT_AUTH_POLICY_LEVEL === 'integrity-only', 'Lite default auth policy must remain integrity-only');
        assert(PRO_DEFAULT_AUTH_POLICY_LEVEL === 'strong-pq-signature', 'Pro default auth policy must remain strong-pq-signature');
        assert(
          DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL === PRO_DEFAULT_AUTH_POLICY_LEVEL,
          'builder default auth policy must match the Pro default'
        );

        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('default-auth-policy');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'default-policy.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 });

        assert(split.bundle.authPolicy.level === PRO_DEFAULT_AUTH_POLICY_LEVEL, 'builder fallback must emit the Pro default policy');
      },
    },
    {
      name: 'restore any-signature policy rejects unsigned archive',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('strict-authn');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'strict.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const shardBytes = await Promise.all(split.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const parsed = shardBytes.map((bytes) => parseShard(bytes));

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
          }),
          'restore unexpectedly allowed any-signature archive without signatures'
        );
      },
    },
    {
      name: 'restore any-signature policy accepts valid external PQ signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('pre-attach-signature');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'signed.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const shardBytes = await Promise.all(split.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const parsed = shardBytes.map((bytes) => parseShard(bytes));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
            pinnedPqPublicKeyFileBytes: pqpkBytes,
          },
        });

        assert(restored.authenticity.status.signatureVerified, 'expected signatureVerified');
        assert(restored.authenticity.status.strongPqSignatureVerified, 'expected strongPqSignatureVerified');
        assert(restored.authenticity.status.signerPinned, 'expected signerPinned from external .pqpk');
        assert(restored.authenticity.status.bundlePinned === false, 'external .pqpk should not set bundlePinned');
        assert(restored.authenticity.status.userPinned === true, 'external .pqpk should set userPinned');
        assert(restored.authenticity.status.policySatisfied, 'expected policySatisfied');
      },
    },
    {
      name: 'restore strong-pq-signature policy accepts one valid strong PQ signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('strong-pq-valid');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'strong-pq-valid.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes } = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          },
        });

        assert(restored.authenticity.status.signatureVerified === true, 'expected signatureVerified');
        assert(restored.authenticity.status.strongPqSignatureVerified === true, 'expected strongPqSignatureVerified');
        assert(restored.authenticity.status.policySatisfied === true, 'expected policySatisfied');
      },
    },
    {
      name: 'restore any-signature policy accepts one valid Ed25519 signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('any-signature-ed25519');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'any-signature-ed25519.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSigBytes = await buildStellarSignatureFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: { signatures: [{ name: 'archive.sig', bytes: stellarSigBytes }] },
        });

        assert(restored.authenticity.status.signatureVerified === true, 'expected signatureVerified');
        assert(restored.authenticity.status.strongPqSignatureVerified === false, 'Ed25519 must not satisfy strong PQ status');
        assert(restored.authenticity.status.policySatisfied === true, 'expected policySatisfied');
      },
    },
    {
      name: 'restore ignores invalid extra signatures when one satisfying signature exists',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('invalid-extra-signatures');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'invalid-extra-signatures.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes } = buildQsigFixture(split.manifestBytes);
        const brokenQsigBytes = mutateTail(qsigBytes, 0x40);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [
              { name: 'archive-good.qsig', bytes: qsigBytes },
              { name: 'archive-bad.qsig', bytes: brokenQsigBytes },
            ],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'one satisfying signature should still pass policy');
        assert(restored.authenticity.verification.results.some((item) => item.ok === false), 'expected an invalid signature result');
        assert(
          restored.authenticity.warnings.some((warning) => warning.includes('did not verify and were ignored')),
          'invalid extra signatures should produce an explicit warning'
        );
      },
    },
    {
      name: 'attach upgrades manifest into bundle and qcont-only restore succeeds',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('post-attach-signature');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'attach.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });
        assert(
          timingSafeEqual(attached.manifestBytes, split.manifestBytes),
          'attach must not mutate canonical manifest bytes'
        );
        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        assert(parsedBundle.bundle.attachments.signatures.length === 1, 'expected attached bundle signature');
        assert(parsedBundle.bundle.attachments.publicKeys.length === 1, 'expected attached bundle public key');

        const updatedShards = await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        for (const updatedShard of updatedShards) {
          assert(
            timingSafeEqual(updatedShard.manifestBytes, split.manifestBytes),
            'embedded attach must preserve canonical manifest bytes inside rewritten shards'
          );
        }
        const restored = await restoreFromShards(updatedShards, { onLog: () => {}, onError: () => {} });
        assert(restored.authenticity.status.policySatisfied, 'attached restore should satisfy archive policy');
        assert(restored.authenticity.status.signatureVerified, 'attached restore should verify signature');
        assert(restored.authenticity.status.signerPinned, 'bundle-attached PQ key should mark signer as pinned during restore');
        assert(restored.authenticity.status.bundlePinned === true, 'bundle-attached PQ key should set bundlePinned');
        assert(restored.authenticity.status.userPinned === false, 'bundle-attached PQ key alone should not set userPinned');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 1, 'expected one pinned bundled signature');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'expected one bundle-pinned bundled signature');
      },
    },
    {
      name: 'restore accepts uploaded bundle for stale shards with same manifest',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('stale-shards-with-uploaded-bundle');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'stale.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const originalShards = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const allShards = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);
        const attached = await attachManifestBundleToShards(allShards, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });

        const restored = await restoreFromShards(originalShards, {
          onLog: () => {},
          onError: () => {},
          verification: { bundleBytes: attached.bundleBytes },
        });

        assert(restored.manifestSource === 'uploaded-bundle', `unexpected manifest source: ${restored.manifestSource}`);
        assert(restored.authenticity.status.policySatisfied, 'uploaded bundle should satisfy archive policy for stale shards');
        assert(restored.authenticity.status.signerPinned, 'uploaded bundle PQ key should mark signer as pinned');
        assert(restored.authenticity.status.bundlePinned === true, 'uploaded bundle PQ key should set bundlePinned');
        assert(restored.authenticity.status.userPinned === false, 'uploaded bundle without user pin should not set userPinned');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 1, 'uploaded bundle should preserve pinned bundled signature');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'uploaded bundle should preserve bundle-pinned count');
      },
    },
    {
      name: 'restore can report both bundlePinned and userPinned for the same bundled PQ signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('bundle-and-user-pin');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'bundle-and-user-pin.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });

        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          {
            onLog: () => {},
            onError: () => {},
            verification: { pinnedPqPublicKeyFileBytes: pqpkBytes },
          }
        );

        assert(restored.authenticity.status.bundlePinned === true, 'bundled signature should remain bundlePinned');
        assert(restored.authenticity.status.userPinned === true, 'matching external PQ pin should set userPinned');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'expected bundle-pinned count for bundled PQ signature');
        assert(restored.authenticity.verification.counts.userPinnedValidTotal === 1, 'expected user-pinned count for bundled PQ signature');
      },
    },
    {
      name: 'attach persists Stellar signer identifier in bundle and restore marks it pinned',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('stellar-bundle-pin');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'stellar-bundle-pin.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSig = await buildStellarSignatureFixtureWithSigner(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.sig', bytes: stellarSig.bytes }],
          expectedEd25519Signer: stellarSig.signer,
        });

        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        const stellarSignature = parsedBundle.bundle.attachments.signatures.find((item) => item.format === 'stellar-sig');
        assert(stellarSignature?.publicKeyRef, 'expected attached Stellar signature to reference a persisted signer identifier');
        const signerAttachment = parsedBundle.bundle.attachments.publicKeys.find((item) => item.id === stellarSignature.publicKeyRef);
        assert(signerAttachment?.encoding === 'stellar-address', 'expected Stellar signer attachment encoding');
        assert(signerAttachment?.value === stellarSig.signer, 'expected persisted Stellar signer identifier');

        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          { onLog: () => {}, onError: () => {} }
        );

        assert(restored.authenticity.status.signatureVerified === true, 'expected bundled Stellar signature to verify');
        assert(restored.authenticity.status.signerPinned === true, 'expected bundled Stellar signer identifier to mark signer as pinned');
        assert(restored.authenticity.status.bundlePinned === true, 'bundled Stellar signer identifier should set bundlePinned');
        assert(restored.authenticity.status.userPinned === false, 'bundled Stellar signer identifier alone should not set userPinned');
        assert(restored.authenticity.verification.counts.validTotal === 1, 'expected one bundled Stellar signature');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 1, 'expected one pinned bundled Stellar signature');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'expected one bundle-pinned bundled Stellar signature');
      },
    },
    {
      name: 'export attached artifacts emits a text file for bundled Stellar signer identifiers',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('stellar-export-attachment');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'stellar-export-attachment.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSig = await buildStellarSignatureFixtureWithSigner(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.sig', bytes: stellarSig.bytes }],
          expectedEd25519Signer: stellarSig.signer,
        });

        const bundle = parseManifestBundleBytes(attached.bundleBytes).bundle;
        const exports = buildAttachedArtifactExports(bundle, 'archive');
        const signerExport = exports.find((item) => item.filename.endsWith('.stellar.txt'));
        assert(signerExport, 'expected a text export for the bundled Stellar signer identifier');
        assert(new TextDecoder().decode(signerExport.bytes) === `${stellarSig.signer}\n`, 'expected Stellar signer export to preserve the signer address');
      },
    },
    {
      name: 'attach maps OpenTimestamps by stamped SHA-256 and preserves completion state',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('ots-target-selection');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);
        const otsA = await buildOtsFixture(sigA.qsigBytes, { completeProof: false });
        const otsB = await buildOtsFixture(sigB.qsigBytes, { completeProof: true });

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [
            { name: 'archive-a.qsig', bytes: sigA.qsigBytes },
            { name: 'archive-b.qsig', bytes: sigB.qsigBytes },
          ],
          timestamps: [
            { name: 'archive-a-initial.qsig.ots', bytes: otsA },
            { name: 'archive-b-completed.qsig.ots', bytes: otsB },
          ],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes, sigB.pqpkBytes],
        });
        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        assert(parsedBundle.bundle.attachments.timestamps.length === 2, 'expected two attached OpenTimestamps proofs');

        const signaturesBySigHex = new Map(
          parsedBundle.bundle.attachments.signatures.map((signature) => [
            bytesToHex(base64ToBytes(signature.signature)),
            signature.id,
          ])
        );
        const timestampsByTarget = new Map(parsedBundle.bundle.attachments.timestamps.map((timestamp) => [timestamp.targetRef, timestamp]));
        const sigAId = signaturesBySigHex.get(bytesToHex(sigA.qsigBytes));
        const sigBId = signaturesBySigHex.get(bytesToHex(sigB.qsigBytes));
        assert(sigAId && sigBId, 'expected attached signatures for both qsig inputs');
        assert(timestampsByTarget.get(sigAId)?.apparentlyComplete === false, 'initial .ots must be marked as apparently incomplete');
        assert(timestampsByTarget.get(sigAId)?.completeProof === false, 'initial .ots must remain incomplete');
        assert(timestampsByTarget.get(sigBId)?.apparentlyComplete === true, 'completed .ots must be marked as apparently complete');
        assert(timestampsByTarget.get(sigBId)?.completeProof === true, 'completed .ots must be marked complete');

        const parsedProof = parseOpenTimestampProof(otsA, { name: 'archive-a-initial.qsig.ots' });
        assert(parsedProof.completeProof === false, 'OpenTimestamps parser must classify initial proof as incomplete');
        assert(parsedProof.appearsComplete === false, 'OpenTimestamps parser must report initial proof as apparently incomplete');

        const evidence = await inspectManifestBundleTimestamps(parsedBundle.bundle);
        assert(evidence.length === 2, 'expected two timestamp evidence entries');
        assert(evidence.every((item) => item.linkLabel === 'OTS evidence linked to signature'), 'timestamp evidence should use honest linkage wording');
        assert(
          evidence.some((item) => item.completionLabel === 'OTS proof appears complete') &&
          evidence.some((item) => item.completionLabel === 'OTS proof appears incomplete'),
          'timestamp evidence should report complete and incomplete states honestly'
        );
      },
    },
    {
      name: 'restore links external OpenTimestamps evidence to external detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-external-ots');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-external-ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const otsBytes = await buildOtsFixture(sig.qsigBytes, { completeProof: true });

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
            timestamps: [{ name: 'archive.qsig.ots', bytes: otsBytes }],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'external signature with external OTS should still satisfy archive policy');
        assert(restored.authenticity.timestampEvidence.length === 1, 'expected one external timestamp evidence entry');
        assert(restored.authenticity.timestampEvidence[0].targetVerified === true, 'external OTS should link to a verified detached signature');
        assert(restored.authenticity.timestampEvidence[0].targetSource === 'external', 'external OTS should report external target source');
      },
    },
    {
      name: 'classifyRestoreInputFiles accepts multiple different .pqpk files',
      fn: async () => {
        const manifestBytes = textBytes('restore-multiple-pqpk-inputs');
        const sigA = buildQsigFixture(manifestBytes);
        const sigB = buildQsigFixture(manifestBytes);
        const classified = await classifyRestoreInputFiles([
          fileLike('a.pqpk', sigA.pqpkBytes),
          fileLike('b.pqpk', sigB.pqpkBytes),
        ]);
        assert(classified.pinnedPqPublicKeyFileBytesList.length === 2, 'expected restore inputs to preserve two different .pqpk files');
        assert(classified.pinnedPqPublicKeyFileBytes instanceof Uint8Array, 'expected restore inputs to retain the first .pqpk as a compatibility field');
      },
    },
    {
      name: 'restore can use multiple provided .pqpk files as candidate user pins',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-multiple-pqpk-pins');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-multiple-pqpk-pins.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [
              { name: 'archive-a.qsig', bytes: sigA.qsigBytes },
              { name: 'archive-b.qsig', bytes: sigB.qsigBytes },
            ],
            pinnedPqPublicKeyFileBytesList: [sigA.pqpkBytes, sigB.pqpkBytes],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'multiple restore .pqpk pins should still allow policy-satisfying restore');
        assert(restored.authenticity.status.userPinned === true, 'at least one provided .pqpk should user-pin a verified signature');
        assert(restored.authenticity.verification.counts.userPinnedValidTotal === 2, 'expected both detached signatures to match one of the provided .pqpk pins');
      },
    },
    {
      name: 'multi-pin verification suppresses warnings from non-selected .pqpk candidates when a user pin matches',
      fn: async () => {
        const manifestBytes = textBytes('multi-pin-warning-suppression');
        const matching = buildQsigFixture(manifestBytes);
        const distractor = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: matching.qsigBytes }],
          pinnedPqPublicKeyFileBytesList: [matching.pqpkBytes, distractor.pqpkBytes],
        });

        assert(verification.status.userPinned === true, 'expected a matching .pqpk to set userPinned');
        assert(
          verification.warnings.every((warning) => !warning.includes('Pinned PQ signer key suite does not match this .qsig and was ignored.')),
          'suite-mismatch warnings from non-selected .pqpk candidates should not leak into a matched result'
        );
        assert(
          verification.warnings.every((warning) => !warning.includes('Using signer public key embedded in .qsig')),
          'embedded-key fallback warnings from non-selected .pqpk candidates should not leak into a matched result'
        );
      },
    },
    {
      name: 'restore links external OpenTimestamps evidence to bundled detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-bundled-ots');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-bundled-ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const otsBytes = await buildOtsFixture(sig.qsigBytes, { completeProof: false });

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });
        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          {
            onLog: () => {},
            onError: () => {},
            verification: {
              timestamps: [{ name: 'archive.qsig.ots', bytes: otsBytes }],
            },
          }
        );

        assert(restored.authenticity.status.policySatisfied === true, 'bundled signature plus external OTS should satisfy archive policy');
        assert(restored.authenticity.timestampEvidence.length === 1, 'expected one external timestamp evidence entry for bundled signature');
        assert(restored.authenticity.timestampEvidence[0].targetSource === 'bundle', 'external OTS should link to bundled detached signature');
      },
    },
    {
      name: 'restore deduplicates OTS evidence per detached signature and prefers complete proofs',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-ots-dedupe');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-ots-dedupe.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);
        const embeddedCompleteA = await buildOtsFixture(sigA.qsigBytes, { completeProof: true });
        const embeddedIncompleteA = await buildOtsFixture(sigA.qsigBytes, { completeProof: false });
        const embeddedCompleteB = await buildOtsFixture(sigB.qsigBytes, { completeProof: true });
        const externalIncompleteB = await buildOtsFixture(sigB.qsigBytes, { completeProof: false });

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [
            { name: 'archive-a.qsig', bytes: sigA.qsigBytes },
            { name: 'archive-b.qsig', bytes: sigB.qsigBytes },
          ],
          timestamps: [
            { name: 'archive-a-complete.qsig.ots', bytes: embeddedCompleteA },
            { name: 'archive-a-incomplete.qsig.ots', bytes: embeddedIncompleteA },
            { name: 'archive-b-complete.qsig.ots', bytes: embeddedCompleteB },
          ],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes, sigB.pqpkBytes],
        });

        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          {
            onLog: () => {},
            onError: () => {},
            verification: {
              timestamps: [
                { name: 'archive-a-complete.external.qsig.ots', bytes: embeddedCompleteA },
                { name: 'archive-b-incomplete.external.qsig.ots', bytes: externalIncompleteB },
              ],
            },
          }
        );

        assert(restored.authenticity.timestampEvidence.length === 2, 'expected one preferred OTS evidence entry per detached signature');
        assert(
          restored.authenticity.timestampEvidence.every((item) => item.apparentlyComplete === true),
          'complete OTS proofs should win over incomplete duplicates for the same detached signature'
        );
      },
    },
    {
      name: 'attach rejects unrelated OpenTimestamps evidence',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('ots-unrelated');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'ots-unrelated.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const unrelatedOts = await buildOtsFixture(textBytes('not-a-detached-signature'), { completeProof: false });

        await expectFailure(
          () => attachManifestBundleToShards(parsed, {
            manifestBytes: split.manifestBytes,
            signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
            timestamps: [{ name: 'archive.qsig.ots', bytes: unrelatedOts }],
            pqPublicKeyFileBytesList: [sig.pqpkBytes],
          }),
          'attach unexpectedly accepted unrelated OpenTimestamps evidence'
        );
      },
    },
    {
      name: 'restore rejects unrelated external OpenTimestamps evidence',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-unrelated-ots');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-unrelated-ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const unrelatedOts = await buildOtsFixture(textBytes('not-a-detached-signature'), { completeProof: false });

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
              timestamps: [{ name: 'archive.qsig.ots', bytes: unrelatedOts }],
            },
          }),
          'restore unexpectedly accepted unrelated external OpenTimestamps evidence'
        );
      },
    },
    {
      name: 'OpenTimestamps evidence never satisfies archive signature policy by itself',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('ots-does-not-satisfy-policy');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'ots-does-not-satisfy-policy.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSigBytes = await buildStellarSignatureFixture(split.manifestBytes);
        const otsBytes = await buildOtsFixture(stellarSigBytes, { completeProof: true });
        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.sig', bytes: stellarSigBytes }],
          timestamps: [{ name: 'archive.sig.ots', bytes: otsBytes }],
        });
        const attachedShards = await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));

        await expectFailure(
          () => restoreFromShards(attachedShards, { onLog: () => {}, onError: () => {} }),
          'OpenTimestamps evidence unexpectedly satisfied strong-pq-signature policy'
        );
      },
    },
    {
      name: 'attach updates manifest-only and bundle-only inputs without rewriting shards',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('manifest-only-attach');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'bundle-only.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const sigA = buildQsigFixture(split.manifestBytes);
        const firstAttach = await attachManifestBundleToShards([], {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive-a.qsig', bytes: sigA.qsigBytes }],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes],
        });

        const sigB = buildQsigFixture(split.manifestBytes);
        const secondAttach = await attachManifestBundleToShards([], {
          bundleBytes: firstAttach.bundleBytes,
          signatures: [{ name: 'archive-b.qsig', bytes: sigB.qsigBytes }],
          pqPublicKeyFileBytesList: [sigB.pqpkBytes],
        });

        assert(firstAttach.shards.length === 0, 'manifest-only attach must not rewrite shards');
        assert(secondAttach.shards.length === 0, 'bundle-only attach must not rewrite shards');
        assert(
          timingSafeEqual(firstAttach.signableManifestBytes, split.manifestBytes) &&
          timingSafeEqual(firstAttach.manifestBytes, split.manifestBytes),
          'manifest-only attach must keep canonical-manifest export separate and unchanged'
        );
        assert(firstAttach.manifestDigestHex === split.manifestDigestHex, 'manifest-only attach must preserve the canonical manifest digest');
        assert(secondAttach.manifestDigestHex === split.manifestDigestHex, 'repeated bundle-only attach must preserve the canonical manifest digest');
        const parsedBundle = parseManifestBundleBytes(secondAttach.bundleBytes);
        assert(parsedBundle.bundle.attachments.signatures.length === 2, 'bundle-only attach must merge signatures into the manifest bundle');

        const originalShards = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const restored = await restoreFromShards(originalShards, {
          onLog: () => {},
          onError: () => {},
          verification: { bundleBytes: secondAttach.bundleBytes },
        });
        assert(restored.authenticity.status.policySatisfied === true, 'repeated attach cycles must preserve signature validity');
        assert(restored.authenticity.verification.counts.validTotal === 2, 'repeated attach cycles must preserve both detached signatures');
      },
    },
    {
      name: 'restore prefers the richer embedded bundle when mixed shards share the same canonical manifest',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-prefer-richer-bundle');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-prefer-richer-bundle.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const originalShards = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const attached = await attachManifestBundleToShards(originalShards, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });
        const updatedShards = await Promise.all(attached.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));

        const mixed = [
          updatedShards[0],
          updatedShards[1],
          originalShards[2],
          originalShards[3],
        ];
        const restored = await restoreFromShards(mixed, {
          onLog: () => {},
          onError: () => {},
        });

        assert(restored.manifestSource === 'embedded-preferred-bundle', `unexpected manifest source: ${restored.manifestSource}`);
        assert(restored.bundleDigestHex === attached.bundleDigestHex, 'restore should prefer the richer embedded bundle digest');
        assert(restored.authenticity.status.policySatisfied === true, 'preferred richer embedded bundle should satisfy archive policy');
        assert(restored.authenticity.status.bundlePinned === true, 'preferred richer embedded bundle should preserve bundled signer pinning');
      },
    },
    {
      name: 'strong-pq-signature policy rejects Ed25519-only signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('legacy-signature-only');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'legacy.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSigBytes = await buildStellarSignatureFixture(split.manifestBytes);

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: { signatures: [{ name: 'archive.sig', bytes: stellarSigBytes }] },
          }),
          'strong-pq-signature archive unexpectedly accepted Ed25519-only signature'
        );
      },
    },
    {
      name: 'restore rejects duplicate shard indices',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-index');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'dup.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const shardBytes = await Promise.all(split.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const parsed = [
          parseShard(shardBytes[0]),
          parseShard(shardBytes[0]),
          parseShard(shardBytes[1]),
          parseShard(shardBytes[2]),
        ];

        await expectFailure(
          () => restoreFromShards(parsed, { onLog: () => {}, onError: () => {} }),
          'restore unexpectedly accepted duplicate shard indices'
        );
      },
    },
    {
      name: 'qenc decrypt must fail with unrelated private key',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('wrong-key-check');
        const encrypted = await encryptFile(payload, pairA.publicKey, 'wrong-key.bin');
        const encryptedBytes = await blobToBytes(encrypted);

        await expectFailure(
          () => decryptFile(encryptedBytes, pairB.secretKey),
          'decrypt unexpectedly succeeded with unrelated private key'
        );
      },
    },
    {
      name: 'qenc decrypt must fail on ciphertext tamper',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('tamper-check');
        const encrypted = await encryptFile(payload, pair.publicKey, 'tamper.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const tampered = mutateTail(encryptedBytes);

        await expectFailure(
          () => decryptFile(tampered, pair.secretKey),
          'decrypt unexpectedly succeeded on tampered qenc'
        );
      },
    },
    {
      name: 'qcont restore fails when missing+corrupted exceeds RS tolerance',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('qcont-too-many-errors');
        const encrypted = await encryptFile(payload, pair.publicKey, 'qcont-fail.bin');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const qconts = split.shards;
        const shardBytes = await Promise.all(qconts.map((shard) => blobToBytes(shard.blob)));

        const subset = shardBytes.slice(0, 4).map((bytes) => bytes.slice());
        subset[0] = mutateTail(subset[0]);
        const parsed = subset.map((bytes) => parseShard(bytes));

        await expectFailure(
          () => restoreFromShards(parsed, { onLog: () => {}, onError: () => {} }),
          'restore unexpectedly succeeded with too many missing/corrupted shards'
        );
      },
    },
    {
      name: 'qenc chunked mode roundtrip (> CHUNK_SIZE)',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(CHUNK_SIZE + 12345);
        const encrypted = await encryptFile(payload, pair.publicKey, 'chunked.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const header = parseQencHeader(encryptedBytes);
        assert(header.metadata.aead_mode === 'per-chunk-aead', 'expected per-chunk-aead mode');
        assert(header.metadata.chunkCount >= 2, 'expected chunkCount >= 2 for chunked payload');
        assert(header.metadata.noncePolicyId === NONCE_POLICY_PER_CHUNK_V3, 'per-chunk noncePolicyId mismatch');
        assert(header.metadata.nonceMode === NONCE_MODE_KMAC_CTR32, 'per-chunk nonceMode mismatch');
        assert(header.metadata.counterBits === 32, 'per-chunk counterBits mismatch');
        assert(header.metadata.maxChunkCount === 0xffffffff, 'per-chunk maxChunkCount mismatch');
        assert(header.metadata.iv_strategy === IV_STRATEGY_KMAC_PREFIX64_CTR32_V3, 'per-chunk iv_strategy mismatch');

        const { decryptedBlob, metadata } = await decryptFile(encryptedBytes, pair.secretKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert(metadata.fileHash === (await hashBytes(payload)), 'chunked metadata hash mismatch');
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'chunked roundtrip mismatch');
      },
    },
    {
      name: 'KMAC wrapper applies SP 800-185 customization and dkLen semantics',
      fn: async () => {
        const key = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        const message = textBytes('Quantum Vault KMAC regression test');
        const out32 = kmac256(key, message, {
          customization: 'quantum-vault:test:v2',
          dkLen: 32,
        });
        const out8 = kmac256(key, message, {
          customization: 'quantum-vault:test:v2',
          dkLen: 8,
        });
        const out32Alt = kmac256(key, message, {
          customization: 'quantum-vault:test:alt:v2',
          dkLen: 32,
        });

        assert(
          bytesToHex(out32) === 'e4c32540bbeba9c4ada8e0b74df68e0dd9280181d1ee95cabe61a7f290a7253d',
          'KMAC 32-byte regression vector mismatch'
        );
        assert(
          bytesToHex(out8) === '166add657780655a',
          'KMAC 8-byte regression vector mismatch'
        );
        assert(
          bytesToHex(out32Alt) === 'e691cf1c1df8c2a55415532c0b1076e1891f11dc0af86c9cab46cc98485bbf88',
          'KMAC alternate customization vector mismatch'
        );
        assert(
          bytesToHex(out8) !== bytesToHex(out32.subarray(0, 8)),
          'KMAC dkLen=8 must not equal truncation of the 32-byte output'
        );
      },
    },
    {
      name: 'deriveChunkIvFromK uses SP 800-185 KMAC prefix derivation',
      fn: async () => {
        const Kiv = Uint8Array.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff));
        const containerNonce = Uint8Array.from(Array.from({ length: 12 }, (_, i) => (i * 5 + 11) & 0xff));
        const iv = deriveChunkIvFromK(Kiv, containerNonce, 7, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, {
          chunkCount: 16,
          maxChunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          counterBits: NONCE_COUNTER_BITS_U32,
          ivStrategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        });

        assert(
          bytesToHex(iv) === '1a0f9d63bb6bf37300000007',
          'deriveChunkIvFromK regression vector mismatch'
        );
      },
    },
    {
      name: 're-encrypt same plaintext keeps (Kenc,nonce) unique',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('nonce-t01-same-plaintext');
        const seenPairs = new Set();

        for (let i = 0; i < 64; i += 1) {
          const encrypted = await encryptFile(payload, pair.publicKey, 'nonce-t01.bin');
          const encryptedBytes = await blobToBytes(encrypted);
          const parsed = parseQencHeader(encryptedBytes);
          assert(parsed.storedKeyCommitment instanceof Uint8Array, 'key commitment is missing');
          assert(parsed.containerNonce instanceof Uint8Array, 'container nonce is missing');
          const pairId = `${bytesToHex(parsed.storedKeyCommitment)}:${bytesToHex(parsed.containerNonce)}`;
          assert(!seenPairs.has(pairId), `detected (Kenc,nonce) reuse at iteration ${i}`);
          seenPairs.add(pairId);
        }
      },
    },
    {
      name: 'reject chunk counter wrap near 2^32 boundary',
      fn: async () => {
        const contract = {
          maxChunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          counterBits: NONCE_COUNTER_BITS_U32,
          ivStrategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        };

        assertPerChunkNonceContract({
          chunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          ...contract,
        });

        await expectFailure(
          async () => {
            assertPerChunkNonceContract({
              chunkCount: NONCE_MAX_CHUNK_COUNT_U32 + 1,
              ...contract,
            });
          },
          'nonce contract unexpectedly accepted chunkCount above uint32 policy bound'
        );

        const Kiv = createLargeDeterministicPayload(32);
        const containerNonce = createLargeDeterministicPayload(12);
        await expectFailure(
          async () => {
            deriveChunkIvFromK(Kiv, containerNonce, NONCE_MAX_CHUNK_COUNT_U32, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, {
              chunkCount: NONCE_MAX_CHUNK_COUNT_U32,
              ...contract,
            });
          },
          'deriveChunkIvFromK unexpectedly accepted wrapped chunk index'
        );
      },
    },
    {
      name: 'crafted per-chunk IV collision campaign is blocked',
      fn: async () => {
        const Kiv = createLargeDeterministicPayload(32);
        const containerNonce = createLargeDeterministicPayload(12);
        const chunkCount = 4096;
        const contract = {
          chunkCount,
          maxChunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          counterBits: NONCE_COUNTER_BITS_U32,
          ivStrategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        };
        assertPerChunkNonceContract(contract);

        const seenIvs = new Set();
        for (let i = 0; i < chunkCount; i += 1) {
          const iv = deriveChunkIvFromK(Kiv, containerNonce, i, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, contract);
          const ivHex = bytesToHex(iv);
          assert(!seenIvs.has(ivHex), `unexpected IV collision at chunk index ${i}`);
          seenIvs.add(ivHex);
        }

        await expectFailure(
          async () => {
            deriveChunkIvFromK(Kiv, containerNonce, 2 ** 32, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, contract);
          },
          'deriveChunkIvFromK unexpectedly accepted overflowed chunk index'
        );
      },
    },
    {
      name: 'parseQencHeader rejects invalid magic',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('qenc-parse-check');
        const encrypted = await encryptFile(payload, pair.publicKey, 'parse.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const malformed = encryptedBytes.slice();
        malformed[0] ^= 0xff;

        await expectFailure(
          async () => {
            parseQencHeader(malformed);
          },
          'parseQencHeader unexpectedly accepted invalid magic'
        );
      },
    },
    {
      name: 'buildQcontShards rejects mismatched private key',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('wrong-key-at-build');
        const encrypted = await encryptFile(payload, pairA.publicKey, 'f10.bin');
        const qencBytes = await blobToBytes(encrypted);

        await expectFailure(
          () => buildQcontShards(qencBytes, pairB.secretKey, { n: 5, k: 3 }),
          'buildQcontShards unexpectedly accepted mismatched private key'
        );
      },
    },
    {
      name: 'decryptFile fails closed when key commitment is missing',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('key-commitment-required');
        const encrypted = await encryptFile(payload, pair.publicKey, 'f11.bin');
        const encBytes = await blobToBytes(encrypted);
        const malformed = removeQencKeyCommitmentBytes(encBytes);

        await expectFailure(
          () => decryptFile(malformed, pair.secretKey),
          'decryptFile unexpectedly accepted missing key commitment'
        );
      },
    },
    {
      name: 'encryptFile rejects empty payload',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        await expectFailure(
          () => encryptFile(new Uint8Array(0), pair.publicKey, 'empty.bin'),
          'encryptFile unexpectedly accepted empty payload'
        );
      },
    },
    {
      name: 'bytes.js: toHex/fromHex roundtrip',
      fn: async () => {
        const original = createLargeDeterministicPayload(64);
        const hex = toHex(original);
        assert(hex.length === 128, 'hex length mismatch');
        const roundtripped = fromHex(hex);
        assert(roundtripped.length === 64, 'fromHex length mismatch');
        assert(timingSafeEqual(original, roundtripped), 'toHex/fromHex roundtrip mismatch');
      },
    },
    {
      name: 'bytes.js: timingSafeEqual rejects length mismatch and bitflip',
      fn: async () => {
        const a = createLargeDeterministicPayload(32);
        const b = a.slice();
        assert(timingSafeEqual(a, b), 'identical arrays must be equal');

        const shorter = a.slice(0, 16);
        assert(!timingSafeEqual(a, shorter), 'different lengths must not be equal');

        const flipped = a.slice();
        flipped[15] ^= 1;
        assert(!timingSafeEqual(a, flipped), 'bitflipped array must not be equal');

        assert(!timingSafeEqual(a, 'not-uint8array'), 'non-Uint8Array must return false');
      },
    },
    {
      name: 'ADV: parseShard rejects empty input',
      fn: async () => {
        await expectFailure(
          () => parseShard(new Uint8Array(0), { strict: true }),
          'parseShard unexpectedly accepted empty Uint8Array'
        );
        await expectFailure(
          () => parseShard(new Uint8Array(4), { strict: true }),
          'parseShard unexpectedly accepted 4-byte Uint8Array'
        );
      },
    },
    {
      name: 'ADV: parseShard rejects invalid magic bytes',
      fn: async () => {
        const garbage = createLargeDeterministicPayload(512);
        await expectFailure(
          () => parseShard(garbage, { strict: true }),
          'parseShard unexpectedly accepted garbage bytes'
        );
      },
    },
    {
      name: 'ADV: validatePublicKey rejects wrong-size keys',
      fn: async () => {
        const { validatePublicKey: vpk, validateSecretKey: vsk } = await import('./mlkem.js');
        await expectFailure(
          () => vpk(new Uint8Array(100)),
          'validatePublicKey accepted wrong-size key'
        );
        await expectFailure(
          () => vpk('not-a-uint8array'),
          'validatePublicKey accepted non-Uint8Array'
        );
        await expectFailure(
          () => vsk(new Uint8Array(100)),
          'validateSecretKey accepted wrong-size key'
        );
      },
    },
    {
      name: 'ADV: encryptFile rejects payload exceeding MAX_FILE_SIZE',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const fakeLargePayload = { length: MAX_FILE_SIZE + 1, [Symbol.iterator]: function*(){} };
        await expectFailure(
          () => encryptFile(fakeLargePayload, pair.publicKey, 'too-big.bin'),
          'encryptFile unexpectedly accepted payload exceeding MAX_FILE_SIZE'
        );
      },
    },
    {
      name: 'ADV: buildQcontShards rejects invalid RS params',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('bad-rs-params');
        const qenc = await blobToBytes(await encryptFile(payload, pair.publicKey, 'rs.bin'));

        await expectFailure(
          () => buildQcontShards(qenc, pair.secretKey, { n: 1, k: 1 }),
          'buildQcontShards accepted n=1, k=1'
        );
        await expectFailure(
          () => buildQcontShards(qenc, pair.secretKey, { n: 3, k: 5 }),
          'buildQcontShards accepted k > n'
        );
      },
    },
    {
      name: 'ADV: qenc decrypt fails on truncated container',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('truncated-container-check');
        const encrypted = await encryptFile(payload, pair.publicKey, 'trunc.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const truncated = encryptedBytes.slice(0, 64);

        await expectFailure(
          () => decryptFile(truncated, pair.secretKey),
          'decryptFile unexpectedly succeeded on truncated container'
        );
      },
    },
    {
      name: 'ADV: qenc chunked decrypt fails on swapped chunks',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload((CHUNK_SIZE * 2) + 4096);
        const encrypted = await encryptFile(payload, pair.publicKey, 'swap.bin');
        const encBytes = await blobToBytes(encrypted);
        const header = parseQencHeader(encBytes);
        assert(header.metadata.chunkCount >= 3, 'need at least 3 chunks for swap test');

        const headerEnd = header.offset;
        const tagLen = 16;
        const chunkCipherLen = CHUNK_SIZE + tagLen;
        const chunk0 = encBytes.slice(headerEnd, headerEnd + chunkCipherLen);
        const chunk1Start = headerEnd + chunkCipherLen;
        const chunk1 = encBytes.slice(chunk1Start, chunk1Start + chunkCipherLen);
        let exercised = false;

        if (chunk0.length === chunkCipherLen && chunk1.length > 0) {
          const swapped = encBytes.slice();
          swapped.set(chunk1.slice(0, Math.min(chunk1.length, chunkCipherLen)), headerEnd);
          swapped.set(chunk0, chunk1Start);
          exercised = true;

          await expectFailure(
            () => decryptFile(swapped, pair.secretKey),
            'decryptFile unexpectedly succeeded with swapped chunks'
          );
        }

        assert(exercised, 'swap test did not exercise full-chunk swap path');
      },
    },
    {
      name: 'ADV: parseShard non-strict returns diagnostics instead of throw',
      fn: async () => {
        const garbage = createLargeDeterministicPayload(512);
        const result = parseShard(garbage, { strict: false });
        assert(Array.isArray(result.diagnostics?.errors), 'non-strict parseShard must return diagnostics.errors');
        assert(result.diagnostics.errors.length > 0, 'non-strict parseShard must report errors for garbage input');
        assert(!result.metaJSON, 'non-strict parseShard must not have metaJSON for garbage input');
      },
    },
    {
      name: 'chunked split + restore end-to-end (per-chunk-aead)',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(CHUNK_SIZE + 50000);
        const encrypted = await encryptFile(payload, pair.publicKey, 'chunked-e2e.bin');
        const qencBytes = await blobToBytes(encrypted);

        const header = parseQencHeader(qencBytes);
        assert(header.metadata.aead_mode === 'per-chunk-aead', 'expected per-chunk-aead');

        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 7, k: 5 }, { authPolicyLevel: 'integrity-only' });
        assert(split.shards.length === 7, 'expected 7 shards');

        const shardBytes = await Promise.all(split.shards.map(s => blobToBytes(s.blob)));
        const subset = shardBytes.slice(0, 6).map(b => parseShard(b));

        const restored = await restoreFromShards(subset, { onLog: () => {}, onError: () => {} });
        assert(restored.qencOk, 'chunked e2e: qenc hash mismatch');

        const { decryptedBlob } = await decryptFile(restored.qencBytes, restored.privKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'chunked e2e: payload mismatch');
      },
    },
  ];
}

export async function runSelfTest({ onProgress } = {}) {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  const cases = buildCases().map((item) => ({
    ...item,
    name: prefixSelfTestName(item.name),
  }));
  const results = [];

  if (typeof onProgress === 'function') {
    onProgress(0, cases.length, 'Starting self-test');
  }

  for (let i = 0; i < cases.length; i += 1) {
    const current = cases[i];
    const result = await runCase(current.name, current.fn);
    results.push(result);
    if (typeof onProgress === 'function') {
      onProgress(i + 1, cases.length, current.name);
    }
  }

  const passed = results.filter((result) => result.ok).length;
  const failed = results.length - passed;

  return {
    ok: failed === 0,
    total: results.length,
    passed,
    failed,
    results,
  };
}
