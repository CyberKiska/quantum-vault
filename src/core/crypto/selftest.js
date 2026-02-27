import { CHUNK_SIZE, decryptFile, encryptFile, generateKeyPair, hashBytes } from './index.js';
import { validatePublicKey, validateSecretKey } from './mlkem.js';
import { buildQcontShards } from './qcont/build.js';
import { parseShard, restoreFromShards } from './qcont/restore.js';
import { parseQencHeader } from './qenc/format.js';
import { createBundlePayloadFromFiles, isBundlePayload, parseBundlePayload } from '../features/bundle-payload.js';
import {
  NONCE_MODE_KMAC_CTR32,
  NONCE_MODE_RANDOM96,
  NONCE_POLICY_PER_CHUNK_V1,
  NONCE_POLICY_SINGLE_CONTAINER_V1,
} from './policy.js';

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

async function ensureRuntimeCrypto() {
  if (globalThis.crypto?.subtle) return;
  const isNode = typeof process !== 'undefined' && Boolean(process.versions?.node);
  if (!isNode) {
    throw new Error('Web Crypto API is not available in current runtime');
  }
  const { webcrypto } = await import('node:crypto');
  globalThis.crypto = webcrypto;
}

async function ensureErasureRuntime() {
  const existing = globalThis.window?.erasure;
  if (existing?.split && existing?.recombine) return;

  if (!globalThis.window) {
    globalThis.window = globalThis;
  }

  await import('../../../public/third-party/erasure.js');

  const erasure = globalThis.window?.erasure;
  if (!erasure?.split || !erasure?.recombine) {
    throw new Error('Reed-Solomon runtime (window.erasure) is unavailable');
  }
}

async function runCase(name, fn) {
  try {
    await fn();
    return { name, ok: true };
  } catch (error) {
    return { name, ok: false, error: error?.message || String(error) };
  }
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

        assert(parsedHeader.metadata.fmt === 'QVv1-4-0', `unexpected format: ${parsedHeader.metadata.fmt}`);
        assert(parsedHeader.metadata.payloadFormat === 'wrapped-v1', 'unexpected payload format');
        assert(parsedHeader.metadata.aead_mode === 'single-container-aead', 'unexpected AEAD mode');
        assert(parsedHeader.metadata.noncePolicyId === NONCE_POLICY_SINGLE_CONTAINER_V1, 'single-container noncePolicyId mismatch');
        assert(parsedHeader.metadata.nonceMode === NONCE_MODE_RANDOM96, 'single-container nonceMode mismatch');
        assert(parsedHeader.metadata.counterBits === 0, 'single-container counterBits mismatch');
        assert(parsedHeader.metadata.maxChunkCount === 1, 'single-container maxChunkCount mismatch');

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
        const built = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 });
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

        const splitA = await buildQcontShards(qencA, pairA.secretKey, { n: 5, k: 3 });
        const splitB = await buildQcontShards(qencB, pairB.secretKey, { n: 5, k: 3 });

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

        const splitA = await buildQcontShards(qencA, pairA.secretKey, { n: 5, k: 3 });
        const splitB = await buildQcontShards(qencB, pairB.secretKey, { n: 5, k: 3 });

        const selectedShardBytes = await Promise.all(splitA.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const distractorShardBytes = await blobToBytes(splitB.shards[0].blob);
        const parsed = [...selectedShardBytes, distractorShardBytes].map((bytes) => parseShard(bytes));

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: { manifestBytes: splitA.manifestBytes },
        });

        assert(restored.qencOk, 'restore with uploaded manifest failed qenc hash check');
        assert(restored.manifestSource === 'uploaded', `unexpected manifest source: ${restored.manifestSource}`);
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
      name: 'restore strict policy requires trusted signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('strict-authn');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'strict.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 });
        const shardBytes = await Promise.all(split.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const parsed = shardBytes.map((bytes) => parseShard(bytes));

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: { requireTrustedSignature: true },
          }),
          'restore unexpectedly allowed strict trusted-signature mode without signatures'
        );
      },
    },
    {
      name: 'restore rejects duplicate shard indices',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-index');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'dup.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 });
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
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 });
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
        assert(header.metadata.noncePolicyId === NONCE_POLICY_PER_CHUNK_V1, 'per-chunk noncePolicyId mismatch');
        assert(header.metadata.nonceMode === NONCE_MODE_KMAC_CTR32, 'per-chunk nonceMode mismatch');
        assert(header.metadata.counterBits === 32, 'per-chunk counterBits mismatch');
        assert(header.metadata.maxChunkCount === 0xffffffff, 'per-chunk maxChunkCount mismatch');

        const { decryptedBlob, metadata } = await decryptFile(encryptedBytes, pair.secretKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert(metadata.fileHash === (await hashBytes(payload)), 'chunked metadata hash mismatch');
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'chunked roundtrip mismatch');
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
  ];
}

export async function runSelfTest({ onProgress } = {}) {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  const cases = buildCases();
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
