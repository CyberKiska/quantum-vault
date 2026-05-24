import assert from 'node:assert/strict';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { buildQencHeader, parseQencHeader } from '../../src/core/crypto/qenc/format.js';
import { FORMAT_VERSION, KEY_COMMITMENT_SIZE, MAGIC } from '../../src/core/crypto/constants.js';
import {
  IV_STRATEGY_SINGLE_IV,
  IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
  NONCE_COUNTER_BITS_U32,
  NONCE_MAX_CHUNK_COUNT_U32,
} from '../../src/core/crypto/aead.js';
import { DEFAULT_CRYPTO_PROFILE } from '../../src/core/crypto/policy.js';

const encoder = new TextEncoder();

function bytes(length, start = 0) {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function metadataForMode(aeadMode) {
  const single = aeadMode === 'single-container-aead';
  return {
    KEM: 'ML-KEM-1024',
    KDF: 'KMAC256',
    AEAD: 'AES-256-GCM',
    aead_mode: aeadMode,
    iv_strategy: single ? IV_STRATEGY_SINGLE_IV : IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
    fmt: FORMAT_VERSION,
    hasKeyCommitment: true,
    payloadFormat: 'wrapped-v1',
    payloadLength: single ? 41 : 8_388_700,
    chunkSize: 8_388_608,
    chunkCount: single ? 1 : 2,
    cryptoProfileId: DEFAULT_CRYPTO_PROFILE.cryptoProfileId,
    kdfTreeId: DEFAULT_CRYPTO_PROFILE.kdfTreeId,
    noncePolicyId: single ? 'QV-GCM-RAND96-v1' : 'QV-GCM-KMACPFX64-CTR32-v3',
    nonceMode: single ? 'random96' : 'kmac-prefix64-ctr32',
    counterBits: single ? 0 : NONCE_COUNTER_BITS_U32,
    maxChunkCount: single ? 1 : NONCE_MAX_CHUNK_COUNT_U32,
    aadPolicyId: DEFAULT_CRYPTO_PROFILE.aadPolicyId,
    domainStrings: {
      kdf: 'quantum-vault:kdf:v2',
      iv: 'quantum-vault:chunk-iv:v2',
      kenc: 'quantum-vault:kenc:v2',
      kiv: 'quantum-vault:kiv:v2',
    },
  };
}

function buildContainer({
  metadata = metadataForMode('single-container-aead'),
  encapsulatedKey = bytes(1568, 0x10),
  containerNonce = bytes(12, 0x20),
  kdfSalt = bytes(16, 0x30),
  keyCommitment = bytes(KEY_COMMITMENT_SIZE, 0x40),
  ciphertext = bytes(17, 0x50),
} = {}) {
  const metaBytes = encoder.encode(JSON.stringify(metadata));
  const header = buildQencHeader({
    encapsulatedKey,
    containerNonce,
    kdfSalt,
    metaBytes,
    keyCommitment,
  });
  return {
    header,
    container: concatBytes(header, ciphertext),
    metaBytes,
    metadata,
    encapsulatedKey,
    containerNonce,
    kdfSalt,
    keyCommitment,
    ciphertext,
  };
}

test('.qenc header builder and parser preserve framing and authenticated metadata bytes', () => {
  const vector = buildContainer();
  const parsed = parseQencHeader(vector.container);
  const view = new DataView(vector.header.buffer, vector.header.byteOffset, vector.header.byteLength);

  assert.deepEqual([...vector.header.subarray(0, MAGIC.length)], [...MAGIC]);
  assert.equal(view.getUint32(MAGIC.length, false), vector.encapsulatedKey.length);
  assert.equal(
    view.getUint16(MAGIC.length + 4 + vector.encapsulatedKey.length + 12 + 16, false),
    vector.metaBytes.length,
  );
  assert.equal(parsed.offset, vector.header.length);
  assert.deepEqual(parsed.header, vector.header);
  assert.deepEqual(parsed.encapsulatedKey, vector.encapsulatedKey);
  assert.deepEqual(parsed.containerNonce, vector.containerNonce);
  assert.deepEqual(parsed.kdfSalt, vector.kdfSalt);
  assert.deepEqual(parsed.metaBytes, vector.metaBytes);
  assert.deepEqual(parsed.metadata, vector.metadata);
  assert.deepEqual(parsed.storedKeyCommitment, vector.keyCommitment);
  assert.equal(parsed.metadata.hasKeyCommitment, true);
  assert.equal(toHex(sha3_512(parsed.header)), toHex(sha3_512(vector.header)));
});

test('.qenc parser accepts the current single-container and per-chunk nonce contracts', () => {
  for (const aeadMode of ['single-container-aead', 'per-chunk-aead']) {
    const vector = buildContainer({ metadata: metadataForMode(aeadMode) });
    const parsed = parseQencHeader(vector.container);
    assert.equal(parsed.metadata.aead_mode, aeadMode);
    assert.equal(parsed.metadata.hasKeyCommitment, true);
    if (aeadMode === 'single-container-aead') {
      assert.equal(parsed.metadata.iv_strategy, IV_STRATEGY_SINGLE_IV);
      assert.equal(parsed.metadata.counterBits, 0);
      assert.equal(parsed.metadata.maxChunkCount, 1);
    } else {
      assert.equal(parsed.metadata.iv_strategy, IV_STRATEGY_KMAC_PREFIX64_CTR32_V3);
      assert.equal(parsed.metadata.counterBits, NONCE_COUNTER_BITS_U32);
      assert.equal(parsed.metadata.maxChunkCount, NONCE_MAX_CHUNK_COUNT_U32);
      assert.equal(parsed.metadata.chunkCount, 2);
    }
  }
});

test('.qenc parser fails closed on malformed header lengths and missing key commitment', () => {
  const vector = buildContainer();

  assert.throws(
    () => parseQencHeader(concatBytes(Uint8Array.of(0x00), vector.container.subarray(1))),
    /magic bytes mismatch/,
  );

  const truncatedEncapsulatedKey = vector.container.slice();
  new DataView(truncatedEncapsulatedKey.buffer).setUint32(MAGIC.length, vector.container.length + 1, false);
  assert.throws(
    () => parseQencHeader(truncatedEncapsulatedKey),
    /encapsulated key length/,
  );

  const missingCommitment = concatBytes(vector.header.subarray(0, vector.header.length - KEY_COMMITMENT_SIZE), bytes(8, 0x99));
  assert.throws(
    () => parseQencHeader(missingCommitment),
    /key commitment missing/,
  );

  assert.throws(
    () => parseQencHeader(vector.header),
    /ciphertext is missing/,
  );

  const noCommitmentFlag = buildContainer({
    metadata: { ...metadataForMode('single-container-aead'), hasKeyCommitment: false },
  });
  assert.throws(
    () => parseQencHeader(noCommitmentFlag.container),
    /hasKeyCommitment must be true/,
  );
});
