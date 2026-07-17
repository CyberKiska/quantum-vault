import assert from 'node:assert/strict';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import {
  buildQencHeader,
  MAX_QENC_METADATA_BYTES,
  parseQencHeader,
} from '../../src/core/crypto/qenc/format.js';
import { KEY_COMMITMENT_SIZE, MAGIC } from '../../src/core/crypto/constants.js';
import {
  IV_STRATEGY_SINGLE_IV,
  IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
  NONCE_COUNTER_BITS_U32,
  NONCE_MAX_CHUNK_COUNT_U32,
} from '../../src/core/crypto/aead.js';
import { ML_KEM_1024_ENCAPSULATED_KEY_SIZE } from '../../src/core/crypto/mlkem.js';

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

function uint16be(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
}

function uint32be(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function padJsonBytes(metadata, length) {
  const jsonBytes = encoder.encode(JSON.stringify(metadata));
  assert.ok(jsonBytes.length <= length, 'metadata fixture exceeds requested padded length');
  const out = new Uint8Array(length);
  out.fill(0x20);
  out.set(jsonBytes);
  return out;
}

function buildRawHeader({
  metaBytes,
  encapsulatedKey = bytes(ML_KEM_1024_ENCAPSULATED_KEY_SIZE, 0x10),
  containerNonce = bytes(12, 0x20),
  kdfSalt = bytes(16, 0x30),
  keyCommitment = bytes(KEY_COMMITMENT_SIZE, 0x40),
}) {
  return concatBytes(
    Uint8Array.from(MAGIC),
    uint32be(encapsulatedKey.length),
    encapsulatedKey,
    containerNonce,
    kdfSalt,
    uint16be(metaBytes.length),
    metaBytes,
    keyCommitment,
  );
}

function metadataForMode(aeadMode) {
  const single = aeadMode === 'single-container-aead';
  return {
    KEM: 'ML-KEM-1024',
    KDF: 'KMAC256',
    AEAD: 'AES-256-GCM',
    aead_mode: aeadMode,
    iv_strategy: single ? IV_STRATEGY_SINGLE_IV : IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
    fmt: 'QVv1-5-0',
    hasKeyCommitment: true,
    payloadFormat: 'wrapped-v1',
    payloadLength: single ? 41 : 8_388_700,
    chunkSize: 8_388_608,
    chunkCount: single ? 1 : 2,
    cryptoProfileId: 'QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2',
    kdfTreeId: 'QV-KDF-TREE-v2',
    noncePolicyId: single ? 'QV-GCM-RAND96-v1' : 'QV-GCM-KMACPFX64-CTR32-v3',
    nonceMode: single ? 'random96' : 'kmac-prefix64-ctr32',
    counterBits: single ? 0 : NONCE_COUNTER_BITS_U32,
    maxChunkCount: single ? 1 : NONCE_MAX_CHUNK_COUNT_U32,
    aadPolicyId: 'QV-AAD-HEADER-CHUNK-v1',
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
  encapsulatedKey = bytes(ML_KEM_1024_ENCAPSULATED_KEY_SIZE, 0x10),
  containerNonce = bytes(12, 0x20),
  kdfSalt = bytes(16, 0x30),
  keyCommitment = bytes(KEY_COMMITMENT_SIZE, 0x40),
  ciphertext = null,
} = {}) {
  const ciphertextBytes = ciphertext || bytes(metadata.payloadLength + (16 * metadata.chunkCount), 0x50);
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
    container: concatBytes(header, ciphertextBytes),
    metaBytes,
    metadata,
    encapsulatedKey,
    containerNonce,
    kdfSalt,
    keyCommitment,
    ciphertext: ciphertextBytes,
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
  assert.equal(JSON.stringify(parsed.metadata), JSON.stringify(vector.metadata));
  assert.deepEqual(parsed.storedKeyCommitment, vector.keyCommitment);
  assert.equal(parsed.metadata.hasKeyCommitment, true);
  assert.equal(vector.header.length, 2245);
  assert.equal(
    toHex(sha3_512(parsed.header)),
    '9925e075fe0cfb67567a553614938c690033b7fb77a38abcc74feab22a1d5ca9ecc1e575c4ddb84b52a7bdf9943cae955de3c193a44d24f37062d350087f675b',
  );
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

  const truncatedEncapsulatedKey = concatBytes(
    Uint8Array.from(MAGIC),
    uint32be(ML_KEM_1024_ENCAPSULATED_KEY_SIZE),
    bytes(65, 0x10),
  );
  assert.throws(
    () => parseQencHeader(truncatedEncapsulatedKey),
    /encapsulated key length exceeds file size/,
  );

  const wrongEncapsulatedKeyLength = vector.container.slice();
  new DataView(wrongEncapsulatedKeyLength.buffer).setUint32(MAGIC.length, vector.container.length + 1, false);
  assert.throws(
    () => parseQencHeader(wrongEncapsulatedKeyLength),
    /Expected 1568 for ML-KEM-1024/,
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

test('.qenc parser rejects duplicate metadata keys and inconsistent authenticated geometry', () => {
  const metadata = metadataForMode('single-container-aead');
  const canonicalText = JSON.stringify(metadata);
  const duplicateMetaBytes = encoder.encode(`{"fmt":"QVv1-5-0",${canonicalText.slice(1)}`);
  const header = buildQencHeader({
    encapsulatedKey: bytes(ML_KEM_1024_ENCAPSULATED_KEY_SIZE, 0x10),
    containerNonce: bytes(12, 0x20),
    kdfSalt: bytes(16, 0x30),
    metaBytes: duplicateMetaBytes,
    keyCommitment: bytes(KEY_COMMITMENT_SIZE, 0x40),
  });
  assert.throws(
    () => parseQencHeader(concatBytes(header, bytes(metadata.payloadLength + 16, 0x50))),
    /Duplicate object key "fmt"/,
  );

  const inconsistent = buildContainer({
    metadata: { ...metadataForMode('per-chunk-aead'), chunkCount: 3 },
  });
  assert.throws(
    () => parseQencHeader(inconsistent.container),
    /chunkCount does not match payloadLength\/chunkSize geometry/,
  );
});

test('.qenc parser requires the exact current algorithms, profile, nonce policy, and domains', () => {
  const cases = [
    ['KEM', (metadata) => { metadata.KEM = 'ML-KEM-768'; }],
    ['KDF', (metadata) => { metadata.KDF = 'HKDF-SHA256'; }],
    ['AEAD', (metadata) => { metadata.AEAD = 'AES-128-GCM'; }],
    ['fmt', (metadata) => { metadata.fmt = 'QVv1-4-0'; }],
    ['payloadFormat', (metadata) => { metadata.payloadFormat = 'raw-v1'; }],
    ['cryptoProfileId', (metadata) => { metadata.cryptoProfileId = 'QV-OTHER-PROFILE-v1'; }],
    ['kdfTreeId', (metadata) => { metadata.kdfTreeId = 'QV-KDF-TREE-v1'; }],
    ['aadPolicyId', (metadata) => { metadata.aadPolicyId = 'QV-AAD-OTHER-v1'; }],
    ['iv_strategy', (metadata) => { metadata.iv_strategy = IV_STRATEGY_KMAC_PREFIX64_CTR32_V3; }],
    ['noncePolicyId', (metadata) => { metadata.noncePolicyId = 'QV-GCM-OTHER-v1'; }],
    ['nonceMode', (metadata) => { metadata.nonceMode = 'counter-only'; }],
    ['counterBits', (metadata) => { metadata.counterBits = 32; }],
    ['maxChunkCount', (metadata) => { metadata.maxChunkCount = 2; }],
    ['domainStrings.kdf', (metadata) => { metadata.domainStrings.kdf = 'quantum-vault:kdf:v1'; }],
    ['domainStrings.iv', (metadata) => { metadata.domainStrings.iv = 'quantum-vault:chunk-iv:v1'; }],
    ['domainStrings.kenc', (metadata) => { metadata.domainStrings.kenc = 'quantum-vault:kenc:v1'; }],
    ['domainStrings.kiv', (metadata) => { metadata.domainStrings.kiv = 'quantum-vault:kiv:v1'; }],
  ];

  for (const [field, mutate] of cases) {
    const metadata = structuredClone(metadataForMode('single-container-aead'));
    mutate(metadata);
    const vector = buildContainer({ metadata });
    assert.throws(
      () => parseQencHeader(vector.container),
      new RegExp(field.replace('.', '\\.')),
      `${field} mismatch should fail closed`,
    );
  }
});

test('.qenc parser rejects missing and unknown public metadata fields', () => {
  const unknownTopLevel = buildContainer({
    metadata: { ...metadataForMode('single-container-aead'), DRBG: 'SP800-90A' },
  });
  assert.throws(
    () => parseQencHeader(unknownTopLevel.container),
    /unknown top-level field/,
  );

  const missingTopLevelMetadata = metadataForMode('single-container-aead');
  delete missingTopLevelMetadata.KEM;
  const missingTopLevel = buildContainer({ metadata: missingTopLevelMetadata });
  assert.throws(
    () => parseQencHeader(missingTopLevel.container),
    /missing top-level\.KEM/,
  );

  const unknownNestedMetadata = metadataForMode('single-container-aead');
  unknownNestedMetadata.domainStrings.wrap = 'quantum-vault:wrap:v1';
  const unknownNested = buildContainer({ metadata: unknownNestedMetadata });
  assert.throws(
    () => parseQencHeader(unknownNested.container),
    /unknown domainStrings field/,
  );

  const missingNestedMetadata = metadataForMode('single-container-aead');
  delete missingNestedMetadata.domainStrings.kiv;
  const missingNested = buildContainer({ metadata: missingNestedMetadata });
  assert.throws(
    () => parseQencHeader(missingNested.container),
    /missing domainStrings\.kiv/,
  );
});

test('.qenc header reader and writer require the exact ML-KEM-1024 encapsulation size', () => {
  const vector = buildContainer();

  for (const invalidLength of [
    ML_KEM_1024_ENCAPSULATED_KEY_SIZE - 1,
    ML_KEM_1024_ENCAPSULATED_KEY_SIZE + 1,
  ]) {
    assert.throws(
      () => buildQencHeader({
        encapsulatedKey: bytes(invalidLength, 0x10),
        containerNonce: vector.containerNonce,
        kdfSalt: vector.kdfSalt,
        metaBytes: vector.metaBytes,
        keyCommitment: vector.keyCommitment,
      }),
      /Invalid encapsulatedKey length/,
    );

    const malformed = vector.container.slice();
    new DataView(malformed.buffer).setUint32(MAGIC.length, invalidLength, false);
    assert.throws(
      () => parseQencHeader(malformed),
      /Expected 1568 for ML-KEM-1024/,
    );
  }
});

test('.qenc header reader and writer share one non-bypassable metadata cap', () => {
  const metadata = metadataForMode('single-container-aead');
  const atLimit = padJsonBytes(metadata, MAX_QENC_METADATA_BYTES);
  const header = buildQencHeader({
    encapsulatedKey: bytes(ML_KEM_1024_ENCAPSULATED_KEY_SIZE, 0x10),
    containerNonce: bytes(12, 0x20),
    kdfSalt: bytes(16, 0x30),
    metaBytes: atLimit,
    keyCommitment: bytes(KEY_COMMITMENT_SIZE, 0x40),
  });
  const ciphertext = bytes(metadata.payloadLength + 16, 0x50);
  assert.equal(parseQencHeader(concatBytes(header, ciphertext)).metaBytes.length, MAX_QENC_METADATA_BYTES);

  const overLimit = padJsonBytes(metadata, MAX_QENC_METADATA_BYTES + 1);
  assert.throws(
    () => buildQencHeader({
      encapsulatedKey: bytes(ML_KEM_1024_ENCAPSULATED_KEY_SIZE, 0x10),
      containerNonce: bytes(12, 0x20),
      kdfSalt: bytes(16, 0x30),
      metaBytes: overLimit,
      keyCommitment: bytes(KEY_COMMITMENT_SIZE, 0x40),
    }),
    /Invalid metaBytes length/,
  );

  const oversizedContainer = concatBytes(buildRawHeader({ metaBytes: overLimit }), ciphertext);
  assert.throws(
    () => parseQencHeader(oversizedContainer),
    /Invalid metadata length: 4097/,
  );
  assert.throws(
    () => parseQencHeader(concatBytes(header, ciphertext), { maxMetaLen: MAX_QENC_METADATA_BYTES + 1 }),
    /maxMetaLen must be an integer between 1 and 4096/,
  );
});

test('.qenc parser checks safe authenticated ciphertext arithmetic and exact length', () => {
  const vector = buildContainer();
  assert.throws(
    () => parseQencHeader(vector.container.subarray(0, vector.container.length - 1)),
    /ciphertext length does not match authenticated geometry/,
  );
  assert.throws(
    () => parseQencHeader(concatBytes(vector.container, Uint8Array.of(0x00))),
    /ciphertext length does not match authenticated geometry/,
  );

  const metadata = {
    ...metadataForMode('single-container-aead'),
    payloadLength: Number.MAX_SAFE_INTEGER,
  };
  const header = buildQencHeader({
    encapsulatedKey: bytes(ML_KEM_1024_ENCAPSULATED_KEY_SIZE, 0x10),
    containerNonce: bytes(12, 0x20),
    kdfSalt: bytes(16, 0x30),
    metaBytes: encoder.encode(JSON.stringify(metadata)),
    keyCommitment: bytes(KEY_COMMITMENT_SIZE, 0x40),
  });

  assert.throws(
    () => parseQencHeader(concatBytes(header, Uint8Array.of(0x50))),
    /ciphertext length exceeds safe integer range/,
  );
});
