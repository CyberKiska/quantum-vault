import assert from 'node:assert/strict';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import {
  decryptFile,
  encryptFile,
  generateKeyPair,
  MAX_QENC_PRIVATE_METADATA_BYTES,
} from '../../src/core/crypto/index.js';
import { concatBytes, toHex } from '../../src/core/crypto/bytes.js';
import { CHUNK_SIZE, FORMAT_VERSION } from '../../src/core/crypto/constants.js';
import {
  decryptChunk,
  encryptChunk,
  IV_STRATEGY_SINGLE_IV,
} from '../../src/core/crypto/aead.js';
import {
  clearKeys,
  computeKeyCommitment,
  deriveKeyWithKmac,
  verifyKeyCommitment,
} from '../../src/core/crypto/kdf.js';
import { decapsulate, encapsulate } from '../../src/core/crypto/mlkem.js';
import { buildPolicyMetadataFields, DEFAULT_CRYPTO_PROFILE } from '../../src/core/crypto/policy.js';
import { buildQencHeader, parseQencHeader } from '../../src/core/crypto/qenc/format.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function uint32be(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function validPrivateMetadata(fileBytes, overrides = {}) {
  return {
    originalFilename: 'private-metadata.bin',
    timestamp: '2026-07-17T12:34:56.789Z',
    fileHash: toHex(sha3_512(fileBytes)),
    originalLength: fileBytes.length,
    ...overrides,
  };
}

async function buildAuthenticatedPrivateMetadataContainer({
  publicKey,
  fileBytes,
  privateMetadata = null,
  privateMetadataBytes = null,
}) {
  const encodedPrivateMetadata = privateMetadataBytes || encoder.encode(JSON.stringify(privateMetadata));
  let sharedSecret = null;
  let Kenc = null;
  let Kiv = null;
  let metaBytes = null;
  let payload = null;
  let keyCommitment = null;

  try {
    const encapsulated = await encapsulate(publicKey);
    sharedSecret = encapsulated.sharedSecret;
    const containerNonce = crypto.getRandomValues(new Uint8Array(12));
    const kdfSalt = crypto.getRandomValues(new Uint8Array(16));
    payload = concatBytes([
      uint32be(encodedPrivateMetadata.length),
      encodedPrivateMetadata,
      fileBytes,
    ]);

    const policyFields = buildPolicyMetadataFields(DEFAULT_CRYPTO_PROFILE, 'single-container-aead');
    const metadata = {
      KEM: 'ML-KEM-1024',
      KDF: 'KMAC256',
      AEAD: 'AES-256-GCM',
      aead_mode: 'single-container-aead',
      iv_strategy: IV_STRATEGY_SINGLE_IV,
      fmt: FORMAT_VERSION,
      hasKeyCommitment: true,
      payloadFormat: 'wrapped-v1',
      payloadLength: payload.length,
      chunkSize: CHUNK_SIZE,
      chunkCount: 1,
      ...policyFields,
      domainStrings: policyFields.domainStrings,
    };
    metaBytes = encoder.encode(JSON.stringify(metadata));
    const derived = await deriveKeyWithKmac(
      sharedSecret,
      kdfSalt,
      metaBytes,
      metadata.domainStrings,
    );
    Kenc = derived.Kenc;
    Kiv = derived.Kiv;
    keyCommitment = computeKeyCommitment(Kenc);
    const header = buildQencHeader({
      encapsulatedKey: encapsulated.encapsulatedKey,
      containerNonce,
      kdfSalt,
      metaBytes,
      keyCommitment,
    });
    const ciphertext = await encryptChunk(derived.aesKey, payload, containerNonce, header);
    return concatBytes([header, ciphertext]);
  } finally {
    if (payload instanceof Uint8Array) payload.fill(0);
    if (metaBytes instanceof Uint8Array) metaBytes.fill(0);
    if (keyCommitment instanceof Uint8Array) keyCommitment.fill(0);
    clearKeys(sharedSecret, Kenc, Kiv);
  }
}

async function inspectWriterPrivateMetadataText(containerBytes, privateKey) {
  const parsed = parseQencHeader(containerBytes);
  let sharedSecret = null;
  let Kenc = null;
  let Kiv = null;
  let payload = null;
  try {
    sharedSecret = await decapsulate(parsed.encapsulatedKey, privateKey);
    const derived = await deriveKeyWithKmac(
      sharedSecret,
      parsed.kdfSalt,
      parsed.metaBytes,
      parsed.metadata.domainStrings,
    );
    Kenc = derived.Kenc;
    Kiv = derived.Kiv;
    assert.equal(verifyKeyCommitment(Kenc, parsed.storedKeyCommitment), true);
    payload = await decryptChunk(
      derived.aesKey,
      containerBytes.subarray(parsed.offset),
      parsed.containerNonce,
      parsed.header,
    );
    assert.ok(payload.length >= 4);
    const privateMetadataLength = new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    ).getUint32(0, false);
    return decoder.decode(payload.subarray(4, 4 + privateMetadataLength));
  } finally {
    if (payload instanceof Uint8Array) payload.fill(0);
    clearKeys(sharedSecret, Kenc, Kiv);
  }
}

async function expectPrivateMetadataRejection({
  publicKey,
  privateKey,
  fileBytes,
  privateMetadata = null,
  privateMetadataBytes = null,
  pattern,
  forbidden = [],
}) {
  const container = await buildAuthenticatedPrivateMetadataContainer({
    publicKey,
    fileBytes,
    privateMetadata,
    privateMetadataBytes,
  });
  await assert.rejects(
    () => decryptFile(container, privateKey),
    (error) => {
      assert.match(String(error?.message || error), pattern);
      for (const value of forbidden) {
        assert.equal(String(error?.message || error).includes(value), false);
      }
      return true;
    },
  );
}

test('wrapped-v1 writer bytes retain the current four-field shape and round-trip', async () => {
  const pair = await generateKeyPair();
  const fileBytes = encoder.encode('wrapped-v1 canonical writer payload');
  try {
    const container = new Uint8Array(
      await (await encryptFile(fileBytes, pair.publicKey, 'writer-roundtrip.bin')).arrayBuffer(),
    );
    const privateMetadataText = await inspectWriterPrivateMetadataText(container, pair.privateKey);
    const parsed = JSON.parse(privateMetadataText);
    assert.deepEqual(Object.keys(parsed), [
      'originalFilename',
      'timestamp',
      'fileHash',
      'originalLength',
    ]);
    assert.equal(privateMetadataText, JSON.stringify({
      originalFilename: 'writer-roundtrip.bin',
      timestamp: parsed.timestamp,
      fileHash: toHex(sha3_512(fileBytes)),
      originalLength: fileBytes.length,
    }));

    const decrypted = await decryptFile(container, pair.privateKey);
    const recovered = new Uint8Array(await decrypted.decryptedBlob.arrayBuffer());
    assert.deepEqual(recovered, fileBytes);
    assert.equal(decrypted.metadata.originalFilename, 'writer-roundtrip.bin');
    assert.equal(decrypted.metadata.timestamp, parsed.timestamp);
    assert.equal(decrypted.metadata.fileHash, toHex(sha3_512(fileBytes)));
    assert.equal(decrypted.metadata.originalLength, fileBytes.length);
    recovered.fill(0);
    container.fill(0);
  } finally {
    fileBytes.fill(0);
    pair.privateKey.fill(0);
    pair.publicKey.fill(0);
  }
});

test('wrapped-v1 writer and reader accept the exact shared private metadata cap', async () => {
  const pair = await generateKeyPair();
  const fileBytes = encoder.encode('private metadata cap boundary');
  try {
    const emptyFilenameMetadataLength = encoder.encode(JSON.stringify(validPrivateMetadata(fileBytes, {
      originalFilename: '',
    }))).length;
    const boundaryFilename = 'b'.repeat(
      MAX_QENC_PRIVATE_METADATA_BYTES - emptyFilenameMetadataLength,
    );
    const container = new Uint8Array(
      await (await encryptFile(fileBytes, pair.publicKey, boundaryFilename)).arrayBuffer(),
    );
    const privateMetadataText = await inspectWriterPrivateMetadataText(container, pair.privateKey);
    assert.equal(encoder.encode(privateMetadataText).length, MAX_QENC_PRIVATE_METADATA_BYTES);

    const decrypted = await decryptFile(container, pair.privateKey);
    assert.equal(decrypted.metadata.originalFilename, boundaryFilename);
    assert.deepEqual(new Uint8Array(await decrypted.decryptedBlob.arrayBuffer()), fileBytes);
    container.fill(0);
  } finally {
    fileBytes.fill(0);
    pair.privateKey.fill(0);
    pair.publicKey.fill(0);
  }
});

test('wrapped-v1 reader rejects non-canonical authenticated private metadata', async (t) => {
  const pair = await generateKeyPair();
  const fileBytes = encoder.encode('private metadata negative vectors');
  const valid = validPrivateMetadata(fileBytes);
  const sensitiveFilename = 'DO_NOT_LEAK_PRIVATE_FILENAME';
  const sensitiveTimestamp = 'DO_NOT_LEAK_PRIVATE_TIMESTAMP';

  try {
    for (const missingField of ['originalFilename', 'timestamp', 'fileHash', 'originalLength']) {
      const metadata = { ...valid };
      delete metadata[missingField];
      await t.test(`missing ${missingField}`, async () => {
        await expectPrivateMetadataRejection({
          publicKey: pair.publicKey,
          privateKey: pair.privateKey,
          fileBytes,
          privateMetadata: metadata,
          pattern: /missing a required field/,
        });
      });
    }

    await t.test('unknown field names and values are not reflected in errors', async () => {
      await expectPrivateMetadataRejection({
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        fileBytes,
        privateMetadata: {
          ...valid,
          DO_NOT_LEAK_UNKNOWN_FIELD: 'DO_NOT_LEAK_UNKNOWN_VALUE',
        },
        pattern: /unknown field/,
        forbidden: ['DO_NOT_LEAK_UNKNOWN_FIELD', 'DO_NOT_LEAK_UNKNOWN_VALUE'],
      });
    });

    await t.test('duplicate fields are rejected without relaying parser details', async () => {
      const duplicateTimestampBytes = encoder.encode(
        `{` +
        `"originalFilename":"${sensitiveFilename}",` +
        `"timestamp":"${sensitiveTimestamp}",` +
        `"timestamp":"${sensitiveTimestamp}",` +
        `"fileHash":"${valid.fileHash}",` +
        `"originalLength":${valid.originalLength}` +
        `}`,
      );
      await expectPrivateMetadataRejection({
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        fileBytes,
        privateMetadataBytes: duplicateTimestampBytes,
        pattern: /Invalid private metadata JSON in decrypted payload/,
        forbidden: [sensitiveFilename, sensitiveTimestamp, valid.fileHash],
      });
      duplicateTimestampBytes.fill(0);
    });

    const wrongTypeVectors = [
      ['originalFilename', { secret: sensitiveFilename }, /originalFilename must be null or a string/],
      ['timestamp', { secret: sensitiveTimestamp }, /timestamp must be a string/],
      ['fileHash', 17, /fileHash must be a 128-character lowercase SHA3-512 hex digest/],
      ['originalLength', String(fileBytes.length), /originalLength must be a positive safe integer/],
    ];
    for (const [field, value, pattern] of wrongTypeVectors) {
      await t.test(`wrong ${field} type`, async () => {
        await expectPrivateMetadataRejection({
          publicKey: pair.publicKey,
          privateKey: pair.privateKey,
          fileBytes,
          privateMetadata: { ...valid, [field]: value },
          pattern,
          forbidden: [sensitiveFilename, sensitiveTimestamp],
        });
      });
    }

    await t.test('timestamp must use the exact current UTC millisecond form', async () => {
      await expectPrivateMetadataRejection({
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        fileBytes,
        privateMetadata: { ...valid, timestamp: sensitiveTimestamp },
        pattern: /timestamp must use canonical UTC ISO-8601 millisecond form/,
        forbidden: [sensitiveTimestamp],
      });
      await expectPrivateMetadataRejection({
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        fileBytes,
        privateMetadata: { ...valid, timestamp: '2026-02-30T12:34:56.789Z' },
        pattern: /timestamp must use canonical UTC ISO-8601 millisecond form/,
        forbidden: ['2026-02-30T12:34:56.789Z'],
      });
    });

    await t.test('reader enforces the shared private metadata byte cap', async () => {
      const oversized = encoder.encode(JSON.stringify({
        ...valid,
        originalFilename: `${sensitiveFilename}${'x'.repeat(MAX_QENC_PRIVATE_METADATA_BYTES)}`,
      }));
      assert.ok(oversized.length > MAX_QENC_PRIVATE_METADATA_BYTES);
      await expectPrivateMetadataRejection({
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        fileBytes,
        privateMetadataBytes: oversized,
        pattern: /Invalid private metadata length/,
        forbidden: [sensitiveFilename],
      });
      oversized.fill(0);
    });

    await t.test('writer enforces the same private metadata byte cap without echoing input', async () => {
      const oversizedFilename = `${sensitiveFilename}${'x'.repeat(MAX_QENC_PRIVATE_METADATA_BYTES)}`;
      await assert.rejects(
        () => encryptFile(fileBytes, pair.publicKey, oversizedFilename),
        (error) => {
          assert.match(String(error?.message || error), /private metadata byte limit/);
          assert.equal(String(error?.message || error).includes(sensitiveFilename), false);
          return true;
        },
      );
    });

    await t.test('originalLength must exactly match recovered bytes without leaking lengths', async () => {
      await expectPrivateMetadataRejection({
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        fileBytes,
        privateMetadata: { ...valid, originalLength: fileBytes.length + 1 },
        pattern: /Authenticated private metadata does not match the decrypted payload/,
        forbidden: [String(fileBytes.length), String(fileBytes.length + 1)],
      });
    });

    for (const [label, fileHash] of [
      ['short', '0'.repeat(127)],
      ['uppercase', 'A'.repeat(128)],
      ['non-hex', `${'0'.repeat(127)}g`],
    ]) {
      await t.test(`${label} fileHash syntax`, async () => {
        await expectPrivateMetadataRejection({
          publicKey: pair.publicKey,
          privateKey: pair.privateKey,
          fileBytes,
          privateMetadata: { ...valid, fileHash },
          pattern: /fileHash must be a 128-character lowercase SHA3-512 hex digest/,
          forbidden: [fileHash],
        });
      });
    }

    await t.test('validly encoded but incorrect fileHash is recomputed before return', async () => {
      const incorrectHash = '0'.repeat(128);
      await expectPrivateMetadataRejection({
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        fileBytes,
        privateMetadata: { ...valid, fileHash: incorrectHash },
        pattern: /Authenticated private metadata does not match the decrypted payload/,
        forbidden: [incorrectHash, valid.fileHash],
      });
    });
  } finally {
    fileBytes.fill(0);
    pair.privateKey.fill(0);
    pair.publicKey.fill(0);
  }
});
