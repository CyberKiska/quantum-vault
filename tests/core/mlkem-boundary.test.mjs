import assert from 'node:assert/strict';
import test from 'node:test';
import {
  decapsulate,
  encapsulate,
  generateKeyPair,
  ML_KEM_1024_ENCAPSULATED_KEY_SIZE,
  ML_KEM_1024_PRIVATE_KEY_SIZE,
} from '../../src/core/crypto/mlkem.js';

test('ML-KEM decapsulation preserves valid shared-secret output', async () => {
  const seed = Uint8Array.from({ length: 64 }, (_, index) => index);
  const { publicKey, privateKey } = await generateKeyPair({ customSeed: seed });
  const { encapsulatedKey, sharedSecret } = await encapsulate(publicKey);

  const decapsulated = await decapsulate(encapsulatedKey, privateKey);

  assert.deepEqual(decapsulated, sharedSecret);
});

test('ML-KEM decapsulation rejects invalid encapsulated key inputs before KEM use', async () => {
  const privateKey = new Uint8Array(ML_KEM_1024_PRIVATE_KEY_SIZE);

  await assert.rejects(
    () => decapsulate(null, privateKey),
    /Encapsulated key must be Uint8Array/,
  );
  await assert.rejects(
    () => decapsulate(new Uint8Array(ML_KEM_1024_ENCAPSULATED_KEY_SIZE - 1), privateKey),
    /Invalid ML-KEM-1024 encapsulated key length: expected 1568 bytes, got 1567/,
  );
  await assert.rejects(
    () => decapsulate(new Uint8Array(ML_KEM_1024_ENCAPSULATED_KEY_SIZE + 1), privateKey),
    /Invalid ML-KEM-1024 encapsulated key length: expected 1568 bytes, got 1569/,
  );
});

test('ML-KEM decapsulation rejects invalid private key inputs before KEM use', async () => {
  const encapsulatedKey = new Uint8Array(ML_KEM_1024_ENCAPSULATED_KEY_SIZE);

  await assert.rejects(
    () => decapsulate(encapsulatedKey, null),
    /Private key must be Uint8Array/,
  );
  await assert.rejects(
    () => decapsulate(encapsulatedKey, new Uint8Array(ML_KEM_1024_PRIVATE_KEY_SIZE - 1)),
    /Invalid ML-KEM-1024 private key length: expected 3168 bytes, got 3167/,
  );
  await assert.rejects(
    () => decapsulate(encapsulatedKey, new Uint8Array(ML_KEM_1024_PRIVATE_KEY_SIZE + 1)),
    /Invalid ML-KEM-1024 private key length: expected 3168 bytes, got 3169/,
  );
});
