import assert from 'node:assert/strict';
import test from 'node:test';
import { clearKeys, deriveKeyWithKmac } from '../../src/core/crypto/kdf.js';

const DOMAINS = Object.freeze({
  kdf: 'QV-TEST-KDF',
  kenc: 'QV-TEST-KENC',
  kiv: 'QV-TEST-KIV',
});

test('KDF accepts byte inputs and never exports the internal master key', async () => {
  const sharedSecret = new Uint8Array(32).fill(0x11);
  const salt = new Uint8Array(16).fill(0x22);
  const metaBytes = new Uint8Array([0x33, 0x44]);
  let derived = null;
  try {
    derived = await deriveKeyWithKmac(sharedSecret, salt, metaBytes, DOMAINS, {
      includeAesKey: false,
    });
    assert.deepEqual(Object.keys(derived).sort(), ['Kenc', 'Kiv', 'aesKey']);
    assert.equal(derived.Kenc.length, 32);
    assert.equal(derived.Kiv.length, 32);
    assert.equal(derived.aesKey, null);
    assert.equal(Object.hasOwn(derived, 'Kraw'), false);
  } finally {
    clearKeys(sharedSecret, salt, metaBytes, derived?.Kenc, derived?.Kiv);
  }
});

for (const [field, args] of [
  ['sharedSecret', ['not-bytes', new Uint8Array(16), new Uint8Array(0)]],
  ['salt', [new Uint8Array(32), 'not-bytes', new Uint8Array(0)]],
  ['metaBytes', [new Uint8Array(32), new Uint8Array(16), 'not-bytes']],
]) {
  test(`KDF rejects non-byte ${field} input before derivation`, async () => {
    await assert.rejects(
      () => deriveKeyWithKmac(...args, DOMAINS, { includeAesKey: false }),
      new RegExp(`${field} must be Uint8Array$`),
    );
  });
}
