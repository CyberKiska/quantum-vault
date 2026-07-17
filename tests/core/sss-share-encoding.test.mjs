import assert from 'node:assert/strict';
import test from 'node:test';
import {
  combineShares,
  splitSecret,
  validateShares,
} from '../../src/core/crypto/splitting/sss.js';

test('Shamir wrapper emits final-byte coordinates in the canonical 1..255 domain', async () => {
  const secret = Uint8Array.of(0x00, 0x7f, 0xff);
  const shares = await splitSecret(secret, 5, 4);
  const coordinates = shares.map((share) => share[share.length - 1]);

  assert.equal(new Set(coordinates).size, shares.length);
  assert.ok(coordinates.every((coordinate) => coordinate >= 1 && coordinate <= 255));
  assert.ok(shares.every((share) => share.length === secret.length + 1));
  assert.deepEqual(await combineShares(shares.slice(0, 4)), secret);
});

test('Shamir wrapper rejects x=0 before the dependency can reinterpret it', async () => {
  const zeroCoordinate = Uint8Array.of(0xaa, 0x00);
  const nonzeroCoordinate = Uint8Array.of(0xbb, 0x01);

  await assert.rejects(
    () => combineShares([zeroCoordinate, nonzeroCoordinate]),
    /Invalid Shamir share coordinates/,
  );
  assert.deepEqual(validateShares([zeroCoordinate, nonzeroCoordinate]), {
    valid: false,
    error: 'Invalid Shamir share coordinates',
  });
});

test('Shamir wrapper rejects duplicate final-byte coordinates consistently', async () => {
  const first = Uint8Array.of(0x11, 0x2a);
  const duplicate = Uint8Array.of(0x22, 0x2a);

  await assert.rejects(
    () => combineShares([first, duplicate]),
    /Invalid Shamir share coordinates/,
  );
  assert.equal(validateShares([first, duplicate]).valid, false);
});
