import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  decodeStellarEd25519PublicKey,
  validateStellarEd25519PublicAddress,
} from '../../src/core/crypto/auth/stellar-sig.js';

const ZERO_PUBLIC_KEY_ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

test('shared Stellar strkey decoder preserves the public address vector and checksum rejection', () => {
  assert.deepEqual(
    decodeStellarEd25519PublicKey(ZERO_PUBLIC_KEY_ADDRESS),
    new Uint8Array(32),
  );
  assert.equal(
    validateStellarEd25519PublicAddress(` ${ZERO_PUBLIC_KEY_ADDRESS} `),
    ZERO_PUBLIC_KEY_ADDRESS,
  );
  assert.throws(
    () => decodeStellarEd25519PublicKey(`${ZERO_PUBLIC_KEY_ADDRESS.slice(0, -1)}G`),
    /checksum/,
  );
});

test('lifecycle artifacts do not redeclare Stellar base32 or CRC16 decoding', async () => {
  const source = await readFile('src/core/crypto/lifecycle/artifacts.js', 'utf8');
  assert.equal(/function\s+crc16Xmodem/.test(source), false);
  assert.equal(/function\s+base32Decode/.test(source), false);
  assert.match(source, /decodeStellarEd25519PublicKey/);
});
