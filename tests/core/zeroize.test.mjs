import assert from 'node:assert/strict';
import test from 'node:test';
import {
  wipeByteArraysInObject,
  wipeBytes,
  wipeRestoreResult,
} from '../../src/core/crypto/zeroize.js';

function allZero(value) {
  return value.every((byte) => byte === 0);
}

test('wipeBytes zeroizes Uint8Array values and ignores non-byte inputs', () => {
  const first = Uint8Array.of(1, 2, 3);
  const second = Uint8Array.of(4, 5);
  const ignored = [6, 7, 8];

  wipeBytes(null, undefined, 'secret', ignored, first, second);
  assert.equal(allZero(first), true);
  assert.equal(allZero(second), true);
  assert.deepEqual(ignored, [6, 7, 8]);

  wipeBytes(first, second);
  assert.equal(allZero(first), true);
  assert.equal(allZero(second), true);
});

test('wipeByteArraysInObject zeroizes only explicitly allowlisted fields and paths', () => {
  const result = {
    qencBytes: Uint8Array.of(1, 1, 1),
    archiveStateBytes: Uint8Array.of(2, 2, 2),
    nested: {
      optional: {
        decBytes: Uint8Array.of(3, 3, 3),
      },
      ignoredBytes: Uint8Array.of(4, 4, 4),
    },
  };

  wipeByteArraysInObject(result, [
    'qencBytes',
    'nested.optional.decBytes',
    'nested.optional.missingBytes',
    ['nested', 'missing', 'keyBytes'],
  ]);

  assert.equal(allZero(result.qencBytes), true);
  assert.equal(allZero(result.nested.optional.decBytes), true);
  assert.deepEqual([...result.archiveStateBytes], [2, 2, 2]);
  assert.deepEqual([...result.nested.ignoredBytes], [4, 4, 4]);

  wipeByteArraysInObject(null, ['qencBytes']);
  wipeByteArraysInObject(undefined, ['qencBytes']);
  wipeByteArraysInObject(result, null);
});

test('wipeRestoreResult zeroizes only core restore output buffers', () => {
  const result = {
    qencBytes: Uint8Array.of(1, 2, 3),
    privKey: Uint8Array.of(4, 5, 6),
    archiveStateBytes: Uint8Array.of(7, 8, 9),
    lifecycleBundleBytes: Uint8Array.of(10, 11, 12),
  };

  wipeRestoreResult(result);
  assert.equal(allZero(result.qencBytes), true);
  assert.equal(allZero(result.privKey), true);
  assert.deepEqual([...result.archiveStateBytes], [7, 8, 9]);
  assert.deepEqual([...result.lifecycleBundleBytes], [10, 11, 12]);

  wipeRestoreResult(result);
  wipeRestoreResult(null);
  wipeRestoreResult(undefined);
  assert.equal(allZero(result.qencBytes), true);
  assert.equal(allZero(result.privKey), true);
});
