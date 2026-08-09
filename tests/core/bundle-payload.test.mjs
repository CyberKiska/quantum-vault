import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createBundlePayloadFromFiles,
  parseBundlePayload,
} from '../../src/core/features/bundle-payload.js';

function fileLike(name, backing, { fail = false } = {}) {
  return {
    name,
    async arrayBuffer() {
      if (fail) throw new Error('fault-injected file read failure');
      return backing.buffer;
    },
  };
}

function assertWiped(bytes, label) {
  assert.ok(bytes.every((value) => value === 0), `${label} was not wiped`);
}

test('bundle assembly copies output and wipes every per-file plaintext view', async () => {
  const first = new Uint8Array([1, 2, 3, 4]);
  const second = new Uint8Array([5, 6, 7]);

  const result = await createBundlePayloadFromFiles([
    fileLike('a.bin', first),
    fileLike('b.bin', second),
  ]);

  assertWiped(first, 'first plaintext input');
  assertWiped(second, 'second plaintext input');
  const parsed = parseBundlePayload(result.bundleBytes);
  assert.deepEqual(parsed.map((entry) => entry.name), ['a.bin', 'b.bin']);
  assert.deepEqual(parsed[0].bytes, new Uint8Array([1, 2, 3, 4]));
  assert.deepEqual(parsed[1].bytes, new Uint8Array([5, 6, 7]));
  result.bundleBytes.fill(0);
  parsed.forEach((entry) => entry.bytes.fill(0));
});

test('a partial bundle read failure wipes all plaintext views already acquired', async () => {
  const acquired = new Uint8Array([0x31, 0x32, 0x33]);
  const failing = new Uint8Array([0x41]);

  await assert.rejects(
    () => createBundlePayloadFromFiles([
      fileLike('acquired.bin', acquired),
      fileLike('failure.bin', failing, { fail: true }),
    ]),
    /Bundle payload preparation failed/,
  );

  assertWiped(acquired, 'acquired plaintext after later read failure');
  assert.deepEqual(failing, new Uint8Array([0x41]));
});

test('a bundle framing failure wipes every plaintext view and reflects no filename', async () => {
  const first = new Uint8Array([0x51, 0x52]);
  const second = new Uint8Array([0x61, 0x62]);
  const privateName = 'duplicate-private-name.txt';

  await assert.rejects(
    () => createBundlePayloadFromFiles([
      fileLike(privateName, first),
      fileLike(privateName, second),
    ]),
    (error) => {
      assert.equal(error.message, 'Bundle payload preparation failed.');
      assert.equal(error.message.includes(privateName), false);
      return true;
    },
  );

  assertWiped(first, 'first plaintext after framing failure');
  assertWiped(second, 'second plaintext after framing failure');
});
