import assert from 'node:assert/strict';
import test from 'node:test';
import { MAX_FILE_SIZE } from '../../src/core/crypto/constants.js';
import {
  buildQvpackPayloadBytes,
  isQvpackPayload,
  MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES,
  MAX_QVPACK_ENCODED_BYTES,
  MAX_QVPACK_ENTRY_COUNT,
  MAX_QVPACK_ENTRY_NAME_BYTES,
  MAX_QVPACK_ENTRY_PAYLOAD_BYTES,
  parseQvpackPayload,
  QVPACK_RESOURCE_PROFILE,
  QvpackFormatError,
  QvpackResourceLimitError,
} from '../../src/core/crypto/qvpack.js';

const encoder = new TextEncoder();

function u16(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
}

function u32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function concatBytes(...chunks) {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function rawQvpack(entries, { version = 1, count = entries.length, trailing = new Uint8Array() } = {}) {
  const chunks = [encoder.encode('QVB1'), new Uint8Array([version]), u16(count)];
  for (const entry of entries) {
    const nameBytes = entry.nameBytes || encoder.encode(entry.name);
    const payload = entry.bytes || new Uint8Array();
    chunks.push(u16(nameBytes.length), nameBytes, u32(entry.declaredSize ?? payload.length), payload);
  }
  chunks.push(trailing);
  return concatBytes(...chunks);
}

function assertFormatRejects(bytes, pattern) {
  assert.throws(
    () => parseQvpackPayload(bytes),
    (error) => {
      assert.ok(error instanceof QvpackFormatError);
      assert.equal(error.code, 'QVPACK_FORMAT_INVALID');
      if (pattern) assert.match(error.message, pattern);
      return true;
    },
  );
}

function assertResourceRejects(bytes, pattern) {
  assert.throws(
    () => parseQvpackPayload(bytes, {
      maxEntryCount: 0xffff,
      maxEntryNameBytes: 0xffff,
      maxAggregatePayloadBytes: 0xffffffff,
      maxEncodedBytes: Number.MAX_SAFE_INTEGER,
    }),
    (error) => {
      assert.ok(error instanceof QvpackResourceLimitError);
      assert.equal(error.code, 'QVPACK_RESOURCE_LIMIT');
      if (pattern) assert.match(error.message, pattern);
      return true;
    },
  );
}

test('QVPACK resource profile is immutable, explicit, and aligned with the QENC plaintext ceiling', () => {
  assert.equal(MAX_QVPACK_ENTRY_COUNT, 4096);
  assert.equal(MAX_QVPACK_ENTRY_NAME_BYTES, 255);
  assert.equal(MAX_QVPACK_ENTRY_PAYLOAD_BYTES, MAX_FILE_SIZE);
  assert.equal(MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES, MAX_FILE_SIZE);
  assert.equal(MAX_QVPACK_ENCODED_BYTES, MAX_FILE_SIZE);
  assert.deepEqual(QVPACK_RESOURCE_PROFILE, {
    maxEntryCount: MAX_QVPACK_ENTRY_COUNT,
    maxEntryNameBytes: MAX_QVPACK_ENTRY_NAME_BYTES,
    maxEntryPayloadBytes: MAX_QVPACK_ENTRY_PAYLOAD_BYTES,
    maxAggregatePayloadBytes: MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES,
    maxEncodedBytes: MAX_QVPACK_ENCODED_BYTES,
  });
  assert.equal(Object.isFrozen(QVPACK_RESOURCE_PROFILE), true);
  assert.throws(() => {
    QVPACK_RESOURCE_PROFILE.maxEntryCount = 0xffff;
  }, TypeError);
});

test('canonical QVPACK v1 writer bytes remain unchanged', () => {
  const bytes = buildQvpackPayloadBytes([
    { name: 'a.txt', bytes: new Uint8Array([0, 1, 2]) },
    { name: 'π.bin', bytes: new Uint8Array([255]) },
  ]);

  assert.equal(
    Buffer.from(bytes).toString('hex'),
    '515642310100020005612e747874000000030001020006cf802e62696e00000001ff',
  );
  assert.equal(isQvpackPayload(bytes), true);
  const parsed = parseQvpackPayload(bytes);
  assert.deepEqual(parsed.map(({ name, bytes: payload }) => ({ name, bytes: [...payload] })), [
    { name: 'a.txt', bytes: [0, 1, 2] },
    { name: 'π.bin', bytes: [255] },
  ]);
});

test('writer and parser reject exact duplicate decoded filenames without reflecting the name', () => {
  const sensitiveName = 'PRIVATE_DUPLICATE_CANARY.txt';
  assert.throws(
    () => buildQvpackPayloadBytes([
      { name: sensitiveName, bytes: new Uint8Array([1]) },
      { name: sensitiveName, bytes: new Uint8Array([2]) },
    ]),
    (error) => {
      assert.ok(error instanceof QvpackFormatError);
      assert.match(error.message, /duplicate entry filename/);
      assert.equal(error.message.includes(sensitiveName), false);
      return true;
    },
  );

  const duplicateBytes = rawQvpack([
    { name: sensitiveName, bytes: new Uint8Array([1]) },
    { name: sensitiveName, bytes: new Uint8Array([2]) },
  ]);
  assert.throws(
    () => parseQvpackPayload(duplicateBytes),
    (error) => {
      assert.ok(error instanceof QvpackFormatError);
      assert.match(error.message, /duplicate entry filename/);
      assert.equal(error.message.includes(sensitiveName), false);
      return true;
    },
  );
});

test('writer rejects lone surrogates, unsafe names, and over-limit names without filename disclosure', () => {
  const canary = 'PRIVATE_FILENAME_CANARY';
  for (const name of [
    `${canary}\ud800.txt`,
    `${canary}/child.txt`,
    `${canary}${'x'.repeat(MAX_QVPACK_ENTRY_NAME_BYTES)}`,
  ]) {
    assert.throws(
      () => buildQvpackPayloadBytes([{ name, bytes: new Uint8Array([1]) }]),
      (error) => {
        assert.equal(error.message.includes(canary), false);
        return true;
      },
    );
  }

  const exactLimitName = 'x'.repeat(MAX_QVPACK_ENTRY_NAME_BYTES);
  assert.equal(
    parseQvpackPayload(buildQvpackPayloadBytes([
      { name: exactLimitName, bytes: new Uint8Array() },
    ]))[0].name,
    exactLimitName,
  );
});

test('parser uses fatal UTF-8 decoding for every filename', () => {
  const invalidUtf8Names = [
    new Uint8Array([0x80]),
    new Uint8Array([0xc0, 0xaf]),
    new Uint8Array([0xed, 0xa0, 0x80]),
    new Uint8Array([0xf4, 0x90, 0x80, 0x80]),
  ];

  for (const nameBytes of invalidUtf8Names) {
    assertFormatRejects(rawQvpack([{ nameBytes, bytes: new Uint8Array() }]), /not valid UTF-8/);
  }
});

test('parser preserves a leading UTF-8 BOM as filename data without aliasing the plain name', () => {
  const bomPrefixedNameBytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x61]);
  const bytes = rawQvpack([
    { nameBytes: bomPrefixedNameBytes, bytes: new Uint8Array([1]) },
    { name: 'a', bytes: new Uint8Array([2]) },
  ]);

  const parsed = parseQvpackPayload(bytes);
  assert.equal(parsed[0].name, '\ufeffa');
  assert.equal(parsed[1].name, 'a');
  assert.notEqual(parsed[0].name, parsed[1].name);
  assert.deepEqual(buildQvpackPayloadBytes(parsed), bytes);
});

test('entry-count, filename, and declared payload limits cannot be widened by callers', () => {
  const overCount = concatBytes(encoder.encode('QVB1'), new Uint8Array([1]), u16(MAX_QVPACK_ENTRY_COUNT + 1));
  assertResourceRejects(overCount, /entry count exceeds resource limit/);

  const overName = rawQvpack([{
    nameBytes: new Uint8Array(MAX_QVPACK_ENTRY_NAME_BYTES + 1).fill(0x61),
    bytes: new Uint8Array(),
  }]);
  assertResourceRejects(overName, /filename exceeds resource limit/);

  const overPayload = rawQvpack([{
    name: 'bounded.bin',
    declaredSize: MAX_QVPACK_ENTRY_PAYLOAD_BYTES + 1,
    bytes: new Uint8Array(),
  }]);
  assertResourceRejects(overPayload, /entry payload exceeds resource limit/);

  const tooManyWriterEntries = Array.from(
    { length: MAX_QVPACK_ENTRY_COUNT + 1 },
    (_, index) => ({ name: `e-${index}`, bytes: new Uint8Array() }),
  );
  assert.throws(
    () => buildQvpackPayloadBytes(tooManyWriterEntries, { maxEntryCount: 0xffff }),
    QvpackResourceLimitError,
  );
});

test('parser rejects non-exact framing: versions, zero count, every truncation, and trailing bytes', () => {
  assertFormatRejects(rawQvpack([{ name: 'a', bytes: new Uint8Array() }], { version: 2 }), /Unsupported/);
  assertFormatRejects(rawQvpack([], { count: 0 }), /contains no files/);

  const canonical = buildQvpackPayloadBytes([
    { name: 'alpha.txt', bytes: new Uint8Array([1, 2, 3]) },
    { name: 'beta.bin', bytes: new Uint8Array() },
  ]);
  for (let length = 0; length < canonical.length; length += 1) {
    assertFormatRejects(canonical.subarray(0, length));
  }
  assertFormatRejects(concatBytes(canonical, new Uint8Array([0])), /trailing bytes/);

  assertFormatRejects(rawQvpack([{
    name: 'payload.bin',
    declaredSize: 2,
    bytes: new Uint8Array([1]),
  }]), /payload is truncated/);
});

test('deterministic property corpus round-trips exact names, payloads, and framing', () => {
  let state = 0x7a1d2e3f;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };

  for (let iteration = 0; iteration < 128; iteration += 1) {
    const entryCount = 1 + (next() % 12);
    const entries = [];
    for (let index = 0; index < entryCount; index += 1) {
      const payload = new Uint8Array(next() % 96);
      for (let byteIndex = 0; byteIndex < payload.length; byteIndex += 1) {
        payload[byteIndex] = next() & 0xff;
      }
      entries.push({
        name: `entry-${iteration}-${index}-${next().toString(16)}-π.bin`,
        bytes: payload,
      });
    }

    const encoded = buildQvpackPayloadBytes(entries);
    const expectedLength = 7 + entries.reduce(
      (sum, entry) => sum + 2 + encoder.encode(entry.name).length + 4 + entry.bytes.length,
      0,
    );
    assert.equal(encoded.length, expectedLength);
    const parsed = parseQvpackPayload(encoded);
    assert.equal(parsed.length, entries.length);
    for (let index = 0; index < entries.length; index += 1) {
      assert.equal(parsed[index].name, entries[index].name);
      assert.deepEqual(parsed[index].bytes, entries[index].bytes);
    }
  }
});
