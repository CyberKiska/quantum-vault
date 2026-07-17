import assert from 'node:assert/strict';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import {
  BROWSER_EXPORT_STATES,
  BrowserExportError,
  MAX_BROWSER_EXPORT_AGGREGATE_BYTES,
  MAX_BROWSER_EXPORT_ARTIFACT_BYTES,
  MAX_BROWSER_EXPORT_ARTIFACTS,
  assertBrowserExportByteProfile,
  createBrowserExportSession,
  digestBrowserExportSourceSha3_512,
} from '../../src/core/export/browser-export-session.js';

const encoder = new TextEncoder();

function bytes(value) {
  return encoder.encode(value);
}

function artifact(name, value, options = {}) {
  const source = options.source || bytes(value);
  return {
    name,
    source,
    role: options.role || 'shard',
    expectedDigest: options.expectedDigest || sha3_512(source),
    dispose: options.dispose,
  };
}

async function requestAndVerify(session, index, expectedName, expectedBytes) {
  await session.request(index, async ({ name, source }) => {
    assert.equal(name, expectedName);
    assert.deepEqual(source, expectedBytes);
  });
  return session.verify(index, {
    name: expectedName,
    digest: sha3_512(expectedBytes),
  });
}

function assertFixedError(error, code) {
  assert.ok(error instanceof BrowserExportError);
  assert.equal(error.code, code);
  assert.match(error.message, /^Browser export /);
  return true;
}

test('validated plan exposes only opaque row state and completes only after every row verifies', async () => {
  const values = ['one', 'two', 'three'];
  const names = values.map((value) => `private-${value}.qcont`);
  const session = await createBrowserExportSession(values.map((value, index) => (
    artifact(names[index], value, { role: index === 2 ? 'archive-state' : 'shard' })
  )));

  assert.deepEqual(session.snapshot(), {
    status: 'active',
    complete: false,
    rows: [
      { index: 0, role: 'shard', state: 'ready' },
      { index: 1, role: 'shard', state: 'ready' },
      { index: 2, role: 'archive-state', state: 'ready' },
    ],
  });

  for (let index = 0; index < values.length; index += 1) {
    await requestAndVerify(session, index, names[index], bytes(values[index]));
    assert.equal(session.complete, index === values.length - 1);
  }

  assert.equal(session.snapshot().status, 'complete');
  assert.ok(session.snapshot().rows.every((row) => row.state === BROWSER_EXPORT_STATES.VERIFIED));
});

test('completion invariant holds across deterministic plan sizes and verification orders', async () => {
  for (let count = 1; count <= 12; count += 1) {
    const plan = Array.from({ length: count }, (_, index) => artifact(`part-${index}.qcont`, `value-${index}`));
    const session = await createBrowserExportSession(plan);
    const order = Array.from({ length: count }, (_, index) => (index * 7) % count);
    const uniqueOrder = [...new Set(order)];
    for (let index = 0; uniqueOrder.length < count; index += 1) {
      if (!uniqueOrder.includes(index)) uniqueOrder.push(index);
    }

    for (let position = 0; position < uniqueOrder.length; position += 1) {
      const index = uniqueOrder[position];
      await requestAndVerify(session, index, `part-${index}.qcont`, bytes(`value-${index}`));
      assert.equal(session.complete, position === count - 1);
    }
  }
});

test('invalid transitions fail closed and a failed verification requires explicit retry', async () => {
  const secretName = 'transition-secret.qcont';
  const source = bytes('transition-bytes');
  const session = await createBrowserExportSession([artifact(secretName, 'transition-bytes')]);

  assert.throws(
    () => session.verify(0, { name: secretName, digest: sha3_512(source) }),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );
  assert.throws(
    () => session.retry(0),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );

  await session.request(0, async () => {});
  await assert.rejects(
    () => session.request(0, async () => {}),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );
  assert.throws(
    () => session.verify(0, { name: 'wrong.qcont', digest: sha3_512(source) }),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_VERIFICATION_FAILED'),
  );
  assert.equal(session.snapshot().rows[0].state, BROWSER_EXPORT_STATES.FAILED);
  await assert.rejects(
    () => session.request(0, async () => {}),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );

  session.retry(0);
  await requestAndVerify(session, 0, secretName, source);
  assert.throws(
    () => session.retry(0),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );
});

test('fixed browser byte profile checks count, individual, aggregate, and arithmetic bounds', () => {
  assert.equal(assertBrowserExportByteProfile([0]), 0);
  assert.equal(
    assertBrowserExportByteProfile([
      MAX_BROWSER_EXPORT_ARTIFACT_BYTES,
      MAX_BROWSER_EXPORT_ARTIFACT_BYTES,
    ]),
    MAX_BROWSER_EXPORT_AGGREGATE_BYTES,
  );

  const invalidPlans = [
    [],
    [-1],
    [1.5],
    [Number.MAX_SAFE_INTEGER + 1],
  ];
  for (const plan of invalidPlans) {
    assert.throws(() => assertBrowserExportByteProfile(plan), BrowserExportError);
  }
  assert.throws(
    () => assertBrowserExportByteProfile(Array(MAX_BROWSER_EXPORT_ARTIFACTS + 1).fill(0)),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_RESOURCE_LIMIT'),
  );
  assert.throws(
    () => assertBrowserExportByteProfile([MAX_BROWSER_EXPORT_ARTIFACT_BYTES + 1]),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_RESOURCE_LIMIT'),
  );
  assert.throws(
    () => assertBrowserExportByteProfile([
      MAX_BROWSER_EXPORT_ARTIFACT_BYTES,
      MAX_BROWSER_EXPORT_ARTIFACT_BYTES,
      1,
    ]),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_RESOURCE_LIMIT'),
  );
});

test('names are rejected rather than sanitized, including portable aliases', async () => {
  const invalidNames = [
    '', '.', '..', 'a/b', 'a\\b', 'a\0b', 'a\u0001b',
    ' leading.qcont', 'trailing.qcont ', 'trailing.',
    'bad<name', 'bad>name', 'bad:name', 'bad"name', 'bad|name', 'bad?name', 'bad*name',
    'CON', 'con.qcont', 'PRN.txt', 'AUX', 'NUL.bin', 'COM1.qcont', 'LPT9.qcont',
    'spoof\u202ereversed.qcont',
    '\ud800.qcont',
  ];
  for (const name of invalidNames) {
    await assert.rejects(
      () => createBrowserExportSession([artifact(name, 'x')]),
      (error) => assertFixedError(error, 'BROWSER_EXPORT_PLAN_INVALID'),
    );
  }

  const aliasPairs = [
    ['Shard-A.qcont', 'shard-a.qcont'],
    ['caf\u00e9.qcont', 'cafe\u0301.qcont'],
    ['same.qcont', 'same.qcont'],
  ];
  for (const [left, right] of aliasPairs) {
    await assert.rejects(
      () => createBrowserExportSession([artifact(left, 'a'), artifact(right, 'b')]),
      (error) => assertFixedError(error, 'BROWSER_EXPORT_PLAN_INVALID'),
    );
  }
});

test('all structural checks finish before any Blob source is hashed', async () => {
  let streamCalls = 0;
  class TrackingBlob extends Blob {
    stream() {
      streamCalls += 1;
      return super.stream();
    }
  }
  const tracked = new TrackingBlob([bytes('tracked')]);
  await assert.rejects(
    () => createBrowserExportSession([
      artifact('valid.qcont', '', { source: tracked, expectedDigest: sha3_512(bytes('tracked')) }),
      artifact('bad/name.qcont', 'invalid'),
    ]),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_PLAN_INVALID'),
  );
  assert.equal(streamCalls, 0);
});

test('a supplied digest must bind the adopted source before publication is possible', async () => {
  const disposed = [];
  const secret = 'digest-secret-name.qcont';
  await assert.rejects(
    () => createBrowserExportSession([
      artifact(secret, 'actual', {
        expectedDigest: sha3_512(bytes('different')),
        dispose: () => disposed.push('disposed'),
      }),
    ]),
    (error) => {
      assertFixedError(error, 'BROWSER_EXPORT_PLAN_INVALID');
      assert.doesNotMatch(error.message, /digest-secret|actual|different/);
      return true;
    },
  );
  assert.deepEqual(disposed, ['disposed']);
});

test('request failure at every index is isolated, fixed-message, and retryable', async () => {
  const count = 8;
  for (let failingIndex = 0; failingIndex < count; failingIndex += 1) {
    const session = await createBrowserExportSession(Array.from(
      { length: count },
      (_, index) => artifact(`private-${index}.qcont`, `bytes-${index}`),
    ));
    await assert.rejects(
      () => session.request(failingIndex, async () => {
        throw new Error(`private-${failingIndex}.qcont`);
      }),
      (error) => {
        assertFixedError(error, 'BROWSER_EXPORT_REQUEST_FAILED');
        assert.doesNotMatch(error.message, /private-/);
        return true;
      },
    );
    const states = session.snapshot().rows.map((row) => row.state);
    assert.equal(states[failingIndex], BROWSER_EXPORT_STATES.FAILED);
    assert.equal(states.filter((state) => state === BROWSER_EXPORT_STATES.READY).length, count - 1);

    session.retry(failingIndex);
    await requestAndVerify(
      session,
      failingIndex,
      `private-${failingIndex}.qcont`,
      bytes(`bytes-${failingIndex}`),
    );
  }
});

test('cancellation is idempotent, preserves verified rows, and runs cleanup once', async () => {
  const cleanupCounts = [0, 0, 0];
  const session = await createBrowserExportSession(Array.from({ length: 3 }, (_, index) => (
    artifact(`cancel-${index}.qcont`, `cancel-${index}`, {
      dispose: () => { cleanupCounts[index] += 1; },
    })
  )));

  await requestAndVerify(session, 0, 'cancel-0.qcont', bytes('cancel-0'));
  const first = session.cancel();
  const second = session.cancel();
  assert.deepEqual(first, second);
  assert.equal(first.status, 'cancelled');
  assert.equal(first.complete, false);
  assert.deepEqual(first.rows.map((row) => row.state), [
    BROWSER_EXPORT_STATES.VERIFIED,
    BROWSER_EXPORT_STATES.CANCELLED,
    BROWSER_EXPORT_STATES.CANCELLED,
  ]);
  assert.deepEqual(cleanupCounts, [1, 1, 1]);
  await assert.rejects(
    () => session.request(1, async () => {}),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );
});

test('cancellation aborts an in-flight requester and cannot be overwritten by late completion', async () => {
  let release;
  let observedSignal;
  const wait = new Promise((resolve) => { release = resolve; });
  const session = await createBrowserExportSession([artifact('inflight.qcont', 'inflight')]);

  const requestPromise = session.request(0, async ({ signal }) => {
    observedSignal = signal;
    await wait;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observedSignal.aborted, false);
  session.cancel();
  assert.equal(observedSignal.aborted, true);
  release();
  await assert.rejects(
    () => requestPromise,
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );
  assert.equal(session.snapshot().rows[0].state, BROWSER_EXPORT_STATES.CANCELLED);
});

test('a concurrent request for one artifact is rejected without duplicating publication', async () => {
  let release;
  let requesterCalls = 0;
  const wait = new Promise((resolve) => { release = resolve; });
  const session = await createBrowserExportSession([artifact('concurrent.qcont', 'concurrent')]);

  const firstRequest = session.request(0, async () => {
    requesterCalls += 1;
    await wait;
  });
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(
    () => session.request(0, async () => { requesterCalls += 1; }),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );
  assert.equal(requesterCalls, 1);

  release();
  await firstRequest;
  assert.equal(requesterCalls, 1);
  assert.equal(
    session.snapshot().rows[0].state,
    BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED,
  );
});

test('snapshots, JSON, and errors never expose private names or digests', async () => {
  const secretName = 'ULTRA-SECRET-client-name.qcont';
  const source = bytes('top-secret-source');
  const digest = sha3_512(source);
  const digestHex = Buffer.from(digest).toString('hex');
  const session = await createBrowserExportSession([
    artifact(secretName, '', { source, expectedDigest: digest, role: 'private-key' }),
  ]);

  const serialized = [
    JSON.stringify(session.snapshot()),
    JSON.stringify(session),
    String(session.snapshot()),
  ].join('\n');
  assert.doesNotMatch(serialized, new RegExp(secretName));
  assert.doesNotMatch(serialized, new RegExp(digestHex));

  await session.request(0, async () => {});
  assert.throws(
    () => session.verify(0, { name: secretName, digest: new Uint8Array(64) }),
    (error) => {
      const exposed = `${error.name}\n${error.message}\n${error.code}\n${JSON.stringify(error)}`;
      assert.doesNotMatch(exposed, new RegExp(secretName));
      assert.doesNotMatch(exposed, new RegExp(digestHex));
      return assertFixedError(error, 'BROWSER_EXPORT_VERIFICATION_FAILED');
    },
  );
});

test('hostile plan accessors cannot reflect private values through errors', async () => {
  const reflectedSecret = 'ACCESSOR-SECRET-MUST-NOT-ESCAPE';
  const hostileArtifact = {};
  Object.defineProperty(hostileArtifact, 'name', {
    enumerable: true,
    get() {
      throw new Error(reflectedSecret);
    },
  });

  await assert.rejects(
    () => createBrowserExportSession([hostileArtifact]),
    (error) => {
      assertFixedError(error, 'BROWSER_EXPORT_PLAN_INVALID');
      assert.doesNotMatch(`${error.message}\n${JSON.stringify(error)}`, new RegExp(reflectedSecret));
      return true;
    },
  );
});

test('Blob hashing is streaming-compatible with byte hashing', async () => {
  const source = bytes('blob-stream-digest');
  const blobDigest = await digestBrowserExportSourceSha3_512(new Blob([source]));
  assert.deepEqual(blobDigest, sha3_512(source));
});

test('Blob hashing aborts with a fixed error and cancels the active reader', async () => {
  const abortController = new AbortController();
  let readerCancelled = false;
  const source = new Blob([new Uint8Array([1, 2])]);
  source.stream = () => new ReadableStream({
    async pull(controller) {
      controller.enqueue(new Uint8Array([1]));
      abortController.abort();
    },
    cancel() {
      readerCancelled = true;
    },
  });

  await assert.rejects(
    () => digestBrowserExportSourceSha3_512(source, { signal: abortController.signal }),
    (error) => assertFixedError(error, 'BROWSER_EXPORT_STATE_INVALID'),
  );
  assert.equal(readerCancelled, true);
});
