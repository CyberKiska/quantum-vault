import assert from 'node:assert/strict';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { resolveErasureRuntime } from '../../src/core/crypto/erasure-runtime.js';
import {
  blobToBytes,
  buildSuccessorRestoreSample,
  ensureErasureRuntime,
  ensureRuntimeCrypto,
  textBytes,
} from '../../src/core/crypto/selftest.js';
import {
  MAX_RECONSTRUCTED_CIPHERTEXT_BYTES,
  reconstructLifecycleCohortMaterial,
} from '../../src/core/crypto/qcont/lifecycle-cohort-shared.js';
import { parseLifecycleShard } from '../../src/core/crypto/qcont/lifecycle-shard.js';
import { buildQencHeader } from '../../src/core/crypto/qenc/format.js';

const DIGEST_LENGTH = 64;

let sample;

function digestHex(bytes) {
  return toHex(sha3_512(bytes));
}

function buildCandidate(shards, overrides = {}) {
  const first = shards[0];
  return {
    archiveId: first.archiveState.archiveId,
    stateId: first.stateId,
    cohortId: first.cohortId,
    archiveStateBytes: first.archiveStateBytes,
    archiveStateDigestHex: first.archiveStateDigestHex,
    archiveState: overrides.archiveState || first.archiveState,
    cohortBindingBytes: first.cohortBindingBytes,
    cohortBindingDigestHex: first.cohortBindingDigestHex,
    cohortBinding: overrides.cohortBinding || first.cohortBinding,
    shards,
  };
}

function tracedRuntime(recombineOverride = null) {
  const delegate = resolveErasureRuntime();
  const calls = [];
  return {
    calls,
    runtime: {
      recombine(encoded, outputLength, k, allowedFailures, encodeBase) {
        calls.push({ outputLength, k, allowedFailures, encodeBase });
        if (recombineOverride) {
          return recombineOverride({
            delegate,
            encoded,
            outputLength,
            k,
            allowedFailures,
            encodeBase,
          });
        }
        return delegate.recombine(encoded, outputLength, k, allowedFailures, encodeBase);
      },
    },
  };
}

function wipeResult(result) {
  if (result?.privKey instanceof Uint8Array) result.privKey.fill(0);
  if (result?.qencBytes instanceof Uint8Array) result.qencBytes.fill(0);
}

function rewriteOuterMetadata(shardBytes, mutate) {
  const view = new DataView(shardBytes.buffer, shardBytes.byteOffset, shardBytes.byteLength);
  const oldLength = view.getUint16(4, false);
  const oldStart = 6;
  const oldEnd = oldStart + oldLength;
  const metadata = JSON.parse(new TextDecoder().decode(shardBytes.subarray(oldStart, oldEnd)));
  mutate(metadata);
  const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
  assert(metadataBytes.length <= 0xffff, 'rewritten test metadata must fit uint16 framing');

  const out = new Uint8Array(shardBytes.length - oldLength + metadataBytes.length);
  out.set(shardBytes.subarray(0, 4), 0);
  new DataView(out.buffer).setUint16(4, metadataBytes.length, false);
  out.set(metadataBytes, 6);
  out.set(shardBytes.subarray(oldEnd), 6 + metadataBytes.length);
  return out;
}

function locateEncapsulatedKey(shardBytes) {
  const view = new DataView(shardBytes.buffer, shardBytes.byteOffset, shardBytes.byteLength);
  let offset = 4;
  const metadataLength = view.getUint16(offset, false);
  offset += 2 + metadataLength;
  for (let artifactIndex = 0; artifactIndex < 3; artifactIndex += 1) {
    const artifactLength = view.getUint32(offset, false);
    offset += 4 + artifactLength + DIGEST_LENGTH;
  }
  const encapsulatedKeyLength = view.getUint32(offset, false);
  offset += 4;
  return { offset, length: encapsulatedKeyLength };
}

function poisonCopiedHeader(shardBytes) {
  const out = shardBytes.slice();
  const encapsulatedKey = locateEncapsulatedKey(out);
  assert(encapsulatedKey.length > 0, 'fixture must contain an encapsulated key');
  out[encapsulatedKey.offset] ^= 0x01;
  return out;
}

function malformedShortFragmentStream(bytes) {
  const out = bytes.slice();
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  const fragmentLength = view.getUint32(0, false);
  assert(fragmentLength > 1, 'fixture fragment must be long enough to shorten');
  view.setUint32(0, fragmentLength - 1, false);
  return out;
}

function malformedLongFragmentStream(bytes) {
  const out = new Uint8Array(bytes.length + 1);
  out.set(bytes, 0);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  const fragmentLength = view.getUint32(0, false);
  view.setUint32(0, fragmentLength + 1, false);
  out[out.length - 1] = 0xa5;
  return out;
}

function malformedOverflowFragmentStream(bytes) {
  const out = bytes.slice();
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(0, 0xffffffff, false);
  return out;
}

function appendBytes(bytes, count) {
  const out = new Uint8Array(bytes.length + count);
  out.set(bytes, 0);
  out.fill(0xa5, bytes.length);
  return out;
}

function digestWithCommittedFaults(committedFaults) {
  return async (bytes) => committedFaults.get(bytes) || digestHex(bytes);
}

test.before(async () => {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();
  sample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('authenticated qcont reconstruction geometry'),
    authPolicyLevel: 'integrity-only',
  });
});

test.after(() => {
  sample?.pair?.privateKey?.fill(0);
});

test('reconstruction ignores a parse-valid poisoned first header and unauthenticated outer geometry', async () => {
  let poisonedBytes = await blobToBytes(sample.split.shards[0].blob);
  poisonedBytes = rewriteOuterMetadata(poisonedBytes, (metadata) => {
    metadata.containerId = '00'.repeat(64);
    metadata.containerHash = '11'.repeat(64);
    metadata.encapBlobHash = '22'.repeat(64);
    metadata.n = 250;
    metadata.k = 249;
    metadata.m = 1;
    metadata.t = 250;
    metadata.chunkSize = Number.MAX_SAFE_INTEGER;
    metadata.chunkCount = Number.MAX_SAFE_INTEGER;
    metadata.payloadLength = Number.MAX_SAFE_INTEGER;
    metadata.ciphertextLength = Number.MAX_SAFE_INTEGER;
    metadata.rsEncodeBase = 1;
  });
  poisonedBytes = poisonCopiedHeader(poisonedBytes);
  const poisoned = await parseLifecycleShard(poisonedBytes, { strict: true });
  const shards = [poisoned, ...sample.parsed.slice(1)];
  const trace = tracedRuntime();
  const warnings = [];
  let result = null;

  try {
    result = await reconstructLifecycleCohortMaterial(buildCandidate(shards), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => digestHex(bytes),
      onWarn: (warning) => warnings.push(warning),
    });
    assert.deepEqual(result.qencBytes, sample.qencBytes);
    assert.deepEqual(result.ignoredQencHeaderIndices, [0]);
    assert.deepEqual(result.corruptedShardIndices, []);
    assert.equal(trace.calls.length, 1, 'single-container fixture should use one RS call');
    assert.equal(
      trace.calls[0].outputLength,
      sample.parsed[0].qencMetaJSON.payloadLength + 16,
      'RS output length must come from authenticated QENC metadata'
    );
    assert.equal(trace.calls[0].encodeBase, 255, 'RS base must be format-fixed');
    assert(warnings.some((warning) => warning.includes('header fields')));
    assert(warnings.some((warning) => warning.includes('redundant metadata')));
  } finally {
    wipeResult(result);
  }
});

test('reconstruction rejects a cohort with no containerId-matching header before Shamir or RS work', async () => {
  const poisoned = await Promise.all(sample.split.shards.map(async (item) => (
    parseLifecycleShard(poisonCopiedHeader(await blobToBytes(item.blob)), { strict: true })
  )));
  const trace = tracedRuntime();
  let keyValidationFinallyCalls = 0;

  await assert.rejects(
    reconstructLifecycleCohortMaterial(buildCandidate(poisoned), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => digestHex(bytes),
      onWarn: () => {},
      keyValidationHooks: {
        onFinally: () => {
          keyValidationFinallyCalls += 1;
        },
      },
    }),
    /No shard carries a supported QENC header matching archive-state containerId/
  );
  assert.equal(trace.calls.length, 0);
  assert.equal(keyValidationFinallyCalls, 0);
});

test('duplicate and out-of-range shard indices remain hard failures', async (t) => {
  const cases = [
    [
      'duplicate',
      sample.parsed.map((shard, index) => (index === 1 ? { ...shard, shardIndex: 0 } : shard)),
      /Duplicate shardIndex 0 detected/,
    ],
    [
      'out-of-range',
      sample.parsed.map((shard, index) => (index === 4 ? { ...shard, shardIndex: 5 } : shard)),
      /Invalid shardIndex 5/,
    ],
  ];
  for (const [label, shards, expectedError] of cases) {
    await t.test(label, async () => {
      const trace = tracedRuntime();
      await assert.rejects(
        reconstructLifecycleCohortMaterial(buildCandidate(shards), {
          erasureRuntime: trace.runtime,
          digestHex: async (bytes) => digestHex(bytes),
          onWarn: () => {},
        }),
        expectedError
      );
      assert.equal(trace.calls.length, 0);
    });
  }
});

test('reconstruction applies the shared closed QENC metadata validator before geometry use', async () => {
  const unsupportedMetadata = {
    ...sample.parsed[0].qencMetaJSON,
    KEM: 'unsupported-kem',
  };
  const unsupportedMetadataBytes = new TextEncoder().encode(JSON.stringify(unsupportedMetadata));
  const shards = sample.parsed.map((shard) => ({
    ...shard,
    qencMetaBytes: unsupportedMetadataBytes,
    qencMetaJSON: unsupportedMetadata,
  }));
  const first = shards[0];
  const unsupportedHeader = buildQencHeader({
    encapsulatedKey: first.encapsulatedKey,
    containerNonce: first.iv,
    kdfSalt: first.salt,
    metaBytes: unsupportedMetadataBytes,
    keyCommitment: first.keyCommit,
  });
  const archiveState = JSON.parse(JSON.stringify(first.archiveState));
  archiveState.qenc.containerId = digestHex(unsupportedHeader);
  const trace = tracedRuntime();

  await assert.rejects(
    reconstructLifecycleCohortMaterial(buildCandidate(shards, { archiveState }), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => digestHex(bytes),
      onWarn: () => {},
    }),
    /KEM must be "ML-KEM-1024"/
  );
  assert.equal(trace.calls.length, 0);
});

test('header, share, and body validity remain independent recovery facets', async () => {
  const corruptedHeaderSourceBytes = await blobToBytes(sample.split.shards[0].blob);
  corruptedHeaderSourceBytes[corruptedHeaderSourceBytes.length - 1] ^= 0x01;
  const corruptedHeaderSource = await parseLifecycleShard(corruptedHeaderSourceBytes, { strict: true });
  const poisonedHeaderExtras = await Promise.all(sample.split.shards.slice(1).map(async (item) => (
    parseLifecycleShard(poisonCopiedHeader(await blobToBytes(item.blob)), { strict: true })
  )));
  const shards = [corruptedHeaderSource, ...poisonedHeaderExtras];
  const trace = tracedRuntime();
  let result = null;

  try {
    result = await reconstructLifecycleCohortMaterial(buildCandidate(shards), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => digestHex(bytes),
      onWarn: () => {},
    });
    assert.deepEqual(result.qencBytes, sample.qencBytes);
    assert.deepEqual(result.ignoredQencHeaderIndices, [1, 2, 3, 4]);
    assert.deepEqual(result.corruptedShardIndices, [0]);
    assert.equal(trace.calls.length, 1);
  } finally {
    wipeResult(result);
  }
});

test('an oversized Shamir share extra is skipped before hashing or combine', async () => {
  const oversizedShare = appendBytes(sample.parsed[4].share, 1);
  const shards = sample.parsed.map((shard) => (
    shard.shardIndex === 4 ? { ...shard, share: oversizedShare } : shard
  ));
  let oversizedShareHashCalls = 0;
  const trace = tracedRuntime();
  let result = null;

  try {
    result = await reconstructLifecycleCohortMaterial(buildCandidate(shards), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => {
        if (bytes === oversizedShare) oversizedShareHashCalls += 1;
        return digestHex(bytes);
      },
      onWarn: () => {},
    });
    assert.deepEqual(result.qencBytes, sample.qencBytes);
    assert.deepEqual(result.invalidShareIndices, [4]);
    assert.equal(oversizedShareHashCalls, 0);
    assert.equal(trace.calls.length, 1);
  } finally {
    wipeResult(result);
  }
});

test('body-hash-valid short fragment records are quarantined instead of padded', async () => {
  const malformed = malformedShortFragmentStream(sample.parsed[4].fragments);
  const shards = sample.parsed.map((shard) => (
    shard.shardIndex === 4 ? { ...shard, fragments: malformed } : shard
  ));
  const committedFaults = new Map([
    [malformed, sample.parsed[0].cohortBinding.shardBodyHashes[4]],
  ]);
  const trace = tracedRuntime();
  let result = null;

  try {
    result = await reconstructLifecycleCohortMaterial(buildCandidate(shards), {
      erasureRuntime: trace.runtime,
      digestHex: digestWithCommittedFaults(committedFaults),
      onWarn: () => {},
    });
    assert.deepEqual(result.qencBytes, sample.qencBytes);
    assert.deepEqual(result.corruptedShardIndices, [4]);
    assert.equal(trace.calls.length, 1);
  } finally {
    wipeResult(result);
  }
});

test('body-hash-valid overlong and overflowing fragment records are quarantined without truncation or allocation', async (t) => {
  const cases = [
    ['overlong', malformedLongFragmentStream],
    ['uint32-overflow', malformedOverflowFragmentStream],
  ];
  for (const [label, mutate] of cases) {
    await t.test(label, async () => {
      const malformed = mutate(sample.parsed[4].fragments);
      const shards = sample.parsed.map((shard) => (
        shard.shardIndex === 4 ? { ...shard, fragments: malformed } : shard
      ));
      const committedFaults = new Map([
        [malformed, sample.parsed[0].cohortBinding.shardBodyHashes[4]],
      ]);
      const trace = tracedRuntime();
      let result = null;

      try {
        result = await reconstructLifecycleCohortMaterial(buildCandidate(shards), {
          erasureRuntime: trace.runtime,
          digestHex: digestWithCommittedFaults(committedFaults),
          onWarn: () => {},
        });
        assert.deepEqual(result.qencBytes, sample.qencBytes);
        assert.deepEqual(result.corruptedShardIndices, [4]);
        assert.equal(trace.calls.length, 1);
      } finally {
        wipeResult(result);
      }
    });
  }
});

test('trailing and oversized fragment bodies are quarantined before body hashing', async (t) => {
  const cases = [
    ['single-trailing-byte', 1],
    ['oversized-body', 64 * 1024],
  ];
  for (const [label, extraBytes] of cases) {
    await t.test(label, async () => {
      const oversizedBody = appendBytes(sample.parsed[4].fragments, extraBytes);
      const shards = sample.parsed.map((shard) => (
        shard.shardIndex === 4 ? { ...shard, fragments: oversizedBody } : shard
      ));
      let oversizedBodyHashCalls = 0;
      const trace = tracedRuntime();
      let result = null;

      try {
        result = await reconstructLifecycleCohortMaterial(buildCandidate(shards), {
          erasureRuntime: trace.runtime,
          digestHex: async (bytes) => {
            if (bytes === oversizedBody) oversizedBodyHashCalls += 1;
            return digestHex(bytes);
          },
          onWarn: () => {},
        });
        assert.deepEqual(result.qencBytes, sample.qencBytes);
        assert.deepEqual(result.corruptedShardIndices, [4]);
        assert.equal(oversizedBodyHashCalls, 0);
        assert.equal(trace.calls.length, 1);
      } finally {
        wipeResult(result);
      }
    });
  }
});

test('malformed committed fragment extras beyond the RS budget fail before recombination', async () => {
  const malformedThree = malformedShortFragmentStream(sample.parsed[3].fragments);
  const malformedFour = malformedShortFragmentStream(sample.parsed[4].fragments);
  const shards = sample.parsed.map((shard) => {
    if (shard.shardIndex === 3) return { ...shard, fragments: malformedThree };
    if (shard.shardIndex === 4) return { ...shard, fragments: malformedFour };
    return shard;
  });
  const committedFaults = new Map([
    [malformedThree, sample.parsed[0].cohortBinding.shardBodyHashes[3]],
    [malformedFour, sample.parsed[0].cohortBinding.shardBodyHashes[4]],
  ]);
  const trace = tracedRuntime();

  await assert.rejects(
    reconstructLifecycleCohortMaterial(buildCandidate(shards), {
      erasureRuntime: trace.runtime,
      digestHex: digestWithCommittedFaults(committedFaults),
      onWarn: () => {},
    }),
    /Too many missing\/corrupted shards for RS reconstruction: allowed 1, got 2/
  );
  assert.equal(trace.calls.length, 0);
});

test('authenticated reconstruction resource limits are checked before key recovery and RS', async () => {
  const trace = tracedRuntime();
  const ciphertextLength = sample.parsed[0].qencMetaJSON.payloadLength + 16;
  let keyValidationFinallyCalls = 0;

  await assert.rejects(
    reconstructLifecycleCohortMaterial(buildCandidate(sample.parsed), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => digestHex(bytes),
      maxCiphertextBytes: ciphertextLength - 1,
      onWarn: () => {},
      keyValidationHooks: {
        onFinally: () => {
          keyValidationFinallyCalls += 1;
        },
      },
    }),
    /exceeds reconstruction limit/
  );
  assert.equal(trace.calls.length, 0);
  assert.equal(keyValidationFinallyCalls, 0);

  await assert.rejects(
    reconstructLifecycleCohortMaterial(buildCandidate(sample.parsed), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => digestHex(bytes),
      maxCiphertextBytes: MAX_RECONSTRUCTED_CIPHERTEXT_BYTES + 1,
      onWarn: () => {},
    }),
    /maxCiphertextBytes cannot exceed/
  );
  assert.equal(trace.calls.length, 0);
});

test('reconstruction rejects a fault-injected RS chunk with the wrong exact length', async () => {
  const trace = tracedRuntime(({ outputLength }) => new Uint8Array(outputLength - 1));
  let keyValidationFinallyCalls = 0;

  await assert.rejects(
    reconstructLifecycleCohortMaterial(buildCandidate(sample.parsed), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => digestHex(bytes),
      onWarn: () => {},
      keyValidationHooks: {
        onFinally: () => {
          keyValidationFinallyCalls += 1;
        },
      },
    }),
    /RS recombination returned an invalid chunk/
  );
  assert.equal(trace.calls.length, 1);
  assert.equal(keyValidationFinallyCalls, 1, 'key-validation cleanup hook must run before post-Shamir failure');
});

test('post-reconstruction validation failure wipes the allocated QENC buffer', async () => {
  const trace = tracedRuntime();
  let allocatedQenc = null;

  await assert.rejects(
    reconstructLifecycleCohortMaterial(buildCandidate(sample.parsed), {
      erasureRuntime: trace.runtime,
      digestHex: async (bytes) => {
        if (
          bytes.length === sample.qencBytes.length
          && bytes[0] === sample.qencBytes[0]
          && bytes[1] === sample.qencBytes[1]
        ) {
          allocatedQenc = bytes;
          throw new Error('injected final QENC digest failure');
        }
        return digestHex(bytes);
      },
      onWarn: () => {},
    }),
    /injected final QENC digest failure/
  );

  assert.ok(allocatedQenc instanceof Uint8Array);
  assert.equal(allocatedQenc.every((byte) => byte === 0), true);
});
