import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import {
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeCohortIdPreimage,
  canonicalizeLifecycleBundle,
  canonicalizeSourceEvidence,
  canonicalizeTransitionRecord,
  deriveCohortId,
  deriveStateId,
  parseArchiveStateDescriptorBytes,
  parseCohortBindingBytes,
  parseLifecycleBundleBytes,
  parseSourceEvidenceBytes,
  parseTransitionRecordBytes,
  validateRuntimeSupportedCohortTuple,
} from '../../src/core/crypto/lifecycle/artifacts.js';

const schemaDir = path.resolve('docs/schema');
const fixturesIndexPath = path.join(schemaDir, 'fixtures/index.json');
const decoder = new TextDecoder();

const artifactHandlers = {
  'archive-state': {
    canonicalize: canonicalizeArchiveStateDescriptor,
    parse: parseArchiveStateDescriptorBytes,
    valueField: 'archiveState',
  },
  'cohort-binding': {
    canonicalize: canonicalizeCohortBinding,
    parse: parseCohortBindingBytes,
    valueField: 'cohortBinding',
  },
  'transition-record': {
    canonicalize: canonicalizeTransitionRecord,
    parse: parseTransitionRecordBytes,
    valueField: 'transitionRecord',
  },
  'source-evidence': {
    canonicalize: canonicalizeSourceEvidence,
    parse: parseSourceEvidenceBytes,
    valueField: 'sourceEvidence',
  },
  'lifecycle-bundle': {
    canonicalize: canonicalizeLifecycleBundle,
    parse: parseLifecycleBundleBytes,
    valueField: 'lifecycleBundle',
  },
};

test('current Shamir/RS profile enforces normative shard-count bounds', () => {
  assert.deepEqual(
    validateRuntimeSupportedCohortTuple({
      n: 5,
      k: 3,
      parity: 2,
      threshold: 4,
      shareCount: 5,
      codecId: 'QV-RS-ErasureCodes-v1',
    }),
    {
      n: 5,
      k: 3,
      parity: 2,
      threshold: 4,
      shareCount: 5,
      codecId: 'QV-RS-ErasureCodes-v1',
      derivedThreshold: 4,
      allowedFailures: 1,
    },
  );
  assert.throws(
    () => validateRuntimeSupportedCohortTuple({
      n: 4,
      k: 2,
      parity: 2,
      threshold: 3,
      shareCount: 4,
      codecId: 'QV-RS-ErasureCodes-v1',
    }),
    /n >= 5/,
  );
  assert.throws(
    () => validateRuntimeSupportedCohortTuple({
      n: 256,
      k: 254,
      parity: 2,
      threshold: 255,
      shareCount: 256,
      codecId: 'QV-RS-ErasureCodes-v1',
    }),
    /n <= 255/,
  );
});

test('lifecycle runtime binds every signature array to its declared family and target', async () => {
  const fixture = JSON.parse(await readFile(
    path.join(schemaDir, 'fixtures/qv-lifecycle-bundle-v1.valid.json'),
    'utf8',
  ));

  const wrongFamily = structuredClone(fixture);
  wrongFamily.attachments.archiveApprovalSignatures[0].signatureFamily = 'maintenance';
  wrongFamily.attachments.archiveApprovalSignatures[0].targetType = 'transition-record';
  await assert.rejects(
    () => canonicalizeLifecycleBundle(wrongFamily),
    /archiveApprovalSignatures entry has wrong signatureFamily/,
  );

  const wrongTarget = structuredClone(fixture);
  wrongTarget.attachments.archiveApprovalSignatures[0].targetRef = `state:${'f'.repeat(128)}`;
  wrongTarget.attachments.archiveApprovalSignatures[0].targetDigest.value = 'f'.repeat(128);
  await assert.rejects(
    () => canonicalizeLifecycleBundle(wrongTarget),
    /archiveApprovalSignatures targetRef mismatch/,
  );

});

async function loadFixtureIndex() {
  return JSON.parse(await readFile(fixturesIndexPath, 'utf8'));
}

async function loadFixture(fixture) {
  const rawBytes = new Uint8Array(await readFile(path.join(schemaDir, fixture.file)));
  return {
    rawBytes,
    object: JSON.parse(decoder.decode(rawBytes)),
  };
}

test('lifecycle schema fixtures canonicalize to stable digest and parser bytes', async () => {
  const index = await loadFixtureIndex();
  const validFixtures = index.fixtures.filter((fixture) => (
    fixture.expectSchemaValid === true &&
    fixture.runtime?.expectParseSuccess === true &&
    typeof fixture.expectedDigestHex === 'string'
  ));

  assert(validFixtures.length > 0, 'expected lifecycle vector fixtures');

  for (const fixture of validFixtures) {
    const artifact = fixture.runtime.artifact;
    const handler = artifactHandlers[artifact];
    assert(handler, `missing handler for ${artifact}`);

    const { object } = await loadFixture(fixture);
    const canonicalized = await handler.canonicalize(object);
    const parsed = await handler.parse(canonicalized.bytes);
    const digestHex = toHex(sha3_512(canonicalized.bytes));

    assert.equal(digestHex, fixture.expectedDigestHex, fixture.id);
    assert.equal(canonicalized.digest.value, fixture.expectedDigestHex, fixture.id);
    assert.equal(parsed.digest.value, fixture.expectedDigestHex, fixture.id);
    assert.deepEqual(parsed.bytes, canonicalized.bytes, fixture.id);
    assert.deepEqual(
      JSON.parse(JSON.stringify(parsed[handler.valueField])),
      JSON.parse(JSON.stringify(canonicalized[handler.valueField])),
      fixture.id,
    );
  }
});

test('archive-state stateId and cohortId derivation stay bound to canonical bytes', async () => {
  const archiveStateFixture = {
    file: 'fixtures/qv-archive-state-descriptor-v1.valid.json',
    expectedDigestHex: 'e72be26038375f48a0de6a43f3d04f2c0988f0c6634b688e60772877066180dbc19a6054ae2220ba202f945aee24e79b99be40171b391f7d91bd904a355e5117',
  };
  const cohortFixture = {
    file: 'fixtures/qv-cohort-binding-v1.valid.json',
    expectedDigestHex: '711a52b581d6a92e8721f5188c516f7af932f9ef2ae11007b33765126ab23b06a94042e47d2b831f1b29340a7744065b7e946f76c5cba47ffa559cd73b6c794c',
    expectedCohortId: 'd14b3541103107a1969fb55db486bd3734a7ef5e05e88e6ab6604a7d38e8cc9b',
  };

  const archiveState = JSON.parse(await readFile(path.join(schemaDir, archiveStateFixture.file), 'utf8'));
  const cohortBinding = JSON.parse(await readFile(path.join(schemaDir, cohortFixture.file), 'utf8'));
  const canonicalArchiveState = canonicalizeArchiveStateDescriptor(archiveState);
  const canonicalCohortBinding = canonicalizeCohortBinding(cohortBinding);
  const preimage = canonicalizeCohortIdPreimage({
    archiveId: archiveState.archiveId,
    stateId: canonicalArchiveState.stateId,
    cohortBindingDigest: canonicalCohortBinding.digest,
  });

  assert.equal(Object.hasOwn(archiveState, 'stateId'), false);
  assert.equal(canonicalArchiveState.stateId, archiveStateFixture.expectedDigestHex);
  assert.equal(deriveStateId(archiveState), archiveStateFixture.expectedDigestHex);
  assert.equal(toHex(sha3_512(canonicalArchiveState.bytes)), archiveStateFixture.expectedDigestHex);
  assert.equal(canonicalCohortBinding.digest.value, cohortFixture.expectedDigestHex);
  assert.equal(
    deriveCohortId({
      archiveId: archiveState.archiveId,
      stateId: canonicalArchiveState.stateId,
      cohortBindingDigest: canonicalCohortBinding.digest,
    }),
    cohortFixture.expectedCohortId,
  );
  assert.equal(toHex(sha3_256(preimage.bytes)), cohortFixture.expectedCohortId);
});

test('lifecycle wire parsers reject non-canonical fixture bytes', async () => {
  const index = await loadFixtureIndex();
  const nonCanonicalVectors = index.fixtures.filter((fixture) => (
    fixture.runtime?.useRawJsonBytes === true &&
    fixture.runtime?.expectParseSuccess === false
  ));

  assert(nonCanonicalVectors.length > 0, 'expected non-canonical wire vectors');

  for (const fixture of nonCanonicalVectors) {
    const handler = artifactHandlers[fixture.runtime.artifact];
    assert(handler, `missing handler for ${fixture.runtime.artifact}`);
    const { rawBytes } = await loadFixture(fixture);
    await assert.rejects(
      async () => handler.parse(rawBytes),
      /canonical/i,
      fixture.id,
    );
  }
});
