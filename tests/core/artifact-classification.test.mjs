import assert from 'node:assert/strict';
import test from 'node:test';
import { bytesEqual, bytesToBase64 } from '../../src/core/crypto/bytes.js';
import { classifyArtifactBytes } from '../../src/core/crypto/artifact-classification.js';
import {
  blobToBytes,
  buildOtsFixture,
  buildQsigFixture,
  buildSuccessorRestoreSample,
  buildSuccessorVerificationBundle,
  ensureErasureRuntime,
  ensureRuntimeCrypto,
  textBytes,
} from '../../src/core/crypto/selftest.js';
import {
  canonicalizeSourceEvidence,
  canonicalizeTransitionRecord,
} from '../../src/core/crypto/lifecycle/artifacts.js';
import { classifyRestoreInputFiles } from '../../src/app/restore-inputs.js';

const FORBIDDEN_CLASSIFICATION_FIELDS = new Set(['trusted', 'policySatisfied', 'releaseAllowed']);
let fixturePromise = null;

function assertNoForbiddenFields(value, path = 'classification') {
  if (value == null || typeof value !== 'object') return;
  if (value instanceof Uint8Array || value instanceof Error) return;

  for (const key of Object.keys(value)) {
    assert.equal(
      FORBIDDEN_CLASSIFICATION_FIELDS.has(key),
      false,
      `${path}.${key} must not be emitted by artifact classification`
    );
    assertNoForbiddenFields(value[key], `${path}.${key}`);
  }
}

function stellarSignatureBytes() {
  return new TextEncoder().encode(JSON.stringify({
    schema: 'stellar-signature/v2',
    proofType: 'sep53-message-signature',
    payloadType: 'raw-bytes',
    signatureScheme: 'sep53-sha256-ed25519',
    input: { type: 'file', size: 0, name: 'archive-state.json' },
    signer: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    hashes: [
      { alg: 'SHA-256', hex: '00'.repeat(32) },
      { alg: 'SHA3-512', hex: '11'.repeat(64) },
    ],
    signatureB64: bytesToBase64(new Uint8Array(64)),
  }));
}

function fileLike(name, bytes) {
  const copy = bytes.slice();
  return {
    name,
    async arrayBuffer() {
      return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength);
    },
  };
}

async function fixtures() {
  if (!fixturePromise) {
    fixturePromise = (async () => {
      await ensureRuntimeCrypto();
      await ensureErasureRuntime();

      const sample = await buildSuccessorRestoreSample({
        payloadBytes: textBytes('artifact-classification-regression'),
        authPolicyLevel: 'integrity-only',
      });
      const qsig = buildQsigFixture(sample.split.archiveStateBytes);
      const otsBytes = await buildOtsFixture(qsig.qsigBytes, { completeProof: true });
      const verificationBundle = await buildSuccessorVerificationBundle(sample.split, {
        includeArchiveApproval: false,
        includeMaintenance: true,
        includeSourceEvidence: true,
      });
      const transitionRecordBytes = canonicalizeTransitionRecord(verificationBundle.transitionRecord).bytes;
      const sourceEvidenceBytes = canonicalizeSourceEvidence(verificationBundle.sourceEvidence).bytes;

      return {
        qcontBytes: await blobToBytes(sample.split.shards[0].blob),
        qsigBytes: qsig.qsigBytes,
        pqpkBytes: qsig.pqpkBytes,
        stellarBytes: stellarSignatureBytes(),
        otsBytes,
        lifecycleBundleBytes: sample.split.lifecycleBundleBytes,
        archiveStateBytes: sample.split.archiveStateBytes,
        transitionRecordBytes,
        sourceEvidenceBytes,
      };
    })();
  }
  return fixturePromise;
}

test('classifyArtifactBytes classifies supported artifact bytes without DOM or File input', async () => {
  const fx = await fixtures();
  const cases = [
    ['QCONT', 'share-1.qcont', fx.qcontBytes, 'qcont-shard', 'qcont'],
    ['QSIG', 'archive.qsig', fx.qsigBytes, 'signature', 'qsig'],
    ['PQPK', 'archive.pqpk', fx.pqpkBytes, 'pqpk', 'pqpk'],
    ['Stellar JSON', 'archive.sig', fx.stellarBytes, 'signature', 'stellar-sig'],
    ['OTS', 'archive.ots', fx.otsBytes, 'ots-proof', 'ots'],
    ['lifecycle bundle', 'archive.lifecycle-bundle.json', fx.lifecycleBundleBytes, 'lifecycle-bundle', 'lifecycle-bundle-json'],
    ['archive-state', 'archive.archive-state.json', fx.archiveStateBytes, 'archive-state', 'archive-state-json'],
    ['source evidence', 'source.source-evidence.json', fx.sourceEvidenceBytes, 'source-evidence', 'source-evidence-json'],
    ['transition record', 'transition.transition-record.json', fx.transitionRecordBytes, 'transition-record', 'transition-record-json'],
  ];

  for (const [label, name, bytes, kind, format] of cases) {
    const result = await classifyArtifactBytes(bytes, { name });
    assert.equal(result.kind, kind, label);
    assert.equal(result.format, format, label);
    assert.equal(result.status, 'recognized', label);
    assert.equal(result.malformed, false, label);
    assert.match(result.fileSha256Hex, /^[0-9a-f]{64}$/, label);
    assertNoForbiddenFields(result, label);
  }
});

test('classifyArtifactBytes reports unknown and malformed artifacts without trust decisions', async () => {
  const unknown = await classifyArtifactBytes(textBytes('not a Quantum Vault artifact'), { name: 'notes.txt' });
  assert.equal(unknown.kind, 'unsupported');
  assert.equal(unknown.format, 'unknown');
  assert.equal(unknown.status, 'unknown');
  assertNoForbiddenFields(unknown, 'unknown');

  const malformed = await classifyArtifactBytes(textBytes('{"schema":"quantum-vault-archive-state-descriptor/v1"'), {
    name: 'bad.archive-state.json',
  });
  assert.equal(malformed.kind, 'archive-state');
  assert.equal(malformed.format, 'archive-state-json');
  assert.equal(malformed.status, 'malformed');
  assert.equal(malformed.malformed, true);
  assert.match(malformed.errorMessage, /json/i);
  assertNoForbiddenFields(malformed, 'malformed');
});

test('classifyRestoreInputFiles keeps restore return shape while using app/core classification', async () => {
  const fx = await fixtures();
  const files = [
    fileLike('share-1.qcont', fx.qcontBytes),
    fileLike('archive.qsig', fx.qsigBytes),
    fileLike('archive.sig', fx.stellarBytes),
    fileLike('archive.pqpk', fx.pqpkBytes),
    fileLike('archive-copy.pqpk', fx.pqpkBytes),
    fileLike('archive.ots', fx.otsBytes),
    fileLike('archive.lifecycle-bundle.json', fx.lifecycleBundleBytes),
    fileLike('archive.archive-state.json', fx.archiveStateBytes),
    fileLike('source.source-evidence.json', fx.sourceEvidenceBytes),
    fileLike('transition.transition-record.json', fx.transitionRecordBytes),
    fileLike('notes.txt', textBytes('ignored')),
  ];

  const result = await classifyRestoreInputFiles(files);

  assert.deepEqual(Object.keys(result), [
    'shardFiles',
    'archiveStateBytes',
    'lifecycleBundleBytes',
    'signatures',
    'timestamps',
    'pinnedPqPublicKeyFileBytes',
    'pinnedPqPublicKeyFileBytesList',
    'ignoredFileNames',
  ]);
  assert.deepEqual(result.shardFiles, [files[0]]);
  assert.deepEqual(result.signatures.map((item) => item.name), ['archive.qsig', 'archive.sig']);
  assert.equal(result.timestamps.length, 1);
  assert.equal(result.timestamps[0].name, 'archive.ots');
  assert.equal(result.pinnedPqPublicKeyFileBytesList.length, 1);
  assert.equal(bytesEqual(result.pinnedPqPublicKeyFileBytes, fx.pqpkBytes), true);
  assert.equal(bytesEqual(result.archiveStateBytes, fx.archiveStateBytes), true);
  assert.equal(bytesEqual(result.lifecycleBundleBytes, fx.lifecycleBundleBytes), true);
  assert.deepEqual(result.ignoredFileNames, [
    'source.source-evidence.json',
    'transition.transition-record.json',
    'notes.txt',
  ]);
});
