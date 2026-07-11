import assert from 'node:assert/strict';
import test from 'node:test';
import { bytesEqual, bytesToBase64 } from '../../src/core/crypto/bytes.js';
import {
  classifyArtifactBytes,
  classifyArtifactPreviewBytes,
} from '../../src/core/crypto/artifact-classification.js';
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
  classifyArtifactFileBytes,
  parseArchiveStateViewBytes,
  parseLifecycleBundleArchiveStateViewBytes,
  parseLifecycleBundleViewBytes,
  parseSourceEvidenceViewBytes,
  parseTransitionRecordViewBytes,
} from '../../src/app/artifact-intake-service.js';
import {
  canonicalizeSourceEvidence,
  canonicalizeTransitionRecord,
} from '../../src/core/crypto/lifecycle/artifacts.js';
import { classifyRestoreInputFiles } from '../../src/app/restore-inputs.js';
import { classifyAttachFiles } from '../../src/core/features/qcont/attach-ui.js';
import { assessShardSelection } from '../../src/app/shard-preview.js';

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
    size: copy.length,
    async arrayBuffer() {
      return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength);
    },
    slice(start = 0, end = copy.length) {
      const sliced = copy.slice(start, end);
      return {
        async arrayBuffer() {
          return sliced.buffer.slice(sliced.byteOffset, sliced.byteOffset + sliced.byteLength);
        },
      };
    },
  };
}

function sliceOnlyFileLike(name, bytes) {
  const copy = bytes.slice();
  return {
    name,
    size: copy.length,
    async arrayBuffer() {
      throw new Error('Full file read is not allowed for this preview fixture');
    },
    slice(start = 0, end = copy.length) {
      const sliced = copy.slice(start, end);
      return {
        async arrayBuffer() {
          return sliced.buffer.slice(sliced.byteOffset, sliced.byteOffset + sliced.byteLength);
        },
      };
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
      const otherSample = await buildSuccessorRestoreSample({
        payloadBytes: textBytes('artifact-classification-regression-other-state'),
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
        otherArchiveStateBytes: otherSample.split.archiveStateBytes,
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

test('classifyArtifactPreviewBytes reports only presentation candidates from bounded bytes', async () => {
  const fx = await fixtures();
  const qsigPreview = classifyArtifactPreviewBytes(fx.qsigBytes.subarray(0, 8), {
    name: 'renamed-signature.bin',
  });
  const pqpkPreview = classifyArtifactPreviewBytes(fx.pqpkBytes.subarray(0, 8), {
    name: 'renamed-public-key.bin',
  });
  const unknownPreview = classifyArtifactPreviewBytes(textBytes('not an artifact'), {
    name: 'notes.txt',
  });

  assert.equal(qsigPreview.kind, 'signature');
  assert.equal(qsigPreview.format, 'qsig');
  assert.equal(qsigPreview.status, 'candidate');
  assert.equal(pqpkPreview.kind, 'pqpk');
  assert.equal(pqpkPreview.format, 'pqpk');
  assert.equal(pqpkPreview.status, 'candidate');
  assert.equal(unknownPreview.kind, 'unsupported');
  assertNoForbiddenFields(qsigPreview, 'qsigPreview');
  assertNoForbiddenFields(pqpkPreview, 'pqpkPreview');
  assertNoForbiddenFields(unknownPreview, 'unknownPreview');
});

test('app lifecycle bundle view helper exposes display data while preserving parser failures', async () => {
  const fx = await fixtures();
  const classified = await classifyArtifactFileBytes(
    fileLike('archive.lifecycle-bundle.json', fx.lifecycleBundleBytes)
  );
  const parsed = await parseLifecycleBundleViewBytes(fx.lifecycleBundleBytes);
  const archiveState = await parseLifecycleBundleArchiveStateViewBytes(fx.lifecycleBundleBytes);

  assert.equal(parsed.lifecycleBundle.type, 'QV-Lifecycle-Bundle');
  assert.equal(parsed.digestHex, classified.classification.metadata.digestHex);
  assert.equal(parsed.digest.value, parsed.digestHex);
  assert.equal(bytesEqual(parsed.canonicalBytes, fx.lifecycleBundleBytes), true);

  assert.equal(archiveState.lifecycleBundleDigestHex, parsed.digestHex);
  assert.equal(archiveState.digestHex, classified.classification.metadata.archiveStateDigestHex);
  assert.equal(archiveState.digest.value, archiveState.digestHex);
  assert.equal(archiveState.stateId, archiveState.digestHex);
  assert.equal(bytesEqual(archiveState.canonicalBytes, fx.archiveStateBytes), true);

  await assert.rejects(
    () => parseLifecycleBundleViewBytes(textBytes('{"type":"QV-Lifecycle-Bundle"')),
    /json|lifecycle/i
  );
  await assert.rejects(
    () => parseLifecycleBundleArchiveStateViewBytes(textBytes('{"type":"QV-Lifecycle-Bundle"')),
    /json|lifecycle/i
  );
});

test('app archive-state view helper exposes display data while preserving parser failures', async () => {
  const fx = await fixtures();
  const classified = await classifyArtifactFileBytes(
    fileLike('archive.archive-state.json', fx.archiveStateBytes)
  );
  const parsed = parseArchiveStateViewBytes(fx.archiveStateBytes);

  assert.equal(parsed.archiveState.schema, 'quantum-vault-archive-state-descriptor/v1');
  assert.equal(parsed.archiveState.stateType, 'archive-state');
  assert.equal(parsed.digestHex, classified.classification.metadata.stateDigestHex);
  assert.equal(parsed.digest.value, parsed.digestHex);
  assert.equal(parsed.stateId, parsed.digestHex);
  assert.equal(bytesEqual(parsed.canonicalBytes, fx.archiveStateBytes), true);

  assert.throws(
    () => parseArchiveStateViewBytes(textBytes('{"type":"QV-Archive-State"')),
    /json|archive-state|archive state/i
  );
});

test('app attach-target view helpers expose target refs and preserve parser failures', async () => {
  const fx = await fixtures();
  const transition = parseTransitionRecordViewBytes(fx.transitionRecordBytes);
  const sourceEvidence = parseSourceEvidenceViewBytes(fx.sourceEvidenceBytes);

  assert.equal(transition.targetRef, `transition:sha3-512:${transition.digestHex}`);
  assert.equal(transition.digest.value, transition.digestHex);
  assert.equal(bytesEqual(transition.canonicalBytes, fx.transitionRecordBytes), true);

  assert.equal(sourceEvidence.targetRef, `source-evidence:sha3-512:${sourceEvidence.digestHex}`);
  assert.equal(sourceEvidence.digest.value, sourceEvidence.digestHex);
  assert.equal(bytesEqual(sourceEvidence.canonicalBytes, fx.sourceEvidenceBytes), true);

  assert.throws(
    () => parseTransitionRecordViewBytes(textBytes('{"type":"QV-Transition-Record"')),
    /json|transition/i
  );
  assert.throws(
    () => parseSourceEvidenceViewBytes(textBytes('{"type":"QV-Source-Evidence"')),
    /json|source-evidence|source evidence/i
  );
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

test('classifyAttachFiles keeps attach return shape while using app/core classification', async () => {
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

  const result = await classifyAttachFiles(files);

  assert.deepEqual(Object.keys(result), [
    'shardFiles',
    'archiveStateBytes',
    'lifecycleBundleBytes',
    'transitionRecordBytes',
    'sourceEvidenceBytes',
    'signatures',
    'timestamps',
    'pqPublicKeyFileBytesList',
  ]);
  assert.deepEqual(result.shardFiles, [files[0]]);
  assert.deepEqual(result.signatures.map((item) => item.name), ['archive.qsig', 'archive.sig']);
  assert.equal(result.timestamps.length, 1);
  assert.equal(result.timestamps[0].name, 'archive.ots');
  assert.equal(result.pqPublicKeyFileBytesList.length, 1);
  assert.equal(bytesEqual(result.pqPublicKeyFileBytesList[0], fx.pqpkBytes), true);
  assert.equal(bytesEqual(result.archiveStateBytes, fx.archiveStateBytes), true);
  assert.equal(bytesEqual(result.lifecycleBundleBytes, fx.lifecycleBundleBytes), true);
  assert.equal(bytesEqual(result.sourceEvidenceBytes, fx.sourceEvidenceBytes), true);
  assert.equal(bytesEqual(result.transitionRecordBytes, fx.transitionRecordBytes), true);
});

test('classifyAttachFiles fails closed for malformed named JSON and legacy manifest inputs', async () => {
  await assert.rejects(
    () => classifyAttachFiles([
      fileLike('bad.source-evidence.json', textBytes('{"type":"QV-Source-Evidence"')),
    ]),
    /json|source-evidence|source evidence/i
  );

  await assert.rejects(
    () => classifyAttachFiles([
      fileLike('old.qvmanifest.json', textBytes('{}')),
    ]),
    /manifest-side files are no longer accepted/i
  );
});

test('restore and attach intake reject conflicting canonical singleton artifacts', async () => {
  const fx = await fixtures();

  await assert.rejects(
    () => classifyRestoreInputFiles([
      fileLike('archive.archive-state.json', fx.archiveStateBytes),
      fileLike('other.archive-state.json', fx.otherArchiveStateBytes),
    ]),
    /Multiple different archive-state descriptor files were provided/
  );

  await assert.rejects(
    () => classifyAttachFiles([
      fileLike('archive.archive-state.json', fx.archiveStateBytes),
      fileLike('other.archive-state.json', fx.otherArchiveStateBytes),
    ]),
    /Multiple different archive-state descriptor files were provided/
  );
});

test('shard preview attachment counts use bounded core preview classification for large non-shard files', async () => {
  const fx = await fixtures();
  const largeSignature = new Uint8Array(512 * 1024);
  largeSignature.set(fx.qsigBytes.subarray(0, 8), 0);

  const assessment = await assessShardSelection([
    fileLike('share-1.qcont', fx.qcontBytes),
    sliceOnlyFileLike('large-renamed-signature.bin', largeSignature),
  ]);

  assert.equal(assessment.ready, false);
  assert.match(assessment.message, /Attachments: 1 signature\(s\)\./);
});
