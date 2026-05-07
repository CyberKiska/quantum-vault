import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { exportSourceEvidenceForSigning } from '../../src/core/crypto/qcont/lifecycle-attach.js';
import { parseLifecycleBundleBytes } from '../../src/core/crypto/lifecycle/artifacts.js';
import { parseLifecycleShard } from '../../src/core/crypto/qcont/lifecycle-shard.js';
import { buildOtsFixture, buildQsigFixture } from '../../src/core/crypto/selftest.js';
import { runQvCli } from '../../src/core/cli/qv.js';

function createCaptureStream() {
  const chunks = [];
  return {
    write(chunk) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return true;
    },
    text() {
      return Buffer.concat(chunks).toString('utf8');
    },
  };
}

async function runCli(args, options = {}) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, {
    stdout,
    stderr,
    stdin: options.stdin,
    cwd: options.cwd,
    env: { ...process.env, QV_ALLOW_DETERMINISTIC: '1', ...(options.env || {}) },
  });
  return {
    exitCode,
    stdoutText: stdout.text(),
    stderrText: stderr.text(),
  };
}

async function makeTempDir() {
  return mkdtemp(join(tmpdir(), 'qv-cli-attach-'));
}

function digestHex(bytes) {
  return toHex(sha3_512(bytes));
}

function modeBits(stats) {
  return stats.mode & 0o777;
}

async function makeSplitFixture(baseDir) {
  const keyDir = join(baseDir, 'keys');
  const keygen = await runCli(['keygen', '--out', keyDir, '--json']);
  assert.equal(keygen.exitCode, 0);
  const keys = JSON.parse(keygen.stdoutText);

  const plaintextPath = join(baseDir, 'payload.bin');
  const qencPath = join(baseDir, 'payload.bin.qenc');
  await writeFile(plaintextPath, new TextEncoder().encode('attach lifecycle artifacts'));
  const encrypted = await runCli([
    'encrypt',
    plaintextPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    qencPath,
    '--json',
  ]);
  assert.equal(encrypted.exitCode, 0);

  const outDir = join(baseDir, 'cohort');
  const split = await runCli([
    'split',
    qencPath,
    '--private-key',
    keys.privateKeyPath,
    '--n',
    '5',
    '--k',
    '3',
    '--out',
    outDir,
    '--auth-policy-level',
    'integrity-only',
    '--archive-id-random',
    '22'.repeat(32),
    '--json',
  ]);
  assert.equal(split.exitCode, 0);
  return JSON.parse(split.stdoutText);
}

async function writeArchiveApprovalFixture(baseDir, archiveStateBytes, { ots = false } = {}) {
  const qsig = buildQsigFixture(archiveStateBytes);
  const qsigPath = join(baseDir, 'archive.qsig');
  const pqpkPath = join(baseDir, 'archive.pqpk');
  await writeFile(qsigPath, qsig.qsigBytes);
  await writeFile(pqpkPath, qsig.pqpkBytes);
  let otsPath = '';
  if (ots) {
    const otsBytes = await buildOtsFixture(qsig.qsigBytes, { completeProof: true });
    otsPath = join(baseDir, 'archive.ots');
    await writeFile(otsPath, otsBytes);
  }
  return { qsigPath, pqpkPath, otsPath };
}

test('attach --json imports archive approval signature, timestamp, and rewrites shards', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir);
  const archiveStateBytes = new Uint8Array(await readFile(split.archiveStateBytesPath));
  const { qsigPath, pqpkPath, otsPath } = await writeArchiveApprovalFixture(baseDir, archiveStateBytes, { ots: true });
  const outBundlePath = join(baseDir, 'attached.lifecycle-bundle.json');
  const outShardsDir = join(baseDir, 'attached-shards');
  const oldUmask = process.umask(0);
  try {
    const result = await runCli([
      'attach',
      '--shards',
      join(split.outDir, '*.qcont'),
      '--sig',
      qsigPath,
      '--pqpk',
      pqpkPath,
      '--ots',
      otsPath,
      '--out-bundle',
      outBundlePath,
      '--out-shards',
      outShardsDir,
      '--json',
    ]);

    assert.equal(result.exitCode, 0);
    assert.equal(result.stderrText, '');
    const report = JSON.parse(result.stdoutText);
    assert.equal(report.command, 'attach');
    assert.equal(report.ok, true);
    assert.equal(report.cliSchemaVersion, 1);
    assert.equal(report.archiveId, split.archiveId);
    assert.equal(report.stateId, split.stateId);
    assert.equal(report.cohortId, split.cohortId);
    assert.equal(report.lifecycleBundlePath, outBundlePath);
    assert.equal(report.lifecycleBundleDigestAlg, 'SHA3-512');
    assert.equal(report.embeddedIntoShards, true);
    assert.equal(report.shardsRewritten.length, 5);
    assert.equal(report.addedAttachments.publicKeys.length, 1);
    assert.equal(report.addedAttachments.archiveApprovalSignatures.length, 1);
    assert.equal(report.addedAttachments.timestamps.length, 1);
    assert.deepEqual(report.embeddedLifecycleBundleDigests, [split.lifecycleBundleDigestHex]);
    assert.equal(report.mixedEmbeddedLifecycleBundleDigests, false);

    const bundleBytes = new Uint8Array(await readFile(outBundlePath));
    assert.equal(report.lifecycleBundleDigestHex, digestHex(bundleBytes));
    assert.equal(modeBits(await stat(outBundlePath)), 0o644);
    const parsedBundle = await parseLifecycleBundleBytes(bundleBytes);
    assert.equal(parsedBundle.lifecycleBundle.attachments.archiveApprovalSignatures.length, 1);
    assert.equal(parsedBundle.lifecycleBundle.attachments.publicKeys.length, 1);
    assert.equal(parsedBundle.lifecycleBundle.attachments.timestamps.length, 1);

    for (const shard of report.shardsRewritten) {
      assert.equal(modeBits(await stat(shard.path)), 0o600);
      const parsedShard = await parseLifecycleShard(new Uint8Array(await readFile(shard.path)), { strict: true });
      assert.equal(parsedShard.archiveState.archiveId, split.archiveId);
      assert.equal(parsedShard.stateId, split.stateId);
      assert.equal(parsedShard.cohortId, split.cohortId);
      assert.equal(parsedShard.lifecycleBundleDigestHex, report.lifecycleBundleDigestHex);
    }
  } finally {
    process.umask(oldUmask);
  }
});

test('attach supports bundle-only output without shard embedding', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir);
  const archiveStateBytes = new Uint8Array(await readFile(split.archiveStateBytesPath));
  const { qsigPath, pqpkPath } = await writeArchiveApprovalFixture(baseDir, archiveStateBytes);
  const outBundlePath = join(baseDir, 'bundle-only.lifecycle-bundle.json');

  const result = await runCli([
    'attach',
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--sig',
    qsigPath,
    '--pqpk',
    pqpkPath,
    '--out-bundle',
    outBundlePath,
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.archiveId, split.archiveId);
  assert.equal(report.stateId, split.stateId);
  assert.equal(report.cohortId, split.cohortId);
  assert.equal(report.embeddedIntoShards, false);
  assert.deepEqual(report.shardsRewritten, []);
  assert.equal(report.addedAttachments.archiveApprovalSignatures.length, 1);
});

test('attach imports typed source-evidence signatures with explicit targets', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir);
  const exported = exportSourceEvidenceForSigning({
    sourceEvidence: {
      relationType: 'reviewed-source',
      sourceObjectType: 'archive-state-descriptor',
      sourceDigests: [
        { alg: 'SHA3-512', value: split.archiveStateDigestHex },
      ],
      externalSourceSignatureRefs: ['sig:external-source-review'],
    },
  });
  const qsig = buildQsigFixture(exported.sourceEvidenceBytes);
  const sourceEvidencePath = join(baseDir, 'source-evidence.json');
  const qsigPath = join(baseDir, 'source-evidence.qsig');
  const pqpkPath = join(baseDir, 'source-evidence.pqpk');
  await writeFile(sourceEvidencePath, exported.sourceEvidenceBytes);
  await writeFile(qsigPath, qsig.qsigBytes);
  await writeFile(pqpkPath, qsig.pqpkBytes);

  const result = await runCli([
    'attach',
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--source-evidence',
    sourceEvidencePath,
    '--sig-import',
    JSON.stringify({
      file: qsigPath,
      signatureFamily: 'source-evidence',
      targetType: 'source-evidence',
      targetRef: exported.targetRef,
      targetDigest: exported.sourceEvidenceDigestHex,
    }),
    '--pqpk',
    pqpkPath,
    '--out-bundle',
    join(baseDir, 'source-attached.lifecycle-bundle.json'),
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.addedAttachments.sourceEvidence.length, 1);
  assert.equal(report.addedAttachments.sourceEvidenceSignatures.length, 1);
  assert.equal(report.addedAttachments.publicKeys.length, 1);
});

test('attach rejects malformed signature import descriptors as usage errors', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir);

  const result = await runCli([
    'attach',
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--sig-import',
    JSON.stringify({
      file: join(baseDir, 'missing.qsig'),
      signatureFamily: 'source-evidence',
      unexpected: true,
    }),
    '--json',
  ]);

  assert.equal(result.exitCode, 2);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.command, 'attach');
  assert.equal(error.ok, false);
  assert.equal(error.qvCode, 'USAGE');

  const duplicateKey = await runCli([
    'attach',
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--sig-import',
    `{"file":"${join(baseDir, 'missing.qsig')}","signatureFamily":"maintenance","signatureFamily":"source-evidence"}`,
    '--json',
  ]);
  assert.equal(duplicateKey.exitCode, 2);
  const duplicateError = JSON.parse(duplicateKey.stdoutText);
  assert.equal(duplicateError.qvCode, 'USAGE');
  assert.match(duplicateError.error, /Duplicate object key/);
});

test('attach maps signature routing and verification failures to SIGNATURE_IMPORT_FAILED', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir);
  const wrong = buildQsigFixture(new TextEncoder().encode('not the selected archive-state'));
  const qsigPath = join(baseDir, 'wrong.qsig');
  const pqpkPath = join(baseDir, 'wrong.pqpk');
  await writeFile(qsigPath, wrong.qsigBytes);
  await writeFile(pqpkPath, wrong.pqpkBytes);

  const result = await runCli([
    'attach',
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--sig',
    qsigPath,
    '--pqpk',
    pqpkPath,
    '--out-bundle',
    join(baseDir, 'wrong.lifecycle-bundle.json'),
    '--json',
  ]);

  assert.equal(result.exitCode, 8);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.command, 'attach');
  assert.equal(error.ok, false);
  assert.equal(error.qvCode, 'SIGNATURE_IMPORT_FAILED');
});
