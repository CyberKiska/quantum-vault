import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { parseLifecycleShard } from '../../src/core/crypto/qcont/lifecycle-shard.js';
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
  return mkdtemp(join(tmpdir(), 'qv-cli-reshare-'));
}

function digestHex(bytes) {
  return toHex(sha3_512(bytes));
}

function modeBits(stats) {
  return stats.mode & 0o777;
}

async function makeSplitFixture(baseDir, archiveIdByte = '33') {
  const keyDir = join(baseDir, `keys-${archiveIdByte}`);
  const keygen = await runCli(['keygen', '--out', keyDir, '--json']);
  assert.equal(keygen.exitCode, 0);
  const keys = JSON.parse(keygen.stdoutText);

  const plaintextPath = join(baseDir, `payload-${archiveIdByte}.bin`);
  const qencPath = join(baseDir, `payload-${archiveIdByte}.bin.qenc`);
  await writeFile(plaintextPath, new TextEncoder().encode(`reshare payload ${archiveIdByte}`));
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

  const outDir = join(baseDir, `cohort-${archiveIdByte}`);
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
    archiveIdByte.repeat(32),
    '--json',
  ]);
  assert.equal(split.exitCode, 0);
  return JSON.parse(split.stdoutText);
}

test('reshare --json writes a same-state successor cohort that restores in dry-run', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir, '33');
  const outDir = join(baseDir, 'reshared');
  const performedAt = '2026-03-25T12:34:56.000Z';
  const oldUmask = process.umask(0);
  try {
    const result = await runCli([
      'reshare',
      '--shards',
      join(split.outDir, '*.qcont'),
      '--n',
      '5',
      '--k',
      '3',
      '--out',
      outDir,
      '--reason-code',
      'cohort-rotation',
      '--operator-role',
      'operator',
      '--notes',
      'scheduled custody rotation',
      '--performed-at',
      performedAt,
      '--json',
    ]);

    assert.equal(result.exitCode, 0);
    assert.equal(result.stderrText, '');
    const report = JSON.parse(result.stdoutText);
    assert.equal(report.command, 'reshare');
    assert.equal(report.ok, true);
    assert.equal(report.cliSchemaVersion, 1);
    assert.equal(report.archiveId, split.archiveId);
    assert.equal(report.stateId, split.stateId);
    assert.equal(report.predecessorCohortId, split.cohortId);
    assert.notEqual(report.cohortId, split.cohortId);
    assert.equal(report.predecessorLifecycleBundleDigestHex, split.lifecycleBundleDigestHex);
    assert.equal(report.predecessorLifecycleBundleSource, 'embedded-lifecycle-bundle');
    assert.equal(report.archiveStateDigestHex, split.archiveStateDigestHex);
    assert.equal(report.maintenanceSignatureCountAdded, 0);
    assert.equal(report.zeroization.attempted, true);
    assert.equal(report.zeroization.privateKeyBytesCleared, true);
    assert.equal(report.zeroization.shareCopiesCleared, true);
    assert.equal(report.semantics.sameStateAvailabilityMaintenance, true);
    assert.equal(report.semantics.archiveReapprovalPerformed, false);
    assert.equal(report.verificationReport.privateKeyHashMatchesMetadata, true);
    assert.deepEqual(report.verificationReport.invalidShareIndices, []);
    assert.equal(report.operationalWarnings.length, 2);

    const archiveStateBytes = new Uint8Array(await readFile(report.archiveStateBytesPath));
    const transitionRecordBytes = new Uint8Array(await readFile(report.transitionRecordPath));
    const lifecycleBundleBytes = new Uint8Array(await readFile(report.lifecycleBundlePath));
    assert.equal(digestHex(archiveStateBytes), split.archiveStateDigestHex);
    assert.equal(digestHex(transitionRecordBytes), report.transitionRecordDigestHex);
    assert.equal(digestHex(lifecycleBundleBytes), report.lifecycleBundleDigestHex);
    assert.equal(modeBits(await stat(report.lifecycleBundlePath)), 0o644);
    assert.equal(modeBits(await stat(report.transitionRecordPath)), 0o644);
    const transitionRecord = JSON.parse(Buffer.from(transitionRecordBytes).toString('utf8'));
    assert.equal(transitionRecord.archiveId, split.archiveId);
    assert.equal(transitionRecord.fromStateId, split.stateId);
    assert.equal(transitionRecord.toStateId, split.stateId);
    assert.equal(transitionRecord.fromCohortId, split.cohortId);
    assert.equal(transitionRecord.toCohortId, report.cohortId);
    assert.equal(transitionRecord.performedAt, performedAt);

    assert.equal(report.shards.length, 5);
    for (const shard of report.shards) {
      assert.equal(modeBits(await stat(shard.path)), 0o600);
      const shardBytes = new Uint8Array(await readFile(shard.path));
      assert.equal(digestHex(shardBytes), shard.shardDigestHex);
      assert.equal(shardBytes.length, shard.shardSize);
      const parsed = await parseLifecycleShard(shardBytes, { strict: true });
      assert.equal(parsed.archiveState.archiveId, split.archiveId);
      assert.equal(parsed.stateId, split.stateId);
      assert.equal(parsed.cohortId, report.cohortId);
      assert.equal(parsed.archiveStateDigestHex, split.archiveStateDigestHex);
      assert.equal(parsed.lifecycleBundleDigestHex, report.lifecycleBundleDigestHex);
    }

    const restore = await runCli([
      'restore',
      '--shards',
      join(outDir, '*.qcont'),
      '--dry-run',
      '--json',
    ]);
    assert.equal(restore.exitCode, 0);
    const restoreReport = JSON.parse(restore.stdoutText);
    assert.equal(restoreReport.wouldSucceed, true);
    assert.equal(restoreReport.outputs, null);
    assert.equal(restoreReport.archiveId, split.archiveId);
    assert.equal(restoreReport.stateId, split.stateId);
    assert.equal(restoreReport.cohortId, report.cohortId);
  } finally {
    process.umask(oldUmask);
  }
});

test('reshare rejects forbidden same-state override flags with RESHARE_CONTRACT_VIOLATION', async () => {
  const forbiddenFlags = [
    '--archive-state',
    '--qenc-hash',
    '--container-id',
    '--auth-policy-level',
    '--min-valid-signatures',
    '--state-type',
  ];

  for (const flag of forbiddenFlags) {
    const result = await runCli(['reshare', flag, 'forbidden', '--json']);
    assert.equal(result.exitCode, 10, flag);
    const error = JSON.parse(result.stdoutText);
    assert.equal(error.command, 'reshare');
    assert.equal(error.ok, false);
    assert.equal(error.qvCode, 'RESHARE_CONTRACT_VIOLATION');
  }
});

test('reshare rejects mixed predecessor cohorts unless explicitly reduced', async () => {
  const baseDir = await makeTempDir();
  const first = await makeSplitFixture(baseDir, '44');
  const second = await makeSplitFixture(baseDir, '55');

  const result = await runCli([
    'reshare',
    '--shards',
    join(first.outDir, '*.qcont'),
    '--shards',
    join(second.outDir, '*.qcont'),
    '--n',
    '5',
    '--k',
    '3',
    '--json',
  ]);

  assert.equal(result.exitCode, 9);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'AMBIGUOUS_INPUTS');
});

test('reshare rejects a mismatched explicit lifecycle bundle fail closed', async () => {
  const baseDir = await makeTempDir();
  const first = await makeSplitFixture(baseDir, '66');
  const second = await makeSplitFixture(baseDir, '77');

  const result = await runCli([
    'reshare',
    '--shards',
    join(first.outDir, '*.qcont'),
    '--bundle',
    second.lifecycleBundleBytesPath,
    '--n',
    '5',
    '--k',
    '3',
    '--json',
  ]);

  assert.equal(result.exitCode, 9);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'AMBIGUOUS_INPUTS');
});

test('reshare maps unsupported RS/Shamir geometry to QUORUM_UNREACHABLE', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir, '88');

  const result = await runCli([
    'reshare',
    '--shards',
    join(split.outDir, '*.qcont'),
    '--n',
    '5',
    '--k',
    '4',
    '--json',
  ]);

  assert.equal(result.exitCode, 7);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'QUORUM_UNREACHABLE');
});
