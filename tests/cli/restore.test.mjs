import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
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
  });
  return {
    exitCode,
    stdoutText: stdout.text(),
    stderrText: stderr.text(),
  };
}

async function makeTempDir() {
  return mkdtemp(join(tmpdir(), 'qv-cli-restore-'));
}

function modeBits(stats) {
  return stats.mode & 0o777;
}

async function exists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function makeSplitFixture(baseDir, {
  authPolicyLevel = 'integrity-only',
  archiveIdByte = '99',
} = {}) {
  const keyDir = join(baseDir, `keys-${archiveIdByte}`);
  const keygen = await runCli(['keygen', '--out', keyDir, '--json']);
  assert.equal(keygen.exitCode, 0);
  const keys = JSON.parse(keygen.stdoutText);

  const plaintext = new TextEncoder().encode(`restore payload ${archiveIdByte}`);
  const plaintextPath = join(baseDir, `payload-${archiveIdByte}.txt`);
  const qencPath = join(baseDir, `payload-${archiveIdByte}.txt.qenc`);
  await writeFile(plaintextPath, plaintext);
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
  const splitArgs = [
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
    '--archive-id-random',
    archiveIdByte.repeat(32),
    '--json',
  ];
  if (authPolicyLevel) {
    splitArgs.splice(splitArgs.length - 1, 0, '--auth-policy-level', authPolicyLevel);
  }
  const split = await runCli(splitArgs);
  assert.equal(split.exitCode, 0);
  return {
    keys,
    plaintext,
    plaintextPath,
    qencPath,
    split: JSON.parse(split.stdoutText),
  };
}

test('restore write mode recovers qenc, private key, and lifecycle sidecars', async () => {
  const baseDir = await makeTempDir();
  const fixture = await makeSplitFixture(baseDir);
  const outDir = join(baseDir, 'restored');
  const oldUmask = process.umask(0);
  try {
    const result = await runCli([
      'restore',
      '--shards',
      join(fixture.split.outDir, '*.qcont'),
      '--out',
      outDir,
      '--json',
    ]);

    assert.equal(result.exitCode, 0);
    assert.equal(result.stderrText, '');
    const report = JSON.parse(result.stdoutText);
    assert.equal(report.command, 'restore');
    assert.equal(report.ok, true);
    assert.equal(report.cliSchemaVersion, 1);
    assert.equal(report.dryRun, false);
    assert.equal(report.wouldSucceed, true);
    assert.equal(report.lifecycleBundleVariantAcknowledgementRequired, false);
    assert.equal(report.policyWarningsAcknowledged, false);
    assert.equal(report.archiveId, fixture.split.archiveId);
    assert.equal(report.stateId, fixture.split.stateId);
    assert.equal(report.cohortId, fixture.split.cohortId);
    assert.equal(report.qencOk, true);
    assert.equal(report.qkeyOk, true);
    assert.equal(report.outputs.qencPath, join(outDir, 'recovered.qenc'));
    assert.equal(report.outputs.keyPath, join(outDir, 'recovered.privateKey.qkey'));
    assert.equal(report.outputs.archiveStatePath, join(outDir, 'recovered-archive-state.json'));
    assert.equal(report.outputs.lifecycleBundlePath, join(outDir, 'recovered-lifecycle-bundle.json'));
    assert.equal(report.outputs.plaintextPath, null);

    assert.deepEqual(
      new Uint8Array(await readFile(report.outputs.qencPath)),
      new Uint8Array(await readFile(fixture.qencPath)),
    );
    assert.deepEqual(
      new Uint8Array(await readFile(report.outputs.keyPath)),
      new Uint8Array(await readFile(fixture.keys.privateKeyPath)),
    );
    assert.deepEqual(
      new Uint8Array(await readFile(report.outputs.archiveStatePath)),
      new Uint8Array(await readFile(fixture.split.archiveStateBytesPath)),
    );
    assert.deepEqual(
      new Uint8Array(await readFile(report.outputs.lifecycleBundlePath)),
      new Uint8Array(await readFile(fixture.split.lifecycleBundleBytesPath)),
    );
    assert.equal(modeBits(await stat(report.outputs.qencPath)), 0o600);
    assert.equal(modeBits(await stat(report.outputs.keyPath)), 0o600);
    assert.equal(modeBits(await stat(report.outputs.lifecycleBundlePath)), 0o600);
  } finally {
    process.umask(oldUmask);
  }
});

test('restore --decrypt writes authenticated plaintext from recovered material', async () => {
  const baseDir = await makeTempDir();
  const fixture = await makeSplitFixture(baseDir, { archiveIdByte: 'aa' });
  const outDir = join(baseDir, 'restored-decrypt');
  const plaintextPath = join(baseDir, 'plaintext.out');

  const result = await runCli([
    'restore',
    '--shards',
    join(fixture.split.outDir, '*.qcont'),
    '--out',
    outDir,
    '--decrypt',
    '--out-plaintext',
    plaintextPath,
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.outputs.plaintextPath, plaintextPath);
  assert.equal(report.plaintext.outputPath, plaintextPath);
  assert.equal(report.plaintext.plaintextLength, fixture.plaintext.length);
  assert.deepEqual(new Uint8Array(await readFile(plaintextPath)), fixture.plaintext);
});

test('restore write mode aborts policy-failed archives without writing outputs', async () => {
  const baseDir = await makeTempDir();
  const fixture = await makeSplitFixture(baseDir, {
    authPolicyLevel: '',
    archiveIdByte: 'bb',
  });
  const outDir = join(baseDir, 'policy-failed');

  const result = await runCli([
    'restore',
    '--shards',
    join(fixture.split.outDir, '*.qcont'),
    '--out',
    outDir,
    '--json',
  ]);

  assert.equal(result.exitCode, 1);
  assert.equal(await exists(outDir), false);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.command, 'restore');
  assert.equal(error.ok, false);
  assert.equal(error.qvCode, 'POLICY_NOT_SATISFIED');
});

test('buildRestoreDryRunSummary gates wouldSucceed on mixed lifecycle-bundle variants without acknowledgement', async () => {
  const { buildRestoreDryRunSummary } = await import('../../src/core/cli/commands/restore.js');
  const baseResult = {
    qencOk: true,
    qkeyOk: true,
    authenticity: { status: { policySatisfied: true }, policy: { satisfied: true } },
    lifecycleVerification: { cohorts: { mixedLifecycleBundleVariantsWithinSelectedCohort: true } },
    archiveId: 'x',
    stateId: 'y',
    cohortId: 'z',
    archiveStateDigestHex: '',
    cohortBindingDigestHex: '',
    lifecycleBundleDigestHex: '',
    selectionSource: '',
    lifecycleBundleSource: '',
    embeddedLifecycleBundleDigestsUsed: [],
    privateKeyHashMatchesMetadata: true,
    rejectedShardIndices: [],
  };
  const blocked = buildRestoreDryRunSummary(baseResult, { acceptPolicyWarnings: false });
  assert.equal(blocked.wouldSucceed, false);
  assert.equal(blocked.lifecycleBundleVariantAcknowledgementRequired, true);
  assert.equal(blocked.policyWarningsAcknowledged, false);

  const allowed = buildRestoreDryRunSummary(baseResult, { acceptPolicyWarnings: true });
  assert.equal(allowed.wouldSucceed, true);
  assert.equal(allowed.policyWarningsAcknowledged, true);
});
test('restore --accept-policy-warnings does not override failed authenticity policy', async () => {
  const baseDir = await makeTempDir();
  const fixture = await makeSplitFixture(baseDir, {
    authPolicyLevel: '',
    archiveIdByte: 'cc',
  });
  const outDir = join(baseDir, 'policy-failed-accepted');

  const result = await runCli([
    'restore',
    '--shards',
    join(fixture.split.outDir, '*.qcont'),
    '--out',
    outDir,
    '--accept-policy-warnings',
    '--json',
  ]);

  assert.equal(result.exitCode, 1);
  assert.equal(await exists(outDir), false);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'POLICY_NOT_SATISFIED');
});
