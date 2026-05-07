import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { parseLifecycleShard } from '../../src/core/crypto/qcont/lifecycle-shard.js';
import { parseQencHeader } from '../../src/core/crypto/qenc/format.js';
import { restoreDryRunFromInputs } from '../../src/core/cli/commands/restore-dry-run.js';
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

async function makeTempDir() {
  return mkdtemp(join(tmpdir(), 'qv-cli-split-'));
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

async function makeKeys(baseDir, name = '') {
  const keyDir = join(baseDir, `${name}keys`);
  const args = ['keygen', '--out', keyDir, '--json'];
  if (name) args.splice(3, 0, '--name', `${name}-`);
  const result = await runCli(args);
  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  return {
    publicKeyPath: report.publicKeyPath,
    privateKeyPath: report.privateKeyPath,
  };
}

function digestHex(bytes) {
  return toHex(sha3_512(bytes));
}

function modeBits(stats) {
  return stats.mode & 0o777;
}

async function encryptFixture({ baseDir, keys, plaintext, filename = 'payload.bin' }) {
  const inputPath = join(baseDir, filename);
  const qencPath = join(baseDir, `${filename}.qenc`);
  await writeFile(inputPath, plaintext);
  const result = await runCli([
    'encrypt',
    inputPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    qencPath,
    '--json',
  ]);
  assert.equal(result.exitCode, 0);
  return { inputPath, qencPath, encryptReport: JSON.parse(result.stdoutText) };
}

test('split --json writes QVqcont-7 shards and canonical lifecycle sidecars', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const plaintext = new TextEncoder().encode('split me into successor lifecycle shards');
  const { qencPath, encryptReport } = await encryptFixture({ baseDir, keys, plaintext });
  const outDir = join(baseDir, 'cohort');
  const privateKeyBytes = new Uint8Array(await readFile(keys.privateKeyPath));
  const oldUmask = process.umask(0);
  try {
    const result = await runCli([
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
      '11'.repeat(32),
      '--json',
    ]);

    assert.equal(result.exitCode, 0);
    assert.equal(result.stderrText, '');
    const report = JSON.parse(result.stdoutText);
    assert.equal(report.command, 'split');
    assert.equal(report.ok, true);
    assert.equal(report.cliSchemaVersion, 1);
    assert.equal(report.inputPath, qencPath);
    assert.equal(report.outDir, outDir);
    assert.equal(report.archiveId, '11'.repeat(32));
    assert.equal(report.n, 5);
    assert.equal(report.k, 3);
    assert.equal(report.m, 2);
    assert.equal(report.t, 4);
    assert.deepEqual(report.shamir, { n: 5, t: 4 });
    assert.equal(report.rsCodecId, 'QV-RS-ErasureCodes-v1');
    assert.deepEqual(report.authPolicy, { level: 'integrity-only', minValidSignatures: 1 });
    assert.equal(report.fmt, 'QVqcont-7');
    assert.equal(report.containerHashHex, encryptReport.containerHashHex);
    assert.equal(report.privateKeyHashHex, digestHex(privateKeyBytes));
    assert.equal(report.shards.length, 5);

    const qencBytes = new Uint8Array(await readFile(qencPath));
    assert.equal(report.containerId, digestHex(parseQencHeader(qencBytes).header));

    const archiveStateBytes = new Uint8Array(await readFile(report.archiveStateBytesPath));
    const cohortBindingBytes = new Uint8Array(await readFile(report.cohortBindingBytesPath));
    const lifecycleBundleBytes = new Uint8Array(await readFile(report.lifecycleBundleBytesPath));
    assert.equal(report.archiveStateDigestHex, digestHex(archiveStateBytes));
    assert.equal(report.cohortBindingDigestHex, digestHex(cohortBindingBytes));
    assert.equal(report.lifecycleBundleDigestHex, digestHex(lifecycleBundleBytes));

    const parsedShards = [];
    for (let index = 0; index < report.shards.length; index += 1) {
      const shard = report.shards[index];
      assert.equal(shard.index, index);
      assert.equal(shard.path, join(outDir, `payload.bin.part${index + 1}-of-5.qcont`));
      const shardBytes = new Uint8Array(await readFile(shard.path));
      assert.equal(shard.shardDigestHex, digestHex(shardBytes));
      assert.equal(shard.shardSize, shardBytes.length);
      assert.equal(modeBits(await stat(shard.path)), 0o600);
      const parsed = await parseLifecycleShard(shardBytes, { strict: true });
      assert.equal(parsed.archiveState.archiveId, report.archiveId);
      assert.equal(parsed.stateId, report.stateId);
      assert.equal(parsed.cohortId, report.cohortId);
      assert.equal(parsed.shardIndex, index);
      assert.equal(parsed.archiveStateDigestHex, report.archiveStateDigestHex);
      assert.equal(parsed.cohortBindingDigestHex, report.cohortBindingDigestHex);
      assert.equal(parsed.lifecycleBundleDigestHex, report.lifecycleBundleDigestHex);
      parsedShards.push(parsed);
    }

    const restoreSummary = await restoreDryRunFromInputs({ parsedShards });
    assert.equal(restoreSummary.wouldSucceed, true);
    assert.equal(restoreSummary.qencOk, true);
    assert.equal(restoreSummary.qkeyOk, true);
    assert.equal(restoreSummary.archiveId, report.archiveId);
    assert.equal(restoreSummary.stateId, report.stateId);
    assert.equal(restoreSummary.cohortId, report.cohortId);
  } finally {
    process.umask(oldUmask);
  }
});

test('split supports private key bytes from stdin', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const { qencPath } = await encryptFixture({
    baseDir,
    keys,
    plaintext: new Uint8Array([1, 2, 3, 4]),
    filename: 'stdin.bin',
  });
  const privateKeyBytes = new Uint8Array(await readFile(keys.privateKeyPath));
  const result = await runCli([
    'split',
    qencPath,
    '--private-key-stdin',
    '--n',
    '5',
    '--k',
    '3',
    '--out',
    join(baseDir, 'stdin-cohort'),
    '--auth-policy-level',
    'integrity-only',
    '--json',
  ], { stdin: privateKeyBytes });

  assert.equal(result.exitCode, 0);
  assert.equal(JSON.parse(result.stdoutText).shards.length, 5);
});

test('split supports private key path via --private-key-env', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const { qencPath } = await encryptFixture({
    baseDir,
    keys,
    plaintext: new Uint8Array([9, 8, 7]),
    filename: 'envsplit.bin',
  });
  const outDir = join(baseDir, 'env-cohort');
  const result = await runCli([
    'split',
    qencPath,
    '--private-key-env',
    'QV_TEST_SPLIT_PRIVKEY',
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
  ], { env: { QV_TEST_SPLIT_PRIVKEY: keys.privateKeyPath } });

  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.shards.length, 5);
  assert.equal(report.archiveId, '22'.repeat(32));
});

test('split --help-internal prints deterministic fixture flags', async () => {
  const result = await runCli(['split', '--help-internal']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.match(result.stdoutText, /--archive-id/);
});

test('split deterministic fixture flags require explicit environment opt-in', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const { qencPath } = await encryptFixture({
    baseDir,
    keys,
    plaintext: new Uint8Array([4, 5, 6]),
    filename: 'deterministic-gate.bin',
  });
  const result = await runCli([
    'split',
    qencPath,
    '--private-key',
    keys.privateKeyPath,
    '--n',
    '5',
    '--k',
    '3',
    '--out',
    join(baseDir, 'blocked-cohort'),
    '--archive-id-random',
    '33'.repeat(32),
    '--json',
  ], { env: { QV_ALLOW_DETERMINISTIC: '' } });

  assert.equal(result.exitCode, 2);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'USAGE');
  assert.match(error.error, /QV_ALLOW_DETERMINISTIC=1/);
});

test('split maps unsupported RS/Shamir geometry to QUORUM_UNREACHABLE', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const { qencPath } = await encryptFixture({
    baseDir,
    keys,
    plaintext: new Uint8Array([5, 6, 7]),
    filename: 'bad-geometry.bin',
  });

  const result = await runCli([
    'split',
    qencPath,
    '--private-key',
    keys.privateKeyPath,
    '--n',
    '5',
    '--k',
    '4',
    '--out',
    join(baseDir, 'bad-geometry'),
    '--json',
  ]);

  assert.equal(result.exitCode, 7);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.command, 'split');
  assert.equal(error.ok, false);
  assert.equal(error.qvCode, 'QUORUM_UNREACHABLE');
});

test('split maps private key/container mismatch to KEY_REJECTED', async () => {
  const baseDir = await makeTempDir();
  const keysA = await makeKeys(baseDir, 'a');
  const keysB = await makeKeys(baseDir, 'b');
  const { qencPath } = await encryptFixture({
    baseDir,
    keys: keysA,
    plaintext: new TextEncoder().encode('wrong key'),
    filename: 'wrong-key.bin',
  });

  const result = await runCli([
    'split',
    qencPath,
    '--private-key',
    keysB.privateKeyPath,
    '--n',
    '5',
    '--k',
    '3',
    '--out',
    join(baseDir, 'wrong-key-cohort'),
    '--json',
  ]);

  assert.equal(result.exitCode, 5);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'KEY_REJECTED');
  assert.equal(error.error, 'Private key does not match this .qenc container');
});
