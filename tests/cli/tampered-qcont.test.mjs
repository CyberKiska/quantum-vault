import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  LIFECYCLE_QCONT_MIN_HEADER_BYTES,
  parseLifecycleShard,
} from '../../src/core/crypto/qcont/lifecycle-shard.js';
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
  return mkdtemp(join(tmpdir(), 'qv-cli-qcont-tamper-'));
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

async function makeKeys(baseDir) {
  const keyDir = join(baseDir, 'keys');
  const result = await runCli(['keygen', '--out', keyDir, '--json']);
  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  return {
    publicKeyPath: report.publicKeyPath,
    privateKeyPath: report.privateKeyPath,
  };
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
  return { qencPath };
}

async function pathExists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

test('single-byte flips in fixed header region fail strict successor shard parse', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const plaintext = new TextEncoder().encode('tamper probe');
  const { qencPath } = await encryptFixture({ baseDir, keys, plaintext });
  const outDir = join(baseDir, 'cohort');
  const splitResult = await runCli([
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
    '44'.repeat(32),
    '--json',
  ]);
  assert.equal(splitResult.exitCode, 0);
  const report = JSON.parse(splitResult.stdoutText);
  const shardPath = report.shards[0].path;
  const good = new Uint8Array(await readFile(shardPath));

  for (let offset = 0; offset < LIFECYCLE_QCONT_MIN_HEADER_BYTES; offset += 1) {
    const tampered = new Uint8Array(good);
    tampered[offset] ^= 0x01;
    await assert.rejects(
      () => parseLifecycleShard(tampered, { strict: true }),
      undefined,
      `expected reject at header offset ${offset}`,
    );
  }
});

test('restore rejects tampered successor shard input before writing recovered artifacts', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const plaintext = new TextEncoder().encode('tamper restore probe');
  const { qencPath } = await encryptFixture({ baseDir, keys, plaintext, filename: 'restore-payload.bin' });
  const outDir = join(baseDir, 'cohort');
  const splitResult = await runCli([
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
    '55'.repeat(32),
    '--json',
  ]);
  assert.equal(splitResult.exitCode, 0);
  const report = JSON.parse(splitResult.stdoutText);
  const good = new Uint8Array(await readFile(report.shards[0].path));
  const tampered = new Uint8Array(good);
  tampered[0] ^= 0x01;

  const tamperedPath = join(baseDir, 'tampered.qcont');
  const restoreOutDir = join(baseDir, 'restore-out');
  await writeFile(tamperedPath, tampered);

  const restore = await runCli([
    'restore',
    '--shards',
    tamperedPath,
    '--out',
    restoreOutDir,
    '--json',
  ]);
  assert.equal(restore.exitCode, 2);
  const error = JSON.parse(restore.stdoutText);
  assert.equal(error.qvCode, 'USAGE');
  assert.match(error.error, /not a supported successor shard/);
  assert.equal(await pathExists(restoreOutDir), false);
});
