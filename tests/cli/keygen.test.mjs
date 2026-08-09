import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import {
  ML_KEM_1024_PRIVATE_KEY_SIZE,
  ML_KEM_1024_PUBLIC_KEY_SIZE,
} from '../../src/core/crypto/mlkem.js';
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
  return mkdtemp(join(tmpdir(), 'qv-cli-keygen-'));
}

async function runCli(args) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, { stdout, stderr });
  return {
    exitCode,
    stdoutText: stdout.text(),
    stderrText: stderr.text(),
  };
}

function digestHex(bytes) {
  return toHex(sha3_512(bytes));
}

function modeBits(stats) {
  return stats.mode & 0o777;
}

test('keygen --json writes ML-KEM-1024 key files with stable report fields', async () => {
  const baseDir = await makeTempDir();
  const outDir = join(baseDir, 'keys');
  const oldUmask = process.umask(0);
  try {
    const result = await runCli(['keygen', '--out', outDir, '--json']);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stderrText, '');
    const report = JSON.parse(result.stdoutText);
    assert.equal(report.command, 'keygen');
    assert.equal(report.ok, true);
    assert.equal(report.cliSchemaVersion, 1);
    assert.deepEqual(report.alg, { KEM: 'ML-KEM-1024' });
    assert.equal(report.publicKeyPath, join(outDir, 'publicKey.qkey'));
    assert.equal(report.privateKeyPath, join(outDir, 'privateKey.qkey'));
    assert.equal(report.publicKeyLength, ML_KEM_1024_PUBLIC_KEY_SIZE);
    assert.equal(report.privateKeyLength, ML_KEM_1024_PRIVATE_KEY_SIZE);
    assert.deepEqual(report.seed, { source: 'secure-random' });
    assert.equal(Object.hasOwn(report, 'publicKeyBase64'), false);

    const publicKeyBytes = new Uint8Array(await readFile(report.publicKeyPath));
    const privateKeyBytes = new Uint8Array(await readFile(report.privateKeyPath));
    assert.equal(publicKeyBytes.length, ML_KEM_1024_PUBLIC_KEY_SIZE);
    assert.equal(privateKeyBytes.length, ML_KEM_1024_PRIVATE_KEY_SIZE);
    assert.equal(report.publicKeyDigestHex, digestHex(publicKeyBytes));
    assert.equal(report.privateKeyDigestHex, digestHex(privateKeyBytes));
    assert.equal(modeBits(await stat(report.publicKeyPath)), 0o644);
    assert.equal(modeBits(await stat(report.privateKeyPath)), 0o600);
  } finally {
    process.umask(oldUmask);
  }
});

test('keygen creates only the requested missing --out directory', async () => {
  const baseDir = await makeTempDir();
  const outDir = join(baseDir, 'requested-keys');
  const result = await runCli(['keygen', '--out', outDir, '--json']);
  assert.equal(result.exitCode, 0);
  const stats = await stat(outDir);
  assert.equal(stats.isDirectory(), true);
  await stat(join(outDir, 'publicKey.qkey'));
  await stat(join(outDir, 'privateKey.qkey'));
});

test('keygen refuses overwrite without --force and allows it with --force', async () => {
  const baseDir = await makeTempDir();
  const outDir = join(baseDir, 'keys');
  const first = await runCli(['keygen', '--out', outDir, '--json']);
  assert.equal(first.exitCode, 0);

  const refused = await runCli(['keygen', '--out', outDir, '--json']);
  assert.equal(refused.exitCode, 2);
  const refusedJson = JSON.parse(refused.stdoutText);
  assert.equal(refusedJson.command, 'keygen');
  assert.equal(refusedJson.ok, false);
  assert.equal(refusedJson.qvCode, 'USAGE');
  assert.match(refusedJson.error, /Refusing to overwrite existing file/);

  const forced = await runCli(['keygen', '--out', outDir, '--force', '--json']);
  assert.equal(forced.exitCode, 0);
});

test('keygen supports --name prefix and public-key-only stdout export', async () => {
  const baseDir = await makeTempDir();
  const outDir = join(baseDir, 'keys');
  const result = await runCli(['keygen', '--out', outDir, '--name', 'archive-', '--print-public']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  await stat(join(outDir, 'archive-publicKey.qkey'));
  await stat(join(outDir, 'archive-privateKey.qkey'));
  const lines = result.stdoutText.trim().split('\n');
  const publicKeyBase64 = lines.at(-1);
  assert.equal(Buffer.from(publicKeyBase64, 'base64').length, ML_KEM_1024_PUBLIC_KEY_SIZE);
  assert.equal(result.stdoutText.includes('privateKey.qkey'), true);
  assert.equal(result.stdoutText.includes(publicKeyBase64), true);
});

test('keygen --json --print-public keeps stdout a single JSON document', async () => {
  const baseDir = await makeTempDir();
  const outDir = join(baseDir, 'keys');
  const result = await runCli(['keygen', '--out', outDir, '--print-public', '--json']);
  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(Buffer.from(report.publicKeyBase64, 'base64').length, ML_KEM_1024_PUBLIC_KEY_SIZE);
});

test('keygen usage errors return qvCode USAGE', async () => {
  const result = await runCli(['keygen', '--json']);
  assert.equal(result.exitCode, 2);
  assert.deepEqual(JSON.parse(result.stdoutText), {
    command: 'keygen',
    ok: false,
    cliSchemaVersion: 1,
    error: 'keygen requires --out <dir>',
    qvCode: 'USAGE',
  });
});

test('keygen missing option values return the usage exit code', async () => {
  const result = await runCli(['keygen', '--out']);
  assert.equal(result.exitCode, 2);
  assert.match(result.stderrText, /--out requires a value/);
});

test('keygen refuses missing --out parent and path-like --name', async () => {
  const baseDir = await makeTempDir();
  const missingParent = join(baseDir, 'missing', 'keys');
  const missingParentResult = await runCli(['keygen', '--out', missingParent, '--json']);
  assert.equal(missingParentResult.exitCode, 2);
  assert.match(JSON.parse(missingParentResult.stdoutText).error, /--out parent directory does not exist/);

  const badNameResult = await runCli(['keygen', '--out', baseDir, '--name', '../bad-', '--json']);
  assert.equal(badNameResult.exitCode, 2);
  assert.match(JSON.parse(badNameResult.stdoutText).error, /--name must be a filename prefix/);
});
