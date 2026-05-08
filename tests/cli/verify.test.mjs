import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { buildQsigFixture } from '../../src/core/crypto/selftest.js';
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
    env: { ...process.env, QV_ALLOW_DETERMINISTIC: '1', ...(options.env || {}) },
  });
  const stdoutText = stdout.text();
  return {
    exitCode,
    stdoutText,
    stderrText: stderr.text(),
    json: stdoutText ? JSON.parse(stdoutText) : null,
  };
}

async function makeTempDir() {
  return mkdtemp(join(tmpdir(), 'qv-cli-verify-'));
}

async function makeSplitFixture(baseDir, {
  authPolicyLevel = 'integrity-only',
  archiveIdByte = 'dd',
} = {}) {
  const keyDir = join(baseDir, `keys-${archiveIdByte}`);
  const keygen = await runCli(['keygen', '--out', keyDir, '--json']);
  assert.equal(keygen.exitCode, 0);
  const keys = keygen.json;

  const plaintextPath = join(baseDir, `payload-${archiveIdByte}.bin`);
  const qencPath = join(baseDir, `payload-${archiveIdByte}.bin.qenc`);
  await writeFile(plaintextPath, new TextEncoder().encode(`verify payload ${archiveIdByte}`));
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
    authPolicyLevel,
    '--archive-id-random',
    archiveIdByte.repeat(32),
    '--json',
  ]);
  assert.equal(split.exitCode, 0);
  return split.json;
}

async function attachArchiveApproval(baseDir, split) {
  const archiveStateBytes = new Uint8Array(await readFile(split.archiveStateBytesPath));
  const qsig = buildQsigFixture(archiveStateBytes);
  const qsigPath = join(baseDir, 'archive.qsig');
  const pqpkPath = join(baseDir, 'archive.pqpk');
  const bundlePath = join(baseDir, 'attached.lifecycle-bundle.json');
  await writeFile(qsigPath, qsig.qsigBytes);
  await writeFile(pqpkPath, qsig.pqpkBytes);
  const attached = await runCli([
    'attach',
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--sig',
    qsigPath,
    '--pqpk',
    pqpkPath,
    '--out-bundle',
    bundlePath,
    '--json',
  ]);
  assert.equal(attached.exitCode, 0);
  return { bundlePath, qsigPath, pqpkPath };
}

test('verify default JSON remains unextended when new flags are absent', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir, {
    authPolicyLevel: 'integrity-only',
    archiveIdByte: 'de',
  });

  const result = await runCli([
    'verify',
    split.archiveStateBytesPath,
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  assert.equal(result.json.command, 'verify');
  assert.equal(result.json.ok, true);
  assert.equal(result.json.policy.satisfied, true);
  assert.equal(Object.hasOwn(result.json, 'requiredPolicy'), false);
  assert.equal(Object.hasOwn(result.json, 'detachedSummary'), false);
});

test('verify --required-policy-level fails closed when requested level is stricter', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir, {
    authPolicyLevel: 'integrity-only',
    archiveIdByte: 'df',
  });

  const result = await runCli([
    'verify',
    split.archiveStateBytesPath,
    '--bundle',
    split.lifecycleBundleBytesPath,
    '--required-policy-level',
    'strong-pq-signature',
    '--json',
  ]);

  assert.equal(result.exitCode, 1);
  assert.equal(result.json.command, 'verify');
  assert.equal(result.json.ok, false);
  assert.equal(result.json.policy.satisfied, true);
  assert.equal(result.json.requiredPolicy.level, 'strong-pq-signature');
  assert.equal(result.json.requiredPolicy.declaredPolicyLevel, 'integrity-only');
  assert.equal(result.json.requiredPolicy.declaredPolicySatisfiesRequired, false);
  assert.equal(result.json.requiredPolicy.satisfied, false);
});

test('verify --required-policy-level passes when archive policy satisfies the requested level', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir, {
    authPolicyLevel: 'strong-pq-signature',
    archiveIdByte: 'e1',
  });
  const { bundlePath } = await attachArchiveApproval(baseDir, split);

  const result = await runCli([
    'verify',
    split.archiveStateBytesPath,
    '--bundle',
    bundlePath,
    '--required-policy-level',
    'strong-pq-signature',
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  assert.equal(result.json.ok, true);
  assert.equal(result.json.policy.level, 'strong-pq-signature');
  assert.equal(result.json.policy.satisfied, true);
  assert.equal(result.json.requiredPolicy.satisfied, true);
});

test('verify --include-detached-summary emits byte-free detached signature metadata', async () => {
  const baseDir = await makeTempDir();
  const split = await makeSplitFixture(baseDir, {
    authPolicyLevel: 'strong-pq-signature',
    archiveIdByte: 'e2',
  });
  const { bundlePath } = await attachArchiveApproval(baseDir, split);

  const result = await runCli([
    'verify',
    split.archiveStateBytesPath,
    '--bundle',
    bundlePath,
    '--include-detached-summary',
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  assert.equal(Array.isArray(result.json.detachedSummary), true);
  assert.equal(result.json.detachedSummary.length, 1);
  const [entry] = result.json.detachedSummary;
  assert.equal(entry.family, 'archive-approval');
  assert.equal(entry.format, 'qsig');
  assert.equal(entry.ok, true);
  assert.equal(entry.targetType, 'archive-state');
  assert.equal(entry.targetRef, `state:${split.stateId}`);
  assert.equal(typeof entry.signatureContentDigestHex, 'string');
  assert.equal(Object.hasOwn(entry, 'signatureBytes'), false);
});
