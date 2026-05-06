import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { encryptFile } from '../../src/core/crypto/index.js';
import { parseQencHeader } from '../../src/core/crypto/qenc/format.js';
import { parseQvpackPayload } from '../../src/core/crypto/qvpack.js';
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
  return mkdtemp(join(tmpdir(), 'qv-cli-decrypt-'));
}

async function runCli(args, options = {}) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, {
    stdout,
    stderr,
    stdin: options.stdin,
    env: options.env,
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

function digestHex(bytes) {
  return toHex(sha3_512(bytes));
}

function modeBits(stats) {
  return stats.mode & 0o777;
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

async function encryptFixture({ baseDir, keys, plaintext, filename = 'plain.txt' }) {
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

test('decrypt --json writes plaintext with stable report fields and stdin private key source', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const plaintext = new TextEncoder().encode('Quantum Vault CLI decrypt\n');
  const { qencPath, encryptReport } = await encryptFixture({
    baseDir,
    keys,
    plaintext,
  });
  const outputPath = join(baseDir, 'restored.txt');
  const privateKeyBytes = new Uint8Array(await readFile(keys.privateKeyPath));
  const oldUmask = process.umask(0);
  try {
    const result = await runCli([
      'decrypt',
      qencPath,
      '--private-key-stdin',
      '--out',
      outputPath,
      '--json',
    ], { stdin: privateKeyBytes });

    assert.equal(result.exitCode, 0);
    assert.equal(result.stderrText, '');
    const report = JSON.parse(result.stdoutText);
    assert.equal(report.command, 'decrypt');
    assert.equal(report.ok, true);
    assert.equal(report.cliSchemaVersion, 1);
    assert.equal(report.inputPath, qencPath);
    assert.equal(report.outputPath, outputPath);
    assert.deepEqual(report.outputPaths, [outputPath]);
    assert.deepEqual(report.alg, {
      KEM: 'ML-KEM-1024',
      KDF: 'KMAC256',
      AEAD: 'AES-256-GCM',
    });
    assert.equal(report.originalFilename, 'plain.txt');
    assert.equal(report.payloadKind, 'file');
    assert.equal(report.fileCount, 1);
    assert.equal(report.qvpackExtracted, false);
    assert.deepEqual(report.qvpackEntries, []);
    assert.equal(report.plaintextLength, plaintext.length);
    assert.equal(report.fileHashHex, digestHex(plaintext));
    assert.equal(report.containerHashHex, encryptReport.containerHashHex);
    assert.equal(report.containerHashAlg, 'SHA3-512');

    const qencBytes = new Uint8Array(await readFile(qencPath));
    const parsed = parseQencHeader(qencBytes);
    assert.equal(report.containerId, digestHex(parsed.header));
    assert.equal(report.fmt, parsed.metadata.fmt);
    assert.equal(report.aeadMode, parsed.metadata.aead_mode);
    assert.equal(report.chunkSize, parsed.metadata.chunkSize);
    assert.equal(report.chunkCount, parsed.metadata.chunkCount);
    assert.equal(report.payloadLength, parsed.metadata.payloadLength);

    assert.deepEqual(new Uint8Array(await readFile(outputPath)), plaintext);
    assert.equal(modeBits(await stat(outputPath)), 0o600);
    assert.equal(privateKeyBytes.every((value) => value === 0), false);
  } finally {
    process.umask(oldUmask);
  }
});

test('decrypt supports private-key-env as a file path source', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const plaintext = new Uint8Array([7, 8, 9]);
  const { qencPath } = await encryptFixture({
    baseDir,
    keys,
    plaintext,
    filename: 'env.bin',
  });
  const outputPath = join(baseDir, 'env-restored.bin');

  const result = await runCli([
    'decrypt',
    qencPath,
    '--private-key-env',
    'QV_TEST_PRIVKEY',
    '--out',
    outputPath,
    '--json',
  ], { env: { QV_TEST_PRIVKEY: keys.privateKeyPath } });

  assert.equal(result.exitCode, 0);
  assert.deepEqual(new Uint8Array(await readFile(outputPath)), plaintext);
});

test('decrypt rejects invalid private key length with KEY_REJECTED', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const { qencPath } = await encryptFixture({
    baseDir,
    keys,
    plaintext: new Uint8Array([1]),
    filename: 'badkey.bin',
  });
  const badKeyPath = join(baseDir, 'bad-private.qkey');
  await writeFile(badKeyPath, new Uint8Array([1, 2, 3]));

  const result = await runCli([
    'decrypt',
    qencPath,
    '--private-key',
    badKeyPath,
    '--out',
    join(baseDir, 'badkey.out'),
    '--json',
  ]);

  assert.equal(result.exitCode, 5);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.command, 'decrypt');
  assert.equal(error.ok, false);
  assert.equal(error.qvCode, 'KEY_REJECTED');
});

test('decrypt maps authentication failure to AEAD_FAILED without writing output', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const { qencPath } = await encryptFixture({
    baseDir,
    keys,
    plaintext: new TextEncoder().encode('tamper target'),
    filename: 'tamper.bin',
  });
  const tamperedPath = join(baseDir, 'tampered.qenc');
  const tampered = new Uint8Array(await readFile(qencPath));
  tampered[tampered.length - 1] ^= 0x01;
  await writeFile(tamperedPath, tampered);
  const outputPath = join(baseDir, 'tampered.out');

  const result = await runCli([
    'decrypt',
    tamperedPath,
    '--private-key',
    keys.privateKeyPath,
    '--out',
    outputPath,
    '--json',
  ]);

  assert.equal(result.exitCode, 6);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'AEAD_FAILED');
  assert.equal(error.error, 'Decrypt authentication failed: invalid private key or tampered container');
  await assert.rejects(() => stat(outputPath), /ENOENT/);
});

test('decrypt refuses unsafe recovered original filenames for derived output paths', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const publicKey = new Uint8Array(await readFile(keys.publicKeyPath));
  const plaintext = new TextEncoder().encode('unsafe name');
  const encrypted = await encryptFile(plaintext, publicKey, '../evil.txt');
  const qencBytes = await blobToBytes(encrypted);
  const qencPath = join(baseDir, 'unsafe.qenc');
  const outDir = join(baseDir, 'out');
  await writeFile(qencPath, qencBytes);
  await mkdir(outDir);

  const result = await runCli([
    'decrypt',
    qencPath,
    '--private-key',
    keys.privateKeyPath,
    '--out-dir',
    outDir,
    '--json',
  ]);

  assert.equal(result.exitCode, 2);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'USAGE');
  assert.match(error.error, /unsafe characters|not safe/);
});

test('decrypt handles authenticated .qvpack payloads and explicit extraction', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const fileA = join(baseDir, 'a.txt');
  const fileB = join(baseDir, 'b.bin');
  const qencPath = join(baseDir, 'bundle.qenc');
  const packOutPath = join(baseDir, 'bundle.qvpack');
  const extractDir = join(baseDir, 'extract');
  const aBytes = new TextEncoder().encode('alpha');
  const bBytes = new Uint8Array([0, 1, 2, 3, 4]);
  await writeFile(fileA, aBytes);
  await writeFile(fileB, bBytes);
  await mkdir(extractDir);

  const encrypted = await runCli([
    'encrypt',
    '--pack',
    fileA,
    fileB,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    qencPath,
    '--filename',
    'bundle.qvpack',
    '--json',
  ]);
  assert.equal(encrypted.exitCode, 0);

  const bundleResult = await runCli([
    'decrypt',
    qencPath,
    '--private-key',
    keys.privateKeyPath,
    '--out',
    packOutPath,
    '--json',
  ]);
  assert.equal(bundleResult.exitCode, 0);
  const bundleReport = JSON.parse(bundleResult.stdoutText);
  assert.equal(bundleReport.payloadKind, 'qvpack');
  assert.equal(bundleReport.fileCount, 2);
  assert.equal(bundleReport.qvpackExtracted, false);
  const qvpackBytes = new Uint8Array(await readFile(packOutPath));
  assert.equal(bundleReport.fileHashHex, digestHex(qvpackBytes));
  assert.equal(parseQvpackPayload(qvpackBytes).length, 2);

  const extractResult = await runCli([
    'decrypt',
    qencPath,
    '--private-key',
    keys.privateKeyPath,
    '--out-dir',
    extractDir,
    '--extract-qvpack',
    '--json',
  ]);
  assert.equal(extractResult.exitCode, 0);
  const extractReport = JSON.parse(extractResult.stdoutText);
  assert.equal(extractReport.outputPath, null);
  assert.equal(extractReport.payloadKind, 'qvpack');
  assert.equal(extractReport.qvpackExtracted, true);
  assert.equal(extractReport.fileCount, 2);
  assert.deepEqual(new Uint8Array(await readFile(join(extractDir, 'a.txt'))), aBytes);
  assert.deepEqual(new Uint8Array(await readFile(join(extractDir, 'b.bin'))), bBytes);
  assert.equal(extractReport.qvpackEntries[0].name, 'a.txt');
  assert.equal(extractReport.qvpackEntries[0].outputPath, join(extractDir, 'a.txt'));
});
