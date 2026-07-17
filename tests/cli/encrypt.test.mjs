import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import {
  decryptFile,
  MAX_QENC_PRIVATE_METADATA_BYTES,
} from '../../src/core/crypto/index.js';
import { parseQencHeader } from '../../src/core/crypto/qenc/format.js';
import { buildQvpackPayloadBytes, parseQvpackPayload } from '../../src/core/crypto/qvpack.js';
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
  return mkdtemp(join(tmpdir(), 'qv-cli-encrypt-'));
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

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

test('encrypt --json writes a .qenc container that decrypts through core', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const inputPath = join(baseDir, 'plain.txt');
  const outputPath = join(baseDir, 'plain.txt.qenc');
  const plaintext = new TextEncoder().encode('Quantum Vault CLI encrypt\n');
  await writeFile(inputPath, plaintext);

  const result = await runCli([
    'encrypt',
    inputPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    outputPath,
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.command, 'encrypt');
  assert.equal(report.ok, true);
  assert.equal(report.cliSchemaVersion, 1);
  assert.deepEqual(report.alg, {
    KEM: 'ML-KEM-1024',
    KDF: 'KMAC256',
    AEAD: 'AES-256-GCM',
  });
  assert.equal(report.inputPath, inputPath);
  assert.deepEqual(report.inputPaths, [inputPath]);
  assert.equal(report.outputPath, outputPath);
  assert.equal(report.publicKeyPath, keys.publicKeyPath);
  assert.equal(report.originalFilename, 'plain.txt');
  assert.equal(report.payloadKind, 'file');
  assert.equal(report.fileCount, 1);
  assert.equal(report.plaintextLength, plaintext.length);
  assert.equal(report.inputLength, plaintext.length);
  assert.equal(report.fileHashHex, digestHex(plaintext));
  assert.equal(report.containerHashAlg, 'SHA3-512');

  const qencBytes = new Uint8Array(await readFile(outputPath));
  assert.equal(report.containerHashHex, digestHex(qencBytes));
  assert.equal(report.containerId, digestHex(parseQencHeader(qencBytes).header));

  const parsed = parseQencHeader(qencBytes);
  assert.equal(report.fmt, parsed.metadata.fmt);
  assert.equal(report.aeadMode, parsed.metadata.aead_mode);
  assert.equal(report.chunkSize, parsed.metadata.chunkSize);
  assert.equal(report.chunkCount, parsed.metadata.chunkCount);
  assert.equal(report.payloadLength, parsed.metadata.payloadLength);

  const privateKey = new Uint8Array(await readFile(keys.privateKeyPath));
  const decrypted = await decryptFile(qencBytes, privateKey);
  const decryptedBytes = await blobToBytes(decrypted.decryptedBlob);
  assert.deepEqual(decryptedBytes, plaintext);
  assert.equal(decrypted.metadata.originalFilename, 'plain.txt');
  assert.equal(decrypted.metadata.fileHash, report.fileHashHex);
});

test('encrypt supports private metadata filename override', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const inputPath = join(baseDir, 'source.bin');
  const outputPath = join(baseDir, 'source.qenc');
  await writeFile(inputPath, new Uint8Array([1, 2, 3, 4]));

  const result = await runCli([
    'encrypt',
    inputPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    outputPath,
    '--filename',
    'safe-name.bin',
    '--json',
  ]);
  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.originalFilename, 'safe-name.bin');

  const rejected = await runCli([
    'encrypt',
    inputPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    join(baseDir, 'bad.qenc'),
    '--filename',
    '../leak.bin',
    '--json',
  ]);
  assert.equal(rejected.exitCode, 2);
  assert.equal(JSON.parse(rejected.stdoutText).qvCode, 'USAGE');
});

test('encrypt rejects oversized private metadata filenames without reflecting them', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const inputPath = join(baseDir, 'source.bin');
  const outputPath = join(baseDir, 'source.qenc');
  const sensitivePrefix = 'DO_NOT_LEAK_OVERSIZED_FILENAME';
  await writeFile(inputPath, new Uint8Array([1, 2, 3, 4]));

  const result = await runCli([
    'encrypt',
    inputPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    outputPath,
    '--filename',
    `${sensitivePrefix}${'x'.repeat(MAX_QENC_PRIVATE_METADATA_BYTES)}`,
    '--json',
  ]);

  assert.equal(result.exitCode, 4);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.qvCode, 'FORMAT_POLICY_REJECT');
  assert.match(error.error, /private metadata byte limit/);
  assert.equal(error.error.includes(sensitivePrefix), false);
  await assert.rejects(() => stat(outputPath), /ENOENT/);
});

test('encrypt rejects invalid public key length with KEY_REJECTED', async () => {
  const baseDir = await makeTempDir();
  const inputPath = join(baseDir, 'plain.bin');
  const publicKeyPath = join(baseDir, 'bad-public.qkey');
  const outputPath = join(baseDir, 'out.qenc');
  await writeFile(inputPath, new Uint8Array([9]));
  await writeFile(publicKeyPath, new Uint8Array([1, 2, 3]));

  const result = await runCli([
    'encrypt',
    inputPath,
    '--public-key',
    publicKeyPath,
    '--out',
    outputPath,
    '--json',
  ]);

  assert.equal(result.exitCode, 5);
  const error = JSON.parse(result.stdoutText);
  assert.equal(error.command, 'encrypt');
  assert.equal(error.ok, false);
  assert.equal(error.qvCode, 'KEY_REJECTED');
});

test('encrypt refuses overwrite unless --force is supplied', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const inputPath = join(baseDir, 'plain.bin');
  const outputPath = join(baseDir, 'out.qenc');
  await writeFile(inputPath, new Uint8Array([1, 2, 3]));

  const first = await runCli(['encrypt', inputPath, '--public-key', keys.publicKeyPath, '--out', outputPath, '--json']);
  assert.equal(first.exitCode, 0);

  const refused = await runCli(['encrypt', inputPath, '--public-key', keys.publicKeyPath, '--out', outputPath, '--json']);
  assert.equal(refused.exitCode, 2);
  assert.equal(JSON.parse(refused.stdoutText).qvCode, 'USAGE');

  const forced = await runCli(['encrypt', inputPath, '--public-key', keys.publicKeyPath, '--out', outputPath, '--force', '--json']);
  assert.equal(forced.exitCode, 0);
  const stats = await stat(outputPath);
  assert.equal(stats.isFile(), true);
});

test('encrypt --pack creates a .qvpack payload before .qenc encryption', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const fileA = join(baseDir, 'a.txt');
  const fileB = join(baseDir, 'b.bin');
  const outputPath = join(baseDir, 'bundle.qenc');
  const aBytes = new TextEncoder().encode('alpha');
  const bBytes = new Uint8Array([0, 1, 2, 3, 4, 5]);
  await writeFile(fileA, aBytes);
  await writeFile(fileB, bBytes);

  const result = await runCli([
    'encrypt',
    '--pack',
    fileA,
    fileB,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    outputPath,
    '--filename',
    'bundle-test.qvpack',
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.payloadKind, 'qvpack');
  assert.equal(report.fileCount, 2);
  assert.equal(report.inputPath, null);
  assert.deepEqual(report.inputPaths, [fileA, fileB]);
  assert.equal(report.originalFilename, 'bundle-test.qvpack');
  assert.equal(report.inputLength, aBytes.length + bBytes.length);
  assert.equal(Array.isArray(report.warnings), true);

  const privateKey = new Uint8Array(await readFile(keys.privateKeyPath));
  const qencBytes = new Uint8Array(await readFile(outputPath));
  const decrypted = await decryptFile(qencBytes, privateKey);
  const qvpackBytes = await blobToBytes(decrypted.decryptedBlob);
  assert.equal(report.fileHashHex, digestHex(qvpackBytes));
  assert.equal(decrypted.metadata.originalFilename, 'bundle-test.qvpack');

  const entries = parseQvpackPayload(qvpackBytes);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].name, 'a.txt');
  assert.deepEqual(entries[0].bytes, aBytes);
  assert.equal(entries[1].name, 'b.bin');
  assert.deepEqual(entries[1].bytes, bBytes);
});

test('encrypt recognizes an existing .qvpack payload by magic', async () => {
  const baseDir = await makeTempDir();
  const keys = await makeKeys(baseDir);
  const packPath = join(baseDir, 'existing.qvpack');
  const outputPath = join(baseDir, 'existing.qvpack.qenc');
  const qvpackBytes = buildQvpackPayloadBytes([
    { name: 'inside.txt', bytes: new TextEncoder().encode('inside') },
  ]);
  await writeFile(packPath, qvpackBytes);

  const result = await runCli([
    'encrypt',
    packPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    outputPath,
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdoutText);
  assert.equal(report.payloadKind, 'qvpack');
  assert.equal(report.fileCount, 1);
  assert.equal(report.originalFilename, 'existing.qvpack');
  assert.equal(report.fileHashHex, digestHex(qvpackBytes));
});
