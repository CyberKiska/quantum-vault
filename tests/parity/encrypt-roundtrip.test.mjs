import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runQvCli } from '../../src/core/cli/qv.js';
import { ensureErasureRuntime, ensureRuntimeCrypto } from '../../src/core/cli/lib/runtime.js';
import { decryptFile, encryptFile, generateKeyPair } from '../../src/core/crypto/index.js';
import { buildLifecycleQcontShards, parseLifecycleShard } from '../../src/core/crypto/qcont/lifecycle-shard.js';
import { restoreFromShards } from '../../src/core/crypto/qcont/restore.js';

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

async function runJsonCli(args, options = {}) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli([...args, '--json'], {
    stdout,
    stderr,
    cwd: options.cwd,
  });
  assert.equal(stderr.text(), '');
  const json = stdout.text() ? JSON.parse(stdout.text()) : null;
  assert.equal(exitCode, 0, json?.error || `qv ${args.join(' ')} failed`);
  return json;
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

test('CLI encrypt output decrypts through the shared core browser-facing API', async () => {
  const baseDir = await mkdtemp(path.join(tmpdir(), 'qv-parity-encrypt-'));
  const keys = await runJsonCli(['keygen', '--out', path.join(baseDir, 'keys')]);
  const plaintext = new TextEncoder().encode('CLI to core parity\n');
  const inputPath = path.join(baseDir, 'plain.txt');
  const qencPath = path.join(baseDir, 'plain.txt.qenc');
  await writeFile(inputPath, plaintext);

  const encrypted = await runJsonCli([
    'encrypt',
    inputPath,
    '--public-key',
    keys.publicKeyPath,
    '--out',
    qencPath,
  ]);

  const qencBytes = new Uint8Array(await readFile(qencPath));
  const privateKey = new Uint8Array(await readFile(keys.privateKeyPath));
  const decrypted = await decryptFile(qencBytes, privateKey);
  const decryptedBytes = await blobToBytes(decrypted.decryptedBlob);

  assert.deepEqual(decryptedBytes, plaintext);
  assert.equal(decrypted.metadata.originalFilename, 'plain.txt');
  assert.equal(decrypted.metadata.fileHash, encrypted.fileHashHex);
});

test('core encrypt output decrypts through the CLI', async () => {
  await ensureRuntimeCrypto();
  const baseDir = await mkdtemp(path.join(tmpdir(), 'qv-parity-core-encrypt-'));
  const { publicKey, privateKey } = await generateKeyPair();
  const plaintext = new TextEncoder().encode('core to CLI parity\n');
  const qencPath = path.join(baseDir, 'core.qenc');
  const keyPath = path.join(baseDir, 'privateKey.qkey');
  const outPath = path.join(baseDir, 'decrypted.txt');
  const qencBytes = await blobToBytes(await encryptFile(plaintext, publicKey, 'core.txt'));

  await writeFile(qencPath, qencBytes);
  await writeFile(keyPath, privateKey);

  const decrypted = await runJsonCli([
    'decrypt',
    qencPath,
    '--private-key',
    keyPath,
    '--out',
    outPath,
  ]);

  assert.equal(decrypted.originalFilename, 'core.txt');
  assert.deepEqual(new Uint8Array(await readFile(outPath)), plaintext);
  privateKey.fill(0);
});

test('CLI split restores through core and core split restores through CLI', async () => {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  const baseDir = await mkdtemp(path.join(tmpdir(), 'qv-parity-split-'));
  const keys = await runJsonCli(['keygen', '--out', path.join(baseDir, 'keys')]);
  const plaintext = new TextEncoder().encode('split restore parity\n');
  const inputPath = path.join(baseDir, 'payload.bin');
  const qencPath = path.join(baseDir, 'payload.bin.qenc');
  await writeFile(inputPath, plaintext);
  await runJsonCli(['encrypt', inputPath, '--public-key', keys.publicKeyPath, '--out', qencPath]);

  const splitDir = path.join(baseDir, 'cli-split');
  const cliSplit = await runJsonCli([
    'split',
    qencPath,
    '--private-key',
    keys.privateKeyPath,
    '--n',
    '5',
    '--k',
    '3',
    '--out',
    splitDir,
    '--auth-policy-level',
    'integrity-only',
    '--archive-id-random',
    '31'.repeat(32),
  ]);

  const cliParsedShards = await Promise.all(cliSplit.shards.map(async (shard) => (
    parseLifecycleShard(new Uint8Array(await readFile(shard.path)), { strict: true })
  )));
  const coreRestored = await restoreFromShards(cliParsedShards);
  assert.deepEqual(coreRestored.qencBytes, new Uint8Array(await readFile(qencPath)));
  assert.deepEqual(coreRestored.privKey, new Uint8Array(await readFile(keys.privateKeyPath)));
  coreRestored.qencBytes.fill(0);
  coreRestored.privKey.fill(0);

  const qencBytes = new Uint8Array(await readFile(qencPath));
  const privateKey = new Uint8Array(await readFile(keys.privateKeyPath));
  const coreSplit = await buildLifecycleQcontShards(qencBytes, privateKey, { n: 5, k: 3 }, {
    authPolicyLevel: 'integrity-only',
    archiveIdRandomBytes: new Uint8Array(32).fill(0x32),
  });
  const coreSplitDir = path.join(baseDir, 'core-split');
  await mkdir(coreSplitDir);
  const shardPaths = [];
  for (const shard of coreSplit.shards) {
    const shardPath = path.join(coreSplitDir, `core.part${shard.index + 1}-of-5.qcont`);
    await writeFile(shardPath, await blobToBytes(shard.blob));
    shardPaths.push(shardPath);
  }

  const cliRestore = await runJsonCli([
    'restore',
    '--shards',
    path.join(coreSplitDir, '*.qcont'),
    '--out',
    path.join(baseDir, 'cli-restore'),
  ]);
  assert.equal(cliRestore.archiveId, coreSplit.archiveId);
  assert.deepEqual(new Uint8Array(await readFile(cliRestore.outputs.qencPath)), qencBytes);
  assert.deepEqual(new Uint8Array(await readFile(cliRestore.outputs.keyPath)), privateKey);

  privateKey.fill(0);
  qencBytes.fill(0);
  for (const shardPath of shardPaths) {
    const bytes = new Uint8Array(await readFile(shardPath));
    bytes.fill(0);
  }
});
