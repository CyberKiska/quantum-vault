import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { writeBytesAtomic, writeJsonAtomic } from '../../src/core/cli/lib/io.js';
import { readSecretBytes } from '../../src/core/cli/lib/secrets.js';

async function makeTempDir() {
  return mkdtemp(join(tmpdir(), 'qv-cli-io-'));
}

function modeBits(stats) {
  return stats.mode & 0o777;
}

test('writeBytesAtomic writes bytes with requested mode and removes temp file', async () => {
  const dir = await makeTempDir();
  const filePath = join(dir, 'secret.bin');
  const oldUmask = process.umask(0);
  try {
    const report = await writeBytesAtomic(filePath, Uint8Array.of(1, 2, 3), { mode: 0o600 });
    assert.equal(report.path, filePath);
    assert.equal(report.bytesWritten, 3);
    assert.deepEqual(new Uint8Array(await readFile(filePath)), Uint8Array.of(1, 2, 3));
    assert.equal(modeBits(await stat(filePath)), 0o600);
    await assert.rejects(stat(`${filePath}.tmp`), { code: 'ENOENT' });
  } finally {
    process.umask(oldUmask);
  }
});

test('writeBytesAtomic refuses overwrite unless force is set', async () => {
  const dir = await makeTempDir();
  const filePath = join(dir, 'artifact.bin');
  await writeBytesAtomic(filePath, Uint8Array.of(1), { mode: 0o600 });
  await assert.rejects(
    writeBytesAtomic(filePath, Uint8Array.of(2), { mode: 0o600 }),
    /Refusing to overwrite existing file/,
  );
  assert.deepEqual(new Uint8Array(await readFile(filePath)), Uint8Array.of(1));
  await writeBytesAtomic(filePath, Uint8Array.of(3), { mode: 0o600, force: true });
  assert.deepEqual(new Uint8Array(await readFile(filePath)), Uint8Array.of(3));
});

test('writeBytesAtomic refuses to clobber a pre-existing temp file', async () => {
  const dir = await makeTempDir();
  const filePath = join(dir, 'artifact.bin');
  const tempPath = `${filePath}.tmp`;
  await writeFile(tempPath, Buffer.from([8, 8]));
  await assert.rejects(
    writeBytesAtomic(filePath, Uint8Array.of(1), { mode: 0o600 }),
    { code: 'EEXIST' },
  );
  assert.deepEqual(new Uint8Array(await readFile(tempPath)), Uint8Array.of(8, 8));
});

test('writeJsonAtomic writes newline-terminated JSON with public artifact mode', async () => {
  const dir = await makeTempDir();
  const filePath = join(dir, 'report.json');
  const oldUmask = process.umask(0);
  try {
    await writeJsonAtomic(filePath, { ok: true, value: 7 });
    assert.equal(await readFile(filePath, 'utf8'), '{\n  "ok": true,\n  "value": 7\n}\n');
    assert.equal(modeBits(await stat(filePath)), 0o644);
  } finally {
    process.umask(oldUmask);
  }
});

test('readSecretBytes reads from a file and dispose zeroizes the returned bytes', async () => {
  const dir = await makeTempDir();
  const filePath = join(dir, 'private.qkey');
  await writeFile(filePath, Buffer.from([9, 8, 7, 6]));
  const secret = await readSecretBytes({ filePath });
  assert.equal(secret.source, 'file');
  assert.deepEqual(secret.bytes, Uint8Array.of(9, 8, 7, 6));
  assert.equal(secret.disposed, false);
  assert.equal(secret.dispose(), true);
  assert.equal(secret.disposed, true);
  assert.deepEqual(secret.bytes, Uint8Array.of(0, 0, 0, 0));
});

test('readSecretBytes reads raw bytes from stdin stream', async () => {
  const stdin = Readable.from([
    Uint8Array.of(1, 2),
    Buffer.from([3, 4]),
  ]);
  const secret = await readSecretBytes({ stdin });
  try {
    assert.equal(secret.source, 'stdin');
    assert.deepEqual(secret.bytes, Uint8Array.of(1, 2, 3, 4));
  } finally {
    secret.dispose();
  }
});

test('readSecretBytes reads env source as a file path only', async () => {
  const dir = await makeTempDir();
  const filePath = join(dir, 'env-private.qkey');
  await writeFile(filePath, Buffer.from([5, 6, 7]));
  const secret = await readSecretBytes({
    envName: 'QV_PRIV_KEY_PATH',
    env: { QV_PRIV_KEY_PATH: filePath },
  });
  try {
    assert.equal(secret.source, 'env-file');
    assert.deepEqual(secret.bytes, Uint8Array.of(5, 6, 7));
  } finally {
    secret.dispose();
  }
});

test('readSecretBytes rejects conflicting secret sources', async () => {
  await assert.rejects(
    readSecretBytes({
      filePath: 'private.qkey',
      stdin: Readable.from([Uint8Array.of(1)]),
    }),
    /Secret input sources are mutually exclusive/,
  );
});

test('readSecretBytes refuses env vars that contain raw secret bytes', async () => {
  await assert.rejects(
    readSecretBytes({
      envName: 'QV_PRIV_KEY_PATH',
      env: { QV_PRIV_KEY_PATH: 'raw-key-bytes\nnot-a-path' },
    }),
    /must contain a file path, not raw secret bytes/,
  );
});
