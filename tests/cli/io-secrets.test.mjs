import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, readFile, readdir, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import {
  readBytesFromFile,
  writeArtifactSetAtomic,
  writeBytesAtomic,
  writeJsonAtomic,
} from '../../src/core/cli/lib/io.js';
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

test('atomic writers refuse directory and symbolic-link destinations even with force', async () => {
  const dir = await makeTempDir();
  const directoryDestination = join(dir, 'directory-destination');
  const directoryMarker = join(directoryDestination, 'keep.txt');
  const symlinkTarget = join(dir, 'symlink-target.bin');
  const symlinkDestination = join(dir, 'symlink-destination.bin');
  const brokenSymlinkDestination = join(dir, 'broken-symlink-destination.bin');
  await mkdir(directoryDestination);
  await writeFile(directoryMarker, Buffer.from('keep'));
  await writeFile(symlinkTarget, Buffer.from('target'));
  await symlink(symlinkTarget, symlinkDestination);
  await symlink(join(dir, 'missing-target.bin'), brokenSymlinkDestination);

  for (const destination of [directoryDestination, symlinkDestination, brokenSymlinkDestination]) {
    await assert.rejects(
      writeBytesAtomic(destination, Uint8Array.of(1), { force: true }),
      { qvCode: 'USAGE' },
    );
    await assert.rejects(
      writeArtifactSetAtomic([{ path: destination, bytes: Uint8Array.of(2) }], { force: true }),
      { qvCode: 'USAGE' },
    );
  }

  assert.equal((await stat(directoryDestination)).isDirectory(), true);
  assert.equal(await readFile(directoryMarker, 'utf8'), 'keep');
  assert.equal((await lstat(symlinkDestination)).isSymbolicLink(), true);
  assert.equal((await lstat(brokenSymlinkDestination)).isSymbolicLink(), true);
  assert.equal(await readFile(symlinkTarget, 'utf8'), 'target');
  assert.deepEqual(
    (await readdir(dir)).filter((name) => name.includes('.tmp') || name.includes('.backup-')),
    [],
  );
});

test('artifact-set preflight rejects a later non-file destination without partial artifacts', async () => {
  const dir = await makeTempDir();
  const firstDestination = join(dir, 'first.bin');
  const directoryDestination = join(dir, 'second.bin');
  const markerPath = join(directoryDestination, 'keep.txt');
  await mkdir(directoryDestination);
  await writeFile(markerPath, Buffer.from('keep'));

  await assert.rejects(
    writeArtifactSetAtomic([
      { path: firstDestination, bytes: Uint8Array.of(1) },
      { path: directoryDestination, bytes: Uint8Array.of(2) },
    ], { force: true }),
    { qvCode: 'USAGE' },
  );

  await assert.rejects(() => stat(firstDestination), { code: 'ENOENT' });
  assert.equal((await stat(directoryDestination)).isDirectory(), true);
  assert.equal(await readFile(markerPath, 'utf8'), 'keep');
  assert.deepEqual(
    (await readdir(dir)).filter((name) => name.includes('.tmp') || name.includes('.backup-')),
    [],
  );
});

test('artifact-set preflight rejects ancestor and descendant destinations before writing', async () => {
  const dir = await makeTempDir();
  const ancestor = join(dir, 'artifact');
  const descendant = join(ancestor, 'nested.bin');

  for (const entries of [
    [
      { path: ancestor, bytes: Uint8Array.of(1) },
      { path: descendant, bytes: Uint8Array.of(2) },
    ],
    [
      { path: descendant, bytes: Uint8Array.of(2) },
      { path: ancestor, bytes: Uint8Array.of(1) },
    ],
  ]) {
    await assert.rejects(
      writeArtifactSetAtomic(entries, { force: true }),
      { qvCode: 'USAGE' },
    );
    await assert.rejects(() => lstat(ancestor), { code: 'ENOENT' });
    assert.deepEqual(
      (await readdir(dir)).filter((name) => name.includes('.tmp') || name.includes('.backup-')),
      [],
    );
  }
});

test('artifact-set preflight rejects duplicate destinations before writing', async () => {
  const dir = await makeTempDir();
  const destination = join(dir, 'duplicate.bin');

  await assert.rejects(
    writeArtifactSetAtomic([
      { path: destination, bytes: Uint8Array.of(1) },
      { path: destination, bytes: Uint8Array.of(2) },
    ], { force: true }),
    { qvCode: 'USAGE' },
  );

  await assert.rejects(() => lstat(destination), { code: 'ENOENT' });
  assert.deepEqual(
    (await readdir(dir)).filter((name) => name.includes('.tmp') || name.includes('.backup-')),
    [],
  );
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

test('small artifact readers enforce explicit pre-read byte caps', async () => {
  const dir = await makeTempDir();
  const filePath = join(dir, 'oversized.json');
  await writeFile(filePath, Buffer.from([1, 2]));

  await assert.rejects(
    readBytesFromFile(filePath, { maxBytes: 1, label: 'Detached artifact' }),
    { qvCode: 'FORMAT_POLICY_REJECT' },
  );
  await assert.rejects(
    readSecretBytes({
      stdin: Readable.from([Uint8Array.of(1), Buffer.from([2])]),
      maxBytes: 1,
      label: 'Private key input',
    }),
    { qvCode: 'FORMAT_POLICY_REJECT' },
  );
  await assert.rejects(
    readSecretBytes({
      envName: 'QV_PRIV_KEY_PATH',
      env: { QV_PRIV_KEY_PATH: filePath },
      maxBytes: 1,
      label: 'Private key input',
    }),
    { qvCode: 'FORMAT_POLICY_REJECT' },
  );
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
