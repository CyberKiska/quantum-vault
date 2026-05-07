import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { lstat, open, readFile, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { QV_CODE, makeQvError } from './exit.js';

const ioPolicy = new AsyncLocalStorage();

function currentIoPolicy() {
  return ioPolicy.getStore() || {};
}

export function symlinksAllowed() {
  return currentIoPolicy().allowSymlink === true;
}

export async function runWithIoPolicy(policy, fn) {
  return ioPolicy.run({ ...(policy || {}) }, fn);
}

export async function assertNoSymlinkPath(filePath) {
  const resolved = path.resolve(filePath);
  const parsed = path.parse(resolved);
  const relative = path.relative(parsed.root, resolved);
  const parts = relative ? relative.split(path.sep).filter(Boolean) : [];
  let cursor = parsed.root;

  for (const part of parts) {
    cursor = path.join(cursor, part);
    const stats = await lstat(cursor);
    if (stats.isSymbolicLink()) {
      if (path.dirname(cursor) === parsed.root) {
        continue;
      }
      throw makeQvError(`Refusing to read symlink without --allow-symlink: ${cursor}`, QV_CODE.USAGE);
    }
  }
}

export async function readBytesFromFile(filePath, options = {}) {
  const allowSymlink = options.allowSymlink ?? currentIoPolicy().allowSymlink === true;
  if (!allowSymlink) {
    await assertNoSymlinkPath(filePath);
  } else {
    await lstat(filePath);
  }
  return new Uint8Array(await readFile(filePath));
}

export const readBytes = readBytesFromFile;

export function makeExternalArtifactRecord(filePath, bytes) {
  return {
    name: path.basename(filePath),
    bytes,
  };
}

export async function readOptionalBytes(filePath) {
  if (!filePath) return null;
  return readBytesFromFile(filePath);
}

function bytesToBuffer(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('writeBytesAtomic requires Uint8Array bytes');
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
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

async function unlinkIfExists(filePath) {
  try {
    await unlink(filePath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

export async function fsyncDirectory(dirPath) {
  let handle = null;
  try {
    handle = await open(dirPath, 'r');
    await handle.sync();
  } catch (error) {
    if (!['EINVAL', 'EISDIR', 'EPERM', 'ENOTSUP'].includes(error?.code)) {
      throw error;
    }
  } finally {
    await handle?.close();
  }
}

async function writeAll(handle, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesWritten } = await handle.write(buffer, offset, buffer.length - offset, offset);
    if (bytesWritten <= 0) {
      throw new Error('Atomic file write made no progress');
    }
    offset += bytesWritten;
  }
}

export async function writeBytesAtomic(filePath, bytes, {
  mode = 0o600,
  force = false,
} = {}) {
  const destination = path.resolve(filePath);
  const tempPath = `${destination}.tmp`;
  const parentDir = path.dirname(destination);
  const buffer = bytesToBuffer(bytes);
  let handle = null;
  let createdTemp = false;

  if (!force && await pathExists(destination)) {
    throw new Error(`Refusing to overwrite existing file: ${destination}`);
  }

  try {
    handle = await open(tempPath, 'wx', mode);
    createdTemp = true;
    await writeAll(handle, buffer);
    await handle.sync();
    await handle.close();
    handle = null;

    if (!force && await pathExists(destination)) {
      throw new Error(`Refusing to overwrite existing file: ${destination}`);
    }

    await rename(tempPath, destination);
    await fsyncDirectory(parentDir);
    return {
      path: destination,
      bytesWritten: buffer.length,
      mode,
    };
  } catch (error) {
    await handle?.close();
    if (createdTemp) {
      await unlinkIfExists(tempPath);
    }
    throw error;
  }
}

function uniqueTempPath(destination) {
  const token = `${process.pid}.${randomUUID()}`;
  return `${destination}.tmp-${token}`;
}

async function writeTempFile(tempPath, bytes, mode) {
  const buffer = bytesToBuffer(bytes);
  const handle = await open(tempPath, 'wx', mode);
  try {
    await writeAll(handle, buffer);
    await handle.sync();
  } finally {
    await handle.close();
  }
  return buffer.length;
}

export async function writeArtifactSetAtomic(entries, { force = false } = {}) {
  if (!Array.isArray(entries) || entries.length === 0) return [];

  const normalized = entries.map((entry) => ({
    path: path.resolve(entry.path),
    bytes: entry.bytes,
    mode: entry.mode ?? 0o600,
  }));
  const destinationSet = new Set(normalized.map((entry) => entry.path));
  if (destinationSet.size !== normalized.length) {
    throw makeQvError('Artifact output paths must be distinct', QV_CODE.USAGE);
  }

  if (!force) {
    for (const entry of normalized) {
      if (await pathExists(entry.path)) {
        throw makeQvError(`Refusing to overwrite existing file: ${entry.path}`, QV_CODE.USAGE);
      }
    }
  }

  const staged = [];
  const renamed = [];
  try {
    for (const entry of normalized) {
      const tempPath = uniqueTempPath(entry.path);
      const bytesWritten = await writeTempFile(tempPath, entry.bytes, entry.mode);
      staged.push({ ...entry, tempPath, bytesWritten });
    }

    for (const entry of staged) {
      if (!force && await pathExists(entry.path)) {
        throw makeQvError(`Refusing to overwrite existing file: ${entry.path}`, QV_CODE.USAGE);
      }
      await rename(entry.tempPath, entry.path);
      renamed.push(entry);
    }

    const dirs = new Set(staged.map((entry) => path.dirname(entry.path)));
    for (const dir of dirs) {
      await fsyncDirectory(dir);
    }

    return staged.map((entry) => ({
      path: entry.path,
      bytesWritten: entry.bytesWritten,
      mode: entry.mode,
    }));
  } catch (error) {
    for (const entry of staged) {
      await unlinkIfExists(entry.tempPath);
    }
    if (!force) {
      for (const entry of renamed.reverse()) {
        await unlinkIfExists(entry.path);
      }
    }
    throw error;
  }
}

export async function writeJsonAtomic(filePath, value, options = {}) {
  const jsonBytes = new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`);
  return writeBytesAtomic(filePath, jsonBytes, {
    mode: 0o644,
    ...options,
  });
}
