import { AsyncLocalStorage } from 'node:async_hooks';
import { constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { link, lstat, open, rename, unlink } from 'node:fs/promises';
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
      // Darwin exposes selected system-managed roots as aliases into /private.
      // Allow only the explicit temporary/runtime aliases required by Node and
      // reject unrelated root-level symlinks such as /etc.
      const allowedDarwinRootAlias = process.platform === 'darwin' && (
        cursor === '/tmp' || cursor === '/var'
      );
      if (allowedDarwinRootAlias) {
        continue;
      }
      throw makeQvError(`Refusing to read symlink without --allow-symlink: ${cursor}`, QV_CODE.USAGE);
    }
  }
}

export async function readBytesFromFile(filePath, options = {}) {
  const allowSymlink = options.allowSymlink ?? currentIoPolicy().allowSymlink === true;
  const resolved = path.resolve(filePath);
  let handle = null;
  if (!allowSymlink) {
    await assertNoSymlinkPath(resolved);
  }

  try {
    const noFollow = Number.isInteger(constants.O_NOFOLLOW) ? constants.O_NOFOLLOW : 0;
    handle = await open(resolved, constants.O_RDONLY | (allowSymlink ? 0 : noFollow));
    const stats = await handle.stat();
    if (!stats.isFile()) {
      throw makeQvError(`Input path is not a regular file: ${resolved}`, QV_CODE.USAGE);
    }
    if (!allowSymlink) {
      // Narrow the path-swap window around descriptor acquisition. Node does not
      // expose portable openat(2), so parent-directory race resistance remains
      // best effort and is documented as such.
      await assertNoSymlinkPath(resolved);
    }
    if (Number.isSafeInteger(options.maxBytes) && stats.size > options.maxBytes) {
      const label = options.label || 'Input file';
      throw makeQvError(
        `${label} exceeds CLI read limit (${stats.size} > ${options.maxBytes} bytes): ${resolved}`,
        QV_CODE.FORMAT_POLICY_REJECT,
      );
    }
    const buffer = await handle.readFile();
    // Preserve Uint8Array slice/copy semantics used by parsers without copying
    // the file buffer. Buffer.prototype.slice() would alias security-sensitive
    // parser fields and let cleanup unexpectedly corrupt sibling state.
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } finally {
    await handle?.close();
  }
}

export const readBytes = readBytesFromFile;

export function makeExternalArtifactRecord(filePath, bytes) {
  return {
    name: path.basename(filePath),
    bytes,
  };
}

export async function readOptionalBytes(filePath, options = {}) {
  if (!filePath) return null;
  return readBytesFromFile(filePath, options);
}

function bytesToBuffer(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('writeBytesAtomic requires Uint8Array bytes');
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

async function lstatIfExists(filePath) {
  try {
    return await lstat(filePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function preflightOutputDestination(destination, force) {
  const stats = await lstatIfExists(destination);
  if (!stats) return;
  if (stats.isSymbolicLink()) {
    throw makeQvError(
      `Refusing to replace symbolic-link output destination: ${destination}`,
      QV_CODE.USAGE,
    );
  }
  if (!stats.isFile()) {
    throw makeQvError(
      `Refusing to replace non-file output destination: ${destination}`,
      QV_CODE.USAGE,
    );
  }
  if (!force) {
    throw makeQvError(`Refusing to overwrite existing file: ${destination}`, QV_CODE.USAGE);
  }
}

function assertIndependentOutputPaths(destinations) {
  const destinationSet = new Set(destinations);
  if (destinationSet.size !== destinations.length) {
    throw makeQvError('Artifact output paths must be distinct', QV_CODE.USAGE);
  }
  for (const destination of destinations) {
    let ancestor = path.dirname(destination);
    while (true) {
      if (destinationSet.has(ancestor)) {
        throw makeQvError(
          'Artifact output paths must not be ancestors or descendants of one another',
          QV_CODE.USAGE,
        );
      }
      const parent = path.dirname(ancestor);
      if (parent === ancestor) break;
      ancestor = parent;
    }
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
  const tempPath = uniqueTempPath(destination);
  const parentDir = path.dirname(destination);
  const buffer = bytesToBuffer(bytes);
  let handle = null;
  let createdTemp = false;

  await preflightOutputDestination(destination, force);

  try {
    handle = await open(tempPath, 'wx', mode);
    createdTemp = true;
    await writeAll(handle, buffer);
    await handle.sync();
    await handle.close();
    handle = null;

    if (force) {
      // The destination may have changed while the private temp file was being
      // written. Re-check immediately before publication; rename replaces a
      // path entry without following it, but callers still require symlink and
      // non-file destinations to fail closed.
      await preflightOutputDestination(destination, true);
      await rename(tempPath, destination);
    } else {
      try {
        await link(tempPath, destination);
      } catch (error) {
        if (error?.code === 'EEXIST') {
          throw makeQvError(`Refusing to overwrite existing file: ${destination}`, QV_CODE.USAGE);
        }
        throw error;
      }
      await unlink(tempPath);
    }
    createdTemp = false;
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

function uniqueBackupPath(destination) {
  const token = `${process.pid}.${randomUUID()}`;
  return `${destination}.backup-${token}`;
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
  assertIndependentOutputPaths(normalized.map((entry) => entry.path));
  for (const entry of normalized) {
    await preflightOutputDestination(entry.path, force);
  }

  const staged = [];
  const renamed = [];
  const backups = [];
  try {
    for (const entry of normalized) {
      const tempPath = uniqueTempPath(entry.path);
      const bytesWritten = await writeTempFile(tempPath, entry.bytes, entry.mode);
      staged.push({ ...entry, tempPath, bytesWritten });
    }

    if (force) {
      for (const entry of staged) {
        const destinationStats = await lstatIfExists(entry.path);
        if (destinationStats) {
          await preflightOutputDestination(entry.path, true);
          const backupPath = uniqueBackupPath(entry.path);
          await rename(entry.path, backupPath);
          backups.push({ path: entry.path, backupPath });
        }
      }
    }

    for (const entry of staged) {
      if (force) {
        await rename(entry.tempPath, entry.path);
      } else {
        try {
          await link(entry.tempPath, entry.path);
        } catch (error) {
          if (error?.code === 'EEXIST') {
            throw makeQvError(`Refusing to overwrite existing file: ${entry.path}`, QV_CODE.USAGE);
          }
          throw error;
        }
        await unlink(entry.tempPath);
      }
      renamed.push(entry);
    }

    const dirs = new Set(staged.map((entry) => path.dirname(entry.path)));
    for (const dir of dirs) {
      await fsyncDirectory(dir);
    }
    for (const backup of backups) {
      try {
        await unlinkIfExists(backup.backupPath);
      } catch {
        // The committed destination is authoritative. A same-mode backup may
        // remain for operator cleanup, but cleanup failure must not trigger a
        // destructive rollback after other backups were already removed.
      }
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
    for (const entry of renamed.reverse()) {
      await unlinkIfExists(entry.path);
    }
    for (const backup of backups.reverse()) {
      await rename(backup.backupPath, backup.path);
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
