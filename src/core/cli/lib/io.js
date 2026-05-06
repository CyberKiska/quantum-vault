import { open, readFile, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';

export async function readBytesFromFile(filePath) {
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

async function fsyncDirectory(dirPath) {
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

export async function writeJsonAtomic(filePath, value, options = {}) {
  const jsonBytes = new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`);
  return writeBytesAtomic(filePath, jsonBytes, {
    mode: 0o644,
    ...options,
  });
}
