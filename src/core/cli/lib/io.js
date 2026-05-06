import { readFile } from 'node:fs/promises';
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
