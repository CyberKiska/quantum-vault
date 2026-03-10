import { bytesEqual } from '../core/crypto/bytes.js';
import { parseArchiveManifestBytes } from '../core/crypto/manifest/archive-manifest.js';
import { parseManifestBundleBytes } from '../core/crypto/manifest/manifest-bundle.js';
import { readFileAsUint8Array } from '../utils.js';

const QCONT_MAGIC = 'QVC1';

function startsWithAscii(bytes, ascii) {
  if (!(bytes instanceof Uint8Array)) return false;
  if (bytes.length < ascii.length) return false;
  for (let i = 0; i < ascii.length; i += 1) {
    if (bytes[i] !== ascii.charCodeAt(i)) return false;
  }
  return true;
}

function tryParseJsonBytes(bytes) {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

export async function classifyRestoreInputFiles(files) {
  const shardFiles = [];
  const signatures = [];
  const timestamps = [];
  const ignoredFileNames = [];
  let manifestBytes = null;
  let bundleBytes = null;
  let pinnedPqPublicKeyFileBytes = null;

  for (const file of files) {
    const name = String(file?.name || 'unnamed');
    const lowerName = name.toLowerCase();

    if (lowerName.endsWith('.qcont')) {
      shardFiles.push(file);
      continue;
    }

    const bytes = await readFileAsUint8Array(file);

    if (startsWithAscii(bytes, QCONT_MAGIC)) {
      shardFiles.push(file);
      continue;
    }

    if (startsWithAscii(bytes, 'PQPK') || lowerName.endsWith('.pqpk')) {
      if (!pinnedPqPublicKeyFileBytes) {
        pinnedPqPublicKeyFileBytes = bytes;
      } else if (!bytesEqual(pinnedPqPublicKeyFileBytes, bytes)) {
        throw new Error('Multiple different .pqpk files were provided. Keep only one pinned PQ key for restore.');
      }
      continue;
    }

    if (startsWithAscii(bytes, 'PQSG') || lowerName.endsWith('.qsig')) {
      signatures.push({ name, bytes });
      continue;
    }

    if (lowerName.endsWith('.ots')) {
      timestamps.push({ name, bytes });
      continue;
    }

    const parsedJson = tryParseJsonBytes(bytes);
    if (parsedJson?.schema === 'stellar-file-signature/v1') {
      signatures.push({ name, bytes });
      continue;
    }
    if (parsedJson?.type === 'QV-Manifest-Bundle') {
      const parsedBundle = parseManifestBundleBytes(bytes);
      if (bundleBytes && !bytesEqual(bundleBytes, parsedBundle.bytes)) {
        throw new Error('Multiple different manifest bundle files were provided. Keep only one.');
      }
      bundleBytes = parsedBundle.bytes;
      continue;
    }

    try {
      const parsedManifest = parseArchiveManifestBytes(bytes);
      if (manifestBytes && !bytesEqual(manifestBytes, parsedManifest.bytes)) {
        throw new Error('Multiple different canonical manifest files were provided. Keep only one.');
      }
      manifestBytes = parsedManifest.bytes;
      continue;
    } catch (error) {
      if (lowerName.endsWith('.qvmanifest.json')) {
        throw error;
      }
    }

    ignoredFileNames.push(name);
  }

  return {
    shardFiles,
    manifestBytes,
    bundleBytes,
    signatures,
    timestamps,
    pinnedPqPublicKeyFileBytes,
    ignoredFileNames,
  };
}
