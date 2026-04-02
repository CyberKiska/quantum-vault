import { bytesEqual } from '../core/crypto/bytes.js';
import { isSupportedStellarSignatureDocument } from '../core/crypto/auth/stellar-sig.js';
import { parseArchiveStateDescriptorBytes, parseLifecycleBundleBytes } from '../core/crypto/lifecycle/artifacts.js';
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
  let archiveStateBytes = null;
  let lifecycleBundleBytes = null;
  const pinnedPqPublicKeyFileBytesList = [];

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
      const alreadyPresent = pinnedPqPublicKeyFileBytesList.some((item) => bytesEqual(item, bytes));
      if (!alreadyPresent) {
        pinnedPqPublicKeyFileBytesList.push(bytes);
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
    if (isSupportedStellarSignatureDocument(parsedJson)) {
      signatures.push({ name, bytes });
      continue;
    }

    try {
      const parsedLifecycleBundle = await parseLifecycleBundleBytes(bytes);
      if (lifecycleBundleBytes && !bytesEqual(lifecycleBundleBytes, parsedLifecycleBundle.bytes)) {
        throw new Error('Multiple different lifecycle bundle files were provided. Keep only one.');
      }
      lifecycleBundleBytes = parsedLifecycleBundle.bytes;
      continue;
    } catch (error) {
      if (lowerName.endsWith('.lifecycle-bundle.json')) {
        throw error;
      }
    }

    try {
      const parsedArchiveState = parseArchiveStateDescriptorBytes(bytes);
      if (archiveStateBytes && !bytesEqual(archiveStateBytes, parsedArchiveState.bytes)) {
        throw new Error('Multiple different archive-state descriptor files were provided. Keep only one.');
      }
      archiveStateBytes = parsedArchiveState.bytes;
      continue;
    } catch (error) {
      if (lowerName.endsWith('.archive-state.json')) {
        throw error;
      }
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
    archiveStateBytes,
    lifecycleBundleBytes,
    signatures,
    timestamps,
    pinnedPqPublicKeyFileBytes: pinnedPqPublicKeyFileBytesList[0] || null,
    pinnedPqPublicKeyFileBytesList,
    ignoredFileNames,
  };
}
