import { bytesEqual } from '../core/crypto/bytes.js';
import { classifyArtifactFileBytes } from './artifact-intake-service.js';

function throwClassificationError(classification, fallbackMessage) {
  if (classification?.error instanceof Error) {
    throw classification.error;
  }
  throw new Error(classification?.errorMessage || fallbackMessage);
}

export async function classifyRestoreInputFiles(files) {
  const shardFiles = [];
  const signatures = [];
  const timestamps = [];
  const ignoredFileNames = [];
  let archiveStateBytes = null;
  let lifecycleBundleBytes = null;
  const pinnedPqPublicKeyFileBytesList = [];

  for (const file of files) {
    const name = String(file?.name || 'unnamed');
    const lowerName = name.toLowerCase();

    if (lowerName.endsWith('.qvmanifest.json')) {
      ignoredFileNames.push(name);
      continue;
    }

    const { bytes, classification } = await classifyArtifactFileBytes(file);

    if (classification.kind === 'qcont-shard') {
      shardFiles.push(file);
      continue;
    }

    if (classification.kind === 'pqpk') {
      const alreadyPresent = pinnedPqPublicKeyFileBytesList.some((item) => bytesEqual(item, bytes));
      if (!alreadyPresent) {
        pinnedPqPublicKeyFileBytesList.push(bytes);
      }
      continue;
    }

    if (classification.kind === 'signature') {
      signatures.push({ name, bytes });
      continue;
    }

    if (classification.kind === 'ots-proof') {
      timestamps.push({ name, bytes });
      continue;
    }

    if (classification.kind === 'lifecycle-bundle') {
      if (classification.status !== 'recognized') {
        if (lowerName.endsWith('.lifecycle-bundle.json')) {
          throwClassificationError(classification, 'Malformed lifecycle bundle file.');
        }
        ignoredFileNames.push(name);
        continue;
      }
      const canonicalBytes = classification.canonicalBytes;
      if (lifecycleBundleBytes && !bytesEqual(lifecycleBundleBytes, canonicalBytes)) {
        throw new Error('Multiple different lifecycle bundle files were provided. Keep only one.');
      }
      lifecycleBundleBytes = canonicalBytes;
      continue;
    }

    if (classification.kind === 'archive-state') {
      if (classification.status !== 'recognized') {
        if (lowerName.endsWith('.archive-state.json')) {
          throwClassificationError(classification, 'Malformed archive-state descriptor file.');
        }
        ignoredFileNames.push(name);
        continue;
      }
      const canonicalBytes = classification.canonicalBytes;
      if (archiveStateBytes && !bytesEqual(archiveStateBytes, canonicalBytes)) {
        throw new Error('Multiple different archive-state descriptor files were provided. Keep only one.');
      }
      archiveStateBytes = canonicalBytes;
      continue;
    }

    ignoredFileNames.push(name);
  }

  return {
    shardFiles,
    archiveStateBytes,
    lifecycleBundleBytes,
    signatures,
    timestamps,
    pinnedPqPublicKeyFileBytes: pinnedPqPublicKeyFileBytesList[0] || null,
    pinnedPqPublicKeyFileBytesList,
    ignoredFileNames,
  };
}
