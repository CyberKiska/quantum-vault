import { startsWithAscii } from '../core/crypto/byte-prefix.js';
import { bytesEqual } from '../core/crypto/bytes.js';
import { isSupportedStellarSignatureDocumentBytes } from '../core/crypto/auth/stellar-sig.js';
import { parseArchiveStateDescriptorBytes, parseLifecycleBundleBytes } from '../core/crypto/lifecycle/artifacts.js';
import { readFileAsUint8Array } from '../utils.js';

const QCONT_MAGIC = 'QVC1';

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

    if (lowerName.endsWith('.qcont')) {
      shardFiles.push(file);
      continue;
    }

    if (lowerName.endsWith('.qvmanifest.json')) {
      ignoredFileNames.push(name);
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
    if (isSupportedStellarSignatureDocumentBytes(bytes)) {
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
