import {
  appendUniqueByteArtifact,
  classifyArtifactFileBytes,
  mergeSingleCanonicalArtifactBytes,
  throwArtifactClassificationError,
} from './artifact-intake-service.js';

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
      bytes.fill(0);
      continue;
    }

    if (classification.kind === 'pqpk') {
      if (!appendUniqueByteArtifact(pinnedPqPublicKeyFileBytesList, bytes)) bytes.fill(0);
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
          bytes.fill(0);
          throwArtifactClassificationError(classification, 'Malformed lifecycle bundle file.');
        }
        ignoredFileNames.push(name);
        bytes.fill(0);
        continue;
      }
      lifecycleBundleBytes = mergeSingleCanonicalArtifactBytes(
        lifecycleBundleBytes,
        classification.canonicalBytes,
        'Multiple different lifecycle bundle files were provided. Keep only one.'
      );
      bytes.fill(0);
      continue;
    }

    if (classification.kind === 'archive-state') {
      if (classification.status !== 'recognized') {
        if (lowerName.endsWith('.archive-state.json')) {
          bytes.fill(0);
          throwArtifactClassificationError(classification, 'Malformed archive-state descriptor file.');
        }
        ignoredFileNames.push(name);
        bytes.fill(0);
        continue;
      }
      archiveStateBytes = mergeSingleCanonicalArtifactBytes(
        archiveStateBytes,
        classification.canonicalBytes,
        'Multiple different archive-state descriptor files were provided. Keep only one.'
      );
      bytes.fill(0);
      continue;
    }

    ignoredFileNames.push(name);
    bytes.fill(0);
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
