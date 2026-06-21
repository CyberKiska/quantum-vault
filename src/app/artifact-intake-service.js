import { classifyArtifactBytes } from '../core/crypto/artifact-classification.js';
import { bytesEqual } from '../core/crypto/bytes.js';
import {
  canonicalizeArchiveStateDescriptor,
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
  parseSourceEvidenceBytes,
  parseTransitionRecordBytes,
} from '../core/crypto/lifecycle/artifacts.js';
import { readFileAsUint8Array } from '../utils.js';

export function artifactFileName(file) {
  return String(file?.name || 'unnamed');
}

/**
 * App-layer file intake boundary: read a File/Blob-like object, then delegate
 * artifact classification to the DOM-free core byte classifier.
 *
 * @param {File|{ name?: string, arrayBuffer: () => Promise<ArrayBuffer> }} file
 * @param {{ name?: string }} [options]
 */
export async function classifyArtifactFileBytes(file, options = {}) {
  const name = String(options.name || artifactFileName(file));
  const bytes = await readFileAsUint8Array(file);
  const classification = await classifyArtifactBytes(bytes, { ...options, name });
  return {
    file,
    name,
    bytes,
    classification,
  };
}

export async function classifyArtifactFilesBytes(files, options = {}) {
  const out = [];
  for (const file of Array.from(files || [])) {
    out.push(await classifyArtifactFileBytes(file, options));
  }
  return out;
}

export function throwArtifactClassificationError(classification, fallbackMessage) {
  if (classification?.error instanceof Error) {
    throw classification.error;
  }
  throw new Error(classification?.errorMessage || fallbackMessage);
}

export function appendUniqueByteArtifact(list, bytes) {
  if (!Array.isArray(list)) {
    throw new TypeError('Unique artifact accumulator must be an array');
  }
  const alreadyPresent = list.some((item) => bytesEqual(item, bytes));
  if (!alreadyPresent) {
    list.push(bytes);
  }
  return !alreadyPresent;
}

export function mergeSingleCanonicalArtifactBytes(existingBytes, canonicalBytes, duplicateMessage) {
  if (!(canonicalBytes instanceof Uint8Array)) {
    throw new TypeError('Recognized canonical artifact is missing canonical bytes');
  }
  if (existingBytes && !bytesEqual(existingBytes, canonicalBytes)) {
    throw new Error(duplicateMessage);
  }
  return canonicalBytes;
}

export async function parseLifecycleBundleViewBytes(bytes) {
  const parsed = await parseLifecycleBundleBytes(bytes);
  const digestHex = parsed.digest?.value || '';
  return {
    lifecycleBundle: parsed.lifecycleBundle,
    digest: parsed.digest,
    digestHex,
    canonicalBytes: parsed.bytes,
  };
}

export async function parseLifecycleBundleArchiveStateViewBytes(bytes) {
  const parsed = await parseLifecycleBundleViewBytes(bytes);
  const archiveState = canonicalizeArchiveStateDescriptor(parsed.lifecycleBundle.archiveState);
  const digestHex = archiveState.digest?.value || '';
  return {
    lifecycleBundle: parsed.lifecycleBundle,
    lifecycleBundleDigest: parsed.digest,
    lifecycleBundleDigestHex: parsed.digestHex,
    archiveState: archiveState.archiveState,
    stateId: archiveState.stateId,
    digest: archiveState.digest,
    digestHex,
    canonicalBytes: archiveState.bytes,
  };
}

export function parseArchiveStateViewBytes(bytes) {
  const parsed = parseArchiveStateDescriptorBytes(bytes);
  const digestHex = parsed.digest?.value || '';
  return {
    archiveState: parsed.archiveState,
    stateId: parsed.stateId,
    digest: parsed.digest,
    digestHex,
    canonicalBytes: parsed.bytes,
  };
}

export function parseTransitionRecordViewBytes(bytes) {
  const parsed = parseTransitionRecordBytes(bytes);
  const digestHex = parsed.digest?.value || '';
  return {
    transitionRecord: parsed.transitionRecord,
    digest: parsed.digest,
    digestHex,
    targetRef: `transition:sha3-512:${digestHex}`,
    canonicalBytes: parsed.bytes,
  };
}

export function parseSourceEvidenceViewBytes(bytes) {
  const parsed = parseSourceEvidenceBytes(bytes);
  const digestHex = parsed.digest?.value || '';
  return {
    sourceEvidence: parsed.sourceEvidence,
    digest: parsed.digest,
    digestHex,
    targetRef: `source-evidence:sha3-512:${digestHex}`,
    canonicalBytes: parsed.bytes,
  };
}
