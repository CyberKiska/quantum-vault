import { classifyArtifactBytes } from '../core/crypto/artifact-classification.js';
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
