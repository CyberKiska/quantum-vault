import { parseJsonBytesStrict } from '../../crypto/manifest/strict-json.js';
import { classifyJsonArtifactObject } from '../lib/artifacts.js';
import { parseSingleFileCommandArgs } from '../lib/args.js';
import { readBytesFromFile } from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';

async function canonicalizeArtifact(bytes, filePath) {
  const rawObject = parseJsonBytesStrict(bytes);
  const descriptor = classifyJsonArtifactObject(rawObject);
  if (!descriptor) {
    throw new Error(`Artifact is not canonicalizable JSON: ${filePath}`);
  }
  const canonicalized = await descriptor.canonicalize(rawObject);
  return {
    command: 'canonicalize',
    file: filePath,
    artifactType: descriptor.artifactType,
    artifactVersion: descriptor.artifactVersion,
    digestAlg: 'SHA3-512',
    digestHex: canonicalized.digest.value,
    canonicalBytes: canonicalized.bytes,
    canonicalJson: canonicalized[descriptor.objectField],
    canonicalJsonText: canonicalized.canonical,
  };
}

export function parseCanonicalizeArgs(args) {
  return parseSingleFileCommandArgs('canonicalize', args);
}

export async function runCanonicalizeCommand(filePath) {
  await ensureRuntimeCrypto();
  const bytes = await readBytesFromFile(filePath);
  return canonicalizeArtifact(bytes, filePath);
}

export function createCanonicalizeJsonReport(report) {
  return {
    command: report.command,
    file: report.file,
    artifactType: report.artifactType,
    artifactVersion: report.artifactVersion,
    digestAlg: report.digestAlg,
    digestHex: report.digestHex,
    canonicalJson: report.canonicalJson,
    canonicalJsonText: report.canonicalJsonText,
  };
}
