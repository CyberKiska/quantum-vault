import { asciiBytes, base64ToBytes, concatBytes, digestSha256, toHex } from '../bytes.js';

const OTS_PREFIX = concatBytes([
  asciiBytes('\x00OpenTimestamps\x00\x00Proof\x00'),
  Uint8Array.of(0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01),
]);
const OTS_HASH_OP_SHA256 = 0x08;

function startsWithBytes(bytes, prefix) {
  if (!(bytes instanceof Uint8Array) || bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i += 1) {
    if (bytes[i] !== prefix[i]) return false;
  }
  return true;
}

function inferCompleteProof(bytes, name = '') {
  const lowerName = String(name || '').toLowerCase();
  if (/(^|[^a-z])(initial|pending|incomplete)([^a-z]|$)/.test(lowerName)) {
    return false;
  }
  if (/(^|[^a-z])(complete|completed|confirmed|upgraded)([^a-z]|$)/.test(lowerName)) {
    return true;
  }
  return bytes.length >= 1024;
}

export function parseOpenTimestampProof(bytes, { name = '' } = {}) {
  if (!(bytes instanceof Uint8Array) || bytes.length < (OTS_PREFIX.length + 1 + 32)) {
    throw new Error(`Invalid OpenTimestamps proof: ${name || 'proof'} is too short`);
  }
  if (!startsWithBytes(bytes, OTS_PREFIX)) {
    throw new Error(`Invalid OpenTimestamps proof header: ${name || 'proof'}`);
  }

  const hashOp = bytes[OTS_PREFIX.length];
  if (hashOp !== OTS_HASH_OP_SHA256) {
    throw new Error(`Unsupported OpenTimestamps digest algorithm in ${name || 'proof'}: expected SHA-256`);
  }

  const stampedDigestBytes = bytes.subarray(OTS_PREFIX.length + 1, OTS_PREFIX.length + 33);
  const appearsComplete = inferCompleteProof(bytes, name);
  return {
    stampedDigestHex: toHex(stampedDigestBytes),
    appearsComplete,
    completeProof: appearsComplete,
  };
}

export function decodeBundleSignatureBytes(signature) {
  if (signature?.signatureEncoding !== 'base64') {
    throw new Error(`Unsupported bundle signature encoding: ${signature?.signatureEncoding ?? 'unknown'}`);
  }
  return base64ToBytes(signature.signature);
}

// This helper supports legacy/reporting call sites that may already carry a
// trusted cached SHA-256 for detached-signature bytes. Successor lifecycle
// attachment code must resolve OTS targets from exact `signature.bytes`
// directly and must not rely on `otsStampedDigestHex` shortcuts.
export async function resolveOpenTimestampTarget({ timestampBytes, timestampName = '', signatures = [] }) {
  const parsedProof = parseOpenTimestampProof(timestampBytes, { name: timestampName });
  const hashedSignatures = await Promise.all(signatures.map(async (signature) => {
    if (!(signature?.bytes instanceof Uint8Array)) return null;
    return {
      signature,
      computedStampedDigestHex: toHex(await digestSha256(signature.bytes)),
    };
  }));
  const uniqueSignatures = [];
  const seenSignatures = new Set();
  for (const entry of hashedSignatures) {
    if (!entry) continue;
    const { signature, computedStampedDigestHex } = entry;
    const dedupeKey = String(
      signature?.signatureContentDigestHex ||
      computedStampedDigestHex ||
      signature?.id ||
      signature?.name ||
      ''
    );
    if (dedupeKey && seenSignatures.has(dedupeKey)) continue;
    if (dedupeKey) seenSignatures.add(dedupeKey);
    uniqueSignatures.push(entry);
  }

  const matches = uniqueSignatures
    .filter((entry) => entry.computedStampedDigestHex === parsedProof.stampedDigestHex)
    .map((entry) => entry.signature);

  if (matches.length === 0) {
    throw new Error(`OpenTimestamps proof ${timestampName || 'proof'} does not match any detached signature`);
  }
  if (matches.length > 1) {
    throw new Error(`OpenTimestamps proof ${timestampName || 'proof'} matches multiple detached signatures`);
  }

  return {
    targetRef: matches[0].id,
    targetName: matches[0].name || matches[0].id,
    targetSource: matches[0].source || 'bundle',
    targetVerified: matches[0].ok === true,
    linked: true,
    apparentlyComplete: parsedProof.appearsComplete,
    completeProof: parsedProof.completeProof,
    stampedDigestHex: parsedProof.stampedDigestHex,
  };
}

export async function inspectManifestBundleTimestamps(bundle) {
  const signatures = Array.isArray(bundle?.attachments?.signatures)
    ? bundle.attachments.signatures.map((signature) => ({
        id: signature.id,
        bytes: decodeBundleSignatureBytes(signature),
      }))
    : [];
  const signaturesById = new Map(signatures.map((signature) => [signature.id, signature]));
  const timestamps = Array.isArray(bundle?.attachments?.timestamps) ? bundle.attachments.timestamps : [];

  return Promise.all(timestamps.map(async (timestamp) => {
    if (timestamp?.proofEncoding !== 'base64') {
      throw new Error(`Unsupported OpenTimestamps proof encoding: ${timestamp?.proofEncoding ?? 'unknown'}`);
    }
    const targetSignature = signaturesById.get(timestamp.targetRef);
    if (!targetSignature) {
      throw new Error(`OpenTimestamps targetRef is unknown: ${timestamp?.targetRef ?? 'unknown'}`);
    }
    const resolved = await resolveOpenTimestampTarget({
      timestampBytes: base64ToBytes(timestamp.proof),
      timestampName: timestamp.id,
      signatures: [targetSignature],
    });
    return {
      id: timestamp.id,
      targetRef: resolved.targetRef,
      targetName: resolved.targetName,
      targetSource: resolved.targetSource,
      targetVerified: resolved.targetVerified,
      linked: true,
      apparentlyComplete: resolved.apparentlyComplete,
      completeProof: resolved.completeProof,
      stampedDigestHex: resolved.stampedDigestHex,
      linkLabel: 'OTS evidence linked to signature',
      completionLabel: resolved.apparentlyComplete ? 'OTS proof appears complete' : 'OTS proof appears incomplete',
    };
  }));
}

export async function parseManifestBundleTimestamps(bundle) {
  await inspectManifestBundleTimestamps(bundle);
}

function timestampEvidencePreference(entry) {
  return [
    entry?.completeProof === true || entry?.apparentlyComplete === true ? 1 : 0,
    String(entry?.linkLabel || '').startsWith('External ') ? 0 : 1,
  ];
}

function compareTimestampEvidencePreference(left, right) {
  const leftScore = timestampEvidencePreference(left);
  const rightScore = timestampEvidencePreference(right);
  for (let i = 0; i < Math.max(leftScore.length, rightScore.length); i += 1) {
    const diff = (leftScore[i] || 0) - (rightScore[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function dedupeTimestampEvidence(entries) {
  const bestByStampedDigest = new Map();
  for (const entry of entries) {
    const dedupeKey = String(entry?.stampedDigestHex || entry?.targetRef || entry?.id || '').trim();
    if (!dedupeKey) continue;
    const current = bestByStampedDigest.get(dedupeKey);
    if (!current || compareTimestampEvidencePreference(entry, current) > 0) {
      bestByStampedDigest.set(dedupeKey, entry);
    }
  }
  return [...bestByStampedDigest.values()];
}

export async function inspectTimestampEvidence({
  bundle,
  externalTimestamps = [],
  signatureArtifacts = [],
}) {
  const embeddedEvidence = await inspectManifestBundleTimestamps(bundle);
  const externalEvidence = await Promise.all(externalTimestamps.map(async (timestamp, index) => {
    if (!(timestamp?.bytes instanceof Uint8Array) || timestamp.bytes.length === 0) {
      throw new Error(`Invalid OpenTimestamps proof: ${timestamp?.name || `timestamp-${index + 1}`}`);
    }
    const resolved = await resolveOpenTimestampTarget({
      timestampBytes: timestamp.bytes,
      timestampName: timestamp.name || `timestamp-${index + 1}`,
      signatures: signatureArtifacts,
    });
    return {
      id: timestamp.name || `timestamp-${index + 1}`,
      targetRef: resolved.targetRef,
      targetName: resolved.targetName,
      targetSource: resolved.targetSource,
      targetVerified: resolved.targetVerified,
      linked: true,
      apparentlyComplete: resolved.apparentlyComplete,
      completeProof: resolved.completeProof,
      stampedDigestHex: resolved.stampedDigestHex,
      linkLabel: 'External OTS evidence linked to signature',
      completionLabel: resolved.apparentlyComplete ? 'OTS proof appears complete' : 'OTS proof appears incomplete',
    };
  }));

  return dedupeTimestampEvidence([...embeddedEvidence, ...externalEvidence]);
}
