import { sha3_512 } from '@noble/hashes/sha3.js';
import { base64ToBytes, toHex } from '../bytes.js';
import { normalizeSignatureSuite } from '../auth/signature-suites.js';
import { QV_CANONICALIZATION_LABEL, canonicalizeJson, canonicalizeJsonToBytes } from './jcs.js';

export const MANIFEST_BUNDLE_TYPE = 'QV-Manifest-Bundle';
export const MANIFEST_BUNDLE_VERSION = 1;
export const MANIFEST_DIGEST_ALG = 'SHA3-512';
export const AUTH_POLICY_COMMITMENT_ALG = 'SHA3-512';

const AUTH_LEVELS = new Set(['integrity-only', 'any-signature', 'strong-pq-signature']);
const SIGNATURE_FORMATS = new Set(['qsig', 'stellar-sig']);
const TIMESTAMP_TYPES = new Set(['opentimestamps']);

function ensureObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function ensureString(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function ensureOptionalString(value, field) {
  if (value == null || value === '') return null;
  return ensureString(value, field);
}

function ensureInteger(value, field, min = 0) {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function ensureHex(value, field, expectedLength = null) {
  const text = ensureString(value, field).toLowerCase();
  if (!/^[0-9a-f]+$/.test(text)) {
    throw new Error(`Invalid ${field}`);
  }
  if (expectedLength != null && text.length !== expectedLength) {
    throw new Error(`Invalid ${field}`);
  }
  return text;
}

function assertCanonicalBytes(bytes, canonicalBytes, field) {
  if (bytes.length !== canonicalBytes.length) {
    throw new Error(`${field} is not ${QV_CANONICALIZATION_LABEL} canonical JSON`);
  }
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] !== canonicalBytes[i]) {
      throw new Error(`${field} is not ${QV_CANONICALIZATION_LABEL} canonical JSON`);
    }
  }
}

function assertUniqueIds(values, field) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value.id)) {
      throw new Error(`Duplicate ${field} id: ${value.id}`);
    }
    seen.add(value.id);
  }
}

function assertUniqueSignaturePayloads(signatures) {
  const seen = new Map();
  for (const signature of signatures) {
    if (signature.signatureEncoding !== 'base64') {
      throw new Error(`Unsupported signatureEncoding for ${signature.id}: ${signature.signatureEncoding}`);
    }
    const digestHex = toHex(sha3_512(base64ToBytes(signature.signature)));
    const existingId = seen.get(digestHex);
    if (existingId) {
      throw new Error(`Duplicate signature payload bytes detected across bundle signatures: ${existingId}, ${signature.id}`);
    }
    seen.set(digestHex, signature.id);
  }
}

export function normalizeAuthPolicy(authPolicy) {
  const source = ensureObject(authPolicy, 'authPolicy');
  const level = String(source.level || '').trim().toLowerCase();
  if (!AUTH_LEVELS.has(level)) {
    throw new Error(`Unsupported authPolicy.level: ${source.level}`);
  }
  return {
    level,
    minValidSignatures: ensureInteger(source.minValidSignatures ?? 1, 'authPolicy.minValidSignatures', 1),
  };
}

export function computeAuthPolicyCommitment(authPolicy) {
  const normalized = normalizeAuthPolicy(authPolicy);
  return {
    alg: AUTH_POLICY_COMMITMENT_ALG,
    canonicalization: QV_CANONICALIZATION_LABEL,
    value: toHex(sha3_512(canonicalizeJsonToBytes(normalized))),
  };
}

export function validateAuthPolicyCommitmentShape(commitment) {
  const source = ensureObject(commitment, 'authPolicyCommitment');
  if (ensureString(source.alg, 'authPolicyCommitment.alg') !== AUTH_POLICY_COMMITMENT_ALG) {
    throw new Error('Unsupported authPolicyCommitment.alg');
  }
  if (ensureString(source.canonicalization, 'authPolicyCommitment.canonicalization') !== QV_CANONICALIZATION_LABEL) {
    throw new Error('Unsupported authPolicyCommitment.canonicalization');
  }
  return {
    alg: source.alg,
    canonicalization: source.canonicalization,
    value: ensureHex(source.value, 'authPolicyCommitment.value', 128),
  };
}

export function assertAuthPolicyCommitment(commitment, authPolicy) {
  const actual = validateAuthPolicyCommitmentShape(commitment);
  const expected = computeAuthPolicyCommitment(authPolicy);
  if (actual.value !== expected.value) {
    throw new Error('authPolicyCommitment mismatch');
  }
  return actual;
}

export function recoverCommittedAuthPolicy(commitment, options = {}) {
  const actual = validateAuthPolicyCommitmentShape(commitment);
  const maxMinValidSignatures = Number.isInteger(options.maxMinValidSignatures)
    ? options.maxMinValidSignatures
    : 64;
  const matches = [];

  for (const level of AUTH_LEVELS) {
    for (let minValidSignatures = 1; minValidSignatures <= maxMinValidSignatures; minValidSignatures += 1) {
      const candidate = { level, minValidSignatures };
      if (computeAuthPolicyCommitment(candidate).value === actual.value) {
        matches.push(candidate);
      }
    }
  }

  if (matches.length === 1) {
    return matches[0];
  }
  if (matches.length === 0) {
    throw new Error('Unable to recover authPolicy from authPolicyCommitment');
  }
  throw new Error('authPolicyCommitment is ambiguous');
}

export function computeManifestDigest(manifest) {
  const bytes = canonicalizeJsonToBytes(manifest);
  return {
    canonical: canonicalizeJson(manifest),
    bytes,
    digestHex: toHex(sha3_512(bytes)),
  };
}

function normalizePublicKey(entry, index) {
  const source = ensureObject(entry, `attachments.publicKeys[${index}]`);
  return {
    id: ensureString(source.id, `attachments.publicKeys[${index}].id`),
    kty: ensureString(source.kty, `attachments.publicKeys[${index}].kty`),
    suite: normalizeSignatureSuite(source.suite),
    encoding: ensureString(source.encoding, `attachments.publicKeys[${index}].encoding`),
    value: ensureString(source.value, `attachments.publicKeys[${index}].value`),
    legacy: source.legacy === true,
  };
}

function normalizeSignature(entry, index, manifestDigestHex) {
  const source = ensureObject(entry, `attachments.signatures[${index}]`);
  const format = ensureString(source.format, `attachments.signatures[${index}].format`);
  if (!SIGNATURE_FORMATS.has(format)) {
    throw new Error(`Unsupported attachments.signatures[${index}].format`);
  }
  const target = ensureObject(source.target, `attachments.signatures[${index}].target`);
  if (ensureString(target.type, `attachments.signatures[${index}].target.type`) !== 'canonical-manifest') {
    throw new Error('Unsupported signature target.type');
  }
  if (ensureString(target.digestAlg, `attachments.signatures[${index}].target.digestAlg`) !== MANIFEST_DIGEST_ALG) {
    throw new Error('Unsupported signature target.digestAlg');
  }
  const digestValue = ensureHex(target.digestValue, `attachments.signatures[${index}].target.digestValue`, 128);
  if (digestValue !== manifestDigestHex) {
    throw new Error('Signature target digest mismatch');
  }
  return {
    id: ensureString(source.id, `attachments.signatures[${index}].id`),
    format,
    suite: normalizeSignatureSuite(source.suite),
    target: {
      type: 'canonical-manifest',
      digestAlg: MANIFEST_DIGEST_ALG,
      digestValue,
    },
    signatureEncoding: ensureString(source.signatureEncoding, `attachments.signatures[${index}].signatureEncoding`),
    signature: ensureString(source.signature, `attachments.signatures[${index}].signature`),
    publicKeyRef: ensureOptionalString(source.publicKeyRef, `attachments.signatures[${index}].publicKeyRef`),
    legacy: source.legacy === true,
  };
}

function normalizeTimestamp(entry, index, signatureIds) {
  const source = ensureObject(entry, `attachments.timestamps[${index}]`);
  const type = ensureString(source.type, `attachments.timestamps[${index}].type`);
  if (!TIMESTAMP_TYPES.has(type)) {
    throw new Error(`Unsupported attachments.timestamps[${index}].type`);
  }
  const targetRef = ensureString(source.targetRef, `attachments.timestamps[${index}].targetRef`);
  if (!signatureIds.has(targetRef)) {
    throw new Error(`attachments.timestamps[${index}].targetRef does not reference a known signature`);
  }
  return {
    id: ensureString(source.id, `attachments.timestamps[${index}].id`),
    type,
    targetRef,
    proofEncoding: ensureString(source.proofEncoding, `attachments.timestamps[${index}].proofEncoding`),
    proof: ensureString(source.proof, `attachments.timestamps[${index}].proof`),
    apparentlyComplete: source.apparentlyComplete === true || source.completeProof === true,
    completeProof: source.apparentlyComplete === true || source.completeProof === true,
  };
}

export function normalizeManifestBundle(bundle) {
  const source = ensureObject(bundle, 'bundle');
  if (ensureString(source.type, 'bundle.type') !== MANIFEST_BUNDLE_TYPE) {
    throw new Error('Unsupported manifest bundle type');
  }
  if (ensureInteger(source.version, 'bundle.version', 1) !== MANIFEST_BUNDLE_VERSION) {
    throw new Error('Unsupported manifest bundle version');
  }
  if (ensureString(source.bundleCanonicalization, 'bundle.bundleCanonicalization') !== QV_CANONICALIZATION_LABEL) {
    throw new Error('Unsupported bundleCanonicalization');
  }
  if (ensureString(source.manifestCanonicalization, 'bundle.manifestCanonicalization') !== QV_CANONICALIZATION_LABEL) {
    throw new Error('Unsupported manifestCanonicalization');
  }

  const manifest = ensureObject(source.manifest, 'bundle.manifest');
  const manifestDigest = computeManifestDigest(manifest);
  const manifestDigestObj = ensureObject(source.manifestDigest, 'bundle.manifestDigest');
  if (ensureString(manifestDigestObj.alg, 'bundle.manifestDigest.alg') !== MANIFEST_DIGEST_ALG) {
    throw new Error('Unsupported bundle.manifestDigest.alg');
  }
  if (ensureHex(manifestDigestObj.value, 'bundle.manifestDigest.value', 128) !== manifestDigest.digestHex) {
    throw new Error('bundle.manifestDigest mismatch');
  }

  const authPolicy = normalizeAuthPolicy(source.authPolicy);
  const attachments = ensureObject(source.attachments || {}, 'bundle.attachments');
  const publicKeys = Array.isArray(attachments.publicKeys)
    ? attachments.publicKeys.map(normalizePublicKey)
    : [];
  const signatures = Array.isArray(attachments.signatures)
    ? attachments.signatures.map((entry, index) => normalizeSignature(entry, index, manifestDigest.digestHex))
    : [];
  assertUniqueIds(publicKeys, 'publicKeys');
  assertUniqueIds(signatures, 'signatures');
  assertUniqueSignaturePayloads(signatures);
  const publicKeyIds = new Set(publicKeys.map((item) => item.id));
  for (const signature of signatures) {
    if (signature.publicKeyRef && !publicKeyIds.has(signature.publicKeyRef)) {
      throw new Error(`attachments.signatures publicKeyRef is unknown: ${signature.publicKeyRef}`);
    }
  }
  const signatureIds = new Set(signatures.map((item) => item.id));
  const timestamps = Array.isArray(attachments.timestamps)
    ? attachments.timestamps.map((entry, index) => normalizeTimestamp(entry, index, signatureIds))
    : [];
  assertUniqueIds(timestamps, 'timestamps');

  return {
    type: MANIFEST_BUNDLE_TYPE,
    version: MANIFEST_BUNDLE_VERSION,
    bundleCanonicalization: QV_CANONICALIZATION_LABEL,
    manifestCanonicalization: QV_CANONICALIZATION_LABEL,
    manifest,
    manifestDigest: {
      alg: MANIFEST_DIGEST_ALG,
      value: manifestDigest.digestHex,
    },
    authPolicy,
    attachments: {
      publicKeys,
      signatures,
      timestamps,
    },
  };
}

export function canonicalizeManifestBundle(bundle) {
  const normalized = normalizeManifestBundle(bundle);
  const canonical = canonicalizeJson(normalized);
  const bytes = canonicalizeJsonToBytes(normalized);
  return {
    bundle: normalized,
    canonical,
    bytes,
    digestHex: toHex(sha3_512(bytes)),
    manifestBytes: computeManifestDigest(normalized.manifest).bytes,
    manifestDigestHex: normalized.manifestDigest.value,
  };
}

export function parseManifestBundleBytes(bundleBytes, options = {}) {
  if (!(bundleBytes instanceof Uint8Array)) {
    throw new Error('bundleBytes must be Uint8Array');
  }
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bundleBytes));
  } catch (error) {
    throw new Error(`Invalid manifest bundle JSON: ${error?.message || error}`);
  }
  const canonicalized = canonicalizeManifestBundle(parsed);
  if (options.requireCanonical !== false) {
    assertCanonicalBytes(bundleBytes, canonicalized.bytes, 'Manifest bundle');
  }
  return canonicalized;
}

export function buildInitialManifestBundle({ manifest, authPolicy }) {
  return normalizeManifestBundle({
    type: MANIFEST_BUNDLE_TYPE,
    version: MANIFEST_BUNDLE_VERSION,
    bundleCanonicalization: QV_CANONICALIZATION_LABEL,
    manifestCanonicalization: QV_CANONICALIZATION_LABEL,
    manifest,
    manifestDigest: {
      alg: MANIFEST_DIGEST_ALG,
      value: computeManifestDigest(manifest).digestHex,
    },
    authPolicy,
    attachments: {
      publicKeys: [],
      signatures: [],
      timestamps: [],
    },
  });
}
