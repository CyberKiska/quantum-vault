import { sha3_512 } from '@noble/hashes/sha3.js';
import { base64ToBytes, toHex } from '../bytes.js';
import { getSignatureSuiteInfo, normalizeSignatureSuite } from '../auth/signature-suites.js';
import { computeDetachedSignatureIdentityDigestHex } from '../auth/signature-identity.js';
import {
  assertAuthPolicyCommitment,
  AUTH_POLICY_COMMITMENT_ALG,
  computeAuthPolicyCommitment,
  normalizeAuthPolicy,
  recoverCommittedAuthPolicy,
  validateAuthPolicyCommitmentShape,
} from './auth-policy.js';
import { canonicalizeArchiveManifest } from './archive-manifest.js';
import {
  BUNDLE_CANONICALIZATION_LABEL,
  MANIFEST_CANONICALIZATION_LABEL,
  canonicalizeJson,
  canonicalizeJsonToBytes,
} from './jcs.js';
import { parseJsonBytesStrict } from './strict-json.js';
import { ensureObject, ensureString, ensureOptionalString, ensureInteger, ensureHex, assertExactKeys } from './validation.js';

export const MANIFEST_BUNDLE_TYPE = 'QV-Manifest-Bundle';
export const MANIFEST_BUNDLE_VERSION = 2;
export const MANIFEST_DIGEST_ALG = 'SHA3-512';

const SIGNATURE_FORMATS = new Set(['qsig', 'stellar-sig']);
const TIMESTAMP_TYPES = new Set(['opentimestamps']);
const PUBLIC_KEY_ENCODINGS = new Set(['base64', 'stellar-address']);

function assertCanonicalBytes(bytes, canonicalBytes, field) {
  if (bytes.length !== canonicalBytes.length) {
    throw new Error(`${field} is not ${BUNDLE_CANONICALIZATION_LABEL} canonical JSON`);
  }
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] !== canonicalBytes[i]) {
      throw new Error(`${field} is not ${BUNDLE_CANONICALIZATION_LABEL} canonical JSON`);
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

function assertUniqueSignatureProofs(signatures) {
  const seen = new Map();
  for (const signature of signatures) {
    if (signature.signatureEncoding !== 'base64') {
      throw new Error(`Unsupported signatureEncoding for ${signature.id}: ${signature.signatureEncoding}`);
    }
    const digestHex = computeDetachedSignatureIdentityDigestHex({
      format: signature.format,
      signatureBytes: base64ToBytes(signature.signature),
    });
    const existingId = seen.get(digestHex);
    if (existingId) {
      throw new Error(`Duplicate signature proof detected across bundle signatures: ${existingId}, ${signature.id}`);
    }
    seen.set(digestHex, signature.id);
  }
}

export function computeManifestDigest(manifest) {
  const canonicalManifest = canonicalizeArchiveManifest(manifest);
  return {
    manifest: canonicalManifest.manifest,
    canonical: canonicalManifest.canonical,
    bytes: canonicalManifest.bytes,
    digestHex: canonicalManifest.digestHex,
  };
}

function normalizePublicKey(entry, index) {
  const source = ensureObject(entry, `attachments.publicKeys[${index}]`);
  assertExactKeys(source, ['id', 'kty', 'suite', 'encoding', 'value'], ['legacy'], `attachments.publicKeys[${index}]`);

  const suite = normalizeSignatureSuite(source.suite);
  const suiteInfo = getSignatureSuiteInfo(suite);
  const kty = ensureString(source.kty, `attachments.publicKeys[${index}].kty`);
  const encoding = ensureString(source.encoding, `attachments.publicKeys[${index}].encoding`);
  if (!PUBLIC_KEY_ENCODINGS.has(encoding)) {
    throw new Error(`Unsupported attachments.publicKeys[${index}].encoding`);
  }
  if (kty !== suiteInfo.publicKeyType) {
    throw new Error(`attachments.publicKeys[${index}].kty does not match suite ${suite}`);
  }
  if (encoding === 'base64' && suite === 'ed25519') {
    throw new Error(`attachments.publicKeys[${index}] ed25519 keys must use stellar-address encoding`);
  }
  if (encoding === 'stellar-address' && suite !== 'ed25519') {
    throw new Error(`attachments.publicKeys[${index}] stellar-address encoding is only valid for ed25519 keys`);
  }
  return {
    id: ensureString(source.id, `attachments.publicKeys[${index}].id`),
    kty,
    suite,
    encoding,
    value: ensureString(source.value, `attachments.publicKeys[${index}].value`),
    legacy: source.legacy === true,
  };
}

function normalizeSignature(entry, index, manifestDigestHex) {
  const source = ensureObject(entry, `attachments.signatures[${index}]`);
  assertExactKeys(
    source,
    ['id', 'format', 'suite', 'target', 'signatureEncoding', 'signature'],
    ['publicKeyRef', 'legacy'],
    `attachments.signatures[${index}]`
  );

  const format = ensureString(source.format, `attachments.signatures[${index}].format`);
  if (!SIGNATURE_FORMATS.has(format)) {
    throw new Error(`Unsupported attachments.signatures[${index}].format`);
  }
  const target = ensureObject(source.target, `attachments.signatures[${index}].target`);
  assertExactKeys(target, ['type', 'digestAlg', 'digestValue'], [], `attachments.signatures[${index}].target`);
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
  const suite = normalizeSignatureSuite(source.suite);
  const signatureEncoding = ensureString(source.signatureEncoding, `attachments.signatures[${index}].signatureEncoding`);
  if (signatureEncoding !== 'base64') {
    throw new Error(`Unsupported attachments.signatures[${index}].signatureEncoding`);
  }
  return {
    id: ensureString(source.id, `attachments.signatures[${index}].id`),
    format,
    suite,
    target: {
      type: 'canonical-manifest',
      digestAlg: MANIFEST_DIGEST_ALG,
      digestValue,
    },
    signatureEncoding,
    signature: ensureString(source.signature, `attachments.signatures[${index}].signature`),
    publicKeyRef: ensureOptionalString(source.publicKeyRef, `attachments.signatures[${index}].publicKeyRef`),
    legacy: source.legacy === true,
  };
}

export function getSignaturePublicKeyRefCompatibilityError(signature, publicKey) {
  if (!signature?.publicKeyRef) return '';
  if (!publicKey) {
    return `attachments.signatures publicKeyRef is unknown: ${signature.publicKeyRef}`;
  }

  if (signature.format === 'qsig') {
    if (publicKey.encoding !== 'base64') {
      return 'attachments.signatures publicKeyRef for qsig must reference a bundled PQ public key stored with encoding "base64"';
    }
    if (publicKey.suite === 'ed25519') {
      return 'attachments.signatures publicKeyRef for qsig must not reference an ed25519 signer';
    }
    if (publicKey.suite !== signature.suite) {
      return `attachments.signatures publicKeyRef suite mismatch for qsig: expected ${signature.suite}, got ${publicKey.suite}`;
    }
    return '';
  }

  if (signature.format === 'stellar-sig') {
    if (publicKey.encoding !== 'stellar-address') {
      return 'attachments.signatures publicKeyRef for stellar-sig must reference a bundled Stellar signer stored with encoding "stellar-address"';
    }
    if (publicKey.suite !== 'ed25519') {
      return 'attachments.signatures publicKeyRef for stellar-sig must reference an ed25519 signer';
    }
    if (signature.suite !== 'ed25519') {
      return `attachments.signatures suite mismatch for stellar-sig: expected ed25519, got ${signature.suite}`;
    }
  }

  return '';
}

function normalizeTimestamp(entry, index, signatureIds) {
  const source = ensureObject(entry, `attachments.timestamps[${index}]`);
  assertExactKeys(
    source,
    ['id', 'type', 'targetRef', 'proofEncoding', 'proof'],
    ['apparentlyComplete', 'completeProof'],
    `attachments.timestamps[${index}]`
  );

  const type = ensureString(source.type, `attachments.timestamps[${index}].type`);
  if (!TIMESTAMP_TYPES.has(type)) {
    throw new Error(`Unsupported attachments.timestamps[${index}].type`);
  }
  const targetRef = ensureString(source.targetRef, `attachments.timestamps[${index}].targetRef`);
  if (!signatureIds.has(targetRef)) {
    throw new Error(`attachments.timestamps[${index}].targetRef does not reference a known signature`);
  }
  const proofEncoding = ensureString(source.proofEncoding, `attachments.timestamps[${index}].proofEncoding`);
  if (proofEncoding !== 'base64') {
    throw new Error(`Unsupported attachments.timestamps[${index}].proofEncoding`);
  }
  return {
    id: ensureString(source.id, `attachments.timestamps[${index}].id`),
    type,
    targetRef,
    proofEncoding,
    proof: ensureString(source.proof, `attachments.timestamps[${index}].proof`),
    apparentlyComplete: source.apparentlyComplete === true || source.completeProof === true,
    completeProof: source.apparentlyComplete === true || source.completeProof === true,
  };
}

export function normalizeManifestBundle(bundle) {
  const source = ensureObject(bundle, 'bundle');
  assertExactKeys(source, [
    'type',
    'version',
    'bundleCanonicalization',
    'manifestCanonicalization',
    'manifest',
    'manifestDigest',
    'authPolicy',
    'attachments',
  ], [], 'bundle');

  if (ensureString(source.type, 'bundle.type') !== MANIFEST_BUNDLE_TYPE) {
    throw new Error('Unsupported manifest bundle type');
  }
  if (ensureInteger(source.version, 'bundle.version', 1) !== MANIFEST_BUNDLE_VERSION) {
    throw new Error('Unsupported manifest bundle version');
  }
  if (ensureString(source.bundleCanonicalization, 'bundle.bundleCanonicalization') !== BUNDLE_CANONICALIZATION_LABEL) {
    throw new Error('Unsupported bundleCanonicalization');
  }
  if (ensureString(source.manifestCanonicalization, 'bundle.manifestCanonicalization') !== MANIFEST_CANONICALIZATION_LABEL) {
    throw new Error('Unsupported manifestCanonicalization');
  }

  const manifestDigest = computeManifestDigest(source.manifest);
  const manifestDigestObj = ensureObject(source.manifestDigest, 'bundle.manifestDigest');
  assertExactKeys(manifestDigestObj, ['alg', 'value'], [], 'bundle.manifestDigest');
  if (ensureString(manifestDigestObj.alg, 'bundle.manifestDigest.alg') !== MANIFEST_DIGEST_ALG) {
    throw new Error('Unsupported bundle.manifestDigest.alg');
  }
  if (ensureHex(manifestDigestObj.value, 'bundle.manifestDigest.value', 128) !== manifestDigest.digestHex) {
    throw new Error('bundle.manifestDigest mismatch');
  }

  const authPolicy = normalizeAuthPolicy(source.authPolicy);
  assertAuthPolicyCommitment(manifestDigest.manifest.authPolicyCommitment, authPolicy);

  const attachments = ensureObject(source.attachments, 'bundle.attachments');
  assertExactKeys(attachments, ['publicKeys', 'signatures', 'timestamps'], [], 'bundle.attachments');
  if (!Array.isArray(attachments.publicKeys) || !Array.isArray(attachments.signatures) || !Array.isArray(attachments.timestamps)) {
    throw new Error('Invalid bundle.attachments');
  }

  const publicKeys = attachments.publicKeys.map((entry, index) => normalizePublicKey(entry, index));
  const signatures = attachments.signatures.map((entry, index) => normalizeSignature(entry, index, manifestDigest.digestHex));
  assertUniqueIds(publicKeys, 'publicKeys');
  assertUniqueIds(signatures, 'signatures');
  assertUniqueSignatureProofs(signatures);

  const publicKeyIds = new Set(publicKeys.map((item) => item.id));
  const publicKeysById = new Map(publicKeys.map((item) => [item.id, item]));
  for (const signature of signatures) {
    if (signature.publicKeyRef && !publicKeyIds.has(signature.publicKeyRef)) {
      throw new Error(`attachments.signatures publicKeyRef is unknown: ${signature.publicKeyRef}`);
    }
    const compatibilityError = getSignaturePublicKeyRefCompatibilityError(
      signature,
      publicKeysById.get(signature.publicKeyRef || '')
    );
    if (compatibilityError) {
      throw new Error(compatibilityError);
    }
  }

  const signatureIds = new Set(signatures.map((item) => item.id));
  const timestamps = attachments.timestamps.map((entry, index) => normalizeTimestamp(entry, index, signatureIds));
  assertUniqueIds(timestamps, 'timestamps');

  return {
    type: MANIFEST_BUNDLE_TYPE,
    version: MANIFEST_BUNDLE_VERSION,
    bundleCanonicalization: BUNDLE_CANONICALIZATION_LABEL,
    manifestCanonicalization: MANIFEST_CANONICALIZATION_LABEL,
    manifest: manifestDigest.manifest,
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
    parsed = parseJsonBytesStrict(bundleBytes);
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
    bundleCanonicalization: BUNDLE_CANONICALIZATION_LABEL,
    manifestCanonicalization: MANIFEST_CANONICALIZATION_LABEL,
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

export {
  assertAuthPolicyCommitment,
  AUTH_POLICY_COMMITMENT_ALG,
  computeAuthPolicyCommitment,
  normalizeAuthPolicy,
  recoverCommittedAuthPolicy,
  validateAuthPolicyCommitmentShape,
};
