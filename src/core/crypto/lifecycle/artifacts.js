import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import {
  slh_dsa_shake_128s,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { base64ToBytes, bytesEqual, digestSha256, toHex } from '../bytes.js';
import { getSignatureSuiteInfo, normalizeSignatureSuite } from '../auth/signature-suites.js';
import {
  normalizeAuthPolicy,
  computeAuthPolicyCommitment,
  assertAuthPolicyCommitment,
  validateAuthPolicyCommitmentShape,
} from '../manifest/auth-policy.js';
import {
  BUNDLE_CANONICALIZATION_LABEL,
  MANIFEST_CANONICALIZATION_LABEL,
  canonicalizeJson,
  canonicalizeJsonToBytes,
} from '../manifest/jcs.js';
import { parseJsonBytesStrict } from '../manifest/strict-json.js';
import {
  assertExactKeys,
  ensureExactString,
  ensureHex,
  ensureInteger,
  ensureObject,
  ensureOptionalString,
  ensureSafeInteger,
  ensureString,
} from '../manifest/validation.js';
import {
  AAD_POLICY_ID_V1,
  CRYPTO_PROFILE_ID_V2,
  KDF_TREE_ID_V2,
  NONCE_POLICY_PER_CHUNK_V3,
  getCryptoProfile,
  getNonceContractForAeadMode,
} from '../policy.js';

export const ARCHIVE_STATE_SCHEMA = 'quantum-vault-archive-state-descriptor/v1';
export const COHORT_BINDING_SCHEMA = 'quantum-vault-cohort-binding/v1';
export const TRANSITION_RECORD_SCHEMA = 'quantum-vault-transition-record/v1';
export const SOURCE_EVIDENCE_SCHEMA = 'quantum-vault-source-evidence/v1';
export const LIFECYCLE_BUNDLE_TYPE = 'QV-Lifecycle-Bundle';

export const ARCHIVE_STATE_VERSION = 1;
export const COHORT_BINDING_VERSION = 1;
export const TRANSITION_RECORD_VERSION = 1;
export const SOURCE_EVIDENCE_VERSION = 1;
export const LIFECYCLE_BUNDLE_VERSION = 1;

export const ARCHIVE_STATE_CANONICALIZATION = MANIFEST_CANONICALIZATION_LABEL;
export const COHORT_BINDING_CANONICALIZATION = MANIFEST_CANONICALIZATION_LABEL;
export const TRANSITION_RECORD_CANONICALIZATION = MANIFEST_CANONICALIZATION_LABEL;
export const SOURCE_EVIDENCE_CANONICALIZATION = MANIFEST_CANONICALIZATION_LABEL;
export const LIFECYCLE_BUNDLE_CANONICALIZATION = BUNDLE_CANONICALIZATION_LABEL;

export const ARCHIVE_STATE_TYPE_DEFAULT = 'archive-state';
export const COHORT_TYPE_DEFAULT = 'shard-cohort';
export const TRANSITION_TYPE_DEFAULT = 'same-state-resharing';
export const SOURCE_EVIDENCE_TYPE_DEFAULT = 'source-evidence';

export const SHA3_512_ALG = 'SHA3-512';
export const SHA3_256_ALG = 'SHA3-256';
export const SHA_256_ALG = 'SHA-256';
export const PRIMARY_ANCHOR = 'qencHash';
export const CONTAINER_ID_ROLE = 'secondary-header-id';
export const CONTAINER_ID_ALG = 'SHA3-512(qenc-header-bytes)';
export const REED_SOLOMON_CODEC_ID = 'QV-RS-ErasureCodes-v1';
export const SHARD_BODY_DEFINITION_ID = 'QV-QCONT-SHARDBODY-v1';
export const SHARE_COMMITMENT_INPUT = 'raw-shamir-share-bytes';

const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ISO_8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const KTY_VALUES = new Set(['ml-dsa-public-key', 'slh-dsa-public-key', 'ed25519-public-key']);
const PUBLIC_KEY_ENCODINGS = new Set(['base64', 'stellar-address']);
const SIGNATURE_FORMATS = new Set(['qsig', 'stellar-sig']);
const SIGNATURE_FAMILIES = new Set(['archive-approval', 'maintenance', 'source-evidence']);
const TARGET_TYPES = new Set(['archive-state', 'transition-record', 'source-evidence']);
const BODY_DEFINITION_INCLUDES = Object.freeze(['fragment-len32-stream']);
const BODY_DEFINITION_EXCLUDES = Object.freeze([
  'qcont-header',
  'embedded-archive-state',
  'embedded-archive-state-digest',
  'embedded-cohort-binding',
  'embedded-cohort-binding-digest',
  'embedded-lifecycle-bundle',
  'embedded-lifecycle-bundle-digest',
  'external-signatures',
]);
const SOURCE_DIGEST_ALLOWED_ALGS = new Set([SHA3_512_ALG, SHA3_256_ALG, SHA_256_ALG]);
const PQ_PUBLIC_KEY_LENGTHS = Object.freeze({
  'mldsa-44': ml_dsa44.lengths.publicKey,
  'mldsa-65': ml_dsa65.lengths.publicKey,
  'mldsa-87': ml_dsa87.lengths.publicKey,
  'slhdsa-shake-128s': slh_dsa_shake_128s.lengths.publicKey,
  'slhdsa-shake-192s': slh_dsa_shake_192s.lengths.publicKey,
  'slhdsa-shake-256s': slh_dsa_shake_256s.lengths.publicKey,
  'slhdsa-shake-256f': slh_dsa_shake_256f.lengths.publicKey,
});
const STELLAR_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STRKEY_VERSION_ED25519_PUBLIC = 6 << 3;

function assertCanonicalBytes(bytes, canonicalBytes, field, canonicalizationLabel) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error(`${field} bytes must be Uint8Array`);
  }
  if (bytes.length !== canonicalBytes.length || !bytesEqual(bytes, canonicalBytes)) {
    throw new Error(`${field} is not ${canonicalizationLabel} canonical JSON`);
  }
}

function ensureNullableHex(value, field, expectedLength) {
  if (value == null) return null;
  return ensureHex(value, field, expectedLength);
}

function ensureNullableString(value, field) {
  if (value == null) return null;
  return ensureString(value, field);
}

function ensureStringArray(value, field) {
  if (!Array.isArray(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value.map((entry, index) => ensureString(entry, `${field}[${index}]`));
}

function assertExactStringArray(value, expected, field) {
  const actual = ensureStringArray(value, field);
  if (actual.length !== expected.length) {
    throw new Error(`Invalid ${field}`);
  }
  for (let i = 0; i < expected.length; i += 1) {
    if (actual[i] !== expected[i]) {
      throw new Error(`Invalid ${field}`);
    }
  }
  return actual;
}

function ensureArray(value, field) {
  if (!Array.isArray(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function ensureBase64String(value, field) {
  const text = ensureString(value, field);
  if (!BASE64_RE.test(text)) {
    throw new Error(`Invalid ${field}`);
  }
  return text;
}

function normalizeIso8601(value, field) {
  const text = ensureString(value, field);
  const ts = Date.parse(text);
  if (Number.isNaN(ts)) {
    throw new Error(`Invalid ${field}`);
  }
  const normalized = new Date(ts).toISOString();
  if (!ISO_8601_RE.test(normalized)) {
    throw new Error(`Invalid ${field}`);
  }
  return normalized;
}

function normalizeDigestObject(value, field, { expectedAlg = null, expectedValueLength = null } = {}) {
  const source = ensureObject(value, field);
  assertExactKeys(source, ['alg', 'value'], [], field);
  const alg = ensureString(source.alg, `${field}.alg`);
  if (expectedAlg != null && alg !== expectedAlg) {
    throw new Error(`Invalid ${field}.alg`);
  }
  return {
    alg,
    value: ensureHex(source.value, `${field}.value`, expectedValueLength),
  };
}

function normalizeDigestArray(value, field) {
  const arr = ensureArray(value, field);
  if (arr.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return arr.map((entry, index) => {
    const digest = normalizeDigestObject(entry, `${field}[${index}]`);
    if (!SOURCE_DIGEST_ALLOWED_ALGS.has(digest.alg)) {
      throw new Error(`Unsupported ${field}[${index}].alg`);
    }
    const expectedLength = digest.alg === SHA3_512_ALG ? 128 : 64;
    if (digest.value.length !== expectedLength) {
      throw new Error(`Invalid ${field}[${index}].value`);
    }
    return digest;
  });
}

function normalizeJsonObject(value, field) {
  const obj = ensureObject(value, field);
  return obj;
}

function crc16Xmodem(bytes) {
  let crc = 0x0000;
  for (let i = 0; i < bytes.length; i += 1) {
    crc ^= bytes[i] << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      if ((crc & 0x8000) !== 0) crc = ((crc << 1) ^ 0x1021) & 0xffff;
      else crc = (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function base32Decode(text) {
  const clean = String(text || '').trim().replace(/=+$/g, '');
  if (!clean) {
    throw new Error('Invalid bundled public key');
  }
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < clean.length; i += 1) {
    const index = STELLAR_BASE32_ALPHABET.indexOf(clean[i]);
    if (index < 0) {
      throw new Error('Invalid bundled public key');
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

function decodeStellarAddress(value) {
  const text = String(value || '').trim();
  if (text.length !== 56 || !text.startsWith('G') || !/^[A-Z2-7]+$/.test(text)) {
    throw new Error('Invalid bundled public key');
  }
  const decoded = base32Decode(text);
  if (decoded.length < 3) {
    throw new Error('Invalid bundled public key');
  }
  const payload = decoded.subarray(0, decoded.length - 2);
  const checksumBytes = decoded.subarray(decoded.length - 2);
  const expectedCrc = crc16Xmodem(payload);
  const actualCrc = checksumBytes[0] | (checksumBytes[1] << 8);
  if (expectedCrc !== actualCrc || payload[0] !== STRKEY_VERSION_ED25519_PUBLIC) {
    throw new Error('Invalid bundled public key');
  }
  const raw = payload.subarray(1);
  if (raw.length !== 32) {
    throw new Error('Invalid bundled public key');
  }
  return raw;
}

function decodeBundledPublicKey(publicKey, field) {
  if (publicKey.encoding === 'base64') {
    const bytes = base64ToBytes(publicKey.value);
    const suite = publicKey.suite;
    const expectedLength = PQ_PUBLIC_KEY_LENGTHS[suite];
    if (!Number.isInteger(expectedLength) || bytes.length !== expectedLength) {
      throw new Error(`Invalid ${field}.value`);
    }
    return bytes;
  }
  if (publicKey.encoding === 'stellar-address') {
    return decodeStellarAddress(publicKey.value);
  }
  throw new Error(`Unsupported ${field}.encoding`);
}

function normalizePublicKeyEntry(value, index) {
  const field = `attachments.publicKeys[${index}]`;
  const source = ensureObject(value, field);
  assertExactKeys(source, ['id', 'kty', 'suite', 'encoding', 'value'], [], field);
  const id = ensureString(source.id, `${field}.id`);
  const kty = ensureString(source.kty, `${field}.kty`);
  if (!KTY_VALUES.has(kty)) {
    throw new Error(`Unsupported ${field}.kty`);
  }
  const suite = normalizeSignatureSuite(source.suite);
  const encoding = ensureString(source.encoding, `${field}.encoding`);
  if (!PUBLIC_KEY_ENCODINGS.has(encoding)) {
    throw new Error(`Unsupported ${field}.encoding`);
  }
  const suiteInfo = getSignatureSuiteInfo(suite);
  if (suiteInfo.publicKeyType !== kty) {
    throw new Error(`Invalid ${field}.kty`);
  }
  if (encoding === 'base64' && suite === 'ed25519') {
    throw new Error(`Invalid ${field}.encoding`);
  }
  if (encoding === 'stellar-address' && suite !== 'ed25519') {
    throw new Error(`Invalid ${field}.encoding`);
  }
  const entry = {
    id,
    kty,
    suite,
    encoding,
    value: encoding === 'base64'
      ? ensureBase64String(source.value, `${field}.value`)
      : ensureString(source.value, `${field}.value`),
  };
  decodeBundledPublicKey(entry, field);
  return entry;
}

function normalizeDetachedSignatureEntry(value, index, familyField) {
  const field = `${familyField}[${index}]`;
  const source = ensureObject(value, field);
  assertExactKeys(
    source,
    ['id', 'signatureFamily', 'format', 'suite', 'targetType', 'targetRef', 'targetDigest', 'signatureEncoding', 'signature'],
    ['publicKeyRef'],
    field
  );

  const signatureFamily = ensureString(source.signatureFamily, `${field}.signatureFamily`);
  if (!SIGNATURE_FAMILIES.has(signatureFamily)) {
    throw new Error(`Unsupported ${field}.signatureFamily`);
  }
  const format = ensureString(source.format, `${field}.format`);
  if (!SIGNATURE_FORMATS.has(format)) {
    throw new Error(`Unsupported ${field}.format`);
  }
  const suite = normalizeSignatureSuite(source.suite);
  const targetType = ensureString(source.targetType, `${field}.targetType`);
  if (!TARGET_TYPES.has(targetType)) {
    throw new Error(`Unsupported ${field}.targetType`);
  }
  if (format === 'qsig' && suite === 'ed25519') {
    throw new Error(`Invalid ${field}.suite`);
  }
  if (format === 'stellar-sig' && suite !== 'ed25519') {
    throw new Error(`Invalid ${field}.suite`);
  }
  return {
    id: ensureString(source.id, `${field}.id`),
    signatureFamily,
    format,
    suite,
    targetType,
    targetRef: ensureString(source.targetRef, `${field}.targetRef`),
    targetDigest: normalizeDigestObject(source.targetDigest, `${field}.targetDigest`, {
      expectedAlg: SHA3_512_ALG,
      expectedValueLength: 128,
    }),
    signatureEncoding: ensureExactString(source.signatureEncoding, `${field}.signatureEncoding`, 'base64'),
    signature: ensureBase64String(source.signature, `${field}.signature`),
    publicKeyRef: ensureOptionalString(source.publicKeyRef, `${field}.publicKeyRef`),
  };
}

function normalizeTimestampEntry(value, index) {
  const field = `attachments.timestamps[${index}]`;
  const source = ensureObject(value, field);
  assertExactKeys(source, ['id', 'type', 'targetRef', 'targetDigest', 'proofEncoding', 'proof'], [], field);
  return {
    id: ensureString(source.id, `${field}.id`),
    type: ensureExactString(source.type, `${field}.type`, 'opentimestamps'),
    targetRef: ensureString(source.targetRef, `${field}.targetRef`),
    targetDigest: normalizeDigestObject(source.targetDigest, `${field}.targetDigest`, {
      expectedAlg: SHA_256_ALG,
      expectedValueLength: 64,
    }),
    proofEncoding: ensureExactString(source.proofEncoding, `${field}.proofEncoding`, 'base64'),
    proof: ensureBase64String(source.proof, `${field}.proof`),
  };
}

function assertUniqueIds(entries, field) {
  const seen = new Set();
  for (const entry of entries) {
    if (seen.has(entry.id)) {
      throw new Error(`Duplicate ${field} id: ${entry.id}`);
    }
    seen.add(entry.id);
  }
}

function normalizeShardingStructure(value, field = 'cohortBinding.sharding') {
  const sharding = ensureObject(value, field);
  assertExactKeys(sharding, ['shamir', 'reedSolomon'], [], field);
  const shamir = ensureObject(sharding.shamir, `${field}.shamir`);
  assertExactKeys(shamir, ['threshold', 'shareCount'], [], `${field}.shamir`);
  const reedSolomon = ensureObject(sharding.reedSolomon, `${field}.reedSolomon`);
  assertExactKeys(reedSolomon, ['n', 'k', 'parity', 'codecId'], [], `${field}.reedSolomon`);
  return {
    shamir: {
      threshold: ensureSafeInteger(shamir.threshold, `${field}.shamir.threshold`, 2),
      shareCount: ensureSafeInteger(shamir.shareCount, `${field}.shamir.shareCount`, 2),
    },
    reedSolomon: {
      n: ensureSafeInteger(reedSolomon.n, `${field}.reedSolomon.n`, 2),
      k: ensureSafeInteger(reedSolomon.k, `${field}.reedSolomon.k`, 2),
      parity: ensureInteger(reedSolomon.parity, `${field}.reedSolomon.parity`, 0, 0xffffffff),
      codecId: ensureExactString(reedSolomon.codecId, `${field}.reedSolomon.codecId`, REED_SOLOMON_CODEC_ID),
    },
  };
}

function validateShardingSemantics(sharding, field = 'cohortBinding.sharding') {
  if (sharding.shamir.threshold > sharding.shamir.shareCount) {
    throw new Error(`Invalid ${field}.shamir.threshold`);
  }
  if (sharding.shamir.shareCount !== sharding.reedSolomon.n) {
    throw new Error(`Invalid ${field}.shamir.shareCount`);
  }
  if (sharding.reedSolomon.k >= sharding.reedSolomon.n) {
    throw new Error(`Invalid ${field}.reedSolomon.k`);
  }
  if (sharding.reedSolomon.parity !== sharding.reedSolomon.n - sharding.reedSolomon.k) {
    throw new Error(`Invalid ${field}.reedSolomon.parity`);
  }
}

function normalizeBodyDefinitionStructure(value, field = 'cohortBinding.bodyDefinition') {
  const source = ensureObject(value, field);
  assertExactKeys(source, ['includes', 'excludes'], [], field);
  return {
    includes: assertExactStringArray(source.includes, BODY_DEFINITION_INCLUDES, `${field}.includes`),
    excludes: assertExactStringArray(source.excludes, BODY_DEFINITION_EXCLUDES, `${field}.excludes`),
  };
}

function normalizeShareCommitment(value, field = 'cohortBinding.shareCommitment') {
  const source = ensureObject(value, field);
  assertExactKeys(source, ['hashAlg', 'input'], [], field);
  return {
    hashAlg: ensureExactString(source.hashAlg, `${field}.hashAlg`, SHA3_512_ALG),
    input: ensureExactString(source.input, `${field}.input`, SHARE_COMMITMENT_INPUT),
  };
}

function ensureHashList(value, field, expectedLength = 128) {
  const arr = ensureArray(value, field);
  if (arr.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return arr.map((entry, index) => ensureHex(entry, `${field}[${index}]`, expectedLength));
}

function normalizeArchiveStateDescriptorStructure(value) {
  const source = ensureObject(value, 'archiveState');
  if (Object.prototype.hasOwnProperty.call(source, 'stateId')) {
    throw new Error('archiveState.stateId MUST NOT be present');
  }
  assertExactKeys(source, [
    'schema',
    'version',
    'stateType',
    'canonicalization',
    'archiveId',
    'parentStateId',
    'cryptoProfileId',
    'kdfTreeId',
    'noncePolicyId',
    'nonceMode',
    'counterBits',
    'maxChunkCount',
    'aadPolicyId',
    'qenc',
    'authPolicyCommitment',
  ], [], 'archiveState');

  const qenc = ensureObject(source.qenc, 'archiveState.qenc');
  assertExactKeys(qenc, [
    'chunkSize',
    'chunkCount',
    'payloadLength',
    'hashAlg',
    'primaryAnchor',
    'qencHash',
    'containerId',
    'containerIdRole',
    'containerIdAlg',
  ], [], 'archiveState.qenc');

  return {
    schema: ensureExactString(source.schema, 'archiveState.schema', ARCHIVE_STATE_SCHEMA),
    version: ensureInteger(source.version, 'archiveState.version', 1, Number.MAX_SAFE_INTEGER),
    stateType: ensureString(source.stateType, 'archiveState.stateType'),
    canonicalization: ensureExactString(source.canonicalization, 'archiveState.canonicalization', ARCHIVE_STATE_CANONICALIZATION),
    archiveId: ensureHex(source.archiveId, 'archiveState.archiveId', 64),
    parentStateId: ensureNullableHex(source.parentStateId, 'archiveState.parentStateId', 128),
    cryptoProfileId: ensureString(source.cryptoProfileId, 'archiveState.cryptoProfileId'),
    kdfTreeId: ensureString(source.kdfTreeId, 'archiveState.kdfTreeId'),
    noncePolicyId: ensureString(source.noncePolicyId, 'archiveState.noncePolicyId'),
    nonceMode: ensureString(source.nonceMode, 'archiveState.nonceMode'),
    counterBits: ensureInteger(source.counterBits, 'archiveState.counterBits', 0, 0xffffffff),
    maxChunkCount: ensureInteger(source.maxChunkCount, 'archiveState.maxChunkCount', 1, 0xffffffff),
    aadPolicyId: ensureString(source.aadPolicyId, 'archiveState.aadPolicyId'),
    qenc: {
      chunkSize: ensureSafeInteger(qenc.chunkSize, 'archiveState.qenc.chunkSize', 1),
      chunkCount: ensureInteger(qenc.chunkCount, 'archiveState.qenc.chunkCount', 1, 0xffffffff),
      payloadLength: ensureSafeInteger(qenc.payloadLength, 'archiveState.qenc.payloadLength', 1),
      hashAlg: ensureExactString(qenc.hashAlg, 'archiveState.qenc.hashAlg', SHA3_512_ALG),
      primaryAnchor: ensureExactString(qenc.primaryAnchor, 'archiveState.qenc.primaryAnchor', PRIMARY_ANCHOR),
      qencHash: ensureHex(qenc.qencHash, 'archiveState.qenc.qencHash', 128),
      containerId: ensureHex(qenc.containerId, 'archiveState.qenc.containerId', 128),
      containerIdRole: ensureExactString(qenc.containerIdRole, 'archiveState.qenc.containerIdRole', CONTAINER_ID_ROLE),
      containerIdAlg: ensureExactString(qenc.containerIdAlg, 'archiveState.qenc.containerIdAlg', CONTAINER_ID_ALG),
    },
    authPolicyCommitment: ensureObject(source.authPolicyCommitment, 'archiveState.authPolicyCommitment'),
  };
}

function validateArchiveStateDescriptorSemantics(value) {
  const state = normalizeArchiveStateDescriptorStructure(value);
  if (state.version !== ARCHIVE_STATE_VERSION) {
    throw new Error('Unsupported archiveState.version');
  }
  const profile = getCryptoProfile(state.cryptoProfileId);
  if (state.kdfTreeId !== profile.kdfTreeId) {
    throw new Error(`archiveState.kdfTreeId does not match profile (${profile.kdfTreeId})`);
  }
  if (state.aadPolicyId !== profile.aadPolicyId) {
    throw new Error(`archiveState.aadPolicyId does not match profile (${profile.aadPolicyId})`);
  }
  const aeadMode = state.counterBits === 0 && state.maxChunkCount === 1
    ? 'single-container-aead'
    : 'per-chunk-aead';
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);
  if (state.noncePolicyId !== nonceContract.noncePolicyId) {
    throw new Error('archiveState.noncePolicyId does not match implied AEAD mode');
  }
  if (state.nonceMode !== nonceContract.nonceMode) {
    throw new Error('archiveState.nonceMode does not match implied AEAD mode');
  }
  if (state.counterBits !== nonceContract.counterBits) {
    throw new Error('archiveState.counterBits does not match implied AEAD mode');
  }
  if (state.maxChunkCount !== nonceContract.maxChunkCount) {
    throw new Error('archiveState.maxChunkCount does not match implied AEAD mode');
  }
  const authPolicyCommitment = validateAuthPolicyCommitmentShape(state.authPolicyCommitment);
  return {
    archiveState: {
      ...state,
      authPolicyCommitment,
    },
    profile,
  };
}

function normalizeCohortBindingStructure(value) {
  const source = ensureObject(value, 'cohortBinding');
  if (Object.prototype.hasOwnProperty.call(source, 'cohortId')) {
    throw new Error('cohortBinding.cohortId MUST NOT be present');
  }
  assertExactKeys(source, [
    'schema',
    'version',
    'cohortType',
    'canonicalization',
    'archiveId',
    'stateId',
    'sharding',
    'bodyDefinitionId',
    'bodyDefinition',
    'shardBodyHashAlg',
    'shardBodyHashes',
    'shareCommitment',
    'shareCommitments',
  ], [], 'cohortBinding');
  return {
    schema: ensureExactString(source.schema, 'cohortBinding.schema', COHORT_BINDING_SCHEMA),
    version: ensureInteger(source.version, 'cohortBinding.version', 1, Number.MAX_SAFE_INTEGER),
    cohortType: ensureString(source.cohortType, 'cohortBinding.cohortType'),
    canonicalization: ensureExactString(source.canonicalization, 'cohortBinding.canonicalization', COHORT_BINDING_CANONICALIZATION),
    archiveId: ensureHex(source.archiveId, 'cohortBinding.archiveId', 64),
    stateId: ensureHex(source.stateId, 'cohortBinding.stateId', 128),
    sharding: normalizeShardingStructure(source.sharding, 'cohortBinding.sharding'),
    bodyDefinitionId: ensureExactString(source.bodyDefinitionId, 'cohortBinding.bodyDefinitionId', SHARD_BODY_DEFINITION_ID),
    bodyDefinition: normalizeBodyDefinitionStructure(source.bodyDefinition, 'cohortBinding.bodyDefinition'),
    shardBodyHashAlg: ensureExactString(source.shardBodyHashAlg, 'cohortBinding.shardBodyHashAlg', SHA3_512_ALG),
    shardBodyHashes: ensureHashList(source.shardBodyHashes, 'cohortBinding.shardBodyHashes'),
    shareCommitment: normalizeShareCommitment(source.shareCommitment, 'cohortBinding.shareCommitment'),
    shareCommitments: ensureHashList(source.shareCommitments, 'cohortBinding.shareCommitments'),
  };
}

function validateCohortBindingSemantics(value) {
  const cohortBinding = normalizeCohortBindingStructure(value);
  if (cohortBinding.version !== COHORT_BINDING_VERSION) {
    throw new Error('Unsupported cohortBinding.version');
  }
  validateShardingSemantics(cohortBinding.sharding, 'cohortBinding.sharding');
  const shardCount = cohortBinding.sharding.reedSolomon.n;
  if (cohortBinding.shardBodyHashes.length !== shardCount) {
    throw new Error('cohortBinding.shardBodyHashes length mismatch');
  }
  if (cohortBinding.shareCommitments.length !== shardCount) {
    throw new Error('cohortBinding.shareCommitments length mismatch');
  }
  return { cohortBinding };
}

function normalizeTransitionRecordStructure(value) {
  const source = ensureObject(value, 'transitionRecord');
  assertExactKeys(source, [
    'schema',
    'version',
    'canonicalization',
    'transitionType',
    'archiveId',
    'fromStateId',
    'toStateId',
    'fromCohortId',
    'toCohortId',
    'fromCohortBindingDigest',
    'toCohortBindingDigest',
    'reasonCode',
    'performedAt',
    'operatorRole',
    'actorHints',
    'notes',
  ], [], 'transitionRecord');
  return {
    schema: ensureExactString(source.schema, 'transitionRecord.schema', TRANSITION_RECORD_SCHEMA),
    version: ensureInteger(source.version, 'transitionRecord.version', 1, Number.MAX_SAFE_INTEGER),
    canonicalization: ensureExactString(
      source.canonicalization,
      'transitionRecord.canonicalization',
      TRANSITION_RECORD_CANONICALIZATION
    ),
    transitionType: ensureString(source.transitionType, 'transitionRecord.transitionType'),
    archiveId: ensureHex(source.archiveId, 'transitionRecord.archiveId', 64),
    fromStateId: ensureHex(source.fromStateId, 'transitionRecord.fromStateId', 128),
    toStateId: ensureHex(source.toStateId, 'transitionRecord.toStateId', 128),
    fromCohortId: ensureHex(source.fromCohortId, 'transitionRecord.fromCohortId', 64),
    toCohortId: ensureHex(source.toCohortId, 'transitionRecord.toCohortId', 64),
    fromCohortBindingDigest: normalizeDigestObject(source.fromCohortBindingDigest, 'transitionRecord.fromCohortBindingDigest', {
      expectedAlg: SHA3_512_ALG,
      expectedValueLength: 128,
    }),
    toCohortBindingDigest: normalizeDigestObject(source.toCohortBindingDigest, 'transitionRecord.toCohortBindingDigest', {
      expectedAlg: SHA3_512_ALG,
      expectedValueLength: 128,
    }),
    reasonCode: ensureString(source.reasonCode, 'transitionRecord.reasonCode'),
    performedAt: normalizeIso8601(source.performedAt, 'transitionRecord.performedAt'),
    operatorRole: ensureString(source.operatorRole, 'transitionRecord.operatorRole'),
    actorHints: normalizeJsonObject(source.actorHints, 'transitionRecord.actorHints'),
    notes: ensureNullableString(source.notes, 'transitionRecord.notes'),
  };
}

function validateTransitionRecordSemantics(value) {
  const transitionRecord = normalizeTransitionRecordStructure(value);
  if (transitionRecord.version !== TRANSITION_RECORD_VERSION) {
    throw new Error('Unsupported transitionRecord.version');
  }
  return { transitionRecord };
}

function normalizeSourceEvidenceStructure(value) {
  const source = ensureObject(value, 'sourceEvidence');
  assertExactKeys(source, [
    'schema',
    'version',
    'sourceEvidenceType',
    'canonicalization',
    'relationType',
    'sourceObjectType',
    'sourceDigests',
    'externalSourceSignatureRefs',
    'mediaType',
  ], [], 'sourceEvidence');
  return {
    schema: ensureExactString(source.schema, 'sourceEvidence.schema', SOURCE_EVIDENCE_SCHEMA),
    version: ensureInteger(source.version, 'sourceEvidence.version', 1, Number.MAX_SAFE_INTEGER),
    sourceEvidenceType: ensureString(source.sourceEvidenceType, 'sourceEvidence.sourceEvidenceType'),
    canonicalization: ensureExactString(
      source.canonicalization,
      'sourceEvidence.canonicalization',
      SOURCE_EVIDENCE_CANONICALIZATION
    ),
    relationType: ensureString(source.relationType, 'sourceEvidence.relationType'),
    sourceObjectType: ensureString(source.sourceObjectType, 'sourceEvidence.sourceObjectType'),
    sourceDigests: normalizeDigestArray(source.sourceDigests, 'sourceEvidence.sourceDigests'),
    externalSourceSignatureRefs: ensureArray(source.externalSourceSignatureRefs, 'sourceEvidence.externalSourceSignatureRefs')
      .map((entry, index) => ensureString(entry, `sourceEvidence.externalSourceSignatureRefs[${index}]`)),
    mediaType: ensureNullableString(source.mediaType, 'sourceEvidence.mediaType'),
  };
}

function validateSourceEvidenceSemantics(value) {
  const sourceEvidence = normalizeSourceEvidenceStructure(value);
  if (sourceEvidence.version !== SOURCE_EVIDENCE_VERSION) {
    throw new Error('Unsupported sourceEvidence.version');
  }
  return { sourceEvidence };
}

function normalizeLifecycleBundleStructure(value) {
  const source = ensureObject(value, 'lifecycleBundle');
  assertExactKeys(source, [
    'type',
    'version',
    'bundleCanonicalization',
    'archiveStateCanonicalization',
    'archiveState',
    'archiveStateDigest',
    'currentCohortBinding',
    'currentCohortBindingDigest',
    'authPolicy',
    'sourceEvidence',
    'transitions',
    'attachments',
  ], [], 'lifecycleBundle');
  const attachments = ensureObject(source.attachments, 'lifecycleBundle.attachments');
  assertExactKeys(attachments, [
    'publicKeys',
    'archiveApprovalSignatures',
    'maintenanceSignatures',
    'sourceEvidenceSignatures',
    'timestamps',
  ], [], 'lifecycleBundle.attachments');
  return {
    type: ensureExactString(source.type, 'lifecycleBundle.type', LIFECYCLE_BUNDLE_TYPE),
    version: ensureInteger(source.version, 'lifecycleBundle.version', 1, Number.MAX_SAFE_INTEGER),
    bundleCanonicalization: ensureExactString(
      source.bundleCanonicalization,
      'lifecycleBundle.bundleCanonicalization',
      LIFECYCLE_BUNDLE_CANONICALIZATION
    ),
    archiveStateCanonicalization: ensureExactString(
      source.archiveStateCanonicalization,
      'lifecycleBundle.archiveStateCanonicalization',
      ARCHIVE_STATE_CANONICALIZATION
    ),
    archiveState: validateArchiveStateDescriptorObject(source.archiveState).archiveState,
    archiveStateDigest: normalizeDigestObject(source.archiveStateDigest, 'lifecycleBundle.archiveStateDigest', {
      expectedAlg: SHA3_512_ALG,
      expectedValueLength: 128,
    }),
    currentCohortBinding: validateCohortBindingObject(source.currentCohortBinding).cohortBinding,
    currentCohortBindingDigest: normalizeDigestObject(
      source.currentCohortBindingDigest,
      'lifecycleBundle.currentCohortBindingDigest',
      { expectedAlg: SHA3_512_ALG, expectedValueLength: 128 }
    ),
    authPolicy: normalizeAuthPolicy(source.authPolicy),
    sourceEvidence: ensureArray(source.sourceEvidence, 'lifecycleBundle.sourceEvidence')
      .map((entry) => validateSourceEvidenceObject(entry).sourceEvidence),
    transitions: ensureArray(source.transitions, 'lifecycleBundle.transitions')
      .map((entry) => validateTransitionRecordObject(entry).transitionRecord),
    attachments: {
      publicKeys: ensureArray(attachments.publicKeys, 'lifecycleBundle.attachments.publicKeys')
        .map((entry, index) => normalizePublicKeyEntry(entry, index)),
      archiveApprovalSignatures: ensureArray(
        attachments.archiveApprovalSignatures,
        'lifecycleBundle.attachments.archiveApprovalSignatures'
      ).map((entry, index) => normalizeDetachedSignatureEntry(entry, index, 'attachments.archiveApprovalSignatures')),
      maintenanceSignatures: ensureArray(
        attachments.maintenanceSignatures,
        'lifecycleBundle.attachments.maintenanceSignatures'
      ).map((entry, index) => normalizeDetachedSignatureEntry(entry, index, 'attachments.maintenanceSignatures')),
      sourceEvidenceSignatures: ensureArray(
        attachments.sourceEvidenceSignatures,
        'lifecycleBundle.attachments.sourceEvidenceSignatures'
      ).map((entry, index) => normalizeDetachedSignatureEntry(entry, index, 'attachments.sourceEvidenceSignatures')),
      timestamps: ensureArray(attachments.timestamps, 'lifecycleBundle.attachments.timestamps')
        .map((entry, index) => normalizeTimestampEntry(entry, index)),
    },
  };
}

function findUniquePublicKeyById(publicKeys, id) {
  const matches = publicKeys.filter((entry) => entry.id === id);
  if (matches.length !== 1) {
    throw new Error(`attachments publicKeyRef is unknown: ${id}`);
  }
  return matches[0];
}

function validateBundledPublicKeyCompatibility(signature, publicKeys, field) {
  if (!signature.publicKeyRef) return null;
  const publicKey = findUniquePublicKeyById(publicKeys, signature.publicKeyRef);
  if (publicKey.suite !== signature.suite) {
    throw new Error(`${field} publicKeyRef suite mismatch`);
  }
  if (signature.format === 'qsig') {
    if (publicKey.encoding !== 'base64' || publicKey.suite === 'ed25519') {
      throw new Error(`${field} publicKeyRef is incompatible with qsig`);
    }
  } else if (signature.format === 'stellar-sig') {
    if (publicKey.encoding !== 'stellar-address' || publicKey.suite !== 'ed25519') {
      throw new Error(`${field} publicKeyRef is incompatible with stellar-sig`);
    }
  }
  decodeBundledPublicKey(publicKey, `${field} bundled key`);
  return publicKey;
}

function validateSignatureTargetConsistency(bundle) {
  const archiveStateDigest = computeArchiveStateDigest(bundle.archiveState);
  const stateId = archiveStateDigest.value;
  const transitionTargets = new Map();
  for (const transition of bundle.transitions) {
    const digest = computeTransitionRecordDigest(transition);
    transitionTargets.set(digest.value, digest);
  }
  const sourceEvidenceTargets = new Map();
  for (const evidence of bundle.sourceEvidence) {
    const digest = computeSourceEvidenceDigest(evidence);
    sourceEvidenceTargets.set(digest.value, digest);
  }

  for (const signature of bundle.attachments.archiveApprovalSignatures) {
    if (signature.signatureFamily !== 'archive-approval') {
      throw new Error('archiveApprovalSignatures entry has wrong signatureFamily');
    }
    if (signature.targetType !== 'archive-state') {
      throw new Error('archiveApprovalSignatures entry has wrong targetType');
    }
    if (signature.targetRef !== `state:${stateId}`) {
      throw new Error('archiveApprovalSignatures targetRef mismatch');
    }
    if (signature.targetDigest.value !== archiveStateDigest.value) {
      throw new Error('archiveApprovalSignatures targetDigest mismatch');
    }
  }

  for (const signature of bundle.attachments.maintenanceSignatures) {
    if (signature.signatureFamily !== 'maintenance') {
      throw new Error('maintenanceSignatures entry has wrong signatureFamily');
    }
    if (signature.targetType !== 'transition-record') {
      throw new Error('maintenanceSignatures entry has wrong targetType');
    }
    if (!signature.targetRef.startsWith('transition:sha3-512:')) {
      throw new Error('maintenanceSignatures targetRef mismatch');
    }
    if (signature.targetRef !== `transition:sha3-512:${signature.targetDigest.value}`) {
      throw new Error('maintenanceSignatures targetRef mismatch');
    }
    if (!transitionTargets.has(signature.targetDigest.value)) {
      throw new Error('maintenanceSignatures targetDigest mismatch');
    }
  }

  for (const signature of bundle.attachments.sourceEvidenceSignatures) {
    if (signature.signatureFamily !== 'source-evidence') {
      throw new Error('sourceEvidenceSignatures entry has wrong signatureFamily');
    }
    if (signature.targetType !== 'source-evidence') {
      throw new Error('sourceEvidenceSignatures entry has wrong targetType');
    }
    if (!signature.targetRef.startsWith('source-evidence:sha3-512:')) {
      throw new Error('sourceEvidenceSignatures targetRef mismatch');
    }
    if (signature.targetRef !== `source-evidence:sha3-512:${signature.targetDigest.value}`) {
      throw new Error('sourceEvidenceSignatures targetRef mismatch');
    }
    if (!sourceEvidenceTargets.has(signature.targetDigest.value)) {
      throw new Error('sourceEvidenceSignatures targetDigest mismatch');
    }
  }
}

async function validateTimestampConsistency(bundle) {
  const signatures = [
    ...bundle.attachments.archiveApprovalSignatures,
    ...bundle.attachments.maintenanceSignatures,
    ...bundle.attachments.sourceEvidenceSignatures,
  ];
  assertUniqueIds(signatures, 'detached signature');
  const signaturesById = new Map(signatures.map((entry) => [entry.id, entry]));
  for (const timestamp of bundle.attachments.timestamps) {
    const signature = signaturesById.get(timestamp.targetRef);
    if (!signature) {
      throw new Error(`attachments.timestamps targetRef is unknown: ${timestamp.targetRef}`);
    }
    const signatureBytes = base64ToBytes(signature.signature);
    const digest = toHex(await digestSha256(signatureBytes));
    if (timestamp.targetDigest.value !== digest) {
      throw new Error('attachments.timestamps targetDigest mismatch');
    }
  }
}

async function validateLifecycleBundleSemantics(bundle) {
  const archiveStateDigest = computeArchiveStateDigest(bundle.archiveState);
  if (bundle.archiveStateDigest.value !== archiveStateDigest.value) {
    throw new Error('lifecycleBundle.archiveStateDigest mismatch');
  }
  const cohortBindingDigest = computeCohortBindingDigest(bundle.currentCohortBinding);
  if (bundle.currentCohortBindingDigest.value !== cohortBindingDigest.value) {
    throw new Error('lifecycleBundle.currentCohortBindingDigest mismatch');
  }
  if (bundle.currentCohortBinding.archiveId !== bundle.archiveState.archiveId) {
    throw new Error('lifecycleBundle archiveId mismatch');
  }
  if (bundle.currentCohortBinding.stateId !== archiveStateDigest.value) {
    throw new Error('lifecycleBundle currentCohortBinding.stateId mismatch');
  }
  assertAuthPolicyCommitment(bundle.archiveState.authPolicyCommitment, bundle.authPolicy);

  assertUniqueIds(bundle.attachments.publicKeys, 'publicKey');
  assertUniqueIds(bundle.attachments.timestamps, 'timestamp');
  const allSignatureEntries = [
    ...bundle.attachments.archiveApprovalSignatures,
    ...bundle.attachments.maintenanceSignatures,
    ...bundle.attachments.sourceEvidenceSignatures,
  ];
  assertUniqueIds(allSignatureEntries, 'detached signature');

  for (const signature of bundle.attachments.archiveApprovalSignatures) {
    validateBundledPublicKeyCompatibility(signature, bundle.attachments.publicKeys, 'archiveApprovalSignatures');
  }
  for (const signature of bundle.attachments.maintenanceSignatures) {
    validateBundledPublicKeyCompatibility(signature, bundle.attachments.publicKeys, 'maintenanceSignatures');
  }
  for (const signature of bundle.attachments.sourceEvidenceSignatures) {
    validateBundledPublicKeyCompatibility(signature, bundle.attachments.publicKeys, 'sourceEvidenceSignatures');
  }

  validateSignatureTargetConsistency(bundle);
  await validateTimestampConsistency(bundle);
  return { lifecycleBundle: bundle };
}

function normalizeLifecycleBundle(value) {
  return normalizeLifecycleBundleStructure(value);
}

function canonicalizeParsedArtifact(bytes, field, canonicalizer) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error(`${field}Bytes must be Uint8Array`);
  }
  let parsed;
  try {
    parsed = parseJsonBytesStrict(bytes);
  } catch (error) {
    throw new Error(`Invalid ${field} JSON: ${error?.message || error}`);
  }
  const canonicalized = canonicalizer(parsed);
  assertCanonicalBytes(bytes, canonicalized.bytes, field, canonicalized.canonicalizationLabel);
  return canonicalized;
}

async function canonicalizeParsedArtifactAsync(bytes, field, canonicalizer) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error(`${field}Bytes must be Uint8Array`);
  }
  let parsed;
  try {
    parsed = parseJsonBytesStrict(bytes);
  } catch (error) {
    throw new Error(`Invalid ${field} JSON: ${error?.message || error}`);
  }
  const canonicalized = await canonicalizer(parsed);
  assertCanonicalBytes(bytes, canonicalized.bytes, field, canonicalized.canonicalizationLabel);
  return canonicalized;
}

export function validateArchiveStateDescriptorObject(value) {
  return validateArchiveStateDescriptorSemantics(value);
}

export function canonicalizeArchiveStateDescriptor(value) {
  const validated = validateArchiveStateDescriptorObject(value);
  const canonical = canonicalizeJson(validated.archiveState);
  const bytes = canonicalizeJsonToBytes(validated.archiveState);
  return {
    archiveState: validated.archiveState,
    canonical,
    bytes,
    digest: {
      alg: SHA3_512_ALG,
      value: toHex(sha3_512(bytes)),
    },
    stateId: toHex(sha3_512(bytes)),
    canonicalizationLabel: ARCHIVE_STATE_CANONICALIZATION,
  };
}

export function parseArchiveStateDescriptorBytes(bytes) {
  return canonicalizeParsedArtifact(bytes, 'Archive state descriptor', canonicalizeArchiveStateDescriptor);
}

export function validateCohortBindingObject(value) {
  return validateCohortBindingSemantics(value);
}

export function canonicalizeCohortBinding(value) {
  const validated = validateCohortBindingObject(value);
  const canonical = canonicalizeJson(validated.cohortBinding);
  const bytes = canonicalizeJsonToBytes(validated.cohortBinding);
  return {
    cohortBinding: validated.cohortBinding,
    canonical,
    bytes,
    digest: {
      alg: SHA3_512_ALG,
      value: toHex(sha3_512(bytes)),
    },
    canonicalizationLabel: COHORT_BINDING_CANONICALIZATION,
  };
}

export function parseCohortBindingBytes(bytes) {
  return canonicalizeParsedArtifact(bytes, 'Cohort binding', canonicalizeCohortBinding);
}

export function validateTransitionRecordObject(value) {
  return validateTransitionRecordSemantics(value);
}

export function canonicalizeTransitionRecord(value) {
  const validated = validateTransitionRecordObject(value);
  const canonical = canonicalizeJson(validated.transitionRecord);
  const bytes = canonicalizeJsonToBytes(validated.transitionRecord);
  return {
    transitionRecord: validated.transitionRecord,
    canonical,
    bytes,
    digest: {
      alg: SHA3_512_ALG,
      value: toHex(sha3_512(bytes)),
    },
    canonicalizationLabel: TRANSITION_RECORD_CANONICALIZATION,
  };
}

export function parseTransitionRecordBytes(bytes) {
  return canonicalizeParsedArtifact(bytes, 'Transition record', canonicalizeTransitionRecord);
}

export function validateSourceEvidenceObject(value) {
  return validateSourceEvidenceSemantics(value);
}

export function canonicalizeSourceEvidence(value) {
  const validated = validateSourceEvidenceObject(value);
  const canonical = canonicalizeJson(validated.sourceEvidence);
  const bytes = canonicalizeJsonToBytes(validated.sourceEvidence);
  return {
    sourceEvidence: validated.sourceEvidence,
    canonical,
    bytes,
    digest: {
      alg: SHA3_512_ALG,
      value: toHex(sha3_512(bytes)),
    },
    canonicalizationLabel: SOURCE_EVIDENCE_CANONICALIZATION,
  };
}

export function parseSourceEvidenceBytes(bytes) {
  return canonicalizeParsedArtifact(bytes, 'Source evidence', canonicalizeSourceEvidence);
}

export async function validateLifecycleBundleObject(value) {
  const normalized = normalizeLifecycleBundle(value);
  return validateLifecycleBundleSemantics(normalized);
}

export async function canonicalizeLifecycleBundle(value) {
  const validated = await validateLifecycleBundleObject(value);
  const canonical = canonicalizeJson(validated.lifecycleBundle);
  const bytes = canonicalizeJsonToBytes(validated.lifecycleBundle);
  return {
    lifecycleBundle: validated.lifecycleBundle,
    canonical,
    bytes,
    digest: {
      alg: SHA3_512_ALG,
      value: toHex(sha3_512(bytes)),
    },
    canonicalizationLabel: LIFECYCLE_BUNDLE_CANONICALIZATION,
  };
}

export async function parseLifecycleBundleBytes(bytes) {
  return canonicalizeParsedArtifactAsync(bytes, 'Lifecycle bundle', canonicalizeLifecycleBundle);
}

export function computeArchiveStateDigest(value) {
  return canonicalizeArchiveStateDescriptor(value).digest;
}

export function deriveStateId(value) {
  return canonicalizeArchiveStateDescriptor(value).stateId;
}

export function computeCohortBindingDigest(value) {
  return canonicalizeCohortBinding(value).digest;
}

export function computeTransitionRecordDigest(value) {
  return canonicalizeTransitionRecord(value).digest;
}

export function computeSourceEvidenceDigest(value) {
  return canonicalizeSourceEvidence(value).digest;
}

export function canonicalizeCohortIdPreimage({ archiveId, stateId, cohortBindingDigest }) {
  const digest = normalizeDigestObject(cohortBindingDigest, 'cohortIdPreimage.cohortBindingDigest', {
    expectedAlg: SHA3_512_ALG,
    expectedValueLength: 128,
  });
  const preimage = {
    type: 'quantum-vault-cohort-id-preimage/v1',
    archiveId: ensureHex(archiveId, 'cohortIdPreimage.archiveId', 64),
    stateId: ensureHex(stateId, 'cohortIdPreimage.stateId', 128),
    cohortBindingDigest: digest,
  };
  const canonical = canonicalizeJson(preimage);
  const bytes = canonicalizeJsonToBytes(preimage);
  return {
    preimage,
    canonical,
    bytes,
  };
}

export function deriveCohortId({ archiveId, stateId, cohortBindingDigest }) {
  return toHex(sha3_256(canonicalizeCohortIdPreimage({ archiveId, stateId, cohortBindingDigest }).bytes));
}

export function generateArchiveId(randomBytes = null) {
  const bytes = randomBytes ?? globalThis.crypto?.getRandomValues(new Uint8Array(32));
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('archiveId generation requires 32 random bytes');
  }
  return toHex(bytes);
}

export function buildArchiveStateDescriptor(params) {
  const authPolicy = normalizeAuthPolicy(params.authPolicy || {
    level: params.authPolicyLevel || 'strong-pq-signature',
    minValidSignatures: params.minValidSignatures ?? 1,
  });
  const profile = getCryptoProfile(params.cryptoProfileId || CRYPTO_PROFILE_ID_V2);
  const aeadMode = params.counterBits === 0 && params.maxChunkCount === 1
    ? 'single-container-aead'
    : 'per-chunk-aead';
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);
  const archiveState = {
    schema: ARCHIVE_STATE_SCHEMA,
    version: ARCHIVE_STATE_VERSION,
    stateType: params.stateType || ARCHIVE_STATE_TYPE_DEFAULT,
    canonicalization: ARCHIVE_STATE_CANONICALIZATION,
    archiveId: ensureHex(params.archiveId, 'archiveId', 64),
    parentStateId: ensureNullableHex(params.parentStateId, 'parentStateId', 128),
    cryptoProfileId: profile.cryptoProfileId,
    kdfTreeId: params.kdfTreeId || profile.kdfTreeId,
    noncePolicyId: params.noncePolicyId || nonceContract.noncePolicyId,
    nonceMode: params.nonceMode || nonceContract.nonceMode,
    counterBits: params.counterBits ?? nonceContract.counterBits,
    maxChunkCount: params.maxChunkCount ?? nonceContract.maxChunkCount,
    aadPolicyId: params.aadPolicyId || profile.aadPolicyId,
    qenc: {
      chunkSize: ensureSafeInteger(params.chunkSize, 'chunkSize', 1),
      chunkCount: ensureInteger(params.chunkCount, 'chunkCount', 1, 0xffffffff),
      payloadLength: ensureSafeInteger(params.payloadLength, 'payloadLength', 1),
      hashAlg: SHA3_512_ALG,
      primaryAnchor: PRIMARY_ANCHOR,
      qencHash: ensureHex(params.qencHash, 'qencHash', 128),
      containerId: ensureHex(params.containerId, 'containerId', 128),
      containerIdRole: CONTAINER_ID_ROLE,
      containerIdAlg: CONTAINER_ID_ALG,
    },
    authPolicyCommitment: computeAuthPolicyCommitment(authPolicy),
  };
  return validateArchiveStateDescriptorObject(archiveState).archiveState;
}

export function buildCohortBinding(params) {
  const cohortBinding = {
    schema: COHORT_BINDING_SCHEMA,
    version: COHORT_BINDING_VERSION,
    cohortType: params.cohortType || COHORT_TYPE_DEFAULT,
    canonicalization: COHORT_BINDING_CANONICALIZATION,
    archiveId: ensureHex(params.archiveId, 'archiveId', 64),
    stateId: ensureHex(params.stateId, 'stateId', 128),
    sharding: {
      shamir: {
        threshold: ensureSafeInteger(params.shamirThreshold, 'shamirThreshold', 2),
        shareCount: ensureSafeInteger(params.shamirShareCount, 'shamirShareCount', 2),
      },
      reedSolomon: {
        n: ensureSafeInteger(params.rsN, 'rsN', 2),
        k: ensureSafeInteger(params.rsK, 'rsK', 2),
        parity: ensureInteger(params.rsParity, 'rsParity', 0, 0xffffffff),
        codecId: ensureExactString(params.rsCodecId || REED_SOLOMON_CODEC_ID, 'rsCodecId', REED_SOLOMON_CODEC_ID),
      },
    },
    bodyDefinitionId: SHARD_BODY_DEFINITION_ID,
    bodyDefinition: {
      includes: [...BODY_DEFINITION_INCLUDES],
      excludes: [...BODY_DEFINITION_EXCLUDES],
    },
    shardBodyHashAlg: SHA3_512_ALG,
    shardBodyHashes: ensureHashList(params.shardBodyHashes, 'shardBodyHashes'),
    shareCommitment: {
      hashAlg: SHA3_512_ALG,
      input: SHARE_COMMITMENT_INPUT,
    },
    shareCommitments: ensureHashList(params.shareCommitments, 'shareCommitments'),
  };
  return validateCohortBindingObject(cohortBinding).cohortBinding;
}

export function buildTransitionRecord(params) {
  const transitionRecord = {
    schema: TRANSITION_RECORD_SCHEMA,
    version: TRANSITION_RECORD_VERSION,
    canonicalization: TRANSITION_RECORD_CANONICALIZATION,
    transitionType: params.transitionType || TRANSITION_TYPE_DEFAULT,
    archiveId: ensureHex(params.archiveId, 'archiveId', 64),
    fromStateId: ensureHex(params.fromStateId, 'fromStateId', 128),
    toStateId: ensureHex(params.toStateId, 'toStateId', 128),
    fromCohortId: ensureHex(params.fromCohortId, 'fromCohortId', 64),
    toCohortId: ensureHex(params.toCohortId, 'toCohortId', 64),
    fromCohortBindingDigest: normalizeDigestObject(params.fromCohortBindingDigest, 'fromCohortBindingDigest', {
      expectedAlg: SHA3_512_ALG,
      expectedValueLength: 128,
    }),
    toCohortBindingDigest: normalizeDigestObject(params.toCohortBindingDigest, 'toCohortBindingDigest', {
      expectedAlg: SHA3_512_ALG,
      expectedValueLength: 128,
    }),
    reasonCode: ensureString(params.reasonCode, 'reasonCode'),
    performedAt: normalizeIso8601(params.performedAt, 'performedAt'),
    operatorRole: ensureString(params.operatorRole, 'operatorRole'),
    actorHints: normalizeJsonObject(params.actorHints || {}, 'actorHints'),
    notes: ensureNullableString(params.notes, 'notes'),
  };
  return validateTransitionRecordObject(transitionRecord).transitionRecord;
}

export function buildSourceEvidence(params) {
  const sourceEvidence = {
    schema: SOURCE_EVIDENCE_SCHEMA,
    version: SOURCE_EVIDENCE_VERSION,
    sourceEvidenceType: params.sourceEvidenceType || SOURCE_EVIDENCE_TYPE_DEFAULT,
    canonicalization: SOURCE_EVIDENCE_CANONICALIZATION,
    relationType: ensureString(params.relationType, 'relationType'),
    sourceObjectType: ensureString(params.sourceObjectType, 'sourceObjectType'),
    sourceDigests: normalizeDigestArray(params.sourceDigests, 'sourceDigests'),
    externalSourceSignatureRefs: ensureArray(params.externalSourceSignatureRefs || [], 'externalSourceSignatureRefs')
      .map((entry, index) => ensureString(entry, `externalSourceSignatureRefs[${index}]`)),
    mediaType: ensureNullableString(params.mediaType, 'mediaType'),
  };
  return validateSourceEvidenceObject(sourceEvidence).sourceEvidence;
}

export async function buildLifecycleBundle(params) {
  const archiveState = validateArchiveStateDescriptorObject(params.archiveState).archiveState;
  const currentCohortBinding = validateCohortBindingObject(params.currentCohortBinding).cohortBinding;
  const authPolicy = normalizeAuthPolicy(params.authPolicy);
  const lifecycleBundle = {
    type: LIFECYCLE_BUNDLE_TYPE,
    version: LIFECYCLE_BUNDLE_VERSION,
    bundleCanonicalization: LIFECYCLE_BUNDLE_CANONICALIZATION,
    archiveStateCanonicalization: ARCHIVE_STATE_CANONICALIZATION,
    archiveState,
    archiveStateDigest: computeArchiveStateDigest(archiveState),
    currentCohortBinding,
    currentCohortBindingDigest: computeCohortBindingDigest(currentCohortBinding),
    authPolicy,
    sourceEvidence: ensureArray(params.sourceEvidence || [], 'sourceEvidence').map((entry) => validateSourceEvidenceObject(entry).sourceEvidence),
    transitions: ensureArray(params.transitions || [], 'transitions').map((entry) => validateTransitionRecordObject(entry).transitionRecord),
    attachments: {
      publicKeys: ensureArray(params.attachments?.publicKeys || [], 'attachments.publicKeys').map((entry, index) => normalizePublicKeyEntry(entry, index)),
      archiveApprovalSignatures: ensureArray(params.attachments?.archiveApprovalSignatures || [], 'attachments.archiveApprovalSignatures')
        .map((entry, index) => normalizeDetachedSignatureEntry(entry, index, 'attachments.archiveApprovalSignatures')),
      maintenanceSignatures: ensureArray(params.attachments?.maintenanceSignatures || [], 'attachments.maintenanceSignatures')
        .map((entry, index) => normalizeDetachedSignatureEntry(entry, index, 'attachments.maintenanceSignatures')),
      sourceEvidenceSignatures: ensureArray(params.attachments?.sourceEvidenceSignatures || [], 'attachments.sourceEvidenceSignatures')
        .map((entry, index) => normalizeDetachedSignatureEntry(entry, index, 'attachments.sourceEvidenceSignatures')),
      timestamps: ensureArray(params.attachments?.timestamps || [], 'attachments.timestamps')
        .map((entry, index) => normalizeTimestampEntry(entry, index)),
    },
  };
  return (await validateLifecycleBundleObject(lifecycleBundle)).lifecycleBundle;
}

export const LIFECYCLE_DEFAULTS = Object.freeze({
  cryptoProfileId: CRYPTO_PROFILE_ID_V2,
  kdfTreeId: KDF_TREE_ID_V2,
  noncePolicyId: NONCE_POLICY_PER_CHUNK_V3,
  aadPolicyId: AAD_POLICY_ID_V1,
});
