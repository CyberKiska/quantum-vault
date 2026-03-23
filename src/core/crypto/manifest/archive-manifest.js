import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../bytes.js';
import { DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL } from '../constants.js';
import {
  AAD_POLICY_ID_V1,
  CRYPTO_PROFILE_ID_V2,
  DEFAULT_CRYPTO_PROFILE,
  KDF_TREE_ID_V2,
  NONCE_POLICY_PER_CHUNK_V3,
  assertChunkCountWithinPolicy,
  getNonceContractForAeadMode,
  getCryptoProfile,
} from '../policy.js';
import { computeAuthPolicyCommitment, validateAuthPolicyCommitmentShape } from './auth-policy.js';
import { MANIFEST_CANONICALIZATION_LABEL, canonicalizeJson, canonicalizeJsonToBytes } from './jcs.js';
import { parseJsonBytesStrict } from './strict-json.js';

const MANIFEST_SCHEMA = 'quantum-vault-archive-manifest/v3';
const MANIFEST_VERSION = 3;

const BODY_DEFINITION_INCLUDES = Object.freeze(['fragment-len32-stream']);
const BODY_DEFINITION_EXCLUDES = Object.freeze([
  'qcont-header',
  'embedded-manifest',
  'embedded-manifest-digest',
  'embedded-bundle',
  'embedded-bundle-digest',
  'external-signatures',
]);

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

function ensureInt(value, field, min = 0) {
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

function ensureHashList(values, field, expectedLength = 128) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return values.map((value, index) => ensureHex(value, `${field}[${index}]`, expectedLength));
}

function ensureStringArray(values, field) {
  if (!Array.isArray(values)) {
    throw new Error(`Invalid ${field}`);
  }
  return values.map((value, index) => ensureString(value, `${field}[${index}]`));
}

function ensureCanonicalBytes(inputBytes, canonicalBytes) {
  if (inputBytes.length !== canonicalBytes.length) return false;
  for (let i = 0; i < inputBytes.length; i += 1) {
    if (inputBytes[i] !== canonicalBytes[i]) return false;
  }
  return true;
}

function assertExactKeys(source, requiredKeys, optionalKeys, field) {
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of Object.keys(source)) {
    if (!allowed.has(key)) {
      throw new Error(`Unknown ${field}.${key}`);
    }
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) {
      throw new Error(`Missing ${field}.${key}`);
    }
  }
}

function assertExactStringArray(values, expected, field) {
  const actual = ensureStringArray(values, field);
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

function validateManifestQenc(source, profile) {
  const qenc = ensureObject(source, 'qenc');
  assertExactKeys(qenc, [
    'format',
    'aeadMode',
    'ivStrategy',
    'chunkSize',
    'chunkCount',
    'payloadLength',
    'hashAlg',
    'qencHash',
    'primaryAnchor',
    'containerId',
    'containerIdRole',
    'containerIdAlg',
  ], [], 'qenc');

  const aeadMode = ensureString(qenc.aeadMode, 'qenc.aeadMode');
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);

  ensureString(qenc.format, 'qenc.format');
  ensureString(qenc.ivStrategy, 'qenc.ivStrategy');
  ensureInt(qenc.chunkSize, 'qenc.chunkSize', 1);
  const chunkCount = ensureInt(qenc.chunkCount, 'qenc.chunkCount', 1);
  ensureInt(qenc.payloadLength, 'qenc.payloadLength', 1);
  ensureHex(qenc.qencHash, 'qenc.qencHash', 128);
  ensureHex(qenc.containerId, 'qenc.containerId', 128);

  if (qenc.hashAlg !== 'SHA3-512') {
    throw new Error('Unsupported qenc.hashAlg');
  }
  if (qenc.primaryAnchor !== 'qencHash') {
    throw new Error('Unsupported qenc.primaryAnchor');
  }
  if (qenc.containerIdRole !== 'secondary-header-id') {
    throw new Error('Unsupported qenc.containerIdRole');
  }
  if (qenc.containerIdAlg !== 'SHA3-512(qenc-header-bytes)') {
    throw new Error('Unsupported qenc.containerIdAlg');
  }

  assertChunkCountWithinPolicy(chunkCount, profile, aeadMode);
  return { qenc, nonceContract };
}

function validateManifestSharding(source) {
  const sharding = ensureObject(source, 'sharding');
  assertExactKeys(sharding, ['shamir', 'reedSolomon'], [], 'sharding');

  const shamir = ensureObject(sharding.shamir, 'sharding.shamir');
  assertExactKeys(shamir, ['threshold', 'shareCount'], [], 'sharding.shamir');
  const threshold = ensureInt(shamir.threshold, 'sharding.shamir.threshold', 2);
  const shareCount = ensureInt(shamir.shareCount, 'sharding.shamir.shareCount', 2);
  if (threshold > shareCount) {
    throw new Error('Invalid sharding.shamir.threshold');
  }

  const reedSolomon = ensureObject(sharding.reedSolomon, 'sharding.reedSolomon');
  assertExactKeys(reedSolomon, ['n', 'k', 'parity', 'codecId'], [], 'sharding.reedSolomon');
  const n = ensureInt(reedSolomon.n, 'sharding.reedSolomon.n', 2);
  const k = ensureInt(reedSolomon.k, 'sharding.reedSolomon.k', 2);
  const parity = ensureInt(reedSolomon.parity, 'sharding.reedSolomon.parity', 0);
  ensureString(reedSolomon.codecId, 'sharding.reedSolomon.codecId');
  if (k >= n) {
    throw new Error('Invalid sharding.reedSolomon.k');
  }
  if (parity !== n - k) {
    throw new Error('Invalid sharding.reedSolomon.parity');
  }

  return sharding;
}

function validateShardBinding(source) {
  const shardBinding = ensureObject(source, 'shardBinding');
  assertExactKeys(
    shardBinding,
    ['bodyDefinitionId', 'bodyDefinition', 'shardBodyHashAlg'],
    ['shardBodyHashes', 'shareCommitment', 'shareCommitments'],
    'shardBinding'
  );

  if (ensureString(shardBinding.bodyDefinitionId, 'shardBinding.bodyDefinitionId') !== 'QV-QCONT-SHARDBODY-v1') {
    throw new Error('Unsupported shardBinding.bodyDefinitionId');
  }
  if (ensureString(shardBinding.shardBodyHashAlg, 'shardBinding.shardBodyHashAlg') !== 'SHA3-512') {
    throw new Error('Unsupported shardBinding.shardBodyHashAlg');
  }

  const bodyDefinition = ensureObject(shardBinding.bodyDefinition, 'shardBinding.bodyDefinition');
  assertExactKeys(bodyDefinition, ['includes', 'excludes'], [], 'shardBinding.bodyDefinition');
  assertExactStringArray(bodyDefinition.includes, BODY_DEFINITION_INCLUDES, 'shardBinding.bodyDefinition.includes');
  assertExactStringArray(bodyDefinition.excludes, BODY_DEFINITION_EXCLUDES, 'shardBinding.bodyDefinition.excludes');

  if (shardBinding.shardBodyHashes != null) {
    ensureHashList(shardBinding.shardBodyHashes, 'shardBinding.shardBodyHashes');
  }

  if (shardBinding.shareCommitment != null || shardBinding.shareCommitments != null) {
    const shareCommitment = ensureObject(shardBinding.shareCommitment, 'shardBinding.shareCommitment');
    assertExactKeys(shareCommitment, ['hashAlg', 'input'], [], 'shardBinding.shareCommitment');
    if (shareCommitment.hashAlg !== 'SHA3-512' || shareCommitment.input !== 'raw-shamir-share-bytes') {
      throw new Error('Invalid shardBinding.shareCommitment descriptor');
    }
    ensureHashList(shardBinding.shareCommitments, 'shardBinding.shareCommitments');
  }

  if (shardBinding.shardBodyHashes == null && shardBinding.shareCommitments == null) {
    throw new Error('Invalid shardBinding: expected shardBodyHashes or shareCommitments');
  }
  return shardBinding;
}

export function validateArchiveManifestObject(manifest) {
  const source = ensureObject(manifest, 'manifest');
  assertExactKeys(source, [
    'schema',
    'version',
    'manifestType',
    'canonicalization',
    'cryptoProfileId',
    'kdfTreeId',
    'noncePolicyId',
    'nonceMode',
    'counterBits',
    'maxChunkCount',
    'aadPolicyId',
    'qenc',
    'sharding',
    'authPolicyCommitment',
  ], ['shardBinding'], 'manifest');

  if (source.schema !== MANIFEST_SCHEMA || source.version !== MANIFEST_VERSION || source.manifestType !== 'archive') {
    throw new Error('Unsupported archive manifest schema/version');
  }
  if (source.canonicalization !== MANIFEST_CANONICALIZATION_LABEL) {
    throw new Error('Unsupported manifest canonicalization');
  }

  const profileId = ensureString(source.cryptoProfileId, 'manifest.cryptoProfileId');
  const profile = getCryptoProfile(profileId);

  if (source.kdfTreeId !== profile.kdfTreeId) {
    throw new Error(`Manifest kdfTreeId does not match profile (${profile.kdfTreeId})`);
  }
  if (source.aadPolicyId !== profile.aadPolicyId) {
    throw new Error(`Manifest aadPolicyId does not match profile (${profile.aadPolicyId})`);
  }

  const { nonceContract } = validateManifestQenc(source.qenc, profile);

  if (source.noncePolicyId !== nonceContract.noncePolicyId) {
    throw new Error(`Manifest noncePolicyId does not match AEAD mode ${source.qenc.aeadMode}`);
  }
  if (source.nonceMode !== nonceContract.nonceMode) {
    throw new Error(`Manifest nonceMode does not match AEAD mode ${source.qenc.aeadMode}`);
  }
  if (source.counterBits !== nonceContract.counterBits) {
    throw new Error(`Manifest counterBits does not match AEAD mode ${source.qenc.aeadMode}`);
  }
  if (source.maxChunkCount !== nonceContract.maxChunkCount) {
    throw new Error(`Manifest maxChunkCount does not match AEAD mode ${source.qenc.aeadMode}`);
  }

  validateManifestSharding(source.sharding);
  validateAuthPolicyCommitmentShape(source.authPolicyCommitment);

  if (source.shardBinding != null) {
    validateShardBinding(source.shardBinding);
  }

  return {
    manifest: source,
    profile,
  };
}

export function buildArchiveManifest(params) {
  const authPolicy = {
    level: params.authPolicyLevel || DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL,
    minValidSignatures: params.minValidSignatures ?? 1,
  };
  const profile = getCryptoProfile(params.cryptoProfileId || CRYPTO_PROFILE_ID_V2);
  const aeadMode = ensureString(params.aeadMode, 'aeadMode');
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);

  const noncePolicyId = ensureString(
    params.noncePolicyId || nonceContract.noncePolicyId,
    'noncePolicyId'
  );
  const nonceMode = ensureString(
    params.nonceMode || nonceContract.nonceMode,
    'nonceMode'
  );
  const counterBits = ensureInt(
    params.counterBits ?? nonceContract.counterBits,
    'counterBits',
    0
  );
  const maxChunkCount = ensureInt(
    params.maxChunkCount ?? nonceContract.maxChunkCount,
    'maxChunkCount',
    1
  );

  if (noncePolicyId !== nonceContract.noncePolicyId) {
    throw new Error(`noncePolicyId does not match AEAD mode ${aeadMode}`);
  }
  if (nonceMode !== nonceContract.nonceMode) {
    throw new Error(`nonceMode does not match AEAD mode ${aeadMode}`);
  }
  if (counterBits !== nonceContract.counterBits) {
    throw new Error(`counterBits does not match AEAD mode ${aeadMode}`);
  }
  if (maxChunkCount !== nonceContract.maxChunkCount) {
    throw new Error(`maxChunkCount does not match AEAD mode ${aeadMode}`);
  }

  const chunkCount = ensureInt(params.chunkCount, 'chunkCount', 1);
  assertChunkCountWithinPolicy(chunkCount, profile, aeadMode);

  const manifest = {
    schema: MANIFEST_SCHEMA,
    version: MANIFEST_VERSION,
    manifestType: 'archive',
    canonicalization: MANIFEST_CANONICALIZATION_LABEL,
    cryptoProfileId: profile.cryptoProfileId,
    kdfTreeId: profile.kdfTreeId,
    noncePolicyId,
    nonceMode,
    counterBits,
    maxChunkCount,
    aadPolicyId: profile.aadPolicyId,
    qenc: {
      format: ensureString(params.qencFormat, 'qencFormat'),
      aeadMode,
      ivStrategy: ensureString(params.ivStrategy, 'ivStrategy'),
      chunkSize: ensureInt(params.chunkSize, 'chunkSize', 1),
      chunkCount,
      payloadLength: ensureInt(params.payloadLength, 'payloadLength', 1),
      hashAlg: 'SHA3-512',
      qencHash: ensureHex(params.qencHash, 'qencHash', 128),
      primaryAnchor: 'qencHash',
      containerId: ensureHex(params.containerId, 'containerId', 128),
      containerIdRole: 'secondary-header-id',
      containerIdAlg: 'SHA3-512(qenc-header-bytes)',
    },
    sharding: {
      shamir: {
        threshold: ensureInt(params.shamirThreshold, 'shamirThreshold', 2),
        shareCount: ensureInt(params.shamirShareCount, 'shamirShareCount', 2),
      },
      reedSolomon: {
        n: ensureInt(params.rsN, 'rsN', 2),
        k: ensureInt(params.rsK, 'rsK', 2),
        parity: ensureInt(params.rsParity, 'rsParity', 0),
        codecId: ensureString(params.rsCodecId || 'QV-RS-ErasureCodes-v1', 'rsCodecId'),
      },
    },
    authPolicyCommitment: computeAuthPolicyCommitment(authPolicy),
  };

  if (manifest.sharding.reedSolomon.parity !== manifest.sharding.reedSolomon.n - manifest.sharding.reedSolomon.k) {
    throw new Error('rsParity must equal rsN-rsK');
  }
  if (manifest.sharding.shamir.threshold > manifest.sharding.shamir.shareCount) {
    throw new Error('shamirThreshold must not exceed shamirShareCount');
  }

  if (
    (Array.isArray(params.shardBodyHashes) && params.shardBodyHashes.length > 0) ||
    (Array.isArray(params.shareCommitments) && params.shareCommitments.length > 0)
  ) {
    const shardBinding = {
      bodyDefinitionId: 'QV-QCONT-SHARDBODY-v1',
      bodyDefinition: {
        includes: [...BODY_DEFINITION_INCLUDES],
        excludes: [...BODY_DEFINITION_EXCLUDES],
      },
      shardBodyHashAlg: 'SHA3-512',
    };
    if (Array.isArray(params.shardBodyHashes) && params.shardBodyHashes.length > 0) {
      shardBinding.shardBodyHashes = ensureHashList(params.shardBodyHashes, 'shardBodyHashes');
    }
    if (Array.isArray(params.shareCommitments) && params.shareCommitments.length > 0) {
      shardBinding.shareCommitment = {
        hashAlg: 'SHA3-512',
        input: 'raw-shamir-share-bytes',
      };
      shardBinding.shareCommitments = ensureHashList(params.shareCommitments, 'shareCommitments');
    }
    manifest.shardBinding = shardBinding;
  }

  return manifest;
}

export function canonicalizeArchiveManifest(manifest) {
  const validated = validateArchiveManifestObject(manifest);
  const canonical = canonicalizeJson(validated.manifest);
  const bytes = canonicalizeJsonToBytes(validated.manifest);
  const digestHex = toHex(sha3_512(bytes));
  return {
    manifest: validated.manifest,
    profile: validated.profile,
    canonical,
    bytes,
    digestHex,
  };
}

export function parseArchiveManifestBytes(manifestBytes) {
  if (!(manifestBytes instanceof Uint8Array)) {
    throw new Error('manifestBytes must be Uint8Array');
  }

  let parsed;
  try {
    parsed = parseJsonBytesStrict(manifestBytes);
  } catch (error) {
    throw new Error(`Invalid manifest JSON: ${error?.message || error}`);
  }

  const validated = validateArchiveManifestObject(parsed);
  const canonical = canonicalizeJson(validated.manifest);
  const canonicalBytes = canonicalizeJsonToBytes(validated.manifest);
  if (!ensureCanonicalBytes(manifestBytes, canonicalBytes)) {
    throw new Error(`Manifest is not ${MANIFEST_CANONICALIZATION_LABEL} canonical JSON`);
  }

  const digestHex = toHex(sha3_512(canonicalBytes));

  return {
    manifest: validated.manifest,
    canonical,
    bytes: canonicalBytes,
    digestHex,
    profile: validated.profile,
  };
}

export const ARCHIVE_MANIFEST_SCHEMA = MANIFEST_SCHEMA;
export const ARCHIVE_MANIFEST_VERSION = MANIFEST_VERSION;
export const ARCHIVE_MANIFEST_DEFAULTS = {
  cryptoProfileId: CRYPTO_PROFILE_ID_V2,
  kdfTreeId: KDF_TREE_ID_V2,
  noncePolicyId: NONCE_POLICY_PER_CHUNK_V3,
  aadPolicyId: AAD_POLICY_ID_V1,
};

export function deriveArchiveManifestFromReconstructedCandidate(params) {
  return buildArchiveManifest({
    ...params,
    cryptoProfileId: params.cryptoProfileId || DEFAULT_CRYPTO_PROFILE.cryptoProfileId,
  });
}
