import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../bytes.js';
import { IV_STRATEGY_KMAC_PREFIX64_CTR32_V3, IV_STRATEGY_SINGLE_IV } from '../aead.js';
import { DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL, FORMAT_VERSION } from '../constants.js';
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
import { computeAuthPolicyCommitment, normalizeAuthPolicy, validateAuthPolicyCommitmentShape } from './auth-policy.js';
import { MANIFEST_CANONICALIZATION_LABEL, canonicalizeJson, canonicalizeJsonToBytes } from './jcs.js';
import { parseJsonBytesStrict } from './strict-json.js';
import {
  ensureObject,
  ensureString,
  ensureInteger,
  ensureSafeInteger,
  ensureExactString,
  ensureHex,
  assertExactKeys,
} from './validation.js';

const MANIFEST_SCHEMA = 'quantum-vault-archive-manifest/v3';
const MANIFEST_VERSION = 3;
const QENC_AEAD_MODE_SINGLE_CONTAINER = 'single-container-aead';
const QENC_AEAD_MODE_PER_CHUNK = 'per-chunk-aead';
const SHA3_512_ALG = 'SHA3-512';
const PRIMARY_ANCHOR = 'qencHash';
const CONTAINER_ID_ROLE = 'secondary-header-id';
const CONTAINER_ID_ALG = 'SHA3-512(qenc-header-bytes)';
const REED_SOLOMON_CODEC_ID = 'QV-RS-ErasureCodes-v1';
const SHARD_BODY_DEFINITION_ID = 'QV-QCONT-SHARDBODY-v1';
const SHARE_COMMITMENT_INPUT = 'raw-shamir-share-bytes';

const BODY_DEFINITION_INCLUDES = Object.freeze(['fragment-len32-stream']);
const BODY_DEFINITION_EXCLUDES = Object.freeze([
  'qcont-header',
  'embedded-manifest',
  'embedded-manifest-digest',
  'embedded-bundle',
  'embedded-bundle-digest',
  'external-signatures',
]);

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

function getExpectedIvStrategyForAeadMode(aeadMode, field = 'aeadMode') {
  if (aeadMode === QENC_AEAD_MODE_SINGLE_CONTAINER) {
    return IV_STRATEGY_SINGLE_IV;
  }
  if (aeadMode === QENC_AEAD_MODE_PER_CHUNK) {
    return IV_STRATEGY_KMAC_PREFIX64_CTR32_V3;
  }
  throw new Error(`Unsupported ${field}: ${aeadMode}`);
}

function ensureManifestAeadMode(value, field) {
  const aeadMode = ensureString(value, field);
  getExpectedIvStrategyForAeadMode(aeadMode, field);
  return aeadMode;
}

function ensureManifestIvStrategy(value, field, aeadMode) {
  return ensureExactString(value, field, getExpectedIvStrategyForAeadMode(aeadMode, 'qenc.aeadMode'));
}

function normalizeManifestQencStructure(source) {
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

  const aeadMode = ensureManifestAeadMode(qenc.aeadMode, 'qenc.aeadMode');
  const chunkCount = ensureInteger(qenc.chunkCount, 'qenc.chunkCount', 1, 0xffffffff);
  if (aeadMode === QENC_AEAD_MODE_SINGLE_CONTAINER && chunkCount !== 1) {
    throw new Error('Invalid qenc.chunkCount');
  }
  return {
    format: ensureExactString(qenc.format, 'qenc.format', FORMAT_VERSION),
    aeadMode,
    ivStrategy: ensureManifestIvStrategy(qenc.ivStrategy, 'qenc.ivStrategy', aeadMode),
    chunkSize: ensureSafeInteger(qenc.chunkSize, 'qenc.chunkSize', 1),
    chunkCount,
    payloadLength: ensureSafeInteger(qenc.payloadLength, 'qenc.payloadLength', 1),
    hashAlg: ensureExactString(qenc.hashAlg, 'qenc.hashAlg', SHA3_512_ALG),
    qencHash: ensureHex(qenc.qencHash, 'qenc.qencHash', 128),
    primaryAnchor: ensureExactString(qenc.primaryAnchor, 'qenc.primaryAnchor', PRIMARY_ANCHOR),
    containerId: ensureHex(qenc.containerId, 'qenc.containerId', 128),
    containerIdRole: ensureExactString(qenc.containerIdRole, 'qenc.containerIdRole', CONTAINER_ID_ROLE),
    containerIdAlg: ensureExactString(qenc.containerIdAlg, 'qenc.containerIdAlg', CONTAINER_ID_ALG),
  };
}

function validateManifestQencSemantics(qenc, profile) {
  const nonceContract = getNonceContractForAeadMode(qenc.aeadMode, profile);
  assertChunkCountWithinPolicy(qenc.chunkCount, profile, qenc.aeadMode);
  return nonceContract;
}

function normalizeManifestShardingStructure(source) {
  const sharding = ensureObject(source, 'sharding');
  assertExactKeys(sharding, ['shamir', 'reedSolomon'], [], 'sharding');

  const shamir = ensureObject(sharding.shamir, 'sharding.shamir');
  assertExactKeys(shamir, ['threshold', 'shareCount'], [], 'sharding.shamir');
  const threshold = ensureSafeInteger(shamir.threshold, 'sharding.shamir.threshold', 2);
  const shareCount = ensureSafeInteger(shamir.shareCount, 'sharding.shamir.shareCount', 2);

  const reedSolomon = ensureObject(sharding.reedSolomon, 'sharding.reedSolomon');
  assertExactKeys(reedSolomon, ['n', 'k', 'parity', 'codecId'], [], 'sharding.reedSolomon');
  const n = ensureSafeInteger(reedSolomon.n, 'sharding.reedSolomon.n', 2);
  const k = ensureSafeInteger(reedSolomon.k, 'sharding.reedSolomon.k', 2);
  const parity = ensureInteger(reedSolomon.parity, 'sharding.reedSolomon.parity', 0, 0xffffffff);
  const codecId = ensureExactString(reedSolomon.codecId, 'sharding.reedSolomon.codecId', REED_SOLOMON_CODEC_ID);

  return {
    shamir: {
      threshold,
      shareCount,
    },
    reedSolomon: {
      n,
      k,
      parity,
      codecId,
    },
  };
}

function validateManifestShardingSemantics(sharding) {
  if (sharding.shamir.threshold > sharding.shamir.shareCount) {
    throw new Error('Invalid sharding.shamir.threshold');
  }
  const { n, k, parity } = sharding.reedSolomon;
  if (k >= n) {
    throw new Error('Invalid sharding.reedSolomon.k');
  }
  if (parity !== n - k) {
    throw new Error('Invalid sharding.reedSolomon.parity');
  }
}

function normalizeShardBindingStructure(source) {
  const shardBinding = ensureObject(source, 'shardBinding');
  assertExactKeys(
    shardBinding,
    ['bodyDefinitionId', 'bodyDefinition', 'shardBodyHashAlg'],
    ['shardBodyHashes', 'shareCommitment', 'shareCommitments'],
    'shardBinding'
  );

  const bodyDefinition = ensureObject(shardBinding.bodyDefinition, 'shardBinding.bodyDefinition');
  assertExactKeys(bodyDefinition, ['includes', 'excludes'], [], 'shardBinding.bodyDefinition');
  const normalized = {
    bodyDefinitionId: ensureExactString(
      shardBinding.bodyDefinitionId,
      'shardBinding.bodyDefinitionId',
      SHARD_BODY_DEFINITION_ID
    ),
    bodyDefinition: {
      includes: assertExactStringArray(
        bodyDefinition.includes,
        BODY_DEFINITION_INCLUDES,
        'shardBinding.bodyDefinition.includes'
      ),
      excludes: assertExactStringArray(
        bodyDefinition.excludes,
        BODY_DEFINITION_EXCLUDES,
        'shardBinding.bodyDefinition.excludes'
      ),
    },
    shardBodyHashAlg: ensureExactString(shardBinding.shardBodyHashAlg, 'shardBinding.shardBodyHashAlg', SHA3_512_ALG),
  };

  if (shardBinding.shardBodyHashes != null) {
    normalized.shardBodyHashes = ensureHashList(shardBinding.shardBodyHashes, 'shardBinding.shardBodyHashes');
  }

  if (shardBinding.shareCommitment != null || shardBinding.shareCommitments != null) {
    const shareCommitment = ensureObject(shardBinding.shareCommitment, 'shardBinding.shareCommitment');
    assertExactKeys(shareCommitment, ['hashAlg', 'input'], [], 'shardBinding.shareCommitment');
    normalized.shareCommitment = {
      hashAlg: ensureExactString(shareCommitment.hashAlg, 'shardBinding.shareCommitment.hashAlg', SHA3_512_ALG),
      input: ensureExactString(shareCommitment.input, 'shardBinding.shareCommitment.input', SHARE_COMMITMENT_INPUT),
    };
    normalized.shareCommitments = ensureHashList(shardBinding.shareCommitments, 'shardBinding.shareCommitments');
  }

  if (normalized.shardBodyHashes == null && normalized.shareCommitments == null) {
    throw new Error('Invalid shardBinding: expected shardBodyHashes or shareCommitments');
  }
  return normalized;
}

function normalizeArchiveManifestStructure(manifest) {
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

  const version = ensureInteger(source.version, 'manifest.version', 1, Number.MAX_SAFE_INTEGER);
  ensureExactString(source.schema, 'manifest.schema', MANIFEST_SCHEMA);
  ensureExactString(source.manifestType, 'manifest.manifestType', 'archive');
  if (version !== MANIFEST_VERSION) {
    throw new Error('Unsupported archive manifest schema/version');
  }

  return {
    schema: source.schema,
    version,
    manifestType: source.manifestType,
    canonicalization: ensureExactString(
      source.canonicalization,
      'manifest.canonicalization',
      MANIFEST_CANONICALIZATION_LABEL
    ),
    cryptoProfileId: ensureString(source.cryptoProfileId, 'manifest.cryptoProfileId'),
    kdfTreeId: ensureString(source.kdfTreeId, 'manifest.kdfTreeId'),
    noncePolicyId: ensureString(source.noncePolicyId, 'manifest.noncePolicyId'),
    nonceMode: ensureString(source.nonceMode, 'manifest.nonceMode'),
    counterBits: ensureInteger(source.counterBits, 'manifest.counterBits', 0, 0xffffffff),
    maxChunkCount: ensureInteger(source.maxChunkCount, 'manifest.maxChunkCount', 1, 0xffffffff),
    aadPolicyId: ensureString(source.aadPolicyId, 'manifest.aadPolicyId'),
    qenc: normalizeManifestQencStructure(source.qenc),
    sharding: normalizeManifestShardingStructure(source.sharding),
    authPolicyCommitment: validateAuthPolicyCommitmentShape(source.authPolicyCommitment),
    ...(source.shardBinding != null ? { shardBinding: normalizeShardBindingStructure(source.shardBinding) } : {}),
  };
}

export function validateArchiveManifestObject(manifest) {
  const normalized = normalizeArchiveManifestStructure(manifest);
  const profile = getCryptoProfile(normalized.cryptoProfileId);

  if (normalized.kdfTreeId !== profile.kdfTreeId) {
    throw new Error(`Manifest kdfTreeId does not match profile (${profile.kdfTreeId})`);
  }
  if (normalized.aadPolicyId !== profile.aadPolicyId) {
    throw new Error(`Manifest aadPolicyId does not match profile (${profile.aadPolicyId})`);
  }

  const nonceContract = validateManifestQencSemantics(normalized.qenc, profile);

  if (normalized.noncePolicyId !== nonceContract.noncePolicyId) {
    throw new Error(`Manifest noncePolicyId does not match AEAD mode ${normalized.qenc.aeadMode}`);
  }
  if (normalized.nonceMode !== nonceContract.nonceMode) {
    throw new Error(`Manifest nonceMode does not match AEAD mode ${normalized.qenc.aeadMode}`);
  }
  if (normalized.counterBits !== nonceContract.counterBits) {
    throw new Error(`Manifest counterBits does not match AEAD mode ${normalized.qenc.aeadMode}`);
  }
  if (normalized.maxChunkCount !== nonceContract.maxChunkCount) {
    throw new Error(`Manifest maxChunkCount does not match AEAD mode ${normalized.qenc.aeadMode}`);
  }

  validateManifestShardingSemantics(normalized.sharding);

  return {
    manifest: normalized,
    profile,
  };
}

export function buildArchiveManifest(params) {
  const authPolicy = normalizeAuthPolicy({
    level: params.authPolicyLevel || DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL,
    minValidSignatures: params.minValidSignatures ?? 1,
  });
  const profile = getCryptoProfile(params.cryptoProfileId || CRYPTO_PROFILE_ID_V2);
  const aeadMode = ensureManifestAeadMode(params.aeadMode, 'aeadMode');
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);

  const noncePolicyId = ensureString(
    params.noncePolicyId || nonceContract.noncePolicyId,
    'noncePolicyId'
  );
  const nonceMode = ensureString(
    params.nonceMode || nonceContract.nonceMode,
    'nonceMode'
  );
  const counterBits = ensureInteger(
    params.counterBits ?? nonceContract.counterBits,
    'counterBits',
    0,
    0xffffffff
  );
  const maxChunkCount = ensureInteger(
    params.maxChunkCount ?? nonceContract.maxChunkCount,
    'maxChunkCount',
    1,
    0xffffffff
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

  const chunkCount = ensureInteger(params.chunkCount, 'chunkCount', 1, 0xffffffff);
  assertChunkCountWithinPolicy(chunkCount, profile, aeadMode);
  const qencFormat = ensureExactString(params.qencFormat, 'qencFormat', FORMAT_VERSION);
  const ivStrategy = ensureManifestIvStrategy(params.ivStrategy, 'ivStrategy', aeadMode);

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
      format: qencFormat,
      aeadMode,
      ivStrategy,
      chunkSize: ensureSafeInteger(params.chunkSize, 'chunkSize', 1),
      chunkCount,
      payloadLength: ensureSafeInteger(params.payloadLength, 'payloadLength', 1),
      hashAlg: SHA3_512_ALG,
      qencHash: ensureHex(params.qencHash, 'qencHash', 128),
      primaryAnchor: PRIMARY_ANCHOR,
      containerId: ensureHex(params.containerId, 'containerId', 128),
      containerIdRole: CONTAINER_ID_ROLE,
      containerIdAlg: CONTAINER_ID_ALG,
    },
    sharding: {
      shamir: {
        threshold: ensureSafeInteger(params.shamirThreshold, 'shamirThreshold', 2),
        shareCount: ensureSafeInteger(params.shamirShareCount, 'shamirShareCount', 2),
      },
      reedSolomon: {
        n: ensureSafeInteger(params.rsN, 'rsN', 2),
        k: ensureSafeInteger(params.rsK, 'rsK', 2),
        parity: ensureInteger(params.rsParity, 'rsParity', 0, 0xffffffff),
        codecId: ensureExactString(
          params.rsCodecId || REED_SOLOMON_CODEC_ID,
          'rsCodecId',
          REED_SOLOMON_CODEC_ID
        ),
      },
    },
    authPolicyCommitment: computeAuthPolicyCommitment(authPolicy),
  };

  if (
    (Array.isArray(params.shardBodyHashes) && params.shardBodyHashes.length > 0) ||
    (Array.isArray(params.shareCommitments) && params.shareCommitments.length > 0)
  ) {
    const shardBinding = {
      bodyDefinitionId: SHARD_BODY_DEFINITION_ID,
      bodyDefinition: {
        includes: [...BODY_DEFINITION_INCLUDES],
        excludes: [...BODY_DEFINITION_EXCLUDES],
      },
      shardBodyHashAlg: SHA3_512_ALG,
    };
    if (Array.isArray(params.shardBodyHashes) && params.shardBodyHashes.length > 0) {
      shardBinding.shardBodyHashes = ensureHashList(params.shardBodyHashes, 'shardBodyHashes');
    }
    if (Array.isArray(params.shareCommitments) && params.shareCommitments.length > 0) {
      shardBinding.shareCommitment = {
        hashAlg: SHA3_512_ALG,
        input: SHARE_COMMITMENT_INPUT,
      };
      shardBinding.shareCommitments = ensureHashList(params.shareCommitments, 'shareCommitments');
    }
    manifest.shardBinding = shardBinding;
  }

  return validateArchiveManifestObject(manifest).manifest;
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
