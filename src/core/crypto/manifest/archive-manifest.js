import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../../utils.js';
import {
  AAD_POLICY_ID_V1,
  CRYPTO_PROFILE_ID_V1,
  DEFAULT_CRYPTO_PROFILE,
  KDF_TREE_ID_V1,
  NONCE_POLICY_PER_CHUNK_V1,
  assertChunkCountWithinPolicy,
  getNonceContractForAeadMode,
  getCryptoProfile,
} from '../policy.js';
import { canonicalizeJson, canonicalizeJsonToBytes } from './jcs.js';

const MANIFEST_SCHEMA = 'quantum-vault-archive-manifest/v1';
const MANIFEST_VERSION = 1;

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

function ensureHashList(values, field) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return values.map((value, index) => {
    const text = ensureString(value, `${field}[${index}]`);
    if (!/^[0-9a-f]+$/i.test(text)) {
      throw new Error(`Invalid ${field}[${index}]`);
    }
    return text.toLowerCase();
  });
}

export function buildArchiveManifest(params) {
  const profile = getCryptoProfile(params.cryptoProfileId || CRYPTO_PROFILE_ID_V1);
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
      qencHash: ensureString(params.qencHash, 'qencHash'),
      primaryAnchor: 'qencHash',
      containerId: ensureString(params.containerId, 'containerId'),
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
    signingPolicy: {
      requireSignature: !!params.requireSignature,
      acceptedAlgorithms: Array.isArray(params.acceptedAlgorithms)
        ? params.acceptedAlgorithms.slice()
        : ['ML-DSA', 'SLH-DSA-SHAKE', 'Ed25519'],
      allowLegacyEd25519: !!params.allowLegacyEd25519,
    },
  };

  if (
    (Array.isArray(params.shardBodyHashes) && params.shardBodyHashes.length > 0) ||
    (Array.isArray(params.shareCommitments) && params.shareCommitments.length > 0)
  ) {
    const shardBinding = {
      bodyDefinitionId: 'QV-QCONT-SHARDBODY-v1',
      bodyDefinition: {
        includes: ['fragment-len32-stream'],
        excludes: [
          'qcont-header',
          'embedded-manifest',
          'embedded-manifest-digest',
          'external-signatures',
        ],
      },
      shardBodyHashAlg: 'SHA3-512',
    };
    if (Array.isArray(params.shardBodyHashes) && params.shardBodyHashes.length > 0) {
      shardBinding.shardBodyHashes = params.shardBodyHashes.slice();
    }
    if (Array.isArray(params.shareCommitments) && params.shareCommitments.length > 0) {
      shardBinding.shareCommitment = {
        hashAlg: 'SHA3-512',
        input: 'raw-shamir-share-bytes',
      };
      shardBinding.shareCommitments = params.shareCommitments.slice();
    }
    manifest.shardBinding = shardBinding;
  }

  return manifest;
}

export function canonicalizeArchiveManifest(manifest) {
  const canonical = canonicalizeJson(manifest);
  const bytes = canonicalizeJsonToBytes(manifest);
  const digestHex = toHex(sha3_512(bytes));
  return { canonical, bytes, digestHex };
}

export function parseArchiveManifestBytes(manifestBytes, options = {}) {
  if (!(manifestBytes instanceof Uint8Array)) {
    throw new Error('manifestBytes must be Uint8Array');
  }

  const text = new TextDecoder().decode(manifestBytes);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid manifest JSON: ${error?.message || error}`);
  }

  const canonical = canonicalizeJson(parsed);
  const canonicalBytes = new TextEncoder().encode(canonical);
  const isCanonical = manifestBytes.length === canonicalBytes.length && manifestBytes.every((b, i) => b === canonicalBytes[i]);
  if (!isCanonical) {
    throw new Error('Manifest is not RFC-8785 canonical JSON');
  }

  if (parsed?.schema !== MANIFEST_SCHEMA || parsed?.version !== MANIFEST_VERSION || parsed?.manifestType !== 'archive') {
    throw new Error('Unsupported archive manifest schema/version');
  }

  const profileId = ensureString(parsed.cryptoProfileId, 'cryptoProfileId');
  const profile = getCryptoProfile(profileId);

  if (parsed.kdfTreeId !== profile.kdfTreeId) {
    throw new Error(`Manifest kdfTreeId does not match profile (${profile.kdfTreeId})`);
  }
  if (parsed.aadPolicyId !== profile.aadPolicyId) {
    throw new Error(`Manifest aadPolicyId does not match profile (${profile.aadPolicyId})`);
  }

  const qenc = parsed.qenc || {};
  const aeadMode = ensureString(qenc.aeadMode, 'qenc.aeadMode');
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);
  if (parsed.noncePolicyId !== nonceContract.noncePolicyId) {
    throw new Error(`Manifest noncePolicyId does not match AEAD mode ${aeadMode}`);
  }
  if (parsed.nonceMode !== nonceContract.nonceMode) {
    throw new Error(`Manifest nonceMode does not match AEAD mode ${aeadMode}`);
  }
  if (parsed.counterBits !== nonceContract.counterBits) {
    throw new Error(`Manifest counterBits does not match AEAD mode ${aeadMode}`);
  }
  if (parsed.maxChunkCount !== nonceContract.maxChunkCount) {
    throw new Error(`Manifest maxChunkCount does not match AEAD mode ${aeadMode}`);
  }

  assertChunkCountWithinPolicy(ensureInt(qenc.chunkCount, 'qenc.chunkCount', 1), profile, aeadMode);
  ensureString(qenc.qencHash, 'qenc.qencHash');
  ensureString(qenc.containerId, 'qenc.containerId');
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

  if (parsed.shardBinding != null) {
    const shardBinding = parsed.shardBinding;
    ensureString(shardBinding.bodyDefinitionId, 'shardBinding.bodyDefinitionId');
    if (shardBinding.bodyDefinitionId !== 'QV-QCONT-SHARDBODY-v1') {
      throw new Error('Unsupported shardBinding.bodyDefinitionId');
    }
    ensureString(shardBinding.shardBodyHashAlg, 'shardBinding.shardBodyHashAlg');
    if (shardBinding.shardBodyHashAlg !== 'SHA3-512') {
      throw new Error('Unsupported shardBinding.shardBodyHashAlg');
    }
    if (
      !Array.isArray(shardBinding?.bodyDefinition?.includes) ||
      !Array.isArray(shardBinding?.bodyDefinition?.excludes)
    ) {
      throw new Error('Invalid shardBinding.bodyDefinition');
    }
    if (shardBinding.shardBodyHashes != null) {
      ensureHashList(shardBinding.shardBodyHashes, 'shardBinding.shardBodyHashes');
    }
    if (shardBinding.shareCommitments != null) {
      ensureHashList(shardBinding.shareCommitments, 'shardBinding.shareCommitments');
      if (!shardBinding.shareCommitment || shardBinding.shareCommitment.hashAlg !== 'SHA3-512' || shardBinding.shareCommitment.input !== 'raw-shamir-share-bytes') {
        throw new Error('Invalid shardBinding.shareCommitment descriptor');
      }
    }
    if (shardBinding.shardBodyHashes == null && shardBinding.shareCommitments == null) {
      throw new Error('Invalid shardBinding: expected shardBodyHashes or shareCommitments');
    }
  }

  const digestHex = toHex(sha3_512(canonicalBytes));

  return {
    manifest: parsed,
    canonical,
    bytes: canonicalBytes,
    digestHex,
    profile,
  };
}

export const ARCHIVE_MANIFEST_SCHEMA = MANIFEST_SCHEMA;
export const ARCHIVE_MANIFEST_VERSION = MANIFEST_VERSION;
export const ARCHIVE_MANIFEST_DEFAULTS = {
  cryptoProfileId: CRYPTO_PROFILE_ID_V1,
  kdfTreeId: KDF_TREE_ID_V1,
  noncePolicyId: NONCE_POLICY_PER_CHUNK_V1,
  aadPolicyId: AAD_POLICY_ID_V1,
};

export function deriveArchiveManifestFromReconstructedCandidate(params) {
  return buildArchiveManifest({
    ...params,
    cryptoProfileId: params.cryptoProfileId || DEFAULT_CRYPTO_PROFILE.cryptoProfileId,
  });
}
