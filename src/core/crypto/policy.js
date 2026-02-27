// Crypto policy registry and validators

export const CRYPTO_PROFILE_ID_V1 = 'QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v1';
export const KDF_TREE_ID_V1 = 'QV-KDF-TREE-v1';
export const NONCE_POLICY_SINGLE_CONTAINER_V1 = 'QV-GCM-RAND96-v1';
export const NONCE_POLICY_PER_CHUNK_V1 = 'QV-GCM-KMACPFX64-CTR32-v2';
export const AAD_POLICY_ID_V1 = 'QV-AAD-HEADER-CHUNK-v1';
export const NONCE_MODE_RANDOM96 = 'random96';
export const NONCE_MODE_KMAC_CTR32 = 'kmac-prefix64-ctr32';

export const PROFILE_REGISTRY = Object.freeze({
  [CRYPTO_PROFILE_ID_V1]: Object.freeze({
    cryptoProfileId: CRYPTO_PROFILE_ID_V1,
    kdfTreeId: KDF_TREE_ID_V1,
    aadPolicyId: AAD_POLICY_ID_V1,
    domainStrings: Object.freeze({
      kdf: 'quantum-vault:kdf:v1',
      iv: 'quantum-vault:chunk-iv:v1',
      kenc: 'quantum-vault:kenc:v1',
      kiv: 'quantum-vault:kiv:v1',
    }),
    noncePolicies: Object.freeze({
      'single-container-aead': Object.freeze({
        noncePolicyId: NONCE_POLICY_SINGLE_CONTAINER_V1,
        nonceMode: NONCE_MODE_RANDOM96,
        counterBits: 0,
        maxChunkCount: 1,
      }),
      'per-chunk-aead': Object.freeze({
        noncePolicyId: NONCE_POLICY_PER_CHUNK_V1,
        nonceMode: NONCE_MODE_KMAC_CTR32,
        counterBits: 32,
        maxChunkCount: 0xffffffff,
      }),
    }),
  }),
});

export const DEFAULT_CRYPTO_PROFILE = PROFILE_REGISTRY[CRYPTO_PROFILE_ID_V1];

export function getCryptoProfile(profileId = CRYPTO_PROFILE_ID_V1) {
  const profile = PROFILE_REGISTRY[profileId];
  if (!profile) {
    throw new Error(`Unsupported cryptoProfileId: ${profileId}`);
  }
  return profile;
}

export function getNonceContractForAeadMode(aeadMode, profile = DEFAULT_CRYPTO_PROFILE) {
  const mode = String(aeadMode || '').trim();
  const contract = profile?.noncePolicies?.[mode];
  if (!contract) {
    throw new Error(`Unsupported AEAD mode for nonce policy: ${mode || '(missing)'}`);
  }
  return contract;
}

export function assertChunkCountWithinPolicy(
  chunkCount,
  profile = DEFAULT_CRYPTO_PROFILE,
  aeadMode = 'per-chunk-aead'
) {
  if (!Number.isInteger(chunkCount) || chunkCount <= 0) {
    throw new Error('chunkCount must be a positive integer');
  }
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);
  if (chunkCount > nonceContract.maxChunkCount) {
    throw new Error(`chunkCount exceeds nonce policy bound (${nonceContract.maxChunkCount})`);
  }
}

export function validateContainerPolicyMetadata(metadata, options = {}) {
  const { allowLegacyWithoutProfile = true } = options;

  const profileId = typeof metadata?.cryptoProfileId === 'string' && metadata.cryptoProfileId.length > 0
    ? metadata.cryptoProfileId
    : null;

  const profile = profileId ? getCryptoProfile(profileId) : DEFAULT_CRYPTO_PROFILE;

  if (!profileId && !allowLegacyWithoutProfile) {
    throw new Error('Container metadata is missing cryptoProfileId');
  }

  const aeadMode = String(metadata?.aead_mode || '').trim();
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);

  if (metadata?.noncePolicyId && metadata.noncePolicyId !== nonceContract.noncePolicyId) {
    throw new Error(`Unsupported noncePolicyId for ${aeadMode}: ${metadata.noncePolicyId}`);
  }

  if (metadata?.nonceMode && metadata.nonceMode !== nonceContract.nonceMode) {
    throw new Error(`Unsupported nonceMode for ${aeadMode}: ${metadata.nonceMode}`);
  }

  if (metadata?.counterBits != null && metadata.counterBits !== nonceContract.counterBits) {
    throw new Error(`Unsupported counterBits for ${aeadMode}: ${metadata.counterBits}`);
  }

  if (metadata?.maxChunkCount != null && metadata.maxChunkCount !== nonceContract.maxChunkCount) {
    throw new Error(`Unsupported maxChunkCount for ${aeadMode}: ${metadata.maxChunkCount}`);
  }

  if (metadata?.aadPolicyId && metadata.aadPolicyId !== profile.aadPolicyId) {
    throw new Error(`Unsupported aadPolicyId: ${metadata.aadPolicyId}`);
  }

  if (metadata?.kdfTreeId && metadata.kdfTreeId !== profile.kdfTreeId) {
    throw new Error(`Unsupported kdfTreeId: ${metadata.kdfTreeId}`);
  }

  const ds = metadata?.domainStrings;
  if (!ds || typeof ds.kdf !== 'string' || typeof ds.iv !== 'string') {
    throw new Error('Container metadata is missing valid domainStrings');
  }

  if (ds.kdf !== profile.domainStrings.kdf || ds.iv !== profile.domainStrings.iv) {
    throw new Error('Container domainStrings do not match allowed crypto profile');
  }

  if (metadata?.chunkCount != null) {
    assertChunkCountWithinPolicy(metadata.chunkCount, profile, aeadMode);
  }

  return {
    ...profile,
    nonceContract,
  };
}

export function buildPolicyMetadataFields(
  profile = DEFAULT_CRYPTO_PROFILE,
  aeadMode = 'per-chunk-aead'
) {
  const nonceContract = getNonceContractForAeadMode(aeadMode, profile);
  return {
    cryptoProfileId: profile.cryptoProfileId,
    kdfTreeId: profile.kdfTreeId,
    noncePolicyId: nonceContract.noncePolicyId,
    nonceMode: nonceContract.nonceMode,
    counterBits: nonceContract.counterBits,
    maxChunkCount: nonceContract.maxChunkCount,
    aadPolicyId: profile.aadPolicyId,
    domainStrings: {
      kdf: profile.domainStrings.kdf,
      iv: profile.domainStrings.iv,
    },
  };
}
