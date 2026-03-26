import { CHUNK_SIZE, FORMAT_VERSION, MAX_FILE_SIZE, decryptFile, encryptFile, generateKeyPair, hashBytes } from './index.js';
import { asciiBytes, base64ToBytes, bytesToBase64, concatBytes, digestSha256, fromHex, timingSafeEqual, utf8ToBytes } from './bytes.js';
import { validatePublicKey, validateSecretKey } from './mlkem.js';
import { buildQcontShards } from './qcont/build.js';
import { attachManifestBundleToShards } from './qcont/attach.js';
import { attachLifecycleBundleToShards } from './qcont/lifecycle-attach.js';
import { buildLifecycleQcontShards, parseLifecycleShard, reshareSameState, rewriteLifecycleBundleInShard } from './qcont/lifecycle-shard.js';
import { parseShard, restoreFromShards } from './qcont/restore.js';
import { parseQencHeader } from './qenc/format.js';
import {
  buildArchiveStateDescriptor,
  buildCohortBinding,
  buildTransitionRecord,
  buildSourceEvidence,
  buildLifecycleBundle,
  canonicalizeArchiveStateDescriptor as canonicalizeLifecycleArchiveState,
  canonicalizeCohortBinding,
  canonicalizeCohortIdPreimage,
  canonicalizeTransitionRecord,
  canonicalizeSourceEvidence,
  canonicalizeLifecycleBundle,
  computeCohortBindingDigest,
  deriveCohortId,
  deriveStateId,
  generateArchiveId,
  parseArchiveStateDescriptorBytes,
  parseCohortBindingBytes,
  parseTransitionRecordBytes,
  parseSourceEvidenceBytes,
  parseLifecycleBundleBytes,
  verifyLifecycleSignatureEntry,
} from './lifecycle/artifacts.js';
import {
  buildInitialManifestBundle,
  canonicalizeManifestBundle,
  MANIFEST_BUNDLE_TYPE,
  MANIFEST_BUNDLE_VERSION,
  parseManifestBundleBytes,
  parseManifestBundleBytesPreviewOnly,
} from './manifest/manifest-bundle.js';
import {
  ARCHIVE_MANIFEST_SCHEMA,
  ARCHIVE_MANIFEST_VERSION,
  buildArchiveManifest,
  canonicalizeArchiveManifest,
  parseArchiveManifestBytes,
} from './manifest/archive-manifest.js';
import { normalizeAuthPolicy } from './manifest/auth-policy.js';
import {
  BUNDLE_CANONICALIZATION_LABEL,
  MANIFEST_CANONICALIZATION_LABEL,
  canonicalizeJson,
  canonicalizeJsonToBytes,
} from './manifest/jcs.js';
import { createBundlePayloadFromFiles, isBundlePayload, parseBundlePayload } from '../features/bundle-payload.js';
import { buildAttachedArtifactExports } from '../features/qcont/attach-ui.js';
import { classifyRestoreInputFiles } from '../../app/restore-inputs.js';
import { verifyManifestSignatures } from './auth/verify-signatures.js';
import { unpackPqpk, unpackQsig } from './auth/qsig.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_shake_128s } from '@noble/post-quantum/slh-dsa.js';
import { inspectManifestBundleTimestamps, parseOpenTimestampProof } from './auth/opentimestamps.js';
import {
  DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL,
  LITE_DEFAULT_AUTH_POLICY_LEVEL,
  PRO_DEFAULT_AUTH_POLICY_LEVEL,
} from './constants.js';
import {
  assertPerChunkNonceContract,
  deriveChunkIvFromK,
  IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
  IV_STRATEGY_SINGLE_IV,
  NONCE_COUNTER_BITS_U32,
  NONCE_MAX_CHUNK_COUNT_U32,
} from './aead.js';
import { toHex } from './bytes.js';
import {
  DEFAULT_CRYPTO_PROFILE,
  NONCE_MODE_KMAC_CTR32,
  NONCE_MODE_RANDOM96,
  NONCE_POLICY_PER_CHUNK_V3,
  NONCE_POLICY_SINGLE_CONTAINER_V1,
} from './policy.js';
import { kmac256 } from './kmac.js';
import { resolveErasureRuntime } from './erasure-runtime.js';
import { parseJsonTextStrict } from './manifest/strict-json.js';

function textBytes(value) {
  return new TextEncoder().encode(value);
}

function legacyCanonicalizeQvC14n(value) {
  function serializeNumber(numberValue) {
    if (!Number.isFinite(numberValue)) {
      throw new Error('Legacy QV-C14N-v1 does not allow non-finite numbers');
    }
    return JSON.stringify(numberValue);
  }

  function serializeArray(arr) {
    const items = arr.map((item) => {
      if (item === undefined || typeof item === 'function' || typeof item === 'symbol') return 'null';
      return serializeValue(item);
    });
    return `[${items.join(',')}]`;
  }

  function serializeObject(obj) {
    const keys = Object.keys(obj).sort();
    const fields = [];
    for (const key of keys) {
      const item = obj[key];
      if (item === undefined || typeof item === 'function' || typeof item === 'symbol') continue;
      fields.push(`${JSON.stringify(key)}:${serializeValue(item)}`);
    }
    return `{${fields.join(',')}}`;
  }

  function serializeValue(item) {
    if (item === null) return 'null';
    const t = typeof item;
    if (t === 'boolean') return item ? 'true' : 'false';
    if (t === 'number') return serializeNumber(item);
    if (t === 'string') return JSON.stringify(item);
    if (t === 'bigint') throw new Error('Legacy QV-C14N-v1 does not allow bigint values');
    if (Array.isArray(item)) return serializeArray(item);
    if (t === 'object') return serializeObject(item);
    throw new Error(`Unsupported legacy QV-C14N-v1 value type: ${t}`);
  }

  return serializeValue(value);
}

function legacyCanonicalizeQvC14nToBytes(value) {
  return textBytes(legacyCanonicalizeQvC14n(value));
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

function toArrayBufferView(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function fileLike(name, bytes) {
  return {
    name,
    async arrayBuffer() {
      return toArrayBufferView(bytes);
    },
  };
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function buildManifestParams(overrides = {}) {
  return {
    aeadMode: 'per-chunk-aead',
    qencFormat: FORMAT_VERSION,
    ivStrategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
    chunkSize: 65536,
    chunkCount: 3,
    payloadLength: 131072,
    qencHash: 'a'.repeat(128),
    containerId: 'b'.repeat(128),
    shamirThreshold: 4,
    shamirShareCount: 5,
    rsN: 5,
    rsK: 3,
    rsParity: 2,
    rsCodecId: 'QV-RS-ErasureCodes-v1',
    ...overrides,
  };
}

function buildTestArchiveManifest(overrides = {}) {
  return buildArchiveManifest(buildManifestParams(overrides));
}

async function buildLifecycleSampleArtifacts() {
  const shardBodyHashes = ['11', '22', '33', '44', '55'].map((value) => value.repeat(64));
  const shareCommitments = ['66', '77', '88', '99', 'aa'].map((value) => value.repeat(64));
  const archiveState = buildArchiveStateDescriptor({
    archiveId: 'ab'.repeat(32),
    parentStateId: null,
    chunkSize: 65536,
    chunkCount: 3,
    payloadLength: 131072,
    qencHash: 'cd'.repeat(64),
    containerId: 'ef'.repeat(64),
    authPolicy: { level: 'strong-pq-signature', minValidSignatures: 1 },
  });
  const canonicalArchiveState = canonicalizeLifecycleArchiveState(archiveState);
  const stateId = canonicalArchiveState.stateId;
  const cohortBinding = buildCohortBinding({
    archiveId: archiveState.archiveId,
    stateId,
    shamirThreshold: 4,
    shamirShareCount: 5,
    rsN: 5,
    rsK: 3,
    rsParity: 2,
    shardBodyHashes,
    shareCommitments,
  });
  const canonicalCohortBinding = canonicalizeCohortBinding(cohortBinding);
  const cohortId = deriveCohortId({
    archiveId: archiveState.archiveId,
    stateId,
    cohortBindingDigest: canonicalCohortBinding.digest,
  });
  const transitionRecord = buildTransitionRecord({
    archiveId: archiveState.archiveId,
    fromStateId: stateId,
    toStateId: stateId,
    fromCohortId: '01'.repeat(32),
    toCohortId: cohortId,
    fromCohortBindingDigest: { alg: 'SHA3-512', value: '23'.repeat(64) },
    toCohortBindingDigest: canonicalCohortBinding.digest,
    reasonCode: 'cohort-rotation',
    performedAt: '2026-03-25T12:34:56.000Z',
    operatorRole: 'operator',
    actorHints: { ceremony: 'reshare-01' },
    notes: null,
  });
  const sourceEvidence = buildSourceEvidence({
    relationType: 'reviewed-source',
    sourceObjectType: 'archive-manifest-v3',
    sourceDigests: [
      { alg: 'SHA3-512', value: '45'.repeat(64) },
      { alg: 'SHA-256', value: '67'.repeat(32) },
    ],
    externalSourceSignatureRefs: ['sig:external-1'],
    mediaType: 'application/json',
  });
  const lifecycleBundle = await buildLifecycleBundle({
    archiveState,
    currentCohortBinding: cohortBinding,
    authPolicy: { level: 'strong-pq-signature', minValidSignatures: 1 },
    sourceEvidence: [sourceEvidence],
    transitions: [transitionRecord],
    attachments: {
      publicKeys: [],
      archiveApprovalSignatures: [],
      maintenanceSignatures: [],
      sourceEvidenceSignatures: [],
      timestamps: [],
    },
  });
  return {
    archiveState,
    canonicalArchiveState,
    stateId,
    cohortBinding,
    canonicalCohortBinding,
    cohortId,
    transitionRecord,
    sourceEvidence,
    lifecycleBundle,
  };
}

function buildBundledMlDsaPublicKey(id, publicKeyBytes, { suite = 'mldsa-87' } = {}) {
  return {
    id,
    kty: 'ml-dsa-public-key',
    suite,
    encoding: 'base64',
    value: bytesToBase64(publicKeyBytes),
  };
}

function buildLifecycleQsigEntry({
  id,
  signatureFamily,
  targetType,
  targetRef,
  targetDigest,
  qsigBytes,
  publicKeyRef = '',
  suite = 'mldsa-87',
}) {
  const entry = {
    id,
    signatureFamily,
    format: 'qsig',
    suite,
    targetType,
    targetRef,
    targetDigest: { alg: 'SHA3-512', value: targetDigest },
    signatureEncoding: 'base64',
    signature: bytesToBase64(qsigBytes),
  };
  if (publicKeyRef) {
    entry.publicKeyRef = publicKeyRef;
  }
  return entry;
}

async function buildSuccessorRestoreSample({
  payloadBytes = textBytes('successor-restore-sample'),
  filename = 'successor-restore-sample.bin',
  authPolicyLevel = 'integrity-only',
  minValidSignatures = 1,
} = {}) {
  const pair = await generateKeyPair({ collectUserEntropy: false });
  const qencBytes = await blobToBytes(await encryptFile(payloadBytes, pair.publicKey, filename));
  const split = await buildLifecycleQcontShards(
    qencBytes,
    pair.secretKey,
    { n: 5, k: 3 },
    { authPolicyLevel, minValidSignatures }
  );
  const parsed = await Promise.all(split.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));
  return {
    pair,
    payloadBytes,
    qencBytes,
    split,
    parsed,
  };
}

async function rewriteLifecycleBundleSubset(parsedShards, lifecycleBundleBytes, selectedIndices = []) {
  const selected = new Set(
    selectedIndices.length > 0
      ? selectedIndices
      : parsedShards.map((shard) => shard.shardIndex)
  );
  return Promise.all(parsedShards.map(async (shard) => {
    if (!selected.has(shard.shardIndex)) {
      return shard;
    }
    const rewritten = rewriteLifecycleBundleInShard(shard, lifecycleBundleBytes);
    return parseLifecycleShard(await blobToBytes(rewritten.blob));
  }));
}

async function buildResharePredecessorSample({
  payloadBytes = textBytes('same-state-reshare-predecessor'),
  authPolicyLevel = 'integrity-only',
  minValidSignatures = 1,
  bundleVariantOptions = null,
} = {}) {
  const sample = await buildSuccessorRestoreSample({
    payloadBytes,
    authPolicyLevel,
    minValidSignatures,
  });
  if (!bundleVariantOptions) {
    return {
      ...sample,
      predecessorLifecycleBundle: sample.split.lifecycleBundle,
      predecessorLifecycleBundleBytes: sample.split.lifecycleBundleBytes,
      predecessorLifecycleBundleDigestHex: sample.split.lifecycleBundleDigestHex,
    };
  }

  const bundleVariant = await buildSuccessorVerificationBundle(sample.split, bundleVariantOptions);
  const rewritten = await rewriteLifecycleBundleSubset(sample.parsed, bundleVariant.bundleBytes);
  return {
    ...sample,
    parsed: rewritten,
    predecessorLifecycleBundle: bundleVariant.bundle,
    predecessorLifecycleBundleBytes: bundleVariant.bundleBytes,
    predecessorLifecycleBundleDigestHex: bundleVariant.digestHex,
    bundleVariant,
  };
}

async function parseResharedShardSet(reshareResult) {
  return Promise.all(
    reshareResult.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob)))
  );
}

function buildMaintenanceArtifactsFactory({ keyId = 'pk-maintenance', signatureId = 'maintenance-sig-reshare' } = {}) {
  return async ({ transitionRecordBytes, transitionRecordDigest, targetRef }) => {
    const qsig = buildQsigFixture(transitionRecordBytes);
    return {
      publicKeys: [
        buildBundledMlDsaPublicKey(keyId, qsig.signerPublicKey),
      ],
      maintenanceSignatures: [
        buildLifecycleQsigEntry({
          id: signatureId,
          signatureFamily: 'maintenance',
          targetType: 'transition-record',
          targetRef,
          targetDigest: transitionRecordDigest.value,
          qsigBytes: qsig.qsigBytes,
          publicKeyRef: keyId,
        }),
      ],
    };
  };
}

async function buildSuccessorVerificationBundle(split, {
  authPolicyLevel = split.lifecycleBundle.authPolicy.level,
  minValidSignatures = split.lifecycleBundle.authPolicy.minValidSignatures,
  includeArchiveApproval = true,
  includeMaintenance = false,
  includeSourceEvidence = false,
  timestampTargetFamily = '',
} = {}) {
  const bundle = cloneJson(split.lifecycleBundle);
  bundle.authPolicy = {
    level: authPolicyLevel,
    minValidSignatures,
  };
  bundle.sourceEvidence = [];
  bundle.transitions = [];
  bundle.attachments = {
    publicKeys: [],
    archiveApprovalSignatures: [],
    maintenanceSignatures: [],
    sourceEvidenceSignatures: [],
    timestamps: [],
  };

  const fixtures = {};
  if (includeArchiveApproval || timestampTargetFamily === 'archive-approval') {
    const qsig = buildQsigFixture(split.archiveStateBytes);
    fixtures.archiveApproval = qsig;
    bundle.attachments.publicKeys.push(buildBundledMlDsaPublicKey('pk-archive', qsig.signerPublicKey));
    if (includeArchiveApproval) {
      bundle.attachments.archiveApprovalSignatures.push(buildLifecycleQsigEntry({
        id: 'archive-approval-sig-1',
        signatureFamily: 'archive-approval',
        targetType: 'archive-state',
        targetRef: `state:${split.stateId}`,
        targetDigest: split.stateId,
        qsigBytes: qsig.qsigBytes,
        publicKeyRef: 'pk-archive',
      }));
    }
  }

  let transitionRecord = null;
  if (includeMaintenance || timestampTargetFamily === 'maintenance') {
    transitionRecord = buildTransitionRecord({
      archiveId: split.archiveId,
      fromStateId: split.stateId,
      toStateId: split.stateId,
      fromCohortId: '01'.repeat(32),
      toCohortId: split.cohortId,
      fromCohortBindingDigest: { alg: 'SHA3-512', value: '23'.repeat(64) },
      toCohortBindingDigest: split.cohortBindingDigestHex
        ? { alg: 'SHA3-512', value: split.cohortBindingDigestHex }
        : canonicalizeCohortBinding(split.cohortBinding).digest,
      reasonCode: 'cohort-rotation',
      performedAt: '2026-03-25T12:34:56.000Z',
      operatorRole: 'operator',
      actorHints: { ceremony: 'restore-phase3' },
      notes: null,
    });
    bundle.transitions = [transitionRecord];
    const canonicalTransition = canonicalizeTransitionRecord(transitionRecord);
    const qsig = buildQsigFixture(canonicalTransition.bytes);
    fixtures.maintenance = qsig;
    bundle.attachments.publicKeys.push(buildBundledMlDsaPublicKey('pk-maintenance', qsig.signerPublicKey));
    if (includeMaintenance) {
      bundle.attachments.maintenanceSignatures.push(buildLifecycleQsigEntry({
        id: 'maintenance-sig-1',
        signatureFamily: 'maintenance',
        targetType: 'transition-record',
        targetRef: `transition:sha3-512:${canonicalTransition.digest.value}`,
        targetDigest: canonicalTransition.digest.value,
        qsigBytes: qsig.qsigBytes,
        publicKeyRef: 'pk-maintenance',
      }));
    }
  }

  let sourceEvidence = null;
  if (includeSourceEvidence || timestampTargetFamily === 'source-evidence') {
    sourceEvidence = buildSourceEvidence({
      relationType: 'reviewed-source',
      sourceObjectType: 'archive-manifest-v3',
      sourceDigests: [
        { alg: 'SHA3-512', value: '45'.repeat(64) },
        { alg: 'SHA-256', value: '67'.repeat(32) },
      ],
      externalSourceSignatureRefs: ['sig:external-restore-phase3'],
      mediaType: 'application/json',
    });
    bundle.sourceEvidence = [sourceEvidence];
    const canonicalSourceEvidence = canonicalizeSourceEvidence(sourceEvidence);
    const qsig = buildQsigFixture(canonicalSourceEvidence.bytes);
    fixtures.sourceEvidence = qsig;
    bundle.attachments.publicKeys.push(buildBundledMlDsaPublicKey('pk-source-evidence', qsig.signerPublicKey));
    if (includeSourceEvidence) {
      bundle.attachments.sourceEvidenceSignatures.push(buildLifecycleQsigEntry({
        id: 'source-evidence-sig-1',
        signatureFamily: 'source-evidence',
        targetType: 'source-evidence',
        targetRef: `source-evidence:sha3-512:${canonicalSourceEvidence.digest.value}`,
        targetDigest: canonicalSourceEvidence.digest.value,
        qsigBytes: qsig.qsigBytes,
        publicKeyRef: 'pk-source-evidence',
      }));
    }
  }

  if (timestampTargetFamily) {
    const targetByFamily = {
      'archive-approval': { id: 'archive-approval-sig-1', qsigBytes: fixtures.archiveApproval?.qsigBytes },
      maintenance: { id: 'maintenance-sig-1', qsigBytes: fixtures.maintenance?.qsigBytes },
      'source-evidence': { id: 'source-evidence-sig-1', qsigBytes: fixtures.sourceEvidence?.qsigBytes },
    };
    const target = targetByFamily[timestampTargetFamily];
    if (!(target?.qsigBytes instanceof Uint8Array)) {
      throw new Error(`No detached signature bytes are available for timestampTargetFamily=${timestampTargetFamily}`);
    }
    const otsBytes = await buildOtsFixture(target.qsigBytes, { completeProof: true });
    bundle.attachments.timestamps.push({
      id: `ots-${timestampTargetFamily}`,
      type: 'opentimestamps',
      targetRef: target.id,
      targetDigest: { alg: 'SHA-256', value: toHex(await digestSha256(target.qsigBytes)) },
      proofEncoding: 'base64',
      proof: bytesToBase64(otsBytes),
    });
  }

  const parsed = await parseLifecycleBundleBytes(canonicalizeJsonToBytes(bundle));
  return {
    bundle: parsed.lifecycleBundle,
    bundleBytes: parsed.bytes,
    digestHex: parsed.digest.value,
    fixtures,
    transitionRecord,
    sourceEvidence,
  };
}

const LIFECYCLE_SAMPLE_VECTORS = Object.freeze({
  archiveStateCanonical: '{"aadPolicyId":"QV-AAD-HEADER-CHUNK-v1","archiveId":"abababababababababababababababababababababababababababababababab","authPolicyCommitment":{"alg":"SHA3-512","canonicalization":"QV-JSON-RFC8785-v1","value":"2c293897933111ac3037ce108c3ced8f05c0835cc880a3fa8cbcef913bea655ac203dfeca4167aeca4a972e2a7799bc9f08d0d1dbedad99b7afc9e3a61cef05a"},"canonicalization":"QV-JSON-RFC8785-v1","counterBits":32,"cryptoProfileId":"QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2","kdfTreeId":"QV-KDF-TREE-v2","maxChunkCount":4294967295,"nonceMode":"kmac-prefix64-ctr32","noncePolicyId":"QV-GCM-KMACPFX64-CTR32-v3","parentStateId":null,"qenc":{"chunkCount":3,"chunkSize":65536,"containerId":"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","containerIdAlg":"SHA3-512(qenc-header-bytes)","containerIdRole":"secondary-header-id","hashAlg":"SHA3-512","payloadLength":131072,"primaryAnchor":"qencHash","qencHash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},"schema":"quantum-vault-archive-state-descriptor/v1","stateType":"archive-state","version":1}',
  stateId: 'e72be26038375f48a0de6a43f3d04f2c0988f0c6634b688e60772877066180dbc19a6054ae2220ba202f945aee24e79b99be40171b391f7d91bd904a355e5117',
  cohortBindingCanonical: '{"archiveId":"abababababababababababababababababababababababababababababababab","bodyDefinition":{"excludes":["qcont-header","embedded-archive-state","embedded-archive-state-digest","embedded-cohort-binding","embedded-cohort-binding-digest","embedded-lifecycle-bundle","embedded-lifecycle-bundle-digest","external-signatures"],"includes":["fragment-len32-stream"]},"bodyDefinitionId":"QV-QCONT-SHARDBODY-v1","canonicalization":"QV-JSON-RFC8785-v1","cohortType":"shard-cohort","schema":"quantum-vault-cohort-binding/v1","shardBodyHashAlg":"SHA3-512","shardBodyHashes":["11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222","33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333","44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444","55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"],"sharding":{"reedSolomon":{"codecId":"QV-RS-ErasureCodes-v1","k":3,"n":5,"parity":2},"shamir":{"shareCount":5,"threshold":4}},"shareCommitment":{"hashAlg":"SHA3-512","input":"raw-shamir-share-bytes"},"shareCommitments":["66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666","77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777","88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888","99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"stateId":"e72be26038375f48a0de6a43f3d04f2c0988f0c6634b688e60772877066180dbc19a6054ae2220ba202f945aee24e79b99be40171b391f7d91bd904a355e5117","version":1}',
  cohortBindingDigest: '711a52b581d6a92e8721f5188c516f7af932f9ef2ae11007b33765126ab23b06a94042e47d2b831f1b29340a7744065b7e946f76c5cba47ffa559cd73b6c794c',
  cohortIdPreimageCanonical: '{"archiveId":"abababababababababababababababababababababababababababababababab","cohortBindingDigest":{"alg":"SHA3-512","value":"711a52b581d6a92e8721f5188c516f7af932f9ef2ae11007b33765126ab23b06a94042e47d2b831f1b29340a7744065b7e946f76c5cba47ffa559cd73b6c794c"},"stateId":"e72be26038375f48a0de6a43f3d04f2c0988f0c6634b688e60772877066180dbc19a6054ae2220ba202f945aee24e79b99be40171b391f7d91bd904a355e5117","type":"quantum-vault-cohort-id-preimage/v1"}',
  cohortId: 'd14b3541103107a1969fb55db486bd3734a7ef5e05e88e6ab6604a7d38e8cc9b',
  transitionRecordCanonical: '{"actorHints":{"ceremony":"reshare-01"},"archiveId":"abababababababababababababababababababababababababababababababab","canonicalization":"QV-JSON-RFC8785-v1","fromCohortBindingDigest":{"alg":"SHA3-512","value":"23232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323"},"fromCohortId":"0101010101010101010101010101010101010101010101010101010101010101","fromStateId":"e72be26038375f48a0de6a43f3d04f2c0988f0c6634b688e60772877066180dbc19a6054ae2220ba202f945aee24e79b99be40171b391f7d91bd904a355e5117","notes":null,"operatorRole":"operator","performedAt":"2026-03-25T12:34:56.000Z","reasonCode":"cohort-rotation","schema":"quantum-vault-transition-record/v1","toCohortBindingDigest":{"alg":"SHA3-512","value":"711a52b581d6a92e8721f5188c516f7af932f9ef2ae11007b33765126ab23b06a94042e47d2b831f1b29340a7744065b7e946f76c5cba47ffa559cd73b6c794c"},"toCohortId":"d14b3541103107a1969fb55db486bd3734a7ef5e05e88e6ab6604a7d38e8cc9b","toStateId":"e72be26038375f48a0de6a43f3d04f2c0988f0c6634b688e60772877066180dbc19a6054ae2220ba202f945aee24e79b99be40171b391f7d91bd904a355e5117","transitionType":"same-state-resharing","version":1}',
  sourceEvidenceCanonical: '{"canonicalization":"QV-JSON-RFC8785-v1","externalSourceSignatureRefs":["sig:external-1"],"mediaType":"application/json","relationType":"reviewed-source","schema":"quantum-vault-source-evidence/v1","sourceDigests":[{"alg":"SHA3-512","value":"45454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545"},{"alg":"SHA-256","value":"6767676767676767676767676767676767676767676767676767676767676767"}],"sourceEvidenceType":"source-evidence","sourceObjectType":"archive-manifest-v3","version":1}',
  lifecycleBundleDigest: '1ffa7e96eb0b05ae0f8b5e6bcb73927b82bd323f58cc5c9408c24f26de22804cbf52892381512a1f1d9fde4b1d848da78671eeca0a3e3d64a9c80950ddddebb6',
});

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function expectFailure(fn, message) {
  let failed = false;
  try {
    await fn();
  } catch {
    failed = true;
  }
  if (!failed) {
    throw new Error(message);
  }
}

function mutateTail(bytes, delta = 1) {
  const out = bytes.slice();
  const index = out.length - 1;
  out[index] ^= delta & 0xff;
  return out;
}

function removeQencKeyCommitmentBytes(containerBytes) {
  const parsed = parseQencHeader(containerBytes);
  const keyCommitmentLen = parsed.storedKeyCommitment?.length || 0;
  if (keyCommitmentLen <= 0) {
    throw new Error('No key commitment present in source container');
  }

  const headerWithoutCommitLen = parsed.offset - keyCommitmentLen;
  const out = new Uint8Array(headerWithoutCommitLen + (containerBytes.length - parsed.offset));
  out.set(containerBytes.subarray(0, headerWithoutCommitLen), 0);
  out.set(containerBytes.subarray(parsed.offset), headerWithoutCommitLen);
  return out;
}

function qcontManifestRegion(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  offset += 4; // magic
  const metaLen = dv.getUint16(offset, false);
  offset += 2 + metaLen;
  const manifestLen = dv.getUint32(offset, false);
  offset += 4;
  return {
    manifestStart: offset,
    manifestLen,
    manifestDigestStart: offset + manifestLen,
  };
}

function mutateQcontManifestByte(bytes, delta = 1) {
  const out = bytes.slice();
  const region = qcontManifestRegion(out);
  if (region.manifestLen <= 0) {
    throw new Error('No embedded manifest to mutate');
  }
  out[region.manifestStart] ^= delta & 0xff;
  return out;
}

function createLargeDeterministicPayload(length) {
  const payload = new Uint8Array(length);
  for (let i = 0; i < payload.length; i += 1) {
    payload[i] = (i * 31 + 17) & 0xff;
  }
  return payload;
}

const bytesToHex = toHex;

function u16le(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

function u32le(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
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

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  while ((out.length % 8) !== 0) out += '=';
  return out;
}

function encodeStellarAddress(publicKeyBytes) {
  const version = 6 << 3;
  const payload = concatBytes([Uint8Array.of(version), publicKeyBytes]);
  const crc = crc16Xmodem(payload);
  const checksum = Uint8Array.of(crc & 0xff, (crc >>> 8) & 0xff);
  return base32Encode(concatBytes([payload, checksum])).replace(/=+$/g, '');
}

const QSIG_FIXTURE_SUITES = Object.freeze({
  'mldsa-87': {
    suiteId: 0x03,
    signer: ml_dsa87,
  },
  'slhdsa-shake-128s': {
    suiteId: 0x11,
    signer: slh_dsa_shake_128s,
  },
});

const STELLAR_PUBLIC_NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
const STELLAR_ENVELOPE_TYPE_TX = 2;
const STELLAR_OPERATION_TYPE_MANAGE_DATA = 10;

function buildQsigFixture(messageBytes, { suite = 'mldsa-87', ctx = 'quantum-signer/v2', embeddedPublicKey = null } = {}) {
  const suiteConfig = QSIG_FIXTURE_SUITES[suite];
  if (!suiteConfig) {
    throw new Error(`Unsupported selftest qsig fixture suite: ${suite}`);
  }

  const { suiteId, signer } = suiteConfig;
  const keys = signer.keygen();
  const embeddedSignerPublicKey = embeddedPublicKey instanceof Uint8Array
    ? embeddedPublicKey
    : keys.publicKey;
  const payloadDigest = sha3_512(messageBytes);
  const ctxBytes = utf8ToBytes(ctx);
  const fingerprintRecord = concatBytes([Uint8Array.of(0x01), sha3_256(embeddedSignerPublicKey)]);
  const authMetaBytes = concatBytes([
    Uint8Array.of(0x10), u16le(embeddedSignerPublicKey.length), embeddedSignerPublicKey,
    Uint8Array.of(0x11), u16le(fingerprintRecord.length), fingerprintRecord,
  ]);
  const authMetaDigest = sha3_256(authMetaBytes);
  const displayMetaBytes = concatBytes([
    Uint8Array.of(0x01), u16le('archive.qvmanifest.json'.length), utf8ToBytes('archive.qvmanifest.json'),
    Uint8Array.of(0x02), u16le(8), (() => {
      const out = new Uint8Array(8);
      const view = new DataView(out.buffer);
      view.setUint32(0, messageBytes.length >>> 0, true);
      view.setUint32(4, 0, true);
      return out;
    })(),
  ]);
  const tbs = concatBytes([
    asciiBytes('QSTB'),
    Uint8Array.of(0x02, 0x00, 0x02, 0x00, suiteId, 0x01, 0x01, 0x01),
    payloadDigest,
    authMetaDigest,
  ]);
  const signature = signer.sign(tbs, keys.secretKey, { context: ctxBytes });
  const qsigBytes = concatBytes([
    asciiBytes('PQSG'),
    Uint8Array.of(0x02, 0x00, suiteId, 0x01, 0x01, 0x01),
    u16le(0x0007),
    payloadDigest,
    authMetaDigest,
    Uint8Array.of(ctxBytes.length, 0x00),
    u16le(authMetaBytes.length),
    u16le(displayMetaBytes.length),
    u32le(signature.length),
    ctxBytes,
    authMetaBytes,
    displayMetaBytes,
    signature,
  ]);
  const pqpkPrefix = concatBytes([
    asciiBytes('PQPK'),
    Uint8Array.of(0x01, 0x01, suiteId, 0x00),
    u32le(keys.publicKey.length),
    keys.publicKey,
  ]);
  const pqpkBytes = concatBytes([pqpkPrefix, u32le(crc32(pqpkPrefix))]);
  return {
    qsigBytes,
    pqpkBytes,
    signerPublicKey: keys.publicKey,
    embeddedSignerPublicKey,
  };
}

function mutateQsigMajorVersion(qsigBytes, versionMajor) {
  const out = qsigBytes.slice();
  out[4] = versionMajor & 0xff;
  return out;
}

function mutatePqpkMajorVersion(pqpkBytes, versionMajor) {
  const out = pqpkBytes.slice();
  out[4] = versionMajor & 0xff;
  const prefix = out.subarray(0, out.length - 4);
  const checksum = u32le(crc32(prefix));
  out.set(checksum, out.length - 4);
  return out;
}

function mutatePqpkVersionMinor(pqpkBytes, versionMinor) {
  const out = pqpkBytes.slice();
  out[5] = versionMinor & 0xff;
  const prefix = out.subarray(0, out.length - 4);
  const checksum = u32le(crc32(prefix));
  out.set(checksum, out.length - 4);
  return out;
}

function mutateQsigAuthMetaLen(qsigBytes, authMetaLen) {
  const out = qsigBytes.slice();
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint16(110, authMetaLen, true);
  return out;
}

function mutatePqpkKeyLen(pqpkBytes, keyLen) {
  const out = pqpkBytes.slice();
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(8, keyLen, true);
  return out;
}

function appendUnknownCriticalQsigMetadata(qsigBytes) {
  const parsed = unpackQsig(qsigBytes);
  const displayMetaParts = [];
  if (parsed.displayMetadata.filename) {
    displayMetaParts.push(Uint8Array.of(0x01), u16le(utf8ToBytes(parsed.displayMetadata.filename).length), utf8ToBytes(parsed.displayMetadata.filename));
  }
  if (parsed.displayMetadata.filesize !== undefined) {
    const sizeBytes = new Uint8Array(8);
    const view = new DataView(sizeBytes.buffer);
    const size = BigInt(parsed.displayMetadata.filesize);
    view.setUint32(0, Number(size & 0xffffffffn), true);
    view.setUint32(4, Number((size >> 32n) & 0xffffffffn), true);
    displayMetaParts.push(Uint8Array.of(0x02), u16le(8), sizeBytes);
  }
  if (parsed.displayMetadata.createdAt) {
    const createdAtBytes = utf8ToBytes(parsed.displayMetadata.createdAt);
    displayMetaParts.push(Uint8Array.of(0x03), u16le(createdAtBytes.length), createdAtBytes);
  }
  const displayMetaBytes = concatBytes(displayMetaParts);
  const authMetaBytes = concatBytes([
    Uint8Array.of(0x10), u16le(parsed.authenticatedMetadata.signerPublicKey.length), parsed.authenticatedMetadata.signerPublicKey,
    Uint8Array.of(0x11), u16le(parsed.authenticatedMetadata.signerFingerprint.length), parsed.authenticatedMetadata.signerFingerprint,
    Uint8Array.of(0x90), u16le(1), Uint8Array.of(0x01),
  ]);
  const mutated = concatBytes([
    asciiBytes('PQSG'),
    Uint8Array.of(
      parsed.versionMajor,
      parsed.versionMinor,
      parsed.suiteId,
      parsed.signatureProfileId,
      parsed.payloadDigestAlgId,
      parsed.authDigestAlgId
    ),
    u16le(parsed.flags || 0),
    parsed.payloadDigest,
    parsed.authMetaDigest,
    Uint8Array.of(parsed.ctxBytes.length, 0x00),
    u16le(authMetaBytes.length),
    u16le(displayMetaBytes.length),
    u32le(parsed.signature.length),
    parsed.ctxBytes,
    authMetaBytes,
    displayMetaBytes,
    parsed.signature,
  ]);
  return mutated;
}

async function buildOtsFixture(stampedBytes, { completeProof = false } = {}) {
  const header = concatBytes([
    asciiBytes('\x00OpenTimestamps\x00\x00Proof\x00'),
    Uint8Array.of(0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01, 0x08),
    await digestSha256(stampedBytes),
  ]);
  const tail = completeProof
    ? createLargeDeterministicPayload(1600)
    : createLargeDeterministicPayload(96);
  return concatBytes([header, tail]);
}

async function createStellarSignerMaterial() {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const signer = encodeStellarAddress(publicKeyBytes);
  return { keyPair, publicKeyBytes, signer };
}

async function buildStellarDigestFixture(messageBytes) {
  const sha256Bytes = await digestSha256(messageBytes);
  const sha3_512Bytes = sha3_512(messageBytes);
  return {
    hashes: [
      { alg: 'SHA-256', hex: bytesToHex(sha256Bytes) },
      { alg: 'SHA3-512', hex: bytesToHex(sha3_512Bytes) },
    ],
    digestEntries: [
      { name: 'ws.sha256', alg: 'SHA-256', bytes: sha256Bytes, digestHex: bytesToHex(sha256Bytes) },
      { name: 'ws.sha3-512', alg: 'SHA3-512', bytes: sha3_512Bytes, digestHex: bytesToHex(sha3_512Bytes) },
    ],
  };
}

async function buildStellarSignatureFixture(messageBytes, signerMaterial = null) {
  const material = signerMaterial || await createStellarSignerMaterial();
  const { hashes } = await buildStellarDigestFixture(messageBytes);
  const payload = await digestSha256(concatBytes([utf8ToBytes('Stellar Signed Message:\n'), messageBytes]));
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', material.keyPair.privateKey, payload));
  const doc = {
    schema: 'stellar-signature/v2',
    proofType: 'sep53-message-signature',
    payloadType: 'raw-bytes',
    signatureScheme: 'sep53-sha256-ed25519',
    input: { type: 'file', size: messageBytes.length, name: 'archive.qvmanifest.json' },
    signer: material.signer,
    hashes,
    signatureB64: bytesToBase64(signature),
  };
  return {
    bytes: new TextEncoder().encode(JSON.stringify(doc)),
    signer: material.signer,
    signerMaterial: material,
  };
}

async function buildStellarSignatureFixtureWithSigner(messageBytes) {
  const fixture = await buildStellarSignatureFixture(messageBytes);
  return {
    bytes: fixture.bytes,
    signer: fixture.signer,
    signerMaterial: fixture.signerMaterial,
  };
}

class XdrWriter {
  constructor() {
    this.parts = [];
  }

  writeRaw(bytes) {
    this.parts.push(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes));
  }

  writeInt32(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setInt32(0, Number(value), false);
    this.parts.push(out);
  }

  writeUint32(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, Number(value), false);
    this.parts.push(out);
  }

  writeInt64(value) {
    const normalized = BigInt(value);
    const out = new Uint8Array(8);
    const view = new DataView(out.buffer);
    view.setUint32(0, Number((normalized >> 32n) & 0xffffffffn), false);
    view.setUint32(4, Number(normalized & 0xffffffffn), false);
    this.parts.push(out);
  }

  writeOpaqueFixed(bytes) {
    const raw = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    this.parts.push(raw);
    const padLen = (4 - (raw.length % 4)) % 4;
    if (padLen > 0) {
      this.parts.push(new Uint8Array(padLen));
    }
  }

  writeOpaque(bytes) {
    const raw = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    this.writeInt32(raw.length);
    this.writeOpaqueFixed(raw);
  }

  writeString(value) {
    this.writeOpaque(utf8ToBytes(value));
  }

  finish() {
    return concatBytes(this.parts);
  }
}

function buildStellarManageDataTransaction(sourceAccountBytes, digestEntries) {
  const writer = new XdrWriter();
  writer.writeInt32(0);
  writer.writeOpaqueFixed(sourceAccountBytes);
  writer.writeUint32(200);
  writer.writeInt64(0n);
  writer.writeInt32(0);
  writer.writeInt32(0);
  writer.writeInt32(digestEntries.length);
  for (const entry of digestEntries) {
    writer.writeInt32(0);
    writer.writeInt32(STELLAR_OPERATION_TYPE_MANAGE_DATA);
    writer.writeString(entry.name);
    writer.writeInt32(1);
    writer.writeOpaque(entry.bytes);
  }
  writer.writeInt32(0);
  return writer.finish();
}

async function computeStellarTransactionHash(txXdr, passphrase) {
  const networkId = await digestSha256(utf8ToBytes(passphrase));
  const writer = new XdrWriter();
  writer.writeRaw(networkId);
  writer.writeInt32(STELLAR_ENVELOPE_TYPE_TX);
  writer.writeRaw(txXdr);
  return digestSha256(writer.finish());
}

function buildDecoratedSignatureEnvelope(txXdr, publicKeyBytes, signatureBytes) {
  const writer = new XdrWriter();
  writer.writeInt32(STELLAR_ENVELOPE_TYPE_TX);
  writer.writeRaw(txXdr);
  writer.writeInt32(1);
  writer.writeOpaqueFixed(publicKeyBytes.slice(28, 32));
  writer.writeOpaque(signatureBytes);
  return writer.finish();
}

async function buildStellarXdrSignatureFixture(messageBytes, signerMaterial = null) {
  const material = signerMaterial || await createStellarSignerMaterial();
  const { hashes, digestEntries } = await buildStellarDigestFixture(messageBytes);
  const txXdr = buildStellarManageDataTransaction(material.publicKeyBytes, digestEntries);
  const txHash = await computeStellarTransactionHash(txXdr, STELLAR_PUBLIC_NETWORK_PASSPHRASE);
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', material.keyPair.privateKey, txHash)
  );
  const signedXdr = buildDecoratedSignatureEnvelope(txXdr, material.publicKeyBytes, signatureBytes);
  const doc = {
    schema: 'stellar-signature/v2',
    proofType: 'xdr-envelope-proof',
    payloadType: 'detached-digests',
    signatureScheme: 'tx-envelope-ed25519',
    input: { type: 'file', size: messageBytes.length, name: 'archive.qvmanifest.json' },
    signer: material.signer,
    txSourceAccount: material.signer,
    hashes,
    manageData: {
      entries: digestEntries.map((entry) => ({
        name: entry.name,
        alg: entry.alg,
        digestHex: entry.digestHex,
      })),
    },
    network: {
      passphrase: STELLAR_PUBLIC_NETWORK_PASSPHRASE,
      hint: 'pubnet',
    },
    signedXdr: bytesToBase64(signedXdr),
  };
  return {
    bytes: new TextEncoder().encode(JSON.stringify(doc)),
    signer: material.signer,
    signerMaterial: material,
  };
}

function rewriteStellarSignatureDocument(bytes, {
  reverseHashes = false,
  reverseManageDataEntries = false,
  pretty = false,
} = {}) {
  const parsed = JSON.parse(new TextDecoder().decode(bytes));
  const rewritten = {
    signer: parsed.signer,
    schema: parsed.schema,
    proofType: parsed.proofType,
    payloadType: parsed.payloadType,
    signatureScheme: parsed.signatureScheme,
  };

  if (parsed.network && typeof parsed.network === 'object') {
    rewritten.network = { ...parsed.network };
  }

  if (Array.isArray(parsed.hashes)) {
    const hashes = parsed.hashes.map((entry) => ({ ...entry }));
    rewritten.hashes = reverseHashes ? hashes.reverse() : hashes;
  }

  if (parsed.manageData && typeof parsed.manageData === 'object') {
    const entries = Array.isArray(parsed.manageData.entries)
      ? parsed.manageData.entries.map((entry) => ({ ...entry }))
      : [];
    rewritten.manageData = {
      entries: reverseManageDataEntries ? entries.reverse() : entries,
    };
  }

  if (parsed.txSourceAccount !== undefined) {
    rewritten.txSourceAccount = parsed.txSourceAccount;
  }
  if (parsed.signedXdr !== undefined) {
    rewritten.signedXdr = parsed.signedXdr;
  }
  if (parsed.input && typeof parsed.input === 'object') {
    rewritten.input = { ...parsed.input };
  }
  if (parsed.signatureB64 !== undefined) {
    rewritten.signatureB64 = parsed.signatureB64;
  }

  const text = pretty
    ? `${JSON.stringify(rewritten, null, 2)}\n`
    : JSON.stringify(rewritten);
  return new TextEncoder().encode(text);
}

async function ensureRuntimeCrypto() {
  if (globalThis.crypto?.subtle) return;
  const isNode = typeof process !== 'undefined' && Boolean(process.versions?.node);
  if (!isNode) {
    throw new Error('Web Crypto API is not available in current runtime');
  }
  // Keep specifier non-literal so browser bundles do not try to resolve node built-ins.
  const nodeCryptoSpecifier = ['node', 'crypto'].join(':');
  const { webcrypto } = await import(nodeCryptoSpecifier);
  globalThis.crypto = webcrypto;
}

async function ensureErasureRuntime() {
  try {
    resolveErasureRuntime();
    return;
  } catch {
    // Continue with runtime bootstrap.
  }

  const isNode = typeof process !== 'undefined' && Boolean(process.versions?.node);
  if (!isNode) {
    throw new Error('Reed-Solomon runtime (globalThis.erasure) is unavailable');
  }

  const fsSpecifier = ['node', 'fs/promises'].join(':');
  const pathSpecifier = ['node', 'path'].join(':');
  const urlSpecifier = ['node', 'url'].join(':');

  const [{ readFile }, { dirname, resolve }, { fileURLToPath }] = await Promise.all([
    import(fsSpecifier),
    import(pathSpecifier),
    import(urlSpecifier),
  ]);

  const thisFile = fileURLToPath(import.meta.url);
  const erasurePath = resolve(dirname(thisFile), '../../../public/third-party/erasure.js');
  const erasureSource = await readFile(erasurePath, 'utf8');

  const cjsShim = { exports: {} };
  const evaluateErasure = new Function('module', 'exports', erasureSource);
  evaluateErasure(cjsShim, cjsShim.exports);
  globalThis.erasure = cjsShim.exports;

  resolveErasureRuntime();
}

async function runCase(name, fn) {
  try {
    await fn();
    return { name, ok: true };
  } catch (error) {
    return { name, ok: false, error: error?.message || String(error) };
  }
}

function classifySelfTestGroup(name) {
  const label = String(name || '');
  if (/^(AUTH|ATTACH|QCONT|CORE): /.test(label)) return null;
  if (/attach|OpenTimestamps|OTS/i.test(label)) return 'ATTACH';
  if (/pinning|signature|auth policy|strong-pq|stellar|detached/i.test(label)) return 'AUTH';
  if (/restore|parseShard|buildQcontShards|qcont|shard|split|cohort/i.test(label)) return 'QCONT';
  return 'CORE';
}

function prefixSelfTestName(name) {
  const group = classifySelfTestGroup(name);
  return group ? `${group}: ${name}` : name;
}

function buildCases() {
  return [
    {
      name: 'ML-KEM keygen',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        assert(publicKey.length === 1568, `public key length mismatch: ${publicKey.length}`);
        assert(secretKey.length === 3168, `secret key length mismatch: ${secretKey.length}`);
        validatePublicKey(publicKey);
        validateSecretKey(secretKey);
      },
    },
    {
      name: 'ML-KEM key import (.qkey bytes)',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const importedPublic = new Uint8Array(await fileLike('public.qkey', publicKey).arrayBuffer());
        const importedSecret = new Uint8Array(await fileLike('secret.qkey', secretKey).arrayBuffer());

        validatePublicKey(importedPublic);
        validateSecretKey(importedSecret);

        const originalPubHash = await hashBytes(publicKey);
        const importedPubHash = await hashBytes(importedPublic);
        const originalSecHash = await hashBytes(secretKey);
        const importedSecHash = await hashBytes(importedSecret);
        assert(originalPubHash === importedPubHash, 'imported public key hash mismatch');
        assert(originalSecHash === importedSecHash, 'imported secret key hash mismatch');
      },
    },
    {
      name: 'one file -> .qenc container encrypt',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('single-file-payload');
        const encrypted = await encryptFile(payload, publicKey, 'single.txt');
        const encryptedBytes = await blobToBytes(encrypted);
        const parsedHeader = parseQencHeader(encryptedBytes);

        assert(parsedHeader.metadata.fmt === FORMAT_VERSION, `unexpected format: ${parsedHeader.metadata.fmt}`);
        assert(parsedHeader.metadata.payloadFormat === 'wrapped-v1', 'unexpected payload format');
        assert(parsedHeader.metadata.aead_mode === 'single-container-aead', 'unexpected AEAD mode');
        assert(parsedHeader.metadata.noncePolicyId === NONCE_POLICY_SINGLE_CONTAINER_V1, 'single-container noncePolicyId mismatch');
        assert(parsedHeader.metadata.nonceMode === NONCE_MODE_RANDOM96, 'single-container nonceMode mismatch');
        assert(parsedHeader.metadata.counterBits === 0, 'single-container counterBits mismatch');
        assert(parsedHeader.metadata.maxChunkCount === 1, 'single-container maxChunkCount mismatch');
        assert(parsedHeader.metadata.cryptoProfileId === DEFAULT_CRYPTO_PROFILE.cryptoProfileId, 'cryptoProfileId mismatch');
        assert(parsedHeader.metadata.kdfTreeId === DEFAULT_CRYPTO_PROFILE.kdfTreeId, 'kdfTreeId mismatch');
        assert(parsedHeader.metadata.domainStrings.kdf === DEFAULT_CRYPTO_PROFILE.domainStrings.kdf, 'domainStrings.kdf mismatch');
        assert(parsedHeader.metadata.domainStrings.iv === DEFAULT_CRYPTO_PROFILE.domainStrings.iv, 'domainStrings.iv mismatch');
        assert(parsedHeader.metadata.domainStrings.kenc === DEFAULT_CRYPTO_PROFILE.domainStrings.kenc, 'domainStrings.kenc mismatch');
        assert(parsedHeader.metadata.domainStrings.kiv === DEFAULT_CRYPTO_PROFILE.domainStrings.kiv, 'domainStrings.kiv mismatch');

        const { decryptedBlob, metadata } = await decryptFile(encryptedBytes, secretKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert(metadata.originalFilename === 'single.txt', 'original filename mismatch');
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'single-file roundtrip mismatch');
      },
    },
    {
      name: 'multi files -> .qenc container encrypt',
      fn: async () => {
        const files = [
          fileLike('a.txt', textBytes('alpha payload')),
          fileLike('b.bin', createLargeDeterministicPayload(2048)),
        ];
        const { bundleBytes, bundleName, fileCount } = await createBundlePayloadFromFiles(files);
        assert(fileCount === 2, `expected 2 files in bundle, got ${fileCount}`);

        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const encrypted = await encryptFile(bundleBytes, publicKey, bundleName);
        const encryptedBytes = await blobToBytes(encrypted);
        const { decryptedBlob, metadata } = await decryptFile(encryptedBytes, secretKey);
        const decrypted = await blobToBytes(decryptedBlob);

        assert(metadata.originalFilename === bundleName, 'bundle original filename mismatch');
        assert(isBundlePayload(decrypted), 'decrypted multi-file payload is not a bundle');

        const entries = parseBundlePayload(decrypted);
        assert(entries.length === 2, `expected 2 entries after decrypt, got ${entries.length}`);
        assert(entries[0].name === 'a.txt', `unexpected first entry name: ${entries[0].name}`);
        assert(entries[1].name === 'b.bin', `unexpected second entry name: ${entries[1].name}`);
        assert((await hashBytes(entries[0].bytes)) === (await hashBytes(textBytes('alpha payload'))), 'entry a.txt hash mismatch');
      },
    },
    {
      name: '.qenc + secret.qkey -> split',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('split-check');
        const encrypted = await encryptFile(payload, publicKey, 'split.txt');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 });
        const shards = split.shards;

        assert(shards.length === 5, `expected 5 shards, got ${shards.length}`);
        assert(split.manifest.schema === ARCHIVE_MANIFEST_SCHEMA, `unexpected manifest schema: ${split.manifest.schema}`);
        assert(split.manifest.version === ARCHIVE_MANIFEST_VERSION, `unexpected manifest version: ${split.manifest.version}`);
        assert(split.manifest.canonicalization === MANIFEST_CANONICALIZATION_LABEL, `unexpected manifest canonicalization: ${split.manifest.canonicalization}`);
        assert(split.bundle.type === MANIFEST_BUNDLE_TYPE, `unexpected bundle type: ${split.bundle.type}`);
        assert(split.bundle.version === MANIFEST_BUNDLE_VERSION, `unexpected bundle version: ${split.bundle.version}`);
        assert(split.bundle.bundleCanonicalization === BUNDLE_CANONICALIZATION_LABEL, `unexpected bundle canonicalization: ${split.bundle.bundleCanonicalization}`);
        assert(split.bundle.manifestCanonicalization === MANIFEST_CANONICALIZATION_LABEL, `unexpected bundle manifestCanonicalization: ${split.bundle.manifestCanonicalization}`);
        for (const shard of shards) {
          const parsed = parseShard(await blobToBytes(shard.blob));
          assert(parsed.metaJSON.n === 5, 'shard metadata n mismatch');
          assert(parsed.metaJSON.k === 3, 'shard metadata k mismatch');
          assert(parsed.metaJSON.t === 4, 'shard metadata t mismatch');
          assert(parsed.metaJSON.hasEmbeddedBundle === true, 'shard metadata must indicate embedded bundle');
          assert(typeof parsed.metaJSON.bundleDigest === 'string' && parsed.metaJSON.bundleDigest.length === 128, 'bundle digest metadata missing');
        }
      },
    },
    {
      name: 'strict JSON parser preserves special property names as inert data keys',
      fn: async () => {
        const parsed = parseJsonTextStrict(
          '{"__proto__":{"polluted":1},"constructor":{"safe":2},"prototype":{"safe":3}}'
        );

        assert(Object.getPrototypeOf(parsed) === null, 'strict JSON parser returned an unexpected prototype-bearing object');
        assert(Object.prototype.hasOwnProperty.call(parsed, '__proto__'), 'strict JSON parser dropped __proto__');
        assert(Object.prototype.hasOwnProperty.call(parsed, 'constructor'), 'strict JSON parser dropped constructor');
        assert(Object.prototype.hasOwnProperty.call(parsed, 'prototype'), 'strict JSON parser dropped prototype');
        assert(Object.getPrototypeOf(parsed.__proto__) === null, '__proto__ value must remain a parsed JSON object');
        assert(parsed.__proto__.polluted === 1, '__proto__ value was not preserved as inert data');
        assert(parsed.constructor.safe === 2, 'constructor value was not preserved as inert data');
        assert(parsed.prototype.safe === 3, 'prototype value was not preserved as inert data');
        assert(
          canonicalizeJson(parsed) === '{"__proto__":{"polluted":1},"constructor":{"safe":2},"prototype":{"safe":3}}',
          'special-key canonicalization output mismatch'
        );
      },
    },
    {
      name: 'RFC 8785 canonicalization is byte-identical to legacy QV-C14N-v1 for covered manifest-family shapes and authPolicy variants',
      fn: async () => {
        const authPolicies = [
          { level: 'integrity-only', minValidSignatures: 1 },
          { level: 'any-signature', minValidSignatures: 2 },
          { level: 'strong-pq-signature', minValidSignatures: 3 },
        ];
        const manifestCases = [
          {
            label: 'per-chunk',
            overrides: {},
          },
          {
            label: 'single-container',
            overrides: {
              aeadMode: 'single-container-aead',
              ivStrategy: IV_STRATEGY_SINGLE_IV,
              chunkCount: 1,
              payloadLength: 2048,
              qencHash: 'c'.repeat(128),
              containerId: 'd'.repeat(128),
            },
          },
        ];

        for (const manifestCase of manifestCases) {
          for (const authPolicy of authPolicies) {
            const manifest = buildTestArchiveManifest({
              ...manifestCase.overrides,
              authPolicyLevel: authPolicy.level,
              minValidSignatures: authPolicy.minValidSignatures,
            });
            const bundle = buildInitialManifestBundle({ manifest, authPolicy });
            const normalizedAuthPolicy = normalizeAuthPolicy(authPolicy);
            const strictManifestBytes = canonicalizeArchiveManifest(manifest).bytes;
            const strictBundleBytes = canonicalizeManifestBundle(bundle).bytes;
            const strictAuthPolicyBytes = canonicalizeJsonToBytes(normalizedAuthPolicy);
            const label = `${manifestCase.label}/${authPolicy.level}/${authPolicy.minValidSignatures}`;

            assert(
              timingSafeEqual(strictManifestBytes, legacyCanonicalizeQvC14nToBytes(manifest)),
              `current archive-manifest shape diverged from legacy QV-C14N-v1 bytes for ${label}`
            );
            assert(
              timingSafeEqual(strictAuthPolicyBytes, legacyCanonicalizeQvC14nToBytes(normalizedAuthPolicy)),
              `current authPolicy shape diverged from legacy QV-C14N-v1 bytes for ${label}`
            );
            assert(
              timingSafeEqual(strictBundleBytes, legacyCanonicalizeQvC14nToBytes(bundle)),
              `current bundle shape diverged from legacy QV-C14N-v1 bytes for ${label}`
            );
          }
        }
      },
    },
    {
      name: 'manifest parser rejects duplicate object keys on the parse path',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('manifest-duplicate-keys');
        const encrypted = await encryptFile(payload, publicKey, 'manifest-duplicate-keys.bin');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 });
        const manifestText = new TextDecoder().decode(split.manifestBytes);
        const duplicateText = `{\"schema\":\"${ARCHIVE_MANIFEST_SCHEMA}\",${manifestText.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseArchiveManifestBytes(textBytes(duplicateText))),
          'manifest parser unexpectedly accepted duplicate object keys'
        );
      },
    },
    {
      name: 'manifest parser rejects lone surrogate escapes on the parse path',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('manifest-lone-surrogate');
        const encrypted = await encryptFile(payload, publicKey, 'manifest-lone-surrogate.bin');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 });
        const manifestText = new TextDecoder().decode(split.manifestBytes);
        const malformedText = manifestText.replace('"manifestType":"archive"', '"manifestType":"\\ud800"');

        await expectFailure(
          () => Promise.resolve(parseArchiveManifestBytes(textBytes(malformedText))),
          'manifest parser unexpectedly accepted a lone surrogate escape'
        );
      },
    },
    {
      name: 'manifest parser rejects unknown signed fields',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('manifest-unknown-fields');
        const encrypted = await encryptFile(payload, publicKey, 'manifest-unknown-fields.bin');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 });
        const manifestText = new TextDecoder().decode(split.manifestBytes);
        const malformedText = `{\"unexpectedField\":1,${manifestText.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseArchiveManifestBytes(textBytes(malformedText))),
          'manifest parser unexpectedly accepted an unknown signed field'
        );
      },
    },
    {
      name: 'manifest bundle parser rejects duplicate object keys on the parse path',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('bundle-duplicate-keys');
        const encrypted = await encryptFile(payload, publicKey, 'bundle-duplicate-keys.bin');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 });
        const bundleText = new TextDecoder().decode(split.bundleBytes);
        const duplicateText = `{\"type\":\"${MANIFEST_BUNDLE_TYPE}\",${bundleText.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseManifestBundleBytes(textBytes(duplicateText))),
          'manifest bundle parser unexpectedly accepted duplicate object keys'
        );
      },
    },
    {
      name: 'manifest builder and parser enforce the same documented current constraints',
      fn: async () => {
        const validManifest = buildTestArchiveManifest({
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const invalidManifestCases = [
          {
            label: 'qenc.format',
            overrides: { qencFormat: 'NOT-QV' },
            mutate(manifest) {
              manifest.qenc.format = 'NOT-QV';
            },
          },
          {
            label: 'qenc.ivStrategy',
            overrides: { ivStrategy: 'made-up-iv' },
            mutate(manifest) {
              manifest.qenc.ivStrategy = 'made-up-iv';
            },
          },
          {
            label: 'rsCodecId',
            overrides: { rsCodecId: 'OTHER-CODEC' },
            mutate(manifest) {
              manifest.sharding.reedSolomon.codecId = 'OTHER-CODEC';
            },
          },
          {
            label: 'qenc.chunkSize safe-integer bound',
            overrides: { chunkSize: 9007199254740992 },
            mutate(manifest) {
              manifest.qenc.chunkSize = 9007199254740992;
            },
          },
        ];

        for (const invalidCase of invalidManifestCases) {
          await expectFailure(
            () => Promise.resolve(buildArchiveManifest(buildManifestParams(invalidCase.overrides))),
            `builder unexpectedly accepted invalid ${invalidCase.label}`
          );
          const mutated = cloneJson(validManifest);
          invalidCase.mutate(mutated);
          await expectFailure(
            () => Promise.resolve(parseArchiveManifestBytes(canonicalizeJsonToBytes(mutated))),
            `parser unexpectedly accepted invalid ${invalidCase.label}`
          );
        }

        const validBundle = buildInitialManifestBundle({
          manifest: validManifest,
          authPolicy: { level: 'any-signature', minValidSignatures: 2 },
        });

        await expectFailure(
          () => Promise.resolve(buildInitialManifestBundle({
            manifest: validManifest,
            authPolicy: { level: 'any-signature', minValidSignatures: 9007199254740992 },
          })),
          'bundle builder unexpectedly accepted an unsafe authPolicy.minValidSignatures'
        );

        const mutatedBundle = cloneJson(validBundle);
        mutatedBundle.authPolicy.minValidSignatures = 9007199254740992;
        await expectFailure(
          () => Promise.resolve(parseManifestBundleBytes(canonicalizeJsonToBytes(mutatedBundle))),
          'bundle parser unexpectedly accepted an unsafe authPolicy.minValidSignatures'
        );
      },
    },
    {
      name: 'bundle preview parsing is isolated behind an explicit preview-only API',
      fn: async () => {
        const manifest = buildTestArchiveManifest({
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const bundle = buildInitialManifestBundle({
          manifest,
          authPolicy: { level: 'any-signature', minValidSignatures: 2 },
        });
        const canonical = canonicalizeManifestBundle(bundle);
        const previewBytes = textBytes(JSON.stringify(bundle, null, 2));

        await expectFailure(
          () => Promise.resolve(parseManifestBundleBytes(previewBytes)),
          'canonical bundle parser unexpectedly accepted preview-only non-canonical bytes'
        );

        const preview = parseManifestBundleBytesPreviewOnly(previewBytes);
        assert(preview.bundle.type === MANIFEST_BUNDLE_TYPE, 'preview-only bundle parser returned an unexpected bundle type');
        assert(
          timingSafeEqual(preview.bytes, canonical.bytes),
          'preview-only bundle parser did not preserve canonical bundle bytes'
        );
      },
    },
    {
      name: 'strict canonicalizer rejects lone surrogate strings',
      fn: async () => {
        await expectFailure(
          () => Promise.resolve(canonicalizeJsonToBytes({ bad: '\ud800' })),
          'strict canonicalizer unexpectedly accepted a lone surrogate string'
        );
      },
    },
    {
      name: 'RFC 8785 number serialization reference vectors',
      fn: async () => {
        const vectors = [
          [0, '0'],
          [-0, '0'],
          [1, '1'],
          [-1, '-1'],
          [0.5, '0.5'],
          [-0.5, '-0.5'],
          [1e20, '100000000000000000000'],
          [1e21, '1e+21'],
          [1e-7, '1e-7'],
          [1e-6, '0.000001'],
          [0.1 + 0.2, '0.30000000000000004'],
          [Number.MAX_SAFE_INTEGER, '9007199254740991'],
          [-Number.MAX_SAFE_INTEGER, '-9007199254740991'],
          [Number.MIN_VALUE, '5e-324'],
          [-Number.MIN_VALUE, '-5e-324'],
          [Number.MAX_VALUE, '1.7976931348623157e+308'],
          [-Number.MAX_VALUE, '-1.7976931348623157e+308'],
        ];
        for (const [input, expected] of vectors) {
          const result = canonicalizeJson(input);
          const label = Object.is(input, -0) ? '-0' : String(input);
          assert(result === expected, `RFC 8785 number vector failed: ${label} -> expected ${expected}, got ${result}`);
        }
      },
    },
    {
      name: 'RFC 8785 object key sorting reference vectors',
      fn: async () => {
        const vectors = [
          [{}, '{}'],
          [{ b: 2, a: 1 }, '{"a":1,"b":2}'],
          [{ '': '', a: 'b' }, '{"":"","a":"b"}'],
          [{ a: { c: 3, b: 2 } }, '{"a":{"b":2,"c":3}}'],
          [{ z: [1, { b: 'c', a: 'd' }], a: 'e' }, '{"a":"e","z":[1,{"a":"d","b":"c"}]}'],
        ];
        for (const [input, expected] of vectors) {
          const result = canonicalizeJson(input);
          assert(result === expected, `RFC 8785 object vector failed: expected ${expected}, got ${result}`);
        }
      },
    },
    {
      name: 'RFC 8785 composite canonicalization reference vector',
      fn: async () => {
        const sample = {
          numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
          string: 'Euro:\u20ac control:\u000f newline:\n quote:" slash:/ backslash:\\',
          literals: [null, true, false],
        };
        const expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"Euro:€ control:\\u000f newline:\\n quote:\\" slash:/ backslash:\\\\"}';
        const result = canonicalizeJson(sample);
        assert(result === expected, `RFC 8785 composite vector failed: expected ${expected}, got ${result}`);
      },
    },
    {
      name: 'RFC 8785 primitive and structural reference vectors',
      fn: async () => {
        const vectors = [
          [null, 'null'],
          [true, 'true'],
          [false, 'false'],
          ['', '""'],
          ['hello', '"hello"'],
          [[], '[]'],
          [[1, 2, 3], '[1,2,3]'],
          [[true, null, 'a'], '[true,null,"a"]'],
        ];
        for (const [input, expected] of vectors) {
          const result = canonicalizeJson(input);
          assert(result === expected, `RFC 8785 primitive vector failed: expected ${expected}, got ${result}`);
        }
      },
    },
    {
      name: 'strict canonicalizer rejects non-finite numbers and unsupported types',
      fn: async () => {
        await expectFailure(
          () => Promise.resolve(canonicalizeJsonToBytes(NaN)),
          'canonicalizer unexpectedly accepted NaN'
        );
        await expectFailure(
          () => Promise.resolve(canonicalizeJsonToBytes(Infinity)),
          'canonicalizer unexpectedly accepted Infinity'
        );
        await expectFailure(
          () => Promise.resolve(canonicalizeJsonToBytes(-Infinity)),
          'canonicalizer unexpectedly accepted -Infinity'
        );
        await expectFailure(
          () => Promise.resolve(canonicalizeJsonToBytes({ bad: undefined })),
          'canonicalizer unexpectedly accepted undefined value'
        );
        await expectFailure(
          () => Promise.resolve(canonicalizeJsonToBytes(BigInt(1))),
          'canonicalizer unexpectedly accepted bigint'
        );
      },
    },
    {
      name: 'canonical manifest byte identity remains stable for a representative current manifest',
      fn: async () => {
        const manifest = buildTestArchiveManifest({
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const expected = '{"aadPolicyId":"QV-AAD-HEADER-CHUNK-v1","authPolicyCommitment":{"alg":"SHA3-512","canonicalization":"QV-JSON-RFC8785-v1","value":"d40373eb7006f8d120acff9e34fe2b6e3cc8eca0cf3e78b48037026aae88d2c230a8b5cb1560710e43c46e6398c2e02bbb8bb0a56d86ca49059b50fcf90eb429"},"canonicalization":"QV-JSON-RFC8785-v1","counterBits":32,"cryptoProfileId":"QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2","kdfTreeId":"QV-KDF-TREE-v2","manifestType":"archive","maxChunkCount":4294967295,"nonceMode":"kmac-prefix64-ctr32","noncePolicyId":"QV-GCM-KMACPFX64-CTR32-v3","qenc":{"aeadMode":"per-chunk-aead","chunkCount":3,"chunkSize":65536,"containerId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","containerIdAlg":"SHA3-512(qenc-header-bytes)","containerIdRole":"secondary-header-id","format":"QVv1-5-0","hashAlg":"SHA3-512","ivStrategy":"kmac-prefix64-ctr32-v3","payloadLength":131072,"primaryAnchor":"qencHash","qencHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"schema":"quantum-vault-archive-manifest/v3","sharding":{"reedSolomon":{"codecId":"QV-RS-ErasureCodes-v1","k":3,"n":5,"parity":2},"shamir":{"shareCount":5,"threshold":4}},"version":3}';
        const canonicalized = canonicalizeArchiveManifest(manifest);

        assert(canonicalized.canonical === expected, 'canonical manifest regression string changed unexpectedly');
        assert(
          timingSafeEqual(canonicalized.bytes, textBytes(expected)),
          'canonical manifest regression bytes changed unexpectedly'
        );
      },
    },
    {
      name: 'successor archive-state canonical bytes and stateId regression vector remain stable',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const expectedArchiveId = generateArchiveId(new Uint8Array(32).fill(0xab));

        assert(expectedArchiveId === sample.archiveState.archiveId, 'archiveId generation regression mismatch');
        assert(
          sample.canonicalArchiveState.canonical === LIFECYCLE_SAMPLE_VECTORS.archiveStateCanonical,
          'archive-state canonical regression string changed unexpectedly'
        );
        assert(
          timingSafeEqual(sample.canonicalArchiveState.bytes, textBytes(LIFECYCLE_SAMPLE_VECTORS.archiveStateCanonical)),
          'archive-state canonical regression bytes changed unexpectedly'
        );
        assert(sample.stateId === LIFECYCLE_SAMPLE_VECTORS.stateId, 'archive-state stateId regression changed unexpectedly');

        const parsed = parseArchiveStateDescriptorBytes(sample.canonicalArchiveState.bytes);
        assert(parsed.digest.value === LIFECYCLE_SAMPLE_VECTORS.stateId, 'archive-state parser digest regression mismatch');
      },
    },
    {
      name: 'successor archive-state supports the single-container nonce contract',
      fn: async () => {
        const archiveState = buildArchiveStateDescriptor({
          archiveId: '12'.repeat(32),
          parentStateId: null,
          noncePolicyId: NONCE_POLICY_SINGLE_CONTAINER_V1,
          nonceMode: NONCE_MODE_RANDOM96,
          counterBits: 0,
          maxChunkCount: 1,
          chunkSize: 2048,
          chunkCount: 1,
          payloadLength: 2048,
          qencHash: '34'.repeat(64),
          containerId: '56'.repeat(64),
          authPolicy: { level: 'strong-pq-signature', minValidSignatures: 1 },
        });
        const canonicalized = canonicalizeLifecycleArchiveState(archiveState);
        const parsed = parseArchiveStateDescriptorBytes(canonicalized.bytes);

        assert(parsed.archiveState.noncePolicyId === NONCE_POLICY_SINGLE_CONTAINER_V1, 'single-container noncePolicyId mismatch');
        assert(parsed.archiveState.nonceMode === NONCE_MODE_RANDOM96, 'single-container nonceMode mismatch');
        assert(parsed.archiveState.counterBits === 0, 'single-container counterBits mismatch');
        assert(parsed.archiveState.maxChunkCount === 1, 'single-container maxChunkCount mismatch');
      },
    },
    {
      name: 'successor cohort-binding canonical bytes and cohortId regression vector remain stable',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const cohortIdPreimage = canonicalizeCohortIdPreimage({
          archiveId: sample.archiveState.archiveId,
          stateId: sample.stateId,
          cohortBindingDigest: sample.canonicalCohortBinding.digest,
        });

        assert(
          sample.canonicalCohortBinding.canonical === LIFECYCLE_SAMPLE_VECTORS.cohortBindingCanonical,
          'cohort-binding canonical regression string changed unexpectedly'
        );
        assert(
          timingSafeEqual(sample.canonicalCohortBinding.bytes, textBytes(LIFECYCLE_SAMPLE_VECTORS.cohortBindingCanonical)),
          'cohort-binding canonical regression bytes changed unexpectedly'
        );
        assert(
          sample.canonicalCohortBinding.digest.value === LIFECYCLE_SAMPLE_VECTORS.cohortBindingDigest,
          'cohort-binding digest regression changed unexpectedly'
        );
        assert(sample.cohortId === LIFECYCLE_SAMPLE_VECTORS.cohortId, 'cohortId regression changed unexpectedly');
        assert(
          cohortIdPreimage.canonical === LIFECYCLE_SAMPLE_VECTORS.cohortIdPreimageCanonical,
          'cohortId preimage canonical regression changed unexpectedly'
        );

        const parsed = parseCohortBindingBytes(sample.canonicalCohortBinding.bytes);
        assert(parsed.digest.value === LIFECYCLE_SAMPLE_VECTORS.cohortBindingDigest, 'cohort-binding parser digest regression mismatch');
      },
    },
    {
      name: 'successor transition-record and source-evidence canonical vectors remain stable',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalTransition = canonicalizeTransitionRecord(sample.transitionRecord);
        const canonicalSourceEvidence = canonicalizeSourceEvidence(sample.sourceEvidence);

        assert(
          canonicalTransition.canonical === LIFECYCLE_SAMPLE_VECTORS.transitionRecordCanonical,
          'transition-record canonical regression string changed unexpectedly'
        );
        assert(
          timingSafeEqual(canonicalTransition.bytes, textBytes(LIFECYCLE_SAMPLE_VECTORS.transitionRecordCanonical)),
          'transition-record canonical regression bytes changed unexpectedly'
        );
        assert(
          canonicalSourceEvidence.canonical === LIFECYCLE_SAMPLE_VECTORS.sourceEvidenceCanonical,
          'source-evidence canonical regression string changed unexpectedly'
        );
        assert(
          timingSafeEqual(canonicalSourceEvidence.bytes, textBytes(LIFECYCLE_SAMPLE_VECTORS.sourceEvidenceCanonical)),
          'source-evidence canonical regression bytes changed unexpectedly'
        );

        assert(
          parseTransitionRecordBytes(canonicalTransition.bytes).digest.value === canonicalTransition.digest.value,
          'transition-record parser digest regression mismatch'
        );
        assert(
          parseSourceEvidenceBytes(canonicalSourceEvidence.bytes).digest.value === canonicalSourceEvidence.digest.value,
          'source-evidence parser digest regression mismatch'
        );
      },
    },
    {
      name: 'successor lifecycle bundle digest and embedded links remain stable',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalBundle = await canonicalizeLifecycleBundle(sample.lifecycleBundle);
        const parsed = await parseLifecycleBundleBytes(canonicalBundle.bytes);

        assert(
          canonicalBundle.digest.value === LIFECYCLE_SAMPLE_VECTORS.lifecycleBundleDigest,
          'lifecycle bundle digest regression changed unexpectedly'
        );
        assert(parsed.digest.value === LIFECYCLE_SAMPLE_VECTORS.lifecycleBundleDigest, 'lifecycle bundle parser digest regression mismatch');
        assert(parsed.lifecycleBundle.archiveStateDigest.value === sample.stateId, 'lifecycle bundle archiveStateDigest mismatch');
        assert(
          parsed.lifecycleBundle.currentCohortBindingDigest.value === LIFECYCLE_SAMPLE_VECTORS.cohortBindingDigest,
          'lifecycle bundle cohort-binding digest mismatch'
        );
      },
    },
    {
      name: 'successor lifecycle bundle parser rejects version values beyond v1',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.version = 2;

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted version 2'
        );
      },
    },
    {
      name: 'successor archive-state parser rejects duplicate object keys on the parse path',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const duplicateText = `{\"schema\":\"${sample.archiveState.schema}\",${sample.canonicalArchiveState.canonical.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseArchiveStateDescriptorBytes(textBytes(duplicateText))),
          'archive-state parser unexpectedly accepted duplicate object keys'
        );
      },
    },
    {
      name: 'successor cohort-binding parser rejects duplicate object keys on the parse path',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const duplicateText = `{\"schema\":\"${sample.cohortBinding.schema}\",${sample.canonicalCohortBinding.canonical.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseCohortBindingBytes(textBytes(duplicateText))),
          'cohort-binding parser unexpectedly accepted duplicate object keys'
        );
      },
    },
    {
      name: 'successor transition-record parser rejects duplicate object keys on the parse path',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalTransition = canonicalizeTransitionRecord(sample.transitionRecord);
        const duplicateText = `{\"schema\":\"${sample.transitionRecord.schema}\",${canonicalTransition.canonical.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseTransitionRecordBytes(textBytes(duplicateText))),
          'transition-record parser unexpectedly accepted duplicate object keys'
        );
      },
    },
    {
      name: 'successor source-evidence parser rejects duplicate object keys on the parse path',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalSourceEvidence = canonicalizeSourceEvidence(sample.sourceEvidence);
        const duplicateText = `{\"schema\":\"${sample.sourceEvidence.schema}\",${canonicalSourceEvidence.canonical.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseSourceEvidenceBytes(textBytes(duplicateText))),
          'source-evidence parser unexpectedly accepted duplicate object keys'
        );
      },
    },
    {
      name: 'successor archive-state parser rejects self-referential stateId fields',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const withStateId = `{\"stateId\":\"${sample.stateId}\",${sample.canonicalArchiveState.canonical.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseArchiveStateDescriptorBytes(textBytes(withStateId))),
          'archive-state parser unexpectedly accepted self-referential stateId'
        );
      },
    },
    {
      name: 'successor cohort-binding parser rejects self-referential cohortId fields',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const withCohortId = `{\"cohortId\":\"${sample.cohortId}\",${sample.canonicalCohortBinding.canonical.slice(1)}`;

        await expectFailure(
          () => Promise.resolve(parseCohortBindingBytes(textBytes(withCohortId))),
          'cohort-binding parser unexpectedly accepted self-referential cohortId'
        );
      },
    },
    {
      name: 'successor lifecycle bundle parser rejects duplicate object keys on the parse path',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalBundle = await canonicalizeLifecycleBundle(sample.lifecycleBundle);
        const duplicateText = `{\"type\":\"${sample.lifecycleBundle.type}\",${canonicalBundle.canonical.slice(1)}`;

        await expectFailure(
          () => parseLifecycleBundleBytes(textBytes(duplicateText)),
          'lifecycle bundle parser unexpectedly accepted duplicate object keys'
        );
      },
    },
    {
      name: 'successor lifecycle bundle fails closed on unknown publicKeyRef',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'archive-approval-sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: sample.stateId },
            signatureEncoding: 'base64',
            signature: 'AA==',
            publicKeyRef: 'missing-public-key',
          },
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted an unknown publicKeyRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle accepts valid archive-approval qsig entries and exact OTS linkage over archive-state bytes',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const qsig = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const otsBytes = await buildOtsFixture(qsig.qsigBytes, { completeProof: true });
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.publicKeys = [
          {
            id: 'pk-1',
            kty: 'ml-dsa-public-key',
            suite: 'mldsa-87',
            encoding: 'base64',
            value: bytesToBase64(qsig.signerPublicKey),
          },
        ];
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: sample.stateId },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
            publicKeyRef: 'pk-1',
          },
        ];
        mutated.attachments.timestamps = [
          {
            id: 'ots-1',
            type: 'opentimestamps',
            targetRef: 'sig-1',
            targetDigest: { alg: 'SHA-256', value: toHex(await digestSha256(qsig.qsigBytes)) },
            proofEncoding: 'base64',
            proof: bytesToBase64(otsBytes),
          },
        ];

        const parsed = await parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated));
        assert(parsed.lifecycleBundle.attachments.archiveApprovalSignatures.length === 1, 'expected one archive-approval signature');
        assert(parsed.lifecycleBundle.attachments.timestamps.length === 1, 'expected one exact OTS attachment');

        const exports = buildAttachedArtifactExports(parsed.lifecycleBundle, 'archive');
        const pqpkExport = exports.find((entry) => entry.filename.endsWith('.pqpk'));
        assert(pqpkExport, 'expected successor export to emit a .pqpk file for bundled PQ keys');
        const unpacked = unpackPqpk(pqpkExport.bytes);
        assert(timingSafeEqual(unpacked.keyBytes, qsig.signerPublicKey), 'successor PQ export did not preserve the bundled raw public key');
      },
    },
    {
      name: 'successor lifecycle bundle rejects invalid archive-approval family mappings',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const qsig = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'sig-1',
            signatureFamily: 'maintenance',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: sample.stateId },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
          },
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted an invalid signatureFamily / targetType mapping'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects archive-approval targetRef mismatches',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const qsig = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${'f'.repeat(128)}`,
            targetDigest: { alg: 'SHA3-512', value: sample.stateId },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
          },
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a mismatched targetRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects archive-approval targetDigest mismatches',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const qsig = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: '0'.repeat(128) },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
          },
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a mismatched targetDigest'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects incompatible publicKeyRef entries',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const qsig = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const stellar = await createStellarSignerMaterial();
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.publicKeys = [
          {
            id: 'pk-1',
            kty: 'ed25519-public-key',
            suite: 'ed25519',
            encoding: 'stellar-address',
            value: stellar.signer,
          },
        ];
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: sample.stateId },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
            publicKeyRef: 'pk-1',
          },
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted an incompatible publicKeyRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects non-verifying publicKeyRef entries',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const qsig = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const wrongKey = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.publicKeys = [
          {
            id: 'pk-1',
            kty: 'ml-dsa-public-key',
            suite: 'mldsa-87',
            encoding: 'base64',
            value: bytesToBase64(wrongKey.signerPublicKey),
          },
        ];
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: sample.stateId },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
            publicKeyRef: 'pk-1',
          },
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a non-verifying publicKeyRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects OTS proofs that do not stamp the exact detached-signature bytes',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const qsig = buildQsigFixture(sample.canonicalArchiveState.bytes);
        const wrongOts = await buildOtsFixture(textBytes('wrong-signature-bytes'), { completeProof: true });
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.archiveApprovalSignatures = [
          {
            id: 'sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: sample.stateId },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
          },
        ];
        mutated.attachments.timestamps = [
          {
            id: 'ots-1',
            type: 'opentimestamps',
            targetRef: 'sig-1',
            targetDigest: { alg: 'SHA-256', value: toHex(await digestSha256(qsig.qsigBytes)) },
            proofEncoding: 'base64',
            proof: bytesToBase64(wrongOts),
          },
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted OTS evidence for different detached-signature bytes'
        );
      },
    },
    {
      name: 'successor lifecycle bundle accepts valid maintenance qsig entries and exact OTS linkage over transition-record bytes',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalTransition = canonicalizeTransitionRecord(sample.transitionRecord);
        const qsig = buildQsigFixture(canonicalTransition.bytes);
        const otsBytes = await buildOtsFixture(qsig.qsigBytes, { completeProof: true });
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.publicKeys = [
          buildBundledMlDsaPublicKey('pk-maint', qsig.signerPublicKey),
        ];
        mutated.attachments.maintenanceSignatures = [
          buildLifecycleQsigEntry({
            id: 'maint-sig-1',
            signatureFamily: 'maintenance',
            targetType: 'transition-record',
            targetRef: `transition:sha3-512:${canonicalTransition.digest.value}`,
            targetDigest: canonicalTransition.digest.value,
            qsigBytes: qsig.qsigBytes,
            publicKeyRef: 'pk-maint',
          }),
        ];
        mutated.attachments.timestamps = [
          {
            id: 'ots-maint-1',
            type: 'opentimestamps',
            targetRef: 'maint-sig-1',
            targetDigest: { alg: 'SHA-256', value: toHex(await digestSha256(qsig.qsigBytes)) },
            proofEncoding: 'base64',
            proof: bytesToBase64(otsBytes),
          },
        ];

        const parsed = await parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated));
        assert(parsed.lifecycleBundle.attachments.maintenanceSignatures.length === 1, 'expected one maintenance signature');
        assert(parsed.lifecycleBundle.attachments.timestamps.length === 1, 'expected one maintenance OTS attachment');
        const verification = await verifyLifecycleSignatureEntry(
          parsed.lifecycleBundle,
          parsed.lifecycleBundle.attachments.maintenanceSignatures[0]
        );
        assert(verification.ok === true, 'expected maintenance signature verification to succeed');
        assert(
          verification.targetRef === `transition:sha3-512:${canonicalTransition.digest.value}`,
          'maintenance verification resolved an unexpected targetRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects invalid maintenance family mappings',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalTransition = canonicalizeTransitionRecord(sample.transitionRecord);
        const qsig = buildQsigFixture(canonicalTransition.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.maintenanceSignatures = [
          buildLifecycleQsigEntry({
            id: 'maint-sig-1',
            signatureFamily: 'source-evidence',
            targetType: 'transition-record',
            targetRef: `transition:sha3-512:${canonicalTransition.digest.value}`,
            targetDigest: canonicalTransition.digest.value,
            qsigBytes: qsig.qsigBytes,
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted an invalid maintenance signatureFamily / targetType mapping'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects maintenance targetRef mismatches',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalTransition = canonicalizeTransitionRecord(sample.transitionRecord);
        const qsig = buildQsigFixture(canonicalTransition.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.maintenanceSignatures = [
          buildLifecycleQsigEntry({
            id: 'maint-sig-1',
            signatureFamily: 'maintenance',
            targetType: 'transition-record',
            targetRef: `transition:sha3-512:${'f'.repeat(128)}`,
            targetDigest: canonicalTransition.digest.value,
            qsigBytes: qsig.qsigBytes,
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a mismatched maintenance targetRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects maintenance targetDigest mismatches',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalTransition = canonicalizeTransitionRecord(sample.transitionRecord);
        const qsig = buildQsigFixture(canonicalTransition.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.maintenanceSignatures = [
          buildLifecycleQsigEntry({
            id: 'maint-sig-1',
            signatureFamily: 'maintenance',
            targetType: 'transition-record',
            targetRef: `transition:sha3-512:${canonicalTransition.digest.value}`,
            targetDigest: '0'.repeat(128),
            qsigBytes: qsig.qsigBytes,
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a mismatched maintenance targetDigest'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects non-verifying maintenance publicKeyRef entries',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalTransition = canonicalizeTransitionRecord(sample.transitionRecord);
        const qsig = buildQsigFixture(canonicalTransition.bytes);
        const wrongKey = buildQsigFixture(canonicalTransition.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.publicKeys = [
          buildBundledMlDsaPublicKey('pk-maint', wrongKey.signerPublicKey),
        ];
        mutated.attachments.maintenanceSignatures = [
          buildLifecycleQsigEntry({
            id: 'maint-sig-1',
            signatureFamily: 'maintenance',
            targetType: 'transition-record',
            targetRef: `transition:sha3-512:${canonicalTransition.digest.value}`,
            targetDigest: canonicalTransition.digest.value,
            qsigBytes: qsig.qsigBytes,
            publicKeyRef: 'pk-maint',
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a non-verifying maintenance publicKeyRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle accepts valid source-evidence qsig entries over source-evidence bytes',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalSourceEvidence = canonicalizeSourceEvidence(sample.sourceEvidence);
        const qsig = buildQsigFixture(canonicalSourceEvidence.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.publicKeys = [
          buildBundledMlDsaPublicKey('pk-source', qsig.signerPublicKey),
        ];
        mutated.attachments.sourceEvidenceSignatures = [
          buildLifecycleQsigEntry({
            id: 'source-sig-1',
            signatureFamily: 'source-evidence',
            targetType: 'source-evidence',
            targetRef: `source-evidence:sha3-512:${canonicalSourceEvidence.digest.value}`,
            targetDigest: canonicalSourceEvidence.digest.value,
            qsigBytes: qsig.qsigBytes,
            publicKeyRef: 'pk-source',
          }),
        ];

        const parsed = await parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated));
        assert(parsed.lifecycleBundle.attachments.sourceEvidenceSignatures.length === 1, 'expected one source-evidence signature');
        const verification = await verifyLifecycleSignatureEntry(
          parsed.lifecycleBundle,
          parsed.lifecycleBundle.attachments.sourceEvidenceSignatures[0]
        );
        assert(verification.ok === true, 'expected source-evidence signature verification to succeed');
        assert(
          verification.targetRef === `source-evidence:sha3-512:${canonicalSourceEvidence.digest.value}`,
          'source-evidence verification resolved an unexpected targetRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects invalid source-evidence family mappings',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalSourceEvidence = canonicalizeSourceEvidence(sample.sourceEvidence);
        const qsig = buildQsigFixture(canonicalSourceEvidence.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.sourceEvidenceSignatures = [
          buildLifecycleQsigEntry({
            id: 'source-sig-1',
            signatureFamily: 'maintenance',
            targetType: 'source-evidence',
            targetRef: `source-evidence:sha3-512:${canonicalSourceEvidence.digest.value}`,
            targetDigest: canonicalSourceEvidence.digest.value,
            qsigBytes: qsig.qsigBytes,
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted an invalid source-evidence signatureFamily / targetType mapping'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects source-evidence targetRef mismatches',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalSourceEvidence = canonicalizeSourceEvidence(sample.sourceEvidence);
        const qsig = buildQsigFixture(canonicalSourceEvidence.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.sourceEvidenceSignatures = [
          buildLifecycleQsigEntry({
            id: 'source-sig-1',
            signatureFamily: 'source-evidence',
            targetType: 'source-evidence',
            targetRef: `source-evidence:sha3-512:${'f'.repeat(128)}`,
            targetDigest: canonicalSourceEvidence.digest.value,
            qsigBytes: qsig.qsigBytes,
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a mismatched source-evidence targetRef'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects source-evidence targetDigest mismatches',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalSourceEvidence = canonicalizeSourceEvidence(sample.sourceEvidence);
        const qsig = buildQsigFixture(canonicalSourceEvidence.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.sourceEvidenceSignatures = [
          buildLifecycleQsigEntry({
            id: 'source-sig-1',
            signatureFamily: 'source-evidence',
            targetType: 'source-evidence',
            targetRef: `source-evidence:sha3-512:${canonicalSourceEvidence.digest.value}`,
            targetDigest: '0'.repeat(128),
            qsigBytes: qsig.qsigBytes,
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a mismatched source-evidence targetDigest'
        );
      },
    },
    {
      name: 'successor lifecycle bundle rejects non-verifying source-evidence publicKeyRef entries',
      fn: async () => {
        const sample = await buildLifecycleSampleArtifacts();
        const canonicalSourceEvidence = canonicalizeSourceEvidence(sample.sourceEvidence);
        const qsig = buildQsigFixture(canonicalSourceEvidence.bytes);
        const wrongKey = buildQsigFixture(canonicalSourceEvidence.bytes);
        const mutated = cloneJson(sample.lifecycleBundle);
        mutated.attachments.publicKeys = [
          buildBundledMlDsaPublicKey('pk-source', wrongKey.signerPublicKey),
        ];
        mutated.attachments.sourceEvidenceSignatures = [
          buildLifecycleQsigEntry({
            id: 'source-sig-1',
            signatureFamily: 'source-evidence',
            targetType: 'source-evidence',
            targetRef: `source-evidence:sha3-512:${canonicalSourceEvidence.digest.value}`,
            targetDigest: canonicalSourceEvidence.digest.value,
            qsigBytes: qsig.qsigBytes,
            publicKeyRef: 'pk-source',
          }),
        ];

        await expectFailure(
          () => parseLifecycleBundleBytes(canonicalizeJsonToBytes(mutated)),
          'lifecycle bundle unexpectedly accepted a non-verifying source-evidence publicKeyRef'
        );
      },
    },
    {
      name: 'successor attach preserves archive-state and cohort-binding bytes while attaching archive-approval signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(CHUNK_SIZE + 3072);
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'lifecycle-attach-regression.bin'));
        const split = await buildLifecycleQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.archiveStateBytes);

        const attached = await attachLifecycleBundleToShards(parsed, {
          signatures: [{ name: 'archive-approval.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });

        assert(timingSafeEqual(attached.signableArchiveStateBytes, split.archiveStateBytes), 'attach changed the external signer target bytes');
        assert(timingSafeEqual(attached.archiveStateBytes, split.archiveStateBytes), 'attach changed archive-state bytes');
        assert(timingSafeEqual(attached.cohortBindingBytes, split.cohortBindingBytes), 'attach changed cohort-binding bytes');

        const reparsed = await Promise.all(attached.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));
        for (const shard of reparsed) {
          assert(timingSafeEqual(shard.archiveStateBytes, split.archiveStateBytes), 'rewritten shard archive-state bytes changed unexpectedly');
          assert(timingSafeEqual(shard.cohortBindingBytes, split.cohortBindingBytes), 'rewritten shard cohort-binding bytes changed unexpectedly');
        }
      },
    },
    {
      name: 'successor attach preserves mixed embedded lifecycle-bundle digests inside one cohort during partial rewrites',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(CHUNK_SIZE + 6144);
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'lifecycle-partial-rewrite.bin'));
        const split = await buildLifecycleQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const parsedOriginal = await Promise.all(split.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));

        const sigA = buildQsigFixture(split.archiveStateBytes);
        const firstAttach = await attachLifecycleBundleToShards(parsedOriginal, {
          signatures: [{ name: 'archive-a.qsig', bytes: sigA.qsigBytes }],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes],
        });
        const parsedFirstAttach = await Promise.all(firstAttach.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));

        const sigB = buildQsigFixture(firstAttach.archiveStateBytes);
        const secondAttach = await attachLifecycleBundleToShards(parsedFirstAttach.slice(0, 2), {
          lifecycleBundleBytes: firstAttach.lifecycleBundleBytes,
          signatures: [{ name: 'archive-b.qsig', bytes: sigB.qsigBytes }],
          pqPublicKeyFileBytesList: [sigB.pqpkBytes],
        });
        const parsedSecondSubset = await Promise.all(secondAttach.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));
        const mixedCohort = [...parsedSecondSubset, ...parsedFirstAttach.slice(2)];
        assert(
          new Set(mixedCohort.map((shard) => `${shard.metaJSON.archiveId}:${shard.metaJSON.stateId}:${shard.metaJSON.cohortId}`)).size === 1,
          'partial successor rewrite unexpectedly changed the cohort identity'
        );

        const sigC = buildQsigFixture(split.archiveStateBytes);
        const mixedAttach = await attachLifecycleBundleToShards(mixedCohort, {
          lifecycleBundleBytes: secondAttach.lifecycleBundleBytes,
          signatures: [{ name: 'archive-c.qsig', bytes: sigC.qsigBytes }],
          pqPublicKeyFileBytesList: [sigC.pqpkBytes],
        });

        assert(mixedAttach.mixedEmbeddedLifecycleBundleDigests === true, 'expected mixed embedded lifecycle-bundle digests to be reported');
        assert(mixedAttach.embeddedLifecycleBundleDigests.length === 2, 'expected two embedded lifecycle-bundle digests inside one cohort');
      },
    },
    {
      name: 'successor shard embedding round-trips archive-state cohort-binding and lifecycle bundle bytes',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(CHUNK_SIZE + 4096);
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'lifecycle-successor.bin'));
        const archiveIdRandomBytes = new Uint8Array(32).fill(0xab);
        const split = await buildLifecycleQcontShards(
          qencBytes,
          pair.secretKey,
          { n: 5, k: 3 },
          { authPolicyLevel: 'integrity-only', archiveIdRandomBytes }
        );

        assert(split.shards.length === 5, 'expected 5 successor shards');
        assert(split.archiveId === generateArchiveId(archiveIdRandomBytes), 'successor shard archiveId mismatch');
        assert(split.stateId === split.archiveStateDigestHex, 'successor shard stateId must equal archive-state digest');
        assert(split.cohortBinding.stateId === split.stateId, 'successor cohort-binding stateId mismatch');
        assert(split.lifecycleBundle.archiveStateDigest.value === split.stateId, 'successor lifecycle bundle archiveStateDigest mismatch');
        assert(
          split.lifecycleBundle.currentCohortBindingDigest.value === split.cohortBindingDigestHex,
          'successor lifecycle bundle cohort-binding digest mismatch'
        );

        for (const shard of split.shards) {
          const parsed = await parseLifecycleShard(await blobToBytes(shard.blob));
          assert(parsed.metaJSON.archiveId === split.archiveId, 'successor shard metadata archiveId mismatch');
          assert(parsed.metaJSON.stateId === split.stateId, 'successor shard metadata stateId mismatch');
          assert(parsed.metaJSON.cohortId === split.cohortId, 'successor shard metadata cohortId mismatch');
          assert(parsed.shardIndex === shard.index, 'successor shard index mismatch');
          assert(parsed.archiveState.archiveId === split.archiveId, 'embedded archive-state archiveId mismatch');
          assert(parsed.stateId === split.stateId, 'embedded archive-state stateId mismatch');
          assert(parsed.cohortBinding.stateId === split.stateId, 'embedded cohort-binding stateId mismatch');
          assert(parsed.cohortId === split.cohortId, 'embedded cohortId mismatch');
          assert(
            timingSafeEqual(parsed.archiveStateBytes, split.archiveStateBytes),
            'embedded archive-state bytes changed unexpectedly'
          );
          assert(
            timingSafeEqual(parsed.cohortBindingBytes, split.cohortBindingBytes),
            'embedded cohort-binding bytes changed unexpectedly'
          );
          assert(
            timingSafeEqual(parsed.lifecycleBundleBytes, split.lifecycleBundleBytes),
            'embedded lifecycle bundle bytes changed unexpectedly'
          );
        }
      },
    },
    {
      name: 'successor restore rejects mixed archiveId candidate inputs without explicit selection',
      fn: async () => {
        const sampleA = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-mixed-archive-a') });
        const sampleB = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-mixed-archive-b') });
        const mixed = [
          ...sampleA.parsed.slice(0, 3),
          sampleB.parsed[0],
        ];

        await expectFailure(
          () => restoreFromShards(mixed, { onLog: () => {}, onError: () => {} }),
          'successor restore unexpectedly accepted mixed archiveId candidates without explicit selection'
        );
      },
    },
    {
      name: 'successor restore rejects mixed stateId candidate inputs without explicit selection',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-mixed-state') });
        const mixed = sample.parsed.map((shard, index) => (
          index === 0
            ? {
                ...shard,
                stateId: 'aa'.repeat(64),
                metaJSON: { ...shard.metaJSON, stateId: 'aa'.repeat(64) },
              }
            : shard
        ));

        await expectFailure(
          () => restoreFromShards(mixed, { onLog: () => {}, onError: () => {} }),
          'successor restore unexpectedly accepted mixed stateId candidates without explicit selection'
        );
      },
    },
    {
      name: 'successor restore rejects mixed cohortId candidate inputs without explicit selection',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-mixed-cohort') });
        const mixed = sample.parsed.map((shard, index) => (
          index === 0
            ? {
                ...shard,
                cohortId: 'bb'.repeat(32),
                metaJSON: { ...shard.metaJSON, cohortId: 'bb'.repeat(32) },
              }
            : shard
        ));

        await expectFailure(
          () => restoreFromShards(mixed, { onLog: () => {}, onError: () => {} }),
          'successor restore unexpectedly accepted mixed cohortId candidates without explicit selection'
        );
      },
    },
    {
      name: 'successor restore rejects exact archive-state byte mismatches inside one candidate set',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-archive-state-byte-mismatch') });
        const mutatedBytes = sample.parsed[0].archiveStateBytes.slice();
        mutatedBytes[mutatedBytes.length - 1] ^= 0x01;
        const mixed = sample.parsed.map((shard, index) => (
          index === 0
            ? { ...shard, archiveStateBytes: mutatedBytes }
            : shard
        ));

        await expectFailure(
          () => restoreFromShards(mixed, { onLog: () => {}, onError: () => {} }),
          'successor restore unexpectedly accepted an exact archive-state byte mismatch'
        );
      },
    },
    {
      name: 'successor restore rejects exact cohort-binding byte mismatches inside one candidate set',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-cohort-binding-byte-mismatch') });
        const mutatedBytes = sample.parsed[0].cohortBindingBytes.slice();
        mutatedBytes[mutatedBytes.length - 1] ^= 0x01;
        const mixed = sample.parsed.map((shard, index) => (
          index === 0
            ? { ...shard, cohortBindingBytes: mutatedBytes }
            : shard
        ));

        await expectFailure(
          () => restoreFromShards(mixed, { onLog: () => {}, onError: () => {} }),
          'successor restore unexpectedly accepted an exact cohort-binding byte mismatch'
        );
      },
    },
    {
      name: 'successor restore accepts a valid same-cohort shard set with one lifecycle-bundle digest',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-restore-single-bundle'),
          authPolicyLevel: 'any-signature',
        });
        const sig = buildQsigFixture(sample.split.archiveStateBytes);
        const attached = await attachLifecycleBundleToShards(sample.parsed, {
          signatures: [{ name: 'archive-approval.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });
        const parsedAttached = await Promise.all(attached.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));

        const restored = await restoreFromShards(parsedAttached, { onLog: () => {}, onError: () => {} });
        assert(restored.archiveId === sample.split.archiveId, 'successor restore archiveId mismatch');
        assert(restored.stateId === sample.split.stateId, 'successor restore stateId mismatch');
        assert(restored.cohortId === sample.split.cohortId, 'successor restore cohortId mismatch');
        assert(restored.lifecycleBundleDigestHex === attached.lifecycleBundleDigestHex, 'successor restore picked the wrong lifecycle-bundle digest');
        assert(
          Array.isArray(restored.embeddedLifecycleBundleDigestsUsed) &&
          restored.embeddedLifecycleBundleDigestsUsed.length === 1 &&
          restored.embeddedLifecycleBundleDigestsUsed[0] === attached.lifecycleBundleDigestHex,
          'successor restore should report exactly one embedded lifecycle-bundle digest'
        );
        assert(restored.authenticity.status.archiveApprovalSignatureVerified === true, 'expected archive-approval signature verification');
        assert(restored.authenticity.status.signerPinned === true, 'expected signer pinning from bundled key material');
        assert(restored.authenticity.status.policySatisfied === true, 'expected archive policy satisfaction');
      },
    },
    {
      name: 'successor restore requires explicit lifecycle-bundle selection when one cohort carries multiple bundle digests',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-restore-multi-bundle'),
          authPolicyLevel: 'any-signature',
        });
        const sigA = buildQsigFixture(sample.split.archiveStateBytes);
        const firstAttach = await attachLifecycleBundleToShards(sample.parsed, {
          signatures: [{ name: 'archive-a.qsig', bytes: sigA.qsigBytes }],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes],
        });
        const parsedFirstAttach = await Promise.all(firstAttach.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));

        const sigB = buildQsigFixture(sample.split.archiveStateBytes);
        const secondAttach = await attachLifecycleBundleToShards(parsedFirstAttach.slice(0, 2), {
          lifecycleBundleBytes: firstAttach.lifecycleBundleBytes,
          signatures: [{ name: 'archive-b.qsig', bytes: sigB.qsigBytes }],
          pqPublicKeyFileBytesList: [sigB.pqpkBytes],
        });
        const parsedSubset = await Promise.all(secondAttach.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));
        const mixed = [...parsedSubset, ...parsedFirstAttach.slice(2)];

        await expectFailure(
          () => restoreFromShards(mixed, { onLog: () => {}, onError: () => {} }),
          'successor restore unexpectedly auto-selected one lifecycle-bundle variant from a mixed-digest cohort'
        );

        const restored = await restoreFromShards(mixed, {
          onLog: () => {},
          onError: () => {},
          verification: { selectedLifecycleBundleDigestHex: secondAttach.lifecycleBundleDigestHex },
        });
        assert(restored.lifecycleBundleDigestHex === secondAttach.lifecycleBundleDigestHex, 'explicit lifecycle-bundle digest selection picked the wrong bundle');
        assert(restored.authenticity.status.bundleCohortMixed === true, 'mixed embedded lifecycle-bundle digests should be reported honestly');
      },
    },
    {
      name: 'successor restore accepts an uploaded lifecycle bundle only when its digests match the selected state and cohort',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-uploaded-lifecycle-bundle-accept'),
          authPolicyLevel: 'any-signature',
        });
        const sig = buildQsigFixture(sample.split.archiveStateBytes);
        const attached = await attachLifecycleBundleToShards(sample.parsed, {
          signatures: [{ name: 'archive-approval.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });
        const parsedAttached = await Promise.all(attached.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));

        const restored = await restoreFromShards(parsedAttached, {
          onLog: () => {},
          onError: () => {},
          verification: { lifecycleBundleBytes: attached.lifecycleBundleBytes },
        });
        assert(restored.selectionSource === 'uploaded-lifecycle-bundle', `unexpected successor selection source: ${restored.selectionSource}`);
        assert(restored.lifecycleBundleDigestHex === attached.lifecycleBundleDigestHex, 'uploaded lifecycle bundle should drive the selected digest');
      },
    },
    {
      name: 'successor restore rejects an uploaded lifecycle bundle whose digests do not match the selected state and cohort',
      fn: async () => {
        const sampleA = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-uploaded-lifecycle-bundle-a'),
          authPolicyLevel: 'any-signature',
        });
        const sampleB = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-uploaded-lifecycle-bundle-b'),
          authPolicyLevel: 'any-signature',
        });
        const sigA = buildQsigFixture(sampleA.split.archiveStateBytes);
        const attachedA = await attachLifecycleBundleToShards(sampleA.parsed, {
          signatures: [{ name: 'archive-approval-a.qsig', bytes: sigA.qsigBytes }],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes],
        });
        const sigB = buildQsigFixture(sampleB.split.archiveStateBytes);
        const attachedB = await attachLifecycleBundleToShards(sampleB.parsed, {
          signatures: [{ name: 'archive-approval-b.qsig', bytes: sigB.qsigBytes }],
          pqPublicKeyFileBytesList: [sigB.pqpkBytes],
        });
        const parsedAttachedA = await Promise.all(attachedA.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));

        await expectFailure(
          () => restoreFromShards(parsedAttachedA, {
            onLog: () => {},
            onError: () => {},
            verification: { lifecycleBundleBytes: attachedB.lifecycleBundleBytes },
          }),
          'successor restore unexpectedly accepted an uploaded lifecycle bundle from a different state/cohort'
        );
      },
    },
    {
      name: 'successor restore uses an uploaded archive-state descriptor to disambiguate mixed candidate inputs',
      fn: async () => {
        const sampleA = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-uploaded-archive-state-a') });
        const sampleB = await buildSuccessorRestoreSample({ payloadBytes: textBytes('successor-uploaded-archive-state-b') });
        const mixed = [
          ...sampleA.parsed.slice(0, 4),
          sampleB.parsed[0],
        ];

        const restored = await restoreFromShards(mixed, {
          onLog: () => {},
          onError: () => {},
          verification: { archiveStateBytes: sampleA.split.archiveStateBytes },
        });
        assert(restored.archiveId === sampleA.split.archiveId, 'uploaded archive-state should select the intended archiveId');
        assert(restored.selectionSource === 'uploaded-archive-state', `unexpected selection source: ${restored.selectionSource}`);
      },
    },
    {
      name: 'successor restore keeps archive approval, maintenance, source evidence, pinning, policy, and OTS as distinct states',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-restore-state-separation'),
          authPolicyLevel: 'any-signature',
        });
        const bundleVariant = await buildSuccessorVerificationBundle(sample.split, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 1,
          includeArchiveApproval: true,
          includeMaintenance: true,
          includeSourceEvidence: true,
          timestampTargetFamily: 'maintenance',
        });
        const rewritten = await rewriteLifecycleBundleSubset(sample.parsed, bundleVariant.bundleBytes);

        const restored = await restoreFromShards(rewritten, { onLog: () => {}, onError: () => {} });
        assert(restored.authenticity.status.integrityVerified === true, 'expected integrityVerified');
        assert(restored.authenticity.status.archiveApprovalSignatureVerified === true, 'expected archive-approval signature verification');
        assert(restored.authenticity.status.maintenanceSignatureVerified === true, 'expected maintenance signature verification');
        assert(restored.authenticity.status.sourceEvidenceSignatureVerified === true, 'expected source-evidence signature verification');
        assert(restored.authenticity.status.otsEvidenceLinked === true, 'expected exact OTS linkage state');
        assert(restored.authenticity.status.signerPinned === true, 'expected signer pinning from bundled keys');
        assert(restored.authenticity.status.policySatisfied === true, 'expected archive policy satisfaction');
        assert(restored.authenticity.verification.counts.validArchiveApproval === 1, 'only one archive-approval signature should count toward archive policy');
        assert(restored.authenticity.verification.counts.archiveApprovalPinnedValidTotal === 1, 'only archive-approval pinning should drive archive trust status');
        assert(restored.authenticity.verification.counts.validMaintenance === 1, 'expected one valid maintenance signature');
        assert(restored.authenticity.verification.counts.validSourceEvidence === 1, 'expected one valid source-evidence signature');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 3, 'all verified detached signature families should still contribute to aggregate pinning counts');
      },
    },
    {
      name: 'successor restore does not let maintenance or source-evidence pinning imply archive-approval pinning',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-restore-pinning-family-separation'),
          authPolicyLevel: 'integrity-only',
        });
        const bundleVariant = await buildSuccessorVerificationBundle(sample.split, {
          authPolicyLevel: 'integrity-only',
          minValidSignatures: 1,
          includeArchiveApproval: false,
          includeMaintenance: true,
          includeSourceEvidence: true,
          timestampTargetFamily: 'maintenance',
        });
        const rewritten = await rewriteLifecycleBundleSubset(sample.parsed, bundleVariant.bundleBytes);

        const restored = await restoreFromShards(rewritten, { onLog: () => {}, onError: () => {} });
        assert(restored.authenticity.status.integrityVerified === true, 'expected integrityVerified');
        assert(restored.authenticity.status.archiveApprovalSignatureVerified === false, 'maintenance/source-evidence must not imply archive-approval verification');
        assert(restored.authenticity.status.signerPinned === false, 'maintenance/source-evidence must not imply archive-approval signer pinning');
        assert(restored.authenticity.status.bundlePinned === false, 'maintenance/source-evidence must not imply archive-approval bundle pinning');
        assert(restored.authenticity.status.userPinned === false, 'maintenance/source-evidence must not imply archive-approval user pinning');
        assert(restored.authenticity.status.maintenanceSignatureVerified === true, 'expected maintenance signature verification');
        assert(restored.authenticity.status.sourceEvidenceSignatureVerified === true, 'expected source-evidence signature verification');
        assert(restored.authenticity.status.otsEvidenceLinked === true, 'expected OTS linkage reporting');
        assert(restored.authenticity.status.policySatisfied === true, 'integrity-only policy should remain satisfied');
        assert(restored.authenticity.verification.counts.validArchiveApproval === 0, 'archive policy counting must remain archive-approval only');
        assert(restored.authenticity.verification.counts.archiveApprovalPinnedValidTotal === 0, 'archive-approval pinning count must remain zero without archive-approval signatures');
        assert(restored.authenticity.verification.counts.archiveApprovalBundlePinnedValidTotal === 0, 'archive-approval bundle pinning count must remain zero without archive-approval signatures');
        assert(restored.authenticity.verification.counts.validMaintenance === 1, 'expected one valid maintenance signature');
        assert(restored.authenticity.verification.counts.validSourceEvidence === 1, 'expected one valid source-evidence signature');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 2, 'aggregate detached-signature pinning may still reflect non-archive families');
      },
    },
    {
      name: 'successor restore does not let maintenance, source-evidence, or OTS satisfy archive policy',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-policy-archive-approval-only'),
          authPolicyLevel: 'any-signature',
        });
        const bundleVariant = await buildSuccessorVerificationBundle(sample.split, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 1,
          includeArchiveApproval: false,
          includeMaintenance: true,
          includeSourceEvidence: true,
          timestampTargetFamily: 'maintenance',
        });
        const rewritten = await rewriteLifecycleBundleSubset(sample.parsed, bundleVariant.bundleBytes);

        await expectFailure(
          () => restoreFromShards(rewritten, { onLog: () => {}, onError: () => {} }),
          'successor restore unexpectedly let maintenance/source-evidence/OTS satisfy archive policy'
        );
      },
    },
    {
      name: 'successor restore fails closed on unresolved publicKeyRef in an uploaded lifecycle bundle',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-restore-publickeyref-fail-closed'),
          authPolicyLevel: 'any-signature',
        });
        const qsig = buildQsigFixture(sample.split.archiveStateBytes);
        const bundle = cloneJson(sample.split.lifecycleBundle);
        bundle.authPolicy = { level: 'any-signature', minValidSignatures: 1 };
        bundle.attachments.archiveApprovalSignatures = [
          {
            id: 'archive-approval-sig-1',
            signatureFamily: 'archive-approval',
            format: 'qsig',
            suite: 'mldsa-87',
            targetType: 'archive-state',
            targetRef: `state:${sample.split.stateId}`,
            targetDigest: { alg: 'SHA3-512', value: sample.split.stateId },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
            publicKeyRef: 'missing-public-key',
          },
        ];

        await expectFailure(
          () => restoreFromShards(sample.parsed, {
            onLog: () => {},
            onError: () => {},
            verification: { lifecycleBundleBytes: canonicalizeJsonToBytes(bundle) },
          }),
          'successor restore unexpectedly accepted an uploaded lifecycle bundle with an unresolved publicKeyRef'
        );
      },
    },
    {
      name: 'successor restore fails closed on mismatched OTS linkage in an uploaded lifecycle bundle',
      fn: async () => {
        const sample = await buildSuccessorRestoreSample({
          payloadBytes: textBytes('successor-restore-ots-fail-closed'),
          authPolicyLevel: 'any-signature',
        });
        const qsig = buildQsigFixture(sample.split.archiveStateBytes);
        const wrongOts = await buildOtsFixture(textBytes('wrong-detached-signature-bytes'), { completeProof: true });
        const bundle = cloneJson(sample.split.lifecycleBundle);
        bundle.authPolicy = { level: 'any-signature', minValidSignatures: 1 };
        bundle.attachments.archiveApprovalSignatures = [
          buildLifecycleQsigEntry({
            id: 'archive-approval-sig-1',
            signatureFamily: 'archive-approval',
            targetType: 'archive-state',
            targetRef: `state:${sample.split.stateId}`,
            targetDigest: sample.split.stateId,
            qsigBytes: qsig.qsigBytes,
          }),
        ];
        bundle.attachments.timestamps = [
          {
            id: 'ots-1',
            type: 'opentimestamps',
            targetRef: 'archive-approval-sig-1',
            targetDigest: { alg: 'SHA-256', value: toHex(await digestSha256(qsig.qsigBytes)) },
            proofEncoding: 'base64',
            proof: bytesToBase64(wrongOts),
          },
        ];

        await expectFailure(
          () => restoreFromShards(sample.parsed, {
            onLog: () => {},
            onError: () => {},
            verification: { lifecycleBundleBytes: canonicalizeJsonToBytes(bundle) },
          }),
          'successor restore unexpectedly accepted mismatched OTS linkage during restore'
        );
      },
    },
    {
      name: 'same-state resharing keeps the archive state unchanged while emitting a new cohort and required transition record',
      fn: async () => {
        const sample = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-same-state-reshare-valid'),
          authPolicyLevel: 'integrity-only',
        });

        const reshared = await reshareSameState(sample.parsed, { n: 5, k: 3 }, {
          transition: {
            reasonCode: 'cohort-rotation',
            performedAt: '2026-03-26T09:30:00.000Z',
            operatorRole: 'operator',
            actorHints: { ceremony: 'phase4-valid-reshare' },
            notes: null,
          },
          onLog: () => {},
          onWarn: () => {},
        });

        assert(reshared.archiveId === sample.split.archiveId, 'reshare archiveId changed unexpectedly');
        assert(reshared.stateId === sample.split.stateId, 'reshare stateId changed unexpectedly');
        assert(reshared.predecessorCohortId === sample.split.cohortId, 'reshare predecessor cohortId mismatch');
        assert(reshared.cohortId !== sample.split.cohortId, 'reshare should emit a fresh successor cohortId');
        assert(timingSafeEqual(reshared.archiveStateBytes, sample.split.archiveStateBytes), 'reshare changed archive-state bytes');
        assert(reshared.archiveStateDigestHex === sample.split.archiveStateDigestHex, 'reshare changed archive-state digest');
        assert(reshared.archiveState.qenc.qencHash === sample.split.archiveState.qenc.qencHash, 'reshare changed qencHash');
        assert(reshared.archiveState.qenc.containerId === sample.split.archiveState.qenc.containerId, 'reshare changed containerId');
        assert(reshared.transitionRecord.fromStateId === sample.split.stateId, 'transition fromStateId mismatch');
        assert(reshared.transitionRecord.toStateId === sample.split.stateId, 'transition toStateId mismatch');
        assert(reshared.transitionRecord.fromCohortId === sample.split.cohortId, 'transition fromCohortId mismatch');
        assert(reshared.transitionRecord.toCohortId === reshared.cohortId, 'transition toCohortId mismatch');
        assert(reshared.lifecycleBundle.transitions.length === sample.predecessorLifecycleBundle.transitions.length + 1, 'reshare did not append exactly one transition record');
        assert(reshared.maintenanceSignatureCountAdded === 0, 'reshare should not require maintenance signatures by default');
        assert(reshared.lifecycleBundle.attachments.maintenanceSignatures.length === sample.predecessorLifecycleBundle.attachments.maintenanceSignatures.length, 'unexpected maintenance signature carry-forward delta');
        assert(reshared.zeroization.attempted === true, 'reshare should attempt best-effort zeroization');
        assert(reshared.zeroization.privateKeyBytesCleared === true, 'reshare should clear reconstructed private key bytes');
        assert(reshared.semantics.sameStateAvailabilityMaintenance === true, 'reshare should report availability-maintenance semantics');
        assert(reshared.semantics.archiveReapprovalPerformed === false, 'reshare must not report archive re-approval');
        assert(reshared.semantics.plaintextDecrypted === false, 'reshare must not report plaintext decryption');
        assert(reshared.semantics.sourceEvidenceCreated === false, 'reshare must not report fresh source evidence');
        assert(reshared.semantics.compromiseRepairClaimed === false, 'reshare must not claim compromise repair');
        assert(
          reshared.operationalWarnings.some((warning) => warning.includes('cannot be proven')),
          'reshare should warn that predecessor shard destruction cannot be proven'
        );
        assert(
          reshared.operationalWarnings.some((warning) => warning.includes('does not revoke leaked predecessor quorum material')),
          'reshare should warn that same-state resharing does not repair old-quorum leakage'
        );

        const reparsed = await parseResharedShardSet(reshared);
        assert(reparsed.length === 5, 'expected five reshared successor shards');
        assert(reparsed.every((shard) => shard.stateId === sample.split.stateId), 'reshared shard stateId mismatch');
        assert(reparsed.every((shard) => shard.cohortId === reshared.cohortId), 'reshared shard cohortId mismatch');
      },
    },
    {
      name: 'same-state resharing allows changed n/k/t while keeping codecId frozen under the v1 schema',
      fn: async () => {
        const sample = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-same-state-reshare-nkt-change'),
          authPolicyLevel: 'integrity-only',
        });

        const reshared = await reshareSameState(sample.parsed, { n: 7, k: 5 }, {
          transition: {
            reasonCode: 'capacity-adjustment',
            performedAt: '2026-03-26T09:31:00.000Z',
            operatorRole: 'operator',
            actorHints: { ceremony: 'phase4-nkt-change' },
            notes: null,
          },
          onLog: () => {},
          onWarn: () => {},
        });

        assert(reshared.stateId === sample.split.stateId, 'changed n/k/t resharing changed stateId unexpectedly');
        assert(reshared.cohortBinding.sharding.reedSolomon.n === 7, 'successor n mismatch');
        assert(reshared.cohortBinding.sharding.reedSolomon.k === 5, 'successor k mismatch');
        assert(reshared.cohortBinding.sharding.reedSolomon.parity === 2, 'successor parity mismatch');
        assert(reshared.cohortBinding.sharding.shamir.threshold === 6, 'successor t mismatch');
        assert(reshared.cohortBinding.sharding.reedSolomon.codecId === 'QV-RS-ErasureCodes-v1', 'successor codecId should remain schema-frozen');
        assert(reshared.cohortBinding.sharding.shamir.threshold !== sample.split.cohortBinding.sharding.shamir.threshold, 'successor threshold should differ from predecessor threshold');
      },
    },
    {
      name: 'same-state resharing rejects mixed predecessor cohorts',
      fn: async () => {
        const sampleA = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-mixed-predecessor-a'),
          authPolicyLevel: 'integrity-only',
        });
        const sampleB = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-mixed-predecessor-b'),
          authPolicyLevel: 'integrity-only',
        });

        const mixed = [
          ...sampleA.parsed.slice(0, 3),
          ...sampleB.parsed.slice(0, 2),
        ];

        await expectFailure(
          () => reshareSameState(mixed, { n: 5, k: 3 }, { onLog: () => {}, onWarn: () => {} }),
          'same-state resharing unexpectedly accepted mixed predecessor cohorts'
        );
      },
    },
    {
      name: 'same-state resharing rejects archive-state mutation attempts',
      fn: async () => {
        const sample = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-archive-state-mutation-reject'),
          authPolicyLevel: 'integrity-only',
        });

        await expectFailure(
          () => reshareSameState(sample.parsed, {
            n: 5,
            k: 3,
            archiveId: 'aa'.repeat(32),
          }, { onLog: () => {}, onWarn: () => {} }),
          'same-state resharing unexpectedly accepted an archiveId override'
        );
      },
    },
    {
      name: 'same-state resharing rejects forbidden state-level field overrides',
      fn: async () => {
        const sample = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-forbidden-state-field-reject'),
          authPolicyLevel: 'integrity-only',
        });

        await expectFailure(
          () => reshareSameState(sample.parsed, {
            n: 5,
            k: 3,
            qencHash: 'ff'.repeat(64),
          }, { onLog: () => {}, onWarn: () => {} }),
          'same-state resharing unexpectedly accepted a qencHash override'
        );
      },
    },
    {
      name: 'same-state resharing preserves archive-approval signatures across resharing',
      fn: async () => {
        const sample = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-archive-approval-survives'),
          authPolicyLevel: 'any-signature',
          bundleVariantOptions: {
            authPolicyLevel: 'any-signature',
            minValidSignatures: 1,
            includeArchiveApproval: true,
            includeMaintenance: false,
            includeSourceEvidence: false,
          },
        });

        const predecessorSignature = sample.predecessorLifecycleBundle.attachments.archiveApprovalSignatures[0];
        const reshared = await reshareSameState(sample.parsed, { n: 5, k: 3 }, {
          transition: {
            reasonCode: 'cohort-rotation',
            performedAt: '2026-03-26T09:32:00.000Z',
            operatorRole: 'operator',
            actorHints: { ceremony: 'phase4-archive-approval' },
            notes: null,
          },
          onLog: () => {},
          onWarn: () => {},
        });

        assert(reshared.lifecycleBundle.attachments.archiveApprovalSignatures.length === 1, 'archive-approval signature should carry forward exactly once');
        assert(
          reshared.lifecycleBundle.attachments.archiveApprovalSignatures[0].signature === predecessorSignature.signature,
          'archive-approval signature bytes changed unexpectedly during resharing'
        );

        const restored = await restoreFromShards(await parseResharedShardSet(reshared), {
          onLog: () => {},
          onError: () => {},
        });
        assert(restored.authenticity.status.archiveApprovalSignatureVerified === true, 'archive-approval signature should remain valid after resharing');
        assert(restored.authenticity.status.policySatisfied === true, 'archive policy should still be satisfied after resharing');
      },
    },
    {
      name: 'same-state resharing preserves prior OTS linkage over archive-approval signatures',
      fn: async () => {
        const sample = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-archive-approval-ots-survives'),
          authPolicyLevel: 'any-signature',
          bundleVariantOptions: {
            authPolicyLevel: 'any-signature',
            minValidSignatures: 1,
            includeArchiveApproval: true,
            includeMaintenance: false,
            includeSourceEvidence: false,
            timestampTargetFamily: 'archive-approval',
          },
        });

        const reshared = await reshareSameState(sample.parsed, { n: 5, k: 3 }, {
          transition: {
            reasonCode: 'cohort-rotation',
            performedAt: '2026-03-26T09:33:00.000Z',
            operatorRole: 'operator',
            actorHints: { ceremony: 'phase4-archive-approval-ots' },
            notes: null,
          },
          onLog: () => {},
          onWarn: () => {},
        });

        const restored = await restoreFromShards(await parseResharedShardSet(reshared), {
          onLog: () => {},
          onError: () => {},
        });
        assert(restored.authenticity.status.archiveApprovalSignatureVerified === true, 'archive-approval signature should still verify after resharing');
        assert(restored.authenticity.status.otsEvidenceLinked === true, 'archive-approval OTS linkage should remain valid after resharing');
      },
    },
    {
      name: 'same-state resharing emits a required transition record and supports optional maintenance signatures',
      fn: async () => {
        const sample = await buildResharePredecessorSample({
          payloadBytes: textBytes('phase4-transition-record-and-maintenance'),
          authPolicyLevel: 'integrity-only',
        });

        const reshared = await reshareSameState(sample.parsed, { n: 5, k: 3 }, {
          transition: {
            reasonCode: 'cohort-rotation',
            performedAt: '2026-03-26T09:34:00.000Z',
            operatorRole: 'operator',
            actorHints: { ceremony: 'phase4-maintenance-signature' },
            notes: null,
          },
          buildMaintenanceArtifacts: buildMaintenanceArtifactsFactory(),
          onLog: () => {},
          onWarn: () => {},
        });

        assert(reshared.lifecycleBundle.transitions.length === sample.predecessorLifecycleBundle.transitions.length + 1, 'reshare should always emit one new transition record');
        assert(reshared.maintenanceSignatureCountAdded === 1, 'reshare should report the added maintenance signature');
        assert(reshared.lifecycleBundle.attachments.maintenanceSignatures.length === 1, 'reshare should embed the new maintenance signature');

        const restored = await restoreFromShards(await parseResharedShardSet(reshared), {
          onLog: () => {},
          onError: () => {},
        });
        assert(restored.authenticity.status.maintenanceSignatureVerified === true, 'optional maintenance signature should verify after resharing');
        assert(restored.authenticity.verification.counts.validArchiveApproval === 0, 'maintenance signatures must not count toward archive policy');
      },
    },
    {
      name: '.qcont reconstruction',
      fn: async () => {
        const { publicKey, secretKey } = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(256 * 1024);
        const encrypted = await encryptFile(payload, publicKey, 'restore.txt');
        const qencBytes = await blobToBytes(encrypted);
        const built = await buildQcontShards(qencBytes, secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const builtShards = built.shards;
        const shardBytes = await Promise.all(builtShards.map((shard) => blobToBytes(shard.blob)));
        const oneCorrupted = shardBytes.map((bytes, idx) => (idx === 0 ? mutateTail(bytes) : bytes.slice()));
        const parsedShards = oneCorrupted.map((bytes) => parseShard(bytes));

        const restored = await restoreFromShards(parsedShards, { onLog: () => {}, onError: () => {} });
        assert(restored.qencOk, 'reconstructed qenc hash mismatch');
        assert(restored.qkeyOk, 'reconstructed qkey hash mismatch');

        const { decryptedBlob } = await decryptFile(restored.qencBytes, restored.privKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'reconstructed payload mismatch');
      },
    },
    {
      name: 'restore rejects mixed manifest cohorts without selector',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payloadA = textBytes('cohort-a');
        const payloadB = textBytes('cohort-b');

        const qencA = await blobToBytes(await encryptFile(payloadA, pairA.publicKey, 'a.bin'));
        const qencB = await blobToBytes(await encryptFile(payloadB, pairB.publicKey, 'b.bin'));

        const splitA = await buildQcontShards(qencA, pairA.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const splitB = await buildQcontShards(qencB, pairB.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });

        const mixed = [
          ...(await Promise.all(splitA.shards.slice(0, 3).map((item) => blobToBytes(item.blob)))),
          ...(await Promise.all(splitB.shards.slice(0, 2).map((item) => blobToBytes(item.blob)))),
        ];
        const parsed = mixed.map((bytes) => parseShard(bytes));

        await expectFailure(
          () => restoreFromShards(parsed, { onLog: () => {}, onError: () => {} }),
          'restore unexpectedly accepted mixed manifest cohorts without selector'
        );
      },
    },
    {
      name: 'restore uses uploaded manifest to select correct cohort',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payloadA = textBytes('selector-a');
        const payloadB = textBytes('selector-b');

        const qencA = await blobToBytes(await encryptFile(payloadA, pairA.publicKey, 'sa.bin'));
        const qencB = await blobToBytes(await encryptFile(payloadB, pairB.publicKey, 'sb.bin'));

        const splitA = await buildQcontShards(qencA, pairA.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const splitB = await buildQcontShards(qencB, pairB.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });

        const selectedShardBytes = await Promise.all(splitA.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const distractorShardBytes = await blobToBytes(splitB.shards[0].blob);
        const parsed = [...selectedShardBytes, distractorShardBytes].map((bytes) => parseShard(bytes));

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: { manifestBytes: splitA.manifestBytes },
        });

        assert(restored.qencOk, 'restore with uploaded manifest failed qenc hash check');
        assert(restored.manifestSource === 'uploaded-manifest', `unexpected manifest source: ${restored.manifestSource}`);
      },
    },
    {
      name: 'parseShard rejects tampered embedded manifest digest',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('manifest-tamper');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'tamper.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 });
        const shardBytes = await blobToBytes(split.shards[0].blob);
        const tampered = mutateQcontManifestByte(shardBytes);

        await expectFailure(
          async () => {
            parseShard(tampered);
          },
          'parseShard unexpectedly accepted tampered embedded manifest'
        );
      },
    },
    {
      name: 'pinning: valid PQ signature without pin remains valid and unpinned',
      fn: async () => {
        const manifestBytes = textBytes('pinning-no-pin');
        const { qsigBytes } = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
        });

        assert(verification.status.signatureVerified === true, 'signature should remain verified without a pin');
        assert(verification.status.signerPinned === false, 'signature should remain unpinned without a pin');
        assert(verification.status.bundlePinned === false, 'external signature without bundle key must not set bundlePinned');
        assert(verification.status.userPinned === false, 'external signature without user pin must not set userPinned');
      },
    },
    {
      name: 'pinning: valid PQ signature with wrong pin remains valid and unpinned',
      fn: async () => {
        const manifestBytes = textBytes('pinning-wrong-pin');
        const { qsigBytes } = buildQsigFixture(manifestBytes);
        const { pqpkBytes: wrongPqpkBytes } = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pinnedPqPublicKeyFileBytes: wrongPqpkBytes,
        });

        assert(verification.status.signatureVerified === true, 'wrong pin must not downgrade signature verification');
        assert(verification.status.signerPinned === false, 'wrong pin must not mark signer as pinned');
        assert(verification.status.userPinned === false, 'wrong pin must not set userPinned');
        assert(
          verification.warnings.some((warning) => warning.includes('Pinned PQ signer key did not match')),
          'wrong pin should emit an explicit warning'
        );
      },
    },
    {
      name: 'pinning: valid PQ signature with matching pin remains valid and pinned',
      fn: async () => {
        const manifestBytes = textBytes('pinning-matching-pin');
        const { qsigBytes, pqpkBytes } = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pinnedPqPublicKeyFileBytes: pqpkBytes,
        });

        assert(verification.status.signatureVerified === true, 'matching pin must preserve signature verification');
        assert(verification.status.signerPinned === true, 'matching pin must mark signer as pinned');
        assert(verification.status.bundlePinned === false, 'external signature should not set bundlePinned');
        assert(verification.status.userPinned === true, 'matching external pin must set userPinned');
      },
    },
    {
      name: 'policy counting ignores duplicate detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-policy-count');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'duplicate-policy-count.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes } = buildQsigFixture(split.manifestBytes);

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [
                { name: 'duplicate-a.qsig', bytes: qsigBytes },
                { name: 'duplicate-b.qsig', bytes: qsigBytes },
              ],
            },
          }),
          'duplicate detached signatures unexpectedly satisfied minValidSignatures'
        );
      },
    },
    {
      name: 'policy counting accepts two unique detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('unique-policy-count');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'unique-policy-count.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [
              { name: 'unique-a.qsig', bytes: sigA.qsigBytes },
              { name: 'unique-b.qsig', bytes: sigB.qsigBytes },
            ],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'two unique signatures should satisfy minValidSignatures');
        assert(restored.authenticity.verification.counts.validTotal === 2, 'expected two unique signatures in policy counts');
      },
    },
    {
      name: 'policy counting ignores a duplicate detached signature repeated in bundle and external inputs',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('bundle-external-duplicate-policy-count');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'bundle-external-duplicate-policy-count.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });
        const updatedShards = await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));

        await expectFailure(
          () => restoreFromShards(updatedShards, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
            },
          }),
          'bundle + external duplicate detached signature unexpectedly satisfied minValidSignatures'
        );
      },
    },
    {
      name: 'verification reports unsupported .qsig major version as an invalid detached signature result',
      fn: async () => {
        const manifestBytes = textBytes('bad-qsig-major');
        const { qsigBytes } = buildQsigFixture(manifestBytes);
        const badQsigBytes = mutateQsigMajorVersion(qsigBytes, 0x01);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'bad.qsig', bytes: badQsigBytes }],
        });

        assert(verification.results.length === 1, 'expected one invalid .qsig result');
        assert(verification.results[0].ok === false, 'unsupported .qsig major version must fail closed');
        assert(
          String(verification.results[0].error || '').includes('Unsupported detached PQ signature major version'),
          'expected unsupported .qsig major version error'
        );
        assert(verification.status.signatureVerified === false, 'malformed .qsig must not satisfy signatureVerified');
      },
    },
    {
      name: 'parser rejects unsupported .pqpk major version',
      fn: async () => {
        const manifestBytes = textBytes('bad-pqpk-major');
        const { pqpkBytes } = buildQsigFixture(manifestBytes);
        const badPqpkBytes = mutatePqpkMajorVersion(pqpkBytes, 0x02);

        await expectFailure(
          () => Promise.resolve(unpackPqpk(badPqpkBytes)),
          '.pqpk parser unexpectedly accepted unsupported major version'
        );
      },
    },
    {
      name: 'verification reports unknown critical .qsig metadata TLV tags as invalid detached signature results',
      fn: async () => {
        const manifestBytes = textBytes('bad-qsig-critical-tag');
        const { qsigBytes } = buildQsigFixture(manifestBytes);
        const badQsigBytes = appendUnknownCriticalQsigMetadata(qsigBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'critical.qsig', bytes: badQsigBytes }],
        });

        assert(verification.results.length === 1, 'expected one invalid .qsig result');
        assert(verification.results[0].ok === false, 'critical-tag .qsig must fail closed');
        assert(
          String(verification.results[0].error || '').includes('Unknown critical authMeta TLV tag'),
          'expected critical authMeta tag failure'
        );
        assert(verification.status.signatureVerified === false, 'invalid .qsig must not satisfy signatureVerified');
      },
    },
    {
      name: 'parser rejects oversized .qsig authenticated metadata length',
      fn: async () => {
        const manifestBytes = textBytes('oversized-qsig-authmeta');
        const { qsigBytes } = buildQsigFixture(manifestBytes);
        const badQsigBytes = mutateQsigAuthMetaLen(qsigBytes, (8 * 1024) + 1);

        await expectFailure(
          () => Promise.resolve(unpackQsig(badQsigBytes)),
          '.qsig parser unexpectedly accepted oversized authenticated metadata'
        );
      },
    },
    {
      name: 'parser rejects oversized .pqpk key length',
      fn: async () => {
        const manifestBytes = textBytes('oversized-pqpk-keylen');
        const { pqpkBytes } = buildQsigFixture(manifestBytes);
        const badPqpkBytes = mutatePqpkKeyLen(pqpkBytes, (16 * 1024) + 1);

        await expectFailure(
          () => Promise.resolve(unpackPqpk(badPqpkBytes)),
          '.pqpk parser unexpectedly accepted oversized key length'
        );
      },
    },
    {
      name: 'manifest bundle rejects duplicate detached signature payload bytes under different ids',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-bundle-signatures');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'duplicate-bundle-signatures.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);
        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });
        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        const duplicateSignature = {
          ...parsedBundle.bundle.attachments.signatures[0],
          id: 'sig-duplicate',
        };
        const mutatedBundle = {
          ...parsedBundle.bundle,
          attachments: {
            ...parsedBundle.bundle.attachments,
            signatures: [
              ...parsedBundle.bundle.attachments.signatures,
              duplicateSignature,
            ],
          },
        };

        await expectFailure(
          () => Promise.resolve(canonicalizeManifestBundle(mutatedBundle)),
          'manifest bundle unexpectedly accepted duplicate detached signature payload bytes'
        );
      },
    },
    {
      name: 'policy counting ignores semantically duplicate Stellar SEP-53 proofs with different JSON formatting',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-stellar-sep53-policy-count');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'duplicate-stellar-sep53-policy-count.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSig = await buildStellarSignatureFixture(split.manifestBytes);
        const duplicateBytes = rewriteStellarSignatureDocument(stellarSig.bytes, { pretty: true });

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [
                { name: 'stellar-a.sig', bytes: stellarSig.bytes },
                { name: 'stellar-b.sig', bytes: duplicateBytes },
              ],
            },
          }),
          'semantically duplicate Stellar SEP-53 proofs unexpectedly satisfied minValidSignatures'
        );
      },
    },
    {
      name: 'attach deduplicates semantically identical Stellar XDR proofs with reordered JSON arrays',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-stellar-xdr-attach');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'duplicate-stellar-xdr-attach.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const stellarSig = await buildStellarXdrSignatureFixture(split.manifestBytes);
        const duplicateBytes = rewriteStellarSignatureDocument(stellarSig.bytes, {
          reverseHashes: true,
          reverseManageDataEntries: true,
          pretty: true,
        });

        const attached = await attachManifestBundleToShards([], {
          manifestBytes: split.manifestBytes,
          signatures: [
            { name: 'stellar-a.sig', bytes: stellarSig.bytes },
            { name: 'stellar-b.sig', bytes: duplicateBytes },
          ],
          embedIntoShards: false,
        });

        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        assert(parsedBundle.bundle.attachments.signatures.length === 1, 'semantically duplicate Stellar proofs should collapse to one stored signature');
      },
    },
    {
      name: 'auth policy defaults: Lite integrity-only, Pro strong-pq, builder fallback matches Pro',
      fn: async () => {
        assert(LITE_DEFAULT_AUTH_POLICY_LEVEL === 'integrity-only', 'Lite default auth policy must remain integrity-only');
        assert(PRO_DEFAULT_AUTH_POLICY_LEVEL === 'strong-pq-signature', 'Pro default auth policy must remain strong-pq-signature');
        assert(
          DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL === PRO_DEFAULT_AUTH_POLICY_LEVEL,
          'builder default auth policy must match the Pro default'
        );

        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('default-auth-policy');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'default-policy.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 });

        assert(split.bundle.authPolicy.level === PRO_DEFAULT_AUTH_POLICY_LEVEL, 'builder fallback must emit the Pro default policy');
      },
    },
    {
      name: 'restore any-signature policy rejects unsigned archive',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('strict-authn');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'strict.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const shardBytes = await Promise.all(split.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const parsed = shardBytes.map((bytes) => parseShard(bytes));

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
          }),
          'restore unexpectedly allowed any-signature archive without signatures'
        );
      },
    },
    {
      name: 'restore any-signature policy accepts valid external PQ signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('pre-attach-signature');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'signed.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const shardBytes = await Promise.all(split.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const parsed = shardBytes.map((bytes) => parseShard(bytes));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
            pinnedPqPublicKeyFileBytes: pqpkBytes,
          },
        });

        assert(restored.authenticity.status.signatureVerified, 'expected signatureVerified');
        assert(restored.authenticity.status.strongPqSignatureVerified, 'expected strongPqSignatureVerified');
        assert(restored.authenticity.status.signerPinned, 'expected signerPinned from external .pqpk');
        assert(restored.authenticity.status.bundlePinned === false, 'external .pqpk should not set bundlePinned');
        assert(restored.authenticity.status.userPinned === true, 'external .pqpk should set userPinned');
        assert(restored.authenticity.status.policySatisfied, 'expected policySatisfied');
      },
    },
    {
      name: 'restore strong-pq-signature policy accepts one valid strong PQ signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('strong-pq-valid');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'strong-pq-valid.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes } = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          },
        });

        assert(restored.authenticity.status.signatureVerified === true, 'expected signatureVerified');
        assert(restored.authenticity.status.strongPqSignatureVerified === true, 'expected strongPqSignatureVerified');
        assert(restored.authenticity.status.policySatisfied === true, 'expected policySatisfied');
      },
    },
    {
      name: 'restore rejects detached PQ signature with unsupported qsig context',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('unsupported-qsig-context');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'unsupported-qsig-context.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes } = buildQsigFixture(split.manifestBytes, { ctx: 'quantum-signer/v3' });

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
            },
          }),
          'restore unexpectedly accepted detached PQ signature with unsupported context'
        );
      },
    },
    {
      name: 'restore any-signature policy accepts one valid Ed25519 signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('any-signature-ed25519');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'any-signature-ed25519.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSigBytes = (await buildStellarSignatureFixture(split.manifestBytes)).bytes;

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: { signatures: [{ name: 'archive.sig', bytes: stellarSigBytes }] },
        });

        assert(restored.authenticity.status.signatureVerified === true, 'expected signatureVerified');
        assert(restored.authenticity.status.strongPqSignatureVerified === false, 'Ed25519 must not satisfy strong PQ status');
        assert(restored.authenticity.status.policySatisfied === true, 'expected policySatisfied');
      },
    },
    {
      name: 'current-format SLH-DSA detached signature verifies against canonical manifest',
      fn: async () => {
        const manifestBytes = textBytes('current-format-slh-manifest');
        const { qsigBytes, pqpkBytes } = buildQsigFixture(manifestBytes, { suite: 'slhdsa-shake-128s' });

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pinnedPqPublicKeyFileBytes: pqpkBytes,
        });

        assert(verification.status.signatureVerified === true, 'current SLH-DSA detached signature should verify');
        assert(verification.status.strongPqSignatureVerified === false, 'SLH-DSA-128s should not count as strong PQ in current policy table');
        assert(verification.status.userPinned === true, 'current SLH-DSA detached signature should match the provided current .pqpk');
      },
    },
    {
      name: 'current-format detached PQ signature does not emit a false fingerprint mismatch warning',
      fn: async () => {
        const manifestBytes = textBytes('current-format-fingerprint-warning-clean');
        const { qsigBytes, pqpkBytes } = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pinnedPqPublicKeyFileBytes: pqpkBytes,
        });

        assert(verification.status.signatureVerified === true, 'current detached PQ signature should verify');
        assert(
          verification.warnings.every((warning) => !warning.includes('Signer fingerprint in .qsig metadata does not match')),
          'valid detached PQ signature unexpectedly emitted a fingerprint mismatch warning'
        );
      },
    },
    {
      name: 'current-format Stellar XDR proof verifies against canonical manifest',
      fn: async () => {
        const manifestBytes = textBytes('current-format-stellar-xdr-manifest');
        const sigBytes = (await buildStellarXdrSignatureFixture(manifestBytes)).bytes;

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.sig', bytes: sigBytes }],
        });

        assert(verification.status.signatureVerified === true, 'current Stellar XDR proof should verify');
        assert(verification.status.strongPqSignatureVerified === false, 'Stellar XDR proof must not count as strong PQ');
      },
    },
    {
      name: 'bundled qsig warns when authenticated signer binding disagrees with the authoritative verification key',
      fn: async () => {
        const manifestBytes = textBytes('bundle-qsig-signer-binding-warning');
        const misleadingBinding = buildQsigFixture(manifestBytes, {
          embeddedPublicKey: unpackPqpk(buildQsigFixture(manifestBytes).pqpkBytes).keyBytes,
        });

        const verification = await verifyManifestSignatures({
          manifestBytes,
          bundlePublicKeys: [{
            id: 'pk-good',
            kty: 'ml-dsa-public-key',
            suite: 'mldsa-87',
            encoding: 'base64',
            value: bytesToBase64(misleadingBinding.pqpkBytes),
            legacy: false,
          }],
          bundleSignatures: [{
            id: 'sig-qsig',
            format: 'qsig',
            suite: 'mldsa-87',
            target: {
              type: 'canonical-manifest',
              digestAlg: 'SHA3-512',
              digestValue: toHex(sha3_512(manifestBytes)),
            },
            signatureEncoding: 'base64',
            signature: bytesToBase64(misleadingBinding.qsigBytes),
            publicKeyRef: 'pk-good',
            legacy: false,
          }],
        });

        assert(verification.results.length === 1, 'expected one bundled qsig verification result');
        assert(verification.results[0].ok === true, 'authoritative bundled qsig should still verify with its referenced key');
        assert(
          verification.warnings.some((warning) => warning.includes('Embedded signer public key does not match the verification key')),
          'mismatched authenticated signer public key should be surfaced'
        );
        assert(
          verification.warnings.some((warning) => warning.includes('Signer fingerprint in .qsig metadata does not match the verification key')),
          'mismatched authenticated signer fingerprint should be surfaced'
        );
      },
    },
    {
      name: 'restore ignores malformed extra .qsig signatures when one satisfying signature exists',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('invalid-extra-signatures');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'invalid-extra-signatures.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes } = buildQsigFixture(split.manifestBytes);
        const malformedQsigBytes = mutateQsigMajorVersion(qsigBytes, 0x01);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [
              { name: 'archive-good.qsig', bytes: qsigBytes },
              { name: 'archive-bad.qsig', bytes: malformedQsigBytes },
            ],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'one satisfying signature should still pass policy');
        assert(restored.authenticity.verification.results.some((item) => item.ok === false), 'expected an invalid signature result');
        assert(
          restored.authenticity.warnings.some((warning) => warning.includes('did not verify and were ignored')),
          'invalid extra signatures should produce an explicit warning'
        );
      },
    },
    {
      name: 'attach upgrades manifest into bundle and qcont-only restore succeeds',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('post-attach-signature');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'attach.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });
        assert(
          timingSafeEqual(attached.manifestBytes, split.manifestBytes),
          'attach must not mutate canonical manifest bytes'
        );
        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        assert(parsedBundle.bundle.attachments.signatures.length === 1, 'expected attached bundle signature');
        assert(parsedBundle.bundle.attachments.publicKeys.length === 1, 'expected attached bundle public key');

        const updatedShards = await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        for (const updatedShard of updatedShards) {
          assert(
            timingSafeEqual(updatedShard.manifestBytes, split.manifestBytes),
            'embedded attach must preserve canonical manifest bytes inside rewritten shards'
          );
        }
        const restored = await restoreFromShards(updatedShards, { onLog: () => {}, onError: () => {} });
        assert(restored.authenticity.status.policySatisfied, 'attached restore should satisfy archive policy');
        assert(restored.authenticity.status.signatureVerified, 'attached restore should verify signature');
        assert(restored.authenticity.status.signerPinned, 'bundle-attached PQ key should mark signer as pinned during restore');
        assert(restored.authenticity.status.bundlePinned === true, 'bundle-attached PQ key should set bundlePinned');
        assert(restored.authenticity.status.userPinned === false, 'bundle-attached PQ key alone should not set userPinned');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 1, 'expected one pinned bundled signature');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'expected one bundle-pinned bundled signature');
      },
    },
    {
      name: 'restore accepts uploaded bundle for stale shards with same manifest',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('stale-shards-with-uploaded-bundle');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'stale.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const originalShards = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const allShards = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);
        const attached = await attachManifestBundleToShards(allShards, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });

        const restored = await restoreFromShards(originalShards, {
          onLog: () => {},
          onError: () => {},
          verification: { bundleBytes: attached.bundleBytes },
        });

        assert(restored.manifestSource === 'uploaded-bundle', `unexpected manifest source: ${restored.manifestSource}`);
        assert(restored.authenticity.status.policySatisfied, 'uploaded bundle should satisfy archive policy for stale shards');
        assert(restored.authenticity.status.signerPinned, 'uploaded bundle PQ key should mark signer as pinned');
        assert(restored.authenticity.status.bundlePinned === true, 'uploaded bundle PQ key should set bundlePinned');
        assert(restored.authenticity.status.userPinned === false, 'uploaded bundle without user pin should not set userPinned');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 1, 'uploaded bundle should preserve pinned bundled signature');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'uploaded bundle should preserve bundle-pinned count');
      },
    },
    {
      name: 'restore can report both bundlePinned and userPinned for the same bundled PQ signature',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('bundle-and-user-pin');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'bundle-and-user-pin.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const { qsigBytes, pqpkBytes } = buildQsigFixture(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: qsigBytes }],
          pqPublicKeyFileBytesList: [pqpkBytes],
        });

        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          {
            onLog: () => {},
            onError: () => {},
            verification: { pinnedPqPublicKeyFileBytes: pqpkBytes },
          }
        );

        assert(restored.authenticity.status.bundlePinned === true, 'bundled signature should remain bundlePinned');
        assert(restored.authenticity.status.userPinned === true, 'matching external PQ pin should set userPinned');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'expected bundle-pinned count for bundled PQ signature');
        assert(restored.authenticity.verification.counts.userPinnedValidTotal === 1, 'expected user-pinned count for bundled PQ signature');
      },
    },
    {
      name: 'bundled qsig publicKeyRef is authoritative and cannot fall back to embedded signer key',
      fn: async () => {
        const manifestBytes = textBytes('bundle-authoritative-qsig-key');
        const matching = buildQsigFixture(manifestBytes);
        const wrong = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          bundlePublicKeys: [{
            id: 'pk-wrong',
            kty: 'ml-dsa-public-key',
            suite: 'mldsa-87',
            encoding: 'base64',
            value: bytesToBase64(wrong.pqpkBytes),
            legacy: false,
          }],
          bundleSignatures: [{
            id: 'sig-qsig',
            format: 'qsig',
            suite: 'mldsa-87',
            target: {
              type: 'canonical-manifest',
              digestAlg: 'SHA3-512',
              digestValue: toHex(sha3_512(manifestBytes)),
            },
            signatureEncoding: 'base64',
            signature: bytesToBase64(matching.qsigBytes),
            publicKeyRef: 'pk-wrong',
            legacy: false,
          }],
        });

        assert(verification.results.length === 1, 'expected one bundled qsig verification result');
        assert(verification.results[0].ok === false, 'bundled qsig with wrong referenced key must fail');
        assert(
          String(verification.results[0].error || '').includes('Bundled PQ public key did not verify'),
          'expected authoritative bundled key failure'
        );
        assert(verification.status.signatureVerified === false, 'failed bundled qsig must not satisfy signatureVerified');
      },
    },
    {
      name: 'bundled qsig publicKeyRef must not reference a Stellar signer attachment',
      fn: async () => {
        const manifestBytes = textBytes('bundle-qsig-stellar-ref');
        const qsig = buildQsigFixture(manifestBytes);
        const stellarSig = await buildStellarSignatureFixtureWithSigner(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          bundlePublicKeys: [{
            id: 'pk-stellar',
            kty: 'ed25519-public-key',
            suite: 'ed25519',
            encoding: 'stellar-address',
            value: stellarSig.signer,
            legacy: false,
          }],
          bundleSignatures: [{
            id: 'sig-qsig',
            format: 'qsig',
            suite: 'mldsa-87',
            target: {
              type: 'canonical-manifest',
              digestAlg: 'SHA3-512',
              digestValue: toHex(sha3_512(manifestBytes)),
            },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
            publicKeyRef: 'pk-stellar',
            legacy: false,
          }],
        });

        assert(verification.results.length === 1, 'expected one bundled qsig verification result');
        assert(verification.results[0].ok === false, 'incompatible qsig publicKeyRef must fail closed');
        assert(
          String(verification.results[0].error || '').includes('must reference a bundled PQ public key'),
          'expected qsig publicKeyRef compatibility error'
        );
      },
    },
    {
      name: 'bundled qsig publicKeyRef must match the referenced PQ suite',
      fn: async () => {
        const manifestBytes = textBytes('bundle-qsig-suite-mismatch');
        const qsig = buildQsigFixture(manifestBytes, { suite: 'mldsa-87' });
        const wrongSuite = buildQsigFixture(manifestBytes, { suite: 'slhdsa-shake-128s' });

        const verification = await verifyManifestSignatures({
          manifestBytes,
          bundlePublicKeys: [{
            id: 'pk-wrong-suite',
            kty: 'slh-dsa-public-key',
            suite: 'slhdsa-shake-128s',
            encoding: 'base64',
            value: bytesToBase64(wrongSuite.pqpkBytes),
            legacy: false,
          }],
          bundleSignatures: [{
            id: 'sig-qsig',
            format: 'qsig',
            suite: 'mldsa-87',
            target: {
              type: 'canonical-manifest',
              digestAlg: 'SHA3-512',
              digestValue: toHex(sha3_512(manifestBytes)),
            },
            signatureEncoding: 'base64',
            signature: bytesToBase64(qsig.qsigBytes),
            publicKeyRef: 'pk-wrong-suite',
            legacy: false,
          }],
        });

        assert(verification.results.length === 1, 'expected one bundled qsig verification result');
        assert(verification.results[0].ok === false, 'qsig suite mismatch must fail closed');
        assert(
          String(verification.results[0].error || '').includes('publicKeyRef suite mismatch for qsig'),
          'expected qsig suite-mismatch error'
        );
      },
    },
    {
      name: 'bundled stellar-sig publicKeyRef must not reference a PQ public key attachment',
      fn: async () => {
        const manifestBytes = textBytes('bundle-stellar-pq-ref');
        const stellarSig = await buildStellarSignatureFixture(manifestBytes);
        const qsig = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          bundlePublicKeys: [{
            id: 'pk-pq',
            kty: 'ml-dsa-public-key',
            suite: 'mldsa-87',
            encoding: 'base64',
            value: bytesToBase64(qsig.pqpkBytes),
            legacy: false,
          }],
          bundleSignatures: [{
            id: 'sig-stellar',
            format: 'stellar-sig',
            suite: 'ed25519',
            target: {
              type: 'canonical-manifest',
              digestAlg: 'SHA3-512',
              digestValue: toHex(sha3_512(manifestBytes)),
            },
            signatureEncoding: 'base64',
            signature: bytesToBase64(stellarSig.bytes),
            publicKeyRef: 'pk-pq',
            legacy: false,
          }],
        });

        assert(verification.results.length === 1, 'expected one bundled stellar-sig verification result');
        assert(verification.results[0].ok === false, 'incompatible stellar-sig publicKeyRef must fail closed');
        assert(
          String(verification.results[0].error || '').includes('must reference a bundled Stellar signer'),
          'expected stellar-sig publicKeyRef compatibility error'
        );
        assert(verification.status.signatureVerified === false, 'incompatible stellar-sig binding must not satisfy signatureVerified');
      },
    },
    {
      name: 'attach persists Stellar signer identifier in bundle and restore marks it pinned',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('stellar-bundle-pin');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'stellar-bundle-pin.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSig = await buildStellarSignatureFixtureWithSigner(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.sig', bytes: stellarSig.bytes }],
          expectedEd25519Signer: stellarSig.signer,
        });

        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        const stellarSignature = parsedBundle.bundle.attachments.signatures.find((item) => item.format === 'stellar-sig');
        assert(stellarSignature?.publicKeyRef, 'expected attached Stellar signature to reference a persisted signer identifier');
        const signerAttachment = parsedBundle.bundle.attachments.publicKeys.find((item) => item.id === stellarSignature.publicKeyRef);
        assert(signerAttachment?.encoding === 'stellar-address', 'expected Stellar signer attachment encoding');
        assert(signerAttachment?.value === stellarSig.signer, 'expected persisted Stellar signer identifier');

        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          { onLog: () => {}, onError: () => {} }
        );

        assert(restored.authenticity.status.signatureVerified === true, 'expected bundled Stellar signature to verify');
        assert(restored.authenticity.status.signerPinned === true, 'expected bundled Stellar signer identifier to mark signer as pinned');
        assert(restored.authenticity.status.bundlePinned === true, 'bundled Stellar signer identifier should set bundlePinned');
        assert(restored.authenticity.status.userPinned === false, 'bundled Stellar signer identifier alone should not set userPinned');
        assert(restored.authenticity.verification.counts.validTotal === 1, 'expected one bundled Stellar signature');
        assert(restored.authenticity.verification.counts.pinnedValidTotal === 1, 'expected one pinned bundled Stellar signature');
        assert(restored.authenticity.verification.counts.bundlePinnedValidTotal === 1, 'expected one bundle-pinned bundled Stellar signature');
      },
    },
    {
      name: 'attach accepts current-format detached signatures and preserves signer references',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('attach-current-format-signatures');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'attach-current-format-signatures.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const manifestBytes = split.manifestBytes;
        const { qsigBytes: mlQsigBytes, pqpkBytes: mlPqpkBytes } = buildQsigFixture(manifestBytes);
        const stellarSigner = await createStellarSignerMaterial();
        const stellarSep53Bytes = (await buildStellarSignatureFixture(manifestBytes, stellarSigner)).bytes;
        const stellarXdrBytes = (await buildStellarXdrSignatureFixture(manifestBytes, stellarSigner)).bytes;

        const attached = await attachManifestBundleToShards([], {
          manifestBytes,
          signatures: [
            { name: 'MLbundle.qsig', bytes: mlQsigBytes },
            { name: 'stellar-sep53.sig', bytes: stellarSep53Bytes },
            { name: 'stellar-xdr.sig', bytes: stellarXdrBytes },
          ],
          pqPublicKeyFileBytesList: [mlPqpkBytes],
        });

        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        assert(parsedBundle.bundle.attachments.signatures.length === 3, 'current-format attach should import all detached signatures');
        assert(parsedBundle.bundle.attachments.publicKeys.length === 2, 'current-format attach should dedupe shared Stellar signer and retain one PQ key');
        assert(parsedBundle.bundle.attachments.signatures.every((item) => item.publicKeyRef), 'attached current-format signatures should retain signer references when available');
      },
    },
    {
      name: 'attach dedupes semantically identical .pqpk wrappers for the same signer',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('attach-semantic-pqpk-dedupe');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'attach-semantic-pqpk-dedupe.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const sig = buildQsigFixture(split.manifestBytes);
        const alternateWrapper = mutatePqpkVersionMinor(sig.pqpkBytes, 0x07);

        const attached = await attachManifestBundleToShards([], {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes, alternateWrapper],
        });

        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        assert(parsedBundle.bundle.attachments.publicKeys.length === 1, 'attach should persist one PQ public key per signer identity');
        assert(parsedBundle.bundle.attachments.signatures.length === 1, 'attach should persist one detached signature');
        assert(
          parsedBundle.bundle.attachments.signatures[0].publicKeyRef === parsedBundle.bundle.attachments.publicKeys[0].id,
          'attached detached signature should reference the deduped PQ public key attachment'
        );
      },
    },
    {
      name: 'export attached artifacts emits a text file for bundled Stellar signer identifiers',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('stellar-export-attachment');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'stellar-export-attachment.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSig = await buildStellarSignatureFixtureWithSigner(split.manifestBytes);

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.sig', bytes: stellarSig.bytes }],
          expectedEd25519Signer: stellarSig.signer,
        });

        const bundle = parseManifestBundleBytes(attached.bundleBytes).bundle;
        const exports = buildAttachedArtifactExports(bundle, 'archive');
        const signerExport = exports.find((item) => item.filename.endsWith('.stellar.txt'));
        assert(signerExport, 'expected a text export for the bundled Stellar signer identifier');
        assert(new TextDecoder().decode(signerExport.bytes) === `${stellarSig.signer}\n`, 'expected Stellar signer export to preserve the signer address');
      },
    },
    {
      name: 'attach maps OpenTimestamps by stamped SHA-256 and preserves completion state',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('ots-target-selection');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);
        const otsA = await buildOtsFixture(sigA.qsigBytes, { completeProof: false });
        const otsB = await buildOtsFixture(sigB.qsigBytes, { completeProof: true });

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [
            { name: 'archive-a.qsig', bytes: sigA.qsigBytes },
            { name: 'archive-b.qsig', bytes: sigB.qsigBytes },
          ],
          timestamps: [
            { name: 'archive-a-initial.qsig.ots', bytes: otsA },
            { name: 'archive-b-completed.qsig.ots', bytes: otsB },
          ],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes, sigB.pqpkBytes],
        });
        const parsedBundle = parseManifestBundleBytes(attached.bundleBytes);
        assert(parsedBundle.bundle.attachments.timestamps.length === 2, 'expected two attached OpenTimestamps proofs');

        const signaturesBySigHex = new Map(
          parsedBundle.bundle.attachments.signatures.map((signature) => [
            bytesToHex(base64ToBytes(signature.signature)),
            signature.id,
          ])
        );
        const timestampsByTarget = new Map(parsedBundle.bundle.attachments.timestamps.map((timestamp) => [timestamp.targetRef, timestamp]));
        const sigAId = signaturesBySigHex.get(bytesToHex(sigA.qsigBytes));
        const sigBId = signaturesBySigHex.get(bytesToHex(sigB.qsigBytes));
        assert(sigAId && sigBId, 'expected attached signatures for both qsig inputs');
        assert(timestampsByTarget.get(sigAId)?.apparentlyComplete === false, 'initial .ots must be marked as apparently incomplete');
        assert(timestampsByTarget.get(sigAId)?.completeProof === false, 'initial .ots must remain incomplete');
        assert(timestampsByTarget.get(sigBId)?.apparentlyComplete === true, 'completed .ots must be marked as apparently complete');
        assert(timestampsByTarget.get(sigBId)?.completeProof === true, 'completed .ots must be marked complete');

        const parsedProof = parseOpenTimestampProof(otsA, { name: 'archive-a-initial.qsig.ots' });
        assert(parsedProof.completeProof === false, 'OpenTimestamps parser must classify initial proof as incomplete');
        assert(parsedProof.appearsComplete === false, 'OpenTimestamps parser must report initial proof as apparently incomplete');

        const evidence = await inspectManifestBundleTimestamps(parsedBundle.bundle);
        assert(evidence.length === 2, 'expected two timestamp evidence entries');
        assert(evidence.every((item) => item.linkLabel === 'OTS evidence linked to signature'), 'timestamp evidence should use honest linkage wording');
        assert(
          evidence.some((item) => item.completionLabel === 'OTS proof appears complete') &&
          evidence.some((item) => item.completionLabel === 'OTS proof appears incomplete'),
          'timestamp evidence should report complete and incomplete states honestly'
        );
      },
    },
    {
      name: 'restore links external OpenTimestamps evidence to external detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-external-ots');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-external-ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const otsBytes = await buildOtsFixture(sig.qsigBytes, { completeProof: true });

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
            timestamps: [{ name: 'archive.qsig.ots', bytes: otsBytes }],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'external signature with external OTS should still satisfy archive policy');
        assert(restored.authenticity.timestampEvidence.length === 1, 'expected one external timestamp evidence entry');
        assert(restored.authenticity.timestampEvidence[0].targetVerified === true, 'external OTS should link to a verified detached signature');
        assert(restored.authenticity.timestampEvidence[0].targetSource === 'external', 'external OTS should report external target source');
      },
    },
    {
      name: 'classifyRestoreInputFiles accepts multiple different .pqpk files',
      fn: async () => {
        const manifestBytes = textBytes('restore-multiple-pqpk-inputs');
        const sigA = buildQsigFixture(manifestBytes);
        const sigB = buildQsigFixture(manifestBytes);
        const classified = await classifyRestoreInputFiles([
          fileLike('a.pqpk', sigA.pqpkBytes),
          fileLike('b.pqpk', sigB.pqpkBytes),
        ]);
        assert(classified.pinnedPqPublicKeyFileBytesList.length === 2, 'expected restore inputs to preserve two different .pqpk files');
        assert(classified.pinnedPqPublicKeyFileBytes instanceof Uint8Array, 'expected restore inputs to retain the first .pqpk as a compatibility field');
      },
    },
    {
      name: 'restore can use multiple provided .pqpk files as candidate user pins',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-multiple-pqpk-pins');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-multiple-pqpk-pins.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, {
          authPolicyLevel: 'any-signature',
          minValidSignatures: 2,
        });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);

        const restored = await restoreFromShards(parsed, {
          onLog: () => {},
          onError: () => {},
          verification: {
            signatures: [
              { name: 'archive-a.qsig', bytes: sigA.qsigBytes },
              { name: 'archive-b.qsig', bytes: sigB.qsigBytes },
            ],
            pinnedPqPublicKeyFileBytesList: [sigA.pqpkBytes, sigB.pqpkBytes],
          },
        });

        assert(restored.authenticity.status.policySatisfied === true, 'multiple restore .pqpk pins should still allow policy-satisfying restore');
        assert(restored.authenticity.status.userPinned === true, 'at least one provided .pqpk should user-pin a verified signature');
        assert(restored.authenticity.verification.counts.userPinnedValidTotal === 2, 'expected both detached signatures to match one of the provided .pqpk pins');
      },
    },
    {
      name: 'multi-pin verification dedupes semantically identical .pqpk wrappers for the same signer',
      fn: async () => {
        const manifestBytes = textBytes('multi-pin-semantic-dedupe');
        const sig = buildQsigFixture(manifestBytes);
        const alternateWrapper = mutatePqpkVersionMinor(sig.pqpkBytes, 0x09);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
          pinnedPqPublicKeyFileBytesList: [sig.pqpkBytes, alternateWrapper],
        });

        assert(verification.results.length === 1, 'expected one detached signature result');
        assert(verification.results[0].ok === true, 'semantically duplicate .pqpk wrappers should still verify');
        assert(verification.status.userPinned === true, 'duplicate wrappers for one signer should still set userPinned');
        assert(
          verification.warnings.every((warning) => !warning.includes('Multiple provided .pqpk files match this detached PQ signature')),
          'semantically duplicate .pqpk wrappers must not trigger ambiguity'
        );
      },
    },
    {
      name: 'multi-pin verification suppresses warnings from non-selected .pqpk candidates when a user pin matches',
      fn: async () => {
        const manifestBytes = textBytes('multi-pin-warning-suppression');
        const matching = buildQsigFixture(manifestBytes);
        const distractor = buildQsigFixture(manifestBytes);

        const verification = await verifyManifestSignatures({
          manifestBytes,
          externalSignatures: [{ name: 'archive.qsig', bytes: matching.qsigBytes }],
          pinnedPqPublicKeyFileBytesList: [matching.pqpkBytes, distractor.pqpkBytes],
        });

        assert(verification.status.userPinned === true, 'expected a matching .pqpk to set userPinned');
        assert(
          verification.warnings.every((warning) => !warning.includes('Pinned PQ signer key suite does not match this .qsig and was ignored.')),
          'suite-mismatch warnings from non-selected .pqpk candidates should not leak into a matched result'
        );
        assert(
          verification.warnings.every((warning) => !warning.includes('Using signer public key embedded in .qsig')),
          'embedded-key fallback warnings from non-selected .pqpk candidates should not leak into a matched result'
        );
      },
    },
    {
      name: 'restore links external OpenTimestamps evidence to bundled detached signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-bundled-ots');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-bundled-ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const otsBytes = await buildOtsFixture(sig.qsigBytes, { completeProof: false });

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });
        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          {
            onLog: () => {},
            onError: () => {},
            verification: {
              timestamps: [{ name: 'archive.qsig.ots', bytes: otsBytes }],
            },
          }
        );

        assert(restored.authenticity.status.policySatisfied === true, 'bundled signature plus external OTS should satisfy archive policy');
        assert(restored.authenticity.timestampEvidence.length === 1, 'expected one external timestamp evidence entry for bundled signature');
        assert(restored.authenticity.timestampEvidence[0].targetSource === 'bundle', 'external OTS should link to bundled detached signature');
      },
    },
    {
      name: 'restore deduplicates OTS evidence per detached signature and prefers complete proofs',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-ots-dedupe');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-ots-dedupe.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sigA = buildQsigFixture(split.manifestBytes);
        const sigB = buildQsigFixture(split.manifestBytes);
        const embeddedCompleteA = await buildOtsFixture(sigA.qsigBytes, { completeProof: true });
        const embeddedIncompleteA = await buildOtsFixture(sigA.qsigBytes, { completeProof: false });
        const embeddedCompleteB = await buildOtsFixture(sigB.qsigBytes, { completeProof: true });
        const externalIncompleteB = await buildOtsFixture(sigB.qsigBytes, { completeProof: false });

        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [
            { name: 'archive-a.qsig', bytes: sigA.qsigBytes },
            { name: 'archive-b.qsig', bytes: sigB.qsigBytes },
          ],
          timestamps: [
            { name: 'archive-a-complete.qsig.ots', bytes: embeddedCompleteA },
            { name: 'archive-a-incomplete.qsig.ots', bytes: embeddedIncompleteA },
            { name: 'archive-b-complete.qsig.ots', bytes: embeddedCompleteB },
          ],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes, sigB.pqpkBytes],
        });

        const restored = await restoreFromShards(
          await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob)))),
          {
            onLog: () => {},
            onError: () => {},
            verification: {
              timestamps: [
                { name: 'archive-a-complete.external.qsig.ots', bytes: embeddedCompleteA },
                { name: 'archive-b-incomplete.external.qsig.ots', bytes: externalIncompleteB },
              ],
            },
          }
        );

        assert(restored.authenticity.timestampEvidence.length === 2, 'expected one preferred OTS evidence entry per detached signature');
        assert(
          restored.authenticity.timestampEvidence.every((item) => item.apparentlyComplete === true),
          'complete OTS proofs should win over incomplete duplicates for the same detached signature'
        );
      },
    },
    {
      name: 'attach rejects unrelated OpenTimestamps evidence',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('ots-unrelated');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'ots-unrelated.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const unrelatedOts = await buildOtsFixture(textBytes('not-a-detached-signature'), { completeProof: false });

        await expectFailure(
          () => attachManifestBundleToShards(parsed, {
            manifestBytes: split.manifestBytes,
            signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
            timestamps: [{ name: 'archive.qsig.ots', bytes: unrelatedOts }],
            pqPublicKeyFileBytesList: [sig.pqpkBytes],
          }),
          'attach unexpectedly accepted unrelated OpenTimestamps evidence'
        );
      },
    },
    {
      name: 'restore rejects unrelated external OpenTimestamps evidence',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-unrelated-ots');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-unrelated-ots.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const unrelatedOts = await buildOtsFixture(textBytes('not-a-detached-signature'), { completeProof: false });

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: {
              signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
              timestamps: [{ name: 'archive.qsig.ots', bytes: unrelatedOts }],
            },
          }),
          'restore unexpectedly accepted unrelated external OpenTimestamps evidence'
        );
      },
    },
    {
      name: 'OpenTimestamps evidence never satisfies archive signature policy by itself',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('ots-does-not-satisfy-policy');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'ots-does-not-satisfy-policy.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSigBytes = (await buildStellarSignatureFixture(split.manifestBytes)).bytes;
        const otsBytes = await buildOtsFixture(stellarSigBytes, { completeProof: true });
        const attached = await attachManifestBundleToShards(parsed, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.sig', bytes: stellarSigBytes }],
          timestamps: [{ name: 'archive.sig.ots', bytes: otsBytes }],
        });
        const attachedShards = await Promise.all(attached.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));

        await expectFailure(
          () => restoreFromShards(attachedShards, { onLog: () => {}, onError: () => {} }),
          'OpenTimestamps evidence unexpectedly satisfied strong-pq-signature policy'
        );
      },
    },
    {
      name: 'attach updates manifest-only and bundle-only inputs without rewriting shards',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('manifest-only-attach');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'bundle-only.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const sigA = buildQsigFixture(split.manifestBytes);
        const firstAttach = await attachManifestBundleToShards([], {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive-a.qsig', bytes: sigA.qsigBytes }],
          pqPublicKeyFileBytesList: [sigA.pqpkBytes],
        });

        const sigB = buildQsigFixture(split.manifestBytes);
        const secondAttach = await attachManifestBundleToShards([], {
          bundleBytes: firstAttach.bundleBytes,
          signatures: [{ name: 'archive-b.qsig', bytes: sigB.qsigBytes }],
          pqPublicKeyFileBytesList: [sigB.pqpkBytes],
        });

        assert(firstAttach.shards.length === 0, 'manifest-only attach must not rewrite shards');
        assert(secondAttach.shards.length === 0, 'bundle-only attach must not rewrite shards');
        assert(
          timingSafeEqual(firstAttach.signableManifestBytes, split.manifestBytes) &&
          timingSafeEqual(firstAttach.manifestBytes, split.manifestBytes),
          'manifest-only attach must keep canonical-manifest export separate and unchanged'
        );
        assert(firstAttach.manifestDigestHex === split.manifestDigestHex, 'manifest-only attach must preserve the canonical manifest digest');
        assert(secondAttach.manifestDigestHex === split.manifestDigestHex, 'repeated bundle-only attach must preserve the canonical manifest digest');
        const parsedBundle = parseManifestBundleBytes(secondAttach.bundleBytes);
        assert(parsedBundle.bundle.attachments.signatures.length === 2, 'bundle-only attach must merge signatures into the manifest bundle');

        const originalShards = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const restored = await restoreFromShards(originalShards, {
          onLog: () => {},
          onError: () => {},
          verification: { bundleBytes: secondAttach.bundleBytes },
        });
        assert(restored.authenticity.status.policySatisfied === true, 'repeated attach cycles must preserve signature validity');
        assert(restored.authenticity.verification.counts.validTotal === 2, 'repeated attach cycles must preserve both detached signatures');
      },
    },
    {
      name: 'restore prefers the richer embedded bundle when mixed shards share the same canonical manifest',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-prefer-richer-bundle');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-prefer-richer-bundle.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const originalShards = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const attached = await attachManifestBundleToShards(originalShards, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });
        const updatedShards = await Promise.all(attached.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));

        const mixed = [
          updatedShards[0],
          updatedShards[1],
          originalShards[2],
          originalShards[3],
        ];
        const restored = await restoreFromShards(mixed, {
          onLog: () => {},
          onError: () => {},
        });

        assert(restored.manifestSource === 'embedded-preferred-bundle', `unexpected manifest source: ${restored.manifestSource}`);
        assert(restored.bundleDigestHex === attached.bundleDigestHex, 'restore should prefer the richer embedded bundle digest');
        assert(restored.authenticity.status.bundleCohortMixed === true, 'mixed embedded shard digests should be surfaced explicitly');
        assert(
          Array.isArray(restored.embeddedBundleDigestsUsed) &&
          restored.embeddedBundleDigestsUsed.length === 2 &&
          restored.embeddedBundleDigestsUsed.includes(split.bundleDigestHex) &&
          restored.embeddedBundleDigestsUsed.includes(attached.bundleDigestHex),
          'restore should report all embedded bundle digests used for reconstruction'
        );
        assert(restored.authenticity.status.policySatisfied === true, 'preferred richer embedded bundle should satisfy archive policy');
        assert(restored.authenticity.status.bundlePinned === true, 'preferred richer embedded bundle should preserve bundled signer pinning');
        assert(
          restored.authenticity.warnings.some((warning) => warning.includes('Payload reconstruction used shards from multiple embedded bundle digests')),
          'mixed embedded bundle cohort should emit an explicit authenticity warning'
        );
      },
    },
    {
      name: 'restore with an uploaded bundle still reports mixed embedded bundle cohorts explicitly',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('restore-uploaded-bundle-mixed-cohort');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'restore-uploaded-bundle-mixed-cohort.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'any-signature' });
        const originalShards = await Promise.all(split.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));
        const sig = buildQsigFixture(split.manifestBytes);
        const attached = await attachManifestBundleToShards(originalShards, {
          manifestBytes: split.manifestBytes,
          signatures: [{ name: 'archive.qsig', bytes: sig.qsigBytes }],
          pqPublicKeyFileBytesList: [sig.pqpkBytes],
        });
        const updatedShards = await Promise.all(attached.shards.map(async (item) => parseShard(await blobToBytes(item.blob))));

        const mixed = [
          updatedShards[0],
          updatedShards[1],
          originalShards[2],
          originalShards[3],
        ];
        const restored = await restoreFromShards(mixed, {
          onLog: () => {},
          onError: () => {},
          verification: { bundleBytes: attached.bundleBytes },
        });

        assert(restored.manifestSource === 'uploaded-bundle', `unexpected manifest source: ${restored.manifestSource}`);
        assert(restored.authenticity.status.bundleCohortMixed === true, 'uploaded bundle restore should still surface mixed shard cohorts');
        assert(
          Array.isArray(restored.embeddedBundleDigestsUsed) &&
          restored.embeddedBundleDigestsUsed.length === 2 &&
          restored.embeddedBundleDigestsUsed.includes(split.bundleDigestHex) &&
          restored.embeddedBundleDigestsUsed.includes(attached.bundleDigestHex),
          'uploaded bundle restore should report all embedded bundle digests used for reconstruction'
        );
        assert(
          restored.authenticity.warnings.some((warning) => warning.includes(`selected bundle ${attached.bundleDigestHex}`)),
          'mixed uploaded-bundle restore should name the selected bundle in its warning'
        );
      },
    },
    {
      name: 'strong-pq-signature policy rejects Ed25519-only signatures',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('legacy-signature-only');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'legacy.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'strong-pq-signature' });
        const parsed = await Promise.all(split.shards.slice(0, 4).map(async (item) => parseShard(await blobToBytes(item.blob))));
        const stellarSigBytes = (await buildStellarSignatureFixture(split.manifestBytes)).bytes;

        await expectFailure(
          () => restoreFromShards(parsed, {
            onLog: () => {},
            onError: () => {},
            verification: { signatures: [{ name: 'archive.sig', bytes: stellarSigBytes }] },
          }),
          'strong-pq-signature archive unexpectedly accepted Ed25519-only signature'
        );
      },
    },
    {
      name: 'restore rejects duplicate shard indices',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('duplicate-index');
        const qencBytes = await blobToBytes(await encryptFile(payload, pair.publicKey, 'dup.bin'));
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const shardBytes = await Promise.all(split.shards.slice(0, 4).map((item) => blobToBytes(item.blob)));
        const parsed = [
          parseShard(shardBytes[0]),
          parseShard(shardBytes[0]),
          parseShard(shardBytes[1]),
          parseShard(shardBytes[2]),
        ];

        await expectFailure(
          () => restoreFromShards(parsed, { onLog: () => {}, onError: () => {} }),
          'restore unexpectedly accepted duplicate shard indices'
        );
      },
    },
    {
      name: 'qenc decrypt must fail with unrelated private key',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('wrong-key-check');
        const encrypted = await encryptFile(payload, pairA.publicKey, 'wrong-key.bin');
        const encryptedBytes = await blobToBytes(encrypted);

        await expectFailure(
          () => decryptFile(encryptedBytes, pairB.secretKey),
          'decrypt unexpectedly succeeded with unrelated private key'
        );
      },
    },
    {
      name: 'qenc decrypt must fail on ciphertext tamper',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('tamper-check');
        const encrypted = await encryptFile(payload, pair.publicKey, 'tamper.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const tampered = mutateTail(encryptedBytes);

        await expectFailure(
          () => decryptFile(tampered, pair.secretKey),
          'decrypt unexpectedly succeeded on tampered qenc'
        );
      },
    },
    {
      name: 'qcont restore fails when missing+corrupted exceeds RS tolerance',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('qcont-too-many-errors');
        const encrypted = await encryptFile(payload, pair.publicKey, 'qcont-fail.bin');
        const qencBytes = await blobToBytes(encrypted);
        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 5, k: 3 }, { authPolicyLevel: 'integrity-only' });
        const qconts = split.shards;
        const shardBytes = await Promise.all(qconts.map((shard) => blobToBytes(shard.blob)));

        const subset = shardBytes.slice(0, 4).map((bytes) => bytes.slice());
        subset[0] = mutateTail(subset[0]);
        const parsed = subset.map((bytes) => parseShard(bytes));

        await expectFailure(
          () => restoreFromShards(parsed, { onLog: () => {}, onError: () => {} }),
          'restore unexpectedly succeeded with too many missing/corrupted shards'
        );
      },
    },
    {
      name: 'qenc chunked mode roundtrip (> CHUNK_SIZE)',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(CHUNK_SIZE + 12345);
        const encrypted = await encryptFile(payload, pair.publicKey, 'chunked.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const header = parseQencHeader(encryptedBytes);
        assert(header.metadata.aead_mode === 'per-chunk-aead', 'expected per-chunk-aead mode');
        assert(header.metadata.chunkCount >= 2, 'expected chunkCount >= 2 for chunked payload');
        assert(header.metadata.noncePolicyId === NONCE_POLICY_PER_CHUNK_V3, 'per-chunk noncePolicyId mismatch');
        assert(header.metadata.nonceMode === NONCE_MODE_KMAC_CTR32, 'per-chunk nonceMode mismatch');
        assert(header.metadata.counterBits === 32, 'per-chunk counterBits mismatch');
        assert(header.metadata.maxChunkCount === 0xffffffff, 'per-chunk maxChunkCount mismatch');
        assert(header.metadata.iv_strategy === IV_STRATEGY_KMAC_PREFIX64_CTR32_V3, 'per-chunk iv_strategy mismatch');

        const { decryptedBlob, metadata } = await decryptFile(encryptedBytes, pair.secretKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert(metadata.fileHash === (await hashBytes(payload)), 'chunked metadata hash mismatch');
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'chunked roundtrip mismatch');
      },
    },
    {
      name: 'KMAC wrapper applies SP 800-185 customization and dkLen semantics',
      fn: async () => {
        const key = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        const message = textBytes('Quantum Vault KMAC regression test');
        const out32 = kmac256(key, message, {
          customization: 'quantum-vault:test:v2',
          dkLen: 32,
        });
        const out8 = kmac256(key, message, {
          customization: 'quantum-vault:test:v2',
          dkLen: 8,
        });
        const out32Alt = kmac256(key, message, {
          customization: 'quantum-vault:test:alt:v2',
          dkLen: 32,
        });

        assert(
          bytesToHex(out32) === 'e4c32540bbeba9c4ada8e0b74df68e0dd9280181d1ee95cabe61a7f290a7253d',
          'KMAC 32-byte regression vector mismatch'
        );
        assert(
          bytesToHex(out8) === '166add657780655a',
          'KMAC 8-byte regression vector mismatch'
        );
        assert(
          bytesToHex(out32Alt) === 'e691cf1c1df8c2a55415532c0b1076e1891f11dc0af86c9cab46cc98485bbf88',
          'KMAC alternate customization vector mismatch'
        );
        assert(
          bytesToHex(out8) !== bytesToHex(out32.subarray(0, 8)),
          'KMAC dkLen=8 must not equal truncation of the 32-byte output'
        );
      },
    },
    {
      name: 'deriveChunkIvFromK uses SP 800-185 KMAC prefix derivation',
      fn: async () => {
        const Kiv = Uint8Array.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff));
        const containerNonce = Uint8Array.from(Array.from({ length: 12 }, (_, i) => (i * 5 + 11) & 0xff));
        const iv = deriveChunkIvFromK(Kiv, containerNonce, 7, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, {
          chunkCount: 16,
          maxChunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          counterBits: NONCE_COUNTER_BITS_U32,
          ivStrategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        });

        assert(
          bytesToHex(iv) === '1a0f9d63bb6bf37300000007',
          'deriveChunkIvFromK regression vector mismatch'
        );
      },
    },
    {
      name: 're-encrypt same plaintext keeps (Kenc,nonce) unique',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('nonce-t01-same-plaintext');
        const seenPairs = new Set();

        for (let i = 0; i < 64; i += 1) {
          const encrypted = await encryptFile(payload, pair.publicKey, 'nonce-t01.bin');
          const encryptedBytes = await blobToBytes(encrypted);
          const parsed = parseQencHeader(encryptedBytes);
          assert(parsed.storedKeyCommitment instanceof Uint8Array, 'key commitment is missing');
          assert(parsed.containerNonce instanceof Uint8Array, 'container nonce is missing');
          const pairId = `${bytesToHex(parsed.storedKeyCommitment)}:${bytesToHex(parsed.containerNonce)}`;
          assert(!seenPairs.has(pairId), `detected (Kenc,nonce) reuse at iteration ${i}`);
          seenPairs.add(pairId);
        }
      },
    },
    {
      name: 'reject chunk counter wrap near 2^32 boundary',
      fn: async () => {
        const contract = {
          maxChunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          counterBits: NONCE_COUNTER_BITS_U32,
          ivStrategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        };

        assertPerChunkNonceContract({
          chunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          ...contract,
        });

        await expectFailure(
          async () => {
            assertPerChunkNonceContract({
              chunkCount: NONCE_MAX_CHUNK_COUNT_U32 + 1,
              ...contract,
            });
          },
          'nonce contract unexpectedly accepted chunkCount above uint32 policy bound'
        );

        const Kiv = createLargeDeterministicPayload(32);
        const containerNonce = createLargeDeterministicPayload(12);
        await expectFailure(
          async () => {
            deriveChunkIvFromK(Kiv, containerNonce, NONCE_MAX_CHUNK_COUNT_U32, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, {
              chunkCount: NONCE_MAX_CHUNK_COUNT_U32,
              ...contract,
            });
          },
          'deriveChunkIvFromK unexpectedly accepted wrapped chunk index'
        );
      },
    },
    {
      name: 'crafted per-chunk IV collision campaign is blocked',
      fn: async () => {
        const Kiv = createLargeDeterministicPayload(32);
        const containerNonce = createLargeDeterministicPayload(12);
        const chunkCount = 4096;
        const contract = {
          chunkCount,
          maxChunkCount: NONCE_MAX_CHUNK_COUNT_U32,
          counterBits: NONCE_COUNTER_BITS_U32,
          ivStrategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        };
        assertPerChunkNonceContract(contract);

        const seenIvs = new Set();
        for (let i = 0; i < chunkCount; i += 1) {
          const iv = deriveChunkIvFromK(Kiv, containerNonce, i, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, contract);
          const ivHex = bytesToHex(iv);
          assert(!seenIvs.has(ivHex), `unexpected IV collision at chunk index ${i}`);
          seenIvs.add(ivHex);
        }

        await expectFailure(
          async () => {
            deriveChunkIvFromK(Kiv, containerNonce, 2 ** 32, DEFAULT_CRYPTO_PROFILE.domainStrings.iv, contract);
          },
          'deriveChunkIvFromK unexpectedly accepted overflowed chunk index'
        );
      },
    },
    {
      name: 'parseQencHeader rejects invalid magic',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('qenc-parse-check');
        const encrypted = await encryptFile(payload, pair.publicKey, 'parse.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const malformed = encryptedBytes.slice();
        malformed[0] ^= 0xff;

        await expectFailure(
          async () => {
            parseQencHeader(malformed);
          },
          'parseQencHeader unexpectedly accepted invalid magic'
        );
      },
    },
    {
      name: 'buildQcontShards rejects mismatched private key',
      fn: async () => {
        const pairA = await generateKeyPair({ collectUserEntropy: false });
        const pairB = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('wrong-key-at-build');
        const encrypted = await encryptFile(payload, pairA.publicKey, 'f10.bin');
        const qencBytes = await blobToBytes(encrypted);

        await expectFailure(
          () => buildQcontShards(qencBytes, pairB.secretKey, { n: 5, k: 3 }),
          'buildQcontShards unexpectedly accepted mismatched private key'
        );
      },
    },
    {
      name: 'decryptFile fails closed when key commitment is missing',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('key-commitment-required');
        const encrypted = await encryptFile(payload, pair.publicKey, 'f11.bin');
        const encBytes = await blobToBytes(encrypted);
        const malformed = removeQencKeyCommitmentBytes(encBytes);

        await expectFailure(
          () => decryptFile(malformed, pair.secretKey),
          'decryptFile unexpectedly accepted missing key commitment'
        );
      },
    },
    {
      name: 'encryptFile rejects empty payload',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        await expectFailure(
          () => encryptFile(new Uint8Array(0), pair.publicKey, 'empty.bin'),
          'encryptFile unexpectedly accepted empty payload'
        );
      },
    },
    {
      name: 'bytes.js: toHex/fromHex roundtrip',
      fn: async () => {
        const original = createLargeDeterministicPayload(64);
        const hex = toHex(original);
        assert(hex.length === 128, 'hex length mismatch');
        const roundtripped = fromHex(hex);
        assert(roundtripped.length === 64, 'fromHex length mismatch');
        assert(timingSafeEqual(original, roundtripped), 'toHex/fromHex roundtrip mismatch');
      },
    },
    {
      name: 'bytes.js: timingSafeEqual rejects length mismatch and bitflip',
      fn: async () => {
        const a = createLargeDeterministicPayload(32);
        const b = a.slice();
        assert(timingSafeEqual(a, b), 'identical arrays must be equal');

        const shorter = a.slice(0, 16);
        assert(!timingSafeEqual(a, shorter), 'different lengths must not be equal');

        const flipped = a.slice();
        flipped[15] ^= 1;
        assert(!timingSafeEqual(a, flipped), 'bitflipped array must not be equal');

        assert(!timingSafeEqual(a, 'not-uint8array'), 'non-Uint8Array must return false');
      },
    },
    {
      name: 'ADV: parseShard rejects empty input',
      fn: async () => {
        await expectFailure(
          () => parseShard(new Uint8Array(0), { strict: true }),
          'parseShard unexpectedly accepted empty Uint8Array'
        );
        await expectFailure(
          () => parseShard(new Uint8Array(4), { strict: true }),
          'parseShard unexpectedly accepted 4-byte Uint8Array'
        );
      },
    },
    {
      name: 'ADV: parseShard rejects invalid magic bytes',
      fn: async () => {
        const garbage = createLargeDeterministicPayload(512);
        await expectFailure(
          () => parseShard(garbage, { strict: true }),
          'parseShard unexpectedly accepted garbage bytes'
        );
      },
    },
    {
      name: 'ADV: validatePublicKey rejects wrong-size keys',
      fn: async () => {
        const { validatePublicKey: vpk, validateSecretKey: vsk } = await import('./mlkem.js');
        await expectFailure(
          () => vpk(new Uint8Array(100)),
          'validatePublicKey accepted wrong-size key'
        );
        await expectFailure(
          () => vpk('not-a-uint8array'),
          'validatePublicKey accepted non-Uint8Array'
        );
        await expectFailure(
          () => vsk(new Uint8Array(100)),
          'validateSecretKey accepted wrong-size key'
        );
      },
    },
    {
      name: 'ADV: encryptFile rejects payload exceeding MAX_FILE_SIZE',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const fakeLargePayload = { length: MAX_FILE_SIZE + 1, [Symbol.iterator]: function*(){} };
        await expectFailure(
          () => encryptFile(fakeLargePayload, pair.publicKey, 'too-big.bin'),
          'encryptFile unexpectedly accepted payload exceeding MAX_FILE_SIZE'
        );
      },
    },
    {
      name: 'ADV: buildQcontShards rejects invalid RS params',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('bad-rs-params');
        const qenc = await blobToBytes(await encryptFile(payload, pair.publicKey, 'rs.bin'));

        await expectFailure(
          () => buildQcontShards(qenc, pair.secretKey, { n: 1, k: 1 }),
          'buildQcontShards accepted n=1, k=1'
        );
        await expectFailure(
          () => buildQcontShards(qenc, pair.secretKey, { n: 3, k: 5 }),
          'buildQcontShards accepted k > n'
        );
      },
    },
    {
      name: 'ADV: qenc decrypt fails on truncated container',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = textBytes('truncated-container-check');
        const encrypted = await encryptFile(payload, pair.publicKey, 'trunc.bin');
        const encryptedBytes = await blobToBytes(encrypted);
        const truncated = encryptedBytes.slice(0, 64);

        await expectFailure(
          () => decryptFile(truncated, pair.secretKey),
          'decryptFile unexpectedly succeeded on truncated container'
        );
      },
    },
    {
      name: 'ADV: qenc chunked decrypt fails on swapped chunks',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload((CHUNK_SIZE * 2) + 4096);
        const encrypted = await encryptFile(payload, pair.publicKey, 'swap.bin');
        const encBytes = await blobToBytes(encrypted);
        const header = parseQencHeader(encBytes);
        assert(header.metadata.chunkCount >= 3, 'need at least 3 chunks for swap test');

        const headerEnd = header.offset;
        const tagLen = 16;
        const chunkCipherLen = CHUNK_SIZE + tagLen;
        const chunk0 = encBytes.slice(headerEnd, headerEnd + chunkCipherLen);
        const chunk1Start = headerEnd + chunkCipherLen;
        const chunk1 = encBytes.slice(chunk1Start, chunk1Start + chunkCipherLen);
        let exercised = false;

        if (chunk0.length === chunkCipherLen && chunk1.length > 0) {
          const swapped = encBytes.slice();
          swapped.set(chunk1.slice(0, Math.min(chunk1.length, chunkCipherLen)), headerEnd);
          swapped.set(chunk0, chunk1Start);
          exercised = true;

          await expectFailure(
            () => decryptFile(swapped, pair.secretKey),
            'decryptFile unexpectedly succeeded with swapped chunks'
          );
        }

        assert(exercised, 'swap test did not exercise full-chunk swap path');
      },
    },
    {
      name: 'ADV: parseShard non-strict returns diagnostics instead of throw',
      fn: async () => {
        const garbage = createLargeDeterministicPayload(512);
        const result = parseShard(garbage, { strict: false });
        assert(Array.isArray(result.diagnostics?.errors), 'non-strict parseShard must return diagnostics.errors');
        assert(result.diagnostics.errors.length > 0, 'non-strict parseShard must report errors for garbage input');
        assert(!result.metaJSON, 'non-strict parseShard must not have metaJSON for garbage input');
      },
    },
    {
      name: 'chunked split + restore end-to-end (per-chunk-aead)',
      fn: async () => {
        const pair = await generateKeyPair({ collectUserEntropy: false });
        const payload = createLargeDeterministicPayload(CHUNK_SIZE + 50000);
        const encrypted = await encryptFile(payload, pair.publicKey, 'chunked-e2e.bin');
        const qencBytes = await blobToBytes(encrypted);

        const header = parseQencHeader(qencBytes);
        assert(header.metadata.aead_mode === 'per-chunk-aead', 'expected per-chunk-aead');

        const split = await buildQcontShards(qencBytes, pair.secretKey, { n: 7, k: 5 }, { authPolicyLevel: 'integrity-only' });
        assert(split.shards.length === 7, 'expected 7 shards');

        const shardBytes = await Promise.all(split.shards.map(s => blobToBytes(s.blob)));
        const subset = shardBytes.slice(0, 6).map(b => parseShard(b));

        const restored = await restoreFromShards(subset, { onLog: () => {}, onError: () => {} });
        assert(restored.qencOk, 'chunked e2e: qenc hash mismatch');

        const { decryptedBlob } = await decryptFile(restored.qencBytes, restored.privKey);
        const decrypted = await blobToBytes(decryptedBlob);
        assert((await hashBytes(payload)) === (await hashBytes(decrypted)), 'chunked e2e: payload mismatch');
      },
    },
  ];
}

export async function runSelfTest({ onProgress } = {}) {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  const cases = buildCases().map((item) => ({
    ...item,
    name: prefixSelfTestName(item.name),
  }));
  const results = [];

  if (typeof onProgress === 'function') {
    onProgress(0, cases.length, 'Starting self-test');
  }

  for (let i = 0; i < cases.length; i += 1) {
    const current = cases[i];
    const result = await runCase(current.name, current.fn);
    results.push(result);
    if (typeof onProgress === 'function') {
      onProgress(i + 1, cases.length, current.name);
    }
  }

  const passed = results.filter((result) => result.ok).length;
  const failed = results.length - passed;

  return {
    ok: failed === 0,
    total: results.length,
    passed,
    failed,
    results,
  };
}
