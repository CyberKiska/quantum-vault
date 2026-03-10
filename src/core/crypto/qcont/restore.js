import { sha3_512 } from '@noble/hashes/sha3.js';
import { hashBytes } from '../index.js';
import { bytesEqual, toHex } from '../bytes.js';
import { buildQencHeader } from '../qenc/format.js';
import { LEGACY_QCONT_FORMAT_VERSION, QCONT_FORMAT_VERSION } from '../constants.js';
import { parseArchiveManifestBytes } from '../manifest/archive-manifest.js';
import {
  assertAuthPolicyCommitment,
  parseManifestBundleBytes,
} from '../manifest/manifest-bundle.js';
import { assertManifestBundleTimestamps, inspectTimestampEvidence } from '../auth/opentimestamps.js';
import { verifyManifestSignatures } from '../auth/verify-signatures.js';
import { validateContainerPolicyMetadata } from '../policy.js';
import { resolveErasureRuntime } from '../erasure-runtime.js';

const QCONT_MAGIC = 'QVC1';
const KEY_COMMITMENT_MAX_LEN = 32;
const DIGEST_LEN = 64;
const MAX_META_LEN = 16 * 1024;
const MAX_MANIFEST_LEN = 1024 * 1024;
const MAX_BUNDLE_LEN = 4 * 1024 * 1024;

function ensurePositiveInteger(value, field, min = 1) {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function ensureEqual(actual, expected, field) {
  if (actual !== expected) {
    throw new Error(`${field} mismatch (expected ${expected}, got ${actual})`);
  }
}

function normalizeHexString(value) {
  return String(value || '').trim().toLowerCase();
}

function bytesMatch(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && bytesEqual(a, b);
}

function evaluateArchivePolicy(authPolicy, verification) {
  const counts = verification?.counts || {
    validTotal: 0,
    validStrongPq: 0,
  };
  const minValidSignatures = ensurePositiveInteger(
    Number(authPolicy.minValidSignatures),
    'authPolicy.minValidSignatures',
    1
  );
  const level = String(authPolicy.level || '');

  if (level === 'integrity-only') {
    return {
      level,
      minValidSignatures,
      satisfied: true,
      reason: 'integrity-only policy does not require signatures',
    };
  }

  if (level === 'any-signature') {
    const satisfied = counts.validTotal >= minValidSignatures;
    return {
      level,
      minValidSignatures,
      satisfied,
      reason: satisfied
        ? 'required signature count satisfied'
        : 'no valid signature satisfies archive policy',
    };
  }

  if (level === 'strong-pq-signature') {
    const satisfied = counts.validTotal >= minValidSignatures && counts.validStrongPq >= 1;
    return {
      level,
      minValidSignatures,
      satisfied,
      reason: satisfied
        ? 'required strong PQ signature present'
        : 'no valid strong PQ signature satisfies archive policy',
    };
  }

  throw new Error(`Unsupported authPolicy.level: ${authPolicy.level}`);
}

function collectCandidateCohorts(shards) {
  const byDigest = new Map();
  for (const shard of shards) {
    const key = `${shard.manifestDigestHex}:${shard.bundleDigestHex}`;
    if (!byDigest.has(key)) {
      byDigest.set(key, {
        key,
        manifestDigestHex: shard.manifestDigestHex,
        bundleDigestHex: shard.bundleDigestHex,
        manifestBytes: shard.manifestBytes,
        bundleBytes: shard.bundleBytes,
        shards: [],
      });
    }
    const entry = byDigest.get(key);
    if (!bytesEqual(entry.manifestBytes, shard.manifestBytes)) {
      throw new Error(`Manifest bytes mismatch inside cohort ${key}`);
    }
    if (!bytesEqual(entry.bundleBytes, shard.bundleBytes)) {
      throw new Error(`Bundle bytes mismatch inside cohort ${key}`);
    }
    entry.shards.push(shard);
  }
  return [...byDigest.values()];
}

async function enrichCandidate(candidate, bundleBytesOverride = null) {
  const parsedManifest = parseArchiveManifestBytes(candidate.manifestBytes);
  if (parsedManifest.digestHex !== candidate.manifestDigestHex) {
    throw new Error('Embedded manifest digest mismatch');
  }
  const selectedBundleBytes = bundleBytesOverride instanceof Uint8Array ? bundleBytesOverride : candidate.bundleBytes;
  const parsedBundle = parseManifestBundleBytes(selectedBundleBytes);
  if (!(bundleBytesOverride instanceof Uint8Array) && parsedBundle.digestHex !== candidate.bundleDigestHex) {
    throw new Error('Embedded bundle digest mismatch');
  }
  if (!bytesEqual(parsedBundle.manifestBytes, parsedManifest.bytes)) {
    throw new Error('Embedded bundle manifest does not match embedded manifest bytes');
  }
  if (parsedBundle.manifestDigestHex !== parsedManifest.digestHex) {
    throw new Error('Embedded bundle manifestDigest does not match embedded manifest digest');
  }
  assertAuthPolicyCommitment(parsedManifest.manifest.authPolicyCommitment, parsedBundle.bundle.authPolicy);
  await assertManifestBundleTimestamps(parsedBundle.bundle);
  return {
    ...candidate,
    embeddedBundleDigestHex: candidate.bundleDigestHex,
    embeddedBundleBytes: candidate.bundleBytes,
    manifest: parsedManifest.manifest,
    manifestBytes: parsedManifest.bytes,
    bundle: parsedBundle.bundle,
    bundleBytes: parsedBundle.bytes,
    bundleDigestHex: parsedBundle.digestHex,
  };
}

async function evaluateCandidateAuthenticity(candidate, verificationOptions = {}) {
  const verification = await verifyManifestSignatures({
    manifestBytes: candidate.manifestBytes,
    bundleSignatures: candidate.bundle.attachments.signatures,
    bundlePublicKeys: candidate.bundle.attachments.publicKeys,
    externalSignatures: Array.isArray(verificationOptions.signatures) ? verificationOptions.signatures : [],
    pinnedPqPublicKeyFileBytes: verificationOptions.pinnedPqPublicKeyFileBytes ?? verificationOptions.pqPublicKeyFileBytes,
    pinnedPqPublicKeyFileBytesList: verificationOptions.pinnedPqPublicKeyFileBytesList,
    expectedEd25519Signer: verificationOptions.expectedEd25519Signer,
  });
  const policy = evaluateArchivePolicy(candidate.bundle.authPolicy, verification);
  const timestampEvidence = await inspectTimestampEvidence({
    bundle: candidate.bundle,
    externalTimestamps: Array.isArray(verificationOptions.timestamps) ? verificationOptions.timestamps : [],
    signatureArtifacts: verification.signatureArtifacts,
  });
  const warnings = [];
  if (policy.level === 'integrity-only') {
    warnings.push('Archive policy is integrity-only; provenance is not bound to a verified signer.');
  }
  const invalidSignatureCount = verification.results.filter((item) => !item.ok).length;
  if (invalidSignatureCount > 0) {
    warnings.push(`${invalidSignatureCount} attached signature(s) did not verify and were ignored for policy evaluation.`);
  }
  return {
    verification,
    policy,
    timestampEvidence,
    warnings,
  };
}

function preferredBundleScore(item) {
  const verificationCounts = item?.authenticity?.verification?.counts || {};
  const attachments = item?.candidate?.bundle?.attachments || {};
  return [
    Number(verificationCounts.validTotal) || 0,
    Number(verificationCounts.validStrongPq) || 0,
    Array.isArray(attachments.signatures) ? attachments.signatures.length : 0,
    Array.isArray(attachments.publicKeys) ? attachments.publicKeys.length : 0,
    Array.isArray(attachments.timestamps) ? attachments.timestamps.length : 0,
  ];
}

function compareScoreDesc(aScore, bScore) {
  for (let i = 0; i < Math.max(aScore.length, bScore.length); i += 1) {
    const diff = (Number(aScore[i]) || 0) - (Number(bScore[i]) || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function selectPreferredSatisfyingCandidate(satisfying) {
  if (!Array.isArray(satisfying) || satisfying.length <= 1) return null;
  const firstManifestDigest = satisfying[0]?.candidate?.manifestDigestHex;
  const firstManifestBytes = satisfying[0]?.candidate?.manifestBytes;
  if (!firstManifestDigest || !(firstManifestBytes instanceof Uint8Array)) return null;

  for (const item of satisfying) {
    if (item?.candidate?.manifestDigestHex !== firstManifestDigest) return null;
    if (!bytesMatch(item?.candidate?.manifestBytes, firstManifestBytes)) return null;
  }

  const ranked = [...satisfying].sort((left, right) => {
    const diff = compareScoreDesc(preferredBundleScore(right), preferredBundleScore(left));
    if (diff !== 0) return diff;
    return String(right?.candidate?.bundleDigestHex || '').localeCompare(String(left?.candidate?.bundleDigestHex || ''));
  });
  if (ranked.length < 2) return ranked[0] || null;
  if (compareScoreDesc(preferredBundleScore(ranked[0]), preferredBundleScore(ranked[1])) === 0) {
    return null;
  }
  return ranked[0];
}

function hasManifestEquivalentSibling(candidates, selectedCandidate) {
  if (!Array.isArray(candidates) || !selectedCandidate) return false;
  for (const candidate of candidates) {
    if (!candidate || candidate.bundleDigestHex === selectedCandidate.bundleDigestHex) continue;
    if (candidate.manifestDigestHex !== selectedCandidate.manifestDigestHex) continue;
    if (bytesMatch(candidate.manifestBytes, selectedCandidate.manifestBytes)) {
      return true;
    }
  }
  return false;
}

function selectExplicitCandidate(candidates, verificationOptions) {
  if (verificationOptions.manifestBytes instanceof Uint8Array) {
    const parsedManifest = parseArchiveManifestBytes(verificationOptions.manifestBytes);
    const matching = candidates.filter((item) => item.manifestDigestHex === parsedManifest.digestHex);
    if (matching.length === 0) {
      throw new Error('Provided canonical manifest does not match any shard cohort');
    }
    if (matching.length > 1) {
      throw new Error('Canonical manifest matches multiple bundle cohorts. Provide the bundle file or pinned signatures to disambiguate.');
    }
    return matching[0];
  }

  return null;
}

async function resolveArchiveContext(shards, verificationOptions = {}) {
  const rawCandidates = collectCandidateCohorts(shards);
  if (rawCandidates.length === 0) {
    throw new Error('No valid shard cohorts found');
  }

  if (verificationOptions.bundleBytes instanceof Uint8Array) {
    const parsedBundle = parseManifestBundleBytes(verificationOptions.bundleBytes);
    const matching = rawCandidates.filter((candidate) => (
      candidate.manifestDigestHex === parsedBundle.manifestDigestHex &&
      bytesEqual(candidate.manifestBytes, parsedBundle.manifestBytes)
    ));
    if (matching.length === 0) {
      throw new Error('Provided manifest bundle does not match any shard manifest');
    }
    const explicitCandidate = await enrichCandidate(matching[0], parsedBundle.bytes);
    const authenticity = await evaluateCandidateAuthenticity(explicitCandidate, verificationOptions);
    if (!authenticity.policy.satisfied) {
      throw new Error(authenticity.policy.reason);
    }
    return {
      candidate: explicitCandidate,
      authenticity,
      source: 'uploaded-bundle',
      candidateDigests: rawCandidates.map((item) => item.bundleDigestHex),
      useManifestWideShardSelection: true,
    };
  }

  const candidates = await Promise.all(rawCandidates.map((candidate) => enrichCandidate(candidate)));
  if (candidates.length === 0) {
    throw new Error('No valid shard cohorts found');
  }

  const explicit = selectExplicitCandidate(candidates, verificationOptions);
  if (explicit) {
    const authenticity = await evaluateCandidateAuthenticity(explicit, verificationOptions);
    if (!authenticity.policy.satisfied) {
      throw new Error(authenticity.policy.reason);
    }
    return {
      candidate: explicit,
      authenticity,
      source: 'uploaded-manifest',
      candidateDigests: candidates.map((item) => item.bundleDigestHex),
      useManifestWideShardSelection: false,
    };
  }

  const evaluated = [];
  for (const candidate of candidates) {
    try {
      evaluated.push({
        candidate,
        authenticity: await evaluateCandidateAuthenticity(candidate, verificationOptions),
        evaluationError: null,
      });
    } catch (error) {
      evaluated.push({
        candidate,
        authenticity: {
          verification: {
            status: {
              signatureVerified: false,
              strongPqSignatureVerified: false,
              signerPinned: false,
              signerIdentityPinned: false,
              bundlePinned: false,
              userPinned: false,
              userPinProvided: false,
            },
            counts: {
              validTotal: 0,
              validStrongPq: 0,
              pinnedValidTotal: 0,
              bundlePinnedValidTotal: 0,
              userPinnedValidTotal: 0,
            },
            results: [],
            warnings: [],
          },
          policy: {
            level: candidate.bundle.authPolicy.level,
            minValidSignatures: candidate.bundle.authPolicy.minValidSignatures,
            satisfied: false,
            reason: error?.message || String(error),
          },
          timestampEvidence: [],
          warnings: [],
        },
        evaluationError: error,
      });
    }
  }

  const satisfying = evaluated.filter((item) => item.authenticity.policy.satisfied);
  if (satisfying.length === 1) {
    const widenSelection = hasManifestEquivalentSibling(candidates, satisfying[0].candidate);
    return {
      candidate: satisfying[0].candidate,
      authenticity: satisfying[0].authenticity,
      source: widenSelection ? 'embedded-preferred-bundle' : 'embedded',
      candidateDigests: candidates.map((item) => item.bundleDigestHex),
      useManifestWideShardSelection: widenSelection,
    };
  }
  if (satisfying.length > 1) {
    const preferred = selectPreferredSatisfyingCandidate(satisfying);
    if (preferred) {
      return {
        candidate: preferred.candidate,
        authenticity: preferred.authenticity,
        source: 'embedded-preferred-bundle',
        candidateDigests: candidates.map((item) => item.bundleDigestHex),
        useManifestWideShardSelection: true,
      };
    }
    throw new Error('Multiple shard cohorts satisfy archive policy. Provide the manifest bundle, canonical manifest, or signer pins to disambiguate.');
  }

  const firstEvaluationError = evaluated.find((item) => item.evaluationError)?.evaluationError;
  if (firstEvaluationError && evaluated.every((item) => item.evaluationError)) {
    throw firstEvaluationError;
  }
  if (candidates.length === 1) {
    throw new Error(evaluated[0].authenticity.policy.reason);
  }
  throw new Error('No shard cohort satisfies archive policy.');
}

function parseShardUnsafe(arr) {
  if (!(arr instanceof Uint8Array)) {
    throw new Error('Shard must be a Uint8Array');
  }

  const minHeader = 4 + 2 + 4 + DIGEST_LEN + 4 + DIGEST_LEN + 4 + 12 + 16 + 2 + 1 + 2 + 2;
  if (arr.length < minHeader) {
    throw new Error('Shard is too small to contain a valid header');
  }

  const dv = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  let off = 0;

  const ensure = (need, reason) => {
    if (off + need > arr.length) {
      throw new Error(`Shard is truncated: ${reason}`);
    }
  };

  const readU8 = (reason) => {
    ensure(1, reason);
    const v = dv.getUint8(off);
    off += 1;
    return v;
  };

  const readU16 = (reason) => {
    ensure(2, reason);
    const v = dv.getUint16(off, false);
    off += 2;
    return v;
  };

  const readU32 = (reason) => {
    ensure(4, reason);
    const v = dv.getUint32(off, false);
    off += 4;
    return v;
  };

  const readBytes = (len, reason) => {
    ensure(len, reason);
    const out = arr.subarray(off, off + len);
    off += len;
    return out;
  };

  const decodeJsonBytes = (bytes, reason) => {
    try {
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (error) {
      throw new Error(`Invalid ${reason}: ${error?.message || error}`);
    }
  };

  const magic = new TextDecoder().decode(readBytes(4, 'magic'));
  if (magic !== QCONT_MAGIC) {
    throw new Error('Invalid .qcont magic');
  }

  const metaLen = readU16('metaLen');
  if (metaLen <= 0 || metaLen > MAX_META_LEN) {
    throw new Error('Invalid shard metadata length');
  }
  const metaBytes = readBytes(metaLen, 'metaJSON');
  const metaJSON = decodeJsonBytes(metaBytes, 'shard metadata JSON');
  if (metaJSON?.alg?.fmt === LEGACY_QCONT_FORMAT_VERSION) {
    throw new Error('Legacy .qcont format is not supported. Rebuild the archive with the new manifest bundle format.');
  }
  if (metaJSON?.alg?.fmt !== QCONT_FORMAT_VERSION) {
    throw new Error(`Unsupported shard format: expected ${QCONT_FORMAT_VERSION}, got ${metaJSON?.alg?.fmt ?? 'unknown'}`);
  }

  const manifestLen = readU32('manifest length');
  if (manifestLen <= 0 || manifestLen > MAX_MANIFEST_LEN) {
    throw new Error('Invalid embedded manifest length');
  }
  const manifestBytes = readBytes(manifestLen, 'manifest bytes');
  const manifestDigestBytes = readBytes(DIGEST_LEN, 'manifest digest');
  const computedManifestDigestBytes = sha3_512(manifestBytes);
  if (!bytesEqual(manifestDigestBytes, computedManifestDigestBytes)) {
    throw new Error('Embedded manifest digest mismatch');
  }
  const manifestDigestHex = toHex(manifestDigestBytes);

  const bundleLen = readU32('bundle length');
  if (bundleLen <= 0 || bundleLen > MAX_BUNDLE_LEN) {
    throw new Error('Invalid embedded bundle length');
  }
  const bundleBytes = readBytes(bundleLen, 'bundle bytes');
  const bundleDigestBytes = readBytes(DIGEST_LEN, 'bundle digest');
  const computedBundleDigestBytes = sha3_512(bundleBytes);
  if (!bytesEqual(bundleDigestBytes, computedBundleDigestBytes)) {
    throw new Error('Embedded bundle digest mismatch');
  }
  const bundleDigestHex = toHex(bundleDigestBytes);

  const encapLen = readU32('encapsulatedKey length');
  if (encapLen <= 0) throw new Error('Invalid encapsulated key length');
  const encapsulatedKey = readBytes(encapLen, 'encapsulatedKey');

  const iv = readBytes(12, 'container nonce');
  const salt = readBytes(16, 'kdf salt');

  const qencMetaLen = readU16('qenc metadata length');
  if (qencMetaLen <= 0 || qencMetaLen > MAX_META_LEN) {
    throw new Error('Invalid qenc metadata length');
  }
  const qencMetaBytes = readBytes(qencMetaLen, 'qenc metadata');
  const qencMetaJSON = decodeJsonBytes(qencMetaBytes, 'qenc metadata JSON');

  if (metaJSON?.hasKeyCommitment !== true) {
    throw new Error('Shard metadata must indicate hasKeyCommitment=true');
  }

  const kcLen = readU8('key commitment length');
  if (kcLen !== KEY_COMMITMENT_MAX_LEN) {
    throw new Error(`Invalid key commitment length: expected ${KEY_COMMITMENT_MAX_LEN}, got ${kcLen}`);
  }
  const keyCommit = readBytes(kcLen, 'key commitment');
  if (normalizeHexString(metaJSON?.keyCommitmentHex) !== normalizeHexString(toHex(keyCommit))) {
    throw new Error('Shard metadata keyCommitmentHex mismatch');
  }

  const shardIndex = readU16('shard index');
  const shareLen = readU16('share length');
  if (shareLen <= 0) throw new Error('Invalid Shamir share length');
  const share = readBytes(shareLen, 'Shamir share');
  const fragments = arr.subarray(off);
  if (fragments.length === 0) {
    throw new Error('Shard fragment payload is empty');
  }

  return {
    metaJSON,
    metaBytes,
    manifestBytes,
    manifestDigestHex,
    bundleBytes,
    bundleDigestHex,
    encapsulatedKey,
    iv,
    salt,
    qencMetaBytes,
    qencMetaJSON,
    keyCommit,
    shardIndex,
    share,
    fragments,
    diagnostics: { errors: [], warnings: [] },
  };
}

export function parseShard(arr, options = {}) {
  const { strict = true } = options;
  try {
    return parseShardUnsafe(arr);
  } catch (error) {
    if (strict) throw error;
    return {
      diagnostics: { errors: [error?.message || String(error)], warnings: [] },
    };
  }
}

function assertManifestMatchesQencMetadata(manifest, qencMetaJSON) {
  const qenc = manifest.qenc || {};

  ensureEqual(qenc.hashAlg, 'SHA3-512', 'qenc.hashAlg');
  ensureEqual(qenc.primaryAnchor, 'qencHash', 'qenc.primaryAnchor');
  ensureEqual(qenc.containerIdRole, 'secondary-header-id', 'qenc.containerIdRole');
  ensureEqual(qenc.containerIdAlg, 'SHA3-512(qenc-header-bytes)', 'qenc.containerIdAlg');

  ensureEqual(qencMetaJSON.fmt, qenc.format, 'qenc.format');
  ensureEqual(qencMetaJSON.aead_mode, qenc.aeadMode, 'qenc.aeadMode');
  ensureEqual(qencMetaJSON.iv_strategy, qenc.ivStrategy, 'qenc.ivStrategy');
  ensureEqual(Number(qencMetaJSON.chunkSize), Number(qenc.chunkSize), 'qenc.chunkSize');
  ensureEqual(Number(qencMetaJSON.chunkCount), Number(qenc.chunkCount), 'qenc.chunkCount');
  ensureEqual(Number(qencMetaJSON.payloadLength), Number(qenc.payloadLength), 'qenc.payloadLength');

  ensureEqual(qencMetaJSON.cryptoProfileId, manifest.cryptoProfileId, 'cryptoProfileId');
  ensureEqual(qencMetaJSON.kdfTreeId, manifest.kdfTreeId, 'kdfTreeId');
  ensureEqual(qencMetaJSON.noncePolicyId, manifest.noncePolicyId, 'noncePolicyId');
  ensureEqual(qencMetaJSON.nonceMode, manifest.nonceMode, 'nonceMode');
  ensureEqual(Number(qencMetaJSON.counterBits), Number(manifest.counterBits), 'counterBits');
  ensureEqual(Number(qencMetaJSON.maxChunkCount), Number(manifest.maxChunkCount), 'maxChunkCount');
  ensureEqual(qencMetaJSON.aadPolicyId, manifest.aadPolicyId, 'aadPolicyId');
}

export async function restoreFromShards(shards, options = {}) {
  const onLog = options.onLog || (() => {});
  const onWarn = options.onWarn || options.onError || (() => {});
  const strict = options.strict ?? true;
  const erasureRuntime = resolveErasureRuntime(options.erasureRuntime ?? options.erasure);

  if (!Array.isArray(shards) || shards.length === 0) {
    throw new Error('No shards provided');
  }

  const prepared = [];
  for (let i = 0; i < shards.length; i += 1) {
    const shard = shards[i];
    if (shard?.diagnostics?.errors?.length) {
      if (strict) {
        throw new Error(`Shard parse failed at input index ${i}: ${shard.diagnostics.errors.join('; ')}`);
      }
      continue;
    }
    prepared.push({
      ...shard,
      inputOrder: i,
      inputShardIndex: Number.isInteger(shard?.shardIndex) ? shard.shardIndex : i,
    });
  }
  if (prepared.length === 0) {
    throw new Error('No valid shards after parsing');
  }

  const verificationOptions = options.verification || {};
  const archiveContext = await resolveArchiveContext(prepared, verificationOptions);
  const candidate = archiveContext.candidate;
  const manifest = candidate.manifest;
  const bundle = candidate.bundle;
  const manifestDigestHex = candidate.manifestDigestHex;
  const bundleDigestHex = candidate.bundleDigestHex;
  const useManifestWideShardSelection = archiveContext.useManifestWideShardSelection === true;
  const selectedEmbeddedBundleDigestHex = candidate.embeddedBundleDigestHex || candidate.bundleDigestHex;

  const group = prepared.filter((shard) => (
    shard.manifestDigestHex === manifestDigestHex &&
    (useManifestWideShardSelection || shard.bundleDigestHex === selectedEmbeddedBundleDigestHex)
  ));
  const rejectedShardIndices = prepared
    .filter((shard) => (
      shard.manifestDigestHex !== manifestDigestHex ||
      (!useManifestWideShardSelection && shard.bundleDigestHex !== selectedEmbeddedBundleDigestHex)
    ))
    .map((shard) => shard.inputShardIndex);

  const n = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.n), 'manifest.sharding.reedSolomon.n', 2);
  const k = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.k), 'manifest.sharding.reedSolomon.k', 2);
  const m = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.parity), 'manifest.sharding.reedSolomon.parity', 0);
  const t = ensurePositiveInteger(Number(manifest?.sharding?.shamir?.threshold), 'manifest.sharding.shamir.threshold', 2);
  const shareCount = ensurePositiveInteger(Number(manifest?.sharding?.shamir?.shareCount), 'manifest.sharding.shamir.shareCount', 2);
  if (shareCount !== n) {
    throw new Error(`Invalid manifest sharding: Shamir shareCount ${shareCount} must equal RS n ${n}`);
  }
  if ((m % 2) !== 0) {
    throw new Error('Invalid manifest sharding: RS parity must be even');
  }
  if (k >= n) {
    throw new Error('Invalid manifest sharding: expected k < n');
  }

  const allowedFailures = m / 2;
  const expectedThreshold = k + allowedFailures;
  if (t !== expectedThreshold) {
    throw new Error(`Invalid manifest threshold: expected ${expectedThreshold}, got ${t}`);
  }

  const qenc = manifest.qenc || {};
  const chunkSize = ensurePositiveInteger(Number(qenc.chunkSize), 'manifest.qenc.chunkSize', 1);
  const chunkCount = ensurePositiveInteger(Number(qenc.chunkCount), 'manifest.qenc.chunkCount', 1);
  const payloadLength = ensurePositiveInteger(Number(qenc.payloadLength), 'manifest.qenc.payloadLength', 1);

  const containerId = String(qenc.containerId || '');
  if (containerId.length === 0) {
    throw new Error('Manifest is missing qenc.containerId');
  }

  const base = group[0];
  if (!(base.keyCommit instanceof Uint8Array) || base.keyCommit.length !== KEY_COMMITMENT_MAX_LEN) {
    throw new Error('Shard is missing required key commitment');
  }
  const shardByIndex = new Map();

  for (const shard of group) {
    if (!Number.isInteger(shard.shardIndex) || shard.shardIndex < 0 || shard.shardIndex >= n) {
      throw new Error(`Invalid shardIndex ${shard.shardIndex}`);
    }
    if (shardByIndex.has(shard.shardIndex)) {
      throw new Error(`Duplicate shardIndex ${shard.shardIndex} detected`);
    }
    shardByIndex.set(shard.shardIndex, shard);

    ensureEqual(shard.metaJSON?.containerId, containerId, 'containerId');
    ensureEqual(Number(shard.metaJSON?.n), n, 'n');
    ensureEqual(Number(shard.metaJSON?.k), k, 'k');
    ensureEqual(Number(shard.metaJSON?.m), m, 'm');
    ensureEqual(Number(shard.metaJSON?.t), t, 't');
    ensureEqual(normalizeHexString(shard.metaJSON?.manifestDigest), manifestDigestHex, 'manifestDigest');
    if (!useManifestWideShardSelection) {
      ensureEqual(normalizeHexString(shard.metaJSON?.bundleDigest), selectedEmbeddedBundleDigestHex, 'bundleDigest');
    }

    if (!bytesEqual(shard.encapsulatedKey, base.encapsulatedKey)) {
      throw new Error(`Shard header mismatch: encapsulatedKey differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.iv, base.iv)) {
      throw new Error(`Shard header mismatch: iv differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.salt, base.salt)) {
      throw new Error(`Shard header mismatch: salt differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.qencMetaBytes, base.qencMetaBytes)) {
      throw new Error(`Shard header mismatch: qenc metadata differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.keyCommit, base.keyCommit)) {
      throw new Error(`Shard header mismatch: key commitment differs for shard ${shard.shardIndex}`);
    }
  }

  const missingIndices = new Set();
  for (let i = 0; i < n; i += 1) {
    if (!shardByIndex.has(i)) missingIndices.add(i);
  }

  const qencMetaJSON = base.qencMetaJSON;
  validateContainerPolicyMetadata(qencMetaJSON, { allowLegacyWithoutProfile: false });
  assertManifestMatchesQencMetadata(manifest, qencMetaJSON);

  const ciphertextLength = ensurePositiveInteger(Number(base.metaJSON?.ciphertextLength), 'ciphertextLength', 1);
  for (const shard of group) {
    ensureEqual(Number(shard.metaJSON?.ciphertextLength), ciphertextLength, 'ciphertextLength');
    ensureEqual(Number(shard.metaJSON?.chunkCount), chunkCount, 'chunkCount');
    ensureEqual(Number(shard.metaJSON?.chunkSize), chunkSize, 'chunkSize');
  }

  const isPerChunkMode = qencMetaJSON.aead_mode === 'per-chunk-aead';
  if (!isPerChunkMode && qencMetaJSON.aead_mode !== 'single-container-aead') {
    throw new Error(`Unsupported AEAD mode: ${qencMetaJSON.aead_mode ?? 'unknown'}`);
  }

  const expectedCiphertextLength = isPerChunkMode
    ? (payloadLength + (16 * chunkCount))
    : ciphertextLength;
  if (isPerChunkMode && ciphertextLength !== expectedCiphertextLength) {
    throw new Error(`Ciphertext length mismatch for per-chunk mode (expected ${expectedCiphertextLength}, got ${ciphertextLength})`);
  }

  const encapHash = await hashBytes(base.encapsulatedKey);
  if (normalizeHexString(base.metaJSON?.encapBlobHash) !== normalizeHexString(encapHash)) {
    throw new Error('encapBlobHash mismatch');
  }
  if (group.length < t) {
    throw new Error(`Need at least ${t} matching shards for selected archive cohort, got ${group.length}`);
  }

  const shareCommitments = manifest?.shardBinding?.shareCommitments || base.metaJSON?.shareCommitments || null;
  const fragmentBodyHashes = manifest?.shardBinding?.shardBodyHashes || base.metaJSON?.fragmentBodyHashes || null;

  let validShareShards = group;
  if (Array.isArray(shareCommitments)) {
    if (shareCommitments.length !== n) {
      throw new Error('Invalid shareCommitments length');
    }
    validShareShards = [];
    const invalidShareIndices = new Set();
    for (const shard of group) {
      const expected = normalizeHexString(shareCommitments[shard.shardIndex]);
      const actual = normalizeHexString(await hashBytes(shard.share));
      if (!expected || actual !== expected) {
        onWarn(`Share commitment verification failed for shard ${shard.shardIndex}. Share will be skipped.`);
        invalidShareIndices.add(shard.shardIndex);
        continue;
      }
      validShareShards.push(shard);
    }
    if (validShareShards.length < t) {
      throw new Error(`Not enough valid shards for Shamir reconstruction: need ${t}, have ${validShareShards.length}`);
    }
    onLog(invalidShareIndices.size > 0 ? `Share commitment failures: ${invalidShareIndices.size} shard(s) rejected.` : 'Share commitments verified.');
  }

  const corruptedShardIndices = new Set();
  if (Array.isArray(fragmentBodyHashes)) {
    if (fragmentBodyHashes.length !== n) {
      throw new Error('Invalid shardBodyHashes length');
    }
    for (const shard of group) {
      const expected = normalizeHexString(fragmentBodyHashes[shard.shardIndex]);
      const actual = normalizeHexString(await hashBytes(shard.fragments));
      if (expected && actual !== expected) {
        onWarn(`Fragment integrity check failed for shard ${shard.shardIndex}. Treating as erasure.`);
        corruptedShardIndices.add(shard.shardIndex);
      }
    }
    if (corruptedShardIndices.size === 0) {
      onLog('Shard body hashes verified.');
    }
  }

  const totalBad = missingIndices.size + corruptedShardIndices.size;
  if (totalBad > allowedFailures) {
    throw new Error(`Too many missing/corrupted shards for RS reconstruction: allowed ${allowedFailures}, got ${totalBad}`);
  }

  const sortedShares = validShareShards.slice().sort((a, b) => a.shardIndex - b.shardIndex);
  const selectedShares = sortedShares.slice(0, t).map((item) => item.share);
  const { combineShares } = await import('../splitting/sss.js');
  const privKey = await combineShares(selectedShares);

  const rsEncodeBase = Number.isInteger(base.metaJSON?.rsEncodeBase) ? base.metaJSON.rsEncodeBase : 255;
  const cipherChunks = [];
  const shardOffsets = new Array(n).fill(0);

  for (let i = 0; i < chunkCount; i += 1) {
    const plainLen = Math.min(chunkSize, payloadLength - (i * chunkSize));
    const thisLen = isPerChunkMode ? (plainLen + 16) : ciphertextLength;

    const encodeSize = Math.floor(rsEncodeBase / n) * n;
    if (encodeSize === 0) throw new Error('RS parameters too large');
    const inputSize = (encodeSize * k) / n;
    const symbolSize = inputSize / k;
    const blocks = Math.ceil(thisLen / inputSize);
    const expectedFragLen = blocks * symbolSize;

    const encoded = new Array(n);
    for (let j = 0; j < n; j += 1) {
      const shard = shardByIndex.get(j);
      const fragStream = (shard && !corruptedShardIndices.has(j)) ? shard.fragments : null;
      if (!fragStream) {
        encoded[j] = new Uint8Array(expectedFragLen);
        continue;
      }

      const streamOffset = shardOffsets[j];
      if (streamOffset + 4 > fragStream.length) {
        throw new Error('Fragment stream underflow');
      }

      const dvFrag = new DataView(fragStream.buffer, fragStream.byteOffset + streamOffset);
      const fragLen = dvFrag.getUint32(0, false);
      const fragStart = streamOffset + 4;
      const fragEnd = fragStart + fragLen;
      if (fragEnd > fragStream.length) {
        throw new Error('Fragment length overflow');
      }

      let fragment = fragStream.subarray(fragStart, fragEnd);
      if (fragment.length < expectedFragLen) {
        const padded = new Uint8Array(expectedFragLen);
        padded.set(fragment);
        fragment = padded;
      } else if (fragment.length > expectedFragLen) {
        fragment = fragment.subarray(0, expectedFragLen);
      }

      encoded[j] = fragment;
      shardOffsets[j] = fragEnd;
    }

    let recombined;
    try {
      recombined = erasureRuntime.recombine(encoded, thisLen, k, m / 2, rsEncodeBase);
    } catch (error) {
      throw new Error(`RS recombination failed on chunk ${i}: ${error?.message ?? error}`);
    }

    cipherChunks.push(recombined);
    if (!isPerChunkMode) break;
  }

  for (let j = 0; j < n; j += 1) {
    if (corruptedShardIndices.has(j)) continue;
    const shard = shardByIndex.get(j);
    if (!shard) continue;
    if (shardOffsets[j] !== shard.fragments.length) {
      throw new Error(`Fragment stream has trailing or missing data in shard ${j}`);
    }
  }

  const ciphertext = isPerChunkMode
    ? (() => {
        const total = cipherChunks.reduce((sum, item) => sum + item.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const chunk of cipherChunks) {
          out.set(chunk, offset);
          offset += chunk.length;
        }
        return out;
      })()
    : cipherChunks[0];

  if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== ciphertextLength) {
    throw new Error('Reconstructed ciphertext length mismatch');
  }

  const header = buildQencHeader({
    encapsulatedKey: base.encapsulatedKey,
    containerNonce: base.iv,
    kdfSalt: base.salt,
    metaBytes: base.qencMetaBytes,
    keyCommitment: base.keyCommit,
  });

  const qencBytes = new Uint8Array(header.length + ciphertext.length);
  qencBytes.set(header, 0);
  qencBytes.set(ciphertext, header.length);

  const recoveredQencHash = normalizeHexString(await hashBytes(qencBytes));
  const expectedQencHash = normalizeHexString(qenc.qencHash);
  if (recoveredQencHash !== expectedQencHash) {
    throw new Error('Reconstructed .qenc hash does not match archive manifest');
  }

  const recoveredPrivHash = normalizeHexString(await hashBytes(privKey));
  const privateKeyHash = normalizeHexString(base.metaJSON?.privateKeyHash || '');
  const qkeyOk = privateKeyHash ? (privateKeyHash === recoveredPrivHash) : true;
  if (!qkeyOk) {
    onWarn('Recovered secret key hash does not match shard metadata.');
  }

  return {
    qencBytes,
    privKey,
    containerId,
    containerHash: expectedQencHash,
    privateKeyHash: privateKeyHash || null,
    recoveredQencHash,
    recoveredPrivHash,
    rejectedShardIndices,
    qencOk: true,
    qkeyOk,
    manifest,
    manifestBytes: candidate.manifestBytes,
    manifestDigestHex,
    bundle,
    bundleBytes: candidate.bundleBytes,
    bundleDigestHex,
    manifestSource: archiveContext.source,
    authenticity: {
      policy: archiveContext.authenticity.policy,
      verification: archiveContext.authenticity.verification,
      warnings: archiveContext.authenticity.warnings,
      status: {
        integrityVerified: true,
        signatureVerified: archiveContext.authenticity.verification.status.signatureVerified,
        strongPqSignatureVerified: archiveContext.authenticity.verification.status.strongPqSignatureVerified,
        signerPinned: archiveContext.authenticity.verification.status.signerPinned,
        signerIdentityPinned: archiveContext.authenticity.verification.status.signerIdentityPinned,
        bundlePinned: archiveContext.authenticity.verification.status.bundlePinned,
        userPinned: archiveContext.authenticity.verification.status.userPinned,
        userPinProvided: archiveContext.authenticity.verification.status.userPinProvided,
        policySatisfied: archiveContext.authenticity.policy.satisfied,
        archivePolicySatisfied: archiveContext.authenticity.policy.satisfied,
      },
      timestampEvidence: archiveContext.authenticity.timestampEvidence,
    },
  };
}
