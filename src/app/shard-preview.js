// UI-layer shard preview helpers.
// Parse only the header portion of a .qcont shard file without touching decrypt logic.

import {
  classifyArtifactBytes,
  classifyArtifactPreviewBytes,
} from '../core/crypto/artifact-classification.js';
import {
  isLifecycleShardPrefixRequirement,
  parseLifecycleShardPreviewPrefix,
} from '../core/crypto/qcont/lifecycle-shard.js';

const MAX_ATTACHMENT_PREVIEW_CLASSIFY_BYTES = 256 * 1024;

async function readFilePrefixBytes(file, maxBytes) {
  const size = Number.isFinite(file?.size) && file.size >= 0 ? file.size : null;
  const end = size == null ? maxBytes : Math.min(size, maxBytes);
  if (typeof file?.slice === 'function') {
    return new Uint8Array(await file.slice(0, end).arrayBuffer());
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  return bytes.length > maxBytes ? bytes.subarray(0, maxBytes) : bytes;
}

function isSmallEnoughForFullPreviewClassification(file) {
  return Number.isFinite(file?.size) && file.size >= 0 && file.size <= MAX_ATTACHMENT_PREVIEW_CLASSIFY_BYTES;
}

export async function parseQcontShardPreviewFile(file) {
  if (!Number.isSafeInteger(file?.size) || file.size <= 0 || typeof file?.slice !== 'function') {
    throw new Error('Shard preview requires a non-empty sliceable file');
  }

  let bytesToRead = Math.min(file.size, 16 * 1024);
  let parsed = null;
  while (!parsed) {
    const bytes = new Uint8Array(await file.slice(0, bytesToRead).arrayBuffer());
    try {
      parsed = await parseLifecycleShardPreviewPrefix(bytes);
    } catch (error) {
      if (!isLifecycleShardPrefixRequirement(error)) throw error;
      if (error.requiredBytes > file.size || error.requiredBytes <= bytes.length) {
        throw new Error('Shard header is truncated');
      }
      bytesToRead = Math.min(file.size, Math.max(error.requiredBytes, bytes.length * 2));
    }
  }

  return {
    sourceFileName: String(file?.name || ''),
    containerId: parsed.metaJSON.containerId,
    archiveId: parsed.metaJSON.archiveId,
    stateId: parsed.stateId,
    cohortId: parsed.cohortId,
    lifecycleBundleDigestHex: parsed.lifecycleBundleDigestHex,
    n: parsed.metaJSON.n,
    t: parsed.metaJSON.t,
    shardIndex: parsed.shardIndex,
    authPolicyLevel: parsed.lifecycleBundle.authPolicy.level,
    hasEmbeddedBundle: true,
  };
}

async function classifyNonShardFile(file) {
  try {
    const name = String(file?.name || 'unnamed');
    const useFullClassification = isSmallEnoughForFullPreviewClassification(file);
    const bytes = useFullClassification
      ? new Uint8Array(await file.arrayBuffer())
      : await readFilePrefixBytes(file, MAX_ATTACHMENT_PREVIEW_CLASSIFY_BYTES);
    const classification = useFullClassification
      ? await classifyArtifactBytes(bytes, { name })
      : classifyArtifactPreviewBytes(bytes, { name });
    if (classification.kind === 'signature') return 'signature';
    if (classification.kind === 'pqpk') return 'pubkey';
    if (classification.kind === 'ots-proof') return 'timestamp';
  } catch {
    return 'other';
  }
  return 'other';
}

export async function assessShardSelection(files) {
  if (!files.length) {
    return { state: 'empty', ready: false };
  }

  const parsed = [];
  let parseErrors = 0;
  const attachments = { signature: 0, pubkey: 0, timestamp: 0, other: 0 };
  for (const file of files) {
    const lowerName = String(file?.name || '').toLowerCase();
    const explicitShardName = lowerName.endsWith('.qcont');
    try {
      parsed.push(await parseQcontShardPreviewFile(file));
    } catch {
      if (explicitShardName) {
        parseErrors += 1;
      } else {
        attachments[await classifyNonShardFile(file)]++;
      }
    }
  }

  if (!parsed.length) {
    return {
      state: 'unknown',
      ready: false,
      message: 'No valid .qcont shard files detected in the selected input.',
    };
  }

  const containerIds = new Set(parsed.map((item) => item.containerId));
  if (containerIds.size !== 1) {
    return {
      state: 'invalid',
      ready: false,
      message: 'Selected shards belong to different containers.',
    };
  }

  const policies = new Set(parsed.map((item) => item.authPolicyLevel));
  if (policies.size !== 1) {
    return {
      state: 'invalid',
      ready: false,
      message: 'Selected shards disagree on archive authenticity policy.',
    };
  }

  const base = parsed[0];
  const uniqueIndices = new Set(parsed.map((item) => item.shardIndex));
  const uniqueCount = uniqueIndices.size;
  const duplicateCount = parsed.length - uniqueCount;
  const ready = uniqueCount >= base.t;

  let message = ready
    ? `Ready: ${uniqueCount}/${base.n} unique shards selected (need >=${base.t}).`
    : `Insufficient: ${uniqueCount}/${base.n} unique shards selected (need >=${base.t}).`;
  message += ` Policy: ${base.authPolicyLevel}.`;

  const states = new Map();
  for (const item of parsed) {
    const stateKey = `${item.archiveId}:${item.stateId}`;
    if (!states.has(stateKey)) {
      states.set(stateKey, {
        cohortIds: new Set(),
        bundleDigestsByCohort: new Map(),
      });
    }
    const entry = states.get(stateKey);
    entry.cohortIds.add(item.cohortId);
    if (!entry.bundleDigestsByCohort.has(item.cohortId)) {
      entry.bundleDigestsByCohort.set(item.cohortId, new Set());
    }
    entry.bundleDigestsByCohort.get(item.cohortId).add(item.lifecycleBundleDigestHex);
  }
  if (states.size > 1) {
    message += ' Explicit archive/state selection is still required below.';
  } else {
    const [onlyState] = [...states.values()];
    if (onlyState?.cohortIds.size > 1) {
      message += ' Explicit same-state cohort selection is still required below.';
    } else {
      const [onlyCohortDigests] = [...(onlyState?.bundleDigestsByCohort?.values() || [])];
      if (onlyCohortDigests && onlyCohortDigests.size > 1) {
        message += ' Explicit lifecycle-bundle selection is still required below.';
      }
    }
  }

  if (duplicateCount > 0) {
    message += ` ${duplicateCount} duplicate shard(s) skipped.`;
  }
  if (parseErrors > 0) {
    message += ` ${parseErrors} unreadable shard file(s).`;
  }

  const verificationParts = [];
  if (attachments.signature > 0) verificationParts.push(`${attachments.signature} signature(s)`);
  if (attachments.pubkey > 0) verificationParts.push(`${attachments.pubkey} public key(s)`);
  if (attachments.timestamp > 0) verificationParts.push(`${attachments.timestamp} timestamp(s)`);
  if (verificationParts.length > 0) {
    message += ` Attachments: ${verificationParts.join(', ')}.`;
  }
  if (attachments.other > 0) {
    message += ` ${attachments.other} unrecognized file(s) skipped.`;
  }

  return {
    state: ready ? 'sufficient' : 'insufficient',
    ready,
    message,
    threshold: base.t,
    preflightDigests: parsed.map((item) => ({
      sourceFileName: item.sourceFileName,
      artifactType: 'QVqcont-7 successor shard',
      policy: item.authPolicyLevel,
      archiveId: item.archiveId,
      stateId: item.stateId,
      cohortId: item.cohortId,
      lifecycleBundleDigestHex: item.lifecycleBundleDigestHex,
      n: item.n,
      t: item.t,
      shardIndex: item.shardIndex,
    })),
  };
}
