import { mergeLifecycleShardIntoCohortGroups } from './lifecycle-cohort-shared.js';

function uniqueStrings(values) {
  return [...new Set(
    values
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));
}

export function collectLifecycleAttachmentCounts(lifecycleBundles = []) {
  const archiveApprovalIds = new Set();
  const publicKeyIds = new Set();
  for (const bundle of lifecycleBundles) {
    const attachments = bundle?.attachments || {};
    for (const signature of attachments.archiveApprovalSignatures || []) {
      archiveApprovalIds.add(String(signature?.id || signature?.signature || archiveApprovalIds.size));
    }
    for (const publicKey of attachments.publicKeys || []) {
      publicKeyIds.add(String(publicKey?.id || publicKey?.value || publicKeyIds.size));
    }
  }
  return {
    archiveApprovalSignatureCount: archiveApprovalIds.size,
    publicKeyCount: publicKeyIds.size,
  };
}

function buildStateSelectionKey(archiveId, stateId) {
  return `${archiveId}:${stateId}`;
}

/** Build the DOM-free fail-closed selection model shared by core tests and UI. */
export function buildSuccessorSelectionModel(parsedShards = []) {
  const byIdentity = new Map();
  for (const shard of parsedShards) {
    mergeLifecycleShardIntoCohortGroups(byIdentity, shard, {
      groupLabel: 'restore candidate set',
      missingIdentityMessage: 'Successor shard is missing archive/state/cohort identity',
    });
  }

  const statesByKey = new Map();
  for (const candidate of byIdentity.values()) {
    const key = buildStateSelectionKey(candidate.archiveId, candidate.stateId);
    if (!statesByKey.has(key)) {
      statesByKey.set(key, {
        key,
        archiveId: candidate.archiveId,
        stateId: candidate.stateId,
        cohorts: [],
      });
    }
    const firstShard = candidate.shards[0];
    const sourceFileNames = uniqueStrings(candidate.shards.map((shard) => shard.sourceFileName));
    const policyLevels = uniqueStrings(candidate.shards.map((shard) => shard.lifecycleBundle?.authPolicy?.level));
    const attachmentCounts = collectLifecycleAttachmentCounts(candidate.shards.map((shard) => shard.lifecycleBundle));
    const bundleSourceFileNamesByDigest = {};
    for (const digestHex of candidate.embeddedLifecycleBundles.keys()) {
      bundleSourceFileNamesByDigest[digestHex] = uniqueStrings(
        candidate.shards
          .filter((shard) => shard.lifecycleBundleDigestHex === digestHex)
          .map((shard) => shard.sourceFileName)
      );
    }
    statesByKey.get(key).cohorts.push({
      archiveId: candidate.archiveId,
      stateId: candidate.stateId,
      cohortId: candidate.cohortId,
      bundleDigests: [...candidate.embeddedLifecycleBundles.keys()].sort(),
      bundleSourceFileNamesByDigest,
      sourceFileNames,
      policyLevels,
      archiveApprovalSignatureCount: attachmentCounts.archiveApprovalSignatureCount,
      publicKeyCount: attachmentCounts.publicKeyCount,
      shardCount: candidate.shards.length,
      n: Number(firstShard?.metaJSON?.n || 0),
      t: Number(firstShard?.metaJSON?.t || 0),
    });
  }

  const states = [...statesByKey.values()]
    .map((state) => ({
      ...state,
      cohorts: state.cohorts.sort((a, b) => a.cohortId.localeCompare(b.cohortId)),
    }))
    .sort((a, b) => a.key.localeCompare(b.key));

  return {
    states,
    hasAmbiguity: states.length > 1 || states.some((state) => (
      state.cohorts.length > 1 || state.cohorts.some((cohort) => cohort.bundleDigests.length > 1)
    )),
  };
}
