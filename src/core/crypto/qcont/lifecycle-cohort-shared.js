import { bytesEqual } from '../bytes.js';

export function normalizeHexString(value) {
  return String(value || '').trim().toLowerCase();
}

/**
 * Insert one parsed successor lifecycle shard into a map of cohort groups keyed by
 * `${archiveId}:${stateId}:${cohortId}`. Used by restore (candidate cohorts) and
 * same-state resharing (predecessor cohort) with identical consistency checks.
 *
 * @param {Map<string, object>} byIdentity Cohort accumulator
 * @param {object} shard Parsed lifecycle shard
 * @param {{ groupLabel: string, missingIdentityMessage: string }} options
 */
export function mergeLifecycleShardIntoCohortGroups(byIdentity, shard, options) {
  const { groupLabel, missingIdentityMessage } = options;
  const archiveId = normalizeHexString(shard?.archiveState?.archiveId || shard?.metaJSON?.archiveId);
  const stateId = normalizeHexString(shard?.stateId || shard?.metaJSON?.stateId);
  const cohortId = normalizeHexString(shard?.cohortId || shard?.metaJSON?.cohortId);
  if (!archiveId || !stateId || !cohortId) {
    throw new Error(missingIdentityMessage);
  }
  const key = `${archiveId}:${stateId}:${cohortId}`;
  if (!byIdentity.has(key)) {
    byIdentity.set(key, {
      key,
      archiveId,
      stateId,
      cohortId,
      archiveStateBytes: shard.archiveStateBytes,
      archiveStateDigestHex: normalizeHexString(shard.archiveStateDigestHex),
      archiveState: shard.archiveState,
      cohortBindingBytes: shard.cohortBindingBytes,
      cohortBindingDigestHex: normalizeHexString(shard.cohortBindingDigestHex),
      cohortBinding: shard.cohortBinding,
      embeddedLifecycleBundles: new Map(),
      shards: [],
    });
  }
  const entry = byIdentity.get(key);
  if (!bytesEqual(entry.archiveStateBytes, shard.archiveStateBytes)) {
    throw new Error(`Exact archive-state byte mismatch inside ${groupLabel} ${key}`);
  }
  if (!bytesEqual(entry.cohortBindingBytes, shard.cohortBindingBytes)) {
    throw new Error(`Exact cohort-binding byte mismatch inside ${groupLabel} ${key}`);
  }
  if (entry.archiveStateDigestHex !== normalizeHexString(shard.archiveStateDigestHex)) {
    throw new Error(`archive-state digest mismatch inside ${groupLabel} ${key}`);
  }
  if (entry.cohortBindingDigestHex !== normalizeHexString(shard.cohortBindingDigestHex)) {
    throw new Error(`cohort-binding digest mismatch inside ${groupLabel} ${key}`);
  }
  if (archiveId !== normalizeHexString(shard?.metaJSON?.archiveId || shard?.archiveState?.archiveId)) {
    throw new Error(`Mixed archiveId values detected inside ${groupLabel} ${key}`);
  }
  if (stateId !== normalizeHexString(shard?.metaJSON?.stateId || shard?.stateId)) {
    throw new Error(`Mixed stateId values detected inside ${groupLabel} ${key}`);
  }
  if (cohortId !== normalizeHexString(shard?.metaJSON?.cohortId || shard?.cohortId)) {
    throw new Error(`Mixed cohortId values detected inside ${groupLabel} ${key}`);
  }

  const lifecycleBundleDigestHex = normalizeHexString(shard.lifecycleBundleDigestHex);
  if (!entry.embeddedLifecycleBundles.has(lifecycleBundleDigestHex)) {
    entry.embeddedLifecycleBundles.set(lifecycleBundleDigestHex, {
      digestHex: lifecycleBundleDigestHex,
      bytes: shard.lifecycleBundleBytes,
      bundle: shard.lifecycleBundle,
    });
  }
  const bundleEntry = entry.embeddedLifecycleBundles.get(lifecycleBundleDigestHex);
  if (!bytesEqual(bundleEntry.bytes, shard.lifecycleBundleBytes)) {
    throw new Error(`Lifecycle-bundle bytes mismatch inside ${groupLabel} ${key} for digest ${lifecycleBundleDigestHex}`);
  }
  entry.shards.push(shard);
}
