import { assessRestoreFromShards } from '../../crypto/qcont/restore.js';
import { parseLifecycleShard } from '../../crypto/qcont/lifecycle-shard.js';
import { takeValue } from '../lib/args.js';
import { dedupeSorted, expandFilePattern } from '../lib/glob.js';
import { readBytesFromFile } from '../lib/io.js';
import { ensureErasureRuntime, ensureRuntimeCrypto } from '../lib/runtime.js';
import { readVerificationInputsFromPaths } from './verify.js';

export function parseRestoreArgs(args) {
  const options = {
    shardPatterns: [],
    archiveStatePath: null,
    bundlePath: null,
    signaturePaths: [],
    pqpkPaths: [],
    otsPaths: [],
    expectedEd25519Signer: '',
    selectedArchiveId: '',
    selectedStateId: '',
    selectedCohortId: '',
    selectedLifecycleBundleDigestHex: '',
    dryRun: false,
    json: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--shards':
        options.shardPatterns.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--archive-state':
        options.archiveStatePath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--bundle':
        options.bundlePath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--sig':
        options.signaturePaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--pqpk':
        options.pqpkPaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--ots':
        options.otsPaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--ed25519-signer':
        options.expectedEd25519Signer = takeValue(args, index, arg);
        index += 1;
        break;
      case '--archive-id':
        options.selectedArchiveId = takeValue(args, index, arg);
        index += 1;
        break;
      case '--state-id':
        options.selectedStateId = takeValue(args, index, arg);
        index += 1;
        break;
      case '--cohort-id':
        options.selectedCohortId = takeValue(args, index, arg);
        index += 1;
        break;
      case '--bundle-digest':
        options.selectedLifecycleBundleDigestHex = takeValue(args, index, arg);
        index += 1;
        break;
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw new Error(`Unknown restore option: ${arg}`);
    }
  }

  if (!options.dryRun) {
    throw new Error('restore is read-only in Phase 1; pass --dry-run');
  }
  if (options.shardPatterns.length === 0) {
    throw new Error('restore --dry-run requires at least one --shards pattern or path');
  }
  return options;
}

export function buildRestoreDryRunSummary(result) {
  return {
    command: 'restore',
    dryRun: true,
    wouldSucceed: (
      result?.qencOk === true &&
      result?.qkeyOk === true &&
      result?.authenticity?.status?.policySatisfied === true
    ),
    archiveId: result.archiveId,
    stateId: result.stateId,
    cohortId: result.cohortId,
    archiveStateDigestHex: result.archiveStateDigestHex,
    cohortBindingDigestHex: result.cohortBindingDigestHex,
    lifecycleBundleDigestHex: result.lifecycleBundleDigestHex,
    selectionSource: result.selectionSource,
    lifecycleBundleSource: result.lifecycleBundleSource,
    embeddedLifecycleBundleDigestsUsed: Array.isArray(result.embeddedLifecycleBundleDigestsUsed)
      ? [...result.embeddedLifecycleBundleDigestsUsed]
      : [],
    qencOk: result.qencOk === true,
    qkeyOk: result.qkeyOk === true,
    privateKeyHashMatchesMetadata: result.privateKeyHashMatchesMetadata === true,
    rejectedShardIndices: Array.isArray(result.rejectedShardIndices) ? [...result.rejectedShardIndices] : [],
    lifecycleVerification: result.lifecycleVerification,
    authenticity: result.authenticity,
  };
}

async function zeroizeRestoreMaterial(result) {
  if (result?.qencBytes instanceof Uint8Array) {
    result.qencBytes.fill(0);
  }
  if (result?.privKey instanceof Uint8Array) {
    result.privKey.fill(0);
  }
}

export async function restoreDryRunFromInputs({
  parsedShards,
  verification = {},
} = {}) {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  let result = null;
  try {
    result = await assessRestoreFromShards(parsedShards, { verification });
    return buildRestoreDryRunSummary(result);
  } finally {
    await zeroizeRestoreMaterial(result);
  }
}

export async function runRestoreDryRunCommand(options, { cwd = process.cwd() } = {}) {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  const shardPaths = [];
  for (const pattern of options.shardPatterns) {
    shardPaths.push(...await expandFilePattern(pattern, cwd));
  }
  const resolvedShardPaths = dedupeSorted(shardPaths);
  if (resolvedShardPaths.length === 0) {
    throw new Error('restore --dry-run matched no shard files');
  }

  const parsedShards = await Promise.all(resolvedShardPaths.map(async (filePath) => {
    const bytes = await readBytesFromFile(filePath);
    try {
      return await parseLifecycleShard(bytes, { strict: true });
    } catch (error) {
      throw new Error(`Shard ${filePath} is not a supported successor shard: ${error?.message || error}`);
    }
  }));

  const inputs = await readVerificationInputsFromPaths({
    archiveStatePath: options.archiveStatePath,
    bundlePath: options.bundlePath,
    signaturePaths: options.signaturePaths,
    pqpkPaths: options.pqpkPaths,
    otsPaths: options.otsPaths,
    expectedEd25519Signer: options.expectedEd25519Signer,
  });

  return restoreDryRunFromInputs({
    parsedShards,
    verification: {
      ...inputs.verification,
      archiveStateBytes: inputs.archiveStateBytes,
      lifecycleBundleBytes: inputs.lifecycleBundleBytes,
      selectedArchiveId: options.selectedArchiveId,
      selectedStateId: options.selectedStateId,
      selectedCohortId: options.selectedCohortId,
      selectedLifecycleBundleDigestHex: options.selectedLifecycleBundleDigestHex,
    },
  });
}

export function renderRestoreSummary(summary) {
  const lines = [
    `Restore dry-run: ${summary.wouldSucceed ? 'would succeed' : 'would fail'}`,
    `ArchiveId: ${summary.archiveId}`,
    `StateId: ${summary.stateId}`,
    `CohortId: ${summary.cohortId}`,
    `Lifecycle bundle digest: ${summary.lifecycleBundleDigestHex}`,
    `Selection source: ${summary.selectionSource || 'embedded'}`,
    `Policy: ${summary.authenticity?.policy?.level || 'unknown'} (${summary.authenticity?.policy?.satisfied ? 'satisfied' : 'not satisfied'})`,
    `qencOk=${summary.qencOk} qkeyOk=${summary.qkeyOk}`,
  ];
  for (const warning of summary?.authenticity?.warnings || []) {
    lines.push(`Warning: ${warning}`);
  }
  return `${lines.join('\n')}\n`;
}
