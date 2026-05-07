import { mkdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { decryptFile } from '../../crypto/index.js';
import { toHex } from '../../crypto/bytes.js';
import {
  assessRestoreFromShards,
  restoreFromShards,
} from '../../crypto/qcont/restore.js';
import { parseLifecycleShard } from '../../crypto/qcont/lifecycle-shard.js';
import { takeValue } from '../lib/args.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';
import { dedupeSorted, expandFilePattern } from '../lib/glob.js';
import { readBytesFromFile, writeBytesAtomic } from '../lib/io.js';
import { ensureErasureRuntime, ensureRuntimeCrypto } from '../lib/runtime.js';
import { readVerificationInputsFromPaths } from './verify.js';

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

function quorumRejected(message, cause) {
  return makeQvError(message, QV_CODE.QUORUM_UNREACHABLE, { cause });
}

function ambiguity(message, cause) {
  return makeQvError(message, QV_CODE.AMBIGUOUS_INPUTS, { cause });
}

function restoredIntegrityFailed(message, cause) {
  return makeQvError(message, QV_CODE.RESTORED_INTEGRITY_FAILED, { cause });
}

function policyNotSatisfied(message, cause) {
  return makeQvError(message, QV_CODE.POLICY_NOT_SATISFIED, { cause });
}

function digestSha3_512Hex(bytes) {
  return toHex(sha3_512(bytes));
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

async function pathExists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function ensureOutputDirectory(outDir) {
  const resolved = path.resolve(outDir);
  try {
    const stats = await stat(resolved);
    if (!stats.isDirectory()) {
      throw usage(`--out must be a directory: ${resolved}`);
    }
    return resolved;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  const parent = path.dirname(resolved);
  try {
    const parentStats = await stat(parent);
    if (!parentStats.isDirectory()) {
      throw usage(`--out parent is not a directory: ${parent}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`--out parent directory does not exist: ${parent}`);
    }
    throw error;
  }
  await mkdir(resolved);
  return resolved;
}

async function ensureOutputParentExists(filePath, label) {
  const parent = path.dirname(path.resolve(filePath));
  try {
    const stats = await stat(parent);
    if (!stats.isDirectory()) {
      throw usage(`${label} parent is not a directory: ${parent}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`${label} parent directory does not exist: ${parent}`);
    }
    throw error;
  }
}

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
    outDir: 'restored',
    outQencPath: '',
    outKeyPath: '',
    decrypt: false,
    outPlaintextPath: '',
    dryRun: false,
    acceptPolicyWarnings: false,
    force: false,
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
      case '--out':
        options.outDir = takeValue(args, index, arg);
        index += 1;
        break;
      case '--out-qenc':
        options.outQencPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--out-key':
        options.outKeyPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--decrypt':
        options.decrypt = true;
        break;
      case '--out-plaintext':
        options.outPlaintextPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--accept-policy-warnings':
        options.acceptPolicyWarnings = true;
        break;
      case '--force':
        options.force = true;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw usage(`Unknown restore option: ${arg}`);
    }
  }

  if (options.shardPatterns.length === 0) {
    throw usage(options.dryRun
      ? 'restore --dry-run requires at least one --shards pattern or path'
      : 'restore requires at least one --shards pattern or path');
  }
  if (options.outPlaintextPath && !options.decrypt) {
    throw usage('restore --out-plaintext requires --decrypt');
  }
  for (const [label, value] of [
    ['--out', options.outDir],
    ['--out-qenc', options.outQencPath],
    ['--out-key', options.outKeyPath],
    ['--out-plaintext', options.outPlaintextPath],
  ]) {
    if (value && value.includes('\0')) {
      throw usage(`restore ${label} path contains an invalid NUL byte`);
    }
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
    outputs: null,
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

async function readParsedShards(options, cwd) {
  const shardPaths = [];
  for (const pattern of options.shardPatterns) {
    shardPaths.push(...await expandFilePattern(pattern, cwd));
  }
  const resolvedShardPaths = dedupeSorted(shardPaths);
  if (resolvedShardPaths.length === 0) {
    throw usage(options.dryRun
      ? 'restore --dry-run matched no shard files'
      : 'restore matched no shard files');
  }

  const parsedShards = await Promise.all(resolvedShardPaths.map(async (filePath) => {
    const bytes = await readBytesFromFile(filePath);
    try {
      return await parseLifecycleShard(bytes, { strict: true });
    } catch (error) {
      throw usage(`Shard ${filePath} is not a supported successor shard: ${error?.message || error}`);
    }
  }));
  return { shardPaths: resolvedShardPaths, parsedShards };
}

async function readRestoreVerification(options) {
  const inputs = await readVerificationInputsFromPaths({
    archiveStatePath: options.archiveStatePath,
    bundlePath: options.bundlePath,
    signaturePaths: options.signaturePaths,
    pqpkPaths: options.pqpkPaths,
    otsPaths: options.otsPaths,
    expectedEd25519Signer: options.expectedEd25519Signer,
  });

  return {
    ...inputs.verification,
    archiveStateBytes: inputs.archiveStateBytes,
    lifecycleBundleBytes: inputs.lifecycleBundleBytes,
    selectedArchiveId: options.selectedArchiveId,
    selectedStateId: options.selectedStateId,
    selectedCohortId: options.selectedCohortId,
    selectedLifecycleBundleDigestHex: options.selectedLifecycleBundleDigestHex,
  };
}

function classifyRestoreError(error) {
  if (typeof error?.qvCode === 'string') return error;
  const message = error?.message || String(error);
  if (error?.authenticity?.policy?.satisfied === false) {
    return policyNotSatisfied(message, error);
  }
  if (/Need at least|Not enough valid shards|Too many missing\/corrupted|Shamir|RS|erasure|quorum/i.test(message)) {
    return quorumRejected(message, error);
  }
  if (/multiple|fork|ambiguous|exactly one|Selected .* not present|bundle digest/i.test(message)) {
    return ambiguity(message, error);
  }
  if (/authenticity policy|policy is not satisfied|policy not satisfied|No archive authenticity policy/i.test(message)) {
    return policyNotSatisfied(message, error);
  }
  if (/qkeyOk|qencOk|hash does not match|private key hash|key commitment/i.test(message)) {
    return restoredIntegrityFailed(message, error);
  }
  return error;
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

  const { parsedShards } = await readParsedShards(options, cwd);
  try {
    const verification = await readRestoreVerification(options);
    return await restoreDryRunFromInputs({ parsedShards, verification });
  } finally {
    for (const shard of parsedShards) {
      shard.share?.fill?.(0);
    }
  }
}

function buildOutputPlan(options, cwd) {
  const outDir = path.resolve(cwd, options.outDir);
  return {
    outDir,
    qencPath: path.resolve(cwd, options.outQencPath || path.join(outDir, 'recovered.qenc')),
    keyPath: path.resolve(cwd, options.outKeyPath || path.join(outDir, 'recovered.privateKey.qkey')),
    archiveStatePath: path.join(outDir, 'recovered-archive-state.json'),
    lifecycleBundlePath: path.join(outDir, 'recovered-lifecycle-bundle.json'),
    plaintextPath: options.decrypt
      ? path.resolve(cwd, options.outPlaintextPath || path.join(outDir, 'recovered.plaintext'))
      : null,
  };
}

async function preflightOutputPlan(plan, force) {
  const outputPaths = [
    plan.qencPath,
    plan.keyPath,
    plan.archiveStatePath,
    plan.lifecycleBundlePath,
    ...(plan.plaintextPath ? [plan.plaintextPath] : []),
  ];
  const unique = new Set(outputPaths);
  if (unique.size !== outputPaths.length) {
    throw usage('restore output paths must be distinct');
  }
  await ensureOutputParentExists(plan.qencPath, '--out-qenc');
  await ensureOutputParentExists(plan.keyPath, '--out-key');
  await ensureOutputParentExists(plan.archiveStatePath, 'archive-state output');
  await ensureOutputParentExists(plan.lifecycleBundlePath, 'lifecycle-bundle output');
  if (plan.plaintextPath) {
    await ensureOutputParentExists(plan.plaintextPath, '--out-plaintext');
  }
  if (!force) {
    for (const filePath of outputPaths) {
      if (await pathExists(filePath)) {
        throw usage(`Refusing to overwrite existing file: ${filePath}`);
      }
    }
  }
}

function assertRestoredIntegrity(result) {
  if (result?.qencOk !== true) {
    throw restoredIntegrityFailed('Restored .qenc integrity check failed');
  }
  if (result?.qkeyOk !== true) {
    throw restoredIntegrityFailed('Restored private key integrity check failed');
  }
}

async function decryptRestoredPlaintext(result) {
  const { decryptedBlob, metadata } = await decryptFile(result.qencBytes, result.privKey);
  const plaintextBytes = await blobToBytes(decryptedBlob);
  const fileHashHex = digestSha3_512Hex(plaintextBytes);
  if (typeof metadata.fileHash === 'string' && metadata.fileHash !== fileHashHex) {
    throw restoredIntegrityFailed('Restored plaintext hash does not match authenticated private metadata');
  }
  return { plaintextBytes, metadata, fileHashHex };
}

function buildRestoreWriteSummary({ result, plan, plaintextReport = null }) {
  return {
    ...buildRestoreDryRunSummary(result),
    dryRun: false,
    wouldSucceed: true,
    outputs: {
      qencPath: plan.qencPath,
      keyPath: plan.keyPath,
      archiveStatePath: plan.archiveStatePath,
      lifecycleBundlePath: plan.lifecycleBundlePath,
      plaintextPath: plan.plaintextPath,
    },
    plaintext: plaintextReport,
  };
}

export async function runRestoreCommand(options, { cwd = process.cwd() } = {}) {
  if (options.dryRun) {
    return runRestoreDryRunCommand(options, { cwd });
  }

  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  const { parsedShards } = await readParsedShards(options, cwd);
  let result = null;
  let plaintextBytes = null;
  try {
    const verification = await readRestoreVerification(options);
    result = await restoreFromShards(parsedShards, { verification });
    assertRestoredIntegrity(result);

    const outDir = await ensureOutputDirectory(path.resolve(cwd, options.outDir));
    const plan = buildOutputPlan({ ...options, outDir }, cwd);
    await preflightOutputPlan(plan, options.force);

    let plaintextReport = null;
    if (options.decrypt) {
      const decrypted = await decryptRestoredPlaintext(result);
      plaintextBytes = decrypted.plaintextBytes;
      plaintextReport = {
        outputPath: plan.plaintextPath,
        plaintextLength: plaintextBytes.length,
        fileHashHex: decrypted.fileHashHex,
        originalFilename: decrypted.metadata.originalFilename ?? null,
      };
    }

    await writeBytesAtomic(plan.qencPath, result.qencBytes, { mode: 0o600, force: options.force });
    await writeBytesAtomic(plan.keyPath, result.privKey, { mode: 0o600, force: options.force });
    await writeBytesAtomic(plan.archiveStatePath, result.archiveStateBytes, { mode: 0o644, force: options.force });
    await writeBytesAtomic(plan.lifecycleBundlePath, result.lifecycleBundleBytes, { mode: 0o600, force: options.force });
    if (plaintextBytes) {
      await writeBytesAtomic(plan.plaintextPath, plaintextBytes, { mode: 0o600, force: options.force });
    }

    return buildRestoreWriteSummary({ result, plan, plaintextReport });
  } catch (error) {
    throw classifyRestoreError(error);
  } finally {
    await zeroizeRestoreMaterial(result);
    if (plaintextBytes instanceof Uint8Array) plaintextBytes.fill(0);
    for (const shard of parsedShards) {
      shard.share?.fill?.(0);
    }
  }
}

export function renderRestoreSummary(summary) {
  const lines = [
    summary.dryRun
      ? `Restore dry-run: ${summary.wouldSucceed ? 'would succeed' : 'would fail'}`
      : `Restored: ${summary.outputs?.qencPath}`,
    `ArchiveId: ${summary.archiveId}`,
    `StateId: ${summary.stateId}`,
    `CohortId: ${summary.cohortId}`,
    `Lifecycle bundle digest: ${summary.lifecycleBundleDigestHex}`,
    `Selection source: ${summary.selectionSource || 'embedded'}`,
    `Policy: ${summary.authenticity?.policy?.level || 'unknown'} (${summary.authenticity?.policy?.satisfied ? 'satisfied' : 'not satisfied'})`,
    `qencOk=${summary.qencOk} qkeyOk=${summary.qkeyOk}`,
  ];
  if (!summary.dryRun) {
    lines.push(`Recovered key: ${summary.outputs?.keyPath}`);
    if (summary.outputs?.plaintextPath) {
      lines.push(`Recovered plaintext: ${summary.outputs.plaintextPath}`);
    }
  }
  for (const warning of summary?.authenticity?.warnings || []) {
    lines.push(`Warning: ${warning}`);
  }
  return `${lines.join('\n')}\n`;
}
