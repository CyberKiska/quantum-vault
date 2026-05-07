import { mkdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../crypto/bytes.js';
import {
  parseLifecycleShard,
  reshareSameState,
} from '../../crypto/qcont/lifecycle-shard.js';
import { attachLifecycleBundleToShards } from '../../crypto/qcont/lifecycle-attach.js';
import { takeValue } from '../lib/args.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';
import { dedupeSorted, expandFilePattern } from '../lib/glob.js';
import {
  makeExternalArtifactRecord,
  readBytesFromFile,
  readOptionalBytes,
  writeArtifactSetAtomic,
} from '../lib/io.js';
import { ensureErasureRuntime, ensureRuntimeCrypto } from '../lib/runtime.js';

const LOWER_HEX_RE = /^[0-9a-f]+$/;
const FORBIDDEN_RESHARE_FLAGS = new Set([
  '--archive-state',
  '--archive-state-bytes',
  '--archive-state-digest',
  '--archive-state-digest-hex',
  '--qenc-hash',
  '--container-id',
  '--crypto-profile-id',
  '--kdf-tree-id',
  '--nonce-policy-id',
  '--nonce-mode',
  '--counter-bits',
  '--max-chunk-count',
  '--aad-policy-id',
  '--auth-policy',
  '--auth-policy-level',
  '--auth-policy-commitment',
  '--min-valid-signatures',
  '--parent-state-id',
  '--state-type',
]);

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

function quorumRejected(message, cause) {
  return makeQvError(message, QV_CODE.QUORUM_UNREACHABLE, { cause });
}

function ambiguity(message, cause) {
  return makeQvError(message, QV_CODE.AMBIGUOUS_INPUTS, { cause });
}

function reshareContract(message, cause) {
  return makeQvError(message, QV_CODE.RESHARE_CONTRACT_VIOLATION, { cause });
}

function signatureImportFailed(message, cause) {
  return makeQvError(message, QV_CODE.SIGNATURE_IMPORT_FAILED, { cause });
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

async function ensureInputFile(filePath, label) {
  try {
    const stats = await stat(filePath);
    if (!stats.isFile()) {
      throw usage(`${label} is not a file: ${filePath}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`${label} does not exist: ${filePath}`);
    }
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

function parsePositiveInt(value, field) {
  const text = String(value || '');
  if (!/^[0-9]+$/.test(text)) {
    throw usage(`${field} must be a positive integer`);
  }
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw usage(`${field} must be a positive safe integer`);
  }
  return parsed;
}

function normalizeLowerHex(value, field, expectedChars) {
  const text = String(value || '').trim();
  if (text.length !== expectedChars || !LOWER_HEX_RE.test(text)) {
    throw usage(`${field} must be ${expectedChars} lowercase hex characters`);
  }
  return text;
}

function parseSingleLine(value, field, fallback = '') {
  const text = String(value ?? '').trim();
  if (!text) return fallback;
  if (text.length > 256 || /[\0\r\n]/.test(text)) {
    throw usage(`${field} must be a short single-line string`);
  }
  return text;
}

function parsePerformedAt(value) {
  const text = parseSingleLine(value, '--performed-at');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(text) || Number.isNaN(Date.parse(text))) {
    throw usage('--performed-at must be an ISO-8601 UTC timestamp such as 2026-03-25T12:34:56.000Z');
  }
  return text;
}

export function parseReshareArgs(args) {
  const options = {
    shardPatterns: [],
    n: null,
    k: null,
    bundlePath: '',
    selectedArchiveId: '',
    selectedStateId: '',
    selectedCohortId: '',
    selectedLifecycleBundleDigestHex: '',
    reasonCode: '',
    operatorRole: '',
    notes: null,
    performedAt: '',
    maintenanceSignaturePaths: [],
    maintenancePqpkPaths: [],
    maintenanceOtsPaths: [],
    outDir: 'reshared-shards',
    force: false,
    json: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (FORBIDDEN_RESHARE_FLAGS.has(arg)) {
      throw reshareContract(`Same-state resharing forbids overriding ${arg}`);
    }
    switch (arg) {
      case '--shards':
        options.shardPatterns.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--n':
        options.n = parsePositiveInt(takeValue(args, index, arg), '--n');
        index += 1;
        break;
      case '--k':
        options.k = parsePositiveInt(takeValue(args, index, arg), '--k');
        index += 1;
        break;
      case '--bundle':
        options.bundlePath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--archive-id':
        options.selectedArchiveId = normalizeLowerHex(takeValue(args, index, arg), '--archive-id', 64);
        index += 1;
        break;
      case '--state-id':
        options.selectedStateId = normalizeLowerHex(takeValue(args, index, arg), '--state-id', 128);
        index += 1;
        break;
      case '--cohort-id':
        options.selectedCohortId = normalizeLowerHex(takeValue(args, index, arg), '--cohort-id', 64);
        index += 1;
        break;
      case '--bundle-digest':
        options.selectedLifecycleBundleDigestHex = normalizeLowerHex(takeValue(args, index, arg), '--bundle-digest', 128);
        index += 1;
        break;
      case '--reason-code':
        options.reasonCode = parseSingleLine(takeValue(args, index, arg), '--reason-code');
        index += 1;
        break;
      case '--operator-role':
        options.operatorRole = parseSingleLine(takeValue(args, index, arg), '--operator-role');
        index += 1;
        break;
      case '--notes':
        options.notes = parseSingleLine(takeValue(args, index, arg), '--notes') || null;
        index += 1;
        break;
      case '--performed-at':
        options.performedAt = parsePerformedAt(takeValue(args, index, arg));
        index += 1;
        break;
      case '--maintenance-sig':
        options.maintenanceSignaturePaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--maintenance-pqpk':
        options.maintenancePqpkPaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--maintenance-ots':
        options.maintenanceOtsPaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--out':
        options.outDir = takeValue(args, index, arg);
        index += 1;
        break;
      case '--force':
        options.force = true;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw usage(`Unknown reshare option: ${arg}`);
    }
  }

  if (options.shardPatterns.length === 0) {
    throw usage('reshare requires at least one --shards pattern or path');
  }
  if (options.n == null) {
    throw usage('reshare requires --n <int>');
  }
  if (options.k == null) {
    throw usage('reshare requires --k <int>');
  }
  if (options.maintenanceOtsPaths.length > 0 && options.maintenanceSignaturePaths.length === 0) {
    throw usage('reshare --maintenance-ots requires at least one --maintenance-sig in the same command');
  }
  if (options.outDir.includes('\0')) {
    throw usage('reshare output path contains an invalid NUL byte');
  }
  return options;
}

async function readShardInputs(patterns, cwd) {
  const shardPaths = [];
  for (const pattern of patterns) {
    shardPaths.push(...await expandFilePattern(pattern, cwd));
  }
  const resolvedShardPaths = dedupeSorted(shardPaths);
  if (resolvedShardPaths.length === 0) {
    throw usage('reshare matched no shard files');
  }
  const parsedShards = [];
  for (const filePath of resolvedShardPaths) {
    const bytes = await readBytesFromFile(filePath);
    try {
      parsedShards.push(await parseLifecycleShard(bytes, { strict: true }));
    } catch (error) {
      throw usage(`Shard ${filePath} is not a supported successor shard: ${error?.message || error}`);
    }
  }
  return { shardPaths: resolvedShardPaths, parsedShards };
}

async function readReshareInputs(options, cwd) {
  if (options.bundlePath) await ensureInputFile(options.bundlePath, '--bundle');
  for (const filePath of [
    ...options.maintenanceSignaturePaths,
    ...options.maintenancePqpkPaths,
    ...options.maintenanceOtsPaths,
  ]) {
    await ensureInputFile(filePath, 'Reshare maintenance input file');
  }
  const { shardPaths, parsedShards } = await readShardInputs(options.shardPatterns, cwd);
  return {
    shardPaths,
    parsedShards,
    lifecycleBundleBytes: await readOptionalBytes(options.bundlePath),
    maintenanceSignatures: await Promise.all(options.maintenanceSignaturePaths.map(async (filePath) => (
      makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath))
    ))),
    maintenancePqpkBytesList: await Promise.all(options.maintenancePqpkPaths.map(readBytesFromFile)),
    maintenanceTimestamps: await Promise.all(options.maintenanceOtsPaths.map(async (filePath) => (
      makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath))
    ))),
  };
}

function classifyReshareError(error) {
  if (typeof error?.qvCode === 'string') return error;
  const message = error?.message || String(error);
  if (/Same-state resharing forbids overriding|must preserve|changed archiveId|changed stateId|changed archive-state|bodyDefinition|new maintenance/i.test(message)) {
    return reshareContract(message, error);
  }
  if (/multiple embedded lifecycle-bundle digests|exactly one predecessor archive\/state\/cohort|Selected predecessor|Selected lifecycle-bundle digest|does not match the predecessor/i.test(message)) {
    return ambiguity(message, error);
  }
  if (/Invalid params\.[nk]|Invalid params\.t|Invalid reshare|Unsupported|Need at least|Not enough valid predecessor shards|Too many missing\/corrupted|RS|Shamir|threshold|codec/i.test(message)) {
    return quorumRejected(message, error);
  }
  if (/signature|\.pqpk|timestamp|OpenTimestamps|ots/i.test(message)) {
    return signatureImportFailed(message, error);
  }
  if (/No predecessor shards|requires parsed successor lifecycle shards|Refusing to overwrite|matched no shard files|not a supported successor shard/i.test(message)) {
    return usage(message);
  }
  return error;
}

function deriveBaseName(shardPaths) {
  const first = path.basename(shardPaths[0] || 'archive.qcont');
  const withoutQcont = first.endsWith('.qcont') ? first.slice(0, -'.qcont'.length) : first;
  return withoutQcont.replace(/\.part\d+-of-\d+$/i, '') || 'archive';
}

function buildOutputPlan({ shardPaths, outDir, result }) {
  const baseName = deriveBaseName(shardPaths);
  const shardCount = result.shards.length;
  return {
    archiveStatePath: path.join(outDir, `${baseName}.archive-state.json`),
    cohortBindingPath: path.join(outDir, `${baseName}.cohort-binding.json`),
    lifecycleBundlePath: path.join(outDir, `${baseName}.lifecycle-bundle.json`),
    transitionRecordPath: path.join(outDir, `${baseName}.transition-record.json`),
    shards: result.shards.map((item, index) => ({
      index: item.index ?? item.shardIndex ?? index,
      path: path.join(outDir, `${baseName}.reshared.part${index + 1}-of-${shardCount}.qcont`),
    })),
  };
}

async function preflightOutputPlan(plan, force) {
  if (force) return;
  const paths = [
    plan.archiveStatePath,
    plan.cohortBindingPath,
    plan.lifecycleBundlePath,
    plan.transitionRecordPath,
    ...plan.shards.map((item) => item.path),
  ];
  for (const filePath of paths) {
    if (await pathExists(filePath)) {
      throw usage(`Refusing to overwrite existing file: ${filePath}`);
    }
  }
}

async function applyMaintenanceImportsIfRequested(result, inputs) {
  if (
    inputs.maintenanceSignatures.length === 0 &&
    inputs.maintenanceTimestamps.length === 0 &&
    inputs.maintenancePqpkBytesList.length === 0
  ) {
    return {
      result,
      maintenanceSignatureCountAdded: result.maintenanceSignatureCountAdded,
    };
  }
  if (inputs.maintenanceSignatures.length === 0) {
    throw usage('reshare maintenance signer keys require at least one --maintenance-sig');
  }

  const successorShardBytes = [];
  const successorShards = [];
  try {
    for (const item of result.shards) {
      const bytes = await blobToBytes(item.blob);
      successorShardBytes.push(bytes);
      successorShards.push(await parseLifecycleShard(bytes, { strict: true }));
    }

    const targetRef = `transition:sha3-512:${result.transitionRecordDigestHex}`;
    const signatureImports = inputs.maintenanceSignatures.map((signature) => ({
      ...signature,
      signatureFamily: 'maintenance',
      targetType: 'transition-record',
      targetRef,
      targetDigest: result.transitionRecordDigestHex,
    }));
    const attached = await attachLifecycleBundleToShards(successorShards, {
      lifecycleBundleBytes: result.lifecycleBundleBytes,
      signatureImports,
      timestamps: inputs.maintenanceTimestamps,
      pqPublicKeyFileBytesList: inputs.maintenancePqpkBytesList,
      embedIntoShards: true,
    });
    const previousIds = new Set(
      (result.lifecycleBundle?.attachments?.maintenanceSignatures || []).map((entry) => entry.id)
    );
    const addedMaintenance = (attached.lifecycleBundle?.attachments?.maintenanceSignatures || [])
      .filter((entry) => !previousIds.has(entry.id))
      .length;
    return {
      result: {
        ...result,
        shards: attached.shards,
        lifecycleBundle: attached.lifecycleBundle,
        lifecycleBundleBytes: attached.lifecycleBundleBytes,
        lifecycleBundleDigestHex: attached.lifecycleBundleDigestHex,
      },
      maintenanceSignatureCountAdded: result.maintenanceSignatureCountAdded + addedMaintenance,
    };
  } finally {
    for (const shard of successorShards) {
      shard.share?.fill?.(0);
    }
    for (const bytes of successorShardBytes) {
      bytes.fill(0);
    }
  }
}

async function writeReshareOutputs({ result, plan, maintenanceSignatureCountAdded, force }) {
  const shardReports = [];
  const stagedShardBytes = [];
  try {
    for (const shard of plan.shards) {
      const item = result.shards.find((candidate) => (candidate.index ?? candidate.shardIndex) === shard.index);
      if (!item) {
        throw new Error(`Missing reshared shard ${shard.index}`);
      }
      const bytes = await blobToBytes(item.blob);
      stagedShardBytes.push({ shard, bytes });
      shardReports.push({
        index: shard.index,
        path: shard.path,
        shardDigestHex: digestSha3_512Hex(bytes),
        shardSize: bytes.length,
      });
    }

    await writeArtifactSetAtomic([
      { path: plan.archiveStatePath, bytes: result.archiveStateBytes, mode: 0o644 },
      { path: plan.cohortBindingPath, bytes: result.cohortBindingBytes, mode: 0o644 },
      { path: plan.lifecycleBundlePath, bytes: result.lifecycleBundleBytes, mode: 0o600 },
      { path: plan.transitionRecordPath, bytes: result.transitionRecordBytes, mode: 0o644 },
      ...stagedShardBytes.map(({ shard, bytes }) => ({
        path: shard.path,
        bytes,
        mode: 0o600,
      })),
    ], { force });
  } finally {
    for (const item of stagedShardBytes) {
      item.bytes.fill(0);
    }
  }

  return {
    command: 'reshare',
    archiveId: result.archiveId,
    stateId: result.stateId,
    predecessorCohortId: result.predecessorCohortId,
    cohortId: result.cohortId,
    predecessorLifecycleBundleDigestHex: result.predecessorLifecycleBundleDigestHex,
    predecessorLifecycleBundleSource: result.predecessorLifecycleBundleSource,
    archiveStateBytesPath: plan.archiveStatePath,
    archiveStateDigestHex: result.archiveStateDigestHex,
    cohortBindingBytesPath: plan.cohortBindingPath,
    cohortBindingDigestHex: result.cohortBindingDigestHex,
    transitionRecordPath: plan.transitionRecordPath,
    transitionRecordDigestHex: result.transitionRecordDigestHex,
    lifecycleBundlePath: plan.lifecycleBundlePath,
    lifecycleBundleDigestHex: result.lifecycleBundleDigestHex,
    shards: shardReports,
    verificationReport: result.verificationReport,
    maintenanceSignatureCountAdded,
    operationalWarnings: result.operationalWarnings,
    semantics: result.semantics,
    zeroization: result.zeroization,
  };
}

export async function runReshareCommand(options, {
  cwd = process.cwd(),
} = {}) {
  await ensureRuntimeCrypto();
  const erasureRuntime = await ensureErasureRuntime();
  let inputs = null;

  try {
    inputs = await readReshareInputs(options, cwd);
    const reshareResult = await reshareSameState(inputs.parsedShards, {
      n: options.n,
      k: options.k,
    }, {
      erasureRuntime,
      selectedArchiveId: options.selectedArchiveId,
      selectedStateId: options.selectedStateId,
      selectedCohortId: options.selectedCohortId,
      selectedLifecycleBundleDigestHex: options.selectedLifecycleBundleDigestHex,
      lifecycleBundleBytes: inputs.lifecycleBundleBytes,
      transition: {
        reasonCode: options.reasonCode || 'cohort-rotation',
        operatorRole: options.operatorRole || 'operator',
        notes: options.notes,
        ...(options.performedAt ? { performedAt: options.performedAt } : {}),
        actorHints: { surface: 'qv-cli' },
      },
    });
    const {
      result,
      maintenanceSignatureCountAdded,
    } = await applyMaintenanceImportsIfRequested(reshareResult, inputs);

    const outDir = await ensureOutputDirectory(path.resolve(cwd, options.outDir));
    const plan = buildOutputPlan({
      shardPaths: inputs.shardPaths,
      outDir,
      result,
    });
    await preflightOutputPlan(plan, options.force);
    return await writeReshareOutputs({
      result,
      plan,
      maintenanceSignatureCountAdded,
      force: options.force,
    });
  } catch (error) {
    throw classifyReshareError(error);
  } finally {
    for (const shard of inputs?.parsedShards || []) {
      shard.share?.fill?.(0);
    }
  }
}

export function renderReshareSummary(report) {
  const lines = [
    `Reshared successor cohort: ${report.cohortId}`,
    `ArchiveId: ${report.archiveId}`,
    `StateId: ${report.stateId}`,
    `Predecessor cohortId: ${report.predecessorCohortId}`,
    `Lifecycle bundle digest: ${report.lifecycleBundleDigestHex}`,
    `Transition record digest: ${report.transitionRecordDigestHex}`,
    `Shards written: ${report.shards.length}`,
  ];
  for (const warning of report.operationalWarnings || []) {
    lines.push(`Warning: ${warning}`);
  }
  lines.push('');
  return `${lines.join('\n')}`;
}
