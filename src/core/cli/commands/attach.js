import { mkdir, stat } from 'node:fs/promises';
import path from 'node:path';
import {
  attachLifecycleBundleToShards,
  exportSourceEvidenceForSigning,
} from '../../crypto/qcont/lifecycle-attach.js';
import {
  deriveCohortId,
  parseLifecycleBundleBytes,
  parseSourceEvidenceBytes,
} from '../../crypto/lifecycle/artifacts.js';
import {
  parseLifecycleShard,
  zeroizeParsedLifecycleShard,
} from '../../crypto/qcont/lifecycle-shard.js';
import { parseJsonBytesStrict, parseJsonTextStrict } from '../../crypto/manifest/strict-json.js';
import { normalizeExpectedEd25519Signer, takeValue } from '../lib/args.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';
import { dedupeSorted, expandFilePattern } from '../lib/glob.js';
import {
  makeExternalArtifactRecord,
  readBytesFromFile,
  readOptionalBytes,
  writeArtifactSetAtomic,
} from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';
import { FILE_MODE, smallArtifactReadOptions } from '../lib/artifact-policy.js';

const SIG_IMPORT_KEYS = new Set([
  'file',
  'name',
  'signatureFamily',
  'targetType',
  'targetRef',
  'targetDigest',
]);

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

function ambiguity(message, cause) {
  return makeQvError(message, QV_CODE.AMBIGUOUS_INPUTS, { cause });
}

function signatureImportFailed(message, cause) {
  return makeQvError(message, QV_CODE.SIGNATURE_IMPORT_FAILED, { cause });
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

async function ensureOutputDirectory(dirPath, label) {
  const resolved = path.resolve(dirPath);
  try {
    const stats = await stat(resolved);
    if (!stats.isDirectory()) {
      throw usage(`${label} must be a directory: ${resolved}`);
    }
    return resolved;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const parent = path.dirname(resolved);
  try {
    const parentStats = await stat(parent);
    if (!parentStats.isDirectory()) {
      throw usage(`${label} parent is not a directory: ${parent}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`${label} parent directory does not exist: ${parent}`);
    }
    throw error;
  }
  await mkdir(resolved);
  return resolved;
}

async function ensureOutputParentExists(filePath, label) {
  await ensureOutputDirectory(path.dirname(path.resolve(filePath)), `${label} parent`);
}

function parseAttachArgs(args) {
  const options = {
    shardPatterns: [],
    archiveStatePath: '',
    bundlePath: '',
    signaturePaths: [],
    signatureImportSpecs: [],
    pqpkPaths: [],
    otsPaths: [],
    sourceEvidencePath: '',
    sourceEvidenceBytesPath: '',
    expectedEd25519Signer: '',
    outBundlePath: 'lifecycle-bundle.json',
    outShardsDir: 'attached-shards',
    noEmbedIntoShards: false,
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
      case '--sig-import':
        options.signatureImportSpecs.push(takeValue(args, index, arg));
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
      case '--source-evidence':
        options.sourceEvidencePath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--source-evidence-bytes':
        options.sourceEvidenceBytesPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--ed25519-signer':
        options.expectedEd25519Signer = normalizeExpectedEd25519Signer(takeValue(args, index, arg), arg);
        index += 1;
        break;
      case '--out-bundle':
        options.outBundlePath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--out-shards':
        options.outShardsDir = takeValue(args, index, arg);
        index += 1;
        break;
      case '--no-embed-into-shards':
        options.noEmbedIntoShards = true;
        break;
      case '--force':
        options.force = true;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw usage(`Unknown attach option: ${arg}`);
    }
  }

  if (options.sourceEvidencePath && options.sourceEvidenceBytesPath) {
    throw usage('attach accepts --source-evidence or --source-evidence-bytes, not both');
  }
  if (options.shardPatterns.length === 0 && !options.bundlePath) {
    throw usage('attach requires --shards or --bundle');
  }
  if (options.outBundlePath.includes('\0') || options.outShardsDir.includes('\0')) {
    throw usage('attach output path contains an invalid NUL byte');
  }
  return options;
}

export { parseAttachArgs };

function parseSigImportSpec(spec) {
  let parsed;
  try {
    parsed = parseJsonTextStrict(spec);
  } catch (error) {
    throw usage(`Invalid --sig-import JSON: ${error?.message || error}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw usage('--sig-import must be a JSON object');
  }
  for (const key of Object.keys(parsed)) {
    if (!SIG_IMPORT_KEYS.has(key)) {
      throw usage(`Unknown --sig-import field: ${key}`);
    }
  }
  if (typeof parsed.file !== 'string' || parsed.file.length === 0) {
    throw usage('--sig-import requires "file"');
  }
  if (typeof parsed.signatureFamily !== 'string' || parsed.signatureFamily.length === 0) {
    throw usage('--sig-import requires "signatureFamily"');
  }
  return parsed;
}

async function readSignatureImport(spec, sourceEvidence = {}) {
  const parsed = parseSigImportSpec(spec);
  const bytes = await readBytesFromFile(parsed.file, smallArtifactReadOptions('--sig-import file'));
  const out = {
    name: parsed.name || path.basename(parsed.file),
    bytes,
    signatureFamily: parsed.signatureFamily,
  };
  for (const key of ['targetType', 'targetRef', 'targetDigest']) {
    if (Object.prototype.hasOwnProperty.call(parsed, key)) {
      out[key] = parsed[key];
    }
  }
  if (out.signatureFamily === 'source-evidence') {
    if (sourceEvidence.sourceEvidenceBytes instanceof Uint8Array) {
      out.sourceEvidenceBytes = sourceEvidence.sourceEvidenceBytes;
    } else if (sourceEvidence.sourceEvidence) {
      out.sourceEvidence = sourceEvidence.sourceEvidence;
    }
  }
  return out;
}

async function readSourceEvidence(options) {
  if (options.sourceEvidenceBytesPath) {
    return {
      sourceEvidenceBytes: await readBytesFromFile(
        options.sourceEvidenceBytesPath,
        smallArtifactReadOptions('--source-evidence-bytes')
      ),
    };
  }
  if (options.sourceEvidencePath) {
    const bytes = await readBytesFromFile(options.sourceEvidencePath, smallArtifactReadOptions('--source-evidence'));
    try {
      const parsed = parseSourceEvidenceBytes(bytes);
      return { sourceEvidenceBytes: parsed.bytes };
    } catch (error) {
      const msg = String(error?.message || error);
      if (/^Invalid Source evidence JSON:/.test(msg)) {
        throw usage(msg.replace(/^Invalid Source evidence JSON:/, '--source-evidence: invalid JSON —'));
      }
      if (/Source evidence is not .* canonical JSON$/.test(msg)) {
        return { sourceEvidence: parseJsonBytesStrict(bytes) };
      }
      throw error;
    }
  }
  return {};
}

async function readShardInputs(patterns, cwd) {
  const shardPaths = [];
  for (const pattern of patterns) {
    shardPaths.push(...await expandFilePattern(pattern, cwd));
  }
  const resolvedShardPaths = dedupeSorted(shardPaths);
  const parsedShards = [];
  const rawShardBytes = [];
  try {
    for (const filePath of resolvedShardPaths) {
      const bytes = await readBytesFromFile(filePath);
      rawShardBytes.push(bytes);
      try {
        parsedShards.push(await parseLifecycleShard(bytes, { strict: true }));
      } catch (error) {
        throw usage(`Shard ${filePath} is not a supported successor shard: ${error?.message || error}`);
      }
    }
    return { shardPaths: resolvedShardPaths, parsedShards, rawShardBytes };
  } catch (error) {
    for (const shard of parsedShards) zeroizeParsedLifecycleShard(shard);
    for (const bytes of rawShardBytes) bytes.fill(0);
    throw error;
  }
}

async function readAttachInputs(options, cwd) {
  if (options.archiveStatePath) await ensureInputFile(options.archiveStatePath, '--archive-state');
  if (options.bundlePath) await ensureInputFile(options.bundlePath, '--bundle');
  for (const filePath of [
    ...options.signaturePaths,
    ...options.pqpkPaths,
    ...options.otsPaths,
  ]) {
    await ensureInputFile(filePath, 'Attach input file');
  }
  if (options.sourceEvidencePath) await ensureInputFile(options.sourceEvidencePath, '--source-evidence');
  if (options.sourceEvidenceBytesPath) await ensureInputFile(options.sourceEvidenceBytesPath, '--source-evidence-bytes');

  const { shardPaths, parsedShards, rawShardBytes } = await readShardInputs(options.shardPatterns, cwd);
  try {
    const sourceEvidence = await readSourceEvidence(options);
    const signatureImports = await Promise.all(options.signatureImportSpecs.map((spec) => (
      readSignatureImport(spec, sourceEvidence)
    )));

    return {
      shardPaths,
      parsedShards,
      rawShardBytes,
      archiveStateBytes: await readOptionalBytes(options.archiveStatePath, smallArtifactReadOptions('--archive-state')),
      lifecycleBundleBytes: await readOptionalBytes(options.bundlePath, smallArtifactReadOptions('--bundle')),
      signatures: await Promise.all(options.signaturePaths.map(async (filePath) => (
        makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath, smallArtifactReadOptions('--sig')))
      ))),
      signatureImports,
      timestamps: await Promise.all(options.otsPaths.map(async (filePath) => (
        makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath, smallArtifactReadOptions('--ots')))
      ))),
      pqPublicKeyFileBytesList: await Promise.all(options.pqpkPaths.map((filePath) => (
        readBytesFromFile(filePath, smallArtifactReadOptions('--pqpk'))
      ))),
    };
  } catch (error) {
    for (const shard of parsedShards) zeroizeParsedLifecycleShard(shard);
    for (const bytes of rawShardBytes) bytes.fill(0);
    throw error;
  }
}

function classifyAttachError(error) {
  if (typeof error?.qvCode === 'string') return error;
  if (typeof error?.code === 'string') return error;
  const message = error?.message || String(error);
  if (/multiple embedded lifecycle-bundle digests|exactly one archive\/state\/cohort|multiple/i.test(message) && /lifecycle-bundle|archive\/state\/cohort|successor shards/i.test(message)) {
    return ambiguity(message, error);
  }
  if (/No successor lifecycle shards or lifecycle bundle|Attach requires --shards|not a supported successor shard|Refusing to overwrite/.test(message)) {
    return usage(message);
  }
  if (/signature|qsig|stellar-sig|publicKeyRef|\.pqpk|timestamp|OpenTimestamps|\.ots\b/i.test(message)) {
    return signatureImportFailed(message, error);
  }
  return error;
}

function attachmentIdSets(previous, next) {
  const attachmentFields = [
    'publicKeys',
    'archiveApprovalSignatures',
    'maintenanceSignatures',
    'sourceEvidenceSignatures',
    'timestamps',
  ];
  const added = {};
  for (const field of attachmentFields) {
    const before = new Set((previous?.attachments?.[field] || []).map((entry) => entry.id));
    added[field] = (next?.attachments?.[field] || [])
      .map((entry) => entry.id)
      .filter((id) => !before.has(id));
  }
  const previousSourceEvidenceDigests = new Set((previous?.sourceEvidence || []).map((entry) => (
    exportSourceEvidenceForSigning({ sourceEvidence: entry }).sourceEvidenceDigestHex
  )));
  added.sourceEvidence = (next?.sourceEvidence || [])
    .map((entry) => exportSourceEvidenceForSigning({ sourceEvidence: entry }).sourceEvidenceDigestHex)
    .filter((digest) => !previousSourceEvidenceDigests.has(digest))
    .map((digest) => `sha3-512:${digest}`);
  return added;
}

async function resolvePreviousBundleForReport(inputs) {
  const bundleBytes = inputs.lifecycleBundleBytes
    || (inputs.parsedShards.length === 1 ? inputs.parsedShards[0].lifecycleBundleBytes : null);
  if (bundleBytes instanceof Uint8Array) {
    return (await parseLifecycleBundleBytes(bundleBytes)).lifecycleBundle;
  }

  const digests = new Map();
  for (const shard of inputs.parsedShards) {
    if (!digests.has(shard.lifecycleBundleDigestHex)) {
      digests.set(shard.lifecycleBundleDigestHex, shard.lifecycleBundleBytes);
    }
  }
  if (digests.size === 1) {
    const [, bytes] = [...digests.entries()][0];
    return (await parseLifecycleBundleBytes(bytes)).lifecycleBundle;
  }
  return null;
}

function deriveReportCohortId(result) {
  return deriveCohortId({
    archiveId: result.archiveState.archiveId,
    stateId: result.stateId,
    cohortBindingDigest: {
      alg: 'SHA3-512',
      value: result.cohortBindingDigestHex,
    },
  });
}

function buildShardOutputPlan(shardPaths, result, outShardsDir) {
  return result.shards.map((item, index) => ({
    index: item.index ?? index,
    sourcePath: shardPaths[index] || '',
    path: path.join(outShardsDir, path.basename(shardPaths[index] || `shard-${index + 1}.qcont`)),
  }));
}

async function preflightOutputs({ outBundlePath, shardPlan, force }) {
  const paths = [outBundlePath, ...shardPlan.map((item) => item.path)];
  if (!force) {
    for (const filePath of paths) {
      if (await pathExists(filePath)) {
        throw usage(`Refusing to overwrite existing file: ${filePath}`);
      }
    }
  }
}

async function writeAttachedArtifacts({ result, outBundlePath, shardPlan, force }) {
  await ensureOutputParentExists(outBundlePath, '--out-bundle');
  const stagedShardBytes = [];
  try {
    for (const shard of shardPlan) {
      const updated = result.shards.find((item) => (item.index ?? item.shardIndex) === shard.index);
      if (!updated) {
        throw new Error(`Missing rewritten shard ${shard.index}`);
      }
      stagedShardBytes.push({
        shard,
        bytes: await blobToBytes(updated.blob),
      });
    }

    await writeArtifactSetAtomic([
      { path: outBundlePath, bytes: result.lifecycleBundleBytes, mode: FILE_MODE.PUBLIC_ARTIFACT },
      ...stagedShardBytes.map(({ shard, bytes }) => ({
        path: shard.path,
        bytes,
        mode: FILE_MODE.SECRET_ARTIFACT,
      })),
    ], { force });
  } finally {
    for (const item of stagedShardBytes) {
      item.bytes.fill(0);
    }
  }
}

function deriveEmbeddedIntoShardsReason(noEmbedIntoShards, shardCount) {
  if (noEmbedIntoShards) return 'opt-out';
  if (shardCount === 0) return 'no-shards';
  return 'embedded';
}

function buildAttachReport({
  result,
  previousBundle,
  outBundlePath,
  shardPlan,
  embeddedIntoShards,
  embeddedIntoShardsReason,
}) {
  return {
    command: 'attach',
    archiveId: result.archiveState.archiveId,
    stateId: result.stateId,
    cohortId: deriveReportCohortId(result),
    lifecycleBundlePath: outBundlePath,
    lifecycleBundleDigestHex: result.lifecycleBundleDigestHex,
    lifecycleBundleDigestAlg: 'SHA3-512',
    embeddedIntoShards,
    embeddedIntoShardsReason,
    shardsRewritten: embeddedIntoShards
      ? shardPlan.map((item) => ({ index: item.index, path: item.path }))
      : [],
    addedAttachments: attachmentIdSets(previousBundle, result.lifecycleBundle),
    embeddedLifecycleBundleDigests: [...(result.embeddedLifecycleBundleDigests || [])],
    mixedEmbeddedLifecycleBundleDigests: result.mixedEmbeddedLifecycleBundleDigests === true,
    archiveStateDigestHex: result.archiveStateDigestHex,
    cohortBindingDigestHex: result.cohortBindingDigestHex,
  };
}

export async function runAttachCommand(options, {
  cwd = process.cwd(),
} = {}) {
  await ensureRuntimeCrypto();
  let inputs = null;

  try {
    inputs = await readAttachInputs(options, cwd);
    const embedIntoShards = inputs.parsedShards.length > 0 && !options.noEmbedIntoShards;
    const result = await attachLifecycleBundleToShards(inputs.parsedShards, {
      archiveStateBytes: inputs.archiveStateBytes,
      lifecycleBundleBytes: inputs.lifecycleBundleBytes,
      signatures: inputs.signatures,
      signatureImports: inputs.signatureImports,
      timestamps: inputs.timestamps,
      pqPublicKeyFileBytesList: inputs.pqPublicKeyFileBytesList,
      expectedEd25519Signer: options.expectedEd25519Signer,
      embedIntoShards,
    });
    const previousBundle = await resolvePreviousBundleForReport(inputs);

    const outBundlePath = path.resolve(cwd, options.outBundlePath);
    const shardPlan = embedIntoShards
      ? buildShardOutputPlan(
          inputs.shardPaths,
          result,
          await ensureOutputDirectory(path.resolve(cwd, options.outShardsDir), '--out-shards')
        )
      : [];
    await preflightOutputs({ outBundlePath, shardPlan, force: options.force });
    await writeAttachedArtifacts({ result, outBundlePath, shardPlan, force: options.force });

    return buildAttachReport({
      result,
      previousBundle,
      outBundlePath,
      shardPlan,
      embeddedIntoShards: embedIntoShards,
      embeddedIntoShardsReason: deriveEmbeddedIntoShardsReason(
        options.noEmbedIntoShards,
        inputs.parsedShards.length,
      ),
    });
  } catch (error) {
    throw classifyAttachError(error);
  } finally {
    for (const shard of inputs?.parsedShards || []) {
      zeroizeParsedLifecycleShard(shard);
    }
    for (const bytes of inputs?.rawShardBytes || []) bytes.fill(0);
  }
}

export function renderAttachSummary(report) {
  const lines = [
    `Attached lifecycle bundle: ${report.lifecycleBundlePath}`,
    `ArchiveId: ${report.archiveId}`,
    `StateId: ${report.stateId}`,
    `CohortId: ${report.cohortId || 'unknown'}`,
    `Lifecycle bundle digest: ${report.lifecycleBundleDigestHex}`,
    `Embedded into shards: ${report.embeddedIntoShards ? 'yes' : 'no'}`,
  ];
  if (report.embeddedIntoShardsReason) {
    lines.push(`Embed decision: ${report.embeddedIntoShardsReason}`);
  }
  lines.push('');
  return `${lines.join('\n')}`;
}
