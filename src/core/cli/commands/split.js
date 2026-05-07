import { mkdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { fromHex, toHex } from '../../crypto/bytes.js';
import { parseQencHeader } from '../../crypto/qenc/format.js';
import { buildLifecycleQcontShards } from '../../crypto/qcont/lifecycle-shard.js';
import { validatePrivateKey } from '../../crypto/mlkem.js';
import { REED_SOLOMON_CODEC_ID } from '../../crypto/lifecycle/artifacts.js';
import { normalizeFlexibleHex, takeValue } from '../lib/args.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';
import { readBytesFromFile, writeArtifactSetAtomic } from '../lib/io.js';
import { ensureErasureRuntime, ensureRuntimeCrypto } from '../lib/runtime.js';
import { readSecretBytes } from '../lib/secrets.js';
import { FILE_MODE, smallArtifactReadOptions } from '../lib/artifact-policy.js';

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

function keyRejected(message, cause) {
  return makeQvError(message, QV_CODE.KEY_REJECTED, { cause });
}

function quorumRejected(message, cause) {
  return makeQvError(message, QV_CODE.QUORUM_UNREACHABLE, { cause });
}

function formatPolicy(message, cause) {
  return makeQvError(message, QV_CODE.FORMAT_POLICY_REJECT, { cause });
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

function parseHexBytes(value, field, expectedBytes) {
  const text = String(value || '').trim();
  if (text.length !== expectedBytes * 2 || !/^[0-9a-fA-F]+$/.test(text)) {
    throw usage(`${field} must be ${expectedBytes * 2} hex characters`);
  }
  return fromHex(text);
}

function normalizeHexOption(value, field, expectedChars) {
  try {
    return normalizeFlexibleHex(value, field, expectedChars);
  } catch (error) {
    if (typeof error?.qvCode === 'string') throw error;
    throw usage(error?.message || String(error));
  }
}

function validateStateType(value) {
  if (!value) return '';
  const text = String(value);
  if (text.length > 128 || /[\0\r\n]/.test(text)) {
    throw usage('--state-type must be a short single-line string');
  }
  return text;
}

function parseSplitInputs(args) {
  const inputs = [];
  const options = {
    inputPath: '',
    privateKeyPath: '',
    privateKeyStdin: false,
    privateKeyEnv: '',
    n: null,
    k: null,
    outDir: 'shards',
    authPolicyLevel: '',
    minValidSignatures: null,
    archiveId: '',
    parentStateId: null,
    stateType: '',
    archiveIdRandomBytes: null,
    force: false,
    json: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--private-key':
        options.privateKeyPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--private-key-stdin':
        options.privateKeyStdin = true;
        break;
      case '--private-key-env':
        options.privateKeyEnv = takeValue(args, index, arg);
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
      case '--out':
        options.outDir = takeValue(args, index, arg);
        index += 1;
        break;
      case '--auth-policy-level':
        options.authPolicyLevel = takeValue(args, index, arg);
        index += 1;
        break;
      case '--min-valid-signatures':
        options.minValidSignatures = parsePositiveInt(takeValue(args, index, arg), '--min-valid-signatures');
        index += 1;
        break;
      case '--archive-id':
        options.archiveId = normalizeHexOption(takeValue(args, index, arg), '--archive-id', 64);
        index += 1;
        break;
      case '--parent-state-id':
        options.parentStateId = normalizeHexOption(takeValue(args, index, arg), '--parent-state-id', 128);
        index += 1;
        break;
      case '--state-type':
        options.stateType = validateStateType(takeValue(args, index, arg));
        index += 1;
        break;
      case '--archive-id-random':
        options.archiveIdRandomBytes = parseHexBytes(takeValue(args, index, arg), '--archive-id-random', 32);
        index += 1;
        break;
      case '--force':
        options.force = true;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        if (arg.startsWith('--')) {
          throw usage(`Unknown split option: ${arg}`);
        }
        inputs.push(arg);
    }
  }

  if (inputs.length !== 1) {
    throw usage('split requires exactly one <input.qenc>');
  }
  options.inputPath = inputs[0];
  return options;
}

function validateSplitOptions(options) {
  const keySources = [
    Boolean(options.privateKeyPath),
    options.privateKeyStdin,
    Boolean(options.privateKeyEnv),
  ].filter(Boolean).length;
  if (keySources !== 1) {
    throw usage('split requires exactly one private key source (--private-key, --private-key-stdin, or --private-key-env)');
  }
  if (options.n == null) {
    throw usage('split requires --n <int>');
  }
  if (options.k == null) {
    throw usage('split requires --k <int>');
  }
  if (options.archiveId && options.archiveIdRandomBytes) {
    throw usage('split accepts --archive-id or --archive-id-random, not both');
  }
  if (String(options.outDir || '').includes('\0')) {
    throw usage('--out contains an invalid NUL byte');
  }
}

function assertDeterministicSplitAllowed(options, env) {
  const deterministicFlags = [
    options.archiveId ? '--archive-id' : '',
    options.archiveIdRandomBytes ? '--archive-id-random' : '',
    options.parentStateId ? '--parent-state-id' : '',
    options.stateType ? '--state-type' : '',
  ].filter(Boolean);
  if (deterministicFlags.length === 0) return;
  if (String(env?.QV_ALLOW_DETERMINISTIC || '') === '1') return;
  throw usage(
    `split deterministic fixture flags require QV_ALLOW_DETERMINISTIC=1: ${deterministicFlags.join(', ')}`
  );
}

export function parseSplitArgs(args) {
  const options = parseSplitInputs(args);
  validateSplitOptions(options);
  return options;
}

function validateAndClonePrivateKey(bytes) {
  try {
    validatePrivateKey(bytes);
  } catch (error) {
    throw keyRejected(error?.message || String(error), error);
  }
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  return out;
}

function classifySplitError(error) {
  if (typeof error?.qvCode === 'string') return error;
  const message = error?.message || String(error);
  if (/Invalid ML-KEM-1024 private key length|Private key must be Uint8Array/.test(message)) {
    return keyRejected(message, error);
  }
  if (/Private key does not match|Key verification failed|key commitment mismatch|decapsulation/i.test(message)) {
    return keyRejected('Private key does not match this .qenc container', error);
  }
  if (/Invalid cohort parameters|Unsupported cohort parameters|RS parameters|Shamir|reedSolomon|parity|threshold|shareCount|2 <= k < n/i.test(message)) {
    return quorumRejected(message, error);
  }
  if (/Invalid file format|File is too small|Unsupported container format|Invalid metadata|Incomplete container|Invalid container|QENC/.test(message)) {
    return formatPolicy(message, error);
  }
  if (/Refusing to overwrite existing file/.test(message)) {
    return usage(message);
  }
  if (/Unsupported authPolicy\.level/.test(message)) {
    return usage(message);
  }
  return error;
}

function splitBaseName(inputPath) {
  const name = path.basename(inputPath).replace(/\.qenc$/i, '');
  if (!name || name === '.' || name === '..' || /[/\\\0]/.test(name)) {
    throw usage('split input filename must produce a safe output basename');
  }
  return name;
}

function buildOutputPlan({ outDir, inputPath, shardCount }) {
  const baseName = splitBaseName(inputPath);
  const shards = [];
  for (let index = 0; index < shardCount; index += 1) {
    shards.push({
      index,
      path: path.join(outDir, `${baseName}.part${index + 1}-of-${shardCount}.qcont`),
    });
  }
  return {
    shards,
    archiveStatePath: path.join(outDir, `${baseName}.archive-state.json`),
    cohortBindingPath: path.join(outDir, `${baseName}.cohort-binding.json`),
    lifecycleBundlePath: path.join(outDir, `${baseName}.lifecycle-bundle.json`),
  };
}

async function preflightOutputPlan(plan, force) {
  if (force) return;
  const paths = [
    plan.archiveStatePath,
    plan.cohortBindingPath,
    plan.lifecycleBundlePath,
    ...plan.shards.map((item) => item.path),
  ];
  for (const filePath of paths) {
    if (await pathExists(filePath)) {
      throw usage(`Refusing to overwrite existing file: ${filePath}`);
    }
  }
}

function buildCoreOptions(options) {
  const coreOptions = {};
  if (options.authPolicyLevel) coreOptions.authPolicyLevel = options.authPolicyLevel;
  if (options.minValidSignatures != null) coreOptions.minValidSignatures = options.minValidSignatures;
  if (options.archiveId) coreOptions.archiveId = options.archiveId;
  if (options.parentStateId) coreOptions.parentStateId = options.parentStateId;
  if (options.stateType) coreOptions.stateType = options.stateType;
  if (options.archiveIdRandomBytes) coreOptions.archiveIdRandomBytes = options.archiveIdRandomBytes;
  return coreOptions;
}

async function collectShardBytes(shards) {
  return Promise.all(shards.map(async (item) => ({
    index: item.index,
    bytes: await blobToBytes(item.blob),
  })));
}

function buildSplitReport({
  options,
  outDir,
  plan,
  split,
  shardBytes,
  qencBytes,
  parsedQenc,
  privateKeyBytes,
}) {
  const sharding = split.cohortBinding.sharding;
  return {
    command: 'split',
    inputPath: options.inputPath,
    outDir,
    archiveId: split.archiveId,
    stateId: split.stateId,
    cohortId: split.cohortId,
    n: sharding.reedSolomon.n,
    k: sharding.reedSolomon.k,
    m: sharding.reedSolomon.parity,
    t: sharding.shamir.threshold,
    rsCodecId: sharding.reedSolomon.codecId || REED_SOLOMON_CODEC_ID,
    shamir: {
      n: sharding.shamir.shareCount,
      t: sharding.shamir.threshold,
    },
    authPolicy: {
      level: split.lifecycleBundle.authPolicy.level,
      minValidSignatures: split.lifecycleBundle.authPolicy.minValidSignatures,
    },
    archiveStateBytesPath: plan.archiveStatePath,
    archiveStateDigestHex: split.archiveStateDigestHex,
    cohortBindingBytesPath: plan.cohortBindingPath,
    cohortBindingDigestHex: split.cohortBindingDigestHex,
    lifecycleBundleBytesPath: plan.lifecycleBundlePath,
    lifecycleBundleDigestHex: split.lifecycleBundleDigestHex,
    shards: shardBytes.map((item) => ({
      index: item.index,
      path: plan.shards[item.index].path,
      shardDigestHex: digestSha3_512Hex(item.bytes),
      shardSize: item.bytes.length,
    })),
    fmt: split.formatVersion,
    containerHashAlg: 'SHA3-512',
    containerHashHex: digestSha3_512Hex(qencBytes),
    containerId: digestSha3_512Hex(parsedQenc.header),
    privateKeyHashHex: digestSha3_512Hex(privateKeyBytes),
  };
}

async function writeSplitArtifacts({ split, shardBytes, plan, force }) {
  await writeArtifactSetAtomic([
    { path: plan.archiveStatePath, bytes: split.archiveStateBytes, mode: FILE_MODE.PUBLIC_ARTIFACT },
    { path: plan.cohortBindingPath, bytes: split.cohortBindingBytes, mode: FILE_MODE.PUBLIC_ARTIFACT },
    { path: plan.lifecycleBundlePath, bytes: split.lifecycleBundleBytes, mode: FILE_MODE.PUBLIC_ARTIFACT },
    ...shardBytes.map((item) => ({
      path: plan.shards[item.index].path,
      bytes: item.bytes,
      mode: FILE_MODE.SECRET_ARTIFACT,
    })),
  ], { force });
}

export function renderSplitInternalHelp() {
  return [
    'qv split — internal / deterministic testing flags',
    '',
    'These options are for fixtures and CI only; production cohorts should omit them.',
    '',
    '  --archive-id <64 lowercase hex chars>     Fixed archiveId (mutually exclusive with --archive-id-random)',
    '  --archive-id-random <64 lowercase hex>    Fixed 32-byte preimage for archiveId randomness',
    '  --parent-state-id <128 lowercase hex>     Root parent state id override',
    '  --state-type <string>                     Short state-type label (<=128 chars)',
    '',
    'Private key sources (exactly one required, same semantics as qv decrypt):',
    '  --private-key <path>',
    '  --private-key-stdin',
    '  --private-key-env <NAME>                  Env var whose value is a filesystem path to privateKey.qkey',
  ].join('\n');
}

export async function runSplitCommand(options, {
  stdin = process.stdin,
  cwd = process.cwd(),
  env = process.env,
} = {}) {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();
  assertDeterministicSplitAllowed(options, env);
  await ensureInputFile(options.inputPath, 'Input .qenc');
  if (options.privateKeyPath) {
    await ensureInputFile(options.privateKeyPath, 'Private key file');
  }

  let secret = null;
  let privateKeyBytes = null;
  let qencBytes = null;
  let shardBytes = null;

  try {
    qencBytes = await readBytesFromFile(options.inputPath);
    const parsedQenc = parseQencHeader(qencBytes);
    secret = await readSecretBytes({
      filePath: options.privateKeyPath || null,
      stdin: options.privateKeyStdin ? stdin : null,
      envName: options.privateKeyEnv || null,
      env,
      ...smallArtifactReadOptions('Private key input'),
    });
    privateKeyBytes = validateAndClonePrivateKey(secret.bytes);

    const split = await buildLifecycleQcontShards(
      qencBytes,
      privateKeyBytes,
      { n: options.n, k: options.k },
      buildCoreOptions(options),
    );
    shardBytes = await collectShardBytes(split.shards);

    const outDirInput = path.isAbsolute(options.outDir)
      ? options.outDir
      : path.join(cwd, options.outDir);
    const outDir = await ensureOutputDirectory(outDirInput);
    const plan = buildOutputPlan({
      outDir,
      inputPath: options.inputPath,
      shardCount: split.shards.length,
    });
    await preflightOutputPlan(plan, options.force);
    await writeSplitArtifacts({ split, shardBytes, plan, force: options.force });

    return buildSplitReport({
      options,
      outDir,
      plan,
      split,
      shardBytes,
      qencBytes,
      parsedQenc,
      privateKeyBytes,
    });
  } catch (error) {
    throw classifySplitError(error);
  } finally {
    secret?.dispose();
    if (privateKeyBytes instanceof Uint8Array) privateKeyBytes.fill(0);
    if (qencBytes instanceof Uint8Array) qencBytes.fill(0);
    if (Array.isArray(shardBytes)) {
      for (const item of shardBytes) {
        if (item.bytes instanceof Uint8Array) item.bytes.fill(0);
      }
    }
  }
}

export function renderSplitSummary(report) {
  const lines = [
    `Split: ${report.shards.length} shards in ${report.outDir}`,
    `ArchiveId: ${report.archiveId}`,
    `StateId: ${report.stateId}`,
    `CohortId: ${report.cohortId}`,
    `Geometry: n=${report.n} k=${report.k} m=${report.m} t=${report.t}`,
    `Archive policy: ${report.authPolicy.level} (min signatures ${report.authPolicy.minValidSignatures})`,
  ];
  lines.push('');
  return `${lines.join('\n')}`;
}
