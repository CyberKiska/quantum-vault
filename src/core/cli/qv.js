import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { startsWithAscii } from '../crypto/byte-prefix.js';
import { bytesEqual, toHex } from '../crypto/bytes.js';
import { parseOpenTimestampProof } from '../crypto/auth/opentimestamps.js';
import { unpackPqpk, unpackQsig } from '../crypto/auth/qsig.js';
import { isSupportedStellarSignatureDocumentBytes } from '../crypto/auth/stellar-sig.js';
import {
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeLifecycleBundle,
  canonicalizeSourceEvidence,
  canonicalizeTransitionRecord,
} from '../crypto/lifecycle/artifacts.js';
import { parseJsonBytesStrict } from '../crypto/manifest/strict-json.js';
import { canonicalizeJson } from '../crypto/manifest/jcs.js';
import {
  assessRestoreFromShards,
  verifyArchiveAuthenticity,
} from '../crypto/qcont/restore.js';
import { parseLifecycleShard } from '../crypto/qcont/lifecycle-shard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');

const JSON_ARTIFACT_DESCRIPTORS = Object.freeze({
  'quantum-vault-archive-state-descriptor/v1': {
    artifactType: 'archive-state-descriptor/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeArchiveStateDescriptor,
    objectField: 'archiveState',
  },
  'quantum-vault-cohort-binding/v1': {
    artifactType: 'cohort-binding/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeCohortBinding,
    objectField: 'cohortBinding',
  },
  'quantum-vault-transition-record/v1': {
    artifactType: 'transition-record/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeTransitionRecord,
    objectField: 'transitionRecord',
  },
  'quantum-vault-source-evidence/v1': {
    artifactType: 'source-evidence/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeSourceEvidence,
    objectField: 'sourceEvidence',
  },
});

function digestSha3_512Hex(bytes) {
  return toHex(sha3_512(bytes));
}

function normalizePathForMatch(value) {
  return String(value).split(path.sep).join('/');
}

function hasGlobPattern(value) {
  return /[*?[\]{}]/.test(String(value || ''));
}

function formatSuiteLabel(parsed) {
  if (typeof parsed?.suiteDisplay === 'string' && parsed.suiteDisplay) {
    return parsed.suiteDisplay;
  }
  if (typeof parsed?.suite === 'string' && parsed.suite) {
    return parsed.suite;
  }
  if (Number.isInteger(parsed?.suiteId)) {
    return `suiteId:${parsed.suiteId}`;
  }
  return 'unknown';
}

function formatVerifyStatusMessage(status = {}) {
  if (status.archiveApprovalSignatureVerified !== true) {
    return 'Archive-approval signatures not verified.';
  }
  const details = [];
  if (status.strongPqSignatureVerified === true) details.push('strong PQ present');
  if (status.bundlePinned === true) details.push('bundle pin active');
  if (status.userPinned === true) details.push('user pin matched');
  if (status.signerPinned === true && status.bundlePinned !== true && status.userPinned !== true) {
    details.push('signer pin active');
  }
  return details.length > 0
    ? `Archive-approval signatures verified (${details.join(', ')}).`
    : 'Archive-approval signatures verified.';
}

async function ensureRuntimeCrypto() {
  if (globalThis.crypto?.subtle) return;
  const { webcrypto } = await import(['node', 'crypto'].join(':'));
  globalThis.crypto = webcrypto;
}

async function ensureErasureRuntime() {
  if (globalThis.erasure?.split && globalThis.erasure?.recombine) {
    return;
  }

  const erasurePath = path.resolve(repoRoot, 'public/third-party/erasure.js');
  const erasureSource = await readFile(erasurePath, 'utf8');
  const cjsShim = { exports: {} };
  const evaluateErasure = new Function('module', 'exports', erasureSource);
  evaluateErasure(cjsShim, cjsShim.exports);
  globalThis.erasure = cjsShim.exports;
}

function classifyJsonArtifactObject(value) {
  const schema = String(value?.schema || '').trim();
  if (JSON_ARTIFACT_DESCRIPTORS[schema]) {
    return JSON_ARTIFACT_DESCRIPTORS[schema];
  }
  if (value?.type === 'QV-Lifecycle-Bundle') {
    return {
      artifactType: 'lifecycle-bundle/v1',
      artifactVersion: 'v1',
      canonicalize: canonicalizeLifecycleBundle,
      objectField: 'lifecycleBundle',
    };
  }
  return null;
}

async function inspectJsonArtifact(bytes, filePath) {
  const rawObject = parseJsonBytesStrict(bytes);
  const descriptor = classifyJsonArtifactObject(rawObject);
  if (!descriptor) {
    throw new Error(`Unsupported JSON artifact for inspect: ${filePath}`);
  }
  const canonicalized = await descriptor.canonicalize(rawObject);
  return {
    command: 'inspect',
    file: filePath,
    artifactType: descriptor.artifactType,
    artifactVersion: descriptor.artifactVersion,
    encoding: 'json',
    digestAlg: 'SHA3-512',
    digestHex: canonicalized.digest.value,
    inputDigestHex: digestSha3_512Hex(bytes),
    canonicalInput: bytesEqual(bytes, canonicalized.bytes),
    canonicalJson: canonicalized[descriptor.objectField],
    canonicalJsonText: canonicalized.canonical,
  };
}

async function inspectBinaryArtifact(bytes, filePath) {
  const inputDigestHex = digestSha3_512Hex(bytes);

  if (startsWithAscii(bytes, 'QVC1')) {
    const parsed = await parseLifecycleShard(bytes, { strict: true });
    return {
      command: 'inspect',
      file: filePath,
      artifactType: 'QVqcont-7',
      artifactVersion: 'QVqcont-7',
      encoding: 'binary',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      canonicalJson: parsed.metaJSON,
      canonicalJsonText: canonicalizeJson(parsed.metaJSON),
      parsedSummary: {
        archiveId: parsed.archiveState.archiveId,
        stateId: parsed.stateId,
        cohortId: parsed.cohortId,
        shardIndex: parsed.shardIndex,
        archiveStateDigestHex: parsed.archiveStateDigestHex,
        cohortBindingDigestHex: parsed.cohortBindingDigestHex,
        lifecycleBundleDigestHex: parsed.lifecycleBundleDigestHex,
      },
    };
  }

  if (startsWithAscii(bytes, 'PQSG')) {
    const parsed = unpackQsig(bytes);
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.qsig',
      artifactVersion: `v${parsed.versionMajor}.${parsed.versionMinor}`,
      encoding: 'binary',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        suite: formatSuiteLabel(parsed),
        suiteId: parsed.suiteId,
        context: parsed.ctx,
        payloadDigestAlg: 'SHA3-512',
        payloadDigestHex: toHex(parsed.payloadDigest),
        authMetaDigestAlg: 'SHA3-256',
        authMetaDigestHex: toHex(parsed.authMetaDigest),
        signatureLength: parsed.signatureLength,
        signerFingerprintHex: parsed.signerFingerprint ? toHex(parsed.signerFingerprint) : null,
        embeddedSignerPublicKey: parsed.metadata?.signerPublicKey instanceof Uint8Array,
      },
    };
  }

  if (startsWithAscii(bytes, 'PQPK')) {
    const parsed = unpackPqpk(bytes);
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.pqpk',
      artifactVersion: `v${parsed.versionMajor}.${parsed.versionMinor}`,
      encoding: 'binary',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        suite: formatSuiteLabel(parsed),
        suiteId: parsed.suiteId,
        keyLength: parsed.keyBytes.length,
        crc32Verified: true,
      },
    };
  }

  try {
    const parsed = parseOpenTimestampProof(bytes, { name: path.basename(filePath) });
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.ots',
      artifactVersion: 'OpenTimestamps-proof-v1',
      encoding: 'binary',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        stampedDigestAlg: 'SHA-256',
        stampedDigestHex: parsed.stampedDigestHex,
        apparentlyComplete: parsed.appearsComplete === true,
        completeProof: parsed.completeProof === true,
      },
    };
  } catch {
    // Continue.
  }

  if (isSupportedStellarSignatureDocumentBytes(bytes)) {
    const parsed = parseJsonBytesStrict(bytes);
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.sig',
      artifactVersion: 'stellar-detached-signature-v1',
      encoding: 'json',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        signer: typeof parsed?.signer === 'string' ? parsed.signer : null,
        hasSignedXdr: typeof parsed?.signedXdr === 'string' && parsed.signedXdr.length > 0,
        hasSep53Signature: typeof parsed?.signatureB64 === 'string' && parsed.signatureB64.length > 0,
      },
    };
  }

  throw new Error(`Unsupported artifact for inspect: ${filePath}`);
}

async function inspectArtifact(bytes, filePath) {
  try {
    return await inspectJsonArtifact(bytes, filePath);
  } catch (error) {
    if (!String(error?.message || error).startsWith('Unsupported JSON artifact')) {
      if (!(error instanceof Error) || !/JSON/.test(error.message)) {
        throw error;
      }
    }
  }
  return inspectBinaryArtifact(bytes, filePath);
}

async function canonicalizeArtifact(bytes, filePath) {
  const rawObject = parseJsonBytesStrict(bytes);
  const descriptor = classifyJsonArtifactObject(rawObject);
  if (!descriptor) {
    throw new Error(`Artifact is not canonicalizable JSON: ${filePath}`);
  }
  const canonicalized = await descriptor.canonicalize(rawObject);
  return {
    command: 'canonicalize',
    file: filePath,
    artifactType: descriptor.artifactType,
    artifactVersion: descriptor.artifactVersion,
    digestAlg: 'SHA3-512',
    digestHex: canonicalized.digest.value,
    canonicalBytes: canonicalized.bytes,
    canonicalJson: canonicalized[descriptor.objectField],
    canonicalJsonText: canonicalized.canonical,
  };
}

async function readBytesFromFile(filePath) {
  return new Uint8Array(await readFile(filePath));
}

function makeExternalArtifactRecord(filePath, bytes) {
  return {
    name: path.basename(filePath),
    bytes,
  };
}

async function readOptionalBytes(filePath) {
  if (!filePath) return null;
  return readBytesFromFile(filePath);
}

async function readVerificationInputsFromPaths({
  archiveStatePath = null,
  bundlePath = null,
  signaturePaths = [],
  pqpkPaths = [],
  otsPaths = [],
  expectedEd25519Signer = '',
} = {}) {
  const archiveStateBytes = archiveStatePath ? await readBytesFromFile(archiveStatePath) : null;
  const lifecycleBundleBytes = await readOptionalBytes(bundlePath);
  const signatures = await Promise.all(signaturePaths.map(async (filePath) => (
    makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath))
  )));
  const timestamps = await Promise.all(otsPaths.map(async (filePath) => (
    makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath))
  )));
  const pinnedPqPublicKeyFileBytesList = await Promise.all(pqpkPaths.map(readBytesFromFile));

  return {
    archiveStateBytes,
    lifecycleBundleBytes,
    verification: {
      signatures,
      timestamps,
      pinnedPqPublicKeyFileBytesList,
      expectedEd25519Signer: String(expectedEd25519Signer || '').trim(),
    },
  };
}

export async function verifyArchiveInputs({
  archiveStateBytes,
  lifecycleBundleBytes = null,
  verification = {},
} = {}) {
  await ensureRuntimeCrypto();
  return verifyArchiveAuthenticity({
    archiveStateBytes,
    lifecycleBundleBytes,
    verification,
  });
}

function buildRestoreDryRunSummary(result) {
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

function renderInspectSummary(report) {
  const lines = [
    `File: ${report.file}`,
    `Type: ${report.artifactType}`,
    `Version: ${report.artifactVersion}`,
    `SHA3-512: ${report.digestHex}`,
  ];
  if (typeof report.canonicalInput === 'boolean') {
    lines.push(`Canonical input: ${report.canonicalInput ? 'yes' : 'no'}`);
  }
  if (report.canonicalJsonText) {
    lines.push('');
    lines.push(report.canonicalJsonText);
  } else if (report.parsedSummary) {
    lines.push('');
    lines.push(JSON.stringify(report.parsedSummary, null, 2));
  }
  return `${lines.join('\n')}\n`;
}

function renderVerifySummary(authenticity) {
  const counts = authenticity?.verification?.counts || {};
  const policy = authenticity?.policy || {};
  const lines = [
    `Policy: ${policy.level || 'unknown'} (${policy.satisfied ? 'satisfied' : 'not satisfied'})`,
    `Reason: ${policy.reason || 'unknown'}`,
    formatVerifyStatusMessage(authenticity?.status || authenticity?.verification?.status || {}),
    `Archive-approval counts: valid=${counts.validArchiveApproval ?? 0}, strong-pq=${counts.validArchiveApprovalStrongPq ?? 0}, pinned=${counts.archiveApprovalPinnedValidTotal ?? 0}`,
    `Detached totals: valid=${counts.validTotal ?? 0}, maintenance=${counts.validMaintenance ?? 0}, source-evidence=${counts.validSourceEvidence ?? 0}`,
  ];
  for (const warning of authenticity?.warnings || []) {
    lines.push(`Warning: ${warning}`);
  }
  return `${lines.join('\n')}\n`;
}

function renderRestoreSummary(summary) {
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

async function collectFilesRecursive(dirPath) {
  const entries = await readdir(dirPath, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collectFilesRecursive(fullPath));
      continue;
    }
    if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

function resolveGlobBase(pattern, cwd) {
  const normalized = normalizePathForMatch(pattern);
  const absolute = path.isAbsolute(pattern);
  const segments = normalized.split('/').filter(Boolean);
  const baseSegments = [];
  for (const segment of segments) {
    if (hasGlobPattern(segment)) break;
    baseSegments.push(segment);
  }
  if (absolute) {
    return baseSegments.length > 0 ? path.resolve(path.sep, ...baseSegments) : path.sep;
  }
  return baseSegments.length > 0 ? path.resolve(cwd, ...baseSegments) : cwd;
}

async function expandFilePattern(pattern, cwd) {
  const resolved = path.resolve(cwd, pattern);
  if (!hasGlobPattern(pattern)) {
    return [resolved];
  }

  const baseDir = resolveGlobBase(pattern, cwd);
  const candidates = await collectFilesRecursive(baseDir);
  const matcher = path.isAbsolute(pattern)
    ? normalizePathForMatch(pattern)
    : normalizePathForMatch(pattern);

  return candidates.filter((candidate) => {
    const normalizedCandidate = normalizePathForMatch(path.isAbsolute(pattern) ? candidate : path.relative(cwd, candidate));
    return path.matchesGlob(normalizedCandidate, matcher);
  }).sort((left, right) => left.localeCompare(right));
}

function dedupeSorted(values) {
  return [...new Set(values.map((value) => path.resolve(value)))].sort((left, right) => left.localeCompare(right));
}

function createJsonError(command, error) {
  return {
    command,
    ok: false,
    error: error?.message || String(error),
  };
}

function writeText(stream, text) {
  stream.write(text);
}

function writeJson(stream, value) {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

function takeValue(args, index, flag) {
  if (index + 1 >= args.length) {
    throw new Error(`${flag} requires a value`);
  }
  return args[index + 1];
}

function parseGlobalJsonFlag(args) {
  return args.includes('--json');
}

function parseSingleFileCommandArgs(command, args) {
  if (args.length === 0 || args[0] === '--json') {
    throw new Error(`${command} requires <artifact-file>`);
  }
  const filePath = args[0];
  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--json') {
      continue;
    }
    throw new Error(`Unknown ${command} option: ${arg}`);
  }
  return { filePath };
}

function parseVerifyArgs(args) {
  if (args.length === 0) {
    throw new Error('verify requires <archive-state.json>');
  }
  const archiveStatePath = args[0];
  const options = {
    archiveStatePath,
    bundlePath: null,
    signaturePaths: [],
    pqpkPaths: [],
    otsPaths: [],
    expectedEd25519Signer: '',
    json: false,
  };

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
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
      case '--json':
        options.json = true;
        break;
      default:
        throw new Error(`Unknown verify option: ${arg}`);
    }
  }
  return options;
}

function parseRestoreArgs(args) {
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

export async function runInspectCommand(filePath) {
  await ensureRuntimeCrypto();
  const bytes = await readBytesFromFile(filePath);
  return inspectArtifact(bytes, filePath);
}

export async function runCanonicalizeCommand(filePath) {
  await ensureRuntimeCrypto();
  const bytes = await readBytesFromFile(filePath);
  return canonicalizeArtifact(bytes, filePath);
}

export async function runVerifyCommand(options) {
  const inputs = await readVerificationInputsFromPaths(options);
  return verifyArchiveInputs(inputs);
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

function helpText() {
  return [
    'Quantum Vault CLI',
    '',
    'Commands:',
    '  qv inspect <artifact-file> [--json]',
    '  qv canonicalize <artifact-file> [--json]',
    '  qv verify <archive-state.json> [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--json]',
    '  qv restore --shards <glob-or-file> [--shards <glob-or-file>] [--archive-state <file>] [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] --dry-run [--json]',
    '',
    'Phase 1 scope:',
    '  restore is read-only and requires --dry-run',
    '  attach and write-mode restore are out of scope',
    '',
  ].join('\n');
}

export async function runQvCli(argv, {
  cwd = process.cwd(),
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  const args = [...argv];
  const command = String(args.shift() || '').trim();

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    writeText(stdout, `${helpText()}\n`);
    return 0;
  }

  const json = parseGlobalJsonFlag(args);

  try {
    if (command === 'inspect') {
      const { filePath } = parseSingleFileCommandArgs('inspect', args);
      const report = await runInspectCommand(filePath);
      if (json) {
        writeJson(stdout, report);
      } else {
        writeText(stdout, renderInspectSummary(report));
      }
      return 0;
    }

    if (command === 'canonicalize') {
      const { filePath } = parseSingleFileCommandArgs('canonicalize', args);
      const report = await runCanonicalizeCommand(filePath);
      if (json) {
        writeJson(stdout, {
          command: report.command,
          file: report.file,
          artifactType: report.artifactType,
          artifactVersion: report.artifactVersion,
          digestAlg: report.digestAlg,
          digestHex: report.digestHex,
          canonicalJson: report.canonicalJson,
          canonicalJsonText: report.canonicalJsonText,
        });
      } else {
        stdout.write(Buffer.from(report.canonicalBytes));
      }
      return 0;
    }

    if (command === 'verify') {
      const options = parseVerifyArgs(args);
      const authenticity = await runVerifyCommand(options);
      if (options.json) {
        writeJson(stdout, authenticity);
      } else {
        writeText(stdout, renderVerifySummary(authenticity));
      }
      return authenticity?.policy?.satisfied === true ? 0 : 1;
    }

    if (command === 'restore') {
      const options = parseRestoreArgs(args);
      const summary = await runRestoreDryRunCommand(options, { cwd });
      if (options.json) {
        writeJson(stdout, summary);
      } else {
        writeText(stdout, renderRestoreSummary(summary));
      }
      return summary.wouldSucceed === true ? 0 : 1;
    }

    throw new Error(`Unknown command: ${command}`);
  } catch (error) {
    if (json) {
      writeJson(stdout, createJsonError(command, error));
    } else {
      writeText(stderr, `${error?.message || error}\n`);
    }
    return 1;
  }
}
