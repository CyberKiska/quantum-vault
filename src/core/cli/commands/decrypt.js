import { stat } from 'node:fs/promises';
import path from 'node:path';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { decryptFile } from '../../crypto/index.js';
import { toHex } from '../../crypto/bytes.js';
import { parseQencHeader } from '../../crypto/qenc/format.js';
import { isQvpackPayload, parseQvpackPayload } from '../../crypto/qvpack.js';
import { validatePrivateKey } from '../../crypto/mlkem.js';
import { takeValue } from '../lib/args.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';
import { readBytesFromFile, writeBytesAtomic } from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';
import { readSecretBytes } from '../lib/secrets.js';

const MAX_OUTPUT_FILENAME_BYTES = 255;

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

function formatPolicy(message, cause) {
  return makeQvError(message, QV_CODE.FORMAT_POLICY_REJECT, { cause });
}

function keyRejected(message, cause) {
  return makeQvError(message, QV_CODE.KEY_REJECTED, { cause });
}

function aeadFailed(cause) {
  return makeQvError(
    'Decrypt authentication failed: invalid private key or tampered container',
    QV_CODE.AEAD_FAILED,
    { cause },
  );
}

function restoredIntegrityFailed(message, cause) {
  return makeQvError(message, QV_CODE.RESTORED_INTEGRITY_FAILED, { cause });
}

function digestSha3_512Hex(bytes) {
  return toHex(sha3_512(bytes));
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

async function ensureFile(filePath, label) {
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

async function ensureDirectory(dirPath, label) {
  try {
    const stats = await stat(dirPath);
    if (!stats.isDirectory()) {
      throw usage(`${label} is not a directory: ${dirPath}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`${label} does not exist: ${dirPath}`);
    }
    throw error;
  }
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

async function ensureOutputParentExists(outPath) {
  await ensureDirectory(path.dirname(path.resolve(outPath)), '--out parent directory');
}

function sanitizeRecoveredFilename(name, label = 'original filename') {
  if (typeof name !== 'string' || name.length === 0) {
    throw usage(`Recovered ${label} is missing`);
  }
  if (name === '.' || name === '..' || name.startsWith('.')) {
    throw usage(`Recovered ${label} is not safe for output`);
  }
  if (/[/\\\0]|[\u0000-\u001f\u007f]/.test(name)) {
    throw usage(`Recovered ${label} contains unsafe characters`);
  }
  const encoded = new TextEncoder().encode(name);
  if (encoded.length === 0 || encoded.length > MAX_OUTPUT_FILENAME_BYTES) {
    throw usage(`Recovered ${label} exceeds ${MAX_OUTPUT_FILENAME_BYTES} UTF-8 bytes`);
  }
  return name;
}

function parseDecryptInputs(args) {
  const inputs = [];
  const options = {
    inputPath: '',
    privateKeyPath: '',
    privateKeyStdin: false,
    privateKeyEnv: '',
    outPath: '',
    outDir: '',
    useOriginalFilename: false,
    extractQvpack: false,
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
      case '--out':
        options.outPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--out-dir':
        options.outDir = takeValue(args, index, arg);
        index += 1;
        break;
      case '--use-original-filename':
        options.useOriginalFilename = true;
        break;
      case '--extract-qvpack':
        options.extractQvpack = true;
        break;
      case '--force':
        options.force = true;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        if (arg.startsWith('--')) {
          throw usage(`Unknown decrypt option: ${arg}`);
        }
        inputs.push(arg);
    }
  }

  if (inputs.length !== 1) {
    throw usage('decrypt requires exactly one <input.qenc>');
  }
  options.inputPath = inputs[0];
  return options;
}

function validateDecryptOptions(options) {
  const keySources = [
    Boolean(options.privateKeyPath),
    options.privateKeyStdin,
    Boolean(options.privateKeyEnv),
  ].filter(Boolean).length;
  if (keySources !== 1) {
    throw usage('decrypt requires exactly one private key source');
  }
  if (options.outPath && options.outDir) {
    throw usage('decrypt accepts --out or --out-dir, not both');
  }
  if (options.outPath && options.useOriginalFilename) {
    throw usage('decrypt --use-original-filename cannot be combined with --out');
  }
  if (options.extractQvpack && !options.outDir) {
    throw usage('decrypt --extract-qvpack requires --out-dir <dir>');
  }
  if (options.extractQvpack && options.outPath) {
    throw usage('decrypt --extract-qvpack cannot be combined with --out');
  }
  if (options.outPath?.includes('\0') || options.outDir?.includes('\0')) {
    throw usage('decrypt output path contains an invalid NUL byte');
  }
}

export function parseDecryptArgs(args) {
  const options = parseDecryptInputs(args);
  validateDecryptOptions(options);
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

function classifyDecryptError(error) {
  if (typeof error?.qvCode === 'string') return error;

  const message = error?.message || String(error);
  if (/Invalid ML-KEM-1024 private key length|Private key must be Uint8Array/.test(message)) {
    return keyRejected(message, error);
  }
  if (/Refusing to overwrite existing file/.test(message)) {
    return usage(message);
  }
  if (/Invalid file format|File is too small|Unsupported container format|Invalid metadata|Incomplete container|Invalid container|Unsupported AEAD mode|QVPACK/.test(message)) {
    return formatPolicy(message, error);
  }
  if (/Key commitment verification failed|KEM decapsulation failed|operation-specific|decrypt|ciphertext|Encrypted payload/.test(message)) {
    return aeadFailed(error);
  }
  return error;
}

function resolveDefaultOutputPath(inputPath) {
  return path.resolve(`${inputPath}.decrypted`);
}

function resolveOutputPath(options, metadata) {
  if (options.outPath) {
    return path.resolve(options.outPath);
  }
  if (options.outDir || options.useOriginalFilename) {
    const dir = path.resolve(options.outDir || path.dirname(options.inputPath));
    const name = sanitizeRecoveredFilename(metadata.originalFilename, 'original filename');
    return path.join(dir, name);
  }
  return resolveDefaultOutputPath(options.inputPath);
}

function createQvpackEntryReports(entries, outputPathByName = new Map()) {
  return entries.map((entry) => ({
    name: entry.name,
    size: entry.bytes.length,
    fileHashHex: digestSha3_512Hex(entry.bytes),
    outputPath: outputPathByName.get(entry.name) || null,
  }));
}

async function writeExtractedQvpack({ entries, outDir, force }) {
  await ensureDirectory(outDir, '--out-dir');
  const seen = new Set();
  const outputPathByName = new Map();
  const planned = [];

  for (const entry of entries) {
    const safeName = sanitizeRecoveredFilename(entry.name, 'QVPACK entry filename');
    if (seen.has(safeName)) {
      throw usage(`QVPACK contains duplicate output filename: ${safeName}`);
    }
    seen.add(safeName);
    const outPath = path.join(path.resolve(outDir), safeName);
    planned.push({ entry, outPath });
    outputPathByName.set(entry.name, outPath);
  }

  if (!force) {
    for (const { outPath } of planned) {
      if (await pathExists(outPath)) {
        throw usage(`Refusing to overwrite existing file: ${outPath}`);
      }
    }
  }

  for (const { entry, outPath } of planned) {
    await writeBytesAtomic(outPath, entry.bytes, {
      mode: 0o600,
      force,
    });
  }
  return outputPathByName;
}

function verifyPlaintextHash(metadata, plaintextBytes) {
  const fileHashHex = digestSha3_512Hex(plaintextBytes);
  if (typeof metadata.fileHash === 'string' && metadata.fileHash !== fileHashHex) {
    throw restoredIntegrityFailed('Decrypted plaintext hash does not match authenticated private metadata');
  }
  return fileHashHex;
}

function buildDecryptReport({
  options,
  parsedHeader,
  metadata,
  qencBytes,
  plaintextBytes,
  fileHashHex,
  outputPath,
  outputPaths,
  payloadKind,
  qvpackEntries,
  qvpackExtracted,
}) {
  return {
    command: 'decrypt',
    inputPath: options.inputPath,
    outputPath,
    outputPaths,
    alg: {
      KEM: metadata.KEM,
      KDF: metadata.KDF,
      AEAD: metadata.AEAD,
    },
    fmt: metadata.fmt,
    aeadMode: metadata.aead_mode,
    chunkSize: metadata.chunkSize,
    chunkCount: metadata.chunkCount,
    payloadLength: metadata.payloadLength,
    plaintextLength: plaintextBytes.length,
    originalFilename: metadata.originalFilename ?? null,
    fileHashHex,
    containerHashAlg: 'SHA3-512',
    containerHashHex: digestSha3_512Hex(qencBytes),
    containerId: digestSha3_512Hex(parsedHeader.header),
    payloadKind,
    fileCount: payloadKind === 'qvpack' ? qvpackEntries.length : 1,
    qvpackExtracted,
    qvpackEntries: payloadKind === 'qvpack' ? qvpackEntries : [],
  };
}

export async function runDecryptCommand(options, {
  stdin = process.stdin,
  env = process.env,
} = {}) {
  await ensureRuntimeCrypto();
  await ensureFile(options.inputPath, 'Input file');
  if (options.outDir) {
    await ensureDirectory(options.outDir, '--out-dir');
  }
  if (options.outPath) {
    await ensureOutputParentExists(options.outPath);
  }

  let secret = null;
  let privateKeyBytes = null;
  let plaintextBytes = null;

  try {
    const qencBytes = await readBytesFromFile(options.inputPath);
    const parsedHeader = parseQencHeader(qencBytes);
    secret = await readSecretBytes({
      filePath: options.privateKeyPath || null,
      stdin: options.privateKeyStdin ? stdin : null,
      envName: options.privateKeyEnv || null,
      env,
    });
    privateKeyBytes = validateAndClonePrivateKey(secret.bytes);

    const { decryptedBlob, metadata } = await decryptFile(qencBytes, privateKeyBytes);
    plaintextBytes = await blobToBytes(decryptedBlob);
    const fileHashHex = verifyPlaintextHash(metadata, plaintextBytes);
    const isPack = isQvpackPayload(plaintextBytes);
    const entries = isPack ? parseQvpackPayload(plaintextBytes) : [];
    let outputPath = null;
    let outputPaths = [];
    let outputPathByEntryName = new Map();

    if (options.extractQvpack) {
      if (!isPack) {
        throw formatPolicy('decrypt --extract-qvpack requires a decrypted QVPACK payload');
      }
      outputPathByEntryName = await writeExtractedQvpack({
        entries,
        outDir: options.outDir,
        force: options.force,
      });
      outputPaths = entries.map((entry) => outputPathByEntryName.get(entry.name));
    } else {
      outputPath = resolveOutputPath(options, metadata);
      await ensureOutputParentExists(outputPath);
      await writeBytesAtomic(outputPath, plaintextBytes, {
        mode: 0o600,
        force: options.force,
      });
      outputPaths = [outputPath];
    }

    return buildDecryptReport({
      options,
      parsedHeader,
      metadata,
      qencBytes,
      plaintextBytes,
      fileHashHex,
      outputPath,
      outputPaths,
      payloadKind: isPack ? 'qvpack' : 'file',
      qvpackEntries: createQvpackEntryReports(entries, outputPathByEntryName),
      qvpackExtracted: options.extractQvpack,
    });
  } catch (error) {
    throw classifyDecryptError(error);
  } finally {
    secret?.dispose();
    if (privateKeyBytes instanceof Uint8Array) privateKeyBytes.fill(0);
    if (plaintextBytes instanceof Uint8Array) plaintextBytes.fill(0);
  }
}

export function renderDecryptSummary(report) {
  const lines = [
    report.qvpackExtracted
      ? `Decrypted and extracted: ${report.outputPaths.length} files`
      : `Decrypted: ${report.outputPath}`,
    `Input: ${report.inputPath}`,
    `Container: ${report.fmt} ${report.aeadMode} chunks=${report.chunkCount} SHA3-512=${report.containerHashHex}`,
    `Plaintext SHA3-512: ${report.fileHashHex}`,
  ];
  if (report.payloadKind === 'qvpack') {
    lines.push(`QVPACK entries: ${report.fileCount}`);
  }
  lines.push('');
  return `${lines.join('\n')}`;
}
