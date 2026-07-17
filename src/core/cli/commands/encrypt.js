import { stat } from 'node:fs/promises';
import path from 'node:path';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { encryptFile } from '../../crypto/index.js';
import { toHex } from '../../crypto/bytes.js';
import { parseQencHeader } from '../../crypto/qenc/format.js';
import {
  buildQvpackPayloadBytes,
  isQvpackPayload,
  parseQvpackPayload,
} from '../../crypto/qvpack.js';
import { validatePublicKey } from '../../crypto/mlkem.js';
import { MAX_FILE_SIZE } from '../../crypto/constants.js';
import { takeValue } from '../lib/args.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';
import { readBytesFromFile, writeBytesAtomic } from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';
import { FILE_MODE, smallArtifactReadOptions } from '../lib/artifact-policy.js';

const LARGE_INPUT_WARNING_THRESHOLD = 256 * 1024 * 1024;

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

function formatPolicy(message, cause) {
  return makeQvError(message, QV_CODE.FORMAT_POLICY_REJECT, { cause });
}

function keyRejected(message, cause) {
  return makeQvError(message, QV_CODE.KEY_REJECTED, { cause });
}

function digestSha3_512Hex(bytes) {
  return toHex(sha3_512(bytes));
}

function basenameOnly(filePath) {
  return path.basename(filePath);
}

function validateEmbeddedFilename(name, label) {
  if (typeof name !== 'string' || name.length === 0) {
    throw usage(`${label} must be a non-empty filename`);
  }
  if (/[/\\\0]/.test(name)) {
    throw usage(`${label} must be a filename, not a path`);
  }
  return name;
}

function validateOutputPath(outPath) {
  if (!outPath) {
    throw usage('encrypt requires --out <output.qenc>');
  }
  if (outPath.includes('\0')) {
    throw usage('--out contains an invalid NUL byte');
  }
}

async function ensureOutputParentExists(outPath) {
  const parent = path.dirname(path.resolve(outPath));
  try {
    const stats = await stat(parent);
    if (!stats.isDirectory()) {
      throw usage(`--out parent is not a directory: ${parent}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`--out parent directory does not exist: ${parent}`);
    }
    throw error;
  }
}

async function statInput(filePath) {
  try {
    const stats = await stat(filePath);
    if (!stats.isFile()) {
      throw usage(`Input path is not a file: ${filePath}`);
    }
    return stats;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`Input file does not exist: ${filePath}`);
    }
    throw error;
  }
}

async function readPublicKeyBytes(publicKeyPath) {
  try {
    return await readBytesFromFile(publicKeyPath, smallArtifactReadOptions('Public key file'));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`Public key file does not exist: ${publicKeyPath}`);
    }
    throw error;
  }
}

function classifyEncryptError(error) {
  const message = error?.message || String(error);
  if (/Invalid ML-KEM-1024 public key length|Public key must be Uint8Array/.test(message)) {
    return keyRejected(message, error);
  }
  if (/Refusing to overwrite existing file/.test(message)) {
    return usage(message);
  }
  if (/exceeds maximum allowed size|fileBytes must be a non-empty Uint8Array|Invalid private metadata|QVPACK/.test(message)) {
    return formatPolicy(message, error);
  }
  return error;
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

function parsePayloadInputs(args) {
  const inputs = [];
  const options = {
    inputPaths: inputs,
    publicKeyPath: '',
    outPath: '',
    filename: '',
    force: false,
    json: false,
    pack: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--public-key':
        options.publicKeyPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--out':
        options.outPath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--filename':
        options.filename = takeValue(args, index, arg);
        index += 1;
        break;
      case '--force':
        options.force = true;
        break;
      case '--json':
        options.json = true;
        break;
      case '--pack':
        options.pack = true;
        break;
      default:
        if (arg.startsWith('--')) {
          throw usage(`Unknown encrypt option: ${arg}`);
        }
        inputs.push(arg);
    }
  }

  return options;
}

function validateEncryptOptions(options) {
  if (options.inputPaths.length === 0) {
    throw usage('encrypt requires <input-file>');
  }
  if (!options.publicKeyPath) {
    throw usage('encrypt requires --public-key <publicKey.qkey>');
  }
  validateOutputPath(options.outPath);

  if (options.pack) {
    if (options.inputPaths.length < 2) {
      throw usage('encrypt --pack requires at least two input files');
    }
    if (options.filename && !options.filename.endsWith('.qvpack')) {
      throw usage('encrypt --pack --filename must end with .qvpack');
    }
  } else if (options.inputPaths.length !== 1) {
    throw usage('encrypt accepts one input file unless --pack is supplied');
  }

  if (options.filename) {
    validateEmbeddedFilename(options.filename, '--filename');
  }
}

export function parseEncryptArgs(args) {
  const options = parsePayloadInputs(args);
  validateEncryptOptions(options);
  return options;
}

async function readSinglePayload(options) {
  const inputPath = options.inputPaths[0];
  const stats = await statInput(inputPath);
  const bytes = await readBytesFromFile(inputPath);
  const isPackPayload = isQvpackPayload(bytes);
  const fileCount = isPackPayload ? parseQvpackPayload(bytes).length : 1;
  return {
    payloadBytes: bytes,
    inputSize: stats.size,
    originalFilename: options.filename || validateEmbeddedFilename(basenameOnly(inputPath), 'input filename'),
    payloadKind: isPackPayload ? 'qvpack' : 'file',
    fileCount,
    packedInputPaths: [],
  };
}

async function readPackedPayload(options) {
  const seenNames = new Set();
  const entries = [];
  let inputSize = 0;

  try {
    for (const inputPath of options.inputPaths) {
      const stats = await statInput(inputPath);
      const name = validateEmbeddedFilename(basenameOnly(inputPath), 'pack entry filename');
      if (seenNames.has(name)) {
        throw usage(`encrypt --pack refuses duplicate entry filename: ${name}`);
      }
      seenNames.add(name);
      const bytes = await readBytesFromFile(inputPath);
      inputSize += stats.size;
      entries.push({ name, bytes });
    }

    const bundleName = options.filename || 'bundle.qvpack';
    return {
      payloadBytes: buildQvpackPayloadBytes(entries),
      inputSize,
      originalFilename: bundleName,
      payloadKind: 'qvpack',
      fileCount: entries.length,
      packedInputPaths: [...options.inputPaths],
    };
  } finally {
    for (const entry of entries) {
      if (entry.bytes instanceof Uint8Array) entry.bytes.fill(0);
    }
  }
}

async function readPayload(options) {
  return options.pack ? readPackedPayload(options) : readSinglePayload(options);
}

function validateAndClonePublicKey(bytes) {
  try {
    validatePublicKey(bytes);
  } catch (error) {
    throw keyRejected(error?.message || String(error), error);
  }
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  return out;
}

function buildEncryptReport({
  options,
  payload,
  payloadBytes,
  qencBytes,
}) {
  const parsed = parseQencHeader(qencBytes);
  const metadata = parsed.metadata;
  return {
    command: 'encrypt',
    alg: {
      KEM: metadata.KEM,
      KDF: metadata.KDF,
      AEAD: metadata.AEAD,
    },
    inputPath: options.pack ? null : options.inputPaths[0],
    inputPaths: [...options.inputPaths],
    outputPath: path.resolve(options.outPath),
    publicKeyPath: path.resolve(options.publicKeyPath),
    fmt: metadata.fmt,
    aeadMode: metadata.aead_mode,
    chunkSize: metadata.chunkSize,
    chunkCount: metadata.chunkCount,
    payloadLength: metadata.payloadLength,
    plaintextLength: payloadBytes.length,
    inputLength: payload.inputSize,
    containerHashAlg: 'SHA3-512',
    containerHashHex: digestSha3_512Hex(qencBytes),
    containerId: digestSha3_512Hex(parsed.header),
    fileHashHex: digestSha3_512Hex(payloadBytes),
    originalFilename: payload.originalFilename,
    payloadKind: payload.payloadKind,
    fileCount: payload.fileCount,
  };
}

export async function runEncryptCommand(options) {
  await ensureRuntimeCrypto();
  await ensureOutputParentExists(options.outPath);

  let payload = null;
  let payloadBytes = null;
  let publicKeyBytes = null;
  let qencBytes = null;

  try {
    publicKeyBytes = validateAndClonePublicKey(await readPublicKeyBytes(options.publicKeyPath));
    payload = await readPayload(options);
    payloadBytes = payload.payloadBytes;
    if (payloadBytes.length > MAX_FILE_SIZE) {
      throw formatPolicy(
        `File size ${payloadBytes.length} exceeds maximum allowed size (${MAX_FILE_SIZE} bytes)`
      );
    }

    const encryptedBlob = await encryptFile(payloadBytes, publicKeyBytes, payload.originalFilename);
    qencBytes = await blobToBytes(encryptedBlob);
    const report = buildEncryptReport({
      options,
      payload,
      payloadBytes,
      qencBytes,
    });

    await writeBytesAtomic(options.outPath, qencBytes, {
      mode: FILE_MODE.PUBLIC_ARTIFACT,
      force: options.force,
    });

    const warnings = [];
    if (payload.inputSize >= LARGE_INPUT_WARNING_THRESHOLD) {
      warnings.push('Input was encrypted with the in-memory CLI path; Node.js memory zeroization is best-effort and true streaming is deferred.');
    }
    if (options.pack) {
      warnings.push('.qvpack is a pre-encryption multi-file payload; restore tooling must detect QVB1 magic after decryption, not rely on filename alone.');
    }
    return warnings.length > 0 ? { ...report, warnings } : report;
  } catch (error) {
    throw classifyEncryptError(error);
  } finally {
    if (publicKeyBytes instanceof Uint8Array) publicKeyBytes.fill(0);
    if (qencBytes instanceof Uint8Array) qencBytes.fill(0);
    if (payloadBytes instanceof Uint8Array) payloadBytes.fill(0);
  }
}

export function renderEncryptSummary(report) {
  const lines = [
    `Encrypted: ${report.outputPath}`,
    `Input: ${report.payloadKind === 'qvpack' ? `${report.fileCount} files packed as ${report.originalFilename}` : report.inputPath}`,
    `Container: ${report.fmt} ${report.aeadMode} chunks=${report.chunkCount} SHA3-512=${report.containerHashHex}`,
    `Plaintext SHA3-512: ${report.fileHashHex}`,
  ];
  if (Array.isArray(report.warnings)) {
    for (const warning of report.warnings) {
      lines.push(`Warning: ${warning}`);
    }
  }
  lines.push('');
  return `${lines.join('\n')}`;
}
