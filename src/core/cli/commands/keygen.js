import { mkdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { generateKeyPair } from '../../crypto/index.js';
import { ML_KEM_1024_PRIVATE_KEY_SIZE, ML_KEM_1024_PUBLIC_KEY_SIZE } from '../../crypto/mlkem.js';
import { toHex } from '../../crypto/bytes.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';
import { writeArtifactSetAtomic } from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';
import { FILE_MODE } from '../lib/artifact-policy.js';
import { takeValue } from '../lib/args.js';

function digestSha3_512Hex(bytes) {
  return toHex(sha3_512(bytes));
}

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
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
  try {
    await mkdir(resolved);
    return resolved;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw usage(`--out parent directory does not exist: ${resolved}`);
    }
    throw error;
  }
}

function resolveKeygenPaths(outDir, name) {
  const prefix = String(name || '');
  return {
    publicKeyPath: path.join(outDir, `${prefix}publicKey.qkey`),
    privateKeyPath: path.join(outDir, `${prefix}privateKey.qkey`),
  };
}

async function preflightOverwrite(paths, force) {
  if (force) return;
  for (const filePath of [paths.publicKeyPath, paths.privateKeyPath]) {
    if (await pathExists(filePath)) {
      throw usage(`Refusing to overwrite existing file: ${filePath}`);
    }
  }
}

function normalizeSeedInfo(seedInfo) {
  return {
    source: seedInfo?.source || 'secure-random',
  };
}

function createKeygenReport({
  publicKeyPath,
  privateKeyPath,
  publicKeyBytes,
  privateKeyBytes,
  seedInfo,
}) {
  return {
    command: 'keygen',
    alg: { KEM: 'ML-KEM-1024' },
    publicKeyPath,
    privateKeyPath,
    publicKeyDigestHex: digestSha3_512Hex(publicKeyBytes),
    privateKeyDigestHex: digestSha3_512Hex(privateKeyBytes),
    publicKeyLength: publicKeyBytes.length,
    privateKeyLength: privateKeyBytes.length,
    seed: normalizeSeedInfo(seedInfo),
  };
}

export function parseKeygenArgs(args) {
  const options = {
    outDir: '',
    name: '',
    force: false,
    printPublic: false,
    json: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--out':
        options.outDir = takeValue(args, index, arg);
        index += 1;
        break;
      case '--name':
        options.name = takeValue(args, index, arg);
        index += 1;
        break;
      case '--force':
        options.force = true;
        break;
      case '--print-public':
        options.printPublic = true;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw usage(`Unknown keygen option: ${arg}`);
    }
  }

  if (!options.outDir) {
    throw usage('keygen requires --out <dir>');
  }
  if (options.name && /[/\\\0]/.test(options.name)) {
    throw usage('--name must be a filename prefix, not a path');
  }
  return options;
}

export async function runKeygenCommand(options) {
  await ensureRuntimeCrypto();

  let generatedPrivateKey = null;
  let privateKeyBytes = null;
  let publicKeyBytes = null;

  try {
    const outDir = await ensureOutputDirectory(options.outDir);
    const paths = resolveKeygenPaths(outDir, options.name);
    await preflightOverwrite(paths, options.force);

    const keyPair = await generateKeyPair({ collectUserEntropy: false });
    generatedPrivateKey = keyPair.privateKey;
    publicKeyBytes = new Uint8Array(keyPair.publicKey.length);
    privateKeyBytes = new Uint8Array(keyPair.privateKey.length);
    publicKeyBytes.set(keyPair.publicKey);
    privateKeyBytes.set(keyPair.privateKey);

    if (publicKeyBytes.length !== ML_KEM_1024_PUBLIC_KEY_SIZE) {
      throw new Error(`Generated public key length mismatch: expected ${ML_KEM_1024_PUBLIC_KEY_SIZE}, got ${publicKeyBytes.length}`);
    }
    if (privateKeyBytes.length !== ML_KEM_1024_PRIVATE_KEY_SIZE) {
      throw new Error(`Generated private key length mismatch: expected ${ML_KEM_1024_PRIVATE_KEY_SIZE}, got ${privateKeyBytes.length}`);
    }

    const report = createKeygenReport({
      ...paths,
      publicKeyBytes,
      privateKeyBytes,
      seedInfo: keyPair.seedInfo,
    });

    await writeArtifactSetAtomic([
      { path: paths.publicKeyPath, bytes: publicKeyBytes, mode: FILE_MODE.PUBLIC_ARTIFACT },
      { path: paths.privateKeyPath, bytes: privateKeyBytes, mode: FILE_MODE.SECRET_ARTIFACT },
    ], { force: options.force });

    return {
      report,
      publicKeyBase64: Buffer.from(publicKeyBytes).toString('base64'),
    };
  } catch (error) {
    if (error?.message === 'CSPRNG health check failed: consecutive outputs are identical') {
      throw makeQvError(error.message, QV_CODE.ENTROPY_FAILED, { cause: error });
    }
    throw error;
  } finally {
    if (generatedPrivateKey instanceof Uint8Array) {
      generatedPrivateKey.fill(0);
    }
    if (privateKeyBytes instanceof Uint8Array) {
      privateKeyBytes.fill(0);
    }
  }
}

export function renderKeygenSummary(report) {
  return [
    `Public key: ${report.publicKeyPath} (${report.publicKeyLength} B) SHA3-512=${report.publicKeyDigestHex}`,
    `Private key: ${report.privateKeyPath} (${report.privateKeyLength} B) SHA3-512=${report.privateKeyDigestHex}`,
    '',
  ].join('\n');
}
