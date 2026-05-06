import { readBytesFromFile } from './io.js';
import { QV_CODE, makeQvError } from './exit.js';

function hasSource(value) {
  return value !== undefined && value !== null && value !== false && String(value).length !== 0;
}

function assertSingleSecretSource({ filePath, stdin, envName }) {
  const selected = [
    hasSource(filePath),
    hasSource(stdin),
    hasSource(envName),
  ].filter(Boolean).length;
  if (selected === 0) {
    throw makeQvError('Secret input requires exactly one source: filePath, stdin, or envName', QV_CODE.USAGE);
  }
  if (selected > 1) {
    throw makeQvError('Secret input sources are mutually exclusive', QV_CODE.USAGE);
  }
}

function createSecret(bytes, source) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Secret bytes must be a Uint8Array');
  }
  let disposed = false;
  return {
    bytes,
    source,
    dispose() {
      if (!disposed) {
        bytes.fill(0);
        disposed = true;
      }
      return disposed;
    },
    get disposed() {
      return disposed;
    },
  };
}

async function readStreamBytes(stream) {
  if (stream instanceof Uint8Array) {
    return new Uint8Array(stream);
  }
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') {
    throw makeQvError('stdin secret source must be an async iterable byte stream', QV_CODE.USAGE);
  }
  const chunks = [];
  for await (const chunk of stream) {
    if (chunk instanceof Uint8Array) {
      chunks.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
      continue;
    }
    if (typeof chunk === 'string') {
      chunks.push(Buffer.from(chunk));
      continue;
    }
    throw makeQvError('stdin secret source yielded a non-byte chunk', QV_CODE.USAGE);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

function getEnvFilePath(envName, env) {
  const name = String(envName || '').trim();
  if (!name) {
    throw makeQvError('Secret env source requires an environment variable name', QV_CODE.USAGE);
  }
  if (!Object.hasOwn(env, name)) {
    throw makeQvError(`Secret environment variable ${name} is not set`, QV_CODE.USAGE);
  }
  const value = String(env[name] || '');
  if (!value) {
    throw makeQvError(`Secret environment variable ${name} is empty`, QV_CODE.USAGE);
  }
  if (/[\0\r\n]/.test(value)) {
    throw makeQvError(
      `Secret environment variable ${name} must contain a file path, not raw secret bytes`,
      QV_CODE.USAGE,
    );
  }
  return value;
}

export async function readSecretBytes({
  filePath = null,
  stdin = null,
  envName = null,
  env = process.env,
} = {}) {
  assertSingleSecretSource({ filePath, stdin, envName });

  if (hasSource(filePath)) {
    return createSecret(await readBytesFromFile(filePath), 'file');
  }

  if (hasSource(stdin)) {
    const stream = stdin === true ? process.stdin : stdin;
    return createSecret(await readStreamBytes(stream), 'stdin');
  }

  const name = String(envName || '').trim();
  const envFilePath = getEnvFilePath(name, env);
  try {
    return createSecret(await readBytesFromFile(envFilePath), 'env-file');
  } catch (error) {
    throw makeQvError(
      `Secret environment variable ${name} must contain a readable file path, not raw secret bytes`,
      QV_CODE.USAGE,
      { cause: error },
    );
  }
}
