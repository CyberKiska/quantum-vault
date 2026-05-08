import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../crypto/bytes.js';
import { VENDORED_ERASURE_JS_SHA3_512 } from '../../crypto/policy.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../../..');

/** Serialize concurrent init when programmatic callers invoke CLI commands in parallel. */
let cryptoInstallPromise = null;
let erasureInstallPromise = null;

export async function ensureRuntimeCrypto() {
  if (globalThis.crypto?.subtle) return;
  cryptoInstallPromise ??= Promise.resolve().then(() => {
    globalThis.crypto = webcrypto;
  });
  await cryptoInstallPromise;
}

async function loadVendoredErasureIntoGlobal() {
  const erasurePath = path.resolve(repoRoot, 'public/third-party/erasure.js');
  const erasureSource = await readFile(erasurePath, 'utf8');
  const erasureBytes = new TextEncoder().encode(erasureSource);
  const erasureDigestHex = toHex(sha3_512(erasureBytes));
  if (erasureDigestHex !== VENDORED_ERASURE_JS_SHA3_512) {
    throw new Error(
      `Vendored erasure.js integrity check failed: expected ${VENDORED_ERASURE_JS_SHA3_512}, got ${erasureDigestHex}`
    );
  }
  const cjsShim = { exports: {} };
  const evaluateErasure = new Function('module', 'exports', erasureSource);
  evaluateErasure(cjsShim, cjsShim.exports);
  globalThis.erasure = cjsShim.exports;
}

export async function ensureErasureRuntime() {
  if (globalThis.erasure?.split && globalThis.erasure?.recombine) {
    return;
  }
  erasureInstallPromise ??= loadVendoredErasureIntoGlobal();
  await erasureInstallPromise;
}
