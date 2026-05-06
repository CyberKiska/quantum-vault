import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../../..');

export async function ensureRuntimeCrypto() {
  if (globalThis.crypto?.subtle) return;
  const { webcrypto } = await import(['node', 'crypto'].join(':'));
  globalThis.crypto = webcrypto;
}

export async function ensureErasureRuntime() {
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
