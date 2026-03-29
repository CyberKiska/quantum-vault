// App-layer crypto service boundary.
// UI modules should consume these high-level operations instead of importing core primitives directly.

import {
    decryptFile as decryptContainerBytes,
    encryptFile as encryptContainerBytes,
    generateKeyPair as generateMlKemKeyPair,
    hashBytes as computeHashHex,
} from '../core/crypto/index.js';
import { buildQcontShards as buildLegacyShardSet } from '../core/crypto/qcont/build.js';
import { attachManifestBundleToShards as attachShardBundle } from '../core/crypto/qcont/attach.js';
import { attachLifecycleBundleToShards as attachLifecycleShardBundle } from '../core/crypto/qcont/lifecycle-attach.js';
import {
    buildLifecycleQcontShards as buildSuccessorShardSet,
    parseLifecycleShard as parseLifecycleQcontShardBytes,
    reshareSameState as reshareSameStateShardSet,
} from '../core/crypto/qcont/lifecycle-shard.js';
import { parseShard as parseQcontShardBytes, restoreFromShards as restoreShardSet } from '../core/crypto/qcont/restore.js';
import {
    assessShardSelection as assessSelectedShards,
    parseQcontShardPreviewFile as parseShardPreviewFile,
} from './shard-preview.js';

function detectShardFormat(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 6) return 'unknown';
    const magic = new TextDecoder().decode(bytes.subarray(0, 4));
    if (magic !== 'QVC1') return 'unknown';
    const metaLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(4, false);
    const metaEnd = 6 + metaLen;
    if (metaLen <= 0 || metaEnd > bytes.length) return 'unknown';
    try {
        const metaJSON = JSON.parse(new TextDecoder().decode(bytes.subarray(6, metaEnd)));
        return String(metaJSON?.alg?.fmt || '').trim();
    } catch {
        return 'unknown';
    }
}

function requireErasureRuntime() {
    const runtime = globalThis.erasure;
    if (!runtime?.split || !runtime?.recombine) {
        throw new Error('Reed-Solomon runtime (globalThis.erasure) is unavailable. Ensure erasure.js is loaded.');
    }
    return runtime;
}

export async function generateKeyPair(options = {}) {
    return generateMlKemKeyPair(options);
}

export async function encryptFile(fileBytes, publicKey, originalFilename) {
    return encryptContainerBytes(fileBytes, publicKey, originalFilename);
}

export async function decryptFile(containerBytes, privateKey) {
    return decryptContainerBytes(containerBytes, privateKey);
}

export async function hashBytes(bytes) {
    return computeHashHex(bytes);
}

export async function buildQcontShards(qencBytes, privKeyBytes, params, options = {}) {
    const erasureRuntime = requireErasureRuntime();
    const artifactFamily = String(options.artifactFamily || 'successor').trim().toLowerCase();
    if (artifactFamily === 'successor') {
        return buildSuccessorShardSet(qencBytes, privKeyBytes, params, { ...options, erasureRuntime });
    }
    if (artifactFamily === 'legacy') {
        return buildLegacyShardSet(qencBytes, privKeyBytes, params, { ...options, erasureRuntime });
    }
    throw new Error(`Unsupported shard artifactFamily "${options.artifactFamily}"`);
}

export async function attachManifestBundleToShards(shards, options = {}) {
    return attachShardBundle(shards, options);
}

export async function attachLifecycleBundleToShards(shards, options = {}) {
    return attachLifecycleShardBundle(shards, options);
}

export function parseShard(bytes, options = {}) {
    return parseQcontShardBytes(bytes, options);
}

export async function parseLifecycleShard(bytes, options = {}) {
    return parseLifecycleQcontShardBytes(bytes, options);
}

export async function reshareSameState(shards, params, options = {}) {
    const erasureRuntime = requireErasureRuntime();
    return reshareSameStateShardSet(shards, params, { ...options, erasureRuntime });
}

export async function parseShardForRestore(bytes, options = {}) {
    return detectShardFormat(bytes) === 'QVqcont-7'
        ? parseLifecycleQcontShardBytes(bytes, options)
        : parseQcontShardBytes(bytes, options);
}

export async function restoreFromShards(shards, options = {}) {
    const erasureRuntime = requireErasureRuntime();
    return restoreShardSet(shards, { ...options, erasureRuntime });
}

export async function runSelfTest(options = {}) {
    const { runSelfTest: runCoreSelfTest } = await import('../core/crypto/selftest.js');
    return runCoreSelfTest(options);
}

export async function assessShardSelection(files) {
    return assessSelectedShards(files);
}

export async function parseQcontShardPreviewFile(file) {
    return parseShardPreviewFile(file);
}
