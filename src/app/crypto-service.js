// App-layer crypto service boundary.
// UI modules should consume these high-level operations instead of importing core primitives directly.

import {
    decryptFile as decryptContainerBytes,
    encryptFile as encryptContainerBytes,
    generateKeyPair as generateMlKemKeyPair,
    hashBytes as computeHashHex,
} from '../core/crypto/index.js';
import { buildQcontShards as buildShardSet } from '../core/crypto/qcont/build.js';
import { parseShard as parseQcontShardBytes, restoreFromShards as restoreShardSet } from '../core/crypto/qcont/restore.js';
import { runSelfTest as runCoreSelfTest } from '../core/crypto/selftest.js';
import {
    assessShardSelection as assessSelectedShards,
    parseQcontShardPreviewFile as parseShardPreviewFile,
} from './shard-preview.js';

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

export async function decryptFile(containerBytes, secretKey) {
    return decryptContainerBytes(containerBytes, secretKey);
}

export async function hashBytes(bytes) {
    return computeHashHex(bytes);
}

export async function buildQcontShards(qencBytes, privKeyBytes, params, options = {}) {
    const erasureRuntime = requireErasureRuntime();
    return buildShardSet(qencBytes, privKeyBytes, params, { ...options, erasureRuntime });
}

export function parseShard(bytes, options = {}) {
    return parseQcontShardBytes(bytes, options);
}

export async function restoreFromShards(shards, options = {}) {
    const erasureRuntime = requireErasureRuntime();
    return restoreShardSet(shards, { ...options, erasureRuntime });
}

export async function runSelfTest(options = {}) {
    return runCoreSelfTest(options);
}

export async function assessShardSelection(files) {
    return assessSelectedShards(files);
}

export async function parseQcontShardPreviewFile(file) {
    return parseShardPreviewFile(file);
}
