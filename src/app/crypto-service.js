// App-layer crypto service boundary.
// UI modules should consume these high-level operations instead of importing core primitives directly.

import {
    decryptFile as decryptContainerBytes,
    encryptFile as encryptContainerBytes,
    generateKeyPair as generateMlKemKeyPair,
    hashBytes as computeHashHex,
} from '../core/crypto/index.js';
import {
    attachLifecycleBundleToShards as attachLifecycleShardBundle,
    exportSourceEvidenceForSigning as exportSourceEvidenceArtifactForSigning,
} from '../core/crypto/qcont/lifecycle-attach.js';
import {
    buildLifecycleQcontShards as buildSuccessorShardSet,
    isLifecycleParsedShard as isParsedSuccessorLifecycleShard,
    parseLifecycleShard as parseLifecycleQcontShardBytes,
    reshareSameState as reshareSameStateShardSet,
} from '../core/crypto/qcont/lifecycle-shard.js';
import { restoreFromShards as restoreShardSet } from '../core/crypto/qcont/restore.js';
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

export async function decryptFile(containerBytes, privateKey) {
    return decryptContainerBytes(containerBytes, privateKey);
}

export async function hashBytes(bytes) {
    return computeHashHex(bytes);
}

export async function buildQcontShards(qencBytes, privKeyBytes, params, options = {}) {
    const erasureRuntime = requireErasureRuntime();
    return buildSuccessorShardSet(qencBytes, privKeyBytes, params, { ...options, erasureRuntime });
}

export async function attachLifecycleBundleToShards(shards, options = {}) {
    return attachLifecycleShardBundle(shards, options);
}

export function exportSourceEvidenceForSigning(options = {}) {
    return exportSourceEvidenceArtifactForSigning(options);
}

export async function parseLifecycleShard(bytes, options = {}) {
    return parseLifecycleQcontShardBytes(bytes, options);
}

export function isLifecycleParsedShard(shard) {
    return isParsedSuccessorLifecycleShard(shard);
}

export async function reshareSameState(shards, params, options = {}) {
    const erasureRuntime = requireErasureRuntime();
    return reshareSameStateShardSet(shards, params, { ...options, erasureRuntime });
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
