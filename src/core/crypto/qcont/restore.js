import { sha3_512 } from '@noble/hashes/sha3.js';
import { hashBytes } from '../index.js';
import { log, logError, logWarning } from '../../features/ui/logging.js';
import { setButtonsDisabled, readFileAsUint8Array, download, bytesEqual, toHex } from '../../../utils.js';
import { buildQencHeader } from '../qenc/format.js';
import { QCONT_FORMAT_VERSION } from '../constants.js';
import { parseArchiveManifestBytes } from '../manifest/archive-manifest.js';
import { verifyManifestSignatures } from '../auth/verify-signatures.js';
import { validateContainerPolicyMetadata } from '../policy.js';

const QCONT_MAGIC = 'QVC1';
const KEY_COMMITMENT_MAX_LEN = 32;
const MANIFEST_DIGEST_LEN = 64;
const MAX_META_LEN = 16 * 1024;
const MAX_MANIFEST_LEN = 1024 * 1024;

function ensurePositiveInteger(value, field, min = 1) {
    if (!Number.isInteger(value) || value < min) {
        throw new Error(`Invalid ${field}`);
    }
    return value;
}

function ensureEqual(actual, expected, field) {
    if (actual !== expected) {
        throw new Error(`${field} mismatch (expected ${expected}, got ${actual})`);
    }
}

function normalizeHexString(value) {
    return String(value || '').trim().toLowerCase();
}

function normalizeAcceptedAlgorithms(manifest) {
    const values = manifest?.signingPolicy?.acceptedAlgorithms;
    const defaults = ['ML-DSA', 'SLH-DSA-SHAKE', 'Ed25519'];
    const source = Array.isArray(values) && values.length > 0 ? values : defaults;
    return new Set(source.map((item) => String(item || '').trim()));
}

function isResultAcceptedByPolicy(result, acceptedAlgorithms) {
    if (!result?.ok) return false;
    if (result.type === 'qsig') {
        const family = String(result.algorithmFamily || '');
        const algorithm = String(result.algorithm || '');
        return acceptedAlgorithms.has(family) || acceptedAlgorithms.has(algorithm);
    }
    if (result.type === 'sig') {
        return acceptedAlgorithms.has('Ed25519');
    }
    return false;
}

function evaluateVerificationSummary(verification, manifest) {
    const acceptedAlgorithms = normalizeAcceptedAlgorithms(manifest);
    let acceptedValidCount = 0;
    let acceptedTrustedCount = 0;

    for (const result of verification.results || []) {
        if (!isResultAcceptedByPolicy(result, acceptedAlgorithms)) continue;
        acceptedValidCount += 1;
        if (result.trusted) acceptedTrustedCount += 1;
    }

    return {
        acceptedValidCount,
        acceptedTrustedCount,
        acceptedAlgorithms: [...acceptedAlgorithms],
    };
}

function collectManifestCandidates(shards) {
    const byDigest = new Map();
    for (const shard of shards) {
        const digestHex = shard.manifestDigestHex;
        if (!byDigest.has(digestHex)) {
            byDigest.set(digestHex, {
                digestHex,
                manifestBytes: shard.manifestBytes,
                shards: [],
            });
        }
        const entry = byDigest.get(digestHex);
        if (!bytesEqual(entry.manifestBytes, shard.manifestBytes)) {
            throw new Error(`Manifest bytes mismatch inside digest cohort ${digestHex}`);
        }
        entry.shards.push(shard);
    }
    return [...byDigest.values()];
}

async function verifyManifestCandidate({
    manifestBytes,
    manifest,
    signatures,
    trustedPqPublicKeyFileBytes,
    pinnedPqFingerprintHex,
    expectedEd25519Signer,
}) {
    if (!Array.isArray(signatures) || signatures.length === 0) {
        return null;
    }

    const allowLegacyByManifest = manifest?.signingPolicy?.allowLegacyEd25519 ?? true;
    const verification = await verifyManifestSignatures({
        manifestBytes,
        signatures,
        trustedPqPublicKeyFileBytes,
        pinnedPqFingerprintHex,
        expectedEd25519Signer,
        allowLegacyEd25519: allowLegacyByManifest,
    });

    return {
        ...verification,
        evaluation: evaluateVerificationSummary(verification, manifest),
    };
}

async function resolveManifestContext(shards, verification = {}) {
    const warnings = [];
    const signatures = Array.isArray(verification.signatures) ? verification.signatures : [];
    const requireTrustedSignature = verification.requireTrustedSignature === true;

    const candidates = collectManifestCandidates(shards).map((candidate) => {
        const parsed = parseArchiveManifestBytes(candidate.manifestBytes);
        if (parsed.digestHex !== candidate.digestHex) {
            throw new Error('Embedded manifest digest mismatch');
        }
        return {
            ...candidate,
            ...parsed,
        };
    });

    if (candidates.length === 0) {
        throw new Error('No embedded manifests found in shard set');
    }

    const uploadedManifestBytes = verification.manifestBytes instanceof Uint8Array
        ? verification.manifestBytes
        : null;

    if (uploadedManifestBytes) {
        const parsedUploaded = parseArchiveManifestBytes(uploadedManifestBytes);
        const selected = candidates.find((item) => item.digestHex === parsedUploaded.digestHex);
        if (!selected) {
            throw new Error('Uploaded manifest does not match any provided shard cohort');
        }

        const verificationSummary = await verifyManifestCandidate({
            manifestBytes: parsedUploaded.bytes,
            manifest: parsedUploaded.manifest,
            signatures,
            trustedPqPublicKeyFileBytes: verification.trustedPqPublicKeyFileBytes,
            pinnedPqFingerprintHex: verification.pinnedPqFingerprintHex,
            expectedEd25519Signer: verification.expectedEd25519Signer,
        });

        if (verificationSummary) {
            if (verificationSummary.evaluation.acceptedValidCount <= 0) {
                throw new Error('Provided signatures do not validate this manifest under signing policy');
            }
            if (requireTrustedSignature && verificationSummary.evaluation.acceptedTrustedCount <= 0) {
                throw new Error('Trusted signature required but no trusted-valid signature was found');
            }
            if (verificationSummary.evaluation.acceptedTrustedCount <= 0) {
                warnings.push('Manifest signatures validated, but no trusted signer identity is pinned.');
            }
        } else {
            if (requireTrustedSignature) {
                throw new Error('Trusted signature is required by restore policy');
            }
            warnings.push('The content is correct, but may not be authentic.');
        }

        return {
            manifest: parsedUploaded.manifest,
            manifestBytes: parsedUploaded.bytes,
            manifestDigestHex: parsedUploaded.digestHex,
            source: 'uploaded',
            verification: verificationSummary,
            warnings,
            candidateDigests: candidates.map((item) => item.digestHex),
        };
    }

    if (signatures.length > 0) {
        const evaluations = [];
        for (const candidate of candidates) {
            const verificationSummary = await verifyManifestCandidate({
                manifestBytes: candidate.bytes,
                manifest: candidate.manifest,
                signatures,
                trustedPqPublicKeyFileBytes: verification.trustedPqPublicKeyFileBytes,
                pinnedPqFingerprintHex: verification.pinnedPqFingerprintHex,
                expectedEd25519Signer: verification.expectedEd25519Signer,
            });
            evaluations.push({ candidate, verification: verificationSummary });
        }

        const valid = evaluations.filter((item) => item.verification?.evaluation?.acceptedValidCount > 0);
        if (valid.length === 0) {
            throw new Error('No embedded manifest candidate validates against provided signatures');
        }

        let acceptable = valid;
        if (requireTrustedSignature) {
            acceptable = valid.filter((item) => item.verification?.evaluation?.acceptedTrustedCount > 0);
            if (acceptable.length === 0) {
                throw new Error('Trusted signature required but no trusted-valid manifest candidate found');
            }
        }

        const trustedPreferred = acceptable.filter((item) => item.verification?.evaluation?.acceptedTrustedCount > 0);
        if (trustedPreferred.length === 1) {
            const chosen = trustedPreferred[0];
            return {
                manifest: chosen.candidate.manifest,
                manifestBytes: chosen.candidate.bytes,
                manifestDigestHex: chosen.candidate.digestHex,
                source: 'embedded',
                verification: chosen.verification,
                warnings,
                candidateDigests: candidates.map((item) => item.digestHex),
            };
        }

        if (acceptable.length !== 1) {
            throw new Error('Multiple manifest candidates satisfy signatures. Pin signer identity or provide manifest file.');
        }

        warnings.push('Manifest signatures validated, but no trusted signer identity is pinned.');
        const chosen = acceptable[0];
        return {
            manifest: chosen.candidate.manifest,
            manifestBytes: chosen.candidate.bytes,
            manifestDigestHex: chosen.candidate.digestHex,
            source: 'embedded',
            verification: chosen.verification,
            warnings,
            candidateDigests: candidates.map((item) => item.digestHex),
        };
    }

    if (requireTrustedSignature) {
        throw new Error('Trusted signature is required by restore policy');
    }
    warnings.push('The content is correct, but may not be authentic.');

    if (candidates.length !== 1) {
        throw new Error('Multiple manifest cohorts detected. Provide signed manifest or detached signature to select a trusted cohort.');
    }

    const chosen = candidates[0];
    return {
        manifest: chosen.manifest,
        manifestBytes: chosen.bytes,
        manifestDigestHex: chosen.digestHex,
        source: 'embedded',
        verification: null,
        warnings,
        candidateDigests: candidates.map((item) => item.digestHex),
    };
}

function parseShardUnsafe(arr) {
    if (!(arr instanceof Uint8Array)) {
        throw new Error('Shard must be a Uint8Array');
    }

    const minHeader = 4 + 2 + 4 + MANIFEST_DIGEST_LEN + 4 + 12 + 16 + 2 + 1 + 2 + 2;
    if (arr.length < minHeader) {
        throw new Error('Shard is too small to contain a valid header');
    }

    const dv = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    let off = 0;

    const ensure = (need, reason) => {
        if (off + need > arr.length) {
            throw new Error(`Shard is truncated: ${reason}`);
        }
    };

    const readU8 = (reason) => {
        ensure(1, reason);
        const v = dv.getUint8(off);
        off += 1;
        return v;
    };

    const readU16 = (reason) => {
        ensure(2, reason);
        const v = dv.getUint16(off, false);
        off += 2;
        return v;
    };

    const readU32 = (reason) => {
        ensure(4, reason);
        const v = dv.getUint32(off, false);
        off += 4;
        return v;
    };

    const readBytes = (len, reason) => {
        ensure(len, reason);
        const out = arr.subarray(off, off + len);
        off += len;
        return out;
    };

    const decodeJsonBytes = (bytes, reason) => {
        try {
            return JSON.parse(new TextDecoder().decode(bytes));
        } catch (error) {
            throw new Error(`Invalid ${reason}: ${error?.message || error}`);
        }
    };

    const magic = new TextDecoder().decode(readBytes(4, 'magic'));
    if (magic !== QCONT_MAGIC) {
        throw new Error('Invalid .qcont magic');
    }

    const metaLen = readU16('metaLen');
    if (metaLen <= 0 || metaLen > MAX_META_LEN) {
        throw new Error('Invalid shard metadata length');
    }
    const metaBytes = readBytes(metaLen, 'metaJSON');
    const metaJSON = decodeJsonBytes(metaBytes, 'shard metadata JSON');
    if (metaJSON?.alg?.fmt !== QCONT_FORMAT_VERSION) {
        throw new Error(`Unsupported shard format: expected ${QCONT_FORMAT_VERSION}, got ${metaJSON?.alg?.fmt ?? 'unknown'}`);
    }

    const manifestLen = readU32('manifest length');
    if (manifestLen <= 0 || manifestLen > MAX_MANIFEST_LEN) {
        throw new Error('Invalid embedded manifest length');
    }
    const manifestBytes = readBytes(manifestLen, 'manifest bytes');
    const manifestDigestBytes = readBytes(MANIFEST_DIGEST_LEN, 'manifest digest');
    const computedManifestDigestBytes = sha3_512(manifestBytes);
    if (!bytesEqual(manifestDigestBytes, computedManifestDigestBytes)) {
        throw new Error('Embedded manifest digest mismatch');
    }
    const manifestDigestHex = toHex(manifestDigestBytes);

    const encapLen = readU32('encapsulatedKey length');
    if (encapLen <= 0) throw new Error('Invalid encapsulated key length');
    const encapsulatedKey = readBytes(encapLen, 'encapsulatedKey');

    const iv = readBytes(12, 'container nonce');
    const salt = readBytes(16, 'kdf salt');

    const qencMetaLen = readU16('qenc metadata length');
    if (qencMetaLen <= 0 || qencMetaLen > MAX_META_LEN) {
        throw new Error('Invalid qenc metadata length');
    }
    const qencMetaBytes = readBytes(qencMetaLen, 'qenc metadata');
    const qencMetaJSON = decodeJsonBytes(qencMetaBytes, 'qenc metadata JSON');

    const kcLen = readU8('key commitment length');
    if (kcLen > KEY_COMMITMENT_MAX_LEN) {
        throw new Error(`Invalid key commitment length: ${kcLen}`);
    }
    const keyCommit = kcLen > 0 ? readBytes(kcLen, 'key commitment') : null;

    const shardIndex = readU16('shard index');
    const shareLen = readU16('share length');
    if (shareLen <= 0) throw new Error('Invalid Shamir share length');
    const share = readBytes(shareLen, 'Shamir share');
    const fragments = arr.subarray(off);
    if (fragments.length === 0) {
        throw new Error('Shard fragment payload is empty');
    }

    return {
        metaJSON,
        metaBytes,
        manifestBytes,
        manifestDigestHex,
        encapsulatedKey,
        iv,
        salt,
        qencMetaBytes,
        qencMetaJSON,
        keyCommit,
        shardIndex,
        share,
        fragments,
        diagnostics: { errors: [], warnings: [] },
    };
}

/**
 * Parse a single .qcont shard from raw bytes
 * @param {Uint8Array} arr - Raw shard bytes
 * @param {object} [options]
 * @param {boolean} [options.strict=true]
 * @returns {object} Parsed shard structure with diagnostics
 */
export function parseShard(arr, options = {}) {
    const { strict = true } = options;
    try {
        return parseShardUnsafe(arr);
    } catch (error) {
        if (strict) throw error;
        return {
            diagnostics: { errors: [error?.message || String(error)], warnings: [] }
        };
    }
}

function assertManifestMatchesQencMetadata(manifest, qencMetaJSON) {
    const qenc = manifest.qenc || {};

    ensureEqual(qenc.hashAlg, 'SHA3-512', 'qenc.hashAlg');
    ensureEqual(qenc.primaryAnchor, 'qencHash', 'qenc.primaryAnchor');
    ensureEqual(qenc.containerIdRole, 'secondary-header-id', 'qenc.containerIdRole');
    ensureEqual(qenc.containerIdAlg, 'SHA3-512(qenc-header-bytes)', 'qenc.containerIdAlg');

    ensureEqual(qencMetaJSON.fmt, qenc.format, 'qenc.format');
    ensureEqual(qencMetaJSON.aead_mode, qenc.aeadMode, 'qenc.aeadMode');
    ensureEqual(qencMetaJSON.iv_strategy, qenc.ivStrategy, 'qenc.ivStrategy');

    ensureEqual(Number(qencMetaJSON.chunkSize), Number(qenc.chunkSize), 'qenc.chunkSize');
    ensureEqual(Number(qencMetaJSON.chunkCount), Number(qenc.chunkCount), 'qenc.chunkCount');
    ensureEqual(Number(qencMetaJSON.payloadLength), Number(qenc.payloadLength), 'qenc.payloadLength');

    ensureEqual(qencMetaJSON.cryptoProfileId, manifest.cryptoProfileId, 'cryptoProfileId');
    ensureEqual(qencMetaJSON.kdfTreeId, manifest.kdfTreeId, 'kdfTreeId');
    ensureEqual(qencMetaJSON.noncePolicyId, manifest.noncePolicyId, 'noncePolicyId');
    ensureEqual(qencMetaJSON.nonceMode, manifest.nonceMode, 'nonceMode');
    ensureEqual(Number(qencMetaJSON.counterBits), Number(manifest.counterBits), 'counterBits');
    ensureEqual(Number(qencMetaJSON.maxChunkCount), Number(manifest.maxChunkCount), 'maxChunkCount');
    ensureEqual(qencMetaJSON.aadPolicyId, manifest.aadPolicyId, 'aadPolicyId');
}

/**
 * Restore .qenc container and private key from parsed shards
 * Core logic without UI dependencies — can be used by both Pro and Lite modes
 *
 * @param {object[]} shards - Array of parsed shard objects (from parseShard)
 * @param {object} options - Optional callbacks and verification options
 * @param {function} [options.onLog] - Log callback (msg) => void
 * @param {function} [options.onError] - Error log callback (msg) => void
 * @param {boolean} [options.strict=true]
 * @param {object} [options.verification]
 * @returns {Promise<object>}
 */
export async function restoreFromShards(shards, options = {}) {
    const onLog = options.onLog || (() => {});
    const onError = options.onError || (() => {});
    const onWarn = options.onWarn || onError;
    const strict = options.strict ?? true;

    if (!Array.isArray(shards) || shards.length === 0) {
        throw new Error('No shards provided');
    }

    const prepared = [];
    for (let i = 0; i < shards.length; i += 1) {
        const shard = shards[i];
        if (shard?.diagnostics?.errors?.length) {
            if (strict) {
                throw new Error(`Shard parse failed at input index ${i}: ${shard.diagnostics.errors.join('; ')}`);
            }
            continue;
        }
        prepared.push({
            ...shard,
            inputOrder: i,
            inputShardIndex: Number.isInteger(shard?.shardIndex) ? shard.shardIndex : i,
        });
    }

    if (prepared.length === 0) {
        throw new Error('No valid shards after parsing');
    }

    const verification = options.verification || {};
    const manifestContext = await resolveManifestContext(prepared, verification);

    const manifest = manifestContext.manifest;
    const manifestDigestHex = manifestContext.manifestDigestHex;
    const group = prepared.filter((shard) => shard.manifestDigestHex === manifestDigestHex);
    const rejectedShardIndices = prepared
        .filter((shard) => shard.manifestDigestHex !== manifestDigestHex)
        .map((shard) => shard.inputShardIndex);

    if (group.length === 0) {
        throw new Error('No shard matches selected manifest digest');
    }

    const n = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.n), 'manifest.sharding.reedSolomon.n', 2);
    const k = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.k), 'manifest.sharding.reedSolomon.k', 2);
    const m = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.parity), 'manifest.sharding.reedSolomon.parity', 0);
    const t = ensurePositiveInteger(Number(manifest?.sharding?.shamir?.threshold), 'manifest.sharding.shamir.threshold', 2);
    const shareCount = ensurePositiveInteger(Number(manifest?.sharding?.shamir?.shareCount), 'manifest.sharding.shamir.shareCount', 2);

    if (shareCount !== n) {
        throw new Error(`Invalid manifest sharding: Shamir shareCount ${shareCount} must equal RS n ${n}`);
    }
    if ((m % 2) !== 0) {
        throw new Error('Invalid manifest sharding: RS parity must be even');
    }
    if (k >= n) {
        throw new Error('Invalid manifest sharding: expected k < n');
    }

    const allowedFailures = m / 2;
    const expectedThreshold = k + allowedFailures;
    if (t !== expectedThreshold) {
        throw new Error(`Invalid manifest threshold: expected ${expectedThreshold}, got ${t}`);
    }

    const qenc = manifest.qenc || {};
    const chunkSize = ensurePositiveInteger(Number(qenc.chunkSize), 'manifest.qenc.chunkSize', 1);
    const chunkCount = ensurePositiveInteger(Number(qenc.chunkCount), 'manifest.qenc.chunkCount', 1);
    const payloadLength = ensurePositiveInteger(Number(qenc.payloadLength), 'manifest.qenc.payloadLength', 1);

    const containerId = String(qenc.containerId || '');
    if (containerId.length === 0) {
        throw new Error('Manifest is missing qenc.containerId');
    }

    const base = group[0];
    const baseKeyCommit = base.keyCommit || new Uint8Array(0);
    const shardByIndex = new Map();

    for (const shard of group) {
        if (!Number.isInteger(shard.shardIndex) || shard.shardIndex < 0 || shard.shardIndex >= n) {
            throw new Error(`Invalid shardIndex ${shard.shardIndex}`);
        }
        if (shardByIndex.has(shard.shardIndex)) {
            throw new Error(`Duplicate shardIndex ${shard.shardIndex} detected`);
        }
        shardByIndex.set(shard.shardIndex, shard);

        ensureEqual(shard.metaJSON?.containerId, containerId, 'containerId');
        ensureEqual(Number(shard.metaJSON?.n), n, 'n');
        ensureEqual(Number(shard.metaJSON?.k), k, 'k');
        ensureEqual(Number(shard.metaJSON?.m), m, 'm');
        ensureEqual(Number(shard.metaJSON?.t), t, 't');

        if (shard.metaJSON?.manifestDigest) {
            ensureEqual(normalizeHexString(shard.metaJSON.manifestDigest), manifestDigestHex, 'manifestDigest');
        }

        if (!bytesEqual(shard.encapsulatedKey, base.encapsulatedKey)) {
            throw new Error(`Shard header mismatch: encapsulatedKey differs for shard ${shard.shardIndex}`);
        }
        if (!bytesEqual(shard.iv, base.iv)) {
            throw new Error(`Shard header mismatch: iv differs for shard ${shard.shardIndex}`);
        }
        if (!bytesEqual(shard.salt, base.salt)) {
            throw new Error(`Shard header mismatch: salt differs for shard ${shard.shardIndex}`);
        }
        if (!bytesEqual(shard.qencMetaBytes, base.qencMetaBytes)) {
            throw new Error(`Shard header mismatch: qenc metadata differs for shard ${shard.shardIndex}`);
        }
        const shardKeyCommit = shard.keyCommit || new Uint8Array(0);
        if (!bytesEqual(shardKeyCommit, baseKeyCommit)) {
            throw new Error(`Shard header mismatch: key commitment differs for shard ${shard.shardIndex}`);
        }
    }

    const missingIndices = new Set();
    for (let i = 0; i < n; i += 1) {
        if (!shardByIndex.has(i)) missingIndices.add(i);
    }

    const qencMetaJSON = base.qencMetaJSON;
    validateContainerPolicyMetadata(qencMetaJSON, { allowLegacyWithoutProfile: false });
    assertManifestMatchesQencMetadata(manifest, qencMetaJSON);

    const ciphertextLength = ensurePositiveInteger(Number(base.metaJSON?.ciphertextLength), 'ciphertextLength', 1);
    for (const shard of group) {
        ensureEqual(Number(shard.metaJSON?.ciphertextLength), ciphertextLength, 'ciphertextLength');
        ensureEqual(Number(shard.metaJSON?.chunkCount), chunkCount, 'chunkCount');
        ensureEqual(Number(shard.metaJSON?.chunkSize), chunkSize, 'chunkSize');
    }

    const isPerChunkMode = qencMetaJSON.aead_mode === 'per-chunk-aead';
    if (!isPerChunkMode && qencMetaJSON.aead_mode !== 'single-container-aead') {
        throw new Error(`Unsupported AEAD mode: ${qencMetaJSON.aead_mode ?? 'unknown'}`);
    }

    const expectedCiphertextLength = isPerChunkMode
        ? (payloadLength + (16 * chunkCount))
        : ciphertextLength;
    if (isPerChunkMode && ciphertextLength !== expectedCiphertextLength) {
        throw new Error(`Ciphertext length mismatch for per-chunk mode (expected ${expectedCiphertextLength}, got ${ciphertextLength})`);
    }

    const encapHash = await hashBytes(base.encapsulatedKey);
    if (base.metaJSON?.encapBlobHash && normalizeHexString(base.metaJSON.encapBlobHash) !== normalizeHexString(encapHash)) {
        throw new Error('encapBlobHash mismatch');
    }

    if (group.length < t) {
        throw new Error(`Need at least ${t} matching shards for selected manifest, got ${group.length}`);
    }

    const shareCommitments = manifest?.shardBinding?.shareCommitments || base.metaJSON?.shareCommitments || null;
    const fragmentBodyHashes = manifest?.shardBinding?.shardBodyHashes || base.metaJSON?.fragmentBodyHashes || null;

    let validShareShards = group;
    if (Array.isArray(shareCommitments)) {
        if (shareCommitments.length !== n) {
            throw new Error('Invalid shareCommitments length');
        }
        validShareShards = [];
        const invalidShareIndices = new Set();
        for (const shard of group) {
            const expected = normalizeHexString(shareCommitments[shard.shardIndex]);
            if (!expected) {
                invalidShareIndices.add(shard.shardIndex);
                continue;
            }
            const actual = normalizeHexString(await hashBytes(shard.share));
            if (actual !== expected) {
                onWarn(`Share commitment verification failed for shard ${shard.shardIndex}. Share will be skipped.`);
                invalidShareIndices.add(shard.shardIndex);
                continue;
            }
            validShareShards.push(shard);
        }
        if (validShareShards.length < t) {
            throw new Error(`Not enough valid shards for Shamir reconstruction: need ${t}, have ${validShareShards.length}`);
        }
        if (invalidShareIndices.size > 0) {
            onWarn(`Share commitment failures: ${invalidShareIndices.size} shard(s) rejected.`);
        } else {
            onLog('Share commitments verified.');
        }
    }

    const corruptedShardIndices = new Set();
    if (Array.isArray(fragmentBodyHashes)) {
        if (fragmentBodyHashes.length !== n) {
            throw new Error('Invalid shardBodyHashes length');
        }
        for (const shard of group) {
            const expected = normalizeHexString(fragmentBodyHashes[shard.shardIndex]);
            if (!expected) continue;
            const actual = normalizeHexString(await hashBytes(shard.fragments));
            if (actual !== expected) {
                onWarn(`Fragment integrity check failed for shard ${shard.shardIndex}. Treating as erasure.`);
                corruptedShardIndices.add(shard.shardIndex);
            }
        }
        if (corruptedShardIndices.size === 0) {
            onLog('Shard body hashes verified.');
        }
    }

    const totalBad = missingIndices.size + corruptedShardIndices.size;
    if (totalBad > allowedFailures) {
        throw new Error(`Too many missing/corrupted shards for RS reconstruction: allowed ${allowedFailures}, got ${totalBad}`);
    }

    const sortedShares = validShareShards.slice().sort((a, b) => a.shardIndex - b.shardIndex);
    const selectedShares = sortedShares.slice(0, t).map((item) => item.share);
    const { combineShares } = await import('../splitting/sss.js');
    const privKey = await combineShares(selectedShares);

    const rsEncodeBase = Number.isInteger(base.metaJSON?.rsEncodeBase) ? base.metaJSON.rsEncodeBase : 255;
    const cipherChunks = [];
    const shardOffsets = new Array(n).fill(0);

    for (let i = 0; i < chunkCount; i += 1) {
        const plainLen = Math.min(chunkSize, payloadLength - (i * chunkSize));
        const thisLen = isPerChunkMode ? (plainLen + 16) : ciphertextLength;

        const encodeSize = Math.floor(rsEncodeBase / n) * n;
        if (encodeSize === 0) throw new Error('RS parameters too large');
        const inputSize = (encodeSize * k) / n;
        const symbolSize = inputSize / k;
        const blocks = Math.ceil(thisLen / inputSize);
        const expectedFragLen = blocks * symbolSize;

        const encoded = new Array(n);
        for (let j = 0; j < n; j += 1) {
            const shard = shardByIndex.get(j);
            const fragStream = (shard && !corruptedShardIndices.has(j)) ? shard.fragments : null;
            if (!fragStream) {
                encoded[j] = new Uint8Array(expectedFragLen);
                continue;
            }

            const streamOffset = shardOffsets[j];
            if (streamOffset + 4 > fragStream.length) {
                throw new Error('Fragment stream underflow');
            }

            const dvFrag = new DataView(fragStream.buffer, fragStream.byteOffset + streamOffset);
            const fragLen = dvFrag.getUint32(0, false);
            const fragStart = streamOffset + 4;
            const fragEnd = fragStart + fragLen;
            if (fragEnd > fragStream.length) {
                throw new Error('Fragment length overflow');
            }

            let fragment = fragStream.subarray(fragStart, fragEnd);
            if (fragment.length < expectedFragLen) {
                const padded = new Uint8Array(expectedFragLen);
                padded.set(fragment);
                fragment = padded;
            } else if (fragment.length > expectedFragLen) {
                fragment = fragment.subarray(0, expectedFragLen);
            }

            encoded[j] = fragment;
            shardOffsets[j] = fragEnd;
        }

        let recombined;
        try {
            recombined = window.erasure.recombine(encoded, thisLen, k, m / 2, rsEncodeBase);
        } catch (error) {
            throw new Error(`RS recombination failed on chunk ${i}: ${error?.message ?? error}`);
        }

        cipherChunks.push(recombined);
        if (!isPerChunkMode) break;
    }

    for (let j = 0; j < n; j += 1) {
        if (corruptedShardIndices.has(j)) continue;
        const shard = shardByIndex.get(j);
        if (!shard) continue;
        if (shardOffsets[j] !== shard.fragments.length) {
            throw new Error(`Fragment stream has trailing or missing data in shard ${j}`);
        }
    }

    const ciphertext = isPerChunkMode
        ? (() => {
            const total = cipherChunks.reduce((sum, item) => sum + item.length, 0);
            const out = new Uint8Array(total);
            let offset = 0;
            for (const chunk of cipherChunks) {
                out.set(chunk, offset);
                offset += chunk.length;
            }
            return out;
        })()
        : cipherChunks[0];

    if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== ciphertextLength) {
        throw new Error('Reconstructed ciphertext length mismatch');
    }

    const header = buildQencHeader({
        encapsulatedKey: base.encapsulatedKey,
        containerNonce: base.iv,
        kdfSalt: base.salt,
        metaBytes: base.qencMetaBytes,
        keyCommitment: (base.keyCommit && base.keyCommit.length > 0) ? base.keyCommit : null,
    });

    const qencBytes = new Uint8Array(header.length + ciphertext.length);
    qencBytes.set(header, 0);
    qencBytes.set(ciphertext, header.length);

    const recoveredQencHash = normalizeHexString(await hashBytes(qencBytes));
    const expectedQencHash = normalizeHexString(qenc.qencHash);
    if (recoveredQencHash !== expectedQencHash) {
        throw new Error('Reconstructed .qenc hash does not match signed manifest');
    }

    const recoveredPrivHash = normalizeHexString(await hashBytes(privKey));
    const privateKeyHash = normalizeHexString(base.metaJSON?.privateKeyHash || '');
    const qkeyOk = privateKeyHash ? (privateKeyHash === recoveredPrivHash) : true;
    if (!qkeyOk) {
        onWarn('Recovered private key hash does not match shard metadata.');
    }

    return {
        qencBytes,
        privKey,
        containerId,
        containerHash: expectedQencHash,
        privateKeyHash: privateKeyHash || null,
        recoveredQencHash,
        recoveredPrivHash,
        rejectedShardIndices,
        qencOk: true,
        qkeyOk,
        manifest,
        manifestBytes: manifestContext.manifestBytes,
        manifestDigestHex,
        manifestSource: manifestContext.source,
        authenticity: {
            warnings: manifestContext.warnings,
            verification: manifestContext.verification,
        },
    };
}

function startsWithAscii(bytes, ascii) {
    if (!(bytes instanceof Uint8Array)) return false;
    if (bytes.length < ascii.length) return false;
    for (let i = 0; i < ascii.length; i += 1) {
        if (bytes[i] !== ascii.charCodeAt(i)) return false;
    }
    return true;
}

function tryParseJsonBytes(bytes) {
    try {
        return JSON.parse(new TextDecoder().decode(bytes));
    } catch {
        return null;
    }
}

async function classifyRestoreInputFiles(files) {
    const shardFiles = [];
    const signatures = [];
    const ignoredFileNames = [];
    const manifestCandidates = [];
    let trustedPqPublicKeyFileBytes = null;

    for (const file of files) {
        const name = String(file?.name || 'unnamed');
        const lowerName = name.toLowerCase();

        if (lowerName.endsWith('.qcont')) {
            shardFiles.push(file);
            continue;
        }

        const bytes = await readFileAsUint8Array(file);

        if (startsWithAscii(bytes, QCONT_MAGIC)) {
            shardFiles.push(file);
            continue;
        }

        if (startsWithAscii(bytes, 'PQPK') || lowerName.endsWith('.pqpk')) {
            if (!trustedPqPublicKeyFileBytes) {
                trustedPqPublicKeyFileBytes = bytes;
            } else if (!bytesEqual(trustedPqPublicKeyFileBytes, bytes)) {
                throw new Error('Multiple different .pqpk files were provided. Keep only one trusted PQ key.');
            }
            continue;
        }

        if (startsWithAscii(bytes, 'PQSG') || lowerName.endsWith('.qsig')) {
            signatures.push({ name, bytes });
            continue;
        }

        const parsedJson = tryParseJsonBytes(bytes);
        if (parsedJson?.schema === 'stellar-file-signature/v1') {
            signatures.push({ name, bytes });
            continue;
        }

        let parsedManifest = null;
        try {
            parsedManifest = parseArchiveManifestBytes(bytes);
        } catch {
            // not a canonical archive manifest
        }

        if (parsedManifest) {
            manifestCandidates.push({
                name,
                bytes: parsedManifest.bytes,
                digestHex: parsedManifest.digestHex,
            });
            continue;
        }

        if (lowerName.endsWith('.qvmanifest.json')) {
            throw new Error(`Invalid canonical manifest file: ${name}`);
        }

        if (lowerName.endsWith('.sig') || lowerName.endsWith('.json')) {
            signatures.push({ name, bytes });
            continue;
        }

        ignoredFileNames.push(name);
    }

    let manifestBytes = null;
    if (manifestCandidates.length > 0) {
        const uniqueDigests = new Set(manifestCandidates.map((item) => item.digestHex));
        if (uniqueDigests.size > 1) {
            throw new Error('Multiple different manifest files were provided. Keep only one canonical manifest.');
        }
        manifestBytes = manifestCandidates[0].bytes;
    }

    return {
        shardFiles,
        manifestBytes,
        signatures,
        trustedPqPublicKeyFileBytes,
        ignoredFileNames,
    };
}

async function readVerificationOptionsFromDom({
    allFiles = [],
    pinnedPqFingerprintInput,
    expectedSignerInput,
    requireTrustedSignatureInput,
}) {
    const classified = await classifyRestoreInputFiles(allFiles);

    return {
        ...classified,
        pinnedPqFingerprintHex: String(pinnedPqFingerprintInput?.value || '').trim(),
        expectedEd25519Signer: String(expectedSignerInput?.value || '').trim(),
        requireTrustedSignature: requireTrustedSignatureInput?.checked === true,
    };
}

function logVerificationSummary(summary, onLog, onWarn) {
    for (const warning of summary?.warnings || []) {
        onWarn(warning);
    }

    const verification = summary?.verification;
    if (!verification) {
        return;
    }

    const evalSummary = verification.evaluation;
    onLog(`Signature results: ${verification.validCount} valid, ${verification.trustedValidCount} trusted-valid.`);
    onLog(`Signing policy accepted: ${evalSummary.acceptedAlgorithms.join(', ')}.`);

    if (evalSummary.acceptedTrustedCount <= 0) {
        onWarn('No trusted-valid signer identity pinned for this restore.');
    }

    for (const warning of verification.warnings || []) {
        onWarn(warning);
    }

    for (const item of verification.results || []) {
        if (item.ok) {
            if (item.type === 'sig') {
                onLog(`Signature OK: ${item.name} (${item.algorithm || 'Ed25519'}, signer ${item.signer || 'unknown'}${item.trusted ? ', trusted' : ''})`);
                continue;
            }
            if (item.type === 'qsig') {
                onLog(`Signature OK: ${item.name} (${item.algorithm || 'PQ'}, fp ${item.signerFingerprintHex || 'unknown'}${item.trusted ? ', trusted' : ''})`);
                continue;
            }
            onLog(`Signature OK: ${item.name} (${item.algorithm || item.type}${item.trusted ? ', trusted' : ''})`);
            continue;
        }
        onWarn(`Signature failed: ${item.name} (${item.error || 'unknown error'})`);
    }
}

/**
 * Initialize Pro Mode restore UI
 * Uses restoreFromShards() core logic
 */
export function initQcontRestoreUI() {
    const qcontShardsInput = document.getElementById('qcontShardsInput');
    const restoreQcontBtn = document.getElementById('restoreQcontBtn');

    const restorePinnedPqFingerprint = document.getElementById('restorePinnedPqFingerprint');
    const restoreExpectedEdSigner = document.getElementById('restoreExpectedEdSigner');
    const restoreRequireTrustedSig = document.getElementById('restoreRequireTrustedSig');

    restoreQcontBtn?.addEventListener('click', async () => {
        const files = qcontShardsInput?.files;
        if (!files?.length) {
            logError('Select .qcont shards');
            return;
        }

        setButtonsDisabled(true);
        try {
            const allFiles = [...files];
            const verificationOptions = await readVerificationOptionsFromDom({
                allFiles,
                pinnedPqFingerprintInput: restorePinnedPqFingerprint,
                expectedSignerInput: restoreExpectedEdSigner,
                requireTrustedSignatureInput: restoreRequireTrustedSig,
            });
            if (!verificationOptions.shardFiles.length) {
                throw new Error('No .qcont shard files were detected in selected input.');
            }
            if (verificationOptions.ignoredFileNames.length > 0) {
                logWarning(`Ignored non-restore attachments: ${verificationOptions.ignoredFileNames.join(', ')}`);
            }

            const shardBytesArr = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
            const shards = shardBytesArr.map((bytes) => parseShard(bytes, { strict: true }));

            const result = await restoreFromShards(shards, {
                onLog: (msg) => log(msg),
                onError: (msg) => logError(msg),
                onWarn: (msg) => logWarning(msg),
                verification: verificationOptions,
            });

            log(`Selected manifest digest: ${result.manifestDigestHex}`);
            log(`Manifest source: ${result.manifestSource}`);
            logVerificationSummary(result.authenticity, (msg) => log(msg), (msg) => logWarning(msg));

            const { qencBytes, privKey, containerId, containerHash, privateKeyHash, recoveredQencHash, recoveredPrivHash, qencOk, qkeyOk } = result;
            log(`Recovered .qenc SHA3-512=${recoveredQencHash} (expected ${containerHash})`);
            log(`Recovered .qkey SHA3-512=${recoveredPrivHash}${privateKeyHash ? ` (expected ${privateKeyHash})` : ''}`);

            const qencBlob = new Blob([qencBytes], { type: 'application/octet-stream' });
            const qkeyBlob = new Blob([privKey], { type: 'application/octet-stream' });
            const qencName = `${containerId}.recovered.qenc`;
            const qkeyName = `${containerId}.recovered.secretKey.qkey`;

            if (qencOk && qkeyOk) {
                download(qencBlob, qencName);
                download(qkeyBlob, qkeyName);
                log('Recovered .qenc and .qkey from authenticated shard cohort.');
            } else {
                logError('Hash mismatch detected. Automatic download is blocked. Review artifacts manually.');
                const logEl = document.getElementById('log');
                const a1 = document.createElement('a');
                a1.href = URL.createObjectURL(qencBlob);
                a1.download = qencName;
                a1.textContent = `Manual download: ${qencName}`;
                a1.target = '_blank';
                a1.rel = 'noopener';

                const a2 = document.createElement('a');
                a2.href = URL.createObjectURL(qkeyBlob);
                a2.download = qkeyName;
                a2.textContent = `Manual download: ${qkeyName}`;
                a2.target = '_blank';
                a2.rel = 'noopener';

                logEl.appendChild(a1);
                logEl.appendChild(document.createTextNode('\n'));
                logEl.appendChild(a2);
                logEl.appendChild(document.createTextNode('\n'));
            }
        } catch (error) {
            logError(error);
        } finally {
            setButtonsDisabled(false);
        }
    });
}

export async function collectRestoreVerificationOptions(prefix = 'restore', files = []) {
    const pinnedPqFingerprintInput = document.getElementById(`${prefix}PinnedPqFingerprint`);
    const expectedSignerInput = document.getElementById(`${prefix}ExpectedEdSigner`);
    const requireTrustedSignatureInput = document.getElementById(`${prefix}RequireTrustedSig`);

    return readVerificationOptionsFromDom({
        allFiles: files,
        pinnedPqFingerprintInput,
        expectedSignerInput,
        requireTrustedSignatureInput,
    });
}
