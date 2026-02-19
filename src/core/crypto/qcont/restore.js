import { sha3_512 } from '@noble/hashes/sha3.js';
import { CHUNK_SIZE, hashBytes } from '../index.js';
import { log, logError } from '../../features/ui/logging.js';
import { setButtonsDisabled, readFileAsUint8Array, download, bytesEqual, toHex } from '../../../utils.js';
import { buildQencHeader } from '../qenc/format.js';
import { QCONT_FORMAT_VERSION } from '../constants.js';

const QCONT_MAGIC = 'QVC1';
const KEY_COMMITMENT_MAX_LEN = 32;

function createShardFingerprint(parts) {
    const total = parts.reduce((acc, part) => acc + part.length, 0);
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        merged.set(part, offset);
        offset += part.length;
    }
    return toHex(sha3_512(merged));
}

function parseShardUnsafe(arr) {
    if (!(arr instanceof Uint8Array)) {
        throw new Error('Shard must be a Uint8Array');
    }
    if (arr.length < 4 + 2 + 4 + 12 + 16 + 2 + 1 + 2 + 2) {
        throw new Error('Shard is too small to contain a valid header');
    }

    const dv = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    let off = 0;
    const ensure = (need, reason) => {
        if (off + need > arr.length) {
            throw new Error(`Shard is truncated: ${reason}`);
        }
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

    const magic = new TextDecoder().decode(readBytes(4, 'magic'));
    if (magic !== QCONT_MAGIC) {
        throw new Error('Invalid .qcont magic');
    }

    const metaLen = readU16('metaLen');
    if (metaLen <= 0) throw new Error('Invalid shard metadata length');
    const metaBytes = readBytes(metaLen, 'metaJSON');
    let metaJSON;
    try {
        metaJSON = JSON.parse(new TextDecoder().decode(metaBytes));
    } catch (error) {
        throw new Error(`Invalid shard metadata JSON: ${error?.message || error}`);
    }
    if (metaJSON?.alg?.fmt !== QCONT_FORMAT_VERSION) {
        throw new Error(`Unsupported shard format: expected ${QCONT_FORMAT_VERSION}, got ${metaJSON?.alg?.fmt ?? 'unknown'}`);
    }

    const encapLen = readU32('encapsulatedKey length');
    if (encapLen <= 0) throw new Error('Invalid encapsulated key length');
    const encapsulatedKey = readBytes(encapLen, 'encapsulatedKey');

    const iv = readBytes(12, 'container nonce');
    const salt = readBytes(16, 'kdf salt');

    const qencMetaLen = readU16('qenc metadata length');
    if (qencMetaLen <= 0) throw new Error('Invalid qenc metadata length');
    const qencMetaBytes = readBytes(qencMetaLen, 'qenc metadata');

    const kcLen = readBytes(1, 'key commitment length')[0];
    if (kcLen > KEY_COMMITMENT_MAX_LEN) {
        throw new Error(`Invalid key commitment length: ${kcLen}`);
    }
    const keyCommit = kcLen > 0 ? readBytes(kcLen, 'key commitment') : null;

    const shardIndex = readU16('shard index');
    const shareLen = readU16('share length');
    if (shareLen <= 0) throw new Error('Invalid Shamir share length');
    const share = readBytes(shareLen, 'Shamir share');
    const fragments = arr.subarray(off);

    const headerFingerprint = createShardFingerprint([
        metaBytes,
        encapsulatedKey,
        iv,
        salt,
        qencMetaBytes,
        keyCommit || new Uint8Array(0)
    ]);

    return {
        metaJSON,
        metaBytes,
        encapsulatedKey,
        iv,
        salt,
        qencMetaBytes,
        keyCommit,
        shardIndex,
        share,
        fragments,
        headerFingerprint,
        diagnostics: { errors: [], warnings: [] }
    };
}

/**
 * Parse a single .qcont shard from raw bytes
 * @param {Uint8Array} arr - Raw shard bytes
 * @param {object} [options]
 * @param {boolean} [options.strict=true]
 * @returns {object} Parsed shard structure with diagnostics/fingerprint
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

/**
 * Restore .qenc container and private key from parsed shards
 * Core logic without UI dependencies — can be used by both Pro and Lite modes
 * 
 * @param {object[]} shards - Array of parsed shard objects (from parseShard)
 * @param {object} options - Optional callbacks for logging
 * @param {function} [options.onLog] - Log callback (msg) => void
 * @param {function} [options.onError] - Error log callback (msg) => void
 * @param {boolean} [options.strict=true]
 * @param {boolean} [options.consensusRequired=true]
 * @returns {Promise<object>} { qencBytes, privKey, containerId, containerHash, privateKeyHash, qencOk, qkeyOk }
 */
export async function restoreFromShards(shards, options = {}) {
    const onLog = options.onLog || (() => {});
    const onError = options.onError || (() => {});
    const strict = options.strict ?? true;
    const consensusRequired = options.consensusRequired ?? true;

    if (!Array.isArray(shards) || shards.length === 0) {
        throw new Error('No shards provided');
    }

    const prepared = [];
    for (let i = 0; i < shards.length; i++) {
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
            inputShardIndex: Number.isInteger(shard?.shardIndex) ? shard.shardIndex : i
        });
    }
    if (prepared.length === 0) {
        throw new Error('No valid shards after parsing');
    }

    let group = prepared;
    let consensusInfo = null;
    const rejectedShardIndices = [];

    if (consensusRequired) {
        const byFingerprint = new Map();
        for (const shard of prepared) {
            const fp = shard.headerFingerprint;
            if (typeof fp !== 'string' || fp.length === 0) {
                if (strict) throw new Error('Shard is missing header fingerprint');
                rejectedShardIndices.push(shard.inputShardIndex);
                continue;
            }
            if (!byFingerprint.has(fp)) byFingerprint.set(fp, []);
            byFingerprint.get(fp).push(shard);
        }
        if (byFingerprint.size === 0) {
            throw new Error('No valid shard cohort found');
        }

        let bestFingerprint = null;
        let bestGroup = null;
        for (const [fingerprint, cohort] of byFingerprint.entries()) {
            if (!bestGroup || cohort.length > bestGroup.length) {
                bestFingerprint = fingerprint;
                bestGroup = cohort;
            }
        }
        group = bestGroup;
        for (const shard of prepared) {
            if (shard.headerFingerprint !== bestFingerprint) {
                rejectedShardIndices.push(shard.inputShardIndex);
            }
        }
        consensusInfo = {
            consensusRequired: true,
            fingerprint: bestFingerprint,
            totalInput: prepared.length,
            cohortSize: group.length,
            rejectedCount: rejectedShardIndices.length
        };
        onLog(`Header consensus selected ${group.length}/${prepared.length} shard(s).`);
    }

    // Validate all shards belong to same container
    const containerIdSet = new Set(group.map(s => s.metaJSON?.containerId));
    if (containerIdSet.size !== 1) {
        throw new Error('Selected shards belong to different containers (containerId mismatch)');
    }

    const containerId = group[0].metaJSON.containerId;
    const { n, k, m, t: metaT, ciphertextLength, chunkSize, chunkCount, containerHash, privateKeyHash, aead_mode } = group[0].metaJSON;
    const rsEncodeBase = Number.isInteger(group[0].metaJSON.rsEncodeBase) ? group[0].metaJSON.rsEncodeBase : 255;
    if ((m % 2) !== 0) {
        throw new Error('Invalid shard parameters: n - k must be even');
    }
    const allowedFailures = m / 2;
    const t = k + allowedFailures;
    if (metaT !== t) {
        throw new Error(`Shard threshold mismatch: meta t=${metaT}, expected t=${t} from n/k`);
    }
    const isPerChunkMode = aead_mode === 'per-chunk';
    if (!isPerChunkMode && aead_mode !== 'single-container') {
        throw new Error(`Unsupported shard AEAD mode: ${aead_mode ?? 'unknown'}`);
    }
    const effectiveLength = group[0].metaJSON.payloadLength || group[0].metaJSON.originalLength;
    
    // Validate shard parameters consistency
    for (const s of group) {
        const mm = s.metaJSON;
        if (
            mm.containerId !== containerId || mm.n !== n || mm.k !== k || mm.m !== m || mm.t !== t ||
            mm.ciphertextLength !== ciphertextLength || mm.chunkCount !== chunkCount || mm.chunkSize !== chunkSize
        ) {
            throw new Error('Shard parameter mismatch (containerId/n/k/m/t)');
        }
    }

    // Validate shard indices and cross-check header consistency
    const shardByIndex = new Map();
    const base = group[0];
    const baseKeyCommit = base.keyCommit || new Uint8Array(0);
    for (const shard of group) {
        if (!Number.isInteger(shard.shardIndex) || shard.shardIndex < 0 || shard.shardIndex >= n) {
            throw new Error(`Invalid shardIndex ${shard.shardIndex}`);
        }
        if (shardByIndex.has(shard.shardIndex)) {
            throw new Error(`Duplicate shardIndex ${shard.shardIndex} detected`);
        }
        shardByIndex.set(shard.shardIndex, shard);

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
    for (let i = 0; i < n; i++) {
        if (!shardByIndex.has(i)) missingIndices.add(i);
    }
    
    // Verify encapsulated key hash
    const encapHash = await hashBytes(group[0].encapsulatedKey);
    if (encapHash !== group[0].metaJSON.encapBlobHash) {
        throw new Error('encapBlobHash mismatch');
    }
    
    // Check threshold
    if (group.length < t) {
        throw new Error(`Need at least ${t} shards, got ${group.length}`);
    }
    
    // Verify share commitments (Verifiable Secret Sharing)
    let validShareShards = group;
    if (group[0].metaJSON.shareCommitments) {
        validShareShards = [];
        const invalidShareIndices = new Set();
        for (const shard of group) {
            const expected = group[0].metaJSON.shareCommitments[shard.shardIndex];
            if (expected) {
                const actual = await hashBytes(shard.share);
                if (actual !== expected) {
                    onError(`Share commitment verification failed for shard ${shard.shardIndex}. Share will be skipped.`);
                    invalidShareIndices.add(shard.shardIndex);
                    continue;
                }
                validShareShards.push(shard);
            } else {
                onError(`Missing share commitment for shard ${shard.shardIndex}. Share will be skipped.`);
                invalidShareIndices.add(shard.shardIndex);
            }
        }
        if (validShareShards.length < t) {
            throw new Error(`Not enough valid shards for Shamir reconstruction: need ${t}, have ${validShareShards.length}`);
        }
        if (invalidShareIndices.size === 0) {
            onLog('Share commitments verified.');
        } else {
            onError(`Share commitments failed for ${invalidShareIndices.size} shard(s). Proceeding with valid shares.`);
        }
    }
    
    // Verify fragment body hashes (shard-level integrity)
    const corruptedShardIndices = new Set();
    if (group[0].metaJSON.fragmentBodyHashes) {
        for (const shard of group) {
            const expected = group[0].metaJSON.fragmentBodyHashes[shard.shardIndex];
            if (expected) {
                const actual = await hashBytes(shard.fragments);
                if (actual !== expected) {
                    onError(`Fragment integrity check failed for shard ${shard.shardIndex}. Treating as erasure.`);
                    corruptedShardIndices.add(shard.shardIndex);
                }
            }
        }
        if (corruptedShardIndices.size === 0) {
            onLog('Fragment body hashes verified.');
        }
    }
    const missingCount = missingIndices.size;
    const totalBad = missingCount + corruptedShardIndices.size;
    if (totalBad > allowedFailures) {
        throw new Error(`Too many missing/corrupted shards for RS reconstruction: allowed ${allowedFailures}, got ${totalBad}`);
    }
    // Restore private key from Shamir shares
    const sortedShares = validShareShards.slice().sort((a, b) => a.shardIndex - b.shardIndex);
    const selectedShares = sortedShares.slice(0, t).map(s => s.share);
    const { combineShares } = await import('../splitting/sss.js');
    const privKey = await combineShares(selectedShares);
    
    // Reconstruct ciphertext via Reed-Solomon
    const totalLen = ciphertextLength;
    const totalChunks = chunkCount;
    const cipherChunks = [];
    const shardOffsets = new Array(n).fill(0);
    
    for (let i = 0; i < totalChunks; i++) {
        const plainLen = Math.min(chunkSize, effectiveLength - (i * chunkSize));
        const thisLen = isPerChunkMode ? (plainLen + 16) : totalLen;
        
        // Library-aligned expected fragment length per shard
        const encodeSize = Math.floor(rsEncodeBase / n) * n;
        if (encodeSize === 0) throw new Error('RS parameters too large');
        const inputSize = (encodeSize * k) / n;
        const symbolSize = inputSize / k;
        const blocks = Math.ceil(thisLen / inputSize);
        const expectedFragLen = blocks * symbolSize;
        
        const encoded = new Array(n);
        for (let j = 0; j < n; j++) {
            // Skip corrupted shards — treat as erasure (zero-filled)
            const matchShard = shardByIndex.get(j);
            const fragStream = (matchShard && !corruptedShardIndices.has(j)) ? matchShard.fragments : null;
            
            if (!fragStream) {
                encoded[j] = new Uint8Array(expectedFragLen);
                continue;
            }
            
            const viewLen = fragStream.length;
            const off = shardOffsets[j];
            if (off + 4 > viewLen) throw new Error('Fragment stream underflow');
            
            const dvFrag = new DataView(fragStream.buffer, fragStream.byteOffset + off);
            const fragLen = dvFrag.getUint32(0, false);
            const fragStart = off + 4;
            const fragEnd = fragStart + fragLen;
            if (fragEnd > viewLen) throw new Error('Fragment length overflow');
            
            let fragSlice = fragStream.subarray(fragStart, fragEnd);
            if (fragLen < expectedFragLen) {
                const padded = new Uint8Array(expectedFragLen);
                padded.set(fragSlice);
                fragSlice = padded;
            } else if (fragLen > expectedFragLen) {
                fragSlice = fragSlice.subarray(0, expectedFragLen);
            }
            
            encoded[j] = fragSlice;
            shardOffsets[j] = fragEnd;
        }
        
        let recombined;
        try {
            recombined = window.erasure.recombine(encoded, thisLen, k, m / 2, rsEncodeBase);
        } catch (e) {
            throw new Error(`RS recombination failed on chunk ${i}: ${e?.message ?? e}`);
        }
        cipherChunks.push(recombined);
        if (!isPerChunkMode) break;
    }

    for (let j = 0; j < n; j++) {
        if (corruptedShardIndices.has(j)) continue;
        const shard = shardByIndex.get(j);
        if (!shard) continue;
        if (shardOffsets[j] !== shard.fragments.length) {
            throw new Error(`Fragment stream has trailing or missing data in shard ${j}`);
        }
    }
    
    const ciphertext = isPerChunkMode
        ? (() => {
            const total = cipherChunks.reduce((a, c) => a + c.length, 0);
            const out = new Uint8Array(total);
            let p = 0;
            for (const ch of cipherChunks) { out.set(ch, p); p += ch.length; }
            return out;
        })()
        : cipherChunks[0];
    
    // Reconstruct header including key commitment if present
    const { encapsulatedKey, iv: containerNonce, salt: kdfSalt, qencMetaBytes, keyCommit } = group[0];
    if (group[0].metaJSON?.hasKeyCommitment && (!keyCommit || keyCommit.length === 0)) {
        throw new Error('Missing key commitment in shard data (expected by metadata).');
    }
    const header = buildQencHeader({
        encapsulatedKey,
        containerNonce,
        kdfSalt,
        metaBytes: qencMetaBytes,
        keyCommitment: (keyCommit && keyCommit.length > 0) ? keyCommit : null
    });
    
    const qencBytes = new Uint8Array(header.length + ciphertext.length);
    qencBytes.set(header, 0);
    qencBytes.set(ciphertext, header.length);
    
    // Verify hashes
    const recoveredQencHash = await hashBytes(qencBytes);
    const recoveredPrivHash = await hashBytes(privKey);
    const qencOk = recoveredQencHash === containerHash;
    const qkeyOk = recoveredPrivHash === privateKeyHash;
    
    return {
        qencBytes,
        privKey,
        containerId,
        containerHash,
        privateKeyHash,
        recoveredQencHash,
        recoveredPrivHash,
        rejectedShardIndices,
        consensusInfo,
        qencOk,
        qkeyOk
    };
}

/**
 * Initialize Pro Mode restore UI
 * Uses restoreFromShards() core logic
 */
export function initQcontRestoreUI() {
    const qcontShardsInput = document.getElementById('qcontShardsInput');
    const restoreQcontBtn = document.getElementById('restoreQcontBtn');

    restoreQcontBtn?.addEventListener('click', async () => {
        const files = qcontShardsInput?.files;
        if (!files?.length) { logError('Select .qcont shards'); return; }
        if (files.length < 2) { logError('Select at least two .qcont shards'); return; }
        
        // First check: all file sizes identical
        const firstSize = files[0].size;
        for (let i = 1; i < files.length; i++) {
            if (files[i].size !== firstSize) {
                logError('All selected .qcont shards must have the same file size.');
                return;
            }
        }
        
        setButtonsDisabled(true);
        try {
            // Parse shards
            const shardBytesArr = await Promise.all([...files].map(readFileAsUint8Array));
            const shards = shardBytesArr.map(parseShard);
            
            // Restore using core logic
            const result = await restoreFromShards(shards, {
                onLog: (msg) => log(msg),
                onError: (msg) => logError(msg)
            });
            
            const { qencBytes, privKey, containerId, containerHash, privateKeyHash, 
                    recoveredQencHash, recoveredPrivHash, qencOk, qkeyOk } = result;
            
            // Log results
            log(`Recovered .qenc SHA3-512=${recoveredQencHash} (expected ${containerHash})`);
            log(qencOk ? 'Hashes match! File integrity verified.' : 'WARNING: .qenc hash mismatch!');
            log(`Recovered .qkey SHA3-512=${recoveredPrivHash} (expected ${privateKeyHash})`);
            log(qkeyOk ? 'Hashes match! File integrity verified.' : 'WARNING: .qkey hash mismatch!');
            
            // Download or show manual links
            const qencBlob = new Blob([qencBytes], { type: 'application/octet-stream' });
            const qkeyBlob = new Blob([privKey], { type: 'application/octet-stream' });
            const qencName = `${containerId}.recovered.qenc`;
            const qkeyName = `${containerId}.recovered.secretKey.qkey`;
            
            if (qencOk && qkeyOk) {
                download(qencBlob, qencName);
                download(qkeyBlob, qkeyName);
                log('✅ Recovered .qenc and .qkey from .qcont shards.');
            } else {
                logError('Hash mismatch detected. Automatic download is blocked. Review and download manually if needed.');
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
        } catch (e) {
            logError(e);
        } finally {
            setButtonsDisabled(false);
        }
    });
}
