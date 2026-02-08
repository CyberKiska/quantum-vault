import { CHUNK_SIZE, hashBytes } from '../index.js';
import { log, logError } from '../../features/ui/logging.js';
import { setButtonsDisabled, readFileAsUint8Array, download } from '../../../utils.js';
import { buildQencHeader } from '../qenc/format.js';

function bytesEqual(a, b) {
    if (a === b) return true;
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Parse a single .qcont shard from raw bytes
 * @param {Uint8Array} arr - Raw shard bytes
 * @returns {object} Parsed shard structure
 */
export function parseShard(arr) {
    const dv = new DataView(arr.buffer, arr.byteOffset);
    let off = 0;
    
    const magic = new TextDecoder().decode(arr.subarray(off, off + 4)); off += 4;
    if (magic !== 'QVC1') throw new Error('Invalid .qcont magic');
    
    const metaLen = dv.getUint16(off, false); off += 2;
    const metaJSON = JSON.parse(new TextDecoder().decode(arr.subarray(off, off + metaLen))); off += metaLen;
    
    const encapLen = dv.getUint32(off, false); off += 4;
    const encapsulatedKey = arr.subarray(off, off + encapLen); off += encapLen;
    
    const iv = arr.subarray(off, off + 12); off += 12;
    const salt = arr.subarray(off, off + 16); off += 16;
    
    const qencMetaLen = dv.getUint16(off, false); off += 2;
    const qencMetaBytes = arr.subarray(off, off + qencMetaLen); off += qencMetaLen;
    
    // Parse key commitment if present (QVqcont-2+)
    let keyCommit = null;
    if (metaJSON.alg?.fmt === 'QVqcont-2') {
        const kcLen = arr[off]; off += 1;
        if (kcLen > 0) {
            keyCommit = arr.subarray(off, off + kcLen);
            off += kcLen;
        }
    }
    
    const shardIndex = dv.getUint16(off, false); off += 2;
    const shareLen = dv.getUint16(off, false); off += 2;
    const share = arr.subarray(off, off + shareLen); off += shareLen;
    const fragments = arr.subarray(off);
    
    return { metaJSON, encapsulatedKey, iv, salt, qencMetaBytes, keyCommit, shardIndex, share, fragments };
}

/**
 * Restore .qenc container and private key from parsed shards
 * Core logic without UI dependencies — can be used by both Pro and Lite modes
 * 
 * @param {object[]} shards - Array of parsed shard objects (from parseShard)
 * @param {object} options - Optional callbacks for logging
 * @param {function} options.onLog - Log callback (msg) => void
 * @param {function} options.onError - Error log callback (msg) => void
 * @returns {Promise<object>} { qencBytes, privKey, containerId, containerHash, privateKeyHash, qencOk, qkeyOk }
 */
export async function restoreFromShards(shards, options = {}) {
    const onLog = options.onLog || (() => {});
    const onError = options.onError || (() => {});
    
    // Validate all shards belong to same container
    const containerIdSet = new Set(shards.map(s => s.metaJSON?.containerId));
    if (containerIdSet.size !== 1) {
        throw new Error('Selected shards belong to different containers (containerId mismatch)');
    }
    
    // Group by container ID (supports future multi-container restore)
    const byId = new Map();
    for (const s of shards) {
        const id = s.metaJSON.containerId;
        if (!byId.has(id)) byId.set(id, []);
        byId.get(id).push(s);
    }
    
    const [containerId, group] = [...byId.entries()][0];
    const { n, k, m, t: metaT, ciphertextLength, chunkSize, chunkCount, containerHash, privateKeyHash, aead_mode } = group[0].metaJSON;
    const rsEncodeBase = Number.isInteger(group[0].metaJSON.rsEncodeBase) ? group[0].metaJSON.rsEncodeBase : 256;
    if ((m % 2) !== 0) {
        throw new Error('Invalid shard parameters: n - k must be even');
    }
    const allowedFailures = m / 2;
    const t = k + allowedFailures;
    if (metaT !== t) {
        throw new Error(`Shard threshold mismatch: meta t=${metaT}, expected t=${t} from n/k`);
    }
    const isPerChunkMode = aead_mode === 'per-chunk' || aead_mode === 'per-chunk-aead';
    const effectiveLength = group[0].metaJSON.payloadLength || group[0].metaJSON.originalLength;
    
    // Validate shard parameters consistency
    for (const s of group) {
        const mm = s.metaJSON;
        if (mm.containerId !== containerId || mm.n !== n || mm.k !== k || mm.m !== m || mm.t !== t) {
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
    if (rsEncodeBase === 256 && (missingIndices.has(0) || missingIndices.has(n - 1) || corruptedShardIndices.has(0) || corruptedShardIndices.has(n - 1))) {
        onError('Legacy RS codeword length 256 cannot recover if shard 1 or shard n is missing/corrupted. Include those shards or rebuild with updated format.');
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
