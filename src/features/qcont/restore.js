import { MAGIC, CHUNK_SIZE, hashBytes } from '../../core/crypto.js';

async function hexDigest(u8) {
    const buf = await crypto.subtle.digest('SHA-256', u8);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

function log(msg) {
    const logEl = document.getElementById('log');
    if (!logEl) return;
    logEl.textContent += `[${new Date().toLocaleTimeString()}] ${msg}\n`;
    logEl.scrollTop = logEl.scrollHeight;
}
function logError(err) {
    const logEl = document.getElementById('log');
    if (!logEl) return;
    const text = (err && err.message) ? err.message : (typeof err === 'string' ? err : String(err));
    const errorSpan = document.createElement('span');
    errorSpan.className = 'error';
    errorSpan.textContent = `[${new Date().toLocaleTimeString()}] ERROR: ${text}`;
    logEl.appendChild(errorSpan);
    logEl.appendChild(document.createTextNode('\n'));
    logEl.scrollTop = logEl.scrollHeight;
}
function setButtonsDisabled(disabled) {
    document.querySelectorAll('button').forEach(btn => { btn.disabled = disabled; });
}
async function readFileAsUint8Array(file) { return new Uint8Array(await file.arrayBuffer()); }
function download(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(a.href);
    a.remove();
}

export function initQcontRestoreUI() {
    const qcontShardsInput = document.getElementById('qcontShardsInput');
    const restoreQcontBtn = document.getElementById('restoreQcontBtn');

    restoreQcontBtn?.addEventListener('click', async () => {
        const files = qcontShardsInput?.files;
        if (!files?.length) { logError('Select .qcont shards'); return; }
        if (files.length < 2) { logError('Select at least two .qcont shards'); return; }
        const firstSize = files[0].size;
        for (let i = 1; i < files.length; i++) {
            if (files[i].size !== firstSize) { logError('All selected .qcont shards must have the same file size.'); return; }
        }
        setButtonsDisabled(true);
        try {
            const shardBytesArr = await Promise.all([...files].map(readFileAsUint8Array));
            const shards = shardBytesArr.map(arr => {
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
                const shardIndex = dv.getUint16(off, false); off += 2;
                const shareLen = dv.getUint16(off, false); off += 2;
                const share = arr.subarray(off, off + shareLen); off += shareLen;
                const fragments = arr.subarray(off);
                console.log(`RESTORE: shardIndex=${shardIndex} totalFragBytes=${fragments.length}`);
                // If perFragmentSize known — log first fragment hash for correlation
                const pfs = metaJSON.perFragmentSize;
                if (pfs && fragments.length >= (4 + pfs)) {
                    const dvf = new DataView(fragments.buffer, fragments.byteOffset);
                    const fLen = dvf.getUint32(0, false);
                    const fStart = 4;
                    const fEnd = fStart + Math.min(fLen, pfs);
                    const firstFrag = fragments.subarray(fStart, fEnd);
                    hexDigest(firstFrag).then(h => console.log(`  -> firstFrag len=${firstFrag.length} sha256=${h}`));
                }
                return { metaJSON, encapsulatedKey, iv, salt, qencMetaBytes, shardIndex, share, fragments };
            });
            const byId = new Map();
            for (const s of shards) {
                const id = s.metaJSON.containerId;
                if (!byId.has(id)) byId.set(id, []);
                byId.get(id).push(s);
            }
            const [containerId, group] = [...byId.entries()][0];
            const { n, k, m, t, ciphertextLength, chunkSize, chunkCount, containerHash, privateKeyHash, aead_mode, perFragmentSize } = group[0].metaJSON;
            const isPerChunkMode = aead_mode === 'per-chunk' || aead_mode === 'per-chunk-aead';
            for (const s of group) {
                const mm = s.metaJSON;
                if (mm.containerId !== containerId || mm.n !== n || mm.k !== k || mm.m !== m || mm.t !== t) {
                    throw new Error('Shard parameter mismatch (containerId/n/k/m/t)');
                }
            }
            const encapHash = await hashBytes(group[0].encapsulatedKey);
            if (encapHash !== group[0].metaJSON.encapBlobHash) throw new Error('encapBlobHash mismatch');
            if (group.length < t) throw new Error(`Need at least ${t} shards, got ${group.length}`);

            const sortedGroup = group.slice().sort((a, b) => a.shardIndex - b.shardIndex);
            const selectedShares = sortedGroup.slice(0, t).map(s => s.share);
            const privKey = await (await import('shamir-secret-sharing')).combine(selectedShares);

            const encodeSize = Math.floor(256 / n) * n;
            const inputSize = (encodeSize * k) / n;
            const totalLen = ciphertextLength;
            const totalChunks = chunkCount;
            const cipherChunks = [];
            const shardOffsets = new Array(n).fill(0);
            for (let i = 0; i < totalChunks; i++) {
                const plainLen = Math.min(chunkSize, (group[0].metaJSON.originalLength) - (i * chunkSize));
                const thisLen = isPerChunkMode ? (plainLen + 16) : totalLen;
                // Library-aligned expected fragment length per shard
                // encodeSize = floor(256/n) * n; inputSize = encodeSize * k / n; symbolSize = inputSize / k
                const encodeSize = Math.floor(256 / n) * n;
                const inputSize = (encodeSize * k) / n;
                const symbolSize = inputSize / k;
                const blocks = Math.ceil(thisLen / inputSize);
                const expectedFragLen = blocks * symbolSize;

                const encoded = new Array(n);
                for (let j = 0; j < n; j++) {
                    const fragStream = group.find(s => s.shardIndex === j)?.fragments;
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
                const recombined = window.erasure.recombine(encoded, thisLen, k, m/2);
                cipherChunks.push(recombined);
                if (!isPerChunkMode) break;
            }
            const ciphertext = isPerChunkMode
                ? (() => { const total = cipherChunks.reduce((a, c) => a + c.length, 0); const out = new Uint8Array(total); let p = 0; for (const ch of cipherChunks) { out.set(ch, p); p += ch.length; } return out; })()
                : cipherChunks[0];

            const header = (() => {
                const { encapsulatedKey, iv, salt, qencMetaBytes } = group[0];
                const keyLenBytes = new Uint8Array(4); new DataView(keyLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);
                const metaLenBytes = new Uint8Array(2); new DataView(metaLenBytes.buffer).setUint16(0, qencMetaBytes.length, false);
                const h = new Uint8Array(MAGIC.length + 4 + encapsulatedKey.length + 12 + 16 + 2 + qencMetaBytes.length);
                let p = 0;
                h.set(MAGIC, p); p += MAGIC.length;
                h.set(keyLenBytes, p); p += 4;
                h.set(encapsulatedKey, p); p += encapsulatedKey.length;
                h.set(iv, p); p += 12;
                h.set(salt, p); p += 16;
                h.set(metaLenBytes, p); p += 2;
                h.set(qencMetaBytes, p);
                return h;
            })();
            const qencBytes = new Uint8Array(header.length + ciphertext.length);
            qencBytes.set(header, 0);
            qencBytes.set(ciphertext, header.length);

            const recoveredQencHash = await hashBytes(qencBytes);
            const recoveredPrivHash = await hashBytes(privKey);
            const qencOk = recoveredQencHash === containerHash;
            const qkeyOk = recoveredPrivHash === privateKeyHash;
            log(`Recovered .qenc SHA3-512=${recoveredQencHash} (expected ${containerHash})`);
            log(qencOk ? 'Hashes match! File integrity verified.' : 'WARNING: .qenc hash mismatch!');
            log(`Recovered .qkey SHA3-512=${recoveredPrivHash} (expected ${privateKeyHash})`);
            log(qkeyOk ? 'Hashes match! File integrity verified.' : 'WARNING: .qkey hash mismatch!');

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
                const a1 = document.createElement('a'); a1.href = URL.createObjectURL(qencBlob); a1.download = qencName; a1.textContent = `Manual download: ${qencName}`; a1.target = '_blank'; a1.rel='noopener';
                const a2 = document.createElement('a'); a2.href = URL.createObjectURL(qkeyBlob); a2.download = qkeyName; a2.textContent = `Manual download: ${qkeyName}`; a2.target = '_blank'; a2.rel='noopener';
                const logEl = document.getElementById('log'); logEl.appendChild(a1); logEl.appendChild(document.createTextNode('\n')); logEl.appendChild(a2); logEl.appendChild(document.createTextNode('\n'));
            }
        } catch (e) { logError(e); } finally { setButtonsDisabled(false); }
    });
}


