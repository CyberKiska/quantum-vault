import { CHUNK_SIZE, hashBytes } from '../index.js';
import { log, logError } from '../../features/ui/logging.js';
import { setButtonsDisabled, readFileAsUint8Array, download, validateRsParams, toHex } from '../../../utils.js';
import { parseQencHeader } from '../qenc/format.js';
import { QCONT_FORMAT_VERSION } from '../constants.js';

export async function buildQcontShards(qencBytes, privKeyBytes, params, options = {}) {
    const formatVersion = options.formatVersion || QCONT_FORMAT_VERSION;
    if (formatVersion !== QCONT_FORMAT_VERSION) {
        throw new Error(`Unsupported shard format version: ${formatVersion}`);
    }

    const { n, k } = params;
    const m = n - k;
    if (k < 2 || n <= k) throw new Error('Invalid RS parameters: require 2 <= k < n');
    if ((m % 2) !== 0) throw new Error('n-k must be even');
    const {
        header,
        offset,
        encapsulatedKey,
        containerNonce,
        kdfSalt,
        metaBytes,
        metadata,
        storedKeyCommitment
    } = parseQencHeader(qencBytes);

    const meta = metadata;
    const keyCommitment = storedKeyCommitment;
    const ciphertext = qencBytes.subarray(offset);

    const ds = meta.domainStrings;
    if (!ds || typeof ds.kdf !== 'string' || typeof ds.iv !== 'string') {
        throw new Error('QENC metadata is missing valid domainStrings');
    }
    const effectiveLength = meta.payloadLength || meta.originalLength;
    const containerId = await hashBytes(header); // header hash as ID
    const containerHash = await hashBytes(qencBytes);

    const t = k + (m / 2);
    if (t > n) throw new Error('Invalid threshold computed');
    const { splitSecret } = await import('../splitting/sss.js');
    const shares = await splitSecret(privKeyBytes, n, t);

    // Compute share commitments (Verifiable Secret Sharing)
    const shareCommitments = [];
    for (let j = 0; j < n; j++) {
        shareCommitments.push(await hashBytes(shares[j]));
    }

    const shardBuffers = Array.from({ length: n }, () => []);

    const chunkSize = meta.chunkSize || CHUNK_SIZE;
    const isPerChunk = meta.aead_mode === 'per-chunk-aead';
    const totalChunks = isPerChunk ? (meta.chunkCount || Math.ceil(effectiveLength / chunkSize)) : 1;

    // RS codeword length must be <= 255 for GF(2^8) to avoid evaluation collisions
    const RS_MAX_CODEWORD = 255;

    let ctOffset = 0;
    let perFragmentSize = 0;
    for (let i = 0; i < totalChunks; i++) {
        let cipherChunk;
        if (isPerChunk) {
            const plainLen = Math.min(chunkSize, effectiveLength - (i * chunkSize));
            const encLen = plainLen + 16;
            cipherChunk = ciphertext.subarray(ctOffset, ctOffset + encLen);
            ctOffset += encLen;
        } else {
            cipherChunk = ciphertext;
        }

        // Library-aligned padding: pad to multiples of inputSize = (encodeSize * k) / n
        const encodeSize = (Math.floor(RS_MAX_CODEWORD / n)) * n;
        if (encodeSize === 0) throw new Error('RS parameters too large');
        const inputSize = (encodeSize * k) / n;
        const padTarget = Math.ceil(cipherChunk.length / inputSize) * inputSize;
        let chunkForRS = cipherChunk;
        if (padTarget > cipherChunk.length) {
            const padded = new Uint8Array(padTarget);
            padded.set(cipherChunk);
            chunkForRS = padded;
        }

        const fragments = window.erasure.split(chunkForRS, k, m/2, RS_MAX_CODEWORD);
        if (fragments.length !== n) throw new Error('RS split returned unexpected number of fragments');
        if (i === 0) perFragmentSize = fragments[0].length;
        for (let j = 0; j < fragments.length; j++) {
            const frag = fragments[j];
            const len32 = new Uint8Array(4); new DataView(len32.buffer).setUint32(0, frag.length, false);
            shardBuffers[j].push(len32, frag);
        }
    }

    // Compute fragment body hashes for all shards (shard-level integrity)
    const shardBodyBytesArr = [];
    const fragmentBodyHashes = [];
    for (let j = 0; j < n; j++) {
        const body = new Blob(shardBuffers[j]);
        const bodyBytes = new Uint8Array(await body.arrayBuffer());
        shardBodyBytesArr.push(bodyBytes);
        fragmentBodyHashes.push(await hashBytes(bodyBytes));
    }

    const timestamp = new Date().toISOString();
    const metaJSON = {
        containerId,
        alg: { KEM: 'ML-KEM-1024', KDF: 'KMAC256', AEAD: 'AES-256-GCM', RS: 'ErasureCodes', fmt: formatVersion },
        aead_mode: isPerChunk ? 'per-chunk' : 'single-container',
        iv_strategy: meta.iv_strategy,
        n, k, m, t,
        rsEncodeBase: RS_MAX_CODEWORD,
        chunkSize,
        chunkCount: totalChunks,
        containerHash,
        encapBlobHash: await hashBytes(encapsulatedKey),
        privateKeyHash: await hashBytes(privKeyBytes),
        payloadLength: meta.payloadLength || null,
        originalLength: effectiveLength,
        ciphertextLength: ciphertext.length,
        domainStrings: { kdf: ds.kdf, iv: ds.iv },
        fragmentFormat: 'len32-prefixed',
        perFragmentSize,
        hasKeyCommitment: !!keyCommitment,
        keyCommitmentHex: keyCommitment ? toHex(keyCommitment) : null,
        shareCommitments,
        fragmentBodyHashes,
        timestamp
    };

    const metaJSONBytes = new TextEncoder().encode(JSON.stringify(metaJSON));
    const metaLenBytes = new Uint8Array(2); new DataView(metaLenBytes.buffer).setUint16(0, metaJSONBytes.length, false);
    const encapLenBytes = new Uint8Array(4); new DataView(encapLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);

    const qcontMagic = new TextEncoder().encode('QVC1');
    const keyCommitBytes = keyCommitment || new Uint8Array(0);
    const keyCommitLenByte = new Uint8Array([keyCommitBytes.length]);

    const qconts = [];
    for (let j = 0; j < n; j++) {
        const bodyBytes = shardBodyBytesArr[j];
        const qencMetaLenBytes = new Uint8Array(2); new DataView(qencMetaLenBytes.buffer).setUint16(0, metaBytes.length, false);
        const shardHeader = new Uint8Array(
            qcontMagic.length + 2 + metaJSONBytes.length + 4 + encapsulatedKey.length +
            12 + 16 + 2 + metaBytes.length + 1 + keyCommitBytes.length + 2 + 2 + shares[j].length
        );
        let p2 = 0;
        shardHeader.set(qcontMagic, p2); p2 += qcontMagic.length;
        shardHeader.set(metaLenBytes, p2); p2 += 2;
        shardHeader.set(metaJSONBytes, p2); p2 += metaJSONBytes.length;
        shardHeader.set(encapLenBytes, p2); p2 += 4;
        shardHeader.set(encapsulatedKey, p2); p2 += encapsulatedKey.length;
        shardHeader.set(containerNonce, p2); p2 += 12;
        shardHeader.set(kdfSalt, p2); p2 += 16;
        shardHeader.set(qencMetaLenBytes, p2); p2 += 2;
        shardHeader.set(metaBytes, p2); p2 += metaBytes.length;
        shardHeader.set(keyCommitLenByte, p2); p2 += 1;
        if (keyCommitBytes.length > 0) { shardHeader.set(keyCommitBytes, p2); p2 += keyCommitBytes.length; }
        const idx = new Uint8Array(2); new DataView(idx.buffer).setUint16(0, j, false);
        shardHeader.set(idx, p2); p2 += 2;
        const shareLen = new Uint8Array(2); new DataView(shareLen.buffer).setUint16(0, shares[j].length, false);
        shardHeader.set(shareLen, p2); p2 += 2;
        shardHeader.set(shares[j], p2);

        const blob = new Blob([shardHeader, bodyBytes], { type: 'application/octet-stream' });
        qconts.push({ blob, index: j });
    }
    return qconts;
}

export function initQcontBuildUI() {
    const qencForQcontInput = document.getElementById('qencForQcontInput');
    const privKeyForQcontInput = document.getElementById('privKeyForQcontInput');
    const rsNInput = document.getElementById('rsN');
    const rsKInput = document.getElementById('rsK');
    const buildQcontBtn = document.getElementById('buildQcontBtn');

    buildQcontBtn?.addEventListener('click', async () => {
        if (!qencForQcontInput?.files?.[0]) { logError('Select .qenc'); return; }
        if (!privKeyForQcontInput?.files?.[0]) { logError('Select private .qkey to split'); return; }
        const privKeyFile = privKeyForQcontInput.files[0];
        if (privKeyFile.size !== 3168) { logError(`Private .qkey must be exactly 3168 bytes (got ${privKeyFile.size} B)`); return; }
        setButtonsDisabled(true);
        try {
            const qencBytes = await readFileAsUint8Array(qencForQcontInput.files[0]);
            const privKeyBytes = await readFileAsUint8Array(privKeyForQcontInput.files[0]);
            const n = parseInt(rsNInput.value, 10);
            const k = parseInt(rsKInput.value, 10);
            if (Number.isNaN(n) || Number.isNaN(k)) throw new Error('Invalid parameters');
            if (k < 2 || n <= k) throw new Error('Require 2 <= k < n');
            if (((n - k) % 2) !== 0) throw new Error('(n - k) must be even');
            if (!validateRsParams(n, k)) {
                throw new Error('Invalid RS parameters: require n≥5, 2≤k<n, and (n-k) even');
            }
            const t = k + ((n - k) / 2);
            log(`Building .qcont shards with n=${n}, k=${k}, m=${n - k} (t=${t}), chunkSize=8 MiB ...`);
            const qconts = await buildQcontShards(qencBytes, privKeyBytes, { n, k });
            const baseName = qencForQcontInput.files[0].name.replace(/\.qenc$/i, '');
            qconts.forEach(({ blob, index }) => {
                const name = `${baseName}.part${index + 1}-of-${qconts.length}.qcont`;
                download(blob, name);
                log(`Saved ${name} (${blob.size} B)`);
            });
            log('.qcont shards built. Distribute files across storage providers.');
        } catch (e) { logError(e); } finally { setButtonsDisabled(false); }
    });
}
