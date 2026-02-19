// --- QCONT shard preview helpers (UI-facing, non-crypto) ---
// Parse only the header portion of a .qcont shard file.

import { QCONT_FORMAT_VERSION } from '../constants.js';

export async function parseQcontShardPreviewFile(file) {
    const decoder = new TextDecoder();
    let bytes = new Uint8Array(await file.slice(0, Math.min(file.size, 16384)).arrayBuffer());
    let dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    const ensureBytes = async (requiredLength) => {
        if (bytes.length >= requiredLength) return;
        const toRead = Math.min(file.size, requiredLength);
        bytes = new Uint8Array(await file.slice(0, toRead).arrayBuffer());
        dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        if (bytes.length < requiredLength) {
            throw new Error('Shard header is truncated');
        }
    };

    await ensureBytes(6);
    const magic = decoder.decode(bytes.subarray(0, 4));
    if (magic !== 'QVC1') throw new Error('Invalid shard file');

    let offset = 4;
    const metaLen = dv.getUint16(offset, false);
    if (metaLen <= 0) {
        throw new Error('Invalid shard metadata length');
    }
    offset += 2;
    await ensureBytes(offset + metaLen);
    const metaJSON = JSON.parse(decoder.decode(bytes.subarray(offset, offset + metaLen)));
    if (metaJSON?.alg?.fmt !== QCONT_FORMAT_VERSION) {
        throw new Error(`Unsupported shard format: expected ${QCONT_FORMAT_VERSION}`);
    }
    offset += metaLen;

    await ensureBytes(offset + 4);
    const encapLen = dv.getUint32(offset, false);
    if (encapLen <= 0) {
        throw new Error('Invalid encapsulated key length');
    }
    offset += 4;
    await ensureBytes(offset + encapLen + 12 + 16 + 2);
    offset += encapLen + 12 + 16;

    const qencMetaLen = dv.getUint16(offset, false);
    offset += 2;
    await ensureBytes(offset + qencMetaLen + 1 + 2);
    offset += qencMetaLen;

    await ensureBytes(offset + 1);
    const keyCommitLen = bytes[offset];
    offset += 1;
    if (keyCommitLen > 32) {
        throw new Error(`Invalid key commitment length ${keyCommitLen}`);
    }
    await ensureBytes(offset + keyCommitLen + 2);
    offset += keyCommitLen;

    await ensureBytes(offset + 2);
    const shardIndex = dv.getUint16(offset, false);

    if (!Number.isInteger(metaJSON?.t) || !Number.isInteger(metaJSON?.n)) {
        throw new Error('Shard metadata is missing n/t');
    }

    return {
        containerId: metaJSON.containerId,
        n: metaJSON.n,
        t: metaJSON.t,
        shardIndex
    };
}

// Assess whether selected .qcont files are ready for restore based on metadata only.

export async function assessShardSelection(files) {
    if (!files.length) {
        return { state: 'empty', ready: false };
    }

    const parsed = [];
    let parseErrors = 0;
    for (const file of files) {
        try {
            parsed.push(await parseQcontShardPreviewFile(file));
        } catch {
            parseErrors++;
        }
    }

    if (!parsed.length) {
        return {
            state: 'unknown',
            ready: false,
            message: 'Unable to read shard metadata from selected files.'
        };
    }

    const containerIds = new Set(parsed.map(item => item.containerId));
    if (containerIds.size !== 1) {
        return {
            state: 'invalid',
            ready: false,
            message: 'Selected shards belong to different containers.'
        };
    }

    const base = parsed[0];
    if (typeof base.containerId !== 'string' || base.containerId.length === 0) {
        return {
            state: 'unknown',
            ready: false,
            message: 'Shard metadata is missing container identity.'
        };
    }
    if (!Number.isInteger(base.n) || !Number.isInteger(base.t) || base.t < 2) {
        return {
            state: 'unknown',
            ready: false,
            message: 'Shard metadata does not contain a valid restore threshold.'
        };
    }

    const mismatch = parsed.some(item => item.n !== base.n || item.t !== base.t);
    if (mismatch) {
        return {
            state: 'invalid',
            ready: false,
            message: 'Shard metadata mismatch (n/t differs between files).'
        };
    }

    const uniqueIndices = new Set(parsed.map(item => item.shardIndex));
    const uniqueCount = uniqueIndices.size;
    const duplicateCount = parsed.length - uniqueCount;
    const ready = uniqueCount >= base.t;

    let message = ready
        ? `Ready: ${uniqueCount}/${base.n} unique shards selected (need >=${base.t}).`
        : `Insufficient: ${uniqueCount}/${base.n} unique shards selected (need >=${base.t}).`;

    if (duplicateCount > 0) {
        message += ` ${duplicateCount} duplicate shard(s) ignored.`;
    }
    if (parseErrors > 0) {
        message += ` ${parseErrors} unreadable file(s) ignored.`;
    }

    return {
        state: ready ? 'sufficient' : 'insufficient',
        ready,
        message,
        threshold: base.t
    };
}
