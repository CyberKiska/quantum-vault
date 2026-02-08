// --- QENC Container Format Helpers ---

import { MAGIC, MINIMAL_CONTAINER_SIZE, KEY_COMMITMENT_SIZE } from '../constants.js';

function bytesEqual(a, b) {
    if (a === b) return true;
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

function writeUint16BE(value) {
    const out = new Uint8Array(2);
    new DataView(out.buffer).setUint16(0, value, false);
    return out;
}

function writeUint32BE(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    return out;
}

/**
 * Build QENC header bytes
 * @param {object} params
 * @param {Uint8Array} params.encapsulatedKey
 * @param {Uint8Array} params.containerNonce - 12 bytes
 * @param {Uint8Array} params.kdfSalt - 16 bytes
 * @param {Uint8Array} params.metaBytes - UTF-8 JSON
 * @param {Uint8Array|null} [params.keyCommitment] - 32 bytes (optional)
 * @returns {Uint8Array}
 */
export function buildQencHeader({
    encapsulatedKey,
    containerNonce,
    kdfSalt,
    metaBytes,
    keyCommitment = null
}) {
    if (!(encapsulatedKey instanceof Uint8Array)) {
        throw new Error('encapsulatedKey must be Uint8Array');
    }
    if (!(containerNonce instanceof Uint8Array) || containerNonce.length !== 12) {
        throw new Error('containerNonce must be 12-byte Uint8Array');
    }
    if (!(kdfSalt instanceof Uint8Array) || kdfSalt.length !== 16) {
        throw new Error('kdfSalt must be 16-byte Uint8Array');
    }
    if (!(metaBytes instanceof Uint8Array)) {
        throw new Error('metaBytes must be Uint8Array');
    }
    if (metaBytes.length <= 0 || metaBytes.length > 0xffff) {
        throw new Error(`Invalid metaBytes length: ${metaBytes.length}`);
    }
    if (keyCommitment !== null) {
        if (!(keyCommitment instanceof Uint8Array)) {
            throw new Error('keyCommitment must be Uint8Array or null');
        }
        if (keyCommitment.length !== KEY_COMMITMENT_SIZE) {
            throw new Error(`keyCommitment must be ${KEY_COMMITMENT_SIZE} bytes`);
        }
    }

    const keyLenBytes = writeUint32BE(encapsulatedKey.length);
    const metaLenBytes = writeUint16BE(metaBytes.length);
    const keyCommitBytes = keyCommitment || new Uint8Array(0);

    const header = new Uint8Array(
        MAGIC.length + keyLenBytes.length + encapsulatedKey.length +
        containerNonce.length + kdfSalt.length +
        metaLenBytes.length + metaBytes.length +
        keyCommitBytes.length
    );

    let p = 0;
    header.set(MAGIC, p); p += MAGIC.length;
    header.set(keyLenBytes, p); p += keyLenBytes.length;
    header.set(encapsulatedKey, p); p += encapsulatedKey.length;
    header.set(containerNonce, p); p += containerNonce.length;
    header.set(kdfSalt, p); p += kdfSalt.length;
    header.set(metaLenBytes, p); p += metaLenBytes.length;
    header.set(metaBytes, p); p += metaBytes.length;
    if (keyCommitBytes.length > 0) {
        header.set(keyCommitBytes, p);
    }

    return header;
}

/**
 * Parse QENC header from container bytes
 * @param {Uint8Array} containerBytes
 * @param {object} [options]
 * @param {number} [options.maxMetaLen=4096]
 * @returns {object}
 */
export function parseQencHeader(containerBytes, options = {}) {
    const { maxMetaLen = 4096 } = options;

    if (!(containerBytes instanceof Uint8Array)) {
        throw new Error('containerBytes must be Uint8Array');
    }
    if (containerBytes.length < MINIMAL_CONTAINER_SIZE) {
        throw new Error(`File is too small to be a valid container (size: ${containerBytes.length} B).`);
    }

    const dv = new DataView(containerBytes.buffer, containerBytes.byteOffset, containerBytes.byteLength);
    let offset = 0;

    const magic = containerBytes.subarray(offset, offset + MAGIC.length);
    if (!bytesEqual(magic, MAGIC)) {
        throw new Error('Invalid file format (magic bytes mismatch).');
    }
    offset += MAGIC.length;

    const keyLen = dv.getUint32(offset, false); offset += 4;
    if (keyLen <= 0) {
        throw new Error(`Invalid encapsulated key length ${keyLen}.`);
    }
    if (offset + keyLen > containerBytes.length) {
        throw new Error('Incomplete container: encapsulated key length exceeds file size.');
    }
    const encapsulatedKey = containerBytes.subarray(offset, offset + keyLen); offset += keyLen;

    if (offset + 12 + 16 + 2 > containerBytes.length) {
        throw new Error('Incomplete container: header is truncated.');
    }

    const containerNonce = containerBytes.subarray(offset, offset + 12); offset += 12;
    const kdfSalt = containerBytes.subarray(offset, offset + 16); offset += 16;
    const metaLen = dv.getUint16(offset, false); offset += 2;

    if (metaLen <= 0 || metaLen > maxMetaLen) {
        throw new Error(`Invalid metadata length: ${metaLen}. Must be between 1 and ${maxMetaLen}.`);
    }
    if (offset + metaLen > containerBytes.length) {
        throw new Error('Incomplete container: metadata length exceeds file size.');
    }

    const metaBytes = containerBytes.subarray(offset, offset + metaLen);
    let metadata;
    try {
        metadata = JSON.parse(new TextDecoder().decode(metaBytes));
    } catch (error) {
        throw new Error(`Invalid metadata JSON: ${error?.message || error}`);
    }
    offset += metaLen;

    let storedKeyCommitment = null;
    if (metadata?.hasKeyCommitment) {
        if (offset + KEY_COMMITMENT_SIZE > containerBytes.length) {
            throw new Error('Incomplete container: key commitment missing.');
        }
        storedKeyCommitment = containerBytes.subarray(offset, offset + KEY_COMMITMENT_SIZE);
        offset += KEY_COMMITMENT_SIZE;
    }

    const header = containerBytes.subarray(0, offset);
    return {
        header,
        offset,
        encapsulatedKey,
        containerNonce,
        kdfSalt,
        metaBytes,
        metadata,
        storedKeyCommitment
    };
}
