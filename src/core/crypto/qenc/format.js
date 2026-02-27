// --- QENC Container Format Helpers ---

import { MAGIC, MINIMAL_CONTAINER_SIZE, KEY_COMMITMENT_SIZE, FORMAT_VERSION } from '../constants.js';
import { bytesEqual } from '../../../utils.js';
import {
    IV_STRATEGY_SINGLE_IV,
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V2,
    NONCE_COUNTER_BITS_U32,
    NONCE_MAX_CHUNK_COUNT_U32,
} from '../aes.js';

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
    if (keyLen > containerBytes.length) {
        throw new Error(`Invalid encapsulated key length ${keyLen}: exceeds container size.`);
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

    if (!metadata || typeof metadata !== 'object') {
        throw new Error('Invalid metadata JSON: expected object');
    }
    if (metadata.fmt !== FORMAT_VERSION) {
        throw new Error(`Unsupported container format: expected ${FORMAT_VERSION}, got ${metadata.fmt ?? 'unknown'}`);
    }
    if (typeof metadata?.aead_mode !== 'string' || metadata.aead_mode.length === 0) {
        throw new Error('Invalid metadata: missing aead_mode');
    }
    if (typeof metadata?.iv_strategy !== 'string' || metadata.iv_strategy.length === 0) {
        throw new Error('Invalid metadata: missing iv_strategy');
    }
    if (!metadata.domainStrings || typeof metadata.domainStrings.kdf !== 'string' || typeof metadata.domainStrings.iv !== 'string') {
        throw new Error('Invalid metadata: missing domainStrings.kdf/domainStrings.iv');
    }
    if (typeof metadata?.noncePolicyId !== 'string' || metadata.noncePolicyId.length === 0) {
        throw new Error('Invalid metadata: missing noncePolicyId');
    }
    if (typeof metadata?.nonceMode !== 'string' || metadata.nonceMode.length === 0) {
        throw new Error('Invalid metadata: missing nonceMode');
    }
    if (!Number.isInteger(metadata?.counterBits) || metadata.counterBits < 0) {
        throw new Error('Invalid metadata: counterBits must be a non-negative integer');
    }
    if (!Number.isInteger(metadata?.maxChunkCount) || metadata.maxChunkCount <= 0) {
        throw new Error('Invalid metadata: maxChunkCount must be a positive integer');
    }
    if (metadata.maxChunkCount > NONCE_MAX_CHUNK_COUNT_U32) {
        throw new Error(`Invalid metadata: maxChunkCount exceeds uint32 counter capacity (${NONCE_MAX_CHUNK_COUNT_U32})`);
    }
    if (metadata.payloadLength != null && (!Number.isInteger(metadata.payloadLength) || metadata.payloadLength <= 0)) {
        throw new Error('Invalid metadata: payloadLength must be a positive integer');
    }
    if (metadata.chunkCount != null && (!Number.isInteger(metadata.chunkCount) || metadata.chunkCount <= 0)) {
        throw new Error('Invalid metadata: chunkCount must be a positive integer');
    }
    if (metadata.chunkSize != null && (!Number.isInteger(metadata.chunkSize) || metadata.chunkSize <= 0)) {
        throw new Error('Invalid metadata: chunkSize must be a positive integer');
    }
    if (metadata.chunkCount != null && metadata.chunkCount > metadata.maxChunkCount) {
        throw new Error('Invalid metadata: chunkCount exceeds maxChunkCount');
    }
    if (metadata.aead_mode === 'single-container-aead') {
        if (metadata.iv_strategy !== IV_STRATEGY_SINGLE_IV) {
            throw new Error(`Invalid metadata: single-container-aead requires iv_strategy="${IV_STRATEGY_SINGLE_IV}"`);
        }
        if (metadata.counterBits !== 0) {
            throw new Error('Invalid metadata: single-container-aead requires counterBits=0');
        }
        if (metadata.maxChunkCount !== 1) {
            throw new Error('Invalid metadata: single-container-aead requires maxChunkCount=1');
        }
    } else if (metadata.aead_mode === 'per-chunk-aead') {
        if (metadata.iv_strategy !== IV_STRATEGY_KMAC_PREFIX64_CTR32_V2) {
            throw new Error(`Invalid metadata: per-chunk-aead requires iv_strategy="${IV_STRATEGY_KMAC_PREFIX64_CTR32_V2}"`);
        }
        if (metadata.counterBits !== NONCE_COUNTER_BITS_U32) {
            throw new Error(`Invalid metadata: per-chunk-aead requires counterBits=${NONCE_COUNTER_BITS_U32}`);
        }
        if (metadata.chunkCount == null) {
            throw new Error('Invalid metadata: per-chunk-aead requires chunkCount');
        }
    } else {
        throw new Error(`Unsupported AEAD mode: ${metadata.aead_mode}`);
    }

    let storedKeyCommitment = null;
    if (metadata?.hasKeyCommitment) {
        if (offset + KEY_COMMITMENT_SIZE > containerBytes.length) {
            throw new Error('Incomplete container: key commitment missing.');
        }
        storedKeyCommitment = containerBytes.subarray(offset, offset + KEY_COMMITMENT_SIZE);
        offset += KEY_COMMITMENT_SIZE;
    }

    if (offset >= containerBytes.length) {
        throw new Error('Invalid container: ciphertext is missing');
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
