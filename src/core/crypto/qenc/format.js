// --- QENC Container Format Helpers ---

import { MAGIC, MINIMAL_CONTAINER_SIZE, KEY_COMMITMENT_SIZE } from '../constants.js';
import {
    IV_STRATEGY_SINGLE_IV,
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
} from '../aead.js';
import { parseJsonBytesStrict } from '../manifest/strict-json.js';
import { ML_KEM_1024_ENCAPSULATED_KEY_SIZE } from '../mlkem.js';
import { getCryptoProfile } from '../policy.js';

export const MAX_QENC_METADATA_BYTES = 4096;

const AES_GCM_TAG_SIZE = 16;
const CURRENT_KEM_ID = 'ML-KEM-1024';
const CURRENT_KDF_ID = 'KMAC256';
const CURRENT_AEAD_ID = 'AES-256-GCM';
const CURRENT_FORMAT_VERSION = 'QVv1-5-0';
const CURRENT_PAYLOAD_FORMAT = 'wrapped-v1';
const CURRENT_CHUNK_SIZE = 8 * 1024 * 1024;
const CURRENT_CRYPTO_PROFILE_ID = 'QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2';
const CURRENT_CRYPTO_PROFILE = getCryptoProfile(CURRENT_CRYPTO_PROFILE_ID);
const QENC_METADATA_FIELDS = Object.freeze([
    'KEM',
    'KDF',
    'AEAD',
    'aead_mode',
    'iv_strategy',
    'fmt',
    'hasKeyCommitment',
    'payloadFormat',
    'payloadLength',
    'chunkSize',
    'chunkCount',
    'cryptoProfileId',
    'kdfTreeId',
    'noncePolicyId',
    'nonceMode',
    'counterBits',
    'maxChunkCount',
    'aadPolicyId',
    'domainStrings',
]);
const DOMAIN_STRING_FIELDS = Object.freeze(['kdf', 'iv', 'kenc', 'kiv']);

function assertExactObjectFields(value, expectedFields, field) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`Invalid metadata: ${field} must be an object`);
    }

    const expected = new Set(expectedFields);
    for (const actualField of Object.keys(value)) {
        if (!expected.has(actualField)) {
            throw new Error(`Invalid metadata: unknown ${field} field`);
        }
    }
    for (const requiredField of expectedFields) {
        if (!Object.hasOwn(value, requiredField)) {
            throw new Error(`Invalid metadata: missing ${field}.${requiredField}`);
        }
    }
}

function assertExactMetadataValue(actual, expected, field) {
    if (actual !== expected) {
        throw new Error(`Invalid metadata: ${field} must be ${JSON.stringify(expected)}`);
    }
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

function magicMatches(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== MAGIC.length) {
        return false;
    }
    for (let i = 0; i < MAGIC.length; i += 1) {
        if (bytes[i] !== MAGIC[i]) {
            return false;
        }
    }
    return true;
}

/**
 * Validate the closed current QENC metadata schema and return the authenticated
 * geometry that is safe to use for framing and allocation decisions.
 *
 * This validator is shared by full-container parsing and QCONT reconstruction
 * so neither path can drift to a mutable default profile or a looser schema.
 *
 * @param {object} metadata
 * @returns {{aeadMode: string, isPerChunk: boolean, payloadLength: number, chunkSize: number, chunkCount: number, ciphertextLength: number}}
 */
export function validateQencMetadata(metadata) {
    assertExactObjectFields(metadata, QENC_METADATA_FIELDS, 'top-level');
    assertExactObjectFields(metadata.domainStrings, DOMAIN_STRING_FIELDS, 'domainStrings');
    assertExactMetadataValue(metadata.KEM, CURRENT_KEM_ID, 'KEM');
    assertExactMetadataValue(metadata.KDF, CURRENT_KDF_ID, 'KDF');
    assertExactMetadataValue(metadata.AEAD, CURRENT_AEAD_ID, 'AEAD');
    assertExactMetadataValue(metadata.fmt, CURRENT_FORMAT_VERSION, 'fmt');
    assertExactMetadataValue(metadata.payloadFormat, CURRENT_PAYLOAD_FORMAT, 'payloadFormat');
    assertExactMetadataValue(
        metadata.cryptoProfileId,
        CURRENT_CRYPTO_PROFILE.cryptoProfileId,
        'cryptoProfileId'
    );
    assertExactMetadataValue(metadata.kdfTreeId, CURRENT_CRYPTO_PROFILE.kdfTreeId, 'kdfTreeId');
    assertExactMetadataValue(metadata.aadPolicyId, CURRENT_CRYPTO_PROFILE.aadPolicyId, 'aadPolicyId');
    for (const field of DOMAIN_STRING_FIELDS) {
        assertExactMetadataValue(
            metadata.domainStrings[field],
            CURRENT_CRYPTO_PROFILE.domainStrings[field],
            `domainStrings.${field}`
        );
    }
    if (!Number.isSafeInteger(metadata.payloadLength) || metadata.payloadLength <= 0) {
        throw new Error('Invalid metadata: payloadLength must be a positive integer');
    }
    if (!Number.isSafeInteger(metadata.chunkCount) || metadata.chunkCount <= 0) {
        throw new Error('Invalid metadata: chunkCount must be a positive integer');
    }
    if (!Number.isSafeInteger(metadata.chunkSize) || metadata.chunkSize <= 0) {
        throw new Error('Invalid metadata: chunkSize must be a positive integer');
    }
    if (metadata.chunkSize !== CURRENT_CHUNK_SIZE) {
        throw new Error(`Invalid metadata: unsupported chunkSize ${metadata.chunkSize}; expected ${CURRENT_CHUNK_SIZE}`);
    }

    let requiredIvStrategy;
    if (metadata.aead_mode === 'single-container-aead') {
        requiredIvStrategy = IV_STRATEGY_SINGLE_IV;
        if (metadata.chunkCount !== 1) {
            throw new Error('Invalid metadata: single-container-aead requires chunkCount=1');
        }
    } else if (metadata.aead_mode === 'per-chunk-aead') {
        requiredIvStrategy = IV_STRATEGY_KMAC_PREFIX64_CTR32_V3;
        const expectedChunkCount = Math.ceil(metadata.payloadLength / metadata.chunkSize);
        if (metadata.chunkCount !== expectedChunkCount) {
            throw new Error(`Invalid metadata: chunkCount does not match payloadLength/chunkSize geometry (expected ${expectedChunkCount})`);
        }
    } else {
        throw new Error('Unsupported AEAD mode in metadata');
    }

    const nonceContract = CURRENT_CRYPTO_PROFILE.noncePolicies[metadata.aead_mode];
    assertExactMetadataValue(metadata.iv_strategy, requiredIvStrategy, 'iv_strategy');
    assertExactMetadataValue(metadata.noncePolicyId, nonceContract.noncePolicyId, 'noncePolicyId');
    assertExactMetadataValue(metadata.nonceMode, nonceContract.nonceMode, 'nonceMode');
    assertExactMetadataValue(metadata.counterBits, nonceContract.counterBits, 'counterBits');
    assertExactMetadataValue(metadata.maxChunkCount, nonceContract.maxChunkCount, 'maxChunkCount');
    if (metadata.chunkCount > metadata.maxChunkCount) {
        throw new Error('Invalid metadata: chunkCount exceeds maxChunkCount');
    }
    if (metadata.hasKeyCommitment !== true) {
        throw new Error('Invalid metadata: hasKeyCommitment must be true');
    }

    const tagBytes = AES_GCM_TAG_SIZE * metadata.chunkCount;
    if (
        !Number.isSafeInteger(tagBytes) ||
        metadata.payloadLength > Number.MAX_SAFE_INTEGER - tagBytes
    ) {
        throw new Error('Invalid metadata: ciphertext length exceeds safe integer range');
    }
    return {
        aeadMode: metadata.aead_mode,
        isPerChunk: metadata.aead_mode === 'per-chunk-aead',
        payloadLength: metadata.payloadLength,
        chunkSize: metadata.chunkSize,
        chunkCount: metadata.chunkCount,
        ciphertextLength: metadata.payloadLength + tagBytes,
    };
}

/**
 * Parse and validate current QENC metadata bytes without requiring a synthetic
 * ciphertext allocation.
 *
 * @param {Uint8Array} metaBytes
 * @param {object} [options]
 * @param {number} [options.maxMetaLen=4096]
 * @returns {{metadata: object, geometry: object}}
 */
export function parseQencMetadataBytes(metaBytes, options = {}) {
    const { maxMetaLen = MAX_QENC_METADATA_BYTES } = options;
    if (
        !Number.isSafeInteger(maxMetaLen) ||
        maxMetaLen <= 0 ||
        maxMetaLen > MAX_QENC_METADATA_BYTES
    ) {
        throw new Error(`maxMetaLen must be an integer between 1 and ${MAX_QENC_METADATA_BYTES}`);
    }
    if (!(metaBytes instanceof Uint8Array)) {
        throw new Error('metaBytes must be Uint8Array');
    }
    if (metaBytes.length <= 0 || metaBytes.length > maxMetaLen) {
        throw new Error(`Invalid metadata length: ${metaBytes.length}. Must be between 1 and ${maxMetaLen}.`);
    }

    let metadata;
    try {
        metadata = parseJsonBytesStrict(metaBytes);
    } catch (error) {
        throw new Error(`Invalid metadata JSON: ${error?.message || error}`);
    }
    return {
        metadata,
        geometry: validateQencMetadata(metadata),
    };
}

/**
 * Build QENC header bytes
 * @param {object} params
 * @param {Uint8Array} params.encapsulatedKey
 * @param {Uint8Array} params.containerNonce - 12 bytes
 * @param {Uint8Array} params.kdfSalt - 16 bytes
 * @param {Uint8Array} params.metaBytes - UTF-8 JSON
 * @param {Uint8Array} params.keyCommitment - 32-byte SHA3-256 commitment of Kenc (required)
 * @returns {Uint8Array}
 */
export function buildQencHeader({
    encapsulatedKey,
    containerNonce,
    kdfSalt,
    metaBytes,
    keyCommitment
}) {
    if (!(encapsulatedKey instanceof Uint8Array)) {
        throw new Error('encapsulatedKey must be Uint8Array');
    }
    if (encapsulatedKey.length !== ML_KEM_1024_ENCAPSULATED_KEY_SIZE) {
        throw new Error(
            `Invalid encapsulatedKey length: expected ${ML_KEM_1024_ENCAPSULATED_KEY_SIZE}, got ${encapsulatedKey.length}`
        );
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
    if (metaBytes.length <= 0 || metaBytes.length > MAX_QENC_METADATA_BYTES) {
        throw new Error(`Invalid metaBytes length: ${metaBytes.length}`);
    }
    if (!(keyCommitment instanceof Uint8Array)) {
        throw new Error('keyCommitment must be Uint8Array');
    }
    if (keyCommitment.length !== KEY_COMMITMENT_SIZE) {
        throw new Error(`keyCommitment must be ${KEY_COMMITMENT_SIZE} bytes`);
    }

    const keyLenBytes = writeUint32BE(encapsulatedKey.length);
    const metaLenBytes = writeUint16BE(metaBytes.length);
    const keyCommitBytes = keyCommitment;

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
    header.set(keyCommitBytes, p);

    return header;
}

/**
 * Parse QENC header from container bytes
 * @param {Uint8Array} containerBytes
 * @param {object} [options]
 * @param {number} [options.maxMetaLen=4096] - caller may impose a lower limit
 * @returns {object}
 */
export function parseQencHeader(containerBytes, options = {}) {
    const { maxMetaLen = MAX_QENC_METADATA_BYTES } = options;

    if (
        !Number.isSafeInteger(maxMetaLen) ||
        maxMetaLen <= 0 ||
        maxMetaLen > MAX_QENC_METADATA_BYTES
    ) {
        throw new Error(`maxMetaLen must be an integer between 1 and ${MAX_QENC_METADATA_BYTES}`);
    }

    if (!(containerBytes instanceof Uint8Array)) {
        throw new Error('containerBytes must be Uint8Array');
    }
    if (containerBytes.length < MINIMAL_CONTAINER_SIZE) {
        throw new Error(`File is too small to be a valid container (size: ${containerBytes.length} B).`);
    }

    const dv = new DataView(containerBytes.buffer, containerBytes.byteOffset, containerBytes.byteLength);
    let offset = 0;

    const magic = containerBytes.subarray(offset, offset + MAGIC.length);
    if (!magicMatches(magic)) {
        throw new Error('Invalid file format (magic bytes mismatch).');
    }
    offset += MAGIC.length;

    const keyLen = dv.getUint32(offset, false); offset += 4;
    if (keyLen !== ML_KEM_1024_ENCAPSULATED_KEY_SIZE) {
        throw new Error(
            `Invalid encapsulated key length ${keyLen}. Expected ${ML_KEM_1024_ENCAPSULATED_KEY_SIZE} for ${CURRENT_KEM_ID}.`
        );
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
    const { metadata, geometry } = parseQencMetadataBytes(metaBytes, { maxMetaLen });
    offset += metaLen;

    if (offset + KEY_COMMITMENT_SIZE > containerBytes.length) {
        throw new Error('Incomplete container: key commitment missing.');
    }
    const storedKeyCommitment = containerBytes.subarray(offset, offset + KEY_COMMITMENT_SIZE);
    offset += KEY_COMMITMENT_SIZE;

    if (offset >= containerBytes.length) {
        throw new Error('Invalid container: ciphertext is missing');
    }
    const ciphertextLength = containerBytes.length - offset;
    if (ciphertextLength !== geometry.ciphertextLength) {
        throw new Error(`Invalid container: ciphertext length does not match authenticated geometry (expected ${geometry.ciphertextLength}, got ${ciphertextLength})`);
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
