// AES-256-GCM AEAD operations and nonce management

import { kmac256 } from '@noble/hashes/sha3-addons.js';
import { CHUNK_SIZE } from './constants.js';

export { AES_KEY_SIZE } from './kdf.js';
export const AES_IV_SIZE = 12;
export const AES_TAG_SIZE = 16;
export const NONCE_COUNTER_BITS_U32 = 32;
export const NONCE_MAX_CHUNK_COUNT_U32 = 0xffffffff;
export const IV_STRATEGY_SINGLE_IV = 'single-iv';
export const IV_STRATEGY_KMAC_PREFIX64_CTR32_V2 = 'kmac-prefix64-ctr32-v2';

const NONCE_PREFIX_SIZE_V2 = 8;
const NONCE_COUNTER_SIZE = 4;
const PER_CHUNK_IV_STRATEGIES = new Set([
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V2,
]);

function assertUint32(value, field) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new Error(`${field} must be a uint32 integer`);
    }
}

export function assertPerChunkNonceContract({
    chunkCount,
    maxChunkCount = NONCE_MAX_CHUNK_COUNT_U32,
    counterBits = NONCE_COUNTER_BITS_U32,
    ivStrategy = IV_STRATEGY_KMAC_PREFIX64_CTR32_V2,
}) {
    if (!PER_CHUNK_IV_STRATEGIES.has(ivStrategy)) {
        throw new Error(`Unsupported per-chunk iv_strategy: ${ivStrategy}`);
    }
    if (!Number.isInteger(counterBits) || counterBits !== NONCE_COUNTER_BITS_U32) {
        throw new Error(`Unsupported counterBits for per-chunk AES-GCM: ${counterBits}`);
    }
    assertUint32(maxChunkCount, 'maxChunkCount');
    if (!Number.isInteger(chunkCount) || chunkCount <= 0) {
        throw new Error('chunkCount must be a positive integer');
    }
    if (chunkCount > maxChunkCount) {
        throw new Error(`chunkCount exceeds nonce policy bound (${maxChunkCount})`);
    }
}

export function buildChunkAAD(headerBytes, chunkIndex, plainLen) {
    const aad = new Uint8Array(headerBytes.length + 8);
    aad.set(headerBytes, 0);
    const dv = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
    dv.setUint32(aad.length - 8, chunkIndex, false);
    dv.setUint32(aad.length - 4, plainLen, false);
    return aad;
}

export function deriveChunkIvFromK(Kiv, containerNonce, chunkIndex, ivCustomization, options = {}) {
    const {
        ivStrategy = IV_STRATEGY_KMAC_PREFIX64_CTR32_V2,
        chunkCount = null,
        maxChunkCount = NONCE_MAX_CHUNK_COUNT_U32,
        counterBits = NONCE_COUNTER_BITS_U32,
    } = options;

    if (typeof ivCustomization !== 'string' || ivCustomization.length === 0) {
        throw new Error('IV customization domain is required');
    }
    if (!(Kiv instanceof Uint8Array) || Kiv.length !== 32) {
        throw new Error('Kiv must be 32-byte Uint8Array');
    }
    if (!(containerNonce instanceof Uint8Array) || containerNonce.length !== AES_IV_SIZE) {
        throw new Error(`containerNonce must be ${AES_IV_SIZE}-byte Uint8Array`);
    }
    assertUint32(chunkIndex, 'chunkIndex');

    if (chunkCount != null) {
        assertPerChunkNonceContract({ chunkCount, maxChunkCount, counterBits, ivStrategy });
        if (chunkIndex >= chunkCount) {
            throw new Error(`chunkIndex ${chunkIndex} out of bounds for chunkCount ${chunkCount}`);
        }
    } else if (!PER_CHUNK_IV_STRATEGIES.has(ivStrategy)) {
        throw new Error(`Unsupported per-chunk iv_strategy: ${ivStrategy}`);
    }

    const idx = new Uint8Array(NONCE_COUNTER_SIZE);
    new DataView(idx.buffer).setUint32(0, chunkIndex, false);

    if (ivStrategy === IV_STRATEGY_KMAC_PREFIX64_CTR32_V2) {
        const prefixFull = kmac256(Kiv, containerNonce, NONCE_PREFIX_SIZE_V2, { customization: ivCustomization });
        const prefix = prefixFull.slice(0, NONCE_PREFIX_SIZE_V2);
        const iv = new Uint8Array(AES_IV_SIZE);
        iv.set(prefix, 0);
        iv.set(idx, NONCE_PREFIX_SIZE_V2);
        return iv;
    }

    throw new Error(`Unsupported per-chunk iv_strategy: ${ivStrategy}`);
}

export async function encryptChunk(aesKey, plaintext, iv, aad) {
    if (iv.length !== AES_IV_SIZE) {
        throw new Error(`IV must be ${AES_IV_SIZE} bytes for AES-GCM`);
    }
    const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        plaintext
    );
    return new Uint8Array(encryptedData);
}

export async function decryptChunk(aesKey, ciphertext, iv, aad) {
    if (iv.length !== AES_IV_SIZE) {
        throw new Error(`IV must be ${AES_IV_SIZE} bytes for AES-GCM`);
    }
    const decryptedData = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        ciphertext
    );
    return new Uint8Array(decryptedData);
}

export function shouldUseChunkedEncryption(fileSize) {
    return fileSize > CHUNK_SIZE;
}

export function calculateChunkCount(fileSize) {
    return Math.ceil(fileSize / CHUNK_SIZE);
}
