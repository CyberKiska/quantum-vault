// --- AES-256-GCM Symmetric Encryption ---

import { kmac256 } from '@noble/hashes/sha3-addons.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { timingSafeEqual } from '../../utils.js';
import { CHUNK_SIZE } from './constants.js';

// Constants
export const AES_KEY_SIZE = 32; // 256 bits
export const AES_IV_SIZE = 12; // 96 bits for GCM
export const AES_TAG_SIZE = 16; // 128 bits
export const NONCE_COUNTER_BITS_U32 = 32;
export const NONCE_MAX_CHUNK_COUNT_U32 = 0xffffffff;
export const IV_STRATEGY_SINGLE_IV = 'single-iv';
export const IV_STRATEGY_KMAC_PREFIX64_CTR32_V2 = 'kmac-prefix64-ctr32-v2';

const NONCE_PREFIX_SIZE_V2 = 8;
const NONCE_COUNTER_SIZE = 4;
const PER_CHUNK_IV_STRATEGIES = new Set([
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V2,
]);
// CHUNK_SIZE is provided via constants.js

function assertUint32(value, field) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new Error(`${field} must be a uint32 integer`);
    }
}

// Hard fail-closed contract to prevent nonce-counter wrap for chunked GCM.
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

// Derive keys from shared secret using KMAC256
export async function deriveKeyWithKmac(sharedSecret, salt, metaBytes, customization) {
    if (typeof customization !== 'string' || customization.length === 0) {
        throw new Error('KMAC customization domain is required');
    }

    // Combine salt and metadata for KMAC input
    const kmacMessage = new Uint8Array(salt.length + metaBytes.length);
    kmacMessage.set(salt, 0);
    kmacMessage.set(metaBytes, salt.length);

    // Derive raw key material
    const derivedKey = kmac256(sharedSecret, kmacMessage, 32, { customization });
    const Kraw = derivedKey;
    
    // Derive encryption key and IV key from raw key
    const Kenc = kmac256(Kraw, new Uint8Array([1]), 32, { customization: 'quantum-vault:kenc:v1' });
    const Kiv = kmac256(Kraw, new Uint8Array([2]), 32, { customization: 'quantum-vault:kiv:v1' });
    
    // Import AES key for Web Crypto API
    const aesKey = await crypto.subtle.importKey(
        'raw', 
        Kenc.buffer, 
        { name: 'AES-GCM' }, 
        false, 
        ['encrypt', 'decrypt']
    );
    
    return { Kraw, Kenc, Kiv, aesKey };
}

// Build AAD for chunk encryption: header || uint32_be(chunkIndex) || uint32_be(plainLen)
export function buildChunkAAD(headerBytes, chunkIndex, plainLen) {
    const aad = new Uint8Array(headerBytes.length + 8);
    aad.set(headerBytes, 0);
    
    const dv = new DataView(aad.buffer);
    dv.setUint32(aad.length - 8, chunkIndex, false);
    dv.setUint32(aad.length - 4, plainLen, false);
    
    return aad;
}

// Derive per-chunk IV from Kiv + containerNonce + chunkIndex.
// kmac-prefix64-ctr32-v2 is injective inside one container: iv = prefix64 || u32(index).
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
    if (!(Kiv instanceof Uint8Array) || Kiv.length !== AES_KEY_SIZE) {
        throw new Error(`Kiv must be ${AES_KEY_SIZE}-byte Uint8Array`);
    }
    if (!(containerNonce instanceof Uint8Array) || containerNonce.length !== AES_IV_SIZE) {
        throw new Error(`containerNonce must be ${AES_IV_SIZE}-byte Uint8Array`);
    }
    assertUint32(chunkIndex, 'chunkIndex');

    if (chunkCount != null) {
        assertPerChunkNonceContract({
            chunkCount,
            maxChunkCount,
            counterBits,
            ivStrategy,
        });
        if (chunkIndex >= chunkCount) {
            throw new Error(`chunkIndex ${chunkIndex} out of bounds for chunkCount ${chunkCount}`);
        }
    } else if (!PER_CHUNK_IV_STRATEGIES.has(ivStrategy)) {
        throw new Error(`Unsupported per-chunk iv_strategy: ${ivStrategy}`);
    }

    // Encode chunk index as 4 bytes
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

// Encrypt chunk with AES-256-GCM
export async function encryptChunk(aesKey, plaintext, iv, aad) {
    if (iv.length !== AES_IV_SIZE) {
        throw new Error(`IV must be ${AES_IV_SIZE} bytes for AES-GCM`);
    }
    
    const encryptedData = await crypto.subtle.encrypt(
        { 
            name: 'AES-GCM', 
            iv, 
            additionalData: aad,
            tagLength: 128 
        }, 
        aesKey, 
        plaintext
    );
    
    return new Uint8Array(encryptedData);
}

// Decrypt chunk with AES-256-GCM
export async function decryptChunk(aesKey, ciphertext, iv, aad) {
    if (iv.length !== AES_IV_SIZE) {
        throw new Error(`IV must be ${AES_IV_SIZE} bytes for AES-GCM`);
    }
    
    const decryptedData = await crypto.subtle.decrypt(
        { 
            name: 'AES-GCM', 
            iv, 
            additionalData: aad,
            tagLength: 128
        }, 
        aesKey, 
        ciphertext
    );
    
    return new Uint8Array(decryptedData);
}

// Use per-chunk encryption for large files
export function shouldUseChunkedEncryption(fileSize) {
    return fileSize > CHUNK_SIZE;
}

// Number of chunks for given size
export function calculateChunkCount(fileSize) {
    return Math.ceil(fileSize / CHUNK_SIZE);
}

// Zeroize sensitive key material
export function clearKeys(...keys) {
    keys.forEach(key => {
        if (key instanceof Uint8Array) {
            key.fill(0);
        }
    });
}

// Compute key commitment: SHA3-256(Kenc)
// Prevents AES-GCM key-commitment attacks (Albertini et al., USENIX Security 2020)
export function computeKeyCommitment(Kenc) {
    if (!(Kenc instanceof Uint8Array) || Kenc.length !== 32) {
        throw new Error('Kenc must be 32-byte Uint8Array');
    }
    return sha3_256(Kenc);
}

// Verify key commitment using constant-time comparison (CWE-208)
export function verifyKeyCommitment(Kenc, expectedCommitment) {
    const computed = computeKeyCommitment(Kenc);
    return timingSafeEqual(computed, expectedCommitment);
}
