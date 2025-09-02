// --- AES-256-GCM Symmetric Encryption ---

import { kmac256 } from '@noble/hashes/sha3-addons.js';
import { CHUNK_SIZE, DEFAULT_CUSTOMIZATION } from './constants.js';

// Constants
export const AES_KEY_SIZE = 32; // 256 bits
export const AES_IV_SIZE = 12; // 96 bits for GCM
export const AES_TAG_SIZE = 16; // 128 bits
// CHUNK_SIZE and DEFAULT_CUSTOMIZATION are provided via constants.js

// Derive keys from shared secret using KMAC256
export async function deriveKeyWithKmac(sharedSecret, salt, metaBytes, customization) {
    // Combine salt and metadata for KMAC input
    const kmacMessage = new Uint8Array(salt.length + metaBytes.length);
    kmacMessage.set(salt, 0);
    kmacMessage.set(metaBytes, salt.length);
    
    const usedCustomization = customization || DEFAULT_CUSTOMIZATION;
    
    // Derive raw key material
    const derivedKey = kmac256(sharedSecret, kmacMessage, 32, { customization: usedCustomization });
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

// Derive per-chunk IV via KMAC256(Kraw, containerNonce||u32(index)) → first 12 bytes
export function deriveChunkIvFromK(Kraw, containerNonce, chunkIndex, ivCustomization) {
    // Encode chunk index as 4 bytes
    const idx = new Uint8Array(4);
    new DataView(idx.buffer).setUint32(0, chunkIndex, false);
    
    // Combine container nonce and chunk index
    const input = new Uint8Array(containerNonce.length + idx.length);
    input.set(containerNonce, 0);
    input.set(idx, containerNonce.length);
    
    const customization = ivCustomization || 'quantum-vault:chunk-iv:v1';
    
    // Derive 16 bytes and take first 12 for AES-GCM IV
    const full = kmac256(Kraw, input, 16, { customization });
    return full.slice(0, 12);
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
