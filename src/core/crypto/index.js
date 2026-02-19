// --- Main Crypto Module - High-level encryption/decryption ---

import { sha3_512 } from '@noble/hashes/sha3.js';
import { generateKeyPair as generateMLKEMKeyPair, encapsulate, decapsulate } from './mlkem.js';
import { 
    deriveKeyWithKmac, 
    buildChunkAAD, 
    deriveChunkIvFromK, 
    encryptChunk, 
    decryptChunk,
    shouldUseChunkedEncryption,
    calculateChunkCount,
    clearKeys,
    computeKeyCommitment,
    verifyKeyCommitment
} from './aes.js';
import { toUint8, toHex } from '../../utils.js';
import { CHUNK_SIZE, FORMAT_VERSION, KDF_DOMAIN_V1, IV_DOMAIN_V1 } from './constants.js';
import { buildQencHeader, parseQencHeader } from './qenc/format.js';

// Re-export utilities and sub-modules for convenience
export { toHex, toUint8 } from '../../utils.js';
export { generateKeyPair as generateMLKEMKeyPair } from './mlkem.js';
export { CHUNK_SIZE, MAGIC, MINIMAL_CONTAINER_SIZE, KEY_COMMITMENT_SIZE, FORMAT_VERSION, KDF_DOMAIN_V1, IV_DOMAIN_V1 } from './constants.js';

/**
 * Generate ML-KEM key pair with enhanced entropy
 * @param {object} options - Key generation options
 * @returns {Promise<{publicKey: Uint8Array, secretKey: Uint8Array, seedInfo: object}>} Key pair
 */
export async function generateKeyPair(options = {}) {
    return await generateMLKEMKeyPair(options);
}

/**
 * Hash bytes using SHA3-512
 * @param {Uint8Array} bytes - Bytes to hash
 * @returns {Promise<string>} Hexadecimal hash string
 */
export async function hashBytes(bytes) { 
    return toHex(sha3_512(bytes)); 
}

/**
 * Encrypt file using quantum-resistant cryptography
 * 
 * Container format (QVv1-4-0):
 *   [MAGIC(4)][keyLen(4)][encapKey][nonce(12)][salt(16)][metaLen(2)][metaJSON][keyCommit(32)][ciphertext]
 * Payload format (wrapped-v1):
 *   [privateMetaLen(4)][privateMetaJSON][fileBytes]
 * 
 * @param {Uint8Array} fileBytes - File data to encrypt
 * @param {Uint8Array} publicKey - ML-KEM-1024 public key
 * @param {string} [originalFilename] - Original filename (optional)
 * @returns {Promise<Blob>} Encrypted container blob
 */
export async function encryptFile(fileBytes, publicKey, originalFilename) {
    // Step 1: KEM Encapsulation (FIPS 203)
    const { encapsulatedKey, sharedSecret } = await encapsulate(publicKey);
    
    // Step 2: Generate random values
    const containerNonce = crypto.getRandomValues(new Uint8Array(12));
    const kdfSalt = crypto.getRandomValues(new Uint8Array(16));
    
    // Step 3: Build private metadata (encrypted inside payload — no cleartext leakage)
    const privateMeta = {
        originalFilename: originalFilename || null,
        timestamp: new Date().toISOString(),
        fileHash: await hashBytes(fileBytes),
        originalLength: fileBytes.length
    };
    const privateMetaBytes = new TextEncoder().encode(JSON.stringify(privateMeta));
    
    // Step 4: Wrap payload = [uint32be privateMetaLen][privateMetaJSON][fileBytes]
    const payloadLength = 4 + privateMetaBytes.length + fileBytes.length;
    const payload = new Uint8Array(payloadLength);
    new DataView(payload.buffer).setUint32(0, privateMetaBytes.length, false);
    payload.set(privateMetaBytes, 4);
    payload.set(fileBytes, 4 + privateMetaBytes.length);
    
    // Step 5: Determine encryption mode
    const isPerChunk = shouldUseChunkedEncryption(payloadLength);
    const chunkCount = isPerChunk ? calculateChunkCount(payloadLength) : 1;
    
    // Step 6: Create public metadata (cleartext header — no sensitive fields)
    const domainStrings = {
        kdf: KDF_DOMAIN_V1,
        iv: IV_DOMAIN_V1
    };
    
    const meta = {
        KEM: 'ML-KEM-1024',
        KDF: 'KMAC256',
        AEAD: 'AES-256-GCM',
        aead_mode: isPerChunk ? 'per-chunk-aead' : 'single-container-aead',
        iv_strategy: isPerChunk ? 'kmac-derive-v1' : 'single-iv',
        fmt: FORMAT_VERSION,
        hasKeyCommitment: true,
        payloadFormat: 'wrapped-v1',
        payloadLength,
        chunkSize: CHUNK_SIZE,
        chunkCount,
        domainStrings
    };
    
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    
    // Step 7: Derive encryption keys (SP 800-185 KMAC256)
    const { Kraw, Kenc, Kiv, aesKey } = await deriveKeyWithKmac(
        sharedSecret, kdfSalt, metaBytes, domainStrings.kdf
    );
    
    // Step 8: Compute key commitment — SHA3-256(Kenc)
    // Prevents key-commitment attacks on AES-GCM (Albertini et al., USENIX 2020)
    const keyCommitment = computeKeyCommitment(Kenc);
    
    // Step 9: Build full header including key commitment
    const header = buildQencHeader({
        encapsulatedKey,
        containerNonce,
        kdfSalt,
        metaBytes,
        keyCommitment
    });
    
    try {
        let resultBlob;
        
        if (!isPerChunk) {
            // Single container encryption (SP 800-38D AES-256-GCM)
            const encryptedData = await encryptChunk(aesKey, payload, containerNonce, header);
            resultBlob = new Blob([header, encryptedData], { type: 'application/octet-stream' });
        } else {
            // Per-chunk encryption
            const cipherChunks = [];
            let offset = 0; 
            let chunkIndex = 0;
            
            while (offset < payload.length) {
                const plainLen = Math.min(CHUNK_SIZE, payload.length - offset);
                const plain = payload.subarray(offset, offset + plainLen);
                const iv = deriveChunkIvFromK(Kiv, containerNonce, chunkIndex, domainStrings.iv);
                const aad = buildChunkAAD(header, chunkIndex, plainLen);
                
                const cipherBuf = await encryptChunk(aesKey, plain, iv, aad);
                cipherChunks.push(cipherBuf);
                
                chunkIndex++; 
                offset += plainLen;
            }
            
            // Combine all chunks
            const total = cipherChunks.reduce((a, c) => a + c.length, 0);
            const encrypted = new Uint8Array(total);
            let q = 0; 
            for (const ch of cipherChunks) { 
                encrypted.set(ch, q); 
                q += ch.length; 
            }
            
            resultBlob = new Blob([header, encrypted], { type: 'application/octet-stream' });
        }
        
        return resultBlob;
        
    } finally {
        // Clear sensitive material
        payload.fill(0);
        clearKeys(sharedSecret, Kraw, Kenc, Kiv);
    }
}

/**
 * Decrypt file using quantum-resistant cryptography
 * @param {Uint8Array} containerBytes - Encrypted container
 * @param {Uint8Array} secretKey - ML-KEM-1024 secret key
 * @returns {Promise<{decryptedBlob: Blob, metadata: object}>} Decrypted file and metadata
 */
export async function decryptFile(containerBytes, secretKey) {
    // Step 1: Parse header
    const {
        header,
        offset,
        encapsulatedKey,
        containerNonce,
        kdfSalt,
        metaBytes,
        metadata,
        storedKeyCommitment
    } = parseQencHeader(containerBytes);
    
    if (encapsulatedKey.length !== 1568) {
        throw new Error(`Invalid encapsulated key length ${encapsulatedKey.length}. Expected 1568 for ML-KEM-1024.`);
    }
    
    const encryptedData = containerBytes.subarray(offset);
    
    // Step 2: KEM Decapsulation (FIPS 203)
    const sharedSecret = await decapsulate(encapsulatedKey, secretKey);
    
    // Step 3: Derive decryption keys (SP 800-185)
    const ds = metadata.domainStrings;
    if (!ds || typeof ds.kdf !== 'string' || typeof ds.iv !== 'string') {
        throw new Error('Container metadata is missing valid domainStrings');
    }
    const { Kraw, Kenc, Kiv, aesKey } = await deriveKeyWithKmac(
        sharedSecret, kdfSalt, metaBytes, ds.kdf
    );
    
    // Step 4: Verify key commitment before decryption (prevents key-commitment attacks)
    if (storedKeyCommitment) {
        if (!verifyKeyCommitment(Kenc, storedKeyCommitment)) {
            clearKeys(sharedSecret, Kraw, Kenc, Kiv);
            throw new Error('Key commitment verification failed. Container may be corrupted or tampered with.');
        }
    }
    
    try {
        let decryptedPayload;
        const effectiveLength = metadata.payloadLength || metadata.originalLength;
        
        if (metadata.aead_mode === 'per-chunk-aead') {
            // Per-chunk decryption
            const totalChunks = metadata.chunkCount || calculateChunkCount(effectiveLength);
            const plains = []; 
            let encOffset = 0;
            
            for (let i = 0; i < totalChunks; i++) {
                const plainLen = Math.min(CHUNK_SIZE, effectiveLength - (i * CHUNK_SIZE));
                const encLen = plainLen + 16; // AES-GCM tag size
                const cipherChunk = encryptedData.subarray(encOffset, encOffset + encLen);
                const iv = deriveChunkIvFromK(Kiv, containerNonce, i, ds.iv);
                const aad = buildChunkAAD(header, i, plainLen);
                
                const decrypted = await decryptChunk(aesKey, cipherChunk, iv, aad);
                plains.push(decrypted); 
                encOffset += encLen;
            }

            if (encOffset !== encryptedData.length) {
                throw new Error('Encrypted payload has trailing or truncated chunk data');
            }
            
            // Combine all chunks
            const totalPlain = plains.reduce((a, c) => a + c.length, 0);
            decryptedPayload = new Uint8Array(totalPlain);
            let p2 = 0; 
            for (const ch of plains) { 
                decryptedPayload.set(ch, p2); 
                p2 += ch.length; 
            }
        } else if (metadata.aead_mode === 'single-container-aead') {
            // Single container decryption
            decryptedPayload = await decryptChunk(aesKey, encryptedData, containerNonce, header);
        } else {
            throw new Error(`Unsupported AEAD mode: ${metadata.aead_mode ?? 'unknown'}`);
        }
        
        // Step 5: Unwrap payload (extract private metadata if wrapped-v1 format)
        let fileBytes;
        let mergedMetadata = { ...metadata };
        
        if (metadata.payloadFormat === 'wrapped-v1') {
            const payloadDv = new DataView(
                decryptedPayload.buffer, decryptedPayload.byteOffset, decryptedPayload.byteLength
            );
            const privateMetaLen = payloadDv.getUint32(0, false);
            
            if (privateMetaLen <= 0 || privateMetaLen > decryptedPayload.length - 4) {
                throw new Error('Invalid private metadata length in decrypted payload');
            }
            
            const privateMetaBytes = decryptedPayload.subarray(4, 4 + privateMetaLen);
            const privateMeta = JSON.parse(new TextDecoder().decode(privateMetaBytes));
            fileBytes = decryptedPayload.subarray(4 + privateMetaLen);
            
            // Merge private metadata into returned metadata for caller
            mergedMetadata = { ...metadata, ...privateMeta };
        } else {
            throw new Error(`Unsupported payload format: ${metadata.payloadFormat ?? 'unknown'}`);
        }
        
        return { decryptedBlob: new Blob([fileBytes]), metadata: mergedMetadata };
        
    } finally {
        // Clear sensitive material
        clearKeys(sharedSecret, Kraw, Kenc, Kiv);
    }
}
