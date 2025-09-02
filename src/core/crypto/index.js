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
    clearKeys
} from './aes.js';
import { toUint8, toHex } from '../../utils.js';
import { MAGIC, MINIMAL_CONTAINER_SIZE, CHUNK_SIZE, DEFAULT_CUSTOMIZATION } from './constants.js';

// Re-export utilities and sub-modules for convenience
export { toHex, toUint8 } from '../../utils.js';
export { generateKeyPair as generateMLKEMKeyPair } from './mlkem.js';
export { CHUNK_SIZE, DEFAULT_CUSTOMIZATION, MAGIC, MINIMAL_CONTAINER_SIZE } from './constants.js';

// Generate ML-KEM key pair
export async function generateKeyPair(options = {}) {
    return await generateMLKEMKeyPair(options);
}

// Hash bytes using SHA3-512
export async function hashBytes(bytes) { 
    return toHex(sha3_512(bytes)); 
}

// Encrypt file using quantum-resistant cryptography
export async function encryptFile(fileBytes, publicKey, originalFilename) {
    // Step 1: KEM Encapsulation
    const { encapsulatedKey, sharedSecret } = await encapsulate(publicKey);
    
    // Step 2: Generate random values
    const containerNonce = crypto.getRandomValues(new Uint8Array(12));
    const kdfSalt = crypto.getRandomValues(new Uint8Array(16));
    
    // Step 3: Determine encryption mode
    const isPerChunk = shouldUseChunkedEncryption(fileBytes.length);
    const chunkCount = isPerChunk ? calculateChunkCount(fileBytes.length) : 1;
    
    // Step 4: Create metadata
    const domainStrings = { 
        kdf: 'quantum-vault:kdf:v1', 
        iv: 'quantum-vault:chunk-iv:v1' 
    };
    
    const meta = {
        KEM: 'ML-KEM-1024',
        KDF: 'KMAC256',
        AEAD: 'AES-256-GCM',
        aead_mode: isPerChunk ? 'per-chunk-aead' : 'single-container-aead',
        iv_strategy: isPerChunk ? 'kmac-derive-v1' : 'single-iv',
        fmt: 'QVv1-3-0',
        timestamp: new Date().toISOString(),
        fileHash: await hashBytes(fileBytes),
        originalLength: fileBytes.length,
        originalFilename: originalFilename || null, // Store original filename if provided
        chunkSize: CHUNK_SIZE,
        chunkCount,
        domainStrings
    };
    
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    
    // Step 5: Build header
    const metaLenBytes = new Uint8Array(2); 
    new DataView(metaLenBytes.buffer).setUint16(0, metaBytes.length, false);
    
    const keyLenBytes = new Uint8Array(4); 
    new DataView(keyLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);
    
    const header = new Uint8Array(
        MAGIC.length + keyLenBytes.length + encapsulatedKey.length + 
        containerNonce.length + kdfSalt.length + metaLenBytes.length + metaBytes.length
    );
    
    let p = 0; 
    header.set(MAGIC, p); p += MAGIC.length; 
    header.set(keyLenBytes, p); p += keyLenBytes.length;
    header.set(encapsulatedKey, p); p += encapsulatedKey.length; 
    header.set(containerNonce, p); p += containerNonce.length;
    header.set(kdfSalt, p); p += kdfSalt.length; 
    header.set(metaLenBytes, p); p += metaLenBytes.length; 
    header.set(metaBytes, p);
    
    // Step 6: Derive encryption keys
    const { Kraw, Kenc, Kiv, aesKey } = await deriveKeyWithKmac(
        sharedSecret, kdfSalt, metaBytes, domainStrings.kdf
    );
    
    try {
        let resultBlob;
        
        if (!isPerChunk) {
            // Single container encryption
            const encryptedData = await encryptChunk(aesKey, fileBytes, containerNonce, header);
            resultBlob = new Blob([header, encryptedData], { type: 'application/octet-stream' });
        } else {
            // Per-chunk encryption
            const cipherChunks = [];
            let offset = 0; 
            let chunkIndex = 0;
            
            while (offset < fileBytes.length) {
                const plainLen = Math.min(CHUNK_SIZE, fileBytes.length - offset);
                const plain = fileBytes.subarray(offset, offset + plainLen);
                const iv = deriveChunkIvFromK(Kiv, containerNonce, chunkIndex, domainStrings.iv);
                const aad = buildChunkAAD(header, chunkIndex, plainLen);
                
                const cipherBuf = await encryptChunk(aesKey, plain, iv, aad);
                cipherChunks.push(cipherBuf);
                
                plain.fill(0); // Clear plaintext
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
        clearKeys(sharedSecret, Kraw, Kenc, Kiv);
    }
}

// Decrypt file using quantum-resistant cryptography
export async function decryptFile(containerBytes, secretKey) {
    if (containerBytes.length < MINIMAL_CONTAINER_SIZE) {
        throw new Error(`File is too small to be a valid container (size: ${containerBytes.length} B).`);
    }
    
    // Step 1: Parse header
    const dv = new DataView(containerBytes.buffer, containerBytes.byteOffset);
    let offset = 0;
    
    // Check magic bytes
    const magic = containerBytes.subarray(offset, offset + MAGIC.length);
    if (new TextDecoder().decode(magic) !== new TextDecoder().decode(MAGIC)) {
        throw new Error('Invalid file format (magic bytes mismatch).');
    }
    offset += MAGIC.length;
    
    // Parse header fields
    const keyLen = dv.getUint32(offset, false); offset += 4;
    if (keyLen !== 1568) {
        throw new Error(`Invalid encapsulated key length ${keyLen}. Expected 1568 for ML-KEM-1024.`);
    }
    const encapsulatedKey = containerBytes.subarray(offset, offset + keyLen); offset += keyLen;
    const containerNonce = containerBytes.subarray(offset, offset + 12); offset += 12;
    const kdfSalt = containerBytes.subarray(offset, offset + 16); offset += 16;
    const metaLen = dv.getUint16(offset, false); offset += 2;
    
    if (metaLen <= 0 || metaLen > 4096) {
        throw new Error(`Invalid metadata length: ${metaLen}. Must be between 1 and 4096.`);
    }
    if (offset + metaLen > containerBytes.length) {
        throw new Error('Incomplete container: metadata length exceeds file size.');
    }
    
    const metaBytes = containerBytes.subarray(offset, offset + metaLen);
    const metadata = JSON.parse(new TextDecoder().decode(metaBytes));
    offset += metaLen;
    
    const header = containerBytes.subarray(0, offset);
    const encryptedData = containerBytes.subarray(offset);
    
    // Step 2: KEM Decapsulation
    const sharedSecret = await decapsulate(encapsulatedKey, secretKey);
    
    // Step 3: Derive decryption keys
    const ds = metadata.domainStrings || metadata.domain || {};
    const { Kraw, Kenc, Kiv, aesKey } = await deriveKeyWithKmac(
        sharedSecret, kdfSalt, metaBytes, ds.kdf || DEFAULT_CUSTOMIZATION
    );
    
    try {
        let decryptedBlob;
        
        if (metadata.aead_mode === 'per-chunk-aead' || metadata.aead_mode === 'per-chunk') {
            // Per-chunk decryption
            const totalChunks = metadata.chunkCount || calculateChunkCount(metadata.originalLength);
            const plains = []; 
            let encOffset = 0;
            
            for (let i = 0; i < totalChunks; i++) {
                const plainLen = Math.min(CHUNK_SIZE, metadata.originalLength - (i * CHUNK_SIZE));
                const encLen = plainLen + 16; // AES-GCM tag size
                const cipherChunk = encryptedData.subarray(encOffset, encOffset + encLen);
                const iv = deriveChunkIvFromK(Kiv, containerNonce, i, ds.iv || 'quantum-vault:chunk-iv:v1');
                const aad = buildChunkAAD(header, i, plainLen);
                
                const decrypted = await decryptChunk(aesKey, cipherChunk, iv, aad);
                plains.push(decrypted); 
                encOffset += encLen;
            }
            
            // Combine all chunks
            const totalPlain = plains.reduce((a, c) => a + c.length, 0);
            const out = new Uint8Array(totalPlain);
            let p2 = 0; 
            for (const ch of plains) { 
                out.set(ch, p2); 
                p2 += ch.length; 
            }
            
            decryptedBlob = new Blob([out]);
        } else {
            // Single container decryption
            const decryptedData = await decryptChunk(aesKey, encryptedData, containerNonce, header);
            decryptedBlob = new Blob([decryptedData]);
        }
        
        return { decryptedBlob, metadata };
        
    } finally {
        // Clear sensitive material
        clearKeys(sharedSecret, Kraw, Kenc, Kiv);
    }
}
