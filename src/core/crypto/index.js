// --- Main Crypto Module - High-level encryption/decryption ---

import { sha3_512 } from '@noble/hashes/sha3.js';
import { generateKeyPair as generateMLKEMKeyPair, encapsulate, decapsulate, ML_KEM_1024_ENCAPSULATED_KEY_SIZE } from './mlkem.js';
import { deriveKeyWithKmac, clearKeys, computeKeyCommitment, verifyKeyCommitment } from './kdf.js';
import {
    buildChunkAAD, 
    deriveChunkIvFromK, 
    assertPerChunkNonceContract,
    encryptChunk, 
    decryptChunk,
    shouldUseChunkedEncryption,
    calculateChunkCount,
    IV_STRATEGY_SINGLE_IV,
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
} from './aead.js';
import { fromHex, timingSafeEqual, toUint8, toHex } from './bytes.js';
import { CHUNK_SIZE, FORMAT_VERSION, MAX_FILE_SIZE } from './constants.js';
import { buildQencHeader, parseQencHeader } from './qenc/format.js';
import { assertNoLoneSurrogates, parseJsonBytesStrict } from './manifest/strict-json.js';
import {
    DEFAULT_CRYPTO_PROFILE,
    assertChunkCountWithinPolicy,
    buildPolicyMetadataFields,
    validateContainerPolicyMetadata,
} from './policy.js';

export const MAX_QENC_PRIVATE_METADATA_BYTES = 4096;

const PRIVATE_METADATA_FIELDS = Object.freeze([
    'originalFilename',
    'timestamp',
    'fileHash',
    'originalLength',
]);
const SHA3_512_HEX_RE = /^[0-9a-f]{128}$/;
const UTC_ISO_8601_MILLIS_RE = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/;
const privateMetadataEncoder = new TextEncoder();

function privateMetadataError(message) {
    return new Error(`Invalid private metadata: ${message}`);
}

function assertBoundedPrivateMetadataString(value, field, { nullable = false } = {}) {
    if (nullable && value === null) return;
    if (typeof value !== 'string') {
        throw privateMetadataError(`${field} must be ${nullable ? 'null or ' : ''}a string`);
    }

    // Reject before UTF-8 encoding when the UTF-16 length alone proves the byte
    // bound cannot hold. This avoids a second unbounded allocation on writer input.
    if (value.length > MAX_QENC_PRIVATE_METADATA_BYTES) {
        throw privateMetadataError(`${field} exceeds the private metadata byte limit`);
    }
    try {
        assertNoLoneSurrogates(value, 'private metadata string');
    } catch {
        throw privateMetadataError(`${field} contains invalid Unicode`);
    }
    let encodedValue = null;
    try {
        encodedValue = privateMetadataEncoder.encode(value);
        if (encodedValue.length > MAX_QENC_PRIVATE_METADATA_BYTES) {
            throw privateMetadataError(`${field} exceeds the private metadata byte limit`);
        }
    } finally {
        if (encodedValue instanceof Uint8Array) encodedValue.fill(0);
    }
}

function validateWrappedPrivateMetadata(privateMetadata, encodedLength) {
    if (!privateMetadata || typeof privateMetadata !== 'object' || Array.isArray(privateMetadata)) {
        throw privateMetadataError('expected a four-field object');
    }
    if (
        !Number.isSafeInteger(encodedLength) ||
        encodedLength < 1 ||
        encodedLength > MAX_QENC_PRIVATE_METADATA_BYTES
    ) {
        throw privateMetadataError('encoded object exceeds the private metadata byte limit');
    }

    const expectedFields = new Set(PRIVATE_METADATA_FIELDS);
    for (const field of Object.keys(privateMetadata)) {
        if (!expectedFields.has(field)) {
            throw privateMetadataError('object contains an unknown field');
        }
    }
    for (const field of PRIVATE_METADATA_FIELDS) {
        if (!Object.hasOwn(privateMetadata, field)) {
            throw privateMetadataError('object is missing a required field');
        }
    }
    if (Object.keys(privateMetadata).length !== PRIVATE_METADATA_FIELDS.length) {
        throw privateMetadataError('expected exactly four fields');
    }

    assertBoundedPrivateMetadataString(privateMetadata.originalFilename, 'originalFilename', { nullable: true });
    assertBoundedPrivateMetadataString(privateMetadata.timestamp, 'timestamp');
    const timestampMillis = UTC_ISO_8601_MILLIS_RE.test(privateMetadata.timestamp)
        ? Date.parse(privateMetadata.timestamp)
        : Number.NaN;
    if (
        !Number.isFinite(timestampMillis) ||
        new Date(timestampMillis).toISOString() !== privateMetadata.timestamp
    ) {
        throw privateMetadataError('timestamp must use canonical UTC ISO-8601 millisecond form');
    }
    if (typeof privateMetadata.fileHash !== 'string' || !SHA3_512_HEX_RE.test(privateMetadata.fileHash)) {
        throw privateMetadataError('fileHash must be a 128-character lowercase SHA3-512 hex digest');
    }
    if (
        !Number.isSafeInteger(privateMetadata.originalLength) ||
        privateMetadata.originalLength <= 0 ||
        privateMetadata.originalLength > MAX_FILE_SIZE
    ) {
        throw privateMetadataError('originalLength must be a positive safe integer within the file-size limit');
    }
}

// Re-export utilities and sub-modules for convenience
export { toHex, toUint8 } from './bytes.js';
export { generateKeyPair as generateMLKEMKeyPair } from './mlkem.js';
export {
    CHUNK_SIZE,
    MAGIC,
    MINIMAL_CONTAINER_SIZE,
    KEY_COMMITMENT_SIZE,
    FORMAT_VERSION,
    KDF_DOMAIN_V2,
    IV_DOMAIN_V2,
    KENC_DOMAIN_V2,
    KIV_DOMAIN_V2,
    MAX_FILE_SIZE,
} from './constants.js';

/**
 * Generate ML-KEM key pair with enhanced entropy
 * @param {object} options - Key generation options
 * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array, seedInfo: object}>} Key pair
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
 * Container format (QVv1-5-0):
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
    if (!(fileBytes instanceof Uint8Array) || fileBytes.length === 0) {
        throw new Error('fileBytes must be a non-empty Uint8Array');
    }
    if (fileBytes.length > MAX_FILE_SIZE) {
        throw new Error(`File size ${fileBytes.length} exceeds maximum allowed size (${MAX_FILE_SIZE} bytes)`);
    }

    // Preserve the current writer's falsy-to-null normalization while refusing
    // truthy non-string values that would emit a private schema the reader cannot
    // safely interpret.
    const normalizedOriginalFilename = originalFilename || null;
    assertBoundedPrivateMetadataString(normalizedOriginalFilename, 'originalFilename', { nullable: true });

    let sharedSecret = null;
    let Kraw = null;
    let Kenc = null;
    let Kiv = null;
    let privateMetaBytes = null;
    let metaBytes = null;
    let payload = null;

    try {
        // Step 1: KEM Encapsulation (FIPS 203)
        const { encapsulatedKey, sharedSecret: encapsulatedSharedSecret } = await encapsulate(publicKey);
        sharedSecret = encapsulatedSharedSecret;

        // Step 2: Generate random values
        const containerNonce = crypto.getRandomValues(new Uint8Array(12));
        const kdfSalt = crypto.getRandomValues(new Uint8Array(16));

        // Step 3: Build private metadata (encrypted inside payload — no cleartext leakage)
        const privateMeta = {
            originalFilename: normalizedOriginalFilename,
            timestamp: new Date().toISOString(),
            fileHash: await hashBytes(fileBytes),
            originalLength: fileBytes.length
        };
        privateMetaBytes = new TextEncoder().encode(JSON.stringify(privateMeta));
        validateWrappedPrivateMetadata(privateMeta, privateMetaBytes.length);

        // Step 4: Wrap payload = [uint32be privateMetaLen][privateMetaJSON][fileBytes]
        const payloadLength = 4 + privateMetaBytes.length + fileBytes.length;
        payload = new Uint8Array(payloadLength);
        new DataView(payload.buffer).setUint32(0, privateMetaBytes.length, false);
        payload.set(privateMetaBytes, 4);
        payload.set(fileBytes, 4 + privateMetaBytes.length);

        // Step 5: Determine encryption mode
        const isPerChunk = shouldUseChunkedEncryption(payloadLength);
        const aeadMode = isPerChunk ? 'per-chunk-aead' : 'single-container-aead';
        const chunkCount = isPerChunk ? calculateChunkCount(payloadLength) : 1;
        assertChunkCountWithinPolicy(chunkCount, DEFAULT_CRYPTO_PROFILE, aeadMode);

        // Step 6: Create public metadata (cleartext header — no sensitive fields)
        const policyFields = buildPolicyMetadataFields(DEFAULT_CRYPTO_PROFILE, aeadMode);
        const domainStrings = policyFields.domainStrings;

        const meta = {
            KEM: 'ML-KEM-1024',
            KDF: 'KMAC256',
            AEAD: 'AES-256-GCM',
            aead_mode: aeadMode,
            iv_strategy: isPerChunk ? IV_STRATEGY_KMAC_PREFIX64_CTR32_V3 : IV_STRATEGY_SINGLE_IV,
            fmt: FORMAT_VERSION,
            hasKeyCommitment: true,
            payloadFormat: 'wrapped-v1',
            payloadLength,
            chunkSize: CHUNK_SIZE,
            chunkCount,
            ...policyFields,
            domainStrings,
        };

        if (isPerChunk) {
            assertPerChunkNonceContract({
                chunkCount,
                maxChunkCount: meta.maxChunkCount,
                counterBits: meta.counterBits,
                ivStrategy: meta.iv_strategy,
            });
        }

        metaBytes = new TextEncoder().encode(JSON.stringify(meta));

        // Step 7: Derive encryption keys (SP 800-185 KMAC256)
        const derived = await deriveKeyWithKmac(sharedSecret, kdfSalt, metaBytes, domainStrings);
        Kraw = derived.Kraw;
        Kenc = derived.Kenc;
        Kiv = derived.Kiv;
        const aesKey = derived.aesKey;

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
                const iv = deriveChunkIvFromK(Kiv, containerNonce, chunkIndex, domainStrings.iv, {
                    ivStrategy: meta.iv_strategy,
                    chunkCount,
                    maxChunkCount: meta.maxChunkCount,
                    counterBits: meta.counterBits,
                });
                const aad = buildChunkAAD(header, chunkIndex, plainLen);
                
                const cipherBuf = await encryptChunk(aesKey, plain, iv, aad);
                cipherChunks.push(cipherBuf);
                
                chunkIndex++; 
                offset += plainLen;
            }

            if (chunkIndex !== chunkCount || offset !== payload.length) {
                throw new Error('Chunk accounting mismatch before finalizing encrypted payload');
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
        // Clear sensitive material and derived byte buffers across all failure paths.
        if (payload instanceof Uint8Array) payload.fill(0);
        if (privateMetaBytes instanceof Uint8Array) privateMetaBytes.fill(0);
        if (metaBytes instanceof Uint8Array) metaBytes.fill(0);
        clearKeys(sharedSecret, Kraw, Kenc, Kiv);
    }
}

/**
 * Decrypt file using quantum-resistant cryptography
 * @param {Uint8Array} containerBytes - Encrypted container
 * @param {Uint8Array} privateKey - ML-KEM-1024 private key
 * @returns {Promise<{decryptedBlob: Blob, metadata: object}>} Decrypted file and metadata
 */
export async function decryptFile(containerBytes, privateKey) {
    const warnings = [];

    if (!(containerBytes instanceof Uint8Array) || containerBytes.length === 0) {
        throw new Error('containerBytes must be a non-empty Uint8Array');
    }

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
    
    if (encapsulatedKey.length !== ML_KEM_1024_ENCAPSULATED_KEY_SIZE) {
        throw new Error(`Invalid encapsulated key length ${encapsulatedKey.length}. Expected ${ML_KEM_1024_ENCAPSULATED_KEY_SIZE} for ML-KEM-1024.`);
    }
    
    const encryptedData = containerBytes.subarray(offset);
    const profile = validateContainerPolicyMetadata(metadata, { allowLegacyWithoutProfile: false });
    
    let sharedSecret = null;
    let Kraw = null;
    let Kenc = null;
    let Kiv = null;
    let decryptedPayload = null;
    let fileBytesOut = null;
    const decryptedChunks = [];

    try {
        // Step 2: KEM Decapsulation (FIPS 203)
        sharedSecret = await decapsulate(encapsulatedKey, privateKey);
        
        // Step 3: Derive decryption keys (SP 800-185)
        const ds = metadata.domainStrings;
        const derived = await deriveKeyWithKmac(sharedSecret, kdfSalt, metaBytes, ds);
        Kraw = derived.Kraw;
        Kenc = derived.Kenc;
        Kiv = derived.Kiv;
        const aesKey = derived.aesKey;
        
        // Step 4: Verify required key commitment before decryption
        if (!(storedKeyCommitment instanceof Uint8Array) || storedKeyCommitment.length !== 32) {
            throw new Error('Container is missing required key commitment.');
        }
        if (!verifyKeyCommitment(Kenc, storedKeyCommitment)) {
            throw new Error('Key commitment verification failed. Container may be corrupted or tampered with.');
        }

        const effectiveLength = metadata.payloadLength || metadata.originalLength;
        
        if (metadata.aead_mode === 'per-chunk-aead') {
            // Per-chunk decryption
            const totalChunks = metadata.chunkCount || calculateChunkCount(effectiveLength);
            assertChunkCountWithinPolicy(totalChunks, profile, metadata.aead_mode);
            const ivStrategy = metadata.iv_strategy;
            assertPerChunkNonceContract({
                chunkCount: totalChunks,
                maxChunkCount: metadata.maxChunkCount,
                counterBits: metadata.counterBits,
                ivStrategy,
            });
            let encOffset = 0;
            
            for (let i = 0; i < totalChunks; i++) {
                const plainLen = Math.min(CHUNK_SIZE, effectiveLength - (i * CHUNK_SIZE));
                const encLen = plainLen + 16; // AES-GCM tag size
                const cipherChunk = encryptedData.subarray(encOffset, encOffset + encLen);
                const iv = deriveChunkIvFromK(Kiv, containerNonce, i, ds.iv, {
                    ivStrategy,
                    chunkCount: totalChunks,
                    maxChunkCount: metadata.maxChunkCount,
                    counterBits: metadata.counterBits,
                });
                const aad = buildChunkAAD(header, i, plainLen);
                
                const decrypted = await decryptChunk(aesKey, cipherChunk, iv, aad);
                decryptedChunks.push(decrypted);
                encOffset += encLen;
            }

            if (encOffset !== encryptedData.length) {
                throw new Error('Encrypted payload has trailing or truncated chunk data');
            }
            
            // Combine all chunks
            const totalPlain = decryptedChunks.reduce((a, c) => a + c.length, 0);
            decryptedPayload = new Uint8Array(totalPlain);
            let p2 = 0; 
            for (const ch of decryptedChunks) {
                decryptedPayload.set(ch, p2); 
                p2 += ch.length; 
            }
        } else if (metadata.aead_mode === 'single-container-aead') {
            // Single container decryption
            decryptedPayload = await decryptChunk(aesKey, encryptedData, containerNonce, header);
        } else {
            throw new Error(`Unsupported AEAD mode: ${metadata.aead_mode ?? 'unknown'}`);
        }

        if (decryptedPayload.length !== effectiveLength) {
            throw new Error(`Decrypted payload length mismatch: expected ${effectiveLength}, got ${decryptedPayload.length}`);
        }
        
        // Step 5: Unwrap payload (extract private metadata if wrapped-v1 format)
        let fileBytes;
        let mergedMetadata = { ...metadata };
        
        if (metadata.payloadFormat === 'wrapped-v1') {
            if (decryptedPayload.length < 4) {
                throw new Error('Invalid private metadata framing in decrypted payload');
            }
            const payloadDv = new DataView(
                decryptedPayload.buffer, decryptedPayload.byteOffset, decryptedPayload.byteLength
            );
            const privateMetaLen = payloadDv.getUint32(0, false);
            
            if (
                privateMetaLen < 1 ||
                privateMetaLen > MAX_QENC_PRIVATE_METADATA_BYTES ||
                privateMetaLen > decryptedPayload.length - 4
            ) {
                throw new Error('Invalid private metadata length in decrypted payload');
            }
            
            const privateMetaBytes = decryptedPayload.subarray(4, 4 + privateMetaLen);
            let privateMeta;
            try {
                privateMeta = parseJsonBytesStrict(privateMetaBytes);
            } catch {
                // Private metadata may contain a sensitive filename or timestamp.
                // Do not relay parser details or decrypted content through errors.
                throw new Error('Invalid private metadata JSON in decrypted payload');
            }
            validateWrappedPrivateMetadata(privateMeta, privateMetaLen);
            fileBytes = decryptedPayload.subarray(4 + privateMetaLen);

            if (privateMeta.originalLength !== fileBytes.length) {
                throw new Error('Authenticated private metadata does not match the decrypted payload');
            }

            let expectedFileHash = null;
            let computedFileHash = null;
            try {
                expectedFileHash = fromHex(privateMeta.fileHash);
                computedFileHash = sha3_512(fileBytes);
                if (!timingSafeEqual(expectedFileHash, computedFileHash)) {
                    throw new Error('Authenticated private metadata does not match the decrypted payload');
                }
            } finally {
                if (expectedFileHash instanceof Uint8Array) expectedFileHash.fill(0);
                if (computedFileHash instanceof Uint8Array) computedFileHash.fill(0);
            }
            
            // Public authenticated policy/format metadata is authoritative. Private
            // metadata may add user-facing fields but cannot rewrite crypto reporting.
            mergedMetadata = { ...privateMeta, ...metadata };
        } else {
            throw new Error(`Unsupported payload format: ${metadata.payloadFormat ?? 'unknown'}`);
        }
        
        // Copy fileBytes before zeroizing decryptedPayload
        fileBytesOut = new Uint8Array(fileBytes.length);
        fileBytesOut.set(fileBytes);
        const decryptedBlob = new Blob([fileBytesOut]);
        fileBytesOut.fill(0);
        fileBytesOut = null;

        return { decryptedBlob, metadata: mergedMetadata, warnings };
        
    } finally {
        for (const chunk of decryptedChunks) {
            if (chunk instanceof Uint8Array) chunk.fill(0);
        }
        if (decryptedPayload instanceof Uint8Array) decryptedPayload.fill(0);
        if (fileBytesOut instanceof Uint8Array) fileBytesOut.fill(0);
        clearKeys(sharedSecret, Kraw, Kenc, Kiv);
    }
}
