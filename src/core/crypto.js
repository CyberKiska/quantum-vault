// --- Libraries ---
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { kmac256 } from '@noble/hashes/sha3-addons.js';
import { sha3_512 } from '@noble/hashes/sha3.js';

// --- Constants ---
export const MAGIC = new TextEncoder().encode('QVv1');
export const DEFAULT_CUSTOMIZATION = 'QuantumVault v1.3.0';
export const MINIMAL_CONTAINER_SIZE = 38; // MAGIC(4) + keyLen(4) + iv(12) + salt(16) + metaLen(2)
export const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB

// --- Utils ---
export const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
export function toUint8(x) {
    if (x instanceof Uint8Array) return x;
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
    throw new TypeError('Expected ArrayBuffer or Uint8Array');
}
export async function hashBytes(bytes) { return toHex(sha3_512(bytes)); }
export async function generateKeyPair() { return ml_kem1024.keygen(); }

// --- Core Crypto Helpers ---
export async function deriveKeyWithKmac(sharedSecret, salt, metaBytes, customization) {
    const kmacMessage = new Uint8Array(salt.length + metaBytes.length);
    kmacMessage.set(salt, 0);
    kmacMessage.set(metaBytes, salt.length);
    const usedCustomization = customization || DEFAULT_CUSTOMIZATION;
    const derivedKey = kmac256(sharedSecret, kmacMessage, 32, { customization: usedCustomization });
    const Kraw = derivedKey;
    const Kenc = kmac256(Kraw, new Uint8Array([1]), 32, { customization: 'quantum-vault:kenc:v1' });
    const Kiv = kmac256(Kraw, new Uint8Array([2]), 32, { customization: 'quantum-vault:kiv:v1' });
    const aesKey = await crypto.subtle.importKey('raw', Kenc.buffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { Kraw, Kenc, Kiv, aesKey };
}

export function buildChunkAAD(headerBytes, chunkIndex, plainLen) {
    const aad = new Uint8Array(headerBytes.length + 8);
    aad.set(headerBytes, 0);
    const dv = new DataView(aad.buffer);
    dv.setUint32(aad.length - 8, chunkIndex, false);
    dv.setUint32(aad.length - 4, plainLen, false);
    return aad;
}

export function deriveChunkIvFromK(Kraw, containerNonce, chunkIndex, ivCustomization) {
    const idx = new Uint8Array(4);
    new DataView(idx.buffer).setUint32(0, chunkIndex, false);
    const input = new Uint8Array(containerNonce.length + idx.length);
    input.set(containerNonce, 0);
    input.set(idx, containerNonce.length);
    const customization = ivCustomization || 'quantum-vault:iv:v1';
    const full = kmac256(Kraw, input, 16, { customization });
    return full.slice(0, 12);
}

function normalizeEncapsulateResult(kemResult) {
    const encapsulatedKey = kemResult.cipherText || kemResult.ciphertext || kemResult.ct;
    const sharedSecret = kemResult.sharedSecret || kemResult.ss;
    if (!encapsulatedKey || !sharedSecret) throw new Error('KEM encapsulation failed: result is missing required fields.');
    return { encapsulatedKey: toUint8(encapsulatedKey), sharedSecret: toUint8(sharedSecret) };
}

// --- High-level Encrypt/Decrypt ---
export async function encryptFile(fileBytes, publicKey) {
    const { encapsulatedKey, sharedSecret } = normalizeEncapsulateResult(await ml_kem1024.encapsulate(publicKey));
    const containerNonce = crypto.getRandomValues(new Uint8Array(12));
    const kdfSalt = crypto.getRandomValues(new Uint8Array(16));
    const isPerChunk = fileBytes.length > CHUNK_SIZE;
    const domainStrings = { kdf: 'quantum-vault:kdf:v1', iv: 'quantum-vault:chunk-iv:v1' };
    const meta = {
        KEM: 'ML-KEM-1024', KDF: 'KMAC256', AEAD: 'AES-256-GCM',
        aead_mode: isPerChunk ? 'per-chunk-aead' : 'single-container-aead',
        iv_strategy: isPerChunk ? 'kmac-derive-v1' : 'single-iv',
        fmt: 'QVv1-3-0', timestamp: new Date().toISOString(),
        fileHash: await hashBytes(fileBytes), originalLength: fileBytes.length,
        chunkSize: CHUNK_SIZE, chunkCount: isPerChunk ? Math.ceil(fileBytes.length / CHUNK_SIZE) : 1,
        domainStrings
    };
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const metaLenBytes = new Uint8Array(2); new DataView(metaLenBytes.buffer).setUint16(0, metaBytes.length, false);
    const keyLenBytes = new Uint8Array(4); new DataView(keyLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);
    const header = new Uint8Array(MAGIC.length + keyLenBytes.length + encapsulatedKey.length + containerNonce.length + kdfSalt.length + metaLenBytes.length + metaBytes.length);
    let p = 0; header.set(MAGIC, p); p += MAGIC.length; header.set(keyLenBytes, p); p += keyLenBytes.length;
    header.set(encapsulatedKey, p); p += encapsulatedKey.length; header.set(containerNonce, p); p += containerNonce.length;
    header.set(kdfSalt, p); p += kdfSalt.length; header.set(metaLenBytes, p); p += metaLenBytes.length; header.set(metaBytes, p);
    const { Kraw, Kenc, Kiv, aesKey } = await deriveKeyWithKmac(sharedSecret, kdfSalt, metaBytes, domainStrings.kdf);
    let resultBlob;
    try {
        if (!isPerChunk) {
            const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: containerNonce, additionalData: header }, aesKey, fileBytes);
            resultBlob = new Blob([header, new Uint8Array(encryptedData)], { type: 'application/octet-stream' });
            return resultBlob;
        }
        const cipherChunks = [];
        let offset = 0; let chunkIndex = 0;
        while (offset < fileBytes.length) {
            const plainLen = Math.min(CHUNK_SIZE, fileBytes.length - offset);
            const plain = fileBytes.subarray(offset, offset + plainLen);
            const iv = deriveChunkIvFromK(Kiv, containerNonce, chunkIndex, domainStrings.iv);
            const aad = buildChunkAAD(header, chunkIndex, plainLen);
            const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, aesKey, plain);
            cipherChunks.push(new Uint8Array(cipherBuf));
            plain.fill(0); chunkIndex++; offset += plainLen;
        }
        const total = cipherChunks.reduce((a, c) => a + c.length, 0);
        const encrypted = new Uint8Array(total);
        { let q = 0; for (const ch of cipherChunks) { encrypted.set(ch, q); q += ch.length; } }
        resultBlob = new Blob([header, encrypted], { type: 'application/octet-stream' });
        return resultBlob;
    } finally {
        sharedSecret.fill(0); Kraw.fill(0); Kenc.fill(0); Kiv.fill(0);
    }
}

export async function decryptFile(containerBytes, secretKey) {
    if (containerBytes.length < MINIMAL_CONTAINER_SIZE) {
        throw new Error(`File is too small to be a valid container (size: ${containerBytes.length} B).`);
    }
    const dv = new DataView(containerBytes.buffer, containerBytes.byteOffset);
    let offset = 0;
    const magic = containerBytes.subarray(offset, offset + MAGIC.length);
    if (new TextDecoder().decode(magic) !== new TextDecoder().decode(MAGIC)) {
        throw new Error('Invalid file format (magic bytes mismatch).');
    }
    offset += MAGIC.length;
    const keyLen = dv.getUint32(offset, false); offset += 4;
    const encapsulatedKey = containerBytes.subarray(offset, offset + keyLen); offset += keyLen;
    const containerNonce = containerBytes.subarray(offset, offset + 12); offset += 12;
    const kdfSalt = containerBytes.subarray(offset, offset + 16); offset += 16;
    const metaLen = dv.getUint16(offset, false); offset += 2;
    if (metaLen <= 0 || metaLen > 4096) throw new Error(`Invalid metadata length: ${metaLen}. Must be between 1 and 4096.`);
    if (offset + metaLen > containerBytes.length) throw new Error('Incomplete container: metadata length exceeds file size.');
    const metaBytes = containerBytes.subarray(offset, offset + metaLen);
    const metadata = JSON.parse(new TextDecoder().decode(metaBytes));
    offset += metaLen;
    const header = containerBytes.subarray(0, offset);
    const encryptedData = containerBytes.subarray(offset);
    const decapsulationResult = await ml_kem1024.decapsulate(encapsulatedKey, secretKey);
    const sharedSecret = toUint8(decapsulationResult);
    if (!sharedSecret || sharedSecret.length === 0) throw new Error('KEM decapsulation failed. The key may be incorrect or the ciphertext corrupted.');
    const ds = metadata.domainStrings || metadata.domain || {};
    const { Kraw, Kenc, Kiv, aesKey } = await deriveKeyWithKmac(sharedSecret, kdfSalt, metaBytes, ds.kdf || DEFAULT_CUSTOMIZATION);
    if (metadata.aead_mode === 'per-chunk-aead' || metadata.aead_mode === 'per-chunk') {
        const totalChunks = metadata.chunkCount || Math.ceil(metadata.originalLength / (metadata.chunkSize || CHUNK_SIZE));
        const plains = []; let encOffset = 0;
        for (let i = 0; i < totalChunks; i++) {
            const plainLen = Math.min(CHUNK_SIZE, metadata.originalLength - (i * CHUNK_SIZE));
            const encLen = plainLen + 16;
            const cipherChunk = encryptedData.subarray(encOffset, encOffset + encLen);
            const iv = deriveChunkIvFromK(Kiv, containerNonce, i, ds.iv || 'quantum-vault:chunk-iv:v1');
            const aad = buildChunkAAD(header, i, plainLen);
            const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, aesKey, cipherChunk);
            plains.push(new Uint8Array(decrypted)); encOffset += encLen;
        }
        const totalPlain = plains.reduce((a, c) => a + c.length, 0);
        const out = new Uint8Array(totalPlain);
        { let p2 = 0; for (const ch of plains) { out.set(ch, p2); p2 += ch.length; } }
        sharedSecret.fill(0); Kraw.fill(0); Kenc.fill(0); Kiv.fill(0);
        return { decryptedBlob: new Blob([out]), metadata };
    }
    const decryptedData = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: containerNonce, additionalData: header }, aesKey, encryptedData);
    sharedSecret.fill(0); Kraw.fill(0); Kenc.fill(0); Kiv.fill(0);
    return { decryptedBlob: new Blob([decryptedData]), metadata };
}


