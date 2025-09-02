// --- ML-KEM-1024 Post-Quantum Key Encapsulation ---

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { generateEnhancedSeed, validateSeed } from './entropy.js';
import { toUint8 } from '../../utils.js';

// Generate ML-KEM-1024 key pair (optionally mixing user entropy)
export async function generateKeyPair(options = {}) {
    const { collectUserEntropy = false, customSeed = null } = options;

    let seed, seedInfo;
    
    if (customSeed) {
        // Use provided seed (e.g., for testing)
        validateSeed(customSeed);
        seed = customSeed;
        seedInfo = { hasUserEntropy: false, source: 'custom' };
    } else {
        // Generate enhanced seed
        const result = await generateEnhancedSeed(collectUserEntropy);
        seed = result.seed;
        seedInfo = { 
            hasUserEntropy: result.hasUserEntropy, 
            source: result.hasUserEntropy ? 'mixed' : 'secure-random' 
        };
    }

    // Generate key pair using seeded generation
    const keyPair = ml_kem1024.keygen(seed);
    
    // Clear seed from memory for security
    seed.fill(0);

    return {
        publicKey: toUint8(keyPair.publicKey),
        secretKey: toUint8(keyPair.secretKey),
        seedInfo
    };
}

// Encapsulate using ML-KEM-1024 public key
export async function encapsulate(publicKey) {
    const result = await ml_kem1024.encapsulate(publicKey);
    
    // Normalize result (lib versions differ in field names)
    const encapsulatedKey = result.cipherText || result.ciphertext || result.ct;
    const sharedSecret = result.sharedSecret || result.ss;
    
    if (!encapsulatedKey || !sharedSecret) {
        throw new Error('KEM encapsulation failed: result is missing required fields.');
    }
    
    return {
        encapsulatedKey: toUint8(encapsulatedKey),
        sharedSecret: toUint8(sharedSecret)
    };
}

// Decapsulate using ML-KEM-1024 secret key
export async function decapsulate(encapsulatedKey, secretKey) {
    const result = await ml_kem1024.decapsulate(encapsulatedKey, secretKey);
    const sharedSecret = toUint8(result);
    
    if (!sharedSecret || sharedSecret.length === 0) {
        throw new Error('KEM decapsulation failed. The key may be incorrect or the ciphertext corrupted.');
    }
    
    return sharedSecret;
}

// Validate ML-KEM-1024 public key size
export function validatePublicKey(publicKey) {
    if (!(publicKey instanceof Uint8Array)) {
        throw new Error('Public key must be Uint8Array');
    }
    // ML-KEM-1024 public key is 1568 bytes
    if (publicKey.length !== 1568) {
        throw new Error(`Invalid ML-KEM-1024 public key length: expected 1568 bytes, got ${publicKey.length}`);
    }
}

// Validate ML-KEM-1024 secret key size
export function validateSecretKey(secretKey) {
    if (!(secretKey instanceof Uint8Array)) {
        throw new Error('Secret key must be Uint8Array');
    }
    // ML-KEM-1024 secret key is 3168 bytes
    if (secretKey.length !== 3168) {
        throw new Error(`Invalid ML-KEM-1024 secret key length: expected 3168 bytes, got ${secretKey.length}`);
    }
}

// Validate ML-KEM-1024 encapsulated key size
export function validateEncapsulatedKey(encapsulatedKey) {
    if (!(encapsulatedKey instanceof Uint8Array)) {
        throw new Error('Encapsulated key must be Uint8Array');
    }
    // ML-KEM-1024 encapsulated key is 1568 bytes
    if (encapsulatedKey.length !== 1568) {
        throw new Error(`Invalid ML-KEM-1024 encapsulated key length: expected 1568 bytes, got ${encapsulatedKey.length}`);
    }
}

// Export constants
export const ML_KEM_1024_PUBLIC_KEY_SIZE = 1568;
export const ML_KEM_1024_SECRET_KEY_SIZE = 3168;
export const ML_KEM_1024_ENCAPSULATED_KEY_SIZE = 1568;
export const ML_KEM_1024_SHARED_SECRET_SIZE = 32;
