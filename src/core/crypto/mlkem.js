// --- ML-KEM-1024 Post-Quantum Key Encapsulation ---

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { generateEnhancedSeed, validateSeed } from './entropy.js';
import { toUint8 } from './bytes.js';

// Generate ML-KEM-1024 key pair (optionally mixing user entropy)
export async function generateKeyPair(options = {}) {
    const { userEntropyBytes = null, customSeed = null } = options;

    let seed, seedInfo;
    
    if (customSeed) {
        // Use provided seed (e.g., deterministic testing) without mutating caller input.
        validateSeed(customSeed);
        seed = customSeed.slice();
        seedInfo = { hasUserEntropy: false, source: 'custom' };
    } else {
        const result = await generateEnhancedSeed({ userEntropyBytes });
        seed = result.seed;
        seedInfo = { 
            hasUserEntropy: result.hasUserEntropy, 
            source: result.hasUserEntropy ? 'mixed' : 'secure-random' 
        };
    }

    try {
        // Generate key pair using seeded generation
        const keyPair = ml_kem1024.keygen(seed);
        return {
            publicKey: toUint8(keyPair.publicKey),
            privateKey: toUint8(keyPair.secretKey),
            seedInfo
        };
    } finally {
        if (seed instanceof Uint8Array) {
            seed.fill(0);
        }
    }
}

// Encapsulate using ML-KEM-1024 public key
// noble-post-quantum v0.5.x API: { cipherText, sharedSecret }
export async function encapsulate(publicKey) {
    validatePublicKey(publicKey);
    const result = await ml_kem1024.encapsulate(publicKey);
    
    const encapsulatedKey = result.cipherText;
    const sharedSecret = result.sharedSecret;
    
    if (!(encapsulatedKey instanceof Uint8Array) || !(sharedSecret instanceof Uint8Array)) {
        throw new Error(
            'KEM encapsulation failed: unexpected API response. ' +
            'Verify noble-post-quantum version compatibility (expected v0.5.x).'
        );
    }
    
    return {
        encapsulatedKey: toUint8(encapsulatedKey),
        sharedSecret: toUint8(sharedSecret)
    };
}

// Decapsulate using ML-KEM-1024 private key
export async function decapsulate(encapsulatedKey, privateKey) {
    const result = await ml_kem1024.decapsulate(encapsulatedKey, privateKey);
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
    if (publicKey.length !== ML_KEM_1024_PUBLIC_KEY_SIZE) {
        throw new Error(`Invalid ML-KEM-1024 public key length: expected ${ML_KEM_1024_PUBLIC_KEY_SIZE} bytes, got ${publicKey.length}`);
    }
}

// Validate ML-KEM-1024 private key size
export function validatePrivateKey(privateKey) {
    if (!(privateKey instanceof Uint8Array)) {
        throw new Error('Private key must be Uint8Array');
    }
    if (privateKey.length !== ML_KEM_1024_PRIVATE_KEY_SIZE) {
        throw new Error(`Invalid ML-KEM-1024 private key length: expected ${ML_KEM_1024_PRIVATE_KEY_SIZE} bytes, got ${privateKey.length}`);
    }
}

// Validate ML-KEM-1024 encapsulated key size
export function validateEncapsulatedKey(encapsulatedKey) {
    if (!(encapsulatedKey instanceof Uint8Array)) {
        throw new Error('Encapsulated key must be Uint8Array');
    }
    if (encapsulatedKey.length !== ML_KEM_1024_ENCAPSULATED_KEY_SIZE) {
        throw new Error(`Invalid ML-KEM-1024 encapsulated key length: expected ${ML_KEM_1024_ENCAPSULATED_KEY_SIZE} bytes, got ${encapsulatedKey.length}`);
    }
}

// Export constants
export const ML_KEM_1024_PUBLIC_KEY_SIZE = 1568;
export const ML_KEM_1024_PRIVATE_KEY_SIZE = 3168;
export const ML_KEM_1024_ENCAPSULATED_KEY_SIZE = 1568;
export const ML_KEM_1024_SHARED_SECRET_SIZE = 32;
