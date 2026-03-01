// Key derivation (KMAC256) and key commitment (SHA3-256)

import { kmac256 } from '@noble/hashes/sha3-addons.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { timingSafeEqual } from './bytes.js';

export const AES_KEY_SIZE = 32;

// Derive keys from shared secret using KMAC256
export async function deriveKeyWithKmac(sharedSecret, salt, metaBytes, customization) {
    if (typeof customization !== 'string' || customization.length === 0) {
        throw new Error('KMAC customization domain is required');
    }

    const kmacMessage = new Uint8Array(salt.length + metaBytes.length);
    kmacMessage.set(salt, 0);
    kmacMessage.set(metaBytes, salt.length);

    const Kraw = kmac256(sharedSecret, kmacMessage, 32, { customization });

    const Kenc = kmac256(Kraw, new Uint8Array([1]), 32, { customization: 'quantum-vault:kenc:v1' });
    const Kiv = kmac256(Kraw, new Uint8Array([2]), 32, { customization: 'quantum-vault:kiv:v1' });

    // Slice the exact region: Kenc may be a view with non-zero byteOffset
    const aesKey = await crypto.subtle.importKey(
        'raw',
        Kenc.buffer.slice(Kenc.byteOffset, Kenc.byteOffset + Kenc.byteLength),
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );

    kmacMessage.fill(0);

    return { Kraw, Kenc, Kiv, aesKey };
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
