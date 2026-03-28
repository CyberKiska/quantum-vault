// Key derivation (KMAC256) and key commitment (SHA3-256)

import { sha3_256 } from '@noble/hashes/sha3.js';
import { timingSafeEqual } from './bytes.js';
import { kmac256, KMAC256_DEFAULT_DKLEN } from './kmac.js';

export const AES_KEY_SIZE = 32;
const KENC_LABEL = new Uint8Array([1]);
const KIV_LABEL = new Uint8Array([2]);

// Derive keys from shared secret using KMAC256 per SP 800-185.
export async function deriveKeyWithKmac(sharedSecret, salt, metaBytes, domainStrings, options = {}) {
    const { includeAesKey = true } = options;
    if (!domainStrings || typeof domainStrings !== 'object') {
        throw new Error('KMAC domainStrings are required');
    }
    if (typeof domainStrings.kdf !== 'string' || domainStrings.kdf.length === 0) {
        throw new Error('KMAC KDF customization domain is required');
    }
    if (typeof domainStrings.kenc !== 'string' || domainStrings.kenc.length === 0) {
        throw new Error('KMAC Kenc customization domain is required');
    }
    if (typeof domainStrings.kiv !== 'string' || domainStrings.kiv.length === 0) {
        throw new Error('KMAC Kiv customization domain is required');
    }

    const kmacMessage = new Uint8Array(salt.length + metaBytes.length);
    kmacMessage.set(salt, 0);
    kmacMessage.set(metaBytes, salt.length);
    let Kraw = null;
    let Kenc = null;
    let Kiv = null;
    let aesKey = null;
    let completed = false;
    try {
        Kraw = kmac256(sharedSecret, kmacMessage, {
            dkLen: KMAC256_DEFAULT_DKLEN,
            customization: domainStrings.kdf,
        });

        Kenc = kmac256(Kraw, KENC_LABEL, {
            dkLen: AES_KEY_SIZE,
            customization: domainStrings.kenc,
        });
        Kiv = kmac256(Kraw, KIV_LABEL, {
            dkLen: AES_KEY_SIZE,
            customization: domainStrings.kiv,
        });

        if (includeAesKey) {
            // Slice the exact region: Kenc may be a view with non-zero byteOffset
            aesKey = await crypto.subtle.importKey(
                'raw',
                Kenc.buffer.slice(Kenc.byteOffset, Kenc.byteOffset + Kenc.byteLength),
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );
        }

        completed = true;
        return { Kraw, Kenc, Kiv, aesKey };
    } finally {
        kmacMessage.fill(0);
        if (!completed) {
            clearKeys(Kraw, Kenc, Kiv);
        }
    }
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
