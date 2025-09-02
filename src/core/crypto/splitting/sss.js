// --- Shamir Secret Sharing ---

import { validateRsParams, calculateShamirThreshold } from '../../../utils.js';

// Split secret into n shares with threshold t
export async function splitSecret(secret, n, t) {
    // Validate
    if (!(secret instanceof Uint8Array)) {
        throw new Error('Secret must be Uint8Array');
    }
    if (secret.length === 0) {
        throw new Error('Secret cannot be empty');
    }
    if (!Number.isInteger(n) || !Number.isInteger(t)) {
        throw new Error('n and t must be integers');
    }
    if (t < 2) {
        throw new Error('Threshold must be at least 2');
    }
    if (t > n) {
        throw new Error('Threshold cannot exceed total shares');
    }
    if (n > 255) {
        throw new Error('Maximum 255 shares supported');
    }

    // Import lib dynamically
    const sss = await import('shamir-secret-sharing');
    
    try {
        const shares = await sss.split(secret, n, t);
        
        // Validate count
        if (!Array.isArray(shares) || shares.length !== n) {
            throw new Error(`Expected ${n} shares, got ${shares.length}`);
        }
        
        // Normalize to Uint8Array
        return shares.map(share => {
            if (share instanceof Uint8Array) {
                return share;
            }
            if (share instanceof ArrayBuffer) {
                return new Uint8Array(share);
            }
            if (ArrayBuffer.isView(share)) {
                return new Uint8Array(share.buffer, share.byteOffset, share.byteLength);
            }
            throw new Error('Invalid share format returned by SSS library');
        });
        
    } catch (error) {
        throw new Error(`Shamir Secret Sharing failed: ${error.message}`);
    }
}

// Combine shares to reconstruct secret
export async function combineShares(shares) {
    // Validate
    if (!Array.isArray(shares)) {
        throw new Error('Shares must be an array');
    }
    if (shares.length < 2) {
        throw new Error('Need at least 2 shares to reconstruct secret');
    }
    if (shares.length > 255) {
        throw new Error('Too many shares provided (max 255)');
    }

    // Validate share types
    for (let i = 0; i < shares.length; i++) {
        if (!(shares[i] instanceof Uint8Array)) {
            throw new Error(`Share ${i} must be Uint8Array`);
        }
        if (shares[i].length === 0) {
            throw new Error(`Share ${i} is empty`);
        }
    }

    // Length consistency
    const shareLength = shares[0].length;
    for (let i = 1; i < shares.length; i++) {
        if (shares[i].length !== shareLength) {
            throw new Error(`Share length mismatch: share 0 has ${shareLength} bytes, share ${i} has ${shares[i].length} bytes`);
        }
    }

    // Import lib dynamically
    const sss = await import('shamir-secret-sharing');
    
    try {
        const secret = await sss.combine(shares);
        
        // Normalize to Uint8Array
        if (secret instanceof Uint8Array) {
            return secret;
        }
        if (secret instanceof ArrayBuffer) {
            return new Uint8Array(secret);
        }
        if (ArrayBuffer.isView(secret)) {
            return new Uint8Array(secret.buffer, secret.byteOffset, secret.byteLength);
        }
        
        throw new Error('Invalid secret format returned by SSS library');
        
    } catch (error) {
        throw new Error(`Shamir Secret reconstruction failed: ${error.message}`);
    }
}

// Shamir threshold from RS params
export function calculateThresholdFromRS(n, k) {
    if (!validateRsParams(n, k)) {
        throw new Error('Invalid Reed-Solomon parameters');
    }
    return calculateShamirThreshold(n, k);
}

// Validate SSS params for RS
export function validateShamirParams(n, k) {
    try {
        const t = calculateThresholdFromRS(n, k);
        return t >= 2 && t <= n && Number.isInteger(t);
    } catch {
        return false;
    }
}

// Basic share info (length, emptiness)
export function getShareInfo(share) {
    if (!(share instanceof Uint8Array)) {
        throw new Error('Share must be Uint8Array');
    }
    
    return {
        length: share.length,
        isEmpty: share.length === 0,
        // Note: share index is embedded by the library; not extracted here
    };
}

// Validate a set of shares for consistency
export function validateShares(shares) {
    if (!Array.isArray(shares)) {
        return { valid: false, error: 'Shares must be an array' };
    }
    
    if (shares.length === 0) {
        return { valid: false, error: 'No shares provided' };
    }
    
    if (shares.length > 255) {
        return { valid: false, error: 'Too many shares (max 255)' };
    }
    
    // Check each share
    for (let i = 0; i < shares.length; i++) {
        if (!(shares[i] instanceof Uint8Array)) {
            return { valid: false, error: `Share ${i} is not Uint8Array` };
        }
        if (shares[i].length === 0) {
            return { valid: false, error: `Share ${i} is empty` };
        }
    }
    
    // Length consistency
    const firstLength = shares[0].length;
    for (let i = 1; i < shares.length; i++) {
        if (shares[i].length !== firstLength) {
            return { 
                valid: false, 
                error: `Share length mismatch: expected ${firstLength}, got ${shares[i].length} at index ${i}` 
            };
        }
    }
    
    return { 
        valid: true, 
        shareCount: shares.length,
        shareLength: firstLength 
    };
}
