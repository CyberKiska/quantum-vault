import { kmac256 as nobleKmac256 } from '@noble/hashes/sha3-addons.js';
import { utf8ToBytes } from './bytes.js';

export const KMAC256_DEFAULT_DKLEN = 32;

// noble exposes SP 800-185's KMAC customization string as `personalization`.
export function kmac256(key, message, options = {}) {
    const {
        customization = '',
        dkLen = KMAC256_DEFAULT_DKLEN,
    } = options;

    if (!(key instanceof Uint8Array)) {
        throw new Error('KMAC key must be Uint8Array');
    }
    if (!(message instanceof Uint8Array)) {
        throw new Error('KMAC message must be Uint8Array');
    }
    if (typeof customization !== 'string') {
        throw new Error('KMAC customization string must be a string');
    }
    if (!Number.isSafeInteger(dkLen) || dkLen <= 0) {
        throw new Error('KMAC dkLen must be a positive integer');
    }

    return nobleKmac256(key, message, {
        dkLen,
        personalization: utf8ToBytes(customization),
    });
}
