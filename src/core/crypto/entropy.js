import { kmac256 } from './kmac.js';

const CONFIG = {
    seedLength: 64,
};

const SEED_LENGTH = CONFIG.seedLength;

export function generateBaseSeed() {
    const seed = crypto.getRandomValues(new Uint8Array(SEED_LENGTH));

    // CSPRNG health check: consecutive outputs must differ.
    const probe = crypto.getRandomValues(new Uint8Array(SEED_LENGTH));
    let identical = true;
    for (let i = 0; i < seed.length; i += 1) {
        if (seed[i] !== probe[i]) {
            identical = false;
            break;
        }
    }
    if (identical) {
        throw new Error('CSPRNG health check failed: consecutive outputs are identical');
    }

    return seed;
}

export function mixEntropy(baseSeed, userEntropy = new Uint8Array(0)) {
    if (!(baseSeed instanceof Uint8Array) || baseSeed.length !== SEED_LENGTH) {
        throw new Error(`Base seed must be ${SEED_LENGTH} bytes`);
    }
    if (!(userEntropy instanceof Uint8Array)) {
        throw new Error('User entropy must be Uint8Array');
    }

    if (userEntropy.length === 0) {
        return baseSeed;
    }

    const kmacMixed = kmac256(baseSeed, userEntropy, {
        customization: 'quantum-vault:entropy-mix:v2',
    });

    const rawMixed = new Uint8Array(SEED_LENGTH);
    rawMixed.set(kmacMixed, 0);
    rawMixed.set(crypto.getRandomValues(new Uint8Array(32)), 32);
    return rawMixed;
}

export async function generateEnhancedSeed(options = {}) {
    const { userEntropyBytes = null } = options;
    const baseSeed = generateBaseSeed();

    if (!(userEntropyBytes instanceof Uint8Array) || userEntropyBytes.length === 0) {
        return { seed: baseSeed, hasUserEntropy: false };
    }

    const mixedSeed = mixEntropy(baseSeed, userEntropyBytes);
    return { seed: mixedSeed, hasUserEntropy: true };
}

export function validateSeed(seed) {
    if (!(seed instanceof Uint8Array)) {
        throw new Error('Seed must be Uint8Array');
    }
    if (seed.length !== SEED_LENGTH) {
        throw new Error(`Seed must be exactly ${SEED_LENGTH} bytes`);
    }
}

export { CONFIG, SEED_LENGTH };
export const MIN_ENTROPY_EVENTS = 100;
