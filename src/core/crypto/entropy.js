// --- Entropy Collection and Key Generation ---

import { sha3_512 } from '@noble/hashes/sha3.js';
import { kmac256 } from '@noble/hashes/sha3-addons.js';

// --- Entropy Collection Configuration ---
// All parameters are documented and configurable to avoid magic numbers
const CONFIG = {
    // Minimum events required for entropy collection completion
    minEvents: 100,

    // Maximum buffer size before processing (privacy: limit stored raw data)
    maxBufferBytes: 2048,

    // Process entropy blocks when buffer reaches this size
    processThresholdBytes: 512,

    // Mix in OS random every N events for additional security
    mixOsEveryNEvents: 32,

    // Maximum collection time in milliseconds
    maxCollectionMs: 30000,

    // Direction buckets for mouse movement quantization (8 cardinal directions)
    directionBuckets: 8,

    // Maximum speed value for quantization (pixels per event)
    maxSpeedPixels: 100,

    // Maximum time delta for quantization (milliseconds)
    maxTimeDeltaMs: 1000,

    // Output seed length for ML-KEM-1024
    seedLength: 64
};

// Derived constants
const SEED_LENGTH = CONFIG.seedLength;

// Generate seed using crypto.getRandomValues()
export function generateBaseSeed() {
    const seed = crypto.getRandomValues(new Uint8Array(SEED_LENGTH));

    // CSPRNG health check (cf. NIST SP 800-90B §4.3)
    const probe = crypto.getRandomValues(new Uint8Array(SEED_LENGTH));
    let identical = true;
    for (let i = 0; i < seed.length; i++) {
        if (seed[i] !== probe[i]) { identical = false; break; }
    }
    if (identical) {
        throw new Error('CSPRNG health check failed: consecutive outputs are identical');
    }

    return seed;
}

// Privacy-preserving mouse movement summarization
function summarizeMouse(dx, dy, dtMs, buttons) {
    // Quantize direction into 8 buckets (cardinal directions)
    const directionRadians = Math.atan2(dy, dx);
    const normalizedAngle = directionRadians + Math.PI; // 0 to 2π
    const bucket = Math.floor((normalizedAngle / (2 * Math.PI)) * CONFIG.directionBuckets) % CONFIG.directionBuckets;

    // Quantize speed (distance moved)
    const speed = Math.min(255, Math.floor(Math.hypot(dx, dy)));

    // Quantize time delta
    const timeDelta = Math.min(CONFIG.maxTimeDeltaMs, Math.max(0, dtMs));

    // Create binary representation
    const summary = new Uint8Array(6);
    summary[0] = 0x01; // Event type: mouse movement
    summary[1] = bucket & 0xFF; // Direction bucket (0-7)
    summary[2] = speed & 0xFF; // Speed (0-255)
    summary[3] = timeDelta & 0xFF; // Time delta low byte
    summary[4] = (timeDelta >> 8) & 0xFF; // Time delta high byte
    summary[5] = buttons & 0xFF; // Button state

    return summary;
}

function summarizeKeyboard(key, keyCode, location, dtMs, isRepeat) {
    // Hash key characteristics to avoid storing actual key values
    const keyHash = (keyCode + location + (isRepeat ? 1 : 0)) & 0xFF;
    const timeDelta = Math.min(CONFIG.maxTimeDeltaMs, Math.max(0, dtMs));

    const summary = new Uint8Array(5);
    summary[0] = 0x02; // Event type: keyboard
    summary[1] = keyHash;
    summary[2] = timeDelta & 0xFF;
    summary[3] = (timeDelta >> 8) & 0xFF;
    summary[4] = location & 0xFF;

    return summary;
}

function summarizeWindow(width, height, dtMs) {
    // Quantize dimensions to prevent exact fingerprinting
    const widthBucket = Math.floor(width / 100) & 0xFF; // 100px buckets
    const heightBucket = Math.floor(height / 100) & 0xFF;
    const timeDelta = Math.min(CONFIG.maxTimeDeltaMs, Math.max(0, dtMs));

    const summary = new Uint8Array(5);
    summary[0] = 0x03; // Event type: window
    summary[1] = widthBucket;
    summary[2] = heightBucket;
    summary[3] = timeDelta & 0xFF;
    summary[4] = (timeDelta >> 8) & 0xFF;

    return summary;
}

export class UserEntropyCollector {
    constructor() {
        this.events = [];
        this.isCollecting = false;
        this.startTime = 0;
        this.listeners = [];
        this.entropyBuffer = new Uint8Array(0);
        this.entropyState = crypto.getRandomValues(new Uint8Array(64)); // 512-bit initial state
        this.lastEventTime = 0;
        this.screenInfo = null; // Fixed screen info as salt
        this.eventCount = 0;
        this.processingQueue = [];
        this.isProcessing = false;

        // Privacy: Track last mouse position for delta calculation
        this.lastMouseX = 0;
        this.lastMouseY = 0;
        this.mouseInitialized = false;
    }

    async startCollection() {
        if (this.isCollecting) {
            throw new Error('Entropy collection already in progress');
        }

        return new Promise((resolve, reject) => {
            this.isCollecting = true;
            this.startTime = performance.now();
            this.lastEventTime = this.startTime;
            this.events = [];
            this.entropyBuffer = new Uint8Array(0);

            // Initialize screen info as fixed salt
            this.screenInfo = {
                width: window.innerWidth,
                height: window.innerHeight,
                screenX: window.screenX,
                screenY: window.screenY,
                colorDepth: window.screen.colorDepth,
                pixelDepth: window.screen.pixelDepth
            };

            // Set up event listeners
            this.setupEventListeners();

            // Timeout fallback
            const timeout = setTimeout(() => {
                console.log('⚠️ Entropy collection timeout reached, generating final seed...');
                this.stopCollection();
                // Return 64-byte seed from current state even if timeout
                const finalSeed = this.generateFinalSeed();
                console.log(`Timeout final seed length: ${finalSeed.length} bytes`);
                resolve(finalSeed);
            }, CONFIG.maxCollectionMs);

            // Check periodically if we have enough entropy
            const checkEntropy = () => {
                if (this.events.length >= CONFIG.minEvents) {
                    clearTimeout(timeout);
                    this.stopCollection();
                    resolve(this.generateFinalSeed());
                } else if (this.isCollecting) {
                    setTimeout(checkEntropy, 100);
                }
            };

            setTimeout(checkEntropy, 100);
        });
    }

    stopCollection() {
        this.isCollecting = false;
        this.removeEventListeners();
    }

    setupEventListeners() {
        // Mouse movement with privacy-preserving delta tracking
        const mouseHandler = (e) => {
            if (!this.isCollecting) return;

            const now = performance.now();
            const timeDelta = now - this.lastEventTime;

            if (!this.mouseInitialized) {
                this.lastMouseX = e.clientX;
                this.lastMouseY = e.clientY;
                this.mouseInitialized = true;
                this.lastEventTime = now;
                return;
            }

            const dx = e.clientX - this.lastMouseX;
            const dy = e.clientY - this.lastMouseY;

            if (dx === 0 && dy === 0) return;

            const summary = summarizeMouse(dx, dy, timeDelta, e.buttons);

            this.lastMouseX = e.clientX;
            this.lastMouseY = e.clientY;
            this.lastEventTime = now;

            this.processEventAsync(summary);

            this.events.push({ type: 'mouse', timestamp: now });
        };

        // Keyboard events with privacy preservation
        const keyHandler = (e) => {
            if (!this.isCollecting) return;

            const now = performance.now();
            const timeDelta = now - this.lastEventTime;

            const summary = summarizeKeyboard(e.key, e.keyCode, e.location, timeDelta, e.repeat);

            this.lastEventTime = now;

            this.processEventAsync(summary);

            this.events.push({ type: 'key', timestamp: now });
        };

        // Window events with privacy preservation
        const windowHandler = () => {
            if (!this.isCollecting) return;

            const now = performance.now();
            const timeDelta = now - this.lastEventTime;

            const summary = summarizeWindow(window.innerWidth, window.innerHeight, timeDelta);

            this.lastEventTime = now;

            this.processEventAsync(summary);

            this.events.push({ type: 'window', timestamp: now });
        };

        // Touch events for mobile
        const touchHandler = (e) => {
            if (!this.isCollecting) return;

            const now = performance.now();
            const timeDelta = now - this.lastEventTime;
            const touch = e.touches[0];

            if (touch) {
                const xBucket = Math.floor(touch.clientX / 50) & 0xFF; // 50px buckets
                const yBucket = Math.floor(touch.clientY / 50) & 0xFF;

                const summary = new Uint8Array(6);
                summary[0] = 0x04; // Event type: touch
                summary[1] = xBucket;
                summary[2] = yBucket;
                summary[3] = Math.min(255, Math.floor(touch.force * 255)) & 0xFF;
                summary[4] = timeDelta & 0xFF;
                summary[5] = (timeDelta >> 8) & 0xFF;

                this.lastEventTime = now;
                this.processEventAsync(summary);
                this.events.push({ type: 'touch', timestamp: now });
            }
        };

        // Add event listeners
        document.addEventListener('mousemove', mouseHandler, { passive: true });
        document.addEventListener('keydown', keyHandler, { passive: true });
        document.addEventListener('keyup', keyHandler, { passive: true });
        window.addEventListener('resize', windowHandler, { passive: true });
        window.addEventListener('focus', windowHandler, { passive: true });
        window.addEventListener('blur', windowHandler, { passive: true });
        document.addEventListener('touchmove', touchHandler, { passive: true });

        // Store listeners for cleanup
        this.listeners = [
            { element: document, event: 'mousemove', handler: mouseHandler },
            { element: document, event: 'keydown', handler: keyHandler },
            { element: document, event: 'keyup', handler: keyHandler },
            { element: window, event: 'resize', handler: windowHandler },
            { element: window, event: 'focus', handler: windowHandler },
            { element: window, event: 'blur', handler: windowHandler },
            { element: document, event: 'touchmove', handler: touchHandler }
        ];
    }

    removeEventListeners() {
        this.listeners.forEach(({ element, event, handler }) => {
            element.removeEventListener(event, handler);
        });
        this.listeners = [];
    }

    processEventAsync(summary) {
        this.processingQueue.push(summary);

        if (!this.isProcessing) {
            this.isProcessing = true;
            setTimeout(() => this.processQueue(), 0);
        }
    }

    async processQueue() {
        while (this.processingQueue.length > 0) {
            const summary = this.processingQueue.shift();
            await this.processEventSummary(summary);

            // Yield control periodically to avoid blocking
            if (this.processingQueue.length > 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        this.isProcessing = false;
    }

    // Process a single event summary using unified hash-then-KMAC pattern
    async processEventSummary(summary) {
        this.eventCount++;

        // Mix OS random periodically for additional security
        if (this.eventCount % CONFIG.mixOsEveryNEvents === 0) {
            const osRandom = crypto.getRandomValues(new Uint8Array(32));
            const combinedInput = new Uint8Array(this.entropyState.length + osRandom.length);
            combinedInput.set(this.entropyState, 0);
            combinedInput.set(osRandom, this.entropyState.length);
            this.entropyState = sha3_512(combinedInput);
        }

        // Create digest from event summary + OS random
        const osRandom = crypto.getRandomValues(new Uint8Array(16));
        const combinedInput = new Uint8Array(summary.length + osRandom.length);
        combinedInput.set(summary, 0);
        combinedInput.set(osRandom, summary.length);

        const digest = sha3_512(combinedInput);

        // Mix digest into entropy state: state := SHA3-512(state || digest)
        const stateInput = new Uint8Array(this.entropyState.length + digest.length);
        stateInput.set(this.entropyState, 0);
        stateInput.set(digest, this.entropyState.length);
        this.entropyState = sha3_512(stateInput);

        summary.fill(0);
    }

    // Generate final 64-byte seed using unified hash-then-KMAC pattern
    generateFinalSeed() {
        if (this.processingQueue.length > 0) {
            this.processingQueue.forEach(summary => {
                this.processEventSummary(summary);
            });
            this.processingQueue = [];
        }

        // Final OS random mixing for additional security
        const finalOsRandom = crypto.getRandomValues(new Uint8Array(32));
        const finalInput = new Uint8Array(this.entropyState.length + finalOsRandom.length);
        finalInput.set(this.entropyState, 0);
        finalInput.set(finalOsRandom, this.entropyState.length);
        this.entropyState = sha3_512(finalInput);

        // Generate final seed using KMAC256 (CTR mode pattern)
        const counter = new Uint8Array(4);
        counter[0] = 0; // Counter starts at 0

        // First 32 bytes: KMAC256(state, counter)
        const firstBlock = kmac256(this.entropyState, counter, undefined, {
            customization: 'quantum-vault:final-seed:v1'
        });

        counter[0] = 1;

        // Next 32 bytes: KMAC256(state, counter)
        const secondBlock = kmac256(this.entropyState, counter, undefined, {
            customization: 'quantum-vault:final-seed:v1'
        });

        // Combine blocks into final 64-byte seed
        const finalSeed = new Uint8Array(SEED_LENGTH);
        finalSeed.set(firstBlock, 0);
        finalSeed.set(secondBlock, 32);

        // Update state for forward secrecy: state := SHA3-512(state || finalSeed)
        const stateUpdate = new Uint8Array(this.entropyState.length + finalSeed.length);
        stateUpdate.set(this.entropyState, 0);
        stateUpdate.set(finalSeed, this.entropyState.length);
        this.entropyState = sha3_512(stateUpdate);

        return finalSeed;
    }

    // Get collection progress with entropy estimation
    getProgress() {
        const collected = this.events.length;
        const required = CONFIG.minEvents;
        const percentage = Math.min(100, Math.round((collected / required) * 100));

        const estimatedEntropyBits = this.estimateEntropyBits();

        return {
            collected,
            required,
            percentage,
            queueSize: this.processingQueue.length,
            estimatedEntropyBits,
            isCollecting: this.isCollecting
        };
    }

    // Estimate entropy bits using simplified NIST SP 800-90B approach
    estimateEntropyBits() {
        if (this.events.length === 0) return 0;

        const eventTypes = { mouse: 0, key: 0, window: 0, touch: 0 };
        this.events.forEach(event => {
            if (event.type in eventTypes) {
                eventTypes[event.type]++;
            }
        });

        const totalEvents = this.events.length;
        let typeEntropy = 0;

        Object.values(eventTypes).forEach(count => {
            if (count > 0) {
                const probability = count / totalEvents;
                typeEntropy -= probability * Math.log2(probability);
            }
        });

        const timingVariability = this.estimateTimingEntropy();

        // Combine estimates with conservative multiplier
        const totalEntropy = (typeEntropy + timingVariability) * this.events.length * 0.1;

        return Math.min(totalEntropy, 512); // Cap at reasonable maximum
    }

    estimateTimingEntropy() {
        if (this.events.length < 2) return 0;

        // Calculate time differences between consecutive events
        const intervals = [];
        for (let i = 1; i < this.events.length; i++) {
            const interval = this.events[i].timestamp - this.events[i-1].timestamp;
            intervals.push(interval);
        }

        // Calculate entropy of interval distribution
        const bucketSize = 50; // 50ms buckets
        const buckets = new Map();

        intervals.forEach(interval => {
            const bucket = Math.floor(interval / bucketSize);
            buckets.set(bucket, (buckets.get(bucket) || 0) + 1);
        });

        let timingEntropy = 0;
        const totalIntervals = intervals.length;

        buckets.forEach(count => {
            const probability = count / totalIntervals;
            timingEntropy -= probability * Math.log2(probability);
        });

        return timingEntropy;
    }
}

// Mix user entropy with base seed using KMAC256
export function mixEntropy(baseSeed, userEntropy = new Uint8Array(0)) {
    if (baseSeed.length !== SEED_LENGTH) {
        throw new Error(`Base seed must be ${SEED_LENGTH} bytes`);
    }

    // If no user entropy, return base seed
    if (userEntropy.length === 0) {
        return baseSeed;
    }

    // Mix using KMAC256 with base seed as key and user entropy as message
    const kmacMixed = kmac256(baseSeed, userEntropy, undefined, {
        customization: 'quantum-vault:entropy-mix:v1'
    });

    // Create 64-byte result by combining KMAC output with additional entropy
    const rawMixed = new Uint8Array(SEED_LENGTH);
    rawMixed.set(kmacMixed, 0); // First 32 bytes from KMAC

    // Fill remaining 32 bytes with additional entropy
    const additionalEntropy = crypto.getRandomValues(new Uint8Array(32));
    rawMixed.set(additionalEntropy, 32);

    // Ensure we have exactly 64 bytes
    if (rawMixed.length === SEED_LENGTH) {
        return rawMixed;
    } else if (rawMixed.length < SEED_LENGTH) {
        // Pad with additional random bytes if too short
        const paddedMixed = new Uint8Array(SEED_LENGTH);
        paddedMixed.set(rawMixed, 0);
        const additionalRandom = crypto.getRandomValues(new Uint8Array(SEED_LENGTH - rawMixed.length));
        paddedMixed.set(additionalRandom, rawMixed.length);
        return paddedMixed;
    } else {
        return rawMixed.slice(0, SEED_LENGTH);
    }
}

// Generate enhanced seed with optional user entropy
export async function generateEnhancedSeed(collectUserEntropy = false) {
    // Always start with crypto.getRandomValues()
    const baseSeed = generateBaseSeed();

    // Default behavior: use crypto.getRandomValues() only
    if (!collectUserEntropy) {
        return { seed: baseSeed, hasUserEntropy: false };
    }

    // Advanced entropy collection (Pro mode only when user requests it)
    try {
        // Collect user entropy
        const collector = new UserEntropyCollector();
        const userEntropy = await collector.startCollection();

        console.log(`Entropy collected: ${userEntropy.length} bytes`);

        // Mix with base seed
        const mixedSeed = mixEntropy(baseSeed, userEntropy);

        // The mixEntropy function should return exactly 64 bytes
        if (mixedSeed.length !== SEED_LENGTH) {
            console.warn(`Mixed seed length mismatch: ${mixedSeed.length}, expected ${SEED_LENGTH}`);
        }

        return {
            seed: mixedSeed,
            hasUserEntropy: userEntropy.length > 0
        };
    } catch (error) {
        // Fall back to base seed if user entropy collection fails
        console.warn('User entropy collection failed, using secure random seed:', error.message);
        console.log(`Fallback seed length: ${baseSeed.length} bytes (expected: ${SEED_LENGTH})`);
        return { seed: baseSeed, hasUserEntropy: false };
    }
}

// Validate seed format
export function validateSeed(seed) {
    if (!(seed instanceof Uint8Array)) {
        throw new Error('Seed must be Uint8Array');
    }
    if (seed.length !== SEED_LENGTH) {
        throw new Error(`Seed must be exactly ${SEED_LENGTH} bytes`);
    }
}

// Export constants and configuration for backward compatibility
export { SEED_LENGTH };
export { CONFIG };
export const MIN_ENTROPY_EVENTS = CONFIG.minEvents; // Backward compatibility
