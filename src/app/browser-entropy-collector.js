import { sha3_512 } from '@noble/hashes/sha3.js';
import { kmac256 } from '@noble/hashes/sha3-addons.js';

const CONFIG = {
    minEvents: 100,
    mixOsEveryNEvents: 32,
    maxCollectionMs: 30000,
    directionBuckets: 8,
    maxTimeDeltaMs: 1000,
    seedLength: 64,
};

function summarizeMouse(dx, dy, dtMs, buttons) {
    const directionRadians = Math.atan2(dy, dx);
    const normalizedAngle = directionRadians + Math.PI;
    const bucket = Math.floor((normalizedAngle / (2 * Math.PI)) * CONFIG.directionBuckets) % CONFIG.directionBuckets;
    const speed = Math.min(255, Math.floor(Math.hypot(dx, dy)));
    const timeDelta = Math.min(CONFIG.maxTimeDeltaMs, Math.max(0, dtMs));

    const summary = new Uint8Array(6);
    summary[0] = 0x01;
    summary[1] = bucket & 0xff;
    summary[2] = speed & 0xff;
    summary[3] = timeDelta & 0xff;
    summary[4] = (timeDelta >> 8) & 0xff;
    summary[5] = buttons & 0xff;
    return summary;
}

function summarizeKeyboard(keyCode, location, dtMs, isRepeat) {
    const keyHash = (keyCode + location + (isRepeat ? 1 : 0)) & 0xff;
    const timeDelta = Math.min(CONFIG.maxTimeDeltaMs, Math.max(0, dtMs));

    const summary = new Uint8Array(5);
    summary[0] = 0x02;
    summary[1] = keyHash;
    summary[2] = timeDelta & 0xff;
    summary[3] = (timeDelta >> 8) & 0xff;
    summary[4] = location & 0xff;
    return summary;
}

function summarizeWindow(width, height, dtMs) {
    const widthBucket = Math.floor(width / 100) & 0xff;
    const heightBucket = Math.floor(height / 100) & 0xff;
    const timeDelta = Math.min(CONFIG.maxTimeDeltaMs, Math.max(0, dtMs));

    const summary = new Uint8Array(5);
    summary[0] = 0x03;
    summary[1] = widthBucket;
    summary[2] = heightBucket;
    summary[3] = timeDelta & 0xff;
    summary[4] = (timeDelta >> 8) & 0xff;
    return summary;
}

export class BrowserEntropyCollector {
    constructor() {
        this.events = [];
        this.isCollecting = false;
        this.startTime = 0;
        this.listeners = [];
        this.entropyBuffer = new Uint8Array(0);
        this.entropyState = crypto.getRandomValues(new Uint8Array(64));
        this.lastEventTime = 0;
        this.eventCount = 0;
        this.processingQueue = [];
        this.isProcessing = false;
        this.lastMouseX = 0;
        this.lastMouseY = 0;
        this.mouseInitialized = false;
    }

    async startCollection() {
        if (typeof window === 'undefined' || typeof document === 'undefined') {
            throw new Error('Browser entropy collection requires DOM runtime');
        }
        if (this.isCollecting) {
            throw new Error('Entropy collection already in progress');
        }

        return new Promise((resolve) => {
            this.isCollecting = true;
            this.startTime = performance.now();
            this.lastEventTime = this.startTime;
            this.events = [];
            this.processingQueue = [];

            this.setupEventListeners();

            const timeout = setTimeout(() => {
                this.stopCollection();
                resolve(this.generateFinalSeed());
            }, CONFIG.maxCollectionMs);

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

        const keyHandler = (e) => {
            if (!this.isCollecting) return;

            const now = performance.now();
            const timeDelta = now - this.lastEventTime;
            const summary = summarizeKeyboard(e.keyCode, e.location, timeDelta, e.repeat);
            this.lastEventTime = now;

            this.processEventAsync(summary);
            this.events.push({ type: 'key', timestamp: now });
        };

        const windowHandler = () => {
            if (!this.isCollecting) return;

            const now = performance.now();
            const timeDelta = now - this.lastEventTime;
            const summary = summarizeWindow(window.innerWidth, window.innerHeight, timeDelta);
            this.lastEventTime = now;

            this.processEventAsync(summary);
            this.events.push({ type: 'window', timestamp: now });
        };

        const touchHandler = (e) => {
            if (!this.isCollecting) return;

            const now = performance.now();
            const timeDelta = now - this.lastEventTime;
            const touch = e.touches[0];
            if (!touch) return;

            const xBucket = Math.floor(touch.clientX / 50) & 0xff;
            const yBucket = Math.floor(touch.clientY / 50) & 0xff;
            const summary = new Uint8Array(6);
            summary[0] = 0x04;
            summary[1] = xBucket;
            summary[2] = yBucket;
            summary[3] = Math.min(255, Math.floor(touch.force * 255)) & 0xff;
            summary[4] = timeDelta & 0xff;
            summary[5] = (timeDelta >> 8) & 0xff;

            this.lastEventTime = now;
            this.processEventAsync(summary);
            this.events.push({ type: 'touch', timestamp: now });
        };

        document.addEventListener('mousemove', mouseHandler, { passive: true });
        document.addEventListener('keydown', keyHandler, { passive: true });
        document.addEventListener('keyup', keyHandler, { passive: true });
        window.addEventListener('resize', windowHandler, { passive: true });
        window.addEventListener('focus', windowHandler, { passive: true });
        window.addEventListener('blur', windowHandler, { passive: true });
        document.addEventListener('touchmove', touchHandler, { passive: true });

        this.listeners = [
            { element: document, event: 'mousemove', handler: mouseHandler },
            { element: document, event: 'keydown', handler: keyHandler },
            { element: document, event: 'keyup', handler: keyHandler },
            { element: window, event: 'resize', handler: windowHandler },
            { element: window, event: 'focus', handler: windowHandler },
            { element: window, event: 'blur', handler: windowHandler },
            { element: document, event: 'touchmove', handler: touchHandler },
        ];
    }

    removeEventListeners() {
        this.listeners.forEach(({ element, event, handler }) => {
            element.removeEventListener(event, handler);
        });
        this.listeners = [];
    }

    wipeSensitiveState() {
        if (this.entropyBuffer instanceof Uint8Array) {
            this.entropyBuffer.fill(0);
        }
        if (this.entropyState instanceof Uint8Array) {
            this.entropyState.fill(0);
        }
        for (const summary of this.processingQueue) {
            if (summary instanceof Uint8Array) {
                summary.fill(0);
            }
        }
        this.processingQueue = [];
    }

    dispose() {
        this.stopCollection();
        this.wipeSensitiveState();
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
            if (this.processingQueue.length > 0) {
                await new Promise((resolve) => setTimeout(resolve, 0));
            }
        }
        this.isProcessing = false;
    }

    async processEventSummary(summary) {
        this.eventCount++;

        if (this.eventCount % CONFIG.mixOsEveryNEvents === 0) {
            const osRandom = crypto.getRandomValues(new Uint8Array(32));
            const combinedInput = new Uint8Array(this.entropyState.length + osRandom.length);
            combinedInput.set(this.entropyState, 0);
            combinedInput.set(osRandom, this.entropyState.length);
            this.entropyState = sha3_512(combinedInput);
        }

        const osRandom = crypto.getRandomValues(new Uint8Array(16));
        const combinedInput = new Uint8Array(summary.length + osRandom.length);
        combinedInput.set(summary, 0);
        combinedInput.set(osRandom, summary.length);

        const digest = sha3_512(combinedInput);
        const stateInput = new Uint8Array(this.entropyState.length + digest.length);
        stateInput.set(this.entropyState, 0);
        stateInput.set(digest, this.entropyState.length);
        this.entropyState = sha3_512(stateInput);
        summary.fill(0);
    }

    generateFinalSeed() {
        if (this.processingQueue.length > 0) {
            this.processingQueue.forEach((summary) => {
                this.processEventSummary(summary);
            });
            this.processingQueue = [];
        }

        const finalOsRandom = crypto.getRandomValues(new Uint8Array(32));
        const finalInput = new Uint8Array(this.entropyState.length + finalOsRandom.length);
        finalInput.set(this.entropyState, 0);
        finalInput.set(finalOsRandom, this.entropyState.length);
        this.entropyState = sha3_512(finalInput);

        const counter = new Uint8Array(4);
        counter[0] = 0;
        const firstBlock = kmac256(this.entropyState, counter, undefined, {
            customization: 'quantum-vault:final-seed:v1',
        });

        counter[0] = 1;
        const secondBlock = kmac256(this.entropyState, counter, undefined, {
            customization: 'quantum-vault:final-seed:v1',
        });

        const finalSeed = new Uint8Array(CONFIG.seedLength);
        finalSeed.set(firstBlock, 0);
        finalSeed.set(secondBlock, 32);

        const stateUpdate = new Uint8Array(this.entropyState.length + finalSeed.length);
        stateUpdate.set(this.entropyState, 0);
        stateUpdate.set(finalSeed, this.entropyState.length);
        this.entropyState = sha3_512(stateUpdate);
        return finalSeed;
    }

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
            isCollecting: this.isCollecting,
        };
    }

    estimateEntropyBits() {
        if (this.events.length === 0) return 0;

        const eventTypes = { mouse: 0, key: 0, window: 0, touch: 0 };
        this.events.forEach((event) => {
            if (event.type in eventTypes) {
                eventTypes[event.type]++;
            }
        });

        const totalEvents = this.events.length;
        let typeEntropy = 0;
        Object.values(eventTypes).forEach((count) => {
            if (count > 0) {
                const probability = count / totalEvents;
                typeEntropy -= probability * Math.log2(probability);
            }
        });

        const timingVariability = this.estimateTimingEntropy();
        const totalEntropy = (typeEntropy + timingVariability) * this.events.length * 0.1;
        return Math.min(totalEntropy, 512);
    }

    estimateTimingEntropy() {
        if (this.events.length < 2) return 0;

        const intervals = [];
        for (let i = 1; i < this.events.length; i += 1) {
            intervals.push(this.events[i].timestamp - this.events[i - 1].timestamp);
        }

        const bucketSize = 50;
        const buckets = new Map();
        intervals.forEach((interval) => {
            const bucket = Math.floor(interval / bucketSize);
            buckets.set(bucket, (buckets.get(bucket) || 0) + 1);
        });

        let timingEntropy = 0;
        const totalIntervals = intervals.length;
        buckets.forEach((count) => {
            const probability = count / totalIntervals;
            timingEntropy -= probability * Math.log2(probability);
        });

        return timingEntropy;
    }
}

