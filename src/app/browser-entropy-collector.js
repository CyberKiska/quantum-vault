import { sha3_512 } from '@noble/hashes/sha3.js';
import { kmac256 } from '../core/crypto/kmac.js';

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
        this.collectionEpoch = 0;
        this.collectionTimeout = null;
        this.progressTimeout = null;
        this.queueTimeout = null;
        this.pendingCollection = null;
        this.disposed = false;
    }

    async startCollection() {
        if (typeof window === 'undefined' || typeof document === 'undefined') {
            throw new Error('Browser entropy collection requires DOM runtime');
        }
        if (this.isCollecting) {
            throw new Error('Entropy collection already in progress');
        }
        if (this.disposed) {
            throw new Error('Entropy collector has been disposed');
        }

        const epoch = ++this.collectionEpoch;
        return new Promise((resolve, reject) => {
            this.isCollecting = true;
            this.startTime = performance.now();
            this.lastEventTime = this.startTime;
            this.events = [];
            this.processingQueue = [];
            this.eventCount = 0;
            this.mouseInitialized = false;
            this.pendingCollection = { epoch, resolve, reject };

            this.setupEventListeners();

            this.collectionTimeout = setTimeout(() => {
                this.completeCollection(epoch);
            }, CONFIG.maxCollectionMs);

            const checkEntropy = () => {
                if (!this.isCollectionActive(epoch)) return;
                if (this.events.length >= CONFIG.minEvents) {
                    this.completeCollection(epoch);
                } else {
                    this.progressTimeout = setTimeout(checkEntropy, 100);
                }
            };

            this.progressTimeout = setTimeout(checkEntropy, 100);
        });
    }

    isCollectionActive(epoch) {
        return this.isCollecting
            && !this.disposed
            && this.collectionEpoch === epoch
            && this.pendingCollection?.epoch === epoch;
    }

    clearScheduledWork() {
        for (const timer of [this.collectionTimeout, this.progressTimeout, this.queueTimeout]) {
            if (timer !== null) clearTimeout(timer);
        }
        this.collectionTimeout = null;
        this.progressTimeout = null;
        this.queueTimeout = null;
    }

    completeCollection(epoch) {
        if (!this.isCollectionActive(epoch)) return;
        const pending = this.pendingCollection;
        let finalSeed = null;
        try {
            this.clearScheduledWork();
            this.processQueue(epoch);
            this.stopCollection();
            finalSeed = this.generateFinalSeed();
            this.pendingCollection = null;
            this.wipeSensitiveState();
            pending.resolve(finalSeed);
            finalSeed = null;
        } catch (error) {
            this.pendingCollection = null;
            this.stopCollection();
            this.wipeSensitiveState();
            pending.reject(error);
        } finally {
            if (finalSeed instanceof Uint8Array) finalSeed.fill(0);
        }
    }

    stopCollection() {
        this.isCollecting = false;
        this.clearScheduledWork();
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
        this.events = [];
        this.eventCount = 0;
        this.isProcessing = false;
    }

    dispose() {
        if (this.disposed) return;
        this.disposed = true;
        const pending = this.pendingCollection;
        this.pendingCollection = null;
        this.collectionEpoch += 1;
        this.stopCollection();
        this.wipeSensitiveState();
        if (pending) {
            const error = new Error('Entropy collection was cancelled');
            error.name = 'AbortError';
            pending.reject(error);
        }
    }

    processEventAsync(summary) {
        if (!this.isCollecting || this.disposed) {
            summary.fill(0);
            return;
        }
        this.processingQueue.push(summary);
        if (!this.isProcessing) {
            this.isProcessing = true;
            const epoch = this.collectionEpoch;
            this.queueTimeout = setTimeout(() => {
                this.queueTimeout = null;
                this.processQueue(epoch);
            }, 0);
        }
    }

    processQueue(epoch = this.collectionEpoch) {
        if (!this.isCollectionActive(epoch)) {
            for (const summary of this.processingQueue) summary.fill(0);
            this.processingQueue = [];
            this.isProcessing = false;
            return;
        }
        while (this.processingQueue.length > 0) {
            const summary = this.processingQueue.shift();
            this.processEventSummary(summary, epoch);
        }
        this.isProcessing = false;
    }

    processEventSummary(summary, epoch = this.collectionEpoch) {
        let periodicRandom = null;
        let periodicInput = null;
        let eventRandom = null;
        let eventInput = null;
        let digest = null;
        let stateInput = null;
        let nextState = null;
        try {
            if (!this.isCollectionActive(epoch)) return;
            this.eventCount += 1;

            if (this.eventCount % CONFIG.mixOsEveryNEvents === 0) {
                periodicRandom = crypto.getRandomValues(new Uint8Array(32));
                periodicInput = new Uint8Array(this.entropyState.length + periodicRandom.length);
                periodicInput.set(this.entropyState, 0);
                periodicInput.set(periodicRandom, this.entropyState.length);
                nextState = sha3_512(periodicInput);
                this.entropyState.fill(0);
                this.entropyState = nextState;
                nextState = null;
            }

            eventRandom = crypto.getRandomValues(new Uint8Array(16));
            eventInput = new Uint8Array(summary.length + eventRandom.length);
            eventInput.set(summary, 0);
            eventInput.set(eventRandom, summary.length);

            digest = sha3_512(eventInput);
            stateInput = new Uint8Array(this.entropyState.length + digest.length);
            stateInput.set(this.entropyState, 0);
            stateInput.set(digest, this.entropyState.length);
            nextState = sha3_512(stateInput);
            this.entropyState.fill(0);
            this.entropyState = nextState;
            nextState = null;
        } finally {
            for (const bytes of [summary, periodicRandom, periodicInput, eventRandom, eventInput, digest, stateInput, nextState]) {
                if (bytes instanceof Uint8Array) bytes.fill(0);
            }
        }
    }

    generateFinalSeed() {
        let finalOsRandom = null;
        let finalInput = null;
        let mixedState = null;
        let counter = null;
        let firstBlock = null;
        let secondBlock = null;
        let finalSeed = null;
        try {
            finalOsRandom = crypto.getRandomValues(new Uint8Array(32));
            finalInput = new Uint8Array(this.entropyState.length + finalOsRandom.length);
            finalInput.set(this.entropyState, 0);
            finalInput.set(finalOsRandom, this.entropyState.length);
            mixedState = sha3_512(finalInput);

            counter = new Uint8Array(4);
            firstBlock = kmac256(mixedState, counter, {
                customization: 'quantum-vault:final-seed:v2',
            });

            counter[0] = 1;
            secondBlock = kmac256(mixedState, counter, {
                customization: 'quantum-vault:final-seed:v2',
            });

            finalSeed = new Uint8Array(CONFIG.seedLength);
            finalSeed.set(firstBlock, 0);
            finalSeed.set(secondBlock, 32);
            const result = finalSeed;
            finalSeed = null;
            return result;
        } finally {
            for (const bytes of [finalOsRandom, finalInput, mixedState, counter, firstBlock, secondBlock, finalSeed]) {
                if (bytes instanceof Uint8Array) bytes.fill(0);
            }
        }
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
