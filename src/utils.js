// --- Utility Functions ---

// Convert bytes to hex string
export const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

// Normalize to Uint8Array
export function toUint8(x) {
    if (x instanceof Uint8Array) return x;
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
    throw new TypeError('Expected ArrayBuffer or Uint8Array');
}

// Shorten hash for display
export function shortenHash(hash) {
    const s = typeof hash === 'string' ? hash : String(hash || '');
    if (s.length < 12) return s;
    return `${s.slice(0, 6)}...${s.slice(-6)}`;
}

// Read File → Uint8Array
export async function readFileAsUint8Array(file) { 
    return new Uint8Array(await file.arrayBuffer()); 
}

// Download blob as file
export function download(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(a.href);
    a.remove();
}

// Enable/disable all buttons
export function setButtonsDisabled(disabled) {
    document.querySelectorAll('button').forEach(btn => { btn.disabled = disabled; });
}

// Format timestamp for logs
export function formatTimestamp() {
    return new Date().toLocaleTimeString();
}

// Filename-friendly timestamp
export function createFilenameTimestamp() {
    return new Date().toISOString().slice(0, 19).replace(/:/g, '-');
}

// Validate Reed–Solomon params
export function validateRsParams(n, k) {
    if (k < 2 || n <= k) return false;
    if ((n - k) % 2 !== 0) return false;
    if (n < 5) return false; // Unstable configurations
    return true;
}

// Shamir threshold from RS params
export function calculateShamirThreshold(n, k) {
    const m = n - k;
    return k + (m / 2);
}

// Constant-time comparison for Uint8Arrays (best-effort in JS; ref. CWE-208)
export function timingSafeEqual(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

// Hex string → Uint8Array
export function fromHex(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
        throw new Error('Invalid hex string');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}
