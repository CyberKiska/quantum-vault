// --- UI Utility Functions ---

export { validateRsParams, calculateShamirThreshold } from './core/crypto/splitting/rs-params.js';

export function shortenHash(hash) {
    const s = typeof hash === 'string' ? hash : String(hash || '');
    if (s.length < 12) return s;
    return `${s.slice(0, 6)}...${s.slice(-6)}`;
}

export async function readFileAsUint8Array(file) { 
    return new Uint8Array(await file.arrayBuffer()); 
}

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

export function setButtonsDisabled(disabled) {
    document.querySelectorAll('button').forEach(btn => { btn.disabled = disabled; });
}

export function formatTimestamp() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function createFilenameTimestamp() {
    return new Date().toISOString().slice(0, 19).replace(/:/g, '-');
}

export function formatFileSize(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
