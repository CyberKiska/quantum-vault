// --- Logging Utilities for Consistent UI ---

import { shortenHash, formatTimestamp } from '../../../utils.js';
import { showToast } from './toast.js';

function rememberLastLogSignature(logEl, signature) {
    if (!logEl) return;
    logEl.dataset.lastLogSignature = signature;
}

// Log message to UI console
export function log(msg, options = {}) {
    const { elementId = 'log', isLiteMode = true } = options;
    const logEl = document.getElementById(elementId);
    if (!logEl) return;
    
    const line = document.createElement('span');
    line.className = 'log-info';
    line.textContent = `[${formatTimestamp()}] ${msg}`;
    logEl.appendChild(line);
    logEl.appendChild(document.createTextNode('\n'));
    logEl.scrollTop = logEl.scrollHeight;
    rememberLastLogSignature(logEl, `info:${String(msg)}`);
}

// Log success message to UI console (green)
export function logSuccess(msg, options = {}) {
    const { elementId = 'log' } = options;
    const logEl = document.getElementById(elementId);
    if (!logEl) return;

    const span = document.createElement('span');
    span.className = 'success';
    span.textContent = `[${formatTimestamp()}] ${msg}`;
    logEl.appendChild(span);
    logEl.appendChild(document.createTextNode('\n'));
    logEl.scrollTop = logEl.scrollHeight;
    rememberLastLogSignature(logEl, `success:${String(msg)}`);
}

// Log error message to UI console AND trigger a toast
export function logError(err, options = {}) {
    const { elementId = 'log', isLiteMode = true, skipToast = false } = options;
    
    const text = (err && err.message) ? err.message : (typeof err === 'string' ? err : String(err));
    
    // Show toast for errors
    if (!skipToast) {
        showToast(text, 'error');
    }

    const logEl = document.getElementById(elementId);
    if (!logEl) return;
    const signature = `error:${text}`;
    if (logEl.dataset.lastLogSignature === signature) {
        return;
    }

    const errorSpan = document.createElement('span');
    errorSpan.className = 'error';
    errorSpan.textContent = `[${formatTimestamp()}] ${text}`;
    logEl.appendChild(errorSpan);
    logEl.appendChild(document.createTextNode('\n'));
    logEl.scrollTop = logEl.scrollHeight;
    rememberLastLogSignature(logEl, signature);
}

// Log warning message to UI console
export function logWarning(msg, options = {}) {
    const { elementId = 'log' } = options;
    
    const logEl = document.getElementById(elementId);
    if (!logEl) return;

    const warningSpan = document.createElement('span');
    warningSpan.className = 'warning';
    warningSpan.textContent = `[${formatTimestamp()}] ${String(msg)}`;
    logEl.appendChild(warningSpan);
    logEl.appendChild(document.createTextNode('\n'));
    logEl.scrollTop = logEl.scrollHeight;
    rememberLastLogSignature(logEl, `warning:${String(msg)}`);
}

function shortenSignerReference(value) {
    const text = typeof value === 'string' ? value.trim() : '';
    if (!text) return '';
    if (/^[0-9a-f]{24,}$/i.test(text)) return shortenHash(text);
    if (/^G[A-Z2-7]{24,}$/i.test(text)) return `${text.slice(0, 6)}...${text.slice(-6)}`;
    return text;
}

function looksLikeAttachmentId(value) {
    const text = typeof value === 'string' ? value.trim() : '';
    return /^(sig|key|ots)-[0-9a-f]{8,}$/i.test(text);
}

export function formatSignatureResultSummary(result) {
    const suite = result?.suiteDisplay || result?.suite || result?.format || result?.type || 'signature';
    const signer = shortenSignerReference(
        result?.signerLabel ||
        result?.signer ||
        result?.signerFingerprintHex ||
        ''
    );
    const detailParts = [suite];
    if (signer) detailParts.push(`signer ${signer}`);
    if (result?.bundlePinned) detailParts.push('bundle-pinned');
    if (result?.userPinned) detailParts.push('user-pinned');
    if (!result?.bundlePinned && !result?.userPinned && result?.signerPinned) detailParts.push('pinned');
    const detail = detailParts.join(', ');

    const referenceName = typeof result?.name === 'string' ? result.name.trim() : '';
    if (!referenceName || looksLikeAttachmentId(referenceName)) {
        return detail;
    }
    return `${referenceName} (${detail})`;
}

export function formatAuthenticityStatusMessage(status = {}) {
    const signatureVerified = status?.archiveApprovalSignatureVerified ?? status?.signatureVerified;
    if (signatureVerified !== true) {
        return '';
    }
    const label = Object.prototype.hasOwnProperty.call(status, 'archiveApprovalSignatureVerified')
        ? 'Archive-approval signatures verified'
        : 'Signatures verified';
    const details = [];
    if (status?.strongPqSignatureVerified === true) {
        details.push('strong PQ present');
    }
    if (status?.bundlePinned === true) {
        details.push('bundle pin active');
    }
    if (status?.userPinned === true) {
        details.push('user pin matched');
    }
    if (status?.signerPinned === true && details.length === 0) {
        details.push('signer pin active');
    }
    return details.length > 0
        ? `${label} (${details.join(', ')}).`
        : `${label}.`;
}

// Log hash with appropriate formatting based on mode
export function logHash(label, hash, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    const displayHash = isLiteMode ? shortenHash(hash) : hash;
    log(`${label}: ${displayHash}`, { elementId, isLiteMode });
}

// Log key generation event
export function logKeyGeneration(privateKeyHash, publicKeyHash, seedInfo, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    
    if (isLiteMode) {
        log('New ML-KEM keypair generated in memory.', { elementId, isLiteMode });
        logHash('Secret Key', privateKeyHash, { isLiteMode, elementId });
        logHash('Public Key', publicKeyHash, { isLiteMode, elementId });
    } else {
        log('New ML-KEM keypair generated in memory.', { elementId, isLiteMode });
        log(`Entropy source: ${seedInfo.source}`, { elementId, isLiteMode });
        if (seedInfo.hasUserEntropy) {
            log('User entropy successfully collected and mixed.', { elementId, isLiteMode });
        }
        logHash('Secret Key Hash', privateKeyHash, { isLiteMode, elementId });
        logHash('Public Key Hash', publicKeyHash, { isLiteMode, elementId });
    }
}

// Log file encryption progress
export function logFileEncryption(filename, fileSize, fileHash, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    
    if (isLiteMode) {
        log(`Encrypting: ${filename} (${fileSize} bytes)`, { elementId, isLiteMode });
        logHash(`Encrypted container hash`, fileHash, { isLiteMode, elementId });
    } else {
        log(`Encrypting file: ${filename} (${fileSize.toLocaleString()} bytes)`, { elementId, isLiteMode });
        logHash('Output SHA3-512', fileHash, { isLiteMode, elementId });
        logSuccess('File encryption completed.', { elementId, isLiteMode });
    }
}

// Log shard creation progress
export function logShardCreation(shardCount, params, filename, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    
    if (isLiteMode) {
        log(`Creating shards: n=${params.n}, k=${params.k}, m=${params.m}, t=${params.t}`, { elementId, isLiteMode });
        log(`Created ${shardCount} shards for ${filename}`, { elementId, isLiteMode });
    } else {
        log(`Creating shards: n=${params.n}, k=${params.k}, m=${params.m}, t=${params.t}`, { elementId, isLiteMode });
        logSuccess(`Created ${shardCount} shards for ${filename}`, { elementId, isLiteMode });
    }
}

// Log restoration progress
export function logRestoration(shardCount, containerId, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;

    if (isLiteMode) {
        log(`Restoring container from ${shardCount} shard files...`, { elementId, isLiteMode });
    } else {
        log(`Restoration started. Input shards: ${shardCount}`, { elementId, isLiteMode });
        logHash('Container ID', containerId, { isLiteMode, elementId });
    }
}

// Determine if a filename is meaningful (not a hash)
export function isMeaningfulFilename(filename) {
    if (!filename.includes('.')) {
        return !/^[a-f0-9]+$/i.test(filename);
    }
    const namePart = filename.split('.')[0];
    if (/^[a-f0-9]+$/i.test(namePart)) {
        return false;
    }
    return /[a-zA-Z]/.test(namePart) || /\s/.test(namePart) || /[-_]/.test(namePart);
}

// Log successful restoration
export function logRestorationSuccess(filename, fileSize, encryptionTime, integrityOk, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;

    if (isLiteMode) {
        if (integrityOk) {
            const displayName = isMeaningfulFilename(filename) ? filename :
                (filename.includes('.') ?
                    `${shortenHash(filename.split('.')[0])}.${filename.split('.').pop()}` : filename);
            logSuccess(`Restored: ${displayName} (${fileSize} bytes) - Encrypted on: ${encryptionTime}`, { elementId, isLiteMode });
        } else {
            logError('Hashes do NOT match. File integrity verification failed.', { elementId, isLiteMode, skipToast: true });
        }
    } else {
        if (integrityOk) {
            logSuccess('Container restored successfully.', { elementId, isLiteMode });
            log(`Restored file: ${filename} (${fileSize.toLocaleString()} bytes)`, { elementId, isLiteMode });
            log(`Original encryption time: ${encryptionTime}`, { elementId, isLiteMode });
            logSuccess('Hashes match. File integrity verified.', { elementId, isLiteMode });
        } else {
            logError('Hashes do NOT match. File integrity verification failed.', { elementId, isLiteMode, skipToast: true });
        }
    }
}

// Log entropy collection progress (Pro mode only)
export function logEntropyProgress(progress, options = {}) {
    const { elementId = 'log' } = options;
    log(`Entropy collection: ${progress.collected}/${progress.required} events (${progress.percentage}%)`, { elementId, isLiteMode: false });
}

// Clear log display
export function clearLog(elementId = 'log') {
    const logEl = document.getElementById(elementId);
    if (logEl) {
        logEl.innerHTML = '';
        delete logEl.dataset.lastLogSignature;
    }
}

// Create structured log entry for complex operations
export function logOperation(operation, details, status, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    
    switch (status) {
        case 'started':
            log(`Started: ${operation}`, { elementId, isLiteMode });
            break;
        case 'progress':
            log(`Progress: ${operation} - ${details.message}`, { elementId, isLiteMode });
            break;
        case 'completed':
            logSuccess(`${operation} completed.`, { elementId, isLiteMode });
            break;
        case 'failed':
            logError(`${operation} failed: ${details.error}`, { elementId, isLiteMode });
            break;
        default:
            log(`${operation}: ${details.message || ''}`, { elementId, isLiteMode });
    }
}
