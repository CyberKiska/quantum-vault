// --- Logging Utilities for Consistent UI ---

import { shortenHash, formatTimestamp } from '../../../utils.js';

// Log message to UI console
export function log(msg, options = {}) {
    const { elementId = 'log', isLiteMode = true } = options;
    const logEl = document.getElementById(elementId);
    if (!logEl) return;
    
    const line = document.createElement('span');
    line.textContent = `[${formatTimestamp()}] ${msg}`;
    logEl.appendChild(line);
    logEl.appendChild(document.createTextNode('\n'));
    logEl.scrollTop = logEl.scrollHeight;
}

// Log error message to UI console
export function logError(err, options = {}) {
    const { elementId = 'log', isLiteMode = true } = options;
    const logEl = document.getElementById(elementId);
    if (!logEl) return;
    
    const text = (err && err.message) ? err.message : (typeof err === 'string' ? err : String(err));
    const errorSpan = document.createElement('span');
    errorSpan.className = 'error';
    errorSpan.textContent = `[${formatTimestamp()}] ERROR: ${text}`;
    logEl.appendChild(errorSpan);
    logEl.appendChild(document.createTextNode('\n'));
    logEl.scrollTop = logEl.scrollHeight;
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
        log('Lite Mode: ML-KEM keys generated automatically', { elementId, isLiteMode });
        logHash('Private Key', privateKeyHash, { isLiteMode, elementId });
        logHash('Public Key', publicKeyHash, { isLiteMode, elementId });
    } else {
        log('Pro Mode: ML-KEM-1024 key pair generated', { elementId, isLiteMode });
        log(`Entropy source: ${seedInfo.source}`, { elementId, isLiteMode });
        if (seedInfo.hasUserEntropy) {
            log('✅ User entropy successfully collected and mixed', { elementId, isLiteMode });
        }
        logHash('Private Key Hash', privateKeyHash, { isLiteMode, elementId });
        logHash('Public Key Hash', publicKeyHash, { isLiteMode, elementId });
    }
}

// Log file encryption progress
export function logFileEncryption(filename, fileSize, fileHash, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    
    if (isLiteMode) {
        log(`⏳ Processing: ${filename} (${fileSize} bytes)`, { elementId, isLiteMode });
        logHash(`✅ Encrypted: ${filename} (hash)`, fileHash, { isLiteMode, elementId });
    } else {
        log(`⏳ Encrypting file: ${filename}`, { elementId, isLiteMode });
        log(`File size: ${fileSize.toLocaleString()} bytes`, { elementId, isLiteMode });
        logHash('File hash (SHA3-512)', fileHash, { isLiteMode, elementId });
        log('✅ File encryption completed', { elementId, isLiteMode });
    }
}

// Log shard creation progress
export function logShardCreation(shardCount, params, filename, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    
    if (isLiteMode) {
        log(`Creating shards with n=${params.n}, k=${params.k}, m=${params.m}, t=${params.t}`, { elementId, isLiteMode });
        log(`Effective threshold: ${params.t} shards (${Math.round((params.t / params.n) * 100)}%)`, { elementId, isLiteMode });
        log(`✅ Created ${shardCount} shards for ${filename}`, { elementId, isLiteMode });
    } else {
        log(`Reed-Solomon Configuration:`, { elementId, isLiteMode });
        log(`  Total shards (n): ${params.n}`, { elementId, isLiteMode });
        log(`  Data shards (k): ${params.k}`, { elementId, isLiteMode });
        log(`  Parity shards (m): ${params.m}`, { elementId, isLiteMode });
        log(`  Shamir threshold (t): ${params.t}`, { elementId, isLiteMode });
        log(`Shards created: ${shardCount} for file "${filename}"`, { elementId, isLiteMode });
        log('✅ Shard creation completed successfully', { elementId, isLiteMode });
    }
}

// Log restoration progress
export function logRestoration(shardCount, containerId, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;

    if (isLiteMode) {
        log(`Restoring ${shortenHash(containerId)} container from ${shardCount} shard files...`, { elementId, isLiteMode });
    } else {
        log(`Restoration Process Started`, { elementId, isLiteMode });
        log(`Input shards: ${shardCount}`, { elementId, isLiteMode });
        logHash('Container ID', containerId, { isLiteMode, elementId });
    }
}

// Determine if a filename is meaningful (not a hash)
export function isMeaningfulFilename(filename) {
    // If no extension, check if it's a hash-like string (hex characters only)
    if (!filename.includes('.')) {
        return !/^[a-f0-9]+$/i.test(filename);
    }

    const namePart = filename.split('.')[0];

    // Check if name part looks like a hash (hex characters only)
    if (/^[a-f0-9]+$/i.test(namePart)) {
        return false;
    }

    // Check for common meaningful patterns
    // Contains letters, spaces, or common file naming patterns
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
            log(`✅ Restoration complete - files have been decrypted and restored. Original file: ${displayName} (${fileSize} bytes) - Encrypted on: ${encryptionTime}`, { elementId, isLiteMode });
        } else {
            logError('⚠️ File integrity check failed - hashes do not match', { elementId, isLiteMode });
        }
    } else {
        if (integrityOk) {
            log('✅ Container restoration completed successfully', { elementId, isLiteMode });
            log(`Restored file: ${filename}`, { elementId, isLiteMode });
            log(`File size: ${fileSize.toLocaleString()} bytes`, { elementId, isLiteMode });
            log(`Original encryption time: ${encryptionTime}`, { elementId, isLiteMode });
            log('✅ File integrity verification passed', { elementId, isLiteMode });
        } else {
            logError('❌ File integrity verification failed', { elementId, isLiteMode });
            log('The restored file may be corrupted or tampered with', { elementId, isLiteMode });
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
    }
}

// Create structured log entry for complex operations
export function logOperation(operation, details, status, options = {}) {
    const { isLiteMode = true, elementId = 'log' } = options;
    
    switch (status) {
        case 'started':
            log(`🚀 ${operation} started`, { elementId, isLiteMode });
            break;
        case 'progress':
            log(`⏳ ${operation}: ${details.message}`, { elementId, isLiteMode });
            break;
        case 'completed':
            log(`✅ ${operation} completed successfully`, { elementId, isLiteMode });
            break;
        case 'failed':
            logError(`❌ ${operation} failed: ${details.error}`, { elementId, isLiteMode });
            break;
        default:
            log(`${operation}: ${details.message || ''}`, { elementId, isLiteMode });
    }
}
