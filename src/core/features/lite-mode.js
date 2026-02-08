// --- Lite Mode - Simplified Interface ---
// Lite mode is a thin UI wrapper over the same cryptographic operations as Pro mode

import { encryptFile, decryptFile, generateKeyPair, hashBytes } from '../crypto/index.js';
import { buildQcontShards } from '../crypto/qcont/build.js';
import { parseShard, restoreFromShards } from '../crypto/qcont/restore.js';
import { validateRsParams, calculateShamirThreshold, readFileAsUint8Array, download, setButtonsDisabled, createFilenameTimestamp } from '../../utils.js';
import { log, logError, logKeyGeneration, logFileEncryption, logShardCreation, logRestoration, logRestorationSuccess } from './ui/logging.js';

// Global state for Lite mode
let liteKeys = null;
let isLiteMode = true; // Default to Lite mode
let originalFileNames = new Map(); // Track original file names for restoration

// Compute RS/SSS params from desired threshold percent
function calculateParametersFromThreshold(n, thresholdPercent) {
    // Validate inputs first
    if (n < 5) {
        return { error: 'Total shards must be at least 5 (configurations with n≤4 are unstable)' };
    }
    
    if (!Number.isFinite(thresholdPercent)) {
        return { error: 'Invalid threshold percent' };
    }

    // Target threshold as number of shards (rounded up for safety)
    const targetT = Math.ceil((thresholdPercent / 100) * n);

    // Search all valid k to find the closest achievable threshold
    let best = null;
    for (let k = 2; k < n; k++) {
        if (!validateRsParams(n, k)) continue;
        const m = n - k;
        const t = calculateShamirThreshold(n, k);
        if (!Number.isInteger(t)) continue;
        const actualThresholdPercent = Math.round((t / n) * 100);
        const diff = Math.abs(t - targetT);
        if (!best || diff < best.diff || (diff === best.diff && t > best.t)) {
            best = { n, k, m, t, actualThresholdPercent, diff };
        }
    }

    if (!best) {
        return { error: 'Cannot find valid configuration - try adjusting total shards or threshold' };
    }

    return {
        n: best.n,
        k: best.k,
        m: best.m,
        t: best.t,
        actualThresholdPercent: best.actualThresholdPercent
    };
}

// Update threshold display
function updateThresholdDisplay() {
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    const thresholdText = document.getElementById('thresholdText');
    const validationDiv = document.getElementById('configValidation');
    
    if (!nInput || !thresholdInput || !thresholdText) return;
    
    const n = parseInt(nInput.value, 10);
    const thresholdPercent = parseInt(thresholdInput.value, 10);
    
    // Clear previous validation
    if (validationDiv) {
        validationDiv.style.display = 'none';
        validationDiv.className = 'validation-message';
    }
    
    if (isNaN(n) || isNaN(thresholdPercent) || n < 5) {
        thresholdText.textContent = 'Invalid parameters';
        if (validationDiv && n < 5 && n > 0) {
            validationDiv.textContent = 'Total shards must be at least 5 (configurations with n≤4 are unstable)';
            validationDiv.style.display = 'block';
        }
        updateCreateShardsButton();
        return;
    }
    
    const params = calculateParametersFromThreshold(n, thresholdPercent);
    
    if (params.error) {
        thresholdText.textContent = 'Configuration Error';
        if (validationDiv) {
            validationDiv.textContent = params.error;
            validationDiv.style.display = 'block';
        }
        updateCreateShardsButton();
        return;
    }
    
    thresholdText.textContent = `≥${params.t} shards required for recovery (${params.actualThresholdPercent}%)`;
    
    // Show success if configuration is good
    if (validationDiv && params.actualThresholdPercent !== thresholdPercent) {
        validationDiv.className = 'validation-message warning';
        validationDiv.textContent = `Configuration adjusted: actual threshold is ${params.actualThresholdPercent}% (${params.t} shards). Using n=${params.n}, k=${params.k}, m=${params.m} (can lose up to ${params.m / 2}).`;
        validationDiv.style.display = 'block';
    } else if (validationDiv) {
        validationDiv.className = 'validation-message success';
        validationDiv.textContent = `✓ Valid configuration: n=${params.n}, k=${params.k}, m=${params.m}, t=${params.t} (can lose up to ${params.m / 2}).`;
        validationDiv.style.display = 'block';
    }
    
    updateCreateShardsButton();
}

// Generate keys automatically for Lite mode
async function generateLiteKeys() {
    try {
        const keyStatus = document.getElementById('keyStatus');
        const statusText = keyStatus?.querySelector('.status-text');
        const statusIcon = keyStatus?.querySelector('.status-icon');
        
        if (statusText) statusText.textContent = 'Generating keys...';
        if (statusIcon) statusIcon.textContent = '🔄';
        
        // Generate keys with default entropy (no user collection in Lite mode)
        const keyPair = await generateKeyPair({ collectUserEntropy: false });
        liteKeys = keyPair;
        
        const skHash = await hashBytes(liteKeys.secretKey);
        const pkHash = await hashBytes(liteKeys.publicKey);
        
        // Log with Lite mode formatting
        logKeyGeneration(skHash, pkHash, keyPair.seedInfo, { isLiteMode: true });
        
        if (statusText) statusText.textContent = 'Keys ready ✓';
        if (statusIcon) statusIcon.textContent = '🔑';
        
        // Enable file input once keys are ready
        const liteFilesInput = document.getElementById('liteFilesInput');
        if (liteFilesInput) liteFilesInput.disabled = false;
        
        // Show download keys button
        const downloadBtn = document.getElementById('liteDownloadKeysBtn');
        if (downloadBtn) downloadBtn.style.display = 'inline-block';
        
        updateCreateShardsButton();
        
    } catch (error) {
        logError(`Failed to generate keys: ${error.message}`, { isLiteMode: true });
        const statusText = document.getElementById('keyStatus')?.querySelector('.status-text');
        const statusIcon = document.getElementById('keyStatus')?.querySelector('.status-icon');
        if (statusText) statusText.textContent = 'Key generation failed ✗';
        if (statusIcon) statusIcon.textContent = '❌';
    }
}

// Update create shards button state
function updateCreateShardsButton() {
    const btn = document.getElementById('liteCreateShardsBtn');
    const filesInput = document.getElementById('liteFilesInput');
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    
    if (!btn || !filesInput) return;
    
    const hasKeys = liteKeys !== null;
    const hasFiles = filesInput.files && filesInput.files.length > 0;
    
    // Check if configuration is valid
    let validConfig = false;
    if (nInput && thresholdInput) {
        const n = parseInt(nInput.value, 10);
        const thresholdPercent = parseInt(thresholdInput.value, 10);
        if (!isNaN(n) && !isNaN(thresholdPercent) && n >= 5) {
            const params = calculateParametersFromThreshold(n, thresholdPercent);
            validConfig = !params.error;
        }
    }
    
    btn.disabled = !hasKeys || !hasFiles || !validConfig;
}

// Download keys backup
function downloadLiteKeys() {
    if (!liteKeys) {
        logError('No keys available to download', { isLiteMode: true });
        return;
    }
    
    const timestamp = createFilenameTimestamp();
    download(new Blob([liteKeys.secretKey]), `quantum-vault-${timestamp}-secretKey.qkey`);
    download(new Blob([liteKeys.publicKey]), `quantum-vault-${timestamp}-publicKey.qkey`);
    
    log('✅ Backup keys downloaded', { isLiteMode: true });
}

// Create shards workflow
async function createLiteShards() {
    const filesInput = document.getElementById('liteFilesInput');
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    
    if (!filesInput?.files?.length) {
        logError('Please select files to encrypt', { isLiteMode: true });
        return;
    }
    
    if (!liteKeys) {
        logError('Keys not ready', { isLiteMode: true });
        return;
    }
    
    const n = parseInt(nInput.value, 10);
    const thresholdPercent = parseInt(thresholdInput.value, 10);
    
    if (isNaN(n) || isNaN(thresholdPercent)) {
        logError('Invalid parameters', { isLiteMode: true });
        return;
    }
    
    setButtonsDisabled(true);
    
    try {
        const params = calculateParametersFromThreshold(n, thresholdPercent);
        
        for (const file of filesInput.files) {
            // 1. Encrypt file
            const fileBytes = await readFileAsUint8Array(file);
            const encBlob = await encryptFile(fileBytes, liteKeys.publicKey, file.name);
            const encBytes = await readFileAsUint8Array(encBlob);
            
            // Store original filename for later restoration
            const encHash = await hashBytes(encBytes);
            originalFileNames.set(encHash, file.name);
            
            // Log encryption
            logFileEncryption(file.name, file.size, encHash, { isLiteMode: true });
            
            // 2. Create shards from encrypted container + private key
            const qconts = await buildQcontShards(encBytes, liteKeys.secretKey, {
                n: params.n,
                k: params.k
            });
            
            // 3. Download shards
            const baseName = file.name.replace(/\.[^/.]+$/, ""); // Remove extension
            qconts.forEach(({ blob, index }) => {
                const shardName = `${baseName}.part${index + 1}-of-${qconts.length}.qcont`;
                download(blob, shardName);
            });
            
            // Log shard creation
            logShardCreation(qconts.length, params, file.name, { isLiteMode: true });
        }
        
        log('🛡️ All files encrypted and split into shards', { isLiteMode: true });
        log('Distribute shards across different storage locations for security', { isLiteMode: true });
        
    } catch (error) {
        logError(`Failed to create shards: ${error.message}`, { isLiteMode: true });
    } finally {
        setButtonsDisabled(false);
    }
}

// Restore from shards (simplified) - uses shared core logic from qcont/restore.js
async function restoreLiteShards() {
    const shardsInput = document.getElementById('liteShardsInput');
    
    if (!shardsInput?.files?.length) {
        logError('Please select shard files to restore', { isLiteMode: true });
        return;
    }
    
    if (shardsInput.files.length < 2) {
        logError('Please select at least 2 shard files', { isLiteMode: true });
        return;
    }
    
    setButtonsDisabled(true);
    
    try {
        // Parse shards using shared function
        const shardBytesArr = await Promise.all([...shardsInput.files].map(readFileAsUint8Array));
        const shards = shardBytesArr.map(parseShard);
        
        // Log restoration start
        const containerId = shards[0]?.metaJSON?.containerId;
        logRestoration(shardsInput.files.length, containerId, { isLiteMode: true });
        
        // Restore using shared core logic
        const result = await restoreFromShards(shards, {
            onLog: (msg) => log(msg, { isLiteMode: true }),
            onError: (msg) => logError(msg, { isLiteMode: true })
        });
        
        const { qencBytes, privKey, containerHash, qencOk, qkeyOk } = result;
        
        if (!qencOk || !qkeyOk) {
            logError('Hash verification failed for container', { isLiteMode: true });
            return;
        }
        
        // Lite mode extra step: decrypt the container to get the original file
        const { decryptedBlob, metadata } = await decryptFile(qencBytes, privKey);
        
        // Try to restore original filename
        const qencHash = await hashBytes(qencBytes);
        let originalName = originalFileNames.get(qencHash);
        
        if (!originalName) {
            // Fallback: try with containerHash
            originalName = originalFileNames.get(containerHash);
        }
        
        if (!originalName) {
            // Use metadata filename if available, otherwise use container ID
            originalName = metadata.originalFilename || `restored-${result.containerId.slice(0, 8)}.file`;
        }
        
        download(decryptedBlob, originalName);
        
        // Verify file integrity
        const decBytes = await readFileAsUint8Array(decryptedBlob);
        const decHash = await hashBytes(decBytes);
        const integrityOk = metadata.fileHash === decHash;
        
        // Log restoration success
        const encryptionTime = metadata.timestamp || 'Unknown';
        logRestorationSuccess(originalName, decryptedBlob.size, encryptionTime, integrityOk, { isLiteMode: true });
        
        log('🎉 Container restored successfully', { isLiteMode: true });
        
    } catch (error) {
        logError(`Restoration failed: ${error?.message ?? error}`, { isLiteMode: true });
    } finally {
        setButtonsDisabled(false);
    }
}

// Mode switching
function toggleMode() {
    const modeToggle = document.getElementById('modeToggle');
    const liteSection = document.getElementById('liteMode');
    const proSection = document.getElementById('proMode');
    
    if (!modeToggle || !liteSection || !proSection) return;
    
    // Toggle is now inverted: checked = Pro mode, unchecked = Lite mode
    isLiteMode = !modeToggle.checked;
    
    if (isLiteMode) {
        liteSection.style.display = 'block';
        proSection.style.display = 'none';
        log('Switched to Lite Mode', { isLiteMode: true });
        
        // Generate keys automatically if not already done
        if (!liteKeys) {
            generateLiteKeys();
        }
    } else {
        liteSection.style.display = 'none';
        proSection.style.display = 'block';
        log('Switched to Pro Mode', { isLiteMode: false });
    }
}

// Initialize Lite Mode
export function initLiteMode() {
    // Set up mode toggle
    const modeToggle = document.getElementById('modeToggle');
    if (modeToggle) {
        modeToggle.addEventListener('change', toggleMode);
    }
    
    // Set up threshold calculation
    const liteN = document.getElementById('liteN');
    const liteThreshold = document.getElementById('liteThreshold');
    if (liteN && liteThreshold) {
        liteN.addEventListener('input', updateThresholdDisplay);
        liteThreshold.addEventListener('input', updateThresholdDisplay);
        updateThresholdDisplay(); // Initial calculation
    }
    
    // Set up file input monitoring
    const liteFilesInput = document.getElementById('liteFilesInput');
    if (liteFilesInput) {
        liteFilesInput.addEventListener('change', updateCreateShardsButton);
        liteFilesInput.disabled = true; // Disabled until keys are ready
    }
    
    // Set up button handlers
    const liteDownloadKeysBtn = document.getElementById('liteDownloadKeysBtn');
    if (liteDownloadKeysBtn) {
        liteDownloadKeysBtn.addEventListener('click', downloadLiteKeys);
    }
    
    const liteCreateShardsBtn = document.getElementById('liteCreateShardsBtn');
    if (liteCreateShardsBtn) {
        liteCreateShardsBtn.addEventListener('click', createLiteShards);
    }
    
    const liteRestoreBtn = document.getElementById('liteRestoreBtn');
    if (liteRestoreBtn) {
        liteRestoreBtn.addEventListener('click', restoreLiteShards);
    }
    
    // Start in Lite mode by default and sync UI once at load time
    isLiteMode = true;
    if (modeToggle) {
        // unchecked = Lite, checked = Pro
        modeToggle.checked = false;
    }
    toggleMode();
    
    log('Lite Mode initialized - toggle to switch to Pro mode', { isLiteMode: true });
}
