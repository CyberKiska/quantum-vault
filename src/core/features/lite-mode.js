// --- Lite Mode - Simplified Interface ---

import { encryptFile, decryptFile, generateKeyPair, hashBytes } from '../crypto/index.js';
import { buildQcontShards } from '../crypto/qcont/build.js';
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
    
    // Target threshold as number of shards
    const targetT = Math.ceil((thresholdPercent / 100) * n);
    
    // Find the best k that gives us closest to target threshold
    // Formula: t = k + (m/2), where m = n - k
    // So: t = k + (n-k)/2 = k + n/2 - k/2 = k/2 + n/2
    // Therefore: k = 2*t - n
    let k = 2 * targetT - n;
    
    // Ensure k is valid (k >= 3 and k < n) to avoid unstable configurations
    k = Math.max(3, Math.min(k, n - 1));
    
    // Ensure (n-k) is even for compatibility
    let m = n - k;
    if (m % 2 !== 0) {
        // Adjust k to make m even
        if (k + 1 < n && k + 1 >= 3) {
            k += 1;
        } else if (k - 1 >= 3) {
            k -= 1;
        } else {
            return { error: 'Cannot find valid configuration - try adjusting total shards or threshold' };
        }
        m = n - k;
    }
    
    // Additional validation for unstable configurations
    if (n <= 4 && k <= 2) {
        return { error: 'Configuration n≤4, k≤2 is unstable. Please use n≥5 with k≥3' };
    }
    
    const finalT = calculateShamirThreshold(n, k);
    const actualThresholdPercent = Math.round((finalT / n) * 100);
    
    // Ensure t is a whole number (it should be, but double-check)
    if (finalT !== Math.floor(finalT)) {
        return { error: 'Invalid configuration results in fractional threshold' };
    }
    
    return {
        n,
        k,
        m,
        t: Math.floor(finalT), // Ensure whole number
        actualThresholdPercent
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
        validationDiv.textContent = `Configuration adjusted: actual threshold is ${params.actualThresholdPercent}% (${params.t} shards)`;
        validationDiv.style.display = 'block';
    } else if (validationDiv) {
        validationDiv.className = 'validation-message success';
        validationDiv.textContent = `✓ Valid configuration: n=${params.n}, k=${params.k}, t=${params.t}`;
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

// Restore from shards (simplified)
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
        // Use the existing restoration logic from qcont/restore.js but adapted for lite mode
        const shardBytesArr = await Promise.all([...shardsInput.files].map(readFileAsUint8Array));
        const shards = shardBytesArr.map(arr => {
            const dv = new DataView(arr.buffer, arr.byteOffset);
            let off = 0;
            const magic = new TextDecoder().decode(arr.subarray(off, off + 4)); off += 4;
            if (magic !== 'QVC1') throw new Error('Invalid .qcont magic');
            const metaLen = dv.getUint16(off, false); off += 2;
            const metaJSON = JSON.parse(new TextDecoder().decode(arr.subarray(off, off + metaLen))); off += metaLen;
            const encapLen = dv.getUint32(off, false); off += 4;
            const encapsulatedKey = arr.subarray(off, off + encapLen); off += encapLen;
            const iv = arr.subarray(off, off + 12); off += 12;
            const salt = arr.subarray(off, off + 16); off += 16;
            const qencMetaLen = dv.getUint16(off, false); off += 2;
            const qencMetaBytes = arr.subarray(off, off + qencMetaLen); off += qencMetaLen;
            const shardIndex = dv.getUint16(off, false); off += 2;
            const shareLen = dv.getUint16(off, false); off += 2;
            const share = arr.subarray(off, off + shareLen); off += shareLen;
            const fragments = arr.subarray(off);
            return { metaJSON, encapsulatedKey, iv, salt, qencMetaBytes, shardIndex, share, fragments };
        });

        // Additional pre-check: ensure all selected shards belong to same containerId
        const idSet = new Set(shards.map(s => s.metaJSON?.containerId));
        if (idSet.size !== 1) {
            logError('Selected shards belong to different containers (containerId mismatch)', { isLiteMode: true });
            return;
        }
        
        // Group by container ID
        const byId = new Map();
        for (const s of shards) {
            const id = s.metaJSON.containerId;
            if (!byId.has(id)) byId.set(id, []);
            byId.get(id).push(s);
        }
        
        // Process each container
        for (const [containerId, group] of byId.entries()) {
            logRestoration(shardsInput.files.length, containerId, { isLiteMode: true });
            
            const { n, k, m, t, ciphertextLength, chunkSize, chunkCount, containerHash, privateKeyHash, aead_mode } = group[0].metaJSON;
            const isPerChunkMode = aead_mode === 'per-chunk' || aead_mode === 'per-chunk-aead';
            
            if (group.length < t) {
                throw new Error(`Need at least ${t} shards for container, got ${group.length}`);
            }
            
            // Restore private key from Shamir shares
            const sortedGroup = group.slice().sort((a, b) => a.shardIndex - b.shardIndex);
            const selectedShares = sortedGroup.slice(0, t).map(s => s.share);
            
            // Import combineShares function
            const { combineShares } = await import('../crypto/splitting/sss.js');
            const privKey = await combineShares(selectedShares);
            
            // Reconstruct encrypted container
            const encodeSize = Math.floor(256 / n) * n;
            const inputSize = (encodeSize * k) / n;
            const totalChunks = chunkCount;
            const cipherChunks = [];
            const shardOffsets = new Array(n).fill(0);
            
            for (let i = 0; i < totalChunks; i++) {
                const plainLen = Math.min(chunkSize, (group[0].metaJSON.originalLength) - (i * chunkSize));
                const thisLen = isPerChunkMode ? (plainLen + 16) : ciphertextLength;
                const encodeSize = Math.floor(256 / n) * n;
                const inputSize = (encodeSize * k) / n;
                const symbolSize = inputSize / k;
                const blocks = Math.ceil(thisLen / inputSize);
                const expectedFragLen = blocks * symbolSize;

                const encoded = new Array(n);
                for (let j = 0; j < n; j++) {
                    const fragStream = group.find(s => s.shardIndex === j)?.fragments;
                    if (!fragStream) {
                        encoded[j] = new Uint8Array(expectedFragLen);
                        continue;
                    }
                    const off = shardOffsets[j];
                    const dvFrag = new DataView(fragStream.buffer, fragStream.byteOffset + off);
                    const fragLen = dvFrag.getUint32(0, false);
                    const fragStart = off + 4;
                    const fragEnd = fragStart + fragLen;
                    let fragSlice = fragStream.subarray(fragStart, fragEnd);
                    if (fragLen < expectedFragLen) {
                        const padded = new Uint8Array(expectedFragLen);
                        padded.set(fragSlice);
                        fragSlice = padded;
                    } else if (fragLen > expectedFragLen) {
                        fragSlice = fragSlice.subarray(0, expectedFragLen);
                    }
                    encoded[j] = fragSlice;
                    shardOffsets[j] = fragEnd;
                }
                const recombined = window.erasure.recombine(encoded, thisLen, k, m/2);
                cipherChunks.push(recombined);
                if (!isPerChunkMode) break;
            }
            
            const ciphertext = isPerChunkMode
                ? (() => { const total = cipherChunks.reduce((a, c) => a + c.length, 0); const out = new Uint8Array(total); let p = 0; for (const ch of cipherChunks) { out.set(ch, p); p += ch.length; } return out; })()
                : cipherChunks[0];
            
            // Reconstruct .qenc header
            const { encapsulatedKey, iv, salt, qencMetaBytes } = group[0];
            const keyLenBytes = new Uint8Array(4); new DataView(keyLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);
            const metaLenBytes = new Uint8Array(2); new DataView(metaLenBytes.buffer).setUint16(0, qencMetaBytes.length, false);
            const MAGIC = new TextEncoder().encode('QVv1');
            const header = new Uint8Array(MAGIC.length + 4 + encapsulatedKey.length + 12 + 16 + 2 + qencMetaBytes.length);
            let p = 0;
            header.set(MAGIC, p); p += MAGIC.length;
            header.set(keyLenBytes, p); p += 4;
            header.set(encapsulatedKey, p); p += encapsulatedKey.length;
            header.set(iv, p); p += 12;
            header.set(salt, p); p += 16;
            header.set(metaLenBytes, p); p += 2;
            header.set(qencMetaBytes, p);
            
            const qencBytes = new Uint8Array(header.length + ciphertext.length);
            qencBytes.set(header, 0);
            qencBytes.set(ciphertext, header.length);
            
            // Verify hashes
            const recoveredQencHash = await hashBytes(qencBytes);
            const recoveredPrivHash = await hashBytes(privKey);
            const qencOk = recoveredQencHash === containerHash;
            const qkeyOk = recoveredPrivHash === privateKeyHash;
            
            if (!qencOk || !qkeyOk) {
                logError(`Hash verification failed for container`, { isLiteMode: true });
                continue;
            }
            
            // Now decrypt the container to get the original file
            const { decryptedBlob, metadata } = await decryptFile(qencBytes, privKey);

            // Try to restore original filename using the correct hash
            // Use the hash of the reconstructed qencBytes (same as encHash from encryption)
            const qencHash = await hashBytes(qencBytes);
            let originalName = originalFileNames.get(qencHash);

            if (!originalName) {
                // Fallback: try with containerHash as well (for backward compatibility)
                originalName = originalFileNames.get(containerHash);
            }

            if (!originalName) {
                // Final fallback: use container ID with .file extension
                originalName = `restored-${containerId.slice(0, 8)}.file`;
            }

            download(decryptedBlob, originalName);

            // Verify file integrity
            const decBytes = await readFileAsUint8Array(decryptedBlob);
            const decHash = await hashBytes(decBytes);
            const integrityOk = metadata.fileHash === decHash;

            // Log restoration success with ISO8601 timestamp
            const encryptionTime = metadata.timestamp || 'Unknown';
            logRestorationSuccess(originalName, decryptedBlob.size, encryptionTime, integrityOk, { isLiteMode: true });
        }
        
        // Final success message
        const containerCount = byId.size;
        if (containerCount === 1) {
            log('🎉 Container restored successfully', { isLiteMode: true });
        } else {
            log(`🎉 ${containerCount} containers restored successfully`, { isLiteMode: true });
        }
        
    } catch (error) {
        logError(`Restoration failed: ${error.message}`, { isLiteMode: true });
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
