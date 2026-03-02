// --- Lite Mode - Simplified Interface ---
// Lite mode is a thin UI wrapper over the same cryptographic operations as Pro mode

import { encryptFile, decryptFile, generateKeyPair, hashBytes } from '../crypto/index.js';
import { buildQcontShards } from '../crypto/qcont/build.js';
import { assessShardSelection } from '../crypto/qcont/preview.js';
import { parseShard, restoreFromShards } from '../crypto/qcont/restore.js';
import { collectRestoreVerificationOptions } from '../crypto/qcont/restore-ui.js';
import { validateRsParams, calculateShamirThreshold, readFileAsUint8Array, download, setButtonsDisabled, createFilenameTimestamp, formatFileSize } from '../../utils.js';
import { createBundlePayloadFromFiles, isBundlePayload, parseBundlePayload } from './bundle-payload.js';
import { log, logError, logSuccess, logKeyGeneration, logFileEncryption, logShardCreation, logRestoration, logRestorationSuccess, logWarning } from './ui/logging.js';
import { updateShardSelectionStatus } from './ui/shards-status.js';
import { showToast } from './ui/toast.js';
import { updateSidebarStatus } from './ui/ui.js';

// Global state for Lite mode
let liteKeys = null;
let isLiteMode = true; // Default to Lite mode
let originalFileNames = new Map(); // Track original file names for restoration
let liteShardsStatusSeq = 0;
let liteLogCollapsed = true;

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

    // Search all valid k with a safety-first policy:
    // prefer the smallest achievable threshold that is >= requested.
    let bestAtOrAbove = null;
    let bestBelow = null;
    for (let k = 2; k < n; k++) {
        if (!validateRsParams(n, k)) continue;
        const m = n - k;
        const t = calculateShamirThreshold(n, k);
        if (!Number.isInteger(t)) continue;
        const actualThresholdPercent = Math.round((t / n) * 100);
        const candidate = { n, k, m, t, actualThresholdPercent };

        if (t >= targetT) {
            if (!bestAtOrAbove || t < bestAtOrAbove.t) {
                bestAtOrAbove = candidate;
            }
        } else if (!bestBelow || t > bestBelow.t) {
            bestBelow = candidate;
        }
    }

    const best = bestAtOrAbove || bestBelow;

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

function getAchievableThresholdsForN(n) {
    const thresholdsByPercent = new Map();
    for (let k = 2; k < n; k++) {
        if (!validateRsParams(n, k)) continue;
        const m = n - k;
        const t = calculateShamirThreshold(n, k);
        if (!Number.isInteger(t)) continue;
        const actualThresholdPercent = Math.round((t / n) * 100);
        thresholdsByPercent.set(actualThresholdPercent, { n, k, m, t, actualThresholdPercent });
    }
    return [...thresholdsByPercent.values()].sort((a, b) => a.actualThresholdPercent - b.actualThresholdPercent);
}

function getAlternativeNRecommendations(requestedPercent, currentN, limit = 2) {
    const candidates = [];
    for (let n = 5; n <= 25; n++) {
        if (n === currentN) continue;
        const params = calculateParametersFromThreshold(n, requestedPercent);
        if (params.error) continue;
        candidates.push({
            n,
            actualThresholdPercent: params.actualThresholdPercent,
            diff: Math.abs(params.actualThresholdPercent - requestedPercent)
        });
    }
    candidates.sort((a, b) => a.diff - b.diff || a.n - b.n);
    return candidates.slice(0, limit);
}

// Update threshold display logic
function updateThresholdDisplay() {
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    const thresholdText = document.getElementById('thresholdText');
    const thresholdDelta = document.getElementById('thresholdDelta');
    const thresholdHint = document.getElementById('thresholdHint');
    
    if (!nInput || !thresholdInput || !thresholdText) return;
    
    const n = parseInt(nInput.value, 10);
    const thresholdPercent = parseInt(thresholdInput.value, 10);
    
    if (thresholdDelta) {
        thresholdDelta.textContent = '';
        thresholdDelta.className = 'threshold-delta';
    }
    if (thresholdHint) {
        thresholdHint.textContent = 'Discrete by RS/SSS constraints.';
        thresholdHint.className = 'info-text';
    }
    
    if (isNaN(n) || isNaN(thresholdPercent) || n < 5) {
        thresholdText.textContent = 'Invalid parameters';
        if (thresholdHint) {
            thresholdHint.className = 'info-text error';
            thresholdHint.textContent = 'Total shards must be at least 5 (n >= 5) to compute a recoverable threshold.';
        }
        updateCreateShardsButton();
        return;
    }
    
    const params = calculateParametersFromThreshold(n, thresholdPercent);
    
    if (params.error) {
        thresholdText.textContent = 'Configuration Error';
        if (thresholdHint) {
            thresholdHint.className = 'info-text error';
            thresholdHint.textContent = `Adjust parameters to a recoverable configuration: ${params.error}`;
        }
        updateCreateShardsButton();
        return;
    }
    
    const delta = params.actualThresholdPercent - thresholdPercent;
    thresholdText.textContent = `Requested ${thresholdPercent}% -> Achievable ${params.actualThresholdPercent}% (>=${params.t}/${params.n} shards)`;
    
    if (thresholdDelta) {
        if (delta === 0) {
            thresholdDelta.className = 'threshold-delta success';
            thresholdDelta.textContent = 'Exact match';
        } else {
            const sign = delta > 0 ? '+' : '';
            thresholdDelta.className = 'threshold-delta warning';
            thresholdDelta.textContent = `${sign}${delta} pp`;
        }
    }

    if (thresholdHint) {
        const achievable = getAchievableThresholdsForN(n);
        const achievablePercents = achievable.map(item => `${item.actualThresholdPercent}%`).join(', ');
        if (delta !== 0) {
            const alternatives = getAlternativeNRecommendations(thresholdPercent, n, 2);
            const recommendation = alternatives.length
                ? ` Try n=${alternatives[0].n} (${alternatives[0].actualThresholdPercent}%)${alternatives[1] ? ` or n=${alternatives[1].n} (${alternatives[1].actualThresholdPercent}%)` : ''}.`
                : '';
            thresholdHint.textContent = `Requested ${thresholdPercent}% is not directly achievable with n=${params.n}. Using nearest recoverable threshold ${params.actualThresholdPercent}% (k=${params.k}, m=${params.m}, t=${params.t}). Achievable thresholds for n=${n}: ${achievablePercents}.${recommendation}`;
            thresholdHint.className = 'info-text warning';
        } else {
            thresholdHint.textContent = `Valid configuration: n=${params.n}, k=${params.k}, m=${params.m}, t=${params.t} (can lose up to ${params.m / 2} shards). Achievable thresholds for n=${n}: ${achievablePercents}.`;
            thresholdHint.className = 'info-text';
        }
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
        updateSidebarStatus(pkHash, skHash);
        
        if (statusText) statusText.textContent = 'Keys ready ✓';
        if (statusIcon) statusIcon.textContent = '🔑';
        
        // Enable file input once keys are ready
        const liteFilesInput = document.getElementById('liteFilesInput');
        if (liteFilesInput) liteFilesInput.disabled = false;
        
        // Show download keys button
        const downloadBtn = document.getElementById('liteDownloadKeysBtn');
        if (downloadBtn) downloadBtn.style.display = 'inline-flex';
        
        updateCreateShardsButton();
        
    } catch (error) {
        logError(`Failed to generate keys: ${error.message}`, { isLiteMode: true });
        const statusText = document.getElementById('keyStatus')?.querySelector('.status-text');
        const statusIcon = document.getElementById('keyStatus')?.querySelector('.status-icon');
        if (statusText) statusText.textContent = 'Key generation failed ✗';
        if (statusIcon) statusIcon.textContent = '❌';
    }
}

// Update file list display
function updateFileListDisplay() {
    const filesInput = document.getElementById('liteFilesInput');
    const filesList = document.getElementById('liteFilesList');
    
    if (!filesInput || !filesList) return;
    
    if (!filesInput.files || filesInput.files.length === 0) {
        filesList.style.display = 'none';
        return;
    }
    
    filesList.replaceChildren();
    for (const file of filesInput.files) {
        const item = document.createElement('div');
        item.className = 'file-item';

        const fileName = document.createElement('span');
        fileName.className = 'file-name';
        fileName.textContent = `📄 ${file.name}`;

        const fileSize = document.createElement('span');
        fileSize.className = 'file-size';
        fileSize.textContent = formatFileSize(file.size);

        item.append(fileName, fileSize);
        filesList.appendChild(item);
    }
    filesList.style.display = 'block';
}

// Update shards status indicator
async function updateShardsStatus() {
    const shardsInput = document.getElementById('liteShardsInput');
    const statusDiv = document.getElementById('shardsStatus');
    const statusText = document.getElementById('shardsStatusText');
    const restoreBtn = document.getElementById('liteRestoreBtn');
    
    if (!shardsInput || !statusDiv || !statusText) return;
    
    const files = [...(shardsInput.files || [])];
    const requestId = ++liteShardsStatusSeq;
    await updateShardSelectionStatus({
        files,
        statusDiv,
        statusText,
        actionButton: restoreBtn,
        isCurrent: () => requestId === liteShardsStatusSeq
    });
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
        showToast('No keys available to download.', 'warning');
        return;
    }
    
    const timestamp = createFilenameTimestamp();
    // Download secret key first (most important)
    download(new Blob([liteKeys.secretKey]), `quantum-vault-${timestamp}-secretKey.qkey`);
    
    // Small delay to prevent browser from blocking the second download
    setTimeout(() => {
        download(new Blob([liteKeys.publicKey]), `quantum-vault-${timestamp}-publicKey.qkey`);
    }, 500);
    
    log('✅ Backup keys downloaded', { isLiteMode: true });
}

// Pipeline Visualization Helper
function updateLitePipeline(viewId, activeStepClass) {
    const view = document.getElementById(viewId);
    if (!view) return;
    const steps = view.querySelectorAll('.pipeline-step');
    steps.forEach(step => {
        if (activeStepClass === null) {
             step.classList.remove('active');
        } else if (step.classList.contains(activeStepClass)) {
            step.classList.add('active');
        } else {
            step.classList.remove('active');
        }
    });
}

// Create shards workflow
async function createLiteShards() {
    const filesInput = document.getElementById('liteFilesInput');
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    
    if (!filesInput?.files?.length) {
        showToast('Please select files to encrypt', 'warning');
        return;
    }
    
    if (!liteKeys) {
        showToast('Keys not ready', 'warning');
        return;
    }
    
    const n = parseInt(nInput.value, 10);
    const thresholdPercent = parseInt(thresholdInput.value, 10);
    
    if (isNaN(n) || isNaN(thresholdPercent)) {
        showToast('Invalid parameters', 'warning');
        return;
    }
    
    setButtonsDisabled(true);
    updateLitePipeline('liteViewProtect', 'step-lock'); // Start: Encrypting
    
    try {
        const params = calculateParametersFromThreshold(n, thresholdPercent);
        if (params.error) {
            throw new Error(params.error);
        }

        const inputFiles = [...filesInput.files];
        const isBundle = inputFiles.length > 1;

        let payloadBytes;
        let payloadName;
        let payloadLabel;
        if (isBundle) {
            const { bundleName, bundleBytes, fileCount } = await createBundlePayloadFromFiles(inputFiles);
            payloadBytes = bundleBytes;
            payloadName = bundleName;
            payloadLabel = `${fileCount} files bundle`;

            const totalInputSize = inputFiles.reduce((acc, file) => acc + file.size, 0);
            log(`Bundled ${fileCount} files (${formatFileSize(totalInputSize)}) into ${bundleName}`, { isLiteMode: true });
        } else {
            const file = inputFiles[0];
            payloadBytes = await readFileAsUint8Array(file);
            payloadName = file.name;
            payloadLabel = file.name;
        }

        // 1. Encrypt payload (single file or multi-file bundle)
        const encBlob = await encryptFile(payloadBytes, liteKeys.publicKey, payloadName);
        const encBytes = await readFileAsUint8Array(encBlob);
        const encHash = await hashBytes(encBytes);
        originalFileNames.set(encHash, payloadName);

        // Log encryption
        logFileEncryption(payloadLabel, payloadBytes.length, encHash, { isLiteMode: true });

        updateLitePipeline('liteViewProtect', 'step-split'); // Transition: Splitting
        
        // 2. Create shards from encrypted container + private key
        const splitResult = await buildQcontShards(encBytes, liteKeys.secretKey, {
            n: params.n,
            k: params.k
        });
        const qconts = splitResult.shards;
        
        // 3. Download shards
        const baseName = payloadName.replace(/\.[^/.]+$/, ''); // Remove extension
        qconts.forEach(({ blob, index }) => {
            const shardName = `${baseName}.part${index + 1}-of-${qconts.length}.qcont`;
            download(blob, shardName);
        });
        const manifestName = `${baseName}.qvmanifest.json`;
        download(new Blob([splitResult.manifestBytes], { type: 'application/json' }), manifestName);
        
        // Log shard creation
        logShardCreation(qconts.length, params, payloadLabel, { isLiteMode: true });
        
        if (isBundle) {
            log('🛡️ Files bundled, encrypted, and split into shards', { isLiteMode: true });
        } else {
            log('🛡️ File encrypted and split into shards', { isLiteMode: true });
        }
        log(`Saved ${manifestName} for detached signing (recommended).`, { isLiteMode: true });
        log('Hint: sign manifest in Quantum Signer to protect against malicious shard substitution.', { isLiteMode: true });
        log('Distribute shards across different storage locations for security', { isLiteMode: true });
        
    } catch (error) {
        logError(`Failed to create shards: ${error.message}`, { isLiteMode: true });
    } finally {
        setButtonsDisabled(false);
        updateCreateShardsButton();
        setTimeout(() => updateLitePipeline('liteViewProtect', null), 2000); // Reset after delay
    }
}

function buildLiteRestoreResultPanel(result, containerOk, decryptOk) {
    const panel = document.getElementById('liteRestoreResult');
    if (!panel) return;

    panel.replaceChildren();
    panel.style.display = 'block';

    const allOk = containerOk && decryptOk;

    const header = document.createElement('h4');
    header.textContent = 'Restore Result';
    panel.appendChild(header);

    const addItem = (ok, text, warn) => {
        const item = document.createElement('div');
        item.className = `restore-result-item ${warn ? 'warn' : (ok ? 'ok' : 'fail')}`;
        item.textContent = `${warn ? '⚠' : (ok ? '✓' : '✗')} ${text}`;
        panel.appendChild(item);
    };

    addItem(result.qencOk, `Container integrity${result.qencOk ? ' verified' : ' FAILED'}`);
    addItem(result.qkeyOk, `Secret key integrity${result.qkeyOk ? ' verified' : ' FAILED'}`);
    if (containerOk) {
        addItem(decryptOk, `Decryption & file integrity${decryptOk ? ' verified' : ' FAILED'}`);
    }

    const verification = result.authenticity?.verification;
    if (verification) {
        for (const item of verification.results || []) {
            if (item.ok) {
                const label = item.type === 'qsig'
                    ? `${item.algorithm || 'PQ'} signature${item.trusted ? ' (trusted)' : ''}`
                    : `${item.algorithm || 'Ed25519'} signature${item.trusted ? ' (trusted)' : ''}`;
                addItem(true, label);
            } else {
                addItem(false, `Signature: ${item.error || 'verification failed'}`);
            }
        }
    } else if ((result.authenticity?.warnings?.length || 0) > 0) {
        addItem(false, 'No signatures verified (unsigned restore)', true);
    }

    panel.className = `restore-result-panel ${allOk ? 'ok' : 'fail'}`;
}

async function restoreLiteShards() {
    const shardsInput = document.getElementById('liteShardsInput');
    
    if (!shardsInput?.files?.length) {
        showToast('Please select shard files to restore', 'warning');
        return;
    }

    const assessment = await assessShardSelection([...(shardsInput.files || [])]);
    if (!assessment.ready) {
        showToast(assessment.message || 'Selected shards do not meet the recovery threshold', 'warning');
        return;
    }
    
    setButtonsDisabled(true);
    updateLitePipeline('liteViewRestore', 'step-combine');

    const liteResultPanel = document.getElementById('liteRestoreResult');
    if (liteResultPanel) {
        liteResultPanel.style.display = 'none';
        liteResultPanel.replaceChildren();
    }
    
    try {
        const verificationOptions = await collectRestoreVerificationOptions('liteRestore', [...shardsInput.files]);
        if (!verificationOptions.shardFiles.length) {
            throw new Error('No .qcont shard files were detected in selected input.');
        }
        if (verificationOptions.ignoredFileNames.length > 0) {
            logWarning(`Ignored non-restore attachments: ${verificationOptions.ignoredFileNames.join(', ')}`, { isLiteMode: true });
        }

        // Parse shards using shared function
        const shardBytesArr = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
        const shards = shardBytesArr.map((arr) => parseShard(arr, { strict: true }));
        
        // Log restoration start
        const containerId = shards[0]?.metaJSON?.containerId;
        logRestoration(verificationOptions.shardFiles.length, containerId, { isLiteMode: true });
        
        // Restore using shared core logic
        const result = await restoreFromShards(shards, {
            onLog: (msg) => log(msg, { isLiteMode: true }),
            onError: (msg) => logError(msg, { isLiteMode: true }),
            onWarn: (msg) => logWarning(msg, { isLiteMode: true }),
            verification: verificationOptions,
        });

        log(`Selected manifest digest: ${result.manifestDigestHex}`, { isLiteMode: true });
        for (const warning of result.authenticity?.warnings || []) {
            logWarning(warning, { isLiteMode: true });
        }
        if (result.authenticity?.verification) {
            const verification = result.authenticity.verification;
            log(`Signature results: ${verification.validCount} valid, ${verification.trustedValidCount} trusted-valid`, { isLiteMode: true });
            for (const item of verification.results || []) {
                if (item.ok) {
                    if (item.type === 'sig') {
                        logSuccess(`Signature OK: ${item.name} (${item.algorithm || 'Ed25519'}, signer ${item.signer || 'unknown'}${item.trusted ? ', trusted' : ''})`, { isLiteMode: true });
                    } else if (item.type === 'qsig') {
                        logSuccess(`Signature OK: ${item.name} (${item.algorithm || 'PQ'}, fp ${item.signerFingerprintHex || 'unknown'}${item.trusted ? ', trusted' : ''})`, { isLiteMode: true });
                    } else {
                        logSuccess(`Signature OK: ${item.name}`, { isLiteMode: true });
                    }
                } else {
                    logWarning(`Signature failed: ${item.name} (${item.error || 'unknown error'})`, { isLiteMode: true });
                }
            }
            for (const warning of verification.warnings || []) {
                logWarning(warning, { isLiteMode: true });
            }
        }

        const { qencBytes, privKey, containerHash, qencOk, qkeyOk } = result;
        
        if (!qencOk || !qkeyOk) {
            logError('Hash verification failed for container', { isLiteMode: true });
            buildLiteRestoreResultPanel(result, false, false);
            return;
        }
        
        const { decryptedBlob, metadata } = await decryptFile(qencBytes, privKey);
        const decBytes = await readFileAsUint8Array(decryptedBlob);
        const decHash = await hashBytes(decBytes);
        const integrityOk = metadata.fileHash === decHash;

        if (!integrityOk) {
            logError('File integrity check failed - hashes do not match', { isLiteMode: true });
            buildLiteRestoreResultPanel(result, true, false);
            return;
        }

        let restoredLabel;
        if (isBundlePayload(decBytes)) {
            const entries = parseBundlePayload(decBytes);
            for (const entry of entries) {
                download(new Blob([entry.bytes]), entry.name);
            }
            restoredLabel = `${entries.length} files bundle`;
            log(`📦 Restored ${entries.length} files from encrypted bundle`, { isLiteMode: true });
        } else {
            const qencHash = await hashBytes(qencBytes);
            let originalName = originalFileNames.get(qencHash);
            
            if (!originalName) {
                originalName = originalFileNames.get(containerHash);
            }
            
            if (!originalName) {
                originalName = metadata.originalFilename || `restored-${result.containerId.slice(0, 8)}.file`;
            }

            download(new Blob([decBytes]), originalName);
            restoredLabel = originalName;
        }

        const encryptionTime = metadata.timestamp || 'Unknown';
        logRestorationSuccess(restoredLabel, decBytes.length, encryptionTime, true, { isLiteMode: true });
        
        logSuccess('Container restored successfully', { isLiteMode: true });
        buildLiteRestoreResultPanel(result, true, true);
        
    } catch (error) {
        logError(`Restoration failed: ${error?.message ?? error}`, { isLiteMode: true });
    } finally {
        setButtonsDisabled(false);
        void updateShardsStatus();
        setTimeout(() => updateLitePipeline('liteViewRestore', null), 2000); // Reset after delay
    }
}

function initLiteTabs() {
    const tabProtect = document.getElementById('liteTabProtect');
    const tabRestore = document.getElementById('liteTabRestore');
    const viewProtect = document.getElementById('liteViewProtect');
    const viewRestore = document.getElementById('liteViewRestore');
    const tabIds = ['liteTabProtect', 'liteTabRestore'];
    const panelByTabId = {
        liteTabProtect: viewProtect,
        liteTabRestore: viewRestore,
    };

    function activateLiteTab(tabId, { focus = false } = {}) {
        tabIds.forEach((currentTabId) => {
            const tabEl = document.getElementById(currentTabId);
            const panelEl = panelByTabId[currentTabId];
            const active = currentTabId === tabId;

            if (tabEl) {
                tabEl.classList.toggle('active', active);
                tabEl.setAttribute('aria-selected', String(active));
                tabEl.tabIndex = active ? 0 : -1;
                if (active && focus) tabEl.focus();
            }

            if (panelEl) {
                panelEl.style.display = active ? 'block' : 'none';
                panelEl.classList.toggle('active', active);
            }
        });
    }

    if (tabProtect && tabRestore && viewProtect && viewRestore) {
        tabProtect.addEventListener('click', () => {
            activateLiteTab('liteTabProtect');
        });

        tabRestore.addEventListener('click', () => {
            activateLiteTab('liteTabRestore');
        });
    }
}

function updateOperationsLogVisibility() {
    const logContainer = document.getElementById('logContainer');
    const logToggleBtn = document.getElementById('logToggleBtn');
    if (!logContainer || !logToggleBtn) return;

    if (isLiteMode) {
        logToggleBtn.style.display = 'inline-flex';
        logContainer.classList.toggle('collapsed', liteLogCollapsed);
        logToggleBtn.textContent = liteLogCollapsed ? 'Show Log' : 'Hide Log';
    } else {
        logContainer.classList.remove('collapsed');
        logToggleBtn.style.display = 'none';
    }
    logToggleBtn.setAttribute('aria-expanded', String(!logContainer.classList.contains('collapsed')));
}

function toggleLiteLogVisibility() {
    if (!isLiteMode) return;
    liteLogCollapsed = !liteLogCollapsed;
    updateOperationsLogVisibility();
}

// Mode switching
function toggleMode() {
    const modeToggle = document.getElementById('modeToggle');
    const liteSection = document.getElementById('liteMode');
    const proSection = document.getElementById('proMode');
    const liteNav = document.getElementById('liteNav');
    const proNav = document.getElementById('proNav');
    
    if (!modeToggle || !liteSection || !proSection) return;
    
    // Toggle is now inverted: checked = Pro mode, unchecked = Lite mode
    isLiteMode = !modeToggle.checked;
    
    if (isLiteMode) {
        liteSection.style.display = 'block';
        proSection.style.display = 'none';
        if (liteNav) liteNav.classList.remove('initially-hidden');
        if (proNav) proNav.classList.add('initially-hidden');
        log('Switched to Lite Mode', { isLiteMode: true });
        
        // Generate keys automatically if not already done
        if (!liteKeys) {
            generateLiteKeys();
        } else {
            // Restore lite keys status to sidebar if previously generated
            hashBytes(liteKeys.publicKey).then(pk => {
                hashBytes(liteKeys.secretKey).then(sk => updateSidebarStatus(pk, sk));
            });
        }
    } else {
        liteSection.style.display = 'none';
        proSection.style.display = 'block';
        if (liteNav) liteNav.classList.add('initially-hidden');
        if (proNav) proNav.classList.remove('initially-hidden');
        log('Switched to Pro Mode', { isLiteMode: false });
        
        // Restore sidebar context from currently selected Pro keys if present.
        void (async () => {
            const pubFile = document.getElementById('pubKeyInput')?.files?.[0];
            const secFile = document.getElementById('privKeyInput')?.files?.[0];
            let pubHash = null;
            let secHash = null;
            try {
                if (pubFile) {
                    const pubBytes = await readFileAsUint8Array(pubFile);
                    pubHash = await hashBytes(pubBytes);
                }
                if (secFile) {
                    const secBytes = await readFileAsUint8Array(secFile);
                    secHash = await hashBytes(secBytes);
                }
            } catch {
                pubHash = pubFile ? 'Loaded' : null;
                secHash = secFile ? 'Loaded' : null;
            }
            updateSidebarStatus(pubHash, secHash);
        })();
    }

    updateOperationsLogVisibility();
}

// Initialize Lite Mode
export function initLiteMode() {
    // Set up mode toggle
    const modeToggle = document.getElementById('modeToggle');
    if (modeToggle) {
        modeToggle.addEventListener('change', toggleMode);
    }

    const logToggleBtn = document.getElementById('logToggleBtn');
    if (logToggleBtn) {
        logToggleBtn.addEventListener('click', toggleLiteLogVisibility);
    }
    
    initLiteTabs();
    
    // Set up threshold calculation for manual inputs
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
        liteFilesInput.addEventListener('change', () => {
            updateFileListDisplay();
            updateCreateShardsButton();
        });
        liteFilesInput.disabled = true; // Disabled until keys are ready
    }
    
    // Set up shard input monitoring
    const liteShardsInput = document.getElementById('liteShardsInput');
    if (liteShardsInput) {
        liteShardsInput.addEventListener('change', () => { void updateShardsStatus(); });
        void updateShardsStatus();
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
