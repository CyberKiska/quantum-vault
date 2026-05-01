// --- Lite Mode - Simplified Interface ---
// Lite mode is a thin UI wrapper over the same cryptographic operations as Pro mode

import {
    encryptFile,
    decryptFile,
    generateKeyPair,
    hashBytes,
    buildQcontShards,
    parseLifecycleShard,
    restoreFromShards,
    assessShardSelection,
} from '../../app/crypto-service.js';
import { LITE_DEFAULT_AUTH_POLICY_LEVEL } from '../crypto/constants.js';
import {
    buildRestorePolicyFailureSummary,
    buildRestoreResultSummary,
    collectRestoreVerificationOptions,
    logRestoreSelectionSummary,
    logVerificationSummary,
    refreshSuccessorSelectionUi,
    renderRestorePreflightForFiles,
} from './qcont/restore-ui.js';
import { registerSessionWipeHandler } from '../../app/session-wipe.js';
import { validateRsParams, calculateShamirThreshold, readFileAsUint8Array, download, setButtonsDisabled, createFilenameTimestamp, formatFileSize } from '../../utils.js';
import { createBundlePayloadFromFiles, isBundlePayload, parseBundlePayload } from './bundle-payload.js';
import {
    log,
    logError,
    logSuccess,
    logKeyGeneration,
    logFileEncryption,
    logShardCreation,
    logRestoration,
    logRestorationSuccess,
    logWarning,
} from './ui/logging.js';
import { updateShardSelectionStatus } from './ui/shards-status.js';
import { showToast } from './ui/toast.js';
import { clearInlineError, showInlineError, summarizeFileList } from './ui/inline-error.js';
import { clearArtifactIntakeTable, renderArtifactIntakeTable } from './ui/artifact-intake.js';
import { initRovingTablist } from './ui/tabs.js';
import { updateSidebarStatus } from './ui/ui.js';
import { describeAuthPolicyHelp, renderAuthPolicyConsequence } from './qcont/auth-policy-help.js';

// Global state for Lite mode
let liteKeys = null;
let isLiteMode = true; // Default to Lite mode
let originalFileNames = new Map(); // Track original file names for restoration
let liteShardsStatusSeq = 0;
let liteLogCollapsed = true;
let unregisterLiteSessionWipe = null;
const LITE_RESTORE_INLINE_ERROR_ID = 'liteRestoreInlineError';

/** After each successful Lite create, key backup row tracks Backup Keys clicks until the next create. */
let liteKeyBackupAfterLastCreate = false;
let liteLastCreateShardCount = 0;

function isLiteShardConfigurationValid() {
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    if (!nInput || !thresholdInput) return false;
    const n = parseInt(nInput.value, 10);
    const thresholdPercent = parseInt(thresholdInput.value, 10);
    if (isNaN(n) || isNaN(thresholdPercent) || n < 5) return false;
    const params = calculateParametersFromThreshold(n, thresholdPercent);
    return !params.error;
}

function refreshLiteCustodyGuidanceVisibility() {
    const panel = document.getElementById('liteCustodyGuidance');
    if (!panel) return;
    const show = liteKeys !== null && isLiteShardConfigurationValid();
    panel.classList.toggle('initially-hidden', !show);
}

function hideLiteExportChecklist() {
    document.getElementById('liteExportChecklist')?.classList.add('initially-hidden');
}

function renderLiteExportChecklistBody(shardCount) {
    const ul = document.getElementById('liteExportChecklistItems');
    if (!ul) return;

    ul.replaceChildren();

    const addRow = (title, detail, tone) => {
        const li = document.createElement('li');
        li.className = `lite-checklist-row lite-checklist-row--${tone}`;
        const titleEl = document.createElement('span');
        titleEl.className = 'lite-checklist-title';
        titleEl.textContent = title;
        const detailEl = document.createElement('span');
        detailEl.className = 'lite-checklist-detail';
        detailEl.textContent = detail;
        li.append(titleEl, detailEl);
        ul.appendChild(li);
    };

    addRow(
        'QVqcont-7 shards exported',
        `${shardCount} files — confirm your browser saved every shard`,
        'ok',
    );
    addRow(
        'Archive-state descriptor exported',
        'Confirm .archive-state.json is retained with your custody records',
        'ok',
    );
    addRow(
        'Lifecycle bundle exported',
        'Confirm .lifecycle-bundle.json is retained for attach and restore workflows',
        'ok',
    );

    const keyExported = liteKeyBackupAfterLastCreate;
    addRow(
        keyExported ? 'Optional key backup exported' : 'Optional key backup not exported',
        keyExported
            ? 'ML-KEM .qkey downloads were triggered from Backup Keys'
            : 'Skipped — optional; threshold recovery normally uses shards. Omit if retaining keys violates policy.',
        keyExported ? 'ok' : 'neutral',
    );
}

function renderLiteExportChecklistAfterCreate(shardCount) {
    liteLastCreateShardCount = shardCount;
    liteKeyBackupAfterLastCreate = false;
    const root = document.getElementById('liteExportChecklist');
    if (!root) return;
    renderLiteExportChecklistBody(shardCount);
    root.classList.remove('initially-hidden');
}

function refreshLiteExportChecklistAfterKeyBackup() {
    if (liteLastCreateShardCount <= 0) return;
    renderLiteExportChecklistBody(liteLastCreateShardCount);
}

function liteRestoreRecoveryAction(error) {
    const message = String(error?.message || error || '').toLowerCase();
    if (message.includes('archive policy') || message.includes('archive-approval')) {
        return 'Load or attach policy-satisfying archive-approval evidence, then retry Lite Restore.';
    }
    if (message.includes('threshold') || message.includes('shard')) {
        return 'Load enough successor QVqcont-7 shards from one archive/state/cohort and remove incompatible files.';
    }
    if (message.includes('lifecycle bundle') || message.includes('selection') || message.includes('cohort')) {
        return 'Choose the exact archive, cohort, or lifecycle bundle variant, or load the matching lifecycle bundle.';
    }
    return 'Review the selected restore inputs, correct the blocking condition, and retry Lite Restore.';
}

function wipeLiteKeyPair(keyPair) {
    if (keyPair?.privateKey instanceof Uint8Array) {
        keyPair.privateKey.fill(0);
    }
    if (keyPair?.publicKey instanceof Uint8Array) {
        keyPair.publicKey.fill(0);
    }
}

function wipeLiteKeys() {
    wipeLiteKeyPair(liteKeys);
    liteKeys = null;
}

function wipeLiteModeSessionSecrets() {
    wipeLiteKeys();
    originalFileNames.clear();
    liteKeyBackupAfterLastCreate = false;
    liteLastCreateShardCount = 0;
    hideLiteExportChecklist();
    refreshLiteCustodyGuidanceVisibility();
}

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
        const previousKeys = liteKeys;

        const keyStatus = document.getElementById('keyStatus');
        const statusText = keyStatus?.querySelector('.status-text');
        const statusIcon = keyStatus?.querySelector('.status-icon');

        document.getElementById('liteCustodyGuidance')?.classList.add('initially-hidden');
        
        if (statusText) statusText.textContent = 'Generating keys...';
        if (statusIcon) statusIcon.textContent = '🔄';
        
        // Generate keys with default entropy (no user collection in Lite mode)
        const keyPair = await generateKeyPair({ collectUserEntropy: false });
        liteKeys = keyPair;
        if (previousKeys && previousKeys !== keyPair) {
            wipeLiteKeyPair(previousKeys);
        }
        
        const skHash = await hashBytes(liteKeys.privateKey);
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
        refreshLiteCustodyGuidanceVisibility();
        
    } catch (error) {
        logError(`Failed to generate keys: ${error.message}`, { isLiteMode: true });
        const statusText = document.getElementById('keyStatus')?.querySelector('.status-text');
        const statusIcon = document.getElementById('keyStatus')?.querySelector('.status-icon');
        if (statusText) statusText.textContent = 'Key generation failed ✗';
        if (statusIcon) statusIcon.textContent = '❌';
        refreshLiteCustodyGuidanceVisibility();
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
    if (files.length === 0) {
        clearArtifactIntakeTable('liteRestoreArtifactIntake');
    }
    const assessment = await updateShardSelectionStatus({
        files,
        statusDiv,
        statusText,
        actionButton: restoreBtn,
        isCurrent: () => requestId === liteShardsStatusSeq
    });
    if (requestId !== liteShardsStatusSeq) return;
    await renderArtifactIntakeTable({
        containerId: 'liteRestoreArtifactIntake',
        files,
        workflow: 'lite-restore',
        label: 'Lite restore artifact intake',
    });
    if (requestId !== liteShardsStatusSeq) return;
    await refreshSuccessorSelectionUi('liteRestore', files, restoreBtn, assessment || { ready: false });
    if (requestId !== liteShardsStatusSeq) return;
    await renderRestorePreflightForFiles({
        prefix: 'liteRestore',
        containerId: 'liteRestorePreflightDecision',
        files,
        expectedSignerInput: document.getElementById('liteRestoreExpectedEdSigner'),
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

    refreshLiteCustodyGuidanceVisibility();
}

// Download keys backup
function downloadLiteKeys() {
    if (!liteKeys) {
        showToast('No keys available to download.', 'warning');
        return;
    }
    
    const timestamp = createFilenameTimestamp();
    // Download private key first (most important)
    download(new Blob([liteKeys.privateKey]), `quantum-vault-${timestamp}-privateKey.qkey`);
    
    // Small delay to prevent browser from blocking the second download
    setTimeout(() => {
        download(new Blob([liteKeys.publicKey]), `quantum-vault-${timestamp}-publicKey.qkey`);
    }, 500);
    
    log('✅ Backup keys downloaded', { isLiteMode: true });
    liteKeyBackupAfterLastCreate = true;
    refreshLiteExportChecklistAfterKeyBackup();
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
    const authPolicyInput = document.getElementById('liteAuthPolicy');
    
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
    
    hideLiteExportChecklist();

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
        const authPolicyLevel = String(authPolicyInput?.value || LITE_DEFAULT_AUTH_POLICY_LEVEL);
        const splitResult = await buildQcontShards(encBytes, liteKeys.privateKey, {
            n: params.n,
            k: params.k
        }, { authPolicyLevel });
        const qconts = splitResult.shards;
        
        // 3. Download shards
        const baseName = payloadName.replace(/\.[^/.]+$/, ''); // Remove extension
        qconts.forEach(({ blob, index }) => {
            const shardName = `${baseName}.part${index + 1}-of-${qconts.length}.qcont`;
            download(blob, shardName);
        });
        const archiveStateName = `${baseName}.archive-state.json`;
        download(new Blob([splitResult.archiveStateBytes], { type: 'application/json' }), archiveStateName);
        const lifecycleBundleName = `${baseName}.lifecycle-bundle.json`;
        download(new Blob([splitResult.lifecycleBundleBytes], { type: 'application/json' }), lifecycleBundleName);
        
        // Log shard creation
        logShardCreation(qconts.length, params, payloadLabel, { isLiteMode: true });
        
        if (isBundle) {
            log('🛡️ Files bundled, encrypted, and split into shards', { isLiteMode: true });
        } else {
            log('🛡️ File encrypted and split into shards', { isLiteMode: true });
        }
        log(`Archive policy: ${authPolicyLevel}`, { isLiteMode: true });
        if (authPolicyLevel === 'integrity-only') {
            log(`Next actions: sign ${archiveStateName} later if you need archive approval, attach detached evidence when ready, or proceed to Restore for integrity-only recovery.`, { isLiteMode: true });
        } else {
            log(`Next actions: sign ${archiveStateName} externally, then attach that detached archive-approval signature to ${lifecycleBundleName} without changing the signed bytes.`, { isLiteMode: true });
        }
        log(`Saved ${lifecycleBundleName}. This mutable lifecycle bundle carries detached evidence separately from the signable archive-state descriptor.`, { isLiteMode: true });
        log('Same-state resharing later is maintenance, not archive re-approval, because the archive-state descriptor stays unchanged while a new cohort and transition record are emitted.', { isLiteMode: true });
        log('Distribute shards across different storage locations for security', { isLiteMode: true });

        renderLiteExportChecklistAfterCreate(qconts.length);
        
    } catch (error) {
        logError(`Failed to create shards: ${error.message}`, { isLiteMode: true });
    } finally {
        setButtonsDisabled(false);
        updateCreateShardsButton();
        setTimeout(() => updateLitePipeline('liteViewProtect', null), 2000); // Reset after delay
    }
}

async function restoreLiteShards() {
    const shardsInput = document.getElementById('liteShardsInput');
    
    if (!shardsInput?.files?.length) {
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: 'No shard files are selected.',
            artifact: 'Lite restore input set',
            action: 'Load successor QVqcont-7 shards and any detached evidence required by the archive policy.',
        });
        showToast('Please select shard files to restore', 'warning');
        return;
    }

    const assessment = await assessShardSelection([...(shardsInput.files || [])]);
    if (!assessment.ready) {
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: assessment.message || 'Selected shards do not meet the recovery threshold.',
            artifact: summarizeFileList([...(shardsInput.files || [])], 'Lite restore input set'),
            action: 'Load enough unique successor shards from one archive/state/cohort, then retry Lite Restore.',
        });
        showToast(assessment.message || 'Selected shards do not meet the recovery threshold', 'warning');
        return;
    }

    const preflight = await renderRestorePreflightForFiles({
        prefix: 'liteRestore',
        containerId: 'liteRestorePreflightDecision',
        files: [...(shardsInput.files || [])],
        expectedSignerInput: document.getElementById('liteRestoreExpectedEdSigner'),
    });
    if (preflight?.canEvaluate === false) {
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: preflight.blockingReason || 'Restore preflight blocked evaluation.',
            artifact: summarizeFileList([...(shardsInput.files || [])], 'Lite restore input set'),
            action: 'Load policy-satisfying archive-approval evidence, then retry Lite Restore.',
        });
        showToast(preflight.blockingReason || 'Restore preflight blocked evaluation.', 'warning');
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
        clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
        const verificationOptions = await collectRestoreVerificationOptions('liteRestore', [...shardsInput.files]);
        if (!verificationOptions.shardFiles.length) {
            throw new Error('No .qcont shard files were detected in selected input.');
        }
        if (verificationOptions.ignoredFileNames.length > 0) {
            logWarning(`Ignored non-restore attachments: ${verificationOptions.ignoredFileNames.join(', ')}`, { isLiteMode: true });
        }

        // Parse shards using shared function
        const shardBytesArr = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
        const shards = await Promise.all(shardBytesArr.map((arr) => parseLifecycleShard(arr, { strict: true })));
        
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

        logRestoreSelectionSummary(result, (message) => log(message, { isLiteMode: true }));
        logVerificationSummary(
            result.authenticity,
            (message) => log(message, { isLiteMode: true }),
            (message) => logWarning(message, { isLiteMode: true }),
            (message) => logSuccess(message, { isLiteMode: true }),
        );

        const { qencBytes, privKey, containerHash, qencOk, qkeyOk } = result;
        
        if (!qencOk || !qkeyOk) {
            showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
                title: 'Lite restore failed',
                cause: 'Recovered container or private key failed integrity verification.',
                artifact: summarizeFileList([...(shardsInput.files || [])], 'Lite restore input set'),
                action: 'Replace corrupted or wrong-cohort shards, then retry Lite Restore.',
            });
            logError('Hash verification failed for container', { isLiteMode: true });
            buildRestoreResultSummary(result, 'liteRestoreResult', {
                liteDecrypt: { containerOk: false, decryptOk: false },
            });
            return;
        }
        
        const { decryptedBlob, metadata } = await decryptFile(qencBytes, privKey);
        const decBytes = await readFileAsUint8Array(decryptedBlob);
        const decHash = await hashBytes(decBytes);
        const integrityOk = metadata.fileHash === decHash;

        if (!integrityOk) {
            showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
                title: 'Lite restore failed',
                cause: 'Decrypted file hash does not match the container metadata.',
                artifact: summarizeFileList([...(shardsInput.files || [])], 'Lite restore input set'),
                action: 'Treat the restore output as invalid; reload the original shard set and retry.',
            });
            logError('File integrity check failed - hashes do not match', { isLiteMode: true });
            buildRestoreResultSummary(result, 'liteRestoreResult', {
                liteDecrypt: { containerOk: true, decryptOk: false },
            });
            return;
        }

        let restoredLabel;
        if (isBundlePayload(decBytes)) {
            const entries = parseBundlePayload(decBytes);
            for (const entry of entries) {
                download(new Blob([entry.bytes]), entry.name);
            }
            restoredLabel = `${entries.length} files bundle`;
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
        
        logSuccess('Container restored successfully from a policy-satisfying archive cohort', { isLiteMode: true });
        clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
        buildRestoreResultSummary(result, 'liteRestoreResult', {
            liteDecrypt: { containerOk: true, decryptOk: true },
        });
        
    } catch (error) {
        buildRestorePolicyFailureSummary(error, 'liteRestoreResult');
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: error,
            artifact: summarizeFileList([...(shardsInput.files || [])], 'Lite restore input set'),
            action: liteRestoreRecoveryAction(error),
        });
        logError(error, { isLiteMode: true });
    } finally {
        setButtonsDisabled(false);
        void updateShardsStatus();
        setTimeout(() => updateLitePipeline('liteViewRestore', null), 2000); // Reset after delay
    }
}

function initLiteTabs() {
    const viewProtect = document.getElementById('liteViewProtect');
    const viewRestore = document.getElementById('liteViewRestore');
    const tabIds = ['liteTabProtect', 'liteTabRestore'];
    const panelByTabId = {
        liteTabProtect: viewProtect,
        liteTabRestore: viewRestore,
    };

    if (viewProtect && viewRestore) initRovingTablist({ tabIds, panelByTabId });
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
                hashBytes(liteKeys.privateKey).then(sk => updateSidebarStatus(pk, sk));
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
    if (!unregisterLiteSessionWipe) {
        unregisterLiteSessionWipe = registerSessionWipeHandler(() => {
            wipeLiteModeSessionSecrets();
        });
    }

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
    const liteAuthPolicy = document.getElementById('liteAuthPolicy');
    const liteAuthPolicyHelp = document.getElementById('liteAuthPolicyHelp');
    const liteAuthPolicyConsequence = document.getElementById('liteAuthPolicyConsequence');
    if (liteN && liteThreshold) {
        liteN.addEventListener('input', updateThresholdDisplay);
        liteThreshold.addEventListener('input', updateThresholdDisplay);
        updateThresholdDisplay(); // Initial calculation
    }
    if (liteAuthPolicy && liteAuthPolicyHelp) {
        const syncLiteAuthPolicyHelp = () => {
            const policyLevel = String(liteAuthPolicy.value || LITE_DEFAULT_AUTH_POLICY_LEVEL);
            liteAuthPolicyHelp.textContent = describeAuthPolicyHelp(policyLevel);
            renderAuthPolicyConsequence(liteAuthPolicyConsequence, policyLevel);
        };
        liteAuthPolicy.addEventListener('change', syncLiteAuthPolicyHelp);
        syncLiteAuthPolicyHelp();
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
        liteShardsInput.addEventListener('change', () => {
            clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
            void updateShardsStatus();
        });
        void updateShardsStatus();
    }
    document.getElementById('liteRestoreExpectedEdSigner')?.addEventListener('input', () => {
        clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
        const files = [...(liteShardsInput?.files || [])];
        if (files.length) {
            void renderRestorePreflightForFiles({
                prefix: 'liteRestore',
                containerId: 'liteRestorePreflightDecision',
                files,
                expectedSignerInput: document.getElementById('liteRestoreExpectedEdSigner'),
            });
        }
    });
    
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
