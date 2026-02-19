import { encryptFile, decryptFile, hashBytes, generateKeyPair } from '../../crypto/index.js';
import { UserEntropyCollector } from '../../crypto/entropy.js';
import { setButtonsDisabled, readFileAsUint8Array, download, formatFileSize } from '../../../utils.js';
import { createBundlePayloadFromFiles, isBundlePayload, parseBundlePayload } from '../bundle-payload.js';
import { log, logError } from './logging.js';
import { updateShardSelectionStatus } from './shards-status.js';

// Pro mode state
let userEntropyCollected = false;
let entropyCollector = null;
let proShardsStatusSeq = 0;

export function initUI() {
    const el = (id) => document.getElementById(id);

    const privKeyInput = el('privKeyInput');
    const pubKeyInput = el('pubKeyInput');
    const dataFileInput = el('dataFileInput');
    const qencForQcontInput = el('qencForQcontInput');
    const privKeyForQcontInput = el('privKeyForQcontInput');
    const rsNInput = el('rsN');
    const rsKInput = el('rsK');
    const rsTextEl = el('rsText');
    const rsRuleN = el('rsRuleN');
    const rsRuleRange = el('rsRuleRange');
    const rsRuleEven = el('rsRuleEven');
    const rsSegData = el('rsSegData');
    const rsSegParity = el('rsSegParity');
    const rsMarker = el('rsMarker');
    const buildQcontBtn = el('buildQcontBtn');
    const qcontShardsInput = el('qcontShardsInput');
    const restoreQcontBtn = el('restoreQcontBtn');
    const genKeyBtn = el('genKeyBtn');
    const encBtn = el('encBtn');
    const decBtn = el('decBtn');
    const proEncStrategyGroup = el('proEncStrategyGroup');
    const proEncStrategyPerFile = el('proEncStrategyPerFile');
    const proEncryptionWarning = el('proEncryptionWarning');
    // Update Pro file list display
    function updateProFilesList() {
        const filesList = el('proFilesList');
        if (!filesList || !dataFileInput) return;
        
        if (!dataFileInput.files || dataFileInput.files.length === 0) {
            filesList.style.display = 'none';
            if (proEncStrategyGroup) proEncStrategyGroup.style.display = 'none';
            return;
        }
        
        filesList.innerHTML = '';
        for (const file of dataFileInput.files) {
            const item = document.createElement('div');
            item.className = 'file-item';
            item.innerHTML = `<span class="file-name">📄 ${file.name}</span><span class="file-size">${formatFileSize(file.size)}</span>`;
            filesList.appendChild(item);
        }
        filesList.style.display = 'block';
        if (proEncStrategyGroup) {
            proEncStrategyGroup.style.display = dataFileInput.files.length > 1 ? 'block' : 'none';
        }
    }
    
    // Update Pro shards status
    async function updateProShardsStatus() {
        const statusDiv = el('proShardsStatus');
        const statusText = el('proShardsStatusText');
        if (!statusDiv || !statusText || !qcontShardsInput) return;
        const files = [...(qcontShardsInput.files || [])];
        const requestId = ++proShardsStatusSeq;
        await updateShardSelectionStatus({
            files,
            statusDiv,
            statusText,
            actionButton: restoreQcontBtn,
            isCurrent: () => requestId === proShardsStatusSeq
        });
    }

    function updateProEncryptionControls() {
        const hasPublicKey = Boolean(pubKeyInput?.files?.[0]);
        const hasPrivateKey = Boolean(privKeyInput?.files?.[0]);

        if (encBtn) encBtn.disabled = !hasPublicKey;
        if (decBtn) decBtn.disabled = !hasPrivateKey;

        if (!proEncryptionWarning) return;

        let message;
        let stateClass;

        if (!hasPublicKey && !hasPrivateKey) {
            message = 'Load keys in tab "1. Key Management": public key for encryption and private key for decryption.';
            stateClass = 'warning';
        } else if (!hasPublicKey) {
            message = 'Encryption is blocked: load a public key in tab "1. Key Management".';
            stateClass = 'warning';
        } else if (!hasPrivateKey) {
            message = 'Decryption is blocked: load a private key in tab "1. Key Management".';
            stateClass = 'warning';
        } else {
            message = 'Keys are loaded. Encryption and decryption are available.';
            stateClass = 'success';
        }

        proEncryptionWarning.className = `operation-warning ${stateClass}`;
        proEncryptionWarning.innerHTML = `<small>${message}</small>`;
    }

    function getEncryptionStrategy() {
        if (proEncStrategyPerFile?.checked) return 'per-file';
        return 'pack';
    }
    
    // Set up file input event listeners
    dataFileInput?.addEventListener('change', updateProFilesList);
    qcontShardsInput?.addEventListener('change', () => { void updateProShardsStatus(); });
    pubKeyInput?.addEventListener('change', updateProEncryptionControls);
    privKeyInput?.addEventListener('change', updateProEncryptionControls);

    function setConstraintState(element, isValid) {
        if (!element) return;
        element.classList.remove('ok', 'fail');
        element.classList.add(isValid ? 'ok' : 'fail');
    }

    function updateRsHints() {
        if (!rsNInput || !rsKInput) return;
        const n = parseInt(rsNInput.value, 10);
        const k = parseInt(rsKInput.value, 10);
        const hasN = Number.isInteger(n);
        const hasK = Number.isInteger(k);
        const validN = hasN && n >= 5;
        const validRange = hasN && hasK && k >= 2 && k < n;
        const validEven = hasN && hasK && ((n - k) % 2 === 0);
        const allValid = validN && validRange && validEven;

        const m = (hasN && hasK) ? (n - k) : 0;
        const t = allValid ? (k + (m / 2)) : 0;

        setConstraintState(rsRuleN, validN);
        setConstraintState(rsRuleRange, validRange);
        setConstraintState(rsRuleEven, validEven);
        if (buildQcontBtn) buildQcontBtn.disabled = !allValid;

        if (rsTextEl) {
            if (allValid) {
                rsTextEl.textContent = `Total: n=${n}. Data: k=${k}. Parity: m=${m}. Threshold: t=${t}. Need >= t shards to restore.`;
                rsTextEl.classList.remove('warning', 'error');
            } else {
                const reasons = [];
                if (!hasN || !hasK) {
                    reasons.push('enter numeric values for n and k');
                } else {
                    if (!validN) reasons.push('n must be >= 5');
                    if (!validRange) reasons.push('require 2 <= k < n');
                    if (!validEven) reasons.push('(n - k) must be even');
                }
                rsTextEl.textContent = `Invalid configuration: ${reasons.join('; ')}.`;
                rsTextEl.classList.add('warning');
            }
        }

        const safeN = hasN && n > 0 ? n : 1;
        const vizK = hasK ? Math.max(0, Math.min(k, safeN)) : 0;
        const vizM = Math.max(0, safeN - vizK);
        const pctData = (vizK / safeN) * 100;
        const pctParity = (vizM / safeN) * 100;
        const pctT = allValid ? (t / n) * 100 : 0;
        if (rsSegData) rsSegData.style.width = `${Math.max(0, Math.min(100, pctData))}%`;
        if (rsSegParity) rsSegParity.style.width = `${Math.max(0, Math.min(100, pctParity))}%`;
        if (rsMarker) rsMarker.style.left = `${Math.max(0, Math.min(100, pctT))}%`;
        // Segment labels and marker label
        const dataLabel = document.getElementById('rsDataLabel');
        const parityLabel = document.getElementById('rsParityLabel');
        const markerLabel = document.getElementById('rsMarkerLabel');
        if (dataLabel) dataLabel.textContent = hasK ? `k=${k}` : 'k=?';
        if (parityLabel) parityLabel.textContent = (hasN && hasK) ? `m=${m}` : 'm=?';
        if (markerLabel) {
            markerLabel.textContent = allValid ? `t=${t}` : 't=?';
            markerLabel.style.left = `${Math.max(0, Math.min(100, pctT))}%`;
        }
        // Axis ticks 0..n
        const ticks = document.getElementById('rsTicks');
        if (ticks) {
            ticks.innerHTML = '';
            if (hasN && n > 0 && n <= 64) {
                for (let i = 0; i <= n; i++) {
                    const tick = document.createElement('span');
                    tick.className = 'tick';
                    tick.style.left = `${(i / n) * 100}%`;
                    tick.title = String(i);
                    ticks.appendChild(tick);
                }
            }
        }
        const bar = rsSegData && rsSegData.parentElement ? rsSegData.parentElement : null;
        if (bar && bar.classList) bar.classList.toggle('rs-error', !allValid);
    }
    [rsNInput, rsKInput].forEach(elm => elm && elm.addEventListener('input', updateRsHints));
    document.addEventListener('DOMContentLoaded', updateRsHints);
    updateRsHints();
    void updateProShardsStatus();
    updateProEncryptionControls();
    updateProFilesList();

    // Advanced entropy collection
    const advancedEntropyBtn = el('advancedEntropyBtn');
    const entropyStatus = el('entropyStatus');
    const entropyText = el('entropyText');
    const entropyBar = el('entropyBar');

    async function collectAdvancedEntropy() {
        if (entropyCollector) return;

        try {
            entropyStatus.style.display = 'block';
            entropyText.textContent = 'Move mouse, type, resize window... Collecting entropy...';
            advancedEntropyBtn.disabled = true;
            advancedEntropyBtn.textContent = '🎲 Collecting...';

            entropyCollector = new UserEntropyCollector();

            // Update progress with enhanced information including entropy estimation
            const progressInterval = setInterval(() => {
                if (!entropyCollector) {
                    clearInterval(progressInterval);
                    return;
                }
                const progress = entropyCollector.getProgress();
                entropyBar.style.width = `${progress.percentage}%`;
                entropyText.textContent = `Events: ${progress.collected}/${progress.required} (${progress.percentage}%) | Queue: ${progress.queueSize} | Est. Entropy: ${Math.round(progress.estimatedEntropyBits)} bits`;
            }, 200);

            await entropyCollector.startCollection();

            clearInterval(progressInterval);
            userEntropyCollected = true;
            entropyCollector = null;

            entropyText.textContent = '✅ Advanced entropy collected successfully! 64-byte seed ready.';
            entropyBar.style.width = '100%';
            advancedEntropyBtn.textContent = '✅ Entropy Collected';
            advancedEntropyBtn.style.backgroundColor = '#28a745';

        } catch (error) {
            log(`Entropy collection failed: ${error.message}`);
            entropyText.textContent = '❌ Entropy collection failed - will use secure random only';
            advancedEntropyBtn.disabled = false;
            advancedEntropyBtn.textContent = '🎲 Collect Additional Entropy';
        }
    }

    advancedEntropyBtn?.addEventListener('click', collectAdvancedEntropy);

    // --- Event Handlers ---
    genKeyBtn?.addEventListener('click', async () => {
        setButtonsDisabled(true);
        try {
            log('Generating ML-KEM-1024 key pair...');
            
            if (userEntropyCollected) {
                log('Using crypto.getRandomValues() + collected user entropy for enhanced security');
            } else {
                log('Using crypto.getRandomValues() with 64-byte seed (secure default)');
            }
            
            // Generate keys with collected entropy if available
            const { secretKey, publicKey, seedInfo } = await generateKeyPair({ 
                collectUserEntropy: userEntropyCollected 
            });
            
            const skHash = await hashBytes(secretKey);
            const pkHash = await hashBytes(publicKey);
            
            log(`Entropy source: ${seedInfo.source}${seedInfo.hasUserEntropy ? ' (enhanced with user entropy)' : ''}`);
            log(`Private Key: secretKey.qkey (${secretKey.length} B) SHA3-512=${skHash}`);
            log(`Public Key: publicKey.qkey (${publicKey.length} B) SHA3-512=${pkHash}`);
            
            download(new Blob([secretKey]), 'secretKey.qkey');
            download(new Blob([publicKey]), 'publicKey.qkey');
            log('✅ Keys generated and downloaded successfully.');
            
            // Reset entropy collection state
            userEntropyCollected = false;
            if (advancedEntropyBtn) {
                advancedEntropyBtn.textContent = '🎲 Collect Additional Entropy';
                advancedEntropyBtn.style.backgroundColor = '';
                advancedEntropyBtn.disabled = false;
            }
            if (entropyStatus) {
                entropyStatus.style.display = 'none';
            }
            
        } catch (e) { logError(e); } finally {
            setButtonsDisabled(false);
            updateProEncryptionControls();
            updateRsHints();
            void updateProShardsStatus();
        }
    });

    encBtn?.addEventListener('click', async () => {
        if (!pubKeyInput?.files?.[0]) { logError('Please select a public key (.qkey).'); return; }
        if (!dataFileInput?.files?.length) { logError('Please select file(s) to encrypt.'); return; }
        setButtonsDisabled(true);
        try {
            const publicKey = await readFileAsUint8Array(pubKeyInput.files[0]);
            const selectedFiles = [...dataFileInput.files];
            const strategy = getEncryptionStrategy();

            if (strategy === 'pack' && selectedFiles.length > 1) {
                const totalInputSize = selectedFiles.reduce((acc, file) => acc + file.size, 0);
                const { bundleName, bundleBytes, fileCount } = await createBundlePayloadFromFiles(selectedFiles);
                log(`Packing ${fileCount} files (${formatFileSize(totalInputSize)}) into one container...`);

                const encBlob = await encryptFile(bundleBytes, publicKey, bundleName);
                const encBytes = await readFileAsUint8Array(encBlob);
                const encHash = await hashBytes(encBytes);
                const outName = `${bundleName}.qenc`;

                download(encBlob, outName);
                log(`✅ Bundle encrypted: ${outName} (${encBlob.size} B) SHA3-512=${encHash}`);
            } else {
                if (strategy === 'per-file' && selectedFiles.length > 1) {
                    log('Encrypting each selected file into a separate container...');
                }
                for (const file of selectedFiles) {
                    log(`Encrypting file ${file.name} (${file.size} B)...`);
                    const fileBytes = await readFileAsUint8Array(file);
                    const encBlob = await encryptFile(fileBytes, publicKey, file.name);
                    const encBytes = await readFileAsUint8Array(encBlob);
                    const encHash = await hashBytes(encBytes);
                    download(encBlob, `${file.name}.qenc`);
                    log(`✅ File encrypted: ${file.name}.qenc (${encBlob.size} B) SHA3-512=${encHash}`);
                }
            }
        } catch (e) { logError(e); } finally {
            setButtonsDisabled(false);
            updateProEncryptionControls();
            updateRsHints();
            void updateProShardsStatus();
            dataFileInput.value = '';
            updateProFilesList();
        }
    });

    decBtn?.addEventListener('click', async () => {
        if (!privKeyInput?.files?.[0]) { logError('Please select a private key (.qkey).'); return; }
        if (!dataFileInput?.files?.length) { logError('Please select file(s) to decrypt (.qenc).'); return; }
        setButtonsDisabled(true);
        try {
            const secretKey = await readFileAsUint8Array(privKeyInput.files[0]);
            for (const file of dataFileInput.files) {
                if (!file.name.toLowerCase().endsWith('.qenc')) { log(`Skipping file ${file.name} as it is not a .qenc container.`); continue; }
                log(`Decrypting file ${file.name} (${file.size} B)...`);
                const containerBytes = await readFileAsUint8Array(file);
                const containerHash = await hashBytes(containerBytes);
                log(`Container hash: SHA3-512=${containerHash}`);
                const { decryptedBlob, metadata } = await decryptFile(containerBytes, secretKey);
                const decBytes = await readFileAsUint8Array(decryptedBlob);
                const decHash = await hashBytes(decBytes);

                if (isBundlePayload(decBytes)) {
                    const entries = parseBundlePayload(decBytes);
                    for (const entry of entries) {
                        download(new Blob([entry.bytes]), entry.name);
                    }
                    log(`✅ Bundle decrypted: extracted ${entries.length} file(s) from ${file.name}`);
                } else {
                    // Use original filename from metadata if available, otherwise fallback to stripping .qenc
                    let outName = metadata.originalFilename;
                    if (!outName) {
                        // Backward compatibility: strip .qenc extension from input filename
                        outName = file.name.replace(/\.qenc$/i, '');
                    }
                    download(decryptedBlob, outName);
                    log(`✅ File decrypted: ${outName} (${decryptedBlob.size} B)`);
                }
                log(`Original file hash (from metadata): ${metadata.fileHash}`);
                log(`Hash of decrypted content: ${decHash}`);
                if (metadata.fileHash === decHash) log('Hashes match! File integrity verified.'); else logError('WARNING: Hashes do NOT match! File may have been corrupted.');
                log(`Encrypted on (UTC): ${metadata.timestamp}`);
            }
        } catch (e) { logError(e); } finally {
            setButtonsDisabled(false);
            updateProEncryptionControls();
            updateRsHints();
            void updateProShardsStatus();
            dataFileInput.value = '';
            updateProFilesList();
        }
    });

    function initProTabs() {
        const tabs = {
            'proTabIdentity': 'proViewIdentity',
            'proTabEncryption': 'proViewEncryption',
            'proTabDistribution': 'proViewDistribution',
            'proTabRestore': 'proViewRestore'
        };
        
        Object.keys(tabs).forEach(tabId => {
            const tab = document.getElementById(tabId);
            if (!tab) return;
            
            tab.addEventListener('click', () => {
                // Deactivate all
                Object.keys(tabs).forEach(t => {
                     const el = document.getElementById(t);
                     if (el) el.classList.remove('active');
                });
                Object.values(tabs).forEach(v => {
                    const view = document.getElementById(v);
                    if (view) {
                        view.style.display = 'none';
                        view.classList.remove('active');
                    }
                });
                
                // Activate current
                tab.classList.add('active');
                const targetView = document.getElementById(tabs[tabId]);
                if (targetView) {
                    targetView.style.display = 'block';
                    targetView.classList.add('active');
                }
                
                // Force layout update if switching to distribution
                if (tabId === 'proTabDistribution') {
                    setTimeout(() => {
                        // Trigger input event to refresh RS hints
                        rsNInput?.dispatchEvent(new Event('input'));
                    }, 10);
                }
            });
        });
    }

    initProTabs();
}
