import { encryptFile, decryptFile, hashBytes, generateKeyPair } from '../../crypto/index.js';
import { UserEntropyCollector } from '../../crypto/entropy.js';
import { setButtonsDisabled, readFileAsUint8Array, download } from '../../../utils.js';

// Pro mode state
let userEntropyCollected = false;
let entropyCollector = null;

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
    const rsSegData = el('rsSegData');
    const rsSegParity = el('rsSegParity');
    const rsMarker = el('rsMarker');
    const buildQcontBtn = el('buildQcontBtn');
    const qcontShardsInput = el('qcontShardsInput');
    const restoreQcontBtn = el('restoreQcontBtn');
    const genKeyBtn = el('genKeyBtn');
    const encBtn = el('encBtn');
    const decBtn = el('decBtn');
    const logEl = el('log');

    const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

    function log(msg) {
        const line = document.createElement('span');
        line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        logEl.appendChild(line);
        logEl.appendChild(document.createTextNode('\n'));
        logEl.scrollTop = logEl.scrollHeight;
    }
    function logError(err) {
        const text = (err && err.message) ? err.message : (typeof err === 'string' ? err : String(err));
        const errorSpan = document.createElement('span');
        errorSpan.className = 'error';
        errorSpan.textContent = `[${new Date().toLocaleTimeString()}] ERROR: ${text}`;
        logEl.appendChild(errorSpan);
        logEl.appendChild(document.createTextNode('\n'));
        logEl.scrollTop = logEl.scrollHeight;
    }
    // setButtonsDisabled, readFileAsUint8Array, download are imported from utils.js
    function logDownloadLink(blob, filename, label) {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.textContent = label || `Download ${filename}`;
        a.target = '_blank';
        a.rel = 'noopener';
        logEl.appendChild(a);
        logEl.appendChild(document.createTextNode('\n'));
    }

    function updateRsHints() {
        if (!rsNInput || !rsKInput) return;
        let n = parseInt(rsNInput.value, 10); if (Number.isNaN(n)) n = 0;
        let k = parseInt(rsKInput.value, 10); if (Number.isNaN(k)) k = 0;
        if (n < 0) n = 0;
        if (k < 0) k = 0;
        if (k >= n) n = k + 1;
        const m = n - k;
        const even = (m % 2) === 0;
        const allowedFailures = even ? (m / 2) : Math.floor(m / 2);
        const t = k + allowedFailures;
        if (rsTextEl) {
            const warnEven = even ? '' : ' (adjust n or k so that n − k is even)';
            const warnEdge = (n === 4 && k === 2) ? ' WARNING: configuration n=4,k=2 is known to be unstable. Use n≥5 (e.g., n=5,k=3).' : '';
            rsTextEl.textContent = `Total: n=${n}. Data: k=${k}. Parity: m=${m}. Threshold: t=${t}. Need ≥ t shards to restore.${warnEven}${warnEdge}`;
        }
        const pctData = n ? (k / n) * 100 : 0;
        const pctParity = n ? (m / n) * 100 : 0;
        const pctT = n ? (t / n) * 100 : 0;
        if (rsSegData) rsSegData.style.width = `${Math.max(0, Math.min(100, pctData))}%`;
        if (rsSegParity) rsSegParity.style.width = `${Math.max(0, Math.min(100, pctParity))}%`;
        if (rsMarker) rsMarker.style.left = `${Math.max(0, Math.min(100, pctT))}%`;
        // Segment labels and marker label
        const dataLabel = document.getElementById('rsDataLabel');
        const parityLabel = document.getElementById('rsParityLabel');
        const markerLabel = document.getElementById('rsMarkerLabel');
        if (dataLabel) dataLabel.textContent = `k=${k} (${Math.round((k / Math.max(1, n)) * 100)}%)`;
        if (parityLabel) parityLabel.textContent = `m=${m} (${Math.round((m / Math.max(1, n)) * 100)}%)`;
        if (markerLabel) {
            markerLabel.textContent = `t=${t}`;
            markerLabel.style.left = `${Math.max(0, Math.min(100, pctT))}%`;
        }
        // Axis ticks 0..n
        const ticks = document.getElementById('rsTicks');
        if (ticks) {
            ticks.innerHTML = '';
            if (n > 0) {
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
        if (bar && bar.classList) bar.classList.toggle('rs-error', !even);
    }
    [rsNInput, rsKInput].forEach(elm => elm && elm.addEventListener('input', updateRsHints));
    document.addEventListener('DOMContentLoaded', updateRsHints);
    updateRsHints();

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
            
        } catch (e) { logError(e); } finally { setButtonsDisabled(false); }
    });

    encBtn?.addEventListener('click', async () => {
        if (!pubKeyInput?.files?.[0]) { logError('Please select a public key (.qkey).'); return; }
        if (!dataFileInput?.files?.length) { logError('Please select file(s) to encrypt.'); return; }
        setButtonsDisabled(true);
        try {
            const publicKey = await readFileAsUint8Array(pubKeyInput.files[0]);
            for (const file of dataFileInput.files) {
                log(`Encrypting file ${file.name} (${file.size} B)...`);
                const fileBytes = await readFileAsUint8Array(file);
                const encBlob = await encryptFile(fileBytes, publicKey, file.name);
                const encBytes = await readFileAsUint8Array(encBlob);
                const encHash = await hashBytes(encBytes);
                download(encBlob, `${file.name}.qenc`);
                log(`✅ File encrypted: ${file.name}.qenc (${encBlob.size} B) SHA3-512=${encHash}`);
            }
        } catch (e) { logError(e); } finally { setButtonsDisabled(false); dataFileInput.value = ''; }
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

                // Use original filename from metadata if available, otherwise fallback to stripping .qenc
                let outName = metadata.originalFilename;
                if (!outName) {
                    // Backward compatibility: strip .qenc extension from input filename
                    outName = file.name.replace(/\.qenc$/i, '');
                }

                download(decryptedBlob, outName);
                log(`✅ File decrypted: ${outName} (${decryptedBlob.size} B)`);
                log(`Original file hash (from metadata): ${metadata.fileHash}`);
                log(`Hash of decrypted content: ${decHash}`);
                if (metadata.fileHash === decHash) log('Hashes match! File integrity verified.'); else logError('WARNING: Hashes do NOT match! File may have been corrupted.');
                log(`Encrypted on (UTC): ${metadata.timestamp}`);
            }
        } catch (e) { logError(e); } finally { setButtonsDisabled(false); dataFileInput.value = ''; }
    });

}

