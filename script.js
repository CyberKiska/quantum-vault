// --- Libraries ---
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { split, combine } from 'shamir-secret-sharing';

// --- DOM Elements ---
const allButtons = document.querySelectorAll('button');
const privKeyInput = document.getElementById('privKeyInput');
const pubKeyInput = document.getElementById('pubKeyInput');
const dataFileInput = document.getElementById('dataFileInput');
const containerToSplitInput = document.getElementById('containerToSplitInput');
const shardsToCombineInput = document.getElementById('shardsToCombineInput');
const shamirSharesInput = document.getElementById('shamirShares');
const shamirThresholdInput = document.getElementById('shamirThreshold');
const genKeyBtn = document.getElementById('genKeyBtn');
const encBtn = document.getElementById('encBtn');
const decBtn = document.getElementById('decBtn');
const splitBtn = document.getElementById('splitBtn');
const combineBtn = document.getElementById('combineBtn');
const logEl = document.getElementById('log');

// --- Utility Functions ---
const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

function log(msg) {
    logEl.textContent += `[${new Date().toLocaleTimeString()}] ${msg}\n`;
    logEl.scrollTop = logEl.scrollHeight;
}

function logError(msg) {
    logEl.innerHTML += `<span class="error">[${new Date().toLocaleTimeString()}] ERROR: ${msg}</span>\n`;
    logEl.scrollTop = logEl.scrollHeight;
}

function setButtonsDisabled(disabled) {
    allButtons.forEach(button => button.disabled = disabled);
}

function download(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(a.href);
    a.remove();
}

async function readFileAsUint8Array(file) {
    return new Uint8Array(await file.arrayBuffer());
}

async function hashBytes(bytes) {
    return toHex(sha3_512(bytes));
}

// --- Core Cryptography ---
async function deriveAesKey(sharedSecret, salt) {
    const derived = hkdf(sha3_512, sharedSecret, salt, new Uint8Array(0), 32);
    return crypto.subtle.importKey('raw', derived, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptFile(fileBytes, publicKey) {
    const { cipherText: encapsulatedKey, sharedSecret } = await ml_kem1024.encapsulate(publicKey);
    if (!encapsulatedKey) {
        throw new Error('Encapsulation failed. The returned key is undefined.');
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await deriveAesKey(sharedSecret, salt);
    const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, fileBytes);
    
    const magicBytes = new TextEncoder().encode('QGv1');
    const keyLenBytes = new Uint8Array(4);
    new DataView(keyLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);

    const header = new Uint8Array([...magicBytes, ...keyLenBytes, ...encapsulatedKey, ...iv, ...salt]);
    return new Blob([header, new Uint8Array(encryptedData)], { type: 'application/octet-stream' });
}

async function decryptFile(containerBytes, secretKey) {
    const magicBytes = new TextDecoder().decode(containerBytes.slice(0, 4));
    if (magicBytes !== 'QGv1') throw new Error('Invalid file format or file is corrupted.');

    let offset = 4;
    const keyLen = new DataView(containerBytes.buffer).getUint32(offset, false);
    offset += 4;
    
    const encapsulatedKey = containerBytes.slice(offset, offset + keyLen);
    offset += keyLen;
    
    const iv = containerBytes.slice(offset, offset + 12);
    offset += 12;
    
    const salt = containerBytes.slice(offset, offset + 16);
    offset += 16;
    
    const encryptedData = containerBytes.slice(offset);

    const sharedSecret = await ml_kem1024.decapsulate(encapsulatedKey, secretKey);
    const aesKey = await deriveAesKey(sharedSecret, salt);
    const decryptedData = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encryptedData);
    return new Blob([decryptedData]);
}

// --- Event Handlers ---
genKeyBtn.addEventListener('click', async () => {
    setButtonsDisabled(true);
    try {
        log('Generating ML-KEM Kyber 1024 key pair...');
        const { secretKey, publicKey } = await ml_kem1024.keygen();
        
        const skHash = await hashBytes(secretKey);
        const pkHash = await hashBytes(publicKey);
        
        log(`Private Key: secretKey.qkey (${secretKey.length} B) SHA3-512=${skHash}`);
        log(`Public Key: publicKey.qkey (${publicKey.length} B) SHA3-512=${pkHash}`);
        
        download(new Blob([secretKey]), 'secretKey.qkey');
        download(new Blob([publicKey]), 'publicKey.qkey');
        
        log('✅ Keys generated and downloaded successfully.');
    } catch (e) {
        logError(e.message);
    } finally {
        setButtonsDisabled(false);
    }
});

encBtn.addEventListener('click', async () => {
    if (!pubKeyInput.files[0]) { logError('Please select a public key (.qkey).'); return; }
    if (!dataFileInput.files.length) { logError('Please select file(s) to encrypt.'); return; }
    
    setButtonsDisabled(true);
    try {
        const publicKey = await readFileAsUint8Array(pubKeyInput.files[0]);
        
        for (const file of dataFileInput.files) {
            log(`Encrypting file ${file.name} (${file.size} B)...`);
            const fileBytes = await readFileAsUint8Array(file);
            const fileHash = await hashBytes(fileBytes);
            log(`  Source file hash: SHA3-512=${fileHash}`);

            const encBlob = await encryptFile(fileBytes, publicKey);
            const encBytes = await readFileAsUint8Array(encBlob);
            const encHash = await hashBytes(encBytes);
            
            download(encBlob, `${file.name}.qenc`);
            log(`✅ File encrypted: ${file.name}.qenc (${encBlob.size} B) SHA3-512=${encHash}`);
        }
    } catch (e) {
        logError(e.message);
    } finally {
        setButtonsDisabled(false);
        dataFileInput.value = '';
    }
});

decBtn.addEventListener('click', async () => {
    if (!privKeyInput.files[0]) { logError('Please select a private key (.qkey).'); return; }
    if (!dataFileInput.files.length) { logError('Please select file(s) to decrypt (.qenc).'); return; }

    setButtonsDisabled(true);
    try {
        const secretKey = await readFileAsUint8Array(privKeyInput.files[0]);
        
        for (const file of dataFileInput.files) {
            if (!file.name.toLowerCase().endsWith('.qenc')) {
                log(`Skipping file ${file.name} as it is not a .qenc container.`);
                continue;
            }
            log(`Decrypting file ${file.name} (${file.size} B)...`);
            const containerBytes = await readFileAsUint8Array(file);
            const containerHash = await hashBytes(containerBytes);
            log(`  Container hash: SHA3-512=${containerHash}`);

            const decBlob = await decryptFile(containerBytes, secretKey);
            const decBytes = await readFileAsUint8Array(decBlob);
            const decHash = await hashBytes(decBytes);
            const outName = file.name.replace(/\.qenc$/i, '');

            download(decBlob, outName);
            log(`✅ File decrypted: ${outName} (${decBlob.size} B) SHA3-512=${decHash}`);
        }
    } catch (e) {
        logError(`Failed to decrypt file. Check if the key is correct. Details: ${e.message}`);
    } finally {
        setButtonsDisabled(false);
        dataFileInput.value = '';
    }
});

splitBtn.addEventListener('click', async () => {
    const file = containerToSplitInput.files[0];
    if (!file) { logError('Please select a .qenc container to split.'); return; }

    setButtonsDisabled(true);
    try {
        const shares = parseInt(shamirSharesInput.value, 10);
        const threshold = parseInt(shamirThresholdInput.value, 10);

        if (isNaN(shares) || isNaN(threshold) || threshold > shares || threshold < 2 || shares < 2) {
            throw new Error('Invalid N and T parameters. Ensure T >= 2 and N >= T.');
        }
        
        log(`Splitting container ${file.name} into ${shares} parts with a threshold of ${threshold}...`);
        const containerBytes = await readFileAsUint8Array(file);
        const containerHash = await hashBytes(containerBytes);
        log(`  Container hash: SHA3-512=${containerHash}`);

        const shards = await split(containerBytes, shares, threshold);
        
        const baseName = file.name.replace(/\.qenc$/i, '');
        shards.forEach((shardBytes, idx) => {
            const shardBlob = new Blob([shardBytes]);
            const shardName = `${baseName}-${idx + 1}.qshard`;
            download(shardBlob, shardName);
            log(`  ✂️ Shard created: ${shardName} (${shardBlob.size} B)`);
        });
        log('✅ Splitting process completed successfully.');

    } catch (e) {
        logError(e.message);
    } finally {
        setButtonsDisabled(false);
    }
});

combineBtn.addEventListener('click', async () => {
    const files = shardsToCombineInput.files;
    if (!files.length) { logError('Please select .qshard files to combine.'); return; }
    
    setButtonsDisabled(true);
    try {
        const threshold = parseInt(shamirThresholdInput.value, 10);
        if (files.length < threshold) {
            throw new Error(`Not enough shards to reconstruct. A minimum of ${threshold} is required, but ${files.length} were selected.`);
        }
        log(`Combining container from ${files.length} shards...`);
        
        const shards = await Promise.all([...files].map(f => readFileAsUint8Array(f)));
        
        const reconstructedBytes = await combine(shards);
        const reconstructedBlob = new Blob([reconstructedBytes]);

        const reconHash = await hashBytes(reconstructedBytes);
        const baseName = files[0].name.replace(/-\d+\.qshard$/i, '');
        const outName = `${baseName}.qenc`;

        download(reconstructedBlob, outName);
        log(`✅ Container combined: ${outName} (${reconstructedBlob.size} B) SHA3-512=${reconHash}`);
        log('  Compare this hash with the original container hash to verify integrity.');

    } catch (e) {
        logError(`Failed to combine container. Ensure the shards are from the same set and meet the threshold. Details: ${e.message}`);
    } finally {
        setButtonsDisabled(false);
    }
});
