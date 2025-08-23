import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { kmac256 } from '@noble/hashes/sha3-addons.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { split, combine } from 'shamir-secret-sharing';

// --- Constants ---
const MAGIC = new TextEncoder().encode('QVv1');
const DEFAULT_CUSTOMIZATION = 'QuantumVault v1.2.0';

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

async function deriveKeyWithKmac(sharedSecret, salt, metaBytes) {
    const kmacMessage = new Uint8Array(salt.length + metaBytes.length);
    kmacMessage.set(salt, 0);
    kmacMessage.set(metaBytes, salt.length);

    const derivedKey = kmac256(sharedSecret, kmacMessage, 32, DEFAULT_CUSTOMIZATION);
    const aesKey = await crypto.subtle.importKey('raw', derivedKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
    
    derivedKey.fill(0);
    sharedSecret.fill(0);

    return aesKey;
}

function normalizeEncapsulateResult(kemResult) {
    const encapsulatedKey = kemResult.cipherText || kemResult.ciphertext || kemResult.ct;
    const sharedSecret = kemResult.sharedSecret || kemResult.ss;
    if (!encapsulatedKey || !sharedSecret) throw new Error('KEM encapsulation failed: result is missing required fields.');
    return { encapsulatedKey, sharedSecret };
}

async function encryptFile(fileBytes, publicKey) {
    const { encapsulatedKey, sharedSecret } = normalizeEncapsulateResult(await ml_kem1024.encapsulate(publicKey));
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const meta = {
        KEM: 'ML-KEM-1024',
        KDF: 'kmac256',
        AEAD: 'AES-256-GCM',
        fmt: 'QVv1-2-0',
        timestamp: new Date().toISOString(),
        fileHash: await hashBytes(fileBytes)
    };
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const metaLenBytes = new Uint8Array(2);
    new DataView(metaLenBytes.buffer).setUint16(0, metaBytes.length, false);

    const keyLenBytes = new Uint8Array(4);
    new DataView(keyLenBytes.buffer).setUint32(0, encapsulatedKey.length, false);

    const header = new Uint8Array(
        MAGIC.length + keyLenBytes.length + encapsulatedKey.length + iv.length + salt.length + metaLenBytes.length + metaBytes.length
    );
    let p = 0;
    header.set(MAGIC, p); p += MAGIC.length;
    header.set(keyLenBytes, p); p += keyLenBytes.length;
    header.set(encapsulatedKey, p); p += encapsulatedKey.length;
    header.set(iv, p); p += iv.length;
    header.set(salt, p); p += salt.length;
    header.set(metaLenBytes, p); p += metaLenBytes.length;
    header.set(metaBytes, p);

    const aesKey = await deriveKeyWithKmac(sharedSecret, salt, metaBytes);
    
    const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header }, aesKey, fileBytes);
    
    return new Blob([header, new Uint8Array(encryptedData)], { type: 'application/octet-stream' });
}

async function decryptFile(containerBytes, secretKey) {
    const dv = new DataView(containerBytes.buffer, containerBytes.byteOffset);
    let offset = 0;

    const magic = containerBytes.subarray(offset, offset + MAGIC.length);
    if (new TextDecoder().decode(magic) !== new TextDecoder().decode(MAGIC)) {
        throw new Error('Invalid file format (magic bytes mismatch).');
    }
    offset += MAGIC.length;

    const keyLen = dv.getUint32(offset, false);
    offset += 4;
    
    const encapsulatedKey = containerBytes.subarray(offset, offset + keyLen);
    offset += keyLen;
    
    const iv = containerBytes.subarray(offset, offset + 12);
    offset += 12;
    
    const salt = containerBytes.subarray(offset, offset + 16);
    offset += 16;

    const metaLen = dv.getUint16(offset, false);
    offset += 2;

    const metaBytes = containerBytes.subarray(offset, offset + metaLen);
    const metadata = JSON.parse(new TextDecoder().decode(metaBytes));
    offset += metaLen;
    
    const header = containerBytes.subarray(0, offset);
    const encryptedData = containerBytes.subarray(offset);

    const sharedSecret = await ml_kem1024.decapsulate(encapsulatedKey, secretKey);
    if (!sharedSecret || sharedSecret.length === 0) {
        throw new Error('KEM decapsulation failed. The key may be incorrect or the ciphertext corrupted.');
    }
    
    const aesKey = await deriveKeyWithKmac(sharedSecret, salt, metaBytes);
    
    const decryptedData = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header }, aesKey, encryptedData);
    
    return { decryptedBlob: new Blob([decryptedData]), metadata };
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
            log(`Container hash: SHA3-512=${containerHash}`);

            const { decryptedBlob, metadata } = await decryptFile(containerBytes, secretKey);
            const decBytes = await readFileAsUint8Array(decryptedBlob);
            const decHash = await hashBytes(decBytes);
            const outName = file.name.replace(/\.qenc$/i, '');

            download(decryptedBlob, outName);
            log(`✅ File decrypted: ${outName} (${decryptedBlob.size} B)`);
            log(`Original file hash (from metadata): ${metadata.fileHash}`);
            log(`Hash of decrypted content:          ${decHash}`);
            if (metadata.fileHash === decHash) {
                log('✨ Hashes match! File integrity verified.');
            } else {
                logError('🚨 WARNING: Hashes do NOT match! File may have been corrupted.');
            }
            log(`Encrypted on (UTC): ${metadata.timestamp}`);
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
            log(`✂️ Shard created: ${shardName} (${shardBlob.size} B)`);
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
        log('Compare this hash with the original container hash to verify integrity.');

    } catch (e) {
        logError(`Failed to combine container. Ensure the shards are from the same set and meet the threshold. Details: ${e.message}`);
    } finally {
        setButtonsDisabled(false);
    }
});
