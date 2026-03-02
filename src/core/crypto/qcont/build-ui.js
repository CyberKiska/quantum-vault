// UI event handler for .qcont shard building (Pro mode)

import { buildQcontShards } from './build.js';
import { log, logError } from '../../features/ui/logging.js';
import { showToast } from '../../features/ui/toast.js';
import { setButtonsDisabled, readFileAsUint8Array, download, validateRsParams } from '../../../utils.js';

export function initQcontBuildUI() {
    const qencForQcontInput = document.getElementById('qencForQcontInput');
    const privKeyForQcontInput = document.getElementById('privKeyForQcontInput');
    const rsNInput = document.getElementById('rsN');
    const rsKInput = document.getElementById('rsK');
    const buildQcontBtn = document.getElementById('buildQcontBtn');

    buildQcontBtn?.addEventListener('click', async () => {
        if (!qencForQcontInput?.files?.[0]) { showToast('Select a .qenc container to split.', 'warning'); return; }
        if (!privKeyForQcontInput?.files?.[0]) { showToast('Select a secret .qkey to split.', 'warning'); return; }
        const privKeyFile = privKeyForQcontInput.files[0];
        if (privKeyFile.size !== 3168) { showToast(`Secret .qkey must be exactly 3168 bytes (got ${privKeyFile.size} B).`, 'warning'); return; }
        setButtonsDisabled(true);
        try {
            const qencBytes = await readFileAsUint8Array(qencForQcontInput.files[0]);
            const privKeyBytes = await readFileAsUint8Array(privKeyForQcontInput.files[0]);
            const n = parseInt(rsNInput.value, 10);
            const k = parseInt(rsKInput.value, 10);
            if (Number.isNaN(n) || Number.isNaN(k)) throw new Error('Invalid parameters');
            if (k < 2 || n <= k) throw new Error('Require 2 <= k < n');
            if (((n - k) % 2) !== 0) throw new Error('(n - k) must be even');
            if (!validateRsParams(n, k)) {
                throw new Error('Invalid RS parameters: require n≥5, 2≤k<n, and (n-k) even');
            }
            const t = k + ((n - k) / 2);
            log(`Building .qcont shards with n=${n}, k=${k}, m=${n - k} (t=${t}), chunkSize=8 MiB ...`);
            const result = await buildQcontShards(qencBytes, privKeyBytes, { n, k });
            const qconts = result.shards;
            const baseName = qencForQcontInput.files[0].name.replace(/\.qenc$/i, '');
            qconts.forEach(({ blob, index }) => {
                const name = `${baseName}.part${index + 1}-of-${qconts.length}.qcont`;
                download(blob, name);
                log(`Saved ${name} (${blob.size} B)`);
            });
            const manifestName = `${baseName}.qvmanifest.json`;
            download(new Blob([result.manifestBytes], { type: 'application/json' }), manifestName);
            log(`Saved ${manifestName} (${result.manifestBytes.length} B) SHA3-512=${result.manifestDigestHex}`);
            log('Manifest can be signed in Quantum Signer / Stellar WebSigner for authenticity verification.');
            log('.qcont shards built. Distribute files across storage providers.');
        } catch (e) { logError(e); } finally { setButtonsDisabled(false); }
    });
}
