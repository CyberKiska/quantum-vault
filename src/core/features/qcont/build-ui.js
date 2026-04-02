// UI event handler for .qcont shard building (Pro mode)

import { buildQcontShards } from '../../../app/crypto-service.js';
import { PRO_DEFAULT_AUTH_POLICY_LEVEL } from '../../crypto/constants.js';
import { describeAuthPolicyHelp } from './auth-policy-help.js';
import { log, logError } from '../ui/logging.js';
import { showToast } from '../ui/toast.js';
import { setButtonsDisabled, readFileAsUint8Array, download, validateRsParams } from '../../../utils.js';

export function initQcontBuildUI() {
    const qencForQcontInput = document.getElementById('qencForQcontInput');
    const privKeyForQcontInput = document.getElementById('privKeyForQcontInput');
    const rsNInput = document.getElementById('rsN');
    const rsKInput = document.getElementById('rsK');
    const authPolicyInput = document.getElementById('proAuthPolicy');
    const authPolicyHelp = document.getElementById('proAuthPolicyHelp');
    const buildQcontBtn = document.getElementById('buildQcontBtn');

    const syncAuthPolicyHelp = () => {
        if (!authPolicyHelp) return;
        authPolicyHelp.textContent = describeAuthPolicyHelp(String(authPolicyInput?.value || PRO_DEFAULT_AUTH_POLICY_LEVEL));
    };
    authPolicyInput?.addEventListener('change', syncAuthPolicyHelp);
    syncAuthPolicyHelp();

    buildQcontBtn?.addEventListener('click', async () => {
        if (!qencForQcontInput?.files?.[0]) { showToast('Select a .qenc container to split.', 'warning'); return; }
        if (!privKeyForQcontInput?.files?.[0]) { showToast('Select a private .qkey to split.', 'warning'); return; }
        const privKeyFile = privKeyForQcontInput.files[0];
        if (privKeyFile.size !== 3168) { showToast(`Private .qkey must be exactly 3168 bytes (got ${privKeyFile.size} B).`, 'warning'); return; }
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
            const authPolicyLevel = String(authPolicyInput?.value || PRO_DEFAULT_AUTH_POLICY_LEVEL);
            log(`Building .qcont shards with n=${n}, k=${k}, m=${n - k} (t=${t}), chunkSize=8 MiB ...`);
            const result = await buildQcontShards(qencBytes, privKeyBytes, { n, k }, { authPolicyLevel });
            const qconts = result.shards;
            const baseName = qencForQcontInput.files[0].name.replace(/\.qenc$/i, '');
            qconts.forEach(({ blob, index }) => {
                const name = `${baseName}.part${index + 1}-of-${qconts.length}.qcont`;
                download(blob, name);
                log(`Saved ${name} (${blob.size} B)`);
            });
            const archiveStateName = `${baseName}.archive-state.json`;
            download(new Blob([result.archiveStateBytes], { type: 'application/json' }), archiveStateName);
            log(`Saved ${archiveStateName} (${result.archiveStateBytes.length} B) SHA3-512=${result.archiveStateDigestHex}`);
            const cohortBindingName = `${baseName}.cohort-binding.json`;
            download(new Blob([result.cohortBindingBytes], { type: 'application/json' }), cohortBindingName);
            log(`Saved ${cohortBindingName} (${result.cohortBindingBytes.length} B) SHA3-512=${result.cohortBindingDigestHex}`);
            const lifecycleBundleName = `${baseName}.lifecycle-bundle.json`;
            download(new Blob([result.lifecycleBundleBytes], { type: 'application/json' }), lifecycleBundleName);
            log(`Saved ${lifecycleBundleName} (${result.lifecycleBundleBytes.length} B) SHA3-512=${result.lifecycleBundleDigestHex}`);
            log(`Archive policy: ${authPolicyLevel}`);
            if (authPolicyLevel === 'integrity-only') {
                log('Next actions: sign the exported archive-state later if you need archive approval, attach detached evidence when ready, or proceed to Restore for integrity-only recovery.');
            } else {
                log('Next actions: sign the exported .archive-state.json file externally, use Attach to merge that detached archive-approval signature into the lifecycle bundle, or proceed to Restore after the evidence is attached.');
            }
            log('Same-state resharing later emits maintenance transition records and preserves archive-approval signatures because the archive-state descriptor bytes stay unchanged.');
            log('.qcont shards built. Distribute files across storage providers.');
        } catch (e) { logError(e); } finally { setButtonsDisabled(false); }
    });
}
