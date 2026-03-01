// UI event handlers for .qcont shard restoration (Pro mode)

import { parseShard, restoreFromShards, classifyRestoreInputFiles } from './restore.js';
import { log, logError, logWarning, logSuccess } from '../../features/ui/logging.js';
import { setButtonsDisabled, readFileAsUint8Array, download } from '../../../utils.js';

async function readVerificationOptionsFromDom({
    allFiles = [],
    pinnedPqFingerprintInput,
    expectedSignerInput,
    requireTrustedSignatureInput,
}) {
    const classified = await classifyRestoreInputFiles(allFiles);

    return {
        ...classified,
        pinnedPqFingerprintHex: String(pinnedPqFingerprintInput?.value || '').trim(),
        expectedEd25519Signer: String(expectedSignerInput?.value || '').trim(),
        requireTrustedSignature: requireTrustedSignatureInput?.checked === true,
    };
}

function logVerificationSummary(summary, onLog, onWarn, onSuccess) {
    for (const warning of summary?.warnings || []) {
        onWarn(warning);
    }

    const verification = summary?.verification;
    if (!verification) return;

    const evalSummary = verification.evaluation;
    onLog(`Signature results: ${verification.validCount} valid, ${verification.trustedValidCount} trusted-valid.`);
    onLog(`Signing policy accepted: ${evalSummary.acceptedAlgorithms.join(', ')}.`);

    if (evalSummary.acceptedTrustedCount <= 0) {
        onWarn('No trusted-valid signer identity pinned for this restore.');
    }

    for (const warning of verification.warnings || []) {
        onWarn(warning);
    }

    for (const item of verification.results || []) {
        if (item.ok) {
            if (item.type === 'sig') {
                onSuccess(`Signature OK: ${item.name} (${item.algorithm || 'Ed25519'}, signer ${item.signer || 'unknown'}${item.trusted ? ', trusted' : ''})`);
                continue;
            }
            if (item.type === 'qsig') {
                onSuccess(`Signature OK: ${item.name} (${item.algorithm || 'PQ'}, fp ${item.signerFingerprintHex || 'unknown'}${item.trusted ? ', trusted' : ''})`);
                continue;
            }
            onSuccess(`Signature OK: ${item.name} (${item.algorithm || item.type}${item.trusted ? ', trusted' : ''})`);
            continue;
        }
        onWarn(`Signature failed: ${item.name} (${item.error || 'unknown error'})`);
    }
}

function buildRestoreResultSummary(result, resultPanelId) {
    const panel = document.getElementById(resultPanelId);
    if (!panel) return;

    panel.replaceChildren();
    panel.style.display = 'block';

    const { qencOk, qkeyOk, authenticity } = result;
    const allOk = qencOk && qkeyOk;

    const header = document.createElement('h4');
    header.textContent = 'Restore Result';
    panel.appendChild(header);

    const addItem = (ok, text) => {
        const item = document.createElement('div');
        item.className = `restore-result-item ${ok ? 'ok' : 'fail'}`;
        item.textContent = `${ok ? '✓' : '✗'} ${text}`;
        panel.appendChild(item);
    };

    addItem(qencOk, `Container integrity${qencOk ? ' verified' : ' FAILED'}`);
    addItem(qkeyOk, `Private key integrity${qkeyOk ? ' verified' : ' FAILED'}`);

    const verification = authenticity?.verification;
    if (verification) {
        const { validCount, trustedValidCount, results } = verification;

        for (const item of results || []) {
            if (item.ok) {
                const label = item.type === 'qsig'
                    ? `${item.algorithm || 'PQ'} signature${item.trusted ? ' (trusted)' : ''}`
                    : `${item.algorithm || 'Ed25519'} signature${item.trusted ? ' (trusted)' : ''}`;
                addItem(true, label);
            } else {
                addItem(false, `Signature: ${item.error || 'verification failed'}`);
            }
        }

        if (validCount === 0 && results?.length > 0) {
            addItem(false, 'No valid signatures');
        }
    } else if ((authenticity?.warnings?.length || 0) > 0) {
        const item = document.createElement('div');
        item.className = 'restore-result-item warn';
        item.textContent = '⚠ No signatures verified (unsigned restore)';
        panel.appendChild(item);
    }

    panel.className = `restore-result-panel ${allOk ? 'ok' : 'fail'}`;
}

export function initQcontRestoreUI() {
    const qcontShardsInput = document.getElementById('qcontShardsInput');
    const restoreQcontBtn = document.getElementById('restoreQcontBtn');

    const restorePinnedPqFingerprint = document.getElementById('restorePinnedPqFingerprint');
    const restoreExpectedEdSigner = document.getElementById('restoreExpectedEdSigner');
    const restoreRequireTrustedSig = document.getElementById('restoreRequireTrustedSig');

    restoreQcontBtn?.addEventListener('click', async () => {
        const files = qcontShardsInput?.files;
        if (!files?.length) {
            logError('Select .qcont shards');
            return;
        }

        const resultPanel = document.getElementById('proRestoreResult');
        if (resultPanel) {
            resultPanel.style.display = 'none';
            resultPanel.replaceChildren();
        }

        setButtonsDisabled(true);
        try {
            const allFiles = [...files];
            const verificationOptions = await readVerificationOptionsFromDom({
                allFiles,
                pinnedPqFingerprintInput: restorePinnedPqFingerprint,
                expectedSignerInput: restoreExpectedEdSigner,
                requireTrustedSignatureInput: restoreRequireTrustedSig,
            });
            if (!verificationOptions.shardFiles.length) {
                throw new Error('No .qcont shard files were detected in selected input.');
            }
            if (verificationOptions.ignoredFileNames.length > 0) {
                logWarning(`Ignored non-restore attachments: ${verificationOptions.ignoredFileNames.join(', ')}`);
            }

            const shardBytesArr = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
            const shards = shardBytesArr.map((bytes) => parseShard(bytes, { strict: true }));

            const result = await restoreFromShards(shards, {
                onLog: (msg) => log(msg),
                onError: (msg) => logError(msg),
                onWarn: (msg) => logWarning(msg),
                verification: verificationOptions,
            });

            log(`Selected manifest digest: ${result.manifestDigestHex}`);
            log(`Manifest source: ${result.manifestSource}`);
            logVerificationSummary(
                result.authenticity,
                (msg) => log(msg),
                (msg) => logWarning(msg),
                (msg) => logSuccess(msg),
            );

            const { qencBytes, privKey, containerId, containerHash, privateKeyHash, recoveredQencHash, recoveredPrivHash, qencOk, qkeyOk } = result;
            log(`Recovered .qenc SHA3-512=${recoveredQencHash} (expected ${containerHash})`);
            log(`Recovered .qkey SHA3-512=${recoveredPrivHash}${privateKeyHash ? ` (expected ${privateKeyHash})` : ''}`);

            const qencBlob = new Blob([qencBytes], { type: 'application/octet-stream' });
            const qkeyBlob = new Blob([privKey], { type: 'application/octet-stream' });
            const qencName = `${containerId}.recovered.qenc`;
            const qkeyName = `${containerId}.recovered.secretKey.qkey`;

            if (qencOk && qkeyOk) {
                download(qencBlob, qencName);
                download(qkeyBlob, qkeyName);
                logSuccess('Recovered .qenc and .qkey from authenticated shard cohort.');
            } else {
                logError('Hash mismatch detected. Automatic download is blocked. Review artifacts manually.');
                const logEl = document.getElementById('log');
                const a1 = document.createElement('a');
                a1.href = URL.createObjectURL(qencBlob);
                a1.download = qencName;
                a1.textContent = `Manual download: ${qencName}`;
                a1.target = '_blank';
                a1.rel = 'noopener';

                const a2 = document.createElement('a');
                a2.href = URL.createObjectURL(qkeyBlob);
                a2.download = qkeyName;
                a2.textContent = `Manual download: ${qkeyName}`;
                a2.target = '_blank';
                a2.rel = 'noopener';

                logEl.appendChild(a1);
                logEl.appendChild(document.createTextNode('\n'));
                logEl.appendChild(a2);
                logEl.appendChild(document.createTextNode('\n'));
            }

            buildRestoreResultSummary(result, 'proRestoreResult');
        } catch (error) {
            logError(error);
        } finally {
            setButtonsDisabled(false);
        }
    });
}

export async function collectRestoreVerificationOptions(prefix = 'restore', files = []) {
    const pinnedPqFingerprintInput = document.getElementById(`${prefix}PinnedPqFingerprint`);
    const expectedSignerInput = document.getElementById(`${prefix}ExpectedEdSigner`);
    const requireTrustedSignatureInput = document.getElementById(`${prefix}RequireTrustedSig`);

    return readVerificationOptionsFromDom({
        allFiles: files,
        pinnedPqFingerprintInput,
        expectedSignerInput,
        requireTrustedSignatureInput,
    });
}
