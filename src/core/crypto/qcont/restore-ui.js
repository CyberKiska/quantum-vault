// UI event handlers for .qcont shard restoration (Pro mode)

import { parseShard, restoreFromShards, classifyRestoreInputFiles } from './restore.js';
import { log, logError, logWarning } from '../../features/ui/logging.js';
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

function logVerificationSummary(summary, onLog, onWarn) {
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
                onLog(`Signature OK: ${item.name} (${item.algorithm || 'Ed25519'}, signer ${item.signer || 'unknown'}${item.trusted ? ', trusted' : ''})`);
                continue;
            }
            if (item.type === 'qsig') {
                onLog(`Signature OK: ${item.name} (${item.algorithm || 'PQ'}, fp ${item.signerFingerprintHex || 'unknown'}${item.trusted ? ', trusted' : ''})`);
                continue;
            }
            onLog(`Signature OK: ${item.name} (${item.algorithm || item.type}${item.trusted ? ', trusted' : ''})`);
            continue;
        }
        onWarn(`Signature failed: ${item.name} (${item.error || 'unknown error'})`);
    }
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
            logVerificationSummary(result.authenticity, (msg) => log(msg), (msg) => logWarning(msg));

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
                log('Recovered .qenc and .qkey from authenticated shard cohort.');
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
