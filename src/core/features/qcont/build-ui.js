// UI event handler for .qcont shard building (Pro mode)

import { buildQcontShards } from '../../../app/crypto-service.js';
import { PRO_DEFAULT_AUTH_POLICY_LEVEL } from '../../crypto/constants.js';
import { isSupportedAuthPolicyLevel } from '../../crypto/manifest/auth-policy.js';
import { ML_KEM_1024_PRIVATE_KEY_SIZE } from '../../crypto/mlkem.js';
import { describeAuthPolicyHelp, renderAuthPolicyConsequence } from './auth-policy-help.js';
import { evaluateRsParams } from './rs-params-display.js';
import { clearInlineError, showInlineError } from '../ui/inline-error.js';
import { renderDecisionCard } from '../ui/decision-card.js';
import { log, logError } from '../ui/logging.js';
import { showToast } from '../ui/toast.js';
import { setWorkflowBusy, readFileAsUint8Array, download } from '../../../utils.js';

const SPLIT_INLINE_ERROR_ID = 'proSplitInlineError';

function evaluateSplitReadiness({
    qencForQcontInput,
    privKeyForQcontInput,
    rsNInput,
    rsKInput,
    authPolicyInput,
}) {
    const qencFile = qencForQcontInput?.files?.[0] || null;
    const privKeyFile = privKeyForQcontInput?.files?.[0] || null;
    const geometry = evaluateRsParams(rsNInput?.value, rsKInput?.value);
    const authPolicyLevel = String(authPolicyInput?.value || '').trim();
    const policyOk = isSupportedAuthPolicyLevel(authPolicyLevel);

    const prerequisites = [
        {
            id: 'qenc',
            ok: Boolean(qencFile),
            text: qencFile
                ? `Encrypted .qenc selected: ${qencFile.name}`
                : 'Select the encrypted .qenc container to split.',
        },
        {
            id: 'private-key',
            ok: Boolean(privKeyFile) && privKeyFile.size === ML_KEM_1024_PRIVATE_KEY_SIZE,
            text: privKeyFile
                ? privKeyFile.size === ML_KEM_1024_PRIVATE_KEY_SIZE
                    ? `Private .qkey artifact selected: ${privKeyFile.name} (${ML_KEM_1024_PRIVATE_KEY_SIZE} B).`
                    : `Private .qkey artifact must be exactly ${ML_KEM_1024_PRIVATE_KEY_SIZE} bytes (got ${privKeyFile.size} B).`
                : `Select a private .qkey artifact (${ML_KEM_1024_PRIVATE_KEY_SIZE} B).`,
        },
        {
            id: 'geometry',
            ok: geometry.valid,
            text: geometry.valid
                ? `Shard geometry valid: n=${geometry.n}, k=${geometry.k}, m=${geometry.m}, threshold t=${geometry.t}.`
                : `Shard geometry invalid: ${geometry.reasons.join('; ') || 'enter valid n and k values'}.`,
        },
        {
            id: 'policy',
            ok: policyOk,
            text: policyOk
                ? `Archive authenticity policy selected: ${authPolicyLevel}.`
                : 'Select a supported archive authenticity policy.',
        },
    ];

    return {
        ready: prerequisites.every((item) => item.ok),
        prerequisites,
        qencFile,
        privKeyFile,
        geometry,
        authPolicyLevel: policyOk ? authPolicyLevel : PRO_DEFAULT_AUTH_POLICY_LEVEL,
    };
}

const PREREQ_LABELS = {
    qenc: 'Container',
    'private-key': 'Private key',
    geometry: 'Geometry',
    policy: 'Policy',
};

function renderSplitReadiness(readiness, buildQcontBtn) {
    const panel = document.getElementById('proSplitReadiness');
    if (!panel) return;

    const tone = readiness.ready ? 'ok' : 'fail';
    const rows = readiness.prerequisites.map((item) => ({
        label: PREREQ_LABELS[item.id] || item.id,
        value: item.text,
        tone: item.ok ? 'ok' : 'fail',
    }));

    renderDecisionCard(
        panel,
        {
            title: 'Split readiness',
            tone,
            primaryOutcome: readiness.ready
                ? 'Ready to build successor shards.'
                : 'Split is blocked until all prerequisites pass.',
            rows,
        },
        {
            extraRootClasses: ['operation-readiness', 'split-readiness'],
            ariaLive: 'polite',
            rootDataTestId: 'split-readiness',
            testIds: {
                primary: 'split-readiness-text',
                rows: 'split-prerequisites',
            },
        }
    );

    if (buildQcontBtn) {
        buildQcontBtn.disabled = !readiness.ready;
    }
}

export function initQcontBuildUI() {
    const qencForQcontInput = document.getElementById('qencForQcontInput');
    const privKeyForQcontInput = document.getElementById('privKeyForQcontInput');
    const rsNInput = document.getElementById('rsN');
    const rsKInput = document.getElementById('rsK');
    const authPolicyInput = document.getElementById('proAuthPolicy');
    const authPolicyHelp = document.getElementById('proAuthPolicyHelp');
    const authPolicyConsequence = document.getElementById('proAuthPolicyConsequence');
    const buildQcontBtn = document.getElementById('buildQcontBtn');

    const selectedArtifactSummary = () => {
        const names = [
            qencForQcontInput?.files?.[0]?.name,
            privKeyForQcontInput?.files?.[0]?.name,
        ].filter(Boolean);
        return names.length > 0 ? names.join(' + ') : 'Pro Split input set';
    };

    const clearSplitErrorAndUpdate = () => {
        clearInlineError(SPLIT_INLINE_ERROR_ID);
        updateSplitReadiness();
    };

    const updateSplitReadiness = () => {
        const readiness = evaluateSplitReadiness({
            qencForQcontInput,
            privKeyForQcontInput,
            rsNInput,
            rsKInput,
            authPolicyInput,
        });
        renderSplitReadiness(readiness, buildQcontBtn);
        return readiness;
    };

    const syncAuthPolicyHelp = () => {
        const policyLevel = String(authPolicyInput?.value || PRO_DEFAULT_AUTH_POLICY_LEVEL);
        if (authPolicyHelp) {
            authPolicyHelp.textContent = describeAuthPolicyHelp(policyLevel);
        }
        renderAuthPolicyConsequence(authPolicyConsequence, policyLevel);
    };
    authPolicyInput?.addEventListener('change', () => {
        clearInlineError(SPLIT_INLINE_ERROR_ID);
        syncAuthPolicyHelp();
        updateSplitReadiness();
    });
    qencForQcontInput?.addEventListener('change', clearSplitErrorAndUpdate);
    privKeyForQcontInput?.addEventListener('change', clearSplitErrorAndUpdate);
    rsNInput?.addEventListener('input', clearSplitErrorAndUpdate);
    rsKInput?.addEventListener('input', clearSplitErrorAndUpdate);
    syncAuthPolicyHelp();
    updateSplitReadiness();

    buildQcontBtn?.addEventListener('click', async () => {
        const readiness = updateSplitReadiness();
        if (!readiness.ready) {
            const firstBlocking = readiness.prerequisites.find((item) => !item.ok);
            showInlineError(SPLIT_INLINE_ERROR_ID, {
                title: 'Split blocked',
                cause: firstBlocking?.text || 'Split prerequisites are incomplete.',
                artifact: selectedArtifactSummary(),
                action: 'Correct the failed prerequisite shown above; private-key/container matching is verified during the split build.',
            });
            showToast(firstBlocking?.text || 'Split prerequisites are incomplete.', 'warning');
            return;
        }
        setWorkflowBusy('proViewDistribution', true);
        try {
            clearInlineError(SPLIT_INLINE_ERROR_ID);
            const qencBytes = await readFileAsUint8Array(readiness.qencFile);
            const privKeyBytes = await readFileAsUint8Array(readiness.privKeyFile);
            const { n, k, t } = readiness.geometry;
            const authPolicyLevel = readiness.authPolicyLevel;
            log(`Building .qcont shards with n=${n}, k=${k}, m=${n - k} (t=${t}), chunkSize=8 MiB ...`);
            const result = await buildQcontShards(qencBytes, privKeyBytes, { n, k }, { authPolicyLevel });
            const qconts = result.shards;
            const baseName = readiness.qencFile.name.replace(/\.qenc$/i, '');
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
        } catch (e) {
            showInlineError(SPLIT_INLINE_ERROR_ID, {
                title: 'Split failed',
                cause: e,
                artifact: selectedArtifactSummary(),
                action: 'Verify the .qenc and private .qkey pair, keep the shard geometry valid, then retry Split.',
            });
            logError(e);
        } finally { setWorkflowBusy('proViewDistribution', false); updateSplitReadiness(); }
    });
}
