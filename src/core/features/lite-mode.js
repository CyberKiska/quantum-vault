// --- Lite Mode - Simplified Interface ---
// Lite mode is a thin UI wrapper over the same cryptographic operations as Pro mode

import {
    encryptFile,
    decryptFile,
    generateKeyPair,
    hashBytes,
    buildQcontShards,
    parseLifecycleShard,
    zeroizeParsedLifecycleShard,
    restoreFromShards,
    assessShardSelection,
} from '../../app/crypto-service.js';
import { wipeBytes, wipeRestoreResult } from '../crypto/zeroize.js';
import {
    buildRestorePolicyFailureSummary,
    buildRestoreResultSummary,
    clearRestorePreflightCard,
    collectRestoreVerificationOptions,
    logRestoreSelectionSummary,
    logVerificationSummary,
    renderRestorePreflightForFiles,
} from './qcont/restore-ui.js';
import { createSuccessorShardInputRefreshController } from './qcont/successor-workflow-input.js';
import { resetSuccessorSelectionSession } from './qcont/successor-selection-ui.js';
import { registerSessionWipeHandler } from '../../app/session-wipe.js';
import { readFileAsUint8Array, setWorkflowBusy } from '../../utils.js';
import { createBundlePayloadFromFiles, isBundlePayload, parseBundlePayload } from './bundle-payload.js';
import {
    log,
    logError,
    logSuccess,
    logRestoration,
    logRestorationSuccess,
    logWarning,
} from './ui/logging.js';
import {
    createLiteArchiveKeyLifecycle,
    LiteArchiveCreationCancelledError,
    wipeLiteArchiveKeyPair,
} from './lite-key-lifecycle.js';
import { showToast } from './ui/toast.js';
import { clearInlineError, showInlineError } from './ui/inline-error.js';
import { clearArtifactIntakeTable } from './ui/artifact-intake.js';
import { initRovingTablist } from './ui/tabs.js';
import { updateSidebarStatus } from './ui/ui.js';
import { describeAuthPolicyHelp, renderAuthPolicyConsequence } from './qcont/auth-policy-help.js';
import { buildRestoreRecoveryAction } from './qcont/restore-recovery-action.js';
import { isSupportedAuthPolicyLevel } from '../crypto/manifest/auth-policy.js';
import {
    BROWSER_EXPORT_STATES,
    MAX_BROWSER_EXPORT_AGGREGATE_BYTES,
    MAX_BROWSER_EXPORT_ARTIFACT_BYTES,
    MAX_BROWSER_EXPORT_ARTIFACTS,
    MAX_BROWSER_EXPORT_NAME_BYTES,
    createBrowserExportSession,
    digestBrowserExportSourceSha3_512,
} from '../export/browser-export-session.js';
import {
    LITE_MAX_SHARDS,
    LITE_MAX_THRESHOLD_PERCENT,
    LITE_MIN_SHARDS,
    LITE_MIN_THRESHOLD_PERCENT,
    calculateParametersFromThreshold,
    getAchievableThresholdsForN,
    getAlternativeNRecommendations,
} from './lite-threshold-params.js';

// Lite retains at most one explicitly authorized successful archive keypair,
// solely for an immediate custody decision. It must be exported or explicitly
// discarded before another fresh operation-local pair can be created.
const liteArchiveKeys = createLiteArchiveKeyLifecycle();
let liteCreateInProgress = false;
let isLiteMode = true; // Default to Lite mode
const liteRestoreShardRefresh = createSuccessorShardInputRefreshController({
  prefix: 'liteRestore',
  inputId: 'liteShardsInput',
  statusDivId: 'shardsStatus',
  statusTextId: 'shardsStatusText',
  actionButtonId: 'liteRestoreBtn',
  intakeContainerId: 'liteRestoreArtifactIntake',
  intakeLabel: 'Lite restore artifact intake',
  intakeWorkflow: 'lite-restore',
  preflightContainerId: 'liteRestorePreflightDecision',
  expectedSignerInputId: 'liteRestoreExpectedEdSigner',
});
let liteLogCollapsed = true;
let unregisterLiteSessionWipe = null;
const LITE_RESTORE_INLINE_ERROR_ID = 'liteRestoreInlineError';
const LITE_EXPORT_RANDOM_BYTES = 16;
const LITE_MAX_INPUT_FILES = 256;
// With the worst supported n/k expansion (24/2 = 12), this leaves at least
// 32 MiB inside the immutable 128 MiB browser-export aggregate profile for
// QVPACK framing, QENC overhead, shares, and embedded lifecycle artifacts.
const LITE_MAX_INPUT_AGGREGATE_BYTES = 8 * 1024 * 1024;
const LITE_OBJECT_URL_REVOKE_DELAY_MS = 1000;

/** Ephemeral controller. Exact output names exist only in its private in-memory map. */
let liteExportController = null;
let liteExportPreparationKind = null;
let liteExportEpoch = 0;
let liteReimportVerification = null;
let liteRestoreOperation = null;
let liteTabController = null;
let boundLiteAuthPolicyControl = null;
let boundLiteRestoreExpectedSignerControl = null;
let boundLiteRestorePreflightRoot = null;
let boundLiteNControl = null;
let boundLiteThresholdControl = null;
let boundLiteRawKeyAcknowledgement = null;
let boundLiteDownloadKeysButton = null;
let boundLiteDiscardKeysButton = null;
let boundLiteKeyDecisionRoot = null;
let liteKeyDecisionObserver = null;
let boundLitePlaintextInput = null;
let boundLiteRestoreInput = null;
let nativeLiteInputValueSetter = null;
let nativeLiteInputFilesGetter = null;
let liteRawKeyBackupGrant = false;
let boundLiteExternalCopyWarningPanel = null;
let boundLiteExternalCopyWarningSummary = null;
// Only the exact controls wired by initLiteMode() are accepted by a custody
// handoff. A same-ID DOM replacement has no trusted event handlers and could
// otherwise strand an operation key behind inert controls.
const boundLiteExportControls = new WeakSet();
// URL -> Blob byte length. The aggregate remains inside the same immutable
// 128 MiB publication profile even if revocation is fault-injected.
const liteOutstandingObjectUrls = new Map();
let liteObjectUrlAccountingCompromised = false;
let liteKeyBackupVerifiedAfterLastCreate = false;
let liteKeyBackupCancelledAfterLastCreate = false;
let liteKeyBackupExternalCopyMayExistAfterLastCreate = false;
let liteRawKeyBackupAuthorizedAfterLastCreate = false;
let liteLastCreateShardCount = 0;
// Monotonic, nonsecret hazard facts for this document lifetime. Session
// boundaries synchronously invalidate controllers/DOM and request cleanup, but
// in-flight work settles cooperatively and browser-managed downloads cannot be
// proven deleted, including across a back-forward-cache pagehide.
let liteArchiveExternalCopyHazard = false;
let litePrivateKeyExternalCopyHazard = false;
let liteRestorePlaintextExternalCopyHazard = false;

function resetLiteRawKeyBackupAcknowledgement() {
    liteRawKeyBackupGrant = false;
    if (boundLiteRawKeyAcknowledgement instanceof HTMLInputElement) {
        try { boundLiteRawKeyAcknowledgement.checked = false; } catch { /* Continue security settlement. */ }
    }
    const current = document.getElementById('liteRetainRawKeyAck');
    if (current instanceof HTMLInputElement && current !== boundLiteRawKeyAcknowledgement) {
        try { current.checked = false; } catch { /* Untrusted replacement is not authority. */ }
    }
}

function clearLiteFileInputNode(input) {
    if (!(input instanceof HTMLInputElement)) return true;
    try {
        if (typeof nativeLiteInputValueSetter === 'function') {
            nativeLiteInputValueSetter.call(input, '');
        } else {
            input.value = '';
        }
    } catch { /* Verify and quarantine below. */ }
    try {
        const files = typeof nativeLiteInputFilesGetter === 'function'
            ? nativeLiteInputFilesGetter.call(input)
            : input.files;
        if (Number(files?.length || 0) === 0) return true;
    } catch { /* Quarantine below. */ }
    try { input.disabled = true; } catch { /* Continue quarantine. */ }
    try { input.remove(); } catch { /* Caller drops bound authority regardless. */ }
    return false;
}

function clearBoundLiteFileInput(boundInput, id) {
    const boundCleared = clearLiteFileInputNode(boundInput);
    const current = document.getElementById(id);
    if (current instanceof HTMLInputElement && current !== boundInput) {
        clearLiteFileInputNode(current);
    }
    return boundCleared;
}

function isLiteElementVisiblyReachable(element) {
    if (!(element instanceof HTMLElement) || !element.isConnected) return false;
    try {
        const rects = element.getClientRects();
        if (rects.length === 0 || ![...rects].some((rect) => rect.width > 0 && rect.height > 0)) {
            return false;
        }
        for (let current = element; current instanceof HTMLElement; current = current.parentElement) {
            if (
                current.hidden ||
                current.hasAttribute('inert') ||
                current.classList.contains('initially-hidden')
            ) {
                return false;
            }
            const style = getComputedStyle(current);
            const opacity = Number.parseFloat(style.opacity);
            if (
                style.display === 'none' ||
                style.visibility === 'hidden' ||
                style.visibility === 'collapse' ||
                style.pointerEvents === 'none' ||
                (Number.isFinite(opacity) && opacity <= 0)
            ) {
                return false;
            }
        }
        return true;
    } catch {
        return false;
    }
}

function hasUsableLiteKeyDecisionControls({ requireReachable = false } = {}) {
    const downloadButton = document.getElementById('liteDownloadKeysBtn');
    const discardButton = document.getElementById('liteDiscardKeysBtn');
    const structurallyUsable =
        downloadButton === boundLiteDownloadKeysButton &&
        discardButton === boundLiteDiscardKeysButton &&
        boundLiteKeyDecisionRoot instanceof HTMLElement &&
        boundLiteKeyDecisionRoot.isConnected &&
        downloadButton.parentElement === boundLiteKeyDecisionRoot &&
        discardButton.parentElement === boundLiteKeyDecisionRoot &&
        downloadButton instanceof HTMLButtonElement &&
        discardButton instanceof HTMLButtonElement &&
        downloadButton.isConnected &&
        discardButton.isConnected;
    if (!structurallyUsable || !requireReachable) return structurallyUsable;
    return !downloadButton.disabled &&
        !discardButton.disabled &&
        isLiteElementVisiblyReachable(downloadButton) &&
        isLiteElementVisiblyReachable(discardButton);
}

function discardRetainedLiteKeyForUnavailableControls() {
    if (!liteArchiveKeys.hasRetainedKeyPair()) return false;
    let retainedKeyPair = null;
    try {
        retainedKeyPair = liteArchiveKeys.takeRetainedKeyPair();
        if (!retainedKeyPair) return false;
        wipeLiteArchiveKeyPair(retainedKeyPair);
        retainedKeyPair = null;
        liteKeyBackupVerifiedAfterLastCreate = false;
        liteKeyBackupCancelledAfterLastCreate = true;
        liteKeyBackupExternalCopyMayExistAfterLastCreate = false;
        resetLiteRawKeyBackupAcknowledgement();
        return true;
    } catch {
        return false;
    } finally {
        try { wipeLiteArchiveKeyPair(retainedKeyPair); } catch { /* Continue fail-closed settlement. */ }
    }
}

function hasUsableLiteRawKeyAcknowledgement() {
    const acknowledgement = document.getElementById('liteRetainRawKeyAck');
    return acknowledgement === boundLiteRawKeyAcknowledgement &&
        acknowledgement instanceof HTMLInputElement &&
        acknowledgement.type === 'checkbox' &&
        acknowledgement.isConnected;
}

function snapshotLiteRawKeyBackupAcknowledgement() {
    const acknowledgement = document.getElementById('liteRetainRawKeyAck');
    let authorized = false;
    try {
        authorized = hasUsableLiteRawKeyAcknowledgement() &&
            acknowledgement.checked === true &&
            liteRawKeyBackupGrant === true;
        return authorized;
    } finally {
        // The trusted-event grant is one shot even when a hostile accessor
        // faults while the Create configuration is being snapshotted.
        resetLiteRawKeyBackupAcknowledgement();
    }
}

function boundedIntegerInput(input, minimum, maximum) {
    const value = Number(input?.value);
    return Number.isInteger(value) && value >= minimum && value <= maximum
        ? value
        : null;
}

function readLiteCreateConfiguration() {
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    if (
        nInput !== boundLiteNControl ||
        thresholdInput !== boundLiteThresholdControl ||
        !(nInput instanceof HTMLInputElement) ||
        !(thresholdInput instanceof HTMLInputElement) ||
        nInput.type !== 'number' ||
        thresholdInput.type !== 'number' ||
        !nInput.isConnected ||
        !thresholdInput.isConnected
    ) {
        return null;
    }
    const n = boundedIntegerInput(
        nInput,
        LITE_MIN_SHARDS,
        LITE_MAX_SHARDS,
    );
    const thresholdPercent = boundedIntegerInput(
        thresholdInput,
        LITE_MIN_THRESHOLD_PERCENT,
        LITE_MAX_THRESHOLD_PERCENT,
    );
    if (n === null || thresholdPercent === null) return null;
    return { n, thresholdPercent };
}

function liteInputSelectionWithinProfile(fileList) {
    const count = Number(fileList?.length || 0);
    if (!Number.isSafeInteger(count) || count === 0 || count > LITE_MAX_INPUT_FILES) return false;
    let aggregate = 0;
    for (let index = 0; index < count; index += 1) {
        const file = fileList[index];
        const size = Number(file?.size);
        if (!Number.isSafeInteger(size) || size < 0) return false;
        if (aggregate > LITE_MAX_INPUT_AGGREGATE_BYTES - size) return false;
        aggregate += size;
    }
    return true;
}

function refreshLiteRawKeyBackupControl() {
    const acknowledgement = document.getElementById('liteRetainRawKeyAck');
    if (
        acknowledgement !== boundLiteRawKeyAcknowledgement ||
        !(acknowledgement instanceof HTMLInputElement) ||
        acknowledgement.type !== 'checkbox' ||
        !acknowledgement.isConnected
    ) {
        liteRawKeyBackupGrant = false;
        if (acknowledgement instanceof HTMLInputElement) {
            acknowledgement.checked = false;
            acknowledgement.disabled = true;
        }
        return;
    }
    const disabled = liteCreateInProgress ||
        liteExportController !== null ||
        liteReimportVerification !== null ||
        liteRestoreOperation !== null ||
        liteArchiveKeys.hasRetainedKeyPair();
    acknowledgement.disabled = disabled;
    if (disabled) resetLiteRawKeyBackupAcknowledgement();
}

function createOpaqueLiteExportBasename() {
    const randomBytes = new Uint8Array(LITE_EXPORT_RANDOM_BYTES);
    try {
        globalThis.crypto.getRandomValues(randomBytes);
        return `qv-${Array.from(randomBytes, (value) => value.toString(16).padStart(2, '0')).join('')}`;
    } finally {
        wipeBytes(randomBytes);
    }
}

function exportSourceByteLength(source) {
    if (source instanceof Uint8Array) return source.byteLength;
    if (source instanceof Blob) return source.size;
    throw new Error('Browser export plan rejected.');
}

function privateExportArtifactMap(plan) {
    const byExactName = new Map();
    plan.forEach((artifact, index) => {
        byExactName.set(artifact.name, {
            index,
            byteLength: exportSourceByteLength(artifact.source),
        });
    });
    return byExactName;
}

function exportRoleLabel(role) {
    switch (role) {
        case 'shard': return 'Shard artifact';
        case 'archive-state': return 'Archive-state artifact';
        case 'lifecycle-bundle': return 'Lifecycle-bundle artifact';
        case 'private-key': return 'Private-key artifact';
        case 'public-key': return 'Public-key artifact';
        default: return 'Artifact';
    }
}

function exportStateLabel(state) {
    switch (state) {
        case BROWSER_EXPORT_STATES.READY: return 'Ready for individual download';
        case BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED: return 'Download requested; re-import not verified';
        case BROWSER_EXPORT_STATES.VERIFIED: return 'Exact name, size, and SHA3-512 digest verified';
        case BROWSER_EXPORT_STATES.FAILED: return 'Verification failed; retry required';
        case BROWSER_EXPORT_STATES.CANCELLED: return 'Cancelled; best-effort cleanup attempted';
        default: return 'Unavailable';
    }
}

function requireLiteExportControls({ requireReachable = false, preparation = false } = {}) {
    const controls = {
        panel: document.getElementById('liteExportSessionPanel'),
        title: document.getElementById('liteExportSessionTitle'),
        status: document.getElementById('liteExportSessionStatus'),
        rowsRoot: document.getElementById('liteExportSessionRows'),
        reimportInput: document.getElementById('liteExportReimportInput'),
        reimportButton: document.getElementById('liteExportReimportBtn'),
        cancelButton: document.getElementById('liteExportCancelBtn'),
    };
    const structuralControls = [
        controls.panel,
        controls.title,
        controls.status,
        controls.rowsRoot,
    ];
    const interactiveControls = [
        controls.reimportInput,
        controls.reimportButton,
        controls.cancelButton,
    ];
    if (
        structuralControls.some((control) => !(control instanceof HTMLElement) || !control.isConnected) ||
        !(controls.reimportInput instanceof HTMLInputElement) ||
        controls.reimportInput.type !== 'file' ||
        !(controls.reimportButton instanceof HTMLButtonElement) ||
        !(controls.cancelButton instanceof HTMLButtonElement) ||
        [...structuralControls, ...interactiveControls].some(
            (control) => !control.isConnected || !boundLiteExportControls.has(control),
        ) ||
        [...structuralControls.slice(1), ...interactiveControls].some(
            (control) => !controls.panel.contains(control),
        )
    ) {
        throw new Error('Lite export controls are unavailable.');
    }
    if (requireReachable) {
        const panelVisible = isLiteElementVisiblyReachable(controls.panel);
        const cancelReachable = !controls.cancelButton.disabled &&
            isLiteElementVisiblyReachable(controls.cancelButton);
        const reimportReachable = preparation || (
            !controls.reimportButton.disabled &&
            isLiteElementVisiblyReachable(controls.reimportButton)
        );
        if (!panelVisible || !cancelReachable || !reimportReachable) {
            throw new Error('Lite export controls are not reachable.');
        }
    }
    return controls;
}

function renderLiteExportSnapshot(kind, snapshot, { active = true } = {}) {
    const {
        panel,
        title,
        status,
        rowsRoot,
        reimportInput,
        reimportButton,
        cancelButton,
    } = requireLiteExportControls();

    const rows = snapshot?.rows || [];
    const verifiedCount = rows.filter((row) => row.state === BROWSER_EXPORT_STATES.VERIFIED).length;
    panel.hidden = false;
    title.textContent = kind === 'key-backup'
        ? 'Verify optional 1-of-1 key artifacts'
        : 'Verify required archive artifacts';
    if (snapshot?.complete) {
        status.textContent = `${verifiedCount} of ${rows.length} artifacts passed exact name, size, and SHA3-512 digest re-import verification. Download requests are not durable-storage proof.`;
    } else if (kind === 'key-backup') {
        status.textContent = `${verifiedCount} of ${rows.length} optional key artifacts re-import verified. The threshold archive is already complete; cancel this optional export if a 1-of-1 copy is not required.`;
    } else {
        status.textContent = `${verifiedCount} of ${rows.length} required archive artifacts re-import verified. Creation remains incomplete until every row is verified.`;
    }

    const totalsByRole = new Map();
    rows.forEach((row) => totalsByRole.set(row.role, (totalsByRole.get(row.role) || 0) + 1));
    const ordinalsByRole = new Map();
    rowsRoot.replaceChildren();
    rows.forEach((row) => {
        const ordinal = (ordinalsByRole.get(row.role) || 0) + 1;
        ordinalsByRole.set(row.role, ordinal);

        const item = document.createElement('li');
        item.className = 'lite-export-session-row';
        item.setAttribute('data-testid', `lite-export-row-${row.index}`);

        const identity = document.createElement('span');
        identity.className = 'lite-export-session-role';
        identity.textContent = `${exportRoleLabel(row.role)} ${ordinal} of ${totalsByRole.get(row.role)}`;

        const state = document.createElement('span');
        state.className = 'lite-export-session-state';
        state.textContent = exportStateLabel(row.state);

        const action = document.createElement('button');
        action.type = 'button';
        action.className = 'button secondary small';
        action.setAttribute('data-testid', `lite-export-row-action-${row.index}`);
        if (row.state === BROWSER_EXPORT_STATES.READY) {
            action.textContent = 'Download';
        } else if (
            row.state === BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED ||
            row.state === BROWSER_EXPORT_STATES.FAILED
        ) {
            action.textContent = 'Retry';
        } else {
            action.textContent = row.state === BROWSER_EXPORT_STATES.VERIFIED ? 'Verified' : 'Unavailable';
            action.disabled = true;
        }
        if (!active) action.disabled = true;
        if (active) {
            action.addEventListener('click', (event) => {
                if (!event.isTrusted || !action.isConnected || !rowsRoot.contains(action)) return;
                void requestLiteExportArtifact(row.index);
            });
        }

        item.append(identity, state, action);
        rowsRoot.appendChild(item);
    });

    const reimportEnabled = active && liteReimportVerification === null;
    reimportInput.disabled = !reimportEnabled;
    reimportButton.disabled = !reimportEnabled;
    reimportButton.classList.toggle('initially-hidden', !active);
    cancelButton.disabled = !active;
    cancelButton.textContent = kind === 'key-backup'
        ? 'Cancel & discard pending 1-of-1 key'
        : 'Cancel incomplete archive export';
    cancelButton.classList.toggle('initially-hidden', !active);
    panel.classList.remove('initially-hidden');
    if (active) requireLiteExportControls({ requireReachable: true });
    return true;
}

function renderLiteExportPreparation(kind) {
    liteExportPreparationKind = kind;
    renderLiteExportSnapshot(kind, { complete: false, rows: [] }, { active: false });
    const { status, cancelButton } = requireLiteExportControls();
    status.textContent = 'Preparing a bounded artifact set in temporary browser memory. No download has been requested. Cancellation is cooperative and may wait for bounded work already running outside this workflow to return.';
    cancelButton.disabled = false;
    cancelButton.classList.remove('initially-hidden');
    requireLiteExportControls({ requireReachable: true, preparation: true });
}

function revokeLiteObjectUrl(objectUrl) {
    if (!liteOutstandingObjectUrls.has(objectUrl)) return true;
    try {
        URL.revokeObjectURL(objectUrl);
        liteOutstandingObjectUrls.delete(objectUrl);
        return true;
    } catch {
        // Keep failed revocations tracked so a later cleanup boundary retries.
        return false;
    }
}

function revokeAllLiteObjectUrls() {
    for (const objectUrl of [...liteOutstandingObjectUrls.keys()]) {
        revokeLiteObjectUrl(objectUrl);
    }
}

function outstandingLiteObjectUrlBytes() {
    let aggregate = 0;
    for (const byteLength of liteOutstandingObjectUrls.values()) {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            aggregate > MAX_BROWSER_EXPORT_AGGREGATE_BYTES - byteLength
        ) {
            return MAX_BROWSER_EXPORT_AGGREGATE_BYTES + 1;
        }
        aggregate += byteLength;
    }
    return aggregate;
}

function requestOneBrowserDownload(source, exactName, signal) {
    let objectUrl = null;
    let objectUrlTracked = false;
    let objectUrlByteLength = 0;
    let anchor = null;
    try {
        if (signal?.aborted) throw new Error('Browser export request cancelled.');
        const blob = source instanceof Blob ? source : new Blob([source], { type: 'application/octet-stream' });
        objectUrlByteLength = blob.size;
        if (
            liteOutstandingObjectUrls.size >= MAX_BROWSER_EXPORT_ARTIFACTS ||
            outstandingLiteObjectUrlBytes() > MAX_BROWSER_EXPORT_AGGREGATE_BYTES - blob.size
        ) {
            throw new Error('Browser export request exceeded the fixed object-URL profile.');
        }
        objectUrl = URL.createObjectURL(blob);
        liteOutstandingObjectUrls.set(objectUrl, blob.size);
        objectUrlTracked = true;
        anchor = document.createElement('a');
        anchor.href = objectUrl;
        anchor.download = exactName;
        anchor.addEventListener('click', (event) => {
            if (signal?.aborted) event.preventDefault();
        }, { capture: true });
        if (signal?.aborted) throw new Error('Browser export request cancelled.');
        // Chromium permits a user-gesture download from a detached anchor. Do
        // not expose the exact private output name or Blob capability to DOM
        // observers, mutation tooling, or page serialization.
        anchor.click();
        return objectUrl;
    } catch (error) {
        if (objectUrl) {
            if (!objectUrlTracked) {
                try { objectUrlTracked = liteOutstandingObjectUrls.has(objectUrl); } catch { /* Fall through. */ }
            }
            if (objectUrlTracked) {
                if (!revokeLiteObjectUrl(objectUrl)) {
                    // The request failed before a durable per-row association;
                    // without that predecessor link no retry is safe.
                    liteObjectUrlAccountingCompromised = true;
                }
            } else {
                // Bookkeeping failed after capability creation. The URL is not
                // in the Map, so bypass the tracked-only helper and revoke it
                // directly before propagating the fixed request failure.
                try {
                    URL.revokeObjectURL(objectUrl);
                } catch {
                    liteObjectUrlAccountingCompromised = true;
                    // If direct revocation also faults, make one bounded attempt
                    // to retain the capability for later cleanup accounting.
                    try {
                        liteOutstandingObjectUrls.set(objectUrl, objectUrlByteLength);
                    } catch {
                        // No further publication is safe when a created
                        // capability can be neither revoked nor accounted for.
                        liteObjectUrlAccountingCompromised = true;
                    }
                }
            }
            runLiteUiBestEffort(refreshLiteExternalCopyWarning);
        }
        throw error;
    } finally {
        if (anchor) {
            try { anchor.removeAttribute('href'); } catch { /* Continue scrub. */ }
            try { anchor.removeAttribute('download'); } catch { /* Continue scrub. */ }
            try { anchor.remove(); } catch { /* Detached cleanup is best effort. */ }
        }
    }
}

function failRequestedExportRowForRetry(controller, index) {
    try {
        controller.session.verify(index, { name: '', digest: new Uint8Array(64) });
    } catch {
        // Deliberately move a requested-but-unverified row to the explicit
        // failed state. The subsequent retry is a new user gesture.
    }
}

function runLiteUiBestEffort(action) {
    try {
        action();
    } catch {
        // Security state transitions must not depend on mutable DOM adapters.
    }
}

async function requestLiteExportArtifact(index) {
    const controller = liteExportController;
    if (!controller) return;
    if (controller.requesting.has(index)) {
        runLiteUiBestEffort(() => {
            logWarning('An artifact download request is already active; the duplicate action was ignored.', { isLiteMode: true });
        });
        return;
    }
    controller.requesting.add(index);
    try {
        requireLiteExportControls({ requireReachable: true });
        const row = controller.session.snapshot().rows[index];
        if (!row) throw new Error('Browser export state rejected.');
        if (liteObjectUrlAccountingCompromised) {
            throw new Error('Browser export capability accounting is unavailable.');
        }
        // Conservatively record the hazard before attempting publication. A
        // false-positive warning is safer than an unreported browser-managed
        // copy if any later adapter step faults.
        if (controller.kind === 'key-backup' && row.role === 'private-key') {
            controller.privateKeyRequestAttempted = true;
            litePrivateKeyExternalCopyHazard = true;
        }
        if (controller.kind === 'archive') {
            liteArchiveExternalCopyHazard = true;
        }
        // Publication is forbidden unless the exact persistent warning surface
        // accepts and visibly renders the conservative hazard state.
        refreshLiteExternalCopyWarning({ strict: true });
        const priorObjectUrl = controller.objectUrls.get(index);
        if (priorObjectUrl) {
            if (!revokeLiteObjectUrl(priorObjectUrl)) {
                throw new Error('Browser export object-URL cleanup is incomplete.');
            }
            controller.objectUrls.delete(index);
            const priorTimer = controller.objectUrlTimers.get(index);
            if (priorTimer !== undefined) clearTimeout(priorTimer);
            controller.objectUrlTimers.delete(index);
        }
        if (row.state === BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED) {
            failRequestedExportRowForRetry(controller, index);
            controller.session.retry(index);
        } else if (row.state === BROWSER_EXPORT_STATES.FAILED) {
            controller.session.retry(index);
        }
        controller.artifactRequestAttempted = true;
        await controller.session.request(index, ({ name, source, signal }) => {
            const requestedObjectUrl = requestOneBrowserDownload(source, name, signal);
            let timer;
            try {
                controller.objectUrls.set(index, requestedObjectUrl);
                timer = setTimeout(() => {
                    if (
                        revokeLiteObjectUrl(requestedObjectUrl) &&
                        controller.objectUrls.get(index) === requestedObjectUrl
                    ) {
                        controller.objectUrls.delete(index);
                    }
                    if (controller.objectUrlTimers.get(index) === timer) {
                        controller.objectUrlTimers.delete(index);
                    }
                    runLiteUiBestEffort(refreshLiteExternalCopyWarning);
                }, LITE_OBJECT_URL_REVOKE_DELAY_MS);
                controller.objectUrlTimers.set(index, timer);
            } catch (error) {
                if (timer !== undefined) clearTimeout(timer);
                try { controller.objectUrls.delete(index); } catch { /* Continue cleanup. */ }
                try { controller.objectUrlTimers.delete(index); } catch { /* Continue cleanup. */ }
                if (!revokeLiteObjectUrl(requestedObjectUrl)) {
                    liteObjectUrlAccountingCompromised = true;
                }
                runLiteUiBestEffort(refreshLiteExternalCopyWarning);
                throw error;
            }
        });
    } catch {
        runLiteUiBestEffort(() => {
            logError('Artifact download request failed; retry the affected row.', { isLiteMode: true });
        });
    } finally {
        controller.requesting.delete(index);
        if (liteExportController === controller) {
            runLiteUiBestEffort(() => {
                renderLiteExportSnapshot(controller.kind, controller.session.snapshot());
            });
        }
    }
}

function completeLiteExportSession(controller, snapshot) {
    if (liteExportController !== controller || !snapshot.complete) return;
    // End controller authority before any best-effort adapter or DOM cleanup.
    liteExportController = null;
    try { revokeAllLiteObjectUrls(); } catch { /* Continue security settlement. */ }
    runLiteUiBestEffort(refreshLiteExternalCopyWarning);
    try { controller.objectUrls.clear(); } catch { /* Continue security settlement. */ }
    try {
        for (const timer of controller.objectUrlTimers.values()) clearTimeout(timer);
    } catch { /* Continue security settlement. */ }
    try { controller.objectUrlTimers.clear(); } catch { /* Continue security settlement. */ }
    try { controller.requesting.clear(); } catch { /* Continue security settlement. */ }
    try { controller.exactArtifacts.clear(); } catch { /* Continue security settlement. */ }

    if (controller.kind === 'archive') {
        let settlementFailed = false;
        let keyRetentionSuppressed = false;
        try {
            if (controller.retainRawKeyForBackup) {
                if (hasUsableLiteKeyDecisionControls()) {
                    liteArchiveKeys.retainAfterSuccess(controller.keyOperation);
                } else {
                    liteArchiveKeys.completeWithoutRetention(controller.keyOperation);
                    keyRetentionSuppressed = true;
                }
            } else {
                liteArchiveKeys.completeWithoutRetention(controller.keyOperation);
            }
        } catch {
            // A lifecycle invariant failure must never strand an untracked
            // operation key after the artifact session has completed.
            try {
                liteArchiveKeys.discardOperation(controller.keyOperation);
            } catch {
                try { liteArchiveKeys.cancelActiveOperation(); } catch { /* Already failed closed. */ }
            }
            settlementFailed = true;
        }
        controller.keyOperation = null;
        liteCreateInProgress = false;
        liteExportPreparationKind = null;
        if (settlementFailed) {
            runLiteUiBestEffort(clearLiteExportSessionPanel);
            runLiteUiBestEffort(refreshLiteKeyAvailability);
            runLiteUiBestEffort(updateCreateShardsButton);
            runLiteUiBestEffort(() => {
                logError('Archive export verified, but key-custody settlement failed closed; controller authority ended and best-effort key and URL cleanup was attempted.', { isLiteMode: true });
            });
            return;
        }
        liteKeyBackupCancelledAfterLastCreate = false;
        liteKeyBackupExternalCopyMayExistAfterLastCreate = false;
        runLiteUiBestEffort(() => {
            renderLiteExportChecklistAfterCreate(
                controller.shardCount,
                controller.retainRawKeyForBackup,
            );
        });
        if (keyRetentionSuppressed) {
            liteKeyBackupCancelledAfterLastCreate = true;
            runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
            runLiteUiBestEffort(() => {
                logWarning('Authorized optional key retention was suppressed because its exact bound decision controls were unavailable; the verified threshold archive remains the recovery path.', { isLiteMode: true });
            });
        }
        runLiteUiBestEffort(() => {
            log('Archive creation completed only after every required artifact passed exact name, size, and SHA3-512 digest re-import verification. Durable storage remains an operator check.', { isLiteMode: true });
        });
    } else {
        liteCreateInProgress = false;
        liteExportPreparationKind = null;
        liteKeyBackupVerifiedAfterLastCreate = true;
        liteKeyBackupCancelledAfterLastCreate = false;
        liteKeyBackupExternalCopyMayExistAfterLastCreate = true;
        runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
        runLiteUiBestEffort(() => {
            log('Both optional 1-of-1 key artifacts passed exact name, size, and SHA3-512 digest re-import verification; controller and key ownership settled and best-effort URL cleanup was attempted. Browser-managed downloads and any reported pending URL capabilities remain outside that proof.', { isLiteMode: true });
        });
    }

    runLiteUiBestEffort(clearLiteExportSessionPanel);
    runLiteUiBestEffort(refreshLiteKeyAvailability);
    runLiteUiBestEffort(updateCreateShardsButton);
}

function setLiteReimportControlsEnabled(enabled) {
    const input = document.getElementById('liteExportReimportInput');
    const button = document.getElementById('liteExportReimportBtn');
    if (input) input.disabled = !enabled;
    if (button) button.disabled = !enabled;
}

function releaseLiteReimportFileRefs(files) {
    if (!Array.isArray(files)) return;
    files.length = 0;
}

function checkedLiteReimportAggregate(files) {
    let aggregate = 0;
    for (const file of files) {
        if (
            !file ||
            typeof file.name !== 'string' ||
            file.name.length === 0 ||
            file.name.length > MAX_BROWSER_EXPORT_NAME_BYTES ||
            !Number.isSafeInteger(file.size) ||
            file.size < 0 ||
            file.size > MAX_BROWSER_EXPORT_ARTIFACT_BYTES ||
            aggregate > MAX_BROWSER_EXPORT_AGGREGATE_BYTES - file.size
        ) {
            return null;
        }
        aggregate += file.size;
    }
    return aggregate;
}

function abortLiteReimportVerification() {
    try { liteReimportVerification?.abortController.abort(); } catch { /* Token release occurs in finally. */ }
}

async function verifyLiteExportReimports(files) {
    const controller = liteExportController;
    if (!controller || !Array.isArray(files) || files.length === 0) {
        releaseLiteReimportFileRefs(files);
        return;
    }
    if (liteReimportVerification) {
        releaseLiteReimportFileRefs(files);
        logWarning('Artifact re-import verification is already active; the additional selection was ignored.', { isLiteMode: true });
        showToast('Wait for the active artifact verification to finish or cancel it.', 'warning');
        return;
    }

    const requestedRows = controller.session.snapshot().rows.filter(
        (row) => row.state === BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED,
    ).length;
    if (
        files.length > MAX_BROWSER_EXPORT_ARTIFACTS ||
        files.length > requestedRows ||
        checkedLiteReimportAggregate(files) === null
    ) {
        releaseLiteReimportFileRefs(files);
        logError('Artifact re-import selection exceeded the fixed verification profile.', { isLiteMode: true });
        showToast('Artifact re-import selection was rejected by the fixed verification profile.', 'error');
        return;
    }

    const verification = {
        controller,
        abortController: new AbortController(),
    };
    liteReimportVerification = verification;
    let rejected = false;

    try {
        runLiteUiBestEffort(() => setLiteReimportControlsEnabled(false));
        for (const file of files) {
            if (
                verification.abortController.signal.aborted ||
                liteExportController !== controller
            ) {
                return;
            }
            const expected = controller.exactArtifacts.get(file.name);
            if (!expected) {
                rejected = true;
                continue;
            }
            const row = controller.session.snapshot().rows[expected.index];
            if (row?.state !== BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED) {
                rejected = true;
                continue;
            }
            if (file.size !== expected.byteLength) {
                failRequestedExportRowForRetry(controller, expected.index);
                rejected = true;
                runLiteUiBestEffort(() => {
                    renderLiteExportSnapshot(controller.kind, controller.session.snapshot());
                });
                continue;
            }

            let digest = null;
            try {
                digest = await digestBrowserExportSourceSha3_512(file, {
                    signal: verification.abortController.signal,
                });
                if (liteExportController !== controller) return;
                const snapshot = controller.session.verify(expected.index, {
                    name: file.name,
                    digest,
                });
                controller.exactArtifacts.delete(file.name);
                if (snapshot.complete) {
                    completeLiteExportSession(controller, snapshot);
                    return;
                }
                runLiteUiBestEffort(() => renderLiteExportSnapshot(controller.kind, snapshot));
            } catch {
                rejected = true;
                if (liteExportController === controller) {
                    runLiteUiBestEffort(() => {
                        renderLiteExportSnapshot(controller.kind, controller.session.snapshot());
                    });
                }
            } finally {
                wipeBytes(digest);
            }
        }

        if (rejected && liteExportController === controller) {
            logError('Artifact re-import verification failed; use the affected row to retry.', { isLiteMode: true });
            showToast('One or more artifacts failed generic re-import verification.', 'error');
        }
    } finally {
        releaseLiteReimportFileRefs(files);
        if (liteReimportVerification === verification) {
            liteReimportVerification = null;
            runLiteUiBestEffort(() => {
                setLiteReimportControlsEnabled(liteExportController === controller);
            });
            runLiteUiBestEffort(refreshLiteKeyAvailability);
            runLiteUiBestEffort(updateCreateShardsButton);
        }
    }
}

function cancelLiteExportSession({ announce = true } = {}) {
    liteExportEpoch += 1;
    abortLiteReimportVerification();
    const controller = liteExportController;
    if (controller) {
        // Revoke controller authority before any adapter, lifecycle, or DOM
        // cleanup whose implementation can fault independently.
        liteExportController = null;
        const archiveArtifactMayExist =
            controller.kind === 'archive' && controller.artifactRequestAttempted === true;
        try { controller.session.cancel(); } catch { /* Continue key settlement. */ }
        try { controller.exactArtifacts.clear(); } catch { /* Continue key settlement. */ }
        try {
            for (const timer of controller.objectUrlTimers.values()) clearTimeout(timer);
        } catch { /* Continue key settlement. */ }
        try { controller.objectUrlTimers.clear(); } catch { /* Continue key settlement. */ }
        try { controller.objectUrls.clear(); } catch { /* Continue key settlement. */ }
        try { controller.requesting.clear(); } catch { /* Continue key settlement. */ }
        if (controller.kind === 'archive') {
            try {
                liteArchiveKeys.discardOperation(controller.keyOperation);
            } catch {
                try { liteArchiveKeys.cancelActiveOperation(); } catch { /* Already failed closed. */ }
            }
            controller.keyOperation = null;
        } else {
            liteKeyBackupCancelledAfterLastCreate = true;
            liteKeyBackupExternalCopyMayExistAfterLastCreate =
                controller.privateKeyRequestAttempted === true;
        }
        liteCreateInProgress = false;
        liteExportPreparationKind = null;
        try { revokeAllLiteObjectUrls(); } catch { /* A tracked capability remains reported. */ }
        resetLiteRawKeyBackupAcknowledgement();
        runLiteUiBestEffort(clearLiteExportSessionPanel);
        runLiteUiBestEffort(refreshLiteExternalCopyWarning);
        if (controller.kind === 'archive') {
            runLiteUiBestEffort(hideLiteExportChecklist);
        } else {
            runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
        }
        runLiteUiBestEffort(refreshLiteKeyAvailability);
        runLiteUiBestEffort(updateCreateShardsButton);
        if (announce) {
            const message = controller.kind === 'key-backup' && controller.privateKeyRequestAttempted
                    ? 'Optional key export cancelled and best-effort in-page cleanup was attempted, but a requested private-key download may still exist outside the page and requires operator-controlled secure deletion.'
                    : (archiveArtifactMayExist
                        ? 'Archive export cancelled; controller and key ownership settled and best-effort URL cleanup was attempted, but requested downloads and any reported pending URL capabilities remain outside that proof. Retain archive copies under the custody policy or securely delete them; a threshold set is a complete recovery root.'
                        : 'Browser export session cancelled; controller and key ownership settled and best-effort URL cleanup was attempted. Any reported pending URL capabilities remain outside that proof.');
            runLiteUiBestEffort(() => logWarning(message, { isLiteMode: true }));
            if (archiveArtifactMayExist) {
                runLiteUiBestEffort(() => {
                    showToast('Requested archive downloads may still exist outside page control.', 'warning');
                });
            }
        }
        return true;
    }
    if (liteCreateInProgress) {
        const preparationKind = liteExportPreparationKind;
        try { liteArchiveKeys.cancelActiveOperation(); } catch { /* Async owner still observes epoch cancellation. */ }
        if (preparationKind === 'key-backup') {
            liteKeyBackupCancelledAfterLastCreate = true;
            liteKeyBackupExternalCopyMayExistAfterLastCreate = false;
            runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
        }
        try { revokeAllLiteObjectUrls(); } catch { /* A tracked capability remains reported. */ }
        resetLiteRawKeyBackupAcknowledgement();
        runLiteUiBestEffort(refreshLiteExternalCopyWarning);
        runLiteUiBestEffort(() => {
            const status = document.getElementById('liteExportSessionStatus');
            if (status) status.textContent = 'Cancellation requested. Some bounded work already running outside this workflow cannot be interrupted; best-effort cleanup of owned temporary bytes will run when control returns.';
        });
        runLiteUiBestEffort(() => {
            const cancelButton = document.getElementById('liteExportCancelBtn');
            if (cancelButton) cancelButton.disabled = true;
        });
        runLiteUiBestEffort(refreshLiteRawKeyBackupControl);
        if (announce) {
            runLiteUiBestEffort(() => {
                logWarning('Cancellation requested; bounded work already running outside the workflow may finish before best-effort cleanup of owned temporary bytes is attempted.', { isLiteMode: true });
            });
        }
        return true;
    }
    try { revokeAllLiteObjectUrls(); } catch { /* A tracked capability remains reported. */ }
    resetLiteRawKeyBackupAcknowledgement();
    runLiteUiBestEffort(refreshLiteExternalCopyWarning);
    return false;
}

function isLiteShardConfigurationValid() {
    const configuration = readLiteCreateConfiguration();
    if (!configuration) return false;
    const { n, thresholdPercent } = configuration;
    const params = calculateParametersFromThreshold(n, thresholdPercent);
    return !params.error;
}

function refreshLiteCustodyGuidanceVisibility() {
    const panel = document.getElementById('liteCustodyGuidance');
    if (!panel) return;
    const show = isLiteShardConfigurationValid();
    panel.classList.toggle('initially-hidden', !show);
}

function hideLiteExportChecklist() {
    document.getElementById('liteExportChecklist')?.classList.add('initially-hidden');
}

function refreshLiteExternalCopyWarning({ strict = false } = {}) {
    let panel = document.getElementById('liteExternalCopyWarning');
    let summary = document.getElementById('liteExternalCopyWarningSummary');
    if (strict) {
        ({ panel, summary } = requireLiteExternalCopyWarningSurface());
    } else if (!panel || !summary) {
        return;
    }

    const warnings = [];
    if (liteArchiveExternalCopyHazard) {
        warnings.push('One or more archive downloads were requested and may remain outside page control; retain them under the archive custody policy or securely delete them. A threshold set is a complete recovery root.');
    }
    if (litePrivateKeyExternalCopyHazard) {
        warnings.push('A raw private-key download was requested and may remain outside page control; the browser cannot delete it. Securely delete every unneeded copy under the key-custody policy.');
    }
    if (liteRestorePlaintextExternalCopyHazard) {
        warnings.push('A restored plaintext download was requested and may remain outside page control; cancellation, page cleanup, and object-URL revocation cannot delete a browser-managed copy.');
    }
    if (liteOutstandingObjectUrls.size > 0) {
        const capabilityLabel = liteOutstandingObjectUrls.size === 1 ? 'capability' : 'capabilities';
        warnings.push(`Best-effort cleanup remains pending for ${liteOutstandingObjectUrls.size} bounded in-page object-URL ${capabilityLabel}. Controller and key settlement do not prove URL revocation.`);
    }
    if (liteObjectUrlAccountingCompromised) {
        warnings.push('Browser object-URL cleanup or per-row capability accounting failed closed. No further Lite publication is allowed in this page; close the page after handling any requested downloads.');
    }
    const message = warnings.join(' ');
    summary.textContent = message;
    panel.classList.toggle('initially-hidden', warnings.length === 0);
    if (strict) {
        requireLiteExternalCopyWarningSurface({ requireVisible: warnings.length > 0 });
        if (summary.textContent !== message) {
            throw new Error('Lite external-copy warning surface rejected the warning.');
        }
    }
}

function requireLiteExternalCopyWarningSurface({ requireVisible = false } = {}) {
    const panel = document.getElementById('liteExternalCopyWarning');
    const summary = document.getElementById('liteExternalCopyWarningSummary');
    if (
        panel !== boundLiteExternalCopyWarningPanel ||
        summary !== boundLiteExternalCopyWarningSummary ||
        !(panel instanceof HTMLElement) ||
        !(summary instanceof HTMLElement) ||
        !panel.isConnected ||
        !summary.isConnected ||
        !panel.contains(summary)
    ) {
        throw new Error('Lite external-copy warning surface is unavailable.');
    }
    if (
        requireVisible && (
            !isLiteElementVisiblyReachable(panel) ||
            !isLiteElementVisiblyReachable(summary)
        )
    ) {
        throw new Error('Lite external-copy warning surface is not visible.');
    }
    return { panel, summary };
}

function clearLiteExportSessionPanel() {
    const panel = document.getElementById('liteExportSessionPanel');
    const rows = document.getElementById('liteExportSessionRows');
    const status = document.getElementById('liteExportSessionStatus');
    const reimportInput = document.getElementById('liteExportReimportInput');
    const reimportButton = document.getElementById('liteExportReimportBtn');
    const cancelButton = document.getElementById('liteExportCancelBtn');
    liteExportPreparationKind = null;
    // Make stale controls non-actionable and non-visible before attempting any
    // cosmetic scrubbing. Each mutable-DOM operation is independent so one
    // hostile setter cannot prevent the terminal transition.
    runLiteUiBestEffort(() => { if (panel) panel.hidden = true; });
    runLiteUiBestEffort(() => panel?.classList.add('initially-hidden'));
    runLiteUiBestEffort(() => { if (reimportInput) reimportInput.disabled = true; });
    runLiteUiBestEffort(() => { if (reimportButton) reimportButton.disabled = true; });
    runLiteUiBestEffort(() => { if (cancelButton) cancelButton.disabled = true; });
    runLiteUiBestEffort(() => {
        for (const action of rows?.querySelectorAll('button') || []) action.disabled = true;
    });
    runLiteUiBestEffort(() => rows?.replaceChildren());
    runLiteUiBestEffort(() => { if (status) status.textContent = ''; });
    runLiteUiBestEffort(() => clearLiteFileInputNode(reimportInput));
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
        'QVqcont-7 shard artifacts re-import verified',
        `${shardCount} matching artifacts returned through the file picker`,
        'ok',
    );
    addRow(
        'Archive-state artifact re-import verified',
        'Matching bytes returned after an individual download request',
        'ok',
    );
    addRow(
        'Lifecycle-bundle artifact re-import verified',
        'Matching bytes returned after an individual download request',
        'ok',
    );

    const keyExported = liteKeyBackupVerifiedAfterLastCreate;
    const keyRetentionAuthorized = liteRawKeyBackupAuthorizedAfterLastCreate;
    const keyExportCancelled = liteKeyBackupCancelledAfterLastCreate;
    const externalPrivateCopyMayExist = liteKeyBackupExternalCopyMayExistAfterLastCreate;
    addRow(
        keyExported
            ? 'Authorized 1-of-1 key backup re-import verified'
            : (keyExportCancelled
                ? (externalPrivateCopyMayExist
                    ? 'Key export cancelled; an external private-key copy may exist'
                    : 'Authorized 1-of-1 key export cancelled')
                : (keyRetentionAuthorized ? 'Authorized 1-of-1 key backup pending' : 'Threshold-only recovery preserved')),
        keyExported
            ? 'Both raw ML-KEM key artifacts passed exact name, size, and SHA3-512 digest verification; controller and key ownership settled and best-effort URL cleanup was attempted, while downloads and any reported pending URL capabilities remain outside that proof'
            : (keyExportCancelled
                ? (externalPrivateCopyMayExist
                    ? 'Best-effort in-page cleanup was attempted, but the browser cannot delete requested downloads; securely delete any unneeded .qkey copies outside this page'
                    : 'The optional export did not complete; best-effort cleanup of temporary in-page key bytes was attempted')
                : (keyRetentionAuthorized
                    ? 'Explicitly authorized for this archive; verify both artifacts once or wipe the browser session'
                    : 'No raw ML-KEM private-key backup was retained after verified archive completion')),
        keyExportCancelled && externalPrivateCopyMayExist
            ? 'warning'
            : (keyExported || keyExportCancelled || !keyRetentionAuthorized ? 'ok' : 'neutral'),
    );
}

function renderLiteExportChecklistAfterCreate(shardCount, keyRetentionAuthorized) {
    liteLastCreateShardCount = shardCount;
    liteKeyBackupVerifiedAfterLastCreate = false;
    liteKeyBackupCancelledAfterLastCreate = false;
    liteKeyBackupExternalCopyMayExistAfterLastCreate = false;
    liteRawKeyBackupAuthorizedAfterLastCreate = keyRetentionAuthorized === true;
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
    return buildRestoreRecoveryAction(error, { verb: 'Lite Restore' });
}

function summarizeLiteRestoreInputs(files) {
    const count = Array.isArray(files) ? files.length : Number(files?.length || 0);
    return Number.isSafeInteger(count) && count > 0
        ? `Lite restore input set (${count} file${count === 1 ? '' : 's'})`
        : 'Lite restore input set';
}

class LiteRestoreOperationCancelledError extends Error {
    constructor() {
        super('Lite restore operation cancelled.');
        this.name = 'LiteRestoreOperationCancelledError';
    }
}

function assertLiteRestoreOperation(operation) {
    if (liteRestoreOperation !== operation || operation?.cancelled === true) {
        throw new LiteRestoreOperationCancelledError();
    }
}

function publishLiteRestoreBlob(operation, blob, filename) {
    let objectUrl = null;
    let objectUrlTracked = false;
    let objectUrlByteLength = 0;
    let anchor = null;
    let failure = null;
    let revocationFailed = false;
    try {
        assertLiteRestoreOperation(operation);
        if (liteObjectUrlAccountingCompromised) {
            throw new Error('Lite publication capability accounting is unavailable.');
        }
        if (!(blob instanceof Blob)) {
            throw new Error('Lite restore output is unavailable.');
        }
        objectUrlByteLength = blob.size;
        if (
            !Number.isSafeInteger(objectUrlByteLength) ||
            objectUrlByteLength < 0 ||
            objectUrlByteLength > MAX_BROWSER_EXPORT_ARTIFACT_BYTES ||
            liteOutstandingObjectUrls.size >= MAX_BROWSER_EXPORT_ARTIFACTS ||
            outstandingLiteObjectUrlBytes() > MAX_BROWSER_EXPORT_AGGREGATE_BYTES - objectUrlByteLength
        ) {
            throw new Error('Lite restore output exceeded the fixed browser publication profile.');
        }
        // Record and visibly render the conservative external-copy hazard before
        // creating any plaintext capability. A false-positive warning is safer
        // than an unreported browser-managed plaintext copy.
        liteRestorePlaintextExternalCopyHazard = true;
        refreshLiteExternalCopyWarning({ strict: true });
        assertLiteRestoreOperation(operation);
        objectUrl = URL.createObjectURL(blob);
        liteOutstandingObjectUrls.set(objectUrl, objectUrlByteLength);
        objectUrlTracked = true;
        assertLiteRestoreOperation(operation);
        anchor = document.createElement('a');
        assertLiteRestoreOperation(operation);
        anchor.href = objectUrl;
        assertLiteRestoreOperation(operation);
        anchor.download = filename;
        assertLiteRestoreOperation(operation);
        anchor.addEventListener('click', (event) => {
            if (liteRestoreOperation !== operation || operation.cancelled === true) {
                event.preventDefault();
            }
        }, { capture: true });
        assertLiteRestoreOperation(operation);
        // Keep authenticated plaintext names and Blob capabilities out of the
        // connected DOM, and recheck the cancellation token at the last
        // application-controlled boundary before the native click.
        anchor.click();
    } catch (error) {
        if (error instanceof LiteRestoreOperationCancelledError) {
            failure = error;
        } else {
            // A faultable adapter setter may have synchronously dispatched the
            // session boundary before throwing its own error. Cancellation
            // remains authoritative and must not become a fresh error render.
            try {
                assertLiteRestoreOperation(operation);
                failure = new Error('Lite restore output publication failed.');
            } catch (cancelError) {
                failure = cancelError;
            }
        }
    } finally {
        if (anchor) {
            try { anchor.removeAttribute('href'); } catch { /* Continue cleanup. */ }
            try { anchor.removeAttribute('download'); } catch { /* Continue cleanup. */ }
            try { anchor.remove(); } catch { /* Detached cleanup is best effort. */ }
        }
        if (objectUrl !== null) {
            if (!objectUrlTracked) {
                try { objectUrlTracked = liteOutstandingObjectUrls.has(objectUrl); } catch { /* Fall through. */ }
            }
            if (objectUrlTracked) {
                if (!revokeLiteObjectUrl(objectUrl)) revocationFailed = true;
            } else {
                // Bookkeeping may have faulted after capability creation. Try a
                // direct revoke, then retain bounded accounting if that faults.
                try {
                    URL.revokeObjectURL(objectUrl);
                } catch {
                    revocationFailed = true;
                    try { liteOutstandingObjectUrls.set(objectUrl, objectUrlByteLength); } catch { /* Poison below. */ }
                }
            }
            if (revocationFailed) liteObjectUrlAccountingCompromised = true;
            runLiteUiBestEffort(refreshLiteExternalCopyWarning);
        }
    }
    if (revocationFailed) {
        assertLiteRestoreOperation(operation);
        throw new Error('Lite restore output publication failed.');
    }
    assertLiteRestoreOperation(operation);
    if (failure) throw failure;
}

function cancelLiteRestoreOperation() {
    if (!liteRestoreOperation) return false;
    liteRestoreOperation.cancelled = true;
    runLiteUiBestEffort(updateCreateShardsButton);
    return true;
}

function clearLiteRestoreSessionPresentation() {
    // Invalidate the outer refresh before its captured File[] can start fresh
    // subsystem generations after this boundary.
    liteRestoreShardRefresh.invalidate();
    // Revoke async generations and File-backed selection state first. That
    // function commits its non-DOM reset before attempting presentation work.
    runLiteUiBestEffort(() => {
        resetSuccessorSelectionSession(
            'liteRestore',
            document.getElementById('liteRestoreBtn'),
        );
    });
    runLiteUiBestEffort(() => clearArtifactIntakeTable('liteRestoreArtifactIntake'));
    runLiteUiBestEffort(() => clearRestorePreflightCard('liteRestorePreflightDecision'));
    if (!clearBoundLiteFileInput(boundLiteRestoreInput, 'liteShardsInput')) {
        boundLiteRestoreInput = null;
        liteRestoreShardRefresh.bindInput(null);
    }
    runLiteUiBestEffort(() => {
        const signer = boundLiteRestoreExpectedSignerControl;
        if (signer instanceof HTMLInputElement) signer.value = '';
    });
    runLiteUiBestEffort(() => {
        const currentSigner = document.getElementById('liteRestoreExpectedEdSigner');
        if (
            currentSigner instanceof HTMLInputElement &&
            currentSigner !== boundLiteRestoreExpectedSignerControl
        ) currentSigner.value = '';
    });
    for (const containerId of [
        'liteRestoreResult',
    ]) {
        runLiteUiBestEffort(() => {
            const container = document.getElementById(containerId);
            if (container) container.classList.add('initially-hidden');
        });
        runLiteUiBestEffort(() => {
            const container = document.getElementById(containerId);
            if (container) container.style.display = 'none';
        });
        runLiteUiBestEffort(() => {
            const container = document.getElementById(containerId);
            if (container) container.replaceChildren();
        });
    }
    runLiteUiBestEffort(() => clearInlineError(LITE_RESTORE_INLINE_ERROR_ID));
    runLiteUiBestEffort(() => {
        const statusText = document.getElementById('shardsStatusText');
        if (statusText) statusText.textContent = 'No restore inputs selected';
    });
    runLiteUiBestEffort(() => {
        const status = document.getElementById('shardsStatus');
        if (status) status.style.display = 'none';
    });
    runLiteUiBestEffort(() => {
        const status = document.getElementById('shardsStatus');
        if (status) status.classList.add('initially-hidden');
    });
    runLiteUiBestEffort(() => {
        const status = document.getElementById('shardsStatus');
        if (status) status.removeAttribute('aria-label');
    });
    runLiteUiBestEffort(() => {
        const reviewRoot = document.getElementById('liteRestoreArchiveReviewRoot');
        if (reviewRoot instanceof HTMLDetailsElement) reviewRoot.open = false;
    });
}

function wipeLiteModeSessionSecrets() {
    try { cancelLiteExportSession({ announce: false }); } catch { /* Continue all independent revocations. */ }
    // Cancellation is cooperative. Keep the operation token until its finally
    // block wipes local reconstructed keys/plaintext and releases the lock.
    try { cancelLiteRestoreOperation(); } catch { /* Continue all independent revocations. */ }
    // Revoke File-backed successor generations even if a mutable input setter
    // or other presentation adapter has been fault-injected.
    clearLiteRestoreSessionPresentation();
    try { liteArchiveKeys.wipeAll(); } catch { /* Best-effort JS heap wipe. */ }
    liteKeyBackupVerifiedAfterLastCreate = false;
    liteKeyBackupCancelledAfterLastCreate = false;
    liteKeyBackupExternalCopyMayExistAfterLastCreate = false;
    liteRawKeyBackupAuthorizedAfterLastCreate = false;
    liteLastCreateShardCount = 0;
    resetLiteRawKeyBackupAcknowledgement();
    if (!clearBoundLiteFileInput(boundLitePlaintextInput, 'liteFilesInput')) {
        boundLitePlaintextInput = null;
    }
    runLiteUiBestEffort(updateFileListDisplay);
    runLiteUiBestEffort(clearLiteExportSessionPanel);
    runLiteUiBestEffort(hideLiteExportChecklist);
    // External-copy hazards are monotonic for this live document. Wiping page
    // memory cannot revoke a download or prove secure deletion, and pagehide
    // may preserve this heap in the back-forward cache.
    runLiteUiBestEffort(refreshLiteExternalCopyWarning);
    runLiteUiBestEffort(refreshLiteKeyAvailability);
    runLiteUiBestEffort(refreshLiteCustodyGuidanceVisibility);
    runLiteUiBestEffort(updateCreateShardsButton);
}

// Update threshold display logic
function updateThresholdDisplay() {
    const nInput = document.getElementById('liteN');
    const thresholdInput = document.getElementById('liteThreshold');
    const thresholdText = document.getElementById('thresholdText');
    const thresholdDelta = document.getElementById('thresholdDelta');
    const thresholdHint = document.getElementById('thresholdHint');
    
    if (!nInput || !thresholdInput || !thresholdText) return;
    
    const n = Number(nInput.value);
    const thresholdPercent = Number(thresholdInput.value);
    
    if (thresholdDelta) {
        thresholdDelta.textContent = '';
        thresholdDelta.className = 'threshold-delta';
    }
    if (thresholdHint) {
        thresholdHint.textContent = 'Discrete by RS/SSS constraints.';
        thresholdHint.className = 'info-text';
    }
    
    if (
        !Number.isInteger(n) ||
        n < LITE_MIN_SHARDS ||
        n > LITE_MAX_SHARDS ||
        !Number.isInteger(thresholdPercent) ||
        thresholdPercent < LITE_MIN_THRESHOLD_PERCENT ||
        thresholdPercent > LITE_MAX_THRESHOLD_PERCENT
    ) {
        thresholdText.textContent = 'Invalid parameters';
        if (thresholdHint) {
            thresholdHint.className = 'info-text error';
            thresholdHint.textContent = `Use integer bounds n=${LITE_MIN_SHARDS}..${LITE_MAX_SHARDS} and threshold=${LITE_MIN_THRESHOLD_PERCENT}..${LITE_MAX_THRESHOLD_PERCENT}%.`;
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

function refreshLiteKeyAvailability() {
    let backupAvailable = liteArchiveKeys.hasRetainedKeyPair() && !liteCreateInProgress;
    let refreshAfterDecisionDiscard = false;
    const statusText = document.getElementById('keyStatus')?.querySelector('.status-text');
    const statusIcon = document.getElementById('keyStatus')?.querySelector('.status-icon');
    const currentDownloadButton = document.getElementById('liteDownloadKeysBtn');
    const currentDiscardButton = document.getElementById('liteDiscardKeysBtn');
    const controlsStructurallyUsable = hasUsableLiteKeyDecisionControls();
    const downloadBtn = controlsStructurallyUsable ? boundLiteDownloadKeysButton : null;
    const discardBtn = controlsStructurallyUsable ? boundLiteDiscardKeysButton : null;

    if (backupAvailable && !controlsStructurallyUsable) {
        const discarded = discardRetainedLiteKeyForUnavailableControls();
        backupAvailable = liteArchiveKeys.hasRetainedKeyPair() && !liteCreateInProgress;
        if (discarded) {
            refreshAfterDecisionDiscard = true;
            runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
            runLiteUiBestEffort(() => {
                logWarning('Pending optional key material was discarded because its exact bound decision controls became unavailable.', { isLiteMode: true });
            });
        }
    }

    if (statusText) {
        if (liteExportController?.kind === 'archive') {
            statusText.textContent = 'Archive incomplete: verify every required artifact';
        } else if (liteExportController?.kind === 'key-backup') {
            statusText.textContent = 'Optional key backup incomplete: verify both artifacts';
        } else if (liteCreateInProgress) {
            statusText.textContent = 'Generating a fresh key for this archive...';
        } else if (liteReimportVerification) {
            statusText.textContent = 'Cancelled artifact verification is settling...';
        } else if (backupAvailable) {
            statusText.textContent = 'Pending 1-of-1 key decision blocks the next archive';
        } else {
            statusText.textContent = 'Fresh keys are generated per archive';
        }
    }
    if (statusIcon) {
        statusIcon.textContent = (liteCreateInProgress || liteReimportVerification)
            ? '🔄'
            : (backupAvailable ? '🔑' : '🛡️');
    }
    if (downloadBtn instanceof HTMLButtonElement) {
        runLiteUiBestEffort(() => { downloadBtn.disabled = !backupAvailable; });
        runLiteUiBestEffort(() => downloadBtn.classList.toggle('initially-hidden', !backupAvailable));
        runLiteUiBestEffort(() => { downloadBtn.style.display = backupAvailable ? 'inline-flex' : ''; });
    }
    if (discardBtn instanceof HTMLButtonElement) {
        runLiteUiBestEffort(() => { discardBtn.disabled = !backupAvailable; });
        runLiteUiBestEffort(() => discardBtn.classList.toggle('initially-hidden', !backupAvailable));
        runLiteUiBestEffort(() => { discardBtn.style.display = backupAvailable ? 'inline-flex' : ''; });
    }
    for (const replacement of [currentDownloadButton, currentDiscardButton]) {
        if (replacement instanceof HTMLButtonElement && replacement !== downloadBtn && replacement !== discardBtn) {
            runLiteUiBestEffort(() => { replacement.disabled = true; });
            runLiteUiBestEffort(() => replacement.classList.add('initially-hidden'));
        }
    }

    if (backupAvailable && !hasUsableLiteKeyDecisionControls({ requireReachable: true })) {
        const discarded = discardRetainedLiteKeyForUnavailableControls();
        backupAvailable = liteArchiveKeys.hasRetainedKeyPair() && !liteCreateInProgress;
        runLiteUiBestEffort(() => { if (downloadBtn) downloadBtn.disabled = true; });
        runLiteUiBestEffort(() => downloadBtn?.classList.add('initially-hidden'));
        runLiteUiBestEffort(() => { if (discardBtn) discardBtn.disabled = true; });
        runLiteUiBestEffort(() => discardBtn?.classList.add('initially-hidden'));
        if (discarded) {
            refreshAfterDecisionDiscard = true;
            runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
            runLiteUiBestEffort(() => {
                logWarning('Pending optional key material was discarded because its exact decision controls were not visibly reachable.', { isLiteMode: true });
            });
        }
    }

    if (refreshAfterDecisionDiscard) {
        refreshLiteKeyAvailability();
        return;
    }

    if (isLiteMode) {
        updateSidebarStatus(backupAvailable, backupAvailable);
    }
}

// Update file list display
function updateFileListDisplay() {
    const filesInput = document.getElementById('liteFilesInput');
    const filesList = document.getElementById('liteFilesList');
    
    if (!filesInput || !filesList) return;
    
    if (!filesInput.files || filesInput.files.length === 0) {
        filesList.replaceChildren();
        filesList.style.display = 'none';
        return;
    }
    
    filesList.replaceChildren();
    const item = document.createElement('div');
    item.className = 'file-item';

    const selection = document.createElement('span');
    selection.className = 'file-name';
    const withinProfile = liteInputSelectionWithinProfile(filesInput.files);
    selection.textContent = withinProfile
        ? `Plaintext selection ready (${filesInput.files.length} ${filesInput.files.length === 1 ? 'file' : 'files'})`
        : 'Plaintext selection exceeds the fixed Lite browser input profile';

    item.appendChild(selection);
    filesList.appendChild(item);
    filesList.style.display = 'block';
    if (!withinProfile) {
        // Do not leave rejected name-bearing File objects attached to the DOM.
        filesInput.value = '';
    }
}

// Update shards status indicator
async function updateShardsStatus() {
  await liteRestoreShardRefresh.refresh();
}

function refreshLiteWorkflowNavigation() {
    const protectTab = document.getElementById('liteTabProtect');
    const restoreTab = document.getElementById('liteTabRestore');
    if (!protectTab || !restoreTab) return;

    const createCustodyBlocked = unresolvedLiteCreateCustodyState() !== null;
    const restoreBlocked = liteRestoreOperation !== null;
    protectTab.disabled = restoreBlocked;
    protectTab.setAttribute('aria-disabled', String(restoreBlocked));
    restoreTab.disabled = createCustodyBlocked;
    restoreTab.setAttribute('aria-disabled', String(createCustodyBlocked));
    if (createCustodyBlocked) {
        // Keep the only visible cancel/discard surface selected. The tab helper
        // also checks live disabled state, so roving keys cannot bypass this.
        liteTabController?.activateTab('liteTabProtect');
        restoreTab.tabIndex = -1;
    } else if (restoreBlocked) {
        liteTabController?.activateTab('liteTabRestore');
        protectTab.tabIndex = -1;
    } else {
        protectTab.tabIndex = protectTab.getAttribute('aria-selected') === 'true' ? 0 : -1;
        restoreTab.tabIndex = restoreTab.getAttribute('aria-selected') === 'true' ? 0 : -1;
    }
}

// Update create shards button state
function updateCreateShardsButton() {
    const btn = document.getElementById('liteCreateShardsBtn');
    const filesInput = document.getElementById('liteFilesInput');

    refreshLiteWorkflowNavigation();
    if (!btn || !filesInput) return;
    
    const configuration = readLiteCreateConfiguration();
    const validConfig = configuration !== null &&
        !calculateParametersFromThreshold(configuration.n, configuration.thresholdPercent).error;
    const validPlaintextControl = filesInput === boundLitePlaintextInput &&
        filesInput instanceof HTMLInputElement &&
        filesInput.type === 'file' &&
        filesInput.isConnected;
    const validSelection = validPlaintextControl && liteInputSelectionWithinProfile(filesInput.files);
    const authPolicyInput = document.getElementById('liteAuthPolicy');
    const validAuthPolicy = authPolicyInput === boundLiteAuthPolicyControl &&
        authPolicyInput instanceof HTMLSelectElement &&
        authPolicyInput.isConnected &&
        isSupportedAuthPolicyLevel(String(authPolicyInput.value).trim());
    const validCustodyControl = hasUsableLiteRawKeyAcknowledgement();

    const operationLocked = liteCreateInProgress ||
        liteExportController !== null ||
        liteReimportVerification !== null ||
        liteRestoreOperation !== null ||
        liteObjectUrlAccountingCompromised;
    const custodyDecisionPending = liteArchiveKeys.hasRetainedKeyPair();
    btn.disabled = operationLocked || custodyDecisionPending || !validSelection || !validConfig ||
        !validAuthPolicy || !validCustodyControl;
    for (const controlId of ['liteFilesInput', 'liteN', 'liteThreshold', 'liteAuthPolicy']) {
        const control = document.getElementById(controlId);
        if (control) control.disabled = operationLocked || custodyDecisionPending;
    }

    refreshLiteCustodyGuidanceVisibility();
    refreshLiteRawKeyBackupControl();
}

// Start a verified, individual-download export for the explicitly retained pair.
async function downloadLiteKeys() {
    if (
        liteCreateInProgress ||
        liteExportController ||
        liteReimportVerification ||
        liteRestoreOperation ||
        liteObjectUrlAccountingCompromised
    ) {
        if (liteObjectUrlAccountingCompromised) {
            runLiteUiBestEffort(() => {
                showToast('Lite publication is unavailable in this page after a capability-cleanup failure; reload before exporting.', 'error');
            });
        }
        runLiteUiBestEffort(updateCreateShardsButton);
        return;
    }
    let retainedKeyPair = null;
    let session = null;
    let exactArtifacts = null;
    let candidateController = null;
    let handedOff = false;
    let exportEpoch = null;

    try {
        if (!hasUsableLiteKeyDecisionControls({ requireReachable: true })) {
            refreshLiteKeyAvailability();
            throw new Error('Lite key-decision controls are unavailable.');
        }
        // Refuse the ownership transfer unless the complete, already-wired
        // recovery UI is present. Missing or replaced controls must leave the
        // retained pair in lifecycle custody.
        requireLiteExportControls();
        // The lifecycle transfers ownership here. Every subsequent statement is
        // inside this fault boundary until a fully rendered controller handoff.
        retainedKeyPair = liteArchiveKeys.takeRetainedKeyPair();
        if (!retainedKeyPair) {
            showToast('No key backup is available.', 'warning');
            return;
        }

        exportEpoch = ++liteExportEpoch;
        liteCreateInProgress = true;
        liteKeyBackupCancelledAfterLastCreate = false;
        renderLiteExportPreparation('key-backup');
        refreshLiteKeyAvailability();
        updateCreateShardsButton();

        const basename = createOpaqueLiteExportBasename();
        const plan = [
            {
                name: `${basename}-private.qkey`,
                source: retainedKeyPair.privateKey,
                role: 'private-key',
            },
            {
                name: `${basename}-public.qkey`,
                source: retainedKeyPair.publicKey,
                role: 'public-key',
            },
        ];
        exactArtifacts = privateExportArtifactMap(plan);
        session = await createBrowserExportSession(plan);
        if (exportEpoch !== liteExportEpoch) {
            session.cancel();
            exactArtifacts.clear();
            return;
        }

        candidateController = {
            kind: 'key-backup',
            session,
            exactArtifacts,
            objectUrls: new Map(),
            objectUrlTimers: new Map(),
            requesting: new Set(),
            privateKeyRequestAttempted: false,
            artifactRequestAttempted: false,
        };
        renderLiteExportSnapshot('key-backup', session.snapshot());
        log('Optional 1-of-1 key artifacts are held temporarily; each requires an individual download request and exact name, size, and SHA3-512 digest verification.', { isLiteMode: true });

        // Mutable DOM adapters can synchronously dispatch pagehide while
        // rendering. Recheck the epoch immediately before the contiguous plain
        // assignments so a session boundary cannot be resurrected.
        if (exportEpoch !== liteExportEpoch) {
            throw new Error('Lite key export setup cancelled.');
        }
        // Final nonthrowing handoff: setup failures above remain locally owned.
        liteExportController = candidateController;
        liteExportPreparationKind = null;
        handedOff = true;
    } catch {
        if (liteExportController === candidateController) {
            liteExportController = null;
        }
        try { session?.cancel(); } catch { /* Continue ownership return. */ }
        try { exactArtifacts?.clear(); } catch { /* Continue ownership return. */ }
        let restoredForRetry = retainedKeyPair === null && liteArchiveKeys.hasRetainedKeyPair();
        if (retainedKeyPair && exportEpoch === liteExportEpoch) {
            try {
                liteArchiveKeys.returnRetainedKeyPair(retainedKeyPair);
                retainedKeyPair = null;
                restoredForRetry = true;
            } catch {
                // The lifecycle wipes a rejected ownership return fail-closed.
            }
        }
        liteKeyBackupCancelledAfterLastCreate = !restoredForRetry;
        if (restoredForRetry) {
            runLiteUiBestEffort(() => {
                logError('Optional key export setup failed; pending key material remains available for retry or explicit discard.', { isLiteMode: true });
            });
            runLiteUiBestEffort(() => {
                showToast('Key export setup failed; the pending key was preserved.', 'warning');
            });
        } else {
            runLiteUiBestEffort(() => {
                logError('Optional key export setup failed closed; temporary key ownership ended and best-effort cleanup was attempted.', { isLiteMode: true });
            });
        }
    } finally {
        try { wipeLiteArchiveKeyPair(retainedKeyPair); } catch { /* Continue state release. */ }
        if (!handedOff) {
            liteCreateInProgress = false;
            liteExportPreparationKind = null;
            runLiteUiBestEffort(clearLiteExportSessionPanel);
            runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
        }
        runLiteUiBestEffort(refreshLiteKeyAvailability);
        runLiteUiBestEffort(updateCreateShardsButton);
    }
}

function discardPendingLiteKeys() {
    if (liteCreateInProgress || liteExportController || liteReimportVerification || liteRestoreOperation) {
        runLiteUiBestEffort(updateCreateShardsButton);
        return;
    }
    const retainedKeyPair = liteArchiveKeys.takeRetainedKeyPair();
    if (!retainedKeyPair) return;

    wipeLiteArchiveKeyPair(retainedKeyPair);
    liteKeyBackupVerifiedAfterLastCreate = false;
    liteKeyBackupCancelledAfterLastCreate = true;
    liteKeyBackupExternalCopyMayExistAfterLastCreate = false;
    resetLiteRawKeyBackupAcknowledgement();
    runLiteUiBestEffort(refreshLiteExportChecklistAfterKeyBackup);
    runLiteUiBestEffort(refreshLiteKeyAvailability);
    runLiteUiBestEffort(updateCreateShardsButton);
    runLiteUiBestEffort(() => {
        logWarning('Pending optional 1-of-1 key material was explicitly discarded; the verified threshold archive remains the recovery path.', { isLiteMode: true });
    });
    runLiteUiBestEffort(() => {
        showToast('Pending 1-of-1 key material discarded.', 'warning');
    });
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
    const authPolicyInput = document.getElementById('liteAuthPolicy');
    if (
        liteCreateInProgress ||
        liteExportController !== null ||
        liteReimportVerification !== null ||
        liteRestoreOperation !== null ||
        liteArchiveKeys.hasRetainedKeyPair() ||
        liteObjectUrlAccountingCompromised
    ) {
        resetLiteRawKeyBackupAcknowledgement();
        if (liteObjectUrlAccountingCompromised) {
            showToast('Lite publication is unavailable in this page after a capability-cleanup failure; reload before creating another archive.', 'error');
        } else if (liteRestoreOperation) {
            showToast('Wait for the active Lite Restore to settle before creating an archive.', 'warning');
        } else if (liteArchiveKeys.hasRetainedKeyPair()) {
            showToast('Export or explicitly discard the pending 1-of-1 key before creating another archive.', 'warning');
        }
        runLiteUiBestEffort(updateCreateShardsButton);
        return;
    }
    // The checkbox is a one-attempt capability. Snapshot and clear it before
    // any validation or asynchronous work so later UI changes cannot alter the
    // operation's key-retention decision or carry authority to another archive.
    if (!hasUsableLiteRawKeyAcknowledgement()) {
        resetLiteRawKeyBackupAcknowledgement();
        showToast('Required Lite key-custody acknowledgement control is unavailable; reload before creating an archive.', 'error');
        logError('Lite archive creation could not start because its bound key-custody acknowledgement control is unavailable.', { isLiteMode: true });
        return;
    }
    if (
        filesInput !== boundLitePlaintextInput ||
        !(filesInput instanceof HTMLInputElement) ||
        filesInput.type !== 'file' ||
        !filesInput.isConnected
    ) {
        resetLiteRawKeyBackupAcknowledgement();
        showToast('Required Lite plaintext input control is unavailable; reload before creating an archive.', 'error');
        logError('Lite archive creation could not start because its bound plaintext input control is unavailable.', { isLiteMode: true });
        return;
    }
    const retainRawKeyForBackup = snapshotLiteRawKeyBackupAcknowledgement();
    
    if (!filesInput?.files?.length) {
        showToast('Please select files to encrypt', 'warning');
        return;
    }

    const configuration = readLiteCreateConfiguration();
    if (!configuration) {
        showToast('Lite create parameters are outside the supported integer bounds.', 'warning');
        return;
    }
    const { n, thresholdPercent } = configuration;
    const params = calculateParametersFromThreshold(n, thresholdPercent);
    if (params.error) {
        showToast('Lite create parameters do not provide a supported recovery configuration.', 'warning');
        return;
    }
    if (!liteInputSelectionWithinProfile(filesInput.files)) {
        filesInput.value = '';
        runLiteUiBestEffort(updateFileListDisplay);
        runLiteUiBestEffort(updateCreateShardsButton);
        showToast('Plaintext selection exceeds the fixed Lite browser input profile.', 'warning');
        return;
    }
    if (
        authPolicyInput !== boundLiteAuthPolicyControl ||
        !(authPolicyInput instanceof HTMLSelectElement) ||
        !authPolicyInput.isConnected
    ) {
        showToast('Required Lite authenticity-policy control is unavailable; reload before creating an archive.', 'error');
        logError('Lite archive creation could not start because its bound authenticity-policy control is unavailable.', { isLiteMode: true });
        return;
    }
    const authPolicyLevel = String(authPolicyInput.value).trim();
    if (!isSupportedAuthPolicyLevel(authPolicyLevel)) {
        showToast('Lite create authenticity policy is unsupported.', 'warning');
        return;
    }

    try {
        // Validate the whole wired custody surface before the lifecycle grants
        // any operation ownership. Rendering validates it again at handoff.
        requireLiteExportControls();
    } catch {
        logError('Lite archive creation could not start because required export controls are unavailable.', { isLiteMode: true });
        showToast('Required Lite export controls are unavailable; reload before creating an archive.', 'error');
        return;
    }

    const inputFiles = [...filesInput.files];
    let payloadBytes = null;
    let encBytes = null;
    let generatedKeyPair = null;
    let archiveStateBytes = null;
    let lifecycleBundleBytes = null;
    let pendingSession = null;
    let exactArtifacts = null;
    let handedOff = false;
    let keyOperation;
    try {
        keyOperation = liteArchiveKeys.beginOperation();
    } catch {
        logError('Lite archive operation could not start because another key operation owns the session.', { isLiteMode: true });
        return;
    }

    // Ownership starts at beginOperation(); every later setup/UI statement is
    // covered by this fault boundary until the controller handoff is complete.
    try {
        // Remove plaintext File references and their name-bearing value from the
        // DOM as soon as this operation owns a bounded local snapshot.
        filesInput.value = '';
        updateFileListDisplay();

        const exportEpoch = ++liteExportEpoch;
        liteCreateInProgress = true;
        hideLiteExportChecklist();
        clearLiteExportSessionPanel();
        renderLiteExportPreparation('archive');
        log(
            retainRawKeyForBackup
                ? 'Create request explicitly authorized one-time raw-key backup retention.'
                : 'Create request selected threshold-only recovery; no raw-key backup retention authorized.',
            { isLiteMode: true },
        );

        setWorkflowBusy('liteViewProtect', true);
        refreshLiteKeyAvailability();
        updateCreateShardsButton();
        const preparationCancelButton = document.getElementById('liteExportCancelBtn');
        if (preparationCancelButton) preparationCancelButton.disabled = false;
        updateLitePipeline('liteViewProtect', 'step-lock'); // Start: Encrypting

        const isBundle = inputFiles.length > 1;

        let payloadName;
        if (isBundle) {
            const { bundleName, bundleBytes } = await createBundlePayloadFromFiles(inputFiles);
            payloadBytes = bundleBytes;
            payloadName = bundleName;
            log('Multiple plaintext inputs were encoded into one encrypted bundle.', { isLiteMode: true });
        } else {
            const file = inputFiles[0];
            payloadBytes = await readFileAsUint8Array(file);
            payloadName = file.name;
        }

        liteArchiveKeys.assertActive(keyOperation);

        // A fresh ML-KEM keypair belongs only to this archive operation.
        generatedKeyPair = await generateKeyPair({ collectUserEntropy: false });
        liteArchiveKeys.adoptKeyPair(keyOperation, generatedKeyPair);
        generatedKeyPair = null;
        log('Fresh ML-KEM keypair generated for this archive operation.', { isLiteMode: true });
        const operationKeyPair = liteArchiveKeys.getOperationKeyPair(keyOperation);

        // 1. Encrypt payload (single file or multi-file bundle)
        const encBlob = await encryptFile(payloadBytes, operationKeyPair.publicKey, payloadName);
        liteArchiveKeys.assertActive(keyOperation);
        encBytes = await readFileAsUint8Array(encBlob);
        liteArchiveKeys.assertActive(keyOperation);

        updateLitePipeline('liteViewProtect', 'step-split'); // Transition: Splitting
        
        // 2. Create shards from encrypted container + private key
        const splitResult = await buildQcontShards(encBytes, operationKeyPair.privateKey, {
            n: params.n,
            k: params.k
        }, { authPolicyLevel });
        liteArchiveKeys.assertActive(keyOperation);
        const qconts = splitResult.shards;
        archiveStateBytes = splitResult.archiveStateBytes;
        lifecycleBundleBytes = splitResult.lifecycleBundleBytes;
        if (!Array.isArray(qconts) || qconts.length !== params.n) {
            throw new Error('Lite shard construction returned an invalid artifact count.');
        }

        // Adopt the complete, bounded n+2 plan before any artifact can be
        // published. Output names are opaque random identifiers and never
        // derive from plaintext metadata.
        const basename = createOpaqueLiteExportBasename();
        const shardCount = qconts.length;
        const plan = qconts.map(({ blob }, index) => ({
            name: `${basename}-shard-${String(index + 1).padStart(2, '0')}-of-${String(shardCount).padStart(2, '0')}.qcont`,
            source: blob,
            role: 'shard',
        }));
        plan.push(
            {
                name: `${basename}-archive-state.json`,
                source: new Blob([archiveStateBytes], { type: 'application/json' }),
                role: 'archive-state',
            },
            {
                name: `${basename}-lifecycle-bundle.json`,
                source: new Blob([lifecycleBundleBytes], { type: 'application/json' }),
                role: 'lifecycle-bundle',
            },
        );

        exactArtifacts = privateExportArtifactMap(plan);
        pendingSession = await createBrowserExportSession(plan);
        liteArchiveKeys.assertActive(keyOperation);
        if (exportEpoch !== liteExportEpoch) {
            throw new LiteArchiveCreationCancelledError();
        }

        const candidateController = {
            kind: 'archive',
            session: pendingSession,
            exactArtifacts,
            objectUrls: new Map(),
            objectUrlTimers: new Map(),
            requesting: new Set(),
            keyOperation,
            retainRawKeyForBackup,
            shardCount,
            artifactRequestAttempted: false,
        };
        refreshLiteKeyAvailability();
        renderLiteExportSnapshot('archive', pendingSession.snapshot());

        log('Encrypted archive artifacts are prepared in temporary browser memory. No download has been requested.', { isLiteMode: true });
        log(`Archive policy: ${authPolicyLevel}`, { isLiteMode: true });
        if (authPolicyLevel === 'integrity-only') {
            log('After every required artifact passes exact re-import verification, externally sign the archive-state artifact if archive approval is required.', { isLiteMode: true });
        } else {
            log('After every required artifact passes exact re-import verification, externally sign the archive-state artifact and attach detached approval evidence.', { isLiteMode: true });
        }
        log('Each artifact requires one individual download request and exact name, size, and SHA3-512 digest re-import verification. This is not durable-storage evidence.', { isLiteMode: true });

        // A mutable DOM/log adapter above can synchronously dispatch pagehide.
        // Revalidate both the session epoch and lifecycle token immediately
        // before the contiguous plain assignments so wipe cannot be undone.
        if (exportEpoch !== liteExportEpoch) {
            throw new LiteArchiveCreationCancelledError();
        }
        liteArchiveKeys.assertActive(keyOperation);
        // Final nonthrowing handoff: all potentially faulting setup remains
        // locally owned and therefore disposable above this point.
        liteExportController = candidateController;
        liteExportPreparationKind = null;
        handedOff = true;
        keyOperation = null;
        pendingSession = null;
        exactArtifacts = null;
    } catch (error) {
        try { pendingSession?.cancel(); } catch { /* Continue operation-key settlement. */ }
        try { exactArtifacts?.clear(); } catch { /* Continue operation-key settlement. */ }
        if (error instanceof LiteArchiveCreationCancelledError) {
            runLiteUiBestEffort(() => {
                logWarning('Lite archive creation cancelled; operation key material was discarded.', { isLiteMode: true });
            });
        } else {
            runLiteUiBestEffort(() => {
                logError('Lite archive preparation failed; no artifact was published.', { isLiteMode: true });
            });
        }
    } finally {
        try { wipeLiteArchiveKeyPair(generatedKeyPair); } catch { /* Continue operation-key settlement. */ }
        try { wipeBytes(payloadBytes, encBytes, archiveStateBytes, lifecycleBundleBytes); } catch { /* Continue operation-key settlement. */ }
        inputFiles.length = 0;
        if (!handedOff) {
            try {
                liteArchiveKeys.discardOperation(keyOperation);
            } catch {
                try { liteArchiveKeys.cancelActiveOperation(); } catch { /* Already failed closed. */ }
            }
            liteCreateInProgress = false;
            liteExportPreparationKind = null;
            runLiteUiBestEffort(clearLiteExportSessionPanel);
        }
        runLiteUiBestEffort(() => setWorkflowBusy('liteViewProtect', false));
        runLiteUiBestEffort(refreshLiteKeyAvailability);
        runLiteUiBestEffort(updateCreateShardsButton);
        runLiteUiBestEffort(() => {
            setTimeout(() => updateLitePipeline('liteViewProtect', null), 2000);
        });
    }
}

async function restoreLiteShards() {
    const shardsInput = document.getElementById('liteShardsInput');

    if (liteObjectUrlAccountingCompromised) {
        showToast('Lite publication is unavailable in this page after a capability-cleanup failure; reload before restoring.', 'error');
        logError('Lite Restore was blocked because browser publication capability accounting is unavailable.', {
            isLiteMode: true,
            skipToast: true,
        });
        return;
    }

    if (unresolvedLiteCreateCustodyState() !== null || liteRestoreOperation !== null) {
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: 'Another Lite custody or restore workflow remains unresolved.',
            artifact: 'Lite restore input set',
            action: 'Complete the active workflow, cancel its export, or explicitly resolve its pending custody decision before restoring.',
        });
        showToast('Resolve the active Lite workflow before restoring.', 'warning');
        logWarning('Lite Restore was blocked because another workflow remains unresolved.', { isLiteMode: true });
        runLiteUiBestEffort(updateCreateShardsButton);
        return;
    }

    if (
        shardsInput !== boundLiteRestoreInput ||
        !(shardsInput instanceof HTMLInputElement) ||
        shardsInput.type !== 'file' ||
        !shardsInput.isConnected
    ) {
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: 'The bound restore input control is unavailable.',
            artifact: 'Lite restore input set',
            action: 'Reload the application and reselect the restore inputs.',
        });
        showToast('Required Lite restore input control is unavailable; reload before restoring.', 'error');
        logError('Lite Restore could not start because its bound input control is unavailable.', { isLiteMode: true });
        return;
    }

    if (!shardsInput.files?.length) {
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: 'No shard files are selected.',
            artifact: 'Lite restore input set',
            action: 'Load successor QVqcont-7 shards and any detached evidence required by the archive policy.',
        });
        showToast('Please select shard files to restore', 'warning');
        return;
    }

    const expectedSignerControl = document.getElementById('liteRestoreExpectedEdSigner');
    const preflightRoot = document.getElementById('liteRestorePreflightDecision');
    if (
        expectedSignerControl !== boundLiteRestoreExpectedSignerControl ||
        !(expectedSignerControl instanceof HTMLInputElement) ||
        !expectedSignerControl.isConnected ||
        preflightRoot !== boundLiteRestorePreflightRoot ||
        !(preflightRoot instanceof HTMLElement) ||
        !preflightRoot.isConnected
    ) {
        showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
            title: 'Lite restore blocked',
            cause: 'A bound restore constraint or preflight control is unavailable.',
            artifact: 'Lite restore input set',
            action: 'Reload the application, reselect the restore inputs, and re-enter any independently obtained signer constraint.',
        });
        showToast('Required Lite restore controls are unavailable; reload before restoring.', 'error');
        logError('Lite Restore could not start because a bound constraint or preflight control is unavailable.', { isLiteMode: true });
        return;
    }

    const selectedFiles = [...shardsInput.files];
    const expectedEd25519Signer = String(expectedSignerControl.value || '').trim();
    const operation = { cancelled: false };
    liteRestoreOperation = operation;
    let shardBytesArr = [];
    let parsedShards = [];
    let bundleEntries = [];
    let result = null;
    let decBytes = null;

    try {
        setWorkflowBusy('liteViewRestore', true);
        assertLiteRestoreOperation(operation);
        updateCreateShardsButton();
        assertLiteRestoreOperation(operation);
        updateLitePipeline('liteViewRestore', 'step-combine');
        assertLiteRestoreOperation(operation);

        const assessment = await assessShardSelection(selectedFiles);
        assertLiteRestoreOperation(operation);
        if (!assessment.ready) {
            showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
                title: 'Lite restore blocked',
                cause: assessment.message || 'Selected shards do not meet the recovery threshold.',
                artifact: summarizeLiteRestoreInputs(selectedFiles),
                action: 'Load enough unique successor shards from one archive/state/cohort, then retry Lite Restore.',
            });
            showToast(assessment.message || 'Selected shards do not meet the recovery threshold', 'warning');
            return;
        }

        const preflight = await renderRestorePreflightForFiles({
            prefix: 'liteRestore',
            containerId: 'liteRestorePreflightDecision',
            files: selectedFiles,
            expectedSignerInput: expectedSignerControl,
            expectedEd25519Signer,
            isCurrent: () => liteRestoreOperation === operation && operation.cancelled !== true,
        });
        assertLiteRestoreOperation(operation);
        if (preflight?.canEvaluate !== true) {
            showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
                title: 'Lite restore blocked',
                cause: preflight?.blockingReason || 'Restore preflight decision is unavailable.',
                artifact: summarizeLiteRestoreInputs(selectedFiles),
                action: 'Load policy-satisfying archive-approval evidence, then retry Lite Restore.',
            });
            showToast(preflight?.blockingReason || 'Restore preflight decision is unavailable.', 'warning');
            return;
        }

        const liteResultPanel = document.getElementById('liteRestoreResult');
        if (liteResultPanel) {
            liteResultPanel.style.display = 'none';
            assertLiteRestoreOperation(operation);
            liteResultPanel.replaceChildren();
            assertLiteRestoreOperation(operation);
        }

        clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
        assertLiteRestoreOperation(operation);
        const verificationOptions = await collectRestoreVerificationOptions('liteRestore', selectedFiles, {
            expectedEd25519Signer,
        });
        assertLiteRestoreOperation(operation);
        if (!verificationOptions.shardFiles.length) {
            throw new Error('No .qcont shard files were detected in selected input.');
        }
        if (verificationOptions.ignoredFileNames.length > 0) {
            logWarning(`Ignored ${verificationOptions.ignoredFileNames.length} non-restore attachment(s).`, { isLiteMode: true });
            assertLiteRestoreOperation(operation);
        }

        // Parse shards using shared function
        shardBytesArr = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
        assertLiteRestoreOperation(operation);
        parsedShards = await Promise.all(shardBytesArr.map((arr) => parseLifecycleShard(arr, { strict: true })));
        assertLiteRestoreOperation(operation);
        
        // Log restoration start
        const containerId = parsedShards[0]?.metaJSON?.containerId;
        logRestoration(verificationOptions.shardFiles.length, containerId, { isLiteMode: true });
        assertLiteRestoreOperation(operation);
        
        // Restore using shared core logic
        result = await restoreFromShards(parsedShards, {
            onLog: (msg) => {
                assertLiteRestoreOperation(operation);
                log(msg, { isLiteMode: true });
                assertLiteRestoreOperation(operation);
            },
            onError: (msg) => {
                assertLiteRestoreOperation(operation);
                logError(msg, { isLiteMode: true });
                assertLiteRestoreOperation(operation);
            },
            onWarn: (msg) => {
                assertLiteRestoreOperation(operation);
                logWarning(msg, { isLiteMode: true });
                assertLiteRestoreOperation(operation);
            },
            verification: verificationOptions,
        });
        assertLiteRestoreOperation(operation);

        logRestoreSelectionSummary(result, (message) => {
            assertLiteRestoreOperation(operation);
            log(message, { isLiteMode: true });
            assertLiteRestoreOperation(operation);
        });
        assertLiteRestoreOperation(operation);
        logVerificationSummary(
            result.authenticity,
            (message) => {
                assertLiteRestoreOperation(operation);
                log(message, { isLiteMode: true });
                assertLiteRestoreOperation(operation);
            },
            (message) => {
                assertLiteRestoreOperation(operation);
                logWarning(message, { isLiteMode: true });
                assertLiteRestoreOperation(operation);
            },
            (message) => {
                assertLiteRestoreOperation(operation);
                logSuccess(message, { isLiteMode: true });
                assertLiteRestoreOperation(operation);
            },
        );
        assertLiteRestoreOperation(operation);

        const { qencBytes, privKey, qencOk, qkeyOk } = result;
        
        if (!qencOk || !qkeyOk) {
            showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
                title: 'Lite restore failed',
                cause: 'Recovered container or private key failed integrity verification.',
                artifact: summarizeLiteRestoreInputs(selectedFiles),
                action: 'Replace corrupted or wrong-cohort shards, then retry Lite Restore.',
            });
            logError('Hash verification failed for container', { isLiteMode: true });
            buildRestoreResultSummary(result, 'liteRestoreResult', {
                liteDecrypt: { containerOk: false, decryptOk: false },
            });
            return;
        }
        
        const { decryptedBlob, metadata } = await decryptFile(qencBytes, privKey);
        assertLiteRestoreOperation(operation);
        decBytes = await readFileAsUint8Array(decryptedBlob);
        assertLiteRestoreOperation(operation);
        const decHash = await hashBytes(decBytes);
        assertLiteRestoreOperation(operation);
        const integrityOk = metadata.fileHash === decHash;

        if (!integrityOk) {
            showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
                title: 'Lite restore failed',
                cause: 'Decrypted file hash does not match the container metadata.',
                artifact: summarizeLiteRestoreInputs(selectedFiles),
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
            bundleEntries = parseBundlePayload(decBytes);
            for (const entry of bundleEntries) {
                assertLiteRestoreOperation(operation);
                publishLiteRestoreBlob(operation, new Blob([entry.bytes]), entry.name);
            }
            restoredLabel = `${bundleEntries.length} files bundle`;
        } else {
            const originalName = metadata.originalFilename || `restored-${result.containerId.slice(0, 8)}.file`;

            assertLiteRestoreOperation(operation);
            publishLiteRestoreBlob(operation, new Blob([decBytes]), originalName);
            restoredLabel = originalName;
        }

        assertLiteRestoreOperation(operation);
        const encryptionTime = metadata.timestamp || 'Unknown';
        logRestorationSuccess(restoredLabel, decBytes.length, encryptionTime, true, { isLiteMode: true });
        assertLiteRestoreOperation(operation);
        logSuccess('Container restored successfully from a policy-satisfying archive cohort', { isLiteMode: true });
        assertLiteRestoreOperation(operation);
        clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
        assertLiteRestoreOperation(operation);
        buildRestoreResultSummary(result, 'liteRestoreResult', {
            liteDecrypt: { containerOk: true, decryptOk: true },
        });
        assertLiteRestoreOperation(operation);
        
    } catch (error) {
        if (error instanceof LiteRestoreOperationCancelledError) {
            // A faultable adapter may have dispatched the session boundary and
            // then continued mutating stale presentation before the token check.
            // Re-apply the terminal clear before emitting the fixed audit event.
            runLiteUiBestEffort(clearLiteRestoreSessionPresentation);
            runLiteUiBestEffort(() => {
                logWarning('Lite Restore was cancelled; no new plaintext output was released after cancellation.', { isLiteMode: true });
            });
        } else {
            buildRestorePolicyFailureSummary(error, 'liteRestoreResult');
            showInlineError(LITE_RESTORE_INLINE_ERROR_ID, {
                title: 'Lite restore blocked',
                cause: error,
                artifact: summarizeLiteRestoreInputs(selectedFiles),
                action: liteRestoreRecoveryAction(error),
            });
            logError(error, { isLiteMode: true });
        }
    } finally {
        for (const entry of bundleEntries) {
            try { wipeBytes(entry?.bytes); } catch { /* Continue cleanup. */ }
        }
        for (const shard of parsedShards) {
            try { zeroizeParsedLifecycleShard(shard); } catch { /* Continue cleanup. */ }
        }
        try { wipeBytes(...shardBytesArr, decBytes); } catch { /* Continue cleanup. */ }
        try { wipeRestoreResult(result); } catch { /* Continue cleanup. */ }
        selectedFiles.length = 0;
        if (operation.cancelled) {
            // Failure-only adapters can dispatch a synchronous session boundary
            // and then finish stale DOM mutation without reaching the catch
            // branch. Re-apply the terminal clear unconditionally at settlement.
            runLiteUiBestEffort(clearLiteRestoreSessionPresentation);
        }
        if (liteRestoreOperation === operation) liteRestoreOperation = null;
        runLiteUiBestEffort(() => setWorkflowBusy('liteViewRestore', false));
        runLiteUiBestEffort(updateCreateShardsButton);
        if (!operation.cancelled) void updateShardsStatus();
        runLiteUiBestEffort(() => {
            setTimeout(() => updateLitePipeline('liteViewRestore', null), 2000);
        });
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

    if (viewProtect && viewRestore) {
        liteTabController = initRovingTablist({ tabIds, panelByTabId });
        refreshLiteWorkflowNavigation();
    }
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

function unresolvedLiteCreateCustodyState() {
    const activeKind = liteExportController?.kind || liteExportPreparationKind;
    if (activeKind === 'key-backup') return 'key-backup';
    if (liteReimportVerification) {
        return liteExportController ? 'verification' : 'verification-settling';
    }
    if (
        activeKind === 'archive' ||
        liteCreateInProgress ||
        liteArchiveKeys.hasActiveOperation()
    ) {
        return 'archive';
    }
    if (liteArchiveKeys.hasRetainedKeyPair()) return 'retained-key';
    return null;
}

function unresolvedLiteModeSwitchState() {
    if (liteRestoreOperation) {
        return liteRestoreOperation.cancelled ? 'restore-settling' : 'restore';
    }
    return unresolvedLiteCreateCustodyState();
}

// Mode switching
function toggleMode() {
    const modeToggle = document.getElementById('modeToggle');
    const liteSection = document.getElementById('liteMode');
    const proSection = document.getElementById('proMode');
    const liteNav = document.getElementById('liteNav');
    const proNav = document.getElementById('proNav');
    
    if (!modeToggle || !liteSection || !proSection) return;

    const unresolvedState = unresolvedLiteModeSwitchState();
    if (modeToggle.checked && unresolvedState) {
        modeToggle.checked = false;
        isLiteMode = true;
        const message = unresolvedState === 'restore'
            ? 'Wait for the active Lite Restore to finish before switching modes.'
            : (unresolvedState === 'restore-settling'
                ? 'Wait for cancelled Lite Restore work to settle before switching modes.'
                : (unresolvedState === 'retained-key'
            ? 'Export or explicitly discard the pending 1-of-1 key before switching modes.'
            : (unresolvedState === 'key-backup'
                ? 'Complete or explicitly cancel the active 1-of-1 key export before switching modes.'
                : (unresolvedState === 'verification'
                    ? 'Complete or explicitly cancel the active artifact verification before switching modes.'
                    : (unresolvedState === 'verification-settling'
                        ? 'Wait for cancelled artifact verification to settle before switching modes.'
                        : 'Complete or explicitly cancel the active Lite archive export before switching modes.')))));
        showToast(message, 'warning');
        logWarning('Mode switch blocked because a Lite custody workflow remains unresolved.', { isLiteMode: true });
        refreshLiteKeyAvailability();
        updateCreateShardsButton();
        return;
    }
    
    // Toggle is now inverted: checked = Pro mode, unchecked = Lite mode
    isLiteMode = !modeToggle.checked;
    
    if (isLiteMode) {
        liteSection.style.display = 'block';
        proSection.style.display = 'none';
        if (liteNav) liteNav.classList.remove('initially-hidden');
        if (proNav) proNav.classList.add('initially-hidden');
        log('Switched to Lite Mode', { isLiteMode: true });
        refreshLiteKeyAvailability();
        refreshLiteExternalCopyWarning();
    } else {
        // Active workflows and pending key decisions are blocked above. This
        // cleanup covers only idle Lite state before entering Pro mode.
        wipeLiteModeSessionSecrets();
        liteSection.style.display = 'none';
        proSection.style.display = 'block';
        if (liteNav) liteNav.classList.add('initially-hidden');
        if (proNav) proNav.classList.remove('initially-hidden');
        log('Switched to Pro Mode', { isLiteMode: false });
        
        const pubFile = document.getElementById('pubKeyInput')?.files?.[0];
        const secFile = document.getElementById('privKeyInput')?.files?.[0];
        updateSidebarStatus(Boolean(pubFile), Boolean(secFile));
    }

    updateOperationsLogVisibility();
}

// Initialize Lite Mode
export function initLiteMode() {
    if (!nativeLiteInputValueSetter || !nativeLiteInputFilesGetter) {
        const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
        const filesDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'files');
        nativeLiteInputValueSetter = typeof valueDescriptor?.set === 'function'
            ? valueDescriptor.set
            : null;
        nativeLiteInputFilesGetter = typeof filesDescriptor?.get === 'function'
            ? filesDescriptor.get
            : null;
    }
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

    const externalCopyWarningPanel = document.getElementById('liteExternalCopyWarning');
    const externalCopyWarningSummary = document.getElementById('liteExternalCopyWarningSummary');
    if (
        externalCopyWarningPanel instanceof HTMLElement &&
        externalCopyWarningSummary instanceof HTMLElement &&
        externalCopyWarningPanel.contains(externalCopyWarningSummary)
    ) {
        boundLiteExternalCopyWarningPanel = externalCopyWarningPanel;
        boundLiteExternalCopyWarningSummary = externalCopyWarningSummary;
    }

    const initialLiteExportControls = [
        document.getElementById('liteExportSessionPanel'),
        document.getElementById('liteExportSessionTitle'),
        document.getElementById('liteExportSessionStatus'),
        document.getElementById('liteExportSessionRows'),
        document.getElementById('liteExportReimportInput'),
        document.getElementById('liteExportReimportBtn'),
        document.getElementById('liteExportCancelBtn'),
    ];
    const initialLiteExportPanel = initialLiteExportControls[0];
    if (
        initialLiteExportPanel instanceof HTMLElement &&
        initialLiteExportControls.every((control) => control instanceof HTMLElement) &&
        initialLiteExportControls.slice(1).every((control) => initialLiteExportPanel.contains(control))
    ) {
        for (const control of initialLiteExportControls) boundLiteExportControls.add(control);
    }

    const rawKeyAcknowledgement = document.getElementById('liteRetainRawKeyAck');
    if (rawKeyAcknowledgement instanceof HTMLInputElement && rawKeyAcknowledgement.type === 'checkbox') {
        boundLiteRawKeyAcknowledgement = rawKeyAcknowledgement;
        // Browser form restoration is not an authorization event. Always begin
        // default-off, then accept only a trusted change on this exact node.
        resetLiteRawKeyBackupAcknowledgement();
        rawKeyAcknowledgement.addEventListener('change', (event) => {
            if (
                event.isTrusted &&
                rawKeyAcknowledgement === boundLiteRawKeyAcknowledgement &&
                rawKeyAcknowledgement.isConnected &&
                !rawKeyAcknowledgement.disabled
            ) {
                liteRawKeyBackupGrant = rawKeyAcknowledgement.checked === true;
            } else {
                resetLiteRawKeyBackupAcknowledgement();
            }
        });
    } else {
        resetLiteRawKeyBackupAcknowledgement();
    }
    
    // Set up threshold calculation for manual inputs
    const liteN = document.getElementById('liteN');
    const liteThreshold = document.getElementById('liteThreshold');
    const liteAuthPolicy = document.getElementById('liteAuthPolicy');
    const liteAuthPolicyHelp = document.getElementById('liteAuthPolicyHelp');
    const liteAuthPolicyConsequence = document.getElementById('liteAuthPolicyConsequence');
    if (
        liteN instanceof HTMLInputElement && liteN.type === 'number' &&
        liteThreshold instanceof HTMLInputElement && liteThreshold.type === 'number'
    ) {
        boundLiteNControl = liteN;
        boundLiteThresholdControl = liteThreshold;
        liteN.addEventListener('input', updateThresholdDisplay);
        liteThreshold.addEventListener('input', updateThresholdDisplay);
        updateThresholdDisplay(); // Initial calculation
    }
    if (liteAuthPolicy instanceof HTMLSelectElement) {
        boundLiteAuthPolicyControl = liteAuthPolicy;
    }
    if (liteAuthPolicy && liteAuthPolicyHelp) {
        const syncLiteAuthPolicyHelp = () => {
            const policyLevel = String(liteAuthPolicy.value).trim();
            liteAuthPolicyHelp.textContent = describeAuthPolicyHelp(policyLevel);
            renderAuthPolicyConsequence(liteAuthPolicyConsequence, policyLevel);
            updateCreateShardsButton();
        };
        liteAuthPolicy.addEventListener('change', syncLiteAuthPolicyHelp);
        syncLiteAuthPolicyHelp();
    }
    
    // Set up file input monitoring
    const liteFilesInput = document.getElementById('liteFilesInput');
    if (liteFilesInput instanceof HTMLInputElement && liteFilesInput.type === 'file') {
        boundLitePlaintextInput = liteFilesInput;
        liteFilesInput.addEventListener('change', () => {
            updateFileListDisplay();
            updateCreateShardsButton();
        });
        liteFilesInput.disabled = false;
    }
    
    // Set up shard input monitoring
    const liteShardsInput = document.getElementById('liteShardsInput');
    if (liteShardsInput instanceof HTMLInputElement && liteShardsInput.type === 'file') {
        boundLiteRestoreInput = liteShardsInput;
        liteRestoreShardRefresh.bindInput(liteShardsInput);
        liteShardsInput.addEventListener('change', () => {
            clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
            void updateShardsStatus();
        });
        void updateShardsStatus();
    }
    const liteRestoreExpectedSigner = document.getElementById('liteRestoreExpectedEdSigner');
    if (liteRestoreExpectedSigner instanceof HTMLInputElement) {
        boundLiteRestoreExpectedSignerControl = liteRestoreExpectedSigner;
    }
    const liteRestorePreflightRoot = document.getElementById('liteRestorePreflightDecision');
    if (liteRestorePreflightRoot instanceof HTMLElement) {
        boundLiteRestorePreflightRoot = liteRestorePreflightRoot;
    }
    liteRestoreExpectedSigner?.addEventListener('input', () => {
        const currentShardsInput = document.getElementById('liteShardsInput');
        if (
            liteRestoreExpectedSigner !== boundLiteRestoreExpectedSignerControl ||
            !liteRestoreExpectedSigner.isConnected ||
            currentShardsInput !== boundLiteRestoreInput ||
            !currentShardsInput?.isConnected
        ) {
            clearLiteRestoreSessionPresentation();
            return;
        }
        clearInlineError(LITE_RESTORE_INLINE_ERROR_ID);
        const files = [...(currentShardsInput.files || [])];
        if (files.length) {
            void renderRestorePreflightForFiles({
                prefix: 'liteRestore',
                containerId: 'liteRestorePreflightDecision',
                files,
                expectedSignerInput: document.getElementById('liteRestoreExpectedEdSigner'),
                actionButton: document.getElementById('liteRestoreBtn'),
            });
        }
    });
    
    // Set up button handlers
    const liteDownloadKeysBtn = document.getElementById('liteDownloadKeysBtn');
    const liteDiscardKeysBtn = document.getElementById('liteDiscardKeysBtn');
    if (
        liteDownloadKeysBtn instanceof HTMLButtonElement &&
        liteDiscardKeysBtn instanceof HTMLButtonElement &&
        liteDownloadKeysBtn.parentElement instanceof HTMLElement &&
        liteDownloadKeysBtn.parentElement === liteDiscardKeysBtn.parentElement
    ) {
        boundLiteDownloadKeysButton = liteDownloadKeysBtn;
        boundLiteDiscardKeysButton = liteDiscardKeysBtn;
        boundLiteKeyDecisionRoot = liteDownloadKeysBtn.parentElement;
        liteDownloadKeysBtn.addEventListener('click', downloadLiteKeys);
        liteDiscardKeysBtn.addEventListener('click', discardPendingLiteKeys);
        if (!liteKeyDecisionObserver) {
            liteKeyDecisionObserver = new MutationObserver(() => {
                if (!liteArchiveKeys.hasRetainedKeyPair()) return;

                // Audit the current decision surface without observing the
                // idempotent repairs made by the audit itself. Otherwise the
                // status/button mutations enqueue an unbounded microtask loop
                // that can starve export verification while a key is retained.
                // Any hostile mutation that triggered this callback is already
                // reflected in the DOM and is checked synchronously below.
                const observer = liteKeyDecisionObserver;
                observer?.disconnect();
                try {
                    runLiteUiBestEffort(refreshLiteKeyAvailability);
                } finally {
                    if (observer === liteKeyDecisionObserver && boundLiteKeyDecisionRoot instanceof HTMLElement) {
                        observer.observe(boundLiteKeyDecisionRoot, {
                            attributes: true,
                            childList: true,
                            subtree: true,
                        });
                    }
                }
            });
            liteKeyDecisionObserver.observe(boundLiteKeyDecisionRoot, {
                attributes: true,
                childList: true,
                subtree: true,
            });
        }
    }

    const liteExportReimportInput = document.getElementById('liteExportReimportInput');
    const liteExportReimportButton = document.getElementById('liteExportReimportBtn');
    if (liteExportReimportButton && liteExportReimportInput) {
        liteExportReimportButton.addEventListener('click', () => {
            if (!liteExportReimportInput.disabled) {
                liteExportReimportInput.click();
            }
        });
        boundLiteExportControls.add(liteExportReimportButton);
    }
    if (liteExportReimportInput) {
        liteExportReimportInput.addEventListener('change', () => {
            const files = [];
            let validSelection = false;
            try {
                const selected = typeof nativeLiteInputFilesGetter === 'function'
                    ? nativeLiteInputFilesGetter.call(liteExportReimportInput)
                    : liteExportReimportInput.files;
                const count = Number(selected?.length || 0);
                if (Number.isSafeInteger(count) && count >= 1 && count <= MAX_BROWSER_EXPORT_ARTIFACTS) {
                    for (let index = 0; index < count; index += 1) {
                        const file = selected[index];
                        if (!(file instanceof File)) throw new Error('Invalid re-import selection.');
                        files.push(file);
                    }
                    validSelection = true;
                }
            } catch {
                validSelection = false;
            }

            // Use the captured native setter, verify the FileList is empty, and
            // quarantine a node that cannot release its filename-bearing refs.
            const inputCleared = clearLiteFileInputNode(liteExportReimportInput);
            if (!inputCleared) {
                releaseLiteReimportFileRefs(files);
                cancelLiteExportSession({ announce: false });
                logError('Artifact re-import control could not release its selected files; the Lite export session failed closed.', { isLiteMode: true });
                showToast('Artifact re-import control failed closed; reload before starting another Lite export.', 'error');
                return;
            }
            if (!validSelection) {
                releaseLiteReimportFileRefs(files);
                logError('Artifact re-import selection exceeded the fixed verification profile.', { isLiteMode: true });
                showToast('Artifact re-import selection was rejected by the fixed verification profile.', 'error');
                return;
            }
            void verifyLiteExportReimports(files);
        });
        boundLiteExportControls.add(liteExportReimportInput);
    }

    const liteExportCancelButton = document.getElementById('liteExportCancelBtn');
    if (liteExportCancelButton) {
        liteExportCancelButton.addEventListener('click', () => {
            cancelLiteExportSession();
        });
        boundLiteExportControls.add(liteExportCancelButton);
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
    refreshLiteKeyAvailability();
    refreshLiteExternalCopyWarning();
    
    log('Lite Mode initialized - toggle to switch to Pro mode', { isLiteMode: true });
}
