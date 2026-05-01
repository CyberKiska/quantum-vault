// --- Quantum Vault Application Entry Point ---

// UI Components and Features
import { initUI } from './core/features/ui/ui.js';
import { initQcontBuildUI } from './core/features/qcont/build-ui.js';
import { initQcontAttachUI } from './core/features/qcont/attach-ui.js';
import { initQcontReshareUI } from './core/features/qcont/reshare-ui.js';
import { initQcontRestoreUI } from './core/features/qcont/restore-ui.js';
import { initLiteMode } from './core/features/lite-mode.js';
import { initDisclosureShells } from './core/features/ui/disclosure.js';
import { initArchiveReviewHubRoots } from './core/features/ui/archive-review-hub.js';
import { installSessionWipeGuards } from './app/session-wipe.js';

const TRANSIENT_PANEL_IDS = [
    'attachResult',
    'liteRestoreResult',
    'liteRestoreInlineError',
    'proReshareResult',
    'proRestoreResult',
    'proRestoreInlineError',
    'restorePreflightDecision',
    'liteRestorePreflightDecision',
    'proSplitInlineError',
    'attachStatus',
    'attachArtifactIntake',
    'attachPlanDecision',
    'attachInlineError',
    'proReviewStatus',
    'reviewArtifactIntake',
    'resharePlanDecision',
    'reshareArtifactIntake',
    'proShardsStatus',
    'restoreArtifactIntake',
    'shardsStatus',
    'liteRestoreArtifactIntake',
    'restoreArchiveInspector',
    'reviewArchiveInspector',
    'attachArchiveInspector',
    'reshareArchiveInspector',
    'liteRestoreArchiveInspector',
    'reshareSuccessorSelection',
    'restoreSuccessorSelection',
    'liteRestoreSuccessorSelection',
];

let transientResetHandlerInstalled = false;

function resetSelectToDefault(select) {
    const options = Array.from(select.options || []);
    const defaultIndex = options.findIndex((option) => option.defaultSelected);
    if (defaultIndex >= 0) {
        select.selectedIndex = defaultIndex;
    } else if (options.length > 0) {
        select.selectedIndex = 0;
    } else {
        select.selectedIndex = -1;
    }
}

function resetControlToDefault(control) {
    const tagName = String(control?.tagName || '').toLowerCase();
    if (!tagName) return;

    if (tagName === 'select') {
        resetSelectToDefault(control);
        return;
    }

    const type = String(control?.type || '').toLowerCase();
    if (type === 'file') {
        control.value = '';
        return;
    }
    if (type === 'checkbox' || type === 'radio') {
        control.checked = Boolean(control.defaultChecked);
        return;
    }

    control.value = control.defaultValue ?? '';
}

function clearTransientPanels() {
    for (const id of TRANSIENT_PANEL_IDS) {
        const element = document.getElementById(id);
        if (!element) continue;
        element.style.display = 'none';
        if (
            element.classList.contains('restore-result-panel') ||
            element.classList.contains('inline-error-panel') ||
            element.classList.contains('artifact-intake-panel') ||
            element.id.endsWith('ArchiveInspector')
        ) {
            element.replaceChildren();
            if (element.id.endsWith('ArchiveInspector')) {
                element.className = 'archive-inspector-host initially-hidden';
            }
        } else if (element.id === 'restorePreflightDecision' || element.id === 'liteRestorePreflightDecision') {
            element.replaceChildren();
            element.className = 'qv-decision-card restore-preflight-card decision-card initially-hidden';
            element.removeAttribute('data-release-state');
            element.setAttribute('data-testid', element.id === 'liteRestorePreflightDecision' ? 'lite-restore-preflight' : 'restore-preflight');
        } else if (element.id === 'attachPlanDecision' || element.id === 'resharePlanDecision') {
            element.replaceChildren();
            element.className = 'initially-hidden';
            element.setAttribute('data-testid', element.id === 'attachPlanDecision' ? 'attach-plan-decision' : 'reshare-plan-decision');
        } else if (element.tagName === 'PRE') {
            element.textContent = '';
        }
    }
}

function resetTransientUiState({ dispatchEvents = false } = {}) {
    if (typeof document === 'undefined') return;

    const controls = Array.from(document.querySelectorAll('input, textarea, select'));
    controls.forEach((control) => resetControlToDefault(control));
    clearTransientPanels();

    if (!dispatchEvents) return;

    controls.forEach((control) => {
        const tagName = String(control?.tagName || '').toLowerCase();
        const type = String(control?.type || '').toLowerCase();
        const primaryEvent = (tagName === 'textarea' || type === 'text' || type === 'number')
            ? 'input'
            : 'change';
        control.dispatchEvent(new Event(primaryEvent, { bubbles: true }));
        if (primaryEvent !== 'change') {
            control.dispatchEvent(new Event('change', { bubbles: true }));
        }
    });
}

// Initialize the application
export function initializeApplication() {
    resetTransientUiState();
    installSessionWipeGuards();

    // Initialize all UI components
    initUI();
    initQcontBuildUI();
    initQcontAttachUI();
    initQcontReshareUI();
    initQcontRestoreUI();
    initLiteMode();
    initDisclosureShells();
    initArchiveReviewHubRoots();

    console.log('Quantum Vault application initialized successfully');
}

if (typeof window !== 'undefined') {
    if (!transientResetHandlerInstalled) {
        window.addEventListener('pageshow', (event) => {
            if (event.persisted) {
                resetTransientUiState({ dispatchEvents: true });
            }
        });
        transientResetHandlerInstalled = true;
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeApplication);
    } else {
        initializeApplication();
    }
}
