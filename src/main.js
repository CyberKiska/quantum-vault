// --- Quantum Vault Application Entry Point ---

// UI Components and Features
import { initUI } from './core/features/ui/ui.js';
import { initQcontBuildUI } from './core/features/qcont/build-ui.js';
import { initQcontAttachUI } from './core/features/qcont/attach-ui.js';
import { initQcontReshareUI } from './core/features/qcont/reshare-ui.js';
import { initQcontRestoreUI } from './core/features/qcont/restore-ui.js';
import { initLiteMode } from './core/features/lite-mode.js';
import { installSessionWipeGuards } from './app/session-wipe.js';

const TRANSIENT_PANEL_IDS = [
    'attachResult',
    'liteRestoreResult',
    'proReshareResult',
    'proRestoreResult',
    'attachStatus',
    'attachModeSummary',
    'proReshareStatus',
    'proShardsStatus',
    'shardsStatus',
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
        if (element.classList.contains('restore-result-panel')) {
            element.replaceChildren();
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
