// --- Quantum Vault Application Entry Point ---

// UI Components and Features
import { initUI } from './core/features/ui/ui.js';
import { initQcontBuildUI } from './core/crypto/qcont/build-ui.js';
import { initQcontRestoreUI } from './core/crypto/qcont/restore-ui.js';
import { initLiteMode } from './core/features/lite-mode.js';
import { installSessionWipeGuards } from './core/crypto/session-wipe.js';

// Initialize the application
export function initializeApplication() {
    installSessionWipeGuards();

    // Initialize all UI components
    initUI();
    initQcontBuildUI();
    initQcontRestoreUI();
    initLiteMode();

    console.log('Quantum Vault application initialized successfully');
}

// No re-exports here. Should import from './core/crypto/index.js' and './utils.js'.

if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeApplication);
    } else {
        initializeApplication();
    }
}
