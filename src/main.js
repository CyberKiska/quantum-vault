// --- Quantum Vault Application Entry Point ---

// UI Components and Features
import { initUI } from './core/features/ui/ui.js';
import { initQcontBuildUI } from './core/features/qcont/build-ui.js';
import { initQcontAttachUI } from './core/features/qcont/attach-ui.js';
import { initQcontRestoreUI } from './core/features/qcont/restore-ui.js';
import { initLiteMode } from './core/features/lite-mode.js';
import { installSessionWipeGuards } from './app/session-wipe.js';

// Initialize the application
export function initializeApplication() {
    installSessionWipeGuards();

    // Initialize all UI components
    initUI();
    initQcontBuildUI();
    initQcontAttachUI();
    initQcontRestoreUI();
    initLiteMode();

    console.log('Quantum Vault application initialized successfully');
}

if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeApplication);
    } else {
        initializeApplication();
    }
}
