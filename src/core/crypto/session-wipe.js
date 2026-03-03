// Session secret wipe registry.
// Modules with long-lived in-memory secrets should register a wipe callback.

const wipeHandlers = new Set();
let listenersInstalled = false;

function runHandlers() {
    for (const handler of wipeHandlers) {
        try {
            handler();
        } catch {
            // Best-effort wipe: ignore individual handler failures.
        }
    }
}

export function registerSessionWipeHandler(handler) {
    if (typeof handler !== 'function') {
        throw new Error('Session wipe handler must be a function');
    }
    wipeHandlers.add(handler);
    return () => wipeHandlers.delete(handler);
}

export function wipeSessionSecrets() {
    runHandlers();
}

export function installSessionWipeGuards() {
    if (listenersInstalled || typeof window === 'undefined') {
        return;
    }

    const onUnload = () => {
        runHandlers();
    };

    // beforeunload is the architecture-mandated baseline.
    window.addEventListener('beforeunload', onUnload, { capture: true });
    // pagehide improves reliability on mobile browsers.
    window.addEventListener('pagehide', onUnload, { capture: true });

    listenersInstalled = true;
}

