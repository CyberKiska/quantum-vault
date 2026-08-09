// Ownership boundary for Lite archive-creation key material.
//
// An operation token exists before asynchronous key generation begins so a
// session wipe or explicit cancellation can cancel the operation while an await
// is in flight. A keypair returned after cancellation is wiped instead of adopted.

export class LiteArchiveCreationCancelledError extends Error {
    constructor() {
        super('Lite archive creation was cancelled.');
        this.name = 'LiteArchiveCreationCancelledError';
    }
}

function isByteArray(value) {
    return value instanceof Uint8Array;
}

function assertKeyPair(keyPair) {
    if (
        !keyPair ||
        !isByteArray(keyPair.privateKey) ||
        !isByteArray(keyPair.publicKey) ||
        keyPair.privateKey.length === 0 ||
        keyPair.publicKey.length === 0
    ) {
        throw new Error('Lite archive key generation returned invalid key material.');
    }
}

export function wipeLiteArchiveKeyPair(keyPair) {
    if (isByteArray(keyPair?.privateKey)) {
        try {
            keyPair.privateKey.fill(0);
        } catch {
            // Best-effort cleanup must not interrupt ownership settlement.
        }
    }
    if (isByteArray(keyPair?.publicKey)) {
        try {
            keyPair.publicKey.fill(0);
        } catch {
            // Continue even if another buffer is detached or otherwise unwritable.
        }
    }
}

export function createLiteArchiveKeyLifecycle() {
    let activeOperation = null;
    let retainedKeyPair = null;
    let nextOperationId = 1;

    function assertActive(operation) {
        if (
            !operation ||
            operation !== activeOperation ||
            operation.cancelled ||
            operation.settled
        ) {
            throw new LiteArchiveCreationCancelledError();
        }
    }

    function beginOperation() {
        if (activeOperation) {
            throw new Error('A Lite archive creation is already active.');
        }
        if (retainedKeyPair) {
            throw new Error('Pending Lite archive key material must be exported or discarded first.');
        }

        const operation = {
            id: nextOperationId,
            keyPair: null,
            cancelled: false,
            settled: false,
        };
        nextOperationId += 1;
        activeOperation = operation;
        return operation;
    }

    function adoptKeyPair(operation, keyPair) {
        try {
            assertKeyPair(keyPair);
            assertActive(operation);
            if (operation.keyPair) {
                throw new Error('Lite archive creation already owns a keypair.');
            }
            operation.keyPair = keyPair;
            return keyPair;
        } catch (error) {
            // Ownership was offered to this lifecycle. Never return rejected or
            // late-arriving key material to the caller unwiped.
            wipeLiteArchiveKeyPair(keyPair);
            throw error;
        }
    }

    function getOperationKeyPair(operation) {
        assertActive(operation);
        assertKeyPair(operation.keyPair);
        return operation.keyPair;
    }

    function settleSuccessfulOperation(operation, retainForBackup) {
        const keyPair = getOperationKeyPair(operation);
        if (retainedKeyPair) {
            // This state is unreachable through the public ownership API, but
            // keep settlement fail-closed if a future refactor violates it.
            throw new Error('Lite archive key settlement found unresolved retained material.');
        }

        retainedKeyPair = retainForBackup ? keyPair : null;
        operation.keyPair = null;
        operation.settled = true;
        activeOperation = null;

        if (!retainForBackup) {
            wipeLiteArchiveKeyPair(keyPair);
        }
    }

    function retainAfterSuccess(operation) {
        settleSuccessfulOperation(operation, true);
    }

    function completeWithoutRetention(operation) {
        settleSuccessfulOperation(operation, false);
    }

    function discardOperation(operation) {
        if (!operation || operation.settled) {
            return;
        }

        wipeLiteArchiveKeyPair(operation.keyPair);
        operation.keyPair = null;
        operation.cancelled = true;
        operation.settled = true;
        if (activeOperation === operation) {
            activeOperation = null;
        }
    }

    function cancelActiveOperation() {
        if (!activeOperation) {
            return false;
        }
        discardOperation(activeOperation);
        return true;
    }

    function takeRetainedKeyPair() {
        const keyPair = retainedKeyPair;
        retainedKeyPair = null;
        return keyPair;
    }

    function returnRetainedKeyPair(keyPair) {
        try {
            assertKeyPair(keyPair);
            if (!activeOperation && retainedKeyPair === keyPair) {
                return keyPair;
            }
            if (activeOperation || retainedKeyPair) {
                throw new Error('Lite archive key ownership return was rejected.');
            }
            retainedKeyPair = keyPair;
            return keyPair;
        } catch (error) {
            // A failed ownership return must not strand caller-offered material.
            if (keyPair !== retainedKeyPair && keyPair !== activeOperation?.keyPair) {
                wipeLiteArchiveKeyPair(keyPair);
            }
            throw error;
        }
    }

    function wipeAll() {
        cancelActiveOperation();
        wipeLiteArchiveKeyPair(retainedKeyPair);
        retainedKeyPair = null;
    }

    return Object.freeze({
        beginOperation,
        adoptKeyPair,
        assertActive,
        getOperationKeyPair,
        retainAfterSuccess,
        completeWithoutRetention,
        discardOperation,
        cancelActiveOperation,
        takeRetainedKeyPair,
        returnRetainedKeyPair,
        hasRetainedKeyPair: () => retainedKeyPair !== null,
        hasActiveOperation: () => activeOperation !== null,
        wipeAll,
    });
}
