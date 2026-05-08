import { createFilenameTimestamp, readFileAsUint8Array } from '../../utils.js';
import {
    buildQvpackPayloadBytes,
    isQvpackPayload,
    parseQvpackPayload,
} from '../crypto/qvpack.js';

export async function createBundlePayloadFromFiles(files) {
    const entries = [];
    for (const file of files) {
        const bytes = await readFileAsUint8Array(file);
        entries.push({ name: file.name, bytes });
    }

    const bundleName = `bundle-${createFilenameTimestamp()}.qvpack`;
    return {
        bundleName,
        bundleBytes: buildQvpackPayloadBytes(entries),
        fileCount: entries.length
    };
}

export function isBundlePayload(bytes) {
    return isQvpackPayload(bytes);
}

export function parseBundlePayload(bytes) {
    return parseQvpackPayload(bytes);
}
