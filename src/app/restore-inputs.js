import { bytesEqual } from '../core/crypto/bytes.js';
import { parseArchiveManifestBytes } from '../core/crypto/manifest/archive-manifest.js';
import { readFileAsUint8Array } from '../utils.js';

const QCONT_MAGIC = 'QVC1';

function startsWithAscii(bytes, ascii) {
    if (!(bytes instanceof Uint8Array)) return false;
    if (bytes.length < ascii.length) return false;
    for (let i = 0; i < ascii.length; i += 1) {
        if (bytes[i] !== ascii.charCodeAt(i)) return false;
    }
    return true;
}

function tryParseJsonBytes(bytes) {
    try {
        return JSON.parse(new TextDecoder().decode(bytes));
    } catch {
        return null;
    }
}

export async function classifyRestoreInputFiles(files) {
    const shardFiles = [];
    const signatures = [];
    const ignoredFileNames = [];
    const manifestCandidates = [];
    let trustedPqPublicKeyFileBytes = null;

    for (const file of files) {
        const name = String(file?.name || 'unnamed');
        const lowerName = name.toLowerCase();

        if (lowerName.endsWith('.qcont')) {
            shardFiles.push(file);
            continue;
        }

        const bytes = await readFileAsUint8Array(file);

        if (startsWithAscii(bytes, QCONT_MAGIC)) {
            shardFiles.push(file);
            continue;
        }

        if (startsWithAscii(bytes, 'PQPK') || lowerName.endsWith('.pqpk')) {
            if (!trustedPqPublicKeyFileBytes) {
                trustedPqPublicKeyFileBytes = bytes;
            } else if (!bytesEqual(trustedPqPublicKeyFileBytes, bytes)) {
                throw new Error('Multiple different .pqpk files were provided. Keep only one trusted PQ key.');
            }
            continue;
        }

        if (startsWithAscii(bytes, 'PQSG') || lowerName.endsWith('.qsig')) {
            signatures.push({ name, bytes });
            continue;
        }

        const parsedJson = tryParseJsonBytes(bytes);
        if (parsedJson?.schema === 'stellar-file-signature/v1') {
            signatures.push({ name, bytes });
            continue;
        }

        let parsedManifest = null;
        try {
            parsedManifest = parseArchiveManifestBytes(bytes);
        } catch {
            // not a canonical archive manifest
        }

        if (parsedManifest) {
            manifestCandidates.push({
                name,
                bytes: parsedManifest.bytes,
                digestHex: parsedManifest.digestHex,
            });
            continue;
        }

        if (lowerName.endsWith('.qvmanifest.json')) {
            throw new Error(`Invalid canonical manifest file: ${name}`);
        }

        if (lowerName.endsWith('.sig') || lowerName.endsWith('.json')) {
            signatures.push({ name, bytes });
            continue;
        }

        ignoredFileNames.push(name);
    }

    let manifestBytes = null;
    if (manifestCandidates.length > 0) {
        const uniqueDigests = new Set(manifestCandidates.map((item) => item.digestHex));
        if (uniqueDigests.size > 1) {
            throw new Error('Multiple different manifest files were provided. Keep only one canonical manifest.');
        }
        manifestBytes = manifestCandidates[0].bytes;
    }

    return {
        shardFiles,
        manifestBytes,
        signatures,
        trustedPqPublicKeyFileBytes,
        ignoredFileNames,
    };
}

