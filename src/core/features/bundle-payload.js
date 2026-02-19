import { createFilenameTimestamp, readFileAsUint8Array } from '../../utils.js';

const BUNDLE_MAGIC = new TextEncoder().encode('QVB1');
const BUNDLE_VERSION = 1;

function buildBundlePayloadBytes(entries) {
    const totalSize = 4 + 1 + 2 + entries.reduce((acc, entry) => (
        acc + 2 + entry.nameBytes.length + 4 + entry.bytes.length
    ), 0);

    const out = new Uint8Array(totalSize);
    const dv = new DataView(out.buffer);
    let offset = 0;

    out.set(BUNDLE_MAGIC, offset);
    offset += 4;
    out[offset] = BUNDLE_VERSION;
    offset += 1;
    dv.setUint16(offset, entries.length, false);
    offset += 2;

    for (const entry of entries) {
        dv.setUint16(offset, entry.nameBytes.length, false);
        offset += 2;
        out.set(entry.nameBytes, offset);
        offset += entry.nameBytes.length;
        dv.setUint32(offset, entry.bytes.length, false);
        offset += 4;
        out.set(entry.bytes, offset);
        offset += entry.bytes.length;
    }

    return out;
}

export async function createBundlePayloadFromFiles(files) {
    const encoder = new TextEncoder();
    const entries = [];
    for (const file of files) {
        const bytes = await readFileAsUint8Array(file);
        const nameBytes = encoder.encode(file.name);
        if (nameBytes.length === 0 || nameBytes.length > 0xffff) {
            throw new Error(`Invalid filename length for bundle entry: "${file.name}"`);
        }
        if (bytes.length > 0xffffffff) {
            throw new Error(`File is too large for bundle format: "${file.name}"`);
        }
        entries.push({ name: file.name, nameBytes, bytes });
    }

    const bundleName = `bundle-${createFilenameTimestamp()}.qvpack`;
    return {
        bundleName,
        bundleBytes: buildBundlePayloadBytes(entries),
        fileCount: entries.length
    };
}

export function isBundlePayload(bytes) {
    return (
        bytes instanceof Uint8Array &&
        bytes.length >= 7 &&
        bytes[0] === BUNDLE_MAGIC[0] &&
        bytes[1] === BUNDLE_MAGIC[1] &&
        bytes[2] === BUNDLE_MAGIC[2] &&
        bytes[3] === BUNDLE_MAGIC[3]
    );
}

export function parseBundlePayload(bytes) {
    if (!isBundlePayload(bytes)) {
        throw new Error('Not a valid bundle payload');
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 4;
    const version = bytes[offset];
    offset += 1;
    if (version !== BUNDLE_VERSION) {
        throw new Error(`Unsupported bundle version: ${version}`);
    }

    if (offset + 2 > bytes.length) throw new Error('Bundle is truncated before entry count');
    const count = dv.getUint16(offset, false);
    offset += 2;
    if (count <= 0) throw new Error('Bundle contains no files');

    const decoder = new TextDecoder();
    const entries = [];
    for (let i = 0; i < count; i++) {
        if (offset + 2 > bytes.length) throw new Error('Bundle is truncated at name length');
        const nameLen = dv.getUint16(offset, false);
        offset += 2;
        if (nameLen <= 0) throw new Error(`Bundle entry ${i} has invalid filename length`);
        if (offset + nameLen > bytes.length) throw new Error(`Bundle entry ${i} filename is truncated`);
        const name = decoder.decode(bytes.subarray(offset, offset + nameLen));
        offset += nameLen;

        if (offset + 4 > bytes.length) throw new Error(`Bundle entry ${i} is missing payload length`);
        const size = dv.getUint32(offset, false);
        offset += 4;
        if (offset + size > bytes.length) throw new Error(`Bundle entry ${i} payload is truncated`);
        const payload = bytes.subarray(offset, offset + size);
        offset += size;

        entries.push({ name, bytes: payload });
    }

    if (offset !== bytes.length) {
        throw new Error('Bundle has trailing bytes');
    }

    return entries;
}
