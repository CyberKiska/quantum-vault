const QVPACK_MAGIC_TEXT = 'QVB1';
const QVPACK_MAGIC = new TextEncoder().encode(QVPACK_MAGIC_TEXT);
const QVPACK_VERSION = 1;
const MAX_ENTRY_NAME_BYTES = 0xffff;
const MAX_ENTRY_PAYLOAD_BYTES = 0xffffffff;

function assertUint8Array(bytes, label) {
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError(`${label} must be Uint8Array`);
    }
}

function assertEntryName(name) {
    if (typeof name !== 'string' || name.length === 0) {
        throw new Error('QVPACK entry name must be a non-empty string');
    }
    if (/[/\\\0]/.test(name)) {
        throw new Error(`QVPACK entry name must not contain path separators or NUL: "${name}"`);
    }
}

function magicMatches(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < QVPACK_MAGIC.length) {
        return false;
    }
    for (let index = 0; index < QVPACK_MAGIC.length; index += 1) {
        if (bytes[index] !== QVPACK_MAGIC[index]) return false;
    }
    return true;
}

export function buildQvpackPayloadBytes(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
        throw new Error('QVPACK requires at least one entry');
    }
    if (entries.length > MAX_ENTRY_NAME_BYTES) {
        throw new Error(`QVPACK entry count exceeds uint16 capacity: ${entries.length}`);
    }

    const encoder = new TextEncoder();
    const normalized = entries.map((entry, index) => {
        const name = entry?.name;
        const bytes = entry?.bytes;
        assertEntryName(name);
        assertUint8Array(bytes, `QVPACK entry ${index} bytes`);
        const nameBytes = encoder.encode(name);
        if (nameBytes.length === 0 || nameBytes.length > MAX_ENTRY_NAME_BYTES) {
            throw new Error(`Invalid filename length for QVPACK entry: "${name}"`);
        }
        if (bytes.length > MAX_ENTRY_PAYLOAD_BYTES) {
            throw new Error(`File is too large for QVPACK entry: "${name}"`);
        }
        return { name, nameBytes, bytes };
    });

    const totalSize = QVPACK_MAGIC.length + 1 + 2 + normalized.reduce((acc, entry) => (
        acc + 2 + entry.nameBytes.length + 4 + entry.bytes.length
    ), 0);

    const out = new Uint8Array(totalSize);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    let offset = 0;

    out.set(QVPACK_MAGIC, offset);
    offset += QVPACK_MAGIC.length;
    out[offset] = QVPACK_VERSION;
    offset += 1;
    dv.setUint16(offset, normalized.length, false);
    offset += 2;

    for (const entry of normalized) {
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

export function isQvpackPayload(bytes) {
    return bytes instanceof Uint8Array && bytes.length >= 7 && magicMatches(bytes);
}

export function parseQvpackPayload(bytes) {
    if (!isQvpackPayload(bytes)) {
        throw new Error('Not a valid QVPACK payload');
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = QVPACK_MAGIC.length;
    const version = bytes[offset];
    offset += 1;
    if (version !== QVPACK_VERSION) {
        throw new Error(`Unsupported QVPACK version: ${version}`);
    }

    if (offset + 2 > bytes.length) throw new Error('QVPACK is truncated before entry count');
    const count = dv.getUint16(offset, false);
    offset += 2;
    if (count <= 0) throw new Error('QVPACK contains no files');

    const decoder = new TextDecoder();
    const entries = [];
    for (let index = 0; index < count; index += 1) {
        if (offset + 2 > bytes.length) throw new Error('QVPACK is truncated at name length');
        const nameLen = dv.getUint16(offset, false);
        offset += 2;
        if (nameLen <= 0) throw new Error(`QVPACK entry ${index} has invalid filename length`);
        if (offset + nameLen > bytes.length) throw new Error(`QVPACK entry ${index} filename is truncated`);
        const name = decoder.decode(bytes.subarray(offset, offset + nameLen));
        assertEntryName(name);
        offset += nameLen;

        if (offset + 4 > bytes.length) throw new Error(`QVPACK entry ${index} is missing payload length`);
        const size = dv.getUint32(offset, false);
        offset += 4;
        if (offset + size > bytes.length) throw new Error(`QVPACK entry ${index} payload is truncated`);
        const payload = bytes.subarray(offset, offset + size);
        offset += size;

        entries.push({ name, bytes: payload });
    }

    if (offset !== bytes.length) {
        throw new Error('QVPACK has trailing bytes');
    }

    return entries;
}

export { QVPACK_MAGIC_TEXT, QVPACK_VERSION };
