import { MAX_FILE_SIZE } from './constants.js';

const QVPACK_MAGIC_TEXT = 'QVB1';
const QVPACK_MAGIC = new TextEncoder().encode(QVPACK_MAGIC_TEXT);
const QVPACK_VERSION = 1;
const QVPACK_HEADER_BYTES = QVPACK_MAGIC.length + 1 + 2;
const QVPACK_ENTRY_FIXED_BYTES = 2 + 4;
const UINT16_MAX = 0xffff;
const UINT32_MAX = 0xffffffff;

export const MAX_QVPACK_ENTRY_COUNT = 4096;
export const MAX_QVPACK_ENTRY_NAME_BYTES = 255;
export const MAX_QVPACK_ENTRY_PAYLOAD_BYTES = Math.min(UINT32_MAX, MAX_FILE_SIZE);
export const MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES = MAX_FILE_SIZE;
export const MAX_QVPACK_ENCODED_BYTES = MAX_FILE_SIZE;

export const QVPACK_RESOURCE_PROFILE = Object.freeze({
    maxEntryCount: MAX_QVPACK_ENTRY_COUNT,
    maxEntryNameBytes: MAX_QVPACK_ENTRY_NAME_BYTES,
    maxEntryPayloadBytes: MAX_QVPACK_ENTRY_PAYLOAD_BYTES,
    maxAggregatePayloadBytes: MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES,
    maxEncodedBytes: MAX_QVPACK_ENCODED_BYTES,
});

export class QvpackFormatError extends Error {
    constructor(message) {
        super(message);
        this.name = 'QvpackFormatError';
        this.code = 'QVPACK_FORMAT_INVALID';
    }
}

export class QvpackResourceLimitError extends Error {
    constructor(message) {
        super(message);
        this.name = 'QvpackResourceLimitError';
        this.code = 'QVPACK_RESOURCE_LIMIT';
    }
}

function formatError(message) {
    return new QvpackFormatError(message);
}

function resourceLimitError(message) {
    return new QvpackResourceLimitError(message);
}

function assertUint8Array(bytes, label) {
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError(`${label} must be Uint8Array`);
    }
}

function containsLoneSurrogate(value) {
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (next < 0xdc00 || next > 0xdfff) return true;
            index += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return true;
        }
    }
    return false;
}

function assertEntryName(name) {
    if (typeof name !== 'string' || name.length === 0) {
        throw formatError('QVPACK entry name must be a non-empty string');
    }
    if (containsLoneSurrogate(name)) {
        throw formatError('QVPACK entry name is not valid Unicode');
    }
    if (/[/\\\0]/.test(name)) {
        throw formatError('QVPACK entry name must not contain path separators or NUL');
    }
}

function checkedAdd(left, right, message) {
    if (
        !Number.isSafeInteger(left) ||
        !Number.isSafeInteger(right) ||
        left < 0 ||
        right < 0 ||
        left > Number.MAX_SAFE_INTEGER - right
    ) {
        throw resourceLimitError(message);
    }
    return left + right;
}

function checkedBoundedAdd(left, right, limit, message) {
    const sum = checkedAdd(left, right, message);
    if (sum > limit) {
        throw resourceLimitError(message);
    }
    return sum;
}

function requireAvailable(totalLength, offset, requiredLength, message) {
    if (
        !Number.isSafeInteger(offset) ||
        !Number.isSafeInteger(requiredLength) ||
        offset < 0 ||
        requiredLength < 0 ||
        offset > totalLength ||
        requiredLength > totalLength - offset
    ) {
        throw formatError(message);
    }
    return offset + requiredLength;
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

function assertEntryCount(count) {
    if (count <= 0) {
        throw formatError('QVPACK contains no files');
    }
    if (count > QVPACK_RESOURCE_PROFILE.maxEntryCount) {
        throw resourceLimitError(
            `QVPACK entry count exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxEntryCount})`
        );
    }
}

function assertNameByteLength(length) {
    if (length <= 0) {
        throw formatError('QVPACK entry has invalid filename length');
    }
    if (length > QVPACK_RESOURCE_PROFILE.maxEntryNameBytes) {
        throw resourceLimitError(
            `QVPACK entry filename exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxEntryNameBytes} UTF-8 bytes)`
        );
    }
}

function assertEntryPayloadByteLength(length) {
    if (length > QVPACK_RESOURCE_PROFILE.maxEntryPayloadBytes) {
        throw resourceLimitError(
            `QVPACK entry payload exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxEntryPayloadBytes} bytes)`
        );
    }
}

export function buildQvpackPayloadBytes(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
        throw formatError('QVPACK requires at least one entry');
    }
    assertEntryCount(entries.length);
    if (entries.length > UINT16_MAX) {
        throw resourceLimitError('QVPACK entry count exceeds uint16 framing capacity');
    }

    const encoder = new TextEncoder();
    const seenNames = new Set();
    let aggregatePayloadBytes = 0;
    let totalSize = QVPACK_HEADER_BYTES;
    const normalized = entries.map((entry, index) => {
        const name = entry?.name;
        const bytes = entry?.bytes;
        assertEntryName(name);
        assertUint8Array(bytes, `QVPACK entry ${index} bytes`);
        if (seenNames.has(name)) {
            throw formatError('QVPACK contains a duplicate entry filename');
        }
        seenNames.add(name);
        const nameBytes = encoder.encode(name);
        assertNameByteLength(nameBytes.length);
        assertEntryPayloadByteLength(bytes.length);
        aggregatePayloadBytes = checkedBoundedAdd(
            aggregatePayloadBytes,
            bytes.length,
            QVPACK_RESOURCE_PROFILE.maxAggregatePayloadBytes,
            `QVPACK aggregate payload exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxAggregatePayloadBytes} bytes)`
        );
        totalSize = checkedBoundedAdd(
            totalSize,
            QVPACK_ENTRY_FIXED_BYTES,
            QVPACK_RESOURCE_PROFILE.maxEncodedBytes,
            `QVPACK encoded payload exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxEncodedBytes} bytes)`
        );
        totalSize = checkedBoundedAdd(
            totalSize,
            nameBytes.length,
            QVPACK_RESOURCE_PROFILE.maxEncodedBytes,
            `QVPACK encoded payload exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxEncodedBytes} bytes)`
        );
        totalSize = checkedBoundedAdd(
            totalSize,
            bytes.length,
            QVPACK_RESOURCE_PROFILE.maxEncodedBytes,
            `QVPACK encoded payload exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxEncodedBytes} bytes)`
        );
        return { nameBytes, bytes };
    });

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

    if (offset !== totalSize) {
        throw formatError('QVPACK writer framing invariant failed');
    }
    return out;
}

export function isQvpackPayload(bytes) {
    return bytes instanceof Uint8Array && bytes.length >= QVPACK_HEADER_BYTES && magicMatches(bytes);
}

export function parseQvpackPayload(bytes) {
    assertUint8Array(bytes, 'QVPACK payload');
    if (bytes.length > QVPACK_RESOURCE_PROFILE.maxEncodedBytes) {
        throw resourceLimitError(
            `QVPACK encoded payload exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxEncodedBytes} bytes)`
        );
    }
    if (!isQvpackPayload(bytes)) {
        throw formatError('Not a valid QVPACK payload');
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = QVPACK_MAGIC.length;
    const version = bytes[offset];
    offset += 1;
    if (version !== QVPACK_VERSION) {
        throw formatError(`Unsupported QVPACK version: ${version}`);
    }

    const countEnd = requireAvailable(
        bytes.length,
        offset,
        2,
        'QVPACK is truncated before entry count'
    );
    const count = dv.getUint16(offset, false);
    offset = countEnd;
    assertEntryCount(count);

    // A filename field is already length-delimited, so an initial UTF-8 BOM is
    // filename data rather than a transport signature. Preserve U+FEFF to keep
    // parse/write byte semantics exact and prevent aliases with the plain name.
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const seenNames = new Set();
    let aggregatePayloadBytes = 0;
    const entries = [];
    for (let index = 0; index < count; index += 1) {
        const nameLengthEnd = requireAvailable(
            bytes.length,
            offset,
            2,
            `QVPACK is truncated at entry ${index} name length`
        );
        const nameLen = dv.getUint16(offset, false);
        offset = nameLengthEnd;
        assertNameByteLength(nameLen);
        const nameEnd = requireAvailable(
            bytes.length,
            offset,
            nameLen,
            `QVPACK entry ${index} filename is truncated`
        );
        let name;
        try {
            name = decoder.decode(bytes.subarray(offset, nameEnd));
        } catch {
            throw formatError(`QVPACK entry ${index} filename is not valid UTF-8`);
        }
        assertEntryName(name);
        if (seenNames.has(name)) {
            throw formatError('QVPACK contains a duplicate entry filename');
        }
        seenNames.add(name);
        offset = nameEnd;

        const payloadLengthEnd = requireAvailable(
            bytes.length,
            offset,
            4,
            `QVPACK entry ${index} is missing payload length`
        );
        const size = dv.getUint32(offset, false);
        offset = payloadLengthEnd;
        assertEntryPayloadByteLength(size);
        aggregatePayloadBytes = checkedBoundedAdd(
            aggregatePayloadBytes,
            size,
            QVPACK_RESOURCE_PROFILE.maxAggregatePayloadBytes,
            `QVPACK aggregate payload exceeds resource limit (${QVPACK_RESOURCE_PROFILE.maxAggregatePayloadBytes} bytes)`
        );
        const payloadEnd = requireAvailable(
            bytes.length,
            offset,
            size,
            `QVPACK entry ${index} payload is truncated`
        );
        const payload = bytes.subarray(offset, payloadEnd);
        offset = payloadEnd;

        entries.push({ name, bytes: payload });
    }

    if (offset !== bytes.length) {
        throw formatError('QVPACK has trailing bytes');
    }

    return entries;
}

export { QVPACK_MAGIC_TEXT, QVPACK_VERSION };
