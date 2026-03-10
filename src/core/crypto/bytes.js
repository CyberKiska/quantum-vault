// Consolidated byte utilities for crypto modules

import { bytesToHex as nobleBytesToHex, hexToBytes as nobleHexToBytes } from '@noble/hashes/utils.js';

// Constant-time comparison (best-effort in JS; ref. CWE-208)
export function timingSafeEqual(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

export const bytesEqual = timingSafeEqual;

export function toHex(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error('bytes must be Uint8Array');
    return nobleBytesToHex(bytes).toLowerCase();
}

export const bytesToHex = toHex;

export function fromHex(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
        throw new Error('Invalid hex string');
    }
    return nobleHexToBytes(hex);
}

export const hexToBytes = fromHex;

export function toUint8(x) {
    if (x instanceof Uint8Array) return x;
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
    throw new TypeError('Expected ArrayBuffer or Uint8Array');
}

export function concatBytes(parts) {
    const total = parts.reduce((acc, p) => acc + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

export function utf8ToBytes(value) {
    return new TextEncoder().encode(String(value));
}

export function bytesToUtf8(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error('bytes must be Uint8Array');
    return new TextDecoder().decode(bytes);
}

export function base64ToBytes(value) {
    const normalized = String(value || '').trim();
    if (!normalized) throw new Error('Empty base64 value');
    if (typeof atob === 'function') {
        const raw = atob(normalized);
        const out = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
        return out;
    }
    if (typeof Buffer !== 'undefined') {
        return Uint8Array.from(Buffer.from(normalized, 'base64'));
    }
    throw new Error('No base64 decoder available');
}

export function bytesToBase64(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error('bytes must be Uint8Array');
    if (typeof btoa === 'function') {
        let raw = '';
        for (let i = 0; i < bytes.length; i += 1) raw += String.fromCharCode(bytes[i]);
        return btoa(raw);
    }
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
    }
    throw new Error('No base64 encoder available');
}

export function asciiBytes(text) {
    const out = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i += 1) out[i] = text.charCodeAt(i) & 0xff;
    return out;
}

export async function digestSha256(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        throw new Error('SHA-256 input must be Uint8Array');
    }
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
        throw new Error('Web Crypto API is not available in current runtime');
    }
    return new Uint8Array(await subtle.digest('SHA-256', bytes));
}
