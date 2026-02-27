import { bytesToHex as nobleBytesToHex, hexToBytes as nobleHexToBytes } from '@noble/hashes/utils.js';

export function bytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function bytesToHex(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('bytes must be Uint8Array');
  return nobleBytesToHex(bytes).toLowerCase();
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex must be string');
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  return nobleHexToBytes(hex);
}

export function utf8ToBytes(value) {
  return new TextEncoder().encode(String(value));
}

export function bytesToUtf8(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('bytes must be Uint8Array');
  return new TextDecoder().decode(bytes);
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

export function asciiBytes(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}
