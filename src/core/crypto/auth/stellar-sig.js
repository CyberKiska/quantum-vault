import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { base64ToBytes, bytesEqual, bytesToHex, utf8ToBytes } from './bytes.js';

const SIGNATURE_SCHEMA = 'stellar-file-signature/v1';
const MODE_SEP53 = 'sep53';
const MAGIC = 'STELLAR-WSIGN/v1';
const SEP53_PREFIX = 'Stellar Signed Message:\n';

const HASH_ALG = Object.freeze({
  SHA256: 'SHA-256',
  SHA3_512: 'SHA3-512',
});

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STRKEY_VERSION_ED25519_PUBLIC = 6 << 3;

function normalizeAlg(value) {
  const up = String(value || '').trim().toUpperCase();
  if (up === HASH_ALG.SHA256) return HASH_ALG.SHA256;
  if (up === HASH_ALG.SHA3_512) return HASH_ALG.SHA3_512;
  throw new Error(`Unsupported hash algorithm: ${value}`);
}

function expectedHexLength(alg) {
  return alg === HASH_ALG.SHA256 ? 64 : 128;
}

function hashFieldName(alg) {
  return alg === HASH_ALG.SHA256 ? 'sha256' : 'sha3_512';
}

function parseHashEntries(doc) {
  if (!Array.isArray(doc?.hashes) || doc.hashes.length === 0) {
    throw new Error('Signature has no hashes[] entries');
  }
  const out = [];
  const seen = new Set();
  for (const entry of doc.hashes) {
    const alg = normalizeAlg(entry?.alg);
    const hex = String(entry?.hex || '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expectedHexLength(alg)) {
      throw new Error(`Invalid hash hex for ${alg}`);
    }
    if (seen.has(alg)) throw new Error(`Duplicate hash entry: ${alg}`);
    seen.add(alg);
    out.push({ alg, hex });
  }
  return out;
}

function buildExpectedMessage(type, size, entries) {
  const lines = [
    MAGIC,
    `type=${type}`,
    `size=${size}`,
    `hashes=${entries.map((e) => e.alg).join(',')}`,
  ];
  for (const entry of entries) {
    lines.push(`${hashFieldName(entry.alg)}=${entry.hex}`);
  }
  return lines.join('\n');
}

function crc16Xmodem(bytes) {
  let crc = 0x0000;
  for (let i = 0; i < bytes.length; i += 1) {
    crc ^= bytes[i] << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      if ((crc & 0x8000) !== 0) crc = ((crc << 1) ^ 0x1021) & 0xffff;
      else crc = (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function base32Decode(text) {
  const clean = String(text || '').trim().replace(/=+$/g, '');
  if (!clean) throw new Error('Empty base32 string');
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < clean.length; i += 1) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx < 0) throw new Error(`Invalid base32 symbol: ${clean[i]}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

function decodeEd25519PublicKey(address) {
  const str = String(address || '').trim();
  if (str.length !== 56 || !str.startsWith('G') || !/^[A-Z2-7]+$/.test(str)) {
    throw new Error('Invalid Stellar public address format');
  }
  const decoded = base32Decode(str);
  if (decoded.length < 3) throw new Error('Invalid Stellar public address');

  const payload = decoded.subarray(0, decoded.length - 2);
  const checksumBytes = decoded.subarray(decoded.length - 2);
  const expectedCrc = crc16Xmodem(payload);
  const actualCrc = checksumBytes[0] | (checksumBytes[1] << 8);
  if (expectedCrc !== actualCrc) throw new Error('Invalid Stellar public address checksum');

  if (payload[0] !== STRKEY_VERSION_ED25519_PUBLIC) {
    throw new Error('Unexpected Stellar key version byte');
  }

  const raw = payload.subarray(1);
  if (raw.length !== 32) throw new Error('Unexpected Stellar public key length');
  return raw;
}

async function verifyEd25519(publicBytes, messageBytes, signatureBytes) {
  const key = await crypto.subtle.importKey('raw', publicBytes, { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, signatureBytes, messageBytes);
}

export async function verifyStellarSigAgainstBytes({
  messageBytes,
  sigJsonBytes,
  expectedSigner = '',
  allowLegacyEd25519 = true,
}) {
  const warnings = [];

  let doc;
  try {
    doc = JSON.parse(new TextDecoder().decode(sigJsonBytes));
  } catch (error) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: `Invalid JSON signature document: ${error?.message || error}`,
      warnings,
    };
  }

  if (doc?.schema !== SIGNATURE_SCHEMA) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: `Unsupported signature schema: ${String(doc?.schema || '(missing)')}`,
      warnings,
    };
  }

  if (String(doc.mode || '').trim() !== MODE_SEP53) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: `Unsupported .sig mode for Quantum Vault: ${String(doc.mode || '(missing)')}`,
      warnings,
    };
  }

  if (!allowLegacyEd25519) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: 'Legacy Ed25519 signatures are disabled by policy',
      warnings,
    };
  }

  warnings.push('Legacy Ed25519 signature is not post-quantum secure. Prefer .qsig for PQ authenticity.');

  let hashEntries;
  try {
    hashEntries = parseHashEntries(doc);
  } catch (error) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: error?.message || String(error),
      warnings,
    };
  }

  const digests = {
    [HASH_ALG.SHA256]: bytesToHex(sha256(messageBytes)),
    [HASH_ALG.SHA3_512]: bytesToHex(sha3_512(messageBytes)),
  };

  for (const entry of hashEntries) {
    if (digests[entry.alg] !== entry.hex) {
      return {
        ok: false,
        trusted: false,
        type: 'sig',
        error: `Digest mismatch for ${entry.alg}`,
        warnings,
      };
    }
  }

  const inputType = String(doc?.input?.type || 'file').trim();
  const expectedMessage = buildExpectedMessage(inputType, messageBytes.length, hashEntries);
  if (String(doc.message || '') !== expectedMessage) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: 'Deterministic message mismatch',
      warnings,
    };
  }

  let signerPublic;
  const signer = String(doc.signer || '').trim();
  try {
    signerPublic = decodeEd25519PublicKey(signer);
  } catch (error) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: `Invalid signer address: ${error?.message || error}`,
      warnings,
    };
  }

  let trusted = false;
  const expected = String(expectedSigner || '').trim();
  if (expected) {
    if (expected !== signer) {
      return {
        ok: false,
        trusted: false,
        type: 'sig',
        error: `Wrong signer: expected ${expected}, got ${signer}`,
        warnings,
      };
    }
    trusted = true;
  } else {
    warnings.push('No expected signer address pinned; identity assurance is weak.');
  }

  let signatureBytes;
  try {
    signatureBytes = base64ToBytes(String(doc.signatureB64 || ''));
  } catch (error) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: `Malformed signatureB64: ${error?.message || error}`,
      warnings,
    };
  }

  if (signatureBytes.length !== 64) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: `Expected 64-byte Ed25519 signature, got ${signatureBytes.length}`,
      warnings,
    };
  }

  const payload = sha256(utf8ToBytes(SEP53_PREFIX + expectedMessage));
  const sigOk = await verifyEd25519(signerPublic, payload, signatureBytes);
  if (!sigOk) {
    return {
      ok: false,
      trusted: false,
      type: 'sig',
      error: 'Ed25519 signature verification failed',
      warnings,
    };
  }

  return {
    ok: true,
    trusted,
    type: 'sig',
    algorithm: 'Ed25519',
    signer,
    warnings,
  };
}
