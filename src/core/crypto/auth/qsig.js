import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_shake_128s,
  slh_dsa_shake_192s,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
} from '@noble/post-quantum/slh-dsa.js';
import { asciiBytes, bytesEqual, bytesToHex, bytesToUtf8, concatBytes } from '../bytes.js';
import { getSignatureSuiteInfo } from './signature-suites.js';

const MAGIC_SIG = asciiBytes('PQSG');
const MAGIC_TBS = asciiBytes('QSTB');
const MAGIC_PQPK = asciiBytes('PQPK');
const SUPPORTED_QSIG_CONTEXT = 'quantum-signer/v2';

const MAX_CONTEXT_BYTES = 255;
const MAX_SIGNATURE_BYTES = 64 * 1024;
const MAX_AUTH_METADATA_BYTES = 8 * 1024;
const MAX_DISPLAY_METADATA_BYTES = 4 * 1024;
const MAX_SIGNATURE_FILE_BYTES = 128 * 1024;
const MAX_KEY_BYTES = 16 * 1024;
const MAX_KEY_FILE_BYTES = 32 * 1024;

const KEY_FORMAT_VERSION_MAJOR = 0x01;
const QSIG_FORMAT_VERSION_MAJOR = 0x02;
const QSIG_TBS_VERSION_MAJOR = 0x02;
const FILE_HASH_LEN = 64;
const AUTH_META_DIGEST_LEN = 32;
const FP_ALG_ID_SHA3_256 = 0x01;
const FP_RECORD_LEN = 33;

const SigFlags = Object.freeze({
  CTX_PRESENT: 1 << 0,
  FILENAME_PRESENT: 1 << 1,
  FILESIZE_PRESENT: 1 << 2,
  CREATED_AT_PRESENT: 1 << 3,
});

const KNOWN_SIG_FLAGS =
  SigFlags.CTX_PRESENT |
  SigFlags.FILENAME_PRESENT |
  SigFlags.FILESIZE_PRESENT |
  SigFlags.CREATED_AT_PRESENT;

const MetadataTag = Object.freeze({
  FILENAME: 0x01,
  FILESIZE: 0x02,
  CREATED_AT: 0x03,
  SIGNER_PUBLIC_KEY: 0x10,
  SIGNER_FINGERPRINT: 0x11,
});

const SignatureProfileId = Object.freeze({
  PQ_DETACHED_PURE_CONTEXT_V2: 0x01,
});

const HashAlgId = Object.freeze({
  SHA3_512: 0x01,
});

const AuthDigestAlgId = Object.freeze({
  SHA3_256: 0x01,
});

const Suite = Object.freeze({
  ML_DSA_44: 0x01,
  ML_DSA_65: 0x02,
  ML_DSA_87: 0x03,
  SLH_DSA_SHAKE_128S: 0x11,
  SLH_DSA_SHAKE_192S: 0x12,
  SLH_DSA_SHAKE_256S: 0x13,
  SLH_DSA_SHAKE_256F: 0x14,
});

const SUITE_REGISTRY = Object.freeze({
  [Suite.ML_DSA_44]: { name: 'ML-DSA-44', family: 'ML-DSA', normalizedSuite: 'mldsa-44', signer: ml_dsa44 },
  [Suite.ML_DSA_65]: { name: 'ML-DSA-65', family: 'ML-DSA', normalizedSuite: 'mldsa-65', signer: ml_dsa65 },
  [Suite.ML_DSA_87]: { name: 'ML-DSA-87', family: 'ML-DSA', normalizedSuite: 'mldsa-87', signer: ml_dsa87 },
  [Suite.SLH_DSA_SHAKE_128S]: { name: 'SLH-DSA-SHAKE-128s', family: 'SLH-DSA-SHAKE', normalizedSuite: 'slhdsa-shake-128s', signer: slh_dsa_shake_128s },
  [Suite.SLH_DSA_SHAKE_192S]: { name: 'SLH-DSA-SHAKE-192s', family: 'SLH-DSA-SHAKE', normalizedSuite: 'slhdsa-shake-192s', signer: slh_dsa_shake_192s },
  [Suite.SLH_DSA_SHAKE_256S]: { name: 'SLH-DSA-SHAKE-256s', family: 'SLH-DSA-SHAKE', normalizedSuite: 'slhdsa-shake-256s', signer: slh_dsa_shake_256s },
  [Suite.SLH_DSA_SHAKE_256F]: { name: 'SLH-DSA-SHAKE-256f', family: 'SLH-DSA-SHAKE', normalizedSuite: 'slhdsa-shake-256f', signer: slh_dsa_shake_256f },
});

class Reader {
  constructor(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error('Expected Uint8Array');
    this.bytes = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.offset = 0;
  }

  remaining() {
    return this.bytes.length - this.offset;
  }

  take(len, field = 'bytes') {
    if (!Number.isInteger(len) || len < 0) throw new Error(`Invalid length for ${field}`);
    if (this.offset + len > this.bytes.length) throw new Error(`Truncated ${field}`);
    const out = this.bytes.subarray(this.offset, this.offset + len);
    this.offset += len;
    return out;
  }

  u8(field = 'u8') {
    if (this.remaining() < 1) throw new Error(`Truncated ${field}`);
    const v = this.dv.getUint8(this.offset);
    this.offset += 1;
    return v;
  }

  u16le(field = 'u16') {
    if (this.remaining() < 2) throw new Error(`Truncated ${field}`);
    const v = this.dv.getUint16(this.offset, true);
    this.offset += 2;
    return v;
  }

  u32le(field = 'u32') {
    if (this.remaining() < 4) throw new Error(`Truncated ${field}`);
    const v = this.dv.getUint32(this.offset, true);
    this.offset += 4;
    return v;
  }
}

function suiteInfo(suiteId) {
  const info = SUITE_REGISTRY[suiteId];
  if (!info) throw new Error(`Unsupported detached PQ signature suiteId: ${suiteId}`);
  return info;
}

function ensureBytesLimit(bytes, maxLen, field) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error(`${field} must be Uint8Array`);
  }
  if (bytes.length > maxLen) {
    throw new Error(`${field} exceeds maximum size (${maxLen} bytes)`);
  }
}

function ensureSupportedSignatureProfile(signatureProfileId) {
  if (signatureProfileId !== SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2) {
    throw new Error(`Unsupported detached PQ signature profile: ${signatureProfileId}`);
  }
}

function ensureSupportedHashAlg(hashAlgId) {
  if (hashAlgId !== HashAlgId.SHA3_512) {
    throw new Error(`Unsupported detached PQ signature hashAlgId: ${hashAlgId}`);
  }
}

function ensureSupportedAuthDigest(authDigestAlgId) {
  if (authDigestAlgId !== AuthDigestAlgId.SHA3_256) {
    throw new Error(`Unsupported detached PQ signature authDigestAlgId: ${authDigestAlgId}`);
  }
}

function ensureSupportedQsigContext(ctx) {
  if (ctx !== SUPPORTED_QSIG_CONTEXT) {
    throw new Error(`Unsupported detached PQ signature context: ${ctx}`);
  }
}

function ensureSupportedFingerprintAlg(algId) {
  if (algId !== FP_ALG_ID_SHA3_256) {
    throw new Error(`Unsupported signer fingerprint algorithm: ${algId}`);
  }
}

function decodeUtf8(bytes, field) {
  try {
    return bytesToUtf8(bytes);
  } catch (error) {
    throw new Error(`Invalid UTF-8 in ${field}: ${error?.message || error}`);
  }
}

function readU64LE(bytes, field) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 8) {
    throw new Error(`Invalid ${field} length`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lo = BigInt(view.getUint32(0, true));
  const hi = BigInt(view.getUint32(4, true));
  return (hi << 32n) | lo;
}

function normalizeIso8601(value) {
  const trimmed = String(value || '').trim();
  if (!trimmed) throw new Error('createdAt is empty');
  const ts = Date.parse(trimmed);
  if (Number.isNaN(ts)) throw new Error('createdAt is not valid ISO-8601');
  return new Date(ts).toISOString();
}

function decodeTlvBlock(bytes, field) {
  const reader = new Reader(bytes);
  const out = [];
  let lastTag = 0;
  const seen = new Set();

  while (reader.remaining() > 0) {
    if (reader.remaining() < 3) {
      throw new Error(`Truncated ${field} TLV header`);
    }
    const tag = reader.u8(`${field}.tag`);
    const len = reader.u16le(`${field}.len`);
    if (tag === 0) throw new Error(`Invalid zero tag in ${field}`);
    if (tag <= lastTag) throw new Error(`Non-canonical ${field} TLV order`);
    if (seen.has(tag)) throw new Error(`Duplicate ${field} TLV tag: ${tag}`);
    const value = reader.take(len, `${field}.tag.${tag}`);
    if (tag >= 0x80) throw new Error(`Unknown critical ${field} TLV tag: ${tag}`);
    lastTag = tag;
    seen.add(tag);
    out.push({ tag, value });
  }

  return out;
}

export function unpackSignerFingerprint(record) {
  if (!(record instanceof Uint8Array) || record.length !== FP_RECORD_LEN) {
    throw new Error('Invalid signer fingerprint record length');
  }
  const algId = record[0];
  ensureSupportedFingerprintAlg(algId);
  return {
    algId,
    digest: record.subarray(1),
  };
}

function parseMetadata(records, field) {
  const metadata = {};

  for (const { tag, value } of records) {
    if (tag === MetadataTag.FILENAME) {
      metadata.filename = decodeUtf8(value, `${field}.filename`);
      continue;
    }

    if (tag === MetadataTag.FILESIZE) {
      metadata.filesize = readU64LE(value, `${field}.filesize`);
      continue;
    }

    if (tag === MetadataTag.CREATED_AT) {
      if (value.length === 8) {
        metadata.createdAt = new Date(Number(readU64LE(value, `${field}.createdAtEpoch`)) * 1000).toISOString();
      } else {
        metadata.createdAt = normalizeIso8601(decodeUtf8(value, `${field}.createdAt`));
      }
      continue;
    }

    if (tag === MetadataTag.SIGNER_PUBLIC_KEY) {
      metadata.signerPublicKey = Uint8Array.from(value);
      continue;
    }

    if (tag === MetadataTag.SIGNER_FINGERPRINT) {
      metadata.signerFingerprint = Uint8Array.from(value);
    }
  }

  if (metadata.signerFingerprint instanceof Uint8Array) {
    const parsed = unpackSignerFingerprint(metadata.signerFingerprint);
    metadata.signerFingerprintAlgId = parsed.algId;
    metadata.signerFingerprintDigest = Uint8Array.from(parsed.digest);
  }

  if (metadata.signerPublicKey instanceof Uint8Array && metadata.signerFingerprintDigest instanceof Uint8Array) {
    const recomputed = sha3_256(metadata.signerPublicKey);
    if (!bytesEqual(recomputed, metadata.signerFingerprintDigest)) {
      throw new Error(`Signer fingerprint does not match signer public key in ${field}`);
    }
  }

  return metadata;
}

function parseAuthenticatedMetadata(authMetaBytes, authMetaDigest, authDigestAlgId) {
  ensureSupportedAuthDigest(authDigestAlgId);
  if (!(authMetaDigest instanceof Uint8Array) || authMetaDigest.length !== AUTH_META_DIGEST_LEN) {
    throw new Error('Invalid authMetaDigest length');
  }

  const records = decodeTlvBlock(authMetaBytes, 'authMeta');
  const allowed = new Set([MetadataTag.SIGNER_PUBLIC_KEY, MetadataTag.SIGNER_FINGERPRINT]);
  for (const { tag } of records) {
    if (!allowed.has(tag)) throw new Error(`Unexpected authMeta tag: ${tag}`);
  }

  const metadata = parseMetadata(records, 'authMeta');
  if (!(metadata.signerPublicKey instanceof Uint8Array) || !(metadata.signerFingerprint instanceof Uint8Array)) {
    throw new Error('Detached PQ signature authMeta is missing signer binding');
  }

  const recomputedDigest = sha3_256(authMetaBytes);
  if (!bytesEqual(recomputedDigest, authMetaDigest)) {
    throw new Error('Detached PQ signature authMetaDigest mismatch');
  }

  return metadata;
}

function parseDisplayMetadata(displayMetaBytes) {
  const records = decodeTlvBlock(displayMetaBytes, 'displayMeta');
  const allowed = new Set([MetadataTag.FILENAME, MetadataTag.FILESIZE, MetadataTag.CREATED_AT]);
  for (const { tag } of records) {
    if (!allowed.has(tag)) throw new Error(`Unexpected displayMeta tag: ${tag}`);
  }
  return parseMetadata(records, 'displayMeta');
}

function buildTBSV2({
  formatVerMajor,
  formatVerMinor,
  suiteId,
  signatureProfileId,
  payloadDigestAlgId,
  authDigestAlgId,
  payloadDigest,
  authMetaDigest,
}) {
  return concatBytes([
    MAGIC_TBS,
    Uint8Array.of(
      QSIG_TBS_VERSION_MAJOR,
      0x00,
      formatVerMajor,
      formatVerMinor,
      suiteId,
      signatureProfileId,
      payloadDigestAlgId,
      authDigestAlgId
    ),
    payloadDigest,
    authMetaDigest,
  ]);
}

export function unpackQsig(sigBytes) {
  ensureBytesLimit(sigBytes, MAX_SIGNATURE_FILE_BYTES, 'Detached PQ signature');
  const reader = new Reader(sigBytes);
  const magic = reader.take(4, 'magic');
  if (!bytesEqual(magic, MAGIC_SIG)) throw new Error('Invalid detached PQ signature magic');

  const versionMajor = reader.u8('versionMajor');
  const versionMinor = reader.u8('versionMinor');
  if (versionMajor !== QSIG_FORMAT_VERSION_MAJOR) {
    throw new Error(`Unsupported detached PQ signature major version: ${versionMajor}`);
  }

  const suiteId = reader.u8('suiteId');
  const signatureProfileId = reader.u8('signatureProfileId');
  const payloadDigestAlgId = reader.u8('payloadDigestAlgId');
  const authDigestAlgId = reader.u8('authDigestAlgId');
  suiteInfo(suiteId);
  ensureSupportedSignatureProfile(signatureProfileId);
  ensureSupportedHashAlg(payloadDigestAlgId);
  ensureSupportedAuthDigest(authDigestAlgId);

  const flags = reader.u16le('flags');
  if ((flags & ~KNOWN_SIG_FLAGS) !== 0) {
    throw new Error(`Unsupported detached PQ signature flags: ${flags}`);
  }

  const payloadDigest = reader.take(FILE_HASH_LEN, 'payloadDigest');
  const authMetaDigest = reader.take(AUTH_META_DIGEST_LEN, 'authMetaDigest');
  const ctxLen = reader.u8('ctxLen');
  if (ctxLen > MAX_CONTEXT_BYTES) {
    throw new Error(`Detached PQ signature ctxLen exceeds maximum size (${MAX_CONTEXT_BYTES} bytes)`);
  }
  const reserved = reader.u8('reserved');
  if (reserved !== 0) throw new Error('Invalid detached PQ signature reserved field');

  const authMetaLen = reader.u16le('authMetaLen');
  const displayMetaLen = reader.u16le('displayMetaLen');
  const sigLen = reader.u32le('sigLen');
  if (authMetaLen > MAX_AUTH_METADATA_BYTES) {
    throw new Error(`Detached PQ signature authMetaLen exceeds maximum size (${MAX_AUTH_METADATA_BYTES} bytes)`);
  }
  if (displayMetaLen > MAX_DISPLAY_METADATA_BYTES) {
    throw new Error(`Detached PQ signature displayMetaLen exceeds maximum size (${MAX_DISPLAY_METADATA_BYTES} bytes)`);
  }
  if (sigLen > MAX_SIGNATURE_BYTES) {
    throw new Error(`Detached PQ signature sigLen exceeds maximum size (${MAX_SIGNATURE_BYTES} bytes)`);
  }
  const expectedRemaining = ctxLen + authMetaLen + displayMetaLen + sigLen;
  if (reader.remaining() !== expectedRemaining) {
    throw new Error('Invalid detached PQ signature length framing');
  }

  const ctxBytes = reader.take(ctxLen, 'ctxBytes');
  if (ctxBytes.length === 0) throw new Error('Detached PQ signature context is required');
  if ((flags & SigFlags.CTX_PRESENT) === 0) {
    throw new Error('Detached PQ signature context flag is missing');
  }

  const authMetaBytes = reader.take(authMetaLen, 'authMetaBytes');
  const displayMetaBytes = reader.take(displayMetaLen, 'displayMetaBytes');
  const signature = reader.take(sigLen, 'signature');

  const authenticatedMetadata = parseAuthenticatedMetadata(authMetaBytes, authMetaDigest, authDigestAlgId);
  const displayMetadata = parseDisplayMetadata(displayMetaBytes);
  const metadata = { ...displayMetadata, ...authenticatedMetadata };

  const hasFilename = displayMetadata.filename !== undefined;
  const hasFilesize = displayMetadata.filesize !== undefined;
  const hasCreatedAt = displayMetadata.createdAt !== undefined;
  if (((flags & SigFlags.FILENAME_PRESENT) !== 0) !== hasFilename) {
    throw new Error('Detached PQ signature filename flag mismatch');
  }
  if (((flags & SigFlags.FILESIZE_PRESENT) !== 0) !== hasFilesize) {
    throw new Error('Detached PQ signature filesize flag mismatch');
  }
  if (((flags & SigFlags.CREATED_AT_PRESENT) !== 0) !== hasCreatedAt) {
    throw new Error('Detached PQ signature createdAt flag mismatch');
  }

  const ctx = decodeUtf8(ctxBytes, 'ctx');
  ensureSupportedQsigContext(ctx);

  const parsed = {
    versionMajor,
    versionMinor,
    suiteId,
    signatureProfileId,
    hashAlgId: payloadDigestAlgId,
    payloadDigestAlgId,
    authDigestAlgId,
    flags,
    fileHash: payloadDigest,
    payloadDigest,
    authMetaDigest,
    ctx,
    ctxBytes,
    authenticatedMetadata,
    displayMetadata,
    metadata,
    signature,
    signatureLength: signature.length,
    signerFingerprint: metadata.signerFingerprint || null,
  };

  parsed.tbs = buildTBSV2({
    formatVerMajor: versionMajor,
    formatVerMinor: versionMinor,
    suiteId,
    signatureProfileId,
    payloadDigestAlgId,
    authDigestAlgId,
    payloadDigest,
    authMetaDigest,
  });

  return parsed;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u32le(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, true);
  return out;
}

function normalizedSuiteToSuiteId(value) {
  const canonical = getSignatureSuiteInfo(value).canonical;
  for (const [suiteId, info] of Object.entries(SUITE_REGISTRY)) {
    if (info.normalizedSuite === canonical) {
      return Number(suiteId);
    }
  }
  throw new Error(`Unsupported detached PQ public key suite: ${value}`);
}

export function packPqpk({
  suite,
  publicKeyBytes,
  versionMinor = 0x01,
} = {}) {
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length === 0) {
    throw new Error('Detached PQ public key bytes must be a non-empty Uint8Array');
  }
  ensureBytesLimit(publicKeyBytes, MAX_KEY_BYTES, 'Detached PQ public key');
  const suiteId = normalizedSuiteToSuiteId(suite);
  const prefix = concatBytes([
    MAGIC_PQPK,
    Uint8Array.of(KEY_FORMAT_VERSION_MAJOR, versionMinor & 0xff, suiteId, 0x00),
    u32le(publicKeyBytes.length),
    publicKeyBytes,
  ]);
  return concatBytes([prefix, u32le(crc32(prefix))]);
}

export function unpackPqpk(publicKeyFileBytes) {
  ensureBytesLimit(publicKeyFileBytes, MAX_KEY_FILE_BYTES, 'Detached PQ public key');
  const reader = new Reader(publicKeyFileBytes);
  const magic = reader.take(4, 'magic');
  if (!bytesEqual(magic, MAGIC_PQPK)) throw new Error('Invalid detached PQ public key magic');

  const versionMajor = reader.u8('versionMajor');
  const versionMinor = reader.u8('versionMinor');
  if (versionMajor !== KEY_FORMAT_VERSION_MAJOR) {
    throw new Error(`Unsupported detached PQ public key major version: ${versionMajor}`);
  }

  const suiteId = reader.u8('suiteId');
  suiteInfo(suiteId);

  const flags = reader.u8('flags');
  if (flags !== 0) throw new Error('Invalid detached PQ public key flags');

  const keyLen = reader.u32le('keyLen');
  if (keyLen > MAX_KEY_BYTES) {
    throw new Error(`Detached PQ public key keyLen exceeds maximum size (${MAX_KEY_BYTES} bytes)`);
  }
  const keyBytes = reader.take(keyLen, 'keyBytes');
  const checksum = reader.u32le('crc32');
  if (reader.remaining() !== 0) throw new Error('Trailing bytes in detached PQ public key');

  const crcInput = publicKeyFileBytes.subarray(0, publicKeyFileBytes.length - 4);
  const expected = crc32(crcInput);
  if (checksum !== expected) {
    throw new Error('Invalid detached PQ public key CRC32');
  }

  return {
    versionMajor,
    versionMinor,
    suiteId,
    keyBytes,
  };
}

function pqPublicKeyIdentityKey({ suiteId, keyBytes }) {
  return `${suiteId}:${bytesToHex(keyBytes)}`;
}

export function normalizePqPublicKeyPins({
  pinnedPqPublicKeyFileBytes = null,
  pinnedPqPublicKeyFileBytesList = [],
  invalidBehavior = 'warn',
  invalidLabel = 'Pinned PQ signer key',
} = {}) {
  if (invalidBehavior !== 'warn' && invalidBehavior !== 'throw') {
    throw new Error(`Unsupported invalidBehavior: ${invalidBehavior}`);
  }

  const pins = [];
  const warnings = [];
  const seen = new Set();
  const add = (bytes) => {
    if (!(bytes instanceof Uint8Array)) return;

    let unpacked;
    try {
      unpacked = unpackPqpk(bytes);
    } catch (error) {
      const message = `${invalidLabel} could not be parsed as .pqpk and was ignored: ${error?.message || error}`;
      if (invalidBehavior === 'throw') {
        throw new Error(message);
      }
      warnings.push(message);
      return;
    }

    const identityKey = pqPublicKeyIdentityKey(unpacked);
    if (seen.has(identityKey)) return;
    seen.add(identityKey);
    pins.push({
      bytes,
      suiteId: unpacked.suiteId,
      keyBytes: unpacked.keyBytes,
      identityKey,
    });
  };

  add(pinnedPqPublicKeyFileBytes);
  if (Array.isArray(pinnedPqPublicKeyFileBytesList)) {
    for (const bytes of pinnedPqPublicKeyFileBytesList) add(bytes);
  }

  return { pins, warnings };
}

function verifyBySuite(suiteId, signature, message, publicKey, contextBytes) {
  const info = suiteInfo(suiteId);
  const opts = contextBytes instanceof Uint8Array && contextBytes.length > 0
    ? { context: contextBytes }
    : {};
  return info.signer.verify(signature, message, publicKey, opts);
}

function appendSignerBindingWarnings(parsed, verificationPublicKey, warnings) {
  if (!(verificationPublicKey instanceof Uint8Array)) {
    return null;
  }

  if (
    parsed?.metadata?.signerPublicKey instanceof Uint8Array &&
    !bytesEqual(parsed.metadata.signerPublicKey, verificationPublicKey)
  ) {
    warnings.push('Embedded signer public key does not match the verification key that satisfied this detached PQ signature.');
  }

  const computedFp = sha3_256(verificationPublicKey);
  if (
    parsed?.metadata?.signerFingerprintDigest instanceof Uint8Array &&
    !bytesEqual(parsed.metadata.signerFingerprintDigest, computedFp)
  ) {
    warnings.push('Signer fingerprint in .qsig metadata does not match the verification key.');
  }

  return computedFp;
}

export function verifyQsigAgainstBytes({
  messageBytes,
  qsigBytes,
  bundlePqPublicKeyFileBytes = null,
  pinnedPqPublicKeyFileBytes = null,
  authoritativeBundlePqPublicKey = false,
}) {
  const parsed = unpackQsig(qsigBytes);
  const warnings = [];
  const fail = (error) => ({
    ok: false,
    bundlePinned: false,
    userPinned: false,
    signerPinned: false,
    type: 'qsig',
    format: 'qsig',
    error,
    warnings,
  });

  const computedFileHash = sha3_512(messageBytes);
  if (!bytesEqual(computedFileHash, parsed.payloadDigest)) {
    return fail('Signed SHA3-512 digest does not match canonical manifest bytes');
  }

  const unpackCandidateKey = (pqpkBytes, label, { optional = false, strictSuiteMatch = false } = {}) => {
    if (!(pqpkBytes instanceof Uint8Array)) return null;
    let unpacked;
    try {
      unpacked = unpackPqpk(pqpkBytes);
    } catch (error) {
      if (optional) {
        warnings.push(`${label} could not be parsed as .pqpk and was ignored: ${error?.message || error}`);
        return null;
      }
      throw error;
    }
    if (unpacked.suiteId !== parsed.suiteId) {
      if (strictSuiteMatch) {
        throw new Error(`${label} suite does not match this detached PQ signature.`);
      }
      warnings.push(`${label} suite does not match this .qsig and was ignored.`);
      return null;
    }
    return {
      keyBytes: unpacked.keyBytes,
      source: label,
    };
  };

  const bundleKey = unpackCandidateKey(
    bundlePqPublicKeyFileBytes,
    'Bundled PQ public key',
    { optional: false, strictSuiteMatch: authoritativeBundlePqPublicKey }
  );
  const pinnedKey = unpackCandidateKey(
    pinnedPqPublicKeyFileBytes,
    'Pinned PQ signer key',
    { optional: true }
  );
  const embeddedKey = parsed.metadata.signerPublicKey instanceof Uint8Array
    ? { keyBytes: parsed.metadata.signerPublicKey, source: 'Embedded PQ public key' }
    : null;

  const verificationOrder = [];
  const seenKeys = new Set();
  const addCandidate = (candidate, keySource) => {
    if (!(candidate?.keyBytes instanceof Uint8Array)) return;
    const keyHex = bytesToHex(candidate.keyBytes);
    if (seenKeys.has(keyHex)) return;
    seenKeys.add(keyHex);
    verificationOrder.push({
      publicKey: candidate.keyBytes,
      keySource,
    });
  };

  addCandidate(bundleKey, 'bundle-pqpk');
  addCandidate(pinnedKey, 'user-pqpk');
  addCandidate(embeddedKey, 'embedded-signature-key');

  if (verificationOrder.length === 0) {
    return fail('No verification key available (.pqpk not provided and no signer public key embedded in .qsig)');
  }

  const bundlePinned = bundleKey instanceof Object
    ? verifyBySuite(parsed.suiteId, parsed.signature, parsed.tbs, bundleKey.keyBytes, parsed.ctxBytes)
    : false;
  const userPinned = pinnedKey instanceof Object
    ? verifyBySuite(parsed.suiteId, parsed.signature, parsed.tbs, pinnedKey.keyBytes, parsed.ctxBytes)
    : false;

  if (bundleKey && !bundlePinned) {
    warnings.push('Bundled PQ public key did not verify this detached PQ signature.');
  }
  if (pinnedKey && !userPinned) {
    warnings.push(bundleKey ? 'Pinned PQ signer key did not match the bundled signer key.' : 'Pinned PQ signer key did not match this verified signature.');
  }

  if (authoritativeBundlePqPublicKey) {
    if (!(bundleKey?.keyBytes instanceof Uint8Array)) {
      return fail('Bundled PQ public key is required for this detached PQ signature');
    }
    if (!bundlePinned) {
      return fail('Bundled PQ public key did not verify this detached PQ signature');
    }

    const suite = suiteInfo(parsed.suiteId);
    const suiteInfoNormalized = getSignatureSuiteInfo(suite.normalizedSuite);
    const computedFp = appendSignerBindingWarnings(parsed, bundleKey.keyBytes, warnings);
    const computedFpHex = bytesToHex(computedFp);
    return {
      ok: true,
      bundlePinned,
      userPinned,
      signerPinned: bundlePinned || userPinned,
      type: 'qsig',
      format: 'qsig',
      suite: suite.normalizedSuite,
      suiteDisplay: suite.name,
      strongPq: suiteInfoNormalized.strongPq,
      keySource: 'bundle-pqpk',
      signerFingerprintHex: computedFpHex,
      signerLabel: computedFpHex,
      warnings,
    };
  }

  let verifiedCandidate = null;
  for (const candidate of verificationOrder) {
    if (verifyBySuite(parsed.suiteId, parsed.signature, parsed.tbs, candidate.publicKey, parsed.ctxBytes)) {
      verifiedCandidate = candidate;
      break;
    }
  }

  if (!verifiedCandidate) {
    return fail('Detached PQ signature verification failed');
  }

  if (
    verifiedCandidate.keySource === 'embedded-signature-key' &&
    !bundlePinned &&
    !userPinned
  ) {
    warnings.push('Using signer public key embedded in .qsig; verification succeeded but signer identity is not pinned.');
  }

  const computedFp = appendSignerBindingWarnings(parsed, verifiedCandidate.publicKey, warnings);
  const computedFpHex = bytesToHex(computedFp);

  const suite = suiteInfo(parsed.suiteId);
  const suiteInfoNormalized = getSignatureSuiteInfo(suite.normalizedSuite);
  return {
    ok: true,
    bundlePinned,
    userPinned,
    signerPinned: bundlePinned || userPinned,
    type: 'qsig',
    format: 'qsig',
    suite: suite.normalizedSuite,
    suiteDisplay: suite.name,
    strongPq: suiteInfoNormalized.strongPq,
    keySource: verifiedCandidate.keySource,
    signerFingerprintHex: computedFpHex,
    signerLabel: computedFpHex,
    warnings,
  };
}
