import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_shake_128s,
  slh_dsa_shake_192s,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
} from '@noble/post-quantum/slh-dsa.js';
import { asciiBytes, bytesEqual, bytesToHex, concatBytes } from '../bytes.js';
import { getSignatureSuiteInfo } from './signature-suites.js';

const MAGIC_SIG = asciiBytes('PQSG');
const MAGIC_TBS = asciiBytes('QSTB');
const MAGIC_PQPK = asciiBytes('PQPK');
const FILE_HASH_LEN = 64;
const SIG_HASH_ALG_ID_SHA3_512 = 0x01;
const FP_ALG_ID_SHA3_256 = 0x01;
const FP_RECORD_LEN = 33;
const QSIG_FLAG_PROFILE_MVP_V1 = 0x000f;

const MetadataTag = Object.freeze({
  SIGNER_PUBLIC_KEY: 0x10,
  SIGNER_FINGERPRINT: 0x11,
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
  if (!info) throw new Error(`Unsupported .qsig suiteId: ${suiteId}`);
  return info;
}

function decodeMetadataTLV(bytes) {
  const reader = new Reader(bytes);
  const out = {
    signerPublicKey: null,
    signerFingerprintRecord: null,
  };

  const knownTags = new Set([
    MetadataTag.SIGNER_PUBLIC_KEY,
    MetadataTag.SIGNER_FINGERPRINT,
  ]);

  let lastTag = -1;
  while (reader.remaining() > 0) {
    const tag = reader.u8('meta.tag');
    const len = reader.u16le('meta.len');
    const value = reader.take(len, `meta.tag.${tag}`);

    if (tag <= lastTag) throw new Error('Non-canonical metadata TLV order');
    lastTag = tag;

    if (tag === MetadataTag.SIGNER_PUBLIC_KEY) {
      out.signerPublicKey = value;
    } else if (tag === MetadataTag.SIGNER_FINGERPRINT) {
      out.signerFingerprintRecord = value;
    } else if (!knownTags.has(tag) && tag >= 0x80) {
      throw new Error(`Unknown critical metadata TLV tag: ${tag}`);
    }
  }

  return out;
}

function unpackSignerFingerprint(record) {
  if (!(record instanceof Uint8Array) || record.length !== FP_RECORD_LEN) {
    throw new Error('Invalid signer fingerprint record length');
  }
  const algId = record[0];
  if (algId !== FP_ALG_ID_SHA3_256) {
    throw new Error(`Unsupported signer fingerprint algorithm: ${algId}`);
  }
  return {
    algId,
    digest: record.subarray(1),
  };
}

function buildTbs(parsed) {
  const ctxLen = parsed.ctxBytes.length;
  if (ctxLen > 0xff) throw new Error('Context length exceeds u8 limit');
  return concatBytes([
    MAGIC_TBS,
    Uint8Array.of(0x01, 0x00, parsed.versionMajor, parsed.versionMinor, parsed.suiteId, parsed.hashAlgId, ctxLen),
    parsed.ctxBytes,
    parsed.fileHash,
  ]);
}

export function unpackQsig(sigBytes) {
  const r = new Reader(sigBytes);

  const magic = r.take(4, 'magic');
  if (!bytesEqual(magic, MAGIC_SIG)) throw new Error('Invalid .qsig magic');

  const versionMajor = r.u8('versionMajor');
  const versionMinor = r.u8('versionMinor');
  if (versionMajor !== 0x01) {
    throw new Error(`Unsupported .qsig major version: ${versionMajor}`);
  }
  const suiteId = r.u8('suiteId');
  const hashAlgId = r.u8('hashAlgId');
  if (hashAlgId !== SIG_HASH_ALG_ID_SHA3_512) {
    throw new Error(`Unsupported .qsig hashAlgId: ${hashAlgId}`);
  }

  suiteInfo(suiteId);

  const flags = r.u16le('flags');
  if (flags !== 0 && flags !== QSIG_FLAG_PROFILE_MVP_V1) {
    throw new Error(`Unsupported .qsig flags value: ${flags}`);
  }
  const fileHash = r.take(FILE_HASH_LEN, 'fileHash');
  const ctxLen = r.u16le('ctxLen');
  const metaLen = r.u16le('metaLen');
  const sigLen = r.u32le('sigLen');

  const expectedRemaining = ctxLen + metaLen + sigLen;
  if (r.remaining() !== expectedRemaining) {
    throw new Error('Invalid .qsig length framing');
  }

  const ctxBytes = r.take(ctxLen, 'ctxBytes');
  const metaBytes = r.take(metaLen, 'metaBytes');
  const signature = r.take(sigLen, 'signature');

  const metadata = decodeMetadataTLV(metaBytes);
  const signerFingerprint = metadata.signerFingerprintRecord
    ? unpackSignerFingerprint(metadata.signerFingerprintRecord)
    : null;

  const parsed = {
    versionMajor,
    versionMinor,
    suiteId,
    hashAlgId,
    flags,
    fileHash,
    ctxBytes,
    signature,
    metadata,
    signerFingerprint,
  };

  parsed.tbs = buildTbs(parsed);
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

export function unpackPqpk(publicKeyFileBytes) {
  const r = new Reader(publicKeyFileBytes);
  const magic = r.take(4, 'magic');
  if (!bytesEqual(magic, MAGIC_PQPK)) throw new Error('Invalid .pqpk magic');

  const versionMajor = r.u8('versionMajor');
  r.u8('versionMinor');
  if (versionMajor !== 0x01) {
    throw new Error(`Unsupported .pqpk major version: ${versionMajor}`);
  }
  const suiteId = r.u8('suiteId');
  suiteInfo(suiteId);

  const reserved = r.u8('reserved');
  if (reserved !== 0) throw new Error('Invalid .pqpk reserved field');

  const keyLen = r.u32le('keyLen');
  const keyBytes = r.take(keyLen, 'keyBytes');
  const checksum = r.u32le('crc32');
  if (r.remaining() !== 0) throw new Error('Trailing bytes in .pqpk');

  const crcInput = publicKeyFileBytes.subarray(0, publicKeyFileBytes.length - 4);
  const expected = crc32(crcInput);
  if (checksum !== expected) {
    throw new Error('Invalid .pqpk CRC32');
  }

  return { suiteId, keyBytes };
}

function verifyBySuite(suiteId, signature, message, publicKey) {
  const info = suiteInfo(suiteId);
  return info.signer.verify(signature, message, publicKey);
}

export function verifyQsigAgainstBytes({
  messageBytes,
  qsigBytes,
  bundlePqPublicKeyFileBytes = null,
  pinnedPqPublicKeyFileBytes = null,
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
  if (!bytesEqual(computedFileHash, parsed.fileHash)) {
    return fail('Signed SHA3-512 hash does not match manifest bytes');
  }

  const candidates = [];
  const seenKeys = new Set();

  const addCandidate = (publicKey, keySource) => {
    if (!(publicKey instanceof Uint8Array)) return;
    const keyHex = bytesToHex(publicKey);
    if (seenKeys.has(keyHex)) return;
    seenKeys.add(keyHex);
    candidates.push({ publicKey, keySource });
  };

  const unpackCandidateKey = (pqpkBytes, label, { optional = false } = {}) => {
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
      warnings.push(`${label} suite does not match this .qsig and was ignored.`);
      return null;
    }
    return unpacked.keyBytes;
  };

  const bundledKey = unpackCandidateKey(
    bundlePqPublicKeyFileBytes,
    'Bundled PQ public key',
    { optional: false }
  );

  if (parsed.metadata.signerPublicKey instanceof Uint8Array) {
    addCandidate(parsed.metadata.signerPublicKey, 'embedded-signature-key');
  }

  const pinnedKey = unpackCandidateKey(
    pinnedPqPublicKeyFileBytes,
    'Pinned PQ signer key',
    { optional: true }
  );
  addCandidate(pinnedKey, 'user-pqpk');

  if (bundledKey instanceof Uint8Array) {
    if (!verifyBySuite(parsed.suiteId, parsed.signature, parsed.tbs, bundledKey)) {
      return fail('PQ signature did not verify with bundled public key');
    }

    const userPinned = pinnedKey instanceof Uint8Array ? bytesEqual(pinnedKey, bundledKey) : false;
    if (pinnedKey instanceof Uint8Array && !userPinned) {
      warnings.push('Pinned PQ signer key did not match the bundled signer key.');
    }

    const computedFp = sha3_256(bundledKey);
    const computedFpHex = bytesToHex(computedFp);
    if (parsed.signerFingerprint && !bytesEqual(parsed.signerFingerprint.digest, computedFp)) {
      warnings.push('Signer fingerprint in .qsig metadata does not match the bundled verification key.');
    }

    const suite = suiteInfo(parsed.suiteId);
    const suiteInfoNormalized = getSignatureSuiteInfo(suite.normalizedSuite);
    return {
      ok: true,
      bundlePinned: true,
      userPinned,
      signerPinned: true,
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

  if (candidates.length === 0) {
    return fail('No verification key available (.pqpk not provided and no embedded signer key)');
  }

  let verifiedCandidate = null;
  for (const candidate of candidates) {
    if (verifyBySuite(parsed.suiteId, parsed.signature, parsed.tbs, candidate.publicKey)) {
      verifiedCandidate = candidate;
      break;
    }
  }

  if (!verifiedCandidate) {
    return fail('PQ signature verification failed');
  }

  const userPinned = pinnedKey instanceof Uint8Array
    ? bytesEqual(pinnedKey, verifiedCandidate.publicKey)
    : false;
  if (pinnedKey instanceof Uint8Array && !userPinned) {
    warnings.push('Pinned PQ signer key did not match this verified signature.');
  }
  if (verifiedCandidate.keySource === 'embedded-signature-key' && !userPinned) {
    warnings.push('Using signer public key embedded in .qsig; verification succeeded but signer identity is not pinned.');
  }

  const computedFp = sha3_256(verifiedCandidate.publicKey);
  const computedFpHex = bytesToHex(computedFp);

  if (parsed.signerFingerprint && !bytesEqual(parsed.signerFingerprint.digest, computedFp)) {
    warnings.push('Signer fingerprint in .qsig metadata does not match the verification key.');
  }

  const suite = suiteInfo(parsed.suiteId);
  const suiteInfoNormalized = getSignatureSuiteInfo(suite.normalizedSuite);
  return {
    ok: true,
    bundlePinned: false,
    userPinned,
    signerPinned: userPinned,
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
