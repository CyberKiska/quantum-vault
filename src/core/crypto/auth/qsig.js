import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_shake_128s,
  slh_dsa_shake_192s,
  slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';
import { asciiBytes, bytesEqual, bytesToHex, concatBytes } from './bytes.js';

const MAGIC_SIG = asciiBytes('PQSG');
const MAGIC_TBS = asciiBytes('QSTB');
const MAGIC_PQPK = asciiBytes('PQPK');
const FILE_HASH_LEN = 64;
const SIG_HASH_ALG_ID_SHA3_512 = 0x01;
const FP_ALG_ID_SHA3_256 = 0x01;
const FP_RECORD_LEN = 33;

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
});

const SUITE_REGISTRY = Object.freeze({
  [Suite.ML_DSA_44]: { name: 'ML-DSA-44', family: 'ML-DSA', signer: ml_dsa44 },
  [Suite.ML_DSA_65]: { name: 'ML-DSA-65', family: 'ML-DSA', signer: ml_dsa65 },
  [Suite.ML_DSA_87]: { name: 'ML-DSA-87', family: 'ML-DSA', signer: ml_dsa87 },
  [Suite.SLH_DSA_SHAKE_128S]: { name: 'SLH-DSA-SHAKE-128s', family: 'SLH-DSA-SHAKE', signer: slh_dsa_shake_128s },
  [Suite.SLH_DSA_SHAKE_192S]: { name: 'SLH-DSA-SHAKE-192s', family: 'SLH-DSA-SHAKE', signer: slh_dsa_shake_192s },
  [Suite.SLH_DSA_SHAKE_256S]: { name: 'SLH-DSA-SHAKE-256s', family: 'SLH-DSA-SHAKE', signer: slh_dsa_shake_256s },
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
  const suiteId = r.u8('suiteId');
  const hashAlgId = r.u8('hashAlgId');
  if (hashAlgId !== SIG_HASH_ALG_ID_SHA3_512) {
    throw new Error(`Unsupported .qsig hashAlgId: ${hashAlgId}`);
  }

  suiteInfo(suiteId);

  r.u16le('flags');
  const fileHash = r.take(FILE_HASH_LEN, 'fileHash');
  const ctxLen = r.u8('ctxLen');
  const reserved = r.u8('reserved');
  if (reserved !== 0) throw new Error('Invalid .qsig reserved field');
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

  r.u8('versionMajor');
  r.u8('versionMinor');
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
  trustedPqPublicKeyFileBytes = null,
  pinnedPqFingerprintHex = '',
}) {
  const parsed = unpackQsig(qsigBytes);
  const warnings = [];

  const computedFileHash = sha3_512(messageBytes);
  if (!bytesEqual(computedFileHash, parsed.fileHash)) {
    return {
      ok: false,
      trusted: false,
      type: 'qsig',
      error: 'Signed SHA3-512 hash does not match manifest bytes',
      warnings,
    };
  }

  let keySource = '';
  let publicKey = null;
  let trusted = false;

  if (trustedPqPublicKeyFileBytes instanceof Uint8Array) {
    const trustedKey = unpackPqpk(trustedPqPublicKeyFileBytes);
    if (trustedKey.suiteId !== parsed.suiteId) {
      return {
        ok: false,
        trusted: false,
        type: 'qsig',
        error: `Trusted .pqpk suite mismatch (sig=${parsed.suiteId}, key=${trustedKey.suiteId})`,
        warnings,
      };
    }
    publicKey = trustedKey.keyBytes;
    keySource = 'trusted-pqpk';
    trusted = true;
  } else if (parsed.metadata.signerPublicKey instanceof Uint8Array) {
    publicKey = parsed.metadata.signerPublicKey;
    keySource = 'embedded-signature-key';
    warnings.push('Using signer public key embedded in .qsig; provide trusted .pqpk for identity assurance.');
  } else {
    return {
      ok: false,
      trusted: false,
      type: 'qsig',
      error: 'No verification key available (.pqpk not provided and no embedded signer key)',
      warnings,
    };
  }

  const computedFp = sha3_256(publicKey);
  const computedFpHex = bytesToHex(computedFp);

  if (parsed.signerFingerprint && !bytesEqual(parsed.signerFingerprint.digest, computedFp)) {
    warnings.push('Signer fingerprint in .qsig metadata does not match the verification key.');
  }

  if (pinnedPqFingerprintHex) {
    const normalized = String(pinnedPqFingerprintHex).toLowerCase();
    if (normalized !== computedFpHex) {
      return {
        ok: false,
        trusted: false,
        type: 'qsig',
        error: `Pinned PQ fingerprint mismatch (expected ${normalized}, got ${computedFpHex})`,
        warnings,
      };
    }
    trusted = true;
  }

  const sigOk = verifyBySuite(parsed.suiteId, parsed.signature, parsed.tbs, publicKey);
  if (!sigOk) {
    return {
      ok: false,
      trusted: false,
      type: 'qsig',
      error: 'PQ signature verification failed',
      warnings,
    };
  }

  const suite = suiteInfo(parsed.suiteId);
  return {
    ok: true,
    trusted,
    type: 'qsig',
    algorithm: suite.name,
    algorithmFamily: suite.family,
    keySource,
    signerFingerprintHex: computedFpHex,
    warnings,
  };
}
