import { sha3_512 } from '@noble/hashes/sha3.js';
import {
  base64ToBytes,
  bytesEqual,
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  digestSha256,
  utf8ToBytes,
} from '../bytes.js';

export const STELLAR_SIGNATURE_SCHEMA = 'stellar-signature/v2';

const PROOF_TYPE = Object.freeze({
  SEP53_MESSAGE: 'sep53-message-signature',
  XDR_ENVELOPE: 'xdr-envelope-proof',
});

const PAYLOAD_TYPE = Object.freeze({
  RAW_BYTES: 'raw-bytes',
  DETACHED_DIGESTS: 'detached-digests',
});

const SIGNATURE_SCHEME = Object.freeze({
  SEP53_SHA256_ED25519: 'sep53-sha256-ed25519',
  TX_ENVELOPE_ED25519: 'tx-envelope-ed25519',
});

const HASH_ALG = Object.freeze({
  SHA256: 'SHA-256',
  SHA3_512: 'SHA3-512',
});

const MANAGE_DATA_NAME = Object.freeze({
  SHA256: 'ws.sha256',
  SHA3_512: 'ws.sha3-512',
});

const PUBLIC_NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
const TESTNET_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';
const SEP53_PREFIX_BYTES = utf8ToBytes('Stellar Signed Message:\n');
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STRKEY_VERSION_ED25519_PUBLIC = 6 << 3;
const LEGACY_ED25519_WARNING = 'Legacy Ed25519 signature is not post-quantum secure. Prefer .qsig for PQ authenticity.';

const ENVELOPE_TYPE_TX = 2;
const OPERATION_TYPE_MANAGE_DATA = 10;
const KEY_TYPE_ED25519 = 0;
const PRECOND_NONE = 0;
const MEMO_NONE = 0;

export function isSupportedStellarSignatureDocument(doc) {
  if (!doc || typeof doc !== 'object') return false;
  if (String(doc.schema || '').trim() !== STELLAR_SIGNATURE_SCHEMA) return false;
  const proofType = String(doc.proofType || '').trim();
  const payloadType = String(doc.payloadType || '').trim();
  const signatureScheme = String(doc.signatureScheme || '').trim();
  return (
    (proofType === PROOF_TYPE.SEP53_MESSAGE &&
      payloadType === PAYLOAD_TYPE.RAW_BYTES &&
      signatureScheme === SIGNATURE_SCHEME.SEP53_SHA256_ED25519) ||
    (proofType === PROOF_TYPE.XDR_ENVELOPE &&
      payloadType === PAYLOAD_TYPE.DETACHED_DIGESTS &&
      signatureScheme === SIGNATURE_SCHEME.TX_ENVELOPE_ED25519)
  );
}

function normalizeHashAlgorithmName(value) {
  const normalized = String(value || '').trim().toUpperCase();
  if (normalized === HASH_ALG.SHA256) return HASH_ALG.SHA256;
  if (normalized === HASH_ALG.SHA3_512) return HASH_ALG.SHA3_512;
  throw new Error(`Unsupported hash algorithm: ${value}`);
}

function expectedDigestHexLength(alg) {
  return normalizeHashAlgorithmName(alg) === HASH_ALG.SHA256 ? 64 : 128;
}

function hashAlgorithmFromManageDataName(name) {
  const normalized = String(name || '').trim();
  if (normalized === MANAGE_DATA_NAME.SHA256) return HASH_ALG.SHA256;
  if (normalized === MANAGE_DATA_NAME.SHA3_512) return HASH_ALG.SHA3_512;
  return null;
}

function parseHashEntries(doc) {
  if (!Array.isArray(doc?.hashes) || doc.hashes.length === 0) {
    throw new Error('Signature has no hashes[] entries');
  }

  const out = [];
  const seen = new Set();
  for (const entry of doc.hashes) {
    const alg = normalizeHashAlgorithmName(entry?.alg);
    const hex = String(entry?.hex || '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expectedDigestHexLength(alg)) {
      throw new Error(`Invalid hash hex for ${alg}`);
    }
    if (seen.has(alg)) throw new Error(`Duplicate hash entry: ${alg}`);
    seen.add(alg);
    out.push({ alg, hex });
  }
  return out;
}

function parseDeclaredManageDataEntries(manageDataSection) {
  const entries = manageDataSection?.entries;
  if (!Array.isArray(entries)) {
    throw new Error('manageData.entries must be an array.');
  }
  if (entries.length === 0) {
    throw new Error('manageData.entries must not be empty.');
  }

  const seen = new Set();
  return entries.map((item) => {
    const name = String(item?.name || '').trim();
    const alg = normalizeHashAlgorithmName(item?.alg);
    const digestHex = String(item?.digestHex || '').toLowerCase();
    if (!name) throw new Error('manageData.entries contains empty name.');
    if (seen.has(name)) throw new Error(`manageData.entries contains duplicate name: ${name}`);
    seen.add(name);
    if (!/^[0-9a-f]+$/.test(digestHex)) {
      throw new Error(`manageData.entries digestHex is invalid for ${name}.`);
    }

    const impliedAlg = hashAlgorithmFromManageDataName(name);
    if (!impliedAlg) throw new Error(`Unsupported ManageData name: ${name}.`);
    if (impliedAlg !== alg) throw new Error(`ManageData name/alg mismatch for ${name}.`);
    if (digestHex.length !== expectedDigestHexLength(alg)) {
      throw new Error(`manageData.entries digestHex length mismatch for ${name}.`);
    }

    return {
      name,
      alg,
      digestHex,
    };
  });
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

async function importEd25519PublicKey(publicBytes) {
  try {
    return await crypto.subtle.importKey('raw', publicBytes, { name: 'Ed25519' }, false, ['verify']);
  } catch {
    const spkiPrefix = Uint8Array.from([
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    return crypto.subtle.importKey('spki', concatBytes([spkiPrefix, publicBytes]), { name: 'Ed25519' }, false, ['verify']);
  }
}

async function verifyEd25519(publicBytes, messageBytes, signatureBytes) {
  const key = await importEd25519PublicKey(publicBytes);
  return crypto.subtle.verify('Ed25519', key, signatureBytes, messageBytes);
}

async function computeSep53PayloadHash(messageBytes) {
  return digestSha256(concatBytes([SEP53_PREFIX_BYTES, messageBytes]));
}

function parseSep53Signature(signatureB64) {
  const signatureBytes = base64ToBytes(String(signatureB64 || ''));
  if (signatureBytes.length !== 64) {
    throw new Error(`Expected 64-byte Ed25519 signature, got ${signatureBytes.length}`);
  }
  return signatureBytes;
}

function validateInputDescriptor(input, messageBytes) {
  if (!input || typeof input !== 'object') return;
  const inputType = String(input.type || '').trim();
  if (inputType && inputType !== 'file' && inputType !== 'text') {
    throw new Error(`Unsupported input.type: ${inputType}`);
  }
  if (Number.isInteger(input.size) && input.size !== messageBytes.length) {
    throw new Error(`Input size mismatch: signature expects ${input.size}, got ${messageBytes.length}`);
  }
}

async function buildDigests(messageBytes) {
  const sha256Bytes = await digestSha256(messageBytes);
  const sha3_512Bytes = sha3_512(messageBytes);
  return {
    [HASH_ALG.SHA256]: {
      alg: HASH_ALG.SHA256,
      bytes: sha256Bytes,
      hex: bytesToHex(sha256Bytes),
    },
    [HASH_ALG.SHA3_512]: {
      alg: HASH_ALG.SHA3_512,
      bytes: sha3_512Bytes,
      hex: bytesToHex(sha3_512Bytes),
    },
  };
}

function buildSuccessResult({ warnings, signer, bundlePinned, userPinned }) {
  return {
    ok: true,
    bundlePinned,
    userPinned,
    signerPinned: bundlePinned || userPinned,
    type: 'sig',
    format: 'stellar-sig',
    suite: 'ed25519',
    suiteDisplay: 'Ed25519',
    strongPq: false,
    signer,
    signerLabel: signer,
    warnings,
  };
}

function buildFailureResult({ error, warnings }) {
  return {
    ok: false,
    bundlePinned: false,
    userPinned: false,
    signerPinned: false,
    type: 'sig',
    format: 'stellar-sig',
    error,
    warnings,
  };
}

function networkHintFromPassphrase(passphrase) {
  const normalized = String(passphrase || '').trim();
  if (normalized === PUBLIC_NETWORK_PASSPHRASE) return 'pubnet';
  if (normalized === TESTNET_NETWORK_PASSPHRASE) return 'testnet';
  return 'custom';
}

function knownNetworkPassphrases() {
  return [PUBLIC_NETWORK_PASSPHRASE, TESTNET_NETWORK_PASSPHRASE];
}

function signatureHint(publicBytes) {
  if (!(publicBytes instanceof Uint8Array) || publicBytes.length !== 32) {
    throw new Error('Stellar signer public key must be 32 bytes.');
  }
  return publicBytes.slice(28, 32);
}

function parseTransactionEnvelope(input) {
  const raw = input instanceof Uint8Array ? input : base64ToBytes(input);
  const reader = new XdrReader(raw);

  const envelopeType = reader.readInt32();
  if (envelopeType !== ENVELOPE_TYPE_TX) {
    throw new Error(`Unsupported Stellar envelope type: ${envelopeType}`);
  }

  const txStart = reader.offset;
  const transaction = parseTransaction(reader);
  const txEnd = reader.offset;
  const signatures = parseDecoratedSignatures(reader);
  reader.ensureConsumed();

  return {
    envelopeType,
    transaction,
    signatures,
    txXdr: raw.slice(txStart, txEnd),
  };
}

function assertSafeManageDataEnvelope(parsed, { expectedEntries } = {}) {
  if (!parsed?.transaction) {
    throw new Error('Envelope parse result is missing transaction.');
  }

  const tx = parsed.transaction;
  if (tx.sequence !== 0n) {
    throw new Error('Unsafe Stellar transaction: sequence must be 0.');
  }
  if (!Number.isInteger(tx.fee) || tx.fee <= 0 || tx.fee > 100000) {
    throw new Error('Unsafe Stellar transaction: fee is outside allowed range.');
  }
  if (!Array.isArray(tx.operations) || tx.operations.length === 0) {
    throw new Error('Unsafe Stellar transaction: at least one operation is required.');
  }
  if (tx.operations.length > 8) {
    throw new Error('Unsafe Stellar transaction: too many operations.');
  }

  const manageDataEntries = [];
  const seenDataNames = new Set();
  for (const op of tx.operations) {
    if (op.type !== OPERATION_TYPE_MANAGE_DATA) {
      throw new Error('Unsafe Stellar transaction: only ManageData operations are allowed.');
    }
    if (op.sourceAccount) {
      throw new Error('Unsafe Stellar transaction: operation-level sourceAccount is not allowed.');
    }
    if (!(op.body?.dataValue instanceof Uint8Array) || op.body.dataValue.length === 0) {
      throw new Error('ManageData operation must include a non-empty value.');
    }

    const dataName = String(op.body?.dataName || '');
    assertSupportedManageDataName(dataName);
    if (seenDataNames.has(dataName)) {
      throw new Error(`Duplicate ManageData name in transaction: ${dataName}`);
    }
    seenDataNames.add(dataName);

    const expectedLength = expectedManageDataLength(dataName);
    if (op.body.dataValue.length !== expectedLength) {
      throw new Error(
        `ManageData value length mismatch for ${dataName}: expected ${expectedLength} bytes, got ${op.body.dataValue.length}.`
      );
    }

    manageDataEntries.push({
      dataName,
      dataValue: op.body.dataValue,
    });
  }

  if (Array.isArray(expectedEntries) && expectedEntries.length > 0) {
    if (expectedEntries.length !== manageDataEntries.length) {
      throw new Error('ManageData operation count does not match expected entries.');
    }

    const entryMap = new Map(manageDataEntries.map((item) => [item.dataName, item]));
    const seenExpected = new Set();
    for (const item of expectedEntries) {
      const dataName = String(item?.dataName || '');
      const dataValue = item?.dataValue instanceof Uint8Array ? item.dataValue : null;
      if (!dataName) throw new Error('Expected ManageData entry has empty name.');
      if (seenExpected.has(dataName)) {
        throw new Error(`Expected ManageData entries contain duplicate name: ${dataName}`);
      }
      seenExpected.add(dataName);

      const actual = entryMap.get(dataName);
      if (!actual) {
        throw new Error(`ManageData name mismatch: missing ${dataName}`);
      }
      if (dataValue && !bytesEqual(dataValue, actual.dataValue)) {
        throw new Error(`ManageData value mismatch for ${dataName}`);
      }
    }
  }

  return {
    sourceAccount: tx.sourceAccount,
    manageDataEntries,
  };
}

async function computeTransactionHash(txXdr, networkPassphrase) {
  if (!(txXdr instanceof Uint8Array)) {
    throw new Error('txXdr must be Uint8Array.');
  }
  const passphrase = String(networkPassphrase || '').trim();
  if (!passphrase) {
    throw new Error('Network passphrase is required.');
  }

  const networkId = await digestSha256(utf8ToBytes(passphrase));
  const writer = new XdrWriter();
  writer.writeRaw(networkId);
  writer.writeInt32(ENVELOPE_TYPE_TX);
  writer.writeRaw(txXdr);
  return digestSha256(writer.finish());
}

async function findValidDecoratedSignature(signatures, signerPublicBytes, txHash) {
  if (!Array.isArray(signatures)) return null;
  const signerHint = signatureHint(signerPublicBytes);

  for (const item of signatures) {
    if (!(item?.signature instanceof Uint8Array) || item.signature.length !== 64) continue;
    if (!(item?.hint instanceof Uint8Array) || item.hint.length !== 4) continue;
    if (!bytesEqual(item.hint, signerHint)) continue;
    if (await verifyEd25519(signerPublicBytes, txHash, item.signature)) {
      return item;
    }
  }

  for (const item of signatures) {
    if (!(item?.signature instanceof Uint8Array) || item.signature.length !== 64) continue;
    if (await verifyEd25519(signerPublicBytes, txHash, item.signature)) {
      return item;
    }
  }

  return null;
}

function parseTransaction(reader) {
  const sourceType = reader.readInt32();
  if (sourceType !== KEY_TYPE_ED25519) {
    throw new Error('Only ED25519 source accounts are supported.');
  }
  const sourceAccount = reader.readOpaqueFixed(32);
  const fee = reader.readUint32();
  const sequence = reader.readInt64();

  const preconditionsType = reader.readInt32();
  if (preconditionsType !== PRECOND_NONE) {
    throw new Error('Only PRECOND_NONE is supported.');
  }

  const memoType = reader.readInt32();
  if (memoType !== MEMO_NONE) {
    throw new Error('Only MEMO_NONE is supported.');
  }

  const operationCount = reader.readInt32();
  if (!Number.isInteger(operationCount) || operationCount < 0 || operationCount > 100) {
    throw new Error(`Invalid Stellar operation count: ${operationCount}`);
  }

  const operations = [];
  for (let i = 0; i < operationCount; i += 1) {
    operations.push(parseOperation(reader));
  }

  const ext = reader.readInt32();
  if (ext !== 0) {
    throw new Error('Only tx.ext.v=0 is supported.');
  }

  return {
    sourceAccount,
    fee,
    sequence,
    operations,
  };
}

function parseOperation(reader) {
  const hasSourceAccount = reader.readInt32();
  if (hasSourceAccount !== 0 && hasSourceAccount !== 1) {
    throw new Error('Invalid operation.sourceAccount optional field.');
  }

  let sourceAccount = null;
  if (hasSourceAccount === 1) {
    const sourceType = reader.readInt32();
    if (sourceType !== KEY_TYPE_ED25519) {
      throw new Error('Only ED25519 operation.sourceAccount is supported.');
    }
    sourceAccount = reader.readOpaqueFixed(32);
  }

  const type = reader.readInt32();
  if (type !== OPERATION_TYPE_MANAGE_DATA) {
    throw new Error(`Unsupported operation type in Stellar proof: ${type}`);
  }

  const dataName = reader.readString();
  const hasDataValue = reader.readInt32();
  if (hasDataValue !== 0 && hasDataValue !== 1) {
    throw new Error('Invalid ManageData optional value flag.');
  }

  const dataValue = hasDataValue ? reader.readOpaque() : null;
  return {
    type,
    sourceAccount,
    body: {
      dataName,
      dataValue,
    },
  };
}

function parseDecoratedSignatures(reader) {
  const count = reader.readInt32();
  if (!Number.isInteger(count) || count < 0 || count > 20) {
    throw new Error(`Invalid Stellar signature count: ${count}`);
  }

  const out = [];
  for (let i = 0; i < count; i += 1) {
    const hint = reader.readOpaqueFixed(4);
    const signature = reader.readOpaque();
    out.push({ hint, signature });
  }
  return out;
}

class XdrWriter {
  constructor() {
    this.parts = [];
  }

  push(bytes) {
    this.parts.push(bytes);
  }

  writeRaw(bytes) {
    this.push(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes));
  }

  writeInt32(value) {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setInt32(0, Number(value), false);
    this.push(bytes);
  }

  finish() {
    return concatBytes(this.parts);
  }
}

class XdrReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  ensureAvailable(length) {
    if (this.offset + length > this.bytes.length) {
      throw new Error('Unexpected end of XDR data.');
    }
  }

  readSlice(length) {
    this.ensureAvailable(length);
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  readInt32() {
    const chunk = this.readSlice(4);
    return new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength).getInt32(0, false);
  }

  readUint32() {
    const chunk = this.readSlice(4);
    return new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength).getUint32(0, false);
  }

  readInt64() {
    const high = this.readUint32();
    const low = this.readUint32();
    return (BigInt(high) << 32n) | BigInt(low);
  }

  readOpaqueFixed(length) {
    const data = this.readSlice(length);
    const pad = (4 - (length % 4)) % 4;
    if (pad) this.readSlice(pad);
    return data;
  }

  readOpaque() {
    const length = this.readInt32();
    if (length < 0) {
      throw new Error('Invalid opaque length.');
    }
    return this.readOpaqueFixed(length);
  }

  readString() {
    return bytesToUtf8(this.readOpaque());
  }

  ensureConsumed() {
    if (this.offset !== this.bytes.length) {
      throw new Error('XDR contains trailing bytes.');
    }
  }
}

function assertSupportedManageDataName(name) {
  if (name !== MANAGE_DATA_NAME.SHA256 && name !== MANAGE_DATA_NAME.SHA3_512) {
    throw new Error(`Unsupported ManageData name: ${name}`);
  }
}

function expectedManageDataLength(name) {
  assertSupportedManageDataName(name);
  return name === MANAGE_DATA_NAME.SHA3_512 ? 64 : 32;
}

export async function verifyStellarSigAgainstBytes({
  messageBytes,
  sigJsonBytes,
  bundleSigner = '',
  expectedSigner = '',
}) {
  const warnings = [LEGACY_ED25519_WARNING];

  let doc;
  try {
    doc = JSON.parse(new TextDecoder().decode(sigJsonBytes));
  } catch (error) {
    return buildFailureResult({
      error: `Invalid JSON signature document: ${error?.message || error}`,
      warnings,
    });
  }

  if (!isSupportedStellarSignatureDocument(doc)) {
    return buildFailureResult({
      error: `Unsupported Stellar signature profile: ${String(doc?.schema || '(missing)')} / ${String(doc?.proofType || '(missing)')} / ${String(doc?.signatureScheme || '(missing)')}`,
      warnings,
    });
  }

  const signer = String(doc.signer || '').trim();
  let signerPublicBytes;
  try {
    signerPublicBytes = decodeEd25519PublicKey(signer);
  } catch (error) {
    return buildFailureResult({
      error: `Invalid signer address: ${error?.message || error}`,
      warnings,
    });
  }

  const declaredSigner = String(bundleSigner || '').trim();
  if (declaredSigner && declaredSigner !== signer) {
    return buildFailureResult({
      error: `Bundled signer identifier does not match signature document signer (expected ${declaredSigner}, got ${signer})`,
      warnings,
    });
  }

  const expected = String(expectedSigner || '').trim();
  let userPinned = false;
  if (expected) {
    if (expected === signer) {
      userPinned = true;
    } else {
      warnings.push(`Pinned Ed25519 signer did not match this verified signature (expected ${expected}, got ${signer}).`);
    }
  }

  let hashEntries;
  try {
    hashEntries = parseHashEntries(doc);
  } catch (error) {
    return buildFailureResult({
      error: error?.message || String(error),
      warnings,
    });
  }

  const digests = await buildDigests(messageBytes);
  for (const entry of hashEntries) {
    if (digests[entry.alg].hex !== entry.hex) {
      return buildFailureResult({
        error: `Digest mismatch for ${entry.alg}`,
        warnings,
      });
    }
  }

  try {
    validateInputDescriptor(doc.input, messageBytes);
  } catch (error) {
    return buildFailureResult({
      error: error?.message || String(error),
      warnings,
    });
  }

  const proofType = String(doc.proofType || '').trim();
  if (proofType === PROOF_TYPE.SEP53_MESSAGE) {
    let signatureBytes;
    try {
      signatureBytes = parseSep53Signature(doc.signatureB64);
    } catch (error) {
      return buildFailureResult({
        error: error?.message || String(error),
        warnings,
      });
    }

    const payloadHash = await computeSep53PayloadHash(messageBytes);
    const sigOk = await verifyEd25519(signerPublicBytes, payloadHash, signatureBytes);
    if (!sigOk) {
      return buildFailureResult({
        error: 'SEP-53 content signature verification failed',
        warnings,
      });
    }

    return buildSuccessResult({
      warnings,
      signer,
      bundlePinned: declaredSigner.length > 0,
      userPinned,
    });
  }

  let parsedEnvelope;
  try {
    parsedEnvelope = parseTransactionEnvelope(String(doc.signedXdr || '').trim());
  } catch (error) {
    return buildFailureResult({
      error: `Malformed signedXdr: ${error?.message || error}`,
      warnings,
    });
  }

  let declaredManageDataEntries;
  try {
    declaredManageDataEntries = parseDeclaredManageDataEntries(doc.manageData);
  } catch (error) {
    return buildFailureResult({
      error: `Malformed manageData section: ${error?.message || error}`,
      warnings,
    });
  }

  let safeOp;
  try {
    safeOp = assertSafeManageDataEnvelope(parsedEnvelope, {
      expectedEntries: declaredManageDataEntries.map((item) => ({ dataName: item.name })),
    });
  } catch (error) {
    return buildFailureResult({
      error: error?.message || String(error),
      warnings,
    });
  }

  if (!bytesEqual(safeOp.sourceAccount, signerPublicBytes)) {
    return buildFailureResult({
      error: 'signedXdr sourceAccount does not match the signer field',
      warnings,
    });
  }

  const declaredTxSource = String(doc.txSourceAccount || '').trim();
  if (declaredTxSource) {
    let txSourcePublicBytes;
    try {
      txSourcePublicBytes = decodeEd25519PublicKey(declaredTxSource);
    } catch (error) {
      return buildFailureResult({
        error: `Invalid txSourceAccount: ${error?.message || error}`,
        warnings,
      });
    }
    if (!bytesEqual(txSourcePublicBytes, safeOp.sourceAccount)) {
      return buildFailureResult({
        error: 'txSourceAccount does not match signedXdr sourceAccount',
        warnings,
      });
    }
  }

  if (safeOp.manageDataEntries.length !== hashEntries.length) {
    return buildFailureResult({
      error: 'signedXdr ManageData count must exactly match hashes[] count.',
      warnings,
    });
  }

  const seenAlgorithms = new Set();
  for (const txEntry of safeOp.manageDataEntries) {
    const declared = declaredManageDataEntries.find((item) => item.name === txEntry.dataName);
    const boundAlg = declared?.alg || hashAlgorithmFromManageDataName(txEntry.dataName);
    if (!boundAlg) {
      return buildFailureResult({
        error: `Cannot determine hash algorithm bound to ManageData ${txEntry.dataName}.`,
        warnings,
      });
    }
    if (seenAlgorithms.has(boundAlg)) {
      return buildFailureResult({
        error: `Duplicate ManageData algorithm binding: ${boundAlg}.`,
        warnings,
      });
    }
    seenAlgorithms.add(boundAlg);

    const expectedLength = boundAlg === HASH_ALG.SHA3_512 ? 64 : 32;
    if (txEntry.dataValue.length !== expectedLength) {
      return buildFailureResult({
        error: `ManageData value length mismatch for ${boundAlg}: expected ${expectedLength} bytes, got ${txEntry.dataValue.length}.`,
        warnings,
      });
    }
    if (!bytesEqual(txEntry.dataValue, digests[boundAlg].bytes)) {
      return buildFailureResult({
        error: `ManageData digest mismatch for ${boundAlg}.`,
        warnings,
      });
    }
    if (declared?.digestHex && declared.digestHex !== digests[boundAlg].hex) {
      return buildFailureResult({
        error: `manageData.digestHex mismatch for ${txEntry.dataName}.`,
        warnings,
      });
    }
    if (!hashEntries.some((entry) => entry.alg === boundAlg)) {
      return buildFailureResult({
        error: `hashes[] does not include bound ManageData algorithm ${boundAlg}.`,
        warnings,
      });
    }
  }

  for (const entry of hashEntries) {
    if (!seenAlgorithms.has(entry.alg)) {
      return buildFailureResult({
        error: `signedXdr is missing ManageData entry for ${entry.alg}.`,
        warnings,
      });
    }
  }

  const passphrase = String(doc.network?.passphrase || '').trim();
  if (!passphrase) {
    return buildFailureResult({
      error: 'network.passphrase is missing.',
      warnings,
    });
  }

  const declaredHint = String(doc.network?.hint || '').trim();
  const expectedHint = networkHintFromPassphrase(passphrase);
  if (declaredHint && declaredHint !== expectedHint) {
    warnings.push(`network.hint mismatch: expected ${expectedHint}, got ${declaredHint}.`);
  }

  const txHash = await computeTransactionHash(parsedEnvelope.txXdr, passphrase);
  const match = await findValidDecoratedSignature(parsedEnvelope.signatures, signerPublicBytes, txHash);
  if (!match) {
    for (const alternative of knownNetworkPassphrases()) {
      if (alternative === passphrase) continue;
      const altHash = await computeTransactionHash(parsedEnvelope.txXdr, alternative);
      const altMatch = await findValidDecoratedSignature(parsedEnvelope.signatures, signerPublicBytes, altHash);
      if (altMatch) {
        return buildFailureResult({
          error: 'Wrong network passphrase: signature is valid under a different known Stellar network passphrase.',
          warnings,
        });
      }
    }

    return buildFailureResult({
      error: 'No valid signer signature found in signedXdr',
      warnings,
    });
  }

  return buildSuccessResult({
    warnings,
    signer,
    bundlePinned: declaredSigner.length > 0,
    userPinned,
  });
}
