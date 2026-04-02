import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../bytes.js';
import { canonicalizeJsonToBytes } from '../manifest/jcs.js';
import { parseJsonBytesStrict } from '../manifest/strict-json.js';

const STELLAR_SIGNATURE_SCHEMA = 'stellar-signature/v2';

const STELLAR_PROOF_TYPE = Object.freeze({
  SEP53_MESSAGE: 'sep53-message-signature',
  XDR_ENVELOPE: 'xdr-envelope-proof',
});

const STELLAR_PAYLOAD_TYPE = Object.freeze({
  RAW_BYTES: 'raw-bytes',
  DETACHED_DIGESTS: 'detached-digests',
});

const STELLAR_SIGNATURE_SCHEME = Object.freeze({
  SEP53_SHA256_ED25519: 'sep53-sha256-ed25519',
  TX_ENVELOPE_ED25519: 'tx-envelope-ed25519',
});

function decodeJsonBytes(bytes) {
  try {
    return parseJsonBytesStrict(bytes);
  } catch {
    return null;
  }
}

function normalizeHashEntries(entries) {
  if (!Array.isArray(entries)) return [];
  return entries
    .map((entry) => ({
      alg: String(entry?.alg || '').trim().toUpperCase(),
      hex: String(entry?.hex || '').trim().toLowerCase(),
    }))
    .filter((entry) => entry.alg && entry.hex)
    .sort((left, right) => (
      left.alg.localeCompare(right.alg) ||
      left.hex.localeCompare(right.hex)
    ));
}

function normalizeManageDataEntries(entries) {
  if (!Array.isArray(entries)) return [];
  return entries
    .map((entry) => ({
      name: String(entry?.name || '').trim(),
      alg: String(entry?.alg || '').trim().toUpperCase(),
      digestHex: String(entry?.digestHex || '').trim().toLowerCase(),
    }))
    .filter((entry) => entry.name && entry.alg && entry.digestHex)
    .sort((left, right) => (
      left.name.localeCompare(right.name) ||
      left.alg.localeCompare(right.alg) ||
      left.digestHex.localeCompare(right.digestHex)
    ));
}

function buildStellarProofIdentityPayload(signatureBytes) {
  const doc = decodeJsonBytes(signatureBytes);
  if (!doc || typeof doc !== 'object') return null;

  const schema = String(doc.schema || '').trim();
  const proofType = String(doc.proofType || '').trim();
  const payloadType = String(doc.payloadType || '').trim();
  const signatureScheme = String(doc.signatureScheme || '').trim();
  const signer = String(doc.signer || '').trim();

  if (schema !== STELLAR_SIGNATURE_SCHEMA || !signer) return null;

  if (
    proofType === STELLAR_PROOF_TYPE.SEP53_MESSAGE &&
    payloadType === STELLAR_PAYLOAD_TYPE.RAW_BYTES &&
    signatureScheme === STELLAR_SIGNATURE_SCHEME.SEP53_SHA256_ED25519
  ) {
    const signatureB64 = String(doc.signatureB64 || '').trim();
    if (!signatureB64) return null;
    return canonicalizeJsonToBytes({
      format: 'stellar-sig',
      schema,
      proofType,
      payloadType,
      signatureScheme,
      signer,
      signatureB64,
      hashes: normalizeHashEntries(doc.hashes),
    });
  }

  if (
    proofType === STELLAR_PROOF_TYPE.XDR_ENVELOPE &&
    payloadType === STELLAR_PAYLOAD_TYPE.DETACHED_DIGESTS &&
    signatureScheme === STELLAR_SIGNATURE_SCHEME.TX_ENVELOPE_ED25519
  ) {
    const signedXdr = String(doc.signedXdr || '').trim();
    const networkPassphrase = String(doc.network?.passphrase || '').trim();
    if (!signedXdr || !networkPassphrase) return null;
    return canonicalizeJsonToBytes({
      format: 'stellar-sig',
      schema,
      proofType,
      payloadType,
      signatureScheme,
      signer,
      networkPassphrase,
      signedXdr,
      hashes: normalizeHashEntries(doc.hashes),
      manageDataEntries: normalizeManageDataEntries(doc.manageData?.entries),
    });
  }

  return null;
}

export function computeDetachedSignatureIdentityDigestHex({ format, signatureBytes }) {
  if (!(signatureBytes instanceof Uint8Array)) {
    throw new Error('signatureBytes must be Uint8Array');
  }

  if (format === 'stellar-sig') {
    const normalized = buildStellarProofIdentityPayload(signatureBytes);
    if (normalized instanceof Uint8Array) {
      return toHex(sha3_512(normalized));
    }
    return null;
  }

  return toHex(sha3_512(signatureBytes));
}
