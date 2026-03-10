import { sha3_512 } from '@noble/hashes/sha3.js';
import { asciiBytes, base64ToBytes, bytesEqual, digestSha256, toHex } from '../bytes.js';
import { verifyQsigAgainstBytes } from './qsig.js';
import { verifyStellarSigAgainstBytes } from './stellar-sig.js';

const MAGIC_QSIG = asciiBytes('PQSG');

function decodeJsonBytes(bytes) {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

function detectExternalSignatureType(signature) {
  const { name = '', bytes } = signature;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return 'unknown';
  if (bytes.length >= 4 && bytesEqual(bytes.subarray(0, 4), MAGIC_QSIG)) return 'qsig';

  const lowerName = String(name).toLowerCase();
  if (lowerName.endsWith('.sig') || lowerName.endsWith('.json') || lowerName.length > 0) {
    const json = decodeJsonBytes(bytes);
    if (json && typeof json === 'object' && json.schema === 'stellar-file-signature/v1') {
      return 'stellar-sig';
    }
  }

  return 'unknown';
}

function loadBundlePublicKey(publicKeyEntry) {
  if (!publicKeyEntry) return null;
  if (publicKeyEntry.encoding !== 'base64') {
    throw new Error(`Unsupported bundle public key encoding: ${publicKeyEntry.encoding}`);
  }
  return base64ToBytes(publicKeyEntry.value);
}

function loadBundleSignerIdentifier(publicKeyEntry) {
  if (!publicKeyEntry) return '';
  if (publicKeyEntry.encoding === 'stellar-address') {
    return String(publicKeyEntry.value || '').trim();
  }
  return '';
}

async function verifyBundleSignature({
  manifestBytes,
  signature,
  publicKeysById,
  pinnedPqPublicKeyFileBytes,
  expectedEd25519Signer,
}) {
  const name = signature.id || 'bundle-signature';
  const bundlePublicKeyEntry = publicKeysById.get(signature.publicKeyRef || '');

  if (signature.format === 'qsig') {
    const qsigBytes = signature.signatureEncoding === 'base64'
      ? base64ToBytes(signature.signature)
      : (() => {
          throw new Error(`Unsupported bundle signature encoding: ${signature.signatureEncoding}`);
        })();
    const bundleVerificationKeyBytes = loadBundlePublicKey(bundlePublicKeyEntry);
    const result = verifyQsigAgainstBytes({
      messageBytes: manifestBytes,
      qsigBytes,
      bundlePqPublicKeyFileBytes: bundleVerificationKeyBytes,
      pinnedPqPublicKeyFileBytes,
    });
    return { ...result, name, source: 'bundle', signatureBytes: qsigBytes, artifactId: signature.id || name };
  }

  if (signature.format === 'stellar-sig') {
    const sigJsonBytes = signature.signatureEncoding === 'base64'
      ? base64ToBytes(signature.signature)
      : (() => {
          throw new Error(`Unsupported bundle signature encoding: ${signature.signatureEncoding}`);
        })();
    const result = await verifyStellarSigAgainstBytes({
      messageBytes: manifestBytes,
      sigJsonBytes,
      bundleSigner: loadBundleSignerIdentifier(bundlePublicKeyEntry),
      expectedSigner: expectedEd25519Signer,
    });
    return { ...result, name, source: 'bundle', signatureBytes: sigJsonBytes, artifactId: signature.id || name };
  }

  return {
    ok: false,
    bundlePinned: false,
    userPinned: false,
    signerPinned: false,
    type: 'unknown',
    format: signature.format,
    name,
    source: 'bundle',
    error: `Unsupported signature format: ${signature.format}`,
    warnings: [],
    artifactId: signature.id || name,
  };
}

async function verifyExternalSignature({
  manifestBytes,
  signature,
  pinnedPqPublicKeyFileBytes,
  expectedEd25519Signer,
}) {
  const sigType = detectExternalSignatureType(signature);
  if (sigType === 'unknown') {
    return {
      ok: false,
      bundlePinned: false,
      userPinned: false,
      signerPinned: false,
      type: 'unknown',
      format: 'unknown',
      name: signature?.name || 'unknown',
      source: 'external',
      error: 'Unsupported signature format',
      warnings: [],
      artifactId: signature?.name || 'unknown',
    };
  }

  if (sigType === 'qsig') {
    const result = verifyQsigAgainstBytes({
      messageBytes: manifestBytes,
      qsigBytes: signature.bytes,
      bundlePqPublicKeyFileBytes: null,
      pinnedPqPublicKeyFileBytes,
    });
    return {
      ...result,
      name: signature?.name || 'signature.qsig',
      source: 'external',
      signatureBytes: signature.bytes,
      artifactId: signature?.name || 'signature.qsig',
    };
  }

  const result = await verifyStellarSigAgainstBytes({
    messageBytes: manifestBytes,
    sigJsonBytes: signature.bytes,
    expectedSigner: expectedEd25519Signer,
  });
  return {
    ...result,
    name: signature?.name || 'signature.sig',
    source: 'external',
    signatureBytes: signature.bytes,
    artifactId: signature?.name || 'signature.sig',
  };
}

function buildCounts(results) {
  const counts = {
    validTotal: 0,
    validStrongPq: 0,
    pinnedValidTotal: 0,
    pinnedValidStrongPq: 0,
    bundlePinnedValidTotal: 0,
    userPinnedValidTotal: 0,
  };
  const duplicateWarnings = [];
  const uniqueValid = new Map();

  for (const result of results) {
    result.countedForPolicy = false;
    if (!result.ok || typeof result.signatureContentDigestHex !== 'string') continue;
    const dedupeKey = `${result.format}:${result.signatureContentDigestHex}`;
    const current = uniqueValid.get(dedupeKey);
    if (!current) {
      uniqueValid.set(dedupeKey, {
        strongPq: result.strongPq === true,
        signerPinned: result.signerPinned === true,
        bundlePinned: result.bundlePinned === true,
        userPinned: result.userPinned === true,
        names: [result.name || result.artifactId || dedupeKey],
      });
      result.countedForPolicy = true;
      continue;
    }

    current.strongPq = current.strongPq || result.strongPq === true;
    current.signerPinned = current.signerPinned || result.signerPinned === true;
    current.bundlePinned = current.bundlePinned || result.bundlePinned === true;
    current.userPinned = current.userPinned || result.userPinned === true;
    current.names.push(result.name || result.artifactId || dedupeKey);
  }

  for (const entry of uniqueValid.values()) {
    counts.validTotal += 1;
    if (entry.strongPq) counts.validStrongPq += 1;
    if (entry.signerPinned) counts.pinnedValidTotal += 1;
    if (entry.signerPinned && entry.strongPq) counts.pinnedValidStrongPq += 1;
    if (entry.bundlePinned) counts.bundlePinnedValidTotal += 1;
    if (entry.userPinned) counts.userPinnedValidTotal += 1;
    if (entry.names.length > 1) {
      duplicateWarnings.push(`Duplicate detached signature ignored for policy counting: ${entry.names.join(', ')}`);
    }
  }

  return { counts, duplicateWarnings };
}

async function attachSignatureDigests(result) {
  if (!(result?.signatureBytes instanceof Uint8Array)) {
    return result;
  }

  return {
    ...result,
    signatureContentDigestAlg: 'SHA3-512',
    signatureContentDigestHex: toHex(sha3_512(result.signatureBytes)),
    otsStampedDigestAlg: 'SHA-256',
    otsStampedDigestHex: toHex(await digestSha256(result.signatureBytes)),
  };
}

export async function verifyManifestSignatures({
  manifestBytes,
  bundleSignatures = [],
  bundlePublicKeys = [],
  externalSignatures = [],
  pinnedPqPublicKeyFileBytes = null,
  expectedEd25519Signer = '',
}) {
  if (!(manifestBytes instanceof Uint8Array)) {
    throw new Error('manifestBytes must be Uint8Array');
  }

  if (!Array.isArray(bundleSignatures) || !Array.isArray(bundlePublicKeys) || !Array.isArray(externalSignatures)) {
    throw new Error('signatures/publicKeys must be arrays');
  }

  const publicKeysById = new Map(bundlePublicKeys.map((item) => [item.id, item]));
  const results = [];
  const warnings = [];
  const userPinProvided = (
    pinnedPqPublicKeyFileBytes instanceof Uint8Array ||
    String(expectedEd25519Signer || '').trim().length > 0
  );

  for (const signature of bundleSignatures) {
    const result = await attachSignatureDigests(await verifyBundleSignature({
      manifestBytes,
      signature,
      publicKeysById,
      pinnedPqPublicKeyFileBytes,
      expectedEd25519Signer,
    }));
    results.push(result);
    if (Array.isArray(result.warnings)) warnings.push(...result.warnings);
  }

  for (const signature of externalSignatures) {
    const result = await attachSignatureDigests(await verifyExternalSignature({
      manifestBytes,
      signature,
      pinnedPqPublicKeyFileBytes,
      expectedEd25519Signer,
    }));
    results.push(result);
    if (Array.isArray(result.warnings)) warnings.push(...result.warnings);
  }

  const { counts, duplicateWarnings } = buildCounts(results);
  warnings.push(...duplicateWarnings);
  return {
    provided: bundleSignatures.length + externalSignatures.length > 0,
    results,
    warnings,
    counts,
    signatureArtifacts: results
      .filter((result) => result.signatureBytes instanceof Uint8Array)
      .map((result) => ({
        id: result.artifactId || result.name,
        name: result.name,
        source: result.source,
        format: result.format,
        bytes: result.signatureBytes,
        ok: result.ok === true,
        signatureContentDigestHex: result.signatureContentDigestHex,
        otsStampedDigestHex: result.otsStampedDigestHex,
      })),
    status: {
      signatureVerified: counts.validTotal > 0,
      strongPqSignatureVerified: counts.validStrongPq > 0,
      signerPinned: counts.pinnedValidTotal > 0,
      signerIdentityPinned: counts.pinnedValidTotal > 0,
      bundlePinned: counts.bundlePinnedValidTotal > 0,
      userPinned: counts.userPinnedValidTotal > 0,
      userPinProvided,
    },
  };
}
