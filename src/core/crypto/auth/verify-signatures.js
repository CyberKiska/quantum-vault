import { sha3_512 } from '@noble/hashes/sha3.js';
import { asciiBytes, base64ToBytes, bytesEqual, digestSha256, toHex } from '../bytes.js';
import { normalizePqPublicKeyPins, verifyQsigAgainstBytes } from './qsig.js';
import { computeDetachedSignatureIdentityDigestHex } from './signature-identity.js';
import { isSupportedStellarSignatureDocument, verifyStellarSigAgainstBytes } from './stellar-sig.js';
import { getSignaturePublicKeyRefCompatibilityError } from '../manifest/manifest-bundle.js';

const MAGIC_QSIG = asciiBytes('PQSG');
const PIN_MISMATCH_WARNING_PREFIX = 'Pinned PQ signer key did not match';
const LEGACY_ED25519_WARNING = 'Legacy Ed25519 signature is not post-quantum secure. Prefer .qsig for PQ authenticity.';

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
    if (json && isSupportedStellarSignatureDocument(json)) {
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

function dedupeWarnings(warnings) {
  return [...new Set((Array.isArray(warnings) ? warnings : []).filter(Boolean))];
}

function buildVerificationFailureResult({
  type = 'unknown',
  format = 'unknown',
  error = 'Verification failed',
  warnings = [],
}) {
  return {
    ok: false,
    bundlePinned: false,
    userPinned: false,
    signerPinned: false,
    type,
    format,
    error,
    warnings: dedupeWarnings(warnings),
  };
}

function buildFormatFailureResult(format, error, warnings = []) {
  if (format === 'qsig') {
    return buildVerificationFailureResult({ type: 'qsig', format: 'qsig', error, warnings });
  }
  if (format === 'stellar-sig') {
    return buildVerificationFailureResult({ type: 'sig', format: 'stellar-sig', error, warnings });
  }
  return buildVerificationFailureResult({ type: 'unknown', format, error, warnings });
}

function safeVerifyQsigAgainstBytes(options) {
  try {
    return verifyQsigAgainstBytes(options);
  } catch (error) {
    return buildFormatFailureResult('qsig', error?.message || String(error));
  }
}

function verifyQsigWithPinnedKeys({
  messageBytes,
  qsigBytes,
  bundlePqPublicKeyFileBytes = null,
  normalizedPinnedPqPins = [],
  authoritativeBundlePqPublicKey = false,
}) {
  if (normalizedPinnedPqPins.length === 0) {
    return safeVerifyQsigAgainstBytes({
      messageBytes,
      qsigBytes,
      bundlePqPublicKeyFileBytes,
      pinnedPqPublicKeyFileBytes: null,
      authoritativeBundlePqPublicKey,
    });
  }
  if (normalizedPinnedPqPins.length === 1) {
    return safeVerifyQsigAgainstBytes({
      messageBytes,
      qsigBytes,
      bundlePqPublicKeyFileBytes,
      pinnedPqPublicKeyFileBytes: normalizedPinnedPqPins[0].bytes,
      authoritativeBundlePqPublicKey,
    });
  }

  let baseline = null;
  let firstOk = null;
  const matches = [];
  const retainedWarnings = [];

  for (const candidatePin of normalizedPinnedPqPins) {
    const result = safeVerifyQsigAgainstBytes({
      messageBytes,
      qsigBytes,
      bundlePqPublicKeyFileBytes,
      pinnedPqPublicKeyFileBytes: candidatePin.bytes,
      authoritativeBundlePqPublicKey,
    });
    if (!baseline) baseline = result;
    if (!firstOk && result.ok) firstOk = result;
    for (const warning of result.warnings || []) {
      if (!String(warning).startsWith(PIN_MISMATCH_WARNING_PREFIX)) {
        retainedWarnings.push(warning);
      }
    }
    if (result.ok && result.userPinned === true) {
      matches.push(result);
    }
  }

  if (matches.length > 1) {
    return {
      ...(firstOk || baseline || {}),
      ok: false,
      bundlePinned: false,
      userPinned: false,
      signerPinned: false,
      type: 'qsig',
      format: 'qsig',
      error: 'Multiple provided .pqpk files match this detached PQ signature. Keep only one exact PQ pin per signer.',
      warnings: dedupeWarnings(retainedWarnings),
    };
  }

  if (matches.length === 1) {
    return {
      ...matches[0],
      warnings: dedupeWarnings(matches[0].warnings || []),
    };
  }

  const verified = firstOk || safeVerifyQsigAgainstBytes({
    messageBytes,
    qsigBytes,
    bundlePqPublicKeyFileBytes,
    pinnedPqPublicKeyFileBytes: null,
    authoritativeBundlePqPublicKey,
  });

  if (!verified.ok) {
    return {
      ...verified,
      warnings: dedupeWarnings([...retainedWarnings, ...(verified.warnings || [])]),
    };
  }

  const mismatchWarning = bundlePqPublicKeyFileBytes instanceof Uint8Array
    ? 'Provided PQ signer keys did not match the bundled signer key.'
    : 'Provided PQ signer keys did not match this verified signature.';

  return {
    ...verified,
    userPinned: false,
    signerPinned: verified.bundlePinned === true,
    warnings: dedupeWarnings([
      ...retainedWarnings,
      ...(verified.warnings || []).filter((warning) => !String(warning).startsWith(PIN_MISMATCH_WARNING_PREFIX)),
      mismatchWarning,
    ]),
  };
}

async function verifyBundleSignature({
  manifestBytes,
  signature,
  publicKeysById,
  normalizedPinnedPqPins,
  expectedEd25519Signer,
}) {
  const name = signature.id || 'bundle-signature';
  const bundlePublicKeyEntry = publicKeysById.get(signature.publicKeyRef || '');
  const compatibilityError = getSignaturePublicKeyRefCompatibilityError(signature, bundlePublicKeyEntry);
  if (compatibilityError) {
    return {
      ...buildFormatFailureResult(signature.format, compatibilityError),
      name,
      source: 'bundle',
      artifactId: signature.id || name,
    };
  }

  if (signature.format === 'qsig') {
    try {
      const qsigBytes = signature.signatureEncoding === 'base64'
        ? base64ToBytes(signature.signature)
        : (() => {
            throw new Error(`Unsupported bundle signature encoding: ${signature.signatureEncoding}`);
          })();
      const bundleVerificationKeyBytes = bundlePublicKeyEntry ? loadBundlePublicKey(bundlePublicKeyEntry) : null;
      const result = verifyQsigWithPinnedKeys({
        messageBytes: manifestBytes,
        qsigBytes,
        bundlePqPublicKeyFileBytes: bundleVerificationKeyBytes,
        normalizedPinnedPqPins,
        authoritativeBundlePqPublicKey: Boolean(bundlePublicKeyEntry),
      });
      return { ...result, name, source: 'bundle', signatureBytes: qsigBytes, artifactId: signature.id || name };
    } catch (error) {
      return {
        ...buildFormatFailureResult('qsig', error?.message || String(error)),
        name,
        source: 'bundle',
        artifactId: signature.id || name,
      };
    }
  }

  if (signature.format === 'stellar-sig') {
    try {
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
    } catch (error) {
      return {
        ...buildFormatFailureResult('stellar-sig', error?.message || String(error)),
        name,
        source: 'bundle',
        artifactId: signature.id || name,
      };
    }
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
  normalizedPinnedPqPins,
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
    const result = verifyQsigWithPinnedKeys({
      messageBytes: manifestBytes,
      qsigBytes: signature.bytes,
      bundlePqPublicKeyFileBytes: null,
      normalizedPinnedPqPins,
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
    if (!result.ok || typeof result.proofIdentityDigestHex !== 'string') continue;
    const dedupeKey = `${result.format}:${result.proofIdentityDigestHex}`;
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
    proofIdentityDigestAlg: 'SHA3-512',
    proofIdentityDigestHex: computeDetachedSignatureIdentityDigestHex({
      format: result.format,
      signatureBytes: result.signatureBytes,
    }),
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
  pinnedPqPublicKeyFileBytesList = [],
  expectedEd25519Signer = '',
}) {
  if (!(manifestBytes instanceof Uint8Array)) {
    throw new Error('manifestBytes must be Uint8Array');
  }

  if (!Array.isArray(bundleSignatures) || !Array.isArray(bundlePublicKeys) || !Array.isArray(externalSignatures)) {
    throw new Error('signatures/publicKeys must be arrays');
  }

  const {
    pins: normalizedPinnedPqPins,
    warnings: pinNormalizationWarnings,
  } = normalizePqPublicKeyPins({
    pinnedPqPublicKeyFileBytes,
    pinnedPqPublicKeyFileBytesList,
    invalidBehavior: 'warn',
    invalidLabel: 'Pinned PQ signer key',
  });
  const publicKeysById = new Map(bundlePublicKeys.map((item) => [item.id, item]));
  const results = [];
  const warnings = [];
  const rawPqPinProvided = (
    pinnedPqPublicKeyFileBytes instanceof Uint8Array ||
    (Array.isArray(pinnedPqPublicKeyFileBytesList) && pinnedPqPublicKeyFileBytesList.some((item) => item instanceof Uint8Array))
  );
  const userPinProvided = (
    rawPqPinProvided ||
    String(expectedEd25519Signer || '').trim().length > 0
  );

  for (const signature of bundleSignatures) {
    const result = await attachSignatureDigests(await verifyBundleSignature({
      manifestBytes,
      signature,
      publicKeysById,
      normalizedPinnedPqPins,
      expectedEd25519Signer,
    }));
    results.push(result);
  }

  for (const signature of externalSignatures) {
    const result = await attachSignatureDigests(await verifyExternalSignature({
      manifestBytes,
      signature,
      normalizedPinnedPqPins,
      expectedEd25519Signer,
    }));
    results.push(result);
  }

  const { counts, duplicateWarnings } = buildCounts(results);
  if (counts.validStrongPq > 0) {
    for (const result of results) {
      if (!Array.isArray(result?.warnings) || result.warnings.length === 0) continue;
      result.warnings = result.warnings.filter((warning) => warning !== LEGACY_ED25519_WARNING);
    }
  }
  for (const result of results) {
    if (Array.isArray(result.warnings)) warnings.push(...result.warnings);
  }
  warnings.push(...pinNormalizationWarnings);
  warnings.push(...duplicateWarnings);
  const dedupedWarnings = dedupeWarnings(warnings);
  return {
    provided: bundleSignatures.length + externalSignatures.length > 0,
    results,
    warnings: dedupedWarnings,
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
