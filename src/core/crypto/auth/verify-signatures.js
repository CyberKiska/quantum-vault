import { asciiBytes, bytesEqual } from './bytes.js';
import { verifyQsigAgainstBytes } from './qsig.js';
import { verifyStellarSigAgainstBytes } from './stellar-sig.js';

const MAGIC_QSIG = asciiBytes('PQSG');

function detectSignatureType(signature) {
  const { name = '', bytes } = signature;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return 'unknown';
  if (bytes.length >= 4 && bytesEqual(bytes.subarray(0, 4), MAGIC_QSIG)) return 'qsig';

  const lowerName = String(name).toLowerCase();
  if (lowerName.endsWith('.sig') || lowerName.endsWith('.json')) {
    try {
      const json = JSON.parse(new TextDecoder().decode(bytes));
      if (json && typeof json === 'object' && json.schema === 'stellar-file-signature/v1') {
        return 'sig';
      }
    } catch {
      // ignore
    }
  }

  return 'unknown';
}

export async function verifyManifestSignatures({
  manifestBytes,
  signatures = [],
  trustedPqPublicKeyFileBytes = null,
  pinnedPqFingerprintHex = '',
  expectedEd25519Signer = '',
  allowLegacyEd25519 = true,
}) {
  if (!(manifestBytes instanceof Uint8Array)) {
    throw new Error('manifestBytes must be Uint8Array');
  }

  if (!Array.isArray(signatures)) {
    throw new Error('signatures must be an array');
  }

  const results = [];
  const warnings = [];

  for (const sig of signatures) {
    const sigType = detectSignatureType(sig);
    if (sigType === 'unknown') {
      results.push({
        ok: false,
        trusted: false,
        type: 'unknown',
        name: sig?.name || 'unknown',
        error: 'Unsupported signature format',
        warnings: [],
      });
      continue;
    }

    if (sigType === 'qsig') {
      const result = verifyQsigAgainstBytes({
        messageBytes: manifestBytes,
        qsigBytes: sig.bytes,
        trustedPqPublicKeyFileBytes,
        pinnedPqFingerprintHex,
      });
      results.push({ ...result, name: sig?.name || 'signature.qsig' });
      if (Array.isArray(result.warnings)) warnings.push(...result.warnings);
      continue;
    }

    const result = await verifyStellarSigAgainstBytes({
      messageBytes: manifestBytes,
      sigJsonBytes: sig.bytes,
      expectedSigner: expectedEd25519Signer,
      allowLegacyEd25519,
    });
    results.push({ ...result, name: sig?.name || 'signature.sig' });
    if (Array.isArray(result.warnings)) warnings.push(...result.warnings);
  }

  const validResults = results.filter((item) => item.ok);
  const trustedValidResults = validResults.filter((item) => item.trusted);

  return {
    provided: signatures.length > 0,
    results,
    warnings,
    validCount: validResults.length,
    trustedValidCount: trustedValidResults.length,
    hasTrustedValid: trustedValidResults.length > 0,
  };
}
