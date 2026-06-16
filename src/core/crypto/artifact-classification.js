/**
 * DOM-free artifact classification.
 *
 * This module may identify artifact kind and parse metadata, but it does not
 * evaluate authenticity, restore acceptance, signer trust, timestamp trust, or
 * release policy.
 */

import { startsWithAscii } from './byte-prefix.js';
import { digestSha256, toHex } from './bytes.js';
import { parseOpenTimestampProof } from './auth/opentimestamps.js';
import { unpackPqpk, unpackQsig } from './auth/qsig.js';
import { isSupportedStellarSignatureDocumentBytes } from './auth/stellar-sig.js';
import {
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
  parseSourceEvidenceBytes,
  parseTransitionRecordBytes,
} from './lifecycle/artifacts.js';
import { parseLifecycleShard } from './qcont/lifecycle-shard.js';

const QCONT_MAGIC = 'QVC1';

function errorMessageText(error) {
  return String(error?.message || error || '').trim();
}

function baseClassification({ name, fileSha256Hex, kind, format, status, malformed = false }) {
  return {
    name,
    kind,
    format,
    status,
    malformed,
    fileSha256Hex,
    metadata: {},
  };
}

function recognized(params, metadata = {}, extras = {}) {
  return {
    ...baseClassification({ ...params, status: 'recognized', malformed: false }),
    metadata,
    ...extras,
  };
}

function malformed(params, error, metadata = {}) {
  return {
    ...baseClassification({ ...params, status: 'malformed', malformed: true }),
    metadata,
    error,
    errorMessage: errorMessageText(error),
  };
}

function legacyManifest(params) {
  return baseClassification({
    ...params,
    kind: 'legacy-manifest',
    format: 'qvmanifest-json',
    status: 'legacy',
  });
}

function unsupported(params) {
  return baseClassification({
    ...params,
    kind: 'unsupported',
    format: 'unknown',
    status: 'unknown',
  });
}

/**
 * Classify artifact bytes without reading from File/Blob and without touching
 * DOM APIs.
 *
 * @param {Uint8Array} bytes
 * @param {{ name?: string }} [options]
 */
export async function classifyArtifactBytes(bytes, options = {}) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Artifact classifier input must be Uint8Array');
  }

  const name = String(options.name || 'unnamed');
  const lowerName = name.toLowerCase();
  const fileSha256Hex = toHex(await digestSha256(bytes));
  const params = { name, fileSha256Hex };

  if (lowerName.endsWith('.qvmanifest.json')) {
    return legacyManifest(params);
  }

  if (lowerName.endsWith('.qcont') || startsWithAscii(bytes, QCONT_MAGIC)) {
    const qcontParams = { ...params, kind: 'qcont-shard', format: 'qcont' };
    try {
      const parsed = await parseLifecycleShard(bytes, { strict: true });
      return recognized(qcontParams, {
        archiveId: parsed.archiveState?.archiveId || '',
        stateId: parsed.stateId || '',
        cohortId: parsed.cohortId || '',
        shardIndex: parsed.shardIndex,
        lifecycleBundleDigestHex: parsed.lifecycleBundleDigestHex || '',
      });
    } catch (error) {
      return malformed(qcontParams, error);
    }
  }

  if (startsWithAscii(bytes, 'PQPK') || lowerName.endsWith('.pqpk')) {
    const pqpkParams = { ...params, kind: 'pqpk', format: 'pqpk' };
    try {
      const parsed = unpackPqpk(bytes);
      return recognized(pqpkParams, {
        suite: parsed.suite || '',
        suiteDisplay: parsed.suiteDisplay || parsed.suite || '',
        publicKeySha256Hex: toHex(await digestSha256(parsed.keyBytes)),
      });
    } catch (error) {
      return malformed(pqpkParams, error);
    }
  }

  if (startsWithAscii(bytes, 'PQSG') || lowerName.endsWith('.qsig')) {
    const qsigParams = { ...params, kind: 'signature', format: 'qsig' };
    try {
      const parsed = unpackQsig(bytes);
      return recognized(qsigParams, {
        payloadDigestHex: toHex(parsed.payloadDigest),
        suite: parsed.suite || '',
        suiteDisplay: parsed.suiteDisplay || parsed.suite || '',
        context: parsed.ctx || '',
      });
    } catch (error) {
      return malformed(qsigParams, error);
    }
  }

  if (lowerName.endsWith('.ots')) {
    const otsParams = { ...params, kind: 'ots-proof', format: 'ots' };
    try {
      const parsed = parseOpenTimestampProof(bytes, { name });
      return recognized(otsParams, {
        stampedDigestHex: parsed.stampedDigestHex || '',
        appearsComplete: parsed.appearsComplete === true,
        completeProof: parsed.completeProof === true,
      });
    } catch (error) {
      return malformed(otsParams, error);
    }
  }

  if (isSupportedStellarSignatureDocumentBytes(bytes)) {
    return recognized(
      { ...params, kind: 'signature', format: 'stellar-sig' },
      { signatureFormat: 'stellar-sig' }
    );
  }

  try {
    const parsed = await parseLifecycleBundleBytes(bytes);
    return recognized(
      { ...params, kind: 'lifecycle-bundle', format: 'lifecycle-bundle-json' },
      {
        digestHex: parsed.digest.value,
        archiveStateDigestHex: parsed.lifecycleBundle?.archiveStateDigest?.value || '',
        currentCohortBindingDigestHex: parsed.lifecycleBundle?.currentCohortBindingDigest?.value || '',
      },
      { canonicalBytes: parsed.bytes }
    );
  } catch (error) {
    if (lowerName.endsWith('.lifecycle-bundle.json')) {
      return malformed(
        { ...params, kind: 'lifecycle-bundle', format: 'lifecycle-bundle-json' },
        error
      );
    }
  }

  try {
    const parsed = parseArchiveStateDescriptorBytes(bytes);
    return recognized(
      { ...params, kind: 'archive-state', format: 'archive-state-json' },
      {
        archiveId: parsed.archiveState?.archiveId || '',
        stateDigestHex: parsed.digest.value,
        authPolicyLevel: parsed.archiveState?.authPolicyCommitment?.level || '',
      },
      { canonicalBytes: parsed.bytes }
    );
  } catch (error) {
    if (lowerName.endsWith('.archive-state.json')) {
      return malformed(
        { ...params, kind: 'archive-state', format: 'archive-state-json' },
        error
      );
    }
  }

  try {
    const parsed = parseTransitionRecordBytes(bytes);
    return recognized(
      { ...params, kind: 'transition-record', format: 'transition-record-json' },
      {
        digestHex: parsed.digest.value,
        fromCohortId: parsed.transitionRecord?.fromCohortId || '',
        toCohortId: parsed.transitionRecord?.toCohortId || '',
      },
      { canonicalBytes: parsed.bytes }
    );
  } catch (error) {
    if (lowerName.endsWith('.transition-record.json')) {
      return malformed(
        { ...params, kind: 'transition-record', format: 'transition-record-json' },
        error
      );
    }
  }

  try {
    const parsed = parseSourceEvidenceBytes(bytes);
    return recognized(
      { ...params, kind: 'source-evidence', format: 'source-evidence-json' },
      {
        digestHex: parsed.digest.value,
        relationType: parsed.sourceEvidence?.relationType || '',
      },
      { canonicalBytes: parsed.bytes }
    );
  } catch (error) {
    if (lowerName.endsWith('.source-evidence.json')) {
      return malformed(
        { ...params, kind: 'source-evidence', format: 'source-evidence-json' },
        error
      );
    }
  }

  return unsupported(params);
}
