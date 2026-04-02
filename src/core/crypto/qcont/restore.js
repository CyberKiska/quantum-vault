/**
 * QCONT restore: successor lifecycle shards only (QVqcont-7).
 *
 * Restore remains fail-closed: ambiguous archive/state/cohort or embedded
 * lifecycle-bundle selection requires explicit operator input, and this module
 * will not auto-select a winner by timestamps, attachment counts, or lexical order.
 */
import { sha3_512 } from '@noble/hashes/sha3.js';
import { hashBytes } from '../index.js';
import { asciiBytes, base64ToBytes, bytesEqual, digestSha256, toHex } from '../bytes.js';
import {
  resolveOpenTimestampTarget,
} from '../auth/opentimestamps.js';
import { computeDetachedSignatureIdentityDigestHex } from '../auth/signature-identity.js';
import { isSupportedStellarSignatureDocumentBytes, verifyStellarSigAgainstBytes } from '../auth/stellar-sig.js';
import { normalizePqPublicKeyPins, packPqpk, verifyQsigAgainstBytes } from '../auth/qsig.js';
import {
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeSourceEvidence,
  decodeLifecycleSignatureBytes,
  inspectLifecycleTransitions,
  LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS,
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
  verifyLifecycleSignatureEntry,
} from '../lifecycle/artifacts.js';
import { validateContainerPolicyMetadata } from '../policy.js';
import { resolveErasureRuntime } from '../erasure-runtime.js';
import {
  mergeLifecycleShardIntoCohortGroups,
  normalizeHexString,
  reconstructLifecycleCohortMaterial,
} from './lifecycle-cohort-shared.js';

const MAGIC_QSIG = asciiBytes('PQSG');
const PIN_MISMATCH_WARNING_PREFIX = 'Pinned PQ signer key did not match';
const KEY_COMMITMENT_MAX_LEN = 32;

function ensurePositiveInteger(value, field, min = 1) {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function ensureEqual(actual, expected, field) {
  if (actual !== expected) {
    throw new Error(`${field} mismatch (expected ${expected}, got ${actual})`);
  }
}

function dedupeWarnings(warnings) {
  return [...new Set((Array.isArray(warnings) ? warnings : []).filter(Boolean))];
}

function findLifecycleSignatureFamilyDescriptor(family) {
  return LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS.find((descriptor) => descriptor.family === family) || null;
}

function isSuccessorParsedShard(shard) {
  return (
    shard?.archiveStateBytes instanceof Uint8Array &&
    shard?.cohortBindingBytes instanceof Uint8Array &&
    shard?.lifecycleBundleBytes instanceof Uint8Array
  );
}

function detectExternalLifecycleSignatureType(signature) {
  const bytes = signature?.bytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return 'unknown';
  if (bytes.length >= MAGIC_QSIG.length && bytesEqual(bytes.subarray(0, MAGIC_QSIG.length), MAGIC_QSIG)) {
    return 'qsig';
  }
  return isSupportedStellarSignatureDocumentBytes(bytes) ? 'stellar-sig' : 'unknown';
}

function buildLifecycleVerificationFailureResult({
  family = 'archive-approval',
  source = 'bundle',
  format = 'unknown',
  suite = format === 'qsig' ? 'unknown' : 'ed25519',
  name = 'signature',
  artifactId = name,
  error = 'Verification failed',
  warnings = [],
  targetType = '',
  targetRef = '',
}) {
  return {
    ok: false,
    selfSigned: false,
    family,
    source,
    format,
    suite,
    type: format === 'stellar-sig' ? 'sig' : format,
    bundlePinned: false,
    userPinned: false,
    signerPinned: false,
    strongPq: false,
    name,
    artifactId,
    error,
    warnings: dedupeWarnings(warnings),
    targetType,
    targetRef,
  };
}

function buildSelfSignedIgnoredWarning(result) {
  const name = String(result?.name || result?.artifactId || 'detached PQ signature').trim();
  return `${name}: detached PQ signature verified only with the embedded signer key and was ignored for trust/policy because no bundled or user-pinned signer key verified.`;
}

function buildPinnedPqSignerMismatchFailure(verified, mismatchWarning) {
  return {
    ...(verified || {}),
    ok: false,
    selfSigned: false,
    bundlePinned: false,
    userPinned: false,
    signerPinned: false,
    type: 'qsig',
    format: 'qsig',
    error: mismatchWarning,
    warnings: dedupeWarnings([
      ...((verified?.warnings || []).filter((warning) => !String(warning).startsWith(PIN_MISMATCH_WARNING_PREFIX))),
    ]),
  };
}

function safeVerifySuccessorQsigAgainstBytes(options) {
  try {
    return verifyQsigAgainstBytes(options);
  } catch (error) {
    return buildLifecycleVerificationFailureResult({
      format: 'qsig',
      suite: 'unknown',
      error: error?.message || String(error),
    });
  }
}

function verifySuccessorQsigWithPinnedKeys({
  messageBytes,
  qsigBytes,
  bundlePqPublicKeyFileBytes = null,
  normalizedPinnedPqPins = [],
  authoritativeBundlePqPublicKey = false,
}) {
  if (normalizedPinnedPqPins.length === 0) {
    return safeVerifySuccessorQsigAgainstBytes({
      messageBytes,
      qsigBytes,
      bundlePqPublicKeyFileBytes,
      pinnedPqPublicKeyFileBytes: null,
      authoritativeBundlePqPublicKey,
    });
  }

  if (normalizedPinnedPqPins.length === 1) {
    const verified = safeVerifySuccessorQsigAgainstBytes({
      messageBytes,
      qsigBytes,
      bundlePqPublicKeyFileBytes,
      pinnedPqPublicKeyFileBytes: normalizedPinnedPqPins[0].bytes,
      authoritativeBundlePqPublicKey,
    });
    if (!verified.ok || verified.userPinned === true) {
      return verified;
    }
    const mismatchWarning = bundlePqPublicKeyFileBytes instanceof Uint8Array
      ? 'Provided PQ signer keys did not match the bundled signer key.'
      : 'Provided PQ signer keys did not match this verified signature.';
    return buildPinnedPqSignerMismatchFailure({
      ...verified,
      warnings: dedupeWarnings([
        ...(verified.warnings || []).filter((warning) => !String(warning).startsWith(PIN_MISMATCH_WARNING_PREFIX)),
      ]),
    }, mismatchWarning);
  }

  let baseline = null;
  let firstOk = null;
  const matches = [];
  const retainedWarnings = [];

  for (const candidatePin of normalizedPinnedPqPins) {
    const result = safeVerifySuccessorQsigAgainstBytes({
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
    return buildLifecycleVerificationFailureResult({
      format: 'qsig',
      suite: 'unknown',
      error: 'Multiple provided .pqpk files match this detached PQ signature. Keep only one exact PQ pin per signer.',
      warnings: dedupeWarnings(retainedWarnings),
    });
  }

  if (matches.length === 1) {
    return {
      ...matches[0],
      warnings: dedupeWarnings(matches[0].warnings || []),
    };
  }

  const verified = firstOk || safeVerifySuccessorQsigAgainstBytes({
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

  return buildPinnedPqSignerMismatchFailure({
    ...verified,
    warnings: dedupeWarnings([
      ...retainedWarnings,
      ...(verified.warnings || []).filter((warning) => !String(warning).startsWith(PIN_MISMATCH_WARNING_PREFIX)),
    ]),
  }, mismatchWarning);
}

function collectSuccessorCandidateCohorts(shards) {
  const byIdentity = new Map();
  for (const shard of shards) {
    mergeLifecycleShardIntoCohortGroups(byIdentity, shard, {
      groupLabel: 'candidate set',
      missingIdentityMessage: 'Successor shard is missing archive/state/cohort identity',
    });
  }
  return [...byIdentity.values()];
}

function analyzeSameStateSuccessorCohorts(candidates) {
  const byState = new Map();
  for (const candidate of candidates) {
    const key = `${candidate.archiveId}:${candidate.stateId}`;
    if (!byState.has(key)) {
      byState.set(key, {
        archiveId: candidate.archiveId,
        stateId: candidate.stateId,
        candidates: [],
      });
    }
    byState.get(key).candidates.push(candidate);
  }

  const states = [...byState.values()].map((entry) => ({
    archiveId: entry.archiveId,
    stateId: entry.stateId,
    candidates: entry.candidates,
    cohortIds: [...new Set(entry.candidates.map((candidate) => candidate.cohortId))].sort(),
    mixedLifecycleBundleVariantCohorts: entry.candidates
      .filter((candidate) => candidate.embeddedLifecycleBundles.size > 1)
      .map((candidate) => candidate.cohortId)
      .sort(),
  })).map((entry) => ({
    ...entry,
    forkDetected: entry.cohortIds.length > 1,
  }));

  return {
    states,
    byState: new Map(states.map((entry) => [`${entry.archiveId}:${entry.stateId}`, entry])),
  };
}

function buildSameStateForkRejectionMessage(stateAnalysis) {
  return [
    `Multiple valid cohorts were detected for archive ${stateAnalysis.archiveId} state ${stateAnalysis.stateId}.`,
    `Cohort IDs: ${stateAnalysis.cohortIds.join(', ')}.`,
    'Restore rejects mixed same-state cohorts; provide shards from exactly one internally consistent cohort.',
    'Quantum Vault will not auto-select a winner by timestamp, attachment count, or lexical identifier order.',
  ].join(' ');
}

function collectSortedUniqueLifecycleBundleDigests(shards) {
  return [...new Set(
    (Array.isArray(shards) ? shards : [])
      .map((item) => normalizeHexString(item?.lifecycleBundleDigestHex))
      .filter(Boolean)
  )].sort();
}

function buildMixedLifecycleBundleVariantWarning(embeddedLifecycleBundleDigestsUsed, selectedLifecycleBundleDigestHex) {
  if (!Array.isArray(embeddedLifecycleBundleDigestsUsed) || embeddedLifecycleBundleDigestsUsed.length <= 1) {
    return '';
  }
  return `Payload reconstruction used shards carrying multiple embedded lifecycle-bundle digests (${embeddedLifecycleBundleDigestsUsed.join(', ')}); authenticity and policy were evaluated against selected lifecycle bundle ${selectedLifecycleBundleDigestHex}.`;
}

function buildSuccessorTransitionReport(lifecycleBundle, signatureResults = []) {
  const inspection = inspectLifecycleTransitions(lifecycleBundle);
  const maintenanceByDigest = new Map();

  for (const result of Array.isArray(signatureResults) ? signatureResults : []) {
    if (String(result?.family || '') !== 'maintenance') continue;
    const digestHex = normalizeHexString(result?.targetDigest?.value);
    if (!digestHex) continue;
    if (!maintenanceByDigest.has(digestHex)) {
      maintenanceByDigest.set(digestHex, {
        signatureIds: [],
        verifiedSignatureIds: [],
        purposeLabels: [],
      });
    }
    const entry = maintenanceByDigest.get(digestHex);
    const signatureId = result?.artifactId || result?.name || '';
    if (signatureId) {
      entry.signatureIds.push(signatureId);
      if (result?.ok === true) {
        entry.verifiedSignatureIds.push(signatureId);
      }
    }
    entry.purposeLabels.push(...(Array.isArray(result?.maintenancePurposeLabels) ? result.maintenancePurposeLabels : []));
  }

  const records = inspection.records.map((record) => {
    const maintenance = maintenanceByDigest.get(record.digest.value) || {
      signatureIds: [],
      verifiedSignatureIds: [],
      purposeLabels: [],
    };
    return {
      index: record.index,
      digestHex: record.digest.value,
      transitionType: record.transitionRecord.transitionType,
      archiveId: record.transitionRecord.archiveId,
      fromStateId: record.transitionRecord.fromStateId,
      toStateId: record.transitionRecord.toStateId,
      fromCohortId: record.transitionRecord.fromCohortId,
      toCohortId: record.transitionRecord.toCohortId,
      fromCohortBindingDigest: record.transitionRecord.fromCohortBindingDigest,
      toCohortBindingDigest: record.transitionRecord.toCohortBindingDigest,
      maintenanceSignatureIds: [...new Set(maintenance.signatureIds)].sort(),
      verifiedMaintenanceSignatureIds: [...new Set(maintenance.verifiedSignatureIds)].sort(),
      maintenanceSignatureCount: [...new Set(maintenance.signatureIds)].length,
      verifiedMaintenanceSignatureCount: [...new Set(maintenance.verifiedSignatureIds)].length,
      maintenancePurposeLabels: [...new Set([
        ...(Array.isArray(record.maintenancePurposeLabels) ? record.maintenancePurposeLabels : []),
        ...maintenance.purposeLabels,
      ])].sort(),
    };
  });

  return {
    present: inspection.present,
    chainValid: inspection.chainValid,
    validationScope: inspection.validationScope,
    count: records.length,
    signed: records.some((record) => record.maintenanceSignatureCount > 0),
    maintenanceSignatureVerified: records.some((record) => record.verifiedMaintenanceSignatureCount > 0),
    maintenancePurposeLabels: [...new Set(records.flatMap((record) => record.maintenancePurposeLabels))].sort(),
    currentArchiveId: inspection.archiveId,
    currentStateId: inspection.stateId,
    currentCohortId: inspection.currentCohortId,
    currentCohortBindingDigestHex: inspection.currentCohortBindingDigest.value,
    records,
  };
}

function buildSuccessorSourceEvidenceReport(lifecycleBundle, signatureResults = []) {
  const sourceEvidenceByDigest = new Map();

  for (const result of Array.isArray(signatureResults) ? signatureResults : []) {
    if (String(result?.family || '') !== 'source-evidence') continue;
    const digestHex = normalizeHexString(result?.targetDigest?.value);
    if (!digestHex) continue;
    if (!sourceEvidenceByDigest.has(digestHex)) {
      sourceEvidenceByDigest.set(digestHex, {
        signatureIds: [],
        verifiedSignatureIds: [],
      });
    }
    const entry = sourceEvidenceByDigest.get(digestHex);
    const signatureId = result?.artifactId || result?.name || '';
    if (signatureId) {
      entry.signatureIds.push(signatureId);
      if (result?.ok === true) {
        entry.verifiedSignatureIds.push(signatureId);
      }
    }
  }

  const records = (Array.isArray(lifecycleBundle?.sourceEvidence) ? lifecycleBundle.sourceEvidence : []).map((sourceEvidence, index) => {
    const canonicalSourceEvidence = canonicalizeSourceEvidence(sourceEvidence);
    const digestHex = canonicalSourceEvidence.digest.value;
    const signatures = sourceEvidenceByDigest.get(digestHex) || {
      signatureIds: [],
      verifiedSignatureIds: [],
    };
    const signatureIds = [...new Set(signatures.signatureIds)].sort();
    const verifiedSignatureIds = [...new Set(signatures.verifiedSignatureIds)].sort();
    const externalSourceSignatureRefs = Array.isArray(sourceEvidence.externalSourceSignatureRefs)
      ? [...sourceEvidence.externalSourceSignatureRefs]
      : [];
    const descriptiveFieldNames = typeof sourceEvidence.mediaType === 'string' && sourceEvidence.mediaType.length > 0
      ? ['mediaType']
      : [];

    return {
      index,
      digestHex,
      targetRef: `source-evidence:sha3-512:${digestHex}`,
      relationType: sourceEvidence.relationType,
      sourceObjectType: sourceEvidence.sourceObjectType,
      sourceDigests: sourceEvidence.sourceDigests.map((digest) => ({ ...digest })),
      externalSourceSignatureRefs,
      externalSourceSignatureRefCount: externalSourceSignatureRefs.length,
      descriptiveFieldNames,
      mediaType: sourceEvidence.mediaType || null,
      sourceEvidenceSignatureIds: signatureIds,
      verifiedSourceEvidenceSignatureIds: verifiedSignatureIds,
      sourceEvidenceSignatureCount: signatureIds.length,
      verifiedSourceEvidenceSignatureCount: verifiedSignatureIds.length,
    };
  });

  return {
    present: records.length > 0,
    count: records.length,
    signed: records.some((record) => record.sourceEvidenceSignatureCount > 0),
    signatureVerified: records.some((record) => record.verifiedSourceEvidenceSignatureCount > 0),
    sourceEvidenceSignatureCount: records.reduce((sum, record) => sum + record.sourceEvidenceSignatureCount, 0),
    verifiedSourceEvidenceSignatureCount: records.reduce((sum, record) => sum + record.verifiedSourceEvidenceSignatureCount, 0),
    externalSourceSignatureRefCount: records.reduce((sum, record) => sum + record.externalSourceSignatureRefCount, 0),
    externalSourceSignatureRefsPresent: records.some((record) => record.externalSourceSignatureRefCount > 0),
    descriptiveFieldNames: [...new Set(records.flatMap((record) => record.descriptiveFieldNames))].sort(),
    records,
  };
}

function buildLifecycleBundleVerifierInputs(publicKey) {
  if (!publicKey) {
    return {
      bundlePqPublicKeyFileBytes: null,
      bundleSigner: '',
      authoritativeBundlePqPublicKey: false,
    };
  }
  if (publicKey.encoding === 'base64') {
    return {
      bundlePqPublicKeyFileBytes: packPqpk({
        suite: publicKey.suite,
        publicKeyBytes: base64ToBytes(publicKey.value),
      }),
      bundleSigner: '',
      authoritativeBundlePqPublicKey: true,
    };
  }
  if (publicKey.encoding === 'stellar-address') {
    return {
      bundlePqPublicKeyFileBytes: null,
      bundleSigner: String(publicKey.value || '').trim(),
      authoritativeBundlePqPublicKey: false,
    };
  }
  throw new Error(`Unsupported lifecycle bundled key encoding: ${publicKey.encoding}`);
}

async function attachLifecycleSignatureDigests(result) {
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

function buildLifecycleVerificationCounts(results) {
  const counts = {
    validTotal: 0,
    validStrongPq: 0,
    pinnedValidTotal: 0,
    bundlePinnedValidTotal: 0,
    userPinnedValidTotal: 0,
    validArchiveApproval: 0,
    validArchiveApprovalStrongPq: 0,
    archiveApprovalPinnedValidTotal: 0,
    archiveApprovalBundlePinnedValidTotal: 0,
    archiveApprovalUserPinnedValidTotal: 0,
    validMaintenance: 0,
    validSourceEvidence: 0,
  };
  const duplicateWarnings = [];
  const selfSignedWarnings = [];
  const uniqueValid = new Map();

  for (const result of results) {
    result.countedForPolicy = false;
    if (result?.selfSigned === true) {
      selfSignedWarnings.push(buildSelfSignedIgnoredWarning(result));
      continue;
    }
    if (!result?.ok || typeof result.proofIdentityDigestHex !== 'string') continue;
    const family = String(result.family || 'archive-approval');
    const dedupeKey = `${family}:${result.format}:${result.proofIdentityDigestHex}`;
    const current = uniqueValid.get(dedupeKey);
    if (!current) {
      uniqueValid.set(dedupeKey, {
        family,
        strongPq: result.strongPq === true,
        signerPinned: result.signerPinned === true,
        bundlePinned: result.bundlePinned === true,
        userPinned: result.userPinned === true,
        names: [result.name || result.artifactId || dedupeKey],
      });
      if (family === 'archive-approval') {
        result.countedForPolicy = true;
      }
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
    if (entry.bundlePinned) counts.bundlePinnedValidTotal += 1;
    if (entry.userPinned) counts.userPinnedValidTotal += 1;
    if (entry.family === 'archive-approval') {
      counts.validArchiveApproval += 1;
      if (entry.strongPq) counts.validArchiveApprovalStrongPq += 1;
      if (entry.signerPinned) counts.archiveApprovalPinnedValidTotal += 1;
      if (entry.bundlePinned) counts.archiveApprovalBundlePinnedValidTotal += 1;
      if (entry.userPinned) counts.archiveApprovalUserPinnedValidTotal += 1;
    } else if (entry.family === 'maintenance') {
      counts.validMaintenance += 1;
    } else if (entry.family === 'source-evidence') {
      counts.validSourceEvidence += 1;
    }
    if (entry.names.length > 1) {
      duplicateWarnings.push(`Duplicate detached ${entry.family} signature ignored for policy/state counting: ${entry.names.join(', ')}`);
    }
  }

  return { counts, duplicateWarnings, selfSignedWarnings };
}

function evaluateSuccessorArchivePolicy(authPolicy, verification) {
  const counts = verification?.counts || {
    validArchiveApproval: 0,
    validArchiveApprovalStrongPq: 0,
  };
  const minValidSignatures = ensurePositiveInteger(
    Number(authPolicy.minValidSignatures),
    'authPolicy.minValidSignatures',
    1
  );
  const level = String(authPolicy.level || '');

  if (level === 'integrity-only') {
    return {
      level,
      minValidSignatures,
      satisfied: true,
      reason: 'integrity-only policy does not require signatures',
    };
  }

  if (level === 'any-signature') {
    const satisfied = counts.validArchiveApproval >= minValidSignatures;
    return {
      level,
      minValidSignatures,
      satisfied,
      reason: satisfied
        ? 'required archive-approval signature count satisfied'
        : 'no verified archive-approval signature satisfies archive policy',
    };
  }

  if (level === 'strong-pq-signature') {
    const satisfied = (
      counts.validArchiveApproval >= minValidSignatures &&
      counts.validArchiveApprovalStrongPq >= 1
    );
    return {
      level,
      minValidSignatures,
      satisfied,
      reason: satisfied
        ? 'required strong PQ archive-approval signature present'
        : 'no verified strong PQ archive-approval signature satisfies archive policy',
    };
  }

  throw new Error(`Unsupported authPolicy.level: ${authPolicy.level}`);
}

async function verifySuccessorBundledSignature({
  bundle,
  signature,
  family,
  normalizedPinnedPqPins,
  expectedEd25519Signer,
}) {
  const name = signature?.id || `${family}-signature`;
  const descriptor = findLifecycleSignatureFamilyDescriptor(family);
  let decodedSignatureBytes = null;
  try {
    const baseline = await verifyLifecycleSignatureEntry(bundle, signature, {
      expectedEd25519Signer,
      expectedFamily: descriptor?.family || family,
      expectedField: descriptor?.field || '',
    });
    const verifierInputs = buildLifecycleBundleVerifierInputs(baseline.publicKey);
    const verification = signature.format === 'qsig'
      ? verifySuccessorQsigWithPinnedKeys({
          messageBytes: baseline.targetBytes,
          qsigBytes: baseline.signatureBytes,
          bundlePqPublicKeyFileBytes: verifierInputs.bundlePqPublicKeyFileBytes,
          normalizedPinnedPqPins,
          authoritativeBundlePqPublicKey: verifierInputs.authoritativeBundlePqPublicKey,
        })
      : await verifyStellarSigAgainstBytes({
          messageBytes: baseline.targetBytes,
          sigJsonBytes: baseline.signatureBytes,
          bundleSigner: verifierInputs.bundleSigner,
          expectedSigner: expectedEd25519Signer,
        });

    return attachLifecycleSignatureDigests({
      ...verification,
      family,
      source: 'bundle',
      name,
      artifactId: signature?.id || name,
      targetType: baseline.targetType,
      targetRef: baseline.targetRef,
      targetDigest: baseline.targetDigest,
      transitionIndex: Number.isInteger(baseline.transitionIndex) ? baseline.transitionIndex : null,
      maintenancePurposeLabels: Array.isArray(baseline.maintenancePurposeLabels)
        ? [...baseline.maintenancePurposeLabels]
        : [],
      signatureBytes: baseline.signatureBytes,
      publicKeyRef: signature?.publicKeyRef || '',
    });
  } catch (error) {
    try {
      decodedSignatureBytes = decodeLifecycleSignatureBytes(signature, 'detached signature');
    } catch {
      decodedSignatureBytes = null;
    }
    return attachLifecycleSignatureDigests({
      ...buildLifecycleVerificationFailureResult({
        family,
        source: 'bundle',
        format: signature?.format || 'unknown',
        suite: signature?.suite || 'unknown',
        name,
        artifactId: signature?.id || name,
        error: error?.message || String(error),
        targetType: signature?.targetType || '',
        targetRef: signature?.targetRef || '',
      }),
      signatureBytes: decodedSignatureBytes,
      maintenancePurposeLabels: [],
      publicKeyRef: signature?.publicKeyRef || '',
    });
  }
}

async function verifySuccessorExternalSignature({
  archiveStateBytes,
  stateId,
  signature,
  normalizedPinnedPqPins,
  expectedEd25519Signer,
}) {
  const format = detectExternalLifecycleSignatureType(signature);
  const name = signature?.name || 'external-signature';
  if (format === 'unknown') {
    return buildLifecycleVerificationFailureResult({
      family: 'archive-approval',
      source: 'external',
      format: 'unknown',
      suite: 'unknown',
      name,
      artifactId: name,
      error: 'Unsupported signature format',
      targetType: 'archive-state',
      targetRef: `state:${stateId}`,
    });
  }

  const verification = format === 'qsig'
    ? verifySuccessorQsigWithPinnedKeys({
        messageBytes: archiveStateBytes,
        qsigBytes: signature.bytes,
        normalizedPinnedPqPins,
      })
    : await verifyStellarSigAgainstBytes({
        messageBytes: archiveStateBytes,
        sigJsonBytes: signature.bytes,
        expectedSigner: expectedEd25519Signer,
      });

  return attachLifecycleSignatureDigests({
    ...verification,
    family: 'archive-approval',
    source: 'external',
    name,
    artifactId: name,
    targetType: 'archive-state',
    targetRef: `state:${stateId}`,
    targetDigest: { alg: 'SHA3-512', value: stateId },
    maintenancePurposeLabels: [],
    signatureBytes: signature.bytes,
  });
}

/**
 * Presentation-only: when multiple OTS evidence rows describe the same stamped digest
 * (or share a fallback key), keep a single row for UI/reporting. Verification and
 * archive policy are computed before this step from full signature results; this
 * function MUST NOT influence policy outcomes.
 */
function dedupePresentationOnlyTimestampEvidence(entries) {
  const bestByDigest = new Map();
  for (const entry of entries) {
    const key = String(entry?.stampedDigestHex || entry?.targetRef || entry?.id || '').trim();
    if (!key) continue;
    const current = bestByDigest.get(key);
    const score = [
      entry?.completeProof === true || entry?.apparentlyComplete === true ? 1 : 0,
      String(entry?.linkLabel || '').startsWith('External ') ? 0 : 1,
    ];
    const currentScore = current
      ? [
          current?.completeProof === true || current?.apparentlyComplete === true ? 1 : 0,
          String(current?.linkLabel || '').startsWith('External ') ? 0 : 1,
        ]
      : [-1, -1];
    const replace = (
      score[0] > currentScore[0] ||
      (score[0] === currentScore[0] && score[1] > currentScore[1])
    );
    if (!current || replace) {
      bestByDigest.set(key, entry);
    }
  }
  return [...bestByDigest.values()];
}

async function inspectSuccessorTimestampEvidence({
  bundle,
  externalTimestamps = [],
  signatureResults = [],
}) {
  const signatureById = new Map(signatureResults
    .filter((entry) => entry?.source === 'bundle')
    .map((entry) => [entry.artifactId || entry.name, entry]));
  const warnings = [];
  const signatureArtifacts = signatureResults
    .filter((entry) => entry?.signatureBytes instanceof Uint8Array)
    .map((entry) => ({
      id: entry.artifactId || entry.name,
      name: entry.name,
      source: entry.source,
      ok: entry.ok === true,
      bytes: entry.signatureBytes,
      otsStampedDigestHex: entry.otsStampedDigestHex,
      targetRef: entry.targetRef,
    }));

  const embeddedEvidence = [];
  for (const timestamp of bundle?.attachments?.timestamps || []) {
    try {
      if (timestamp?.proofEncoding !== 'base64') {
        throw new Error(`Unsupported OpenTimestamps proof encoding: ${timestamp?.proofEncoding ?? 'unknown'}`);
      }
      const signature = signatureById.get(timestamp.targetRef);
      if (!signature) {
        throw new Error(`OpenTimestamps targetRef is unknown: ${timestamp?.targetRef ?? 'unknown'}`);
      }
      const resolved = await resolveOpenTimestampTarget({
        timestampBytes: base64ToBytes(timestamp.proof),
        timestampName: timestamp.id,
        signatures: [{
          id: signature.artifactId || signature.name,
          name: signature.name,
          source: signature.source,
          ok: signature.ok === true,
          bytes: signature.signatureBytes,
          otsStampedDigestHex: signature.otsStampedDigestHex,
        }],
      });
      embeddedEvidence.push({
        id: timestamp.id,
        targetRef: signature.targetRef || timestamp.targetRef,
        targetName: signature.name || signature.artifactId || timestamp.targetRef,
        targetSource: resolved.targetSource,
        targetVerified: resolved.targetVerified,
        linked: true,
        apparentlyComplete: resolved.apparentlyComplete,
        completeProof: resolved.completeProof,
        stampedDigestHex: resolved.stampedDigestHex,
        linkLabel: 'OTS evidence linked to signature',
        completionLabel: resolved.apparentlyComplete ? 'OTS proof appears complete' : 'OTS proof appears incomplete',
      });
    } catch (error) {
      warnings.push(`OpenTimestamps evidence ${timestamp?.id || 'unknown'} did not link cleanly and was ignored: ${error?.message || error}`);
    }
  }

  const externalEvidence = [];
  for (let index = 0; index < (Array.isArray(externalTimestamps) ? externalTimestamps.length : 0); index += 1) {
    const timestamp = externalTimestamps[index];
    const timestampName = timestamp?.name || `timestamp-${index + 1}`;
    try {
      if (!(timestamp?.bytes instanceof Uint8Array) || timestamp.bytes.length === 0) {
        throw new Error(`Invalid OpenTimestamps proof: ${timestampName}`);
      }
      const resolved = await resolveOpenTimestampTarget({
        timestampBytes: timestamp.bytes,
        timestampName,
        signatures: signatureArtifacts,
      });
      const matchingSignature = signatureResults.find((entry) => (
        (entry.artifactId || entry.name) === resolved.targetRef
      )) || null;
      externalEvidence.push({
        id: timestampName,
        targetRef: matchingSignature?.targetRef || resolved.targetRef,
        targetName: resolved.targetName,
        targetSource: resolved.targetSource,
        targetVerified: resolved.targetVerified,
        linked: true,
        apparentlyComplete: resolved.apparentlyComplete,
        completeProof: resolved.completeProof,
        stampedDigestHex: resolved.stampedDigestHex,
        linkLabel: 'External OTS evidence linked to signature',
        completionLabel: resolved.apparentlyComplete ? 'OTS proof appears complete' : 'OTS proof appears incomplete',
      });
    } catch (error) {
      warnings.push(`OpenTimestamps evidence ${timestampName} did not link cleanly and was ignored: ${error?.message || error}`);
    }
  }

  return {
    evidence: dedupePresentationOnlyTimestampEvidence([...embeddedEvidence, ...externalEvidence]),
    warnings: dedupeWarnings(warnings),
  };
}

async function evaluateSuccessorAuthenticity(candidate, lifecycleBundle, verificationOptions = {}) {
  const {
    pins: normalizedPinnedPqPins,
    warnings: pinNormalizationWarnings,
  } = normalizePqPublicKeyPins({
    pinnedPqPublicKeyFileBytes: verificationOptions.pinnedPqPublicKeyFileBytes ?? verificationOptions.pqPublicKeyFileBytes,
    pinnedPqPublicKeyFileBytesList: verificationOptions.pinnedPqPublicKeyFileBytesList,
    invalidBehavior: 'warn',
    invalidLabel: 'Pinned PQ signer key',
  });
  const expectedEd25519Signer = String(verificationOptions.expectedEd25519Signer || '').trim();
  const results = [];
  const familyEntries = LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS.map((descriptor) => [
    descriptor.family,
    lifecycleBundle?.attachments?.[descriptor.field] || [],
  ]);

  for (const [family, signatures] of familyEntries) {
    for (const signature of signatures) {
      results.push(await verifySuccessorBundledSignature({
        bundle: lifecycleBundle,
        signature,
        family,
        normalizedPinnedPqPins,
        expectedEd25519Signer,
      }));
    }
  }

  const externalSignatures = Array.isArray(verificationOptions.signatures) ? verificationOptions.signatures : [];
  for (const signature of externalSignatures) {
    results.push(await verifySuccessorExternalSignature({
      archiveStateBytes: candidate.archiveStateBytes,
      stateId: candidate.stateId,
      signature,
      normalizedPinnedPqPins,
      expectedEd25519Signer,
    }));
  }

  const { counts, duplicateWarnings, selfSignedWarnings } = buildLifecycleVerificationCounts(results);
  const warnings = [];
  for (const result of results) {
    for (const warning of result.warnings || []) warnings.push(warning);
  }
  warnings.push(...pinNormalizationWarnings);
  warnings.push(...selfSignedWarnings);
  warnings.push(...duplicateWarnings);

  const policy = evaluateSuccessorArchivePolicy(lifecycleBundle.authPolicy, { counts });
  const timestampInspection = await inspectSuccessorTimestampEvidence({
    bundle: lifecycleBundle,
    externalTimestamps: Array.isArray(verificationOptions.timestamps) ? verificationOptions.timestamps : [],
    signatureResults: results.filter((item) => item.signatureBytes instanceof Uint8Array),
  });
  warnings.push(...(timestampInspection.warnings || []));
  const transitionReport = buildSuccessorTransitionReport(lifecycleBundle, results);
  const sourceEvidenceReport = buildSuccessorSourceEvidenceReport(lifecycleBundle, results);

  const userPinProvided = (
    normalizedPinnedPqPins.length > 0 ||
    expectedEd25519Signer.length > 0
  );
  if (policy.level === 'integrity-only' && counts.validArchiveApproval === 0) {
    warnings.push('Archive policy is integrity-only; archive approval is not bound to a verified signer.');
  }
  const invalidSignatureCount = results.filter((item) => item.ok !== true).length;
  if (invalidSignatureCount > 0) {
    warnings.push(`${invalidSignatureCount} detached signature(s) did not verify and were ignored for archive policy evaluation.`);
  }

  return {
    verification: {
      provided: results.length > 0,
      results,
      warnings: dedupeWarnings(warnings),
      counts,
      signatureArtifacts: results
        .filter((result) => result.signatureBytes instanceof Uint8Array)
        .map((result) => ({
          id: result.artifactId || result.name,
          name: result.name,
          source: result.source,
          family: result.family,
          format: result.format,
          ok: result.ok === true,
          signatureBytes: result.signatureBytes,
          signatureContentDigestHex: result.signatureContentDigestHex,
          proofIdentityDigestHex: result.proofIdentityDigestHex,
          otsStampedDigestHex: result.otsStampedDigestHex,
          targetRef: result.targetRef,
          targetType: result.targetType,
          transitionIndex: Number.isInteger(result.transitionIndex) ? result.transitionIndex : null,
          maintenancePurposeLabels: Array.isArray(result.maintenancePurposeLabels)
            ? [...result.maintenancePurposeLabels]
            : [],
        })),
      status: {
        archiveApprovalSignatureVerified: counts.validArchiveApproval > 0,
        strongPqSignatureVerified: counts.validArchiveApprovalStrongPq > 0,
        signerPinned: counts.archiveApprovalPinnedValidTotal > 0,
        bundlePinned: counts.archiveApprovalBundlePinnedValidTotal > 0,
        userPinned: counts.archiveApprovalUserPinnedValidTotal > 0,
        userPinProvided,
        transitionRecordPresent: transitionReport.present,
        transitionChainValid: transitionReport.chainValid,
        sourceEvidencePresent: sourceEvidenceReport.present,
        maintenanceSignatureVerified: counts.validMaintenance > 0,
        sourceEvidenceSignatureVerified: counts.validSourceEvidence > 0,
        otsEvidenceLinked: timestampInspection.evidence.length > 0,
      },
    },
    policy,
    timestampEvidence: timestampInspection.evidence,
    transitionReport,
    sourceEvidenceReport,
    warnings: dedupeWarnings(warnings),
  };
}

async function resolveSuccessorArchiveContext(shards, verificationOptions = {}) {
  const rawCandidates = collectSuccessorCandidateCohorts(shards);
  if (rawCandidates.length === 0) {
    throw new Error('No valid successor archive/state/cohort candidate sets found');
  }

  let candidates = rawCandidates;
  let selectionSource = 'embedded';
  let uploadedArchiveState = null;
  let stateScopedAnalysis = analyzeSameStateSuccessorCohorts(candidates);
  const selectedArchiveId = normalizeHexString(verificationOptions.selectedArchiveId);
  const selectedStateId = normalizeHexString(verificationOptions.selectedStateId);
  const selectedCohortId = normalizeHexString(verificationOptions.selectedCohortId);

  const applyExplicitCandidateFilter = (field, selectedValue, label, sourceLabel) => {
    if (!selectedValue) return;
    candidates = candidates.filter((candidate) => normalizeHexString(candidate?.[field]) === selectedValue);
    if (candidates.length === 0) {
      throw new Error(`Selected ${label} ${selectedValue} does not match any successor shard candidate.`);
    }
    selectionSource = sourceLabel;
  };

  applyExplicitCandidateFilter('archiveId', selectedArchiveId, 'archiveId', 'selected-archive-id');

  if (verificationOptions.archiveStateBytes instanceof Uint8Array) {
    uploadedArchiveState = parseArchiveStateDescriptorBytes(verificationOptions.archiveStateBytes);
    candidates = candidates.filter((candidate) => bytesEqual(candidate.archiveStateBytes, uploadedArchiveState.bytes));
    if (candidates.length === 0) {
      throw new Error('Provided archive-state descriptor does not match any shard archive/state candidate');
    }
    selectionSource = 'uploaded-archive-state';
  }

  applyExplicitCandidateFilter('stateId', selectedStateId, 'stateId', 'selected-state-id');
  stateScopedAnalysis = analyzeSameStateSuccessorCohorts(candidates);
  applyExplicitCandidateFilter('cohortId', selectedCohortId, 'cohortId', 'selected-cohort-id');

  let lifecycleBundle;
  let lifecycleBundleBytes;
  let lifecycleBundleDigestHex;
  let lifecycleBundleSource = 'embedded';
  let candidate = null;

  if (verificationOptions.lifecycleBundleBytes instanceof Uint8Array) {
    const parsedBundle = await parseLifecycleBundleBytes(verificationOptions.lifecycleBundleBytes);
    const canonicalBundleArchiveState = canonicalizeArchiveStateDescriptor(parsedBundle.lifecycleBundle.archiveState);
    const canonicalBundleCohortBinding = canonicalizeCohortBinding(parsedBundle.lifecycleBundle.currentCohortBinding);
    if (uploadedArchiveState && !bytesEqual(uploadedArchiveState.bytes, canonicalBundleArchiveState.bytes)) {
      throw new Error('Provided archive-state descriptor does not match provided lifecycle bundle');
    }
    const matching = candidates.filter((item) => (
      item.archiveStateDigestHex === parsedBundle.lifecycleBundle.archiveStateDigest.value &&
      item.cohortBindingDigestHex === parsedBundle.lifecycleBundle.currentCohortBindingDigest.value &&
      bytesEqual(item.archiveStateBytes, canonicalBundleArchiveState.bytes) &&
      bytesEqual(item.cohortBindingBytes, canonicalBundleCohortBinding.bytes)
    ));
    if (matching.length === 0) {
      throw new Error('Provided lifecycle bundle does not match the selected archive/state/cohort candidate');
    }
    if (matching.length > 1) {
      throw new Error('Provided lifecycle bundle matches multiple successor shard candidates unexpectedly');
    }
    candidate = matching[0];
    lifecycleBundle = parsedBundle.lifecycleBundle;
    lifecycleBundleBytes = parsedBundle.bytes;
    lifecycleBundleDigestHex = parsedBundle.digest.value;
    lifecycleBundleSource = 'uploaded-lifecycle-bundle';
    selectionSource = 'uploaded-lifecycle-bundle';
  } else {
    if (candidates.length > 1) {
      if (stateScopedAnalysis.states.length === 1 && stateScopedAnalysis.states[0].forkDetected) {
        throw new Error(buildSameStateForkRejectionMessage(stateScopedAnalysis.states[0]));
      }
      if (uploadedArchiveState || selectedArchiveId || selectedStateId) {
        throw new Error(
          'Selected successor archive/state still matches multiple shard cohorts. Provide the lifecycle bundle or explicitly select one cohort.'
        );
      }
      throw new Error(
        'Multiple successor archive/state/cohort candidate sets were found. Provide the archive-state descriptor, lifecycle bundle, or explicit archive/state/cohort selection to disambiguate.'
      );
    }
    candidate = candidates[0];
    const embeddedDigests = [...candidate.embeddedLifecycleBundles.keys()].sort();
    const explicitDigest = normalizeHexString(verificationOptions.selectedLifecycleBundleDigestHex);
    if (explicitDigest) {
      const selected = candidate.embeddedLifecycleBundles.get(explicitDigest);
      if (!selected) {
        throw new Error(`Selected lifecycle-bundle digest ${explicitDigest} is not present in the chosen archive/state/cohort candidate`);
      }
      lifecycleBundle = selected.bundle;
      lifecycleBundleBytes = selected.bytes;
      lifecycleBundleDigestHex = selected.digestHex;
      lifecycleBundleSource = 'embedded-selected-lifecycle-bundle-digest';
    } else if (embeddedDigests.length === 1) {
      const selected = candidate.embeddedLifecycleBundles.get(embeddedDigests[0]);
      lifecycleBundle = selected.bundle;
      lifecycleBundleBytes = selected.bytes;
      lifecycleBundleDigestHex = selected.digestHex;
    } else {
      throw new Error(
        'Selected archive/state/cohort carries multiple embedded lifecycle-bundle digests. Provide lifecycle-bundle bytes or explicit operator selection of one embedded bundle digest.'
      );
    }
  }

  const selectedStateAnalysis = stateScopedAnalysis.byState.get(`${candidate.archiveId}:${candidate.stateId}`) || {
    archiveId: candidate.archiveId,
    stateId: candidate.stateId,
    cohortIds: [candidate.cohortId],
    forkDetected: false,
    mixedLifecycleBundleVariantCohorts: candidate.embeddedLifecycleBundles.size > 1 ? [candidate.cohortId] : [],
  };
  const explicitlySelectedLifecycleBundle = (
    lifecycleBundleSource === 'uploaded-lifecycle-bundle' ||
    lifecycleBundleSource === 'embedded-selected-lifecycle-bundle-digest'
  );
  const explicitlySelectedCohort = selectedCohortId === candidate.cohortId;
  if (selectedStateAnalysis.forkDetected && !explicitlySelectedLifecycleBundle && !explicitlySelectedCohort) {
    throw new Error(buildSameStateForkRejectionMessage(selectedStateAnalysis));
  }

  const authenticity = await evaluateSuccessorAuthenticity(candidate, lifecycleBundle, verificationOptions);
  if (selectedStateAnalysis.forkDetected && (explicitlySelectedLifecycleBundle || explicitlySelectedCohort)) {
    authenticity.warnings = dedupeWarnings([
      ...(authenticity.warnings || []),
      `Multiple valid cohorts remain known for archive ${candidate.archiveId} state ${candidate.stateId}. Proceeding with explicitly selected cohort ${candidate.cohortId}; known cohort IDs: ${selectedStateAnalysis.cohortIds.join(', ')}. Quantum Vault did not auto-select a winner.`,
    ]);
  } else {
    authenticity.warnings = dedupeWarnings(authenticity.warnings || []);
  }
  if (!authenticity.policy.satisfied) {
    throw new Error(authenticity.policy.reason);
  }

  return {
    candidate,
    lifecycleBundle,
    lifecycleBundleBytes,
    lifecycleBundleDigestHex,
    selectionSource,
    lifecycleBundleSource,
    availableLifecycleBundleDigests: [...candidate.embeddedLifecycleBundles.keys()].sort(),
    cohortSelection: {
      sameStateForkDetected: selectedStateAnalysis.forkDetected,
      knownCohortIdsForState: [...selectedStateAnalysis.cohortIds],
      mixedLifecycleBundleVariantCohorts: [...selectedStateAnalysis.mixedLifecycleBundleVariantCohorts],
      explicitlySelectedCohort,
      explicitlySelectedLifecycleBundle,
    },
    authenticity,
  };
}

function assertArchiveStateMatchesQencMetadata(archiveState, qencMetaJSON) {
  const qenc = archiveState.qenc || {};

  ensureEqual(qenc.hashAlg, 'SHA3-512', 'qenc.hashAlg');
  ensureEqual(qenc.primaryAnchor, 'qencHash', 'qenc.primaryAnchor');
  ensureEqual(qenc.containerIdRole, 'secondary-header-id', 'qenc.containerIdRole');
  ensureEqual(qenc.containerIdAlg, 'SHA3-512(qenc-header-bytes)', 'qenc.containerIdAlg');

  ensureEqual(Number(qencMetaJSON.chunkSize), Number(qenc.chunkSize), 'qenc.chunkSize');
  ensureEqual(Number(qencMetaJSON.chunkCount), Number(qenc.chunkCount), 'qenc.chunkCount');
  ensureEqual(Number(qencMetaJSON.payloadLength), Number(qenc.payloadLength), 'qenc.payloadLength');

  ensureEqual(qencMetaJSON.cryptoProfileId, archiveState.cryptoProfileId, 'cryptoProfileId');
  ensureEqual(qencMetaJSON.kdfTreeId, archiveState.kdfTreeId, 'kdfTreeId');
  ensureEqual(qencMetaJSON.noncePolicyId, archiveState.noncePolicyId, 'noncePolicyId');
  ensureEqual(qencMetaJSON.nonceMode, archiveState.nonceMode, 'nonceMode');
  ensureEqual(Number(qencMetaJSON.counterBits), Number(archiveState.counterBits), 'counterBits');
  ensureEqual(Number(qencMetaJSON.maxChunkCount), Number(archiveState.maxChunkCount), 'maxChunkCount');
  ensureEqual(qencMetaJSON.aadPolicyId, archiveState.aadPolicyId, 'aadPolicyId');
}

async function restoreSuccessorFromShards(shards, options = {}) {
  const onLog = options.onLog || (() => {});
  const onWarn = options.onWarn || options.onError || (() => {});
  const erasureRuntime = resolveErasureRuntime(options.erasureRuntime ?? options.erasure);
  const verificationOptions = options.verification || {};
  const keyValidationHooks = options.keyValidationHooks || null;

  const archiveContext = await resolveSuccessorArchiveContext(shards, verificationOptions);
  const candidate = archiveContext.candidate;
  const archiveState = candidate.archiveState;
  const cohortBinding = candidate.cohortBinding;
  const lifecycleBundle = archiveContext.lifecycleBundle;
  const lifecycleBundleDigestHex = archiveContext.lifecycleBundleDigestHex;

  const group = candidate.shards.slice();
  const embeddedLifecycleBundleDigestsUsed = collectSortedUniqueLifecycleBundleDigests(group);
  const bundleCohortMixed = embeddedLifecycleBundleDigestsUsed.length > 1;
  const rejectedShardIndices = shards
    .filter((shard) => (
      normalizeHexString(shard?.metaJSON?.archiveId) !== candidate.archiveId ||
      normalizeHexString(shard?.metaJSON?.stateId) !== candidate.stateId ||
      normalizeHexString(shard?.metaJSON?.cohortId) !== candidate.cohortId
    ))
    .map((shard) => shard.inputShardIndex);
  const qenc = archiveState.qenc || {};
  const containerId = String(qenc.containerId || '');
  const reconstructed = await reconstructLifecycleCohortMaterial(candidate, {
    erasureRuntime,
    onLog,
    onWarn,
    keyCommitmentLength: KEY_COMMITMENT_MAX_LEN,
    digestHex: async (bytes) => hashBytes(bytes),
    validateQencMeta: (currentArchiveState, qencMetaJSON) => {
      validateContainerPolicyMetadata(qencMetaJSON, { allowLegacyWithoutProfile: false });
      assertArchiveStateMatchesQencMetadata(currentArchiveState, qencMetaJSON);
    },
    keyValidationHooks,
    messages: {
      needThreshold: (threshold, count) => `Need at least ${threshold} matching shards for selected archive/state/cohort, got ${count}`,
      missingKeyCommitment: 'Successor shard is missing required key commitment',
      archiveStateMismatch: 'Exact archive-state byte mismatch inside selected successor cohort',
      cohortBindingMismatch: 'Exact cohort-binding byte mismatch inside selected successor cohort',
      shareCommitmentFailure: (index) => `Share commitment verification failed for shard ${index}. Share will be skipped.`,
      notEnoughValidShares: (threshold, count) => `Not enough valid shards for Shamir reconstruction: need ${threshold}, have ${count}`,
      shareCommitmentSummary: (count) => `Share commitment failures: ${count} shard(s) rejected.`,
      shareCommitmentVerified: 'Share commitments verified.',
      shardBodyFailure: (index) => `Fragment integrity check failed for shard ${index}. Treating as erasure.`,
      shardBodyVerified: 'Shard body hashes verified.',
      tooManyMissingCorrupted: (allowed, total) => `Too many missing/corrupted shards for RS reconstruction: allowed ${allowed}, got ${total}`,
      recoveredPrivateKeyCommitmentFailure: 'Recovered ML-KEM private key does not satisfy the embedded .qenc key commitment.',
      qencHashMismatch: 'Reconstructed .qenc hash does not match archive-state descriptor',
      privateKeyHashMismatch: 'Recovered private key hash does not match shard metadata.',
    },
  });

  const qencBytes = reconstructed.qencBytes;
  const privKey = reconstructed.privKey;
  const recoveredQencHash = normalizeHexString(await hashBytes(qencBytes));
  const expectedQencHash = normalizeHexString(qenc.qencHash);
  const recoveredPrivHash = normalizeHexString(await hashBytes(privKey));
  const privateKeyHash = normalizeHexString(group[0]?.metaJSON?.privateKeyHash || '');
  const qkeyOk = reconstructed.recoveredKeyCommitmentValidated === true;

  const authenticityWarnings = [...(archiveContext.authenticity.warnings || [])];
  const mixedBundleWarning = buildMixedLifecycleBundleVariantWarning(
    embeddedLifecycleBundleDigestsUsed,
    lifecycleBundleDigestHex
  );
  if (mixedBundleWarning) {
    authenticityWarnings.push(mixedBundleWarning);
  }

  const successorStatus = archiveContext.authenticity.verification.status;
  const transitionReport = archiveContext.authenticity.transitionReport;
  const sourceEvidenceReport = archiveContext.authenticity.sourceEvidenceReport;
  return {
    qencBytes,
    privKey,
    archiveId: candidate.archiveId,
    stateId: candidate.stateId,
    cohortId: candidate.cohortId,
    containerId,
    containerHash: expectedQencHash,
    privateKeyHash: privateKeyHash || null,
    privateKeyHashMatchesMetadata: reconstructed.privateKeyHashMatchesMetadata,
    recoveredQencHash,
    recoveredPrivHash,
    rejectedShardIndices,
    qencOk: true,
    qkeyOk,
    archiveState,
    archiveStateBytes: candidate.archiveStateBytes,
    archiveStateDigestHex: candidate.archiveStateDigestHex,
    cohortBinding,
    cohortBindingBytes: candidate.cohortBindingBytes,
    cohortBindingDigestHex: candidate.cohortBindingDigestHex,
    lifecycleBundle,
    lifecycleBundleBytes: archiveContext.lifecycleBundleBytes,
    lifecycleBundleDigestHex,
    bundleDigestHex: lifecycleBundleDigestHex,
    embeddedLifecycleBundleDigestsUsed,
    manifestSource: archiveContext.selectionSource,
    selectionSource: archiveContext.selectionSource,
    lifecycleBundleSource: archiveContext.lifecycleBundleSource,
    lifecycleVerification: {
      transitions: transitionReport,
      sourceEvidence: sourceEvidenceReport,
      cohorts: {
        forkDetected: archiveContext.cohortSelection.sameStateForkDetected === true,
        knownCohortIdsForState: [...archiveContext.cohortSelection.knownCohortIdsForState],
        mixedLifecycleBundleVariantsWithinSelectedCohort: bundleCohortMixed,
        mixedLifecycleBundleVariantCohorts: [...archiveContext.cohortSelection.mixedLifecycleBundleVariantCohorts],
        availableLifecycleBundleDigests: [...archiveContext.availableLifecycleBundleDigests],
      },
    },
    authenticity: {
      policy: archiveContext.authenticity.policy,
      verification: archiveContext.authenticity.verification,
      transitionReport,
      sourceEvidenceReport,
      warnings: [...new Set(authenticityWarnings.filter(Boolean))],
      status: {
        integrityVerified: true,
        archiveApprovalSignatureVerified: successorStatus.archiveApprovalSignatureVerified,
        strongPqSignatureVerified: successorStatus.strongPqSignatureVerified,
        signerPinned: successorStatus.signerPinned,
        bundlePinned: successorStatus.bundlePinned,
        userPinned: successorStatus.userPinned,
        userPinProvided: successorStatus.userPinProvided,
        transitionRecordPresent: transitionReport.present,
        transitionChainValid: transitionReport.chainValid,
        sourceEvidencePresent: sourceEvidenceReport.present,
        cohortForkDetected: archiveContext.cohortSelection.sameStateForkDetected === true,
        bundleCohortMixed,
        mixedLifecycleBundleVariantsWithinCohort: bundleCohortMixed,
        maintenanceSignatureVerified: successorStatus.maintenanceSignatureVerified,
        sourceEvidenceSignatureVerified: successorStatus.sourceEvidenceSignatureVerified,
        otsEvidenceLinked: successorStatus.otsEvidenceLinked,
        policySatisfied: archiveContext.authenticity.policy.satisfied,
        archivePolicySatisfied: archiveContext.authenticity.policy.satisfied,
      },
      timestampEvidence: archiveContext.authenticity.timestampEvidence,
    },
  };
}

export async function restoreFromShards(shards, options = {}) {
  const onLog = options.onLog || (() => {});
  const onWarn = options.onWarn || options.onError || (() => {});
  const strict = options.strict ?? true;
  const erasureRuntime = resolveErasureRuntime(options.erasureRuntime ?? options.erasure);
  const verificationOptions = options.verification || {};

  if (!Array.isArray(shards) || shards.length === 0) {
    throw new Error('No shards provided');
  }

  if (
    verificationOptions.manifestBytes instanceof Uint8Array ||
    verificationOptions.bundleBytes instanceof Uint8Array
  ) {
    throw new Error('Successor restore does not accept legacy manifest or legacy bundle artifacts.');
  }

  const prepared = [];
  for (let i = 0; i < shards.length; i += 1) {
    const shard = shards[i];
    if (shard?.diagnostics?.errors?.length) {
      if (strict) {
        throw new Error(`Shard parse failed at input index ${i}: ${shard.diagnostics.errors.join('; ')}`);
      }
      continue;
    }
    prepared.push({
      ...shard,
      inputOrder: i,
      inputShardIndex: Number.isInteger(shard?.shardIndex) ? shard.shardIndex : i,
    });
  }
  if (prepared.length === 0) {
    throw new Error('No valid shards after parsing');
  }

  const nonSuccessorIndices = prepared
    .map((shard, index) => (isSuccessorParsedShard(shard) ? null : index))
    .filter((index) => Number.isInteger(index));
  if (nonSuccessorIndices.length > 0) {
    throw new Error(
      `Restore requires prepared successor lifecycle shards only. Non-successor parsed input indices: ${nonSuccessorIndices.join(', ')}.`
    );
  }

  return restoreSuccessorFromShards(prepared, {
    ...options,
    onLog,
    onWarn,
    erasureRuntime,
  });
}
