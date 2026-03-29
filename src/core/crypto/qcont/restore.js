/**
 * QCONT restore: successor lifecycle shards (QVqcont-7) and legacy manifest/bundle shards.
 *
 * Successor restore MUST NOT apply manifest-era bundle ranking heuristics. Ambiguous cohort or
 * embedded lifecycle-bundle selection fails closed unless the operator supplies explicit
 * lifecycle-bundle bytes, archive-state bytes, selected archive/state/cohort identity,
 * or selectedLifecycleBundleDigestHex
 * (see resolveSuccessorArchiveContext).
 *
 * Legacy manifest restore may use score-based preference only when candidates share the same
 * embedded manifest digest and identical manifest bytes (see selectPreferredSatisfyingCandidate).
 */
import { sha3_512 } from '@noble/hashes/sha3.js';
import { hashBytes } from '../index.js';
import { asciiBytes, base64ToBytes, bytesEqual, digestSha256, toHex } from '../bytes.js';
import { buildQencHeader } from '../qenc/format.js';
import { LEGACY_QCONT_FORMAT_VERSION, QCONT_FORMAT_VERSION } from '../constants.js';
import { parseArchiveManifestBytes } from '../manifest/archive-manifest.js';
import {
  assertAuthPolicyCommitment,
  parseManifestBundleBytes,
} from '../manifest/manifest-bundle.js';
import {
  assertManifestBundleTimestamps,
  inspectTimestampEvidence,
  resolveOpenTimestampTarget,
} from '../auth/opentimestamps.js';
import { computeDetachedSignatureIdentityDigestHex } from '../auth/signature-identity.js';
import { isSupportedStellarSignatureDocument, verifyStellarSigAgainstBytes } from '../auth/stellar-sig.js';
import { verifyManifestSignatures } from '../auth/verify-signatures.js';
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
import { combineSharesFromCopiedSlices } from './shamir-share-combine.js';

const QCONT_MAGIC = 'QVC1';
const MAGIC_QSIG = asciiBytes('PQSG');
const PIN_MISMATCH_WARNING_PREFIX = 'Pinned PQ signer key did not match';
const KEY_COMMITMENT_MAX_LEN = 32;
const DIGEST_LEN = 64;
const MAX_META_LEN = 16 * 1024;
const MAX_MANIFEST_LEN = 1024 * 1024;
const MAX_BUNDLE_LEN = 4 * 1024 * 1024;

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

function bytesMatch(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && bytesEqual(a, b);
}

function evaluateArchivePolicy(authPolicy, verification) {
  const counts = verification?.counts || {
    validTotal: 0,
    validStrongPq: 0,
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
    const satisfied = counts.validTotal >= minValidSignatures;
    return {
      level,
      minValidSignatures,
      satisfied,
      reason: satisfied
        ? 'required signature count satisfied'
        : 'no valid signature satisfies archive policy',
    };
  }

  if (level === 'strong-pq-signature') {
    const satisfied = counts.validTotal >= minValidSignatures && counts.validStrongPq >= 1;
    return {
      level,
      minValidSignatures,
      satisfied,
      reason: satisfied
        ? 'required strong PQ signature present'
        : 'no valid strong PQ signature satisfies archive policy',
    };
  }

  throw new Error(`Unsupported authPolicy.level: ${authPolicy.level}`);
}

function dedupeWarnings(warnings) {
  return [...new Set((Array.isArray(warnings) ? warnings : []).filter(Boolean))];
}

function findLifecycleSignatureFamilyDescriptor(family) {
  return LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS.find((descriptor) => descriptor.family === family) || null;
}

function decodeJsonBytes(bytes) {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

function isSuccessorParsedShard(shard) {
  return (
    shard?.archiveStateBytes instanceof Uint8Array &&
    shard?.cohortBindingBytes instanceof Uint8Array &&
    shard?.lifecycleBundleBytes instanceof Uint8Array
  );
}

function isLegacyParsedShard(shard) {
  return shard?.manifestBytes instanceof Uint8Array && shard?.bundleBytes instanceof Uint8Array;
}

function detectExternalLifecycleSignatureType(signature) {
  const bytes = signature?.bytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return 'unknown';
  if (bytes.length >= MAGIC_QSIG.length && bytesEqual(bytes.subarray(0, MAGIC_QSIG.length), MAGIC_QSIG)) {
    return 'qsig';
  }
  const parsed = decodeJsonBytes(bytes);
  return isSupportedStellarSignatureDocument(parsed) ? 'stellar-sig' : 'unknown';
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
    return safeVerifySuccessorQsigAgainstBytes({
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
  const uniqueValid = new Map();

  for (const result of results) {
    result.countedForPolicy = false;
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

  return { counts, duplicateWarnings };
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

  const { counts, duplicateWarnings } = buildLifecycleVerificationCounts(results);
  const warnings = [];
  for (const result of results) {
    for (const warning of result.warnings || []) warnings.push(warning);
  }
  warnings.push(...pinNormalizationWarnings);
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

function collectCandidateCohorts(shards) {
  const byDigest = new Map();
  for (const shard of shards) {
    const key = `${shard.manifestDigestHex}:${shard.bundleDigestHex}`;
    if (!byDigest.has(key)) {
      byDigest.set(key, {
        key,
        manifestDigestHex: shard.manifestDigestHex,
        bundleDigestHex: shard.bundleDigestHex,
        manifestBytes: shard.manifestBytes,
        bundleBytes: shard.bundleBytes,
        shards: [],
      });
    }
    const entry = byDigest.get(key);
    if (!bytesEqual(entry.manifestBytes, shard.manifestBytes)) {
      throw new Error(`Manifest bytes mismatch inside cohort ${key}`);
    }
    if (!bytesEqual(entry.bundleBytes, shard.bundleBytes)) {
      throw new Error(`Bundle bytes mismatch inside cohort ${key}`);
    }
    entry.shards.push(shard);
  }
  return [...byDigest.values()];
}

async function enrichCandidate(candidate, bundleBytesOverride = null) {
  const parsedManifest = parseArchiveManifestBytes(candidate.manifestBytes);
  if (parsedManifest.digestHex !== candidate.manifestDigestHex) {
    throw new Error('Embedded manifest digest mismatch');
  }
  const selectedBundleBytes = bundleBytesOverride instanceof Uint8Array ? bundleBytesOverride : candidate.bundleBytes;
  const parsedBundle = parseManifestBundleBytes(selectedBundleBytes);
  if (!(bundleBytesOverride instanceof Uint8Array) && parsedBundle.digestHex !== candidate.bundleDigestHex) {
    throw new Error('Embedded bundle digest mismatch');
  }
  if (!bytesEqual(parsedBundle.manifestBytes, parsedManifest.bytes)) {
    throw new Error('Embedded bundle manifest does not match embedded manifest bytes');
  }
  if (parsedBundle.manifestDigestHex !== parsedManifest.digestHex) {
    throw new Error('Embedded bundle manifestDigest does not match embedded manifest digest');
  }
  assertAuthPolicyCommitment(parsedManifest.manifest.authPolicyCommitment, parsedBundle.bundle.authPolicy);
  await assertManifestBundleTimestamps(parsedBundle.bundle);
  return {
    ...candidate,
    embeddedBundleDigestHex: candidate.bundleDigestHex,
    embeddedBundleBytes: candidate.bundleBytes,
    manifest: parsedManifest.manifest,
    manifestBytes: parsedManifest.bytes,
    bundle: parsedBundle.bundle,
    bundleBytes: parsedBundle.bytes,
    bundleDigestHex: parsedBundle.digestHex,
  };
}

async function evaluateCandidateAuthenticity(candidate, verificationOptions = {}) {
  const verification = await verifyManifestSignatures({
    manifestBytes: candidate.manifestBytes,
    bundleSignatures: candidate.bundle.attachments.signatures,
    bundlePublicKeys: candidate.bundle.attachments.publicKeys,
    externalSignatures: Array.isArray(verificationOptions.signatures) ? verificationOptions.signatures : [],
    pinnedPqPublicKeyFileBytes: verificationOptions.pinnedPqPublicKeyFileBytes ?? verificationOptions.pqPublicKeyFileBytes,
    pinnedPqPublicKeyFileBytesList: verificationOptions.pinnedPqPublicKeyFileBytesList,
    expectedEd25519Signer: verificationOptions.expectedEd25519Signer,
  });
  const policy = evaluateArchivePolicy(candidate.bundle.authPolicy, verification);
  const timestampEvidence = await inspectTimestampEvidence({
    bundle: candidate.bundle,
    externalTimestamps: Array.isArray(verificationOptions.timestamps) ? verificationOptions.timestamps : [],
    signatureArtifacts: verification.signatureArtifacts,
  });
  const warnings = [];
  if (policy.level === 'integrity-only' && verification.counts.validTotal === 0) {
    warnings.push('Archive policy is integrity-only; provenance is not bound to a verified signer.');
  }
  const invalidSignatureCount = verification.results.filter((item) => !item.ok).length;
  if (invalidSignatureCount > 0) {
    warnings.push(`${invalidSignatureCount} attached signature(s) did not verify and were ignored for policy evaluation.`);
  }
  return {
    verification,
    policy,
    timestampEvidence,
    warnings,
  };
}

/**
 * Legacy manifest/bundle restore only: rank manifest-side bundle variants that already
 * share the same embedded manifest digest and identical manifest bytes. Never used for
 * successor lifecycle cohort or lifecycle-bundle selection (see resolveSuccessorArchiveContext).
 */
function preferredBundleScore(item) {
  const verificationCounts = item?.authenticity?.verification?.counts || {};
  const attachments = item?.candidate?.bundle?.attachments || {};
  return [
    Number(verificationCounts.validTotal) || 0,
    Number(verificationCounts.validStrongPq) || 0,
    Array.isArray(attachments.signatures) ? attachments.signatures.length : 0,
    Array.isArray(attachments.publicKeys) ? attachments.publicKeys.length : 0,
    Array.isArray(attachments.timestamps) ? attachments.timestamps.length : 0,
  ];
}

function compareScoreDesc(aScore, bScore) {
  for (let i = 0; i < Math.max(aScore.length, bScore.length); i += 1) {
    const diff = (Number(aScore[i]) || 0) - (Number(bScore[i]) || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Legacy-only tie-break: pick one policy-satisfying manifest cohort when candidates are
 * manifest-equivalent (same manifestDigestHex + manifest bytes) and scores differ.
 * Returns null when ambiguous (ties), forcing the caller to fail closed without a winner.
 * Not used for successor lifecycle restore.
 */
function selectPreferredSatisfyingCandidate(satisfying) {
  if (!Array.isArray(satisfying) || satisfying.length <= 1) return null;
  const firstManifestDigest = satisfying[0]?.candidate?.manifestDigestHex;
  const firstManifestBytes = satisfying[0]?.candidate?.manifestBytes;
  if (!firstManifestDigest || !(firstManifestBytes instanceof Uint8Array)) return null;

  for (const item of satisfying) {
    if (item?.candidate?.manifestDigestHex !== firstManifestDigest) return null;
    if (!bytesMatch(item?.candidate?.manifestBytes, firstManifestBytes)) return null;
  }

  const ranked = [...satisfying].sort((left, right) => {
    const diff = compareScoreDesc(preferredBundleScore(right), preferredBundleScore(left));
    if (diff !== 0) return diff;
    return String(right?.candidate?.bundleDigestHex || '').localeCompare(String(left?.candidate?.bundleDigestHex || ''));
  });
  if (ranked.length < 2) return ranked[0] || null;
  if (compareScoreDesc(preferredBundleScore(ranked[0]), preferredBundleScore(ranked[1])) === 0) {
    return null;
  }
  return ranked[0];
}

function hasManifestEquivalentSibling(candidates, selectedCandidate) {
  if (!Array.isArray(candidates) || !selectedCandidate) return false;
  for (const candidate of candidates) {
    if (!candidate || candidate.bundleDigestHex === selectedCandidate.bundleDigestHex) continue;
    if (candidate.manifestDigestHex !== selectedCandidate.manifestDigestHex) continue;
    if (bytesMatch(candidate.manifestBytes, selectedCandidate.manifestBytes)) {
      return true;
    }
  }
  return false;
}

function collectSortedUniqueBundleDigests(shards) {
  return [...new Set(
    (Array.isArray(shards) ? shards : [])
      .map((item) => normalizeHexString(item?.bundleDigestHex))
      .filter(Boolean)
  )].sort();
}

function buildMixedBundleCohortWarning(embeddedBundleDigestsUsed, selectedBundleDigestHex) {
  if (!Array.isArray(embeddedBundleDigestsUsed) || embeddedBundleDigestsUsed.length <= 1) {
    return '';
  }
  return `Payload reconstruction used shards from multiple embedded bundle digests (${embeddedBundleDigestsUsed.join(', ')}); authenticity and policy were evaluated against selected bundle ${selectedBundleDigestHex}.`;
}

function selectExplicitCandidate(candidates, verificationOptions) {
  if (verificationOptions.manifestBytes instanceof Uint8Array) {
    const parsedManifest = parseArchiveManifestBytes(verificationOptions.manifestBytes);
    const matching = candidates.filter((item) => item.manifestDigestHex === parsedManifest.digestHex);
    if (matching.length === 0) {
      throw new Error('Provided canonical manifest does not match any shard cohort');
    }
    if (matching.length > 1) {
      throw new Error('Canonical manifest matches multiple bundle cohorts. Provide the bundle file or pinned signatures to disambiguate.');
    }
    return matching[0];
  }

  return null;
}

async function resolveArchiveContext(shards, verificationOptions = {}) {
  const rawCandidates = collectCandidateCohorts(shards);
  if (rawCandidates.length === 0) {
    throw new Error('No valid shard cohorts found');
  }

  if (verificationOptions.bundleBytes instanceof Uint8Array) {
    const parsedBundle = parseManifestBundleBytes(verificationOptions.bundleBytes);
    const matching = rawCandidates.filter((candidate) => (
      candidate.manifestDigestHex === parsedBundle.manifestDigestHex &&
      bytesEqual(candidate.manifestBytes, parsedBundle.manifestBytes)
    ));
    if (matching.length === 0) {
      throw new Error('Provided manifest bundle does not match any shard manifest');
    }
    const explicitCandidate = await enrichCandidate(matching[0], parsedBundle.bytes);
    const authenticity = await evaluateCandidateAuthenticity(explicitCandidate, verificationOptions);
    if (!authenticity.policy.satisfied) {
      throw new Error(authenticity.policy.reason);
    }
    return {
      candidate: explicitCandidate,
      authenticity,
      source: 'uploaded-bundle',
      candidateDigests: rawCandidates.map((item) => item.bundleDigestHex),
      useManifestWideShardSelection: true,
    };
  }

  const candidates = await Promise.all(rawCandidates.map((candidate) => enrichCandidate(candidate)));
  if (candidates.length === 0) {
    throw new Error('No valid shard cohorts found');
  }

  const explicit = selectExplicitCandidate(candidates, verificationOptions);
  if (explicit) {
    const authenticity = await evaluateCandidateAuthenticity(explicit, verificationOptions);
    if (!authenticity.policy.satisfied) {
      throw new Error(authenticity.policy.reason);
    }
    return {
      candidate: explicit,
      authenticity,
      source: 'uploaded-manifest',
      candidateDigests: candidates.map((item) => item.bundleDigestHex),
      useManifestWideShardSelection: false,
    };
  }

  const evaluated = [];
  for (const candidate of candidates) {
    try {
      evaluated.push({
        candidate,
        authenticity: await evaluateCandidateAuthenticity(candidate, verificationOptions),
        evaluationError: null,
      });
    } catch (error) {
      evaluated.push({
        candidate,
        authenticity: {
          verification: {
            status: {
              signatureVerified: false,
              strongPqSignatureVerified: false,
              signerPinned: false,
              bundlePinned: false,
              userPinned: false,
              userPinProvided: false,
            },
            counts: {
              validTotal: 0,
              validStrongPq: 0,
              pinnedValidTotal: 0,
              bundlePinnedValidTotal: 0,
              userPinnedValidTotal: 0,
            },
            results: [],
            warnings: [],
          },
          policy: {
            level: candidate.bundle.authPolicy.level,
            minValidSignatures: candidate.bundle.authPolicy.minValidSignatures,
            satisfied: false,
            reason: error?.message || String(error),
          },
          timestampEvidence: [],
          warnings: [],
        },
        evaluationError: error,
      });
    }
  }

  const satisfying = evaluated.filter((item) => item.authenticity.policy.satisfied);
  if (satisfying.length === 1) {
    const widenSelection = hasManifestEquivalentSibling(candidates, satisfying[0].candidate);
    return {
      candidate: satisfying[0].candidate,
      authenticity: satisfying[0].authenticity,
      source: widenSelection ? 'embedded-preferred-bundle' : 'embedded',
      candidateDigests: candidates.map((item) => item.bundleDigestHex),
      useManifestWideShardSelection: widenSelection,
    };
  }
  if (satisfying.length > 1) {
    const preferred = selectPreferredSatisfyingCandidate(satisfying);
    if (preferred) {
      return {
        candidate: preferred.candidate,
        authenticity: preferred.authenticity,
        source: 'embedded-preferred-bundle',
        candidateDigests: candidates.map((item) => item.bundleDigestHex),
        useManifestWideShardSelection: true,
      };
    }
    throw new Error('Multiple shard cohorts satisfy archive policy. Provide the manifest bundle, canonical manifest, or signer pins to disambiguate.');
  }

  const firstEvaluationError = evaluated.find((item) => item.evaluationError)?.evaluationError;
  if (firstEvaluationError && evaluated.every((item) => item.evaluationError)) {
    throw firstEvaluationError;
  }
  if (candidates.length === 1) {
    throw new Error(evaluated[0].authenticity.policy.reason);
  }
  throw new Error('No shard cohort satisfies archive policy.');
}

function parseShardUnsafe(arr) {
  if (!(arr instanceof Uint8Array)) {
    throw new Error('Shard must be a Uint8Array');
  }

  const minHeader = 4 + 2 + 4 + DIGEST_LEN + 4 + DIGEST_LEN + 4 + 12 + 16 + 2 + 1 + 2 + 2;
  if (arr.length < minHeader) {
    throw new Error('Shard is too small to contain a valid header');
  }

  const dv = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  let off = 0;

  const ensure = (need, reason) => {
    if (off + need > arr.length) {
      throw new Error(`Shard is truncated: ${reason}`);
    }
  };

  const readU8 = (reason) => {
    ensure(1, reason);
    const v = dv.getUint8(off);
    off += 1;
    return v;
  };

  const readU16 = (reason) => {
    ensure(2, reason);
    const v = dv.getUint16(off, false);
    off += 2;
    return v;
  };

  const readU32 = (reason) => {
    ensure(4, reason);
    const v = dv.getUint32(off, false);
    off += 4;
    return v;
  };

  const readBytes = (len, reason) => {
    ensure(len, reason);
    const out = arr.subarray(off, off + len);
    off += len;
    return out;
  };

  const decodeJsonBytes = (bytes, reason) => {
    try {
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (error) {
      throw new Error(`Invalid ${reason}: ${error?.message || error}`);
    }
  };

  const magic = new TextDecoder().decode(readBytes(4, 'magic'));
  if (magic !== QCONT_MAGIC) {
    throw new Error('Invalid .qcont magic');
  }

  const metaLen = readU16('metaLen');
  if (metaLen <= 0 || metaLen > MAX_META_LEN) {
    throw new Error('Invalid shard metadata length');
  }
  const metaBytes = readBytes(metaLen, 'metaJSON');
  const metaJSON = decodeJsonBytes(metaBytes, 'shard metadata JSON');
  if (metaJSON?.alg?.fmt === LEGACY_QCONT_FORMAT_VERSION) {
    throw new Error('Legacy .qcont format is not supported. Rebuild the archive with the new manifest bundle format.');
  }
  if (metaJSON?.alg?.fmt !== QCONT_FORMAT_VERSION) {
    throw new Error(`Unsupported shard format: expected ${QCONT_FORMAT_VERSION}, got ${metaJSON?.alg?.fmt ?? 'unknown'}`);
  }

  const manifestLen = readU32('manifest length');
  if (manifestLen <= 0 || manifestLen > MAX_MANIFEST_LEN) {
    throw new Error('Invalid embedded manifest length');
  }
  const manifestBytes = readBytes(manifestLen, 'manifest bytes');
  const manifestDigestBytes = readBytes(DIGEST_LEN, 'manifest digest');
  const computedManifestDigestBytes = sha3_512(manifestBytes);
  if (!bytesEqual(manifestDigestBytes, computedManifestDigestBytes)) {
    throw new Error('Embedded manifest digest mismatch');
  }
  const manifestDigestHex = toHex(manifestDigestBytes);

  const bundleLen = readU32('bundle length');
  if (bundleLen <= 0 || bundleLen > MAX_BUNDLE_LEN) {
    throw new Error('Invalid embedded bundle length');
  }
  const bundleBytes = readBytes(bundleLen, 'bundle bytes');
  const bundleDigestBytes = readBytes(DIGEST_LEN, 'bundle digest');
  const computedBundleDigestBytes = sha3_512(bundleBytes);
  if (!bytesEqual(bundleDigestBytes, computedBundleDigestBytes)) {
    throw new Error('Embedded bundle digest mismatch');
  }
  const bundleDigestHex = toHex(bundleDigestBytes);

  const encapLen = readU32('encapsulatedKey length');
  if (encapLen <= 0) throw new Error('Invalid encapsulated key length');
  const encapsulatedKey = readBytes(encapLen, 'encapsulatedKey');

  const iv = readBytes(12, 'container nonce');
  const salt = readBytes(16, 'kdf salt');

  const qencMetaLen = readU16('qenc metadata length');
  if (qencMetaLen <= 0 || qencMetaLen > MAX_META_LEN) {
    throw new Error('Invalid qenc metadata length');
  }
  const qencMetaBytes = readBytes(qencMetaLen, 'qenc metadata');
  const qencMetaJSON = decodeJsonBytes(qencMetaBytes, 'qenc metadata JSON');

  if (metaJSON?.hasKeyCommitment !== true) {
    throw new Error('Shard metadata must indicate hasKeyCommitment=true');
  }

  const kcLen = readU8('key commitment length');
  if (kcLen !== KEY_COMMITMENT_MAX_LEN) {
    throw new Error(`Invalid key commitment length: expected ${KEY_COMMITMENT_MAX_LEN}, got ${kcLen}`);
  }
  const keyCommit = readBytes(kcLen, 'key commitment');
  if (normalizeHexString(metaJSON?.keyCommitmentHex) !== normalizeHexString(toHex(keyCommit))) {
    throw new Error('Shard metadata keyCommitmentHex mismatch');
  }

  const shardIndex = readU16('shard index');
  const shareLen = readU16('share length');
  if (shareLen <= 0) throw new Error('Invalid Shamir share length');
  const share = readBytes(shareLen, 'Shamir share');
  const fragments = arr.subarray(off);
  if (fragments.length === 0) {
    throw new Error('Shard fragment payload is empty');
  }

  return {
    metaJSON,
    metaBytes,
    manifestBytes,
    manifestDigestHex,
    bundleBytes,
    bundleDigestHex,
    encapsulatedKey,
    iv,
    salt,
    qencMetaBytes,
    qencMetaJSON,
    keyCommit,
    shardIndex,
    share,
    fragments,
    diagnostics: { errors: [], warnings: [] },
  };
}

export function parseShard(arr, options = {}) {
  const { strict = true } = options;
  try {
    return parseShardUnsafe(arr);
  } catch (error) {
    if (strict) throw error;
    return {
      diagnostics: { errors: [error?.message || String(error)], warnings: [] },
    };
  }
}

function assertManifestMatchesQencMetadata(manifest, qencMetaJSON) {
  const qenc = manifest.qenc || {};

  ensureEqual(qenc.hashAlg, 'SHA3-512', 'qenc.hashAlg');
  ensureEqual(qenc.primaryAnchor, 'qencHash', 'qenc.primaryAnchor');
  ensureEqual(qenc.containerIdRole, 'secondary-header-id', 'qenc.containerIdRole');
  ensureEqual(qenc.containerIdAlg, 'SHA3-512(qenc-header-bytes)', 'qenc.containerIdAlg');

  ensureEqual(qencMetaJSON.fmt, qenc.format, 'qenc.format');
  ensureEqual(qencMetaJSON.aead_mode, qenc.aeadMode, 'qenc.aeadMode');
  ensureEqual(qencMetaJSON.iv_strategy, qenc.ivStrategy, 'qenc.ivStrategy');
  ensureEqual(Number(qencMetaJSON.chunkSize), Number(qenc.chunkSize), 'qenc.chunkSize');
  ensureEqual(Number(qencMetaJSON.chunkCount), Number(qenc.chunkCount), 'qenc.chunkCount');
  ensureEqual(Number(qencMetaJSON.payloadLength), Number(qenc.payloadLength), 'qenc.payloadLength');

  ensureEqual(qencMetaJSON.cryptoProfileId, manifest.cryptoProfileId, 'cryptoProfileId');
  ensureEqual(qencMetaJSON.kdfTreeId, manifest.kdfTreeId, 'kdfTreeId');
  ensureEqual(qencMetaJSON.noncePolicyId, manifest.noncePolicyId, 'noncePolicyId');
  ensureEqual(qencMetaJSON.nonceMode, manifest.nonceMode, 'nonceMode');
  ensureEqual(Number(qencMetaJSON.counterBits), Number(manifest.counterBits), 'counterBits');
  ensureEqual(Number(qencMetaJSON.maxChunkCount), Number(manifest.maxChunkCount), 'maxChunkCount');
  ensureEqual(qencMetaJSON.aadPolicyId, manifest.aadPolicyId, 'aadPolicyId');
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

  if (!Array.isArray(shards) || shards.length === 0) {
    throw new Error('No shards provided');
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

  const successorCount = prepared.filter(isSuccessorParsedShard).length;
  const legacyCount = prepared.filter(isLegacyParsedShard).length;
  const verificationOptions = options.verification || {};
  if (successorCount > 0 && legacyCount > 0) {
    throw new Error('Restore does not support mixing legacy and successor shard families.');
  }
  if (successorCount === prepared.length) {
    if (verificationOptions.manifestBytes instanceof Uint8Array || verificationOptions.bundleBytes instanceof Uint8Array) {
      throw new Error('Successor restore does not accept legacy manifest or manifest-bundle artifacts.');
    }
    return restoreSuccessorFromShards(prepared, {
      ...options,
      onLog,
      onWarn,
      erasureRuntime,
    });
  }
  if (legacyCount === prepared.length) {
    if (verificationOptions.archiveStateBytes instanceof Uint8Array || verificationOptions.lifecycleBundleBytes instanceof Uint8Array) {
      throw new Error('Legacy restore does not accept successor archive-state or lifecycle-bundle artifacts.');
    }
  }
  const archiveContext = await resolveArchiveContext(prepared, verificationOptions);
  const candidate = archiveContext.candidate;
  const manifest = candidate.manifest;
  const bundle = candidate.bundle;
  const manifestDigestHex = candidate.manifestDigestHex;
  const bundleDigestHex = candidate.bundleDigestHex;
  const useManifestWideShardSelection = archiveContext.useManifestWideShardSelection === true;
  const selectedEmbeddedBundleDigestHex = candidate.embeddedBundleDigestHex || candidate.bundleDigestHex;

  const group = prepared.filter((shard) => (
    shard.manifestDigestHex === manifestDigestHex &&
    (useManifestWideShardSelection || shard.bundleDigestHex === selectedEmbeddedBundleDigestHex)
  ));
  const embeddedBundleDigestsUsed = collectSortedUniqueBundleDigests(group);
  const bundleCohortMixed = embeddedBundleDigestsUsed.length > 1;
  const rejectedShardIndices = prepared
    .filter((shard) => (
      shard.manifestDigestHex !== manifestDigestHex ||
      (!useManifestWideShardSelection && shard.bundleDigestHex !== selectedEmbeddedBundleDigestHex)
    ))
    .map((shard) => shard.inputShardIndex);

  const n = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.n), 'manifest.sharding.reedSolomon.n', 2);
  const k = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.k), 'manifest.sharding.reedSolomon.k', 2);
  const m = ensurePositiveInteger(Number(manifest?.sharding?.reedSolomon?.parity), 'manifest.sharding.reedSolomon.parity', 0);
  const t = ensurePositiveInteger(Number(manifest?.sharding?.shamir?.threshold), 'manifest.sharding.shamir.threshold', 2);
  const shareCount = ensurePositiveInteger(Number(manifest?.sharding?.shamir?.shareCount), 'manifest.sharding.shamir.shareCount', 2);
  if (shareCount !== n) {
    throw new Error(`Invalid manifest sharding: Shamir shareCount ${shareCount} must equal RS n ${n}`);
  }
  if ((m % 2) !== 0) {
    throw new Error('Invalid manifest sharding: RS parity must be even');
  }
  if (k >= n) {
    throw new Error('Invalid manifest sharding: expected k < n');
  }

  const allowedFailures = m / 2;
  const expectedThreshold = k + allowedFailures;
  if (t !== expectedThreshold) {
    throw new Error(`Invalid manifest threshold: expected ${expectedThreshold}, got ${t}`);
  }

  const qenc = manifest.qenc || {};
  const chunkSize = ensurePositiveInteger(Number(qenc.chunkSize), 'manifest.qenc.chunkSize', 1);
  const chunkCount = ensurePositiveInteger(Number(qenc.chunkCount), 'manifest.qenc.chunkCount', 1);
  const payloadLength = ensurePositiveInteger(Number(qenc.payloadLength), 'manifest.qenc.payloadLength', 1);

  const containerId = String(qenc.containerId || '');
  if (containerId.length === 0) {
    throw new Error('Manifest is missing qenc.containerId');
  }

  const base = group[0];
  if (!(base.keyCommit instanceof Uint8Array) || base.keyCommit.length !== KEY_COMMITMENT_MAX_LEN) {
    throw new Error('Shard is missing required key commitment');
  }
  const shardByIndex = new Map();

  for (const shard of group) {
    if (!Number.isInteger(shard.shardIndex) || shard.shardIndex < 0 || shard.shardIndex >= n) {
      throw new Error(`Invalid shardIndex ${shard.shardIndex}`);
    }
    if (shardByIndex.has(shard.shardIndex)) {
      throw new Error(`Duplicate shardIndex ${shard.shardIndex} detected`);
    }
    shardByIndex.set(shard.shardIndex, shard);

    ensureEqual(shard.metaJSON?.containerId, containerId, 'containerId');
    ensureEqual(Number(shard.metaJSON?.n), n, 'n');
    ensureEqual(Number(shard.metaJSON?.k), k, 'k');
    ensureEqual(Number(shard.metaJSON?.m), m, 'm');
    ensureEqual(Number(shard.metaJSON?.t), t, 't');
    ensureEqual(normalizeHexString(shard.metaJSON?.manifestDigest), manifestDigestHex, 'manifestDigest');
    if (!useManifestWideShardSelection) {
      ensureEqual(normalizeHexString(shard.metaJSON?.bundleDigest), selectedEmbeddedBundleDigestHex, 'bundleDigest');
    }

    if (!bytesEqual(shard.encapsulatedKey, base.encapsulatedKey)) {
      throw new Error(`Shard header mismatch: encapsulatedKey differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.iv, base.iv)) {
      throw new Error(`Shard header mismatch: iv differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.salt, base.salt)) {
      throw new Error(`Shard header mismatch: salt differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.qencMetaBytes, base.qencMetaBytes)) {
      throw new Error(`Shard header mismatch: qenc metadata differs for shard ${shard.shardIndex}`);
    }
    if (!bytesEqual(shard.keyCommit, base.keyCommit)) {
      throw new Error(`Shard header mismatch: key commitment differs for shard ${shard.shardIndex}`);
    }
  }

  const missingIndices = new Set();
  for (let i = 0; i < n; i += 1) {
    if (!shardByIndex.has(i)) missingIndices.add(i);
  }

  const qencMetaJSON = base.qencMetaJSON;
  validateContainerPolicyMetadata(qencMetaJSON, { allowLegacyWithoutProfile: false });
  assertManifestMatchesQencMetadata(manifest, qencMetaJSON);

  const ciphertextLength = ensurePositiveInteger(Number(base.metaJSON?.ciphertextLength), 'ciphertextLength', 1);
  for (const shard of group) {
    ensureEqual(Number(shard.metaJSON?.ciphertextLength), ciphertextLength, 'ciphertextLength');
    ensureEqual(Number(shard.metaJSON?.chunkCount), chunkCount, 'chunkCount');
    ensureEqual(Number(shard.metaJSON?.chunkSize), chunkSize, 'chunkSize');
  }

  const isPerChunkMode = qencMetaJSON.aead_mode === 'per-chunk-aead';
  if (!isPerChunkMode && qencMetaJSON.aead_mode !== 'single-container-aead') {
    throw new Error(`Unsupported AEAD mode: ${qencMetaJSON.aead_mode ?? 'unknown'}`);
  }

  const expectedCiphertextLength = isPerChunkMode
    ? (payloadLength + (16 * chunkCount))
    : ciphertextLength;
  if (isPerChunkMode && ciphertextLength !== expectedCiphertextLength) {
    throw new Error(`Ciphertext length mismatch for per-chunk mode (expected ${expectedCiphertextLength}, got ${ciphertextLength})`);
  }

  const encapHash = await hashBytes(base.encapsulatedKey);
  if (normalizeHexString(base.metaJSON?.encapBlobHash) !== normalizeHexString(encapHash)) {
    throw new Error('encapBlobHash mismatch');
  }
  if (group.length < t) {
    throw new Error(`Need at least ${t} matching shards for selected archive cohort, got ${group.length}`);
  }

  const shareCommitments = manifest?.shardBinding?.shareCommitments || base.metaJSON?.shareCommitments || null;
  const fragmentBodyHashes = manifest?.shardBinding?.shardBodyHashes || base.metaJSON?.fragmentBodyHashes || null;

  let validShareShards = group;
  if (Array.isArray(shareCommitments)) {
    if (shareCommitments.length !== n) {
      throw new Error('Invalid shareCommitments length');
    }
    validShareShards = [];
    const invalidShareIndices = new Set();
    for (const shard of group) {
      const expected = normalizeHexString(shareCommitments[shard.shardIndex]);
      const actual = normalizeHexString(await hashBytes(shard.share));
      if (!expected || actual !== expected) {
        onWarn(`Share commitment verification failed for shard ${shard.shardIndex}. Share will be skipped.`);
        invalidShareIndices.add(shard.shardIndex);
        continue;
      }
      validShareShards.push(shard);
    }
    if (validShareShards.length < t) {
      throw new Error(`Not enough valid shards for Shamir reconstruction: need ${t}, have ${validShareShards.length}`);
    }
    onLog(invalidShareIndices.size > 0 ? `Share commitment failures: ${invalidShareIndices.size} shard(s) rejected.` : 'Share commitments verified.');
  }

  const corruptedShardIndices = new Set();
  if (Array.isArray(fragmentBodyHashes)) {
    if (fragmentBodyHashes.length !== n) {
      throw new Error('Invalid shardBodyHashes length');
    }
    for (const shard of group) {
      const expected = normalizeHexString(fragmentBodyHashes[shard.shardIndex]);
      const actual = normalizeHexString(await hashBytes(shard.fragments));
      if (expected && actual !== expected) {
        onWarn(`Fragment integrity check failed for shard ${shard.shardIndex}. Treating as erasure.`);
        corruptedShardIndices.add(shard.shardIndex);
      }
    }
    if (corruptedShardIndices.size === 0) {
      onLog('Shard body hashes verified.');
    }
  }

  const totalBad = missingIndices.size + corruptedShardIndices.size;
  if (totalBad > allowedFailures) {
    throw new Error(`Too many missing/corrupted shards for RS reconstruction: allowed ${allowedFailures}, got ${totalBad}`);
  }

  const sortedShares = validShareShards.slice().sort((a, b) => a.shardIndex - b.shardIndex);
  const { secret: privKey } = await combineSharesFromCopiedSlices(sortedShares, t);

  const rsEncodeBase = Number.isInteger(base.metaJSON?.rsEncodeBase) ? base.metaJSON.rsEncodeBase : 255;
  const cipherChunks = [];
  const shardOffsets = new Array(n).fill(0);

  for (let i = 0; i < chunkCount; i += 1) {
    const plainLen = Math.min(chunkSize, payloadLength - (i * chunkSize));
    const thisLen = isPerChunkMode ? (plainLen + 16) : ciphertextLength;

    const encodeSize = Math.floor(rsEncodeBase / n) * n;
    if (encodeSize === 0) throw new Error('RS parameters too large');
    const inputSize = (encodeSize * k) / n;
    const symbolSize = inputSize / k;
    const blocks = Math.ceil(thisLen / inputSize);
    const expectedFragLen = blocks * symbolSize;

    const encoded = new Array(n);
    for (let j = 0; j < n; j += 1) {
      const shard = shardByIndex.get(j);
      const fragStream = (shard && !corruptedShardIndices.has(j)) ? shard.fragments : null;
      if (!fragStream) {
        encoded[j] = new Uint8Array(expectedFragLen);
        continue;
      }

      const streamOffset = shardOffsets[j];
      if (streamOffset + 4 > fragStream.length) {
        throw new Error('Fragment stream underflow');
      }

      const dvFrag = new DataView(fragStream.buffer, fragStream.byteOffset + streamOffset);
      const fragLen = dvFrag.getUint32(0, false);
      const fragStart = streamOffset + 4;
      const fragEnd = fragStart + fragLen;
      if (fragEnd > fragStream.length) {
        throw new Error('Fragment length overflow');
      }

      let fragment = fragStream.subarray(fragStart, fragEnd);
      if (fragment.length < expectedFragLen) {
        const padded = new Uint8Array(expectedFragLen);
        padded.set(fragment);
        fragment = padded;
      } else if (fragment.length > expectedFragLen) {
        fragment = fragment.subarray(0, expectedFragLen);
      }

      encoded[j] = fragment;
      shardOffsets[j] = fragEnd;
    }

    let recombined;
    try {
      recombined = erasureRuntime.recombine(encoded, thisLen, k, m / 2, rsEncodeBase);
    } catch (error) {
      throw new Error(`RS recombination failed on chunk ${i}: ${error?.message ?? error}`);
    }

    cipherChunks.push(recombined);
    if (!isPerChunkMode) break;
  }

  for (let j = 0; j < n; j += 1) {
    if (corruptedShardIndices.has(j)) continue;
    const shard = shardByIndex.get(j);
    if (!shard) continue;
    if (shardOffsets[j] !== shard.fragments.length) {
      throw new Error(`Fragment stream has trailing or missing data in shard ${j}`);
    }
  }

  const ciphertext = isPerChunkMode
    ? (() => {
        const total = cipherChunks.reduce((sum, item) => sum + item.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const chunk of cipherChunks) {
          out.set(chunk, offset);
          offset += chunk.length;
        }
        return out;
      })()
    : cipherChunks[0];

  if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== ciphertextLength) {
    throw new Error('Reconstructed ciphertext length mismatch');
  }

  const header = buildQencHeader({
    encapsulatedKey: base.encapsulatedKey,
    containerNonce: base.iv,
    kdfSalt: base.salt,
    metaBytes: base.qencMetaBytes,
    keyCommitment: base.keyCommit,
  });

  const qencBytes = new Uint8Array(header.length + ciphertext.length);
  qencBytes.set(header, 0);
  qencBytes.set(ciphertext, header.length);

  const recoveredQencHash = normalizeHexString(await hashBytes(qencBytes));
  const expectedQencHash = normalizeHexString(qenc.qencHash);
  if (recoveredQencHash !== expectedQencHash) {
    throw new Error('Reconstructed .qenc hash does not match archive manifest');
  }

  const recoveredPrivHash = normalizeHexString(await hashBytes(privKey));
  const privateKeyHash = normalizeHexString(base.metaJSON?.privateKeyHash || '');
  const qkeyOk = privateKeyHash ? (privateKeyHash === recoveredPrivHash) : true;
  if (!qkeyOk) {
    onWarn('Recovered private key hash does not match shard metadata.');
  }
  const authenticityWarnings = [...(archiveContext.authenticity.warnings || [])];
  const mixedBundleWarning = buildMixedBundleCohortWarning(embeddedBundleDigestsUsed, bundleDigestHex);
  if (mixedBundleWarning) {
    authenticityWarnings.push(mixedBundleWarning);
  }

  return {
    qencBytes,
    privKey,
    containerId,
    containerHash: expectedQencHash,
    privateKeyHash: privateKeyHash || null,
    recoveredQencHash,
    recoveredPrivHash,
    rejectedShardIndices,
    qencOk: true,
    qkeyOk,
    manifest,
    manifestBytes: candidate.manifestBytes,
    manifestDigestHex,
    bundle,
    bundleBytes: candidate.bundleBytes,
    bundleDigestHex,
    embeddedBundleDigestsUsed,
    manifestSource: archiveContext.source,
    authenticity: {
      policy: archiveContext.authenticity.policy,
      verification: archiveContext.authenticity.verification,
      warnings: [...new Set(authenticityWarnings.filter(Boolean))],
      status: {
        integrityVerified: true,
        signatureVerified: archiveContext.authenticity.verification.status.signatureVerified,
        strongPqSignatureVerified: archiveContext.authenticity.verification.status.strongPqSignatureVerified,
        signerPinned: archiveContext.authenticity.verification.status.signerPinned,
        bundlePinned: archiveContext.authenticity.verification.status.bundlePinned,
        userPinned: archiveContext.authenticity.verification.status.userPinned,
        userPinProvided: archiveContext.authenticity.verification.status.userPinProvided,
        bundleCohortMixed,
        policySatisfied: archiveContext.authenticity.policy.satisfied,
        archivePolicySatisfied: archiveContext.authenticity.policy.satisfied,
      },
      timestampEvidence: archiveContext.authenticity.timestampEvidence,
    },
  };
}
