import assert from 'node:assert/strict';
import test from 'node:test';
import {
  blobToBytes,
  buildOtsFixture,
  buildQsigFixture,
  buildSuccessorRestoreSample,
  buildSuccessorVerificationBundle,
  ensureErasureRuntime,
  ensureRuntimeCrypto,
  textBytes,
} from '../../src/core/crypto/selftest.js';
import { parseLifecycleShard, reshareSameState } from '../../src/core/crypto/qcont/lifecycle-shard.js';
import { assessRestoreFromShards, restoreFromShards } from '../../src/core/crypto/qcont/restore.js';
import { canonicalizeLifecycleBundle } from '../../src/core/crypto/lifecycle/artifacts.js';
import { computeDetachedSignatureIdentityDigestHex } from '../../src/core/crypto/auth/signature-identity.js';

async function parseShardSet(result) {
  return Promise.all(result.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function withLifecycleBundle(parsedShards, bundle, bundleBytes, digestHex) {
  return parsedShards.map((shard) => ({
    ...shard,
    lifecycleBundle: bundle,
    lifecycleBundleBytes: bundleBytes,
    lifecycleBundleDigestHex: digestHex,
  }));
}

function wipeRestoreResult(result) {
  if (result?.qencBytes instanceof Uint8Array) result.qencBytes.fill(0);
  if (result?.privKey instanceof Uint8Array) result.privKey.fill(0);
}

function mutateQsigDisplayFilenameByte(qsigBytes) {
  const out = qsigBytes.slice();
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  const contextLength = out[108];
  const authenticatedMetadataLength = view.getUint16(110, true);
  const displayMetadataLength = view.getUint16(112, true);
  const displayMetadataOffset = 118 + contextLength + authenticatedMetadataLength;
  assert(displayMetadataLength >= 4, 'fixture must carry mutable display metadata');
  out[displayMetadataOffset + 3] ^= 0x01;
  return out;
}

test.before(async () => {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();
});

test('restore policy vectors keep integrity-only separate from signature-required policies', async () => {
  const integrityOnly = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-integrity-only'),
    authPolicyLevel: 'integrity-only',
  });
  const integrityResult = await restoreFromShards(integrityOnly.parsed, {
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(integrityResult.authenticity.policy.level, 'integrity-only');
    assert.equal(integrityResult.authenticity.policy.satisfied, true);
    assert.equal(integrityResult.authenticity.status.policySatisfied, true);
  } finally {
    wipeRestoreResult(integrityResult);
    integrityOnly.pair.privateKey.fill(0);
  }

  const signatureRequired = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-any-signature'),
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
  });
  const unsignedAssessment = await assessRestoreFromShards(signatureRequired.parsed, {
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(unsignedAssessment.authenticity.policy.level, 'any-signature');
    assert.equal(unsignedAssessment.authenticity.policy.satisfied, false);
    assert.equal(unsignedAssessment.authenticity.verification.counts.validArchiveApproval, 0);
    assert.equal(unsignedAssessment.authenticity.status.policySatisfied, false);
  } finally {
    wipeRestoreResult(unsignedAssessment);
    signatureRequired.pair.privateKey.fill(0);
  }
});

test('restore policy vectors require strong PQ archive approval for strong-pq-signature policy', async () => {
  const sample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-strong-pq'),
    authPolicyLevel: 'strong-pq-signature',
    minValidSignatures: 1,
  });

  const unsignedAssessment = await assessRestoreFromShards(sample.parsed, {
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(unsignedAssessment.authenticity.policy.level, 'strong-pq-signature');
    assert.equal(unsignedAssessment.authenticity.policy.satisfied, false);
    assert.equal(unsignedAssessment.authenticity.status.strongPqSignatureVerified, false);
    assert.equal(unsignedAssessment.authenticity.status.policySatisfied, false);
  } finally {
    wipeRestoreResult(unsignedAssessment);
  }

  const signedBundle = await buildSuccessorVerificationBundle(sample.split, {
    authPolicyLevel: 'strong-pq-signature',
    minValidSignatures: 1,
    includeArchiveApproval: true,
    includeMaintenance: false,
    includeSourceEvidence: false,
  });
  const signedShards = withLifecycleBundle(sample.parsed, signedBundle.bundle, signedBundle.bundleBytes, signedBundle.digestHex);
  const signedAssessment = await assessRestoreFromShards(signedShards, {
    verification: { lifecycleBundleBytes: signedBundle.bundleBytes },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(signedAssessment.authenticity.verification.counts.validArchiveApproval, 1);
    assert.equal(signedAssessment.authenticity.verification.counts.validArchiveApprovalStrongPq, 1);
    assert.equal(signedAssessment.authenticity.status.strongPqSignatureVerified, true);
    assert.equal(signedAssessment.authenticity.status.bundlePinned, true);
    assert.equal(signedAssessment.authenticity.policy.satisfied, true);
  } finally {
    wipeRestoreResult(signedAssessment);
    sample.pair.privateKey.fill(0);
  }
});

test('restore derives lifecycle policy from canonical bundle bytes rather than mutable parsed objects', async () => {
  const sample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-canonical-byte-authority'),
    authPolicyLevel: 'strong-pq-signature',
    minValidSignatures: 1,
  });
  const mutated = sample.parsed.map((shard) => {
    const archiveState = cloneJson(shard.archiveState);
    archiveState.qenc.payloadLength += 1;
    const cohortBinding = cloneJson(shard.cohortBinding);
    cohortBinding.sharding.shamir.threshold = 2;
    return {
      ...shard,
      archiveState,
      cohortBinding,
      lifecycleBundle: {
        ...shard.lifecycleBundle,
        authPolicy: {
          level: 'integrity-only',
          minValidSignatures: 1,
        },
      },
    };
  });

  try {
    const assessment = await assessRestoreFromShards(mutated, {
      onLog: () => {},
      onError: () => {},
    });
    assert.equal(assessment.authenticity.policy.level, 'strong-pq-signature');
    assert.equal(assessment.authenticity.policy.satisfied, false);
    await assert.rejects(
      async () => restoreFromShards(mutated, { onLog: () => {}, onError: () => {} }),
      /strong PQ archive-approval signature/,
    );
  } finally {
    sample.pair.privateKey.fill(0);
  }
});

test('restore counts one approval per verified signer when qsig display metadata differs', async () => {
  const sample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-distinct-signers'),
    authPolicyLevel: 'any-signature',
    minValidSignatures: 2,
  });
  const approval = buildQsigFixture(sample.split.archiveStateBytes);
  const displayVariant = mutateQsigDisplayFilenameByte(approval.qsigBytes);

  const originalIdentity = computeDetachedSignatureIdentityDigestHex({
    format: 'qsig',
    signatureBytes: approval.qsigBytes,
  });
  const variantIdentity = computeDetachedSignatureIdentityDigestHex({
    format: 'qsig',
    signatureBytes: displayVariant,
  });

  const assessment = await assessRestoreFromShards(sample.parsed, {
    verification: {
      signatures: [
        { name: 'approval-a.qsig', bytes: approval.qsigBytes },
        { name: 'approval-a-display-variant.qsig', bytes: displayVariant },
      ],
      pinnedPqPublicKeyFileBytesList: [approval.pqpkBytes],
    },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(originalIdentity, variantIdentity);
    assert.equal(assessment.authenticity.verification.counts.validArchiveApproval, 1);
    assert.equal(assessment.authenticity.policy.satisfied, false);
    assert(assessment.authenticity.warnings.some((warning) => /ignored for archive-approval policy\/state counting/.test(warning)));
  } finally {
    wipeRestoreResult(assessment);
    sample.pair.privateKey.fill(0);
  }
});

test('restore policy vectors pin signer trust and ignore self-signed PQ approvals for policy', async () => {
  const sample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-pins'),
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
  });
  const archiveApproval = buildQsigFixture(sample.split.archiveStateBytes);
  const wrongPin = buildQsigFixture(textBytes('wrong-pinned-signer'));

  const selfSignedOnly = await assessRestoreFromShards(sample.parsed, {
    verification: {
      signatures: [{ name: 'archive-approval.qsig', bytes: archiveApproval.qsigBytes }],
    },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(selfSignedOnly.authenticity.verification.counts.validArchiveApproval, 0);
    assert.equal(selfSignedOnly.authenticity.policy.satisfied, false);
    assert.equal(selfSignedOnly.authenticity.status.signerPinned, false);
  } finally {
    wipeRestoreResult(selfSignedOnly);
  }

  const wrongPinned = await assessRestoreFromShards(sample.parsed, {
    verification: {
      signatures: [{ name: 'archive-approval.qsig', bytes: archiveApproval.qsigBytes }],
      pinnedPqPublicKeyFileBytesList: [wrongPin.pqpkBytes],
    },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(wrongPinned.authenticity.verification.counts.validArchiveApproval, 0);
    assert.equal(wrongPinned.authenticity.policy.satisfied, false);
    assert.equal(wrongPinned.authenticity.status.userPinProvided, true);
    assert.equal(wrongPinned.authenticity.status.userPinned, false);
    assert(wrongPinned.authenticity.verification.results.some((result) => result.ok === false));
  } finally {
    wipeRestoreResult(wrongPinned);
  }

  const pinned = await assessRestoreFromShards(sample.parsed, {
    verification: {
      signatures: [{ name: 'archive-approval.qsig', bytes: archiveApproval.qsigBytes }],
      pinnedPqPublicKeyFileBytesList: [archiveApproval.pqpkBytes],
    },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(pinned.authenticity.verification.counts.validArchiveApproval, 1);
    assert.equal(pinned.authenticity.policy.satisfied, true);
    assert.equal(pinned.authenticity.status.signerPinned, true);
    assert.equal(pinned.authenticity.status.userPinned, true);
  } finally {
    wipeRestoreResult(pinned);
    sample.pair.privateKey.fill(0);
  }
});

test('restore policy vectors ignore maintenance, source-evidence, and unresolved publicKeyRef entries for archive approval', async () => {
  const evidenceOnly = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-maint-source-only'),
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
  });
  const evidenceBundle = await buildSuccessorVerificationBundle(evidenceOnly.split, {
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
    includeArchiveApproval: false,
    includeMaintenance: true,
    includeSourceEvidence: true,
    timestampTargetFamily: 'maintenance',
  });
  const evidenceOnlyShards = withLifecycleBundle(
    evidenceOnly.parsed,
    evidenceBundle.bundle,
    evidenceBundle.bundleBytes,
    evidenceBundle.digestHex,
  );
  const evidenceAssessment = await assessRestoreFromShards(evidenceOnlyShards, {
    verification: { lifecycleBundleBytes: evidenceBundle.bundleBytes },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(evidenceAssessment.authenticity.verification.counts.validMaintenance, 1);
    assert.equal(evidenceAssessment.authenticity.verification.counts.validSourceEvidence, 1);
    assert.equal(evidenceAssessment.authenticity.verification.counts.validArchiveApproval, 0);
    assert.equal(evidenceAssessment.authenticity.status.maintenanceSignatureVerified, true);
    assert.equal(evidenceAssessment.authenticity.status.sourceEvidenceSignatureVerified, true);
    assert.equal(evidenceAssessment.authenticity.status.otsEvidenceLinked, true);
    assert.equal(evidenceAssessment.authenticity.policy.satisfied, false);
  } finally {
    wipeRestoreResult(evidenceAssessment);
    evidenceOnly.pair.privateKey.fill(0);
  }

  const unresolved = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-unresolved-public-key-ref'),
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
  });
  const signedBundle = await buildSuccessorVerificationBundle(unresolved.split, {
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
    includeArchiveApproval: true,
    includeMaintenance: false,
    includeSourceEvidence: false,
  });
  const unresolvedBundle = cloneJson(signedBundle.bundle);
  unresolvedBundle.attachments.publicKeys = [];
  const canonicalUnresolvedBundle = await canonicalizeLifecycleBundle(unresolvedBundle);
  const unresolvedShards = withLifecycleBundle(
    unresolved.parsed,
    canonicalUnresolvedBundle.lifecycleBundle,
    canonicalUnresolvedBundle.bytes,
    canonicalUnresolvedBundle.digest.value,
  );
  const unresolvedAssessment = await assessRestoreFromShards(unresolvedShards, {
    verification: { lifecycleBundleBytes: canonicalUnresolvedBundle.bytes },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(unresolvedAssessment.authenticity.verification.counts.validArchiveApproval, 0);
    assert.equal(unresolvedAssessment.authenticity.policy.satisfied, false);
    assert(unresolvedAssessment.authenticity.verification.results.some((result) => (
      result.ok === false &&
      result.family === 'archive-approval' &&
      result.publicKeyRef === 'pk-archive'
    )));
  } finally {
    wipeRestoreResult(unresolvedAssessment);
    unresolved.pair.privateKey.fill(0);
  }
});

test('restore successor selection rejects same-state cohort ambiguity unless explicit', async () => {
  const sample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-successor-ambiguity'),
    authPolicyLevel: 'integrity-only',
  });
  const reshared = await reshareSameState(sample.parsed, { n: 5, k: 3 }, {
    transition: {
      reasonCode: 'cohort-rotation',
      operatorRole: 'operator',
      actorHints: { ceremony: 'core-vector' },
      performedAt: '2026-05-24T00:00:00.000Z',
    },
  });
  const resharedParsed = await parseShardSet(reshared);
  const ambiguous = [...sample.parsed.slice(0, 4), ...resharedParsed.slice(0, 4)];

  await assert.rejects(
    async () => restoreFromShards(ambiguous, { onLog: () => {}, onError: () => {} }),
    /Multiple valid cohorts were detected/,
  );

  const selected = await restoreFromShards(ambiguous, {
    verification: { selectedCohortId: reshared.cohortId },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(selected.cohortId, reshared.cohortId);
    assert.equal(selected.lifecycleVerification.cohorts.forkDetected, true);
    assert.equal(selected.authenticity.policy.satisfied, true);
    assert(selected.authenticity.warnings.some((warning) => /explicitly selected cohort/.test(warning)));
  } finally {
    wipeRestoreResult(selected);
    sample.pair.privateKey.fill(0);
  }
});

test('restore successor selection rejects multiple archive and state candidates unless narrowed explicitly', async () => {
  const archiveA = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-selection-archive-a'),
    authPolicyLevel: 'integrity-only',
    buildOptions: { archiveIdRandomBytes: new Uint8Array(32).fill(0xa1) },
  });
  const archiveB = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-selection-archive-b'),
    authPolicyLevel: 'integrity-only',
    buildOptions: { archiveIdRandomBytes: new Uint8Array(32).fill(0xb2) },
  });
  const mixedArchives = [...archiveA.parsed.slice(0, 4), ...archiveB.parsed.slice(0, 4)];

  await assert.rejects(
    async () => restoreFromShards(mixedArchives, { onLog: () => {}, onError: () => {} }),
    /Multiple successor archive\/state\/cohort candidate sets/,
  );

  const selectedArchive = await restoreFromShards(mixedArchives, {
    verification: { selectedArchiveId: archiveB.split.archiveId },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(selectedArchive.archiveId, archiveB.split.archiveId);
    assert.equal(selectedArchive.selectionSource, 'selected-archive-id');
    assert.equal(selectedArchive.authenticity.policy.satisfied, true);
  } finally {
    wipeRestoreResult(selectedArchive);
  }

  const stateA = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-selection-state-a'),
    authPolicyLevel: 'integrity-only',
    buildOptions: { archiveIdRandomBytes: new Uint8Array(32).fill(0xc3) },
  });
  const stateB = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-selection-state-b'),
    authPolicyLevel: 'integrity-only',
    buildOptions: { archiveIdRandomBytes: new Uint8Array(32).fill(0xc3) },
  });
  const mixedStates = [...stateA.parsed.slice(0, 4), ...stateB.parsed.slice(0, 4)];

  await assert.rejects(
    async () => restoreFromShards(mixedStates, {
      verification: { selectedArchiveId: stateA.split.archiveId },
      onLog: () => {},
      onError: () => {},
    }),
    /multiple shard cohorts/,
  );

  const selectedState = await restoreFromShards(mixedStates, {
    verification: { selectedStateId: stateB.split.stateId },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(selectedState.archiveId, stateB.split.archiveId);
    assert.equal(selectedState.stateId, stateB.split.stateId);
    assert.equal(selectedState.selectionSource, 'selected-state-id');
  } finally {
    wipeRestoreResult(selectedState);
  }

  const uploadedArchiveState = await restoreFromShards(mixedStates, {
    verification: { archiveStateBytes: stateA.split.archiveStateBytes },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(uploadedArchiveState.stateId, stateA.split.stateId);
    assert.equal(uploadedArchiveState.selectionSource, 'uploaded-archive-state');
  } finally {
    wipeRestoreResult(uploadedArchiveState);
    archiveA.pair.privateKey.fill(0);
    archiveB.pair.privateKey.fill(0);
    stateA.pair.privateKey.fill(0);
    stateB.pair.privateKey.fill(0);
  }
});

test('restore successor selection handles uploaded lifecycle bundles and mixed embedded bundle digests explicitly', async () => {
  const forkBase = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-selection-uploaded-bundle'),
    authPolicyLevel: 'integrity-only',
  });
  const successor = await reshareSameState(forkBase.parsed, { n: 5, k: 3 }, {
    transition: {
      reasonCode: 'cohort-rotation',
      operatorRole: 'operator',
      actorHints: { ceremony: 'core-uploaded-bundle' },
      performedAt: '2026-05-24T00:00:00.000Z',
    },
  });
  const successorParsed = await parseShardSet(successor);
  const forkedCandidates = [...forkBase.parsed.slice(0, 4), ...successorParsed.slice(0, 4)];

  const uploadedBundleSelected = await restoreFromShards(forkedCandidates, {
    verification: { lifecycleBundleBytes: successor.lifecycleBundleBytes },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(uploadedBundleSelected.cohortId, successor.cohortId);
    assert.equal(uploadedBundleSelected.selectionSource, 'uploaded-lifecycle-bundle');
    assert.equal(uploadedBundleSelected.lifecycleBundleSource, 'uploaded-lifecycle-bundle');
    assert.equal(uploadedBundleSelected.lifecycleVerification.cohorts.forkDetected, true);
  } finally {
    wipeRestoreResult(uploadedBundleSelected);
  }

  await assert.rejects(
    async () => restoreFromShards(forkedCandidates, {
      verification: {
        lifecycleBundleBytes: successor.lifecycleBundleBytes,
        selectedLifecycleBundleDigestHex: forkBase.split.lifecycleBundleDigestHex,
      },
      onLog: () => {},
      onError: () => {},
    }),
    /do not match selectedLifecycleBundleDigestHex/,
  );

  const mixedBundleBase = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-selection-mixed-bundle-digests'),
    authPolicyLevel: 'integrity-only',
  });
  const alternateBundle = await buildSuccessorVerificationBundle(mixedBundleBase.split, {
    authPolicyLevel: 'integrity-only',
    includeArchiveApproval: true,
    includeMaintenance: false,
    includeSourceEvidence: false,
  });
  const mixedBundleShards = mixedBundleBase.parsed.map((shard, index) => (
    index < 2
      ? {
          ...shard,
          lifecycleBundle: alternateBundle.bundle,
          lifecycleBundleBytes: alternateBundle.bundleBytes,
          lifecycleBundleDigestHex: alternateBundle.digestHex,
        }
      : shard
  ));

  await assert.rejects(
    async () => restoreFromShards(mixedBundleShards, { onLog: () => {}, onError: () => {} }),
    /multiple embedded lifecycle-bundle digests/,
  );

  const selectedDigest = await restoreFromShards(mixedBundleShards, {
    verification: { selectedLifecycleBundleDigestHex: alternateBundle.digestHex },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(selectedDigest.lifecycleBundleDigestHex, alternateBundle.digestHex);
    assert.equal(selectedDigest.lifecycleBundleSource, 'embedded-selected-lifecycle-bundle-digest');
    assert.deepEqual(
      selectedDigest.lifecycleVerification.cohorts.availableLifecycleBundleDigests,
      [mixedBundleBase.split.lifecycleBundleDigestHex, alternateBundle.digestHex].sort(),
    );
    assert.equal(selectedDigest.lifecycleVerification.cohorts.mixedLifecycleBundleVariantsWithinSelectedCohort, true);
    assert.equal(selectedDigest.authenticity.policy.satisfied, true);
  } finally {
    wipeRestoreResult(selectedDigest);
    forkBase.pair.privateKey.fill(0);
    mixedBundleBase.pair.privateKey.fill(0);
  }
});

test('OTS evidence is policy-neutral reporting for signature-required restores', async () => {
  const sample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('core-policy-ots-non-policy'),
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
  });
  const unsignedBundle = await buildSuccessorVerificationBundle(sample.split, {
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
    includeArchiveApproval: false,
    includeMaintenance: false,
    includeSourceEvidence: false,
  });
  const archiveApproval = buildQsigFixture(sample.split.archiveStateBytes);
  const otsBytes = await buildOtsFixture(archiveApproval.qsigBytes, { completeProof: true });
  const unsignedBundleShards = sample.parsed.map((shard) => ({
    ...shard,
    lifecycleBundle: unsignedBundle.bundle,
    lifecycleBundleBytes: unsignedBundle.bundleBytes,
    lifecycleBundleDigestHex: unsignedBundle.digestHex,
  }));

  const assessed = await assessRestoreFromShards(unsignedBundleShards, {
    verification: {
      signatures: [{ name: 'archive-approval.qsig', bytes: archiveApproval.qsigBytes }],
      timestamps: [{ name: 'archive-approval.complete.ots', bytes: otsBytes }],
    },
    onLog: () => {},
    onError: () => {},
  });
  try {
    assert.equal(assessed.authenticity.status.otsEvidenceLinked, true);
    assert.equal(assessed.authenticity.timestampEvidence.length, 1);
    assert.equal(assessed.authenticity.timestampEvidence[0].apparentlyComplete, true);
    assert.equal(assessed.authenticity.timestampEvidence[0].targetVerified, true);
    assert.equal(assessed.authenticity.verification.counts.validArchiveApproval, 0);
    assert.equal(assessed.authenticity.policy.level, 'any-signature');
    assert.equal(assessed.authenticity.policy.satisfied, false);
    assert.equal(assessed.authenticity.status.policySatisfied, false);
  } finally {
    wipeRestoreResult(assessed);
    sample.pair.privateKey.fill(0);
  }
});
