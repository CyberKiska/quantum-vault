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

async function parseShardSet(result) {
  return Promise.all(result.shards.map(async (item) => parseLifecycleShard(await blobToBytes(item.blob))));
}

function wipeRestoreResult(result) {
  if (result?.qencBytes instanceof Uint8Array) result.qencBytes.fill(0);
  if (result?.privKey instanceof Uint8Array) result.privKey.fill(0);
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
