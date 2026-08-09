import assert from 'node:assert/strict';
import test from 'node:test';
import {
  blobToBytes,
  buildOtsFixture,
  buildQsigFixture,
  buildSuccessorRestoreSample,
  ensureErasureRuntime,
  ensureRuntimeCrypto,
  textBytes,
} from '../../src/core/crypto/selftest.js';
import { digestSha256, toHex } from '../../src/core/crypto/bytes.js';
import {
  dedupeTimestampEvidenceForPresentation,
  inspectLifecycleTimestampEvidence,
  parseOpenTimestampProof,
  resolveOpenTimestampTarget,
} from '../../src/core/crypto/auth/opentimestamps.js';
import { assessRestoreFromShards } from '../../src/core/crypto/qcont/restore.js';

function wipeRestoreResult(result) {
  if (result?.qencBytes instanceof Uint8Array) result.qencBytes.fill(0);
  if (result?.privKey instanceof Uint8Array) result.privKey.fill(0);
}

test.before(async () => {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();
});

test('shipped OTS presentation dedupe prefers completion then embedded linkage', () => {
  const rows = [
    { id: 'external-incomplete', stampedDigestHex: 'aa', apparentlyComplete: false, linkLabel: 'External OTS evidence linked to signature' },
    { id: 'external-complete', stampedDigestHex: 'aa', apparentlyComplete: true, linkLabel: 'External OTS evidence linked to signature' },
    { id: 'embedded-complete', stampedDigestHex: 'aa', apparentlyComplete: true, linkLabel: 'OTS evidence linked to signature' },
    { id: 'other', stampedDigestHex: 'bb', apparentlyComplete: false, linkLabel: 'OTS evidence linked to signature' },
  ];
  assert.deepEqual(
    dedupeTimestampEvidenceForPresentation(rows).map((entry) => entry.id),
    ['embedded-complete', 'other'],
  );
});

test('OpenTimestamps parser reports SHA-256 target digest and apparent completion only', async () => {
  const signature = buildQsigFixture(textBytes('ots-parser-reporting'));
  const completeProof = await buildOtsFixture(signature.qsigBytes, { completeProof: true });
  const incompleteProof = await buildOtsFixture(signature.qsigBytes, { completeProof: false });
  const stampedDigestHex = toHex(await digestSha256(signature.qsigBytes));

  const complete = parseOpenTimestampProof(completeProof, { name: 'archive.complete.ots' });
  assert.equal(complete.stampedDigestHex, stampedDigestHex);
  assert.equal(complete.appearsComplete, true);
  assert.equal(complete.completeProof, true);

  const incomplete = parseOpenTimestampProof(incompleteProof, { name: 'archive.pending.ots' });
  assert.equal(incomplete.stampedDigestHex, stampedDigestHex);
  assert.equal(incomplete.appearsComplete, false);
  assert.equal(incomplete.completeProof, false);
});

test('OpenTimestamps target resolution is bound to exact detached signature bytes, not cached digest fields', async () => {
  const signature = buildQsigFixture(textBytes('ots-exact-byte-binding'));
  const timestampBytes = await buildOtsFixture(signature.qsigBytes, { completeProof: true });
  const staleCachedDigestHex = toHex(await digestSha256(textBytes('stale-ots-cache')));

  const resolved = await resolveOpenTimestampTarget({
    timestampBytes,
    timestampName: 'archive.qsig.ots',
    signatures: [{
      id: 'sig:external-1',
      name: 'archive.qsig',
      source: 'external',
      ok: true,
      bytes: signature.qsigBytes,
      otsStampedDigestHex: staleCachedDigestHex,
    }],
  });

  assert.equal(resolved.linked, true);
  assert.equal(resolved.targetRef, 'sig:external-1');
  assert.equal(resolved.targetSource, 'external');
  assert.equal(resolved.targetVerified, true);
  assert.equal(resolved.stampedDigestHex, toHex(await digestSha256(signature.qsigBytes)));

  await assert.rejects(
    async () => resolveOpenTimestampTarget({
      timestampBytes,
      timestampName: 'archive.qsig.ots',
      signatures: [{
        id: 'sig:wrong-bytes',
        name: 'wrong.qsig',
        source: 'external',
        ok: true,
        bytes: textBytes('not-the-detached-signature'),
        otsStampedDigestHex: resolved.stampedDigestHex,
      }],
    }),
    /does not match any detached signature/,
  );
});

test('OpenTimestamps target resolution rejects zero and ambiguous detached signature matches', async () => {
  const signature = buildQsigFixture(textBytes('ots-match-cardinality'));
  const otherSignature = buildQsigFixture(textBytes('ots-other-signature'));
  const timestampBytes = await buildOtsFixture(signature.qsigBytes, { completeProof: false });

  await assert.rejects(
    async () => resolveOpenTimestampTarget({
      timestampBytes,
      timestampName: 'archive.qsig.ots',
      signatures: [{
        id: 'sig:other',
        name: 'other.qsig',
        source: 'external',
        ok: true,
        bytes: otherSignature.qsigBytes,
      }],
    }),
    /does not match any detached signature/,
  );

  await assert.rejects(
    async () => resolveOpenTimestampTarget({
      timestampBytes,
      timestampName: 'archive.qsig.ots',
      signatures: [
        {
          id: 'sig:one',
          name: 'one.qsig',
          source: 'external',
          ok: true,
          bytes: signature.qsigBytes,
          signatureContentDigestHex: '11'.repeat(64),
        },
        {
          id: 'sig:two',
          name: 'two.qsig',
          source: 'external',
          ok: true,
          bytes: signature.qsigBytes,
          signatureContentDigestHex: '22'.repeat(64),
        },
      ],
    }),
    /matches multiple detached signatures/,
  );
});

test('OpenTimestamps target resolution rejects a declared digest that differs from proof and signature bytes', async () => {
  const signature = buildQsigFixture(textBytes('ots-declared-target-digest'));
  const timestampBytes = await buildOtsFixture(signature.qsigBytes, { completeProof: true });

  await assert.rejects(
    async () => resolveOpenTimestampTarget({
      timestampBytes,
      timestampName: 'archive.qsig.ots',
      declaredTargetDigest: { alg: 'SHA-256', value: '00'.repeat(32) },
      signatures: [{
        id: 'sig:archive',
        name: 'archive.qsig',
        source: 'bundle',
        ok: true,
        bytes: signature.qsigBytes,
      }],
    }),
    /does not match its declared targetDigest/,
  );
});

test('OpenTimestamps reporting preserves linkage fields while ignoring stale cached signature digests', async () => {
  const signature = buildQsigFixture(textBytes('ots-reporting-cache-ignore'));
  const timestampBytes = await buildOtsFixture(signature.qsigBytes, { completeProof: false });
  const staleCachedDigestHex = toHex(await digestSha256(textBytes('stale-reporting-cache')));

  const evidence = await inspectLifecycleTimestampEvidence({
    bundle: {},
    externalTimestamps: [{ name: 'archive.qsig.ots', bytes: timestampBytes }],
    signatureArtifacts: [{
      id: 'sig:external-1',
      name: 'archive.qsig',
      source: 'external',
      ok: true,
      bytes: signature.qsigBytes,
      otsStampedDigestHex: staleCachedDigestHex,
    }],
  });

  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].targetRef, 'sig:external-1');
  assert.equal(evidence[0].targetName, 'archive.qsig');
  assert.equal(evidence[0].targetSource, 'external');
  assert.equal(evidence[0].targetVerified, true);
  assert.equal(evidence[0].apparentlyComplete, false);
  assert.equal(evidence[0].completeProof, false);
  assert.equal(evidence[0].stampedDigestHex, toHex(await digestSha256(signature.qsigBytes)));
});

test('complete-looking OTS evidence never satisfies any-signature or strong-pq-signature archive policy', async () => {
  for (const authPolicyLevel of ['any-signature', 'strong-pq-signature']) {
    const sample = await buildSuccessorRestoreSample({
      payloadBytes: textBytes(`ots-non-policy-${authPolicyLevel}`),
      authPolicyLevel,
      minValidSignatures: 1,
    });
    const archiveApproval = buildQsigFixture(sample.split.archiveStateBytes);
    const timestampBytes = await buildOtsFixture(archiveApproval.qsigBytes, { completeProof: true });

    const assessed = await assessRestoreFromShards(sample.parsed, {
      verification: {
        signatures: [{ name: 'archive-approval.qsig', bytes: archiveApproval.qsigBytes }],
        timestamps: [{ name: 'archive-approval.complete.ots', bytes: timestampBytes }],
      },
      onLog: () => {},
      onError: () => {},
    });

    try {
      assert.equal(assessed.authenticity.policy.level, authPolicyLevel);
      assert.equal(assessed.authenticity.status.otsEvidenceLinked, true);
      assert.equal(assessed.authenticity.timestampEvidence.length, 1);
      assert.equal(assessed.authenticity.timestampEvidence[0].apparentlyComplete, true);
      assert.equal(assessed.authenticity.verification.counts.validArchiveApproval, 0);
      assert.equal(assessed.authenticity.verification.counts.validArchiveApprovalStrongPq, 0);
      assert.equal(assessed.authenticity.status.archiveApprovalSignatureVerified, false);
      assert.equal(assessed.authenticity.status.strongPqSignatureVerified, false);
      assert.equal(assessed.authenticity.policy.satisfied, false);
      assert.equal(assessed.authenticity.status.policySatisfied, false);
    } finally {
      wipeRestoreResult(assessed);
      sample.pair.privateKey.fill(0);
      for (const shard of sample.parsed) {
        if (shard?.share instanceof Uint8Array) shard.share.fill(0);
      }
      for (const shard of sample.split.shards) {
        const bytes = await blobToBytes(shard.blob);
        bytes.fill(0);
      }
    }
  }
});
