import {
  blobToBytes,
  buildOtsFixture,
  buildQsigFixture,
  buildSuccessorRestoreSample,
  buildSuccessorVerificationBundle,
  ensureErasureRuntime,
  ensureRuntimeCrypto,
  textBytes,
} from '../../../src/core/crypto/selftest.js';
import {
  buildSourceEvidence,
  canonicalizeLifecycleBundle,
  canonicalizeSourceEvidence,
  canonicalizeTransitionRecord,
} from '../../../src/core/crypto/lifecycle/artifacts.js';
import {
  reshareSameState,
  rewriteLifecycleBundleInShard,
} from '../../../src/core/crypto/qcont/lifecycle-shard.js';

function filePayload(name, bytes, mimeType = 'application/octet-stream') {
  return {
    name,
    mimeType,
    buffer: Buffer.from(bytes),
  };
}

async function shardPayloads(shards, prefix) {
  return Promise.all(shards.map(async (item, index) => (
    filePayload(`${prefix}-${index + 1}.qcont`, await blobToBytes(item.blob))
  )));
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

let cachedFixtureSetPromise = null;

async function buildBrowserFixtureSet() {
  await ensureRuntimeCrypto();
  await ensureErasureRuntime();

  const strongPolicySample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-strong-pq'),
    authPolicyLevel: 'strong-pq-signature',
    minValidSignatures: 1,
  });
  const strongPolicySignature = buildQsigFixture(strongPolicySample.split.archiveStateBytes);

  const buildFlowSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-build-flow'),
    authPolicyLevel: 'integrity-only',
  });

  const selfSignedSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-self-signed'),
    authPolicyLevel: 'any-signature',
    minValidSignatures: 1,
  });
  const selfSignedArchiveApproval = buildQsigFixture(selfSignedSample.split.archiveStateBytes);

  const ambiguousSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-ambiguous-cohort'),
    authPolicyLevel: 'integrity-only',
  });
  const reshared = await reshareSameState(ambiguousSample.parsed, { n: 5, k: 3 }, {
    transition: {
      reasonCode: 'cohort-rotation',
      operatorRole: 'operator',
      actorHints: { ceremony: 'browser-qa' },
      performedAt: '2026-04-19T00:00:00.000Z',
    },
  });

  const mixedBundleSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-mixed-bundle'),
    authPolicyLevel: 'integrity-only',
  });
  const alternateBundle = await buildSuccessorVerificationBundle(mixedBundleSample.split, {
    authPolicyLevel: 'integrity-only',
    includeArchiveApproval: true,
    includeMaintenance: false,
    includeSourceEvidence: false,
  });
  const mixedBundleShards = mixedBundleSample.parsed.map((shard, index) => (
    index < 2
      ? rewriteLifecycleBundleInShard(shard, alternateBundle.bundleBytes)
      : mixedBundleSample.split.shards[index]
  ));

  const attachSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-attach-ots'),
    authPolicyLevel: 'integrity-only',
  });
  const attachArchiveApproval = buildQsigFixture(attachSample.split.archiveStateBytes);
  const wrongOts = await buildOtsFixture(textBytes('browser-qa-wrong-ots-target'), { completeProof: true });

  const reshareExportSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-reshare-export'),
    authPolicyLevel: 'integrity-only',
  });

  const maintenanceAttachSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-maintenance-attach'),
    authPolicyLevel: 'integrity-only',
  });
  const maintenanceAttachBundle = await buildSuccessorVerificationBundle(maintenanceAttachSample.split, {
    authPolicyLevel: 'integrity-only',
    includeArchiveApproval: false,
    includeMaintenance: false,
    includeSourceEvidence: false,
    timestampTargetFamily: 'maintenance',
  });
  const unsignedMaintenanceBundle = cloneJson(maintenanceAttachBundle.bundle);
  unsignedMaintenanceBundle.attachments.publicKeys = [];
  unsignedMaintenanceBundle.attachments.maintenanceSignatures = [];
  unsignedMaintenanceBundle.attachments.timestamps = [];
  const unsignedMaintenanceBundleCanonical = await canonicalizeLifecycleBundle(unsignedMaintenanceBundle);
  const maintenanceTransitionRecordCanonical = canonicalizeTransitionRecord(maintenanceAttachBundle.transitionRecord);
  const maintenanceWrongTargetSignature = buildQsigFixture(maintenanceAttachSample.split.archiveStateBytes);

  const sourceEvidenceAttachSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-source-evidence-attach'),
    authPolicyLevel: 'integrity-only',
  });
  const wrongTargetSourceEvidence = canonicalizeSourceEvidence(buildSourceEvidence({
    relationType: 'supports',
    sourceObjectType: 'archive-state-descriptor',
    sourceDigests: [{ alg: 'SHA3-512', value: 'cd'.repeat(64) }],
    externalSourceSignatureRefs: ['sig:wrong-target-review'],
  }));
  const sourceEvidenceWrongTargetSignature = buildQsigFixture(sourceEvidenceAttachSample.split.archiveStateBytes);

  const archiveApprovalAttachSample = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-archive-approval-attach'),
    authPolicyLevel: 'strong-pq-signature',
    minValidSignatures: 1,
  });
  const archiveApprovalAttachSignature = buildQsigFixture(archiveApprovalAttachSample.split.archiveStateBytes);

  const lifecycleMismatchA = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-lifecycle-mismatch-a'),
    authPolicyLevel: 'integrity-only',
  });
  const lifecycleMismatchB = await buildSuccessorRestoreSample({
    payloadBytes: textBytes('browser-qa-lifecycle-mismatch-b'),
    authPolicyLevel: 'integrity-only',
  });

  return {
    buildFlowFiles: [
      filePayload('browser-build-flow.qenc', buildFlowSample.qencBytes),
      filePayload('browser-build-flow.private.qkey', buildFlowSample.pair.privateKey),
    ],
    strongPolicyFailFiles: await shardPayloads(strongPolicySample.split.shards, 'strong-pq'),
    strongPolicySatisfiedFiles: [
      ...(await shardPayloads(strongPolicySample.split.shards, 'strong-pq')),
      filePayload('strong-pq-archive.qsig', strongPolicySignature.qsigBytes),
      filePayload('strong-pq-archive.pqpk', strongPolicySignature.pqpkBytes),
    ],
    selfSignedFiles: [
      ...(await shardPayloads(selfSignedSample.split.shards, 'self-signed')),
      filePayload('self-signed-archive.qsig', selfSignedArchiveApproval.qsigBytes),
    ],
    ambiguousCohortFiles: [
      ...(await shardPayloads(ambiguousSample.split.shards, 'ambiguous-a')),
      ...(await shardPayloads(reshared.shards, 'ambiguous-b')),
    ],
    mixedBundleFiles: await shardPayloads(mixedBundleShards, 'mixed-bundle'),
    mixedBundleDigestHex: alternateBundle.digestHex,
    legacyManifestFiles: [
      filePayload(
        'archive.qvmanifest.json',
        textBytes('{"schema":"quantum-vault-archive-manifest/v3","version":3}'),
        'application/json'
      ),
    ],
    attachWrongOtsFiles: [
      ...(await shardPayloads(attachSample.split.shards, 'attach-ots')),
      filePayload('attach-archive.qsig', attachArchiveApproval.qsigBytes),
      filePayload('attach-archive.pqpk', attachArchiveApproval.pqpkBytes),
      filePayload('attach-archive.ots', wrongOts),
    ],
    archiveApprovalAttachBaseFiles: [
      filePayload('archive-approval-base.lifecycle-bundle.json', archiveApprovalAttachSample.split.lifecycleBundleBytes, 'application/json'),
      filePayload('archive-approval.qsig', archiveApprovalAttachSignature.qsigBytes),
      filePayload('archive-approval.pqpk', archiveApprovalAttachSignature.pqpkBytes),
    ],
    archiveApprovalAttachRestoreShardFiles: await shardPayloads(archiveApprovalAttachSample.split.shards, 'archive-approval-restore'),
    reshareExportFiles: await shardPayloads(reshareExportSample.split.shards, 'reshare-export'),
    maintenanceAttachBaseFiles: [
      filePayload('maintenance-base.lifecycle-bundle.json', unsignedMaintenanceBundleCanonical.bytes, 'application/json'),
      filePayload('maintenance-base.transition-record.json', maintenanceTransitionRecordCanonical.bytes, 'application/json'),
    ],
    maintenanceAttachSignatureFiles: [
      filePayload('maintenance.qsig', maintenanceAttachBundle.fixtures.maintenance.qsigBytes),
      filePayload('maintenance.pqpk', maintenanceAttachBundle.fixtures.maintenance.pqpkBytes),
    ],
    maintenanceWrongTargetFiles: [
      filePayload('maintenance-base.lifecycle-bundle.json', unsignedMaintenanceBundleCanonical.bytes, 'application/json'),
      filePayload('maintenance-base.transition-record.json', maintenanceTransitionRecordCanonical.bytes, 'application/json'),
      filePayload('wrong-maintenance-target.qsig', maintenanceWrongTargetSignature.qsigBytes),
      filePayload('wrong-maintenance-target.pqpk', maintenanceWrongTargetSignature.pqpkBytes),
    ],
    maintenanceRestoreShardFiles: await shardPayloads(maintenanceAttachSample.split.shards, 'maintenance-restore'),
    sourceEvidenceAttachBaseFiles: [
      filePayload('source-evidence-base.lifecycle-bundle.json', sourceEvidenceAttachSample.split.lifecycleBundleBytes, 'application/json'),
    ],
    sourceEvidenceWrongTargetFiles: [
      filePayload('source-evidence-base.lifecycle-bundle.json', sourceEvidenceAttachSample.split.lifecycleBundleBytes, 'application/json'),
      filePayload('wrong-target.source-evidence.json', wrongTargetSourceEvidence.bytes, 'application/json'),
      filePayload('wrong-source-evidence-target.qsig', sourceEvidenceWrongTargetSignature.qsigBytes),
      filePayload('wrong-source-evidence-target.pqpk', sourceEvidenceWrongTargetSignature.pqpkBytes),
    ],
    sourceEvidenceRestoreShardFiles: await shardPayloads(sourceEvidenceAttachSample.split.shards, 'source-evidence-restore'),
    lifecycleBundleMismatchFiles: [
      ...(await shardPayloads(lifecycleMismatchA.split.shards, 'lifecycle-mismatch-a')),
      filePayload('wrong.lifecycle-bundle.json', lifecycleMismatchB.split.lifecycleBundleBytes, 'application/json'),
    ],
  };
}

export async function getBrowserFixtureSet() {
  if (!cachedFixtureSetPromise) {
    cachedFixtureSetPromise = buildBrowserFixtureSet();
  }
  return cachedFixtureSetPromise;
}
