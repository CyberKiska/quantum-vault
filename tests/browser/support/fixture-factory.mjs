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

  return {
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
  };
}

export async function getBrowserFixtureSet() {
  if (!cachedFixtureSetPromise) {
    cachedFixtureSetPromise = buildBrowserFixtureSet();
  }
  return cachedFixtureSetPromise;
}
