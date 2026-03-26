import { sha3_512 } from '@noble/hashes/sha3.js';
import { base64ToBytes, bytesToBase64, bytesEqual, digestSha256, toHex } from '../bytes.js';
import { parseOpenTimestampProof } from '../auth/opentimestamps.js';
import { normalizePqPublicKeyPins, unpackPqpk, verifyQsigAgainstBytes } from '../auth/qsig.js';
import { computeDetachedSignatureIdentityDigestHex } from '../auth/signature-identity.js';
import { getSignatureSuiteInfo } from '../auth/signature-suites.js';
import { isSupportedStellarSignatureDocument, verifyStellarSigAgainstBytes } from '../auth/stellar-sig.js';
import {
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeLifecycleBundle,
  decodeLifecycleSignatureBytes,
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
  verifyLifecycleSignatureEntry,
} from '../lifecycle/artifacts.js';
import { rewriteLifecycleBundleInShard } from './lifecycle-shard.js';

function ensureSingleLifecycleCohort(shards) {
  const byKey = new Map();
  for (const shard of shards) {
    const key = `${shard.metaJSON.archiveId}:${shard.metaJSON.stateId}:${shard.metaJSON.cohortId}`;
    if (!byKey.has(key)) {
      byKey.set(key, {
        archiveId: shard.metaJSON.archiveId,
        stateId: shard.metaJSON.stateId,
        cohortId: shard.metaJSON.cohortId,
        archiveStateBytes: shard.archiveStateBytes,
        cohortBindingBytes: shard.cohortBindingBytes,
        lifecycleBundleVariants: new Map(),
        shards: [],
      });
    }
    const entry = byKey.get(key);
    if (!bytesEqual(entry.archiveStateBytes, shard.archiveStateBytes)) {
      throw new Error('Selected successor shards do not agree on embedded archive-state bytes');
    }
    if (!bytesEqual(entry.cohortBindingBytes, shard.cohortBindingBytes)) {
      throw new Error('Selected successor shards do not agree on embedded cohort-binding bytes');
    }
    if (!entry.lifecycleBundleVariants.has(shard.lifecycleBundleDigestHex)) {
      entry.lifecycleBundleVariants.set(shard.lifecycleBundleDigestHex, {
        digestHex: shard.lifecycleBundleDigestHex,
        bytes: shard.lifecycleBundleBytes,
      });
    } else if (!bytesEqual(entry.lifecycleBundleVariants.get(shard.lifecycleBundleDigestHex).bytes, shard.lifecycleBundleBytes)) {
      throw new Error('Selected successor shards do not agree on lifecycle-bundle bytes for one embedded digest');
    }
    entry.shards.push(shard);
  }
  if (byKey.size !== 1) {
    throw new Error('Attach requires successor shards from exactly one archive/state/cohort set.');
  }
  return [...byKey.values()][0];
}

function attachmentId(prefix, bytes) {
  return `${prefix}-${toHex(sha3_512(bytes)).slice(0, 16)}`;
}

function signatureAttachmentId(format, bytes) {
  return `sig-${computeDetachedSignatureIdentityDigestHex({
    format,
    signatureBytes: bytes,
  }).slice(0, 16)}`;
}

function detectExternalSignatureType(signature) {
  const bytes = signature?.bytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return 'unknown';
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x51 && bytes[2] === 0x53 && bytes[3] === 0x47) {
    return 'qsig';
  }
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (isSupportedStellarSignatureDocument(parsed)) {
      return 'stellar-sig';
    }
  } catch {
    // ignore
  }
  return 'unknown';
}

function pqSuiteFromSuiteId(suiteId) {
  const suiteMap = {
    0x01: 'mldsa-44',
    0x02: 'mldsa-65',
    0x03: 'mldsa-87',
    0x11: 'slhdsa-shake-128s',
    0x12: 'slhdsa-shake-192s',
    0x13: 'slhdsa-shake-256s',
    0x14: 'slhdsa-shake-256f',
  };
  const suite = suiteMap[suiteId];
  if (!suite) {
    throw new Error(`Unsupported .pqpk suite id: ${suiteId}`);
  }
  return suite;
}

function buildLifecyclePublicKeyAttachment(pin) {
  const unpacked = pin?.suiteId ? pin : unpackPqpk(pin?.bytes);
  const suite = pqSuiteFromSuiteId(unpacked.suiteId);
  const suiteInfo = getSignatureSuiteInfo(suite);
  return {
    id: attachmentId('key', new TextEncoder().encode(pin?.identityKey || `${unpacked.suiteId}:${toHex(unpacked.keyBytes)}`)),
    kty: suiteInfo.publicKeyType,
    suite,
    encoding: 'base64',
    value: bytesToBase64(unpacked.keyBytes),
  };
}

function buildLifecycleStellarSignerAttachment(signer) {
  const signerAddress = String(signer || '').trim();
  if (!signerAddress) return null;
  return {
    id: attachmentId('key', new TextEncoder().encode(signerAddress)),
    kty: 'ed25519-public-key',
    suite: 'ed25519',
    encoding: 'stellar-address',
    value: signerAddress,
  };
}

function stableStringifyForAttachmentMerge(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringifyForAttachmentMerge).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringifyForAttachmentMerge(value[k])}`).join(',')}}`;
}

/**
 * Merge lifecycle bundle attachment rows by `id`. Duplicate ids with identical content
 * are skipped; duplicate ids with differing content fail closed.
 */
export function mergeLifecycleAttachmentEntriesById(existingValues, nextValues) {
  const out = [...existingValues];
  const byId = new Map(out.map((item) => [item.id, item]));
  for (const value of nextValues) {
    if (byId.has(value.id)) {
      const prev = byId.get(value.id);
      if (stableStringifyForAttachmentMerge(prev) !== stableStringifyForAttachmentMerge(value)) {
        throw new Error(`Lifecycle attachment merge conflict: duplicate id "${value.id}" with differing content`);
      }
      continue;
    }
    out.push(value);
    byId.set(value.id, value);
  }
  return out;
}

async function assertLifecycleBundleEntriesValid(bundle, expectedEd25519Signer = '') {
  const signatureGroups = [
    ...bundle.attachments.archiveApprovalSignatures,
    ...bundle.attachments.maintenanceSignatures,
    ...bundle.attachments.sourceEvidenceSignatures,
  ];
  for (const signature of signatureGroups) {
    await verifyLifecycleSignatureEntry(bundle, signature, { expectedEd25519Signer });
  }

  const signaturesById = new Map(signatureGroups.map((signature) => [signature.id, signature]));
  for (const timestamp of bundle.attachments.timestamps) {
    const signature = signaturesById.get(timestamp.targetRef);
    if (!signature) {
      throw new Error(`attachments.timestamps targetRef is unknown: ${timestamp.targetRef}`);
    }
    const signatureBytes = decodeLifecycleSignatureBytes(signature, 'detached signature');
    const digestHex = toHex(await digestSha256(signatureBytes));
    if (timestamp.targetDigest.value !== digestHex) {
      throw new Error('attachments.timestamps targetDigest mismatch');
    }
    const parsedProof = parseOpenTimestampProof(base64ToBytes(timestamp.proof), { name: timestamp.id });
    if (parsedProof.stampedDigestHex !== digestHex) {
      throw new Error('attachments.timestamps proof digest mismatch');
    }
  }
}

function buildBundleSignaturePayloads(bundle) {
  return [
    ...bundle.attachments.archiveApprovalSignatures,
    ...bundle.attachments.maintenanceSignatures,
    ...bundle.attachments.sourceEvidenceSignatures,
  ].map((signature) => ({
    id: signature.id,
    bytes: decodeLifecycleSignatureBytes(signature, 'detached signature'),
    }));
}

async function resolveLifecycleOpenTimestampTarget({ timestampBytes, timestampName = '', signatures = [] }) {
  const parsedProof = parseOpenTimestampProof(timestampBytes, { name: timestampName });
  const matches = [];
  for (const signature of signatures) {
    if (!(signature?.bytes instanceof Uint8Array)) continue;
    if (toHex(await digestSha256(signature.bytes)) === parsedProof.stampedDigestHex) {
      matches.push(signature);
    }
  }
  if (matches.length === 0) {
    throw new Error(`OpenTimestamps proof ${timestampName || 'proof'} does not match any detached signature`);
  }
  if (matches.length > 1) {
    throw new Error(`OpenTimestamps proof ${timestampName || 'proof'} matches multiple detached signatures`);
  }
  return {
    targetRef: matches[0].id,
    stampedDigestHex: parsedProof.stampedDigestHex,
  };
}

function verifyQsigOrThrow(options, signatureName) {
  try {
    return verifyQsigAgainstBytes(options);
  } catch (error) {
    throw new Error(`${signatureName}: ${error?.message || error}`);
  }
}

async function importExternalArchiveApprovalQsig({
  archiveStateBytes,
  archiveStateDigest,
  stateId,
  signature,
  normalizedPqPins,
}) {
  let matchedKey = null;
  const successful = [];
  for (const candidatePin of normalizedPqPins) {
    const result = verifyQsigOrThrow({
      messageBytes: archiveStateBytes,
      qsigBytes: signature.bytes,
      bundlePqPublicKeyFileBytes: candidatePin.bytes,
      pinnedPqPublicKeyFileBytes: candidatePin.bytes,
    }, signature.name || 'signature.qsig');
    if (result.ok && result.signerPinned) {
      successful.push({ result, pin: candidatePin });
    }
  }

  let verified;
  if (successful.length === 1) {
    verified = successful[0].result;
    matchedKey = successful[0].pin;
  } else if (successful.length > 1) {
    throw new Error(`Multiple .pqpk files verify ${signature.name}. Keep only the intended signer key.`);
  } else {
    if (normalizedPqPins.length > 0) {
      throw new Error(`${signature.name}: no provided .pqpk file matches this detached PQ signature.`);
    }
    verified = verifyQsigOrThrow({
      messageBytes: archiveStateBytes,
      qsigBytes: signature.bytes,
      bundlePqPublicKeyFileBytes: null,
    }, signature.name || 'signature.qsig');
    if (!verified.ok) {
      throw new Error(`${signature.name}: ${verified.error}`);
    }
  }

  const publicKeyAttachment = matchedKey ? buildLifecyclePublicKeyAttachment(matchedKey) : null;
  return {
    publicKeys: publicKeyAttachment ? [publicKeyAttachment] : [],
    signature: {
      id: signatureAttachmentId('qsig', signature.bytes),
      signatureFamily: 'archive-approval',
      format: 'qsig',
      suite: verified.suite,
      targetType: 'archive-state',
      targetRef: `state:${stateId}`,
      targetDigest: archiveStateDigest,
      signatureEncoding: 'base64',
      signature: bytesToBase64(signature.bytes),
      publicKeyRef: publicKeyAttachment?.id,
    },
  };
}

async function importExternalArchiveApprovalStellarSig({
  archiveStateBytes,
  archiveStateDigest,
  stateId,
  signature,
  expectedEd25519Signer = '',
}) {
  const verified = await verifyStellarSigAgainstBytes({
    messageBytes: archiveStateBytes,
    sigJsonBytes: signature.bytes,
    expectedSigner: expectedEd25519Signer,
  });
  if (!verified.ok) {
    throw new Error(`${signature.name}: ${verified.error}`);
  }
  if (String(expectedEd25519Signer || '').trim() && verified.userPinned !== true) {
    throw new Error(`${signature.name}: signer does not match the expected pinned Stellar signer`);
  }
  const publicKeyAttachment = buildLifecycleStellarSignerAttachment(verified.signer);
  return {
    publicKeys: publicKeyAttachment ? [publicKeyAttachment] : [],
    signature: {
      id: signatureAttachmentId('stellar-sig', signature.bytes),
      signatureFamily: 'archive-approval',
      format: 'stellar-sig',
      suite: 'ed25519',
      targetType: 'archive-state',
      targetRef: `state:${stateId}`,
      targetDigest: archiveStateDigest,
      signatureEncoding: 'base64',
      signature: bytesToBase64(signature.bytes),
      publicKeyRef: publicKeyAttachment?.id,
    },
  };
}

async function resolveLifecycleAttachContext(shards, options = {}) {
  const prepared = Array.isArray(shards)
    ? shards.map((shard, index) => {
        if (shard?.diagnostics?.errors?.length) {
          throw new Error(`Successor shard parse failed at input index ${index}: ${shard.diagnostics.errors.join('; ')}`);
        }
        if (!(shard?.archiveStateBytes instanceof Uint8Array) || !(shard?.cohortBindingBytes instanceof Uint8Array)) {
          throw new Error(`Attach requires successor lifecycle shards; input index ${index} is not a successor shard`);
        }
        return shard;
      })
    : [];

  if (prepared.length > 0) {
    const cohort = ensureSingleLifecycleCohort(prepared);
    const embeddedArchiveState = parseArchiveStateDescriptorBytes(cohort.archiveStateBytes);
    const explicitArchiveStateBytes = options.archiveStateBytes instanceof Uint8Array
      ? parseArchiveStateDescriptorBytes(options.archiveStateBytes).bytes
      : null;
    if (explicitArchiveStateBytes && !bytesEqual(explicitArchiveStateBytes, embeddedArchiveState.bytes)) {
      throw new Error('Provided archive-state descriptor does not match the selected successor shard set');
    }

    let workingBundle;
    let lifecycleBundleBytes;
    if (options.lifecycleBundleBytes instanceof Uint8Array) {
      const parsedBundle = await parseLifecycleBundleBytes(options.lifecycleBundleBytes);
      if (parsedBundle.lifecycleBundle.archiveStateDigest.value !== embeddedArchiveState.digest.value) {
        throw new Error('Provided lifecycle bundle does not match the selected archive-state digest');
      }
      const canonicalCohortBinding = canonicalizeCohortBinding(prepared[0].cohortBinding);
      if (parsedBundle.lifecycleBundle.currentCohortBindingDigest.value !== canonicalCohortBinding.digest.value) {
        throw new Error('Provided lifecycle bundle does not match the selected cohort-binding digest');
      }
      if (!bytesEqual(canonicalizeArchiveStateDescriptor(parsedBundle.lifecycleBundle.archiveState).bytes, embeddedArchiveState.bytes)) {
        throw new Error('Provided lifecycle bundle does not match the selected archive-state bytes');
      }
      if (!bytesEqual(canonicalizeCohortBinding(parsedBundle.lifecycleBundle.currentCohortBinding).bytes, cohort.cohortBindingBytes)) {
        throw new Error('Provided lifecycle bundle does not match the selected cohort-binding bytes');
      }
      workingBundle = parsedBundle.lifecycleBundle;
      lifecycleBundleBytes = parsedBundle.bytes;
    } else if (cohort.lifecycleBundleVariants.size === 1) {
      const variant = [...cohort.lifecycleBundleVariants.values()][0];
      const parsedBundle = await parseLifecycleBundleBytes(variant.bytes);
      workingBundle = parsedBundle.lifecycleBundle;
      lifecycleBundleBytes = parsedBundle.bytes;
    } else {
      throw new Error(
        'Selected successor shards contain multiple embedded lifecycle-bundle digests. Provide explicit lifecycle-bundle bytes to choose one fail closed.'
      );
    }

    return {
      preparedShards: prepared,
      archiveState: embeddedArchiveState.archiveState,
      archiveStateBytes: embeddedArchiveState.bytes,
      archiveStateDigest: embeddedArchiveState.digest,
      stateId: embeddedArchiveState.stateId,
      cohortBinding: prepared[0].cohortBinding,
      cohortBindingBytes: cohort.cohortBindingBytes,
      lifecycleBundle: workingBundle,
      lifecycleBundleBytes,
      embeddedLifecycleBundleDigests: [...cohort.lifecycleBundleVariants.keys()].sort(),
    };
  }

  if (options.lifecycleBundleBytes instanceof Uint8Array) {
    const parsedBundle = await parseLifecycleBundleBytes(options.lifecycleBundleBytes);
    const canonicalArchiveState = canonicalizeArchiveStateDescriptor(parsedBundle.lifecycleBundle.archiveState);
    if (options.archiveStateBytes instanceof Uint8Array) {
      const explicitArchiveState = parseArchiveStateDescriptorBytes(options.archiveStateBytes);
      if (!bytesEqual(explicitArchiveState.bytes, canonicalArchiveState.bytes)) {
        throw new Error('Provided archive-state descriptor does not match the provided lifecycle bundle');
      }
    }
    const canonicalCohortBinding = canonicalizeCohortBinding(parsedBundle.lifecycleBundle.currentCohortBinding);
    return {
      preparedShards: [],
      archiveState: parsedBundle.lifecycleBundle.archiveState,
      archiveStateBytes: canonicalArchiveState.bytes,
      archiveStateDigest: canonicalArchiveState.digest,
      stateId: canonicalArchiveState.stateId,
      cohortBinding: parsedBundle.lifecycleBundle.currentCohortBinding,
      cohortBindingBytes: canonicalCohortBinding.bytes,
      lifecycleBundle: parsedBundle.lifecycleBundle,
      lifecycleBundleBytes: parsedBundle.bytes,
      embeddedLifecycleBundleDigests: [parsedBundle.digest.value],
    };
  }

  throw new Error('No successor lifecycle shards or lifecycle bundle were provided for attach.');
}

export async function attachLifecycleBundleToShards(shards, options = {}) {
  const expectedEd25519Signer = String(options.expectedEd25519Signer || '').trim();
  const {
    preparedShards,
    archiveStateBytes,
    archiveStateDigest,
    stateId,
    cohortBindingBytes,
    lifecycleBundle,
    embeddedLifecycleBundleDigests,
  } = await resolveLifecycleAttachContext(shards, options);

  await assertLifecycleBundleEntriesValid(lifecycleBundle, expectedEd25519Signer);

  const pqPublicKeyFileBytesList = Array.isArray(options.pqPublicKeyFileBytesList)
    ? options.pqPublicKeyFileBytesList.filter((item) => item instanceof Uint8Array)
    : [];
  const normalizedPqPins = normalizePqPublicKeyPins({
    pinnedPqPublicKeyFileBytesList: pqPublicKeyFileBytesList,
    invalidBehavior: 'throw',
    invalidLabel: 'Pinned PQ signer key',
  }).pins;

  const externalSignatures = Array.isArray(options.signatures) ? options.signatures : [];
  const importedPublicKeys = [];
  const importedArchiveApprovalSignatures = [];
  for (const signature of externalSignatures) {
    const type = detectExternalSignatureType(signature);
    if (type === 'qsig') {
      const imported = await importExternalArchiveApprovalQsig({
        archiveStateBytes,
        archiveStateDigest,
        stateId,
        signature,
        normalizedPqPins,
      });
      importedPublicKeys.push(...imported.publicKeys);
      importedArchiveApprovalSignatures.push(imported.signature);
      continue;
    }
    if (type === 'stellar-sig') {
      const imported = await importExternalArchiveApprovalStellarSig({
        archiveStateBytes,
        archiveStateDigest,
        stateId,
        signature,
        expectedEd25519Signer,
      });
      importedPublicKeys.push(...imported.publicKeys);
      importedArchiveApprovalSignatures.push(imported.signature);
      continue;
    }
    throw new Error(`Unsupported signature file: ${signature?.name || 'unknown'}`);
  }

  const mergedBundle = {
    ...lifecycleBundle,
    attachments: {
      publicKeys: mergeLifecycleAttachmentEntriesById(lifecycleBundle.attachments.publicKeys, importedPublicKeys),
      archiveApprovalSignatures: mergeLifecycleAttachmentEntriesById(
        lifecycleBundle.attachments.archiveApprovalSignatures,
        importedArchiveApprovalSignatures
      ),
      maintenanceSignatures: [...lifecycleBundle.attachments.maintenanceSignatures],
      sourceEvidenceSignatures: [...lifecycleBundle.attachments.sourceEvidenceSignatures],
      timestamps: [...lifecycleBundle.attachments.timestamps],
    },
  };

  const timestampFiles = Array.isArray(options.timestamps) ? options.timestamps : [];
  if (timestampFiles.length > 0) {
    const signaturePayloads = buildBundleSignaturePayloads(mergedBundle);
    const importedTimestamps = await Promise.all(timestampFiles.map(async (timestamp) => {
      if (!(timestamp?.bytes instanceof Uint8Array) || timestamp.bytes.length === 0) {
        throw new Error(`Invalid timestamp file: ${timestamp?.name || 'unknown'}`);
      }
      const resolved = await resolveLifecycleOpenTimestampTarget({
        timestampBytes: timestamp.bytes,
        timestampName: timestamp.name,
        signatures: signaturePayloads,
      });
      return {
        id: attachmentId('ots', timestamp.bytes),
        type: 'opentimestamps',
        targetRef: resolved.targetRef,
        targetDigest: {
          alg: 'SHA-256',
          value: resolved.stampedDigestHex,
        },
        proofEncoding: 'base64',
        proof: bytesToBase64(timestamp.bytes),
      };
    }));
    mergedBundle.attachments.timestamps = mergeLifecycleAttachmentEntriesById(mergedBundle.attachments.timestamps, importedTimestamps);
  }

  const canonicalBundle = await canonicalizeLifecycleBundle(mergedBundle);
  await assertLifecycleBundleEntriesValid(canonicalBundle.lifecycleBundle, expectedEd25519Signer);

  const canonicalArchiveState = canonicalizeArchiveStateDescriptor(canonicalBundle.lifecycleBundle.archiveState);
  if (!bytesEqual(canonicalArchiveState.bytes, archiveStateBytes)) {
    throw new Error('Attach changed the archive-state descriptor bytes, which is forbidden');
  }
  const canonicalCurrentCohortBinding = canonicalizeCohortBinding(canonicalBundle.lifecycleBundle.currentCohortBinding);
  if (!bytesEqual(canonicalCurrentCohortBinding.bytes, cohortBindingBytes)) {
    throw new Error('Attach changed the cohort-binding bytes, which is forbidden');
  }

  const embedIntoShards = options.embedIntoShards !== false;
  const updatedShards = embedIntoShards
    ? preparedShards.map((shard) => rewriteLifecycleBundleInShard(shard, canonicalBundle.bytes))
    : [];

  return {
    shards: updatedShards,
    archiveState: canonicalBundle.lifecycleBundle.archiveState,
    archiveStateBytes,
    archiveStateDigestHex: archiveStateDigest.value,
    stateId,
    cohortBinding: canonicalBundle.lifecycleBundle.currentCohortBinding,
    cohortBindingBytes,
    cohortBindingDigestHex: canonicalCurrentCohortBinding.digest.value,
    lifecycleBundle: canonicalBundle.lifecycleBundle,
    lifecycleBundleBytes: canonicalBundle.bytes,
    lifecycleBundleDigestHex: canonicalBundle.digest.value,
    signableArchiveStateBytes: archiveStateBytes,
    embeddedLifecycleBundleDigests,
    mixedEmbeddedLifecycleBundleDigests: embeddedLifecycleBundleDigests.length > 1,
  };
}
