import { sha3_512 } from '@noble/hashes/sha3.js';
import { base64ToBytes, bytesToBase64, bytesEqual, toHex } from '../bytes.js';
import { parseArchiveManifestBytes } from '../manifest/archive-manifest.js';
import {
  buildInitialManifestBundle,
  canonicalizeManifestBundle,
  parseManifestBundleBytes,
  recoverCommittedAuthPolicy,
} from '../manifest/manifest-bundle.js';
import { verifyManifestSignatures } from '../auth/verify-signatures.js';
import {
  assertManifestBundleTimestamps,
  decodeBundleSignatureBytes,
  resolveOpenTimestampTarget,
} from '../auth/opentimestamps.js';
import { normalizePqPublicKeyPins, verifyQsigAgainstBytes, unpackPqpk } from '../auth/qsig.js';
import { computeDetachedSignatureIdentityDigestHex } from '../auth/signature-identity.js';
import { isSupportedStellarSignatureDocument, verifyStellarSigAgainstBytes } from '../auth/stellar-sig.js';
import { getSignatureSuiteInfo } from '../auth/signature-suites.js';
import { buildShardBlob } from './build.js';

function ensureSingleCohort(shards) {
  const byKey = new Map();
  for (const shard of shards) {
    const key = `${shard.manifestDigestHex}:${shard.bundleDigestHex}`;
    if (!byKey.has(key)) {
      byKey.set(key, {
        manifestDigestHex: shard.manifestDigestHex,
        bundleDigestHex: shard.bundleDigestHex,
        manifestBytes: shard.manifestBytes,
        bundleBytes: shard.bundleBytes,
        shards: [],
      });
    }
    const entry = byKey.get(key);
    if (!bytesEqual(entry.manifestBytes, shard.manifestBytes) || !bytesEqual(entry.bundleBytes, shard.bundleBytes)) {
      throw new Error('Selected shards do not agree on embedded manifest/bundle bytes');
    }
    entry.shards.push(shard);
  }
  if (byKey.size !== 1) {
    throw new Error('Attach requires shards from exactly one archive cohort.');
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

function buildPublicKeyAttachment(pin) {
  const pqpkBytes = pin?.bytes;
  const unpacked = pin?.suiteId
    ? pin
    : unpackPqpk(pqpkBytes);
  const suiteMap = {
    0x01: 'mldsa-44',
    0x02: 'mldsa-65',
    0x03: 'mldsa-87',
    0x11: 'slhdsa-shake-128s',
    0x12: 'slhdsa-shake-192s',
    0x13: 'slhdsa-shake-256s',
    0x14: 'slhdsa-shake-256f',
  };
  const suite = suiteMap[unpacked.suiteId];
  if (!suite) {
    throw new Error(`Unsupported .pqpk suite id: ${unpacked.suiteId}`);
  }
  const suiteInfo = getSignatureSuiteInfo(suite);
  return {
    id: attachmentId('key', new TextEncoder().encode(pin?.identityKey || `${unpacked.suiteId}:${toHex(unpacked.keyBytes)}`)),
    kty: suiteInfo.publicKeyType,
    suite,
    encoding: 'base64',
    value: bytesToBase64(pqpkBytes),
    legacy: false,
  };
}

function buildStellarSignerAttachment(signer) {
  const signerAddress = String(signer || '').trim();
  if (!signerAddress) return null;
  return {
    id: attachmentId('key', new TextEncoder().encode(signerAddress)),
    kty: 'ed25519-public-key',
    suite: 'ed25519',
    encoding: 'stellar-address',
    value: signerAddress,
    legacy: false,
  };
}

function mergeById(existingValues, nextValues) {
  const out = [...existingValues];
  const seen = new Set(existingValues.map((item) => item.id));
  for (const value of nextValues) {
    if (seen.has(value.id)) continue;
    out.push(value);
    seen.add(value.id);
  }
  return out;
}

function buildBundleSignaturePayloads(signatures) {
  return signatures.map((signature) => ({
    id: signature.id,
    suite: signature.suite,
    bytes: decodeBundleSignatureBytes(signature),
  }));
}

function verifyQsigOrThrow(options, signatureName) {
  try {
    return verifyQsigAgainstBytes(options);
  } catch (error) {
    throw new Error(`${signatureName}: ${error?.message || error}`);
  }
}

async function importExternalQsig({ manifestBytes, signature, normalizedPqPins }) {
  let matchedKey = null;
  const successful = [];
  for (const candidatePin of normalizedPqPins) {
    const result = verifyQsigOrThrow({
      messageBytes: manifestBytes,
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
      messageBytes: manifestBytes,
      qsigBytes: signature.bytes,
      bundlePqPublicKeyFileBytes: null,
    }, signature.name || 'signature.qsig');
    if (!verified.ok) {
      throw new Error(`${signature.name}: ${verified.error}`);
    }
  }

  const publicKeyAttachment = matchedKey ? buildPublicKeyAttachment(matchedKey) : null;
  return {
    publicKeys: publicKeyAttachment ? [publicKeyAttachment] : [],
    signature: {
      id: signatureAttachmentId('qsig', signature.bytes),
      format: 'qsig',
      suite: verified.suite,
      target: {
        type: 'canonical-manifest',
        digestAlg: 'SHA3-512',
        digestValue: toHex(sha3_512(manifestBytes)),
      },
      signatureEncoding: 'base64',
      signature: bytesToBase64(signature.bytes),
      publicKeyRef: publicKeyAttachment?.id || null,
      legacy: false,
    },
  };
}

async function importExternalStellarSig({ manifestBytes, signature, expectedEd25519Signer }) {
  const verified = await verifyStellarSigAgainstBytes({
    messageBytes: manifestBytes,
    sigJsonBytes: signature.bytes,
    expectedSigner: expectedEd25519Signer,
  });
  if (!verified.ok) {
    throw new Error(`${signature.name}: ${verified.error}`);
  }
  if (String(expectedEd25519Signer || '').trim() && verified.userPinned !== true) {
    throw new Error(`${signature.name}: signer does not match the expected pinned Stellar signer`);
  }
  const publicKeyAttachment = buildStellarSignerAttachment(verified.signer);
  return {
    publicKeys: publicKeyAttachment ? [publicKeyAttachment] : [],
    signature: {
      id: signatureAttachmentId('stellar-sig', signature.bytes),
      format: 'stellar-sig',
      suite: 'ed25519',
      target: {
        type: 'canonical-manifest',
        digestAlg: 'SHA3-512',
        digestValue: toHex(sha3_512(manifestBytes)),
      },
      signatureEncoding: 'base64',
      signature: bytesToBase64(signature.bytes),
      publicKeyRef: publicKeyAttachment?.id || null,
      legacy: false,
    },
  };
}

function resolveAttachContext(shards, options = {}) {
  const prepared = Array.isArray(shards)
    ? shards.map((shard, index) => {
        if (shard?.diagnostics?.errors?.length) {
          throw new Error(`Shard parse failed at input index ${index}: ${shard.diagnostics.errors.join('; ')}`);
        }
        return shard;
      })
    : [];

  if (prepared.length > 0) {
    const cohort = ensureSingleCohort(prepared);
    const embeddedManifest = parseArchiveManifestBytes(cohort.manifestBytes);
    const embeddedBundle = parseManifestBundleBytes(cohort.bundleBytes);
    if (!bytesEqual(embeddedBundle.manifestBytes, embeddedManifest.bytes)) {
      throw new Error('Embedded bundle manifest does not match embedded canonical manifest bytes');
    }

    let workingBundle = embeddedBundle.bundle;
    if (options.bundleBytes instanceof Uint8Array) {
      const parsedBundle = parseManifestBundleBytes(options.bundleBytes);
      if (!bytesEqual(parsedBundle.manifestBytes, embeddedManifest.bytes)) {
        throw new Error('Provided bundle does not match selected shard manifest');
      }
      workingBundle = parsedBundle.bundle;
    } else if (options.manifestBytes instanceof Uint8Array) {
      const parsedManifest = parseArchiveManifestBytes(options.manifestBytes);
      if (!bytesEqual(parsedManifest.bytes, embeddedManifest.bytes)) {
        throw new Error('Provided canonical manifest does not match selected shard manifest');
      }
    }

    return {
      preparedShards: prepared,
      embeddedManifest,
      workingBundle,
    };
  }

  if (options.bundleBytes instanceof Uint8Array) {
    const parsedBundle = parseManifestBundleBytes(options.bundleBytes);
    const embeddedManifest = parseArchiveManifestBytes(parsedBundle.manifestBytes);
    return {
      preparedShards: [],
      embeddedManifest,
      workingBundle: parsedBundle.bundle,
    };
  }

  if (options.manifestBytes instanceof Uint8Array) {
    const parsedManifest = parseArchiveManifestBytes(options.manifestBytes);
    return {
      preparedShards: [],
      embeddedManifest: parsedManifest,
      workingBundle: buildInitialManifestBundle({
        manifest: parsedManifest.manifest,
        authPolicy: recoverCommittedAuthPolicy(parsedManifest.manifest.authPolicyCommitment),
      }),
    };
  }

  throw new Error('No .qcont shards or manifest bundle were provided for attach.');
}

export async function attachManifestBundleToShards(shards, options = {}) {
  const {
    preparedShards,
    embeddedManifest,
    workingBundle,
  } = resolveAttachContext(shards, options);

  const existingVerification = await verifyManifestSignatures({
    manifestBytes: embeddedManifest.bytes,
    bundleSignatures: workingBundle.attachments.signatures,
    bundlePublicKeys: workingBundle.attachments.publicKeys,
    externalSignatures: [],
    pinnedPqPublicKeyFileBytes: null,
  });
  const existingInvalid = existingVerification.results.filter((item) => !item.ok);
  if (existingInvalid.length > 0) {
    throw new Error(`Existing manifest bundle contains invalid signatures: ${existingInvalid[0].error}`);
  }
  await assertManifestBundleTimestamps(workingBundle);

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
  const importedSignatures = [];
  for (const signature of externalSignatures) {
    const type = detectExternalSignatureType(signature);
    if (type === 'qsig') {
      const imported = await importExternalQsig({
        manifestBytes: embeddedManifest.bytes,
        signature,
        normalizedPqPins,
      });
      importedPublicKeys.push(...imported.publicKeys);
      importedSignatures.push(imported.signature);
      continue;
    }
    if (type === 'stellar-sig') {
      const imported = await importExternalStellarSig({
        manifestBytes: embeddedManifest.bytes,
        signature,
        expectedEd25519Signer: options.expectedEd25519Signer,
      });
      importedPublicKeys.push(...imported.publicKeys);
      importedSignatures.push(imported.signature);
      continue;
    }
    throw new Error(`Unsupported signature file: ${signature?.name || 'unknown'}`);
  }

  const mergedBundle = {
    ...workingBundle,
    attachments: {
      publicKeys: mergeById(workingBundle.attachments.publicKeys, importedPublicKeys),
      signatures: mergeById(workingBundle.attachments.signatures, importedSignatures),
      timestamps: [...workingBundle.attachments.timestamps],
    },
  };

  const timestampFiles = Array.isArray(options.timestamps) ? options.timestamps : [];
  if (timestampFiles.length > 0) {
    const signaturePayloads = buildBundleSignaturePayloads(mergedBundle.attachments.signatures);
    const importedTimestamps = await Promise.all(timestampFiles.map(async (timestamp) => {
      if (!(timestamp?.bytes instanceof Uint8Array) || timestamp.bytes.length === 0) {
        throw new Error(`Invalid timestamp file: ${timestamp?.name || 'unknown'}`);
      }
      const resolved = await resolveOpenTimestampTarget({
        timestampBytes: timestamp.bytes,
        timestampName: timestamp.name,
        signatures: signaturePayloads,
      });
      return {
        id: attachmentId('ots', timestamp.bytes),
        type: 'opentimestamps',
        targetRef: resolved.targetRef,
        proofEncoding: 'base64',
        proof: bytesToBase64(timestamp.bytes),
        apparentlyComplete: resolved.apparentlyComplete,
        completeProof: resolved.completeProof,
      };
    }));
    mergedBundle.attachments.timestamps = mergeById(mergedBundle.attachments.timestamps, importedTimestamps);
  }
  await assertManifestBundleTimestamps(mergedBundle);

  const canonicalBundle = canonicalizeManifestBundle(mergedBundle);
  if (!bytesEqual(canonicalBundle.manifestBytes, embeddedManifest.bytes)) {
    throw new Error('Attach changed the canonical manifest bytes, which is forbidden');
  }

  const embedIntoShards = options.embedIntoShards !== false;
  const updatedShards = embedIntoShards
    ? preparedShards.map((shard, index) => {
        const metaJSON = {
          ...shard.metaJSON,
          hasEmbeddedBundle: true,
          bundleDigest: canonicalBundle.digestHex,
          authPolicyLevel: mergedBundle.authPolicy.level,
        };
        return {
          index,
          shardIndex: shard.shardIndex,
          blob: buildShardBlob({
            metaJSON,
            manifestBytes: embeddedManifest.bytes,
            bundleBytes: canonicalBundle.bytes,
            encapsulatedKey: shard.encapsulatedKey,
            containerNonce: shard.iv,
            kdfSalt: shard.salt,
            qencMetaBytes: shard.qencMetaBytes,
            keyCommitment: shard.keyCommit,
            shardIndex: shard.shardIndex,
            share: shard.share,
            bodyBytes: shard.fragments,
          }),
        };
      })
    : [];

  return {
    shards: updatedShards,
    manifestBytes: embeddedManifest.bytes,
    manifestDigestHex: embeddedManifest.digestHex,
    bundle: mergedBundle,
    bundleBytes: canonicalBundle.bytes,
    bundleDigestHex: canonicalBundle.digestHex,
    signableManifestBytes: embeddedManifest.bytes,
  };
}
