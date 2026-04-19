import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToBase64, bytesEqual, toHex } from '../bytes.js';
import { resolveOpenTimestampTarget } from '../auth/opentimestamps.js';
import { normalizePqPublicKeyPins, unpackPqpk, verifyQsigAgainstBytes } from '../auth/qsig.js';
import { computeDetachedSignatureIdentityDigestHex } from '../auth/signature-identity.js';
import { getSignatureSuiteInfo } from '../auth/signature-suites.js';
import { isSupportedStellarSignatureDocumentBytes, verifyStellarSigAgainstBytes } from '../auth/stellar-sig.js';
import {
  buildSourceEvidence,
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeLifecycleBundle,
  canonicalizeSourceEvidence,
  decodeLifecycleSignatureBytes,
  LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS,
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
  parseSourceEvidenceBytes,
  resolveLifecycleSignatureTarget,
  verifyLifecycleSignatureEntry,
} from '../lifecycle/artifacts.js';
import { rewriteLifecycleBundleInShard } from './lifecycle-shard.js';

const SHA3_512_HEX_RE = /^[0-9a-f]{128}$/;
const LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTOR_BY_FAMILY = new Map(
  LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS.map((descriptor) => [descriptor.family, descriptor])
);
const TARGET_REF_PATTERNS = Object.freeze({
  'archive-approval': /^state:([0-9a-f]{128})$/,
  maintenance: /^transition:sha3-512:([0-9a-f]{128})$/,
  'source-evidence': /^source-evidence:sha3-512:([0-9a-f]{128})$/,
});

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
  if (isSupportedStellarSignatureDocumentBytes(bytes)) {
    return 'stellar-sig';
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

function importLabel(signatureImport, fallback = 'signature import') {
  const label = String(signatureImport?.name || '').trim();
  return label || fallback;
}

function normalizeImportTargetDigest(value, field) {
  if (value == null) return null;
  if (typeof value === 'string') {
    if (!SHA3_512_HEX_RE.test(value)) {
      throw new Error(`Invalid ${field}`);
    }
    return {
      alg: 'SHA3-512',
      value,
    };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid ${field}`);
  }
  if (value.alg !== 'SHA3-512' || !SHA3_512_HEX_RE.test(String(value.value || ''))) {
    throw new Error(`Invalid ${field}`);
  }
  return {
    alg: 'SHA3-512',
    value: String(value.value),
  };
}

function digestFromTargetRef(targetRef, descriptor, label) {
  const pattern = TARGET_REF_PATTERNS[descriptor.family];
  const match = pattern?.exec(targetRef);
  if (!match) {
    throw new Error(`${label}: invalid targetRef for ${descriptor.family}`);
  }
  return {
    alg: 'SHA3-512',
    value: match[1],
  };
}

function sourceEvidenceTargetRef(digestHex) {
  return `source-evidence:sha3-512:${digestHex}`;
}

function resolveSignatureImportDescriptor(signatureImport, label) {
  const family = String(signatureImport?.signatureFamily || '').trim();
  const descriptor = LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTOR_BY_FAMILY.get(family);
  if (!descriptor) {
    throw new Error(`${label}: unsupported signatureFamily "${family}"`);
  }
  return descriptor;
}

function buildDeclaredSignatureTarget(signatureImport, descriptor, defaultTarget, options = {}) {
  const label = options.label || importLabel(signatureImport);
  const providedTargetType = typeof signatureImport?.targetType === 'string'
    ? String(signatureImport.targetType).trim()
    : '';
  const targetType = providedTargetType || descriptor.targetType;
  if (targetType !== descriptor.targetType) {
    throw new Error(
      `${label}: wrong targetType for ${descriptor.family} import; expected ${descriptor.targetType}, got ${targetType}`
    );
  }

  const providedTargetRef = typeof signatureImport?.targetRef === 'string'
    ? String(signatureImport.targetRef).trim()
    : '';
  if (options.requireExplicitTargetRef && !providedTargetRef) {
    throw new Error(`${label}: ${descriptor.family} imports require explicit targetRef; refusing to route by guess`);
  }

  const targetRef = providedTargetRef || defaultTarget?.targetRef || '';
  if (!targetRef) {
    throw new Error(`${label}: missing targetRef`);
  }

  const refDigest = digestFromTargetRef(targetRef, descriptor, label);
  const declaredTargetDigest = normalizeImportTargetDigest(signatureImport?.targetDigest, `${label}.targetDigest`);
  if (declaredTargetDigest && declaredTargetDigest.value !== refDigest.value) {
    throw new Error(`${label}: targetDigest does not match targetRef`);
  }
  if (defaultTarget?.targetDigest?.value && defaultTarget.targetDigest.value !== refDigest.value) {
    throw new Error(`${label}: targetRef does not match the selected ${descriptor.family} target`);
  }

  return {
    signatureFamily: descriptor.family,
    targetType: descriptor.targetType,
    targetRef,
    targetDigest: declaredTargetDigest || defaultTarget?.targetDigest || refDigest,
  };
}

function resolveTypedSignatureTarget(bundle, signatureImport, descriptor, defaultTarget, options = {}) {
  const declaredTarget = buildDeclaredSignatureTarget(signatureImport, descriptor, defaultTarget, options);
  try {
    return resolveLifecycleSignatureTarget(bundle, declaredTarget, {
      expectedFamily: descriptor.family,
    });
  } catch (error) {
    throw new Error(`${options.label || importLabel(signatureImport)}: ${error?.message || error}`);
  }
}

function resolveSourceEvidenceArtifact(input = {}, label = 'source-evidence') {
  const hasBytes = input.sourceEvidenceBytes instanceof Uint8Array;
  const hasBuilderParams = input.sourceEvidence != null;
  if (hasBytes && hasBuilderParams) {
    throw new Error(`${label}: provide either sourceEvidenceBytes or sourceEvidence, not both`);
  }
  if (hasBytes) {
    const parsed = parseSourceEvidenceBytes(input.sourceEvidenceBytes);
    return {
      sourceEvidence: parsed.sourceEvidence,
      bytes: parsed.bytes,
      digest: parsed.digest,
      targetRef: sourceEvidenceTargetRef(parsed.digest.value),
    };
  }
  if (hasBuilderParams) {
    const canonical = canonicalizeSourceEvidence(buildSourceEvidence(input.sourceEvidence));
    return {
      sourceEvidence: canonical.sourceEvidence,
      bytes: canonical.bytes,
      digest: canonical.digest,
      targetRef: sourceEvidenceTargetRef(canonical.digest.value),
    };
  }
  throw new Error(`${label}: source-evidence import requires sourceEvidenceBytes or sourceEvidence`);
}

export function exportSourceEvidenceForSigning(options = {}) {
  const canonical = resolveSourceEvidenceArtifact(options, 'source-evidence export');
  return {
    sourceEvidence: canonical.sourceEvidence,
    sourceEvidenceBytes: canonical.bytes,
    sourceEvidenceDigestHex: canonical.digest.value,
    targetType: 'source-evidence',
    targetRef: canonical.targetRef,
    targetDigest: canonical.digest,
  };
}

function mergeLifecycleSourceEvidenceEntries(existingValues, nextValues) {
  const out = [...existingValues];
  const byDigest = new Map(out.map((entry) => {
    const canonical = canonicalizeSourceEvidence(entry);
    return [canonical.digest.value, canonical];
  }));

  for (const value of nextValues) {
    const canonical = canonicalizeSourceEvidence(value);
    if (byDigest.has(canonical.digest.value)) {
      const previous = byDigest.get(canonical.digest.value);
      if (!bytesEqual(previous.bytes, canonical.bytes)) {
        throw new Error(
          `Lifecycle source-evidence merge conflict: duplicate digest "${canonical.digest.value}" with differing content`
        );
      }
      continue;
    }
    out.push(canonical.sourceEvidence);
    byDigest.set(canonical.digest.value, canonical);
  }
  return out;
}

async function assertImportedLifecycleSignatureEntriesValid(bundle, signaturesByField, expectedEd25519Signer = '') {
  for (const descriptor of LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS) {
    const signatures = Array.isArray(signaturesByField?.[descriptor.field]) ? signaturesByField[descriptor.field] : [];
    for (const signature of signatures) {
      await verifyLifecycleSignatureEntry(bundle, signature, {
        expectedEd25519Signer,
        expectedFamily: descriptor.family,
        expectedField: descriptor.field,
      });
    }
  }
}

function buildBundleSignaturePayloads(bundle) {
  return LIFECYCLE_SIGNATURE_FAMILY_DESCRIPTORS.flatMap((descriptor) => (
    Array.isArray(bundle?.attachments?.[descriptor.field]) ? bundle.attachments[descriptor.field] : []
  )).map((signature) => ({
    id: signature.id,
    bytes: decodeLifecycleSignatureBytes(signature, 'detached signature'),
  }));
}

function verifyQsigOrThrow(options, signatureName) {
  try {
    return verifyQsigAgainstBytes(options);
  } catch (error) {
    throw new Error(`${signatureName}: ${error?.message || error}`);
  }
}

async function importExternalLifecycleQsig({
  signatureFamily,
  target,
  signature,
  normalizedPqPins,
}) {
  let matchedKey = null;
  const successful = [];
  for (const candidatePin of normalizedPqPins) {
    const result = verifyQsigOrThrow({
      messageBytes: target.bytes,
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
      messageBytes: target.bytes,
      qsigBytes: signature.bytes,
      bundlePqPublicKeyFileBytes: null,
    }, signature.name || 'signature.qsig');
    if (!verified.ok) {
      throw new Error(`${signature.name}: ${verified.error}`);
    }
  }

  // Embedded-key-only verification may still be imported as unpinned evidence, but
  // lifecycle attach must not synthesize bundled signer material or a publicKeyRef
  // without an authoritative .pqpk match.
  const publicKeyAttachment = matchedKey ? buildLifecyclePublicKeyAttachment(matchedKey) : null;
  return {
    publicKeys: publicKeyAttachment ? [publicKeyAttachment] : [],
    signature: {
      id: signatureAttachmentId('qsig', signature.bytes),
      signatureFamily,
      format: 'qsig',
      suite: verified.suite,
      targetType: target.targetType,
      targetRef: target.targetRef,
      targetDigest: target.digest,
      signatureEncoding: 'base64',
      signature: bytesToBase64(signature.bytes),
      publicKeyRef: publicKeyAttachment?.id,
    },
  };
}

async function importExternalLifecycleStellarSig({
  signatureFamily,
  target,
  signature,
  expectedEd25519Signer = '',
}) {
  const verified = await verifyStellarSigAgainstBytes({
    messageBytes: target.bytes,
    sigJsonBytes: signature.bytes,
    expectedSigner: expectedEd25519Signer,
  });
  if (!verified.ok) {
    throw new Error(`${signature.name}: ${verified.error}`);
  }
  const publicKeyAttachment = buildLifecycleStellarSignerAttachment(verified.signer);
  return {
    publicKeys: publicKeyAttachment ? [publicKeyAttachment] : [],
    signature: {
      id: signatureAttachmentId('stellar-sig', signature.bytes),
      signatureFamily,
      format: 'stellar-sig',
      suite: 'ed25519',
      targetType: target.targetType,
      targetRef: target.targetRef,
      targetDigest: target.digest,
      signatureEncoding: 'base64',
      signature: bytesToBase64(signature.bytes),
      publicKeyRef: publicKeyAttachment?.id,
    },
  };
}

async function importExternalLifecycleSignature({
  signatureFamily,
  target,
  signature,
  normalizedPqPins,
  expectedEd25519Signer = '',
}) {
  const type = detectExternalSignatureType(signature);
  if (type === 'qsig') {
    return importExternalLifecycleQsig({
      signatureFamily,
      target,
      signature,
      normalizedPqPins,
    });
  }
  if (type === 'stellar-sig') {
    return importExternalLifecycleStellarSig({
      signatureFamily,
      target,
      signature,
      expectedEd25519Signer,
    });
  }
  throw new Error(`Unsupported signature file: ${signature?.name || 'unknown'}`);
}

function collectSignatureImports(options = {}) {
  const imports = [];
  for (const signature of Array.isArray(options.signatures) ? options.signatures : []) {
    imports.push({
      ...signature,
      signatureFamily: 'archive-approval',
    });
  }
  for (const signatureImport of Array.isArray(options.signatureImports) ? options.signatureImports : []) {
    imports.push(signatureImport);
  }
  return imports;
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

  const pqPublicKeyFileBytesList = Array.isArray(options.pqPublicKeyFileBytesList)
    ? options.pqPublicKeyFileBytesList.filter((item) => item instanceof Uint8Array)
    : [];
  const normalizedPqPins = normalizePqPublicKeyPins({
    pinnedPqPublicKeyFileBytesList: pqPublicKeyFileBytesList,
    invalidBehavior: 'throw',
    invalidLabel: 'Pinned PQ signer key',
  }).pins;

  const signatureImports = collectSignatureImports(options);
  const importedPublicKeys = [];
  const importedSignaturesByField = {
    archiveApprovalSignatures: [],
    maintenanceSignatures: [],
    sourceEvidenceSignatures: [],
  };
  let importedSourceEvidence = [];
  for (const signatureImport of signatureImports) {
    const label = importLabel(signatureImport, 'signature import');
    if (!(signatureImport?.bytes instanceof Uint8Array) || signatureImport.bytes.length === 0) {
      throw new Error(`Invalid signature file: ${label}`);
    }
    const descriptor = resolveSignatureImportDescriptor(signatureImport, label);
    let targetBundle = lifecycleBundle;
    let defaultTarget = null;

    if (descriptor.family === 'archive-approval') {
      defaultTarget = {
        targetRef: `state:${stateId}`,
        targetDigest: archiveStateDigest,
      };
    } else if (descriptor.family === 'source-evidence') {
      const exported = exportSourceEvidenceForSigning({
        sourceEvidenceBytes: signatureImport?.sourceEvidenceBytes,
        sourceEvidence: signatureImport?.sourceEvidence,
      });
      importedSourceEvidence = mergeLifecycleSourceEvidenceEntries(importedSourceEvidence, [exported.sourceEvidence]);
      targetBundle = {
        ...lifecycleBundle,
        sourceEvidence: mergeLifecycleSourceEvidenceEntries(lifecycleBundle.sourceEvidence, importedSourceEvidence),
      };
      defaultTarget = {
        targetRef: exported.targetRef,
        targetDigest: exported.targetDigest,
      };
    }

    const target = resolveTypedSignatureTarget(targetBundle, signatureImport, descriptor, defaultTarget, {
      label,
      requireExplicitTargetRef: descriptor.family === 'maintenance',
    });
    const imported = await importExternalLifecycleSignature({
      signatureFamily: descriptor.family,
      target,
      signature: {
        name: label,
        bytes: signatureImport.bytes,
      },
      normalizedPqPins,
      expectedEd25519Signer,
    });
    importedPublicKeys.push(...imported.publicKeys);
    importedSignaturesByField[descriptor.field].push(imported.signature);
  }

  const mergedBundle = {
    ...lifecycleBundle,
    sourceEvidence: mergeLifecycleSourceEvidenceEntries(lifecycleBundle.sourceEvidence, importedSourceEvidence),
    attachments: {
      publicKeys: mergeLifecycleAttachmentEntriesById(lifecycleBundle.attachments.publicKeys, importedPublicKeys),
      archiveApprovalSignatures: mergeLifecycleAttachmentEntriesById(
        lifecycleBundle.attachments.archiveApprovalSignatures,
        importedSignaturesByField.archiveApprovalSignatures
      ),
      maintenanceSignatures: mergeLifecycleAttachmentEntriesById(
        lifecycleBundle.attachments.maintenanceSignatures,
        importedSignaturesByField.maintenanceSignatures
      ),
      sourceEvidenceSignatures: mergeLifecycleAttachmentEntriesById(
        lifecycleBundle.attachments.sourceEvidenceSignatures,
        importedSignaturesByField.sourceEvidenceSignatures
      ),
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
      const resolved = await resolveOpenTimestampTarget({
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
  await assertImportedLifecycleSignatureEntriesValid(
    canonicalBundle.lifecycleBundle,
    importedSignaturesByField,
    expectedEd25519Signer
  );

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
