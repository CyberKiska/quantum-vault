import { attachManifestBundleToShards, parseShard } from '../../../app/crypto-service.js';
import { base64ToBytes } from '../../crypto/bytes.js';
import { parseArchiveManifestBytes } from '../../crypto/manifest/archive-manifest.js';
import { parseManifestBundleBytes } from '../../crypto/manifest/manifest-bundle.js';
import { isSupportedStellarSignatureDocument } from '../../crypto/auth/stellar-sig.js';
import { log, logError, logSuccess, logWarning } from '../ui/logging.js';
import { showToast } from '../ui/toast.js';
import { download, readFileAsUint8Array, setButtonsDisabled } from '../../../utils.js';

function startsWithAscii(bytes, ascii) {
  if (!(bytes instanceof Uint8Array) || bytes.length < ascii.length) return false;
  for (let i = 0; i < ascii.length; i += 1) {
    if (bytes[i] !== ascii.charCodeAt(i)) return false;
  }
  return true;
}

async function classifyAttachFiles(files) {
  const shardFiles = [];
  const signatures = [];
  const timestamps = [];
  const pqPublicKeyFileBytesList = [];
  let manifestBytes = null;
  let bundleBytes = null;

  for (const file of files) {
    const name = String(file?.name || 'unnamed');
    const lowerName = name.toLowerCase();
    if (lowerName.endsWith('.qcont')) {
      shardFiles.push(file);
      continue;
    }

    const bytes = await readFileAsUint8Array(file);
    if (startsWithAscii(bytes, 'QVC1')) {
      shardFiles.push(file);
      continue;
    }
    if (startsWithAscii(bytes, 'PQPK') || lowerName.endsWith('.pqpk')) {
      pqPublicKeyFileBytesList.push(bytes);
      continue;
    }
    if (startsWithAscii(bytes, 'PQSG') || lowerName.endsWith('.qsig')) {
      signatures.push({ name, bytes });
      continue;
    }
    if (lowerName.endsWith('.ots')) {
      timestamps.push({ name, bytes });
      continue;
    }

    try {
      const parsedBundle = parseManifestBundleBytes(bytes);
      if (bundleBytes) throw new Error('Multiple manifest bundle files were provided.');
      bundleBytes = parsedBundle.bytes;
      continue;
    } catch {
      // try other file types
    }

    try {
      const parsedManifest = parseArchiveManifestBytes(bytes);
      if (manifestBytes) throw new Error('Multiple canonical manifest files were provided.');
      manifestBytes = parsedManifest.bytes;
      continue;
    } catch {
      // try stellar signature
    }

    try {
      const parsed = JSON.parse(new TextDecoder().decode(bytes));
      if (isSupportedStellarSignatureDocument(parsed)) {
        signatures.push({ name, bytes });
        continue;
      }
    } catch {
      // ignore
    }
  }

  return {
    shardFiles,
    manifestBytes,
    bundleBytes,
    signatures,
    timestamps,
    pqPublicKeyFileBytesList,
  };
}

function stripManifestVariantSuffix(name) {
  return String(name || 'archive')
    .replace(/\.signable\.qvmanifest\.json$/i, '')
    .replace(/\.extended\.qvmanifest\.json$/i, '')
    .replace(/\.bundle\.qvmanifest\.json$/i, '')
    .replace(/\.qvmanifest\.json$/i, '');
}

function deriveManifestBaseName(sourceFiles) {
  const explicit = sourceFiles.find((file) => String(file?.name || '').toLowerCase().endsWith('.qvmanifest.json'));
  if (explicit) return stripManifestVariantSuffix(explicit.name);
  const shard = sourceFiles.find((file) => String(file?.name || '').toLowerCase().endsWith('.qcont'));
  if (!shard) return 'archive';
  return stripManifestVariantSuffix(shard.name.replace(/\.part\d+-of-\d+\.qcont$/i, ''));
}

function deriveManifestFilename(sourceFiles) {
  return `${deriveManifestBaseName(sourceFiles)}.qvmanifest.json`;
}

function deriveBundleFilename(sourceFiles) {
  return `${deriveManifestBaseName(sourceFiles)}.extended.qvmanifest.json`;
}

function deriveSignableManifestFilename(sourceFiles) {
  return `${deriveManifestBaseName(sourceFiles)}.signable.qvmanifest.json`;
}

export function buildAttachedArtifactExports(bundle, baseName) {
  const exports = [];
  for (const publicKey of bundle?.attachments?.publicKeys || []) {
    if (publicKey.encoding === 'base64') {
      exports.push({
        filename: `${baseName}-${publicKey.id}.pqpk`,
        bytes: base64ToBytes(publicKey.value),
        type: 'application/octet-stream',
      });
      continue;
    }
    if (publicKey.encoding === 'stellar-address') {
      exports.push({
        filename: `${baseName}-${publicKey.id}.stellar.txt`,
        bytes: new TextEncoder().encode(`${String(publicKey.value || '').trim()}\n`),
        type: 'text/plain;charset=utf-8',
      });
      continue;
    }
    throw new Error(`Cannot export attached public key ${publicKey.id}: unsupported encoding ${publicKey.encoding}`);
  }

  for (const signature of bundle?.attachments?.signatures || []) {
    if (signature.signatureEncoding !== 'base64') {
      throw new Error(`Cannot export attached signature ${signature.id}: unsupported encoding ${signature.signatureEncoding}`);
    }
    const extension = signature.format === 'stellar-sig' ? 'sig' : 'qsig';
    exports.push({
      filename: `${baseName}-${signature.id}.${extension}`,
      bytes: base64ToBytes(signature.signature),
      type: 'application/octet-stream',
    });
  }

  for (const timestamp of bundle?.attachments?.timestamps || []) {
    if (timestamp.proofEncoding !== 'base64') {
      throw new Error(`Cannot export attached OTS evidence ${timestamp.id}: unsupported encoding ${timestamp.proofEncoding}`);
    }
    exports.push({
      filename: `${baseName}-${timestamp.id}.ots`,
      bytes: base64ToBytes(timestamp.proof),
      type: 'application/octet-stream',
    });
  }

  return exports;
}

async function parseAttachShards(classified) {
  const shardBytes = await Promise.all(classified.shardFiles.map(readFileAsUint8Array));
  return shardBytes.map((bytes) => parseShard(bytes, { strict: true }));
}

function deriveAttachPlan(classified, shards) {
  if (!Array.isArray(shards) || shards.length === 0) {
    return {
      embedIntoShards: false,
      modeLabel: 'Manifest-side bundle only',
      hint: 'No shard files are loaded. Attach will update only the manifest-side bundle.',
      warning: false,
    };
  }

  const cohortKeys = new Set(shards.map((shard) => `${shard.manifestDigestHex}:${shard.bundleDigestHex}`));
  if (cohortKeys.size !== 1) {
    throw new Error('Attach requires shard files from exactly one archive cohort.');
  }

  const uniqueIndices = new Set(shards.map((shard) => shard.shardIndex));
  if (uniqueIndices.size !== shards.length) {
    throw new Error('Attach input contains duplicate shard indices. Keep only one copy of each shard.');
  }

  const expectedShardCount = Number(shards[0]?.metaJSON?.n);
  if (!Number.isInteger(expectedShardCount) || expectedShardCount <= 0) {
    throw new Error('Attach could not determine the expected shard count for this archive.');
  }

  if (uniqueIndices.size === expectedShardCount) {
    return {
      embedIntoShards: true,
      modeLabel: 'Embed into selected shards',
      hint: `Full shard cohort detected (${uniqueIndices.size}/${expectedShardCount}). Attach will rewrite the selected shard files and update the manifest-side bundle.`,
      warning: false,
    };
  }

  return {
    embedIntoShards: false,
    modeLabel: 'Manifest-side bundle only',
    hint: `Only ${uniqueIndices.size}/${expectedShardCount} shard files are loaded. Attach cannot rewrite every shard, so only the manifest-side bundle will be updated.`,
    warning: true,
  };
}

async function resolveAttachSourceBundle(classified) {
  if (classified.bundleBytes instanceof Uint8Array) {
    return parseManifestBundleBytes(classified.bundleBytes).bundle;
  }
  if (classified.shardFiles.length > 0) {
    const shardBytes = await readFileAsUint8Array(classified.shardFiles[0]);
    const parsedShard = parseShard(shardBytes, { strict: true });
    return parseManifestBundleBytes(parsedShard.bundleBytes).bundle;
  }
  if (classified.manifestBytes instanceof Uint8Array) {
    return null;
  }
  throw new Error('No canonical manifest or manifest bundle is available.');
}

async function updateAttachStatus() {
  const input = document.getElementById('qcontAttachInput');
  const status = document.getElementById('attachStatus');
  const text = document.getElementById('attachStatusText');
  const hint = document.getElementById('attachStatusHint');
  if (!input || !status || !text || !hint) return;
  const count = input.files?.length || 0;
  status.classList.toggle('initially-hidden', count === 0);
  if (count === 0) {
    text.textContent = '0 attach files selected';
    hint.textContent = '';
    return;
  }

  text.textContent = `${count} attach file(s) selected`;
  try {
    const classified = await classifyAttachFiles([...(input.files || [])]);
    const shards = await parseAttachShards(classified);
    const plan = deriveAttachPlan(classified, shards);
    text.textContent = `${count} attach file(s) selected. ${plan.modeLabel}.`;
    hint.textContent = plan.hint;
  } catch (error) {
    hint.textContent = error?.message || String(error);
  }
}

async function exportSignableManifest() {
  const input = document.getElementById('qcontAttachInput');
  const files = [...(input?.files || [])];
  if (!files.length) {
    showToast('Select attach files first.', 'warning');
    return;
  }

  setButtonsDisabled(true);
  try {
    const classified = await classifyAttachFiles(files);
    let manifestBytes = classified.manifestBytes;
    if (!manifestBytes && classified.bundleBytes) {
      manifestBytes = parseManifestBundleBytes(classified.bundleBytes).manifestBytes;
    }
    if (!manifestBytes && classified.shardFiles.length > 0) {
      const shardBytes = await readFileAsUint8Array(classified.shardFiles[0]);
      const parsedShard = parseShard(shardBytes, { strict: true });
      manifestBytes = parsedShard.manifestBytes;
    }
    if (!(manifestBytes instanceof Uint8Array)) {
      throw new Error('No canonical manifest is available to export.');
    }
    const name = deriveSignableManifestFilename(files);
    download(new Blob([manifestBytes], { type: 'application/json' }), name);
    logSuccess(`Extracted canonical signable manifest: ${name}`);
  } catch (error) {
    logError(error);
  } finally {
    setButtonsDisabled(false);
  }
}

async function exportAttachedArtifacts() {
  const input = document.getElementById('qcontAttachInput');
  const files = [...(input?.files || [])];
  if (!files.length) {
    showToast('Select attach files first.', 'warning');
    return;
  }

  setButtonsDisabled(true);
  try {
    const classified = await classifyAttachFiles(files);
    const bundle = await resolveAttachSourceBundle(classified);
    if (!bundle) {
      throw new Error('The selected inputs contain only the canonical manifest; there are no attached artifacts to export.');
    }

    const baseName = deriveManifestBaseName(files);
    const artifacts = buildAttachedArtifactExports(bundle, baseName);
    let exportedCount = 0;
    for (const artifact of artifacts) {
      download(new Blob([artifact.bytes], { type: artifact.type }), artifact.filename);
      exportedCount += 1;
    }

    if (exportedCount === 0) {
      throw new Error('No attached signatures, keys, or OTS evidence were found to export.');
    }
    logSuccess(`Exported ${exportedCount} attached artifact(s), including any embedded OTS evidence.`);
  } catch (error) {
    logError(error);
  } finally {
    setButtonsDisabled(false);
  }
}

async function attachFilesToShards() {
  const input = document.getElementById('qcontAttachInput');
  const expectedEdSigner = document.getElementById('attachExpectedEdSigner');
  const files = [...(input?.files || [])];
  if (!files.length) {
    showToast('Select attach files first.', 'warning');
    return;
  }

  setButtonsDisabled(true);
  try {
    const classified = await classifyAttachFiles(files);
    if (
      !classified.shardFiles.length &&
      !(classified.bundleBytes instanceof Uint8Array) &&
      !(classified.manifestBytes instanceof Uint8Array)
    ) {
      throw new Error('Attach requires at least one .qcont shard, canonical manifest, or existing manifest bundle.');
    }
    const shards = await parseAttachShards(classified);
    const plan = deriveAttachPlan(classified, shards);
    if (plan.warning) {
      logWarning(plan.hint);
    } else {
      log(plan.hint);
    }
    const result = await attachManifestBundleToShards(shards, {
      manifestBytes: classified.manifestBytes,
      bundleBytes: classified.bundleBytes,
      signatures: classified.signatures,
      timestamps: classified.timestamps,
      pqPublicKeyFileBytesList: classified.pqPublicKeyFileBytesList,
      expectedEd25519Signer: String(expectedEdSigner?.value || '').trim(),
      embedIntoShards: plan.embedIntoShards,
    });

    if (plan.embedIntoShards && classified.shardFiles.length > 0) {
      classified.shardFiles.forEach((file, index) => {
        const updated = result.shards[index];
        download(updated.blob, file.name);
        log(`Updated ${file.name} (${updated.blob.size} B)`);
      });
    }

    const manifestName = deriveBundleFilename(files);
    download(new Blob([result.bundleBytes], { type: 'application/json' }), manifestName);
    if (plan.embedIntoShards && classified.shardFiles.length > 0) {
      logSuccess(`Embedded attached artifacts into the selected shards and updated ${manifestName}.`);
    } else {
      logSuccess(`Updated ${manifestName} as a manifest-side bundle without rewriting shard files.`);
    }
    log(`Bundle digest: ${result.bundleDigestHex}`);
    log('Detached signatures still bind the embedded canonical manifest bytes, not the whole bundle file.');
  } catch (error) {
    logError(error);
  } finally {
    setButtonsDisabled(false);
  }
}

export function initQcontAttachUI() {
  const attachInput = document.getElementById('qcontAttachInput');
  const attachBtn = document.getElementById('attachQcontBtn');
  const exportBtn = document.getElementById('exportSignableManifestBtn');
  const exportArtifactsBtn = document.getElementById('exportAttachedArtifactsBtn');

  attachInput?.addEventListener('change', () => { void updateAttachStatus(); });
  attachBtn?.addEventListener('click', attachFilesToShards);
  exportBtn?.addEventListener('click', exportSignableManifest);
  exportArtifactsBtn?.addEventListener('click', exportAttachedArtifacts);
}
