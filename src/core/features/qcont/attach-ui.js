import {
  attachLifecycleBundleToShards,
  parseLifecycleShard,
} from '../../../app/crypto-service.js';
import { packPqpk } from '../../crypto/auth/qsig.js';
import { base64ToBytes, bytesEqual } from '../../crypto/bytes.js';
import { isSupportedStellarSignatureDocumentBytes } from '../../crypto/auth/stellar-sig.js';
import {
  canonicalizeArchiveStateDescriptor,
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
} from '../../crypto/lifecycle/artifacts.js';
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

function isLegacyAttachFilename(name) {
  return /\.qvmanifest\.json$/i.test(String(name || ''));
}

export async function classifyAttachFiles(files) {
  const shardFiles = [];
  const signatures = [];
  const timestamps = [];
  const pqPublicKeyFileBytesList = [];
  let archiveStateBytes = null;
  let lifecycleBundleBytes = null;

  for (const file of files) {
    const name = String(file?.name || 'unnamed');
    const lowerName = name.toLowerCase();
    if (lowerName.endsWith('.qcont')) {
      shardFiles.push(file);
      continue;
    }
    if (isLegacyAttachFilename(name)) {
      throw new Error(
        'Unsupported attach input: manifest-side files are no longer accepted here. Use successor shards, archive-state descriptors, lifecycle bundles, detached signatures, .pqpk files, or .ots proofs.'
      );
    }

    const bytes = await readFileAsUint8Array(file);
    if (startsWithAscii(bytes, 'QVC1')) {
      shardFiles.push(file);
      continue;
    }
    if (startsWithAscii(bytes, 'PQPK') || lowerName.endsWith('.pqpk')) {
      const alreadyPresent = pqPublicKeyFileBytesList.some((item) => bytesEqual(item, bytes));
      if (!alreadyPresent) {
        pqPublicKeyFileBytesList.push(bytes);
      }
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
    if (isSupportedStellarSignatureDocumentBytes(bytes)) {
      signatures.push({ name, bytes });
      continue;
    }

    try {
      const parsedLifecycleBundle = await parseLifecycleBundleBytes(bytes);
      if (lifecycleBundleBytes && !bytesEqual(lifecycleBundleBytes, parsedLifecycleBundle.bytes)) {
        throw new Error('Multiple different lifecycle bundle files were provided. Keep only one.');
      }
      lifecycleBundleBytes = parsedLifecycleBundle.bytes;
      continue;
    } catch (error) {
      if (lowerName.endsWith('.lifecycle-bundle.json')) {
        throw error;
      }
    }

    try {
      const parsedArchiveState = parseArchiveStateDescriptorBytes(bytes);
      if (archiveStateBytes && !bytesEqual(archiveStateBytes, parsedArchiveState.bytes)) {
        throw new Error('Multiple different archive-state descriptor files were provided. Keep only one.');
      }
      archiveStateBytes = parsedArchiveState.bytes;
      continue;
    } catch (error) {
      if (lowerName.endsWith('.archive-state.json')) {
        throw error;
      }
    }
  }

  return {
    shardFiles,
    archiveStateBytes,
    lifecycleBundleBytes,
    signatures,
    timestamps,
    pqPublicKeyFileBytesList,
  };
}

function stripArchiveVariantSuffix(name) {
  return String(name || 'archive')
    .replace(/\.archive-state\.json$/i, '')
    .replace(/\.cohort-binding\.json$/i, '')
    .replace(/\.transition-record\.json$/i, '')
    .replace(/\.lifecycle-bundle\.json$/i, '');
}

function deriveArchiveBaseName(sourceFiles) {
  const explicit = sourceFiles.find((file) => /\.(archive-state\.json|lifecycle-bundle\.json)$/i.test(String(file?.name || '')));
  if (explicit) return stripArchiveVariantSuffix(explicit.name);
  const shard = sourceFiles.find((file) => String(file?.name || '').toLowerCase().endsWith('.qcont'));
  if (!shard) return 'archive';
  return stripArchiveVariantSuffix(shard.name.replace(/\.part\d+-of-\d+\.qcont$/i, ''));
}

function deriveSignableFilename(sourceFiles) {
  return `${deriveArchiveBaseName(sourceFiles)}.archive-state.json`;
}

function deriveBundleFilename(sourceFiles) {
  return `${deriveArchiveBaseName(sourceFiles)}.lifecycle-bundle.json`;
}

function clearAttachResultPanel() {
  const panel = document.getElementById('attachResult');
  if (!panel) return;
  panel.style.display = 'none';
  panel.replaceChildren();
}

function setAttachActionAvailability({
  canAttach = false,
  canExportSignable = false,
  canExportArtifacts = false,
} = {}) {
  const attachBtn = document.getElementById('attachQcontBtn');
  const exportBtn = document.getElementById('exportSignableArtifactBtn');
  const exportArtifactsBtn = document.getElementById('exportAttachedArtifactsBtn');
  if (attachBtn) attachBtn.disabled = !canAttach;
  if (exportBtn) exportBtn.disabled = !canExportSignable;
  if (exportArtifactsBtn) exportArtifactsBtn.disabled = !canExportArtifacts;
}

export function buildAttachedArtifactExports(bundle, baseName) {
  if (bundle?.type !== 'QV-Lifecycle-Bundle') {
    throw new Error('Unsupported attach export source: expected a successor lifecycle bundle.');
  }

  const exports = [];
  for (const publicKey of bundle.attachments.publicKeys || []) {
    if (publicKey.encoding === 'base64') {
      exports.push({
        filename: `${baseName}-${publicKey.id}.pqpk`,
        bytes: packPqpk({
          suite: publicKey.suite,
          publicKeyBytes: base64ToBytes(publicKey.value),
        }),
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

  const signatures = [
    ...(bundle.attachments.archiveApprovalSignatures || []),
    ...(bundle.attachments.maintenanceSignatures || []),
    ...(bundle.attachments.sourceEvidenceSignatures || []),
  ];
  for (const signature of signatures) {
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

  for (const timestamp of bundle.attachments.timestamps || []) {
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
  return Promise.all(shardBytes.map(async (bytes, index) => {
    try {
      return await parseLifecycleShard(bytes, { strict: true });
    } catch (error) {
      throw new Error(
        `Shard ${classified.shardFiles[index]?.name || index + 1} is not a supported successor shard: expected QVqcont-7. ${error?.message || error}`
      );
    }
  }));
}

function deriveAttachPlan(shards) {
  if (!Array.isArray(shards) || shards.length === 0) {
    return {
      embedIntoShards: false,
      modeLabel: 'Lifecycle-bundle only',
      hint: 'No shard files are loaded. Attach will update only the standalone lifecycle bundle.',
      warning: false,
    };
  }

  const uniqueIndices = new Set(shards.map((shard) => shard.shardIndex));
  if (uniqueIndices.size !== shards.length) {
    throw new Error('Attach input contains duplicate shard indices. Keep only one copy of each shard.');
  }

  const expectedShardCount = Number(shards[0]?.metaJSON?.n);
  if (!Number.isInteger(expectedShardCount) || expectedShardCount <= 0) {
    throw new Error('Attach could not determine the expected shard count for this archive.');
  }

  const cohortKeys = new Set(shards.map((shard) => `${shard.metaJSON.archiveId}:${shard.metaJSON.stateId}:${shard.metaJSON.cohortId}`));
  if (cohortKeys.size !== 1) {
    throw new Error('Attach requires successor shards from exactly one archive/state/cohort set.');
  }

  if (uniqueIndices.size === expectedShardCount) {
    return {
      embedIntoShards: true,
      modeLabel: 'Embed into selected successor shards',
      hint: `Full successor shard cohort detected (${uniqueIndices.size}/${expectedShardCount}). Attach will rewrite the selected shard files and update the lifecycle bundle.`,
      warning: false,
    };
  }

  return {
    embedIntoShards: true,
    modeLabel: 'Partial successor shard rewrite',
    hint: `Only ${uniqueIndices.size}/${expectedShardCount} successor shard files are loaded. Attach will rewrite only the selected shard files; other shards may continue carrying a different embedded lifecycle-bundle digest within the same cohort.`,
    warning: true,
  };
}

async function resolveAttachSourceBundle(classified) {
  if (classified.lifecycleBundleBytes instanceof Uint8Array) {
    return (await parseLifecycleBundleBytes(classified.lifecycleBundleBytes)).lifecycleBundle;
  }
  if (classified.shardFiles.length > 0) {
    const shardBytes = await readFileAsUint8Array(classified.shardFiles[0]);
    const parsedShard = await parseLifecycleShard(shardBytes, { strict: true });
    return parsedShard.lifecycleBundle;
  }
  if (classified.archiveStateBytes instanceof Uint8Array) {
    return null;
  }
  throw new Error('No archive-state descriptor or lifecycle bundle is available.');
}

async function updateAttachStatus() {
  const input = document.getElementById('qcontAttachInput');
  const status = document.getElementById('attachStatus');
  const text = document.getElementById('attachStatusText');
  const hint = document.getElementById('attachStatusHint');
  const modeSummary = document.getElementById('attachModeSummary');
  if (!input || !status || !text || !hint) return;
  const count = input.files?.length || 0;
  if (count === 0) {
    status.style.display = 'none';
    status.className = 'shards-status initially-hidden';
    text.textContent = 'Select attach inputs to see the attach plan.';
    hint.textContent = '';
    if (modeSummary) {
      modeSummary.textContent = '';
      modeSummary.classList.add('initially-hidden');
    }
    setAttachActionAvailability();
    clearAttachResultPanel();
    return;
  }

  status.style.display = 'block';
  status.className = 'shards-status unknown';
  text.textContent = 'Analyzing attach inputs...';
  hint.textContent = `${count} file(s) loaded.`;
  status.setAttribute('aria-label', text.textContent);
  try {
    const files = [...(input.files || [])];
    const classified = await classifyAttachFiles(files);
    const shards = await parseAttachShards(classified);
    const plan = deriveAttachPlan(shards);
    const canAttach = classified.shardFiles.length > 0 || classified.lifecycleBundleBytes instanceof Uint8Array;
    const canExportSignable = (
      classified.archiveStateBytes instanceof Uint8Array ||
      classified.lifecycleBundleBytes instanceof Uint8Array ||
      classified.shardFiles.length > 0
    );

    let canExportArtifacts = false;
    try {
      const bundle = await resolveAttachSourceBundle(classified);
      if (bundle) {
        canExportArtifacts = buildAttachedArtifactExports(bundle, deriveArchiveBaseName(files)).length > 0;
      }
    } catch {
      canExportArtifacts = false;
    }

    let stateClass = 'sufficient';
    let summary;
    if (!canAttach) {
      stateClass = 'invalid';
      summary = 'More input required: load successor shards or a lifecycle bundle';
    } else if (plan.warning) {
      stateClass = 'insufficient';
    }

    if (!summary) {
      summary = plan.embedIntoShards
        ? (plan.warning ? 'Ready to update selected shards only' : 'Ready to embed into selected shards')
        : 'Ready to update lifecycle bundle only';
    }

    status.className = `shards-status ${stateClass}`;
    text.textContent = summary;
    hint.textContent = `${count} file(s) loaded. ${!canAttach
      ? 'Attach stays blocked until the input includes successor shards or an existing lifecycle bundle.'
      : plan.hint}`;
    status.setAttribute('aria-label', summary);
    if (modeSummary) {
      modeSummary.textContent = `${summary}\n${plan.modeLabel}`;
      modeSummary.classList.remove('initially-hidden');
    }
    setAttachActionAvailability({
      canAttach,
      canExportSignable,
      canExportArtifacts,
    });
  } catch (error) {
    const message = error?.message || String(error);
    const summary = message.startsWith('Unsupported attach input:')
      ? 'Unsupported attach input'
      : 'Attach inputs need attention';
    status.className = 'shards-status invalid';
    status.style.display = 'block';
    text.textContent = summary;
    hint.textContent = `${count} file(s) loaded. ${message}`;
    status.setAttribute('aria-label', summary);
    if (modeSummary) {
      modeSummary.textContent = summary;
      modeSummary.classList.remove('initially-hidden');
    }
    setAttachActionAvailability();
  }
}

function buildAttachResultSummary({ plan, classified }) {
  const panel = document.getElementById('attachResult');
  if (!panel) return;

  panel.replaceChildren();
  panel.style.display = 'block';

  const header = document.createElement('h4');
  header.textContent = 'Attach Result';
  panel.appendChild(header);

  const addSection = (title) => {
    const section = document.createElement('div');
    section.className = 'restore-result-section';
    section.textContent = title;
    panel.appendChild(section);
  };

  const addPolar = (ok, okText, failText, warnOnFail = false) => {
    const item = document.createElement('div');
    const useWarn = !ok && warnOnFail;
    item.className = `restore-result-item ${useWarn ? 'warn' : (ok ? 'ok' : 'fail')}`;
    item.textContent = `${ok ? '✓' : (useWarn ? '⚠' : '✗')} ${ok ? okText : failText}`;
    panel.appendChild(item);
  };

  const addNeutral = (textValue) => {
    const item = document.createElement('div');
    item.className = 'restore-result-item neutral';
    item.textContent = `· ${textValue}`;
    panel.appendChild(item);
  };

  const signatureCount = classified.signatures.length;
  const timestampCount = classified.timestamps.length;
  const publicKeyCount = classified.pqPublicKeyFileBytesList.length;

  addSection('Result');
  addPolar(true, 'Lifecycle bundle updated', '');
  if (plan.embedIntoShards) {
    addPolar(true, 'Selected shard files updated', '');
  } else {
    addNeutral('Shard files were not rewritten.');
  }
  addPolar(true, 'Signable archive-state bytes remained unchanged', '');

  addSection('Detached Evidence');
  if (signatureCount > 0) addPolar(true, `Detached signatures merged (${signatureCount})`, '');
  else addNeutral('No detached signatures were supplied.');
  if (publicKeyCount > 0) addPolar(true, `Signer public keys merged (${publicKeyCount})`, '');
  else addNeutral('No signer public keys were supplied.');
  if (timestampCount > 0) addPolar(true, `Timestamp proofs merged (${timestampCount})`, '');
  else addNeutral('No timestamp proofs were supplied.');

  addSection('Next Actions');
  addNeutral('Export the updated lifecycle bundle or shard set, or continue to Restore with the merged evidence.');

  panel.className = 'restore-result-panel ok';
}

async function exportSignableArtifact() {
  const input = document.getElementById('qcontAttachInput');
  const files = [...(input?.files || [])];
  if (!files.length) {
    showToast('Select attach files first.', 'warning');
    return;
  }

  setButtonsDisabled(true);
  try {
    const classified = await classifyAttachFiles(files);

    let signableBytes = classified.archiveStateBytes;
    if (!signableBytes && classified.lifecycleBundleBytes) {
      const parsedLifecycleBundle = await parseLifecycleBundleBytes(classified.lifecycleBundleBytes);
      signableBytes = canonicalizeArchiveStateDescriptor(parsedLifecycleBundle.lifecycleBundle.archiveState).bytes;
    }
    if (!signableBytes && classified.shardFiles.length > 0) {
      const shardBytes = await readFileAsUint8Array(classified.shardFiles[0]);
      const parsedShard = await parseLifecycleShard(shardBytes, { strict: true });
      signableBytes = parsedShard.archiveStateBytes;
    }
    if (!(signableBytes instanceof Uint8Array)) {
      throw new Error('No archive-state descriptor is available to export.');
    }

    const name = deriveSignableFilename(files);
    download(new Blob([signableBytes], { type: 'application/json' }), name);
    logSuccess(`Extracted canonical archive-state descriptor: ${name}`);
  } catch (error) {
    logError(error);
  } finally {
    setButtonsDisabled(false);
    void updateAttachStatus();
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
      throw new Error('The selected inputs contain only the archive-state descriptor; there are no attached artifacts to export.');
    }

    const baseName = deriveArchiveBaseName(files);
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
    void updateAttachStatus();
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
    const shards = await parseAttachShards(classified);
    if (!classified.shardFiles.length && !(classified.lifecycleBundleBytes instanceof Uint8Array)) {
      throw new Error('Attach requires at least one successor .qcont shard or an existing lifecycle bundle.');
    }

    const plan = deriveAttachPlan(shards);
    if (plan.warning) {
      logWarning(plan.hint);
    } else {
      log(plan.hint);
    }

    const expectedEd25519Signer = String(expectedEdSigner?.value || '').trim();
    const result = await attachLifecycleBundleToShards(shards, {
      archiveStateBytes: classified.archiveStateBytes,
      lifecycleBundleBytes: classified.lifecycleBundleBytes,
      signatures: classified.signatures,
      timestamps: classified.timestamps,
      pqPublicKeyFileBytesList: classified.pqPublicKeyFileBytesList,
      expectedEd25519Signer,
      embedIntoShards: plan.embedIntoShards,
    });

    if (plan.embedIntoShards && classified.shardFiles.length > 0) {
      classified.shardFiles.forEach((file, index) => {
        const updated = result.shards[index];
        download(updated.blob, file.name);
        log(`Updated ${file.name} (${updated.blob.size} B)`);
      });
    }

    const bundleName = deriveBundleFilename(files);
    download(new Blob([result.lifecycleBundleBytes], { type: 'application/json' }), bundleName);
    if (plan.embedIntoShards && classified.shardFiles.length > 0) {
      logSuccess(`Embedded attached artifacts into the selected successor shards and updated ${bundleName}.`);
    } else {
      logSuccess(`Updated ${bundleName} without rewriting shard files.`);
    }
    log(`Lifecycle bundle digest: ${result.lifecycleBundleDigestHex}`);
    if (result.mixedEmbeddedLifecycleBundleDigests) {
      logWarning('The selected successor shard set previously carried multiple embedded lifecycle-bundle digests within one cohort. The attach result preserves that fact without treating it as mixed cohorts.');
    }
    log('Detached archive-approval signatures bind the canonical archive-state descriptor bytes, not mutable lifecycle-bundle bytes.');
    log('Next actions: export the updated lifecycle bundle or shard set, or continue to Restore with the merged evidence.');
    buildAttachResultSummary({ plan, classified });
  } catch (error) {
    logError(error);
  } finally {
    setButtonsDisabled(false);
    void updateAttachStatus();
  }
}

export function initQcontAttachUI() {
  const attachInput = document.getElementById('qcontAttachInput');
  const attachBtn = document.getElementById('attachQcontBtn');
  const exportBtn = document.getElementById('exportSignableArtifactBtn');
  const exportArtifactsBtn = document.getElementById('exportAttachedArtifactsBtn');

  attachInput?.addEventListener('change', () => {
    clearAttachResultPanel();
    void updateAttachStatus();
  });
  attachBtn?.addEventListener('click', attachFilesToShards);
  exportBtn?.addEventListener('click', exportSignableArtifact);
  exportArtifactsBtn?.addEventListener('click', exportAttachedArtifacts);
  setAttachActionAvailability();
  void updateAttachStatus();
}
