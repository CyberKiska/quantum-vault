import {
  attachLifecycleBundleToShards,
  exportSourceEvidenceForSigning,
  parseLifecycleShard,
} from '../../../app/crypto-service.js';
import { packPqpk } from '../../crypto/auth/qsig.js';
import { base64ToBytes, bytesEqual } from '../../crypto/bytes.js';
import { isSupportedStellarSignatureDocumentBytes } from '../../crypto/auth/stellar-sig.js';
import {
  canonicalizeArchiveStateDescriptor,
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
  parseSourceEvidenceBytes,
  parseTransitionRecordBytes,
} from '../../crypto/lifecycle/artifacts.js';
import { startsWithAscii } from '../../crypto/byte-prefix.js';
import { log, logError, logSuccess, logWarning } from '../ui/logging.js';
import { showToast } from '../ui/toast.js';
import { download, readFileAsUint8Array, setButtonsDisabled } from '../../../utils.js';

const ATTACH_CHANNELS = Object.freeze({
  'archive-approval': Object.freeze({
    label: 'Archive approval',
    buttonLabel: 'Attach Archive-Approval Evidence',
    channelHelp: 'Archive approval attaches detached signatures over the canonical archive-state descriptor. Maintenance and source-evidence remain separate evidence channels and never satisfy archive policy on their own.',
    inputHint: 'Load one archive cohort plus any archive-approval .qsig/.sig, .pqpk signer pins, and optional .ots proofs you want to merge.',
    emptySelectionText: 'Select archive-approval attach inputs to see the attach plan.',
    attachSummary: 'Archive-approval evidence merged',
  }),
  maintenance: Object.freeze({
    label: 'Maintenance signature',
    buttonLabel: 'Attach Maintenance Evidence',
    channelHelp: 'Maintenance signatures target a canonical transition-record already present in the selected lifecycle bundle. This evidence stays separate from archive approval and does not satisfy archive policy.',
    inputHint: 'Load one archive cohort or lifecycle bundle, the matching canonical transition-record.json, one or more maintenance .qsig/.sig files, any .pqpk signer pins, and optional .ots proofs.',
    emptySelectionText: 'Select maintenance attach inputs to see the attach plan.',
    attachSummary: 'Maintenance evidence merged',
  }),
  'source-evidence': Object.freeze({
    label: 'Source evidence',
    buttonLabel: 'Attach Source-Evidence Signatures',
    channelHelp: 'Source-evidence signatures target canonical source-evidence JSON, not archive-state approval bytes. This channel is provenance only and never satisfies archive policy.',
    inputHint: 'Load one archive cohort or lifecycle bundle, the canonical source-evidence.json artifact, one or more detached signatures over that exact JSON, any .pqpk signer pins, and optional .ots proofs.',
    emptySelectionText: 'Select source-evidence attach inputs to see the attach plan.',
    attachSummary: 'Source-evidence signatures merged',
  }),
});
const SOURCE_DIGEST_ALGORITHMS = Object.freeze(['SHA3-512', 'SHA3-256', 'SHA-256']);
const SOURCE_EVIDENCE_DIGEST_DEFAULT = Object.freeze({
  alg: 'SHA3-512',
  value: '',
});

function isLegacyAttachFilename(name) {
  return /\.qvmanifest\.json$/i.test(String(name || ''));
}

function activeAttachChannel() {
  const select = document.getElementById('attachEvidenceChannel');
  const value = String(select?.value || 'archive-approval');
  return ATTACH_CHANNELS[value] ? value : 'archive-approval';
}

function attachChannelConfig(channel = activeAttachChannel()) {
  return ATTACH_CHANNELS[channel] || ATTACH_CHANNELS['archive-approval'];
}

function ensureSingleCanonicalArtifact(existingBytes, parsedArtifact, duplicateMessage) {
  if (existingBytes && !bytesEqual(existingBytes, parsedArtifact.bytes)) {
    throw new Error(duplicateMessage);
  }
  return parsedArtifact.bytes;
}

export async function classifyAttachFiles(files) {
  const shardFiles = [];
  const signatures = [];
  const timestamps = [];
  const pqPublicKeyFileBytesList = [];
  let archiveStateBytes = null;
  let lifecycleBundleBytes = null;
  let transitionRecordBytes = null;
  let sourceEvidenceBytes = null;

  for (const file of files) {
    const name = String(file?.name || 'unnamed');
    const lowerName = name.toLowerCase();
    if (lowerName.endsWith('.qcont')) {
      shardFiles.push(file);
      continue;
    }
    if (isLegacyAttachFilename(name)) {
      throw new Error(
        'Unsupported attach input: manifest-side files are no longer accepted here. Use successor shards, archive-state descriptors, lifecycle bundles, archive-approval .qsig/.sig files, .pqpk files, or .ots proofs.'
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
      archiveStateBytes = ensureSingleCanonicalArtifact(
        archiveStateBytes,
        parsedArchiveState,
        'Multiple different archive-state descriptor files were provided. Keep only one.'
      );
      continue;
    } catch (error) {
      if (lowerName.endsWith('.archive-state.json')) {
        throw error;
      }
    }

    try {
      const parsedTransitionRecord = parseTransitionRecordBytes(bytes);
      transitionRecordBytes = ensureSingleCanonicalArtifact(
        transitionRecordBytes,
        parsedTransitionRecord,
        'Multiple different transition-record files were provided. Keep only one.'
      );
      continue;
    } catch (error) {
      if (lowerName.endsWith('.transition-record.json')) {
        throw error;
      }
    }

    try {
      const parsedSourceEvidence = parseSourceEvidenceBytes(bytes);
      sourceEvidenceBytes = ensureSingleCanonicalArtifact(
        sourceEvidenceBytes,
        parsedSourceEvidence,
        'Multiple different source-evidence files were provided. Keep only one.'
      );
      continue;
    } catch (error) {
      if (lowerName.endsWith('.source-evidence.json')) {
        throw error;
      }
    }
  }

  return {
    shardFiles,
    archiveStateBytes,
    lifecycleBundleBytes,
    transitionRecordBytes,
    sourceEvidenceBytes,
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

function deriveSourceEvidenceFilename(sourceFiles) {
  return `${deriveArchiveBaseName(sourceFiles)}.source-evidence.json`;
}

function setAttachChannelUi(channel = activeAttachChannel()) {
  const config = attachChannelConfig(channel);
  const help = document.getElementById('attachChannelHelp');
  const hint = document.getElementById('attachInputHint');
  const attachBtn = document.getElementById('attachQcontBtn');
  const sourceEvidenceBuilderSection = document.getElementById('sourceEvidenceBuilderSection');
  if (help) help.textContent = config.channelHelp;
  if (hint) hint.textContent = `${config.inputHint} Signing remains external.`;
  if (attachBtn) attachBtn.textContent = config.buttonLabel;
  if (sourceEvidenceBuilderSection) {
    const visible = channel === 'source-evidence';
    sourceEvidenceBuilderSection.classList.toggle('initially-hidden', !visible);
    sourceEvidenceBuilderSection.open = visible;
  }
}

function createSourceEvidenceDigestRow(initial = SOURCE_EVIDENCE_DIGEST_DEFAULT) {
  const row = document.createElement('div');
  row.className = 'split-grid source-evidence-digest-row';

  const algGroup = document.createElement('div');
  algGroup.className = 'form-group';
  const algLabel = document.createElement('label');
  algLabel.textContent = 'Digest algorithm';
  const algSelect = document.createElement('select');
  algSelect.className = 'source-evidence-digest-alg';
  for (const alg of SOURCE_DIGEST_ALGORITHMS) {
    const option = document.createElement('option');
    option.value = alg;
    option.textContent = alg;
    if (alg === initial.alg) option.selected = true;
    algSelect.appendChild(option);
  }
  algGroup.appendChild(algLabel);
  algGroup.appendChild(algSelect);

  const valueGroup = document.createElement('div');
  valueGroup.className = 'form-group';
  const valueLabel = document.createElement('label');
  valueLabel.textContent = 'Hex digest';
  const valueInput = document.createElement('input');
  valueInput.type = 'text';
  valueInput.className = 'source-evidence-digest-value';
  valueInput.placeholder = 'Lowercase hex digest';
  valueInput.value = initial.value || '';
  valueGroup.appendChild(valueLabel);
  valueGroup.appendChild(valueInput);

  const removeGroup = document.createElement('div');
  removeGroup.className = 'form-group';
  const removeLabel = document.createElement('label');
  removeLabel.textContent = 'Row';
  const removeButton = document.createElement('button');
  removeButton.type = 'button';
  removeButton.className = 'button secondary small';
  removeButton.textContent = 'Remove';
  removeButton.addEventListener('click', () => {
    const rows = [...document.querySelectorAll('#sourceEvidenceDigestRows .source-evidence-digest-row')];
    if (rows.length <= 1) {
      showToast('Keep at least one source digest row.', 'warning');
      return;
    }
    row.remove();
  });
  removeGroup.appendChild(removeLabel);
  removeGroup.appendChild(removeButton);

  row.appendChild(algGroup);
  row.appendChild(valueGroup);
  row.appendChild(removeGroup);
  return row;
}

function ensureSourceEvidenceDigestRows() {
  const container = document.getElementById('sourceEvidenceDigestRows');
  if (!container) return;
  if (container.children.length === 0) {
    container.appendChild(createSourceEvidenceDigestRow());
  }
}

function collectSourceEvidenceBuilderParams() {
  const relationType = String(document.getElementById('sourceEvidenceRelationType')?.value || '').trim();
  const sourceObjectType = String(document.getElementById('sourceEvidenceObjectType')?.value || '').trim();
  const rows = [...document.querySelectorAll('#sourceEvidenceDigestRows .source-evidence-digest-row')];
  const sourceDigests = rows.map((row, index) => {
    const alg = String(row.querySelector('.source-evidence-digest-alg')?.value || '').trim();
    const value = String(row.querySelector('.source-evidence-digest-value')?.value || '').trim().toLowerCase();
    if (!alg || !value) {
      throw new Error(`Source digest row ${index + 1} is incomplete.`);
    }
    return { alg, value };
  });
  if (!relationType) {
    throw new Error('Source-evidence relationType is required.');
  }
  if (!sourceObjectType) {
    throw new Error('Source-evidence sourceObjectType is required.');
  }
  if (sourceDigests.length === 0) {
    throw new Error('Provide at least one source digest.');
  }

  const params = {
    relationType,
    sourceObjectType,
    sourceDigests,
  };

  const externalRefsText = String(document.getElementById('sourceEvidenceExternalRefs')?.value || '').trim();
  if (externalRefsText) {
    const externalSourceSignatureRefs = externalRefsText
      .split(/\r?\n|,/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (externalSourceSignatureRefs.length > 0) {
      params.externalSourceSignatureRefs = externalSourceSignatureRefs;
    }
  }

  const mediaTypeOptIn = document.getElementById('sourceEvidenceMediaTypeOptIn')?.checked === true;
  const mediaType = String(document.getElementById('sourceEvidenceMediaType')?.value || '').trim();
  if (mediaTypeOptIn) {
    params.descriptiveFieldOptIn = ['mediaType'];
    if (mediaType) {
      params.mediaType = mediaType;
    }
  }

  return params;
}

function updateSourceEvidenceOptInUi() {
  const optInChecked = document.getElementById('sourceEvidenceMediaTypeOptIn')?.checked === true;
  const group = document.getElementById('sourceEvidenceMediaTypeGroup');
  if (group) {
    group.classList.toggle('initially-hidden', !optInChecked);
  }
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

function deriveAttachRequirements(channel, classified) {
  const hasAttachTarget = classified.shardFiles.length > 0 || classified.lifecycleBundleBytes instanceof Uint8Array;
  if (channel === 'maintenance') {
    return {
      canAttach: hasAttachTarget && classified.transitionRecordBytes instanceof Uint8Array && classified.signatures.length > 0,
      missingLabel: 'load successor shards or a lifecycle bundle, one canonical transition-record.json, and at least one maintenance signature',
    };
  }
  if (channel === 'source-evidence') {
    return {
      canAttach: hasAttachTarget && classified.sourceEvidenceBytes instanceof Uint8Array && classified.signatures.length > 0,
      missingLabel: 'load successor shards or a lifecycle bundle, one canonical source-evidence.json, and at least one detached signature',
    };
  }
  return {
    canAttach: hasAttachTarget,
    missingLabel: 'load successor shards or a lifecycle bundle',
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
  const channel = activeAttachChannel();
  const channelConfig = attachChannelConfig(channel);
  setAttachChannelUi(channel);
  if (!input || !status || !text || !hint) return;
  const count = input.files?.length || 0;
  if (count === 0) {
    status.style.display = 'none';
    status.className = 'shards-status initially-hidden';
    text.textContent = channelConfig.emptySelectionText;
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
    const requirements = deriveAttachRequirements(channel, classified);
    const canAttach = requirements.canAttach;
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
      summary = `More input required: ${requirements.missingLabel}`;
    } else if (plan.warning) {
      stateClass = 'insufficient';
    }

    if (!summary) {
      summary = plan.embedIntoShards
        ? (plan.warning ? `Ready to update selected shards only (${channelConfig.label.toLowerCase()})` : `Ready to embed ${channelConfig.label.toLowerCase()} evidence into selected shards`)
        : `Ready to update the lifecycle bundle only (${channelConfig.label.toLowerCase()})`;
    }

    status.className = `shards-status ${stateClass}`;
    text.textContent = summary;
    hint.textContent = `${count} file(s) loaded. ${!canAttach
      ? `Attach stays blocked until the input includes ${requirements.missingLabel}.`
      : `${plan.hint} ${channelConfig.channelHelp}`}`;
    status.setAttribute('aria-label', summary);
    if (modeSummary) {
      const artifactSummary = [
        `Signatures: ${classified.signatures.length}`,
        `Pins: ${classified.pqPublicKeyFileBytesList.length}`,
        `OTS proofs: ${classified.timestamps.length}`,
        `Transition record: ${classified.transitionRecordBytes instanceof Uint8Array ? 'yes' : 'no'}`,
        `Source evidence: ${classified.sourceEvidenceBytes instanceof Uint8Array ? 'yes' : 'no'}`,
      ].join('\n');
      modeSummary.textContent = `${summary}\n${plan.modeLabel}\n${artifactSummary}`;
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

function buildAttachResultSummary({ plan, classified, channel }) {
  const panel = document.getElementById('attachResult');
  if (!panel) return;
  const channelConfig = attachChannelConfig(channel);

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

  addSection('Evidence Channel');
  addNeutral(`${channelConfig.label} selected for this attach run.`);
  if (channel === 'maintenance') {
    addPolar(true, 'Transition-record target stayed separate from archive approval', '');
  } else if (channel === 'source-evidence') {
    addPolar(true, 'Source-evidence signatures stayed separate from archive approval', '');
  } else {
    addPolar(true, 'Archive-approval signatures stayed on archive-state bytes', '');
  }

  addSection('Imported Files');
  if (signatureCount > 0) {
    const label = channel === 'archive-approval'
      ? 'Archive-approval signatures merged'
      : channel === 'maintenance'
        ? 'Maintenance signatures merged'
        : 'Source-evidence signatures merged';
    addPolar(true, `${label} (${signatureCount})`, '');
  } else {
    addNeutral(`No ${channelConfig.label.toLowerCase()} .qsig/.sig files were supplied.`);
  }
  if (channel === 'maintenance') {
    if (classified.transitionRecordBytes instanceof Uint8Array) addPolar(true, 'Canonical transition-record target loaded', '');
    else addNeutral('No transition-record.json target was supplied.');
  }
  if (channel === 'source-evidence') {
    if (classified.sourceEvidenceBytes instanceof Uint8Array) addPolar(true, 'Canonical source-evidence artifact loaded', '');
    else addNeutral('No source-evidence.json artifact was supplied.');
  }
  if (publicKeyCount > 0) addPolar(true, `.pqpk signer pins merged (${publicKeyCount})`, '');
  else addNeutral('No .pqpk signer pins were supplied.');
  if (timestampCount > 0) addPolar(true, `.ots proofs merged (${timestampCount})`, '');
  else addNeutral('No .ots proofs were supplied.');

  addSection('Next Actions');
  addNeutral('Continue to Restore to inspect archive approval, maintenance, and source-evidence channels separately.');

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
      throw new Error('The selected inputs contain only the archive-state descriptor; there are no attached bundle files to export.');
    }

    const baseName = deriveArchiveBaseName(files);
    const artifacts = buildAttachedArtifactExports(bundle, baseName);
    let exportedCount = 0;
    for (const artifact of artifacts) {
      download(new Blob([artifact.bytes], { type: artifact.type }), artifact.filename);
      exportedCount += 1;
    }

    if (exportedCount === 0) {
      throw new Error('No attached signatures, signer keys, or OTS proofs were found in the lifecycle bundle.');
    }
    logSuccess(`Exported ${exportedCount} attached lifecycle-bundle file(s), including any embedded OTS proofs.`);
  } catch (error) {
    logError(error);
  } finally {
    setButtonsDisabled(false);
    void updateAttachStatus();
  }
}

async function exportSourceEvidenceArtifact() {
  setButtonsDisabled(true);
  try {
    const input = document.getElementById('qcontAttachInput');
    const files = [...(input?.files || [])];
    const exported = exportSourceEvidenceForSigning({
      sourceEvidence: collectSourceEvidenceBuilderParams(),
    });
    const filename = deriveSourceEvidenceFilename(files);
    download(new Blob([exported.sourceEvidenceBytes], { type: 'application/json' }), filename);
    logSuccess(`Exported canonical source-evidence JSON for external signing: ${filename}`);
    log(`Source-evidence digest: ${exported.sourceEvidenceDigestHex}`);
    log('This export is the signing target. Sign it externally, then re-import the same .source-evidence.json plus the detached signature through Attach > Source evidence.');
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
  const channel = activeAttachChannel();
  const channelConfig = attachChannelConfig(channel);
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
    let signatureImports = [];
    let legacyArchiveApprovalSignatures = classified.signatures;
    if (channel === 'maintenance') {
      if (!(classified.transitionRecordBytes instanceof Uint8Array)) {
        throw new Error('Maintenance attach requires one canonical transition-record.json artifact.');
      }
      const parsedTransitionRecord = parseTransitionRecordBytes(classified.transitionRecordBytes);
      signatureImports = classified.signatures.map((signature) => ({
        ...signature,
        signatureFamily: 'maintenance',
        targetType: 'transition-record',
        targetRef: `transition:sha3-512:${parsedTransitionRecord.digest.value}`,
        targetDigest: parsedTransitionRecord.digest.value,
      }));
      legacyArchiveApprovalSignatures = [];
    } else if (channel === 'source-evidence') {
      if (!(classified.sourceEvidenceBytes instanceof Uint8Array)) {
        throw new Error('Source-evidence attach requires one canonical source-evidence.json artifact.');
      }
      const parsedSourceEvidence = parseSourceEvidenceBytes(classified.sourceEvidenceBytes);
      signatureImports = classified.signatures.map((signature) => ({
        ...signature,
        signatureFamily: 'source-evidence',
        targetType: 'source-evidence',
        targetRef: `source-evidence:sha3-512:${parsedSourceEvidence.digest.value}`,
        targetDigest: parsedSourceEvidence.digest.value,
        sourceEvidenceBytes: parsedSourceEvidence.bytes,
      }));
      legacyArchiveApprovalSignatures = [];
    }
    const result = await attachLifecycleBundleToShards(shards, {
      archiveStateBytes: classified.archiveStateBytes,
      lifecycleBundleBytes: classified.lifecycleBundleBytes,
      signatures: legacyArchiveApprovalSignatures,
      signatureImports,
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
      logSuccess(`Embedded the updated lifecycle bundle into the selected successor shards and wrote ${bundleName}.`);
    } else {
      logSuccess(`Updated ${bundleName} without rewriting shard files.`);
    }
    log(`Lifecycle bundle digest: ${result.lifecycleBundleDigestHex}`);
    if (result.mixedEmbeddedLifecycleBundleDigests) {
      logWarning('The selected successor shard set previously carried multiple embedded lifecycle-bundle digests within one cohort. The attach result preserves that fact without treating it as mixed cohorts.');
    }
    if (channel === 'maintenance') {
      logSuccess('Maintenance signatures were attached against a canonical transition-record target already present in the selected lifecycle bundle.');
      log('Maintenance signatures remain a separate evidence channel and do not imply archive-policy satisfaction.');
    } else if (channel === 'source-evidence') {
      logSuccess('Source-evidence signatures were attached against canonical source-evidence JSON.');
      log('Source evidence remains provenance only and does not imply archive approval or archive-policy satisfaction.');
    } else {
      log('Detached archive-approval signatures bind the canonical archive-state descriptor bytes, not mutable lifecycle-bundle bytes.');
    }
    log('All signing remains external in this workflow. Quantum Vault imports detached artifacts and reports each channel separately at Restore.');
    log('Next actions: export the updated archive-state descriptor, lifecycle bundle, or shard set, or continue to Restore with the merged evidence.');
    buildAttachResultSummary({ plan, classified, channel });
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
  const attachChannel = document.getElementById('attachEvidenceChannel');
  const exportBtn = document.getElementById('exportSignableArtifactBtn');
  const exportArtifactsBtn = document.getElementById('exportAttachedArtifactsBtn');
  const exportSourceEvidenceBtn = document.getElementById('exportSourceEvidenceBtn');
  const addDigestBtn = document.getElementById('addSourceEvidenceDigestBtn');
  const mediaTypeOptIn = document.getElementById('sourceEvidenceMediaTypeOptIn');

  attachInput?.addEventListener('change', () => {
    clearAttachResultPanel();
    void updateAttachStatus();
  });
  attachChannel?.addEventListener('change', () => {
    clearAttachResultPanel();
    setAttachChannelUi(activeAttachChannel());
    void updateAttachStatus();
  });
  attachBtn?.addEventListener('click', attachFilesToShards);
  exportBtn?.addEventListener('click', exportSignableArtifact);
  exportArtifactsBtn?.addEventListener('click', exportAttachedArtifacts);
  exportSourceEvidenceBtn?.addEventListener('click', exportSourceEvidenceArtifact);
  addDigestBtn?.addEventListener('click', () => {
    const container = document.getElementById('sourceEvidenceDigestRows');
    container?.appendChild(createSourceEvidenceDigestRow());
  });
  mediaTypeOptIn?.addEventListener('change', updateSourceEvidenceOptInUi);
  ensureSourceEvidenceDigestRows();
  updateSourceEvidenceOptInUi();
  setAttachChannelUi(activeAttachChannel());
  setAttachActionAvailability();
  void updateAttachStatus();
}
