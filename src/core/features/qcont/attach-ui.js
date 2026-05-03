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
import { clearInlineError, showInlineError, summarizeFileList } from '../ui/inline-error.js';
import { clearArtifactIntakeTable, renderArtifactIntakeTable } from '../ui/artifact-intake.js';
import { buildAttachEvidenceMatrixSections, renderEvidenceMatrix } from '../ui/evidence-matrix.js';
import { log, logError, logSuccess, logWarning } from '../ui/logging.js';
import { showToast } from '../ui/toast.js';
import { download, readFileAsUint8Array, setWorkflowBusy } from '../../../utils.js';
import { clearArchiveInspector, renderArchiveInspectorPanel } from './archive-inspector-ui.js';
import { renderDecisionCard } from '../ui/decision-card.js';
import { syncArchiveReviewHub } from '../ui/archive-review-hub.js';
import { deriveArchiveBaseName } from './archive-name.js';
import {
  ATTACH_CHANNELS,
  attachChannelConfig,
  buildAttachPlanDecisionModel,
  deriveAttachRequirements,
} from './attach-plan-view-model.js';
import {
  clearAttachTargetBindingPreview,
  refreshAttachTargetBindingPreview,
} from './attach-target-preview-ui.js';
import {
  clearSourceEvidenceExportError,
  collectSourceEvidenceBuilderParams,
  createSourceEvidenceDigestRow,
  ensureSourceEvidenceDigestRows,
  initSourceEvidenceApplyFileToAllRows,
  refreshSourceEvidenceBuilderUi,
  showSourceEvidenceExportError,
  updateSourceEvidenceOptInUi,
} from './source-evidence-builder-ui.js';

const ATTACH_INLINE_ERROR_ID = 'attachInlineError';
let lastAttachIntakeError = null;
let attachStatusSeq = 0;

function isLegacyAttachFilename(name) {
  return /\.qvmanifest\.json$/i.test(String(name || ''));
}

function activeAttachChannel() {
  const select = document.getElementById('attachEvidenceChannel');
  const value = String(select?.value || 'archive-approval');
  return ATTACH_CHANNELS[value] ? value : 'archive-approval';
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
  refreshSourceEvidenceBuilderUi(channel);
}

function clearAttachResultPanel() {
  const panel = document.getElementById('attachResult');
  if (!panel) return;
  panel.style.display = 'none';
  panel.replaceChildren();
}

function attachRecoveryAction(error) {
  const message = String(error?.message || error || '').toLowerCase();
  if (message.includes('manifest-side') || message.includes('unsupported attach input')) {
    return 'Remove legacy manifest-side files and load successor shards, archive-state descriptors, lifecycle bundles, or detached evidence artifacts.';
  }
  if (message.includes('ots')) {
    return 'Check that each OTS proof targets a loaded detached signature by SHA-256(signatureBytes), then retry Attach.';
  }
  if (message.includes('transition-record')) {
    return 'Load the canonical transition-record.json for this lifecycle bundle plus matching maintenance signatures, then retry Attach.';
  }
  if (message.includes('source-evidence')) {
    return 'Load the canonical source-evidence.json plus detached signatures over that exact JSON, then retry Attach.';
  }
  return 'Remove conflicting or unsupported attach inputs, keep one archive/state/cohort set, then retry Attach.';
}

function setPartialRewriteAcknowledgementRequired(required) {
  const panel = document.getElementById('attachPartialRewriteAckPanel');
  const checkbox = document.getElementById('attachPartialRewriteAck');
  if (panel) {
    panel.classList.toggle('initially-hidden', !required);
  }
  if (checkbox) {
    checkbox.required = required;
    checkbox.disabled = !required;
    if (!required) checkbox.checked = false;
  }
}

function partialRewriteAcknowledged() {
  return document.getElementById('attachPartialRewriteAck')?.checked === true;
}

function setAttachActionAvailability({
  canAttach = false,
  canExportSignable = false,
  canExportArtifacts = false,
  partialRewriteRequiresAck = false,
} = {}) {
  const attachBtn = document.getElementById('attachQcontBtn');
  const exportBtn = document.getElementById('exportSignableArtifactBtn');
  const exportArtifactsBtn = document.getElementById('exportAttachedArtifactsBtn');
  const partialBlocked = partialRewriteRequiresAck && !partialRewriteAcknowledged();
  if (attachBtn) attachBtn.disabled = !canAttach || partialBlocked;
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
      selectedShardCount: 0,
      expectedShardCount: 0,
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
      selectedShardCount: uniqueIndices.size,
      expectedShardCount,
      warning: false,
    };
  }

  return {
    embedIntoShards: true,
    modeLabel: 'Partial successor shard rewrite',
    hint: `Only ${uniqueIndices.size}/${expectedShardCount} successor shard files are loaded. Attach will rewrite only the selected shard files; other shards from the same cohort may still carry older embedded lifecycle-bundle bytes.`,
    selectedShardCount: uniqueIndices.size,
    expectedShardCount,
    warning: true,
  };
}

function shortHexForAttachPreview(value) {
  const s = String(value || '').trim();
  if (!s) return '—';
  if (s.length <= 40) return s;
  return `${s.slice(0, 18)}…${s.slice(-12)}`;
}

async function safeAttachPreviewPlan(classified) {
  if (!classified) {
    return { shards: [], plan: deriveAttachPlan([]) };
  }
  try {
    const shards = await parseAttachShards(classified);
    return { shards, plan: deriveAttachPlan(shards) };
  } catch {
    return { shards: [], plan: deriveAttachPlan([]) };
  }
}

async function resolveAttachBindingTarget(classified, channel, shards) {
  if (channel === 'maintenance') {
    if (classified.transitionRecordBytes instanceof Uint8Array) {
      try {
        const parsed = parseTransitionRecordBytes(classified.transitionRecordBytes);
        return {
          artifactLabel: 'transition-record (canonical JSON)',
          targetRef: `transition:sha3-512:${parsed.digest.value}`,
          digestSummary: shortHexForAttachPreview(parsed.digest.value),
        };
      } catch {
        return {
          artifactLabel: 'transition-record',
          targetRef: '(unreadable transition-record.json)',
          digestSummary: '—',
        };
      }
    }
    return {
      artifactLabel: 'transition-record',
      targetRef: '(load canonical transition-record.json)',
      digestSummary: '—',
    };
  }
  if (channel === 'source-evidence') {
    if (classified.sourceEvidenceBytes instanceof Uint8Array) {
      try {
        const parsed = parseSourceEvidenceBytes(classified.sourceEvidenceBytes);
        return {
          artifactLabel: 'source-evidence (canonical JSON)',
          targetRef: `source-evidence:sha3-512:${parsed.digest.value}`,
          digestSummary: shortHexForAttachPreview(parsed.digest.value),
        };
      } catch {
        return {
          artifactLabel: 'source-evidence',
          targetRef: '(unreadable source-evidence.json)',
          digestSummary: '—',
        };
      }
    }
    return {
      artifactLabel: 'source-evidence',
      targetRef: '(load canonical source-evidence.json)',
      digestSummary: '—',
    };
  }
  try {
    if (Array.isArray(shards) && shards.length > 0 && shards[0]?.archiveStateBytes instanceof Uint8Array) {
      const embedded = parseArchiveStateDescriptorBytes(shards[0].archiveStateBytes);
      return {
        artifactLabel: 'archive-state descriptor (canonical JSON)',
        targetRef: `state:${embedded.stateId}`,
        digestSummary: shortHexForAttachPreview(embedded.digest.value),
      };
    }
    if (classified.lifecycleBundleBytes instanceof Uint8Array) {
      const parsed = await parseLifecycleBundleBytes(classified.lifecycleBundleBytes);
      const canon = canonicalizeArchiveStateDescriptor(parsed.lifecycleBundle.archiveState);
      return {
        artifactLabel: 'archive-state descriptor (canonical JSON)',
        targetRef: `state:${canon.stateId}`,
        digestSummary: shortHexForAttachPreview(canon.digest.value),
      };
    }
    if (classified.archiveStateBytes instanceof Uint8Array) {
      const parsed = parseArchiveStateDescriptorBytes(classified.archiveStateBytes);
      return {
        artifactLabel: 'archive-state descriptor (canonical JSON)',
        targetRef: `state:${parsed.stateId}`,
        digestSummary: shortHexForAttachPreview(parsed.digest.value),
      };
    }
  } catch {
    return {
      artifactLabel: 'archive-state descriptor',
      targetRef: '(could not resolve)',
      digestSummary: '—',
    };
  }
  return {
    artifactLabel: 'archive-state descriptor',
    targetRef: '(load successor shards or a lifecycle bundle)',
    digestSummary: '—',
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
  const requestId = ++attachStatusSeq;
  const input = document.getElementById('qcontAttachInput');
  const status = document.getElementById('attachStatus');
  const text = document.getElementById('attachStatusText');
  const hint = document.getElementById('attachStatusHint');
  const planPanel = document.getElementById('attachPlanDecision');
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
    lastAttachIntakeError = null;
    clearArtifactIntakeTable('attachArtifactIntake');
    clearArchiveInspector('attachArchiveInspector');
    setPartialRewriteAcknowledgementRequired(false);
    if (planPanel) {
      renderDecisionCard(planPanel, null, {
        rootDataTestId: 'attach-plan-decision',
      });
    }
    setAttachActionAvailability();
    clearAttachResultPanel();
    clearAttachTargetBindingPreview();
    if (requestId !== attachStatusSeq) return;
    syncArchiveReviewHub('attach');
    return;
  }

  status.style.display = 'block';
  status.className = 'shards-status unknown';
  text.textContent = 'Analyzing attach inputs...';
  hint.textContent = `${count} file(s) loaded.`;
  status.setAttribute('aria-label', text.textContent);
  let classified = null;
  try {
    const files = [...(input.files || [])];
    classified = await classifyAttachFiles(files);
    if (requestId !== attachStatusSeq) return;
    await renderArtifactIntakeTable({
      containerId: 'attachArtifactIntake',
      files,
      workflow: 'attach',
      channel,
      label: `${channelConfig.label} artifact intake`,
      error: lastAttachIntakeError,
    });
    if (requestId !== attachStatusSeq) return;
    const shards = await parseAttachShards(classified);
    if (requestId !== attachStatusSeq) return;
    const plan = deriveAttachPlan(shards);
    const requirements = deriveAttachRequirements(channel, classified);
    const binding = await resolveAttachBindingTarget(classified, channel, shards);
    const canAttach = requirements.canAttach;
    const partialRewriteRequiresAck = canAttach && plan.embedIntoShards && plan.warning;
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

    if (requestId !== attachStatusSeq) return;

    let stateClass = 'sufficient';
    let summary;
    let statusHint;
    if (!canAttach) {
      stateClass = 'invalid';
      summary = `More input required: ${requirements.missingLabel}`;
      statusHint = `${count} file(s) loaded. Attach stays blocked until the input includes ${requirements.missingLabel}.`;
    } else if (plan.warning) {
      stateClass = 'insufficient';
    }

    if (!summary) {
      if (plan.embedIntoShards && plan.warning) {
        summary = partialRewriteAcknowledged()
          ? `Ready: partial shard rewrite (${channelConfig.label.toLowerCase()})`
          : `Partial rewrite: acknowledgement required (${channelConfig.label.toLowerCase()})`;
      } else {
        summary = plan.embedIntoShards
          ? `Ready: embed evidence into selected shards (${channelConfig.label.toLowerCase()})`
          : `Ready: update lifecycle bundle only (${channelConfig.label.toLowerCase()})`;
      }
    }

    if (!statusHint) {
      statusHint = `${count} file(s) loaded. ${partialRewriteRequiresAck
        ? (partialRewriteAcknowledged()
          ? 'Acknowledgement recorded. The decision card shows the selected shard rewrite scope.'
          : 'Acknowledge the partial shard rewrite below before attaching.')
        : channelConfig.channelHelp}`;
    }

    const showStatusPanel = !partialRewriteRequiresAck;
    status.style.display = showStatusPanel ? 'block' : 'none';
    status.className = `shards-status ${stateClass}${showStatusPanel ? '' : ' initially-hidden'}`;
    text.textContent = summary;
    hint.textContent = statusHint;
    status.setAttribute('aria-label', summary);
    setPartialRewriteAcknowledgementRequired(partialRewriteRequiresAck);
    const lede = `${count} file(s) loaded. ${canAttach
      ? `${plan.hint} ${channelConfig.channelHelp}`
      : `Attach stays blocked until the input includes ${requirements.missingLabel}.`}`;
    if (planPanel) {
      const planModel = buildAttachPlanDecisionModel({
        channel,
        channelConfig,
        classified,
        shards,
        plan,
        requirements,
        canAttach,
        stateClass,
        summary,
        lede,
        binding,
      });
      renderDecisionCard(
        planPanel,
        planModel,
        {
          rootDataTestId: 'attach-plan-decision',
          ariaLive: 'polite',
          testIds: { primary: 'attach-mode-summary' },
        }
      );
    }
    setAttachActionAvailability({
      canAttach,
      canExportSignable,
      canExportArtifacts,
      partialRewriteRequiresAck,
    });
    await refreshAttachTargetBindingPreview({
      channel,
      classified,
      shards,
      plan,
      binding,
      error: lastAttachIntakeError || undefined,
    });
    if (requestId !== attachStatusSeq) return;
    if (shards.length > 0) {
      void renderArchiveInspectorPanel('attachArchiveInspector', { attachShards: shards });
    } else {
      void renderArchiveInspectorPanel('attachArchiveInspector', { files: [...(input.files || [])] });
    }
    if (requestId !== attachStatusSeq) return;
    syncArchiveReviewHub('attach');
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
    const previewCtx = await safeAttachPreviewPlan(classified);
    if (requestId !== attachStatusSeq) return;
    const errRequirements = classified
      ? deriveAttachRequirements(channel, classified)
      : { canAttach: false, missingLabel: 'load attach inputs' };
    const binding = classified
      ? await resolveAttachBindingTarget(classified, channel, previewCtx.shards)
      : null;
    if (planPanel) {
      const planModel = buildAttachPlanDecisionModel({
        channel,
        channelConfig,
        classified,
        shards: previewCtx.shards,
        plan: previewCtx.plan,
        requirements: errRequirements,
        canAttach: errRequirements.canAttach,
        stateClass: 'invalid',
        summary,
        lede: `${count} file(s) loaded. ${message}`,
        errorMode: true,
        errorMessage: message,
        binding,
      });
      renderDecisionCard(
        planPanel,
        planModel,
        {
          rootDataTestId: 'attach-plan-decision',
          ariaLive: 'polite',
          testIds: { primary: 'attach-mode-summary' },
        }
      );
    }
    lastAttachIntakeError = error;
    await renderArtifactIntakeTable({
      containerId: 'attachArtifactIntake',
      files: [...(input.files || [])],
      workflow: 'attach',
      channel,
      label: `${channelConfig.label} artifact intake`,
      error,
    });
    if (requestId !== attachStatusSeq) return;
    await refreshAttachTargetBindingPreview({
      channel,
      classified,
      shards: previewCtx.shards,
      plan: previewCtx.plan,
      binding,
      error,
    });
    if (requestId !== attachStatusSeq) return;
    void renderArchiveInspectorPanel('attachArchiveInspector', { files: [...(input.files || [])] });
    setPartialRewriteAcknowledgementRequired(false);
    setAttachActionAvailability();
    showInlineError(ATTACH_INLINE_ERROR_ID, {
      title: 'Attach inputs blocked',
      cause: message,
      artifact: summarizeFileList([...(input.files || [])], 'Attach input set'),
      action: attachRecoveryAction(error),
    });
    if (requestId !== attachStatusSeq) return;
    syncArchiveReviewHub('attach');
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

  renderEvidenceMatrix(
    panel,
    buildAttachEvidenceMatrixSections({ classified, plan, channelConfig, channel }),
    { compact: true }
  );

  panel.className = `restore-result-panel ${plan.warning ? 'warn' : 'ok'}`;
}

async function exportSignableArtifact() {
  const input = document.getElementById('qcontAttachInput');
  const files = [...(input?.files || [])];
  if (!files.length) {
    showToast('Select attach files first.', 'warning');
    return;
  }

  setWorkflowBusy('proViewAttach', true);
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
    setWorkflowBusy('proViewAttach', false);
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

  setWorkflowBusy('proViewAttach', true);
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
    setWorkflowBusy('proViewAttach', false);
    void updateAttachStatus();
  }
}

async function exportSourceEvidenceArtifact() {
  clearSourceEvidenceExportError();
  setWorkflowBusy('proViewAttach', true);
  try {
    let params;
    try {
      params = collectSourceEvidenceBuilderParams();
    } catch (err) {
      const msg = String(err?.message || err);
      showToast(msg, 'warning');
      showSourceEvidenceExportError(msg);
      return;
    }
    const input = document.getElementById('qcontAttachInput');
    const files = [...(input?.files || [])];
    const exported = exportSourceEvidenceForSigning({
      sourceEvidence: params,
    });
    const filename = deriveSourceEvidenceFilename(files);
    download(new Blob([exported.sourceEvidenceBytes], { type: 'application/json' }), filename);
    clearSourceEvidenceExportError();
    logSuccess(`Exported canonical source-evidence JSON for external signing: ${filename}`);
    log(`Source-evidence digest: ${exported.sourceEvidenceDigestHex}`);
    log('This export is the signing target. Sign it externally, then re-import the same .source-evidence.json plus the detached signature through Attach > Source evidence.');
  } catch (error) {
    const msg = String(error?.message || error);
    logError(error);
    showToast(msg, 'warning');
    showSourceEvidenceExportError(msg);
  } finally {
    setWorkflowBusy('proViewAttach', false);
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
    showInlineError(ATTACH_INLINE_ERROR_ID, {
      title: 'Attach blocked',
      cause: 'No attach input files are selected.',
      artifact: 'Attach input set',
      action: 'Load successor shards or a lifecycle bundle plus the detached evidence artifacts for the selected channel.',
    });
    showToast('Select attach files first.', 'warning');
    return;
  }

  setWorkflowBusy('proViewAttach', true);
  try {
    clearInlineError(ATTACH_INLINE_ERROR_ID);
    const classified = await classifyAttachFiles(files);
    const shards = await parseAttachShards(classified);
    if (!classified.shardFiles.length && !(classified.lifecycleBundleBytes instanceof Uint8Array)) {
      throw new Error('Attach requires at least one successor .qcont shard or an existing lifecycle bundle.');
    }

    const plan = deriveAttachPlan(shards);
    if (plan.embedIntoShards && plan.warning && !partialRewriteAcknowledged()) {
      showInlineError(ATTACH_INLINE_ERROR_ID, {
        title: 'Attach blocked',
        cause: 'Partial shard rewrite requires explicit acknowledgement.',
        artifact: summarizeFileList(files, 'Attach input set'),
        action: 'Check the partial rewrite acknowledgement or load the full shard cohort before attaching.',
      });
      showToast('Acknowledge partial shard rewrite before attaching.', 'warning');
      return;
    }
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
    lastAttachIntakeError = null;
    clearInlineError(ATTACH_INLINE_ERROR_ID);
    buildAttachResultSummary({ plan, classified, channel });
  } catch (error) {
    lastAttachIntakeError = error;
    await renderArtifactIntakeTable({
      containerId: 'attachArtifactIntake',
      files,
      workflow: 'attach',
      channel,
      label: `${channelConfig.label} artifact intake`,
      error,
    });
    showInlineError(ATTACH_INLINE_ERROR_ID, {
      title: 'Attach failed',
      cause: error,
      artifact: summarizeFileList(files, 'Attach input set'),
      action: attachRecoveryAction(error),
    });
    logError(error);
  } finally {
    setWorkflowBusy('proViewAttach', false);
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
  const partialRewriteAck = document.getElementById('attachPartialRewriteAck');
  const sourceEvidenceBuilderSection = document.getElementById('sourceEvidenceBuilderSection');
  const refreshSourceEvidenceBuilderForActiveChannel = () => refreshSourceEvidenceBuilderUi(activeAttachChannel());
  const updateSourceEvidenceOptInForActiveChannel = () => updateSourceEvidenceOptInUi(activeAttachChannel());

  attachInput?.addEventListener('change', () => {
    lastAttachIntakeError = null;
    clearInlineError(ATTACH_INLINE_ERROR_ID);
    clearAttachResultPanel();
    void updateAttachStatus();
  });
  attachChannel?.addEventListener('change', () => {
    lastAttachIntakeError = null;
    clearInlineError(ATTACH_INLINE_ERROR_ID);
    clearAttachResultPanel();
    setAttachChannelUi(activeAttachChannel());
    void updateAttachStatus();
  });
  partialRewriteAck?.addEventListener('change', () => {
    clearInlineError(ATTACH_INLINE_ERROR_ID);
    void updateAttachStatus();
  });
  attachBtn?.addEventListener('click', attachFilesToShards);
  exportBtn?.addEventListener('click', exportSignableArtifact);
  exportArtifactsBtn?.addEventListener('click', exportAttachedArtifacts);
  exportSourceEvidenceBtn?.addEventListener('click', exportSourceEvidenceArtifact);
  addDigestBtn?.addEventListener('click', () => {
    const container = document.getElementById('sourceEvidenceDigestRows');
    container?.appendChild(createSourceEvidenceDigestRow({
      onChange: refreshSourceEvidenceBuilderForActiveChannel,
    }));
    refreshSourceEvidenceBuilderForActiveChannel();
  });
  sourceEvidenceBuilderSection?.addEventListener('input', refreshSourceEvidenceBuilderForActiveChannel);
  sourceEvidenceBuilderSection?.addEventListener('change', refreshSourceEvidenceBuilderForActiveChannel);
  mediaTypeOptIn?.addEventListener('change', updateSourceEvidenceOptInForActiveChannel);
  ensureSourceEvidenceDigestRows({ onChange: refreshSourceEvidenceBuilderForActiveChannel });
  initSourceEvidenceApplyFileToAllRows(refreshSourceEvidenceBuilderForActiveChannel);
  updateSourceEvidenceOptInForActiveChannel();
  setAttachChannelUi(activeAttachChannel());
  setAttachActionAvailability();
  void updateAttachStatus();
}
