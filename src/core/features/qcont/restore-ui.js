import {
  parseLifecycleShard,
  restoreFromShards,
  zeroizeParsedLifecycleShard,
} from '../../../app/crypto-service.js';
import { registerSessionWipeHandler } from '../../../app/session-wipe.js';
import { classifyRestoreInputFiles } from '../../../app/restore-inputs.js';
import { parseLifecycleBundleViewBytes } from '../../../app/artifact-intake-service.js';
import { download, readFileAsUint8Array, setWorkflowBusy, shortenHash } from '../../../utils.js';
import { wipeRestoreResult } from '../../crypto/zeroize.js';
import {
  formatAuthenticityStatusMessage,
  formatSignatureResultSummary,
  log,
  logError,
  logSuccess,
  logWarning,
} from '../ui/logging.js';
import { renderDecisionCard } from '../ui/decision-card.js';
import { buildLifecyclePathDecisionRow } from './successor-selection-view-model.js';
import { clearInlineError, showInlineError, summarizeFileList } from '../ui/inline-error.js';
import { renderArtifactIntakeTable } from '../ui/artifact-intake.js';
import {
  buildRestoreEvidenceMatrixSections,
  buildRestorePolicyFailureEvidenceMatrixSections,
  getRestoreReleaseState,
  renderSplitRestoreEvidence,
} from '../ui/evidence-matrix.js';
import { showToast } from '../ui/toast.js';
import { buildRestoreRecoveryAction } from './restore-recovery-action.js';
import { collectLifecycleAttachmentCounts, peekSuccessorSelectionState } from './successor-selection-ui.js';
const RESTORE_INLINE_ERROR_ID = 'proRestoreInlineError';
const RESTORE_PREFLIGHT_CARD_ID = 'restorePreflightDecision';
let proRestoreEvaluation = null;
let restoreSelectionListenerRegistered = false;

function restoreRecoveryAction(error) {
  return buildRestoreRecoveryAction(error, { verb: 'Restore' });
}

function releaseTextForPolicy(policyLevel, allowed) {
  if (!allowed) return 'Plaintext release: blocked';
  if (policyLevel === 'integrity-only') return 'Plaintext release: allowed by integrity-only policy';
  if (policyLevel === 'strong-pq-signature') return 'Plaintext release: allowed by strong PQ archive-approval policy';
  if (policyLevel === 'any-signature') return 'Plaintext release: allowed by archive-signature policy';
  return 'Plaintext release: allowed by selected archive policy';
}

function preflightAlertLabel(blockingTone, compact) {
  if (blockingTone === 'fail') return compact ? 'Block' : 'Blocking reason';
  if (blockingTone === 'warn') return 'Warning';
  return compact ? 'Note' : 'Next step';
}

function restoreDefaultActionLabel(prefix) {
  return prefix === 'liteRestore' ? 'Restore Selected Archive' : 'Evaluate Restore';
}

function restoreBlockedActionLabel(decision) {
  const reason = String(decision?.blockingReason || '').toLowerCase();
  if (reason.includes('no successor') || reason.includes('no shard')) return 'Load Restore Inputs';
  if (reason.includes('threshold') || reason.includes('selected shards')) return 'Load More Shards';
  if (reason.includes('selection') || reason.includes('archive/state') || reason.includes('cohort')) return 'Resolve Archive Selection';
  if (reason.includes('archive-approval') || reason.includes('signature evidence')) return 'Add Archive-Approval Evidence';
  return 'Resolve Restore Blocker';
}

function applyRestorePreflightActionState(actionButton, decision, { prefix = 'restore' } = {}) {
  if (!actionButton) return;
  if (!actionButton.dataset.defaultLabel) {
    actionButton.dataset.defaultLabel = actionButton.textContent || restoreDefaultActionLabel(prefix);
  }
  const defaultLabel = actionButton.dataset.defaultLabel || restoreDefaultActionLabel(prefix);
  const blocked = decision?.canEvaluate === false;
  actionButton.textContent = blocked ? restoreBlockedActionLabel(decision) : defaultLabel;
  actionButton.disabled = blocked;
  if (blocked) {
    const reason = decision?.blockingReason || 'Resolve the restore preflight blocker before evaluation.';
    actionButton.title = reason;
    actionButton.setAttribute('aria-label', `${actionButton.textContent}: ${reason}`);
  } else {
    actionButton.removeAttribute('title');
    actionButton.removeAttribute('aria-label');
  }
}

function shouldShowPreflightAlertRow(decision) {
  const reason = String(decision.blockingReason || '').trim();
  if (decision.blockingTone === 'fail' || decision.blockingTone === 'warn') return true;
  if (decision.blockingTone === 'ok' && (!reason || reason === 'None')) return false;
  return Boolean(reason);
}

function renderRestorePreflightCard(containerId, decision, options = {}) {
  const compact = options.compact === true;
  const panel = document.getElementById(containerId);
  if (!panel) return;

  const rootTestId = containerId === 'liteRestorePreflightDecision' ? 'lite-restore-preflight' : 'restore-preflight';

  if (!decision) {
    renderDecisionCard(panel, null, {
      rootDataTestId: rootTestId,
    });
    return;
  }

  const policyLabel = 'Policy';
  const archiveLabel = compact ? 'Archive / state / cohort' : 'Archive, state, and cohort';
  const thresholdLabel = compact ? 'Threshold' : 'Threshold readiness';
  const rows = [
    { label: policyLabel, value: decision.policy || 'unknown', tone: decision.policyTone || 'neutral' },
    { label: archiveLabel, value: decision.selection || 'Pending selection', tone: decision.selectionTone || 'neutral' },
  ];
  if (decision.lifecyclePathRow) {
    rows.push(decision.lifecyclePathRow);
  }
  rows.push(
    { label: thresholdLabel, value: decision.thresholdReadiness || 'Not evaluated', tone: decision.thresholdTone || 'neutral' },
  );
  if (shouldShowPreflightAlertRow(decision)) {
    rows.push({
      label: preflightAlertLabel(decision.blockingTone, compact),
      value: decision.blockingReason || 'None',
      tone: decision.blockingTone || 'neutral',
    });
  }

  renderDecisionCard(
    panel,
    {
      title: 'Restore decision',
      tone: decision.tone || 'neutral',
      primaryOutcome: decision.releaseText || 'Plaintext release: blocked',
      lede: decision.lede || 'Restore inputs are evaluated before any recovered bytes can be released.',
      rows,
    },
    {
      dataAttrs: { 'release-state': decision.releaseState || 'blocked' },
      rootDataTestId: rootTestId,
      ariaLive: 'polite',
    }
  );
}

function clearRestorePreflightCard(containerId) {
  renderRestorePreflightCard(containerId, null);
}

function getSelectedPreflightPath(model, selection = {}) {
  const states = Array.isArray(model?.states) ? model.states : [];
  let selectedState = states.find((state) => state.key === selection.selectedStateKey) || null;
  if (!selectedState && selection.selectedArchiveId && selection.selectedStateId) {
    selectedState = states.find((state) => (
      state.archiveId === selection.selectedArchiveId && state.stateId === selection.selectedStateId
    )) || null;
  }
  if (!selectedState && states.length === 1) {
    selectedState = states[0];
  }

  let selectedCohort = null;
  if (selectedState) {
    selectedCohort = selectedState.cohorts.find((cohort) => cohort.cohortId === selection.selectedCohortId) || null;
    if (!selectedCohort && selectedState.cohorts.length === 1) {
      selectedCohort = selectedState.cohorts[0];
    }
  }

  let selectedLifecycleBundleDigestHex = selection.selectedLifecycleBundleDigestHex || null;
  if (!selectedLifecycleBundleDigestHex && selectedCohort?.bundleDigests.length === 1) {
    selectedLifecycleBundleDigestHex = selectedCohort.bundleDigests[0];
  }

  return { selectedState, selectedCohort, selectedLifecycleBundleDigestHex };
}

function formatPreflightSelection({ selectedState, selectedCohort }) {
  if (!selectedState && !selectedCohort) return 'Pending selection';
  const archiveState = selectedState
    ? `Archive ${shortenHash(selectedState.archiveId)} / State ${shortenHash(selectedState.stateId)}`
    : 'Archive/state selected by supplied lifecycle bundle';
  const cohort = selectedCohort ? `Cohort ${shortenHash(selectedCohort.cohortId)}` : 'cohort pending';
  return `${archiveState} / ${cohort}`;
}

function countProvidedLifecycleEvidence(parsedProvidedBundle) {
  return collectLifecycleAttachmentCounts(parsedProvidedBundle?.lifecycleBundle ? [parsedProvidedBundle.lifecycleBundle] : []);
}

function buildPreflightBlockedDecision({
  assessment,
  selectedState,
  selectedCohort,
  selectedLifecycleBundleDigestHex,
  policyLevel = 'unknown',
  reason,
  tone = 'fail',
  compact = false,
  lifecyclePathRow = null,
}) {
  const thresholdReady = assessment?.ready === true;
  return {
    releaseText: releaseTextForPolicy(policyLevel, false),
    releaseState: 'blocked',
    tone,
    lede: compact
      ? 'Release stays blocked until this is resolved.'
      : 'No recovered bytes will be released while this condition is unresolved.',
    thresholdReadiness: thresholdReady
      ? assessment.message || 'Threshold ready'
      : assessment?.message || 'Threshold not ready',
    thresholdTone: thresholdReady ? 'ok' : 'fail',
    selection: formatPreflightSelection({ selectedState, selectedCohort }),
    selectionTone: selectedState && selectedCohort ? 'ok' : 'warn',
    lifecycleBundleDigest: selectedLifecycleBundleDigestHex
      ? shortenHash(selectedLifecycleBundleDigestHex)
      : 'Pending selection',
    bundleTone: selectedLifecycleBundleDigestHex ? 'ok' : 'warn',
    policy: policyLevel,
    policyTone: policyLevel === 'integrity-only' ? 'warn' : 'neutral',
    blockingReason: reason,
    blockingTone: 'fail',
    canEvaluate: false,
    lifecyclePathRow,
  };
}

/**
 * Pure view-model for the restore decision card (shared by Lite and Pro preflight).
 * Callers supply classified inputs and optional parsed lifecycle bundle; async I/O stays outside.
 */
export function buildRestoreDecisionViewModel({
  assessment = null,
  classified,
  parsedProvidedBundle = null,
  successorSelection = {},
  classifyError = null,
  expectedEd25519Signer = '',
  compact = false,
}) {
  if (classifyError) {
    return buildPreflightBlockedDecision({
      assessment,
      selectedState: null,
      selectedCohort: null,
      selectedLifecycleBundleDigestHex: null,
      policyLevel: 'unknown',
      reason: classifyError,
      compact,
    });
  }
  if (!classified) {
    return buildPreflightBlockedDecision({
      assessment,
      selectedState: null,
      selectedCohort: null,
      selectedLifecycleBundleDigestHex: null,
      policyLevel: 'unknown',
      reason: 'Restore inputs could not be classified.',
      compact,
    });
  }

  const selected = successorSelection;
  const model = selected.model || { states: [] };
  const lifecyclePathRow = buildLifecyclePathDecisionRow(selected, classified);
  const { selectedState, selectedCohort, selectedLifecycleBundleDigestHex } = getSelectedPreflightPath(model, selected);
  const providedCounts = countProvidedLifecycleEvidence(parsedProvidedBundle);
  const policyLevel = String(
    parsedProvidedBundle?.lifecycleBundle?.authPolicy?.level ||
    selectedCohort?.policyLevels?.[0] ||
    selectedState?.cohorts?.flatMap((cohort) => cohort.policyLevels || [])?.[0] ||
    'unknown'
  );
  const lifecycleBundleDigest = parsedProvidedBundle?.digest?.value || selectedLifecycleBundleDigestHex;

  if (!classified.shardFiles.length) {
    return buildPreflightBlockedDecision({
      assessment,
      selectedState,
      selectedCohort,
      selectedLifecycleBundleDigestHex: lifecycleBundleDigest,
      policyLevel,
      reason: 'No successor QVqcont-7 shard files were detected.',
      compact,
      lifecyclePathRow,
    });
  }
  if (assessment?.ready !== true) {
    return buildPreflightBlockedDecision({
      assessment,
      selectedState,
      selectedCohort,
      selectedLifecycleBundleDigestHex: lifecycleBundleDigest,
      policyLevel,
      reason: assessment?.message || 'Selected shards do not meet the recovery threshold.',
      compact,
      lifecyclePathRow,
    });
  }
  if (selected.selectionComplete === false) {
    return buildPreflightBlockedDecision({
      assessment,
      selectedState,
      selectedCohort,
      selectedLifecycleBundleDigestHex: lifecycleBundleDigest,
      policyLevel,
      reason: 'Resolve archive/state/cohort/lifecycle-bundle selection before restore evaluation.',
      compact,
      lifecyclePathRow,
    });
  }

  const detachedSignatureCount = classified.signatures.length;
  const embeddedArchiveApprovalCount = (
    Number(selectedCohort?.archiveApprovalSignatureCount || 0) +
    Number(providedCounts.archiveApprovalSignatureCount || 0)
  );
  const signatureCount = detachedSignatureCount + embeddedArchiveApprovalCount;
  const userPinnedPqKeyCount = Array.isArray(classified.pinnedPqPublicKeyFileBytesList)
    ? classified.pinnedPqPublicKeyFileBytesList.length
    : 0;
  const embeddedPublicKeyCount = (
    Number(selectedCohort?.publicKeyCount || 0) +
    Number(providedCounts.publicKeyCount || 0)
  );

  const thresholdText = assessment?.message || 'Threshold ready';
  const common = {
    thresholdReadiness: thresholdText,
    thresholdTone: 'ok',
    selection: formatPreflightSelection({ selectedState, selectedCohort }),
    selectionTone: selectedState && selectedCohort ? 'ok' : 'neutral',
    lifecycleBundleDigest: lifecycleBundleDigest ? shortenHash(lifecycleBundleDigest) : 'Embedded or provided bundle selected',
    bundleTone: lifecycleBundleDigest ? 'ok' : 'neutral',
    policy: policyLevel,
    policyTone: policyLevel === 'integrity-only' ? 'warn' : 'neutral',
    lifecyclePathRow,
  };

  if (policyLevel === 'integrity-only') {
    return {
      ...common,
      releaseText: releaseTextForPolicy(policyLevel, true),
      releaseState: 'allowed-provisional',
      tone: 'warn',
      lede: compact
        ? 'Integrity-only policy: external archive approval is not required; verification must still pass.'
        : 'Policy consequence is clear before evaluation: archive approval is not required, but integrity checks must still pass before release.',
      blockingReason: 'None. Archive approval is not required by this policy.',
      blockingTone: 'warn',
      canEvaluate: true,
    };
  }

  if ((policyLevel === 'strong-pq-signature' || policyLevel === 'any-signature') && signatureCount < 1) {
    const reason = policyLevel === 'strong-pq-signature'
      ? 'strong PQ archive-approval signature evidence is required before reconstruction.'
      : 'Archive-signature policy requires archive-approval signature evidence before reconstruction.';
    return {
      ...common,
      releaseText: releaseTextForPolicy(policyLevel, false),
      releaseState: 'blocked',
      tone: 'fail',
      lede: compact
        ? 'Required archive-approval signature evidence is missing before reconstruction.'
        : 'Restore evaluation is blocked before reconstruction because required approval evidence is absent.',
      blockingReason: reason,
      blockingTone: 'fail',
      canEvaluate: false,
    };
  }

  const evidenceParts = [
    `${signatureCount} archive-approval signature artifact${signatureCount === 1 ? '' : 's'}`,
    `${userPinnedPqKeyCount + embeddedPublicKeyCount} signer pin artifact${userPinnedPqKeyCount + embeddedPublicKeyCount === 1 ? '' : 's'}`,
  ];
  if (expectedEd25519Signer) evidenceParts.push('expected Ed25519 signer entered');

  return {
    ...common,
    releaseText: releaseTextForPolicy(policyLevel, false),
    releaseState: 'pending-evaluation',
    tone: 'neutral',
    lede: compact
      ? `Evidence present (${evidenceParts.join(', ')}). Run Restore to verify before release.`
      : `Evidence is present (${evidenceParts.join(', ')}). Release remains blocked until cryptographic evaluation succeeds.`,
    blockingReason: compact
      ? 'Run Restore to verify; release stays blocked until integrity and policy checks pass.'
      : 'Run Evaluate Restore; release remains blocked until integrity and archive policy checks pass.',
    blockingTone: 'neutral',
    canEvaluate: true,
  };
}

async function buildRestorePreflightDecisionForFiles({
  prefix = 'restore',
  files = [],
  expectedSignerInput,
}) {
  const selected = peekSuccessorSelectionState(prefix) || {};
  const assessment = selected.assessment || null;
  const compact = prefix === 'liteRestore';
  if (!files.length) return null;

  let classified;
  try {
    classified = await classifyRestoreInputFiles(files);
  } catch (error) {
    return buildRestoreDecisionViewModel({
      assessment,
      classified: null,
      parsedProvidedBundle: null,
      successorSelection: selected,
      classifyError: error?.message || String(error),
      expectedEd25519Signer: String(expectedSignerInput?.value || '').trim(),
      compact,
    });
  }

  let parsedProvidedBundle = null;
  if (classified.lifecycleBundleBytes instanceof Uint8Array) {
    try {
      parsedProvidedBundle = await parseLifecycleBundleViewBytes(classified.lifecycleBundleBytes);
    } catch {
      parsedProvidedBundle = null;
    }
  }

  return buildRestoreDecisionViewModel({
    assessment,
    classified,
    parsedProvidedBundle,
    successorSelection: selected,
    classifyError: null,
    expectedEd25519Signer: String(expectedSignerInput?.value || '').trim(),
    compact,
  });
}

export async function renderRestorePreflightForFiles({
  prefix = 'restore',
  containerId = RESTORE_PREFLIGHT_CARD_ID,
  files = [],
  expectedSignerInput = null,
  actionButton = null,
}) {
  const decision = await buildRestorePreflightDecisionForFiles({ prefix, files, expectedSignerInput });
  renderRestorePreflightCard(containerId, decision, { compact: prefix === 'liteRestore' });
  applyRestorePreflightActionState(actionButton, decision, { prefix });
  return decision;
}

export function buildRestoreDecisionViewModelFromEvaluationResult(result) {
  const policyLevel = String(result?.authenticity?.policy?.level || 'unknown');
  const releaseAllowed = (
    result?.qencOk === true &&
    result?.qkeyOk === true &&
    result?.authenticity?.status?.policySatisfied === true
  );
  let reason = 'None';
  if (!result?.qencOk || !result?.qkeyOk) {
    reason = 'Recovered container or private key failed integrity verification.';
  } else if (result?.authenticity?.status?.policySatisfied !== true) {
    reason = 'Archive policy is not satisfied by verified archive-approval evidence.';
  }

  let blockingReason = reason;
  const blockingTone = releaseAllowed ? (policyLevel === 'integrity-only' ? 'warn' : 'ok') : 'fail';
  if (releaseAllowed && policyLevel === 'integrity-only') {
    blockingReason = 'Integrity-only: external archive approval is not claimed for this recovery.';
  }

  return {
    releaseText: releaseTextForPolicy(policyLevel, releaseAllowed),
    releaseState: releaseAllowed ? 'allowed' : 'blocked',
    tone: releaseAllowed ? (policyLevel === 'integrity-only' ? 'warn' : 'ok') : 'fail',
    lede: releaseAllowed
      ? 'Evaluation passed. Recovered bytes remain local until Release Recovered Files is pressed.'
      : 'Evaluation completed without release permission.',
    thresholdReadiness: 'Threshold met and reconstruction evaluated',
    thresholdTone: 'ok',
    selection: `Archive ${shortenHash(result?.archiveId || '')} / State ${shortenHash(result?.stateId || '')} / Cohort ${shortenHash(result?.cohortId || '')}`,
    selectionTone: 'ok',
    lifecycleBundleDigest: result?.lifecycleBundleDigestHex ? shortenHash(result.lifecycleBundleDigestHex) : 'unknown',
    bundleTone: result?.lifecycleBundleDigestHex ? 'ok' : 'neutral',
    policy: policyLevel,
    policyTone: policyLevel === 'integrity-only' ? 'warn' : 'neutral',
    blockingReason,
    blockingTone,
    canEvaluate: true,
    canRelease: releaseAllowed,
  };
}

function setReleaseButtonState(enabled) {
  const button = document.getElementById('releaseRestoredFilesBtn');
  if (!button) return;
  button.disabled = !enabled;
  button.classList.toggle('initially-hidden', !enabled);
  button.style.display = enabled ? 'inline-flex' : 'none';
}

function clearProRestoreEvaluation() {
  wipeRestoreResult(proRestoreEvaluation?.result);
  proRestoreEvaluation = null;
  setReleaseButtonState(false);
}

async function readVerificationOptionsFromDom({
  prefix = 'restore',
  allFiles = [],
  expectedSignerInput,
}) {
  const classified = await classifyRestoreInputFiles(allFiles);
  const selected = peekSuccessorSelectionState(prefix) || {};
  return {
    ...classified,
    expectedEd25519Signer: String(expectedSignerInput?.value || '').trim(),
    selectedArchiveId: selected.selectedArchiveId || null,
    selectedStateId: selected.selectedStateId || null,
    selectedCohortId: selected.selectedCohortId || null,
    selectedLifecycleBundleDigestHex: selected.selectedLifecycleBundleDigestHex || null,
  };
}

export function logVerificationSummary(authenticity, onLog, onWarn, onSuccess) {
  const policy = authenticity?.policy;
  const verification = authenticity?.verification;
  const status = authenticity?.status;
  const sourceEvidenceReport = authenticity?.sourceEvidenceReport;

  if (policy) {
    onLog(`Archive policy: ${policy.level} (min signatures ${policy.minValidSignatures})`);
    if (policy.satisfied) {
      onSuccess('Archive policy satisfied.');
    }
  }

  if (status) {
    const signatureStatus = formatAuthenticityStatusMessage(status);
    if (signatureStatus) {
      if (status.signerPinned) onSuccess(signatureStatus);
      else onWarn(`${signatureStatus.slice(0, -1)}; no signer pin is active.`);
    }
  }

  for (const warning of authenticity?.warnings || []) {
    onWarn(warning);
  }
  for (const evidence of authenticity?.timestampEvidence || []) {
    const completionLabel = evidence.apparentlyComplete === true
      ? 'OTS proof appears complete (heuristic)'
      : 'OTS proof incomplete or pending';
    onLog(`${evidence.linkLabel}: ${evidence.targetRef}. ${completionLabel}. Timestamp evidence does not satisfy archive policy.`);
  }
  if (sourceEvidenceReport?.present) {
    const descriptiveFieldCount = Array.isArray(sourceEvidenceReport.descriptiveFieldNames)
      ? sourceEvidenceReport.descriptiveFieldNames.length
      : 0;
    onLog(
      `Source evidence: objects=${sourceEvidenceReport.count}, signed=${sourceEvidenceReport.sourceEvidenceSignatureCount}, verified=${sourceEvidenceReport.verifiedSourceEvidenceSignatureCount}, external-source-signature-refs=${sourceEvidenceReport.externalSourceSignatureRefCount}, descriptive-fields=${descriptiveFieldCount}.`
    );
  }
  if (!verification) return;

  const counts = verification.counts || {};
  onLog(
    `Archive-approval counts: valid=${counts.validArchiveApproval ?? 0}, strong-pq=${counts.validArchiveApprovalStrongPq ?? 0}, pinned=${counts.archiveApprovalPinnedValidTotal ?? 0}, bundle-pinned=${counts.archiveApprovalBundlePinnedValidTotal ?? 0}, user-pinned=${counts.archiveApprovalUserPinnedValidTotal ?? 0}.`
  );
  onLog(
    `Maintenance counts: valid=${counts.validMaintenance ?? 0}, transition-records=${authenticity?.status?.transitionRecordPresent === true ? 1 : 0}.`
  );
  onLog(
    `Source-evidence counts: valid=${counts.validSourceEvidence ?? 0}, objects=${sourceEvidenceReport?.count ?? 0}.`
  );
  onLog(
    `Detached signature totals across all families: valid=${counts.validTotal ?? 0}, strong-pq=${counts.validStrongPq ?? 0}, pinned=${counts.pinnedValidTotal ?? 0}, bundle-pinned=${counts.bundlePinnedValidTotal ?? 0}, user-pinned=${counts.userPinnedValidTotal ?? 0}.`
  );
  for (const warning of verification.warnings || []) {
    onWarn(warning);
  }
  for (const item of verification.results || []) {
    if (item.ok) {
      onSuccess(`Signature OK: ${formatSignatureResultSummary(item)}`);
    } else {
      onWarn(`Signature failed: ${item.name} (${item.error || 'unknown error'})`);
    }
  }
}

export function logRestoreSelectionSummary(result, onLog) {
  onLog(`Selected archiveId: ${result.archiveId}`);
  onLog(`Selected stateId: ${result.stateId}`);
  onLog(`Selected cohortId: ${result.cohortId}`);
  onLog(`Selected lifecycle bundle digest: ${result.lifecycleBundleDigestHex}`);
  if (Array.isArray(result.embeddedLifecycleBundleDigestsUsed) && result.embeddedLifecycleBundleDigestsUsed.length > 0) {
    onLog(`Embedded lifecycle bundle digests used: ${result.embeddedLifecycleBundleDigestsUsed.join(', ')}`);
  }
  onLog(`Selection source: ${result.selectionSource || 'embedded'}`);
}

/**
 * @param {object} result - restoreFromShards result
 * @param {string} resultPanelId - DOM id of `.restore-result-panel`
 * @param {{ liteDecrypt?: { containerOk: boolean, decryptOk: boolean } }} [options] - Lite mode adds decrypt/output line under Integrity
 */
export function buildRestoreResultSummary(result, resultPanelId, options = {}) {
  const panel = document.getElementById(resultPanelId);
  if (!panel) return;

  panel.replaceChildren();
  panel.style.display = 'block';
  const { releaseAllowed, policyLevel, policyOk } = getRestoreReleaseState(result, options);
  const releasePerformed = options.releasePerformed !== false;

  const header = document.createElement('h4');
  if (releaseAllowed && !releasePerformed && policyLevel === 'integrity-only') {
    header.textContent = 'Plaintext release allowed under integrity-only policy';
  } else if (releaseAllowed && !releasePerformed && policyLevel === 'strong-pq-signature') {
    header.textContent = 'Plaintext release allowed under strong PQ archive-approval policy';
  } else if (releaseAllowed && !releasePerformed && policyLevel === 'any-signature') {
    header.textContent = 'Plaintext release allowed under archive-signature policy';
  } else if (releaseAllowed && policyLevel === 'integrity-only') {
    header.textContent = 'Plaintext released under integrity-only policy';
  } else if (releaseAllowed && policyLevel === 'strong-pq-signature') {
    header.textContent = 'Plaintext released under strong PQ archive-approval policy';
  } else if (releaseAllowed && policyLevel === 'any-signature') {
    header.textContent = 'Plaintext released under archive-signature policy';
  } else if (!policyOk) {
    header.textContent = 'Plaintext not released: archive policy not satisfied';
  } else {
    header.textContent = 'Plaintext not released: integrity check failed';
  }
  panel.appendChild(header);

  const intro = document.createElement('p');
  intro.className = 'restore-result-lede';
  intro.textContent = releaseAllowed
    ? (
        releasePerformed
          ? 'Restore release is separated from archive approval, signer pinning, timestamp evidence, maintenance evidence, and source evidence.'
          : 'Evaluation passed. Recovered bytes are held in memory until Release Recovered Files is pressed.'
      )
    : 'No plaintext was released. Review the failed row before retrying restore.';
  panel.appendChild(intro);

  renderSplitRestoreEvidence(panel, buildRestoreEvidenceMatrixSections(result, options), {
    compact: options.compact === true,
    disclosureLabel: 'Evidence matrix',
    startExpanded: options.evidenceExpanded === true,
  });

  const panelTone = releaseAllowed && policyLevel !== 'integrity-only' ? 'ok' : (releaseAllowed ? 'warn' : 'fail');
  panel.className = `restore-result-panel ${panelTone}`;
}

function isArchivePolicyFailureMessage(error) {
  const message = String(error?.message || error || '').toLowerCase();
  return (
    message.includes('archive-policy signature') ||
    message.includes('archive policy') ||
    message.includes('archive-approval signature satisfies archive policy') ||
    message.includes('strong pq archive-approval signature satisfies archive policy')
  );
}

export function buildRestorePolicyFailureSummary(error, resultPanelId) {
  const panel = document.getElementById(resultPanelId);
  if (!panel || !isArchivePolicyFailureMessage(error)) return false;

  panel.replaceChildren();
  panel.style.display = 'block';

  const header = document.createElement('h4');
  header.textContent = 'Plaintext not released: archive policy not satisfied';
  panel.appendChild(header);

  const intro = document.createElement('p');
  intro.className = 'restore-result-lede';
  intro.textContent = 'No plaintext or recovered key was exported because archive policy blocked restore before reconstruction.';
  panel.appendChild(intro);

  renderSplitRestoreEvidence(panel, buildRestorePolicyFailureEvidenceMatrixSections(error), { compact: true });

  panel.className = 'restore-result-panel fail';
  return true;
}

export function initQcontRestoreUI() {
  registerSessionWipeHandler(clearProRestoreEvaluation);
  const qcontShardsInput = document.getElementById('qcontShardsInput');
  const restoreQcontBtn = document.getElementById('restoreQcontBtn');
  const releaseRestoredFilesBtn = document.getElementById('releaseRestoredFilesBtn');

  const restoreExpectedEdSigner = document.getElementById('restoreExpectedEdSigner');

  if (!restoreSelectionListenerRegistered) {
    document.addEventListener('qv:successor-selection-change', (event) => {
      if (event?.detail?.prefix !== 'restore') return;
      clearInlineError(RESTORE_INLINE_ERROR_ID);
      clearProRestoreEvaluation();
    });
    restoreSelectionListenerRegistered = true;
  }

  restoreQcontBtn?.addEventListener('click', async () => {
    const files = qcontShardsInput?.files;
    if (!files?.length) {
      showInlineError(RESTORE_INLINE_ERROR_ID, {
        title: 'Restore blocked',
        cause: 'No restore input files are selected.',
        artifact: 'Restore input set',
        action: 'Load successor QVqcont-7 shards and any detached evidence required by the archive policy.',
      });
      showToast('Select .qcont shards to restore.', 'warning');
      return;
    }

    clearProRestoreEvaluation();
    const resultPanel = document.getElementById('proRestoreResult');
    if (resultPanel) {
      resultPanel.style.display = 'none';
      resultPanel.replaceChildren();
    }

    setWorkflowBusy('proViewRestore', true);
    let renderedPreflightDecision = null;
    let shardBytesArr = [];
    let shards = [];
    try {
      clearInlineError(RESTORE_INLINE_ERROR_ID);
      const allFiles = [...files];
      const preflight = await renderRestorePreflightForFiles({
        prefix: 'restore',
        containerId: RESTORE_PREFLIGHT_CARD_ID,
        files: allFiles,
        expectedSignerInput: restoreExpectedEdSigner,
      });
      renderedPreflightDecision = preflight;
      if (preflight && preflight.canEvaluate === false) {
        throw new Error(preflight.blockingReason || 'Restore preflight blocked evaluation.');
      }

      const verificationOptions = await readVerificationOptionsFromDom({
        prefix: 'restore',
        allFiles,
        expectedSignerInput: restoreExpectedEdSigner,
      });
      if (!verificationOptions.shardFiles.length) {
        throw new Error('No .qcont shard files were detected in selected input.');
      }
      if (verificationOptions.ignoredFileNames.length > 0) {
        logWarning(`Ignored non-restore attachments: ${verificationOptions.ignoredFileNames.join(', ')}`);
      }

      shardBytesArr = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
      shards = await Promise.all(shardBytesArr.map((bytes) => parseLifecycleShard(bytes, { strict: true })));

      const result = await restoreFromShards(shards, {
        onLog: (msg) => log(msg),
        onError: (msg) => logError(msg),
        onWarn: (msg) => logWarning(msg),
        verification: verificationOptions,
      });

      logRestoreSelectionSummary(result, log);
      logVerificationSummary(result.authenticity, log, logWarning, logSuccess);

      const { containerHash, privateKeyHash, recoveredQencHash, recoveredPrivHash, qencOk, qkeyOk } = result;
      log(`Recovered .qenc SHA3-512=${recoveredQencHash} (expected ${containerHash})`);
      log(`Recovered .qkey SHA3-512=${recoveredPrivHash}${privateKeyHash ? ` (expected ${privateKeyHash})` : ''}`);

      if (qencOk && qkeyOk && result.authenticity?.status?.policySatisfied) {
        proRestoreEvaluation = { result };
        setReleaseButtonState(true);
        logSuccess('Restore inputs evaluated. Release Recovered Files is now available.');
        clearInlineError(RESTORE_INLINE_ERROR_ID);
      } else {
        clearProRestoreEvaluation();
        logError('Verification failed. Release Recovered Files remains blocked.');
      }

      renderRestorePreflightCard(RESTORE_PREFLIGHT_CARD_ID, buildRestoreDecisionViewModelFromEvaluationResult(result));
      buildRestoreResultSummary(result, 'proRestoreResult', { releasePerformed: false });
    } catch (error) {
      buildRestorePolicyFailureSummary(error, 'proRestoreResult');
      if (renderedPreflightDecision?.canEvaluate === false) {
        renderRestorePreflightCard(RESTORE_PREFLIGHT_CARD_ID, renderedPreflightDecision);
      } else {
        renderRestorePreflightCard(RESTORE_PREFLIGHT_CARD_ID, {
          releaseText: releaseTextForPolicy('unknown', false),
          releaseState: 'blocked',
          tone: 'fail',
          lede: 'Restore evaluation did not release recovered bytes.',
          thresholdReadiness: 'See restore input status',
          thresholdTone: 'neutral',
          selection: 'See selected archive/state/cohort',
          selectionTone: 'neutral',
          lifecycleBundleDigest: 'See selected lifecycle bundle',
          bundleTone: 'neutral',
          policy: 'unknown',
          policyTone: 'neutral',
          blockingReason: error?.message || String(error),
          blockingTone: 'fail',
        });
      }
      await renderArtifactIntakeTable({
        containerId: 'restoreArtifactIntake',
        files: [...(files || [])],
        workflow: 'restore',
        label: 'Restore artifact intake',
        error,
      });
      showInlineError(RESTORE_INLINE_ERROR_ID, {
        title: 'Restore blocked',
        cause: error,
        artifact: summarizeFileList([...(files || [])], 'Restore input set'),
        action: restoreRecoveryAction(error),
      });
      logError(error);
    } finally {
      for (const shard of shards) zeroizeParsedLifecycleShard(shard);
      for (const bytes of shardBytesArr) {
        if (bytes instanceof Uint8Array) bytes.fill(0);
      }
      setWorkflowBusy('proViewRestore', false);
      setReleaseButtonState(Boolean(proRestoreEvaluation));
    }
  });

  releaseRestoredFilesBtn?.addEventListener('click', () => {
    const result = proRestoreEvaluation?.result;
    if (!result) {
      showToast('Evaluate restore inputs before release.', 'warning');
      return;
    }
    try {
      const { qencBytes, privKey, containerId, qencOk, qkeyOk } = result;
      if (!(qencOk && qkeyOk && result.authenticity?.status?.policySatisfied)) {
        throw new Error('Release blocked: restore evaluation is no longer policy-satisfying.');
      }
      download(new Blob([qencBytes], { type: 'application/octet-stream' }), `${containerId}.recovered.qenc`);
      download(new Blob([privKey], { type: 'application/octet-stream' }), `${containerId}.recovered.privateKey.qkey`);
      buildRestoreResultSummary(result, 'proRestoreResult', { releasePerformed: true });
      renderRestorePreflightCard(RESTORE_PREFLIGHT_CARD_ID, buildRestoreDecisionViewModelFromEvaluationResult(result));
      logSuccess('Recovered .qenc and .qkey released from a policy-satisfying archive cohort.');
      clearInlineError(RESTORE_INLINE_ERROR_ID);
    } catch (error) {
      showInlineError(RESTORE_INLINE_ERROR_ID, {
        title: 'Release blocked',
        cause: error,
        artifact: 'Evaluated restore output',
        action: 'Re-evaluate the selected restore inputs and release only after the preflight card allows it.',
      });
      logError(error);
    } finally {
      clearProRestoreEvaluation();
    }
  });

  qcontShardsInput?.addEventListener('change', () => {
    clearProRestoreEvaluation();
    clearInlineError(RESTORE_INLINE_ERROR_ID);
    const files = [...(qcontShardsInput.files || [])];
    if (!files.length) clearRestorePreflightCard(RESTORE_PREFLIGHT_CARD_ID);
  });
  restoreExpectedEdSigner?.addEventListener('input', () => {
    clearProRestoreEvaluation();
    clearInlineError(RESTORE_INLINE_ERROR_ID);
    const files = [...(qcontShardsInput?.files || [])];
    if (files.length) {
      void renderRestorePreflightForFiles({
        prefix: 'restore',
        containerId: RESTORE_PREFLIGHT_CARD_ID,
        files,
        expectedSignerInput: restoreExpectedEdSigner,
        actionButton: restoreQcontBtn,
      });
    }
  });
}

export async function collectRestoreVerificationOptions(prefix = 'restore', files = []) {
  const expectedSignerInput = document.getElementById(`${prefix}ExpectedEdSigner`);

  return readVerificationOptionsFromDom({
    prefix,
    allFiles: files,
    expectedSignerInput,
  });
}
