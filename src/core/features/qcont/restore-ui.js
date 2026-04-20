import { parseLifecycleShard, restoreFromShards } from '../../../app/crypto-service.js';
import { classifyRestoreInputFiles } from '../../../app/restore-inputs.js';
import { download, readFileAsUint8Array, setButtonsDisabled, shortenHash } from '../../../utils.js';
import { parseArchiveStateDescriptorBytes } from '../../crypto/lifecycle/artifacts.js';
import { mergeLifecycleShardIntoCohortGroups } from '../../crypto/qcont/lifecycle-cohort-shared.js';
import {
  formatAuthenticityStatusMessage,
  formatSignatureResultSummary,
  log,
  logError,
  logSuccess,
  logWarning,
} from '../ui/logging.js';
import { showToast } from '../ui/toast.js';

const successorSelectionState = new Map();

function getSuccessorSelectionElements(prefix = 'restore') {
  return {
    container: document.getElementById(`${prefix}SuccessorSelection`),
    summary: document.getElementById(`${prefix}SuccessorSelectionSummary`),
    help: document.getElementById(`${prefix}SuccessorSelectionHelp`),
    stateGroup: document.getElementById(`${prefix}StateSelectionGroup`),
    stateSelect: document.getElementById(`${prefix}StateSelection`),
    cohortGroup: document.getElementById(`${prefix}CohortSelectionGroup`),
    cohortSelect: document.getElementById(`${prefix}CohortSelection`),
    bundleGroup: document.getElementById(`${prefix}BundleSelectionGroup`),
    bundleSelect: document.getElementById(`${prefix}BundleSelection`),
  };
}

function buildStateSelectionKey(archiveId, stateId) {
  return `${archiveId}:${stateId}`;
}

function describeStateOption(state) {
  return `Archive ${shortenHash(state.archiveId)} / State ${shortenHash(state.stateId)} (${state.cohorts.length} cohort${state.cohorts.length === 1 ? '' : 's'})`;
}

function describeCohortOption(cohort) {
  const bundleVariantCount = cohort.bundleDigests.length;
  const bundleLabel = bundleVariantCount === 1
    ? '1 embedded lifecycle bundle'
    : `${bundleVariantCount} embedded lifecycle bundles`;
  return `Cohort ${shortenHash(cohort.cohortId)} (${cohort.shardCount}/${cohort.n} shards loaded, threshold ${cohort.t}, ${bundleLabel})`;
}

function populateSelectionOptions(select, options, selectedValue, placeholder) {
  if (!select) return;
  select.replaceChildren();
  if (placeholder) {
    const placeholderOption = document.createElement('option');
    placeholderOption.value = '';
    placeholderOption.textContent = placeholder;
    select.appendChild(placeholderOption);
  }
  for (const option of options) {
    const optionEl = document.createElement('option');
    optionEl.value = option.value;
    optionEl.textContent = option.label;
    select.appendChild(optionEl);
  }
  select.value = selectedValue || '';
}

function setRestoreActionAvailability(prefix, actionButton) {
  if (!actionButton) return;
  const state = successorSelectionState.get(prefix);
  const readyForThreshold = state?.assessment?.ready === true;
  const readyForSelection = state?.selectionComplete !== false;
  actionButton.disabled = !(readyForThreshold && readyForSelection);
}

function renderSelectionInfoUi(prefix, actionButton, nextState, summaryText, helpText, mode = 'invalid') {
  const elements = getSuccessorSelectionElements(prefix);
  if (elements.container) {
    elements.container.style.display = 'block';
    elements.container.className = 'verification-section successor-selection';
  }
  if (elements.summary) elements.summary.textContent = summaryText;
  if (elements.help) elements.help.textContent = helpText;
  [elements.stateGroup, elements.cohortGroup, elements.bundleGroup].forEach((group) => {
    if (group) group.style.display = 'none';
  });
  successorSelectionState.set(prefix, {
    ...nextState,
    mode,
    selectionRequired: true,
    selectionComplete: false,
  });
  setRestoreActionAvailability(prefix, actionButton);
  return successorSelectionState.get(prefix);
}

function clearSuccessorSelectionUi(prefix, actionButton) {
  const elements = getSuccessorSelectionElements(prefix);
  if (elements.container) {
    elements.container.style.display = 'none';
    elements.container.className = 'verification-section initially-hidden';
  }
  if (elements.summary) elements.summary.textContent = '';
  if (elements.help) elements.help.textContent = '';
  [elements.stateGroup, elements.cohortGroup, elements.bundleGroup].forEach((group) => {
    if (group) group.style.display = 'none';
  });
  successorSelectionState.set(prefix, {
    mode: 'none',
    assessment: successorSelectionState.get(prefix)?.assessment || null,
    actionButton,
    files: [],
    selectionRequired: false,
    selectionComplete: true,
    selectedArchiveId: null,
    selectedStateId: null,
    selectedCohortId: null,
    selectedLifecycleBundleDigestHex: null,
  });
  setRestoreActionAvailability(prefix, actionButton);
}

export function buildSuccessorSelectionModel(parsedShards = []) {
  const byIdentity = new Map();
  for (const shard of parsedShards) {
    mergeLifecycleShardIntoCohortGroups(byIdentity, shard, {
      groupLabel: 'restore candidate set',
      missingIdentityMessage: 'Successor shard is missing archive/state/cohort identity',
    });
  }

  const statesByKey = new Map();
  for (const candidate of byIdentity.values()) {
    const key = buildStateSelectionKey(candidate.archiveId, candidate.stateId);
    if (!statesByKey.has(key)) {
      statesByKey.set(key, {
        key,
        archiveId: candidate.archiveId,
        stateId: candidate.stateId,
        cohorts: [],
      });
    }
    const firstShard = candidate.shards[0];
    statesByKey.get(key).cohorts.push({
      archiveId: candidate.archiveId,
      stateId: candidate.stateId,
      cohortId: candidate.cohortId,
      bundleDigests: [...candidate.embeddedLifecycleBundles.keys()].sort(),
      shardCount: candidate.shards.length,
      n: Number(firstShard?.metaJSON?.n || 0),
      t: Number(firstShard?.metaJSON?.t || 0),
    });
  }

  const states = [...statesByKey.values()]
    .map((state) => ({
      ...state,
      cohorts: state.cohorts.sort((a, b) => a.cohortId.localeCompare(b.cohortId)),
    }))
    .sort((a, b) => a.key.localeCompare(b.key));

  return {
    states,
    hasAmbiguity: states.length > 1 || states.some((state) => (
      state.cohorts.length > 1 || state.cohorts.some((cohort) => cohort.bundleDigests.length > 1)
    )),
  };
}

export async function refreshSuccessorSelectionUi(prefix = 'restore', files = [], actionButton = null, assessment = null) {
  const elements = getSuccessorSelectionElements(prefix);
  const previous = successorSelectionState.get(prefix) || {};
  const nextState = {
    ...previous,
    files,
    assessment,
    actionButton,
    mode: 'none',
    selectionRequired: false,
    selectionComplete: true,
    selectedArchiveId: null,
    selectedStateId: null,
    selectedCohortId: null,
    selectedLifecycleBundleDigestHex: null,
  };

  successorSelectionState.set(prefix, nextState);
  if (!elements.container || !elements.summary || !elements.help) {
    return nextState;
  }
  if (!files.length) {
    clearSuccessorSelectionUi(prefix, actionButton);
    return successorSelectionState.get(prefix);
  }

  try {
    const classified = await classifyRestoreInputFiles(files);
    if (!classified.shardFiles.length) {
      return renderSelectionInfoUi(
        prefix,
        actionButton,
        nextState,
        'No supported successor .qcont shards were found in the selected files.',
        'Load successor .qcont shards plus any optional archive-state descriptors, lifecycle bundles, detached signatures, .pqpk signer pins, or .ots proofs.',
        'unsupported'
      );
    }

    const shardBytes = await Promise.all(classified.shardFiles.map(readFileAsUint8Array));
    const successorShards = await Promise.all(shardBytes.map((bytes) => parseLifecycleShard(bytes, { strict: true })));

    if (!successorShards.length) {
      return renderSelectionInfoUi(
        prefix,
        actionButton,
        nextState,
        'No supported successor .qcont shards were found in the selected files.',
        'Load successor .qcont shards to choose an archive-state, same-state cohort, or lifecycle bundle.',
        'unsupported'
      );
    }

    elements.container.style.display = 'block';
    elements.container.className = 'verification-section successor-selection';

    const model = buildSuccessorSelectionModel(successorShards);
    const uploadedArchiveState = classified.archiveStateBytes instanceof Uint8Array
      ? parseArchiveStateDescriptorBytes(classified.archiveStateBytes)
      : null;
    const lifecycleBundleProvided = classified.lifecycleBundleBytes instanceof Uint8Array;
    const uploadedStateKey = uploadedArchiveState
      ? buildStateSelectionKey(uploadedArchiveState.archiveState.archiveId, uploadedArchiveState.digest.value)
      : null;

    let selectedStateKey = uploadedStateKey;
    if (!selectedStateKey && model.states.length === 1) {
      selectedStateKey = model.states[0].key;
    }
    if (!selectedStateKey && model.states.some((state) => state.key === previous.selectedStateKey)) {
      selectedStateKey = previous.selectedStateKey;
    }
    if (!selectedStateKey && model.states.some((state) => state.key === elements.stateSelect?.value)) {
      selectedStateKey = elements.stateSelect.value;
    }

    const selectedState = model.states.find((state) => state.key === selectedStateKey) || null;

    let selectedCohortId = null;
    if (!lifecycleBundleProvided && selectedState?.cohorts.length === 1) {
      selectedCohortId = selectedState.cohorts[0].cohortId;
    }
    if (!selectedCohortId && selectedState?.cohorts.some((cohort) => cohort.cohortId === previous.selectedCohortId)) {
      selectedCohortId = previous.selectedCohortId;
    }
    if (!selectedCohortId && selectedState?.cohorts.some((cohort) => cohort.cohortId === elements.cohortSelect?.value)) {
      selectedCohortId = elements.cohortSelect.value;
    }

    const selectedCohort = selectedState?.cohorts.find((cohort) => cohort.cohortId === selectedCohortId) || null;

    let selectedLifecycleBundleDigestHex = null;
    if (!lifecycleBundleProvided && selectedCohort?.bundleDigests.length === 1) {
      selectedLifecycleBundleDigestHex = selectedCohort.bundleDigests[0];
    }
    if (
      !selectedLifecycleBundleDigestHex &&
      selectedCohort?.bundleDigests.includes(previous.selectedLifecycleBundleDigestHex)
    ) {
      selectedLifecycleBundleDigestHex = previous.selectedLifecycleBundleDigestHex;
    }
    if (
      !selectedLifecycleBundleDigestHex &&
      selectedCohort?.bundleDigests.includes(elements.bundleSelect?.value)
    ) {
      selectedLifecycleBundleDigestHex = elements.bundleSelect.value;
    }

    const stateChoiceRequired = !lifecycleBundleProvided && !uploadedArchiveState && model.states.length > 1;
    const cohortChoiceRequired = !lifecycleBundleProvided && !!selectedState && selectedState.cohorts.length > 1;
    const bundleChoiceRequired = !lifecycleBundleProvided && !!selectedCohort && selectedCohort.bundleDigests.length > 1;
    const selectionRequired = stateChoiceRequired || cohortChoiceRequired || bundleChoiceRequired;
    const selectionComplete = (
      (!stateChoiceRequired || Boolean(selectedState)) &&
      (!cohortChoiceRequired || Boolean(selectedCohortId)) &&
      (!bundleChoiceRequired || Boolean(selectedLifecycleBundleDigestHex))
    );

    populateSelectionOptions(
      elements.stateSelect,
      model.states.map((state) => ({ value: state.key, label: describeStateOption(state) })),
      stateChoiceRequired ? selectedStateKey : '',
      stateChoiceRequired ? 'Choose one archive and state' : null
    );
    if (elements.stateGroup) {
      elements.stateGroup.style.display = stateChoiceRequired ? 'block' : 'none';
    }

    populateSelectionOptions(
      elements.cohortSelect,
      selectedState
        ? selectedState.cohorts.map((cohort) => ({ value: cohort.cohortId, label: describeCohortOption(cohort) }))
        : [],
      cohortChoiceRequired ? selectedCohortId : '',
      cohortChoiceRequired ? 'Choose one same-state cohort' : null
    );
    if (elements.cohortGroup) {
      elements.cohortGroup.style.display = cohortChoiceRequired ? 'block' : 'none';
    }

    populateSelectionOptions(
      elements.bundleSelect,
      selectedCohort
        ? selectedCohort.bundleDigests.map((digestHex) => ({
            value: digestHex,
            label: `Lifecycle bundle ${shortenHash(digestHex)}`,
          }))
        : [],
      bundleChoiceRequired ? selectedLifecycleBundleDigestHex : '',
      bundleChoiceRequired ? 'Choose one embedded lifecycle bundle' : null
    );
    if (elements.bundleGroup) {
      elements.bundleGroup.style.display = bundleChoiceRequired ? 'block' : 'none';
    }

    const totalCohorts = model.states.reduce((acc, state) => acc + state.cohorts.length, 0);
    const totalBundleVariants = model.states.reduce((acc, state) => (
      acc + state.cohorts.reduce((innerAcc, cohort) => innerAcc + cohort.bundleDigests.length, 0)
    ), 0);
    elements.summary.textContent = `Successor restore candidates: ${model.states.length} archive-state candidate${model.states.length === 1 ? '' : 's'}, ${totalCohorts} cohort${totalCohorts === 1 ? '' : 's'}, ${totalBundleVariants} embedded lifecycle bundle variant${totalBundleVariants === 1 ? '' : 's'}.`;
    if (lifecycleBundleProvided) {
      elements.help.textContent = 'The uploaded lifecycle bundle already fixes the archive, state, and cohort selection.';
    } else if (uploadedArchiveState) {
      elements.help.textContent = selectionRequired
        ? 'The uploaded archive-state descriptor fixed the archive state. Choose the remaining cohort or lifecycle bundle below.'
        : 'The uploaded archive-state descriptor fixed the archive state. No additional successor selection is required.';
    } else if (selectionRequired) {
      elements.help.textContent = 'Choose the exact archive, cohort, or lifecycle bundle below. Quantum Vault will not auto-select an ambiguous successor path.';
    } else {
      elements.help.textContent = 'One successor restore path is available from the selected shard set.';
    }

    const stateForRestore = stateChoiceRequired && selectedState
      ? { selectedArchiveId: selectedState.archiveId, selectedStateId: selectedState.stateId }
      : { selectedArchiveId: null, selectedStateId: null };
    successorSelectionState.set(prefix, {
      ...nextState,
      mode: 'successor',
      model,
      selectedStateKey,
      selectedArchiveId: stateForRestore.selectedArchiveId,
      selectedStateId: stateForRestore.selectedStateId,
      selectedCohortId: cohortChoiceRequired ? selectedCohortId : null,
      selectedLifecycleBundleDigestHex: bundleChoiceRequired ? selectedLifecycleBundleDigestHex : null,
      selectionRequired,
      selectionComplete,
    });
  } catch (error) {
    renderSelectionInfoUi(
      prefix,
      actionButton,
      nextState,
      'Successor restore selection could not be derived from the selected files.',
      error?.message || String(error),
      'invalid'
    );
  }

  const current = successorSelectionState.get(prefix);
  if (elements.stateSelect) {
    elements.stateSelect.onchange = () => {
      const latest = successorSelectionState.get(prefix);
      void refreshSuccessorSelectionUi(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  if (elements.cohortSelect) {
    elements.cohortSelect.onchange = () => {
      const latest = successorSelectionState.get(prefix);
      void refreshSuccessorSelectionUi(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  if (elements.bundleSelect) {
    elements.bundleSelect.onchange = () => {
      const latest = successorSelectionState.get(prefix);
      void refreshSuccessorSelectionUi(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  setRestoreActionAvailability(prefix, actionButton);
  return current;
}

async function readVerificationOptionsFromDom({
  prefix = 'restore',
  allFiles = [],
  expectedSignerInput,
}) {
  const classified = await classifyRestoreInputFiles(allFiles);
  const selected = successorSelectionState.get(prefix) || {};
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
    onLog(`${evidence.linkLabel}: ${evidence.targetRef}. ${evidence.completionLabel}.`);
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
  const { qencOk, qkeyOk, authenticity } = result;
  const policyOk = authenticity?.status?.policySatisfied === true;
  let allOk = qencOk && qkeyOk && policyOk;
  if (options.liteDecrypt) {
    const { containerOk, decryptOk } = options.liteDecrypt;
    allOk = qencOk && qkeyOk && containerOk && decryptOk && policyOk;
  }

  const header = document.createElement('h4');
  header.textContent = 'Restore Result';
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
    const icon = ok ? '✓' : (useWarn ? '⚠' : '✗');
    item.textContent = `${icon} ${ok ? okText : failText}`;
    panel.appendChild(item);
  };

  const addNeutral = (text) => {
    const item = document.createElement('div');
    item.className = 'restore-result-item neutral';
    item.textContent = `· ${text}`;
    panel.appendChild(item);
  };

  addSection('Integrity');
  addPolar(qencOk, 'Container integrity verified', 'Container integrity check failed');
  addPolar(qkeyOk, 'Private key integrity verified', 'Private key integrity check failed');
  if (options.liteDecrypt?.containerOk) {
    addPolar(
      options.liteDecrypt.decryptOk,
      'Decryption and file integrity verified',
      'Decryption or file integrity check failed',
    );
  }

  const status = authenticity?.status || {};
  const archiveApprovalVerified = status.archiveApprovalSignatureVerified === true;
  const cohortInspection = result.lifecycleVerification?.cohorts || {};
  addSection('Archive Approval');
  addPolar(
    archiveApprovalVerified,
    'Archive-approval signature verified',
    'No verified archive-approval signature over archive-state',
  );
  addPolar(
    status.strongPqSignatureVerified === true,
    'Strong PQ archive-approval signature verified',
    'Strong PQ archive-approval signature not present',
    archiveApprovalVerified === true && status.strongPqSignatureVerified !== true,
  );
  addNeutral('Maintenance and source-evidence signatures are reported separately and do not satisfy archive policy.');

  addSection('Maintenance');
  if (status.transitionRecordPresent !== true) {
    addNeutral('No same-state resharing on this archive yet — transition and maintenance rows are omitted (not an error).');
  } else {
    addPolar(true, 'Transition record present', 'Transition record missing');
    addPolar(
      status.transitionChainValid === true,
      'Transition-chain references valid',
      'Transition-chain references invalid or broken',
    );
    addPolar(
      status.maintenanceSignatureVerified === true,
      'Maintenance signature verified',
      'No verified maintenance signature on transition record(s)',
    );
    addNeutral('Maintenance signatures authorize resharing events only; they do not replace archive approval.');
  }

  addSection('Source Evidence');
  if (status.sourceEvidencePresent !== true) {
    addNeutral('No source-evidence objects on this archive (optional provenance).');
  } else {
    addPolar(
      status.sourceEvidenceSignatureVerified === true,
      'Source-evidence signature verified',
      'Source-evidence present but no verified signature',
    );
    addNeutral('Source evidence is provenance only; it does not imply archive approval.');
  }

  addSection('Selection');
  if (cohortInspection.forkDetected === true) {
    addPolar(false, '', 'Same-state cohort fork remains known for this archive state', true);
  }
  if (status.bundleCohortMixed === true) {
    addPolar(false, '', 'Mixed embedded lifecycle bundle variants were present in the selected cohort', true);
  } else {
    addPolar(true, 'One lifecycle bundle variant selected for policy evaluation', '');
  }
  addSection('Pinning & Evidence');
  addPolar(
    status.bundlePinned === true,
    'Lifecycle-bundle signer pinned',
    'Lifecycle-bundle signer not pinned',
    archiveApprovalVerified === true && status.bundlePinned !== true,
  );
  if (status.userPinProvided === true || status.userPinned === true) {
    addPolar(
      status.userPinned === true,
      'User-supplied signer pin matched',
      status.userPinProvided === true ? 'User-supplied pin did not match a verifying signer' : 'User signer not pinned',
      status.userPinProvided === true && status.userPinned !== true,
    );
  }
  const timestampEvidence = Array.isArray(authenticity?.timestampEvidence) ? authenticity.timestampEvidence : [];
  if (timestampEvidence.length > 0) {
    const completeCount = timestampEvidence.filter((item) => item.apparentlyComplete === true).length;
    const incompleteCount = timestampEvidence.length - completeCount;
    const appendStatusLine = (ok, text, warn = false) => {
      const item = document.createElement('div');
      item.className = `restore-result-item ${warn ? 'warn' : (ok ? 'ok' : 'fail')}`;
      item.textContent = `${ok ? '✓' : (warn ? '⚠' : '✗')} ${text}`;
      panel.appendChild(item);
    };
    appendStatusLine(true, `OTS evidence linked to ${timestampEvidence.length} signature${timestampEvidence.length === 1 ? '' : 's'}`);
    if (completeCount > 0) {
      appendStatusLine(true, `OTS proof complete (${completeCount})`);
    }
    if (incompleteCount > 0) {
      appendStatusLine(false, `OTS proof not yet complete (${incompleteCount}) — calendars may still be pending`, true);
    }
  }
  addSection('Policy');
  addPolar(status.policySatisfied === true, 'Archive policy satisfied', 'Archive policy not satisfied');
  addNeutral('Archive policy evaluation remains archive-approval-only in Phase 1.');

  panel.className = `restore-result-panel ${allOk ? 'ok' : 'fail'}`;
}

export function initQcontRestoreUI() {
  const qcontShardsInput = document.getElementById('qcontShardsInput');
  const restoreQcontBtn = document.getElementById('restoreQcontBtn');

  const restoreExpectedEdSigner = document.getElementById('restoreExpectedEdSigner');

  restoreQcontBtn?.addEventListener('click', async () => {
    const files = qcontShardsInput?.files;
    if (!files?.length) {
      showToast('Select .qcont shards to restore.', 'warning');
      return;
    }

    const resultPanel = document.getElementById('proRestoreResult');
    if (resultPanel) {
      resultPanel.style.display = 'none';
      resultPanel.replaceChildren();
    }

    setButtonsDisabled(true);
    let recoveredPrivKey = null;
    try {
      const allFiles = [...files];
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

      const shardBytesArr = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
      const shards = await Promise.all(shardBytesArr.map((bytes) => parseLifecycleShard(bytes, { strict: true })));

      const result = await restoreFromShards(shards, {
        onLog: (msg) => log(msg),
        onError: (msg) => logError(msg),
        onWarn: (msg) => logWarning(msg),
        verification: verificationOptions,
      });

      logRestoreSelectionSummary(result, log);
      logVerificationSummary(result.authenticity, log, logWarning, logSuccess);

      const { qencBytes, privKey, containerId, containerHash, privateKeyHash, recoveredQencHash, recoveredPrivHash, qencOk, qkeyOk } = result;
      recoveredPrivKey = privKey instanceof Uint8Array ? privKey : null;
      log(`Recovered .qenc SHA3-512=${recoveredQencHash} (expected ${containerHash})`);
      log(`Recovered .qkey SHA3-512=${recoveredPrivHash}${privateKeyHash ? ` (expected ${privateKeyHash})` : ''}`);

      const qencBlob = new Blob([qencBytes], { type: 'application/octet-stream' });
      const qkeyBlob = new Blob([privKey], { type: 'application/octet-stream' });
      const qencName = `${containerId}.recovered.qenc`;
      const qkeyName = `${containerId}.recovered.privateKey.qkey`;

      if (qencOk && qkeyOk && result.authenticity?.status?.policySatisfied) {
        download(qencBlob, qencName);
        download(qkeyBlob, qkeyName);
        logSuccess('Recovered .qenc and .qkey from a policy-satisfying archive cohort.');
      } else {
        logError('Verification failed. Automatic download is blocked.');
      }

      buildRestoreResultSummary(result, 'proRestoreResult');
    } catch (error) {
      logError(error);
    } finally {
      // Best-effort only: JS runtimes do not guarantee overwriting secrets in memory.
      if (recoveredPrivKey instanceof Uint8Array) {
        recoveredPrivKey.fill(0);
      }
      setButtonsDisabled(false);
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
