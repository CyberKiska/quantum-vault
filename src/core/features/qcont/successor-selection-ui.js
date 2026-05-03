import { parseLifecycleShard } from '../../../app/crypto-service.js';
import { classifyRestoreInputFiles } from '../../../app/restore-inputs.js';
import { readFileAsUint8Array } from '../../../utils.js';
import { parseArchiveStateDescriptorBytes } from '../../crypto/lifecycle/artifacts.js';
import { mergeLifecycleShardIntoCohortGroups } from '../../crypto/qcont/lifecycle-cohort-shared.js';
import { syncArchiveReviewHub } from '../ui/archive-review-hub.js';
import {
  createDigestDetailEntry,
  createDigestDetailsPanel,
  formatCohortParameters,
  shortDigestLabel,
} from '../ui/digest-details.js';
import { clearArchiveInspector, renderArchiveInspectorPanel } from './archive-inspector-ui.js';
import { buildSuccessorSelectionUiMode } from './successor-selection-view-model.js';

const successorSelectionState = new Map();

const ARCHIVE_INSPECTOR_CONTAINER_BY_PREFIX = Object.freeze({
  restore: 'restoreArchiveInspector',
  reshare: 'reshareArchiveInspector',
  liteRestore: 'liteRestoreArchiveInspector',
});

/** Read-only snapshot for hub / tests (no mutation guarantees on nested fields). */
export function peekSuccessorSelectionState(prefix) {
  return successorSelectionState.get(prefix) || null;
}

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
  return `Archive ${shortDigestLabel(state.archiveId)} / State ${shortDigestLabel(state.stateId)} (${state.cohorts.length} cohort${state.cohorts.length === 1 ? '' : 's'})`;
}

function describeCohortOption(cohort) {
  const bundleVariantCount = cohort.bundleDigests.length;
  const bundleLabel = bundleVariantCount === 1
    ? '1 embedded lifecycle bundle'
    : `${bundleVariantCount} embedded lifecycle bundles`;
  return `Cohort ${shortDigestLabel(cohort.cohortId)} (${cohort.shardCount}/${cohort.n} shards loaded, threshold ${cohort.t}, ${bundleLabel})`;
}

function uniqueStrings(values) {
  return [...new Set(
    values
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));
}

function describePolicyLevels(policyLevels = []) {
  return policyLevels.length > 0 ? policyLevels.join(', ') : 'unknown';
}

export function collectLifecycleAttachmentCounts(lifecycleBundles = []) {
  const archiveApprovalIds = new Set();
  const publicKeyIds = new Set();
  for (const bundle of lifecycleBundles) {
    const attachments = bundle?.attachments || {};
    for (const signature of attachments.archiveApprovalSignatures || []) {
      archiveApprovalIds.add(String(signature?.id || signature?.signature || archiveApprovalIds.size));
    }
    for (const publicKey of attachments.publicKeys || []) {
      publicKeyIds.add(String(publicKey?.id || publicKey?.value || publicKeyIds.size));
    }
  }
  return {
    archiveApprovalSignatureCount: archiveApprovalIds.size,
    publicKeyCount: publicKeyIds.size,
  };
}

function syncArchiveInspectorForPrefix(prefix, files = []) {
  const containerId = ARCHIVE_INSPECTOR_CONTAINER_BY_PREFIX[prefix];
  if (!containerId) return;
  const selection = successorSelectionState.get(prefix);
  if (selection?.parsedSuccessorShards?.length && selection?.model) {
    void renderArchiveInspectorPanel(containerId, { files, successorSelection: selection });
  } else if (files.length > 0) {
    void renderArchiveInspectorPanel(containerId, { files, successorSelection: null });
  } else {
    clearArchiveInspector(containerId);
  }
}

function ensureSelectionDetailsHost(prefix, elements) {
  if (!elements.container) return null;
  let host = elements.container.querySelector('[data-successor-digest-details="true"]');
  if (!host) {
    host = document.createElement('div');
    host.className = 'successor-digest-details';
    host.setAttribute('data-successor-digest-details', 'true');
    host.setAttribute('data-testid', `${prefix}-digest-details`);
    elements.container.appendChild(host);
  }
  return host;
}

function clearSelectionDetails(prefix) {
  const elements = getSuccessorSelectionElements(prefix);
  const host = elements.container?.querySelector('[data-successor-digest-details="true"]');
  if (host) {
    host.replaceChildren();
    host.classList.add('initially-hidden');
  }
}

function collectStateBundleDigests(state) {
  return uniqueStrings(state.cohorts.flatMap((cohort) => cohort.bundleDigests));
}

function collectStateSourceFiles(state) {
  return uniqueStrings(state.cohorts.flatMap((cohort) => cohort.sourceFileNames || []));
}

function collectStatePolicies(state) {
  return uniqueStrings(state.cohorts.flatMap((cohort) => cohort.policyLevels || []));
}

function renderSuccessorDigestDetails(prefix, {
  elements,
  model,
  selectedState,
  selectedCohort,
  selectedLifecycleBundleDigestHex,
  selectionRequired,
  helpText,
}) {
  const host = ensureSelectionDetailsHost(prefix, elements);
  if (!host || !model?.states?.length) return;
  host.replaceChildren();
  host.classList.remove('initially-hidden');

  const sections = [{
    title: 'Selection Context',
    rows: [{
      title: selectionRequired ? 'Explicit selection required' : 'Single restore path selected',
      copyKind: 'selection-context',
      entries: [
        createDigestDetailEntry('Why selection is required', helpText),
        createDigestDetailEntry('Artifact type', 'QVqcont-7 successor shard set'),
        createDigestDetailEntry('Archive-state candidates', String(model.states.length)),
        createDigestDetailEntry(
          'Cohort candidates',
          String(model.states.reduce((count, state) => count + state.cohorts.length, 0))
        ),
        createDigestDetailEntry('Policy', describePolicyLevels(uniqueStrings(model.states.flatMap(collectStatePolicies)))),
      ],
    }],
  }];

  const statesToShow = model.states.length > 1 || !selectedState ? model.states : [selectedState];
  const stateRows = [];
  for (const state of statesToShow) {
    const sourceFileNames = collectStateSourceFiles(state);
    const bundleDigests = collectStateBundleDigests(state);
    stateRows.push({
      title: `Archive ${shortDigestLabel(state.archiveId)} / State ${shortDigestLabel(state.stateId)}`,
      copyValue: state.stateId,
      copyLabel: 'Copy state digest',
      copyKind: 'state',
      entries: [
        createDigestDetailEntry('Source filenames', sourceFileNames),
        createDigestDetailEntry('Artifact type', 'Archive-state candidate from embedded QVqcont-7 shards'),
        createDigestDetailEntry('Policy', describePolicyLevels(collectStatePolicies(state))),
        createDigestDetailEntry('Archive id', state.archiveId),
        createDigestDetailEntry('State digest (SHA3-512)', state.stateId),
        createDigestDetailEntry('Cohorts', String(state.cohorts.length)),
        createDigestDetailEntry('Lifecycle-bundle digest', bundleDigests),
      ],
    });
  }
  sections.push({
    title: model.states.length > 1 ? 'Archive/State Candidates' : 'Selected Archive State',
    rows: stateRows,
  });

  const cohortsToShow = selectedState
    ? selectedState.cohorts
    : model.states.flatMap((state) => state.cohorts);
  if (cohortsToShow.length > 0) {
    const cohortRows = [];
    for (const cohort of cohortsToShow) {
      cohortRows.push({
        title: `Cohort ${shortDigestLabel(cohort.cohortId)}`,
        copyValue: cohort.cohortId,
        copyLabel: 'Copy cohort id',
        copyKind: 'cohort',
        entries: [
          createDigestDetailEntry('Source filenames', cohort.sourceFileNames),
          createDigestDetailEntry('Artifact type', 'Same-state cohort candidate'),
          createDigestDetailEntry('Policy', describePolicyLevels(cohort.policyLevels)),
          createDigestDetailEntry('Cohort parameters', formatCohortParameters(cohort)),
          createDigestDetailEntry('Archive id', cohort.archiveId),
          createDigestDetailEntry('State digest (SHA3-512)', cohort.stateId),
          createDigestDetailEntry('Cohort id', cohort.cohortId),
          createDigestDetailEntry('Lifecycle-bundle digest', cohort.bundleDigests),
        ],
      });
    }
    sections.push({
      title: cohortsToShow.length > 1 ? 'Cohort Candidates' : 'Selected Cohort',
      rows: cohortRows,
    });
  }

  const bundleRows = [];
  const bundleCohorts = selectedCohort ? [selectedCohort] : cohortsToShow;
  for (const cohort of bundleCohorts) {
    for (const digestHex of cohort.bundleDigests) {
      if (
        selectedLifecycleBundleDigestHex &&
        digestHex !== selectedLifecycleBundleDigestHex &&
        selectedCohort
      ) {
        continue;
      }
      bundleRows.push({ cohort, digestHex });
    }
  }
  if (bundleRows.length > 0) {
    const renderedBundleRows = [];
    for (const { cohort, digestHex } of bundleRows) {
      renderedBundleRows.push({
        title: `Lifecycle bundle ${shortDigestLabel(digestHex)}`,
        copyValue: digestHex,
        copyLabel: 'Copy bundle digest',
        copyKind: 'lifecycle-bundle',
        entries: [
          createDigestDetailEntry('Source filenames', cohort.bundleSourceFileNamesByDigest?.[digestHex] || cohort.sourceFileNames),
          createDigestDetailEntry('Artifact type', 'Embedded successor lifecycle bundle'),
          createDigestDetailEntry('Policy', describePolicyLevels(cohort.policyLevels)),
          createDigestDetailEntry('Cohort parameters', formatCohortParameters(cohort)),
          createDigestDetailEntry('Cohort id', cohort.cohortId),
          createDigestDetailEntry('Lifecycle-bundle digest (SHA3-512)', digestHex),
        ],
      });
    }
    sections.push({
      title: bundleRows.length > 1 ? 'Lifecycle Bundle Candidates' : 'Selected Lifecycle Bundle',
      rows: renderedBundleRows,
    });
  }

  const panel = createDigestDetailsPanel({
    note: 'Short labels stay primary. Expand this panel only when comparing full identifiers or preserving audit notes.',
    sections,
    badgeText: selectionRequired ? 'Required' : '',
    badgeTone: selectionRequired ? 'warn' : 'neutral',
  });
  host.appendChild(panel);
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
  clearSelectionDetails(prefix);
  successorSelectionState.set(prefix, {
    ...nextState,
    mode,
    selectionRequired: true,
    selectionComplete: false,
    successorSelectionUiMode: 'blocked',
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
  clearSelectionDetails(prefix);
  successorSelectionState.set(prefix, {
    mode: 'none',
    assessment: successorSelectionState.get(prefix)?.assessment || null,
    actionButton,
    files: [],
    selectionRequired: false,
    selectionComplete: true,
    successorSelectionUiMode: 'none',
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
    const sourceFileNames = uniqueStrings(candidate.shards.map((shard) => shard.sourceFileName));
    const policyLevels = uniqueStrings(candidate.shards.map((shard) => shard.lifecycleBundle?.authPolicy?.level));
    const attachmentCounts = collectLifecycleAttachmentCounts(candidate.shards.map((shard) => shard.lifecycleBundle));
    const bundleSourceFileNamesByDigest = {};
    for (const digestHex of candidate.embeddedLifecycleBundles.keys()) {
      bundleSourceFileNamesByDigest[digestHex] = uniqueStrings(
        candidate.shards
          .filter((shard) => shard.lifecycleBundleDigestHex === digestHex)
          .map((shard) => shard.sourceFileName)
      );
    }
    statesByKey.get(key).cohorts.push({
      archiveId: candidate.archiveId,
      stateId: candidate.stateId,
      cohortId: candidate.cohortId,
      bundleDigests: [...candidate.embeddedLifecycleBundles.keys()].sort(),
      bundleSourceFileNamesByDigest,
      sourceFileNames,
      policyLevels,
      archiveApprovalSignatureCount: attachmentCounts.archiveApprovalSignatureCount,
      publicKeyCount: attachmentCounts.publicKeyCount,
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

export async function refreshSuccessorSelectionUi(prefix = 'restore', files = [], actionButton = null, assessment = null, options = {}) {
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
    successorSelectionUiMode: 'none',
    selectedArchiveId: null,
    selectedStateId: null,
    selectedCohortId: null,
    selectedLifecycleBundleDigestHex: null,
  };

  successorSelectionState.set(prefix, nextState);
  if (!elements.container || !elements.summary || !elements.help) {
    syncArchiveReviewHub(prefix, peekSuccessorSelectionState(prefix));
    return nextState;
  }
  if (!files.length) {
    clearArchiveInspector(ARCHIVE_INSPECTOR_CONTAINER_BY_PREFIX[prefix]);
    clearSuccessorSelectionUi(prefix, actionButton);
    syncArchiveReviewHub(prefix, peekSuccessorSelectionState(prefix));
    return successorSelectionState.get(prefix);
  }

  try {
    const classified = await classifyRestoreInputFiles(files);
    if (!classified.shardFiles.length) {
      const out = renderSelectionInfoUi(
        prefix,
        actionButton,
        nextState,
        'No supported successor .qcont shards were found in the selected files.',
        'Load successor .qcont shards plus any optional archive-state descriptors, lifecycle bundles, detached signatures, .pqpk signer pins, or .ots proofs.',
        'unsupported'
      );
      syncArchiveReviewHub(prefix, peekSuccessorSelectionState(prefix));
      return out;
    }

    const shardBytes = await Promise.all(classified.shardFiles.map(readFileAsUint8Array));
    const successorShards = await Promise.all(shardBytes.map(async (bytes, index) => {
      const shard = await parseLifecycleShard(bytes, { strict: true });
      return {
        ...shard,
        sourceFileName: classified.shardFiles[index]?.name || `selected-shard-${index + 1}.qcont`,
      };
    }));

    if (!successorShards.length) {
      const out = renderSelectionInfoUi(
        prefix,
        actionButton,
        nextState,
        'No supported successor .qcont shards were found in the selected files.',
        'Load successor .qcont shards to choose an archive-state, same-state cohort, or lifecycle bundle.',
        'unsupported'
      );
      syncArchiveReviewHub(prefix, peekSuccessorSelectionState(prefix));
      return out;
    }

    const model = buildSuccessorSelectionModel(successorShards);
    const uploadedArchiveState = classified.archiveStateBytes instanceof Uint8Array
      ? parseArchiveStateDescriptorBytes(classified.archiveStateBytes)
      : null;
    const lifecycleBundleProvided = classified.lifecycleBundleBytes instanceof Uint8Array;
    const uploadedStateKey = uploadedArchiveState
      ? buildStateSelectionKey(uploadedArchiveState.archiveState.archiveId, uploadedArchiveState.digest.value)
      : null;

    const pickFirstAvailable = (candidates, isMember) => {
      for (const candidate of candidates) {
        if (candidate && isMember(candidate)) return candidate;
      }
      return null;
    };

    const selectedStateKey = uploadedStateKey || pickFirstAvailable(
      [
        model.states.length === 1 ? model.states[0].key : null,
        previous.selectedStateKey,
        elements.stateSelect?.value,
      ],
      (key) => model.states.some((state) => state.key === key),
    );
    const selectedState = model.states.find((state) => state.key === selectedStateKey) || null;

    const selectedCohortId = lifecycleBundleProvided
      ? null
      : pickFirstAvailable(
          [
            selectedState?.cohorts.length === 1 ? selectedState.cohorts[0].cohortId : null,
            previous.selectedCohortId,
            elements.cohortSelect?.value,
          ],
          (id) => Boolean(selectedState?.cohorts.some((cohort) => cohort.cohortId === id)),
        );
    const selectedCohort = selectedState?.cohorts.find((cohort) => cohort.cohortId === selectedCohortId) || null;

    const selectedLifecycleBundleDigestHex = lifecycleBundleProvided
      ? null
      : pickFirstAvailable(
          [
            selectedCohort?.bundleDigests.length === 1 ? selectedCohort.bundleDigests[0] : null,
            previous.selectedLifecycleBundleDigestHex,
            elements.bundleSelect?.value,
          ],
          (digest) => Boolean(selectedCohort?.bundleDigests.includes(digest)),
        );

    const stateChoiceRequired = !lifecycleBundleProvided && !uploadedArchiveState && model.states.length > 1;
    const cohortChoiceRequired = !lifecycleBundleProvided && !!selectedState && selectedState.cohorts.length > 1;
    const bundleChoiceRequired = !lifecycleBundleProvided && !!selectedCohort && selectedCohort.bundleDigests.length > 1;
    const selectionRequired = stateChoiceRequired || cohortChoiceRequired || bundleChoiceRequired;
    const selectionComplete = (
      (!stateChoiceRequired || Boolean(selectedState)) &&
      (!cohortChoiceRequired || Boolean(selectedCohortId)) &&
      (!bundleChoiceRequired || Boolean(selectedLifecycleBundleDigestHex))
    );

    const successorSelectionUiMode = buildSuccessorSelectionUiMode(true, selectionRequired);
    if (successorSelectionUiMode === 'single') {
      elements.container.style.display = 'none';
      elements.container.classList.add('initially-hidden');
      clearSelectionDetails(prefix);
    } else {
      elements.container.style.display = 'block';
      elements.container.classList.remove('initially-hidden');
      elements.container.className = 'verification-section successor-selection';
    }

    const renderSelectionGroup = (select, group, options, value, required, placeholder) => {
      populateSelectionOptions(select, options, required ? value : '', required ? placeholder : null);
      if (group) group.style.display = required ? 'block' : 'none';
    };

    renderSelectionGroup(
      elements.stateSelect,
      elements.stateGroup,
      model.states.map((state) => ({ value: state.key, label: describeStateOption(state) })),
      selectedStateKey,
      stateChoiceRequired,
      'Choose one archive and state',
    );
    renderSelectionGroup(
      elements.cohortSelect,
      elements.cohortGroup,
      selectedState
        ? selectedState.cohorts.map((cohort) => ({ value: cohort.cohortId, label: describeCohortOption(cohort) }))
        : [],
      selectedCohortId,
      cohortChoiceRequired,
      'Choose one same-state cohort',
    );
    renderSelectionGroup(
      elements.bundleSelect,
      elements.bundleGroup,
      selectedCohort
        ? selectedCohort.bundleDigests.map((digestHex) => ({
            value: digestHex,
            label: `Lifecycle bundle ${shortDigestLabel(digestHex)}`,
          }))
        : [],
      selectedLifecycleBundleDigestHex,
      bundleChoiceRequired,
      'Choose one embedded lifecycle bundle',
    );

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
    if (successorSelectionUiMode === 'ambiguous') {
      renderSuccessorDigestDetails(prefix, {
        elements,
        model,
        selectedState,
        selectedCohort,
        selectedLifecycleBundleDigestHex,
        selectionRequired,
        helpText: elements.help.textContent,
      });
    }

    const stateForRestore = stateChoiceRequired && selectedState
      ? { selectedArchiveId: selectedState.archiveId, selectedStateId: selectedState.stateId }
      : { selectedArchiveId: null, selectedStateId: null };
    successorSelectionState.set(prefix, {
      ...nextState,
      mode: 'successor',
      model,
      parsedSuccessorShards: successorShards,
      selectedStateKey,
      selectedArchiveId: stateForRestore.selectedArchiveId,
      selectedStateId: stateForRestore.selectedStateId,
      selectedCohortId: cohortChoiceRequired ? selectedCohortId : null,
      selectedLifecycleBundleDigestHex: bundleChoiceRequired ? selectedLifecycleBundleDigestHex : null,
      selectionRequired,
      selectionComplete,
      successorSelectionUiMode,
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
  const onSelectionChange = () => {
    document.dispatchEvent(new CustomEvent('qv:successor-selection-change', {
      detail: { prefix, state: successorSelectionState.get(prefix) },
    }));
    if (typeof options.onSelectionChange === 'function') {
      options.onSelectionChange({ prefix, state: successorSelectionState.get(prefix) });
    }
    const latest = successorSelectionState.get(prefix);
    void refreshSelectionAndPreflight({
      prefix,
      files: latest?.files || [],
      actionButton: latest?.actionButton || actionButton,
      assessment: latest?.assessment || assessment,
      preflightContainerId: options.preflightContainerId,
      expectedSignerInput: options.expectedSignerInput,
      renderPreflightForFiles: options.renderPreflightForFiles,
      onSelectionChange: options.onSelectionChange,
    });
  };
  for (const select of [elements.stateSelect, elements.cohortSelect, elements.bundleSelect]) {
    if (select) select.onchange = onSelectionChange;
  }
  setRestoreActionAvailability(prefix, actionButton);
  syncArchiveInspectorForPrefix(prefix, files);
  syncArchiveReviewHub(prefix, peekSuccessorSelectionState(prefix));
  return current;
}

export async function refreshSelectionAndPreflight({
  prefix = 'restore',
  files = [],
  actionButton = null,
  assessment = null,
  preflightContainerId = null,
  expectedSignerInput = null,
  renderPreflightForFiles = null,
  onSelectionChange = null,
}) {
  await refreshSuccessorSelectionUi(prefix, files, actionButton, assessment, {
    preflightContainerId,
    expectedSignerInput,
    renderPreflightForFiles,
    onSelectionChange,
  });
  if (!preflightContainerId || typeof renderPreflightForFiles !== 'function') return;
  await renderPreflightForFiles({
    prefix,
    containerId: preflightContainerId,
    files,
    expectedSignerInput,
  });
}
