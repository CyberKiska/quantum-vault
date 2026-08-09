import { parseLifecycleShard, zeroizeParsedLifecycleShard } from '../../../app/crypto-service.js';
import {
  parseArchiveStateViewBytes,
  parseLifecycleBundleArchiveStateViewBytes,
} from '../../../app/artifact-intake-service.js';
import { classifyRestoreInputFiles } from '../../../app/restore-inputs.js';
import { readFileAsUint8Array } from '../../../utils.js';
import {
  buildSuccessorSelectionModel,
  collectLifecycleAttachmentCounts,
} from '../../crypto/qcont/successor-selection-model.js';
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
const successorRefreshEpochs = new Map();

export { buildSuccessorSelectionModel, collectLifecycleAttachmentCounts };

function presentationBestEffort(action) {
  try { action(); } catch { /* State invalidation must survive mutable DOM faults. */ }
}

const ARCHIVE_INSPECTOR_CONTAINER_BY_PREFIX = Object.freeze({
  restore: 'restoreArchiveInspector',
  reshare: 'reshareArchiveInspector',
  liteRestore: 'liteRestoreArchiveInspector',
});

/** Read-only snapshot for hub / tests (no mutation guarantees on nested fields). */
export function peekSuccessorSelectionState(prefix) {
  return successorSelectionState.get(prefix) || null;
}

export function buildSuccessorSelectionChangeDetail(prefix, state) {
  return {
    prefix,
    selection: {
      mode: String(state?.mode || 'none'),
      selectionRequired: state?.selectionRequired === true,
      selectionComplete: state?.selectionComplete === true,
      successorSelectionUiMode: String(state?.successorSelectionUiMode || 'none'),
      selectedArchiveId: state?.selectedArchiveId || null,
      selectedStateId: state?.selectedStateId || null,
      selectedCohortId: state?.selectedCohortId || null,
      selectedLifecycleBundleDigestHex: state?.selectedLifecycleBundleDigestHex || null,
    },
  };
}

export function buildSuccessorInspectorShard(shard) {
  return {
    sourceFileName: shard.sourceFileName,
    archiveState: shard.archiveState,
    stateId: shard.stateId,
    cohortId: shard.cohortId,
    lifecycleBundleDigestHex: shard.lifecycleBundleDigestHex,
    lifecycleBundle: shard.lifecycleBundle,
    metaJSON: {
      archiveId: shard.metaJSON?.archiveId,
      stateId: shard.metaJSON?.stateId,
      cohortId: shard.metaJSON?.cohortId,
      n: shard.metaJSON?.n,
      t: shard.metaJSON?.t,
    },
  };
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
  if (elements.container) {
    presentationBestEffort(() => { elements.container.style.display = 'none'; });
    presentationBestEffort(() => { elements.container.className = 'verification-section initially-hidden'; });
  }
  if (elements.summary) presentationBestEffort(() => { elements.summary.textContent = ''; });
  if (elements.help) presentationBestEffort(() => { elements.help.textContent = ''; });
  [elements.stateGroup, elements.cohortGroup, elements.bundleGroup].forEach((group) => {
    if (group) presentationBestEffort(() => { group.style.display = 'none'; });
  });
  for (const select of [elements.stateSelect, elements.cohortSelect, elements.bundleSelect]) {
    if (select) {
      presentationBestEffort(() => { select.onchange = null; });
      presentationBestEffort(() => select.replaceChildren());
    }
  }
  presentationBestEffort(() => clearSelectionDetails(prefix));
  presentationBestEffort(() => setRestoreActionAvailability(prefix, actionButton));
}

/** Synchronously revoke File/state/DOM ownership for a workflow session boundary. */
export function resetSuccessorSelectionSession(prefix = 'restore', actionButton = null) {
  successorRefreshEpochs.set(prefix, (successorRefreshEpochs.get(prefix) || 0) + 1);
  successorSelectionState.set(prefix, {
    mode: 'none',
    assessment: null,
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
  presentationBestEffort(() => clearArchiveInspector(ARCHIVE_INSPECTOR_CONTAINER_BY_PREFIX[prefix]));
  presentationBestEffort(() => clearSuccessorSelectionUi(prefix, actionButton));
  presentationBestEffort(() => {
    syncArchiveReviewHub(prefix, successorSelectionState.get(prefix), { collapseWhenClear: true });
  });
  return successorSelectionState.get(prefix);
}

/** Resolve optional external selectors only after proving model membership. */
export function resolveExternallyFixedSuccessorSelection(model, {
  uploadedArchiveState = null,
  uploadedLifecycleBundle = null,
} = {}) {
  const archiveStateKey = uploadedArchiveState
    ? buildStateSelectionKey(uploadedArchiveState.archiveState.archiveId, uploadedArchiveState.digest.value)
    : null;
  const lifecycleStateKey = uploadedLifecycleBundle
    ? buildStateSelectionKey(uploadedLifecycleBundle.archiveState.archiveId, uploadedLifecycleBundle.digest.value)
    : null;

  if (archiveStateKey && !model.states.some((state) => state.key === archiveStateKey)) {
    throw new Error('Uploaded archive-state descriptor does not match any loaded successor shard archive/state.');
  }
  if (lifecycleStateKey && !model.states.some((state) => state.key === lifecycleStateKey)) {
    throw new Error('Uploaded lifecycle bundle does not match any loaded successor shard archive/state.');
  }
  if (archiveStateKey && lifecycleStateKey && archiveStateKey !== lifecycleStateKey) {
    throw new Error('Uploaded lifecycle bundle and archive-state descriptor select different archive states.');
  }

  const stateKey = lifecycleStateKey || archiveStateKey;
  const selectedState = model.states.find((state) => state.key === stateKey) || null;
  const cohortId = uploadedLifecycleBundle?.cohortId || null;
  if (cohortId && !selectedState?.cohorts.some((cohort) => cohort.cohortId === cohortId)) {
    throw new Error('Uploaded lifecycle bundle does not match any loaded successor shard cohort.');
  }

  return { stateKey, cohortId };
}

export async function refreshSuccessorSelectionUi(prefix = 'restore', files = [], actionButton = null, assessment = null, options = {}) {
  const isCurrent = typeof options.isCurrent === 'function' ? options.isCurrent : () => true;
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
    syncArchiveReviewHub(prefix, peekSuccessorSelectionState(prefix), { collapseWhenClear: true });
    return successorSelectionState.get(prefix);
  }

  let shardBytes = [];
  let successorShards = [];
  try {
    const classified = await classifyRestoreInputFiles(files);
    if (!isCurrent()) return successorSelectionState.get(prefix) || null;
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

    shardBytes = await Promise.all(classified.shardFiles.map(readFileAsUint8Array));
    if (!isCurrent()) return successorSelectionState.get(prefix) || null;
    successorShards = await Promise.all(shardBytes.map(async (bytes, index) => {
      const shard = await parseLifecycleShard(bytes, { strict: true });
      return {
        ...shard,
        sourceFileName: classified.shardFiles[index]?.name || `selected-shard-${index + 1}.qcont`,
      };
    }));
    if (!isCurrent()) return successorSelectionState.get(prefix) || null;

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
      ? parseArchiveStateViewBytes(classified.archiveStateBytes)
      : null;
    const uploadedLifecycleBundle = classified.lifecycleBundleBytes instanceof Uint8Array
      ? await parseLifecycleBundleArchiveStateViewBytes(classified.lifecycleBundleBytes)
      : null;
    const lifecycleBundleProvided = uploadedLifecycleBundle !== null;
    const externalSelection = resolveExternallyFixedSuccessorSelection(model, {
      uploadedArchiveState,
      uploadedLifecycleBundle,
    });

    const pickFirstAvailable = (candidates, isMember) => {
      for (const candidate of candidates) {
        if (candidate && isMember(candidate)) return candidate;
      }
      return null;
    };

    const selectedStateKey = externalSelection.stateKey || pickFirstAvailable(
      [
        model.states.length === 1 ? model.states[0].key : null,
        previous.selectedStateKey,
        elements.stateSelect?.value,
      ],
      (key) => model.states.some((state) => state.key === key),
    );
    const selectedState = model.states.find((state) => state.key === selectedStateKey) || null;

    const selectedCohortId = lifecycleBundleProvided
      ? externalSelection.cohortId
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
    const inspectorShards = successorShards.map(buildSuccessorInspectorShard);
    successorSelectionState.set(prefix, {
      ...nextState,
      mode: 'successor',
      model,
      parsedSuccessorShards: inspectorShards,
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
    if (!isCurrent()) return successorSelectionState.get(prefix) || null;
    renderSelectionInfoUi(
      prefix,
      actionButton,
      nextState,
      'Successor restore selection could not be derived from the selected files.',
      error?.message || String(error),
      'invalid'
    );
  } finally {
    for (const shard of successorShards) zeroizeParsedLifecycleShard(shard);
    for (const bytes of shardBytes) {
      if (bytes instanceof Uint8Array) bytes.fill(0);
    }
  }

  if (!isCurrent()) return successorSelectionState.get(prefix) || null;
  const current = successorSelectionState.get(prefix);
  const onSelectionChange = () => {
    const detail = buildSuccessorSelectionChangeDetail(prefix, successorSelectionState.get(prefix));
    document.dispatchEvent(new CustomEvent('qv:successor-selection-change', {
      detail,
    }));
    if (typeof options.onSelectionChange === 'function') {
      options.onSelectionChange(detail);
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
  isCurrent: externalIsCurrent = () => true,
}) {
  const refreshEpoch = (successorRefreshEpochs.get(prefix) || 0) + 1;
  successorRefreshEpochs.set(prefix, refreshEpoch);
  const isCurrent = () => (
    successorRefreshEpochs.get(prefix) === refreshEpoch && externalIsCurrent()
  );
  await refreshSuccessorSelectionUi(prefix, files, actionButton, assessment, {
    preflightContainerId,
    expectedSignerInput,
    renderPreflightForFiles,
    onSelectionChange,
    isCurrent,
  });
  if (!isCurrent()) return;
  if (!preflightContainerId || typeof renderPreflightForFiles !== 'function') return;
  await renderPreflightForFiles({
    prefix,
    containerId: preflightContainerId,
    files,
    expectedSignerInput,
    actionButton,
    isCurrent,
  });
}
