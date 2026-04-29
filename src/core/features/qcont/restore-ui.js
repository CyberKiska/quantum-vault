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
import { clearInlineError, showInlineError, summarizeFileList } from '../ui/inline-error.js';
import { showToast } from '../ui/toast.js';

const successorSelectionState = new Map();
const RESTORE_INLINE_ERROR_ID = 'proRestoreInlineError';

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

function restoreRecoveryAction(error) {
  const message = String(error?.message || error || '').toLowerCase();
  if (message.includes('archive policy') || message.includes('archive-approval')) {
    return 'Attach or load policy-satisfying archive-approval signatures and signer pins when required, then retry Restore.';
  }
  if (message.includes('lifecycle bundle') || message.includes('cohort') || message.includes('selection')) {
    return 'Choose the exact archive, cohort, or lifecycle bundle variant, or load the matching descriptor/bundle to disambiguate.';
  }
  if (message.includes('qcont') || message.includes('shard')) {
    return 'Load enough successor QVqcont-7 shards from one archive/state/cohort and remove incompatible files.';
  }
  return 'Review the selected restore inputs, correct the blocking condition, and retry Restore.';
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

function uniqueStrings(values) {
  return [...new Set(
    values
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));
}

function formatDetailValue(value) {
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : 'None';
  }
  return String(value || 'None');
}

function describePolicyLevels(policyLevels = []) {
  return policyLevels.length > 0 ? policyLevels.join(', ') : 'unknown';
}

function createDetailEntry(term, value) {
  return { term, value };
}

async function copyTextToClipboard(text) {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall through to the local textarea copy path for restricted browser contexts.
    }
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  textarea.style.top = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  textarea.remove();
  if (!copied) {
    throw new Error('Clipboard API unavailable');
  }
}

function bindCopyButton(button, value, copiedLabel = 'Copied') {
  button.addEventListener('click', async () => {
    const originalLabel = button.textContent;
    try {
      await copyTextToClipboard(value);
      button.textContent = copiedLabel;
      showToast('Copied full digest.', 'success');
      setTimeout(() => {
        button.textContent = originalLabel;
      }, 1600);
    } catch {
      showToast('Copy failed. Select the expanded digest manually.', 'warning');
    }
  });
}

function appendDigestDetailRow(section, {
  title,
  copyValue = '',
  copyLabel = 'Copy',
  copyKind = 'digest',
  entries = [],
}) {
  const row = document.createElement('div');
  row.className = 'digest-detail-row';
  row.setAttribute('data-digest-kind', copyKind);

  const head = document.createElement('div');
  head.className = 'digest-detail-row-head';
  const titleEl = document.createElement('span');
  titleEl.className = 'digest-detail-title';
  titleEl.textContent = title;
  head.appendChild(titleEl);

  if (copyValue) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'button secondary small digest-copy-button';
    button.textContent = copyLabel;
    button.setAttribute('data-copy-value', copyValue);
    button.setAttribute('data-digest-kind', copyKind);
    bindCopyButton(button, copyValue);
    head.appendChild(button);
  }

  const details = document.createElement('dl');
  details.className = 'digest-detail-list';
  for (const entry of entries) {
    const term = document.createElement('dt');
    term.textContent = entry.term;
    const value = document.createElement('dd');
    value.textContent = formatDetailValue(entry.value);
    if (/digest|archive id|cohort id|state/i.test(entry.term)) {
      value.classList.add('digest-detail-mono');
    }
    details.append(term, value);
  }

  row.append(head, details);
  section.appendChild(row);
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

function addDigestDetailSection(panel, title) {
  const section = document.createElement('div');
  section.className = 'digest-detail-section';
  const heading = document.createElement('h5');
  heading.textContent = title;
  section.appendChild(heading);
  panel.appendChild(section);
  return section;
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

  const panel = document.createElement('details');
  panel.className = 'digest-details-panel';
  const summary = document.createElement('summary');
  summary.textContent = 'Digest details and copy';
  panel.appendChild(summary);

  const note = document.createElement('p');
  note.className = 'muted-copy';
  note.textContent = 'Short labels stay primary. Expand this panel only when comparing full identifiers or preserving audit notes.';
  panel.appendChild(note);

  const contextSection = addDigestDetailSection(panel, 'Selection Context');
  appendDigestDetailRow(contextSection, {
    title: selectionRequired ? 'Explicit selection required' : 'Single restore path selected',
    copyKind: 'selection-context',
    entries: [
      createDetailEntry('Why selection is required', helpText),
      createDetailEntry('Artifact type', 'QVqcont-7 successor shard set'),
      createDetailEntry('Archive-state candidates', String(model.states.length)),
      createDetailEntry(
        'Cohort candidates',
        String(model.states.reduce((count, state) => count + state.cohorts.length, 0))
      ),
      createDetailEntry('Policy', describePolicyLevels(uniqueStrings(model.states.flatMap(collectStatePolicies)))),
    ],
  });

  const statesToShow = model.states.length > 1 || !selectedState ? model.states : [selectedState];
  const stateSection = addDigestDetailSection(
    panel,
    model.states.length > 1 ? 'Archive/State Candidates' : 'Selected Archive State'
  );
  for (const state of statesToShow) {
    const sourceFileNames = collectStateSourceFiles(state);
    const bundleDigests = collectStateBundleDigests(state);
    appendDigestDetailRow(stateSection, {
      title: `Archive ${shortenHash(state.archiveId)} / State ${shortenHash(state.stateId)}`,
      copyValue: state.stateId,
      copyLabel: 'Copy state digest',
      copyKind: 'state',
      entries: [
        createDetailEntry('Source filenames', sourceFileNames),
        createDetailEntry('Artifact type', 'Archive-state candidate from embedded QVqcont-7 shards'),
        createDetailEntry('Policy', describePolicyLevels(collectStatePolicies(state))),
        createDetailEntry('Archive id', state.archiveId),
        createDetailEntry('State digest (SHA3-512)', state.stateId),
        createDetailEntry('Cohorts', String(state.cohorts.length)),
        createDetailEntry('Lifecycle-bundle digest', bundleDigests),
      ],
    });
  }

  const cohortsToShow = selectedState
    ? selectedState.cohorts
    : model.states.flatMap((state) => state.cohorts);
  if (cohortsToShow.length > 0) {
    const cohortSection = addDigestDetailSection(
      panel,
      cohortsToShow.length > 1 ? 'Cohort Candidates' : 'Selected Cohort'
    );
    for (const cohort of cohortsToShow) {
      appendDigestDetailRow(cohortSection, {
        title: `Cohort ${shortenHash(cohort.cohortId)}`,
        copyValue: cohort.cohortId,
        copyLabel: 'Copy cohort id',
        copyKind: 'cohort',
        entries: [
          createDetailEntry('Source filenames', cohort.sourceFileNames),
          createDetailEntry('Artifact type', 'Same-state cohort candidate'),
          createDetailEntry('Policy', describePolicyLevels(cohort.policyLevels)),
          createDetailEntry('Cohort parameters', `${cohort.shardCount}/${cohort.n} shards loaded, threshold ${cohort.t}`),
          createDetailEntry('Archive id', cohort.archiveId),
          createDetailEntry('State digest (SHA3-512)', cohort.stateId),
          createDetailEntry('Cohort id', cohort.cohortId),
          createDetailEntry('Lifecycle-bundle digest', cohort.bundleDigests),
        ],
      });
    }
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
    const bundleSection = addDigestDetailSection(
      panel,
      bundleRows.length > 1 ? 'Lifecycle Bundle Candidates' : 'Selected Lifecycle Bundle'
    );
    for (const { cohort, digestHex } of bundleRows) {
      appendDigestDetailRow(bundleSection, {
        title: `Lifecycle bundle ${shortenHash(digestHex)}`,
        copyValue: digestHex,
        copyLabel: 'Copy bundle digest',
        copyKind: 'lifecycle-bundle',
        entries: [
          createDetailEntry('Source filenames', cohort.bundleSourceFileNamesByDigest?.[digestHex] || cohort.sourceFileNames),
          createDetailEntry('Artifact type', 'Embedded successor lifecycle bundle'),
          createDetailEntry('Policy', describePolicyLevels(cohort.policyLevels)),
          createDetailEntry('Cohort parameters', `${cohort.shardCount}/${cohort.n} shards loaded, threshold ${cohort.t}`),
          createDetailEntry('Cohort id', cohort.cohortId),
          createDetailEntry('Lifecycle-bundle digest (SHA3-512)', digestHex),
        ],
      });
    }
  }

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
    const successorShards = await Promise.all(shardBytes.map(async (bytes, index) => {
      const shard = await parseLifecycleShard(bytes, { strict: true });
      return {
        ...shard,
        sourceFileName: classified.shardFiles[index]?.name || `selected-shard-${index + 1}.qcont`,
      };
    }));

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
    renderSuccessorDigestDetails(prefix, {
      elements,
      model,
      selectedState,
      selectedCohort,
      selectedLifecycleBundleDigestHex,
      selectionRequired,
      helpText: elements.help.textContent,
    });

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
      if (prefix === 'restore') clearInlineError(RESTORE_INLINE_ERROR_ID);
      const latest = successorSelectionState.get(prefix);
      void refreshSuccessorSelectionUi(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  if (elements.cohortSelect) {
    elements.cohortSelect.onchange = () => {
      if (prefix === 'restore') clearInlineError(RESTORE_INLINE_ERROR_ID);
      const latest = successorSelectionState.get(prefix);
      void refreshSuccessorSelectionUi(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  if (elements.bundleSelect) {
    elements.bundleSelect.onchange = () => {
      if (prefix === 'restore') clearInlineError(RESTORE_INLINE_ERROR_ID);
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

function countSelfVerifiedSignatures(authenticity) {
  const results = Array.isArray(authenticity?.verification?.results)
    ? authenticity.verification.results
    : [];
  return results.filter((item) => {
    if (item?.selfSigned === true) return true;
    const warnings = Array.isArray(item?.warnings) ? item.warnings : [];
    return warnings.some((warning) => {
      const text = String(warning || '').toLowerCase();
      return (
        text.includes('cryptographic self-verification') ||
        text.includes('verified only with the signer public key embedded in the .qsig')
      );
    });
  }).length;
}

function appendSelfVerifiedSignatureRow(addRow, authenticity) {
  const selfVerifiedCount = countSelfVerifiedSignatures(authenticity);
  if (selfVerifiedCount > 0) {
    addRow(
      'Self-verified signature',
      'Cryptographically self-verified, ignored for archive policy',
      'warn',
      `${selfVerifiedCount} detached PQ signature${selfVerifiedCount === 1 ? '' : 's'} verified only with the public key embedded in the .qsig wrapper. No bundled or user-supplied signer pin corroborated the signer.`
    );
  } else {
    addRow('Self-verified signature', 'None reported', 'neutral');
  }
}

function appendSignerPinRows(addRow, addPolarRow, status, archiveApprovalVerified) {
  const pinSources = [];
  if (status.bundlePinned === true) pinSources.push('bundle');
  if (status.userPinned === true) pinSources.push('user input');

  if (pinSources.length > 0) {
    addRow(
      'Archive-approval signer pin',
      `Signer pinned by ${pinSources.join(' and ')}`,
      'ok',
      'Pinning strengthens signer provenance reporting but remains separate from archive-policy evaluation.'
    );
  } else if (archiveApprovalVerified) {
    addRow(
      'Archive-approval signer pin',
      'Signer not pinned',
      'warn',
      'A valid archive-approval signature may satisfy policy without pinning; signer pinning remains a separate status.'
    );
  } else {
    addRow('Archive-approval signer pin', 'No verified archive-approval signer to pin', 'neutral');
  }

  addPolarRow(
    'Bundle signer pin',
    status.bundlePinned === true,
    'Bundle signer pin matched',
    'No bundle signer pin matched archive approval',
    archiveApprovalVerified === true && status.bundlePinned !== true ? 'warn' : 'neutral',
  );
  if (status.userPinProvided === true || status.userPinned === true) {
    addPolarRow(
      'User-entered signer pin',
      status.userPinned === true,
      'User-entered signer pin matched',
      status.userPinProvided === true ? 'User-entered signer pin did not match a verifying archive-approval signer' : 'User-entered signer pin not active',
      status.userPinProvided === true && status.userPinned !== true ? 'warn' : 'neutral',
    );
  } else {
    addRow('User-entered signer pin', 'No user-entered signer pin provided', 'neutral');
  }
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
  const status = authenticity?.status || {};
  const policy = authenticity?.policy || {};
  const policyLevel = String(policy.level || 'unknown');
  const policyOk = authenticity?.status?.policySatisfied === true;
  let releaseAllowed = qencOk && qkeyOk && policyOk;
  if (options.liteDecrypt) {
    const { containerOk, decryptOk } = options.liteDecrypt;
    releaseAllowed = qencOk && qkeyOk && containerOk && decryptOk && policyOk;
  }

  const header = document.createElement('h4');
  if (releaseAllowed && policyLevel === 'integrity-only') {
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
    ? 'Restore release is separated from archive approval, signer pinning, timestamp evidence, maintenance evidence, and source evidence.'
    : 'No plaintext was released. Review the failed row before retrying restore.';
  panel.appendChild(intro);

  const matrix = document.createElement('div');
  matrix.className = 'restore-verification-matrix';
  panel.appendChild(matrix);

  const addSection = (title) => {
    const section = document.createElement('div');
    section.className = 'restore-result-section';
    section.textContent = title;
    matrix.appendChild(section);
  };

  const addRow = (label, value, tone = 'neutral', detail = '') => {
    const item = document.createElement('div');
    item.className = `restore-result-item restore-matrix-row ${tone}`;
    const labelEl = document.createElement('span');
    labelEl.className = 'restore-matrix-label';
    labelEl.textContent = label;
    const valueEl = document.createElement('span');
    valueEl.className = 'restore-matrix-value';
    valueEl.textContent = value;
    item.append(labelEl, valueEl);
    if (detail) {
      const detailEl = document.createElement('span');
      detailEl.className = 'restore-matrix-detail';
      detailEl.textContent = detail;
      item.appendChild(detailEl);
    }
    matrix.appendChild(item);
  };

  const addPolarRow = (label, ok, okText, failText, failTone = 'fail', detail = '') => {
    addRow(label, ok ? okText : failText, ok ? 'ok' : failTone, detail);
  };

  const addNeutral = (text) => {
    addRow('Note', text, 'neutral');
  };

  addSection('Restore Decision');
  if (releaseAllowed && policyLevel === 'integrity-only') {
    addRow(
      'Plaintext release',
      'Allowed by integrity-only policy',
      'warn',
      'No archive-approval signature is required by the selected policy.'
    );
  } else if (releaseAllowed) {
    addRow('Plaintext release', `Allowed by ${policyLevel} policy`, 'ok');
  } else {
    addRow('Plaintext release', 'Blocked', 'fail');
  }

  addSection('Verification Matrix');
  addPolarRow('Container integrity', qencOk, 'Container integrity verified', 'Container integrity check failed');
  addPolarRow('Private key recovery', qkeyOk, 'Private key integrity verified', 'Private key integrity check failed');
  if (options.liteDecrypt) {
    addPolarRow(
      'Plaintext integrity',
      options.liteDecrypt.decryptOk,
      'Decryption and file integrity verified',
      'Decryption or file integrity check failed',
    );
  }

  const archiveApprovalVerified = status.archiveApprovalSignatureVerified === true;
  const cohortInspection = result.lifecycleVerification?.cohorts || {};
  addPolarRow(
    'Archive approval',
    archiveApprovalVerified,
    'Archive-approval signature verified',
    'No verified archive-approval signature over archive-state',
    policyLevel === 'integrity-only' ? 'warn' : 'fail',
  );
  addPolarRow(
    'Strong PQ approval',
    status.strongPqSignatureVerified === true,
    'Strong PQ archive-approval signature verified',
    'Strong PQ archive-approval signature not present',
    archiveApprovalVerified === true && status.strongPqSignatureVerified !== true ? 'warn' : 'neutral',
  );
  appendSelfVerifiedSignatureRow(addRow, authenticity);

  if (status.transitionRecordPresent !== true) {
    addRow('Maintenance evidence', 'No transition or maintenance evidence present', 'neutral');
  } else {
    addPolarRow('Transition record', true, 'Transition record present', 'Transition record missing');
    addPolarRow(
      'Transition chain',
      status.transitionChainValid === true,
      'Transition-chain references valid',
      'Transition-chain references invalid or broken',
    );
    addPolarRow(
      'Maintenance evidence',
      status.maintenanceSignatureVerified === true,
      'Maintenance signature verified',
      'No verified maintenance signature on transition record(s)',
      'warn',
      'Maintenance signatures do not satisfy archive policy.'
    );
  }

  if (status.sourceEvidencePresent !== true) {
    addRow('Source evidence', 'No source-evidence objects present', 'neutral');
  } else {
    addPolarRow(
      'Source evidence',
      status.sourceEvidenceSignatureVerified === true,
      'Source-evidence signature verified',
      'Source-evidence present but no verified signature',
      'warn',
      'Source evidence does not satisfy archive policy.'
    );
  }

  if (cohortInspection.forkDetected === true) {
    addRow('Cohort selection', 'Same-state cohort fork remains known for this archive state', 'warn');
  }
  if (status.bundleCohortMixed === true) {
    addRow('Lifecycle bundle selection', 'Mixed embedded lifecycle bundle variants were present in the selected cohort', 'warn');
  } else {
    addRow('Lifecycle bundle selection', 'One lifecycle bundle variant selected for policy evaluation', 'ok');
  }

  appendSignerPinRows(addRow, addPolarRow, status, archiveApprovalVerified);

  const timestampEvidence = Array.isArray(authenticity?.timestampEvidence) ? authenticity.timestampEvidence : [];
  if (timestampEvidence.length > 0) {
    const completeCount = timestampEvidence.filter((item) => item.apparentlyComplete === true).length;
    const incompleteCount = timestampEvidence.length - completeCount;
    const completionParts = [];
    if (completeCount > 0) {
      completionParts.push(`OTS proof appears complete (heuristic): ${completeCount}`);
    }
    if (incompleteCount > 0) {
      completionParts.push(`OTS proof incomplete or pending: ${incompleteCount}`);
    }
    addRow(
      'Timestamp evidence',
      `OTS evidence linked to ${timestampEvidence.length} signature${timestampEvidence.length === 1 ? '' : 's'}`,
      incompleteCount > 0 ? 'warn' : 'ok',
      `${completionParts.join('; ')}. Timestamp evidence does not satisfy archive policy.`
    );
  } else {
    addRow('Timestamp evidence', 'No OTS evidence linked', 'neutral');
  }

  addPolarRow(
    'Archive policy',
    status.policySatisfied === true,
    'Archive policy satisfied',
    'Archive policy not satisfied',
    'fail',
    'Archive policy evaluation remains archive-approval-only.'
  );
  addNeutral('Maintenance, source-evidence, and timestamp evidence are reported separately and do not authorize restore.');

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

  const matrix = document.createElement('div');
  matrix.className = 'restore-verification-matrix';
  panel.appendChild(matrix);

  const addRow = (label, value, tone = 'neutral', detail = '') => {
    const item = document.createElement('div');
    item.className = `restore-result-item restore-matrix-row ${tone}`;
    const labelEl = document.createElement('span');
    labelEl.className = 'restore-matrix-label';
    labelEl.textContent = label;
    const valueEl = document.createElement('span');
    valueEl.className = 'restore-matrix-value';
    valueEl.textContent = value;
    item.append(labelEl, valueEl);
    if (detail) {
      const detailEl = document.createElement('span');
      detailEl.className = 'restore-matrix-detail';
      detailEl.textContent = detail;
      item.appendChild(detailEl);
    }
    matrix.appendChild(item);
  };
  const addPolarRow = (label, ok, okText, failText, failTone = 'fail', detail = '') => {
    addRow(label, ok ? okText : failText, ok ? 'ok' : failTone, detail);
  };

  const reason = String(error?.message || error || 'Archive policy not satisfied');
  const authenticity = error?.authenticity || null;
  const status = authenticity?.status || {};
  addRow('Plaintext release', 'Blocked', 'fail');
  addRow('Archive policy', 'Archive policy not satisfied', 'fail', reason);
  addRow('Integrity', 'Not evaluated after policy block', 'neutral');
  addRow(
    'Archive approval',
    status.archiveApprovalSignatureVerified === true
      ? 'Archive-approval signature verified but not policy-satisfying'
      : 'No policy-satisfying archive-approval signature verified',
    'fail'
  );
  addPolarRow(
    'Strong PQ approval',
    status.strongPqSignatureVerified === true,
    'Strong PQ archive-approval signature verified',
    'Strong PQ archive-approval signature not present',
    'neutral'
  );
  appendSelfVerifiedSignatureRow(addRow, authenticity);
  appendSignerPinRows(addRow, addPolarRow, status, status.archiveApprovalSignatureVerified === true);
  addRow('Evidence channels', 'Maintenance, source-evidence, and timestamp evidence cannot satisfy archive policy', 'neutral');

  panel.className = 'restore-result-panel fail';
  return true;
}

export function initQcontRestoreUI() {
  const qcontShardsInput = document.getElementById('qcontShardsInput');
  const restoreQcontBtn = document.getElementById('restoreQcontBtn');

  const restoreExpectedEdSigner = document.getElementById('restoreExpectedEdSigner');

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

    const resultPanel = document.getElementById('proRestoreResult');
    if (resultPanel) {
      resultPanel.style.display = 'none';
      resultPanel.replaceChildren();
    }

    setButtonsDisabled(true);
    let recoveredPrivKey = null;
    try {
      clearInlineError(RESTORE_INLINE_ERROR_ID);
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
        clearInlineError(RESTORE_INLINE_ERROR_ID);
      } else {
        logError('Verification failed. Automatic download is blocked.');
      }

      buildRestoreResultSummary(result, 'proRestoreResult');
    } catch (error) {
      buildRestorePolicyFailureSummary(error, 'proRestoreResult');
      showInlineError(RESTORE_INLINE_ERROR_ID, {
        title: 'Restore blocked',
        cause: error,
        artifact: summarizeFileList([...(files || [])], 'Restore input set'),
        action: restoreRecoveryAction(error),
      });
      logError(error);
    } finally {
      // Best-effort only: JS runtimes do not guarantee overwriting secrets in memory.
      if (recoveredPrivKey instanceof Uint8Array) {
        recoveredPrivKey.fill(0);
      }
      setButtonsDisabled(false);
    }
  });

  qcontShardsInput?.addEventListener('change', () => {
    clearInlineError(RESTORE_INLINE_ERROR_ID);
  });
  restoreExpectedEdSigner?.addEventListener('input', () => {
    clearInlineError(RESTORE_INLINE_ERROR_ID);
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
