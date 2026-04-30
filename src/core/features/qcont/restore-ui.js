import { parseLifecycleShard, restoreFromShards } from '../../../app/crypto-service.js';
import { classifyRestoreInputFiles } from '../../../app/restore-inputs.js';
import { download, readFileAsUint8Array, setButtonsDisabled, shortenHash } from '../../../utils.js';
import { parseArchiveStateDescriptorBytes, parseLifecycleBundleBytes } from '../../crypto/lifecycle/artifacts.js';
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
import { renderArtifactIntakeTable } from '../ui/artifact-intake.js';
import {
  buildRestoreEvidenceMatrixSections,
  buildRestorePolicyFailureEvidenceMatrixSections,
  getRestoreReleaseState,
  renderEvidenceMatrix,
} from '../ui/evidence-matrix.js';
import { showToast } from '../ui/toast.js';

const successorSelectionState = new Map();
const RESTORE_INLINE_ERROR_ID = 'proRestoreInlineError';
const RESTORE_PREFLIGHT_CARD_ID = 'restorePreflightDecision';
let proRestoreEvaluation = null;

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

function collectLifecycleAttachmentCounts(lifecycleBundles = []) {
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

function releaseTextForPolicy(policyLevel, allowed) {
  if (!allowed) return 'Plaintext release: blocked';
  if (policyLevel === 'integrity-only') return 'Plaintext release: allowed by integrity-only policy';
  if (policyLevel === 'strong-pq-signature') return 'Plaintext release: allowed by strong PQ archive-approval policy';
  if (policyLevel === 'any-signature') return 'Plaintext release: allowed by archive-signature policy';
  return 'Plaintext release: allowed by selected archive policy';
}

function addPreflightRow(list, label, value, tone = 'neutral') {
  const item = document.createElement('div');
  item.className = `restore-preflight-row ${tone}`;
  const labelEl = document.createElement('span');
  labelEl.className = 'restore-preflight-label';
  labelEl.textContent = label;
  const valueEl = document.createElement('span');
  valueEl.className = 'restore-preflight-value';
  valueEl.textContent = value;
  item.append(labelEl, valueEl);
  list.appendChild(item);
}

function renderRestorePreflightCard(containerId, decision) {
  const panel = document.getElementById(containerId);
  if (!panel) return;
  if (!decision) {
    panel.replaceChildren();
    panel.style.display = 'none';
    panel.className = 'restore-preflight-card initially-hidden';
    return;
  }

  panel.replaceChildren();
  panel.style.display = 'block';
  panel.className = `restore-preflight-card ${decision.tone || 'neutral'}`;
  panel.setAttribute('data-release-state', decision.releaseState || 'blocked');

  const header = document.createElement('h4');
  header.textContent = decision.releaseText || 'Plaintext release: blocked';
  panel.appendChild(header);

  const lede = document.createElement('p');
  lede.className = 'restore-preflight-lede';
  lede.textContent = decision.lede || 'Restore inputs are evaluated before any recovered bytes can be released.';
  panel.appendChild(lede);

  const rows = document.createElement('div');
  rows.className = 'restore-preflight-rows';
  addPreflightRow(rows, 'Threshold readiness', decision.thresholdReadiness || 'Not evaluated', decision.thresholdTone || 'neutral');
  addPreflightRow(rows, 'Selected archive/state/cohort', decision.selection || 'Pending selection', decision.selectionTone || 'neutral');
  addPreflightRow(rows, 'Selected lifecycle-bundle digest', decision.lifecycleBundleDigest || 'Pending selection', decision.bundleTone || 'neutral');
  addPreflightRow(rows, 'Policy', decision.policy || 'unknown', decision.policyTone || 'neutral');
  addPreflightRow(rows, 'Blocking reason', decision.blockingReason || 'None', decision.blockingTone || 'neutral');
  panel.appendChild(rows);
}

function clearRestorePreflightCard(containerId) {
  renderRestorePreflightCard(containerId, null);
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
      if (prefix === 'restore') {
        clearInlineError(RESTORE_INLINE_ERROR_ID);
        clearProRestoreEvaluation();
      }
      const latest = successorSelectionState.get(prefix);
      void refreshSelectionAndPreflight(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  if (elements.cohortSelect) {
    elements.cohortSelect.onchange = () => {
      if (prefix === 'restore') {
        clearInlineError(RESTORE_INLINE_ERROR_ID);
        clearProRestoreEvaluation();
      }
      const latest = successorSelectionState.get(prefix);
      void refreshSelectionAndPreflight(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  if (elements.bundleSelect) {
    elements.bundleSelect.onchange = () => {
      if (prefix === 'restore') {
        clearInlineError(RESTORE_INLINE_ERROR_ID);
        clearProRestoreEvaluation();
      }
      const latest = successorSelectionState.get(prefix);
      void refreshSelectionAndPreflight(prefix, latest?.files || [], latest?.actionButton || actionButton, latest?.assessment || assessment);
    };
  }
  setRestoreActionAvailability(prefix, actionButton);
  return current;
}

async function refreshSelectionAndPreflight(prefix, files, actionButton, assessment) {
  await refreshSuccessorSelectionUi(prefix, files, actionButton, assessment);
  if (!files?.length) return;
  const containerId = prefix === 'restore' ? RESTORE_PREFLIGHT_CARD_ID : `${prefix}PreflightDecision`;
  await renderRestorePreflightForFiles({
    prefix,
    containerId,
    files,
    expectedSignerInput: document.getElementById(`${prefix}ExpectedEdSigner`),
  });
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
}) {
  const thresholdReady = assessment?.ready === true;
  return {
    releaseText: releaseTextForPolicy(policyLevel, false),
    releaseState: 'blocked',
    tone,
    lede: 'No recovered bytes will be released while this condition is unresolved.',
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
  };
}

async function buildRestorePreflightDecisionForFiles({
  prefix = 'restore',
  files = [],
  expectedSignerInput,
}) {
  const selected = successorSelectionState.get(prefix) || {};
  const assessment = selected.assessment || null;
  if (!files.length) return null;

  let classified;
  try {
    classified = await classifyRestoreInputFiles(files);
  } catch (error) {
    return buildPreflightBlockedDecision({
      assessment,
      policyLevel: 'unknown',
      reason: error?.message || String(error),
    });
  }

  const model = selected.model || { states: [] };
  const { selectedState, selectedCohort, selectedLifecycleBundleDigestHex } = getSelectedPreflightPath(model, selected);
  let parsedProvidedBundle = null;
  if (classified.lifecycleBundleBytes instanceof Uint8Array) {
    try {
      parsedProvidedBundle = await parseLifecycleBundleBytes(classified.lifecycleBundleBytes);
    } catch {
      parsedProvidedBundle = null;
    }
  }
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
  const expectedEd25519Signer = String(expectedSignerInput?.value || '').trim();

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
  };

  if (policyLevel === 'integrity-only') {
    return {
      ...common,
      releaseText: releaseTextForPolicy(policyLevel, true),
      releaseState: 'allowed-provisional',
      tone: 'warn',
      lede: 'Policy consequence is clear before evaluation: archive approval is not required, but integrity checks must still pass before release.',
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
      lede: 'Restore evaluation is blocked before reconstruction because required approval evidence is absent.',
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
    lede: `Evidence is present (${evidenceParts.join(', ')}). Release remains blocked until cryptographic evaluation succeeds.`,
    blockingReason: 'Run Evaluate Restore Inputs; release remains blocked until integrity and archive policy checks pass.',
    blockingTone: 'neutral',
    canEvaluate: true,
  };
}

export async function renderRestorePreflightForFiles({
  prefix = 'restore',
  containerId = RESTORE_PREFLIGHT_CARD_ID,
  files = [],
  expectedSignerInput = null,
}) {
  const decision = await buildRestorePreflightDecisionForFiles({ prefix, files, expectedSignerInput });
  renderRestorePreflightCard(containerId, decision);
  return decision;
}

function buildRestorePreflightFromResult(result) {
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
    blockingReason: reason,
    blockingTone: releaseAllowed ? (policyLevel === 'integrity-only' ? 'warn' : 'ok') : 'fail',
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
  if (proRestoreEvaluation?.result?.privKey instanceof Uint8Array) {
    proRestoreEvaluation.result.privKey.fill(0);
  }
  proRestoreEvaluation = null;
  setReleaseButtonState(false);
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

  renderEvidenceMatrix(panel, buildRestoreEvidenceMatrixSections(result, options), {
    compact: options.compact === true,
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

  renderEvidenceMatrix(panel, buildRestorePolicyFailureEvidenceMatrixSections(error), { compact: true });

  panel.className = 'restore-result-panel fail';
  return true;
}

export function initQcontRestoreUI() {
  const qcontShardsInput = document.getElementById('qcontShardsInput');
  const restoreQcontBtn = document.getElementById('restoreQcontBtn');
  const releaseRestoredFilesBtn = document.getElementById('releaseRestoredFilesBtn');

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

    clearProRestoreEvaluation();
    const resultPanel = document.getElementById('proRestoreResult');
    if (resultPanel) {
      resultPanel.style.display = 'none';
      resultPanel.replaceChildren();
    }

    setButtonsDisabled(true);
    let renderedPreflightDecision = null;
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

      renderRestorePreflightCard(RESTORE_PREFLIGHT_CARD_ID, buildRestorePreflightFromResult(result));
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
      setButtonsDisabled(false);
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
      renderRestorePreflightCard(RESTORE_PREFLIGHT_CARD_ID, buildRestorePreflightFromResult(result));
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
