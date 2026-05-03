import { isLifecycleParsedShard, parseLifecycleShard, reshareSameState } from '../../../app/crypto-service.js';
import { collectRestoreVerificationOptions } from './restore-ui.js';
import { bindRsParamsUI } from './rs-params-display.js';
import { createSuccessorShardInputRefreshController } from './successor-workflow-input.js';
import { download, readFileAsUint8Array, setWorkflowBusy } from '../../../utils.js';
import { log, logError, logSuccess, logWarning } from '../ui/logging.js';
import { showToast } from '../ui/toast.js';
import { renderDecisionCard } from '../ui/decision-card.js';
import {
  evidenceNoteRow,
  evidenceRow,
  evidenceSection,
  renderEvidenceMatrix,
} from '../ui/evidence-matrix.js';
import { deriveArchiveBaseName } from './archive-name.js';

let lastReshareExports = null;

function parsePositiveInteger(input, field) {
  const value = parseInt(String(input?.value || ''), 10);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function buildReshareResultSummary(result) {
  const panel = document.getElementById('proReshareResult');
  if (!panel) return;

  panel.replaceChildren();
  panel.style.display = 'block';

  const header = document.createElement('h4');
  header.textContent = 'Reshare Result';
  panel.appendChild(header);

  const cohortRotated = result.predecessorCohortId !== result.cohortId;
  const maintenanceSignatureCount = Number(result.maintenanceSignatureCountAdded || 0);

  const sections = [
    evidenceSection('Result', [
      evidenceRow('Archive state', 'Archive-state descriptor preserved exactly', 'ok'),
      evidenceRow(
        'Successor cohort',
        cohortRotated ? 'New successor cohort emitted' : 'No cohort rotation occurred',
        cohortRotated ? 'ok' : 'warn'
      ),
      evidenceRow(
        'Transition record',
        result.transitionRecordDigestHex ? 'Transition record emitted' : 'Transition record missing',
        result.transitionRecordDigestHex ? 'ok' : 'fail'
      ),
      evidenceRow(
        'Lifecycle bundle',
        result.lifecycleBundleDigestHex ? 'Lifecycle bundle updated for the new cohort' : 'Lifecycle bundle digest missing',
        result.lifecycleBundleDigestHex ? 'ok' : 'fail'
      ),
    ]),
    evidenceSection('Maintenance Evidence', [
      evidenceRow('Archive approval', 'Archive approval remains separate from maintenance resharing', 'ok'),
      maintenanceSignatureCount > 0
        ? evidenceRow(
            'Maintenance signatures',
            `Maintenance signatures added to the transition record (${maintenanceSignatureCount})`,
            'ok'
          )
        : evidenceRow(
            'Maintenance signatures',
            'No new maintenance signatures were attached. The transition record can be signed and attached later.',
            'neutral'
          ),
      evidenceNoteRow('The emitted transition-record.json is the external signing target for maintenance signatures.'),
    ]),
    evidenceSection('Next Actions', [
      evidenceRow(
        'Next step',
        'Distribute the new cohort, attach maintenance signatures later if needed, or continue to Restore with the updated evidence set.',
        'neutral'
      ),
    ]),
  ];

  renderEvidenceMatrix(panel, sections, { compact: true });

  panel.className = 'restore-result-panel ok';
}

function setReshareExportVisibility(visible) {
  const actions = document.getElementById('reshareExportActions');
  if (!actions) return;
  actions.classList.toggle('initially-hidden', !visible);
}

function clearReshareExportState() {
  lastReshareExports = null;
  setReshareExportVisibility(false);
}

function exportCachedReshareArtifact(kind) {
  if (!lastReshareExports) {
    showToast('Run resharing successfully before exporting result artifacts.', 'warning');
    return;
  }
  if (kind === 'transition-record') {
    download(new Blob([lastReshareExports.transitionRecordBytes], { type: 'application/json' }), lastReshareExports.transitionRecordName);
    logSuccess(`Exported ${lastReshareExports.transitionRecordName} for external maintenance signing.`);
    return;
  }
  if (kind === 'lifecycle-bundle') {
    download(new Blob([lastReshareExports.lifecycleBundleBytes], { type: 'application/json' }), lastReshareExports.lifecycleBundleName);
    logSuccess(`Exported ${lastReshareExports.lifecycleBundleName}.`);
  }
}

function renderResharePlanDecision(files, assessment) {
  const panel = document.getElementById('resharePlanDecision');
  if (!panel) return;
  if (!files.length) {
    renderDecisionCard(panel, null, { rootDataTestId: 'reshare-plan-decision' });
    return;
  }
  const a = assessment || { state: 'unknown', ready: false, message: 'Cannot evaluate shard threshold.' };
  let tone = 'neutral';
  if (a.ready === true && a.state === 'sufficient') tone = 'ok';
  else if (a.state === 'invalid') tone = 'fail';
  else if (a.state === 'insufficient' || a.state === 'unknown') tone = 'warn';

  renderDecisionCard(
    panel,
    {
      title: 'Reshare plan',
      tone,
      primaryOutcome: a.message || 'Analyze shard inputs to plan reshare.',
      lede: 'Same archive-state bytes; emits a new successor cohort, transition record, and updated lifecycle bundle. Does not re-evaluate full archive restore policy.',
      rows: [
        { label: 'Selected files', value: String(files.length), tone: 'neutral' },
        { label: 'Threshold gate', value: a.ready === true ? 'Satisfied for loaded cohort' : 'Not satisfied', tone: a.ready === true ? 'ok' : 'warn' },
      ],
    },
    { rootDataTestId: 'reshare-plan-decision', ariaLive: 'polite' }
  );
}

export function initQcontReshareUI() {
  const input = document.getElementById('qcontReshareInput');
  const reshareBtn = document.getElementById('reshareQcontBtn');
  const exportTransitionRecordBtn = document.getElementById('exportReshareTransitionRecordBtn');
  const exportLifecycleBundleBtn = document.getElementById('exportReshareLifecycleBundleBtn');
  const nInput = document.getElementById('reshareN');
  const kInput = document.getElementById('reshareK');
  const reasonCodeInput = document.getElementById('reshareReasonCode');
  const operatorRoleInput = document.getElementById('reshareOperatorRole');
  const notesInput = document.getElementById('reshareNotes');

  const refreshReshareInput = createSuccessorShardInputRefreshController({
    prefix: 'reshare',
    inputId: 'qcontReshareInput',
    statusDivId: 'proReshareStatus',
    statusTextId: 'proReshareStatusText',
    actionButtonId: 'reshareQcontBtn',
    intakeContainerId: 'reshareArtifactIntake',
    intakeLabel: 'Reshare artifact intake',
    intakeWorkflow: 'reshare',
    preflightContainerId: null,
    onAfterRefresh(files, assessment) {
      renderResharePlanDecision(files, assessment);
    },
  });

  async function updateReshareStatus() {
    await refreshReshareInput.refresh();
  }

  bindRsParamsUI({
    nInput,
    kInput,
    summaryEl: document.getElementById('reshareRsText'),
    ruleN: document.getElementById('reshareRuleN'),
    ruleRange: document.getElementById('reshareRuleRange'),
    ruleEven: document.getElementById('reshareRuleEven'),
    segData: document.getElementById('reshareSegData'),
    segParity: document.getElementById('reshareSegParity'),
    marker: document.getElementById('reshareMarker'),
    dataLabel: document.getElementById('reshareDataLabel'),
    parityLabel: document.getElementById('reshareParityLabel'),
    markerLabel: document.getElementById('reshareMarkerLabel'),
    ticks: document.getElementById('reshareRsTicks'),
    onValidityChange(valid) {
      if (!valid) {
        if (reshareBtn) reshareBtn.disabled = true;
      } else {
        void updateReshareStatus();
      }
    },
  });

  input?.addEventListener('change', () => {
    const resultPanel = document.getElementById('proReshareResult');
    if (resultPanel) {
      resultPanel.style.display = 'none';
      resultPanel.replaceChildren();
    }
    clearReshareExportState();
    void updateReshareStatus();
  });
  exportTransitionRecordBtn?.addEventListener('click', () => exportCachedReshareArtifact('transition-record'));
  exportLifecycleBundleBtn?.addEventListener('click', () => exportCachedReshareArtifact('lifecycle-bundle'));
  void updateReshareStatus();

  reshareBtn?.addEventListener('click', async () => {
    const files = [...(input?.files || [])];
    if (!files.length) {
      showToast('Select successor .qcont shards to reshare.', 'warning');
      return;
    }

    const resultPanel = document.getElementById('proReshareResult');
    if (resultPanel) {
      resultPanel.style.display = 'none';
      resultPanel.replaceChildren();
    }

    setWorkflowBusy('proViewReshare', true);
    try {
      const verificationOptions = await collectRestoreVerificationOptions('reshare', files);
      if (!verificationOptions.shardFiles.length) {
        throw new Error('No .qcont shard files were detected in selected input.');
      }
      if (verificationOptions.ignoredFileNames.length > 0) {
        logWarning(`Ignored non-reshare attachments: ${verificationOptions.ignoredFileNames.join(', ')}`);
      }

      const shardBytes = await Promise.all(verificationOptions.shardFiles.map(readFileAsUint8Array));
      const parsedShards = await Promise.all(shardBytes.map((bytes) => parseLifecycleShard(bytes, { strict: false })));
      const shards = parsedShards.map((shard, index) => {
        if (isLifecycleParsedShard(shard)) {
          return shard;
        }
        const errors = Array.isArray(shard?.diagnostics?.errors) ? shard.diagnostics.errors : [];
        const legacyRejected = errors.some((message) => /unsupported shard format|unsupported shard artifactfamily|qvqcont-6/i.test(String(message || '')));
        if (legacyRejected) {
          throw new Error('Legacy shards are not supported for resharing.');
        }
        throw new Error(
          errors.length > 0
            ? `Failed to parse successor shard input: ${errors.join('; ')}`
            : `Failed to parse successor shard input at selected shard ${index + 1}.`
        );
      });
      const n = parsePositiveInteger(nInput, 'reshare n');
      const k = parsePositiveInteger(kInput, 'reshare k');
      const reasonCode = String(reasonCodeInput?.value || 'cohort-rotation').trim() || 'cohort-rotation';
      const operatorRole = String(operatorRoleInput?.value || 'operator').trim() || 'operator';
      const notes = String(notesInput?.value || '').trim() || null;

      const result = await reshareSameState(shards, { n, k }, {
        selectedArchiveId: verificationOptions.selectedArchiveId,
        selectedStateId: verificationOptions.selectedStateId,
        selectedCohortId: verificationOptions.selectedCohortId,
        selectedLifecycleBundleDigestHex: verificationOptions.selectedLifecycleBundleDigestHex,
        lifecycleBundleBytes: verificationOptions.lifecycleBundleBytes,
        expectedEd25519Signer: verificationOptions.expectedEd25519Signer,
        transition: {
          reasonCode,
          operatorRole,
          notes,
          performedAt: new Date().toISOString(),
          actorHints: {
            surface: 'pro-reshare-ui',
          },
        },
        onLog: (message) => log(message),
        onWarn: (message) => logWarning(message),
      });

      const baseName = deriveArchiveBaseName(files);
      result.shards.forEach(({ blob, index }) => {
        const name = `${baseName}.reshared.part${index + 1}-of-${result.shards.length}.qcont`;
        download(blob, name);
        log(`Saved ${name} (${blob.size} B)`);
      });

      const archiveStateName = `${baseName}.archive-state.json`;
      download(new Blob([result.archiveStateBytes], { type: 'application/json' }), archiveStateName);
      log(`Saved ${archiveStateName} (${result.archiveStateBytes.length} B) SHA3-512=${result.archiveStateDigestHex}`);

      const cohortBindingName = `${baseName}.cohort-binding.json`;
      download(new Blob([result.cohortBindingBytes], { type: 'application/json' }), cohortBindingName);
      log(`Saved ${cohortBindingName} (${result.cohortBindingBytes.length} B) SHA3-512=${result.cohortBindingDigestHex}`);

      const lifecycleBundleName = `${baseName}.lifecycle-bundle.json`;
      download(new Blob([result.lifecycleBundleBytes], { type: 'application/json' }), lifecycleBundleName);
      log(`Saved ${lifecycleBundleName} (${result.lifecycleBundleBytes.length} B) SHA3-512=${result.lifecycleBundleDigestHex}`);

      const transitionRecordName = `${baseName}.transition-record.json`;
      download(new Blob([result.transitionRecordBytes], { type: 'application/json' }), transitionRecordName);
      log(`Saved ${transitionRecordName} (${result.transitionRecordBytes.length} B) SHA3-512=${result.transitionRecordDigestHex}`);
      log('The transition record is the maintenance signing target. Sign it externally, then re-import it with the detached signature through Attach > Maintenance signature.');

      lastReshareExports = {
        lifecycleBundleBytes: result.lifecycleBundleBytes,
        lifecycleBundleName,
        transitionRecordBytes: result.transitionRecordBytes,
        transitionRecordName,
      };
      setReshareExportVisibility(true);

      log(`ArchiveId preserved: ${result.archiveId}`);
      log(`StateId preserved: ${result.stateId}`);
      log(`Predecessor cohortId: ${result.predecessorCohortId}`);
      log(`Successor cohortId: ${result.cohortId}`);
      log('Same-state resharing is maintenance. It emits a new cohort and transition record without changing archive-state approval bytes.');
      for (const warning of result.operationalWarnings || []) {
        logWarning(warning);
      }
      if (result.maintenanceSignatureCountAdded > 0) {
        logSuccess(`Attached ${result.maintenanceSignatureCountAdded} new maintenance signature(s) to the reshared lifecycle bundle.`);
      } else {
        log('No new maintenance signatures were added. The emitted transition record can be signed externally and attached later as maintenance evidence.');
      }
      log('Next actions: distribute the new cohort, attach maintenance signatures later if needed, or continue to Restore with the updated evidence set.');

      buildReshareResultSummary(result);
      logSuccess('Same-state resharing completed successfully.');
    } catch (error) {
      if (/legacy shards are not supported for resharing/i.test(String(error?.message || error))) {
        showToast('Legacy shards are not supported for resharing.', 'warning');
      }
      clearReshareExportState();
      logError(error);
    } finally {
      setWorkflowBusy('proViewReshare', false);
      void updateReshareStatus();
    }
  });
}
