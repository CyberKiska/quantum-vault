import { isLifecycleParsedShard, parseLifecycleShard, reshareSameState } from '../../../app/crypto-service.js';
import { collectRestoreVerificationOptions, refreshSuccessorSelectionUi } from './restore-ui.js';
import { bindRsParamsUI } from './rs-params-display.js';
import { updateShardSelectionStatus } from '../ui/shards-status.js';
import { download, readFileAsUint8Array, setButtonsDisabled } from '../../../utils.js';
import { log, logError, logSuccess, logWarning } from '../ui/logging.js';
import { showToast } from '../ui/toast.js';

let reshareStatusSeq = 0;

function deriveReshareBaseName(files = []) {
  const shard = files.find((file) => String(file?.name || '').toLowerCase().endsWith('.qcont'));
  if (!shard) return 'archive';
  return String(shard.name)
    .replace(/\.part\d+-of-\d+\.qcont$/i, '')
    .replace(/\.archive-state\.json$/i, '')
    .replace(/\.cohort-binding\.json$/i, '')
    .replace(/\.lifecycle-bundle\.json$/i, '')
    .replace(/\.transition-record\.json$/i, '');
}

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

  const addSection = (title) => {
    const section = document.createElement('div');
    section.className = 'restore-result-section';
    section.textContent = title;
    panel.appendChild(section);
  };

  const addItem = (ok, text, warn = false) => {
    const item = document.createElement('div');
    item.className = `restore-result-item ${warn ? 'warn' : (ok ? 'ok' : 'fail')}`;
    item.textContent = `${warn ? '⚠' : (ok ? '✓' : '✗')} ${text}`;
    panel.appendChild(item);
  };

  const addNeutral = (text) => {
    const item = document.createElement('div');
    item.className = 'restore-result-item neutral';
    item.textContent = `· ${text}`;
    panel.appendChild(item);
  };

  addSection('Result');
  addItem(true, 'Archive-state descriptor preserved exactly');
  addItem(result.predecessorCohortId !== result.cohortId, 'New successor cohort emitted');
  addItem(Boolean(result.transitionRecordDigestHex), 'Transition record emitted');
  addItem(Boolean(result.lifecycleBundleDigestHex), 'Lifecycle bundle updated for the new cohort');

  addSection('Maintenance Evidence');
  addItem(true, 'Archive approval remains separate from maintenance resharing');
  if (result.maintenanceSignatureCountAdded > 0) {
    addItem(true, `Maintenance signatures added to the transition record (${result.maintenanceSignatureCountAdded})`);
  } else {
    addNeutral('No new maintenance signatures were attached. The transition record can be signed and attached later.');
  }

  addSection('Next Actions');
  addNeutral('Distribute the new cohort, attach maintenance signatures later if needed, or continue to Restore with the updated evidence set.');

  panel.className = 'restore-result-panel ok';
}

async function updateReshareStatus() {
  const input = document.getElementById('qcontReshareInput');
  const statusDiv = document.getElementById('proReshareStatus');
  const statusText = document.getElementById('proReshareStatusText');
  const actionButton = document.getElementById('reshareQcontBtn');
  if (!input || !statusDiv || !statusText || !actionButton) return;

  const files = [...(input.files || [])];
  const requestId = ++reshareStatusSeq;
  const assessment = await updateShardSelectionStatus({
    files,
    statusDiv,
    statusText,
    actionButton,
    isCurrent: () => requestId === reshareStatusSeq,
  });
  if (requestId !== reshareStatusSeq) return;
  await refreshSuccessorSelectionUi('reshare', files, actionButton, assessment || { ready: false });
}

export function initQcontReshareUI() {
  const input = document.getElementById('qcontReshareInput');
  const reshareBtn = document.getElementById('reshareQcontBtn');
  const nInput = document.getElementById('reshareN');
  const kInput = document.getElementById('reshareK');
  const reasonCodeInput = document.getElementById('reshareReasonCode');
  const operatorRoleInput = document.getElementById('reshareOperatorRole');
  const notesInput = document.getElementById('reshareNotes');

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
    void updateReshareStatus();
  });
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

    setButtonsDisabled(true);
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

      const baseName = deriveReshareBaseName(files);
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
      logError(error);
    } finally {
      setButtonsDisabled(false);
      void updateReshareStatus();
    }
  });
}
