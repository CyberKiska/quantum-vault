import { parseShard, restoreFromShards } from '../../../app/crypto-service.js';
import { classifyRestoreInputFiles } from '../../../app/restore-inputs.js';
import { download, readFileAsUint8Array, setButtonsDisabled } from '../../../utils.js';
import {
  formatAuthenticityStatusMessage,
  formatSignatureResultSummary,
  log,
  logError,
  logSuccess,
  logWarning,
} from '../ui/logging.js';
import { showToast } from '../ui/toast.js';

async function readVerificationOptionsFromDom({
  allFiles = [],
  expectedSignerInput,
}) {
  const classified = await classifyRestoreInputFiles(allFiles);
  return {
    ...classified,
    expectedEd25519Signer: String(expectedSignerInput?.value || '').trim(),
  };
}

function logVerificationSummary(authenticity, onLog, onWarn, onSuccess) {
  const policy = authenticity?.policy;
  const verification = authenticity?.verification;
  const status = authenticity?.status;

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
  if (!verification) return;

  const counts = verification.counts;
  onLog(`Signature counts: valid=${counts.validTotal}, strong-pq=${counts.validStrongPq}, pinned=${counts.pinnedValidTotal}, bundle-pinned=${counts.bundlePinnedValidTotal}, user-pinned=${counts.userPinnedValidTotal}.`);
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

function buildRestoreResultSummary(result, resultPanelId) {
  const panel = document.getElementById(resultPanelId);
  if (!panel) return;

  panel.replaceChildren();
  panel.style.display = 'block';
  const { qencOk, qkeyOk, authenticity } = result;
  const allOk = qencOk && qkeyOk && authenticity?.status?.policySatisfied;

  const header = document.createElement('h4');
  header.textContent = 'Restore Result';
  panel.appendChild(header);

  const addItem = (ok, text, warn = false) => {
    const item = document.createElement('div');
    item.className = `restore-result-item ${warn ? 'warn' : (ok ? 'ok' : 'fail')}`;
    item.textContent = `${warn ? '⚠' : (ok ? '✓' : '✗')} ${text}`;
    panel.appendChild(item);
  };

  addItem(qencOk, `Container integrity${qencOk ? ' verified' : ' FAILED'}`);
  addItem(qkeyOk, `Secret key integrity${qkeyOk ? ' verified' : ' FAILED'}`);

  const status = authenticity?.status || {};
  addItem(status.signatureVerified === true, 'Signature verified', status.signatureVerified !== true);
  addItem(status.strongPqSignatureVerified === true, 'Strong PQ signature verified', status.signatureVerified === true && status.strongPqSignatureVerified !== true);
  addItem(status.bundlePinned === true, 'Bundle signer pinned', status.signatureVerified === true && status.bundlePinned !== true);
  if (status.userPinProvided === true || status.userPinned === true) {
    addItem(status.userPinned === true, 'User signer pinned', status.userPinProvided === true && status.userPinned !== true);
  }
  addItem(status.policySatisfied === true, 'Archive policy satisfied', status.policySatisfied !== true);

  const timestampEvidence = Array.isArray(authenticity?.timestampEvidence) ? authenticity.timestampEvidence : [];
  if (timestampEvidence.length > 0) {
    const completeCount = timestampEvidence.filter((item) => item.apparentlyComplete === true).length;
    const incompleteCount = timestampEvidence.length - completeCount;
    addItem(true, `OTS evidence linked to ${timestampEvidence.length} signature${timestampEvidence.length === 1 ? '' : 's'}`);
    if (completeCount > 0) {
      addItem(true, `OTS proof appears complete (${completeCount})`);
    }
    if (incompleteCount > 0) {
      addItem(false, `OTS proof appears incomplete (${incompleteCount})`, true);
    }
  }

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
    try {
      const allFiles = [...files];
      const verificationOptions = await readVerificationOptionsFromDom({
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
      const shards = shardBytesArr.map((bytes) => parseShard(bytes, { strict: true }));

      const result = await restoreFromShards(shards, {
        onLog: (msg) => log(msg),
        onError: (msg) => logError(msg),
        onWarn: (msg) => logWarning(msg),
        verification: verificationOptions,
      });

      log(`Selected manifest digest: ${result.manifestDigestHex}`);
      log(`Selected bundle digest: ${result.bundleDigestHex}`);
      log(`Manifest source: ${result.manifestSource}`);
      logVerificationSummary(result.authenticity, log, logWarning, logSuccess);

      const { qencBytes, privKey, containerId, containerHash, privateKeyHash, recoveredQencHash, recoveredPrivHash, qencOk, qkeyOk } = result;
      log(`Recovered .qenc SHA3-512=${recoveredQencHash} (expected ${containerHash})`);
      log(`Recovered .qkey SHA3-512=${recoveredPrivHash}${privateKeyHash ? ` (expected ${privateKeyHash})` : ''}`);

      const qencBlob = new Blob([qencBytes], { type: 'application/octet-stream' });
      const qkeyBlob = new Blob([privKey], { type: 'application/octet-stream' });
      const qencName = `${containerId}.recovered.qenc`;
      const qkeyName = `${containerId}.recovered.secretKey.qkey`;

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
      setButtonsDisabled(false);
    }
  });
}

export async function collectRestoreVerificationOptions(prefix = 'restore', files = []) {
  const expectedSignerInput = document.getElementById(`${prefix}ExpectedEdSigner`);

  return readVerificationOptionsFromDom({
    allFiles: files,
    expectedSignerInput,
  });
}
