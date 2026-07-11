/**
 * Per-file artifact classification for intake reporting only.
 * Outputs describe what the UI shows the operator; they do not gate crypto workflows.
 */

import { classifyArtifactFileBytes } from '../../../app/artifact-intake-service.js';
import { shortDigestLabel } from './digest-details.js';

/** Default next-action copy from markAccepted; grouped rows replace duplicates with one summary (see artifact-table-ui). */
export const DEFAULT_ACCEPTED_NEXT_ACTION = 'No action needed before evaluation.';
export const GROUP_ACCEPTED_NEXT_ACTION = 'No further action on these items before evaluation.';

function inferSignatureClass(workflow, channel) {
  if (workflow === 'attach') {
    if (channel === 'maintenance') return 'maintenance signature';
    if (channel === 'source-evidence') return 'source-evidence signature';
    return 'archive-approval signature';
  }
  return 'archive-approval signature';
}

function inferSignatureRole(workflow, channel) {
  if (workflow === 'attach' && channel !== 'archive-approval') return 'Separate evidence only';
  if (workflow === 'restore' || workflow === 'lite-restore') return 'Can satisfy archive policy when verified and trusted';
  return 'Can satisfy archive policy';
}

function errorMessageText(error) {
  return String(error?.message || error || '').trim();
}

function rowProblemOverride(row, error) {
  const message = errorMessageText(error);
  if (!message) return null;
  const lower = message.toLowerCase();
  const lowerName = String(row.file || '').toLowerCase();

  if (row.kind === 'ots-proof' && (
    lower.includes('opentimestamps') ||
    lower.includes('ots') ||
    lower.includes('does not match any detached signature') ||
    lower.includes('targetref is unknown')
  )) {
    return {
      status: 'wrong target',
      tone: 'fail',
      nextAction: 'Load the detached signature this OTS proof stamps, or remove this proof.',
    };
  }

  if (row.kind === 'signature' && (
    lower.includes('wrong bytes') ||
    lower.includes('wrong target') ||
    lower.includes('instead of the transition record') ||
    lower.includes('instead of source-evidence') ||
    lower.includes('no provided .pqpk file matches this detached pq signature')
  )) {
    return {
      status: 'wrong target',
      tone: 'fail',
      nextAction: lowerName.endsWith('.qsig')
        ? 'Re-sign the exact channel target bytes and load the matching signer .pqpk.'
        : 'Load a signature over the expected channel target.',
    };
  }

  if (row.kind === 'lifecycle-bundle' && lower.includes('lifecycle bundle') && lower.includes('does not match')) {
    return {
      status: 'conflict',
      tone: 'fail',
      nextAction: 'Replace this lifecycle bundle with one from the selected archive/state/cohort.',
    };
  }

  return null;
}

function createBaseRow(file, workflow, channel) {
  const name = String(file?.name || 'unnamed');
  return {
    file: name,
    kind: 'unsupported',
    classifiedAs: 'unsupported',
    target: 'Not recognized',
    role: 'Ignored',
    status: 'unsupported',
    tone: 'fail',
    nextAction: 'Remove this file or replace it with a supported Quantum Vault artifact.',
    details: [],
    workflow,
    channel,
  };
}

function addDetail(row, label, value, copyValue = value) {
  const text = Array.isArray(value) ? value.filter(Boolean).join(', ') : String(value || '');
  if (!text) return;
  row.details.push({ label, value: text, copyValue: String(copyValue || text) });
}

function markAccepted(row, { classifiedAs, target, role, kind, nextAction = DEFAULT_ACCEPTED_NEXT_ACTION }) {
  row.kind = kind;
  row.classifiedAs = classifiedAs;
  row.target = target;
  row.role = role;
  row.status = 'accepted';
  row.tone = 'ok';
  row.nextAction = nextAction;
}

/**
 * @param {File} file
 * @param {{ workflow?: string, channel?: string }} [options]
 */
export async function classifyArtifactFile(file, options = {}) {
  const { workflow = 'restore', channel = 'archive-approval' } = options;
  const row = createBaseRow(file, workflow, channel);
  const name = row.file;
  const lowerName = name.toLowerCase();

  if (lowerName.endsWith('.qvmanifest.json')) {
    row.status = workflow === 'attach' ? 'unsupported' : 'ignored';
    row.tone = workflow === 'attach' ? 'fail' : 'warn';
    row.nextAction = workflow === 'attach'
      ? 'Remove legacy manifest-side files; use successor shards or lifecycle artifacts.'
      : 'No action. Legacy manifest-side files are ignored by successor workflows.';
    return row;
  }

  let classification;
  try {
    ({ classification } = await classifyArtifactFileBytes(file));
  } catch (error) {
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `File could not be read: ${errorMessageText(error)}`;
    return row;
  }

  addDetail(row, 'File SHA-256', classification.fileSha256Hex);
  const metadata = classification.metadata || {};
  const message = errorMessageText(classification.errorMessage || classification.error);

  if (classification.kind === 'qcont-shard') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: 'QVqcont-7 shard',
        target: `Archive ${shortDigestLabel(metadata.archiveId, { edgeLength: 8 })} / Cohort ${shortDigestLabel(metadata.cohortId, { edgeLength: 8 })}`,
        role: workflow === 'reshare' ? 'Reshare predecessor input' : 'Restore threshold material',
        kind: 'qcont-shard',
      });
      addDetail(row, 'Archive id', metadata.archiveId);
      addDetail(row, 'State digest', metadata.stateId);
      addDetail(row, 'Cohort id', metadata.cohortId);
      addDetail(row, 'Shard index', String(metadata.shardIndex));
      addDetail(row, 'Lifecycle-bundle digest', metadata.lifecycleBundleDigestHex);
      return row;
    }
    row.kind = 'qcont-shard';
    row.classifiedAs = 'QVqcont-7 shard';
    row.target = 'Unreadable shard metadata';
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace this shard. ${message}`;
    return row;
  }

  if (classification.kind === 'pqpk') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: 'PQ signer key',
        target: metadata.suiteDisplay || metadata.suite,
        role: 'Signer pin material',
        kind: 'pqpk',
        nextAction: 'Use with matching detached PQ signatures when policy requires trusted signer evidence.',
      });
      addDetail(row, 'Signature suite', metadata.suiteDisplay || metadata.suite);
      addDetail(row, 'Public key SHA-256', metadata.publicKeySha256Hex);
      return row;
    }
    row.kind = 'pqpk';
    row.classifiedAs = 'PQ signer key';
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace malformed signer key. ${message}`;
    return row;
  }

  if (classification.kind === 'signature') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: inferSignatureClass(workflow, channel),
        target: classification.format === 'stellar-sig'
          ? 'Stellar detached signature document'
          : `Payload digest ${shortDigestLabel(metadata.payloadDigestHex, { edgeLength: 8 })}`,
        role: inferSignatureRole(workflow, channel),
        kind: 'signature',
        nextAction: 'Evaluation will verify target bytes and signer trust before using this signature.',
      });
      row.status = 'pending';
      row.tone = 'warn';
      if (classification.format === 'qsig') {
        addDetail(row, 'Payload digest', metadata.payloadDigestHex);
        addDetail(row, 'Signature suite', metadata.suiteDisplay || metadata.suite);
        addDetail(row, 'Context', metadata.context);
      }
      return row;
    }
    row.kind = 'signature';
    row.classifiedAs = inferSignatureClass(workflow, channel);
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace malformed detached PQ signature. ${message}`;
    return row;
  }

  if (classification.kind === 'ots-proof') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: 'OTS proof',
        target: `Stamped SHA-256 ${shortDigestLabel(metadata.stampedDigestHex, { edgeLength: 8 })}`,
        role: 'Timestamp only',
        kind: 'ots-proof',
        nextAction: 'Evaluation will link this proof to a loaded detached signature.',
      });
      row.status = 'pending';
      row.tone = 'warn';
      addDetail(row, 'Stamped SHA-256', metadata.stampedDigestHex);
      addDetail(row, 'Proof completeness', metadata.appearsComplete ? 'complete-looking' : 'pending/incomplete');
      return row;
    }
    row.kind = 'ots-proof';
    row.classifiedAs = 'OTS proof';
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace malformed timestamp proof. ${message}`;
    return row;
  }

  if (classification.kind === 'lifecycle-bundle') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: 'lifecycle bundle',
        target: `Bundle ${shortDigestLabel(metadata.digestHex, { edgeLength: 8 })}`,
        role: workflow === 'attach' ? 'Evidence merge target' : 'Disambiguation input',
        kind: 'lifecycle-bundle',
      });
      addDetail(row, 'Lifecycle-bundle digest', metadata.digestHex);
      addDetail(row, 'Archive-state digest', metadata.archiveStateDigestHex);
      addDetail(row, 'Current cohort-binding digest', metadata.currentCohortBindingDigestHex);
      return row;
    }
    row.kind = 'lifecycle-bundle';
    row.classifiedAs = 'lifecycle bundle';
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace malformed lifecycle bundle. ${message}`;
    return row;
  }

  if (classification.kind === 'archive-state') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: 'archive-state descriptor',
        target: `State ${shortDigestLabel(metadata.stateDigestHex, { edgeLength: 8 })}`,
        role: workflow === 'attach' ? 'Archive approval target' : 'Disambiguation input',
        kind: 'archive-state',
      });
      addDetail(row, 'Archive id', metadata.archiveId);
      addDetail(row, 'State digest', metadata.stateDigestHex);
      return row;
    }
    row.kind = 'archive-state';
    row.classifiedAs = 'archive-state descriptor';
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace malformed archive-state descriptor. ${message}`;
    return row;
  }

  if (classification.kind === 'transition-record') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: 'transition-record JSON',
        target: `Transition ${shortDigestLabel(metadata.digestHex, { edgeLength: 8 })}`,
        role: 'Separate evidence only',
        kind: 'transition-record',
      });
      addDetail(row, 'Transition-record digest', metadata.digestHex);
      addDetail(row, 'From cohort', metadata.fromCohortId);
      addDetail(row, 'To cohort', metadata.toCohortId);
      return row;
    }
    row.kind = 'transition-record';
    row.classifiedAs = 'transition-record JSON';
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace malformed transition record. ${message}`;
    return row;
  }

  if (classification.kind === 'source-evidence') {
    if (classification.status === 'recognized') {
      markAccepted(row, {
        classifiedAs: 'source-evidence JSON',
        target: `Source evidence ${shortDigestLabel(metadata.digestHex, { edgeLength: 8 })}`,
        role: 'Separate evidence only',
        kind: 'source-evidence',
      });
      addDetail(row, 'Source-evidence digest', metadata.digestHex);
      addDetail(row, 'Relation type', metadata.relationType);
      return row;
    }
    row.kind = 'source-evidence';
    row.classifiedAs = 'source-evidence JSON';
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `Replace malformed source-evidence JSON. ${message}`;
    return row;
  }

  row.status = workflow === 'restore' || workflow === 'lite-restore' || workflow === 'reshare' ? 'ignored' : 'unsupported';
  row.tone = row.status === 'ignored' ? 'warn' : 'fail';
  row.nextAction = row.status === 'ignored'
    ? 'No action. This file is not used by this workflow.'
    : 'Remove this unsupported file from the attach set.';
  return row;
}

function applyDuplicateStatus(rows) {
  const seen = new Map();
  for (const row of rows) {
    const fingerprint = row.details.find((entry) => entry.label === 'File SHA-256')?.value;
    if (!fingerprint || row.tone === 'fail') continue;
    const key = `${row.kind}:${fingerprint}`;
    if (!seen.has(key)) {
      seen.set(key, row);
      continue;
    }
    row.status = 'duplicate';
    row.tone = 'warn';
    row.nextAction = 'Remove the duplicate file unless you intentionally want redundant intake evidence.';
  }
}

function applyProblemOverrides(rows, error) {
  for (const row of rows) {
    const override = rowProblemOverride(row, error);
    if (!override) continue;
    row.status = override.status;
    row.tone = override.tone;
    row.nextAction = override.nextAction;
  }
}

/**
 * Classify each file and apply intake-only duplicate / workflow-error overlays.
 *
 * @param {File[]} files
 * @param {{ workflow?: string, channel?: string, error?: unknown }} [options]
 * @returns {Promise<Array<Awaited<ReturnType<typeof classifyArtifactFile>>>>}
 */
export async function classifyArtifactIntakeRows(files, options = {}) {
  const { workflow = 'restore', channel = 'archive-approval', error = null } = options;
  const rows = [];
  for (const file of files) {
    rows.push(await classifyArtifactFile(file, { workflow, channel }));
  }
  applyDuplicateStatus(rows);
  applyProblemOverrides(rows, error);
  return rows;
}
