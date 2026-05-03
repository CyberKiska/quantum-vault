import { parseLifecycleShard } from '../../../app/crypto-service.js';
import { readFileAsUint8Array } from '../../../utils.js';
import { startsWithAscii } from '../../crypto/byte-prefix.js';
import { digestSha256, toHex } from '../../crypto/bytes.js';
import { parseOpenTimestampProof } from '../../crypto/auth/opentimestamps.js';
import { unpackPqpk, unpackQsig } from '../../crypto/auth/qsig.js';
import { isSupportedStellarSignatureDocumentBytes } from '../../crypto/auth/stellar-sig.js';
import {
  parseArchiveStateDescriptorBytes,
  parseLifecycleBundleBytes,
  parseSourceEvidenceBytes,
  parseTransitionRecordBytes,
} from '../../crypto/lifecycle/artifacts.js';
import { createDisclosurePanel } from './disclosure.js';
import { createDigestDetailList, shortDigestLabel } from './digest-details.js';

const DEFAULT_TABLE_LABEL = 'Selected artifact intake';

/** Default next-action copy from markAccepted; grouped rows replace duplicates with one summary. */
const DEFAULT_ACCEPTED_NEXT_ACTION = 'No action needed before evaluation.';
const GROUP_ACCEPTED_NEXT_ACTION = 'No further action on these items before evaluation.';

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

async function classifyArtifactFile(file, options) {
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

  let bytes;
  try {
    bytes = await readFileAsUint8Array(file);
  } catch (error) {
    row.status = 'malformed';
    row.tone = 'fail';
    row.nextAction = `File could not be read: ${errorMessageText(error)}`;
    return row;
  }

  addDetail(row, 'File SHA-256', toHex(await digestSha256(bytes)));

  if (lowerName.endsWith('.qcont') || startsWithAscii(bytes, 'QVC1')) {
    try {
      const parsed = await parseLifecycleShard(bytes, { strict: true });
      markAccepted(row, {
        classifiedAs: 'QVqcont-7 shard',
        target: `Archive ${shortDigestLabel(parsed.archiveState?.archiveId, { edgeLength: 8 })} / Cohort ${shortDigestLabel(parsed.cohortId, { edgeLength: 8 })}`,
        role: workflow === 'reshare' ? 'Reshare predecessor input' : 'Restore threshold material',
        kind: 'qcont-shard',
      });
      addDetail(row, 'Archive id', parsed.archiveState?.archiveId);
      addDetail(row, 'State digest', parsed.stateId);
      addDetail(row, 'Cohort id', parsed.cohortId);
      addDetail(row, 'Shard index', String(parsed.shardIndex));
      addDetail(row, 'Lifecycle-bundle digest', parsed.lifecycleBundleDigestHex);
    } catch (error) {
      row.kind = 'qcont-shard';
      row.classifiedAs = 'QVqcont-7 shard';
      row.target = 'Unreadable shard metadata';
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace this shard. ${errorMessageText(error)}`;
    }
    return row;
  }

  if (startsWithAscii(bytes, 'PQPK') || lowerName.endsWith('.pqpk')) {
    try {
      const parsed = unpackPqpk(bytes);
      markAccepted(row, {
        classifiedAs: 'PQ signer key',
        target: parsed.suiteDisplay || parsed.suite,
        role: 'Signer pin material',
        kind: 'pqpk',
        nextAction: 'Use with matching detached PQ signatures when policy requires trusted signer evidence.',
      });
      addDetail(row, 'Signature suite', parsed.suiteDisplay || parsed.suite);
      addDetail(row, 'Public key SHA-256', toHex(await digestSha256(parsed.keyBytes)));
    } catch (error) {
      row.kind = 'pqpk';
      row.classifiedAs = 'PQ signer key';
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace malformed signer key. ${errorMessageText(error)}`;
    }
    return row;
  }

  if (startsWithAscii(bytes, 'PQSG') || lowerName.endsWith('.qsig')) {
    try {
      const parsed = unpackQsig(bytes);
      markAccepted(row, {
        classifiedAs: inferSignatureClass(workflow, channel),
        target: `Payload digest ${shortDigestLabel(toHex(parsed.payloadDigest), { edgeLength: 8 })}`,
        role: inferSignatureRole(workflow, channel),
        kind: 'signature',
        nextAction: 'Evaluation will verify target bytes and signer trust before using this signature.',
      });
      row.status = 'pending';
      row.tone = 'warn';
      addDetail(row, 'Payload digest', toHex(parsed.payloadDigest));
      addDetail(row, 'Signature suite', parsed.suiteDisplay || parsed.suite);
      addDetail(row, 'Context', parsed.ctx);
    } catch (error) {
      row.kind = 'signature';
      row.classifiedAs = inferSignatureClass(workflow, channel);
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace malformed detached PQ signature. ${errorMessageText(error)}`;
    }
    return row;
  }

  if (lowerName.endsWith('.ots')) {
    try {
      const parsed = parseOpenTimestampProof(bytes, { name });
      markAccepted(row, {
        classifiedAs: 'OTS proof',
        target: `Stamped SHA-256 ${shortDigestLabel(parsed.stampedDigestHex, { edgeLength: 8 })}`,
        role: 'Timestamp only',
        kind: 'ots-proof',
        nextAction: 'Evaluation will link this proof to a loaded detached signature.',
      });
      row.status = 'pending';
      row.tone = 'warn';
      addDetail(row, 'Stamped SHA-256', parsed.stampedDigestHex);
      addDetail(row, 'Proof completeness', parsed.appearsComplete ? 'complete-looking' : 'pending/incomplete');
    } catch (error) {
      row.kind = 'ots-proof';
      row.classifiedAs = 'OTS proof';
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace malformed timestamp proof. ${errorMessageText(error)}`;
    }
    return row;
  }

  if (isSupportedStellarSignatureDocumentBytes(bytes)) {
    markAccepted(row, {
      classifiedAs: inferSignatureClass(workflow, channel),
      target: 'Stellar detached signature document',
      role: inferSignatureRole(workflow, channel),
      kind: 'signature',
      nextAction: 'Evaluation will verify target bytes and signer trust before using this signature.',
    });
    row.status = 'pending';
    row.tone = 'warn';
    return row;
  }

  try {
    const parsed = await parseLifecycleBundleBytes(bytes);
    markAccepted(row, {
      classifiedAs: 'lifecycle bundle',
      target: `Bundle ${shortDigestLabel(parsed.digest.value, { edgeLength: 8 })}`,
      role: workflow === 'attach' ? 'Evidence merge target' : 'Disambiguation input',
      kind: 'lifecycle-bundle',
    });
    addDetail(row, 'Lifecycle-bundle digest', parsed.digest.value);
    addDetail(row, 'Archive-state digest', parsed.lifecycleBundle?.archiveStateDigest?.value);
    addDetail(row, 'Current cohort-binding digest', parsed.lifecycleBundle?.currentCohortBindingDigest?.value);
    return row;
  } catch (error) {
    if (lowerName.endsWith('.lifecycle-bundle.json')) {
      row.kind = 'lifecycle-bundle';
      row.classifiedAs = 'lifecycle bundle';
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace malformed lifecycle bundle. ${errorMessageText(error)}`;
      return row;
    }
  }

  try {
    const parsed = parseArchiveStateDescriptorBytes(bytes);
    markAccepted(row, {
      classifiedAs: 'archive-state descriptor',
      target: `State ${shortDigestLabel(parsed.digest.value, { edgeLength: 8 })}`,
      role: workflow === 'attach' ? 'Archive approval target' : 'Disambiguation input',
      kind: 'archive-state',
    });
    addDetail(row, 'Archive id', parsed.archiveState?.archiveId);
    addDetail(row, 'State digest', parsed.digest.value);
    addDetail(row, 'Archive policy', parsed.archiveState?.authPolicyCommitment?.level);
    return row;
  } catch (error) {
    if (lowerName.endsWith('.archive-state.json')) {
      row.kind = 'archive-state';
      row.classifiedAs = 'archive-state descriptor';
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace malformed archive-state descriptor. ${errorMessageText(error)}`;
      return row;
    }
  }

  try {
    const parsed = parseTransitionRecordBytes(bytes);
    markAccepted(row, {
      classifiedAs: 'transition-record JSON',
      target: `Transition ${shortDigestLabel(parsed.digest.value, { edgeLength: 8 })}`,
      role: 'Separate evidence only',
      kind: 'transition-record',
    });
    addDetail(row, 'Transition-record digest', parsed.digest.value);
    addDetail(row, 'From cohort', parsed.transitionRecord?.fromCohortId);
    addDetail(row, 'To cohort', parsed.transitionRecord?.toCohortId);
    return row;
  } catch (error) {
    if (lowerName.endsWith('.transition-record.json')) {
      row.kind = 'transition-record';
      row.classifiedAs = 'transition-record JSON';
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace malformed transition record. ${errorMessageText(error)}`;
      return row;
    }
  }

  try {
    const parsed = parseSourceEvidenceBytes(bytes);
    markAccepted(row, {
      classifiedAs: 'source-evidence JSON',
      target: `Source evidence ${shortDigestLabel(parsed.digest.value, { edgeLength: 8 })}`,
      role: 'Separate evidence only',
      kind: 'source-evidence',
    });
    addDetail(row, 'Source-evidence digest', parsed.digest.value);
    addDetail(row, 'Relation type', parsed.sourceEvidence?.relationType);
    return row;
  } catch (error) {
    if (lowerName.endsWith('.source-evidence.json')) {
      row.kind = 'source-evidence';
      row.classifiedAs = 'source-evidence JSON';
      row.status = 'malformed';
      row.tone = 'fail';
      row.nextAction = `Replace malformed source-evidence JSON. ${errorMessageText(error)}`;
      return row;
    }
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

function isGroupableArtifactRow(row) {
  return row.status === 'accepted' && row.tone === 'ok';
}

function artifactGroupKey(row) {
  return `${row.kind}::${row.classifiedAs}`;
}

/**
 * Collapse consecutive accepted+ok rows that share kind and classified label into one segment.
 * Failed, pending, duplicate, conflict, ignored, and other non-accepted rows stay individual.
 *
 * @param {ReturnType<typeof createBaseRow>[]} rows
 * @returns {({ type: 'single', row: typeof rows[0] } | { type: 'group', rows: typeof rows })[]}
 */
export function groupArtifactRows(rows) {
  const segments = [];
  let i = 0;
  while (i < rows.length) {
    const row = rows[i];
    if (!isGroupableArtifactRow(row)) {
      segments.push({ type: 'single', row });
      i += 1;
      continue;
    }
    const key = artifactGroupKey(row);
    const chunk = [row];
    i += 1;
    while (i < rows.length && isGroupableArtifactRow(rows[i]) && artifactGroupKey(rows[i]) === key) {
      chunk.push(rows[i]);
      i += 1;
    }
    if (chunk.length >= 2) {
      segments.push({ type: 'group', rows: chunk });
    } else {
      segments.push({ type: 'single', row: chunk[0] });
    }
  }
  return segments;
}

function pluralizeClassifiedLabel(classifiedAs) {
  const map = {
    'QVqcont-7 shard': 'QVqcont-7 shards',
    'archive-state descriptor': 'archive-state descriptors',
    'lifecycle bundle': 'lifecycle bundles',
    'PQ signer key': 'PQ signer keys',
    'transition-record JSON': 'transition-record JSON documents',
    'source-evidence JSON': 'source-evidence JSON documents',
    'archive-approval signature': 'archive-approval signatures',
    'maintenance signature': 'maintenance signatures',
    'source-evidence signature': 'source-evidence signatures',
  };
  return map[classifiedAs] || `${classifiedAs}s`;
}

function mergeUniqueField(memberRows, field) {
  const values = [...new Set(memberRows.map((r) => r[field]).filter((v) => v != null && String(v).trim()))];
  if (values.length === 0) return 'Not available';
  if (values.length === 1) return String(values[0]);
  return `${values.length} variants (see details)`;
}

function mergeNextActionForGroup(memberRows) {
  const texts = [...new Set(memberRows.map((r) => r.nextAction))];
  if (texts.length === 1) {
    const t = texts[0];
    if (t === DEFAULT_ACCEPTED_NEXT_ACTION) return GROUP_ACCEPTED_NEXT_ACTION;
    return t;
  }
  return GROUP_ACCEPTED_NEXT_ACTION;
}

function buildDetailDl(row) {
  return createDigestDetailList(row.details, {
    listClassName: 'artifact-detail-list',
    termKey: 'label',
    valueKey: 'value',
    valueWrapperClassName: 'artifact-detail-value',
    copyButtonClassName: 'button secondary small artifact-copy-button',
    copySuccessMessage: 'Copied artifact detail.',
    copyFailureMessage: 'Copy failed. Select the expanded value manually.',
  });
}

function countDetailEntries(memberRows) {
  return memberRows.reduce((n, r) => n + (Array.isArray(r.details) ? r.details.length : 0), 0);
}

function appendTextCell(tr, className, text, label = '') {
  const td = document.createElement('td');
  td.className = className;
  if (label) td.setAttribute('data-label', label);
  td.textContent = text || 'Not available';
  tr.appendChild(td);
  return td;
}

function statusLabel(row) {
  return row.status.charAt(0).toUpperCase() + row.status.slice(1);
}

function artifactRowDisclosureDefaultOpen(row) {
  if (row.tone === 'fail') return true;
  const s = String(row.status || '').toLowerCase();
  return (
    s === 'unsupported' ||
    s === 'wrong target' ||
    s === 'conflict' ||
    s === 'duplicate'
  );
}

function createDetails(row) {
  if (!row.details.length) return null;
  const list = buildDetailDl(row);
  const badgeTone = row.tone === 'fail' ? 'fail' : row.tone === 'warn' ? 'warn' : 'ok';
  return createDisclosurePanel({
    summary: 'Details/copy',
    badgeText: String(row.details.length),
    badgeTone,
    defaultOpen: artifactRowDisclosureDefaultOpen(row),
    className: 'artifact-row-details',
    body: list,
  });
}

function createGroupDetails(memberRows) {
  const totalDetails = countDetailEntries(memberRows);
  if (totalDetails === 0) return null;
  const body = document.createElement('div');
  body.className = 'artifact-group-detail-body';
  const intro = document.createElement('p');
  intro.className = 'muted-copy artifact-group-detail-intro';
  intro.textContent = 'Per-file identifiers and digests:';
  body.appendChild(intro);
  for (const member of memberRows) {
    if (!member.details?.length) continue;
    const block = document.createElement('div');
    block.className = 'artifact-group-member';
    const fileHead = document.createElement('p');
    fileHead.className = 'artifact-group-member-file';
    fileHead.textContent = member.file || 'Unnamed file';
    block.appendChild(fileHead);
    block.appendChild(buildDetailDl(member));
    body.appendChild(block);
  }
  const anyProblem = memberRows.some(artifactRowDisclosureDefaultOpen);
  const badgeTone = memberRows.some((r) => r.tone === 'fail')
    ? 'fail'
    : memberRows.some((r) => r.tone === 'warn')
      ? 'warn'
      : 'ok';
  return createDisclosurePanel({
    summary: 'Details/copy',
    badgeText: String(totalDetails),
    badgeTone,
    defaultOpen: anyProblem,
    className: 'artifact-row-details artifact-group-details',
    body,
  });
}

function renderArtifactTableRows(tbody, segments) {
  for (const segment of segments) {
    if (segment.type === 'single') {
      renderSingleArtifactRow(tbody, segment.row);
      continue;
    }
    renderGroupedArtifactRow(tbody, segment.rows);
  }
}

function renderSingleArtifactRow(tbody, row) {
  const tr = document.createElement('tr');
  tr.className = `artifact-row ${row.tone}`;
  tr.setAttribute('data-artifact-status', row.status);
  tr.setAttribute('data-artifact-kind', row.kind);

  appendTextCell(tr, 'artifact-file-cell', row.file, 'File');
  appendTextCell(tr, 'artifact-class-cell', row.classifiedAs, 'Classified as');
  appendTextCell(tr, 'artifact-target-cell', row.target, 'Target');
  appendTextCell(tr, 'artifact-role-cell', row.role, 'Role');

  const statusCell = document.createElement('td');
  statusCell.setAttribute('data-label', 'Status');
  const badge = document.createElement('span');
  badge.className = `artifact-status-badge ${row.tone}`;
  badge.textContent = statusLabel(row);
  statusCell.appendChild(badge);
  tr.appendChild(statusCell);

  appendTextCell(tr, 'artifact-action-cell', row.nextAction, 'Next action');
  tbody.appendChild(tr);

  const details = createDetails(row);
  if (details) {
    const detailsTr = document.createElement('tr');
    detailsTr.className = `artifact-detail-row ${row.tone}`;
    const detailsTd = document.createElement('td');
    detailsTd.className = 'artifact-detail-cell';
    detailsTd.colSpan = 6;
    detailsTd.setAttribute('data-label', 'Details');
    detailsTd.appendChild(details);
    detailsTr.appendChild(detailsTd);
    tbody.appendChild(detailsTr);
  }
}

function renderGroupedArtifactRow(tbody, memberRows) {
  const n = memberRows.length;
  const template = memberRows[0];
  const classifiedPlural = pluralizeClassifiedLabel(template.classifiedAs);
  const tr = document.createElement('tr');
  tr.className = `artifact-row ${template.tone} artifact-row-group`;
  tr.setAttribute('data-artifact-group', 'true');
  tr.setAttribute('data-artifact-status', template.status);
  tr.setAttribute('data-artifact-kind', template.kind);
  tr.setAttribute('data-artifact-count', String(n));
  tr.title = `${n} ${classifiedPlural} accepted`;

  appendTextCell(tr, 'artifact-file-cell', `${n} files`, 'File');
  appendTextCell(tr, 'artifact-class-cell', classifiedPlural, 'Classified as');
  appendTextCell(tr, 'artifact-target-cell', mergeUniqueField(memberRows, 'target'), 'Target');
  appendTextCell(tr, 'artifact-role-cell', mergeUniqueField(memberRows, 'role'), 'Role');

  const statusCell = document.createElement('td');
  statusCell.setAttribute('data-label', 'Status');
  const badge = document.createElement('span');
  badge.className = `artifact-status-badge ${template.tone}`;
  badge.textContent = statusLabel(template);
  statusCell.appendChild(badge);
  tr.appendChild(statusCell);

  appendTextCell(tr, 'artifact-action-cell', mergeNextActionForGroup(memberRows), 'Next action');
  tbody.appendChild(tr);

  const details = createGroupDetails(memberRows);
  if (details) {
    const detailsTr = document.createElement('tr');
    detailsTr.className = `artifact-detail-row ${template.tone}`;
    const detailsTd = document.createElement('td');
    detailsTd.className = 'artifact-detail-cell';
    detailsTd.colSpan = 6;
    detailsTd.setAttribute('data-label', 'Details');
    detailsTd.appendChild(details);
    detailsTr.appendChild(detailsTd);
    tbody.appendChild(detailsTr);
  }
}

function renderRows(host, rows, label) {
  host.replaceChildren();
  host.classList.add('artifact-list', 'artifact-intake-panel', 'artifact-table');
  host.classList.remove('initially-hidden');
  host.style.display = 'block';
  host.setAttribute('aria-live', 'polite');

  const heading = document.createElement('h4');
  heading.textContent = label || DEFAULT_TABLE_LABEL;
  host.appendChild(heading);

  const wrapper = document.createElement('div');
  wrapper.className = 'artifact-intake-scroll';
  const table = document.createElement('table');
  table.className = 'artifact-intake-table';
  table.setAttribute('data-testid', `${host.dataset.testid || host.id}-table`);

  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  ['File', 'Classified as', 'Target', 'Role', 'Status', 'Next action'].forEach((title) => {
    const th = document.createElement('th');
    th.scope = 'col';
    th.textContent = title;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  renderArtifactTableRows(tbody, groupArtifactRows(rows));
  table.appendChild(tbody);
  wrapper.appendChild(table);
  host.appendChild(wrapper);
}

export function clearArtifactIntakeTable(containerId) {
  const host = document.getElementById(containerId);
  if (!host) return;
  host.replaceChildren();
  host.classList.add('initially-hidden');
  host.style.display = 'none';
}

export async function renderArtifactIntakeTable({
  containerId,
  files = [],
  workflow = 'restore',
  channel = 'archive-approval',
  label = DEFAULT_TABLE_LABEL,
  error = null,
} = {}) {
  const host = document.getElementById(containerId);
  if (!host) return [];

  const fileList = Array.from(files || []);
  if (fileList.length === 0) {
    clearArtifactIntakeTable(containerId);
    return [];
  }

  host.classList.remove('initially-hidden');
  host.style.display = 'block';
  host.replaceChildren();
  const loading = document.createElement('p');
  loading.className = 'muted-copy';
  loading.textContent = 'Classifying selected artifacts...';
  host.appendChild(loading);

  const rows = [];
  for (const file of fileList) {
    rows.push(await classifyArtifactFile(file, { workflow, channel }));
  }
  applyDuplicateStatus(rows);
  applyProblemOverrides(rows, error);
  renderRows(host, rows, label);
  return rows;
}
