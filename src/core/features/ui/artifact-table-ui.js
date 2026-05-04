/**
 * DOM rendering for classified artifact intake rows. No classification logic.
 */

import { createDisclosurePanel } from './disclosure.js';
import { createDigestDetailList } from './digest-details.js';
import { DEFAULT_ACCEPTED_NEXT_ACTION, GROUP_ACCEPTED_NEXT_ACTION } from './artifact-classifier.js';

export const DEFAULT_ARTIFACT_INTAKE_TABLE_LABEL = 'Selected artifact intake';

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
 * @param {unknown[]} rows
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
    className: 'artifact-row-details',
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

/**
 * @param {HTMLElement} host
 * @param {unknown[]} rows - classified rows
 * @param {string} [label]
 */
export function renderArtifactIntakePanel(host, rows, label = DEFAULT_ARTIFACT_INTAKE_TABLE_LABEL) {
  host.replaceChildren();
  host.classList.add('artifact-intake-panel');
  host.classList.remove('initially-hidden');
  host.style.display = 'block';
  host.setAttribute('role', 'region');
  host.setAttribute('aria-label', label || DEFAULT_ARTIFACT_INTAKE_TABLE_LABEL);

  const heading = document.createElement('h4');
  heading.textContent = label || DEFAULT_ARTIFACT_INTAKE_TABLE_LABEL;
  host.appendChild(heading);

  const liveSummary = document.createElement('p');
  liveSummary.className = 'visually-hidden';
  liveSummary.setAttribute('aria-live', 'polite');
  liveSummary.textContent = `${rows.length} artifact${rows.length === 1 ? '' : 's'} classified.`;
  host.appendChild(liveSummary);

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
