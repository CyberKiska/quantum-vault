/**
 * Artifact intake: orchestrates classification (artifact-classifier.js) and table UI (artifact-table-ui.js).
 */

import { classifyArtifactIntakeRows } from './artifact-classifier.js';
import {
  DEFAULT_ARTIFACT_INTAKE_TABLE_LABEL,
  renderArtifactIntakePanel,
} from './artifact-table-ui.js';

export { classifyArtifactFile, classifyArtifactIntakeRows } from './artifact-classifier.js';
export { groupArtifactRows } from './artifact-table-ui.js';

const artifactIntakeEpochs = new Map();

function nextArtifactIntakeEpoch(containerId) {
  const epoch = (artifactIntakeEpochs.get(containerId) || 0) + 1;
  artifactIntakeEpochs.set(containerId, epoch);
  return epoch;
}

export function clearArtifactIntakeTable(containerId) {
  nextArtifactIntakeEpoch(containerId);
  const host = document.getElementById(containerId);
  if (!host) return;
  try { host.style.display = 'none'; } catch { /* Keep clearing independently. */ }
  try { host.classList.add('initially-hidden'); } catch { /* Keep clearing independently. */ }
  try { host.replaceChildren(); } catch { /* Hidden stale content is non-actionable. */ }
}

/**
 * @param {{
 *   containerId: string,
 *   files?: File[],
 *   workflow?: string,
 *   channel?: string,
 *   label?: string,
 *   error?: unknown,
 * }} [options]
 */
export async function renderArtifactIntakeTable({
  containerId,
  files = [],
  workflow = 'restore',
  channel = 'archive-approval',
  label = DEFAULT_ARTIFACT_INTAKE_TABLE_LABEL,
  error = null,
  isCurrent: externalIsCurrent = () => true,
} = {}) {
  const host = document.getElementById(containerId);
  if (!host) return [];
  const renderEpoch = nextArtifactIntakeEpoch(containerId);
  const isCurrent = () => artifactIntakeEpochs.get(containerId) === renderEpoch &&
    externalIsCurrent() && host.isConnected && document.getElementById(containerId) === host;

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

  const rows = await classifyArtifactIntakeRows(fileList, { workflow, channel, error });
  if (!isCurrent()) return [];
  renderArtifactIntakePanel(host, rows, label);
  return rows;
}
