/**
 * Shared "shard input panel refresh" helper used by every restore-shaped surface
 * (Lite Restore, Pro Restore, Reshare). Prefer wiring through
 * `successor-workflow-input.js` (`createSuccessorShardInputRefreshController`) so
 * status DOM ids, re-entrancy guards, and preflight options stay DRY.
 *
 * It runs the same async sequence:
 *   1. updateShardSelectionStatus  (assess threshold readiness)
 *   2. renderArtifactIntakeTable   (artifact-classifier + artifact-table-ui)
 *   3. refreshSelectionAndPreflight (archive/state/cohort/bundle disambiguation)
 *   4. optional renderRestorePreflightForFiles (only when preflightContainerId is set)
 *
 * Each step honours the shared `isCurrent()` re-entrancy guard so stale async
 * work does not clobber the latest selection.
 */

import { updateShardSelectionStatus } from '../ui/shards-status.js';
import { clearArtifactIntakeTable, renderArtifactIntakeTable } from '../ui/artifact-intake.js';
import { renderRestorePreflightForFiles } from './restore-ui.js';
import { refreshSelectionAndPreflight } from './successor-selection-ui.js';

/**
 * @typedef {Object} RestoreInputPanelOptions
 * @property {string} prefix - "restore" | "liteRestore" | "reshare"
 * @property {File[]} files
 * @property {HTMLElement|null} statusDiv
 * @property {HTMLElement|null} statusText
 * @property {HTMLButtonElement|null} actionButton
 * @property {string} intakeContainerId - id of the artifact-intake host
 * @property {string} intakeLabel - heading for the intake table
 * @property {('restore'|'lite-restore'|'reshare'|'attach')} intakeWorkflow
 * @property {string|null} [preflightContainerId] - id of preflight decision card; null skips it
 * @property {HTMLInputElement|null} [expectedSignerInput]
 * @property {(event: { prefix: string, selection: object }) => void} [onSelectionChange]
 * @property {() => boolean} [isCurrent] - re-entrancy guard; defaults to always true
 */

/**
 * @param {RestoreInputPanelOptions} options
 * @returns {Promise<{ assessment: object|null }>}
 */
export async function refreshRestoreInputPanel(options) {
  const {
    prefix,
    files,
    statusDiv,
    statusText,
    actionButton,
    intakeContainerId,
    intakeLabel,
    intakeWorkflow,
    preflightContainerId = null,
    expectedSignerInput = null,
    isCurrent = () => true,
  } = options;

  const list = Array.isArray(files) ? files : Array.from(files || []);
  if (list.length === 0) {
    clearArtifactIntakeTable(intakeContainerId);
  }

  const assessment = await updateShardSelectionStatus({
    files: list,
    statusDiv,
    statusText,
    actionButton,
    isCurrent,
  });
  if (!isCurrent()) return { assessment: null };

  await renderArtifactIntakeTable({
    containerId: intakeContainerId,
    files: list,
    workflow: intakeWorkflow,
    label: intakeLabel,
    isCurrent,
  });
  if (!isCurrent()) return { assessment: assessment || null };

  await refreshSelectionAndPreflight({
    prefix,
    files: list,
    actionButton,
    assessment: assessment || { ready: false },
    preflightContainerId,
    expectedSignerInput,
    renderPreflightForFiles: renderRestorePreflightForFiles,
    onSelectionChange: options.onSelectionChange,
    isCurrent,
  });
  if (!isCurrent()) return { assessment: assessment || null };
  return { assessment: assessment || null };
}
