/**
 * Shared "shard input panel refresh" helper used by every restore-shaped surface
 * (Lite Restore, Pro Restore, Reshare). It runs the same async sequence:
 *   1. updateShardSelectionStatus  (assess threshold readiness)
 *   2. renderArtifactIntakeTable   (per-file classification)
 *   3. refreshSuccessorSelectionUi (archive/state/cohort/bundle disambiguation)
 *   4. optional renderRestorePreflightForFiles (only restore-shaped tabs use it)
 *
 * Each step honours the shared `isCurrent()` re-entrancy guard so stale async
 * work does not clobber the latest selection.
 */

import { updateShardSelectionStatus } from '../ui/shards-status.js';
import { clearArtifactIntakeTable, renderArtifactIntakeTable } from '../ui/artifact-intake.js';
import { refreshSuccessorSelectionUi, renderRestorePreflightForFiles } from './restore-ui.js';

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
  });
  if (!isCurrent()) return { assessment: assessment || null };

  await refreshSuccessorSelectionUi(prefix, list, actionButton, assessment || { ready: false });
  if (!isCurrent()) return { assessment: assessment || null };

  if (preflightContainerId) {
    await renderRestorePreflightForFiles({
      prefix,
      containerId: preflightContainerId,
      files: list,
      expectedSignerInput,
    });
  }
  return { assessment: assessment || null };
}
