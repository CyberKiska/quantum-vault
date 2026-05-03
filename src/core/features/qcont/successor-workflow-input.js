/**
 * Shared wiring for successor shard file inputs: status line, intake table, and
 * selection/preflight (see refreshRestoreInputPanel). Used by Pro Restore, Lite
 * Restore, and Pro Reshare. Reshare keeps preflightContainerId null so no
 * restore policy / preflight card runs.
 */

import { refreshRestoreInputPanel } from './restore-input-panel.js';

export function createSuccessorShardInputRefreshController(options) {
  let seq = 0;

  return {
    async refresh() {
      const input = document.getElementById(options.inputId);
      const statusDiv = document.getElementById(options.statusDivId);
      const statusText = document.getElementById(options.statusTextId);
      const actionButton = document.getElementById(options.actionButtonId);
      if (!input || !statusDiv || !statusText || !actionButton) {
        return { assessment: null };
      }

      const files = [...(input.files || [])];
      const requestId = ++seq;
      const expectedSignerInput = options.expectedSignerInputId
        ? document.getElementById(options.expectedSignerInputId)
        : null;

      const { assessment } = await refreshRestoreInputPanel({
        prefix: options.prefix,
        files,
        statusDiv,
        statusText,
        actionButton,
        intakeContainerId: options.intakeContainerId,
        intakeLabel: options.intakeLabel,
        intakeWorkflow: options.intakeWorkflow,
        preflightContainerId: options.preflightContainerId ?? null,
        expectedSignerInput,
        onSelectionChange: options.onSelectionChange,
        isCurrent: () => requestId === seq,
      });

      if (requestId !== seq) {
        return { assessment: null };
      }

      if (options.onAfterRefresh) {
        await options.onAfterRefresh(files, assessment);
      }

      return { assessment: assessment || null };
    },
  };
}
