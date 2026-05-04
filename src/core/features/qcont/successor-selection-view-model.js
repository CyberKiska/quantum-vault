/**
 * Pure view helpers for successor selection UI (UX Commit 33).
 * No DOM and no cryptographic policy decisions.
 */

/**
 * @typedef {'none'|'blocked'|'single'|'ambiguous'} SuccessorSelectionUiMode
 */

/**
 * @param {boolean} hasSuccessorShards
 * @param {boolean} selectionRequired
 * @returns {SuccessorSelectionUiMode}
 */
export function buildSuccessorSelectionUiMode(hasSuccessorShards, selectionRequired) {
  if (!hasSuccessorShards) return 'none';
  if (selectionRequired) return 'ambiguous';
  return 'single';
}

/**
 * @param {{ hasSuccessorShards?: boolean, selectionRequired?: boolean }} [candidates]
 * @returns {{ mode: SuccessorSelectionUiMode }}
 */
export function buildSuccessorSelectionViewModel(candidates = {}) {
  const hasSuccessorShards = Boolean(candidates.hasSuccessorShards);
  const selectionRequired = Boolean(candidates.selectionRequired);
  return { mode: buildSuccessorSelectionUiMode(hasSuccessorShards, selectionRequired) };
}

/**
 * One-line lifecycle-path summary for the restore preflight decision card when the
 * successor panel is collapsed (single unambiguous path).
 *
 * @param {object|null} successorSelection - state from successorSelectionState
 * @param {object|null} classified - classifyRestoreInputFiles result
 * @returns {{ label: string, value: string, tone: string }|null}
 */
export function buildLifecyclePathDecisionRow(successorSelection, classified) {
  if (!classified?.shardFiles?.length) return null;
  if (!successorSelection || successorSelection.mode !== 'successor') return null;
  if (successorSelection.selectionRequired) return null;
  if (successorSelection.selectionComplete === false) return null;

  if (classified.lifecycleBundleBytes instanceof Uint8Array) {
    return {
      label: 'Lifecycle path',
      value: 'Locked by uploaded lifecycle bundle; no manual path choice.',
      tone: 'ok',
    };
  }
  if (classified.archiveStateBytes instanceof Uint8Array) {
    return {
      label: 'Lifecycle path',
      value: 'Archive/state fixed by supplied descriptor; remaining path resolved automatically.',
      tone: 'ok',
    };
  }
  return {
    label: 'Lifecycle path',
    value: 'Selected automatically, no ambiguity',
    tone: 'ok',
  };
}
