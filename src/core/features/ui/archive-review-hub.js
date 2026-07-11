/**
 * Single "Archive review" disclosure wrapping artifact intake, lifecycle/inspector,
 * evidence notes, and technical context (Commit 31).
 */

import { wireDisclosureAria } from './disclosure.js';

const HUB_ROOT_IDS = {
  restore: 'restoreArchiveReviewRoot',
  liteRestore: 'liteRestoreArchiveReviewRoot',
  attach: 'attachArchiveReviewRoot',
  reshare: 'reshareArchiveReviewRoot',
  review: 'reviewArchiveReviewRoot',
};

const INTAKE_IDS = {
  restore: 'restoreArtifactIntake',
  liteRestore: 'liteRestoreArtifactIntake',
  attach: 'attachArtifactIntake',
  reshare: 'reshareArtifactIntake',
  review: 'reviewArtifactIntake',
};

export function hubPrefixUsesSuccessorSelection(prefix) {
  return prefix === 'restore' || prefix === 'liteRestore' || prefix === 'reshare';
}

function intakeShowsAttentionSignals(intakeId) {
  const el = document.getElementById(intakeId);
  if (!el) return false;
  return Boolean(el.querySelector(
    [
      '.artifact-row.fail',
      '[data-artifact-status="unsupported"]',
      '[data-artifact-status="malformed"]',
      '[data-artifact-status="wrong target"]',
      '[data-artifact-status="duplicate"]',
    ].join(',')
  ));
}

function attachHubNeedsOpen() {
  const panel = document.getElementById('attachPartialRewriteAckPanel');
  if (panel && !panel.classList.contains('initially-hidden')) return true;
  return intakeShowsAttentionSignals(INTAKE_IDS.attach);
}

function successorSelectionNeedsOpen(selection) {
  if (!selection) return false;
  if (selection.selectionRequired === true) return true;
  if (selection.successorSelectionUiMode === 'ambiguous') return true;
  if (selection.model?.hasAmbiguity === true && selection.successorSelectionUiMode !== 'single') return true;
  return false;
}

/**
 * Opens the outer hub disclosure when attention is required. Background refreshes
 * preserve an already-open disclosure so they cannot undo an operator action.
 * Explicit empty-input resets may request collapse with `collapseWhenClear`.
 *
 * @param {'restore'|'liteRestore'|'attach'|'reshare'|'review'} prefix
 * @param {object|null} [successorSelection] - from restore successorSelectionState (restore / lite / reshare)
 * @param {{ collapseWhenClear?: boolean }} [options]
 */
export function syncArchiveReviewHub(prefix, successorSelection = null, options = {}) {
  const rootId = HUB_ROOT_IDS[prefix];
  if (!rootId) return;
  const root = document.getElementById(rootId);
  if (!(root instanceof HTMLDetailsElement)) return;

  let open = false;
  if (prefix === 'attach') {
    open = attachHubNeedsOpen();
  } else if (hubPrefixUsesSuccessorSelection(prefix)) {
    const intakeId = INTAKE_IDS[prefix];
    open = intakeShowsAttentionSignals(intakeId) || successorSelectionNeedsOpen(successorSelection);
  } else {
    open = intakeShowsAttentionSignals(INTAKE_IDS.review);
  }

  if (open) {
    root.open = true;
  } else if (options.collapseWhenClear === true) {
    root.open = false;
  }
  wireDisclosureAria(root);
}

/** Ensure hub outer disclosures have aria-expanded sync (idempotent). */
export function initArchiveReviewHubRoots() {
  for (const rootId of Object.values(HUB_ROOT_IDS)) {
    const root = document.getElementById(rootId);
    if (root instanceof HTMLDetailsElement) {
      wireDisclosureAria(root);
    }
  }
}
