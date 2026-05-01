/**
 * Shared next-action copy for restore failures.
 * Pro Restore, Lite Restore, and any other restore-shaped surface use this so
 * the recovery hint stays consistent across surfaces and tests.
 *
 * Pure UI-utility code: no DOM access, no cryptographic decisions.
 */

/**
 * @param {unknown} error
 * @param {{ verb?: string }} [options] - retry verb (e.g. "Restore", "Lite Restore")
 * @returns {string}
 */
export function buildRestoreRecoveryAction(error, options = {}) {
  const verb = options.verb || 'Restore';
  const message = String(error?.message || error || '').toLowerCase();
  if (message.includes('archive policy') || message.includes('archive-approval')) {
    return `Load or attach policy-satisfying archive-approval signatures and signer pins when required, then retry ${verb}.`;
  }
  if (
    message.includes('lifecycle bundle') ||
    message.includes('cohort') ||
    message.includes('selection')
  ) {
    return 'Choose the exact archive, cohort, or lifecycle bundle variant, or load the matching descriptor or bundle to disambiguate.';
  }
  if (
    message.includes('qcont') ||
    message.includes('shard') ||
    message.includes('threshold')
  ) {
    return `Load enough successor QVqcont-7 shards from one archive/state/cohort and remove incompatible files, then retry ${verb}.`;
  }
  return `Review the selected restore inputs, correct the blocking condition, and retry ${verb}.`;
}
