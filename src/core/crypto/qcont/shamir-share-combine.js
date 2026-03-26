/**
 * Shamir reconstruction using explicit share copies that are zeroized after use.
 * Keeps restore / resharing paths aligned and avoids passing live shard buffers into
 * the underlying SSS implementation.
 *
 * @param {Array<{ share: Uint8Array }>} sortedShares Sorted shard entries with `.share`
 * @param {number} t Threshold count (first t entries are used)
 * @returns {Promise<{ secret: Uint8Array, shareCopiesCleared: boolean }>}
 */
export async function combineSharesFromCopiedSlices(sortedShares, t) {
  const selectedShareCopies = sortedShares.slice(0, t).map((item) => item.share.slice());
  let secret = null;
  try {
    const { combineShares } = await import('../splitting/sss.js');
    secret = await combineShares(selectedShareCopies);
  } finally {
    for (const share of selectedShareCopies) {
      share.fill(0);
    }
  }
  const shareCopiesCleared = selectedShareCopies.every((share) => share.every((value) => value === 0));
  return { secret, shareCopiesCleared };
}
