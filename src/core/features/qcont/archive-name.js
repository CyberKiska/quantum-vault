/**
 * Shared archive-name helpers for export filenames.
 * Used by Attach, Reshare, and any surface that derives output names from a
 * mixed input set of `.qcont` shards and lifecycle-related JSON artifacts.
 *
 * Pure UI-utility code: no cryptographic semantics, no DOM access.
 */

const ARTIFACT_VARIANT_SUFFIXES = [
  /\.archive-state\.json$/i,
  /\.cohort-binding\.json$/i,
  /\.transition-record\.json$/i,
  /\.lifecycle-bundle\.json$/i,
  /\.source-evidence\.json$/i,
];

const SHARD_PART_SUFFIX = /\.part\d+-of-\d+\.qcont$/i;
const EXPLICIT_NAME_LIKE = /\.(archive-state\.json|lifecycle-bundle\.json|cohort-binding\.json)$/i;

/** Strip any recognized lifecycle-artifact suffix from a filename. */
export function stripArchiveVariantSuffix(name) {
  let result = String(name || 'archive');
  for (const suffix of ARTIFACT_VARIANT_SUFFIXES) {
    result = result.replace(suffix, '');
  }
  return result;
}

/**
 * Derive a canonical archive base name from a heterogenous input file set.
 * Prefers an explicit archive-state/lifecycle-bundle/cohort-binding filename
 * (those tend to be hand-named); falls back to the first `.qcont` shard with
 * its `.partN-of-M.qcont` suffix removed.
 *
 * @param {Iterable<{ name?: string }>} sourceFiles
 * @param {string} [fallback]
 */
export function deriveArchiveBaseName(sourceFiles, fallback = 'archive') {
  const list = Array.isArray(sourceFiles) ? sourceFiles : Array.from(sourceFiles || []);
  const explicit = list.find((file) => EXPLICIT_NAME_LIKE.test(String(file?.name || '')));
  if (explicit) return stripArchiveVariantSuffix(explicit.name);
  const shard = list.find((file) => String(file?.name || '').toLowerCase().endsWith('.qcont'));
  if (!shard) return fallback;
  return stripArchiveVariantSuffix(String(shard.name).replace(SHARD_PART_SUFFIX, ''));
}
