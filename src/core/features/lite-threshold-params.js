import {
  calculateShamirThreshold,
  validateRsParams,
} from '../crypto/splitting/rs-params.js';

export const LITE_MIN_SHARDS = 5;
export const LITE_MAX_SHARDS = 25;
export const LITE_MIN_THRESHOLD_PERCENT = 50;
export const LITE_MAX_THRESHOLD_PERCENT = 90;

// Compute the supported RS/Shamir geometry at or above the requested threshold.
export function calculateParametersFromThreshold(n, thresholdPercent) {
  if (!Number.isInteger(n) || n < LITE_MIN_SHARDS || n > LITE_MAX_SHARDS) {
    return { error: `Total shards must be an integer from ${LITE_MIN_SHARDS} to ${LITE_MAX_SHARDS}` };
  }
  if (
    !Number.isInteger(thresholdPercent)
    || thresholdPercent < LITE_MIN_THRESHOLD_PERCENT
    || thresholdPercent > LITE_MAX_THRESHOLD_PERCENT
  ) {
    return {
      error: `Threshold percent must be an integer from ${LITE_MIN_THRESHOLD_PERCENT} to ${LITE_MAX_THRESHOLD_PERCENT}`,
    };
  }

  const targetT = Math.ceil((thresholdPercent / 100) * n);
  let bestAtOrAbove = null;
  for (let k = 2; k < n; k += 1) {
    if (!validateRsParams(n, k)) continue;
    const m = n - k;
    const t = calculateShamirThreshold(n, k);
    if (!Number.isInteger(t)) continue;
    const actualThresholdPercent = Math.round((t / n) * 100);
    const candidate = { n, k, m, t, actualThresholdPercent };
    if (t >= targetT && (!bestAtOrAbove || t < bestAtOrAbove.t)) {
      bestAtOrAbove = candidate;
    }
  }

  if (!bestAtOrAbove) {
    return { error: 'No supported configuration meets or exceeds the requested threshold' };
  }
  return { ...bestAtOrAbove };
}

export function getAchievableThresholdsForN(n) {
  const thresholdsByPercent = new Map();
  for (let k = 2; k < n; k += 1) {
    if (!validateRsParams(n, k)) continue;
    const m = n - k;
    const t = calculateShamirThreshold(n, k);
    if (!Number.isInteger(t)) continue;
    const actualThresholdPercent = Math.round((t / n) * 100);
    thresholdsByPercent.set(actualThresholdPercent, { n, k, m, t, actualThresholdPercent });
  }
  return [...thresholdsByPercent.values()]
    .sort((left, right) => left.actualThresholdPercent - right.actualThresholdPercent);
}

export function getAlternativeNRecommendations(requestedPercent, currentN, limit = 2) {
  const candidates = [];
  for (let n = LITE_MIN_SHARDS; n <= LITE_MAX_SHARDS; n += 1) {
    if (n === currentN) continue;
    const params = calculateParametersFromThreshold(n, requestedPercent);
    if (params.error) continue;
    candidates.push({
      n,
      actualThresholdPercent: params.actualThresholdPercent,
      diff: Math.abs(params.actualThresholdPercent - requestedPercent),
    });
  }
  candidates.sort((left, right) => left.diff - right.diff || left.n - right.n);
  return candidates.slice(0, limit);
}
