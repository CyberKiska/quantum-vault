import assert from 'node:assert/strict';
import test from 'node:test';

import {
  LITE_MAX_SHARDS,
  LITE_MAX_THRESHOLD_PERCENT,
  LITE_MIN_SHARDS,
  LITE_MIN_THRESHOLD_PERCENT,
  calculateParametersFromThreshold,
  getAchievableThresholdsForN,
  getAlternativeNRecommendations,
} from '../../src/core/features/lite-threshold-params.js';
import {
  calculateShamirThreshold,
  validateRsParams,
} from '../../src/core/crypto/splitting/rs-params.js';

test('Lite threshold selection returns the smallest supported threshold at or above the request', () => {
  for (let n = LITE_MIN_SHARDS; n <= LITE_MAX_SHARDS; n += 1) {
    for (
      let requestedPercent = LITE_MIN_THRESHOLD_PERCENT;
      requestedPercent <= LITE_MAX_THRESHOLD_PERCENT;
      requestedPercent += 1
    ) {
      const result = calculateParametersFromThreshold(n, requestedPercent);
      const candidates = [];
      for (let k = 2; k < n; k += 1) {
        if (!validateRsParams(n, k)) continue;
        const t = calculateShamirThreshold(n, k);
        if (t >= Math.ceil((requestedPercent / 100) * n)) candidates.push({ k, t });
      }

      if (candidates.length === 0) {
        assert.equal(result.error, 'No supported configuration meets or exceeds the requested threshold');
        continue;
      }
      const expectedT = Math.min(...candidates.map((candidate) => candidate.t));
      assert.deepEqual(result, {
        n,
        k: candidates.find((candidate) => candidate.t === expectedT).k,
        m: n - candidates.find((candidate) => candidate.t === expectedT).k,
        t: expectedT,
        actualThresholdPercent: Math.round((expectedT / n) * 100),
      });
    }
  }
});

test('Lite threshold helpers preserve exact boundary and recommendation behavior', () => {
  assert.deepEqual(getAchievableThresholdsForN(5), [
    { n: 5, k: 3, m: 2, t: 4, actualThresholdPercent: 80 },
  ]);
  assert.deepEqual(getAchievableThresholdsForN(10), [
    { n: 10, k: 2, m: 8, t: 6, actualThresholdPercent: 60 },
    { n: 10, k: 4, m: 6, t: 7, actualThresholdPercent: 70 },
    { n: 10, k: 6, m: 4, t: 8, actualThresholdPercent: 80 },
    { n: 10, k: 8, m: 2, t: 9, actualThresholdPercent: 90 },
  ]);
  assert.deepEqual(getAlternativeNRecommendations(90, 5, 2), [
    { n: 10, actualThresholdPercent: 90, diff: 0 },
    { n: 20, actualThresholdPercent: 90, diff: 0 },
  ]);

  for (const [n, percent] of [
    [4, 50], [26, 50], [5.5, 50], [5, 49], [5, 91], [5, 50.5],
  ]) {
    assert.equal(typeof calculateParametersFromThreshold(n, percent).error, 'string');
  }
});
