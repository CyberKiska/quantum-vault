/**
 * Shared RS/SSS parameter summary, constraint indicators, and bar visualization
 * for Split and Reshare (and any other surface using the same n/k rules).
 */

function setConstraintState(element, isValid) {
  if (!element) return;
  element.classList.remove('ok', 'fail');
  element.classList.add(isValid ? 'ok' : 'fail');
}

export function evaluateRsParams(nValue, kValue) {
  const n = parseInt(nValue, 10);
  const k = parseInt(kValue, 10);
  const hasN = Number.isInteger(n);
  const hasK = Number.isInteger(k);
  const validN = hasN && n >= 5;
  const validRange = hasN && hasK && k >= 2 && k < n;
  const validEven = hasN && hasK && ((n - k) % 2 === 0);
  const valid = validN && validRange && validEven;
  const m = (hasN && hasK) ? (n - k) : 0;
  const t = valid ? (k + (m / 2)) : 0;
  const reasons = [];

  if (!hasN || !hasK) {
    reasons.push('enter numeric values for n and k');
  } else {
    if (!validN) reasons.push('n must be at least 5');
    if (!validRange) reasons.push('require 2 <= k < n');
    if (!validEven) reasons.push('(n - k) must be even');
  }

  return {
    n,
    k,
    hasN,
    hasK,
    validN,
    validRange,
    validEven,
    valid,
    m,
    t,
    reasons,
  };
}

/**
 * @param {object} config
 * @param {HTMLInputElement|null} config.nInput
 * @param {HTMLInputElement|null} config.kInput
 * @param {HTMLElement|null} [config.summaryEl]
 * @param {HTMLElement|null} [config.ruleN]
 * @param {HTMLElement|null} [config.ruleRange]
 * @param {HTMLElement|null} [config.ruleEven]
 * @param {HTMLElement|null} [config.segData]
 * @param {HTMLElement|null} [config.segParity]
 * @param {HTMLElement|null} [config.marker]
 * @param {HTMLElement|null} [config.dataLabel]
 * @param {HTMLElement|null} [config.parityLabel]
 * @param {HTMLElement|null} [config.markerLabel]
 * @param {HTMLElement|null} [config.ticks]
 * @param {(valid: boolean) => void} [config.onValidityChange] - e.g. Reshare: refresh button state
 */
export function bindRsParamsUI(config) {
  const {
    nInput,
    kInput,
    summaryEl,
    ruleN,
    ruleRange,
    ruleEven,
    segData,
    segParity,
    marker,
    dataLabel,
    parityLabel,
    markerLabel,
    ticks,
    onValidityChange,
  } = config;

  function update() {
    if (!nInput || !kInput) return;
    const state = evaluateRsParams(nInput.value, kInput.value);
    const {
      n,
      k,
      hasN,
      hasK,
      validN,
      validRange,
      validEven,
      valid: allValid,
      m,
      t,
      reasons,
    } = state;

    setConstraintState(ruleN, validN);
    setConstraintState(ruleRange, validRange);
    setConstraintState(ruleEven, validEven);

    onValidityChange?.(allValid);

    if (summaryEl) {
      if (allValid) {
        summaryEl.textContent = `Total: n=${n}. Data: k=${k}. Parity: m=${m}. Threshold: t=${t}. Need >= t shards to restore.`;
        summaryEl.classList.remove('warning', 'error');
      } else {
        summaryEl.textContent = `Invalid configuration: ${reasons.join('; ')}.`;
        summaryEl.classList.add('warning');
      }
    }

    const safeN = hasN && n > 0 ? n : 1;
    const vizK = hasK ? Math.max(0, Math.min(k, safeN)) : 0;
    const vizM = Math.max(0, safeN - vizK);
    const pctData = (vizK / safeN) * 100;
    const pctParity = (vizM / safeN) * 100;
    const pctT = allValid ? (t / n) * 100 : 0;
    if (segData) segData.style.width = `${Math.max(0, Math.min(100, pctData))}%`;
    if (segParity) segParity.style.width = `${Math.max(0, Math.min(100, pctParity))}%`;
    if (marker) marker.style.left = `${Math.max(0, Math.min(100, pctT))}%`;
    if (dataLabel) dataLabel.textContent = hasK ? `k=${k}` : 'k=?';
    if (parityLabel) parityLabel.textContent = (hasN && hasK) ? `m=${m}` : 'm=?';
    if (markerLabel) {
      markerLabel.textContent = allValid ? `t=${t}` : 't=?';
      markerLabel.style.left = `${Math.max(0, Math.min(100, pctT))}%`;
    }
    if (ticks) {
      ticks.innerHTML = '';
      if (hasN && n > 0 && n <= 64) {
        for (let i = 0; i <= n; i += 1) {
          const tick = document.createElement('span');
          tick.className = 'tick';
          tick.style.left = `${(i / n) * 100}%`;
          tick.title = String(i);
          ticks.appendChild(tick);
        }
      }
    }
    const bar = segData && segData.parentElement ? segData.parentElement : null;
    if (bar && bar.classList) bar.classList.toggle('rs-error', !allValid);
  }

  nInput?.addEventListener('input', update);
  kInput?.addEventListener('input', update);
  update();

  return { update };
}
