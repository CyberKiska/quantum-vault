/**
 * Shared decision-card shell: feature modules supply a view model; this module only builds DOM.
 * No cryptographic policy logic here.
 */

const TONE_PREFIX = 'qv-decision-card--';

function resolveHost(host) {
  if (!host) return null;
  return typeof host === 'string' ? document.getElementById(host) : host;
}

/**
 * @param {HTMLElement|string|null} host
 * @param {null|{
 *   title: string,
 *   tone?: string,
 *   primaryOutcome: string,
 *   lede?: string,
 *   rows?: { label: string, value: string, tone?: string }[],
 *   actions?: HTMLElement[],
 *   detailsId?: string,
 * }} model
 * @param {{
 *   extraRootClasses?: string[],
 *   dataAttrs?: Record<string, string>,
 *   ariaLive?: string,
 *   testIds?: { title?: string, primary?: string, lede?: string, rows?: string },
 *   rootDataTestId?: string,
 * }} [options]
 */
export function renderDecisionCard(host, model, options = {}) {
  const root = resolveHost(host);
  if (!root) return;

  const extra = options.extraRootClasses || [];
  const dataAttrs = options.dataAttrs || {};

  if (!model) {
    try { root.style.display = 'none'; } catch { /* Keep clearing independently. */ }
    try {
      root.className = ['qv-decision-card', 'initially-hidden', ...extra].filter(Boolean).join(' ');
    } catch { /* Keep clearing independently. */ }
    try { root.replaceChildren(); } catch { /* Hidden stale content is non-actionable. */ }
    try { root.removeAttribute('aria-live'); } catch { /* Keep clearing independently. */ }
    try { root.removeAttribute('data-release-state'); } catch { /* Keep clearing independently. */ }
    for (const [key, value] of Object.entries(dataAttrs)) {
      const attr = key.startsWith('data-') ? key : `data-${key}`;
      try { root.removeAttribute(attr); } catch { /* Keep clearing independently. */ }
    }
    if (options.rootDataTestId) {
      try { root.setAttribute('data-testid', options.rootDataTestId); } catch { /* Cosmetic only. */ }
    }
    return;
  }

  const tone = model.tone || 'neutral';
  root.replaceChildren();
  root.style.display = 'block';
  root.className = ['qv-decision-card', `${TONE_PREFIX}${tone}`, ...extra].filter(Boolean).join(' ');
  if (options.rootDataTestId) {
    root.setAttribute('data-testid', options.rootDataTestId);
  }
  if (options.ariaLive) {
    root.setAttribute('aria-live', options.ariaLive);
  } else {
    root.removeAttribute('aria-live');
  }
  for (const [key, value] of Object.entries(dataAttrs)) {
    const attr = key.startsWith('data-') ? key : `data-${key}`;
    if (value === undefined || value === null) root.removeAttribute(attr);
    else root.setAttribute(attr, String(value));
  }

  const testIds = options.testIds || {};

  const titleEl = document.createElement('h4');
  titleEl.className = 'qv-decision-card__title';
  titleEl.textContent = model.title || '';
  if (testIds.title) titleEl.setAttribute('data-testid', testIds.title);
  root.appendChild(titleEl);

  const primary = document.createElement('p');
  primary.className = 'qv-decision-card__primary';
  primary.textContent = model.primaryOutcome || '';
  if (testIds.primary) primary.setAttribute('data-testid', testIds.primary);
  if (model.detailsId) {
    primary.setAttribute('aria-details', model.detailsId);
  }
  root.appendChild(primary);

  if (model.lede) {
    const lede = document.createElement('p');
    lede.className = 'qv-decision-card__lede';
    lede.textContent = model.lede;
    if (testIds.lede) lede.setAttribute('data-testid', testIds.lede);
    root.appendChild(lede);
  }

  if (Array.isArray(model.rows) && model.rows.length > 0) {
    const rowsHost = document.createElement('div');
    rowsHost.className = 'qv-decision-card__rows';
    if (testIds.rows) rowsHost.setAttribute('data-testid', testIds.rows);
    for (const row of model.rows) {
      const rowEl = document.createElement('div');
      const rowTone = row.tone || 'neutral';
      rowEl.className = `qv-decision-card__row qv-decision-card__row--${rowTone}`;
      const label = document.createElement('span');
      label.className = 'qv-decision-card__label';
      label.textContent = row.label;
      const value = document.createElement('span');
      value.className = 'qv-decision-card__value';
      value.textContent = row.value;
      rowEl.append(label, value);
      rowsHost.appendChild(rowEl);
    }
    root.appendChild(rowsHost);
  }

  if (Array.isArray(model.actions) && model.actions.length > 0) {
    const bar = document.createElement('div');
    bar.className = 'qv-decision-card__actions';
    for (const node of model.actions) {
      if (node instanceof HTMLElement) bar.appendChild(node);
    }
    root.appendChild(bar);
  }
}
