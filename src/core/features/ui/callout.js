/**
 * Shared callout shells (warning / blocking / info). Copy stays with callers; this module only builds DOM.
 */

function resolveHost(host) {
  if (!host) return null;
  return typeof host === 'string' ? document.getElementById(host) : host;
}

function renderCalloutVariant(host, variant, { title, body } = {}) {
  const root = resolveHost(host);
  if (!root) return;
  root.replaceChildren();
  const base = 'qv-callout';
  const tone = `${base}--${variant}`;
  root.className = [base, tone, 'operation-warning'].join(' ');
  if (title) {
    const h = document.createElement('h4');
    h.className = 'qv-callout__title';
    h.textContent = title;
    root.appendChild(h);
  }
  const p = document.createElement('p');
  p.className = 'qv-callout__body';
  p.textContent = body || '';
  root.appendChild(p);
}

/** Non-blocking caution (amber styling). */
export function renderWarningCallout(host, { title, body } = {}) {
  renderCalloutVariant(host, 'warning', { title, body });
}

/** Hard guard / fail-closed emphasis (red styling). */
export function renderBlockingCallout(host, { title, body } = {}) {
  renderCalloutVariant(host, 'blocking', { title, body });
}

/** Neutral guidance (blue / muted informational styling). */
export function renderInfoCallout(host, { title, body } = {}) {
  renderCalloutVariant(host, 'info', { title, body });
}

/** Positive / ready state (green styling). */
export function renderSuccessCallout(host, { title, body } = {}) {
  renderCalloutVariant(host, 'success', { title, body });
}
