/**
 * Shared <details> disclosure shell: consistent summary, optional badge, body slot, aria-expanded sync.
 * Feature modules supply copy and body nodes; this module does not encode cryptographic rules.
 */

function syncSummaryExpanded(detailsEl) {
  const summary = detailsEl.querySelector(':scope > summary');
  if (!summary) return;
  summary.setAttribute('aria-expanded', detailsEl.open ? 'true' : 'false');
}

/**
 * Wire aria-expanded on the first summary (native details already supports keyboard toggle).
 * @param {HTMLDetailsElement} detailsEl
 */
export function wireDisclosureAria(detailsEl) {
  if (!(detailsEl instanceof HTMLDetailsElement) || detailsEl.dataset.qvDisclosureAria === '1') return;
  detailsEl.dataset.qvDisclosureAria = '1';
  syncSummaryExpanded(detailsEl);
  detailsEl.addEventListener('toggle', () => syncSummaryExpanded(detailsEl));
}

/**
 * @param {{
 *   title?: string,
 *   summary: string,
 *   badgeText?: string,
 *   badgeTone?: 'neutral'|'ok'|'warn'|'fail',
 *   defaultOpen?: boolean,
 *   body: HTMLElement,
 *   className?: string,
 *   testId?: string,
 * }} options
 * @returns {HTMLDetailsElement}
 */
export function createDisclosurePanel(options) {
  const details = document.createElement('details');
  const classes = ['qv-disclosure', options.className || ''].filter(Boolean);
  details.className = classes.join(' ');
  if (options.testId) {
    details.setAttribute('data-testid', options.testId);
  }
  if (options.defaultOpen) {
    details.open = true;
  }

  const summary = document.createElement('summary');
  summary.className = 'qv-disclosure__summary';

  if (options.title) {
    const titleEl = document.createElement('strong');
    titleEl.className = 'qv-disclosure__title';
    titleEl.textContent = options.title;
    summary.appendChild(titleEl);
    summary.appendChild(document.createTextNode(' '));
  }

  const label = document.createElement('span');
  label.className = 'qv-disclosure__summary-text';
  label.textContent = options.summary;
  summary.appendChild(label);

  if (options.badgeText) {
    const badge = document.createElement('span');
    const tone = options.badgeTone || 'neutral';
    badge.className = `qv-disclosure__badge qv-disclosure__badge--${tone}`;
    badge.textContent = options.badgeText;
    summary.appendChild(badge);
  }

  const bodyWrap = document.createElement('div');
  bodyWrap.className = 'qv-disclosure__body';
  bodyWrap.appendChild(options.body);

  details.append(summary, bodyWrap);
  wireDisclosureAria(details);
  return details;
}

const DISCLOSURE_INIT_SELECTOR = [
  'details.technical-details',
  'details.verification-section',
  'details.tip',
  'details.artifact-row-details',
  'details.evidence-matrix-details',
].join(', ');

/**
 * Upgrade static <details> in the document (or subtree) with shared classes and aria-expanded sync.
 * Skips elements already processed by createDisclosurePanel (dataset.qvDisclosureAria).
 */
export function initDisclosureShells(root = document) {
  for (const details of root.querySelectorAll(DISCLOSURE_INIT_SELECTOR)) {
    if (!(details instanceof HTMLDetailsElement)) continue;
    if (details.dataset.qvDisclosureAria === '1') continue;
    details.classList.add('qv-disclosure');
    const summary = details.querySelector(':scope > summary');
    if (summary) summary.classList.add('qv-disclosure__summary');
    wireDisclosureAria(details);
  }
}
