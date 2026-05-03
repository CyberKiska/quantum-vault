import { shortenHash } from '../../../utils.js';
import { createDisclosurePanel } from './disclosure.js';
import { showToast } from './toast.js';

const MONO_DETAIL_TERM = /digest|archive id|cohort id|state/i;

export function shortDigestLabel(value, { edgeLength = 6, fallback = 'Not available' } = {}) {
  const text = String(value || '').trim();
  if (!text) return fallback;
  if (edgeLength === 6) return shortenHash(text);
  if (text.length <= edgeLength * 2 + 3) return text;
  return `${text.slice(0, edgeLength)}...${text.slice(-edgeLength)}`;
}

export function formatDigestDetailValue(value, fallback = 'None') {
  if (Array.isArray(value)) {
    const values = value.map((item) => String(item || '').trim()).filter(Boolean);
    return values.length > 0 ? values.join(', ') : fallback;
  }
  const text = String(value || '').trim();
  return text || fallback;
}

export function createDigestDetailEntry(term, value, options = {}) {
  return { term, value, ...options };
}

export function formatCohortParameters({ shardCount, n, t } = {}) {
  const loaded = Number(shardCount || 0);
  const total = Number(n || 0);
  const threshold = Number(t || 0);
  if (!loaded && !total && !threshold) return 'None';
  return `${loaded}/${total} shards loaded, threshold ${threshold}`;
}

async function copyTextToClipboard(text) {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall through to the textarea copy path for restricted browser contexts.
    }
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  textarea.style.top = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  textarea.remove();
  if (!copied) {
    throw new Error('Clipboard API unavailable');
  }
}

export function createDigestCopyButton({
  value,
  label = 'Copy',
  copiedLabel = 'Copied',
  className = 'button secondary small digest-copy-button',
  copyKind = 'digest',
  successMessage = 'Copied full digest.',
  failureMessage = 'Copy failed. Select the expanded digest manually.',
} = {}) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.setAttribute('data-copy-value', String(value || ''));
  if (copyKind) button.setAttribute('data-digest-kind', copyKind);
  button.addEventListener('click', async () => {
    const originalLabel = button.textContent;
    try {
      await copyTextToClipboard(String(value || ''));
      button.textContent = copiedLabel;
      showToast(successMessage, 'success');
      setTimeout(() => {
        button.textContent = originalLabel;
      }, 1600);
    } catch {
      showToast(failureMessage, 'warning');
    }
  });
  return button;
}

export function createDigestDetailList(entries = [], options = {}) {
  const {
    listClassName = 'digest-detail-list',
    termKey = 'term',
    valueKey = 'value',
    copyValueKey = 'copyValue',
    valueWrapperClassName = '',
    copyButtonClassName = 'button secondary small digest-copy-button',
    copyLabel = 'Copy',
    copySuccessMessage = 'Copied full digest.',
    copyFailureMessage = 'Copy failed. Select the expanded value manually.',
    monoTermPattern = MONO_DETAIL_TERM,
  } = options;

  const list = document.createElement('dl');
  list.className = listClassName;
  for (const entry of entries) {
    const termText = String(entry?.[termKey] || entry?.label || '').trim();
    const valueText = formatDigestDetailValue(entry?.[valueKey]);
    const dt = document.createElement('dt');
    dt.textContent = termText;
    const dd = document.createElement('dd');
    const valueTarget = valueWrapperClassName ? document.createElement('span') : dd;
    if (valueWrapperClassName) valueTarget.className = valueWrapperClassName;
    valueTarget.textContent = valueText;
    if (monoTermPattern && monoTermPattern.test(termText)) {
      valueTarget.classList.add('digest-detail-mono');
    }
    if (valueWrapperClassName) dd.appendChild(valueTarget);
    const copyValue = entry?.[copyValueKey];
    if (copyValue) {
      dd.appendChild(createDigestCopyButton({
        value: copyValue,
        label: entry.copyLabel || copyLabel,
        className: copyButtonClassName,
        copyKind: entry.copyKind || 'detail',
        successMessage: copySuccessMessage,
        failureMessage: copyFailureMessage,
      }));
    }
    list.append(dt, dd);
  }
  return list;
}

export function createDigestDetailRow({
  title,
  copyValue = '',
  copyLabel = 'Copy',
  copyKind = 'digest',
  entries = [],
} = {}) {
  const row = document.createElement('div');
  row.className = 'digest-detail-row';
  row.setAttribute('data-digest-kind', copyKind);

  const head = document.createElement('div');
  head.className = 'digest-detail-row-head';
  const titleEl = document.createElement('span');
  titleEl.className = 'digest-detail-title';
  titleEl.textContent = String(title || '');
  head.appendChild(titleEl);

  if (copyValue) {
    head.appendChild(createDigestCopyButton({
      value: copyValue,
      label: copyLabel,
      copyKind,
    }));
  }

  row.append(head, createDigestDetailList(entries));
  return row;
}

export function createDigestDetailSection(title, rows = []) {
  const section = document.createElement('div');
  section.className = 'digest-detail-section';
  const heading = document.createElement('h5');
  heading.textContent = title;
  section.appendChild(heading);
  for (const row of rows) {
    section.appendChild(createDigestDetailRow(row));
  }
  return section;
}

export function createDigestDetailsPanel({
  note = '',
  sections = [],
  summary = 'Digest details and copy',
  badgeText = '',
  badgeTone = 'neutral',
  defaultOpen = false,
  className = 'digest-details-panel technical-details',
} = {}) {
  const body = document.createElement('div');
  body.className = 'digest-details-body';
  if (note) {
    const noteEl = document.createElement('p');
    noteEl.className = 'muted-copy';
    noteEl.textContent = note;
    body.appendChild(noteEl);
  }
  for (const section of sections) {
    body.appendChild(createDigestDetailSection(section.title, section.rows || []));
  }
  return createDisclosurePanel({
    summary,
    badgeText,
    badgeTone,
    defaultOpen,
    className,
    body,
  });
}
