function errorText(error) {
  if (error && typeof error.message === 'string') return error.message;
  if (typeof error === 'string') return error;
  return String(error || 'Unknown error');
}

function appendErrorField(list, label, value) {
  const term = document.createElement('dt');
  term.textContent = label;
  const detail = document.createElement('dd');
  detail.textContent = value || 'Unknown';
  list.append(term, detail);
}

export function summarizeFileList(files = [], fallback = 'Selected input set') {
  const names = files.map((file) => String(file?.name || '').trim()).filter(Boolean);
  if (names.length === 0) return fallback;
  if (names.length <= 3) return names.join(', ');
  return `${names.slice(0, 3).join(', ')} + ${names.length - 3} more file(s)`;
}

export function clearInlineError(panelId) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  panel.replaceChildren();
  panel.classList.add('initially-hidden');
  panel.style.display = 'none';
}

export function showInlineError(panelId, {
  title = 'Action blocked',
  cause,
  artifact = 'Selected input set',
  action = 'Review the selected inputs, correct the blocking condition, and retry.',
} = {}) {
  const panel = document.getElementById(panelId);
  if (!panel) return;

  panel.replaceChildren();
  panel.className = 'inline-error-panel';
  panel.style.display = 'block';
  panel.setAttribute('role', 'alert');
  panel.setAttribute('aria-live', 'assertive');

  const heading = document.createElement('h4');
  heading.textContent = title;
  const list = document.createElement('dl');
  list.className = 'inline-error-fields';
  appendErrorField(list, 'Cause', errorText(cause));
  appendErrorField(list, 'Affected artifact', artifact);
  appendErrorField(list, 'Next recovery action', action);
  panel.append(heading, list);
}
