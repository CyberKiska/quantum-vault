import { showToast } from '../ui/toast.js';
import { hashBlobForSourceDigestAlg } from './source-evidence-file-digest.js';

const SOURCE_DIGEST_ALGORITHMS = Object.freeze(['SHA3-512', 'SHA3-256', 'SHA-256']);
const SOURCE_DIGEST_HEX_LENGTH = Object.freeze({
  'SHA3-512': 128,
  'SHA3-256': 64,
  'SHA-256': 64,
});
const SOURCE_EVIDENCE_DIGEST_DEFAULT = Object.freeze({
  alg: 'SHA3-512',
  value: '',
});

function expectedSourceDigestHexLength(alg) {
  return SOURCE_DIGEST_HEX_LENGTH[alg] ?? null;
}

function normalizeSourceDigestValue(alg, rawValue, rowIndex) {
  const expectedLen = expectedSourceDigestHexLength(alg);
  const label = `Digest row ${rowIndex + 1}`;
  if (expectedLen == null) {
    return { ok: false, normalized: '', error: `${label}: unsupported digest algorithm.` };
  }
  const trimmed = String(rawValue || '').trim().toLowerCase();
  if (!trimmed) {
    return {
      ok: false,
      normalized: '',
      error: `${label}: enter a ${expectedLen}-character lowercase hex digest for ${alg}.`,
    };
  }
  if (!/^[0-9a-f]+$/.test(trimmed)) {
    return {
      ok: false,
      normalized: trimmed,
      error: `${label}: digest must contain only hexadecimal characters (0-9, a-f).`,
    };
  }
  if (trimmed.length !== expectedLen) {
    return {
      ok: false,
      normalized: trimmed,
      error: `${label}: ${alg} requires exactly ${expectedLen} hex characters (got ${trimmed.length}).`,
    };
  }
  return { ok: true, normalized: trimmed, error: null };
}

function readSourceEvidenceDigestRowsFromDom() {
  const rows = [...document.querySelectorAll('#sourceEvidenceDigestRows .source-evidence-digest-row')];
  return rows.map((row, index) => {
    const alg = String(row.querySelector('.source-evidence-digest-alg')?.value || '').trim();
    const rawValue = String(row.querySelector('.source-evidence-digest-value')?.value || '');
    const hintEl = row.querySelector('.source-evidence-digest-hint');
    return { row, index, alg, rawValue, hintEl };
  });
}

function findDuplicateDigestAlgorithmsFromRows(rowStates) {
  const seen = new Set();
  for (let i = 0; i < rowStates.length; i++) {
    const alg = rowStates[i].alg;
    if (!expectedSourceDigestHexLength(alg)) continue;
    if (seen.has(alg)) {
      return `Digest row ${i + 1}: duplicate algorithm ${alg}. Each digest row must use a distinct algorithm.`;
    }
    seen.add(alg);
  }
  return null;
}

export function clearSourceEvidenceExportError() {
  const el = document.getElementById('sourceEvidenceExportError');
  if (!el) return;
  el.textContent = '';
  el.classList.add('initially-hidden');
}

export function showSourceEvidenceExportError(message) {
  const el = document.getElementById('sourceEvidenceExportError');
  if (!el) return;
  el.textContent = String(message || '');
  el.classList.remove('initially-hidden');
}

export function refreshSourceEvidenceBuilderUi(channel) {
  const exportBtn = document.getElementById('exportSourceEvidenceBtn');
  const previewEl = document.getElementById('sourceEvidenceExportPreview');
  const exportErrEl = document.getElementById('sourceEvidenceExportError');

  const resetRowHints = () => {
    for (const hint of document.querySelectorAll('.source-evidence-digest-hint')) {
      hint.textContent = '';
      hint.classList.remove('source-evidence-digest-hint--error');
    }
  };

  if (channel !== 'source-evidence') {
    if (exportBtn) exportBtn.disabled = true;
    if (previewEl) {
      previewEl.textContent = '';
      previewEl.classList.add('initially-hidden');
    }
    if (exportErrEl) {
      exportErrEl.textContent = '';
      exportErrEl.classList.add('initially-hidden');
    }
    resetRowHints();
    return;
  }

  if (previewEl) previewEl.classList.remove('initially-hidden');

  const relationType = String(document.getElementById('sourceEvidenceRelationType')?.value || '').trim();
  const sourceObjectType = String(document.getElementById('sourceEvidenceObjectType')?.value || '').trim();
  const externalRefsText = String(document.getElementById('sourceEvidenceExternalRefs')?.value || '').trim();
  const mediaTypeOptIn = document.getElementById('sourceEvidenceMediaTypeOptIn')?.checked === true;
  const mediaType = String(document.getElementById('sourceEvidenceMediaType')?.value || '').trim();

  const rowStates = readSourceEvidenceDigestRowsFromDom();
  const dupErr = findDuplicateDigestAlgorithmsFromRows(rowStates);
  const normalizedResults = rowStates.map((rs) => normalizeSourceDigestValue(rs.alg, rs.rawValue, rs.index));

  const algCounts = {};
  for (const rs of rowStates) {
    algCounts[rs.alg] = (algCounts[rs.alg] || 0) + 1;
  }

  for (let i = 0; i < rowStates.length; i++) {
    const { alg, hintEl } = rowStates[i];
    const res = normalizedResults[i];
    if (!hintEl) continue;
    hintEl.classList.remove('source-evidence-digest-hint--error');
    const expectedLen = expectedSourceDigestHexLength(alg);
    const dupRow = expectedLen != null && (algCounts[alg] || 0) > 1;
    if (dupRow) {
      hintEl.textContent = 'Duplicate algorithm - keep one row per algorithm.';
      hintEl.classList.add('source-evidence-digest-hint--error');
      continue;
    }
    if (!res.ok) {
      hintEl.textContent = String(res.error || '').replace(/^Digest row \d+: /, '');
      hintEl.classList.add('source-evidence-digest-hint--error');
    } else {
      hintEl.textContent = `${res.normalized.length} hex characters (matches ${alg})`;
    }
  }

  const digestOk = !dupErr && normalizedResults.every((r) => r.ok);
  const formOk = Boolean(relationType && sourceObjectType && rowStates.length > 0 && digestOk);
  if (exportBtn) exportBtn.disabled = !formOk;

  const refsList = externalRefsText
    ? externalRefsText
        .split(/\r?\n|,/)
        .map((value) => value.trim())
        .filter(Boolean)
    : [];

  const lines = [
    'Export preview',
    `Relation type: ${relationType || '(required)'}`,
    `Source object type: ${sourceObjectType || '(required)'}`,
    `Digests (${rowStates.length}):`,
  ];
  for (let i = 0; i < rowStates.length; i++) {
    const rs = rowStates[i];
    const res = normalizedResults[i];
    const expectedLen = expectedSourceDigestHexLength(rs.alg);
    const dupRow = expectedLen != null && (algCounts[rs.alg] || 0) > 1;
    let status;
    if (dupRow) status = 'duplicate algorithm';
    else if (!res.ok) status = 'invalid';
    else status = `${res.normalized.length} hex`;
    lines.push(`  - ${rs.alg}: ${status}`);
  }
  lines.push(`Digest algorithms listed: ${rowStates.map((r) => r.alg).join(', ') || '-'}`);
  lines.push(`External source-signature refs: ${refsList.length ? refsList.join(', ') : 'none'}`);
  lines.push(
    `Optional descriptive fields: ${
      mediaTypeOptIn ? `media type opted-in${mediaType ? ` (${mediaType})` : ' (empty)'}` : 'none'
    }`
  );
  lines.push('');
  lines.push(
    'Policy: Source evidence is provenance-only. It never satisfies archive restore policy by itself - attach archive-approval signatures separately when policy requires them.'
  );
  if (!formOk) {
    lines.push('');
    lines.push('Fix the issues above before export.');
  }

  if (previewEl) previewEl.textContent = lines.join('\n');

  if (exportErrEl && formOk) {
    exportErrEl.textContent = '';
    exportErrEl.classList.add('initially-hidden');
  }
}

export function createSourceEvidenceDigestRow({
  initial = SOURCE_EVIDENCE_DIGEST_DEFAULT,
  onChange = () => {},
} = {}) {
  const row = document.createElement('div');
  row.className = 'split-grid source-evidence-digest-row';

  const algGroup = document.createElement('div');
  algGroup.className = 'form-group';
  const algLabel = document.createElement('label');
  algLabel.textContent = 'Digest algorithm';
  const algSelect = document.createElement('select');
  algSelect.className = 'source-evidence-digest-alg';
  for (const alg of SOURCE_DIGEST_ALGORITHMS) {
    const option = document.createElement('option');
    option.value = alg;
    option.textContent = alg;
    if (alg === initial.alg) option.selected = true;
    algSelect.appendChild(option);
  }
  algGroup.appendChild(algLabel);
  algGroup.appendChild(algSelect);

  const valueGroup = document.createElement('div');
  valueGroup.className = 'form-group';
  const valueLabel = document.createElement('label');
  valueLabel.textContent = 'Hex digest';
  const valueInput = document.createElement('input');
  valueInput.type = 'text';
  valueInput.className = 'source-evidence-digest-value';
  valueInput.placeholder = 'Lowercase hex digest';
  valueInput.value = initial.value || '';
  valueGroup.appendChild(valueLabel);
  valueGroup.appendChild(valueInput);
  const digestHint = document.createElement('small');
  digestHint.className = 'muted-copy source-evidence-digest-hint';
  digestHint.setAttribute('aria-live', 'polite');
  valueGroup.appendChild(digestHint);

  const removeGroup = document.createElement('div');
  removeGroup.className = 'form-group';
  const removeLabel = document.createElement('label');
  removeLabel.textContent = 'Row';
  const removeButton = document.createElement('button');
  removeButton.type = 'button';
  removeButton.className = 'button secondary small';
  removeButton.textContent = 'Remove';
  removeButton.addEventListener('click', () => {
    const rows = [...document.querySelectorAll('#sourceEvidenceDigestRows .source-evidence-digest-row')];
    if (rows.length <= 1) {
      showToast('Keep at least one source digest row.', 'warning');
      return;
    }
    row.remove();
    onChange();
  });
  removeGroup.appendChild(removeLabel);
  removeGroup.appendChild(removeButton);

  row.appendChild(algGroup);
  row.appendChild(valueGroup);
  row.appendChild(removeGroup);
  return row;
}

export function ensureSourceEvidenceDigestRows({ onChange = () => {} } = {}) {
  const container = document.getElementById('sourceEvidenceDigestRows');
  if (!container) return;
  if (container.children.length === 0) {
    container.appendChild(createSourceEvidenceDigestRow({ onChange }));
  }
  onChange();
}

// Hash one file with each row’s selected algorithm and write hex into every digest value field.

export async function applySourceEvidenceFileToAllDigestRows(file, { onRefresh } = {}) {
  const rows = [...document.querySelectorAll('#sourceEvidenceDigestRows .source-evidence-digest-row')];
  if (rows.length === 0) {
    showToast('Add at least one source digest row first.', 'warning');
    return;
  }

  const rowStatesForDup = rows.map((row, index) => ({
    row,
    index,
    alg: String(row.querySelector('.source-evidence-digest-alg')?.value || '').trim(),
    rawValue: '',
    hintEl: null,
  }));
  const dupErr = findDuplicateDigestAlgorithmsFromRows(rowStatesForDup);
  if (dupErr) {
    showToast('Use a different algorithm on each row before applying one file.', 'warning');
    return;
  }

  const digestCache = new Map();
  try {
    for (const row of rows) {
      const alg = String(row.querySelector('.source-evidence-digest-alg')?.value || '').trim();
      const valueInput = row.querySelector('.source-evidence-digest-value');
      if (!valueInput || expectedSourceDigestHexLength(alg) == null) {
        throw new Error(`Unsupported digest algorithm: ${alg || '(empty)'}`);
      }
      if (!digestCache.has(alg)) {
        digestCache.set(alg, hashBlobForSourceDigestAlg(file, alg));
      }
      valueInput.value = await digestCache.get(alg);
    }
    const sizeLabel = file.size.toLocaleString();
    showToast(
      `Source evidence: filled ${rows.length} digest row(s) from one file (${sizeLabel} bytes).`,
      'success',
      4200
    );
    onRefresh?.();
  } catch (err) {
    showToast(String(err?.message || err), 'error');
  }
}

let sourceEvidenceApplyFileUiInitialized = false;

export function initSourceEvidenceApplyFileToAllRows(onRefresh) {
  if (sourceEvidenceApplyFileUiInitialized) return;
  const btn = document.getElementById('sourceEvidenceApplyFileToDigestsBtn');
  const input = document.getElementById('sourceEvidenceApplyFileInput');
  if (!btn || !input) return;
  sourceEvidenceApplyFileUiInitialized = true;

  btn.addEventListener('click', () => {
    input.value = '';
    input.click();
  });

  input.addEventListener('change', async () => {
    const picked = input.files?.[0];
    input.value = '';
    if (!picked) return;
    btn.disabled = true;
    try {
      await applySourceEvidenceFileToAllDigestRows(picked, { onRefresh });
    } finally {
      btn.disabled = false;
    }
  });
}

export function collectSourceEvidenceBuilderParams() {
  const relationType = String(document.getElementById('sourceEvidenceRelationType')?.value || '').trim();
  const sourceObjectType = String(document.getElementById('sourceEvidenceObjectType')?.value || '').trim();
  if (!relationType) {
    throw new Error('Source-evidence relationType is required.');
  }
  if (!sourceObjectType) {
    throw new Error('Source-evidence sourceObjectType is required.');
  }

  const rowStates = readSourceEvidenceDigestRowsFromDom();
  if (rowStates.length === 0) {
    throw new Error('Provide at least one source digest.');
  }

  const dupErr = findDuplicateDigestAlgorithmsFromRows(rowStates);
  if (dupErr) {
    throw new Error(dupErr);
  }

  const sourceDigests = [];
  for (const { alg, rawValue, index } of rowStates) {
    const res = normalizeSourceDigestValue(alg, rawValue, index);
    if (!res.ok) {
      throw new Error(res.error);
    }
    sourceDigests.push({ alg, value: res.normalized });
  }

  const params = {
    relationType,
    sourceObjectType,
    sourceDigests,
  };

  const externalRefsText = String(document.getElementById('sourceEvidenceExternalRefs')?.value || '').trim();
  if (externalRefsText) {
    const externalSourceSignatureRefs = externalRefsText
      .split(/\r?\n|,/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (externalSourceSignatureRefs.length > 0) {
      params.externalSourceSignatureRefs = externalSourceSignatureRefs;
    }
  }

  const mediaTypeOptIn = document.getElementById('sourceEvidenceMediaTypeOptIn')?.checked === true;
  const mediaType = String(document.getElementById('sourceEvidenceMediaType')?.value || '').trim();
  if (mediaTypeOptIn) {
    params.descriptiveFieldOptIn = ['mediaType'];
    if (mediaType) {
      params.mediaType = mediaType;
    }
  }

  return params;
}

export function updateSourceEvidenceOptInUi(channel) {
  const optInChecked = document.getElementById('sourceEvidenceMediaTypeOptIn')?.checked === true;
  const group = document.getElementById('sourceEvidenceMediaTypeGroup');
  if (group) {
    group.classList.toggle('initially-hidden', !optInChecked);
  }
  refreshSourceEvidenceBuilderUi(channel);
}
