import { classifyRestoreInputFiles } from '../../../app/restore-inputs.js';
import { parseLifecycleShard } from '../../../app/crypto-service.js';
import { readFileAsUint8Array, shortenHash } from '../../../utils.js';
import { parseLifecycleBundleBytes } from '../../crypto/lifecycle/artifacts.js';
import { createDisclosurePanel } from '../ui/disclosure.js';

const INSPECTOR_POLICY_NOTE = 'Maintenance signatures and source-evidence objects are separate from archive approval. They do not satisfy archive restore policy on their own. Timestamp (.ots) evidence is timestamp-only and also does not satisfy archive policy.';

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

export function clearArchiveInspector(containerId) {
  const root = document.getElementById(containerId);
  if (!root) return;
  root.replaceChildren();
  root.className = 'archive-inspector-host initially-hidden';
  root.style.display = 'none';
}

function countAttachments(bundle) {
  const att = bundle?.attachments || {};
  return {
    archiveApproval: (att.archiveApprovalSignatures || []).length,
    maintenance: (att.maintenanceSignatures || []).length,
    sourceEvidenceSigs: (att.sourceEvidenceSignatures || []).length,
    timestamps: (att.timestamps || []).length,
    publicKeys: (att.publicKeys || []).length,
    sourceEvidenceObjects: (bundle?.sourceEvidence || []).length,
  };
}

function buildTimelineSteps(bundle) {
  const steps = [];
  if (!bundle?.archiveState) return steps;
  const stateDigest = bundle.archiveStateDigest?.value || '';
  steps.push({
    label: 'Archive state (this bundle)',
    detail: `Archive-state digest ${shortenHash(stateDigest)} · policy ${String(bundle.authPolicy?.level || 'unknown')}`,
  });
  const transitions = Array.isArray(bundle.transitions) ? bundle.transitions : [];
  for (let i = 0; i < transitions.length; i += 1) {
    const tr = transitions[i];
    const reason = String(tr?.reasonCode || 'transition').trim();
    const fromC = shortenHash(tr?.fromCohortId || '');
    const toC = shortenHash(tr?.toCohortId || '');
    steps.push({
      label: `Transition ${i + 1}: ${reason}`,
      detail: `Same-state maintenance · cohort ${fromC} → ${toC} · ${String(tr?.performedAt || '')}`,
    });
  }
  return steps;
}

function pickShardForBundle(parsedShards, cohortId, bundleDigestHex) {
  if (!Array.isArray(parsedShards) || parsedShards.length === 0) return null;
  let pool = parsedShards;
  if (cohortId) {
    const filtered = parsedShards.filter((s) => String(s?.cohortId || s?.metaJSON?.cohortId || '') === cohortId);
    if (filtered.length) pool = filtered;
  }
  if (bundleDigestHex) {
    const match = pool.find((s) => String(s?.lifecycleBundleDigestHex || '') === bundleDigestHex);
    if (match) return match;
  }
  return pool[0];
}

function collectForkWarnings(model, selection, selectedCohort) {
  const warnings = [];
  if (model?.hasAmbiguity) {
    warnings.push('Multiple archive states, same-state cohorts, or embedded lifecycle bundle variants are present. Quantum Vault will not auto-select a path; resolve ambiguity in the selectors before relying on a single timeline.');
  }
  if (selection?.selectionRequired && selection?.selectionComplete === false) {
    warnings.push('Selection is incomplete. The timeline and evidence counts may not match the cohort you will operate on after disambiguation.');
  }
  if (
    selectedCohort &&
    selectedCohort.bundleDigests?.length > 1 &&
    !selection?.selectedLifecycleBundleDigestHex
  ) {
    warnings.push('This cohort carries multiple embedded lifecycle bundle digests. Pick a bundle variant to align the inspector with one embedded branch.');
  }
  return warnings;
}

function findSelectedState(model, selection) {
  if (!model?.states?.length) return null;
  if (selection?.selectedStateKey) {
    return model.states.find((s) => s.key === selection.selectedStateKey) || null;
  }
  if (selection?.selectedArchiveId && selection?.selectedStateId) {
    return model.states.find((s) => (
      s.archiveId === selection.selectedArchiveId && s.stateId === selection.selectedStateId
    )) || null;
  }
  if (model.states.length === 1) return model.states[0];
  return null;
}

function findSelectedCohort(model, selection) {
  const state = findSelectedState(model, selection);
  if (!state || !selection?.selectedCohortId) return null;
  return state.cohorts.find((c) => c.cohortId === selection.selectedCohortId) || null;
}

async function buildBundleViewFromFiles(files) {
  const classified = await classifyRestoreInputFiles(files);
  if (classified.lifecycleBundleBytes instanceof Uint8Array) {
    try {
      const parsed = await parseLifecycleBundleBytes(classified.lifecycleBundleBytes);
      return { bundle: parsed.lifecycleBundle, bundleDigest: parsed.digest?.value || null, classified };
    } catch {
      return { bundle: null, bundleDigest: null, classified };
    }
  }
  if (!classified.shardFiles.length) {
    return { bundle: null, bundleDigest: null, classified };
  }
  const shardBytes = await readFileAsUint8Array(classified.shardFiles[0]);
  const shard = await parseLifecycleShard(shardBytes, { strict: true });
  return {
    bundle: shard.lifecycleBundle,
    bundleDigest: shard.lifecycleBundleDigestHex || null,
    classified,
  };
}

function renderInspectorDom(root, {
  title,
  archiveId,
  stateId,
  cohortLines,
  bundleDigest,
  bundleDigestList,
  n,
  t,
  shardLoaded,
  timelineSteps,
  evidence,
  warnings,
  bundleJson,
}) {
  root.replaceChildren();
  root.classList.remove('initially-hidden');
  root.style.display = 'block';
  root.className = 'archive-inspector decision-card';
  root.setAttribute('role', 'region');
  root.setAttribute('aria-label', 'Archive lifecycle inspector');

  const head = el('h4', 'archive-inspector-title', title);
  root.appendChild(head);

  const policy = el('p', 'muted-copy archive-inspector-policy-note', INSPECTOR_POLICY_NOTE);
  root.appendChild(policy);

  if (warnings.length) {
    const ul = el('ul', 'archive-inspector-warnings');
    for (const w of warnings) {
      ul.appendChild(el('li', null, w));
    }
    root.appendChild(ul);
  }

  const facts = el('dl', 'archive-inspector-facts');
  const addRow = (term, value) => {
    const dt = el('dt', null, term);
    const dd = el('dd', 'digest-detail-mono', value);
    facts.append(dt, dd);
  };
  addRow('Archive id', archiveId ? shortenHash(archiveId) : '—');
  addRow('Archive-state digest (state id)', stateId ? shortenHash(stateId) : '—');
  addRow('Lifecycle bundle digest (primary)', bundleDigest ? shortenHash(bundleDigest) : '—');
  if (bundleDigestList.length > 1) {
    addRow('All embedded bundle digests seen', bundleDigestList.map((d) => shortenHash(d)).join(', '));
  }
  addRow('Cohort geometry (n / threshold t)', n && t ? `${n} shards · threshold ${t}` : '—');
  addRow('QVqcont-7 shards loaded', String(shardLoaded));
  for (const line of cohortLines) {
    addRow('Cohort', line);
  }
  root.appendChild(facts);

  const tlTitle = el('h5', 'archive-inspector-subhead', 'Lifecycle timeline');
  root.appendChild(tlTitle);
  const ol = el('ol', 'archive-inspector-timeline');
  if (!timelineSteps.length) {
    ol.appendChild(el('li', 'muted-copy', 'No lifecycle bundle content available for this input set.'));
  } else {
    for (const step of timelineSteps) {
      const li = el('li', 'archive-inspector-timeline-step');
      li.appendChild(el('span', 'archive-inspector-timeline-label', step.label));
      li.appendChild(el('span', 'muted-copy archive-inspector-timeline-detail', step.detail));
      ol.appendChild(li);
    }
  }
  root.appendChild(ol);

  const evTitle = el('h5', 'archive-inspector-subhead', 'Evidence present in bundle (counts)');
  root.appendChild(evTitle);
  const ev = el('dl', 'archive-inspector-facts');
  const addEv = (term, value) => {
    const dt = el('dt', null, term);
    const dd = el('dd', null, String(value));
    ev.append(dt, dd);
  };
  addEv('Archive approval signatures', evidence.archiveApproval);
  addEv('Maintenance signatures', evidence.maintenance);
  addEv('Source-evidence objects', evidence.sourceEvidenceObjects);
  addEv('Source-evidence signatures', evidence.sourceEvidenceSigs);
  addEv('Signer public-key entries', evidence.publicKeys);
  addEv('Timestamp (.ots) proofs', evidence.timestamps);
  root.appendChild(ev);

  if (bundleJson) {
    const pre = el('pre', 'mono-box archive-inspector-json-pre');
    pre.textContent = bundleJson.length > 12000 ? `${bundleJson.slice(0, 12000)}\n… (truncated)` : bundleJson;
    const details = createDisclosurePanel({
      summary: 'Full lifecycle bundle JSON',
      defaultOpen: false,
      className: 'technical-details archive-inspector-json',
      body: pre,
    });
    root.appendChild(details);
  }
}

/**
 * Read-only archive / lifecycle inspector for Review, Restore, Reshare, Attach, and Lite Restore.
 *
 * @param {string} containerId
 * @param {{ files?: File[], successorSelection?: object|null, attachShards?: object[]|null }} options
 */
export async function renderArchiveInspectorPanel(containerId, options = {}) {
  const root = document.getElementById(containerId);
  if (!root) return;

  const { files = [], successorSelection = null, attachShards = null } = options;

  try {
    if (attachShards && attachShards.length > 0) {
      const shard = attachShards[0];
      const bundle = shard.lifecycleBundle;
      if (!bundle) {
        clearArchiveInspector(containerId);
        return;
      }
      const evidence = countAttachments(bundle);
      const timelineSteps = buildTimelineSteps(bundle);
      const cohortId = String(shard.cohortId || shard.metaJSON?.cohortId || '');
      const n = Number(shard.metaJSON?.n || 0);
      const t = Number(shard.metaJSON?.t || 0);
      const bundleDigest = shard.lifecycleBundleDigestHex || '';
      const json = JSON.stringify(bundle, null, 2);
      renderInspectorDom(root, {
        title: 'Archive inspector (read-only)',
        archiveId: String(shard.archiveState?.archiveId || shard.metaJSON?.archiveId || ''),
        stateId: String(shard.stateId || shard.metaJSON?.stateId || ''),
        cohortLines: [`${shortenHash(cohortId)} · ${attachShards.length} shard file(s) loaded for attach`],
        bundleDigest,
        bundleDigestList: bundleDigest ? [bundleDigest] : [],
        n,
        t,
        shardLoaded: attachShards.length,
        timelineSteps,
        evidence,
        warnings: attachShards.length < n ? ['Partial shard set: other cohort members may still embed a different lifecycle bundle digest until rewritten.'] : [],
        bundleJson: json,
      });
      return;
    }

    if (successorSelection?.model && Array.isArray(successorSelection.parsedSuccessorShards)) {
      const { model, parsedSuccessorShards, selectionRequired, selectionComplete } = successorSelection;
      const selectedState = findSelectedState(model, successorSelection);
      const selectedCohort = findSelectedCohort(model, successorSelection)
        || (selectedState?.cohorts?.length === 1 ? selectedState.cohorts[0] : null);
      const warnings = collectForkWarnings(model, successorSelection, selectedCohort);
      const bundleDigestHex = successorSelection.selectedLifecycleBundleDigestHex
        || (selectedCohort?.bundleDigests?.length === 1 ? selectedCohort.bundleDigests[0] : null);
      const shard = pickShardForBundle(
        parsedSuccessorShards,
        selectedCohort?.cohortId || null,
        bundleDigestHex
      );
      const bundle = shard?.lifecycleBundle || null;
      const evidence = bundle ? countAttachments(bundle) : {
        archiveApproval: 0,
        maintenance: 0,
        sourceEvidenceSigs: 0,
        timestamps: 0,
        publicKeys: 0,
        sourceEvidenceObjects: 0,
      };
      const timelineSteps = bundle ? buildTimelineSteps(bundle) : [];
      const cohortLines = [];
      if (selectedState?.cohorts?.length) {
        for (const c of selectedState.cohorts) {
          const marker = c.cohortId === selectedCohort?.cohortId ? ' (selected path)' : '';
          cohortLines.push(
            `${shortenHash(c.cohortId)} · ${c.shardCount}/${c.n} shards · threshold ${c.t}${marker}`
          );
        }
      } else if (model.states?.length > 1) {
        cohortLines.push(`${model.states.length} archive-state candidates — use the selection controls to pick one before treating a cohort row as authoritative.`);
      }
      const n = selectedCohort ? Number(selectedCohort.n || 0) : Number(shard?.metaJSON?.n || 0);
      const t = selectedCohort ? Number(selectedCohort.t || 0) : Number(shard?.metaJSON?.t || 0);
      const digestList = selectedCohort?.bundleDigests?.length
        ? selectedCohort.bundleDigests
        : (bundleDigestHex ? [bundleDigestHex] : []);
      const json = bundle ? JSON.stringify(bundle, null, 2) : '';
      renderInspectorDom(root, {
        title: 'Archive inspector (read-only)',
        archiveId: selectedState?.archiveId || String(shard?.archiveState?.archiveId || ''),
        stateId: selectedState?.stateId || String(shard?.stateId || bundle?.archiveStateDigest?.value || ''),
        cohortLines: cohortLines.length ? cohortLines : ['—'],
        bundleDigest: bundleDigestHex || shard?.lifecycleBundleDigestHex || '',
        bundleDigestList: digestList,
        n,
        t,
        shardLoaded: parsedSuccessorShards.length,
        timelineSteps,
        evidence,
        warnings,
        bundleJson: json,
      });
      if (selectionRequired && selectionComplete === false) {
        root.setAttribute('data-inspector-selection', 'incomplete');
      } else {
        root.setAttribute('data-inspector-selection', 'ready');
      }
      return;
    }

    if (files.length > 0) {
      const { bundle, bundleDigest, classified } = await buildBundleViewFromFiles(files);
      const warnings = [];
      if (!bundle && !classified.shardFiles.length) {
        clearArchiveInspector(containerId);
        return;
      }
      if (classified.shardFiles.length > 1) {
        warnings.push('Multiple shard files are loaded; inspector shows the first parseable successor shard only. Use Restore or Review with the full set for cohort-level ambiguity handling.');
      }
      if (!bundle) {
        renderInspectorDom(root, {
          title: 'Archive inspector (read-only)',
          archiveId: '—',
          stateId: '—',
          cohortLines: ['Load at least one successor .qcont shard to see cohort binding and threshold from shard headers.'],
          bundleDigest: bundleDigest || '',
          bundleDigestList: bundleDigest ? [bundleDigest] : [],
          n: 0,
          t: 0,
          shardLoaded: classified.shardFiles.length,
          timelineSteps: [],
          evidence: {
            archiveApproval: 0,
            maintenance: 0,
            sourceEvidenceSigs: 0,
            timestamps: 0,
            publicKeys: 0,
            sourceEvidenceObjects: 0,
          },
          warnings,
          bundleJson: '',
        });
        return;
      }
      const evidence = countAttachments(bundle);
      const timelineSteps = buildTimelineSteps(bundle);
      let shardLoaded = classified.shardFiles.length;
      let n = 0;
      let t = 0;
      let cohortLine = '—';
      if (classified.shardFiles.length) {
        const shardBytes = await readFileAsUint8Array(classified.shardFiles[0]);
        const shard = await parseLifecycleShard(shardBytes, { strict: true });
        n = Number(shard.metaJSON?.n || 0);
        t = Number(shard.metaJSON?.t || 0);
        cohortLine = `${shortenHash(shard.cohortId || shard.metaJSON?.cohortId || '')} · from first shard`;
      }
      renderInspectorDom(root, {
        title: 'Archive inspector (read-only)',
        archiveId: String(bundle.archiveState?.archiveId || ''),
        stateId: String(bundle.archiveStateDigest?.value || ''),
        cohortLines: [cohortLine],
        bundleDigest: bundleDigest || '',
        bundleDigestList: bundleDigest ? [bundleDigest] : [],
        n,
        t,
        shardLoaded,
        timelineSteps,
        evidence,
        warnings,
        bundleJson: JSON.stringify(bundle, null, 2),
      });
      return;
    }
  } catch {
    clearArchiveInspector(containerId);
    return;
  }

  clearArchiveInspector(containerId);
}
