import { createDisclosurePanel } from './disclosure.js';

export function evidenceSection(title, rows = []) {
  return { title, rows };
}

export function evidenceRow(label, value, tone = 'neutral', detail = '') {
  return { type: 'row', label, value, tone, detail };
}

export function evidencePolarRow(label, ok, okText, failText, failTone = 'fail', detail = '') {
  return evidenceRow(label, ok ? okText : failText, ok ? 'ok' : failTone, detail);
}

export function evidenceNoteRow(text) {
  return evidenceRow('Note', text, 'neutral');
}

export function renderEvidenceMatrix(host, sections = [], options = {}) {
  if (!host) return null;

  const matrix = document.createElement('div');
  const mode = options.compact ? 'compact' : 'expanded';
  matrix.className = `restore-verification-matrix evidence-matrix ${mode}`;
  if (options.testId) matrix.setAttribute('data-testid', options.testId);
  if (options.matrixClassName) {
    for (const cls of String(options.matrixClassName).split(/\s+/).filter(Boolean)) {
      matrix.classList.add(cls);
    }
  }

  let rowCount = 0;
  let failCount = 0;
  for (const section of sections) {
    if (!section) continue;
    const title = typeof section === 'string' ? section : section.title;
    if (title) {
      const sectionEl = document.createElement('div');
      sectionEl.className = 'restore-result-section evidence-matrix-section';
      sectionEl.textContent = title;
      matrix.appendChild(sectionEl);
    }

    const rows = Array.isArray(section.rows) ? section.rows : [];
    for (const row of rows) {
      if (!row) continue;
      rowCount += 1;
      if (row.tone === 'fail') failCount += 1;
      const item = document.createElement('div');
      item.className = `restore-result-item restore-matrix-row evidence-matrix-row ${row.tone || 'neutral'}`;

      const labelEl = document.createElement('span');
      labelEl.className = 'restore-matrix-label evidence-matrix-label';
      labelEl.textContent = row.label || 'Status';

      const valueEl = document.createElement('span');
      valueEl.className = 'restore-matrix-value evidence-matrix-value';
      valueEl.textContent = row.value || '';

      item.append(labelEl, valueEl);

      if (row.detail) {
        const detailEl = document.createElement('span');
        detailEl.className = 'restore-matrix-detail evidence-matrix-detail';
        detailEl.textContent = row.detail;
        item.appendChild(detailEl);
      }
      matrix.appendChild(item);
    }
  }

  if (options.disclosureLabel) {
    const defaultOpen =
      options.startExpanded === true || failCount > 0;
    const parent = createDisclosurePanel({
      summary: options.disclosureLabel,
      badgeText: failCount > 0 ? `${failCount} issue${failCount === 1 ? '' : 's'}` : rowCount > 0 ? `${rowCount}` : '',
      badgeTone: failCount > 0 ? 'warn' : 'neutral',
      defaultOpen,
      className: `evidence-matrix-details technical-details ${options.compact ? 'compact' : 'expanded'}`,
      testId: options.disclosureTestId,
      body: matrix,
    });
    host.appendChild(parent);
  } else {
    host.appendChild(matrix);
  }

  return matrix;
}

export function renderSplitRestoreEvidence(host, split, options = {}) {
  if (!host || !split) return null;

  const primaryEl = document.createElement('div');
  primaryEl.className = 'restore-evidence-primary';
  renderEvidenceMatrix(primaryEl, split.primary || [], {
    compact: options.compact !== false,
    disclosureLabel: null,
    matrixClassName: options.primaryMatrixClassName,
    testId: options.primaryTestId,
  });
  host.appendChild(primaryEl);

  const secondary = split.secondary || [];
  if (!secondary.length) return primaryEl;

  renderEvidenceMatrix(host, secondary, {
    compact: options.compact !== false,
    disclosureLabel: options.disclosureLabel || 'Evidence matrix',
    startExpanded: options.startExpanded,
    disclosureTestId: options.disclosureTestId,
    matrixClassName: options.secondaryMatrixClassName,
  });
  return primaryEl;
}

export function buildRestoreOutcomeDetailRows(result, options = {}) {
  const { releaseAllowed, policyLevel } = getRestoreReleaseState(result, options);
  const rows = [];
  if (!releaseAllowed) {
    let reason = 'Recovered container or private key failed integrity verification.';
    const { qencOk, qkeyOk, authenticity } = result;
    if (qencOk && qkeyOk) {
      if (options.liteDecrypt) {
        const { containerOk, decryptOk } = options.liteDecrypt;
        if (containerOk !== true) {
          reason = 'Recovered container failed integrity verification.';
        } else if (decryptOk !== true) {
          reason = 'Decryption or file integrity check failed.';
        } else if (authenticity?.status?.policySatisfied !== true) {
          reason = 'Archive policy is not satisfied by verified archive-approval evidence.';
        }
      } else if (authenticity?.status?.policySatisfied !== true) {
        reason = 'Archive policy is not satisfied by verified archive-approval evidence.';
      }
    }
    rows.push(evidenceRow('Blocking reason', reason, 'fail'));
  } else if (policyLevel === 'integrity-only') {
    rows.push(evidenceRow(
      'Release note',
      'Integrity-only: external archive approval is not claimed for this recovery.',
      'warn',
    ));
  }
  return rows;
}

function countSelfVerifiedSignatures(authenticity) {
  const results = Array.isArray(authenticity?.verification?.results)
    ? authenticity.verification.results
    : [];
  return results.filter((item) => {
    if (item?.selfSigned === true) return true;
    const warnings = Array.isArray(item?.warnings) ? item.warnings : [];
    return warnings.some((warning) => {
      const text = String(warning || '').toLowerCase();
      return (
        text.includes('cryptographic self-verification') ||
        text.includes('verified only with the signer public key embedded in the .qsig')
      );
    });
  }).length;
}

function buildSelfVerifiedSignatureRow(authenticity) {
  const selfVerifiedCount = countSelfVerifiedSignatures(authenticity);
  if (selfVerifiedCount > 0) {
    return evidenceRow(
      'Self-verified signature',
      'Cryptographically self-verified, ignored for archive policy',
      'warn',
      `${selfVerifiedCount} detached PQ signature${selfVerifiedCount === 1 ? '' : 's'} verified only with the public key embedded in the .qsig wrapper. No independently supplied signer pin authorized the signer.`
    );
  }
  return evidenceRow('Self-verified signature', 'None reported', 'neutral');
}

function buildSignerPinRows(status, archiveApprovalVerified) {
  const rows = [];
  const bundledKeyVerified = status.bundledKeyVerified === true || status.bundlePinned === true;
  const externallyPinned = status.externallyPinned === true || status.userPinned === true;

  if (externallyPinned) {
    rows.push(evidenceRow(
      'Archive-approval signer pin',
      'Signer pinned by external user input',
      'ok',
      'Only independently supplied signer pins currently authorize a verified archive-approval signature for policy counting.'
    ));
  } else if (archiveApprovalVerified) {
    rows.push(evidenceRow(
      'Archive-approval signer pin',
      'Signer not externally pinned',
      'warn',
      'The signature may be cryptographically valid, but archive policy will not count it without an independently supplied signer pin.'
    ));
  } else {
    rows.push(evidenceRow('Archive-approval signer pin', 'No verified archive-approval signer to pin', 'neutral'));
  }

  rows.push(evidencePolarRow(
    'Bundled signer material',
    bundledKeyVerified,
    'Signature verified with bundled key (not a trust anchor)',
    'No bundled key verified an archive-approval signature',
    'neutral',
  ));

  if (status.userPinProvided === true || externallyPinned) {
    rows.push(evidencePolarRow(
      'User-entered signer pin',
      externallyPinned,
      'User-entered signer pin matched',
      status.userPinProvided === true ? 'User-entered signer pin did not match a verifying archive-approval signer' : 'User-entered signer pin not active',
      status.userPinProvided === true && status.userPinned !== true ? 'warn' : 'neutral',
    ));
  } else {
    rows.push(evidenceRow('User-entered signer pin', 'No user-entered signer pin provided', 'neutral'));
  }

  return rows;
}

export function getRestoreReleaseState(result, options = {}) {
  const { qencOk, qkeyOk, authenticity } = result;
  const policyOk = authenticity?.status?.policySatisfied === true;
  let releaseAllowed = qencOk && qkeyOk && policyOk;
  if (options.liteDecrypt) {
    const { containerOk, decryptOk } = options.liteDecrypt;
    releaseAllowed = qencOk && qkeyOk && containerOk && decryptOk && policyOk;
  }
  const policyLevel = String(authenticity?.policy?.level || 'unknown');
  return { releaseAllowed, policyLevel, policyOk };
}

export function buildRestoreEvidenceMatrixSections(result, options = {}) {
  const { qencOk, qkeyOk, authenticity } = result;
  const status = authenticity?.status || {};
  const { releaseAllowed, policyLevel } = getRestoreReleaseState(result, options);
  const archiveApprovalCryptographicallyVerified = (
    status.archiveApprovalCryptographicallyVerified === true ||
    status.archiveApprovalSignatureVerified === true
  );
  const strongPqCryptographicallyVerified = (
    status.strongPqArchiveApprovalCryptographicallyVerified === true ||
    status.strongPqSignatureVerified === true
  );
  const cohortInspection = result.lifecycleVerification?.cohorts || {};
  const decisionRows = [];

  if (releaseAllowed && policyLevel === 'integrity-only') {
    decisionRows.push(evidenceRow(
      'Plaintext release',
      'Allowed by integrity-only policy',
      'warn',
      'No archive-approval signature is required by the selected policy.'
    ));
  } else if (releaseAllowed) {
    decisionRows.push(evidenceRow('Plaintext release', `Allowed by ${policyLevel} policy`, 'ok'));
  } else {
    decisionRows.push(evidenceRow('Plaintext release', 'Blocked', 'fail'));
  }

  decisionRows.push(...buildRestoreOutcomeDetailRows(result, options));

  const integrityRows = [
    evidencePolarRow('Container integrity', qencOk, 'Container integrity verified', 'Container integrity check failed'),
    evidencePolarRow('Private key recovery', qkeyOk, 'Private key integrity verified', 'Private key integrity check failed'),
  ];
  if (options.liteDecrypt) {
    integrityRows.push(evidencePolarRow(
      'Plaintext integrity',
      options.liteDecrypt.decryptOk,
      'Decryption and file integrity verified',
      'Decryption or file integrity check failed',
    ));
  }

  const policyRows = [
    evidencePolarRow(
      'Archive policy',
      status.policySatisfied === true,
      'Archive policy satisfied',
      'Archive policy not satisfied',
      'fail',
      'Archive policy evaluation remains archive-approval-only.'
    ),
    evidencePolarRow(
      'Archive approval',
      archiveApprovalCryptographicallyVerified,
      'Archive-approval signature verified cryptographically',
      'No cryptographically verified archive-approval signature over archive-state',
      policyLevel === 'integrity-only' ? 'warn' : 'fail',
    ),
    evidencePolarRow(
      'Strong PQ approval',
      strongPqCryptographicallyVerified,
      'Strong PQ archive-approval signature verified cryptographically',
      'Strong PQ archive-approval signature not present',
      archiveApprovalCryptographicallyVerified === true && !strongPqCryptographicallyVerified ? 'warn' : 'neutral',
    ),
    ...integrityRows,
  ];

  const secondaryRows = [
    buildSelfVerifiedSignatureRow(authenticity),
  ];

  if (status.transitionRecordPresent !== true) {
    secondaryRows.push(evidenceRow('Maintenance evidence', 'No transition or maintenance evidence present', 'neutral'));
  } else {
    secondaryRows.push(
      evidencePolarRow('Transition record', true, 'Transition record present', 'Transition record missing'),
      evidencePolarRow(
        'Transition chain',
        status.transitionChainValid === true,
        'Transition-chain references valid',
        'Transition-chain references invalid or broken',
      ),
      evidencePolarRow(
        'Maintenance evidence',
        status.maintenanceSignatureVerified === true,
        'Maintenance signature verified',
        'No verified maintenance signature on transition record(s)',
        'warn',
        'Maintenance signatures do not satisfy archive policy.'
      )
    );
  }

  if (status.sourceEvidencePresent !== true) {
    secondaryRows.push(evidenceRow('Source evidence', 'No source-evidence objects present', 'neutral'));
  } else {
    secondaryRows.push(evidencePolarRow(
      'Source evidence',
      status.sourceEvidenceSignatureVerified === true,
      'Source-evidence signature verified',
      'Source-evidence present but no verified signature',
      'warn',
      'Source evidence does not satisfy archive policy.'
    ));
  }

  if (cohortInspection.forkDetected === true) {
    secondaryRows.push(evidenceRow('Cohort selection', 'Same-state cohort fork remains known for this archive state', 'warn'));
  }
  if (status.bundleCohortMixed === true) {
    secondaryRows.push(evidenceRow('Lifecycle bundle selection', 'Mixed embedded lifecycle bundle variants were present in the selected cohort', 'warn'));
  } else {
    secondaryRows.push(evidenceRow('Lifecycle bundle selection', 'One lifecycle bundle variant selected for policy evaluation', 'ok'));
  }

  secondaryRows.push(...buildSignerPinRows(status, archiveApprovalCryptographicallyVerified));

  const timestampEvidence = Array.isArray(authenticity?.timestampEvidence) ? authenticity.timestampEvidence : [];
  if (timestampEvidence.length > 0) {
    const completeCount = timestampEvidence.filter((item) => item.apparentlyComplete === true).length;
    const incompleteCount = timestampEvidence.length - completeCount;
    const completionParts = [];
    if (completeCount > 0) {
      completionParts.push(`OTS proof appears complete (heuristic): ${completeCount}`);
    }
    if (incompleteCount > 0) {
      completionParts.push(`OTS proof incomplete or pending: ${incompleteCount}`);
    }
    secondaryRows.push(evidenceRow(
      'Timestamp evidence',
      `OTS evidence linked to ${timestampEvidence.length} signature${timestampEvidence.length === 1 ? '' : 's'}`,
      incompleteCount > 0 ? 'warn' : 'ok',
      `${completionParts.join('; ')}. Timestamp evidence does not satisfy archive policy.`
    ));
  } else {
    secondaryRows.push(evidenceRow('Timestamp evidence', 'No OTS evidence linked', 'neutral'));
  }

  secondaryRows.push(
    evidenceNoteRow('Maintenance, source-evidence, and timestamp evidence are reported separately and do not authorize restore.')
  );

  return {
    primary: [
      evidenceSection('Restore Decision', decisionRows),
      evidenceSection('Policy & integrity', policyRows),
    ],
    secondary: [
      evidenceSection('Evidence details', secondaryRows),
    ],
  };
}

export function buildRestorePolicyFailureEvidenceMatrixSections(error) {
  const reason = String(error?.message || error || 'Archive policy not satisfied');
  const authenticity = error?.authenticity || null;
  const status = authenticity?.status || {};
  const archiveApprovalCryptographicallyVerified = (
    status.archiveApprovalCryptographicallyVerified === true ||
    status.archiveApprovalSignatureVerified === true
  );
  const strongPqCryptographicallyVerified = (
    status.strongPqArchiveApprovalCryptographicallyVerified === true ||
    status.strongPqSignatureVerified === true
  );

  return {
    primary: [
      evidenceSection('Restore Decision', [
        evidenceRow('Plaintext release', 'Blocked', 'fail'),
        evidenceRow('Archive policy', 'Archive policy not satisfied', 'fail', reason),
        evidenceRow('Integrity', 'Not evaluated after policy block', 'neutral'),
        evidenceRow(
          'Archive approval',
          archiveApprovalCryptographicallyVerified
            ? 'Archive-approval signature cryptographically verified but not externally authorized'
            : 'No policy-satisfying archive-approval signature verified',
          'fail'
        ),
        evidencePolarRow(
          'Strong PQ approval',
          strongPqCryptographicallyVerified,
          'Strong PQ archive-approval signature verified cryptographically',
          'Strong PQ archive-approval signature not present',
          'neutral'
        ),
      ]),
    ],
    secondary: [
      evidenceSection('Evidence details', [
        buildSelfVerifiedSignatureRow(authenticity),
        ...buildSignerPinRows(status, archiveApprovalCryptographicallyVerified),
        evidenceRow('Evidence channels', 'Maintenance, source-evidence, and timestamp evidence cannot satisfy archive policy', 'neutral'),
      ]),
    ],
  };
}

export function buildAttachEvidenceMatrixSections({ classified, plan, channelConfig, channel }) {
  const signatureCount = classified.signatures.length;
  const timestampCount = classified.timestamps.length;
  const publicKeyCount = classified.pqPublicKeyFileBytesList.length;
  const resultRows = [evidencePolarRow('Lifecycle bundle', true, 'Lifecycle bundle updated', '')];

  if (plan.embedIntoShards) {
    const shardCountText = `${plan.selectedShardCount}/${plan.expectedShardCount}`;
    if (plan.warning) {
      resultRows.push(evidenceRow(
        'Shard rewrite',
        `Only ${shardCountText} selected shard files were rewritten; other shards may still carry older embedded lifecycle-bundle bytes.`,
        'warn'
      ));
    } else {
      resultRows.push(evidencePolarRow('Shard rewrite', true, `Selected shard files updated (${shardCountText})`, ''));
    }
  } else {
    resultRows.push(evidenceRow('Shard rewrite', 'Shard files were not rewritten.', 'neutral'));
  }
  resultRows.push(evidencePolarRow('Archive-state bytes', true, 'Signable archive-state bytes remained unchanged', ''));

  const channelRows = [
    evidenceRow('Attach channel', `${channelConfig.label} selected for this attach run.`, 'neutral'),
  ];
  if (channel === 'maintenance') {
    channelRows.push(evidencePolarRow('Evidence boundary', true, 'Transition-record target stayed separate from archive approval', ''));
  } else if (channel === 'source-evidence') {
    channelRows.push(evidencePolarRow('Evidence boundary', true, 'Source-evidence signatures stayed separate from archive approval', ''));
  } else {
    channelRows.push(evidencePolarRow('Evidence boundary', true, 'Archive-approval signatures stayed on archive-state bytes', ''));
  }

  const importedRows = [];
  if (signatureCount > 0) {
    const label = channel === 'archive-approval'
      ? 'Archive-approval signatures merged'
      : channel === 'maintenance'
        ? 'Maintenance signatures merged'
        : 'Source-evidence signatures merged';
    importedRows.push(evidencePolarRow('Detached signatures', true, `${label} (${signatureCount})`, ''));
  } else {
    importedRows.push(evidenceRow('Detached signatures', `No ${channelConfig.label.toLowerCase()} .qsig/.sig files were supplied.`, 'neutral'));
  }
  if (channel === 'maintenance') {
    importedRows.push(classified.transitionRecordBytes instanceof Uint8Array
      ? evidencePolarRow('Transition-record target', true, 'Canonical transition-record target loaded', '')
      : evidenceRow('Transition-record target', 'No transition-record.json target was supplied.', 'neutral'));
  }
  if (channel === 'source-evidence') {
    importedRows.push(classified.sourceEvidenceBytes instanceof Uint8Array
      ? evidencePolarRow('Source-evidence target', true, 'Canonical source-evidence artifact loaded', '')
      : evidenceRow('Source-evidence target', 'No source-evidence.json artifact was supplied.', 'neutral'));
  }
  importedRows.push(publicKeyCount > 0
    ? evidencePolarRow('Signer pins', true, `.pqpk signer pins merged (${publicKeyCount})`, '')
    : evidenceRow('Signer pins', 'No .pqpk signer pins were supplied.', 'neutral'));
  if (timestampCount > 0) {
    importedRows.push(
      evidencePolarRow('Timestamp evidence', true, `.ots proofs merged (${timestampCount})`, ''),
      evidenceRow('Timestamp target', 'OTS evidence targets detached signature bytes by SHA-256(signatureBytes), not archive-state or lifecycle-bundle bytes.', 'neutral'),
      evidenceRow('Timestamp policy', 'Timestamp evidence does not satisfy archive policy.', 'neutral')
    );
  } else {
    importedRows.push(evidenceRow('Timestamp evidence', 'No .ots proofs were supplied.', 'neutral'));
  }

  return [
    evidenceSection('Result', resultRows),
    evidenceSection('Evidence Channel', channelRows),
    evidenceSection('Imported Files', importedRows),
    evidenceSection('Next Actions', [
      evidenceRow('Next step', 'Continue to Restore to inspect archive approval, maintenance, and source-evidence channels separately.', 'neutral'),
    ]),
  ];
}
