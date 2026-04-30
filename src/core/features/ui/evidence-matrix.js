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

  host.appendChild(matrix);
  return matrix;
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
      `${selfVerifiedCount} detached PQ signature${selfVerifiedCount === 1 ? '' : 's'} verified only with the public key embedded in the .qsig wrapper. No bundled or user-supplied signer pin corroborated the signer.`
    );
  }
  return evidenceRow('Self-verified signature', 'None reported', 'neutral');
}

function buildSignerPinRows(status, archiveApprovalVerified) {
  const rows = [];
  const pinSources = [];
  if (status.bundlePinned === true) pinSources.push('bundle');
  if (status.userPinned === true) pinSources.push('user input');

  if (pinSources.length > 0) {
    rows.push(evidenceRow(
      'Archive-approval signer pin',
      `Signer pinned by ${pinSources.join(' and ')}`,
      'ok',
      'Pinning strengthens signer provenance reporting but remains separate from archive-policy evaluation.'
    ));
  } else if (archiveApprovalVerified) {
    rows.push(evidenceRow(
      'Archive-approval signer pin',
      'Signer not pinned',
      'warn',
      'A valid archive-approval signature may satisfy policy without pinning; signer pinning remains a separate status.'
    ));
  } else {
    rows.push(evidenceRow('Archive-approval signer pin', 'No verified archive-approval signer to pin', 'neutral'));
  }

  rows.push(evidencePolarRow(
    'Bundle signer pin',
    status.bundlePinned === true,
    'Bundle signer pin matched',
    'No bundle signer pin matched archive approval',
    archiveApprovalVerified === true && status.bundlePinned !== true ? 'warn' : 'neutral',
  ));

  if (status.userPinProvided === true || status.userPinned === true) {
    rows.push(evidencePolarRow(
      'User-entered signer pin',
      status.userPinned === true,
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
  const archiveApprovalVerified = status.archiveApprovalSignatureVerified === true;
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

  const verificationRows = [
    evidencePolarRow('Container integrity', qencOk, 'Container integrity verified', 'Container integrity check failed'),
    evidencePolarRow('Private key recovery', qkeyOk, 'Private key integrity verified', 'Private key integrity check failed'),
  ];
  if (options.liteDecrypt) {
    verificationRows.push(evidencePolarRow(
      'Plaintext integrity',
      options.liteDecrypt.decryptOk,
      'Decryption and file integrity verified',
      'Decryption or file integrity check failed',
    ));
  }

  verificationRows.push(
    evidencePolarRow(
      'Archive approval',
      archiveApprovalVerified,
      'Archive-approval signature verified',
      'No verified archive-approval signature over archive-state',
      policyLevel === 'integrity-only' ? 'warn' : 'fail',
    ),
    evidencePolarRow(
      'Strong PQ approval',
      status.strongPqSignatureVerified === true,
      'Strong PQ archive-approval signature verified',
      'Strong PQ archive-approval signature not present',
      archiveApprovalVerified === true && status.strongPqSignatureVerified !== true ? 'warn' : 'neutral',
    ),
    buildSelfVerifiedSignatureRow(authenticity)
  );

  if (status.transitionRecordPresent !== true) {
    verificationRows.push(evidenceRow('Maintenance evidence', 'No transition or maintenance evidence present', 'neutral'));
  } else {
    verificationRows.push(
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
    verificationRows.push(evidenceRow('Source evidence', 'No source-evidence objects present', 'neutral'));
  } else {
    verificationRows.push(evidencePolarRow(
      'Source evidence',
      status.sourceEvidenceSignatureVerified === true,
      'Source-evidence signature verified',
      'Source-evidence present but no verified signature',
      'warn',
      'Source evidence does not satisfy archive policy.'
    ));
  }

  if (cohortInspection.forkDetected === true) {
    verificationRows.push(evidenceRow('Cohort selection', 'Same-state cohort fork remains known for this archive state', 'warn'));
  }
  if (status.bundleCohortMixed === true) {
    verificationRows.push(evidenceRow('Lifecycle bundle selection', 'Mixed embedded lifecycle bundle variants were present in the selected cohort', 'warn'));
  } else {
    verificationRows.push(evidenceRow('Lifecycle bundle selection', 'One lifecycle bundle variant selected for policy evaluation', 'ok'));
  }

  verificationRows.push(...buildSignerPinRows(status, archiveApprovalVerified));

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
    verificationRows.push(evidenceRow(
      'Timestamp evidence',
      `OTS evidence linked to ${timestampEvidence.length} signature${timestampEvidence.length === 1 ? '' : 's'}`,
      incompleteCount > 0 ? 'warn' : 'ok',
      `${completionParts.join('; ')}. Timestamp evidence does not satisfy archive policy.`
    ));
  } else {
    verificationRows.push(evidenceRow('Timestamp evidence', 'No OTS evidence linked', 'neutral'));
  }

  verificationRows.push(
    evidencePolarRow(
      'Archive policy',
      status.policySatisfied === true,
      'Archive policy satisfied',
      'Archive policy not satisfied',
      'fail',
      'Archive policy evaluation remains archive-approval-only.'
    ),
    evidenceNoteRow('Maintenance, source-evidence, and timestamp evidence are reported separately and do not authorize restore.')
  );

  return [
    evidenceSection('Restore Decision', decisionRows),
    evidenceSection('Verification Matrix', verificationRows),
  ];
}

export function buildRestorePolicyFailureEvidenceMatrixSections(error) {
  const reason = String(error?.message || error || 'Archive policy not satisfied');
  const authenticity = error?.authenticity || null;
  const status = authenticity?.status || {};
  const archiveApprovalVerified = status.archiveApprovalSignatureVerified === true;

  return [
    evidenceSection('Restore Decision', [
      evidenceRow('Plaintext release', 'Blocked', 'fail'),
      evidenceRow('Archive policy', 'Archive policy not satisfied', 'fail', reason),
      evidenceRow('Integrity', 'Not evaluated after policy block', 'neutral'),
      evidenceRow(
        'Archive approval',
        archiveApprovalVerified
          ? 'Archive-approval signature verified but not policy-satisfying'
          : 'No policy-satisfying archive-approval signature verified',
        'fail'
      ),
      evidencePolarRow(
        'Strong PQ approval',
        status.strongPqSignatureVerified === true,
        'Strong PQ archive-approval signature verified',
        'Strong PQ archive-approval signature not present',
        'neutral'
      ),
      buildSelfVerifiedSignatureRow(authenticity),
      ...buildSignerPinRows(status, archiveApprovalVerified),
      evidenceRow('Evidence channels', 'Maintenance, source-evidence, and timestamp evidence cannot satisfy archive policy', 'neutral'),
    ]),
  ];
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
