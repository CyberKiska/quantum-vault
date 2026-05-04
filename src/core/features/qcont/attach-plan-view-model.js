export const ATTACH_CHANNELS = Object.freeze({
  'archive-approval': Object.freeze({
    label: 'Archive approval',
    buttonLabel: 'Attach Archive-Approval Evidence',
    channelHelp: 'Archive approval attaches detached signatures over the canonical archive-state descriptor. Maintenance and source-evidence remain separate evidence channels and never satisfy archive policy on their own.',
    inputHint: 'Load one archive cohort plus any archive-approval .qsig/.sig, .pqpk signer pins, and optional .ots proofs you want to merge.',
    emptySelectionText: 'Select archive-approval attach inputs to see the attach plan.',
    attachSummary: 'Archive-approval evidence merged',
  }),
  maintenance: Object.freeze({
    label: 'Maintenance signature',
    buttonLabel: 'Attach Maintenance Evidence',
    channelHelp: 'Maintenance signatures target a canonical transition-record already present in the selected lifecycle bundle. This evidence stays separate from archive approval and does not satisfy archive policy.',
    inputHint: 'Load one archive cohort or lifecycle bundle, the matching canonical transition-record.json, one or more maintenance .qsig/.sig files, any .pqpk signer pins, and optional .ots proofs.',
    emptySelectionText: 'Select maintenance attach inputs to see the attach plan.',
    attachSummary: 'Maintenance evidence merged',
  }),
  'source-evidence': Object.freeze({
    label: 'Source evidence',
    buttonLabel: 'Attach Source-Evidence Signatures',
    channelHelp: 'Source-evidence signatures target canonical source-evidence JSON, not archive-state approval bytes. This channel is provenance only and never satisfies archive policy.',
    inputHint: 'Load one archive cohort or lifecycle bundle, the canonical source-evidence.json artifact, one or more detached signatures over that exact JSON, any .pqpk signer pins, and optional .ots proofs.',
    emptySelectionText: 'Select source-evidence attach inputs to see the attach plan.',
    attachSummary: 'Source-evidence signatures merged',
  }),
});

export function attachChannelConfig(channel = 'archive-approval') {
  return ATTACH_CHANNELS[channel] || ATTACH_CHANNELS['archive-approval'];
}

export function deriveAttachRequirements(channel, classified) {
  const hasAttachTarget = classified.shardFiles.length > 0 || classified.lifecycleBundleBytes instanceof Uint8Array;
  if (channel === 'maintenance') {
    return {
      canAttach: hasAttachTarget && classified.transitionRecordBytes instanceof Uint8Array && classified.signatures.length > 0,
      missingLabel: 'load successor shards or a lifecycle bundle, one canonical transition-record.json, and at least one maintenance signature',
    };
  }
  if (channel === 'source-evidence') {
    return {
      canAttach: hasAttachTarget && classified.sourceEvidenceBytes instanceof Uint8Array && classified.signatures.length > 0,
      missingLabel: 'load successor shards or a lifecycle bundle, one canonical source-evidence.json, and at least one detached signature',
    };
  }
  return {
    canAttach: hasAttachTarget,
    missingLabel: 'load successor shards or a lifecycle bundle',
  };
}

export function describeAttachShardRewrite(plan, shardsParseLikelyFailed) {
  if (shardsParseLikelyFailed) {
    return 'Shard rewrite: not evaluated - fix shard or lifecycle bundle inputs first.';
  }
  if (!plan.embedIntoShards) {
    return 'Shard rewrite: bundle-only (no successor shard files loaded).';
  }
  if (plan.warning) {
    return `Shard rewrite: partial cohort (${plan.selectedShardCount}/${plan.expectedShardCount} shards selected).`;
  }
  return `Shard rewrite: full cohort (${plan.selectedShardCount}/${plan.expectedShardCount} shards).`;
}

export function attachSignatureFamilyDescription(channel) {
  if (channel === 'maintenance') return 'maintenance - detached signatures over canonical transition-record JSON';
  if (channel === 'source-evidence') return 'source-evidence - detached signatures over canonical source-evidence JSON';
  return 'archive-approval - detached signatures over canonical archive-state descriptor JSON';
}

export function attachArchivePolicyBindingLine(channel) {
  if (channel === 'archive-approval') {
    return 'Archive policy binding: verified signatures on this channel can satisfy archive restore policy when Restore trusts them.';
  }
  return 'Archive policy binding: this channel does not satisfy archive restore policy by itself (maintenance or provenance only).';
}

export function attachOtsRuleLine() {
  return 'OTS rule: each proof must stamp SHA-256(detached signature bytes) for a signature file present in this intake (.qsig / supported .sig).';
}

/**
 * View model for the Attach plan decision card.
 * Keeps an operator-first summary on the card; raw binding dump stays in attach-target-preview-ui.
 */
export function buildAttachPlanDecisionModel({
  channel,
  channelConfig,
  classified,
  shards,
  plan,
  requirements,
  canAttach,
  stateClass,
  summary,
  lede,
  errorMode = false,
  errorMessage = '',
  binding = null,
}) {
  const tone = errorMode ? 'fail' : stateClass === 'invalid' ? 'fail' : stateClass === 'insufficient' ? 'warn' : 'ok';

  if (errorMode) {
    const rows = [];
    if (classified) {
      rows.push({ label: 'Evidence channel', value: channelConfig.label, tone: 'neutral' });
      const policyTone = channel === 'archive-approval' ? 'neutral' : 'warn';
      rows.push({
        label: 'Archive restore policy',
        value: attachArchivePolicyBindingLine(channel),
        tone: policyTone,
      });
      rows.push(
        { label: 'Target artifact', value: binding?.artifactLabel || '-', tone: 'neutral' },
        { label: 'Anchor digest (SHA3-512)', value: binding?.digestSummary || '-', tone: 'neutral' },
        {
          label: 'Shard rewrite scope',
          value: describeAttachShardRewrite(plan, Boolean(
            classified.shardFiles.length > 0 && shards.length === 0
          )),
          tone: plan.warning ? 'warn' : 'neutral',
        },
        { label: 'Lifecycle update', value: plan.modeLabel, tone: plan.warning ? 'warn' : 'neutral' },
      );
    }
    rows.push({
      label: classified ? 'Blocking detail' : 'Details',
      value: errorMessage,
      tone: 'fail',
    });
    return {
      title: 'Attach plan',
      tone,
      primaryOutcome: summary,
      lede,
      rows,
    };
  }

  const shardsLikelyInvalid = Boolean(
    classified && classified.shardFiles.length > 0 && shards.length === 0
  );
  const policyTone = channel === 'archive-approval' ? 'ok' : 'warn';
  const mergeTargetTone = !canAttach ? 'fail' : plan.warning ? 'warn' : 'neutral';

  const rows = [
    { label: 'Evidence channel', value: channelConfig.label, tone: 'neutral' },
    {
      label: 'Archive restore policy',
      value: attachArchivePolicyBindingLine(channel),
      tone: policyTone,
    },
    { label: 'Target artifact', value: binding?.artifactLabel || '-', tone: 'neutral' },
    { label: 'Anchor digest (SHA3-512)', value: binding?.digestSummary || '-', tone: 'neutral' },
    {
      label: 'Shard rewrite scope',
      value: describeAttachShardRewrite(plan, shardsLikelyInvalid),
      tone: plan.warning ? 'warn' : 'neutral',
    },
    { label: 'Lifecycle update', value: plan.modeLabel, tone: mergeTargetTone },
    {
      label: 'Evidence loaded',
      value: `${classified.signatures.length} detached signature(s), ${classified.pqPublicKeyFileBytesList.length} signer pin(s), ${classified.timestamps.length} OTS proof(s)`,
      tone: 'neutral',
    },
    {
      label: 'Transition record',
      value: classified.transitionRecordBytes instanceof Uint8Array ? 'Loaded' : 'Not loaded',
      tone: 'neutral',
    },
    {
      label: 'Source evidence JSON',
      value: classified.sourceEvidenceBytes instanceof Uint8Array ? 'Loaded' : 'Not loaded',
      tone: 'neutral',
    },
  ];

  if (!canAttach) {
    rows.push({
      label: 'Merge readiness',
      value: `Blocked until you ${requirements.missingLabel}.`,
      tone: 'fail',
    });
  }

  return {
    title: 'Attach plan',
    tone,
    primaryOutcome: summary,
    lede,
    rows,
  };
}
