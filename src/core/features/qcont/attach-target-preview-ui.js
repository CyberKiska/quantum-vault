import {
  attachArchivePolicyBindingLine,
  attachChannelConfig,
  attachOtsRuleLine,
  attachSignatureFamilyDescription,
  deriveAttachRequirements,
  describeAttachShardRewrite,
} from './attach-plan-view-model.js';

export function formatAttachTargetBindingPreview({
  channel,
  classified,
  shards,
  plan,
  binding = null,
  error,
}) {
  const lines = [];
  lines.push('Attach target binding (technical)');
  const channelConfig = attachChannelConfig(channel);
  lines.push(`Evidence channel: ${channelConfig.label}`);
  const requirements = classified
    ? deriveAttachRequirements(channel, classified)
    : { canAttach: false, missingLabel: 'load attach inputs' };
  lines.push(
    `Lifecycle merge target: ${requirements.canAttach ? 'successor shards and/or lifecycle bundle present' : `incomplete - ${requirements.missingLabel}`}`
  );

  const shardsLikelyInvalid = Boolean(
    classified && classified.shardFiles.length > 0 && shards.length === 0
  );
  lines.push(describeAttachShardRewrite(plan, shardsLikelyInvalid));

  lines.push(`Target artifact: ${binding?.artifactLabel || '-'}`);
  lines.push(`Target ref: ${binding?.targetRef || '-'}`);
  lines.push(`Target digest (hex): ${binding?.digestSummary || '-'}`);

  lines.push(`Signature family: ${attachSignatureFamilyDescription(channel)}`);
  lines.push(
    `Signer public-key material: ${classified ? classified.pqPublicKeyFileBytesList.length : 0} pin file(s) (.pqpk / packaged pins)`
  );
  lines.push(`Detached signatures loaded: ${classified ? classified.signatures.length : 0}`);
  lines.push(`OTS proofs loaded: ${classified ? classified.timestamps.length : 0}`);
  lines.push(attachOtsRuleLine());
  lines.push(attachArchivePolicyBindingLine(channel));
  lines.push('Per-file classification and wrong-target hints: see artifact intake table above.');
  if (error) {
    lines.push(`Evaluation note: ${String(error.message || error)}`);
  }
  return lines.join('\n');
}

export function refreshAttachTargetBindingPreview({
  channel,
  classified,
  shards,
  plan,
  binding,
  error,
}) {
  const el = document.getElementById('attachTargetBindingPreview');
  if (!el) return;
  el.textContent = formatAttachTargetBindingPreview({ channel, classified, shards, plan, binding, error });
  el.classList.remove('initially-hidden');
}

export function clearAttachTargetBindingPreview() {
  const el = document.getElementById('attachTargetBindingPreview');
  if (!el) return;
  el.textContent = '';
  el.classList.add('initially-hidden');
}
