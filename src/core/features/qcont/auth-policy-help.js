export function describeAuthPolicyHelp(authPolicyLevel) {
  if (authPolicyLevel === 'integrity-only') {
    return 'Without an externally anchored archive-approval signature over the archive-state descriptor, restore verifies integrity only and does not claim archive approval. Self-verified signatures are ignored for archive policy.';
  }
  return 'Without a policy-valid detached archive-approval signature over the archive-state descriptor, restore will block before the file is decrypted. Self-verified signatures are cryptographically valid proof material but do not satisfy archive policy.';
}
