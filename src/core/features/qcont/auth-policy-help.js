export function describeAuthPolicyHelp(authPolicyLevel) {
  if (authPolicyLevel === 'integrity-only') {
    return 'Without an external archive-approval signature over the archive-state descriptor, restore verifies integrity only and does not claim archive approval.';
  }
  return 'Without an external detached archive-approval signature over the archive-state descriptor, restore will block before the file is decrypted.';
}
