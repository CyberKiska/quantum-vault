export function describeAuthPolicyHelp(authPolicyLevel) {
  if (authPolicyLevel === 'integrity-only') {
    return 'Without an archive-approval signature matched by an independently supplied signer pin, restore verifies integrity only and does not claim archive approval. Embedded or bundled keys are not trust anchors.';
  }
  return 'Without a detached archive-approval signature matched by an independently supplied signer pin, restore will block before the file is decrypted. Embedded and bundled signer material may verify cryptographically but cannot authorize policy.';
}

export function describeAuthPolicyConsequence(authPolicyLevel) {
  if (authPolicyLevel === 'integrity-only') {
    return {
      tone: 'warning',
      title: 'Integrity-only restore consequence',
      lines: [
        'Restore may release plaintext without archive-approval signature.',
        'Integrity is checked; archive approval is not claimed.',
      ],
    };
  }
  if (authPolicyLevel === 'any-signature') {
    return {
      tone: 'informational',
      title: 'Signature-required restore consequence',
      lines: [
        'Restore requires at least one valid archive-approval signature matched by an external signer pin.',
        'Maintenance, source-evidence, and timestamp evidence do not satisfy this policy.',
      ],
    };
  }
  return {
    tone: 'strict',
    title: 'Strong-PQ restore consequence',
    lines: [
      'Restore requires a strong PQ archive-approval signature over the archive-state descriptor matched by an external signer pin.',
      'Embedded or bundled signer material alone is ignored for policy.',
    ],
  };
}

export function renderAuthPolicyConsequence(panel, authPolicyLevel) {
  if (!panel) return;
  const consequence = describeAuthPolicyConsequence(authPolicyLevel);
  panel.className = `policy-consequence-panel ${consequence.tone}`;
  panel.setAttribute('data-policy-tone', consequence.tone);
  panel.setAttribute('aria-live', 'polite');
  panel.replaceChildren();

  const heading = document.createElement('h4');
  heading.textContent = consequence.title;
  panel.appendChild(heading);

  const list = document.createElement('ul');
  consequence.lines.forEach((line) => {
    const item = document.createElement('li');
    item.textContent = line;
    list.appendChild(item);
  });
  panel.appendChild(list);
}
