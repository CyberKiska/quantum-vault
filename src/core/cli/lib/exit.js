export const EXIT = Object.freeze({
  OK: 0,
  ERROR: 1,
  USAGE: 2,
  ENTROPY: 3,
  FORMAT_POLICY: 4,
  KEY: 5,
  AEAD: 6,
  QUORUM: 7,
  SIGNATURE_IMPORT: 8,
  AMBIGUITY: 9,
  RESHARE_CONTRACT: 10,
  RESTORED_INTEGRITY: 11,
});

export const QV_CODE = Object.freeze({
  UNEXPECTED: 'UNEXPECTED',
  USAGE: 'USAGE',
  ENTROPY_FAILED: 'ENTROPY_FAILED',
  FORMAT_POLICY_REJECT: 'FORMAT_POLICY_REJECT',
  KEY_REJECTED: 'KEY_REJECTED',
  AEAD_FAILED: 'AEAD_FAILED',
  QUORUM_UNREACHABLE: 'QUORUM_UNREACHABLE',
  SIGNATURE_IMPORT_FAILED: 'SIGNATURE_IMPORT_FAILED',
  AMBIGUOUS_INPUTS: 'AMBIGUOUS_INPUTS',
  RESHARE_CONTRACT_VIOLATION: 'RESHARE_CONTRACT_VIOLATION',
  RESTORED_INTEGRITY_FAILED: 'RESTORED_INTEGRITY_FAILED',
});

const QV_CODE_TO_EXIT = Object.freeze({
  [QV_CODE.UNEXPECTED]: EXIT.ERROR,
  [QV_CODE.USAGE]: EXIT.USAGE,
  [QV_CODE.ENTROPY_FAILED]: EXIT.ENTROPY,
  [QV_CODE.FORMAT_POLICY_REJECT]: EXIT.FORMAT_POLICY,
  [QV_CODE.KEY_REJECTED]: EXIT.KEY,
  [QV_CODE.AEAD_FAILED]: EXIT.AEAD,
  [QV_CODE.QUORUM_UNREACHABLE]: EXIT.QUORUM,
  [QV_CODE.SIGNATURE_IMPORT_FAILED]: EXIT.SIGNATURE_IMPORT,
  [QV_CODE.AMBIGUOUS_INPUTS]: EXIT.AMBIGUITY,
  [QV_CODE.RESHARE_CONTRACT_VIOLATION]: EXIT.RESHARE_CONTRACT,
  [QV_CODE.RESTORED_INTEGRITY_FAILED]: EXIT.RESTORED_INTEGRITY,
});

const CORE_ERROR_QV_CODE_RULES = Object.freeze([
  // Future command commits add audited core-error mappings here.
]);

export function makeQvError(message, qvCode = QV_CODE.UNEXPECTED, options = {}) {
  const error = new Error(message, options);
  error.qvCode = qvCode;
  return error;
}

export function getErrorQvCode(error) {
  if (typeof error?.qvCode === 'string' && Object.hasOwn(QV_CODE_TO_EXIT, error.qvCode)) {
    return error.qvCode;
  }
  const message = error?.message || String(error);
  for (const rule of CORE_ERROR_QV_CODE_RULES) {
    if (rule.pattern.test(message)) {
      return rule.qvCode;
    }
  }
  return QV_CODE.UNEXPECTED;
}

export function mapErrorToExitCode(error) {
  return QV_CODE_TO_EXIT[getErrorQvCode(error)] ?? EXIT.ERROR;
}
