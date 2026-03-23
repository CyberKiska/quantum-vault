import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../bytes.js';
import { MANIFEST_CANONICALIZATION_LABEL, canonicalizeJsonToBytes } from './jcs.js';
import { ensureObject, ensureString, ensureInteger, ensureHex, assertExactKeys } from './validation.js';

export const AUTH_POLICY_COMMITMENT_ALG = 'SHA3-512';

const AUTH_LEVELS = new Set(['integrity-only', 'any-signature', 'strong-pq-signature']);

export function normalizeAuthPolicy(authPolicy) {
  const source = ensureObject(authPolicy, 'authPolicy');
  assertExactKeys(source, ['level', 'minValidSignatures'], [], 'authPolicy');
  const level = String(source.level || '').trim().toLowerCase();
  if (!AUTH_LEVELS.has(level)) {
    throw new Error(`Unsupported authPolicy.level: ${source.level}`);
  }
  return {
    level,
    minValidSignatures: ensureInteger(source.minValidSignatures ?? 1, 'authPolicy.minValidSignatures', 1),
  };
}

export function computeAuthPolicyCommitment(authPolicy) {
  const normalized = normalizeAuthPolicy(authPolicy);
  return {
    alg: AUTH_POLICY_COMMITMENT_ALG,
    canonicalization: MANIFEST_CANONICALIZATION_LABEL,
    value: toHex(sha3_512(canonicalizeJsonToBytes(normalized))),
  };
}

export function validateAuthPolicyCommitmentShape(commitment) {
  const source = ensureObject(commitment, 'authPolicyCommitment');
  assertExactKeys(source, ['alg', 'canonicalization', 'value'], [], 'authPolicyCommitment');
  if (ensureString(source.alg, 'authPolicyCommitment.alg') !== AUTH_POLICY_COMMITMENT_ALG) {
    throw new Error('Unsupported authPolicyCommitment.alg');
  }
  if (ensureString(source.canonicalization, 'authPolicyCommitment.canonicalization') !== MANIFEST_CANONICALIZATION_LABEL) {
    throw new Error('Unsupported authPolicyCommitment.canonicalization');
  }
  return {
    alg: source.alg,
    canonicalization: source.canonicalization,
    value: ensureHex(source.value, 'authPolicyCommitment.value', 128),
  };
}

export function assertAuthPolicyCommitment(commitment, authPolicy) {
  const actual = validateAuthPolicyCommitmentShape(commitment);
  const expected = computeAuthPolicyCommitment(authPolicy);
  if (actual.value !== expected.value) {
    throw new Error('authPolicyCommitment mismatch');
  }
  return actual;
}

export function recoverCommittedAuthPolicy(commitment, options = {}) {
  const actual = validateAuthPolicyCommitmentShape(commitment);
  const maxMinValidSignatures = Number.isInteger(options.maxMinValidSignatures)
    ? options.maxMinValidSignatures
    : 64;
  const matches = [];

  for (const level of AUTH_LEVELS) {
    for (let minValidSignatures = 1; minValidSignatures <= maxMinValidSignatures; minValidSignatures += 1) {
      const candidate = { level, minValidSignatures };
      if (computeAuthPolicyCommitment(candidate).value === actual.value) {
        matches.push(candidate);
      }
    }
  }

  if (matches.length === 1) {
    return matches[0];
  }
  if (matches.length === 0) {
    throw new Error('Unable to recover authPolicy from authPolicyCommitment');
  }
  throw new Error('authPolicyCommitment is ambiguous');
}
