import { AUTH_POLICY_LEVELS } from '../../crypto/manifest/auth-policy.js';
import { validateStellarEd25519PublicAddress } from '../../crypto/auth/stellar-sig.js';
import { QV_CODE, makeQvError } from './exit.js';

export function takeValue(args, index, flag) {
  if (index + 1 >= args.length) {
    throw new Error(`${flag} requires a value`);
  }
  return args[index + 1];
}

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

export function normalizeLowerHex(value, field, expectedChars) {
  const text = String(value || '').trim();
  if (text.length !== expectedChars || !/^[0-9a-f]+$/.test(text)) {
    throw usage(`${field} must be ${expectedChars} lowercase hex characters`);
  }
  return text;
}

export function normalizeFlexibleHex(value, field, expectedChars) {
  const text = String(value || '').trim().toLowerCase();
  if (text.length !== expectedChars || !/^[0-9a-f]+$/.test(text)) {
    throw usage(`${field} must be ${expectedChars} hex characters`);
  }
  return text;
}

export function normalizeRequiredPolicyLevel(value, field = '--required-policy-level') {
  const text = String(value || '').trim();
  if (!AUTH_POLICY_LEVELS.includes(text)) {
    throw usage(`${field} must be one of ${AUTH_POLICY_LEVELS.join(', ')}`);
  }
  return text;
}

export function normalizeExpectedEd25519Signer(value, field = '--ed25519-signer') {
  const text = String(value || '').trim();
  if (!text) return '';
  try {
    return validateStellarEd25519PublicAddress(text);
  } catch (error) {
    throw usage(`${field} must be a valid Stellar Ed25519 public address: ${error?.message || error}`);
  }
}

export function parseSingleFileCommandArgs(command, args) {
  if (args.length === 0 || args[0] === '--json') {
    throw new Error(`${command} requires <artifact-file>`);
  }
  const filePath = args[0];
  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--json') {
      continue;
    }
    throw new Error(`Unknown ${command} option: ${arg}`);
  }
  return { filePath };
}
