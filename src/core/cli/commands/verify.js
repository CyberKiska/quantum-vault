import { verifyArchiveAuthenticity } from '../../crypto/qcont/restore.js';
import { takeValue } from '../lib/args.js';
import {
  makeExternalArtifactRecord,
  readBytesFromFile,
  readOptionalBytes,
} from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';

function formatVerifyStatusMessage(status = {}) {
  if (status.archiveApprovalSignatureVerified !== true) {
    return 'Archive-approval signatures not verified.';
  }
  const details = [];
  if (status.strongPqSignatureVerified === true) details.push('strong PQ present');
  if (status.bundlePinned === true) details.push('bundle pin active');
  if (status.userPinned === true) details.push('user pin matched');
  if (status.signerPinned === true && status.bundlePinned !== true && status.userPinned !== true) {
    details.push('signer pin active');
  }
  return details.length > 0
    ? `Archive-approval signatures verified (${details.join(', ')}).`
    : 'Archive-approval signatures verified.';
}

export function parseVerifyArgs(args) {
  if (args.length === 0) {
    throw new Error('verify requires <archive-state.json>');
  }
  const archiveStatePath = args[0];
  const options = {
    archiveStatePath,
    bundlePath: null,
    signaturePaths: [],
    pqpkPaths: [],
    otsPaths: [],
    expectedEd25519Signer: '',
    json: false,
  };

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--bundle':
        options.bundlePath = takeValue(args, index, arg);
        index += 1;
        break;
      case '--sig':
        options.signaturePaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--pqpk':
        options.pqpkPaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--ots':
        options.otsPaths.push(takeValue(args, index, arg));
        index += 1;
        break;
      case '--ed25519-signer':
        options.expectedEd25519Signer = takeValue(args, index, arg);
        index += 1;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw new Error(`Unknown verify option: ${arg}`);
    }
  }
  return options;
}

export async function readVerificationInputsFromPaths({
  archiveStatePath = null,
  bundlePath = null,
  signaturePaths = [],
  pqpkPaths = [],
  otsPaths = [],
  expectedEd25519Signer = '',
} = {}) {
  const archiveStateBytes = archiveStatePath ? await readBytesFromFile(archiveStatePath) : null;
  const lifecycleBundleBytes = await readOptionalBytes(bundlePath);
  const signatures = await Promise.all(signaturePaths.map(async (filePath) => (
    makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath))
  )));
  const timestamps = await Promise.all(otsPaths.map(async (filePath) => (
    makeExternalArtifactRecord(filePath, await readBytesFromFile(filePath))
  )));
  const pinnedPqPublicKeyFileBytesList = await Promise.all(pqpkPaths.map(readBytesFromFile));

  return {
    archiveStateBytes,
    lifecycleBundleBytes,
    verification: {
      signatures,
      timestamps,
      pinnedPqPublicKeyFileBytesList,
      expectedEd25519Signer: String(expectedEd25519Signer || '').trim(),
    },
  };
}

export async function verifyArchiveInputs({
  archiveStateBytes,
  lifecycleBundleBytes = null,
  verification = {},
} = {}) {
  await ensureRuntimeCrypto();
  return verifyArchiveAuthenticity({
    archiveStateBytes,
    lifecycleBundleBytes,
    verification,
  });
}

export async function runVerifyCommand(options) {
  const inputs = await readVerificationInputsFromPaths(options);
  return verifyArchiveInputs(inputs);
}

export function renderVerifySummary(authenticity) {
  const counts = authenticity?.verification?.counts || {};
  const policy = authenticity?.policy || {};
  const lines = [
    `Policy: ${policy.level || 'unknown'} (${policy.satisfied ? 'satisfied' : 'not satisfied'})`,
    `Reason: ${policy.reason || 'unknown'}`,
    formatVerifyStatusMessage(authenticity?.status || authenticity?.verification?.status || {}),
    `Archive-approval counts: valid=${counts.validArchiveApproval ?? 0}, strong-pq=${counts.validArchiveApprovalStrongPq ?? 0}, pinned=${counts.archiveApprovalPinnedValidTotal ?? 0}`,
    `Detached totals: valid=${counts.validTotal ?? 0}, maintenance=${counts.validMaintenance ?? 0}, source-evidence=${counts.validSourceEvidence ?? 0}`,
  ];
  for (const warning of authenticity?.warnings || []) {
    lines.push(`Warning: ${warning}`);
  }
  return `${lines.join('\n')}\n`;
}
