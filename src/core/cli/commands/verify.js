import { verifyArchiveAuthenticity } from '../../crypto/qcont/restore.js';
import { takeValue } from '../lib/args.js';
import {
  makeExternalArtifactRecord,
  readBytesFromFile,
  readOptionalBytes,
} from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';

const POLICY_STRENGTH = Object.freeze({
  'integrity-only': 0,
  'any-signature': 1,
  'strong-pq-signature': 2,
});

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

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
    throw usage('verify requires <archive-state.json>');
  }
  const archiveStatePath = args[0];
  const options = {
    archiveStatePath,
    bundlePath: null,
    signaturePaths: [],
    pqpkPaths: [],
    otsPaths: [],
    expectedEd25519Signer: '',
    includeDetachedSummary: false,
    requiredPolicyLevel: '',
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
      case '--include-detached-summary':
        options.includeDetachedSummary = true;
        break;
      case '--required-policy-level':
        options.requiredPolicyLevel = normalizePolicyLevel(takeValue(args, index, arg), '--required-policy-level');
        index += 1;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw usage(`Unknown verify option: ${arg}`);
    }
  }
  return options;
}

function normalizePolicyLevel(value, field) {
  const text = String(value || '').trim();
  if (!Object.hasOwn(POLICY_STRENGTH, text)) {
    throw usage(`${field} must be one of integrity-only, any-signature, strong-pq-signature`);
  }
  return text;
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
  const authenticity = await verifyArchiveInputs(inputs);
  return buildVerifyReport(authenticity, options);
}

function buildDetachedSummary(authenticity) {
  const artifacts = Array.isArray(authenticity?.verification?.signatureArtifacts)
    ? authenticity.verification.signatureArtifacts
    : [];
  return artifacts.map((artifact) => ({
    id: artifact.id || null,
    name: artifact.name || null,
    source: artifact.source || null,
    family: artifact.family || null,
    format: artifact.format || null,
    ok: artifact.ok === true,
    targetType: artifact.targetType || null,
    targetRef: artifact.targetRef || null,
    signatureContentDigestHex: artifact.signatureContentDigestHex || null,
    proofIdentityDigestHex: artifact.proofIdentityDigestHex || null,
    otsStampedDigestHex: artifact.otsStampedDigestHex || null,
    transitionIndex: Number.isInteger(artifact.transitionIndex) ? artifact.transitionIndex : null,
    maintenancePurposeLabels: Array.isArray(artifact.maintenancePurposeLabels)
      ? [...artifact.maintenancePurposeLabels]
      : [],
  }));
}

function evaluateRequiredPolicy(authenticity, requiredPolicyLevel) {
  if (!requiredPolicyLevel) return null;
  const declaredLevel = String(authenticity?.policy?.level || '');
  const declaredStrength = POLICY_STRENGTH[declaredLevel];
  const requiredStrength = POLICY_STRENGTH[requiredPolicyLevel];
  const declaredKnown = Number.isInteger(declaredStrength);
  const declaredAtLeastRequired = declaredKnown && declaredStrength >= requiredStrength;
  const archivePolicySatisfied = authenticity?.policy?.satisfied === true;
  const satisfied = archivePolicySatisfied && declaredAtLeastRequired;
  return {
    level: requiredPolicyLevel,
    declaredPolicyLevel: declaredLevel || 'unknown',
    declaredPolicySatisfiesRequired: declaredAtLeastRequired,
    archivePolicySatisfied,
    satisfied,
    reason: satisfied
      ? `Archive policy satisfies required policy level ${requiredPolicyLevel}.`
      : (
          archivePolicySatisfied
            ? `Archive policy level ${declaredLevel || 'unknown'} is weaker than required policy level ${requiredPolicyLevel}.`
            : `Archive policy did not satisfy its declared level ${declaredLevel || 'unknown'}.`
        ),
  };
}

export function buildVerifyReport(authenticity, options = {}) {
  const requiredPolicy = evaluateRequiredPolicy(authenticity, options.requiredPolicyLevel);
  const report = {
    ...authenticity,
  };
  if (requiredPolicy) {
    report.requiredPolicy = requiredPolicy;
  }
  if (options.includeDetachedSummary) {
    report.detachedSummary = buildDetachedSummary(authenticity);
  }
  return report;
}

export function verifyReportSatisfied(report) {
  return (
    report?.policy?.satisfied === true &&
    report?.requiredPolicy?.satisfied !== false
  );
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
  if (authenticity?.requiredPolicy) {
    lines.push(`Required policy: ${authenticity.requiredPolicy.level} (${authenticity.requiredPolicy.satisfied ? 'satisfied' : 'not satisfied'})`);
  }
  if (Array.isArray(authenticity?.detachedSummary)) {
    lines.push(`Detached summary entries: ${authenticity.detachedSummary.length}`);
  }
  for (const warning of authenticity?.warnings || []) {
    lines.push(`Warning: ${warning}`);
  }
  return `${lines.join('\n')}\n`;
}
