import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ARCHIVE_STATE_SCHEMA,
  COHORT_BINDING_SCHEMA,
  LIFECYCLE_BUNDLE_TYPE,
  LIFECYCLE_BUNDLE_VERSION,
  SOURCE_EVIDENCE_SCHEMA,
  TRANSITION_RECORD_SCHEMA,
} from '../../crypto/lifecycle/artifacts.js';
import { LIFECYCLE_QCONT_FORMAT_VERSION } from '../../crypto/qcont/lifecycle-shard.js';
import { CRYPTO_PROFILE_ID_V2 } from '../../crypto/policy.js';
import { FORMAT_VERSION } from '../../crypto/constants.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../../..');

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

export function parseVersionArgs(args) {
  const options = { json: false };
  for (const arg of args) {
    switch (arg) {
      case '--json':
        options.json = true;
        break;
      default:
        throw usage(`Unknown version option: ${arg}`);
    }
  }
  return options;
}

async function readPackageVersion() {
  const packageJson = JSON.parse(await readFile(path.join(repoRoot, 'package.json'), 'utf8'));
  return String(packageJson.version || '');
}

export async function runVersionCommand() {
  return {
    command: 'version',
    version: await readPackageVersion(),
    format: {
      qenc: FORMAT_VERSION,
      qcont: LIFECYCLE_QCONT_FORMAT_VERSION,
      lifecycleBundle: `${LIFECYCLE_BUNDLE_TYPE}/v${LIFECYCLE_BUNDLE_VERSION}`,
      archiveState: ARCHIVE_STATE_SCHEMA,
      cohortBinding: COHORT_BINDING_SCHEMA,
      transitionRecord: TRANSITION_RECORD_SCHEMA,
      sourceEvidence: SOURCE_EVIDENCE_SCHEMA,
    },
    alg: {
      KEM: 'ML-KEM-1024',
      KDF: 'KMAC256',
      AEAD: 'AES-256-GCM',
      digest: ['SHA3-512', 'SHA3-256'],
    },
    cryptoProfileId: CRYPTO_PROFILE_ID_V2,
  };
}

export function renderVersionSummary(report) {
  return [
    `Quantum Vault ${report.version}`,
    `QENC: ${report.format.qenc}`,
    `QCONT: ${report.format.qcont}`,
    `Lifecycle bundle: ${report.format.lifecycleBundle}`,
    `Crypto profile: ${report.cryptoProfileId}`,
    '',
  ].join('\n');
}
