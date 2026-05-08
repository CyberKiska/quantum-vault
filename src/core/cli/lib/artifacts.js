import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../crypto/bytes.js';
import {
  canonicalizeArchiveStateDescriptor,
  canonicalizeCohortBinding,
  canonicalizeLifecycleBundle,
  canonicalizeSourceEvidence,
  canonicalizeTransitionRecord,
} from '../../crypto/lifecycle/artifacts.js';

export const JSON_ARTIFACT_DESCRIPTORS = Object.freeze({
  'quantum-vault-archive-state-descriptor/v1': {
    artifactType: 'archive-state-descriptor/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeArchiveStateDescriptor,
    objectField: 'archiveState',
  },
  'quantum-vault-cohort-binding/v1': {
    artifactType: 'cohort-binding/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeCohortBinding,
    objectField: 'cohortBinding',
  },
  'quantum-vault-transition-record/v1': {
    artifactType: 'transition-record/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeTransitionRecord,
    objectField: 'transitionRecord',
  },
  'quantum-vault-source-evidence/v1': {
    artifactType: 'source-evidence/v1',
    artifactVersion: 'v1',
    canonicalize: canonicalizeSourceEvidence,
    objectField: 'sourceEvidence',
  },
});

export function digestSha3_512Hex(bytes) {
  return toHex(sha3_512(bytes));
}

export function classifyJsonArtifactObject(value) {
  const schema = String(value?.schema || '').trim();
  if (JSON_ARTIFACT_DESCRIPTORS[schema]) {
    return JSON_ARTIFACT_DESCRIPTORS[schema];
  }
  if (value?.type === 'QV-Lifecycle-Bundle') {
    return {
      artifactType: 'lifecycle-bundle/v1',
      artifactVersion: 'v1',
      canonicalize: canonicalizeLifecycleBundle,
      objectField: 'lifecycleBundle',
    };
  }
  return null;
}
