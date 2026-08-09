import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveExternallyFixedSuccessorSelection } from '../../src/core/features/qcont/successor-selection-ui.js';

const archiveId = '11'.repeat(32);
const stateId = '22'.repeat(64);
const cohortId = '33'.repeat(64);
const model = {
  states: [{
    key: `${archiveId}:${stateId}`,
    archiveId,
    stateId,
    cohorts: [{ cohortId }],
  }],
};

function archiveStateView(overrides = {}) {
  return {
    archiveState: { archiveId: overrides.archiveId || archiveId },
    digest: { value: overrides.stateId || stateId },
  };
}

function lifecycleBundleView(overrides = {}) {
  return {
    ...archiveStateView(overrides),
    cohortId: overrides.cohortId || cohortId,
  };
}

test('external archive-state and lifecycle selectors must be members of the loaded shard model', () => {
  assert.deepEqual(resolveExternallyFixedSuccessorSelection(model, {
    uploadedArchiveState: archiveStateView(),
  }), {
    stateKey: `${archiveId}:${stateId}`,
    cohortId: null,
  });
  assert.deepEqual(resolveExternallyFixedSuccessorSelection(model, {
    uploadedLifecycleBundle: lifecycleBundleView(),
  }), {
    stateKey: `${archiveId}:${stateId}`,
    cohortId,
  });

  assert.throws(
    () => resolveExternallyFixedSuccessorSelection(model, {
      uploadedArchiveState: archiveStateView({ stateId: '44'.repeat(64) }),
    }),
    /archive-state descriptor does not match/
  );
  assert.throws(
    () => resolveExternallyFixedSuccessorSelection(model, {
      uploadedLifecycleBundle: lifecycleBundleView({ cohortId: '55'.repeat(64) }),
    }),
    /lifecycle bundle does not match any loaded successor shard cohort/
  );
});

test('external lifecycle bundle and archive-state descriptor cannot select different states', () => {
  const secondStateId = '66'.repeat(64);
  const extendedModel = {
    states: [
      ...model.states,
      {
        key: `${archiveId}:${secondStateId}`,
        archiveId,
        stateId: secondStateId,
        cohorts: [{ cohortId: '77'.repeat(64) }],
      },
    ],
  };
  assert.throws(
    () => resolveExternallyFixedSuccessorSelection(extendedModel, {
      uploadedArchiveState: archiveStateView(),
      uploadedLifecycleBundle: lifecycleBundleView({ stateId: secondStateId, cohortId: '77'.repeat(64) }),
    }),
    /select different archive states/
  );
});
