import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildSuccessorInspectorShard,
  buildSuccessorSelectionChangeDetail,
} from '../../src/core/features/qcont/successor-selection-ui.js';

test('successor selection events expose an allowlisted summary rather than retained shard state', () => {
  const privateFingerprintCanary = 'a5'.repeat(64);
  const detail = buildSuccessorSelectionChangeDetail('restore', {
    mode: 'successor',
    selectionRequired: true,
    selectionComplete: false,
    successorSelectionUiMode: 'ambiguous',
    selectedArchiveId: '11'.repeat(32),
    selectedStateId: '22'.repeat(64),
    selectedCohortId: '33'.repeat(64),
    selectedLifecycleBundleDigestHex: '44'.repeat(64),
    parsedSuccessorShards: [{ metaJSON: { privateKeyHash: privateFingerprintCanary } }],
    files: [{ name: 'PRIVATE_FILENAME_CANARY.qcont' }],
    actionButton: { textContent: privateFingerprintCanary },
  });

  assert.deepEqual(Object.keys(detail).sort(), ['prefix', 'selection']);
  assert.deepEqual(Object.keys(detail.selection).sort(), [
    'mode',
    'selectedArchiveId',
    'selectedCohortId',
    'selectedLifecycleBundleDigestHex',
    'selectedStateId',
    'selectionComplete',
    'selectionRequired',
    'successorSelectionUiMode',
  ]);
  assert.equal(JSON.stringify(detail).includes(privateFingerprintCanary), false);
  assert.equal(JSON.stringify(detail).includes('PRIVATE_FILENAME_CANARY'), false);
});

test('successor inspector state retains only the metadata fields it renders', () => {
  const privateFingerprintCanary = 'b6'.repeat(64);
  const inspectorShard = buildSuccessorInspectorShard({
    sourceFileName: 'shard-1.qcont',
    archiveState: { archiveId: 'archive-id' },
    stateId: 'state-id',
    cohortId: 'cohort-id',
    lifecycleBundleDigestHex: 'bundle-digest',
    lifecycleBundle: { schema: 'QV-Lifecycle-Bundle' },
    metaJSON: {
      archiveId: 'archive-id',
      stateId: 'state-id',
      cohortId: 'cohort-id',
      n: 5,
      t: 4,
      privateKeyHash: privateFingerprintCanary,
      qencHash: 'c7'.repeat(64),
      keyCommitmentHex: 'd8'.repeat(32),
    },
  });

  assert.deepEqual(Object.keys(inspectorShard.metaJSON).sort(), [
    'archiveId',
    'cohortId',
    'n',
    'stateId',
    't',
  ]);
  assert.equal(JSON.stringify(inspectorShard).includes(privateFingerprintCanary), false);
});
