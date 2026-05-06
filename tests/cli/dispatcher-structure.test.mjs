import assert from 'node:assert/strict';
import test from 'node:test';

const commandContracts = Object.freeze([
  {
    modulePath: '../../src/core/cli/commands/inspect.js',
    exports: ['parseInspectArgs', 'renderInspectSummary', 'runInspectCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/canonicalize.js',
    exports: ['createCanonicalizeJsonReport', 'parseCanonicalizeArgs', 'runCanonicalizeCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/verify.js',
    exports: ['parseVerifyArgs', 'renderVerifySummary', 'runVerifyCommand', 'verifyArchiveInputs'],
  },
  {
    modulePath: '../../src/core/cli/commands/restore-dry-run.js',
    exports: ['parseRestoreArgs', 'renderRestoreSummary', 'restoreDryRunFromInputs', 'runRestoreDryRunCommand'],
  },
]);

test('CLI command modules expose dispatcher contracts', async () => {
  for (const contract of commandContracts) {
    const moduleExports = await import(contract.modulePath);
    for (const exportName of contract.exports) {
      assert.equal(
        typeof moduleExports[exportName],
        'function',
        `${contract.modulePath} exports ${exportName}`,
      );
    }
  }
});

test('top-level CLI module preserves public Phase 1 exports', async () => {
  const moduleExports = await import('../../src/core/cli/qv.js');
  for (const exportName of [
    'restoreDryRunFromInputs',
    'runCanonicalizeCommand',
    'runInspectCommand',
    'runQvCli',
    'runRestoreDryRunCommand',
    'runVerifyCommand',
    'verifyArchiveInputs',
  ]) {
    assert.equal(typeof moduleExports[exportName], 'function', `qv.js exports ${exportName}`);
  }
});
