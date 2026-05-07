import assert from 'node:assert/strict';
import test from 'node:test';

const commandContracts = Object.freeze([
  {
    modulePath: '../../src/core/cli/commands/inspect.js',
    exports: ['parseInspectArgs', 'renderInspectSummary', 'runInspectCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/keygen.js',
    exports: ['parseKeygenArgs', 'renderKeygenSummary', 'runKeygenCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/canonicalize.js',
    exports: ['createCanonicalizeJsonReport', 'parseCanonicalizeArgs', 'runCanonicalizeCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/verify.js',
    exports: ['buildVerifyReport', 'parseVerifyArgs', 'renderVerifySummary', 'runVerifyCommand', 'verifyArchiveInputs', 'verifyReportSatisfied'],
  },
  {
    modulePath: '../../src/core/cli/commands/selftest.js',
    exports: ['parseSelftestArgs', 'renderSelftestSummary', 'runSelftestCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/version.js',
    exports: ['parseVersionArgs', 'renderVersionSummary', 'runVersionCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/restore.js',
    exports: ['parseRestoreArgs', 'renderRestoreSummary', 'restoreDryRunFromInputs', 'runRestoreCommand', 'runRestoreDryRunCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/split.js',
    exports: ['parseSplitArgs', 'renderSplitSummary', 'runSplitCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/attach.js',
    exports: ['parseAttachArgs', 'renderAttachSummary', 'runAttachCommand'],
  },
  {
    modulePath: '../../src/core/cli/commands/reshare.js',
    exports: ['parseReshareArgs', 'renderReshareSummary', 'runReshareCommand'],
  },
  {
    modulePath: '../../src/core/cli/lib/exit.js',
    exports: ['getErrorQvCode', 'makeQvError', 'mapErrorToExitCode'],
  },
  {
    modulePath: '../../src/core/cli/lib/json.js',
    exports: ['createJsonError', 'withCliJsonEnvelope', 'writeJson'],
  },
  {
    modulePath: '../../src/core/cli/lib/io.js',
    exports: ['readBytes', 'writeBytesAtomic', 'writeJsonAtomic'],
  },
  {
    modulePath: '../../src/core/cli/lib/secrets.js',
    exports: ['readSecretBytes'],
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

test('CLI exit registry maps explicit qvCode values', async () => {
  const { EXIT, QV_CODE, makeQvError, mapErrorToExitCode } = await import('../../src/core/cli/lib/exit.js');
  assert.equal(mapErrorToExitCode(makeQvError('bad args', QV_CODE.USAGE)), EXIT.USAGE);
  assert.equal(mapErrorToExitCode(makeQvError('ambiguous cohort', QV_CODE.AMBIGUOUS_INPUTS)), EXIT.AMBIGUITY);
  assert.equal(mapErrorToExitCode(new Error('plain error')), EXIT.ERROR);
});

test('top-level CLI module preserves public Phase 1 exports', async () => {
  const moduleExports = await import('../../src/core/cli/qv.js');
  for (const exportName of [
    'restoreDryRunFromInputs',
    'runAttachCommand',
    'runCanonicalizeCommand',
    'runInspectCommand',
    'runQvCli',
    'runReshareCommand',
    'runRestoreCommand',
    'runRestoreDryRunCommand',
    'runSelftestCommand',
    'runSplitCommand',
    'runVersionCommand',
    'runVerifyCommand',
    'verifyReportSatisfied',
    'verifyArchiveInputs',
  ]) {
    assert.equal(typeof moduleExports[exportName], 'function', `qv.js exports ${exportName}`);
  }
});
