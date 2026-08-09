import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
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
    exports: ['parseSplitArgs', 'renderSplitInternalHelp', 'renderSplitSummary', 'runSplitCommand'],
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
    exports: ['readBytes', 'runWithIoPolicy', 'writeBytesAtomic', 'writeJsonAtomic'],
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

async function listSourceFiles(dir) {
  const out = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...await listSourceFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      out.push(fullPath);
    }
  }
  return out;
}

test('CLI hardening boundary keeps Node APIs out of core crypto and UI modules out of CLI', async () => {
  for (const filePath of await listSourceFiles('src/core/crypto')) {
    const source = await readFile(filePath, 'utf8');
    assert.equal(/from\s+['"]node:/.test(source), false, `${filePath} imports a node: module`);
  }

  for (const filePath of await listSourceFiles('src/core/cli')) {
    const source = await readFile(filePath, 'utf8');
    assert.equal(/features\/.*-ui\.js/.test(source), false, `${filePath} imports browser UI code`);
  }
});

test('top-level CLI keeps the self-test dependency lazy', async () => {
  const source = await readFile('src/core/cli/qv.js', 'utf8');
  assert.equal(
    /from\s+['"]\.\/commands\/selftest\.js['"]/.test(source),
    false,
    'qv.js must not statically import the self-test graph',
  );
  assert.match(source, /await import\(['"]\.\/commands\/selftest\.js['"]\)/);
});

test('CLI commands use the shared SHA3-512 report digest helper', async () => {
  for (const filePath of await listSourceFiles('src/core/cli/commands')) {
    const source = await readFile(filePath, 'utf8');
    assert.equal(
      /function\s+digestSha3_512Hex\s*\(/.test(source),
      false,
      `${filePath} redeclares digestSha3_512Hex`,
    );
  }
});

test('CLI exit registry maps explicit qvCode values', async () => {
  const { EXIT, QV_CODE, makeQvError, mapErrorToExitCode } = await import('../../src/core/cli/lib/exit.js');
  assert.equal(mapErrorToExitCode(makeQvError('bad args', QV_CODE.USAGE)), EXIT.USAGE);
  assert.equal(mapErrorToExitCode(makeQvError('ambiguous cohort', QV_CODE.AMBIGUOUS_INPUTS)), EXIT.AMBIGUITY);
  assert.equal(EXIT.FORMAT_POLICY, 4);
  assert.equal(
    mapErrorToExitCode(makeQvError('bounded locally', QV_CODE.RESOURCE_LIMIT)),
    EXIT.FORMAT_POLICY,
  );
  assert.equal(
    mapErrorToExitCode(makeQvError('ack', QV_CODE.RESTORE_LIFECYCLE_VARIANT_ACK_REQUIRED)),
    EXIT.RESTORE_VARIANT_ACK,
  );
  assert.equal(
    mapErrorToExitCode(Object.assign(new Error('explicit'), {
      qvCode: QV_CODE.USAGE,
      kind: 'quorum-unreachable',
    })),
    EXIT.USAGE,
  );
  assert.equal(
    mapErrorToExitCode(Object.assign(new Error('structured'), { kind: 'quorum-unreachable' })),
    EXIT.QUORUM,
  );
  assert.equal(mapErrorToExitCode(new Error('plain error')), EXIT.ERROR);
});

test('CLI parsers fail closed on ambiguous selector and policy shapes', async () => {
  const { parseRestoreArgs } = await import('../../src/core/cli/commands/restore.js');
  const { parseReshareArgs } = await import('../../src/core/cli/commands/reshare.js');
  const { parseVerifyArgs } = await import('../../src/core/cli/commands/verify.js');

  assert.throws(
    () => parseRestoreArgs(['--shards', 'cohort/*.qcont', '--archive-id', 'A'.repeat(64)]),
    { qvCode: 'USAGE' },
  );
  assert.throws(
    () => parseRestoreArgs(['--shards', 'cohort/*.qcont', '--state-id', '0'.repeat(127)]),
    { qvCode: 'USAGE' },
  );
  assert.throws(
    () => parseRestoreArgs(['--shards', 'cohort/*.qcont', '--bundle-digest', 'f'.repeat(127)]),
    { qvCode: 'USAGE' },
  );
  assert.throws(
    () => parseRestoreArgs(['--shards', 'cohort/*.qcont', '--ed25519-signer', 'not-a-stellar-address']),
    { qvCode: 'USAGE' },
  );
  assert.throws(
    () => parseRestoreArgs(['--shards', 'cohort/*.qcont', '--required-policy-level', 'weaker-than-known']),
    { qvCode: 'USAGE' },
  );
  assert.throws(
    () => parseVerifyArgs(['archive-state.json', '--required-policy-level', 'weaker-than-known']),
    { qvCode: 'USAGE' },
  );
  assert.throws(
    () => parseVerifyArgs(['archive-state.json', '--ed25519-signer', 'not-a-stellar-address']),
    { qvCode: 'USAGE' },
  );
  assert.throws(
    () => parseReshareArgs(['--shards', 'cohort/*.qcont', '--n', '5', '--k', '3', '--maintenance-pqpk', 'pin.pqpk']),
    { qvCode: 'USAGE' },
  );
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
