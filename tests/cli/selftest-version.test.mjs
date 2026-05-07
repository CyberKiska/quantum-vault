import assert from 'node:assert/strict';
import test from 'node:test';
import { runQvCli } from '../../src/core/cli/qv.js';

function createCaptureStream() {
  const chunks = [];
  return {
    write(chunk) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return true;
    },
    text() {
      return Buffer.concat(chunks).toString('utf8');
    },
  };
}

async function runCli(args) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, { stdout, stderr });
  return {
    exitCode,
    stdoutText: stdout.text(),
    stderrText: stderr.text(),
    json: stdout.text() ? JSON.parse(stdout.text()) : null,
  };
}

test('selftest --json emits stable filtered report shape', async () => {
  const result = await runCli([
    'selftest',
    '--filter',
    'RFC 8785 number serialization reference vectors',
    '--json',
  ]);

  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'selftest');
  assert.equal(result.json.ok, true);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.filter, 'RFC 8785 number serialization reference vectors');
  assert.equal(result.json.total, 1);
  assert.equal(result.json.passed, 1);
  assert.equal(result.json.failed, 0);
  assert.equal(result.json.results.length, 1);
  assert.equal(result.json.results[0].ok, true);
  assert.match(result.json.results[0].name, /RFC 8785 number serialization reference vectors/);
});

test('selftest rejects unmatched filters as usage errors', async () => {
  const result = await runCli(['selftest', '--filter', 'no-such-selftest-case', '--json']);
  assert.equal(result.exitCode, 2);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'selftest');
  assert.equal(result.json.ok, false);
  assert.equal(result.json.qvCode, 'USAGE');
});

test('version --json emits package and registered format metadata', async () => {
  const result = await runCli(['version', '--json']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'version');
  assert.equal(result.json.ok, true);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.version, '2.1.1');
  assert.equal(result.json.format.qenc, 'QVv1-5-0');
  assert.equal(result.json.format.qcont, 'QVqcont-7');
  assert.equal(result.json.format.lifecycleBundle, 'QV-Lifecycle-Bundle/v1');
  assert.equal(result.json.format.archiveState, 'quantum-vault-archive-state-descriptor/v1');
  assert.equal(result.json.format.cohortBinding, 'quantum-vault-cohort-binding/v1');
  assert.equal(result.json.format.transitionRecord, 'quantum-vault-transition-record/v1');
  assert.equal(result.json.format.sourceEvidence, 'quantum-vault-source-evidence/v1');
  assert.deepEqual(result.json.alg, {
    KEM: 'ML-KEM-1024',
    KDF: 'KMAC256',
    AEAD: 'AES-256-GCM',
    digest: ['SHA3-512', 'SHA3-256'],
  });
  assert.equal(result.json.cryptoProfileId, 'QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2');
});
