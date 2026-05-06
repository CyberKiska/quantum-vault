import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runCanonicalizeCommand, runQvCli } from '../../src/core/cli/qv.js';

const archiveStateFixture = 'docs/schema/fixtures/qv-archive-state-descriptor-v1.valid.json';

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

async function runJsonCommand(args) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, { stdout, stderr });
  const stdoutText = stdout.text();
  return {
    exitCode,
    stdoutText,
    stderrText: stderr.text(),
    json: stdoutText ? JSON.parse(stdoutText) : null,
  };
}

async function createCanonicalArchiveStateFixture() {
  const dir = await mkdtemp(join(tmpdir(), 'qv-cli-json-'));
  const report = await runCanonicalizeCommand(archiveStateFixture);
  const filePath = join(dir, 'archive-state.json');
  await writeFile(filePath, Buffer.from(report.canonicalBytes));
  return filePath;
}

test('inspect --json emits stable CLI envelope', async () => {
  const result = await runJsonCommand(['inspect', archiveStateFixture, '--json']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'inspect');
  assert.equal(result.json.ok, true);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.artifactType, 'archive-state-descriptor/v1');
  assert.equal(result.json.digestAlg, 'SHA3-512');
  assert.equal(result.stdoutText.endsWith('\n'), true);
});

test('canonicalize --json emits stable CLI envelope', async () => {
  const result = await runJsonCommand(['canonicalize', archiveStateFixture, '--json']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'canonicalize');
  assert.equal(result.json.ok, true);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.artifactType, 'archive-state-descriptor/v1');
  assert.equal(typeof result.json.canonicalJsonText, 'string');
});

test('verify --json preserves policy exit semantics inside the envelope', async () => {
  const canonicalArchiveStatePath = await createCanonicalArchiveStateFixture();
  const result = await runJsonCommand(['verify', canonicalArchiveStatePath, '--json']);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'verify');
  assert.equal(result.json.ok, false);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.policy?.satisfied, false);
});

test('JSON errors include schema version and qvCode', async () => {
  const result = await runJsonCommand(['inspect', '--json']);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stderrText, '');
  assert.deepEqual(result.json, {
    command: 'inspect',
    ok: false,
    cliSchemaVersion: 1,
    error: 'inspect requires <artifact-file>',
    qvCode: 'UNEXPECTED',
  });
});

test('non-JSON errors use the centralized CLI formatter', async () => {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(['inspect'], { stdout, stderr });
  assert.equal(exitCode, 1);
  assert.equal(stdout.text(), '');
  assert.equal(stderr.text(), 'qv: inspect: inspect requires <artifact-file>\n');
});
