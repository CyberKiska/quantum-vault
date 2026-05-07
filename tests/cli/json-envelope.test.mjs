import assert from 'node:assert/strict';
import { mkdtemp, symlink, writeFile } from 'node:fs/promises';
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

test('command help and global color/quiet flags are accepted without parser errors', async () => {
  async function runRaw(args) {
    const stdout = createCaptureStream();
    const stderr = createCaptureStream();
    const exitCode = await runQvCli(args, { stdout, stderr });
    return { exitCode, stdoutText: stdout.text(), stderrText: stderr.text() };
  }

  for (const command of [
    'keygen',
    'encrypt',
    'decrypt',
    'split',
    'attach',
    'reshare',
    'inspect',
    'canonicalize',
    'verify',
    'restore',
    'selftest',
    'version',
  ]) {
    const direct = await runRaw([command, '--help']);
    assert.equal(direct.exitCode, 0, command);
    assert.equal(direct.stderrText, '', command);
    assert.match(direct.stdoutText, new RegExp(`Usage: qv ${command}`), command);

    const viaHelp = await runRaw(['help', command]);
    assert.equal(viaHelp.exitCode, 0, command);
    assert.equal(viaHelp.stderrText, '', command);
    assert.equal(viaHelp.stdoutText, direct.stdoutText, command);
  }

  const version = await runJsonCommand(['--no-color', '--quiet', 'version', '--color', '--json']);
  assert.equal(version.exitCode, 0);
  assert.equal(version.stderrText, '');
  assert.equal(version.json.command, 'version');
});

test('direct symlink inputs fail closed unless --allow-symlink is explicit', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qv-cli-symlink-'));
  const linkPath = join(dir, 'archive-state.link.json');
  await symlink(join(process.cwd(), archiveStateFixture), linkPath);

  const refused = await runJsonCommand(['inspect', linkPath, '--json']);
  assert.equal(refused.exitCode, 2);
  assert.equal(refused.json.qvCode, 'USAGE');
  assert.match(refused.json.error, /Refusing to read symlink/);

  const allowed = await runJsonCommand(['inspect', linkPath, '--allow-symlink', '--json']);
  assert.equal(allowed.exitCode, 0);
  assert.equal(allowed.json.artifactType, 'archive-state-descriptor/v1');
});
