import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runCanonicalizeCommand, runQvCli } from '../../src/core/cli/qv.js';
import { assertNoSymlinkPath } from '../../src/core/cli/lib/io.js';

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

async function runJsonCommand(args, options = {}) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, { stdout, stderr, ...options });
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

function assertStableEnvelopePrefix(json, expectedOk) {
  assert.deepEqual(Object.keys(json).slice(0, 3), ['command', 'ok', 'cliSchemaVersion']);
  if (typeof expectedOk === 'boolean') {
    assert.equal(json.ok, expectedOk);
  }
}

test('inspect --json emits stable CLI envelope', async () => {
  const result = await runJsonCommand(['inspect', archiveStateFixture, '--json']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'inspect');
  assertStableEnvelopePrefix(result.json, true);
  assert.equal(result.json.ok, true);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.artifactType, 'archive-state-descriptor/v1');
  assert.equal(result.json.digestAlg, 'SHA3-512');
  assert.equal(result.stdoutText.endsWith('\n'), true);
});

test('inspect accepts --json before the artifact path', async () => {
  const result = await runJsonCommand(['inspect', '--json', archiveStateFixture]);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'inspect');
  assert.equal(result.json.ok, true);
  assert.equal(result.json.artifactType, 'archive-state-descriptor/v1');
});

test('canonicalize accepts --json before the artifact path', async () => {
  const result = await runJsonCommand(['canonicalize', '--json', archiveStateFixture]);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'canonicalize');
  assert.equal(result.json.ok, true);
  assert.equal(typeof result.json.canonicalJsonText, 'string');
});

test('verify accepts --json before the archive-state path', async () => {
  const archiveStatePath = await createCanonicalArchiveStateFixture();
  const result = await runJsonCommand(['verify', '--json', archiveStatePath]);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'verify');
  assert.equal(result.json.ok, false);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.policy.level, 'unresolved');
});

test('global --json is accepted before the command', async () => {
  const result = await runJsonCommand(['--json', 'version']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'version');
});

test('canonicalize --json emits stable CLI envelope', async () => {
  const result = await runJsonCommand(['canonicalize', archiveStateFixture, '--json']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderrText, '');
  assert.equal(result.json.command, 'canonicalize');
  assertStableEnvelopePrefix(result.json, true);
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
  assertStableEnvelopePrefix(result.json, false);
  assert.equal(result.json.ok, false);
  assert.equal(result.json.cliSchemaVersion, 1);
  assert.equal(result.json.policy?.satisfied, false);
});

test('JSON errors include schema version and qvCode', async () => {
  const result = await runJsonCommand(['inspect', '--json']);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stderrText, '');
  assertStableEnvelopePrefix(result.json, false);
  assert.deepEqual(result.json, {
    command: 'inspect',
    ok: false,
    cliSchemaVersion: 1,
    error: 'inspect requires <artifact-file>',
    qvCode: 'UNEXPECTED',
  });
});

test('root-level symlink path components keep the documented macOS /tmp carve-out narrow', async () => {
  const tmpStats = await lstat('/tmp');
  if (!tmpStats.isSymbolicLink()) {
    return;
  }

  const dir = await mkdtemp('/tmp/qv-cli-root-symlink-');
  const archivePath = join(dir, 'archive-state.json');
  await writeFile(archivePath, await readFile(archiveStateFixture));

  await assert.doesNotReject(assertNoSymlinkPath(archivePath));

  const etcStats = await lstat('/etc');
  if (etcStats.isSymbolicLink()) {
    await assert.rejects(
      assertNoSymlinkPath('/etc/hosts'),
      /Refusing to read symlink without --allow-symlink: \/etc/,
    );
  }
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

  const version = await runJsonCommand(['--no-color', '--quiet', '--color', 'version', '--json']);
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

  const allowed = await runJsonCommand(['--allow-symlink', 'inspect', linkPath, '--json']);
  assert.equal(allowed.exitCode, 0);
  assert.equal(allowed.json.artifactType, 'archive-state-descriptor/v1');
});

test('a command option value cannot enable the global symlink policy', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qv-cli-symlink-value-'));
  const linkPath = join(dir, 'archive-state.link.json');
  await symlink(join(process.cwd(), archiveStateFixture), linkPath);

  const result = await runJsonCommand([
    'verify',
    linkPath,
    '--bundle',
    '--allow-symlink',
    '--json',
  ]);
  assert.equal(result.exitCode, 2);
  assert.equal(result.json.qvCode, 'USAGE');
  assert.match(result.json.error, /Refusing to read symlink/);
});

test('filesystem exit classification is independent of cwd text', async () => {
  const root = await mkdtemp(join(tmpdir(), 'qv-cli-exit-cwd-'));
  const cwdA = join(root, 'aa');
  const cwdRs = join(root, 'dirs');
  await mkdir(cwdA);
  await mkdir(cwdRs);

  for (const cwd of [cwdA, cwdRs]) {
    const result = await runJsonCommand(
      ['restore', '--shards', 'missing.qcont', '--json'],
      { cwd },
    );
    assert.equal(result.exitCode, 1, cwd);
    assert.equal(result.json.qvCode, 'INPUT_IO_FAILED', cwd);
  }
});

test('symlinked parent path components fail closed unless --allow-symlink is explicit', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qv-cli-symlink-parent-'));
  const realDir = join(dir, 'real');
  const linkDir = join(dir, 'linked');
  await mkdir(realDir);
  const archivePath = join(realDir, 'archive-state.json');
  await writeFile(archivePath, await readFile(archiveStateFixture));
  await symlink(realDir, linkDir);
  const linkedArchivePath = join(linkDir, 'archive-state.json');

  const refused = await runJsonCommand(['inspect', linkedArchivePath, '--json']);
  assert.equal(refused.exitCode, 2);
  assert.equal(refused.json.qvCode, 'USAGE');
  assert.match(refused.json.error, /Refusing to read symlink/);

  const allowed = await runJsonCommand(['--allow-symlink', 'inspect', linkedArchivePath, '--json']);
  assert.equal(allowed.exitCode, 0);
  assert.equal(allowed.json.artifactType, 'archive-state-descriptor/v1');
});
