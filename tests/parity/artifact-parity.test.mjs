import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { runCanonicalizeCommand, runInspectCommand, runQvCli } from '../../src/core/cli/qv.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { canonicalizeJsonToBytes } from '../../src/core/crypto/manifest/jcs.js';

const schemaDir = path.resolve('docs/schema');
const fixturesIndexPath = path.join(schemaDir, 'fixtures/index.json');
const corpusDir = path.join(schemaDir, 'corpus');

function createCaptureStream() {
  const chunks = [];
  return {
    write(chunk) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return true;
    },
    bytes() {
      return Buffer.concat(chunks);
    },
    text() {
      return this.bytes().toString('utf8');
    },
  };
}

async function runCli(args) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, { stdout, stderr });
  return {
    exitCode,
    stdoutBytes: stdout.bytes(),
    stdoutText: stdout.text(),
    stderrText: stderr.text(),
    json: stdout.text() ? JSON.parse(stdout.text()) : null,
  };
}

async function listJsonFiles(dir) {
  const files = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listJsonFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      files.push(fullPath);
    }
  }
  return files;
}

function decodeCaseBytes(corpusCase) {
  assert.equal(corpusCase.encoding, 'base64');
  return Uint8Array.from(Buffer.from(corpusCase.bytes, 'base64'));
}

function digestHex(bytes) {
  return toHex(sha3_512(bytes));
}

function jsonClone(value) {
  return JSON.parse(JSON.stringify(value));
}

test('schema JSON fixtures canonicalize byte-identically through CLI and core', async () => {
  const index = JSON.parse(await readFile(fixturesIndexPath, 'utf8'));
  const runtimeValidFixtures = index.fixtures.filter((fixture) => (
    fixture.expectSchemaValid === true &&
    fixture.runtime?.expectParseSuccess === true &&
    typeof fixture.expectedDigestHex === 'string'
  ));

  assert(runtimeValidFixtures.length > 0, 'expected runtime-valid schema fixtures');

  for (const fixture of runtimeValidFixtures) {
    const filePath = path.join(schemaDir, fixture.file);
    const instance = JSON.parse(await readFile(filePath, 'utf8'));
    const expectedCanonicalBytes = canonicalizeJsonToBytes(instance);
    const expectedCanonicalText = new TextDecoder().decode(expectedCanonicalBytes);
    const expectedDigestHex = digestHex(expectedCanonicalBytes);

    const rawCanonical = await runCli(['canonicalize', filePath]);
    assert.equal(rawCanonical.exitCode, 0, fixture.id);
    assert.equal(rawCanonical.stderrText, '', fixture.id);
    assert.deepEqual(rawCanonical.stdoutBytes, Buffer.from(expectedCanonicalBytes), fixture.id);

    const canonicalJson = await runCli(['canonicalize', filePath, '--json']);
    assert.equal(canonicalJson.exitCode, 0, fixture.id);
    assert.equal(canonicalJson.stderrText, '', fixture.id);
    assert.equal(canonicalJson.json.command, 'canonicalize', fixture.id);
    assert.equal(canonicalJson.json.ok, true, fixture.id);
    assert.equal(canonicalJson.json.cliSchemaVersion, 1, fixture.id);
    assert.equal(canonicalJson.json.digestHex, fixture.expectedDigestHex, fixture.id);
    assert.equal(canonicalJson.json.digestHex, expectedDigestHex, fixture.id);
    assert.equal(canonicalJson.json.canonicalJsonText, expectedCanonicalText, fixture.id);

    const inspectJson = await runCli(['inspect', filePath, '--json']);
    assert.equal(inspectJson.exitCode, 0, fixture.id);
    assert.equal(inspectJson.stderrText, '', fixture.id);
    assert.equal(inspectJson.json.command, 'inspect', fixture.id);
    assert.equal(inspectJson.json.ok, true, fixture.id);
    assert.equal(inspectJson.json.cliSchemaVersion, 1, fixture.id);
    assert.equal(inspectJson.json.digestHex, expectedDigestHex, fixture.id);
    assert.equal(inspectJson.json.canonicalJsonText, expectedCanonicalText, fixture.id);

    const coreCanonical = await runCanonicalizeCommand(filePath);
    const coreInspect = await runInspectCommand(filePath);
    assert.deepEqual(canonicalJson.json.canonicalJson, jsonClone(coreCanonical.canonicalJson), fixture.id);
    assert.deepEqual(inspectJson.json.canonicalJson, jsonClone(coreInspect.canonicalJson), fixture.id);
  }
});

test('binary corpus fixtures inspect through the CLI envelope with core parity', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'qv-parity-corpus-'));
  const corpusFiles = await listJsonFiles(corpusDir);
  assert(corpusFiles.length > 0, 'expected binary corpus fixtures');

  for (const corpusPath of corpusFiles) {
    const corpusCase = JSON.parse(await readFile(corpusPath, 'utf8'));
    const bytes = decodeCaseBytes(corpusCase);
    const artifactPath = path.join(tempDir, `${corpusCase.id}.artifact`);
    await writeFile(artifactPath, bytes);

    const inspected = await runCli(['inspect', artifactPath, '--json']);
    if (corpusCase.valid === true) {
      assert.equal(inspected.exitCode, 0, corpusCase.id);
      assert.equal(inspected.stderrText, '', corpusCase.id);
      assert.equal(inspected.json.command, 'inspect', corpusCase.id);
      assert.equal(inspected.json.ok, true, corpusCase.id);
      assert.equal(inspected.json.cliSchemaVersion, 1, corpusCase.id);
      assert.equal(inspected.json.artifactType, corpusCase.artifactType, corpusCase.id);
      assert.equal(inspected.json.digestAlg, 'SHA3-512', corpusCase.id);
      assert.equal(inspected.json.digestHex, corpusCase.expectedDigest, corpusCase.id);

      const coreInspect = await runInspectCommand(artifactPath);
      assert.equal(inspected.json.artifactVersion, coreInspect.artifactVersion, corpusCase.id);
      assert.deepEqual(inspected.json.parsedSummary ?? null, coreInspect.parsedSummary ?? null, corpusCase.id);
      continue;
    }

    assert.equal(inspected.stderrText, '', corpusCase.id);
    assert.equal(inspected.json.command, 'inspect', corpusCase.id);
    assert.equal(inspected.json.cliSchemaVersion, 1, corpusCase.id);
    if (inspected.exitCode === 0) {
      assert.equal(inspected.json.ok, true, corpusCase.id);
      assert.equal(inspected.json.artifactType, corpusCase.artifactType, corpusCase.id);
      assert.equal(inspected.json.digestAlg, 'SHA3-512', corpusCase.id);
      assert.equal(inspected.json.digestHex, corpusCase.expectedDigest, corpusCase.id);
    } else {
      assert.equal(inspected.json.ok, false, corpusCase.id);
      assert.equal(typeof inspected.json.qvCode, 'string', corpusCase.id);
      assert.equal(typeof inspected.json.error, 'string', corpusCase.id);
    }
  }
});
