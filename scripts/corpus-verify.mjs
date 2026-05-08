import { mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { runSchemaFixtureCheck } from './schema-fixtures.mjs';
import { runQvCli } from '../src/core/cli/qv.js';
import { toHex } from '../src/core/crypto/bytes.js';
import { unpackPqpk, unpackQsig, verifyQsigAgainstBytes } from '../src/core/crypto/auth/qsig.js';
import { parseOpenTimestampProof, resolveOpenTimestampTarget } from '../src/core/crypto/auth/opentimestamps.js';
import { parseLifecycleShard } from '../src/core/crypto/qcont/lifecycle-shard.js';

const thisDir = dirname(fileURLToPath(import.meta.url));
const corpusDir = resolve(thisDir, '../docs/schema/corpus');

function formatError(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function assert(value, message) {
  if (!value) {
    throw new Error(message);
  }
}

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

async function runCliJson(args) {
  const stdout = createCaptureStream();
  const stderr = createCaptureStream();
  const exitCode = await runQvCli(args, { stdout, stderr });
  const stdoutText = stdout.text();
  if (stderr.text() !== '') {
    throw new Error(`qv ${args.join(' ')} emitted stderr in --json mode`);
  }
  let json = null;
  try {
    json = stdoutText ? JSON.parse(stdoutText) : null;
  } catch (error) {
    throw new Error(`qv ${args.join(' ')} emitted non-JSON stdout: ${error?.message || error}`);
  }
  return { exitCode, json };
}

function decodeCaseBytes(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return Uint8Array.from(Buffer.from(value, 'base64'));
}

function decodeOptionalRuntimeBytes(runtime, field) {
  if (!runtime || typeof runtime !== 'object' || runtime[field] == null) {
    return null;
  }
  return decodeCaseBytes(runtime[field], `runtime.${field}`);
}

async function listCorpusFiles(dir) {
  const out = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...await listCorpusFiles(fullPath));
      continue;
    }
    if (entry.isFile() && extname(entry.name) === '.json') {
      out.push(fullPath);
    }
  }
  return out;
}

function ensureExpectedDigest(corpusCase, bytes) {
  assert(corpusCase.encoding === 'base64', `${corpusCase.id}: unsupported encoding ${corpusCase.encoding}`);
  assert(corpusCase.expectedDigestAlg === 'SHA3-512', `${corpusCase.id}: unsupported expectedDigestAlg ${corpusCase.expectedDigestAlg}`);
  const actualDigest = toHex(sha3_512(bytes));
  if (actualDigest !== corpusCase.expectedDigest) {
    throw new Error(`${corpusCase.id}: digest mismatch: expected ${corpusCase.expectedDigest}, got ${actualDigest}`);
  }
}

function artifactFileName(corpusCase) {
  const id = String(corpusCase.id || 'artifact').replace(/[^A-Za-z0-9._-]/g, '_');
  const extensionByType = {
    'QVqcont-7': '.qcont',
    '.qsig': '.qsig',
    '.pqpk': '.pqpk',
    '.ots': '.ots',
  };
  return `${id}${extensionByType[corpusCase.artifactType] || '.bin'}`;
}

async function verifyCliJsonEnvelopeForCorpusCase(corpusCase, bytes, tempDir) {
  const artifactPath = join(tempDir, artifactFileName(corpusCase));
  await writeFile(artifactPath, bytes);

  const inspected = await runCliJson(['inspect', artifactPath, '--json']);
  if (corpusCase.valid === true) {
    assert(inspected.exitCode === 0, `${corpusCase.id}: qv inspect --json exited ${inspected.exitCode}`);
    assert(inspected.json?.command === 'inspect', `${corpusCase.id}: inspect command mismatch`);
    assert(inspected.json?.ok === true, `${corpusCase.id}: inspect ok mismatch`);
    assert(inspected.json?.cliSchemaVersion === 1, `${corpusCase.id}: inspect cliSchemaVersion mismatch`);
    assert(inspected.json?.artifactType === corpusCase.artifactType, `${corpusCase.id}: inspect artifactType mismatch`);
    assert(inspected.json?.digestAlg === 'SHA3-512', `${corpusCase.id}: inspect digestAlg mismatch`);
    assert(inspected.json?.digestHex === corpusCase.expectedDigest, `${corpusCase.id}: inspect digest mismatch`);
  } else {
    assert(inspected.json?.command === 'inspect', `${corpusCase.id}: inspect command mismatch`);
    assert(inspected.json?.cliSchemaVersion === 1, `${corpusCase.id}: inspect cliSchemaVersion mismatch`);
    if (inspected.exitCode === 0) {
      assert(inspected.json?.ok === true, `${corpusCase.id}: inspect ok mismatch`);
      assert(inspected.json?.artifactType === corpusCase.artifactType, `${corpusCase.id}: inspect artifactType mismatch`);
      assert(inspected.json?.digestAlg === 'SHA3-512', `${corpusCase.id}: inspect digestAlg mismatch`);
      assert(inspected.json?.digestHex === corpusCase.expectedDigest, `${corpusCase.id}: inspect digest mismatch`);
    } else {
      assert(inspected.json?.ok === false, `${corpusCase.id}: inspect error ok mismatch`);
      assert(typeof inspected.json?.qvCode === 'string', `${corpusCase.id}: inspect error qvCode missing`);
      assert(typeof inspected.json?.error === 'string', `${corpusCase.id}: inspect error message missing`);
    }
  }

  const canonicalized = await runCliJson(['canonicalize', artifactPath, '--json']);
  assert(canonicalized.json?.command === 'canonicalize', `${corpusCase.id}: canonicalize command mismatch`);
  assert(canonicalized.json?.cliSchemaVersion === 1, `${corpusCase.id}: canonicalize cliSchemaVersion mismatch`);
  if (canonicalized.exitCode === 0) {
    assert(canonicalized.json?.ok === true, `${corpusCase.id}: canonicalize ok mismatch`);
    assert(canonicalized.json?.digestAlg === 'SHA3-512', `${corpusCase.id}: canonicalize digestAlg mismatch`);
    assert(typeof canonicalized.json?.canonicalJsonText === 'string', `${corpusCase.id}: canonicalize canonicalJsonText missing`);
  } else {
    assert(canonicalized.json?.ok === false, `${corpusCase.id}: canonicalize error ok mismatch`);
    assert(typeof canonicalized.json?.qvCode === 'string', `${corpusCase.id}: canonicalize error qvCode missing`);
    assert(typeof canonicalized.json?.error === 'string', `${corpusCase.id}: canonicalize error message missing`);
  }
}

function normalizeSignatureArtifacts(runtime = {}) {
  const signatures = Array.isArray(runtime.signatures) ? runtime.signatures : [];
  return signatures.map((signature, index) => ({
    id: String(signature.id || `sig-${index + 1}`),
    name: String(signature.name || signature.id || `sig-${index + 1}`),
    source: String(signature.source || 'external'),
    ok: signature.ok === true,
    bytes: decodeCaseBytes(signature.bytes, `runtime.signatures[${index}].bytes`),
    signatureContentDigestHex: typeof signature.signatureContentDigestHex === 'string'
      ? signature.signatureContentDigestHex
      : undefined,
  }));
}

function verifyExpectedSubset(actual, expected, field) {
  if (!expected || typeof expected !== 'object') return;
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (expectedValue && typeof expectedValue === 'object' && !Array.isArray(expectedValue)) {
      verifyExpectedSubset(actual?.[key], expectedValue, `${field}.${key}`);
      continue;
    }
    if (actual?.[key] !== expectedValue) {
      throw new Error(`${field}.${key} mismatch: expected ${expectedValue}, got ${actual?.[key]}`);
    }
  }
}

async function executeRuntimeCheck(corpusCase, bytes) {
  const runtime = corpusCase.runtime || {};

  switch (corpusCase.artifactType) {
    case 'QVqcont-7': {
      const parsed = await parseLifecycleShard(bytes, { strict: true });
      verifyExpectedSubset(parsed.metaJSON, runtime.expectedMetaJSON, `${corpusCase.id}.metaJSON`);
      return parsed;
    }
    case '.qsig': {
      const messageBytes = decodeOptionalRuntimeBytes(runtime, 'messageBytes');
      if (!(messageBytes instanceof Uint8Array)) {
        return unpackQsig(bytes);
      }
      const verification = verifyQsigAgainstBytes({
        messageBytes,
        qsigBytes: bytes,
        pinnedPqPublicKeyFileBytes: decodeOptionalRuntimeBytes(runtime, 'pinnedPqPublicKeyBytes'),
        bundlePqPublicKeyFileBytes: decodeOptionalRuntimeBytes(runtime, 'bundlePqPublicKeyBytes'),
        authoritativeBundlePqPublicKey: runtime.authoritativeBundlePqPublicKey === true,
      });
      if (!verification.ok) {
        throw new Error(verification.error || 'Detached PQ signature verification failed');
      }
      if (runtime.expectedSuite) {
        assert(verification.suite === runtime.expectedSuite, `${corpusCase.id}: expected suite ${runtime.expectedSuite}, got ${verification.suite}`);
      }
      return verification;
    }
    case '.pqpk': {
      const unpacked = unpackPqpk(bytes);
      if (runtime.expectedSuiteId != null) {
        assert(unpacked.suiteId === runtime.expectedSuiteId, `${corpusCase.id}: suiteId mismatch`);
      }
      return unpacked;
    }
    case '.ots': {
      const signatures = normalizeSignatureArtifacts(runtime);
      if (signatures.length === 0) {
        return parseOpenTimestampProof(bytes, { name: corpusCase.id });
      }
      return resolveOpenTimestampTarget({
        timestampBytes: bytes,
        timestampName: corpusCase.id,
        signatures,
      });
    }
    default:
      throw new Error(`${corpusCase.id}: unsupported artifactType ${corpusCase.artifactType}`);
  }
}

async function verifyBinaryCorpusCase(filePath, tempDir) {
  const corpusCase = JSON.parse(await readFile(filePath, 'utf8'));
  if (!corpusCase || typeof corpusCase !== 'object') {
    throw new Error(`Invalid corpus case JSON: ${filePath}`);
  }
  const bytes = decodeCaseBytes(corpusCase.bytes, 'bytes');
  ensureExpectedDigest(corpusCase, bytes);
  await verifyCliJsonEnvelopeForCorpusCase(corpusCase, bytes, tempDir);

  if (corpusCase.valid === true) {
    await executeRuntimeCheck(corpusCase, bytes);
    return;
  }

  const rejectionReason = String(corpusCase.rejectionReason || '').trim();
  assert(rejectionReason.length > 0, `${corpusCase.id}: invalid cases must declare rejectionReason`);

  try {
    await executeRuntimeCheck(corpusCase, bytes);
  } catch (error) {
    const actualMessage = formatError(error);
    if (!actualMessage.includes(rejectionReason)) {
      throw new Error(`${corpusCase.id}: expected rejection substring "${rejectionReason}", got "${actualMessage}"`);
    }
    return;
  }
  throw new Error(`${corpusCase.id}: invalid corpus case unexpectedly passed runtime verification`);
}

export async function runCorpusVerify() {
  const schemaReport = await runSchemaFixtureCheck();
  const binaryFiles = await listCorpusFiles(corpusDir);
  const binaryResults = [];
  const tempDir = await mkdtemp(join(tmpdir(), 'qv-corpus-cli-'));

  for (const filePath of binaryFiles) {
    const label = filePath.slice(corpusDir.length + 1);
    try {
      await verifyBinaryCorpusCase(filePath, tempDir);
      binaryResults.push({ name: label, ok: true });
    } catch (error) {
      binaryResults.push({ name: label, ok: false, error: formatError(error) });
    }
  }

  const results = [
    ...schemaReport.results.map((result) => ({
      name: `json:${result.name}`,
      ok: result.ok,
      error: result.error,
    })),
    ...binaryResults.map((result) => ({
      name: `binary:${result.name}`,
      ok: result.ok,
      error: result.error,
    })),
  ];

  const passed = results.filter((result) => result.ok).length;
  return {
    ok: passed === results.length,
    passed,
    total: results.length,
    results,
  };
}

async function main() {
  const report = await runCorpusVerify();
  console.log(`Corpus verify: ${report.ok ? 'PASS' : 'FAIL'} (${report.passed}/${report.total})`);
  for (const result of report.results) {
    if (result.ok) {
      console.log(`  OK   ${result.name}`);
    } else {
      console.log(`  FAIL ${result.name}: ${result.error}`);
    }
  }
  if (!report.ok) {
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
