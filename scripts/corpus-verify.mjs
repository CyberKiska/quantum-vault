import { readdir, readFile } from 'node:fs/promises';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { runSchemaFixtureCheck } from './schema-fixtures.mjs';
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

async function verifyBinaryCorpusCase(filePath) {
  const corpusCase = JSON.parse(await readFile(filePath, 'utf8'));
  if (!corpusCase || typeof corpusCase !== 'object') {
    throw new Error(`Invalid corpus case JSON: ${filePath}`);
  }
  const bytes = decodeCaseBytes(corpusCase.bytes, 'bytes');
  ensureExpectedDigest(corpusCase, bytes);

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

  for (const filePath of binaryFiles) {
    const label = filePath.slice(corpusDir.length + 1);
    try {
      await verifyBinaryCorpusCase(filePath);
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
