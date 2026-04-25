import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha3_512 } from '@noble/hashes/sha3.js';
import {
  parseArchiveStateDescriptorBytes,
  parseCohortBindingBytes,
  parseTransitionRecordBytes,
  parseSourceEvidenceBytes,
  parseLifecycleBundleBytes,
} from '../src/core/crypto/lifecycle/artifacts.js';
import { toHex } from '../src/core/crypto/bytes.js';
import { canonicalizeJsonToBytes } from '../src/core/crypto/manifest/jcs.js';
import { SchemaValidationError, createSchemaRegistry } from './lib/json-schema-lite.mjs';

const thisDir = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(thisDir, '../docs/schema');
const ACTIVE_SCHEMA_FILES = Object.freeze([
  'qv-common-types.schema.json',
  'qv-archive-state-descriptor-v1.schema.json',
  'qv-cohort-binding-v1.schema.json',
  'qv-transition-record-v1.schema.json',
  'qv-source-evidence-v1.schema.json',
  'qv-lifecycle-bundle-v1.schema.json',
]);
const ACTIVE_SCHEMA_SET = new Set(ACTIVE_SCHEMA_FILES);

function schemaUriForFile(fileName) {
  return `https://quantum-vault.local/schema/${fileName}`;
}

async function readJsonFile(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

async function readFileBytes(filePath) {
  return new Uint8Array(await readFile(filePath));
}

async function loadSchemaRegistry() {
  const entries = [];
  for (const fileName of ACTIVE_SCHEMA_FILES) {
    const schema = await readJsonFile(resolve(schemaDir, fileName));
    entries.push({
      uri: schemaUriForFile(fileName),
      schema
    });
  }
  return createSchemaRegistry(entries);
}

function formatError(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function ensureExpectedFailure(error, expectedMessageIncludes, label) {
  if (!expectedMessageIncludes) return;
  const actualMessage = formatError(error);
  if (!actualMessage.includes(expectedMessageIncludes)) {
    throw new Error(`${label} failed with unexpected message: expected substring "${expectedMessageIncludes}", got "${actualMessage}"`);
  }
}

function assertParserFailure(parseFn, bytes, runtime, label) {
  try {
    parseFn(bytes);
  } catch (error) {
    ensureExpectedFailure(error, runtime.expectErrorIncludes, label);
    return null;
  }
  throw new Error(`${label} unexpectedly accepted schema-valid semantic-invalid fixture`);
}

async function assertAsyncParserFailure(parseFn, bytes, runtime, label) {
  try {
    await parseFn(bytes);
  } catch (error) {
    ensureExpectedFailure(error, runtime.expectErrorIncludes, label);
    return null;
  }
  throw new Error(`${label} unexpectedly accepted schema-valid semantic-invalid fixture`);
}

async function assertTransitionRecordBundleContextExpectation(fixture, instance, rawJsonBytes) {
  const runtime = fixture.runtime || {};
  const bytes = runtime.useRawJsonBytes === true ? rawJsonBytes : canonicalizeJsonToBytes(instance);

  if (runtime.expectStandaloneParseSuccess === false) {
    assertParserFailure(parseTransitionRecordBytes, bytes, runtime, 'transition-record parser');
  } else {
    parseTransitionRecordBytes(bytes);
  }

  const bundlePath = resolve(schemaDir, runtime.contextualLifecycleBundleFile);
  const bundle = await readJsonFile(bundlePath);
  const transitionIndex = Number.isInteger(runtime.contextualTransitionIndex) ? runtime.contextualTransitionIndex : 0;
  if (!Array.isArray(bundle.transitions) || transitionIndex < 0 || transitionIndex >= bundle.transitions.length) {
    throw new Error(`Invalid contextualTransitionIndex for ${fixture.id}`);
  }
  bundle.transitions[transitionIndex] = instance;
  const bundleBytes = canonicalizeJsonToBytes(bundle);

  if (runtime.expectParseSuccess) {
    return parseLifecycleBundleBytes(bundleBytes);
  }
  return assertAsyncParserFailure(parseLifecycleBundleBytes, bundleBytes, runtime, 'lifecycle-bundle parser');
}

async function assertRuntimeExpectation(fixture, instance, rawJsonBytes) {
  const runtime = fixture.runtime;
  const bytes = runtime.useRawJsonBytes === true ? rawJsonBytes : canonicalizeJsonToBytes(instance);
  if (runtime.artifact === 'archive-state') {
    if (runtime.expectParseSuccess) {
      return parseArchiveStateDescriptorBytes(bytes);
    }
    return assertParserFailure(parseArchiveStateDescriptorBytes, bytes, runtime, 'archive-state parser');
  }
  if (runtime.artifact === 'cohort-binding') {
    if (runtime.expectParseSuccess) {
      return parseCohortBindingBytes(bytes);
    }
    return assertParserFailure(parseCohortBindingBytes, bytes, runtime, 'cohort-binding parser');
  }
  if (runtime.artifact === 'transition-record') {
    if (typeof runtime.contextualLifecycleBundleFile === 'string' && runtime.contextualLifecycleBundleFile) {
      return assertTransitionRecordBundleContextExpectation(fixture, instance, rawJsonBytes);
    }
    if (runtime.expectParseSuccess) {
      return parseTransitionRecordBytes(bytes);
    }
    return assertParserFailure(parseTransitionRecordBytes, bytes, runtime, 'transition-record parser');
  }
  if (runtime.artifact === 'source-evidence') {
    if (runtime.expectParseSuccess) {
      return parseSourceEvidenceBytes(bytes);
    }
    return assertParserFailure(parseSourceEvidenceBytes, bytes, runtime, 'source-evidence parser');
  }
  if (runtime.artifact === 'lifecycle-bundle') {
    if (runtime.expectParseSuccess) {
      return parseLifecycleBundleBytes(bytes);
    }
    return assertAsyncParserFailure(parseLifecycleBundleBytes, bytes, runtime, 'lifecycle-bundle parser');
  }
  throw new Error(`Unsupported runtime artifact kind: ${runtime.artifact}`);
}

function computeExpectedDigestHex(instance) {
  return toHex(sha3_512(canonicalizeJsonToBytes(instance)));
}

export async function runSchemaFixtureCheck() {
  const registry = await loadSchemaRegistry();
  const index = await readJsonFile(resolve(schemaDir, 'fixtures/index.json'));
  const results = [];
  const fixtures = index.fixtures || [];

  for (const fixture of fixtures) {
    try {
      if (!ACTIVE_SCHEMA_SET.has(fixture.schema)) {
        throw new Error(`fixture references unsupported schema: ${fixture.schema}`);
      }
      const instancePath = resolve(schemaDir, fixture.file);
      const instance = await readJsonFile(instancePath);
      const rawJsonBytes = await readFileBytes(instancePath);
      let schemaValid = false;
      let schemaError = null;
      try {
        registry.validate(schemaUriForFile(fixture.schema), instance);
        schemaValid = true;
      } catch (error) {
        schemaError = error;
      }

      if (fixture.expectSchemaValid === true && !schemaValid) {
        throw schemaError;
      }
      let parsed = null;
      if (fixture.runtime) {
        parsed = await assertRuntimeExpectation(fixture, instance, rawJsonBytes);
      }

      if (fixture.expectSchemaValid === false) {
        if (!(schemaError instanceof SchemaValidationError)) {
          throw new Error('schema validation unexpectedly succeeded');
        }
      }
      if (fixture.expectedDigestHex != null) {
        if (!(fixture.expectSchemaValid === true && fixture.runtime?.expectParseSuccess === true)) {
          throw new Error('expectedDigestHex is only supported for schema-valid runtime-valid fixtures');
        }
        const actualDigestHex = computeExpectedDigestHex(instance);
        if (actualDigestHex !== fixture.expectedDigestHex) {
          throw new Error(`digest mismatch: expected ${fixture.expectedDigestHex}, got ${actualDigestHex}`);
        }
        if (parsed?.digest?.value !== fixture.expectedDigestHex) {
          throw new Error(`runtime digest mismatch: expected ${fixture.expectedDigestHex}, got ${parsed?.digest?.value ?? 'missing'}`);
        }
      }

      results.push({ name: fixture.id, ok: true });
    } catch (error) {
      results.push({ name: fixture.id, ok: false, error: formatError(error) });
    }
  }

  const passed = results.filter((result) => result.ok).length;
  return {
    ok: passed === results.length,
    passed,
    total: results.length,
    results
  };
}

async function main() {
  const report = await runSchemaFixtureCheck();

  console.log(`Schema fixtures: ${report.ok ? 'PASS' : 'FAIL'} (${report.passed}/${report.total})`);
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
