import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseArchiveStateDescriptorBytes,
  parseCohortBindingBytes,
  parseTransitionRecordBytes,
  parseSourceEvidenceBytes,
  parseLifecycleBundleBytes,
} from '../src/core/crypto/lifecycle/artifacts.js';
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

async function assertRuntimeExpectation(fixture, instance, rawJsonBytes) {
  const runtime = fixture.runtime;
  const bytes = runtime.useRawJsonBytes === true ? rawJsonBytes : canonicalizeJsonToBytes(instance);
  if (runtime.artifact === 'archive-state') {
    if (runtime.expectParseSuccess) {
      parseArchiveStateDescriptorBytes(bytes);
      return;
    }
    let failed = false;
    try {
      parseArchiveStateDescriptorBytes(bytes);
    } catch {
      failed = true;
    }
    if (!failed) {
      throw new Error('archive-state parser unexpectedly accepted schema-valid semantic-invalid fixture');
    }
    return;
  }
  if (runtime.artifact === 'cohort-binding') {
    if (runtime.expectParseSuccess) {
      parseCohortBindingBytes(bytes);
      return;
    }
    let failed = false;
    try {
      parseCohortBindingBytes(bytes);
    } catch {
      failed = true;
    }
    if (!failed) {
      throw new Error('cohort-binding parser unexpectedly accepted schema-valid semantic-invalid fixture');
    }
    return;
  }
  if (runtime.artifact === 'transition-record') {
    if (runtime.expectParseSuccess) {
      parseTransitionRecordBytes(bytes);
      return;
    }
    let failed = false;
    try {
      parseTransitionRecordBytes(bytes);
    } catch {
      failed = true;
    }
    if (!failed) {
      throw new Error('transition-record parser unexpectedly accepted schema-valid semantic-invalid fixture');
    }
    return;
  }
  if (runtime.artifact === 'source-evidence') {
    if (runtime.expectParseSuccess) {
      parseSourceEvidenceBytes(bytes);
      return;
    }
    let failed = false;
    try {
      parseSourceEvidenceBytes(bytes);
    } catch {
      failed = true;
    }
    if (!failed) {
      throw new Error('source-evidence parser unexpectedly accepted schema-valid semantic-invalid fixture');
    }
    return;
  }
  if (runtime.artifact === 'lifecycle-bundle') {
    if (runtime.expectParseSuccess) {
      await parseLifecycleBundleBytes(bytes);
      return;
    }
    let failed = false;
    try {
      await parseLifecycleBundleBytes(bytes);
    } catch {
      failed = true;
    }
    if (!failed) {
      throw new Error('lifecycle-bundle parser unexpectedly accepted schema-valid semantic-invalid fixture');
    }
    return;
  }
  throw new Error(`Unsupported runtime artifact kind: ${runtime.artifact}`);
}

export async function runSchemaFixtureCheck() {
  const registry = await loadSchemaRegistry();
  const index = await readJsonFile(resolve(schemaDir, 'fixtures/index.json'));
  const results = [];
  const activeFixtures = (index.fixtures || []).filter((fixture) => ACTIVE_SCHEMA_SET.has(fixture.schema));

  for (const fixture of activeFixtures) {
    try {
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
      if (fixture.runtime) {
        await assertRuntimeExpectation(fixture, instance, rawJsonBytes);
      }

      if (fixture.expectSchemaValid === false) {
        if (!(schemaError instanceof SchemaValidationError)) {
          throw new Error('schema validation unexpectedly succeeded');
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

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
