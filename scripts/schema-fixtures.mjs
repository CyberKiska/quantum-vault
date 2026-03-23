import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArchiveManifestBytes } from '../src/core/crypto/manifest/archive-manifest.js';
import { parseManifestBundleBytes } from '../src/core/crypto/manifest/manifest-bundle.js';
import { canonicalizeJsonToBytes } from '../src/core/crypto/manifest/jcs.js';
import { SchemaValidationError, createSchemaRegistry } from './lib/json-schema-lite.mjs';

const thisDir = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(thisDir, '../docs/schema');

function schemaUriForFile(fileName) {
  return `https://quantum-vault.local/schema/${fileName}`;
}

async function readJsonFile(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

async function loadSchemaRegistry() {
  const schemaFiles = [
    'qv-common-types.schema.json',
    'qv-manifest-v3.schema.json',
    'qv-manifest-bundle-v2.schema.json'
  ];
  const entries = [];
  for (const fileName of schemaFiles) {
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

async function assertRuntimeExpectation(fixture, instance) {
  const bytes = canonicalizeJsonToBytes(instance);
  const runtime = fixture.runtime;
  if (runtime.artifact === 'manifest') {
    if (runtime.expectParseSuccess) {
      parseArchiveManifestBytes(bytes);
      return;
    }
    let failed = false;
    try {
      parseArchiveManifestBytes(bytes);
    } catch {
      failed = true;
    }
    if (!failed) {
      throw new Error('manifest parser unexpectedly accepted schema-valid semantic-invalid fixture');
    }
    return;
  }
  if (runtime.artifact === 'bundle') {
    if (runtime.expectParseSuccess) {
      parseManifestBundleBytes(bytes);
      return;
    }
    let failed = false;
    try {
      parseManifestBundleBytes(bytes);
    } catch {
      failed = true;
    }
    if (!failed) {
      throw new Error('bundle parser unexpectedly accepted schema-valid semantic-invalid fixture');
    }
    return;
  }
  throw new Error(`Unsupported runtime artifact kind: ${runtime.artifact}`);
}

export async function runSchemaFixtureCheck() {
  const registry = await loadSchemaRegistry();
  const index = await readJsonFile(resolve(schemaDir, 'fixtures/index.json'));
  const results = [];

  for (const fixture of index.fixtures || []) {
    try {
      const instancePath = resolve(schemaDir, fixture.file);
      const instance = await readJsonFile(instancePath);
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
        await assertRuntimeExpectation(fixture, instance);
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
