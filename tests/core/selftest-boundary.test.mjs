import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('cryptographic self-test graph does not invert the core-to-app boundary', async () => {
  const source = await readFile('src/core/crypto/selftest.js', 'utf8');
  assert.equal(/from\s+['"][^'"]*\/features\//.test(source), false);
  assert.equal(/from\s+['"][^'"]*\/app\//.test(source), false);
});
