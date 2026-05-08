import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { compareUtf16, dedupeSorted } from '../../src/core/cli/lib/glob.js';

test('compareUtf16 uses UTF-16 code unit ordering', () => {
  assert.equal(compareUtf16('a', 'b'), -1);
  assert.equal(compareUtf16('b', 'a'), 1);
  assert.equal(compareUtf16('a', 'a'), 0);
  const ordered = ['z', 'ä', 'a'].sort(compareUtf16);
  assert.deepEqual(ordered, ['a', 'z', 'ä']);
});

test('dedupeSorted removes duplicates and orders paths deterministically', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qv-glob-'));
  const pA = join(dir, 'a');
  const pZ = join(dir, 'z');
  const resolved = dedupeSorted([pZ, pA, pZ]);
  assert.equal(resolved.length, 2);
  assert.deepEqual(resolved, [pA, pZ]);
});
