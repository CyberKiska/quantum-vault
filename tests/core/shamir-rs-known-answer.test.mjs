import assert from 'node:assert/strict';
import test from 'node:test';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { toHex } from '../../src/core/crypto/bytes.js';
import { resolveErasureRuntime } from '../../src/core/crypto/erasure-runtime.js';
import { combineShares, validateShares } from '../../src/core/crypto/splitting/sss.js';
import { ensureErasureRuntime } from '../../src/core/cli/lib/runtime.js';

const SHAMIR_SECRET = Uint8Array.of(0x00, 0x00, 0x01, 0xff);
const SHAMIR_COORDINATES = Object.freeze([1, 2, 3, 254, 255]);
const SHAMIR_COEFFICIENTS = Object.freeze([
  Object.freeze([0x00, 0x01, 0x02, 0x03]),
  Object.freeze([0x00, 0x10, 0x20, 0x30]),
  Object.freeze([0x01, 0x7f, 0x80, 0xff]),
  Object.freeze([0xff, 0x00, 0x01, 0x02]),
]);
const SHAMIR_SHARE_HEX = Object.freeze([
  '000001fc01',
  '123b70eb02',
  '189b44e403',
  '636a4acafe',
  '4cac2a0aff',
]);

// Direct polynomial-basis multiplication is independent of the dependency's
// logarithm tables. The low-byte reduction constant represents modulus 0x11b.
function shamirMultiply(left, right) {
  let a = left;
  let b = right;
  let result = 0;
  for (let bit = 0; bit < 8; bit += 1) {
    if ((b & 1) !== 0) result ^= a;
    const carry = (a & 0x80) !== 0;
    a = (a << 1) & 0xff;
    if (carry) a ^= 0x1b;
    b >>>= 1;
  }
  return result;
}

function evaluateShamirPolynomial(coefficients, coordinate) {
  let result = coefficients[coefficients.length - 1];
  for (let index = coefficients.length - 2; index >= 0; index -= 1) {
    result = shamirMultiply(result, coordinate) ^ coefficients[index];
  }
  return result;
}

function buildReferenceShare(coordinate) {
  return Uint8Array.of(
    ...SHAMIR_COEFFICIENTS.map((coefficients) =>
      evaluateShamirPolynomial(coefficients, coordinate)),
    coordinate,
  );
}

test('fixed Shamir 4-of-5 shares preserve leading zero and ff secret bytes', async () => {
  const shares = SHAMIR_COORDINATES.map(buildReferenceShare);
  assert.deepEqual(shares.map((share) => toHex(share)), SHAMIR_SHARE_HEX);

  for (let omitted = 0; omitted < shares.length; omitted += 1) {
    const selected = shares.filter((_, index) => index !== omitted);
    assert.deepEqual(await combineShares(selected), SHAMIR_SECRET);
  }
});

test('fixed Shamir vector rejects zero and duplicate final-byte coordinates', async () => {
  const shares = SHAMIR_COORDINATES.map(buildReferenceShare);
  const zeroCoordinate = shares[0].slice();
  zeroCoordinate[zeroCoordinate.length - 1] = 0;
  const duplicateCoordinate = shares[1].slice();
  duplicateCoordinate[duplicateCoordinate.length - 1] = shares[0][shares[0].length - 1];

  await assert.rejects(
    () => combineShares([zeroCoordinate, shares[1], shares[2], shares[3]]),
    /Invalid Shamir share coordinates/,
  );
  await assert.rejects(
    () => combineShares([shares[0], duplicateCoordinate, shares[2], shares[3]]),
    /Invalid Shamir share coordinates/,
  );
  assert.equal(validateShares([zeroCoordinate, shares[1]]).valid, false);
  assert.equal(validateShares([shares[0], duplicateCoordinate]).valid, false);
});

const RUST_RS_FRAGMENT_SHA3_512 = Object.freeze([
  '832f1bdd46161c635ee2ad8e0468901725e94908a2685291fb70743016fe2c507567576d84bcf694a33fe8af1d821bdee7360e6be9f20ed855fe6d6db4a87a19',
  'e5ca23a4e11816df7492af58f2f782f1dc88a056e935e56f8e50b8bedb4e59fe1f55c4c5a9ab9b3994eeb71eacc4f76f19e5395a1945bc2ed6f5c5292958cbce',
  '4b954fb5c201d18e8434cf039cc788f204321ce510e5c6d27598a04f00ba889a4cdff04c2de645070b3094108b87d3e4bcaaa05f0fd154990b96610292268791',
  '1ebaebeaa992695ede5f709e5ce44abf953a10d54afec7286ff6eb53df58d6d7e5d07295b6e8cb9b14f0f7621353982270fbaa01d810838ac6dde927389771b4',
  '9fbf8a9798f06cf6bc5a8c3c55de9ac5bdefd693b5737b8bbef14ec396632e2ea8a61c63800fcf3965befa9dca5e7bbaafe11c0e401bff76ea0486e68c7ff57b',
]);

async function loadPinnedErasureRuntime() {
  await ensureErasureRuntime();
  return resolveErasureRuntime();
}

function rustRsInput() {
  return Uint8Array.from({ length: 154 }, (_, index) => index);
}

test('vendored RS matches the pinned Rust n=5 k=3 fragment-hash vector', async () => {
  const runtime = await loadPinnedErasureRuntime();
  const input = rustRsInput();
  const fragments = runtime.split(input, 3, 1, 255);

  assert.deepEqual(fragments.map((fragment) => fragment.length), [102, 102, 102, 102, 102]);
  assert.deepEqual(
    fragments.map((fragment) => toHex(sha3_512(fragment))),
    RUST_RS_FRAGMENT_SHA3_512,
  );
  assert.deepEqual(runtime.recombine(fragments, input.length, 3, 1, 255), input);
});

test('vendored RS corrects one whole fragment but not two for n=5 k=3', async () => {
  const runtime = await loadPinnedErasureRuntime();
  const input = rustRsInput();
  const fragments = runtime.split(input, 3, 1, 255);

  for (let missing = 0; missing < fragments.length; missing += 1) {
    const oneMissing = fragments.map((fragment) => fragment.slice());
    oneMissing[missing].fill(0);
    assert.deepEqual(runtime.recombine(oneMissing, input.length, 3, 1, 255), input);
  }

  const twoMissing = fragments.map((fragment) => fragment.slice());
  twoMissing[0].fill(0);
  twoMissing[1].fill(0);
  let failure = null;
  try {
    runtime.recombine(twoMissing, input.length, 3, 1, 255);
  } catch (error) {
    failure = error;
  }
  assert.notEqual(failure, null, 'two missing fragments exceed f=1 and must not recover');
});

test('low-level vendored RS is not an exact fragment-framing validator', async () => {
  const runtime = await loadPinnedErasureRuntime();
  const input = rustRsInput();
  const fragments = runtime.split(input, 3, 1, 255);
  const truncated = fragments.map((fragment) => fragment.slice());
  truncated[0] = truncated[0].subarray(0, 51);

  // This dependency behavior is why QVqcont validates authenticated exact
  // lengths before recombination and validates the returned length and qencHash.
  const lowLevelResult = runtime.recombine(truncated, input.length, 3, 1, 255);
  assert.equal(lowLevelResult.length, 153);
  assert.notDeepEqual(lowLevelResult, input);
});
