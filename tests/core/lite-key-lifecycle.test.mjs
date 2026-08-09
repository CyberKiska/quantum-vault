import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createLiteArchiveKeyLifecycle,
  LiteArchiveCreationCancelledError,
  wipeLiteArchiveKeyPair,
} from '../../src/core/features/lite-key-lifecycle.js';

function keyPair(privateFill, publicFill) {
  return {
    privateKey: new Uint8Array(32).fill(privateFill),
    publicKey: new Uint8Array(24).fill(publicFill),
    seedInfo: { source: 'test', hasUserEntropy: false },
  };
}

function assertWiped(bytes, label) {
  assert.ok(bytes.every((value) => value === 0), `${label} was not wiped`);
}

test('pending retained material rejects a new operation without changing its bytes', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const retained = keyPair(0x01, 0x02);

  const retainedOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(retainedOperation, retained);
  lifecycle.retainAfterSuccess(retainedOperation);

  assert.throws(
    () => lifecycle.beginOperation(),
    /must be exported or discarded first/,
  );
  assert.ok(retained.privateKey.every((value) => value === 0x01));
  assert.ok(retained.publicKey.every((value) => value === 0x02));
  assert.equal(lifecycle.hasRetainedKeyPair(), true);
  assert.equal(lifecycle.hasActiveOperation(), false);

  const taken = lifecycle.takeRetainedKeyPair();
  assert.equal(taken, retained);
  wipeLiteArchiveKeyPair(taken);
  assertWiped(retained.privateKey, 'explicitly released retained private key');
  assertWiped(retained.publicKey, 'explicitly released retained public key');
});

test('a later operation starts only after retained ownership is explicitly transferred', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const first = keyPair(0x11, 0x12);
  const second = keyPair(0x21, 0x22);

  const firstOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(firstOperation, first);
  lifecycle.retainAfterSuccess(firstOperation);
  assert.equal(lifecycle.hasRetainedKeyPair(), true);

  const transferred = lifecycle.takeRetainedKeyPair();
  assert.equal(transferred, first);
  const secondOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(secondOperation, second);
  lifecycle.completeWithoutRetention(secondOperation);

  assert.ok(first.privateKey.every((value) => value === 0x11));
  assert.ok(first.publicKey.every((value) => value === 0x12));
  assertWiped(second.privateKey, 'threshold-only private key');
  assertWiped(second.publicKey, 'threshold-only public key');
  assert.equal(lifecycle.hasRetainedKeyPair(), false);

  wipeLiteArchiveKeyPair(transferred);
  assertWiped(first.privateKey, 'transferred private key');
  assertWiped(first.publicKey, 'transferred public key');
});

test('failure without a prior authorized success offers no new backup pair', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const failed = keyPair(0x43, 0x44);
  const failedOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(failedOperation, failed);
  lifecycle.discardOperation(failedOperation);

  assertWiped(failed.privateKey, 'failed private key');
  assertWiped(failed.publicKey, 'failed public key');
  assert.equal(lifecycle.hasRetainedKeyPair(), false);
  assert.equal(lifecycle.takeRetainedKeyPair(), null);
});

test('cancellation wipes an adopted pair and rejects future use of its operation token', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const cancelled = keyPair(0x51, 0x52);
  const operation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(operation, cancelled);

  assert.equal(lifecycle.cancelActiveOperation(), true);
  assertWiped(cancelled.privateKey, 'cancelled private key');
  assertWiped(cancelled.publicKey, 'cancelled public key');
  assert.throws(
    () => lifecycle.getOperationKeyPair(operation),
    LiteArchiveCreationCancelledError,
  );
  assert.equal(lifecycle.hasRetainedKeyPair(), false);
});

test('a second operation cannot take ownership while the first remains active', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const first = keyPair(0x57, 0x58);
  const operation = lifecycle.beginOperation();

  assert.throws(() => lifecycle.beginOperation(), /already active/);
  lifecycle.adoptKeyPair(operation, first);
  lifecycle.completeWithoutRetention(operation);

  assertWiped(first.privateKey, 'single-owner private key');
  assertWiped(first.publicKey, 'single-owner public key');
  assert.equal(lifecycle.hasActiveOperation(), false);
});

test('key generation that returns after cancellation is rejected and wiped', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const operation = lifecycle.beginOperation();
  lifecycle.cancelActiveOperation();

  const latePair = keyPair(0x61, 0x62);
  assert.throws(
    () => lifecycle.adoptKeyPair(operation, latePair),
    LiteArchiveCreationCancelledError,
  );
  assertWiped(latePair.privateKey, 'late private key');
  assertWiped(latePair.publicKey, 'late public key');
  assert.equal(lifecycle.hasRetainedKeyPair(), false);
});

test('session wipe clears either retained or active operation material', () => {
  const retainedLifecycle = createLiteArchiveKeyLifecycle();
  const activeLifecycle = createLiteArchiveKeyLifecycle();
  const retained = keyPair(0x71, 0x72);
  const active = keyPair(0x81, 0x82);

  const retainedOperation = retainedLifecycle.beginOperation();
  retainedLifecycle.adoptKeyPair(retainedOperation, retained);
  retainedLifecycle.retainAfterSuccess(retainedOperation);

  const activeOperation = activeLifecycle.beginOperation();
  activeLifecycle.adoptKeyPair(activeOperation, active);
  retainedLifecycle.wipeAll();
  activeLifecycle.wipeAll();

  assertWiped(retained.privateKey, 'session-retained private key');
  assertWiped(retained.publicKey, 'session-retained public key');
  assertWiped(active.privateKey, 'session-active private key');
  assertWiped(active.publicKey, 'session-active public key');
  assert.equal(retainedLifecycle.hasRetainedKeyPair(), false);
  assert.equal(activeLifecycle.hasActiveOperation(), false);
});

test('taking the optional backup transfers ownership and the caller can wipe it', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const retained = keyPair(0x91, 0x92);
  const operation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(operation, retained);
  lifecycle.retainAfterSuccess(operation);

  const taken = lifecycle.takeRetainedKeyPair();
  assert.equal(taken, retained);
  assert.equal(lifecycle.hasRetainedKeyPair(), false);

  wipeLiteArchiveKeyPair(taken);
  assertWiped(retained.privateKey, 'backed-up private key');
  assertWiped(retained.publicKey, 'backed-up public key');
});

test('a failed export setup can return transferred ownership without copying or wiping it', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const retained = keyPair(0xa1, 0xa2);
  const operation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(operation, retained);
  lifecycle.retainAfterSuccess(operation);

  const transferred = lifecycle.takeRetainedKeyPair();
  assert.equal(lifecycle.returnRetainedKeyPair(transferred), retained);
  assert.equal(lifecycle.returnRetainedKeyPair(transferred), retained);
  assert.equal(lifecycle.hasRetainedKeyPair(), true);
  assert.ok(retained.privateKey.every((value) => value === 0xa1));
  assert.ok(retained.publicKey.every((value) => value === 0xa2));
  assert.throws(() => lifecycle.beginOperation(), /must be exported or discarded first/);

  const returned = lifecycle.takeRetainedKeyPair();
  assert.equal(returned, retained);
  wipeLiteArchiveKeyPair(returned);
  assertWiped(retained.privateKey, 'returned private key');
  assertWiped(retained.publicKey, 'returned public key');
});

test('a conflicting ownership return fails closed and wipes the offered pair', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const active = lifecycle.beginOperation();
  const offered = keyPair(0xa3, 0xa4);

  assert.throws(
    () => lifecycle.returnRetainedKeyPair(offered),
    /ownership return was rejected/,
  );
  assertWiped(offered.privateKey, 'rejected returned private key');
  assertWiped(offered.publicKey, 'rejected returned public key');
  lifecycle.discardOperation(active);
});

test('a conflicting ownership return cannot overwrite or wipe a retained pair', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const retained = keyPair(0xa5, 0xa6);
  const offered = keyPair(0xa7, 0xa8);
  const operation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(operation, retained);
  lifecycle.retainAfterSuccess(operation);

  assert.throws(
    () => lifecycle.returnRetainedKeyPair(offered),
    /ownership return was rejected/,
  );
  assertWiped(offered.privateKey, 'conflicting offered private key');
  assertWiped(offered.publicKey, 'conflicting offered public key');
  assert.ok(retained.privateKey.every((value) => value === 0xa5));
  assert.ok(retained.publicKey.every((value) => value === 0xa6));

  const returned = lifecycle.takeRetainedKeyPair();
  wipeLiteArchiveKeyPair(returned);
});

test('best-effort pair cleanup tolerates a detached buffer and continues', () => {
  const pair = keyPair(0xb1, 0xb2);
  structuredClone(pair.privateKey, { transfer: [pair.privateKey.buffer] });

  assert.doesNotThrow(() => wipeLiteArchiveKeyPair(pair));
  assert.equal(pair.privateKey.byteLength, 0);
  assertWiped(pair.publicKey, 'public key after detached private key');
});
