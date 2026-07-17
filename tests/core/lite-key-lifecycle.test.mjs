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

test('Lite key lifecycle retains only the latest successful archive pair and wipes the superseded pair', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const first = keyPair(0x11, 0x12);
  const second = keyPair(0x21, 0x22);

  const firstOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(firstOperation, first);
  lifecycle.retainAfterSuccess(firstOperation);
  assert.equal(lifecycle.hasRetainedKeyPair(), true);

  const secondOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(secondOperation, second);
  lifecycle.retainAfterSuccess(secondOperation);

  assertWiped(first.privateKey, 'superseded private key');
  assertWiped(first.publicKey, 'superseded public key');
  assert.equal(lifecycle.hasRetainedKeyPair(), true);
  assert.ok(second.privateKey.some((value) => value !== 0));
  assert.ok(second.publicKey.some((value) => value !== 0));

  lifecycle.wipeAll();
  assertWiped(second.privateKey, 'latest retained private key');
  assertWiped(second.publicKey, 'latest retained public key');
});

test('failed Lite archive operation is wiped without discarding the last successful backup pair', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const successful = keyPair(0x31, 0x32);
  const failed = keyPair(0x41, 0x42);

  const successfulOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(successfulOperation, successful);
  lifecycle.retainAfterSuccess(successfulOperation);

  const failedOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(failedOperation, failed);
  lifecycle.discardOperation(failedOperation);

  assertWiped(failed.privateKey, 'failed operation private key');
  assertWiped(failed.publicKey, 'failed operation public key');
  assert.equal(lifecycle.hasRetainedKeyPair(), true);
  assert.ok(successful.privateKey.some((value) => value !== 0));

  lifecycle.wipeAll();
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

test('session wipe clears both the retained pair and an active successor pair', () => {
  const lifecycle = createLiteArchiveKeyLifecycle();
  const retained = keyPair(0x71, 0x72);
  const active = keyPair(0x81, 0x82);

  const retainedOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(retainedOperation, retained);
  lifecycle.retainAfterSuccess(retainedOperation);

  const activeOperation = lifecycle.beginOperation();
  lifecycle.adoptKeyPair(activeOperation, active);
  lifecycle.wipeAll();

  assertWiped(retained.privateKey, 'session-retained private key');
  assertWiped(retained.publicKey, 'session-retained public key');
  assertWiped(active.privateKey, 'session-active private key');
  assertWiped(active.publicKey, 'session-active public key');
  assert.equal(lifecycle.hasRetainedKeyPair(), false);
  assert.equal(lifecycle.hasActiveOperation(), false);
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
