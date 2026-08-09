import assert from 'node:assert/strict';
import test from 'node:test';

import { BrowserEntropyCollector } from '../../src/app/browser-entropy-collector.js';

class FakeEventTarget {
  constructor() {
    this.handlers = new Map();
    this.innerWidth = 1280;
    this.innerHeight = 720;
  }

  addEventListener(type, handler) {
    const handlers = this.handlers.get(type) || new Set();
    handlers.add(handler);
    this.handlers.set(type, handlers);
  }

  removeEventListener(type, handler) {
    this.handlers.get(type)?.delete(handler);
  }

  emit(type, event = {}) {
    for (const handler of this.handlers.get(type) || []) handler(event);
  }

  listenerCount() {
    return [...this.handlers.values()].reduce((count, handlers) => count + handlers.size, 0);
  }
}

function installFakeDom() {
  const previousWindow = globalThis.window;
  const previousDocument = globalThis.document;
  const fakeWindow = new FakeEventTarget();
  const fakeDocument = new FakeEventTarget();
  globalThis.window = fakeWindow;
  globalThis.document = fakeDocument;
  return {
    fakeWindow,
    fakeDocument,
    restore() {
      if (previousWindow === undefined) delete globalThis.window;
      else globalThis.window = previousWindow;
      if (previousDocument === undefined) delete globalThis.document;
      else globalThis.document = previousDocument;
    },
  };
}

test('browser entropy completion drains queued summaries and wipes collector state', async () => {
  const dom = installFakeDom();
  let seed = null;
  try {
    const collector = new BrowserEntropyCollector();
    const completion = collector.startCollection();
    for (let index = 0; index < 100; index += 1) {
      dom.fakeDocument.emit('keydown', {
        keyCode: 65 + (index % 26),
        location: index % 4,
        repeat: false,
      });
    }

    seed = await completion;
    assert.equal(seed.length, 64);
    assert.equal(seed.some((byte) => byte !== 0), true);
    assert.equal(collector.isCollecting, false);
    assert.equal(collector.processingQueue.length, 0);
    assert.equal(collector.entropyState.every((byte) => byte === 0), true);
    assert.equal(dom.fakeWindow.listenerCount(), 0);
    assert.equal(dom.fakeDocument.listenerCount(), 0);
  } finally {
    seed?.fill(0);
    dom.restore();
  }
});

test('disposing an active entropy collector cancels timers and prevents late state mutation', async () => {
  const dom = installFakeDom();
  try {
    const collector = new BrowserEntropyCollector();
    const completion = collector.startCollection();
    dom.fakeDocument.emit('keydown', { keyCode: 65, location: 0, repeat: false });

    collector.dispose();
    await assert.rejects(completion, (error) => error?.name === 'AbortError');
    await new Promise((resolve) => setTimeout(resolve, 150));

    assert.equal(collector.isCollecting, false);
    assert.equal(collector.processingQueue.length, 0);
    assert.equal(collector.entropyState.every((byte) => byte === 0), true);
    assert.equal(dom.fakeWindow.listenerCount(), 0);
    assert.equal(dom.fakeDocument.listenerCount(), 0);
    await assert.rejects(
      () => collector.startCollection(),
      /disposed/
    );
  } finally {
    dom.restore();
  }
});
