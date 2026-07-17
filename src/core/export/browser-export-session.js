import { sha3_512 } from '@noble/hashes/sha3.js';

// This is an operational browser profile, not a wire-format limit. It covers
// the Lite UI maximum (25 shards plus metadata) while keeping whole-buffer
// publication plans deliberately below the much larger core format ceilings.
// Raising it requires measured browser-memory evidence and a streaming design.
export const MAX_BROWSER_EXPORT_ARTIFACTS = 64;
export const MAX_BROWSER_EXPORT_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const MAX_BROWSER_EXPORT_AGGREGATE_BYTES = 128 * 1024 * 1024;
export const MAX_BROWSER_EXPORT_NAME_BYTES = 255;
export const SHA3_512_DIGEST_BYTES = 64;

export const BROWSER_EXPORT_STATES = Object.freeze({
  READY: 'ready',
  REQUESTED_UNVERIFIED: 'requested-unverified',
  VERIFIED: 'verified',
  FAILED: 'failed',
  CANCELLED: 'cancelled',
});

export const BROWSER_EXPORT_ROLES = Object.freeze([
  'shard',
  'archive-state',
  'cohort-binding',
  'lifecycle-bundle',
  'transition-record',
  'public-key',
  'private-key',
  'encrypted-container',
  'plaintext',
  'detached-artifact',
  'other',
]);

const ROLE_SET = new Set(BROWSER_EXPORT_ROLES);
const WINDOWS_RESERVED_BASENAME_RE = /^(?:con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])$/i;
const WINDOWS_BAD_COMPONENT_RE = /[<>:"/\\|?*]/;
const CONTROL_CHARACTER_RE = /[\u0000-\u001f\u007f]/;
const BIDI_CONTROL_RE = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;

const ERROR_DEFINITIONS = Object.freeze({
  PLAN_INVALID: Object.freeze({
    code: 'BROWSER_EXPORT_PLAN_INVALID',
    message: 'Browser export plan is invalid',
  }),
  RESOURCE_LIMIT: Object.freeze({
    code: 'BROWSER_EXPORT_RESOURCE_LIMIT',
    message: 'Browser export resource limit exceeded',
  }),
  STATE_INVALID: Object.freeze({
    code: 'BROWSER_EXPORT_STATE_INVALID',
    message: 'Browser export state transition rejected',
  }),
  REQUEST_FAILED: Object.freeze({
    code: 'BROWSER_EXPORT_REQUEST_FAILED',
    message: 'Browser export request failed',
  }),
  VERIFICATION_FAILED: Object.freeze({
    code: 'BROWSER_EXPORT_VERIFICATION_FAILED',
    message: 'Browser export verification failed',
  }),
});

export class BrowserExportError extends Error {
  constructor(definition) {
    super(definition.message);
    this.name = 'BrowserExportError';
    this.code = definition.code;
  }
}

function exportError(definition) {
  return new BrowserExportError(definition);
}

function planInvalid() {
  throw exportError(ERROR_DEFINITIONS.PLAN_INVALID);
}

function resourceLimit() {
  throw exportError(ERROR_DEFINITIONS.RESOURCE_LIMIT);
}

function stateInvalid() {
  throw exportError(ERROR_DEFINITIONS.STATE_INVALID);
}

function containsLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function validateExactFilename(name) {
  if (typeof name !== 'string' || name.length === 0 || containsLoneSurrogate(name)) {
    planInvalid();
  }
  if (
    name === '.' ||
    name === '..' ||
    CONTROL_CHARACTER_RE.test(name) ||
    BIDI_CONTROL_RE.test(name) ||
    WINDOWS_BAD_COMPONENT_RE.test(name) ||
    /^[ ]/.test(name) ||
    /[. ]$/.test(name)
  ) {
    planInvalid();
  }

  const encodedLength = new TextEncoder().encode(name).length;
  if (encodedLength === 0) planInvalid();
  if (encodedLength > MAX_BROWSER_EXPORT_NAME_BYTES) resourceLimit();

  const firstComponent = name.split('.')[0];
  if (WINDOWS_RESERVED_BASENAME_RE.test(firstComponent)) planInvalid();
}

function portableFilenameAlias(name) {
  // This is intentionally a conservative approximation rather than a rename:
  // exact names are retained privately, while aliases are rejected up front.
  return name.normalize('NFC').toLowerCase().replace(/[. ]+$/u, '');
}

function sourceByteLength(source) {
  if (source instanceof Uint8Array) return source.byteLength;
  if (typeof Blob !== 'undefined' && source instanceof Blob) return source.size;
  planInvalid();
}

function validateByteLength(value) {
  if (!Number.isSafeInteger(value) || value < 0) planInvalid();
  if (value > MAX_BROWSER_EXPORT_ARTIFACT_BYTES) resourceLimit();
}

/**
 * Validate the immutable browser publication profile using checked arithmetic.
 * This helper accepts lengths rather than allocating boundary-sized artifacts,
 * and the session factory applies it again to the actual sources.
 */
export function assertBrowserExportByteProfile(byteLengths) {
  if (!Array.isArray(byteLengths) || byteLengths.length === 0) planInvalid();
  if (byteLengths.length > MAX_BROWSER_EXPORT_ARTIFACTS) resourceLimit();

  let aggregate = 0;
  for (const byteLength of byteLengths) {
    validateByteLength(byteLength);
    if (aggregate > MAX_BROWSER_EXPORT_AGGREGATE_BYTES - byteLength) {
      resourceLimit();
    }
    aggregate += byteLength;
  }
  return aggregate;
}

function validateDigest(digest) {
  if (!(digest instanceof Uint8Array) || digest.byteLength !== SHA3_512_DIGEST_BYTES) {
    planInvalid();
  }
}

function digestsEqual(left, right) {
  if (
    !(left instanceof Uint8Array) ||
    !(right instanceof Uint8Array) ||
    left.byteLength !== SHA3_512_DIGEST_BYTES ||
    right.byteLength !== SHA3_512_DIGEST_BYTES
  ) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < SHA3_512_DIGEST_BYTES; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function throwIfAborted(signal) {
  if (signal?.aborted) stateInvalid();
}

/** Hash a bounded byte or Blob source without converting a Blob wholesale. */
export async function digestBrowserExportSourceSha3_512(source, { signal } = {}) {
  const byteLength = sourceByteLength(source);
  validateByteLength(byteLength);
  throwIfAborted(signal);

  if (source instanceof Uint8Array) {
    return sha3_512(source);
  }

  const hasher = sha3_512.create();
  const reader = source.stream().getReader();
  let streamedByteLength = 0;
  let reachedEndOfStream = false;
  const abortReader = () => {
    void reader.cancel().catch(() => {});
  };
  signal?.addEventListener('abort', abortReader, { once: true });
  try {
    while (true) {
      throwIfAborted(signal);
      const { done, value } = await reader.read();
      if (done) {
        reachedEndOfStream = true;
        break;
      }
      if (!(value instanceof Uint8Array)) planInvalid();
      try {
        throwIfAborted(signal);
        // A non-EOF empty chunk makes no progress and permits an attacker-
        // controlled Blob stream to consume unbounded pulls within a bounded
        // declared length. Native Blob streams do not require empty chunks.
        if (value.byteLength === 0) planInvalid();
        if (value.byteLength > byteLength - streamedByteLength) planInvalid();
        streamedByteLength += value.byteLength;
        hasher.update(value);
      } finally {
        value.fill(0);
      }
    }
    throwIfAborted(signal);
    if (streamedByteLength !== byteLength) planInvalid();
    return hasher.digest();
  } finally {
    signal?.removeEventListener('abort', abortReader);
    if (!reachedEndOfStream) {
      try {
        void reader.cancel().catch(() => {});
      } catch {
        // Cancellation is best-effort and must not replace the fixed failure.
      }
    }
    reader.releaseLock();
    if (typeof hasher.destroy === 'function') hasher.destroy();
  }
}

function cloneOwnedSource(source) {
  return source instanceof Uint8Array ? source.slice() : source;
}

function cloneRequestSource(source) {
  return source instanceof Uint8Array ? source.slice() : source;
}

function wipeBytes(value) {
  if (value instanceof Uint8Array) value.fill(0);
}

function publicRow(artifact) {
  return Object.freeze({
    index: artifact.index,
    role: artifact.role,
    state: artifact.state,
  });
}

function fixedSnapshot(artifacts, cancelled) {
  const complete = !cancelled && artifacts.length > 0 && artifacts.every(
    (artifact) => artifact.state === BROWSER_EXPORT_STATES.VERIFIED,
  );
  const status = complete ? 'complete' : (cancelled ? 'cancelled' : 'active');
  return Object.freeze({
    status,
    complete,
    rows: Object.freeze(artifacts.map(publicRow)),
  });
}

function normalizePlanArtifacts(rawArtifacts) {
  if (!Array.isArray(rawArtifacts) || rawArtifacts.length === 0) planInvalid();
  if (rawArtifacts.length > MAX_BROWSER_EXPORT_ARTIFACTS) resourceLimit();

  const seenAliases = new Set();
  const structural = rawArtifacts.map((artifact, index) => {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) planInvalid();
    const { name, source, role, expectedDigest, dispose } = artifact;
    validateExactFilename(name);
    if (!ROLE_SET.has(role)) planInvalid();
    if (dispose != null && typeof dispose !== 'function') planInvalid();
    if (expectedDigest != null) validateDigest(expectedDigest);

    const alias = portableFilenameAlias(name);
    if (seenAliases.has(alias)) planInvalid();
    seenAliases.add(alias);

    const byteLength = sourceByteLength(source);
    return {
      index,
      name,
      source,
      role,
      expectedDigest,
      dispose: dispose || null,
      byteLength,
    };
  });

  assertBrowserExportByteProfile(structural.map((artifact) => artifact.byteLength));
  return structural;
}

function disposeArtifact(artifact) {
  if (artifact.disposed) return;
  artifact.disposed = true;
  wipeBytes(artifact.source);
  wipeBytes(artifact.expectedDigest);
  artifact.source = null;
  artifact.expectedDigest = null;
  const dispose = artifact.dispose;
  artifact.dispose = null;
  if (dispose) {
    try {
      dispose();
    } catch {
      // Cleanup is deliberately best-effort and never reflects callback data.
    }
  }
}

function requireArtifact(artifacts, index) {
  if (!Number.isInteger(index) || index < 0 || index >= artifacts.length) stateInvalid();
  return artifacts[index];
}

export class BrowserExportSession {
  #artifacts;
  #cancelled = false;
  #abortController = new AbortController();

  constructor(token, artifacts) {
    if (token !== SESSION_CONSTRUCTOR_TOKEN) planInvalid();
    this.#artifacts = artifacts;
  }

  snapshot() {
    return fixedSnapshot(this.#artifacts, this.#cancelled);
  }

  toJSON() {
    return this.snapshot();
  }

  get complete() {
    return this.snapshot().complete;
  }

  get cancelled() {
    return this.#cancelled;
  }

  async request(index, requester) {
    const artifact = requireArtifact(this.#artifacts, index);
    if (
      this.#cancelled ||
      typeof requester !== 'function' ||
      artifact.busy ||
      artifact.state !== BROWSER_EXPORT_STATES.READY
    ) {
      stateInvalid();
    }

    artifact.busy = true;
    let requestSource = null;
    try {
      requestSource = cloneRequestSource(artifact.source);
      await requester(Object.freeze({
        name: artifact.name,
        source: requestSource,
        byteLength: artifact.byteLength,
        signal: this.#abortController.signal,
      }));
      if (this.#cancelled || artifact.state === BROWSER_EXPORT_STATES.CANCELLED) {
        stateInvalid();
      }
      artifact.state = BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED;
      return this.snapshot();
    } catch (error) {
      if (!this.#cancelled && artifact.state !== BROWSER_EXPORT_STATES.CANCELLED) {
        artifact.state = BROWSER_EXPORT_STATES.FAILED;
      }
      if (error instanceof BrowserExportError && error.code === ERROR_DEFINITIONS.STATE_INVALID.code) {
        throw error;
      }
      throw exportError(ERROR_DEFINITIONS.REQUEST_FAILED);
    } finally {
      wipeBytes(requestSource);
      artifact.busy = false;
    }
  }

  verify(index, evidence) {
    const artifact = requireArtifact(this.#artifacts, index);
    if (
      this.#cancelled ||
      artifact.busy ||
      artifact.state !== BROWSER_EXPORT_STATES.REQUESTED_UNVERIFIED
    ) {
      stateInvalid();
    }

    const exactName = evidence?.name;
    const digest = evidence?.digest;
    if (
      typeof exactName !== 'string' ||
      exactName !== artifact.name ||
      !digestsEqual(digest, artifact.expectedDigest)
    ) {
      artifact.state = BROWSER_EXPORT_STATES.FAILED;
      throw exportError(ERROR_DEFINITIONS.VERIFICATION_FAILED);
    }

    artifact.state = BROWSER_EXPORT_STATES.VERIFIED;
    disposeArtifact(artifact);
    return this.snapshot();
  }

  retry(index) {
    const artifact = requireArtifact(this.#artifacts, index);
    if (this.#cancelled || artifact.busy || artifact.state !== BROWSER_EXPORT_STATES.FAILED) {
      stateInvalid();
    }
    artifact.state = BROWSER_EXPORT_STATES.READY;
    return this.snapshot();
  }

  cancel() {
    if (this.complete || this.#cancelled) return this.snapshot();
    this.#cancelled = true;
    this.#abortController.abort();
    for (const artifact of this.#artifacts) {
      if (artifact.state !== BROWSER_EXPORT_STATES.VERIFIED) {
        artifact.state = BROWSER_EXPORT_STATES.CANCELLED;
      }
      disposeArtifact(artifact);
    }
    return this.snapshot();
  }
}

const SESSION_CONSTRUCTOR_TOKEN = Object.freeze({});

/**
 * Adopt a complete artifact plan. Structural/profile checks run for the whole
 * set before any source is hashed or made available to a publication adapter.
 * The exact adopted bytes are then SHA3-512 checked before the session exists.
 */
export async function createBrowserExportSession(rawArtifacts) {
  let structural;
  try {
    structural = normalizePlanArtifacts(rawArtifacts);
  } catch (error) {
    if (error instanceof BrowserExportError) throw error;
    // Getters and other hostile plan objects must not smuggle their own
    // messages or values across the public error boundary.
    throw exportError(ERROR_DEFINITIONS.PLAN_INVALID);
  }
  const adopted = structural.map((artifact) => ({
    index: artifact.index,
    name: artifact.name,
    role: artifact.role,
    byteLength: artifact.byteLength,
    source: cloneOwnedSource(artifact.source),
    expectedDigest: artifact.expectedDigest ? artifact.expectedDigest.slice() : null,
    dispose: artifact.dispose,
    disposed: false,
    busy: false,
    state: BROWSER_EXPORT_STATES.READY,
  }));

  try {
    for (const artifact of adopted) {
      let computedDigest;
      try {
        computedDigest = await digestBrowserExportSourceSha3_512(artifact.source);
      } catch {
        planInvalid();
      }
      if (artifact.expectedDigest && !digestsEqual(computedDigest, artifact.expectedDigest)) {
        wipeBytes(computedDigest);
        planInvalid();
      }
      if (!artifact.expectedDigest) artifact.expectedDigest = computedDigest;
      else wipeBytes(computedDigest);
    }
    return new BrowserExportSession(SESSION_CONSTRUCTOR_TOKEN, adopted);
  } catch (error) {
    for (const artifact of adopted) disposeArtifact(artifact);
    if (error instanceof BrowserExportError) throw error;
    throw exportError(ERROR_DEFINITIONS.PLAN_INVALID);
  }
}
