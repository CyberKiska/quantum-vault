const RESTORE_RESULT_BYTE_FIELDS = Object.freeze(['qencBytes', 'privKey']);

function isByteArray(value) {
  return value instanceof Uint8Array;
}

function normalizePath(path) {
  if (Array.isArray(path)) return path.filter((part) => typeof part === 'string' && part.length > 0);
  if (typeof path === 'string' && path.length > 0) return path.split('.').filter(Boolean);
  return [];
}

function readPath(target, path) {
  const parts = normalizePath(path);
  if (parts.length === 0) return undefined;

  let current = target;
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined;
    current = current[part];
  }
  return current;
}

/** Best-effort zeroization for byte buffers. Non-byte values are ignored. */
export function wipeBytes(...values) {
  for (const value of values) {
    if (!isByteArray(value)) continue;
    try {
      value.fill(0);
    } catch {
      // Best-effort cleanup must not mask the caller's original success/failure path.
    }
  }
}

/**
 * Best-effort zeroization of explicitly allowlisted byte-array fields.
 * Allowlist entries may be top-level keys (`qencBytes`) or simple paths (`nested.keyBytes`).
 */
export function wipeByteArraysInObject(target, allowlist = []) {
  if (target == null || typeof target !== 'object' || !Array.isArray(allowlist)) return;
  for (const path of allowlist) {
    wipeBytes(readPath(target, path));
  }
}

/** Best-effort cleanup facade for core restore results. */
export function wipeRestoreResult(result) {
  wipeByteArraysInObject(result, RESTORE_RESULT_BYTE_FIELDS);
}
