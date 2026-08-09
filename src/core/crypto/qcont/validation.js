export function ensureEqual(actual, expected, field) {
  if (actual !== expected) {
    throw new Error(`${field} mismatch (expected ${expected}, got ${actual})`);
  }
}
