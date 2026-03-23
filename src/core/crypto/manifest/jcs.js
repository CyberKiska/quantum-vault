import { assertNoLoneSurrogates } from './strict-json.js';

export const MANIFEST_CANONICALIZATION_LABEL = 'QV-JSON-RFC8785-v1';
export const BUNDLE_CANONICALIZATION_LABEL = 'QV-BUNDLE-JSON-v1';

const encoder = new TextEncoder();

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function serializeNumber(value) {
  if (!Number.isFinite(value)) {
    throw new Error('RFC 8785 does not allow non-finite numbers');
  }
  return JSON.stringify(value);
}

function serializeString(value, field = 'string') {
  assertNoLoneSurrogates(value, field);
  return JSON.stringify(value);
}

function serializeArray(arr, stack, field) {
  if (stack.has(arr)) {
    throw new Error('RFC 8785 does not allow cyclic structures');
  }
  stack.add(arr);
  try {
    const items = arr.map((item, index) => serializeValue(item, stack, `${field}[${index}]`));
    return `[${items.join(',')}]`;
  } finally {
    stack.delete(arr);
  }
}

function serializeObject(obj, stack, field) {
  if (!isPlainObject(obj)) {
    throw new Error(`RFC 8785 requires plain JSON objects for ${field}`);
  }
  if (stack.has(obj)) {
    throw new Error('RFC 8785 does not allow cyclic structures');
  }
  stack.add(obj);
  const keys = Object.keys(obj).sort();
  try {
    const fields = [];
    for (const key of keys) {
      const value = obj[key];
      fields.push(`${serializeString(key, `${field} key`)}:${serializeValue(value, stack, `${field}.${key}`)}`);
    }
    return `{${fields.join(',')}}`;
  } finally {
    stack.delete(obj);
  }
}

function serializeValue(value, stack = new Set(), field = 'value') {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return serializeNumber(value);
  if (t === 'string') return serializeString(value, field);
  if (t === 'bigint') throw new Error(`RFC 8785 does not allow bigint values for ${field}`);
  if (t === 'undefined' || t === 'function' || t === 'symbol') {
    throw new Error(`RFC 8785 does not allow ${t} values for ${field}`);
  }
  if (Array.isArray(value)) return serializeArray(value, stack, field);
  if (t === 'object') return serializeObject(value, stack, field);
  throw new Error(`Unsupported RFC 8785 value type for ${field}: ${t}`);
}

export function canonicalizeJson(value) {
  return serializeValue(value, new Set(), 'value');
}

export function canonicalizeJsonToBytes(value) {
  return encoder.encode(canonicalizeJson(value));
}
