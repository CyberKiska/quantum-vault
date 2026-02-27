// RFC 8785 (JCS) canonical JSON serializer (subset for deterministic manifests)

const encoder = new TextEncoder();

function serializeNumber(value) {
  if (!Number.isFinite(value)) {
    throw new Error('JCS does not allow non-finite numbers');
  }
  return JSON.stringify(value);
}

function serializeArray(arr) {
  const items = arr.map((item) => {
    if (item === undefined || typeof item === 'function' || typeof item === 'symbol') return 'null';
    return serializeValue(item);
  });
  return `[${items.join(',')}]`;
}

function serializeObject(obj) {
  const keys = Object.keys(obj).sort();
  const fields = [];
  for (const key of keys) {
    const value = obj[key];
    if (value === undefined || typeof value === 'function' || typeof value === 'symbol') continue;
    fields.push(`${JSON.stringify(key)}:${serializeValue(value)}`);
  }
  return `{${fields.join(',')}}`;
}

function serializeValue(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return serializeNumber(value);
  if (t === 'string') return JSON.stringify(value);
  if (t === 'bigint') throw new Error('JCS does not allow bigint values');
  if (Array.isArray(value)) return serializeArray(value);
  if (t === 'object') return serializeObject(value);
  throw new Error(`Unsupported JCS value type: ${t}`);
}

export function canonicalizeJson(value) {
  return serializeValue(value);
}

export function canonicalizeJsonToBytes(value) {
  return encoder.encode(canonicalizeJson(value));
}
