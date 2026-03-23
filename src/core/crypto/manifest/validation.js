export function ensureObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

export function ensureString(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

export function ensureOptionalString(value, field) {
  if (value == null || value === '') return null;
  return ensureString(value, field);
}

export function ensureInteger(value, field, min = 0) {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

export function ensureHex(value, field, expectedLength = null) {
  const text = ensureString(value, field).toLowerCase();
  if (!/^[0-9a-f]+$/.test(text)) {
    throw new Error(`Invalid ${field}`);
  }
  if (expectedLength != null && text.length !== expectedLength) {
    throw new Error(`Invalid ${field}`);
  }
  return text;
}

export function assertExactKeys(source, requiredKeys, optionalKeys, field) {
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of Object.keys(source)) {
    if (!allowed.has(key)) {
      throw new Error(`Unknown ${field}.${key}`);
    }
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) {
      throw new Error(`Missing ${field}.${key}`);
    }
  }
}
