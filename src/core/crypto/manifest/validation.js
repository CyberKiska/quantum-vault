export function ensureObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function isPlainJsonObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeIJsonFreeformValue(value, field, stack) {
  if (value === null) return null;

  const valueType = typeof value;
  if (valueType === 'boolean' || valueType === 'string') {
    return value;
  }
  if (valueType === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value) || value < 0) {
      throw new Error(`Invalid ${field}`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (stack.has(value)) {
      throw new Error(`Invalid ${field}`);
    }
    stack.add(value);
    try {
      return value.map((entry, index) => normalizeIJsonFreeformValue(entry, `${field}[${index}]`, stack));
    } finally {
      stack.delete(value);
    }
  }
  if (!isPlainJsonObject(value)) {
    throw new Error(`Invalid ${field}`);
  }
  if (stack.has(value)) {
    throw new Error(`Invalid ${field}`);
  }
  stack.add(value);
  try {
    const normalized = Object.getPrototypeOf(value) === null ? Object.create(null) : {};
    for (const key of Object.keys(value)) {
      normalized[key] = normalizeIJsonFreeformValue(value[key], `${field}.${key}`, stack);
    }
    return normalized;
  } finally {
    stack.delete(value);
  }
}

export function ensureIJsonFreeformValue(value, field) {
  return normalizeIJsonFreeformValue(value, field, new Set());
}

export function ensureString(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

export function ensureOptionalString(value, field) {
  if (value == null) return null;
  return ensureString(value, field);
}

export function ensureInteger(value, field, min = 0, max = null) {
  if (!Number.isInteger(value) || value < min || (max != null && value > max)) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

export function ensureSafeInteger(value, field, min = 0) {
  return ensureInteger(value, field, min, Number.MAX_SAFE_INTEGER);
}

export function ensureExactString(value, field, expected) {
  const text = ensureString(value, field);
  if (text !== expected) {
    throw new Error(`Invalid ${field}`);
  }
  return text;
}

export function ensureHex(value, field, expectedLength = null) {
  const text = ensureString(value, field);
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
