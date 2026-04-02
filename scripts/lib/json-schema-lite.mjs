function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deepEqual(left, right) {
  if (Object.is(left, right)) {
    return true;
  }
  if (typeof left !== typeof right) {
    return false;
  }
  if (Array.isArray(left)) {
    if (!Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    for (let i = 0; i < left.length; i += 1) {
      if (!deepEqual(left[i], right[i])) {
        return false;
      }
    }
    return true;
  }
  if (isObject(left)) {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right || {});
    if (leftKeys.length !== rightKeys.length) {
      return false;
    }
    for (const key of leftKeys) {
      if (!Object.prototype.hasOwnProperty.call(right, key)) {
        return false;
      }
      if (!deepEqual(left[key], right[key])) {
        return false;
      }
    }
    return true;
  }
  return false;
}

function encodePointerToken(token) {
  return String(token).replace(/~/g, '~0').replace(/\//g, '~1');
}

function decodePointerToken(token) {
  return String(token).replace(/~1/g, '/').replace(/~0/g, '~');
}

function joinInstancePath(path, segment) {
  if (typeof segment === 'number') {
    return `${path}[${segment}]`;
  }
  if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(segment)) {
    return `${path}.${segment}`;
  }
  return `${path}[${JSON.stringify(segment)}]`;
}

function resolveJsonPointer(document, pointer) {
  if (!pointer || pointer === '#') {
    return document;
  }
  if (!pointer.startsWith('#')) {
    throw new Error(`Unsupported non-fragment JSON Pointer: ${pointer}`);
  }
  const tokens = pointer.slice(1).split('/');
  let current = document;
  for (const token of tokens) {
    if (token === '') {
      continue;
    }
    const key = decodePointerToken(token);
    if (Array.isArray(current)) {
      const index = Number.parseInt(key, 10);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) {
        throw new Error(`JSON Pointer does not resolve: ${pointer}`);
      }
      current = current[index];
      continue;
    }
    if (!isObject(current) || !Object.prototype.hasOwnProperty.call(current, key)) {
      throw new Error(`JSON Pointer does not resolve: ${pointer}`);
    }
    current = current[key];
  }
  return current;
}

// This helper is intentionally limited to the keyword subset used by the
// checked-in Quantum Vault schemas and fixture corpus. It is not a general
// draft 2020-12 validator.
export const SUPPORTED_SCHEMA_KEYS = new Set([
  '$schema',
  '$id',
  '$defs',
  '$ref',
  'title',
  'description',
  'type',
  'const',
  'enum',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'minItems',
  'maxItems',
  'minLength',
  'maxLength',
  'pattern',
  'minimum',
  'maximum',
  'oneOf',
  'allOf'
]);

function assertSupportedSchemaKeywords(schema, schemaPath) {
  if (!isObject(schema)) {
    return;
  }
  for (const key of Object.keys(schema)) {
    if (!SUPPORTED_SCHEMA_KEYS.has(key)) {
      throw new Error(`Unsupported JSON Schema keyword in local validator at ${schemaPath}: ${key}`);
    }
  }
}

function matchesType(typeName, value) {
  switch (typeName) {
    case 'object':
      return isObject(value);
    case 'array':
      return Array.isArray(value);
    case 'string':
      return typeof value === 'string';
    case 'integer':
      return Number.isInteger(value);
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'null':
      return value === null;
    default:
      throw new Error(`Unsupported JSON Schema type in local validator: ${typeName}`);
  }
}

class SchemaValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SchemaValidationError';
  }
}

export function createSchemaRegistry(entries) {
  const documents = new Map();
  for (const entry of entries) {
    if (!entry?.uri || !entry?.schema) {
      throw new Error('Schema registry entries must include uri and schema');
    }
    documents.set(entry.uri, entry.schema);
  }

  function resolveRef(baseUri, ref, fromSchemaPath) {
    const resolved = new URL(ref, baseUri);
    const documentUri = `${resolved.origin}${resolved.pathname}`;
    const document = documents.get(documentUri);
    if (!document) {
      throw new Error(`Unresolved schema reference at ${fromSchemaPath}: ${ref}`);
    }
    return {
      schema: resolveJsonPointer(document, resolved.hash || '#'),
      baseUri: documentUri,
      schemaPath: `${documentUri}${resolved.hash || '#'}`
    };
  }

  function validateSchema(instance, schema, baseUri, instancePath, schemaPath) {
    if (schema === true) {
      return;
    }
    if (schema === false) {
      throw new SchemaValidationError(`${instancePath}: rejected by boolean false schema (${schemaPath})`);
    }
    assertSupportedSchemaKeywords(schema, schemaPath);

    if (schema.$ref) {
      const resolved = resolveRef(baseUri, schema.$ref, schemaPath);
      validateSchema(instance, resolved.schema, resolved.baseUri, instancePath, resolved.schemaPath);
    }

    if (Array.isArray(schema.allOf)) {
      for (let index = 0; index < schema.allOf.length; index += 1) {
        validateSchema(
          instance,
          schema.allOf[index],
          baseUri,
          instancePath,
          `${schemaPath}/allOf/${index}`
        );
      }
    }

    if (Array.isArray(schema.oneOf)) {
      let matches = 0;
      for (let index = 0; index < schema.oneOf.length; index += 1) {
        try {
          validateSchema(
            instance,
            schema.oneOf[index],
            baseUri,
            instancePath,
            `${schemaPath}/oneOf/${index}`
          );
          matches += 1;
        } catch (error) {
          if (!(error instanceof SchemaValidationError)) {
            throw error;
          }
        }
      }
      if (matches !== 1) {
        throw new SchemaValidationError(
          `${instancePath}: expected exactly one matching branch at ${schemaPath}, got ${matches}`
        );
      }
    }

    if (Object.prototype.hasOwnProperty.call(schema, 'const') && !deepEqual(instance, schema.const)) {
      throw new SchemaValidationError(`${instancePath}: expected const ${JSON.stringify(schema.const)} at ${schemaPath}`);
    }

    if (Array.isArray(schema.enum)) {
      let matched = false;
      for (const option of schema.enum) {
        if (deepEqual(instance, option)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        throw new SchemaValidationError(`${instancePath}: expected one of ${JSON.stringify(schema.enum)} at ${schemaPath}`);
      }
    }

    if (schema.type) {
      if (!matchesType(schema.type, instance)) {
        throw new SchemaValidationError(`${instancePath}: expected type ${schema.type} at ${schemaPath}`);
      }
    }

    if (typeof instance === 'string') {
      if (schema.minLength != null && instance.length < schema.minLength) {
        throw new SchemaValidationError(`${instancePath}: string shorter than minLength ${schema.minLength} at ${schemaPath}`);
      }
      if (schema.maxLength != null && instance.length > schema.maxLength) {
        throw new SchemaValidationError(`${instancePath}: string longer than maxLength ${schema.maxLength} at ${schemaPath}`);
      }
      if (schema.pattern != null && !(new RegExp(schema.pattern).test(instance))) {
        throw new SchemaValidationError(`${instancePath}: string does not match pattern ${schema.pattern} at ${schemaPath}`);
      }
    }

    if (typeof instance === 'number') {
      if (schema.minimum != null && instance < schema.minimum) {
        throw new SchemaValidationError(`${instancePath}: number smaller than minimum ${schema.minimum} at ${schemaPath}`);
      }
      if (schema.maximum != null && instance > schema.maximum) {
        throw new SchemaValidationError(`${instancePath}: number larger than maximum ${schema.maximum} at ${schemaPath}`);
      }
    }

    if (Array.isArray(instance)) {
      if (schema.minItems != null && instance.length < schema.minItems) {
        throw new SchemaValidationError(`${instancePath}: array shorter than minItems ${schema.minItems} at ${schemaPath}`);
      }
      if (schema.maxItems != null && instance.length > schema.maxItems) {
        throw new SchemaValidationError(`${instancePath}: array longer than maxItems ${schema.maxItems} at ${schemaPath}`);
      }
      if (schema.items) {
        for (let index = 0; index < instance.length; index += 1) {
          validateSchema(
            instance[index],
            schema.items,
            baseUri,
            joinInstancePath(instancePath, index),
            `${schemaPath}/items`
          );
        }
      }
    }

    if (isObject(instance)) {
      if (Array.isArray(schema.required)) {
        for (const key of schema.required) {
          if (!Object.prototype.hasOwnProperty.call(instance, key)) {
            throw new SchemaValidationError(`${instancePath}: missing required property ${key} at ${schemaPath}`);
          }
        }
      }

      const properties = isObject(schema.properties) ? schema.properties : {};
      for (const key of Object.keys(properties)) {
        if (Object.prototype.hasOwnProperty.call(instance, key)) {
          validateSchema(
            instance[key],
            properties[key],
            baseUri,
            joinInstancePath(instancePath, key),
            `${schemaPath}/properties/${encodePointerToken(key)}`
          );
        }
      }

      if (schema.additionalProperties === false) {
        const allowed = new Set(Object.keys(properties));
        for (const key of Object.keys(instance)) {
          if (!allowed.has(key)) {
            throw new SchemaValidationError(`${instancePath}: additional property ${key} is not allowed at ${schemaPath}`);
          }
        }
      } else if (isObject(schema.additionalProperties)) {
        const allowed = new Set(Object.keys(properties));
        for (const key of Object.keys(instance)) {
          if (!allowed.has(key)) {
            validateSchema(
              instance[key],
              schema.additionalProperties,
              baseUri,
              joinInstancePath(instancePath, key),
              `${schemaPath}/additionalProperties`
            );
          }
        }
      }
    }
  }

  function validate(schemaUri, instance) {
    const document = documents.get(schemaUri);
    if (!document) {
      throw new Error(`Unknown schema URI: ${schemaUri}`);
    }
    validateSchema(instance, document, schemaUri, '$', `${schemaUri}#`);
  }

  return {
    validate
  };
}

export { SchemaValidationError };
