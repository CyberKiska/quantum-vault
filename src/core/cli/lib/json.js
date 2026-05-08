import { getErrorQvCode } from './exit.js';

export const CLI_SCHEMA_VERSION = 1;

export function withCliJsonEnvelope(value, {
  command = '',
  ok,
} = {}) {
  const source = value && typeof value === 'object' ? value : {};
  const {
    command: sourceCommand,
    ok: sourceOk,
    cliSchemaVersion: _sourceSchemaVersion,
    ...rest
  } = source;
  return {
    command: command || sourceCommand || '',
    ok: typeof ok === 'boolean' ? ok : (typeof sourceOk === 'boolean' ? sourceOk : true),
    cliSchemaVersion: CLI_SCHEMA_VERSION,
    ...rest,
  };
}

export function createJsonError(command, error) {
  return {
    command,
    ok: false,
    cliSchemaVersion: CLI_SCHEMA_VERSION,
    error: error?.message || String(error),
    qvCode: getErrorQvCode(error),
  };
}

export function writeText(stream, text) {
  stream.write(text);
}

export function writeJson(stream, value) {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

export function parseGlobalJsonFlag(args) {
  return args.includes('--json');
}
