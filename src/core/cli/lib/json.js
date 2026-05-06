export function createJsonError(command, error) {
  return {
    command,
    ok: false,
    error: error?.message || String(error),
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
