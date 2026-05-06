export function takeValue(args, index, flag) {
  if (index + 1 >= args.length) {
    throw new Error(`${flag} requires a value`);
  }
  return args[index + 1];
}

export function parseSingleFileCommandArgs(command, args) {
  if (args.length === 0 || args[0] === '--json') {
    throw new Error(`${command} requires <artifact-file>`);
  }
  const filePath = args[0];
  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--json') {
      continue;
    }
    throw new Error(`Unknown ${command} option: ${arg}`);
  }
  return { filePath };
}
