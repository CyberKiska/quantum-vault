import {
  createCanonicalizeJsonReport,
  parseCanonicalizeArgs,
  runCanonicalizeCommand,
} from './commands/canonicalize.js';
import {
  parseInspectArgs,
  renderInspectSummary,
  runInspectCommand,
} from './commands/inspect.js';
import {
  parseKeygenArgs,
  renderKeygenSummary,
  runKeygenCommand,
} from './commands/keygen.js';
import {
  parseEncryptArgs,
  renderEncryptSummary,
  runEncryptCommand,
} from './commands/encrypt.js';
import {
  parseDecryptArgs,
  renderDecryptSummary,
  runDecryptCommand,
} from './commands/decrypt.js';
import {
  parseRestoreArgs,
  renderRestoreSummary,
  restoreDryRunFromInputs,
  runRestoreCommand,
  runRestoreDryRunCommand,
} from './commands/restore.js';
import {
  parseSplitArgs,
  renderSplitInternalHelp,
  renderSplitSummary,
  runSplitCommand,
} from './commands/split.js';
import {
  parseAttachArgs,
  renderAttachSummary,
  runAttachCommand,
} from './commands/attach.js';
import {
  parseReshareArgs,
  renderReshareSummary,
  runReshareCommand,
} from './commands/reshare.js';
import {
  parseVerifyArgs,
  renderVerifySummary,
  runVerifyCommand,
  verifyReportSatisfied,
  verifyArchiveInputs,
} from './commands/verify.js';
import {
  parseSelftestArgs,
  renderSelftestSummary,
  runSelftestCommand,
} from './commands/selftest.js';
import {
  parseVersionArgs,
  renderVersionSummary,
  runVersionCommand,
} from './commands/version.js';
import {
  createJsonError,
  parseGlobalJsonFlag,
  withCliJsonEnvelope,
  writeJson,
  writeText,
} from './lib/json.js';
import { EXIT, mapErrorToExitCode } from './lib/exit.js';
import { runWithIoPolicy } from './lib/io.js';

export {
  restoreDryRunFromInputs,
  runCanonicalizeCommand,
  runDecryptCommand,
  runEncryptCommand,
  runInspectCommand,
  runKeygenCommand,
  runAttachCommand,
  runReshareCommand,
  runRestoreCommand,
  runRestoreDryRunCommand,
  runSelftestCommand,
  runSplitCommand,
  runVersionCommand,
  runVerifyCommand,
  verifyReportSatisfied,
  verifyArchiveInputs,
};

const COMMAND_HELP = Object.freeze({
  keygen: 'qv keygen --out <dir> [--name <prefix>] [--force] [--print-public] [--json]',
  encrypt: 'qv encrypt <input-file> --public-key <publicKey.qkey> --out <output.qenc> [--filename <name>] [--force] [--json]\nqv encrypt --pack <file> <file> [...] --public-key <publicKey.qkey> --out <output.qenc> [--filename <bundle.qvpack>] [--force] [--json]',
  decrypt: 'qv decrypt <input.qenc> --private-key <privateKey.qkey> [--out <file>] [--out-dir <dir>] [--use-original-filename] [--extract-qvpack] [--force] [--json]',
  split: 'qv split <input.qenc> (--private-key <path> | --private-key-stdin | --private-key-env <NAME>) --n <int> --k <int> [--out <dir>] [--auth-policy-level <level>] [--min-valid-signatures <int>] [--force] [--json]\nInternal/testing flags: qv split --help-internal',
  attach: 'qv attach [--shards <glob-or-file> ...] [--archive-state <file>] [--bundle <file>] [--sig <file> ...] [--sig-import <json> ...] [--pqpk <file> ...] [--ots <file> ...] [--source-evidence <json-file> | --source-evidence-bytes <file>] [--ed25519-signer <address>] [--out-bundle <file>] [--out-shards <dir>] [--no-embed-into-shards] [--force] [--json]',
  reshare: 'qv reshare --shards <glob-or-file> ... --n <int> --k <int> [--bundle <file>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] [--reason-code <string>] [--operator-role <string>] [--notes <string>] [--performed-at <iso8601>] [--maintenance-sig <file> ...] [--maintenance-pqpk <file> ...] [--maintenance-ots <file> ...] [--out <dir>] [--force] [--json]',
  inspect: 'qv inspect <artifact-file> [--json]',
  canonicalize: 'qv canonicalize <artifact-file> [--json]',
  verify: 'qv verify <archive-state.json> [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--include-detached-summary] [--required-policy-level <level>] [--json]',
  restore: 'qv restore --shards <glob-or-file> [--shards <glob-or-file>] [--archive-state <file>] [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] [--required-policy-level <level>] [--out <dir>] [--out-qenc <file>] [--out-key <file>] [--decrypt --out-plaintext <file>] [--dry-run] [--accept-policy-warnings] [--force] [--json]',
  selftest: 'qv selftest [--filter <substring>] [--json]',
  version: 'qv version [--json]',
});

function globalHelpText() {
  return [
    'Global flags:',
    '  Global flags must precede the command, except --help / -h.',
    '  --json             Emit a single stable JSON document on stdout.',
    '  --no-color         Disable ANSI color. This is the default.',
    '  --color            Opt in to color only when stderr is a TTY. Current output remains plain.',
    '  --quiet            Suppress future human progress messages on stderr.',
    '  --allow-symlink    Permit explicit symlink input paths. Default is fail-closed.',
    '  --help, -h         Show help.',
  ].join('\n');
}

function commandHelpText(command) {
  const usage = COMMAND_HELP[command];
  if (!usage) return '';
  const lines = [`Usage: ${usage}`, '', globalHelpText(), ''];
  if (command === 'split') {
    lines.splice(2, 0, 'Deterministic test-only flags: `qv split --help-internal`.', '');
  }
  return lines.join('\n');
}

function helpText() {
  return [
    'Quantum Vault CLI',
    '',
    'Commands:',
    '  qv keygen --out <dir> [--name <prefix>] [--force] [--print-public] [--json]',
    '  qv encrypt <input-file> --public-key <publicKey.qkey> --out <output.qenc> [--filename <name>] [--force] [--json]',
    '  qv encrypt --pack <file> <file> [...] --public-key <publicKey.qkey> --out <output.qenc> [--filename <bundle.qvpack>] [--force] [--json]',
    '  qv decrypt <input.qenc> --private-key <privateKey.qkey> [--out <file>] [--out-dir <dir>] [--use-original-filename] [--extract-qvpack] [--force] [--json]',
    '  qv split <input.qenc> (--private-key <path> | --private-key-stdin | --private-key-env <NAME>) --n <int> --k <int> [--out <dir>] [--auth-policy-level <level>] [--min-valid-signatures <int>] [--force] [--json]',
    '  qv attach [--shards <glob-or-file> ...] [--archive-state <file>] [--bundle <file>] [--sig <file> ...] [--sig-import <json> ...] [--pqpk <file> ...] [--ots <file> ...] [--source-evidence <json-file> | --source-evidence-bytes <file>] [--ed25519-signer <address>] [--out-bundle <file>] [--out-shards <dir>] [--no-embed-into-shards] [--force] [--json]',
    '  qv reshare --shards <glob-or-file> ... --n <int> --k <int> [--bundle <file>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] [--reason-code <string>] [--operator-role <string>] [--notes <string>] [--performed-at <iso8601>] [--maintenance-sig <file> ...] [--maintenance-pqpk <file> ...] [--maintenance-ots <file> ...] [--out <dir>] [--force] [--json]',
    '  qv inspect <artifact-file> [--json]',
    '  qv canonicalize <artifact-file> [--json]',
    '  qv verify <archive-state.json> [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--include-detached-summary] [--required-policy-level <level>] [--json]',
    '  qv restore --shards <glob-or-file> [--shards <glob-or-file>] [--archive-state <file>] [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] [--required-policy-level <level>] [--out <dir>] [--out-qenc <file>] [--out-key <file>] [--decrypt --out-plaintext <file>] [--dry-run] [--accept-policy-warnings] [--force] [--json]',
    '  qv selftest [--filter <substring>] [--json]',
    '  qv version [--json]',
    '',
    'Run `qv help <command>` or `qv <command> --help` for command-specific help.',
    '',
    globalHelpText(),
    '',
    'Current write scope:',
    '  keygen writes ML-KEM-1024 .qkey files',
    '  encrypt writes .qenc containers and can pre-pack multiple files as .qvpack payloads',
    '  decrypt writes plaintext files and can explicitly extract authenticated .qvpack payloads',
    '  split writes QVqcont-7 shards plus archive-state, cohort-binding, and lifecycle-bundle JSON',
    '  attach writes updated lifecycle-bundle JSON and can rewrite successor shards with the bundle embedded',
    '  reshare writes a same-state successor cohort plus transition and lifecycle-bundle JSON',
    '  restore writes recovered .qenc/.qkey artifacts unless --dry-run is supplied',
    '  selftest runs the core cryptographic self-test suite',
    '  version prints registered format and cryptographic profile identifiers',
    '',
  ].join('\n');
}

function parseGlobalFlags(rawArgs, stderr) {
  const args = [];
  const options = {
    help: false,
    json: false,
    quiet: false,
    color: false,
    allowSymlink: false,
  };

  let commandSeen = false;
  for (const arg of rawArgs) {
    if (arg === '--help' || arg === '-h') {
      options.help = true;
      continue;
    }
    if (!commandSeen && arg === '--json') {
      options.json = true;
      continue;
    }
    if (!commandSeen && arg === '--quiet') {
      options.quiet = true;
      continue;
    }
    if (!commandSeen && arg === '--no-color') {
      options.color = false;
      continue;
    }
    if (!commandSeen && arg === '--color') {
      options.color = stderr?.isTTY === true;
      continue;
    }
    if (!commandSeen && arg === '--allow-symlink') {
      options.allowSymlink = true;
      continue;
    }
    args.push(arg);
    commandSeen = true;
  }
  return { ...options, args };
}

function formatCliError(command, error) {
  const label = command || 'qv';
  return `qv: ${label}: ${error?.message || error}\n`;
}

export async function runQvCli(argv, {
  cwd = process.cwd(),
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  env = process.env,
} = {}) {
  const globalOptions = parseGlobalFlags([...argv], stderr);
  const args = [...globalOptions.args];
  const command = String(args.shift() || '').trim();
  if (globalOptions.json && !args.includes('--json')) {
    args.push('--json');
  }

  if (!command) {
    writeText(stdout, `${helpText()}\n`);
    return EXIT.OK;
  }

  if (command === 'help') {
    const subject = String(args.shift() || '').trim();
    if (!subject) {
      writeText(stdout, `${helpText()}\n`);
      return EXIT.OK;
    }
    const text = commandHelpText(subject);
    if (!text) {
      writeText(stderr, `qv: help: Unknown command: ${subject}\n`);
      return EXIT.USAGE;
    }
    writeText(stdout, text);
    return EXIT.OK;
  }

  if (globalOptions.help) {
    const text = commandHelpText(command);
    if (!text) {
      writeText(stderr, `qv: ${command}: Unknown command: ${command}\n`);
      return EXIT.USAGE;
    }
    writeText(stdout, text);
    return EXIT.OK;
  }

  if (command === 'split' && args[0] === '--help-internal') {
    writeText(stdout, `${renderSplitInternalHelp()}\n`);
    return EXIT.OK;
  }

  let json = parseGlobalJsonFlag(args);
  let inspectCanonicalizeArgs = args;
  if (command === 'inspect' || command === 'canonicalize') {
    json = args.includes('--json');
    inspectCanonicalizeArgs = args.filter((arg) => arg !== '--json');
  }

  try {
    return await runWithIoPolicy({ allowSymlink: globalOptions.allowSymlink }, async () => {
    if (command === 'keygen') {
      const options = parseKeygenArgs(args);
      const { report, publicKeyBase64 } = await runKeygenCommand(options);
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(options.printPublic
          ? { ...report, publicKeyBase64 }
          : report));
      } else {
        writeText(stdout, renderKeygenSummary(report));
        if (options.printPublic) {
          writeText(stdout, `${publicKeyBase64}\n`);
        }
      }
      return EXIT.OK;
    }

    if (command === 'encrypt') {
      const options = parseEncryptArgs(args);
      const report = await runEncryptCommand(options);
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderEncryptSummary(report));
      }
      return EXIT.OK;
    }

    if (command === 'decrypt') {
      const options = parseDecryptArgs(args);
      const report = await runDecryptCommand(options, { stdin, env });
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderDecryptSummary(report));
      }
      return EXIT.OK;
    }

    if (command === 'split') {
      const options = parseSplitArgs(args, { env });
      const report = await runSplitCommand(options, { stdin, cwd, env });
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderSplitSummary(report));
      }
      return EXIT.OK;
    }

    if (command === 'attach') {
      const options = parseAttachArgs(args);
      const report = await runAttachCommand(options, { cwd });
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderAttachSummary(report));
      }
      return EXIT.OK;
    }

    if (command === 'reshare') {
      const options = parseReshareArgs(args);
      const report = await runReshareCommand(options, { cwd });
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderReshareSummary(report));
      }
      return EXIT.OK;
    }

    if (command === 'inspect') {
      const { filePath } = parseInspectArgs(inspectCanonicalizeArgs);
      const report = await runInspectCommand(filePath);
      if (json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderInspectSummary(report));
      }
      return EXIT.OK;
    }

    if (command === 'canonicalize') {
      const { filePath } = parseCanonicalizeArgs(inspectCanonicalizeArgs);
      const report = await runCanonicalizeCommand(filePath);
      if (json) {
        writeJson(stdout, withCliJsonEnvelope(createCanonicalizeJsonReport(report)));
      } else {
        stdout.write(Buffer.from(report.canonicalBytes));
      }
      return EXIT.OK;
    }

    if (command === 'verify') {
      const options = parseVerifyArgs(args);
      const authenticity = await runVerifyCommand(options);
      const policySatisfied = verifyReportSatisfied(authenticity);
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(authenticity, {
          command: 'verify',
          ok: policySatisfied,
        }));
      } else {
        writeText(stdout, renderVerifySummary(authenticity));
      }
      return policySatisfied ? EXIT.OK : EXIT.ERROR;
    }

    if (command === 'restore') {
      const options = parseRestoreArgs(args);
      const summary = await runRestoreCommand(options, { cwd });
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(summary, {
          ok: summary.wouldSucceed === true,
        }));
      } else {
        writeText(stdout, renderRestoreSummary(summary));
      }
      return summary.wouldSucceed === true ? EXIT.OK : EXIT.ERROR;
    }

    if (command === 'selftest') {
      const options = parseSelftestArgs(args);
      const report = await runSelftestCommand(options);
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(report, {
          ok: report.ok === true,
        }));
      } else {
        writeText(stdout, renderSelftestSummary(report));
      }
      return report.ok === true ? EXIT.OK : EXIT.ERROR;
    }

    if (command === 'version') {
      const options = parseVersionArgs(args);
      const report = await runVersionCommand(options);
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderVersionSummary(report));
      }
      return EXIT.OK;
    }

    throw new Error(`Unknown command: ${command}`);
    });
  } catch (error) {
    if (json) {
      writeJson(stdout, createJsonError(command, error));
    } else {
      writeText(stderr, formatCliError(command, error));
    }
    return mapErrorToExitCode(error);
  }
}
