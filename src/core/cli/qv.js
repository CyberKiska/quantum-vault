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
  parseRestoreArgs,
  renderRestoreSummary,
  restoreDryRunFromInputs,
  runRestoreDryRunCommand,
} from './commands/restore-dry-run.js';
import {
  parseVerifyArgs,
  renderVerifySummary,
  runVerifyCommand,
  verifyArchiveInputs,
} from './commands/verify.js';
import {
  createJsonError,
  parseGlobalJsonFlag,
  writeJson,
  writeText,
} from './lib/json.js';

export {
  restoreDryRunFromInputs,
  runCanonicalizeCommand,
  runInspectCommand,
  runRestoreDryRunCommand,
  runVerifyCommand,
  verifyArchiveInputs,
};

function helpText() {
  return [
    'Quantum Vault CLI',
    '',
    'Commands:',
    '  qv inspect <artifact-file> [--json]',
    '  qv canonicalize <artifact-file> [--json]',
    '  qv verify <archive-state.json> [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--json]',
    '  qv restore --shards <glob-or-file> [--shards <glob-or-file>] [--archive-state <file>] [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] --dry-run [--json]',
    '',
    'Phase 1 scope:',
    '  restore is read-only and requires --dry-run',
    '  attach and write-mode restore are out of scope',
    '',
  ].join('\n');
}

export async function runQvCli(argv, {
  cwd = process.cwd(),
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  const args = [...argv];
  const command = String(args.shift() || '').trim();

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    writeText(stdout, `${helpText()}\n`);
    return 0;
  }

  const json = parseGlobalJsonFlag(args);

  try {
    if (command === 'inspect') {
      const { filePath } = parseInspectArgs(args);
      const report = await runInspectCommand(filePath);
      if (json) {
        writeJson(stdout, report);
      } else {
        writeText(stdout, renderInspectSummary(report));
      }
      return 0;
    }

    if (command === 'canonicalize') {
      const { filePath } = parseCanonicalizeArgs(args);
      const report = await runCanonicalizeCommand(filePath);
      if (json) {
        writeJson(stdout, createCanonicalizeJsonReport(report));
      } else {
        stdout.write(Buffer.from(report.canonicalBytes));
      }
      return 0;
    }

    if (command === 'verify') {
      const options = parseVerifyArgs(args);
      const authenticity = await runVerifyCommand(options);
      if (options.json) {
        writeJson(stdout, authenticity);
      } else {
        writeText(stdout, renderVerifySummary(authenticity));
      }
      return authenticity?.policy?.satisfied === true ? 0 : 1;
    }

    if (command === 'restore') {
      const options = parseRestoreArgs(args);
      const summary = await runRestoreDryRunCommand(options, { cwd });
      if (options.json) {
        writeJson(stdout, summary);
      } else {
        writeText(stdout, renderRestoreSummary(summary));
      }
      return summary.wouldSucceed === true ? 0 : 1;
    }

    throw new Error(`Unknown command: ${command}`);
  } catch (error) {
    if (json) {
      writeJson(stdout, createJsonError(command, error));
    } else {
      writeText(stderr, `${error?.message || error}\n`);
    }
    return 1;
  }
}
