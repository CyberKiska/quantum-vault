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
  withCliJsonEnvelope,
  writeJson,
  writeText,
} from './lib/json.js';
import { EXIT, mapErrorToExitCode } from './lib/exit.js';

export {
  restoreDryRunFromInputs,
  runCanonicalizeCommand,
  runInspectCommand,
  runKeygenCommand,
  runRestoreDryRunCommand,
  runVerifyCommand,
  verifyArchiveInputs,
};

function helpText() {
  return [
    'Quantum Vault CLI',
    '',
    'Commands:',
    '  qv keygen --out <dir> [--name <prefix>] [--force] [--print-public] [--json]',
    '  qv inspect <artifact-file> [--json]',
    '  qv canonicalize <artifact-file> [--json]',
    '  qv verify <archive-state.json> [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--json]',
    '  qv restore --shards <glob-or-file> [--shards <glob-or-file>] [--archive-state <file>] [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] --dry-run [--json]',
    '',
    'Current write scope:',
    '  keygen writes ML-KEM-1024 .qkey files',
    '  restore is read-only and requires --dry-run',
    '  encrypt, decrypt, split, attach, and write-mode restore are not yet available',
    '',
  ].join('\n');
}

function formatCliError(command, error) {
  const label = command || 'qv';
  return `qv: ${label}: ${error?.message || error}\n`;
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
    return EXIT.OK;
  }

  const json = parseGlobalJsonFlag(args);

  try {
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

    if (command === 'inspect') {
      const { filePath } = parseInspectArgs(args);
      const report = await runInspectCommand(filePath);
      if (json) {
        writeJson(stdout, withCliJsonEnvelope(report));
      } else {
        writeText(stdout, renderInspectSummary(report));
      }
      return EXIT.OK;
    }

    if (command === 'canonicalize') {
      const { filePath } = parseCanonicalizeArgs(args);
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
      const policySatisfied = authenticity?.policy?.satisfied === true;
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
      const summary = await runRestoreDryRunCommand(options, { cwd });
      if (options.json) {
        writeJson(stdout, withCliJsonEnvelope(summary, {
          ok: summary.wouldSucceed === true,
        }));
      } else {
        writeText(stdout, renderRestoreSummary(summary));
      }
      return summary.wouldSucceed === true ? EXIT.OK : EXIT.ERROR;
    }

    throw new Error(`Unknown command: ${command}`);
  } catch (error) {
    if (json) {
      writeJson(stdout, createJsonError(command, error));
    } else {
      writeText(stderr, formatCliError(command, error));
    }
    return mapErrorToExitCode(error);
  }
}
