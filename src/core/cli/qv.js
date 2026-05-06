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
  runRestoreDryRunCommand,
} from './commands/restore-dry-run.js';
import {
  parseSplitArgs,
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
  runDecryptCommand,
  runEncryptCommand,
  runInspectCommand,
  runKeygenCommand,
  runAttachCommand,
  runReshareCommand,
  runRestoreDryRunCommand,
  runSplitCommand,
  runVerifyCommand,
  verifyArchiveInputs,
};

function helpText() {
  return [
    'Quantum Vault CLI',
    '',
    'Commands:',
    '  qv keygen --out <dir> [--name <prefix>] [--force] [--print-public] [--json]',
    '  qv encrypt <input-file> --public-key <publicKey.qkey> --out <output.qenc> [--filename <name>] [--force] [--json]',
    '  qv encrypt --pack <file> <file> [...] --public-key <publicKey.qkey> --out <output.qenc> [--filename <bundle.qvpack>] [--force] [--json]',
    '  qv decrypt <input.qenc> --private-key <privateKey.qkey> [--out <file>] [--out-dir <dir>] [--use-original-filename] [--extract-qvpack] [--force] [--json]',
    '  qv split <input.qenc> --private-key <privateKey.qkey> --n <int> --k <int> [--out <dir>] [--auth-policy-level <level>] [--min-valid-signatures <int>] [--force] [--json]',
    '  qv attach [--shards <glob-or-file> ...] [--archive-state <file>] [--bundle <file>] [--sig <file> ...] [--sig-import <json> ...] [--pqpk <file> ...] [--ots <file> ...] [--source-evidence <json-file> | --source-evidence-bytes <file>] [--ed25519-signer <address>] [--out-bundle <file>] [--out-shards <dir>] [--no-embed-into-shards] [--force] [--json]',
    '  qv reshare --shards <glob-or-file> ... --n <int> --k <int> [--bundle <file>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] [--reason-code <string>] [--operator-role <string>] [--notes <string>] [--performed-at <iso8601>] [--maintenance-sig <file> ...] [--maintenance-pqpk <file> ...] [--maintenance-ots <file> ...] [--out <dir>] [--force] [--json]',
    '  qv inspect <artifact-file> [--json]',
    '  qv canonicalize <artifact-file> [--json]',
    '  qv verify <archive-state.json> [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--json]',
    '  qv restore --shards <glob-or-file> [--shards <glob-or-file>] [--archive-state <file>] [--bundle <file>] [--sig <file>] [--pqpk <file>] [--ots <file>] [--ed25519-signer <address>] [--archive-id <hex>] [--state-id <hex>] [--cohort-id <hex>] [--bundle-digest <hex>] --dry-run [--json]',
    '',
    'Current write scope:',
    '  keygen writes ML-KEM-1024 .qkey files',
    '  encrypt writes .qenc containers and can pre-pack multiple files as .qvpack payloads',
    '  decrypt writes plaintext files and can explicitly extract authenticated .qvpack payloads',
    '  split writes QVqcont-7 shards plus archive-state, cohort-binding, and lifecycle-bundle JSON',
    '  attach writes updated lifecycle-bundle JSON and can rewrite successor shards with the bundle embedded',
    '  reshare writes a same-state successor cohort plus transition and lifecycle-bundle JSON',
    '  restore is read-only and requires --dry-run',
    '  write-mode restore is not yet available',
    '',
  ].join('\n');
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
      const options = parseSplitArgs(args);
      const report = await runSplitCommand(options, { stdin, cwd });
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
