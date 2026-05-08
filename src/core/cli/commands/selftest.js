import { runSelfTest } from '../../crypto/selftest.js';
import { takeValue } from '../lib/args.js';
import { QV_CODE, makeQvError } from '../lib/exit.js';

function usage(message) {
  return makeQvError(message, QV_CODE.USAGE);
}

export function parseSelftestArgs(args) {
  const options = {
    filter: '',
    json: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--filter':
        options.filter = takeValue(args, index, arg);
        index += 1;
        break;
      case '--json':
        options.json = true;
        break;
      default:
        throw usage(`Unknown selftest option: ${arg}`);
    }
  }

  if (options.filter.length > 256 || /[\0\r\n]/.test(options.filter)) {
    throw usage('--filter must be a short single-line substring');
  }
  return options;
}

export async function runSelftestCommand(options = {}) {
  const report = await runSelfTest({ filter: options.filter });
  if (options.filter && report.total === 0) {
    throw usage(`selftest --filter matched no cases: ${options.filter}`);
  }
  return {
    command: 'selftest',
    ...report,
    filter: options.filter || null,
  };
}

export function renderSelftestSummary(report) {
  const lines = [
    `Self-test: ${report.ok ? 'PASS' : 'FAIL'} (${report.passed}/${report.total})`,
  ];
  if (report.filter) {
    lines.push(`Filter: ${report.filter}`);
  }
  for (const result of report.results || []) {
    lines.push(result.ok
      ? `  OK   ${result.name}`
      : `  FAIL ${result.name}: ${result.error}`);
  }
  return `${lines.join('\n')}\n`;
}
