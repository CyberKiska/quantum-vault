import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

function playwrightBinaryPath() {
  const suffix = process.platform === 'win32' ? '.cmd' : '';
  return path.join(root, 'node_modules', '.bin', `playwright${suffix}`);
}

function ensureBuiltBundle() {
  const manifestPath = path.join(root, 'dist', 'BUILD.manifest.json');
  if (!existsSync(manifestPath)) {
    throw new Error('dist/BUILD.manifest.json is missing. Run npm run build before npm run test:browser.');
  }
}

async function main() {
  ensureBuiltBundle();

  const playwrightBin = playwrightBinaryPath();
  if (!existsSync(playwrightBin)) {
    throw new Error('@playwright/test is not installed. Run npm install first.');
  }

  const child = spawn(playwrightBin, ['test', ...process.argv.slice(2)], {
    cwd: root,
    stdio: 'inherit',
    env: process.env,
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

main().catch((error) => {
  console.error(error?.message || error);
  process.exit(1);
});
