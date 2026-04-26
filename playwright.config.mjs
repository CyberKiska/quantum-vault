import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from '@playwright/test';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = __dirname;
const buildManifestPath = path.join(root, 'dist', 'BUILD.manifest.json');
const port = Number(process.env.PLAYWRIGHT_PORT || 4173);

function normalizeBasePath(value) {
  const basePath = String(value || '/').trim() || '/';
  if (basePath === '/') return '/';
  return `/${basePath.replace(/^\/+|\/+$/g, '')}/`;
}

const buildManifest = existsSync(buildManifestPath)
  ? JSON.parse(readFileSync(buildManifestPath, 'utf8'))
  : { basePath: '/' };
const basePath = normalizeBasePath(buildManifest.basePath);
const serverUrl = `http://127.0.0.1:${port}${basePath === '/' ? '/' : basePath}`;
const baseURL = `http://127.0.0.1:${port}${basePath === '/' ? '' : basePath.slice(0, -1)}`;

export default defineConfig({
  testDir: './tests/browser',
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI
    ? [['list'], ['html', { open: 'never' }]]
    : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    testIdAttribute: 'data-testid',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
      },
    },
  ],
  webServer: {
    command: `node scripts/serve-dist.mjs --port ${port}`,
    url: serverUrl,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
