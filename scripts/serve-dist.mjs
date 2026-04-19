import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const distDir = path.join(root, 'dist');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

function parsePort(argv) {
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--port' && index + 1 < argv.length) {
      const port = Number(argv[index + 1]);
      if (Number.isInteger(port) && port > 0) {
        return port;
      }
    }
  }
  return Number(process.env.PORT || 4173);
}

async function loadBuildManifest() {
  const manifestPath = path.join(distDir, 'BUILD.manifest.json');
  if (!existsSync(manifestPath)) {
    throw new Error('Built dist/BUILD.manifest.json not found. Run npm run build first.');
  }
  return JSON.parse(await readFile(manifestPath, 'utf8'));
}

function normalizeBasePath(value) {
  const basePath = String(value || '/').trim() || '/';
  if (basePath === '/') return '/';
  return `/${basePath.replace(/^\/+|\/+$/g, '')}/`;
}

function requestPathToRelativePath(requestPath, basePath) {
  if (basePath !== '/' && requestPath === '/') {
    return null;
  }

  if (basePath !== '/') {
    if (requestPath === basePath.slice(0, -1)) {
      return null;
    }
    if (!requestPath.startsWith(basePath)) {
      return '__not_found__';
    }
    const withoutBase = requestPath.slice(basePath.length);
    return withoutBase === '' ? 'index.html' : withoutBase;
  }

  return requestPath === '/' ? 'index.html' : requestPath.replace(/^\/+/, '');
}

async function serveDistFile(relativePath) {
  const resolved = path.resolve(distDir, relativePath);
  if (!resolved.startsWith(`${distDir}${path.sep}`) && resolved !== path.join(distDir, 'index.html')) {
    return { status: 403, body: 'Forbidden', type: 'text/plain; charset=utf-8' };
  }
  if (!existsSync(resolved)) {
    return { status: 404, body: 'Not Found', type: 'text/plain; charset=utf-8' };
  }

  const ext = path.extname(resolved);
  return {
    status: 200,
    body: await readFile(resolved),
    type: MIME[ext] || 'application/octet-stream',
  };
}

async function main() {
  const port = parsePort(process.argv.slice(2));
  const buildManifest = await loadBuildManifest();
  const basePath = normalizeBasePath(buildManifest.basePath);

  const server = createServer(async (req, res) => {
    try {
      const requestUrl = new URL(req.url || '/', `http://127.0.0.1:${port}`);
      const relativePath = requestPathToRelativePath(requestUrl.pathname, basePath);

      if (relativePath === null) {
        const location = basePath === '/' ? '/' : basePath;
        res.writeHead(302, { Location: location });
        res.end();
        return;
      }
      if (relativePath === '__not_found__') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not Found');
        return;
      }

      const response = await serveDistFile(decodeURIComponent(relativePath));
      res.writeHead(response.status, { 'Content-Type': response.type });
      res.end(response.body);
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(error?.message || 'Internal Server Error');
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`Dist server: http://127.0.0.1:${port}${basePath === '/' ? '/' : basePath}`);
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
