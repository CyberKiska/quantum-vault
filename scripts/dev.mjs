import { existsSync, watch } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProject } from './build.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const distDir = path.join(root, 'dist');
const srcDir = path.join(root, 'src');
const publicDir = path.join(root, 'public');
const port = Number(process.env.PORT || 5173);

const ROOT_WATCH_FILES = new Set(['index.html', 'style.css']);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

async function serveFile(urlPath) {
  const relativePath = urlPath === '/' ? 'index.html' : decodeURIComponent(urlPath).replace(/^\//, '');
  const filePath = path.resolve(distDir, relativePath);

  if (!filePath.startsWith(`${distDir}${path.sep}`) && filePath !== path.join(distDir, 'index.html')) {
    return { status: 403, body: 'Forbidden', type: 'text/plain; charset=utf-8' };
  }

  if (!existsSync(filePath)) {
    return { status: 404, body: 'Not Found', type: 'text/plain; charset=utf-8' };
  }

  const ext = path.extname(filePath);
  const type = MIME[ext] || 'application/octet-stream';
  const body = await readFile(filePath);
  return { status: 200, body, type };
}

async function runBuild() {
  await buildProject({ minify: false });
}

async function main() {
  await runBuild();

  const server = createServer(async (req, res) => {
    try {
      const requestUrl = new URL(req.url || '/', `http://localhost:${port}`);
      const response = await serveFile(requestUrl.pathname);
      res.writeHead(response.status, { 'Content-Type': response.type });
      res.end(response.body);
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(error?.message || 'Internal Server Error');
    }
  });

  server.listen(port, () => {
    console.log(`Dev server: http://localhost:${port}`);
  });

  let timer = null;
  const scheduleRebuild = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        await runBuild();
        console.log('Rebuilt.');
      } catch (error) {
        console.error('Build failed:', error?.message || error);
      }
    }, 120);
  };

  watch(srcDir, { recursive: true }, scheduleRebuild);

  if (existsSync(publicDir)) {
    watch(publicDir, { recursive: true }, scheduleRebuild);
  }

  watch(root, { recursive: false }, (_eventType, filename) => {
    if (filename && ROOT_WATCH_FILES.has(filename.toString())) {
      scheduleRebuild();
    }
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
