import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

function normalizeBasePath(value) {
  if (!value || value.trim() === '') return '/';
  let out = value.trim();
  if (!out.startsWith('/')) out = `/${out}`;
  if (!out.endsWith('/')) out = `${out}/`;
  return out;
}

async function copyPublicAssets(publicDir, distDir) {
  let entries = [];
  try {
    entries = await readdir(publicDir, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }

  await Promise.all(
    entries.map((entry) =>
      cp(path.join(publicDir, entry.name), path.join(distDir, entry.name), {
        recursive: true,
        force: true,
      })
    )
  );
}

export async function buildProject({ minify = true } = {}) {
  const distDir = path.join(root, 'dist');
  const assetsDir = path.join(distDir, 'assets');
  const srcDir = path.join(root, 'src');
  const publicDir = path.join(root, 'public');
  const basePath = normalizeBasePath(process.env.BASE_PATH || '/');

  await rm(distDir, { recursive: true, force: true });
  await mkdir(assetsDir, { recursive: true });

  await build({
    entryPoints: [path.join(srcDir, 'main.js')],
    outfile: path.join(assetsDir, 'main.js'),
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2022'],
    sourcemap: true,
    minify,
    logLevel: 'info',
  });

  const [htmlTemplate, css] = await Promise.all([
    readFile(path.join(root, 'index.html'), 'utf8'),
    readFile(path.join(root, 'style.css'), 'utf8'),
  ]);

  const html = htmlTemplate.replaceAll('%BASE_PATH%', basePath);

  await copyPublicAssets(publicDir, distDir);

  await Promise.all([
    writeFile(path.join(distDir, 'index.html'), html, 'utf8'),
    writeFile(path.join(distDir, 'style.css'), css, 'utf8'),
    writeFile(path.join(distDir, '.nojekyll'), '', 'utf8'),
  ]);

  console.log(`Build completed. basePath=${basePath}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildProject().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
