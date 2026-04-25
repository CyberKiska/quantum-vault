import { createHash } from 'node:crypto';
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, version as esbuildVersion } from 'esbuild';
import { createSchemaRegistry } from './lib/json-schema-lite.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const BUILD_MANIFEST_FILENAME = 'BUILD.manifest.json';
const BUILD_MANIFEST_TYPE = 'quantum-vault-build-manifest/v1';
const BUILD_MANIFEST_VERSION = 1;
const BUILD_TIMESTAMP_ENV = 'BUILD_TIMESTAMP';
const ERASURE_JS_SHA256 = '83a5c2789808cc4f0236e3d184cc160a0e995f105094d844c0fe813bab069c3d';

function normalizeBasePath(value) {
  if (!value || value.trim() === '') return '/';
  let out = value.trim();
  if (!out.startsWith('/')) out = `/${out}`;
  if (!out.endsWith('/')) out = `${out}/`;
  return out;
}

function normalizeRelativePath(value) {
  return String(value).split(path.sep).join('/');
}

function hashHex(bytes, algorithm) {
  return createHash(algorithm).update(bytes).digest('hex');
}

function sriSha384(bytes) {
  return `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
}

function parseNpmVersionFromUserAgent(userAgent) {
  const match = /(?:^|\s)npm\/([^\s]+)/.exec(String(userAgent || ''));
  return match ? match[1] : null;
}

function resolveBuildTimestamp(explicitTimestamp) {
  const candidate = explicitTimestamp ?? process.env[BUILD_TIMESTAMP_ENV];
  if (candidate == null || String(candidate).trim() === '') {
    return new Date().toISOString();
  }
  const normalized = new Date(candidate).toISOString();
  if (normalized !== candidate) {
    throw new Error(
      `${BUILD_TIMESTAMP_ENV} must be a canonical ISO-8601 timestamp in UTC; got ${JSON.stringify(candidate)}`
    );
  }
  return normalized;
}

function resolveBuildCommand(explicitBuildCommand) {
  if (typeof explicitBuildCommand === 'string' && explicitBuildCommand.trim() !== '') {
    return explicitBuildCommand.trim();
  }
  const lifecycleEvent = String(process.env.npm_lifecycle_event || '').trim();
  if (lifecycleEvent) {
    return `npm run ${lifecycleEvent}`;
  }
  return `node ${normalizeRelativePath(path.relative(root, __filename))}`;
}

function resolvePinnedNpmVersion(packageJson) {
  const packageManager = String(packageJson?.packageManager || '');
  if (packageManager.startsWith('npm@')) {
    return packageManager.slice('npm@'.length);
  }
  return null;
}

function resolveNpmVersion(packageJson) {
  return (
    parseNpmVersionFromUserAgent(process.env.npm_config_user_agent) ||
    resolvePinnedNpmVersion(packageJson) ||
    'unknown'
  );
}

async function readJsonFile(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
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

async function listRegularFiles(dir, relativeDir = '') {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const absolutePath = path.join(dir, entry.name);
    const relativePath = relativeDir ? path.join(relativeDir, entry.name) : entry.name;

    if (entry.isDirectory()) {
      files.push(...await listRegularFiles(absolutePath, relativePath));
      continue;
    }
    if (entry.isFile()) {
      files.push(normalizeRelativePath(relativePath));
    }
  }

  return files;
}

async function loadBuildManifestSchemaRegistry() {
  const schemaPath = path.join(root, 'docs', 'schema', 'qv-build-manifest-v1.schema.json');
  const schema = await readJsonFile(schemaPath);
  return createSchemaRegistry([
    {
      uri: schema.$id,
      schema,
    },
  ]);
}

async function buildManifestForDirectory({
  distDir,
  buildTimestamp,
  buildCommand,
  nodeVersion,
  npmVersion,
  basePath,
  minify,
}) {
  const allFiles = await listRegularFiles(distDir);
  const artifactPaths = allFiles.filter((filePath) => filePath !== BUILD_MANIFEST_FILENAME);
  const artifacts = [];

  for (const relativePath of artifactPaths) {
    const absolutePath = path.join(distDir, relativePath);
    const bytes = await readFile(absolutePath);
    const fileStat = await stat(absolutePath);
    artifacts.push({
      path: relativePath,
      sizeBytes: fileStat.size,
      sha256: hashHex(bytes, 'sha256'),
      'sha3-512': hashHex(bytes, 'sha3-512'),
    });
  }

  return {
    type: BUILD_MANIFEST_TYPE,
    version: BUILD_MANIFEST_VERSION,
    buildTimestamp,
    buildCommand,
    nodeVersion,
    npmVersion,
    esbuildVersion,
    basePath,
    minify: minify === true,
    artifacts,
  };
}

function injectBuildIntegrities(htmlTemplate, { basePath, erasureSri, mainJsSri }) {
  return htmlTemplate
    .replaceAll('%BASE_PATH%', basePath)
    .replaceAll('%ERASURE_JS_SRI%', erasureSri)
    .replaceAll('%MAIN_JS_SRI%', mainJsSri);
}

export async function buildProject({
  minify = true,
  distDir = path.join(root, 'dist'),
  basePath = normalizeBasePath(process.env.BASE_PATH || '/'),
  buildTimestamp = resolveBuildTimestamp(),
  buildCommand = resolveBuildCommand(),
} = {}) {
  const assetsDir = path.join(distDir, 'assets');
  const srcDir = path.join(root, 'src');
  const publicDir = path.join(root, 'public');
  const packageJson = await readJsonFile(path.join(root, 'package.json'));
  const nodeVersion = process.version;
  const npmVersion = resolveNpmVersion(packageJson);

  await rm(distDir, { recursive: true, force: true });
  await mkdir(assetsDir, { recursive: true });

  const erasurePath = path.join(publicDir, 'third-party', 'erasure.js');
  const erasureBytes = await readFile(erasurePath);
  const erasureHash = hashHex(erasureBytes, 'sha256');
  if (erasureHash !== ERASURE_JS_SHA256) {
    throw new Error(
      `Third-party erasure.js integrity check failed.\n` +
      `  Expected SHA-256: ${ERASURE_JS_SHA256}\n` +
      `  Got:             ${erasureHash}\n` +
      `  File: ${erasurePath}`
    );
  }
  console.log(`Verified erasure.js integrity (SHA-256: ${erasureHash.slice(0, 16)}…)`);

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

  await copyPublicAssets(publicDir, distDir);

  const [htmlTemplate, css, mainJsBytes] = await Promise.all([
    readFile(path.join(root, 'index.html'), 'utf8'),
    readFile(path.join(root, 'style.css'), 'utf8'),
    readFile(path.join(assetsDir, 'main.js')),
  ]);

  // We scope HTML integrity attributes to executable scripts only. Non-script
  // artifacts remain covered by BUILD.manifest.json rather than implying that
  // browsers enforce SRI uniformly across every deployed file type.
  const html = injectBuildIntegrities(htmlTemplate, {
    basePath,
    erasureSri: sriSha384(erasureBytes),
    mainJsSri: sriSha384(mainJsBytes),
  });

  await Promise.all([
    writeFile(path.join(distDir, 'index.html'), html, 'utf8'),
    writeFile(path.join(distDir, 'style.css'), css, 'utf8'),
    writeFile(path.join(distDir, '.nojekyll'), '', 'utf8'),
  ]);

  // Determinism here means "same source tree, lockfile, build inputs, and
  // pinned Node/npm/esbuild versions produce the same emitted bytes." The
  // only intentionally variable field is buildTimestamp, which can be fixed
  // via BUILD_TIMESTAMP for reproducible CI. This does not claim cross-version
  // or cross-platform bit identity beyond the bytes esbuild actually emits.
  const manifest = await buildManifestForDirectory({
    distDir,
    buildTimestamp,
    buildCommand,
    nodeVersion,
    npmVersion,
    basePath,
    minify,
  });
  const schemaRegistry = await loadBuildManifestSchemaRegistry();
  schemaRegistry.validate('https://quantum-vault.local/schema/qv-build-manifest-v1.schema.json', manifest);

  await writeFile(
    path.join(distDir, BUILD_MANIFEST_FILENAME),
    `${JSON.stringify(manifest, null, 2)}\n`,
    'utf8'
  );

  console.log(
    `Build completed. basePath=${basePath} timestamp=${buildTimestamp} npm=${npmVersion} esbuild=${esbuildVersion}`
  );

  return {
    distDir,
    manifest,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildProject().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
