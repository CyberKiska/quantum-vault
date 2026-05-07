import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(thisDir, '..');
const qvBin = path.join(repoRoot, 'bin/qv.mjs');
const decoder = new TextDecoder();

function formatFailure(result) {
  const stdout = result.stdout.trim();
  const stderr = result.stderr.trim();
  return [
    `qv ${result.args.join(' ')} exited ${result.exitCode}`,
    stdout ? `stdout: ${stdout}` : '',
    stderr ? `stderr: ${stderr}` : '',
  ].filter(Boolean).join('\n');
}

function assert(value, message) {
  if (!value) {
    throw new Error(message);
  }
}

function runQv(args, {
  cwd = repoRoot,
  input = null,
} = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [qvBin, ...args], {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        NO_COLOR: '1',
      },
    });
    const stdout = [];
    const stderr = [];

    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (exitCode) => {
      resolve({
        args,
        exitCode,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });

    if (input) {
      child.stdin.end(Buffer.from(input.buffer, input.byteOffset, input.byteLength));
    } else {
      child.stdin.end();
    }
  });
}

async function runJsonQv(args, options = {}) {
  const result = await runQv([...args, '--json'], options);
  if (result.exitCode !== 0) {
    throw new Error(formatFailure(result));
  }
  if (result.stderr !== '') {
    throw new Error(`qv ${result.args.join(' ')} emitted stderr: ${result.stderr}`);
  }
  return JSON.parse(result.stdout);
}

async function main() {
  const baseDir = await mkdtemp(path.join(tmpdir(), 'qv-cli-selftest-'));
  const keyDir = path.join(baseDir, 'keys');
  const plaintextPath = path.join(baseDir, 'payload.txt');
  const qencPath = path.join(baseDir, 'payload.txt.qenc');
  const decryptedPath = path.join(baseDir, 'payload.out');
  const splitDir = path.join(baseDir, 'cohort');
  const restoreDir = path.join(baseDir, 'restored');
  const plaintext = new TextEncoder().encode('Quantum Vault CLI end-to-end selftest\n');

  await writeFile(plaintextPath, plaintext);

  const keygen = await runJsonQv(['keygen', '--out', keyDir]);
  assert(keygen.publicKeyLength === 1568, 'keygen public-key length mismatch');
  assert(keygen.privateKeyLength === 3168, 'keygen private-key length mismatch');

  const encrypt = await runJsonQv([
    'encrypt',
    plaintextPath,
    '--public-key',
    keygen.publicKeyPath,
    '--out',
    qencPath,
  ]);
  assert(encrypt.payloadKind === 'file', 'encrypt payloadKind mismatch');

  const decrypt = await runJsonQv([
    'decrypt',
    qencPath,
    '--private-key',
    keygen.privateKeyPath,
    '--out',
    decryptedPath,
  ]);
  assert(decrypt.outputPath === decryptedPath, 'decrypt output path mismatch');
  assert(decoder.decode(await readFile(decryptedPath)) === decoder.decode(plaintext), 'decrypt plaintext mismatch');

  const split = await runJsonQv([
    'split',
    qencPath,
    '--private-key',
    keygen.privateKeyPath,
    '--n',
    '5',
    '--k',
    '3',
    '--out',
    splitDir,
    '--auth-policy-level',
    'integrity-only',
    '--archive-id-random',
    '13'.repeat(32),
  ]);
  assert(split.fmt === 'QVqcont-7', 'split format mismatch');
  assert(split.shards.length === 5, 'split shard count mismatch');

  const dryRun = await runJsonQv([
    'restore',
    '--shards',
    path.join(splitDir, '*.qcont'),
    '--dry-run',
  ]);
  assert(dryRun.wouldSucceed === true, 'restore dry-run did not succeed');
  assert(dryRun.archiveId === split.archiveId, 'restore dry-run archiveId mismatch');

  const restore = await runJsonQv([
    'restore',
    '--shards',
    path.join(splitDir, '*.qcont'),
    '--out',
    restoreDir,
  ]);
  assert(restore.wouldSucceed === true, 'restore write mode did not succeed');
  assert(restore.outputs?.qencPath, 'restore qenc output missing');
  assert(restore.outputs?.keyPath, 'restore key output missing');
  assert(Buffer.compare(await readFile(restore.outputs.qencPath), await readFile(qencPath)) === 0, 'restore .qenc bytes mismatch');
  assert(Buffer.compare(await readFile(restore.outputs.keyPath), await readFile(keygen.privateKeyPath)) === 0, 'restore private-key bytes mismatch');

  const inspect = await runJsonQv(['inspect', split.shards[0].path]);
  assert(inspect.artifactType === 'QVqcont-7', 'inspect shard artifact type mismatch');

  const canonicalize = await runJsonQv(['canonicalize', split.archiveStateBytesPath]);
  assert(canonicalize.digestHex === split.archiveStateDigestHex, 'canonicalize archive-state digest mismatch');

  const version = await runJsonQv(['version']);
  assert(version.format?.qcont === 'QVqcont-7', 'version qcont format mismatch');

  console.log('CLI selftest: PASS (keygen/encrypt/decrypt/split/restore/inspect/canonicalize/version)');
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
