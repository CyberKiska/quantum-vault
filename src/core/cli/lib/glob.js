import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { assertNoSymlinkPath, symlinksAllowed } from './io.js';

/** Locale-independent UTF-16 code unit ordering (deterministic across environments). */
export function compareUtf16(a, b) {
  const left = String(a);
  const right = String(b);
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export function normalizePathForMatch(value) {
  return String(value).split(path.sep).join('/');
}

export function hasGlobPattern(value) {
  return /[*?[\]{}]/.test(String(value || ''));
}

async function collectFilesRecursive(dirPath) {
  const entries = await readdir(dirPath, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => compareUtf16(left.name, right.name))) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      files.push(...await collectFilesRecursive(fullPath));
      continue;
    }
    if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

function resolveGlobBase(pattern, cwd) {
  const normalized = normalizePathForMatch(pattern);
  const absolute = path.isAbsolute(pattern);
  const segments = normalized.split('/').filter(Boolean);
  const baseSegments = [];
  for (const segment of segments) {
    if (hasGlobPattern(segment)) break;
    baseSegments.push(segment);
  }
  if (absolute) {
    return baseSegments.length > 0 ? path.resolve(path.sep, ...baseSegments) : path.sep;
  }
  return baseSegments.length > 0 ? path.resolve(cwd, ...baseSegments) : cwd;
}

export async function expandFilePattern(pattern, cwd) {
  const resolved = path.resolve(cwd, pattern);
  if (!hasGlobPattern(pattern)) {
    return [resolved];
  }

  const baseDir = resolveGlobBase(pattern, cwd);
  if (!symlinksAllowed()) {
    await assertNoSymlinkPath(baseDir);
  }
  const candidates = await collectFilesRecursive(baseDir);
  const matcher = path.isAbsolute(pattern)
    ? normalizePathForMatch(pattern)
    : normalizePathForMatch(pattern);

  return candidates.filter((candidate) => {
    const normalizedCandidate = normalizePathForMatch(path.isAbsolute(pattern) ? candidate : path.relative(cwd, candidate));
    return path.matchesGlob(normalizedCandidate, matcher);
  }).sort(compareUtf16);
}

export function dedupeSorted(values) {
  return [...new Set(values.map((value) => path.resolve(value)))].sort(compareUtf16);
}
