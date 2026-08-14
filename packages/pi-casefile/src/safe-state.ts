import { randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

function isWithin(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
}

function validateComponent(component: string): void {
  if (!component || component === "." || component === ".." || basename(component) !== component) {
    throw new Error(`Unsafe state path component: ${component}`);
  }
}

function verifyDirectory(path: string, canonicalRoot: string): void {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`State directory must be a real directory, not a symlink: ${path}`);
  }
  const canonical = realpathSync(path);
  if (!isWithin(canonicalRoot, canonical)) {
    throw new Error(`State directory resolves outside its workspace: ${path}`);
  }
}

/**
 * Create and verify a state-directory chain beneath a trusted workspace root.
 * Every child component is checked with lstat so a pre-planted symlink cannot
 * redirect ledger, evidence, or scratchpad writes outside the workspace.
 */
export function ensureSafeStateDirectory(root: string, components: string[]): string {
  const canonicalRoot = realpathSync(root);
  let current = resolve(root);
  for (const component of components) {
    validateComponent(component);
    current = join(current, component);
    if (!existsSync(current)) {
      try {
        mkdirSync(current, { mode: 0o700 });
      } catch (error) {
        // A concurrent creator is acceptable only if the postcondition below
        // proves it created a real in-workspace directory.
        if (!existsSync(current)) throw error;
      }
    }
    verifyDirectory(current, canonicalRoot);
  }
  return current;
}

/** Verify an existing state-directory chain without creating anything. */
export function assertSafeStateDirectory(root: string, components: string[]): string {
  const canonicalRoot = realpathSync(root);
  let current = resolve(root);
  for (const component of components) {
    validateComponent(component);
    current = join(current, component);
    if (!existsSync(current)) throw new Error(`State directory does not exist: ${current}`);
    verifyDirectory(current, canonicalRoot);
  }
  return current;
}

/** Return false for a missing file; reject symlinks and special files. */
export function assertSafeRegularFile(path: string, label = "State file"): boolean {
  if (!existsSync(path)) return false;
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`${label} must be a regular, non-symlink file: ${path}`);
  }
  return true;
}

export function readSafeFile(path: string, label = "State file"): Buffer {
  if (!assertSafeRegularFile(path, label)) throw new Error(`${label} does not exist: ${path}`);
  return readFileSync(path);
}

/**
 * Write through an exclusive temporary file and atomically rename it into
 * place. An existing symlink is rejected, and rename replaces the directory
 * entry rather than following a destination changed after the check.
 */
export function writeSafeFileAtomic(path: string, data: string | Buffer): void {
  assertSafeRegularFile(path);
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    writeFileSync(tmp, data, { flag: "wx", mode: 0o600 });
    renameSync(tmp, path);
  } finally {
    if (existsSync(tmp)) rmSync(tmp, { force: true });
  }
}

/** Create a new immutable state file; collisions and symlinks fail closed. */
export function writeSafeFileExclusive(path: string, data: string | Buffer): void {
  writeFileSync(path, data, { flag: "wx", mode: 0o600 });
}
