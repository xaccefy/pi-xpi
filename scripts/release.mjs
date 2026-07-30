#!/usr/bin/env node

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const RELEASE_TARGET = process.argv[2];
const BUMP_TYPES = new Set(["major", "minor", "patch"]);
const SEMVER_RE = /^\d+\.\d+\.\d+$/;

if (!RELEASE_TARGET || (!BUMP_TYPES.has(RELEASE_TARGET) && !SEMVER_RE.test(RELEASE_TARGET))) {
  process.exit(1);
}

function run(cmd, options = {}) {
  try {
    return execSync(cmd, {
      encoding: "utf-8",
      stdio: options.silent ? "pipe" : "inherit",
      timeout: 30_000,
      ...options,
    });
  } catch (_e) {
    if (!options.ignoreError) {
      process.exit(1);
    }
    return null;
  }
}

function getVersion() {
  const pkg = JSON.parse(readFileSync("package.json", "utf-8"));
  return pkg.version;
}

function shellQuote(value) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function stageChangedFiles() {
  const output = run("git ls-files -m -o -d --exclude-standard", { silent: true });
  const paths = [
    ...new Set(
      (output || "")
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  ];
  if (paths.length === 0) return;
  run(`git add -- ${paths.map(shellQuote).join(" ")}`);
}

function commitIfStaged(message) {
  try {
    execSync("git diff --cached --quiet", { timeout: 30_000 });
  } catch {
    run(`git commit -m "${message}"`);
  }
}

// Delegate the actual version writes to bump-version.js — one implementation,
// no drift. It handles patch|minor|major and explicit x.y.z targets.
function bumpOrSetVersion(target) {
  run(`node scripts/bump-version.js ${target}`);
  return getVersion();
}

const status = run("git status --porcelain", { silent: true });
if (status?.trim()) {
  process.exit(1);
}
run("npm test");

const version = bumpOrSetVersion(RELEASE_TARGET);
stageChangedFiles();
commitIfStaged(`Release v${version}`);
run(`git tag v${version}`);
run("git push origin main");
run(`git push origin v${version}`);
