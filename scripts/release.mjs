#!/usr/bin/env node

import { execSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const RELEASE_TARGET = process.argv[2];
const BUMP_TYPES = new Set(["major", "minor", "patch"]);
const SEMVER_RE = /^\d+\.\d+\.\d+$/;

if (!RELEASE_TARGET || (!BUMP_TYPES.has(RELEASE_TARGET) && !SEMVER_RE.test(RELEASE_TARGET))) {
  console.error(
    `error: invalid release target "${RELEASE_TARGET ?? ""}" — expected major|minor|patch or an x.y.z version`,
  );
  process.exit(1);
}

function run(cmd, options = {}) {
  try {
    return execSync(cmd, {
      encoding: "utf-8",
      stdio: options.silent ? "pipe" : "inherit",
      ...options,
    });
  } catch (_e) {
    if (!options.ignoreError) {
      console.error(`error: command failed: ${cmd}`);
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
    execSync("git diff --cached --quiet");
  } catch {
    run(`git commit -m "${message}"`);
  }
}

function bumpOrSetVersion(target) {
  const currentVersion = getVersion();
  let newVersion;

  if (BUMP_TYPES.has(target)) {
    const parts = currentVersion.split(".").map(Number);
    if (target === "major") {
      parts[0] += 1;
      parts[1] = 0;
      parts[2] = 0;
    } else if (target === "minor") {
      parts[1] += 1;
      parts[2] = 0;
    } else if (target === "patch") {
      parts[2] += 1;
    }
    newVersion = parts.join(".");
  } else {
    if (
      target.localeCompare(currentVersion, undefined, { numeric: true, sensitivity: "base" }) <= 0
    ) {
      console.error(
        `error: target version ${target} is not greater than current ${currentVersion}`,
      );
      process.exit(1);
    }
    newVersion = target;
  }

  const packagesDir = "packages";
  const packages = readdirSync(packagesDir).filter((name) => {
    try {
      return statSync(join(packagesDir, name)).isDirectory();
    } catch {
      return false;
    }
  });

  const targetPaths = [
    "package.json",
    ...packages.map((pkg) => join(packagesDir, pkg, "package.json")),
  ];

  for (const pkgPath of targetPaths) {
    if (existsSync(pkgPath)) {
      const data = JSON.parse(readFileSync(pkgPath, "utf-8"));
      data.version = newVersion;
      writeFileSync(pkgPath, `${JSON.stringify(data, null, 2)}\n`);
    }
  }

  return newVersion;
}

function getChangelogs() {
  const packagesDir = "packages";
  const packages = readdirSync(packagesDir);
  const changelogs = packages
    .map((pkg) => join(packagesDir, pkg, "CHANGELOG.md"))
    .filter((path) => existsSync(path));
  if (existsSync("CHANGELOG.md")) changelogs.push("CHANGELOG.md");
  return changelogs;
}

function updateChangelogsForRelease(version) {
  // Shared with .github/workflows/release.yml so local and CI releases stamp
  // changelogs identically.
  // stamp-changelogs removed — no CHANGELOG.md files exist in the repo
}

function addUnreleasedSection() {
  const changelogs = getChangelogs();
  const unreleasedSection = "## [Unreleased]\n\n";
  for (const changelog of changelogs) {
    const content = readFileSync(changelog, "utf-8");
    const updated = content.replace(/^(## \[)/m, `${unreleasedSection}$1`);
    writeFileSync(changelog, updated);
  }
}

const status = run("git status --porcelain", { silent: true });
if (status?.trim()) {
  console.error("error: working tree is dirty — commit or stash changes before releasing");
  process.exit(1);
}
run("npm test");

const version = bumpOrSetVersion(RELEASE_TARGET);
updateChangelogsForRelease(version);
stageChangedFiles();
commitIfStaged(`Release v${version}`);
run(`git tag v${version}`);
addUnreleasedSection();
stageChangedFiles();
commitIfStaged("Add [Unreleased] section for next cycle");
run("git push origin main");
run(`git push origin v${version}`);
